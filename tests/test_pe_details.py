"""Synthetic byte fixtures only: never load a PE or inspect installed programs."""

import io
import json
import struct

import pytest

from forensic_app.pe_details import LIMITS, analyze_pe


def fixture(bits=32, sections=1):
    data = bytearray(0x2000)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional = 224 if bits == 32 else 240
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14c, sections, 0, 0, 0, optional, 0)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x10b if bits == 32 else 0x20b)
    struct.pack_into('<I', data, opt + 60, 0x400)
    directory = opt + (96 if bits == 32 else 112)
    struct.pack_into('<I', data, directory - 4, 16)
    section = opt + optional
    for i in range(sections):
        struct.pack_into('<IIII', data, section + i * 40 + 8,
                         0x1000, 0x1000 + i * 0x1000, 0x1000, 0x400 + i * 0x1000)
    return data, directory, section


def directory(data, offset, index, rva, size):
    struct.pack_into('<II', data, offset + index * 8, rva, size)


def imports(bits=32, fallback=False):
    data, dirs, section = fixture(bits)
    directory(data, dirs, 1, 0x1000, 40)
    struct.pack_into('<5I', data, 0x400, 0 if fallback else 0x1100, 0, 0, 0x1080, 0x1100)
    data[0x480:0x48d] = b'EXAMPLE.dll\0\0\0'
    fmt = '<III' if bits == 32 else '<QQQ'
    struct.pack_into(fmt, data, 0x500, 0x1200, (1 << (bits - 1)) | 42, 0)
    struct.pack_into('<H', data, 0x600, 7)
    data[0x602:0x60b] = b'Function\0'
    return data, dirs, section


def analyze(data):
    value = analyze_pe(io.BytesIO(data), len(data))
    json.dumps(value)
    return value


@pytest.mark.parametrize('bits', [32, 64])
@pytest.mark.parametrize('fallback', [False, True])
def test_normal_imports_and_ordinals(bits, fallback):
    data, _dirs, _section = imports(bits, fallback)
    result = analyze(data)
    assert result['pe_kind'] == ('PE32' if bits == 32 else 'PE32+')
    part = result['imports']
    assert part['status'] == 'completed'
    assert part['function_count'] == 2
    entry = part['entries'][0]
    assert entry['dll'] == 'EXAMPLE.dll'
    assert entry['functions'] == [{'kind': 'name', 'hint': 7, 'name': 'Function'},
                                  {'kind': 'ordinal', 'ordinal': 42}]
    assert entry['thunk_source'] == ('first_thunk_fallback' if fallback else 'original')


def test_old_optional_zero_is_unsupported():
    data, _dirs, _section = fixture()
    struct.pack_into('<H', data, 0x94, 0)
    result = analyze(data)
    assert result['pe_kind'] is None
    assert all(result[k]['status'] == 'unsupported' for k in ('imports', 'resources', 'overlay'))


@pytest.mark.parametrize('kind,reason', [('virtual', 'rva_not_file_backed'),
                                        ('overflow', 'rva_overflow'),
                                        ('ambiguous', 'rva_ambiguous')])
def test_invalid_rva_ranges(kind, reason):
    data, dirs, section = imports()
    if kind == 'virtual':
        directory(data, dirs, 1, 0x2000, 40)
        struct.pack_into('<I', data, section + 8, 0x2000)
    elif kind == 'overflow':
        directory(data, dirs, 1, 0xfffffff0, 40)
    else:
        struct.pack_into('<H', data, 0x86, 2)
        data[section + 40:section + 80] = data[section:section + 40]
    assert reason in analyze(data)['imports']['reasons']


def test_no_unbounded_strings_and_bound_fallback_uncertain():
    data, _dirs, _section = imports(fallback=True)
    data[0x602:0xa02] = b'A' * 1024
    part = analyze(data)['imports']
    assert part['status'] == 'limited'
    assert part['partial']
    assert 'string_limit_reached' in part['reasons']
    assert 'bound_or_invalid_first_thunk' in part['reasons']
    assert part['entries'][0]['functions'] == []


def resources():
    data, dirs, section = fixture()
    directory(data, dirs, 2, 0x1000, 0x200)
    struct.pack_into('<HH', data, 0x40c, 1, 0)
    struct.pack_into('<II', data, 0x410, 0x80000080, 0x40)
    struct.pack_into('<4I', data, 0x440, 0x1300, 3, 1200, 0)
    struct.pack_into('<H', data, 0x480, 4)
    data[0x482:0x48a] = 'Name'.encode('utf-16le')
    data[0x700:0x703] = b'XYZ'
    return data, dirs, section


def test_resources_names_metadata_no_payload_read():
    data, _dirs, _section = resources()

    class Guard(io.BytesIO):
        def read(self, count=-1):
            assert self.tell() + count <= 0x700 or self.tell() >= 0x703
            return super().read(count)

    part = analyze_pe(Guard(data), len(data))['resources']
    assert part['status'] == 'completed'
    assert part['entries'] == [{'path': [{'name': 'Name'}], 'data_rva': 0x1300,
                               'bytes': 3, 'codepage': 1200, 'reserved': 0,
                               'file_offset': 0x700, 'data_range_valid': True}]


@pytest.mark.parametrize('change,reason', [('cycle', 'resource_directory_repeated'),
                                         ('outside', 'resource_root_range_invalid'),
                                         ('name', 'resource_name_limit_reached')])
def test_resource_rejects_cycles_root_escape_and_names(change, reason):
    data, _dirs, _section = resources()
    if change == 'cycle':
        struct.pack_into('<I', data, 0x414, 0x80000000)
    elif change == 'outside':
        struct.pack_into('<I', data, 0x414, 0x200)
    else:
        struct.pack_into('<H', data, 0x480, 257)
    assert reason in analyze(data)['resources']['reasons']


def test_resource_depth_limit():
    data, _dirs, _section = fixture()
    directory(data, _dirs, 2, 0x1000, 0x200)
    for i in range(8):
        offset = 0x400 + i * 24
        struct.pack_into('<HHII', data, offset + 12, 0, 1, i, 0x80000000 | (i + 1) * 24)
    assert 'resource_depth_limit_reached' in analyze(data)['resources']['reasons']


def test_library_and_function_limits(monkeypatch):
    data, _dirs, _section = imports()
    monkeypatch.setitem(LIMITS, 'import_functions', 1)
    part = analyze(data)['imports']
    assert part['status'] == 'limited'
    assert part['function_count'] == 1
    monkeypatch.setitem(LIMITS, 'import_libraries', 0)
    assert 'import_library_limit_reached' in analyze(data)['imports']['reasons']


def test_resource_node_limit(monkeypatch):
    data, _dirs, _section = resources()
    monkeypatch.setitem(LIMITS, 'resource_nodes', 1)
    assert 'resource_node_limit_reached' in analyze(data)['resources']['reasons']


def test_certificate_file_offset_excluded_from_overlay():
    data, dirs, _section = fixture()
    directory(data, dirs, 4, 0x1800, 16)
    struct.pack_into('<IHH', data, 0x1800, 12, 0x200, 2)
    part = analyze(data)['overlay']
    assert part['status'] == 'completed'
    assert part['signature_verification'] == 'not_performed'
    assert part['certificate_ranges'] == [{'file_offset': 0x1800, 'bytes': 16}]
    assert part['entries'] == [{'file_offset': 0x1400, 'bytes': 0x400},
                               {'file_offset': 0x1810, 'bytes': 0x7f0}]
    assert part['overlay_bytes'] == 0xbf0


@pytest.mark.parametrize('position,length,record,reason', [
    (0x1000, 16, 12, 'certificate_image_overlap_or_gap'),
    (0x1801, 16, 12, 'certificate_range_invalid'),
    (0x1800, 16, 0, 'certificate_entry_invalid'),
    (0x1800, 16, 40, 'certificate_entry_invalid'),
    (0xfffffff8, 16, None, 'certificate_range_invalid')])
def test_uncertain_certificate_does_not_claim_overlay(position, length, record, reason):
    data, dirs, _section = fixture()
    directory(data, dirs, 4, position, length)
    if record is not None:
        struct.pack_into('<IHH', data, position, record, 0x200, 2)
    part = analyze(data)['overlay']
    assert reason in part['reasons']
    assert part['partial'] and part['certificate_ranges'] == []
    assert 'overlay_bytes' not in part


def test_truncated_and_io_failure():
    data, _dirs, _section = fixture()
    part = analyze_pe(io.BytesIO(data[:80]), len(data))['imports']
    assert 'truncated_read' in part['reasons']

    class Failed(io.BytesIO):
        def read(self, count=-1):
            raise OSError('not leaked')

    assert analyze_pe(Failed(), 200)['imports']['reasons'] == ['source_io_error']


@pytest.mark.parametrize('exception', [RuntimeError, OSError, ValueError])
def test_callback_exceptions_propagate(exception):
    data, _dirs, _section = imports()
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls == 9:
            raise exception('cancel')

    with pytest.raises(exception, match='cancel'):
        analyze_pe(io.BytesIO(data), len(data), check)


@pytest.mark.parametrize('budget', ['read_bytes', 'read_calls'])
def test_io_budgets(monkeypatch, budget):
    data, _dirs, _section = fixture()
    monkeypatch.setitem(LIMITS, budget, 1)
    part = analyze(data)['imports']
    assert part['status'] == 'limited'
    assert part['reasons'] == ['read_budget_reached']


def test_truncation_prefixes_never_raise():
    data, _dirs, _section = imports(64)
    for count in range(0, len(data), 17):
        analyze(data[:count])


def test_headers_are_valid_file_backed_rva_source():
    data, dirs, _section = fixture()
    directory(data, dirs, 1, 0x300, 40)
    struct.pack_into('<5I', data, 0x300, 0x350, 0, 0, 0x340, 0x350)
    data[0x340:0x346] = b'A.dll\0'
    struct.pack_into('<II', data, 0x350, 0x80000001, 0)
    part = analyze(data)['imports']
    assert part['status'] == 'completed'
    assert part['entries'][0]['functions'] == [{'kind': 'ordinal', 'ordinal': 1}]


def test_physical_alias_different_rva_is_rejected():
    data, _dirs, section = imports()
    struct.pack_into('<H', data, 0x86, 2)
    data[section + 40:section + 80] = data[section:section + 40]
    struct.pack_into('<I', data, section + 40 + 12, 0x3000)
    result = analyze(data)
    assert result['imports']['reasons'] == ['file_mapping_ambiguous']
    assert result['overlay']['reasons'] == ['image_file_ranges_invalid']


def test_unterminated_descriptor_retains_partial_entries():
    data, dirs, _section = imports()
    directory(data, dirs, 1, 0x1000, 20)
    part = analyze(data)['imports']
    assert part['reasons'] == ['import_descriptor_terminator_missing']
    assert part['partial'] and part['function_count'] == 2


@pytest.mark.parametrize('issue,reason', [('utf16', 'resource_name_invalid_utf16'),
                                        ('data', 'rva_not_file_backed')])
def test_resource_invalid_names_and_payload_range(issue, reason):
    data, _dirs, section = resources()
    if issue == 'utf16':
        data[0x482:0x48a] = b'\x00\xd8' * 4
    else:
        struct.pack_into('<I', data, section + 8, 0x2000)
        struct.pack_into('<I', data, 0x440, 0x2000)
    assert reason in analyze(data)['resources']['reasons']


def test_certificate_limit_stays_uncertain(monkeypatch):
    data, dirs, _section = fixture()
    directory(data, dirs, 4, 0x1800, 16)
    struct.pack_into('<IHHIHH', data, 0x1800, 8, 0x200, 2, 8, 0x200, 2)
    monkeypatch.setitem(LIMITS, 'certificates', 1)
    part = analyze(data)['overlay']
    assert part['reasons'] == ['certificate_limit_reached']
    assert part['certificate_ranges'] == [] and 'overlay_bytes' not in part


def test_large_imports_stop_within_read_budget(monkeypatch):
    data, dirs, _section = fixture()
    directory(data, dirs, 1, 0x1000, 40)
    struct.pack_into('<5I', data, 0x400, 0x1100, 0, 0, 0x1080, 0x1100)
    data[0x480:0x486] = b'A.dll\0'
    for i in range(100):
        struct.pack_into('<I', data, 0x500 + i * 4, 0x1300)
    data[0x702:0x704] = b'F\0'
    monkeypatch.setitem(LIMITS, 'read_bytes', 4096)

    class Counting(io.BytesIO):
        total = 0
        reads = 0

        def read(self, count=-1):
            assert count >= 0
            self.total += count
            self.reads += 1
            return super().read(count)

    source = Counting(data)
    result = analyze_pe(source, len(data))
    assert result['imports']['status'] == 'limited'
    assert source.total <= 4096
    assert source.reads <= LIMITS['read_calls']
