"""Bounded, read-only PE metadata. No loader, extraction or signature verification.

The caller owns the already locked binary handle. Only internal parse/IO errors are
converted to reason codes; exceptions from the cancellation callback propagate.
"""

import struct

LIMITS = {'read_bytes': 4 * 1024**2, 'read_calls': 40000, 'sections': 96,
          'import_libraries': 256, 'import_functions': 8192, 'string_bytes': 1024,
          'resource_nodes': 2048, 'resource_depth': 5, 'resource_name_units': 256,
          'certificates': 256}


class _Invalid(Exception):
    def __init__(self, reason, limited=False):
        self.reason = reason
        self.limited = limited


def _part(scope):
    return {'schema_version': 1, 'scope': scope, 'status': 'completed',
            'partial': False, 'reasons': [], 'limits': dict(LIMITS), 'entries': []}


def _fail(part, error):
    part.update(status='limited' if error.limited else 'error', partial=True)
    if error.reason not in part['reasons']:
        part['reasons'].append(error.reason)


class _PE:
    def __init__(self, source, size, check):
        self.source, self.size, self.check = source, size, check
        self.bytes = self.calls = 0

    def read(self, offset, count):
        self.check()
        if offset < 0 or count < 0 or offset + count > self.size:
            raise _Invalid('file_range_invalid')
        if self.bytes + count > LIMITS['read_bytes'] or self.calls >= LIMITS['read_calls']:
            raise _Invalid('read_budget_reached', True)
        self.bytes += count
        self.calls += 1
        try:
            self.source.seek(offset)
            value = self.source.read(count)
        except (OSError, ValueError):
            raise _Invalid('source_io_error') from None
        if len(value) != count:
            raise _Invalid('truncated_read')
        return value

    def headers(self):
        head = self.read(0, 64)
        if head[:2] != b'MZ':
            raise _Invalid('dos_signature_invalid')
        offset = struct.unpack_from('<I', head, 60)[0]
        if offset < 64:
            raise _Invalid('pe_header_offset_invalid')
        coff = self.read(offset, 24)
        if coff[:4] != b'PE\0\0':
            raise _Invalid('pe_signature_invalid')
        count = struct.unpack_from('<H', coff, 6)[0]
        optional = struct.unpack_from('<H', coff, 20)[0]
        if not 0 < count <= LIMITS['sections']:
            raise _Invalid('section_count_invalid')
        if optional < 2:
            raise _Invalid('optional_header_unsupported')
        if optional > 4096:
            raise _Invalid('optional_header_size_invalid')
        data = self.read(offset + 24, optional)
        magic = struct.unpack_from('<H', data)[0]
        if magic not in (0x10b, 0x20b):
            raise _Invalid('optional_header_unsupported')
        self.kind = 'PE32' if magic == 0x10b else 'PE32+'
        self.width = 4 if magic == 0x10b else 8
        directory = 96 if magic == 0x10b else 112
        if len(data) < directory:
            raise _Invalid('optional_header_truncated')
        self.header_size = struct.unpack_from('<I', data, 60)[0]
        table_end = offset + 24 + optional + count * 40
        if self.header_size < table_end or self.header_size > self.size:
            raise _Invalid('header_size_invalid')
        directories = struct.unpack_from('<I', data, directory - 4)[0]
        if directories > (len(data) - directory) // 8:
            raise _Invalid('directory_table_truncated')
        self.directories = [struct.unpack_from('<II', data, directory + i * 8)
                            for i in range(min(directories, 16))]
        self.sections = []
        raw = self.read(offset + 24 + optional, count * 40)
        for i in range(count):
            self.check()
            virtual, rva, length, pointer = struct.unpack_from('<IIII', raw, i * 40 + 8)
            if rva + max(virtual, length) > 2**32:
                raise _Invalid('section_rva_overflow')
            self.sections.append((rva, max(virtual, length), pointer, length))

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def mapping(self, rva, count):
        if rva < 0 or count < 0 or rva + max(count, 1) > 2**32:
            raise _Invalid('rva_overflow')
        end = rva + max(count, 1)
        candidates = []
        if rva < self.header_size and end > 0:
            candidates.append((0, self.header_size, 0, self.header_size))
        candidates.extend(s for s in self.sections if rva < s[0] + s[1] and end > s[0])
        if len(candidates) != 1:
            raise _Invalid('rva_ambiguous' if candidates else 'rva_unmapped')
        base, _virtual, pointer, raw = candidates[0]
        delta = rva - base
        if delta < 0 or delta + max(count, 1) > raw or pointer + raw > self.size:
            raise _Invalid('rva_not_file_backed')
        # A second physical section alias also makes this byte source uncertain.
        position = pointer + delta
        physical = [(0, self.header_size)] + [(s[2], s[2] + s[3]) for s in self.sections if s[3]]
        if sum(position < b and position + max(count, 1) > a for a, b in physical) != 1:
            raise _Invalid('file_mapping_ambiguous')
        return position, raw - delta

    def rread(self, rva, count):
        offset, _remaining = self.mapping(rva, count)
        return self.read(offset, count)

    def string(self, rva):
        offset, remaining = self.mapping(rva, 1)
        count = min(remaining, LIMITS['string_bytes'])
        # Validate the entire bounded read against competing RVA ranges.
        self.mapping(rva, count)
        data = self.read(offset, count)
        terminator = data.find(b'\0')
        if terminator < 0:
            raise _Invalid('string_limit_reached' if count == LIMITS['string_bytes']
                           else 'string_unterminated', count == LIMITS['string_bytes'])
        try:
            return data[:terminator].decode('ascii')
        except UnicodeDecodeError:
            raise _Invalid('import_name_not_ascii') from None


def _imports(pe, result):
    result['scope'] = 'Declared normal imports only; no delay-load or dependency resolution.'
    rva, size = pe.directory(1)
    result.update(directory_rva=rva, directory_bytes=size, function_count=0)
    if not rva and not size:
        return
    if not rva or size < 20:
        raise _Invalid('import_directory_invalid')
    pe.mapping(rva, size)
    for index in range(min(size // 20, LIMITS['import_libraries'] + 1)):
        pe.check()
        descriptor = struct.unpack('<5I', pe.rread(rva + index * 20, 20))
        if not any(descriptor):
            return
        if index >= LIMITS['import_libraries']:
            raise _Invalid('import_library_limit_reached', True)
        original, timestamp, _forwarder, name, first = descriptor
        entry = {'dll': pe.string(name), 'descriptor_rva': rva + index * 20,
                 'thunk_source': 'original' if original else 'first_thunk_fallback',
                 'timestamp_untrusted': timestamp, 'functions': []}
        result['entries'].append(entry)
        thunk = original or first
        if not thunk:
            raise _Invalid('import_thunk_missing')
        j = 0
        while True:
            value = int.from_bytes(pe.rread(thunk + j * pe.width, pe.width), 'little')
            if not value:
                break
            if result['function_count'] >= LIMITS['import_functions']:
                raise _Invalid('import_function_limit_reached', True)
            ordinal_flag = 1 << (pe.width * 8 - 1)
            if value & ordinal_flag:
                if value & ~(ordinal_flag | 0xffff):
                    raise _Invalid('import_ordinal_reserved_bits')
                function = {'kind': 'ordinal', 'ordinal': value & 0xffff}
            else:
                if value > 0x7fffffff:
                    raise _Invalid('import_name_rva_invalid')
                try:
                    hint = int.from_bytes(pe.rread(value, 2), 'little')
                    function = {'kind': 'name', 'hint': hint, 'name': pe.string(value + 2)}
                except _Invalid:
                    if not original:
                        entry['unresolved_first_thunk'] = True
                        result['reasons'].append('bound_or_invalid_first_thunk')
                    raise
            entry['functions'].append(function)
            result['function_count'] += 1
            j += 1
    raise _Invalid('import_descriptor_terminator_missing')


def _resources(pe, result):
    root, size = pe.directory(2)
    result.update(directory_rva=root, directory_bytes=size, node_count=0)
    if not root and not size:
        return
    if not root or size < 16:
        raise _Invalid('resource_directory_invalid')
    pe.mapping(root, size)

    def read(relative, count):
        if relative < 0 or relative + count > size:
            raise _Invalid('resource_root_range_invalid')
        return pe.rread(root + relative, count)

    visited = set()

    def visit(relative, path, depth):
        pe.check()
        if depth > LIMITS['resource_depth']:
            raise _Invalid('resource_depth_limit_reached', True)
        if relative in visited:
            raise _Invalid('resource_directory_repeated')
        visited.add(relative)
        result['node_count'] += 1
        if result['node_count'] > LIMITS['resource_nodes']:
            raise _Invalid('resource_node_limit_reached', True)
        header = read(relative, 16)
        named, ids = struct.unpack_from('<HH', header, 12)
        for i in range(named + ids):
            pe.check()
            if result['node_count'] >= LIMITS['resource_nodes']:
                raise _Invalid('resource_node_limit_reached', True)
            result['node_count'] += 1
            name, target = struct.unpack('<II', read(relative + 16 + i * 8, 8))
            if name & 0x80000000:
                position = name & 0x7fffffff
                if position % 2:
                    raise _Invalid('resource_name_alignment_invalid')
                length = int.from_bytes(read(position, 2), 'little')
                if length > LIMITS['resource_name_units']:
                    raise _Invalid('resource_name_limit_reached', True)
                try:
                    label = {'name': read(position + 2, length * 2).decode('utf-16le')}
                except UnicodeDecodeError:
                    raise _Invalid('resource_name_invalid_utf16') from None
            else:
                label = {'id': name}
            current = path + [label]
            if target & 0x80000000:
                visit(target & 0x7fffffff, current, depth + 1)
            else:
                rva, length, codepage, reserved = struct.unpack('<4I', read(target, 16))
                item = {'path': current, 'data_rva': rva, 'bytes': length,
                        'codepage': codepage, 'reserved': reserved, 'file_offset': None}
                result['entries'].append(item)
                if length:
                    item['file_offset'] = pe.mapping(rva, length)[0]
                item['data_range_valid'] = True
    visit(0, [], 0)


def _overlay(pe, result):
    ranges = [(0, pe.header_size)]
    ranges.extend((s[2], s[2] + s[3]) for s in pe.sections if s[3])
    ranges.sort()
    for i, (start, end) in enumerate(ranges):
        pe.check()
        if end > pe.size or (i and start < ranges[i - 1][1]):
            raise _Invalid('image_file_ranges_invalid')
    image_end = max(end for _start, end in ranges)
    result.update(image_end_offset=image_end, trailing_bytes=pe.size - image_end,
                  certificate_ranges=[], certificate_entries=[], signature_verification='not_performed')
    cert, size = pe.directory(4)
    result.update(security_directory_file_offset=cert, security_directory_bytes=size)
    if cert or size:
        if not cert or size < 8 or cert % 8 or size % 8 or cert + size > pe.size:
            raise _Invalid('certificate_range_invalid')
        if cert < image_end:
            raise _Invalid('certificate_image_overlap_or_gap')
        position = cert
        certificates = []
        while position < cert + size:
            if len(certificates) >= LIMITS['certificates']:
                raise _Invalid('certificate_limit_reached', True)
            length, revision, kind = struct.unpack('<IHH', pe.read(position, 8))
            rounded = (length + 7) & ~7
            if length < 8 or position + rounded > cert + size:
                raise _Invalid('certificate_entry_invalid')
            certificates.append({'file_offset': position, 'bytes': length,
                                 'padded_bytes': rounded, 'revision': revision, 'type': kind})
            position += rounded
        result['certificate_entries'] = certificates
        result['certificate_ranges'] = [{'file_offset': cert, 'bytes': size}]
        if image_end < cert:
            result['entries'].append({'file_offset': image_end, 'bytes': cert - image_end})
        if cert + size < pe.size:
            result['entries'].append({'file_offset': cert + size, 'bytes': pe.size - cert - size})
    elif image_end < pe.size:
        result['entries'].append({'file_offset': image_end, 'bytes': pe.size - image_end})
    result['overlay_bytes'] = sum(entry['bytes'] for entry in result['entries'])


def analyze_pe(source, size, check=lambda: None):
    """Return JSON metadata within fixed read/traversal budgets; never execute input."""
    result = {'pe_kind': None, 'imports': _part('Declared normal imports'),
              'resources': _part('Resource tree metadata only; payloads not read or extracted.'),
              'overlay': _part('Trailing file ranges outside headers/sections, excluding a structurally bounded certificate table; no signature validity or trust assessment.')}
    pe = _PE(source, size, check)
    try:
        pe.headers()
    except _Invalid as error:
        for name in ('imports', 'resources', 'overlay'):
            _fail(result[name], error)
            if error.reason == 'optional_header_unsupported':
                result[name]['status'] = 'unsupported'
        return result
    result['pe_kind'] = pe.kind
    for name, parser in [('imports', _imports), ('resources', _resources), ('overlay', _overlay)]:
        try:
            parser(pe, result[name])
        except _Invalid as error:
            _fail(result[name], error)
        result[name]['io_read_bytes_total'] = pe.bytes
        result[name]['io_read_calls_total'] = pe.calls
    return result
