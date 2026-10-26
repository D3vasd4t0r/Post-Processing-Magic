"""Frozen Windows EXE: ZIP-only source access and metadata-only reports.

Creates its own ZIPs, PowerShell workflow, data root and ephemeral port. Never
accepts an evidence argument or touches another running application instance.
"""

import argparse
import hashlib
import io
import json
import os
import socket
import sqlite3
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zipfile import ZIP_DEFLATED, ZipFile

from smoke_support import wait_ready

from forensic_app import __version__
from forensic_app.desktop_session import DesktopSession
from forensic_app.launcher import parser
from forensic_app.modes import ModeDraft, ModeStore
from forensic_app.storage import Storage

CLI_MARKER = 'SOURCE_SMOKE_CLI_ONLY_040'


def main():
    options = argparse.ArgumentParser(description=__doc__)
    options.add_argument('--exe', type=Path, required=True)
    executable = options.parse_args().exe.resolve(strict=True)
    folder = Path(__file__).resolve().parents[1]/'.local-data'/('sources-smoke-'+str(time.time_ns()))
    storage = Storage(folder/'state')
    storage.initialize()
    modes = ModeStore(storage)
    modes.initialize()
    mode = modes.list_modes()[0]['id']
    modes.save(mode, ModeDraft(name='Own sources smoke only', effort='Medium', steps=[{
        'type': 'powershell',
        'script': "New-Item -ItemType Directory PostMortem/OwnEmpty -Force | Out-Null\n"
                  "Set-Content PostMortem/result.txt 'Own synthetic output'\n"
                  f"Write-Output '{CLI_MARKER}'",
    }]), create=False)
    stream = io.BytesIO()
    with ZipFile(stream, 'w', compression=ZIP_DEFLATED) as archive:
        # Deliberately compressible synthetic input proves the forced setting is
        # effective, while all ordinary ZIP traversal/size limits still apply.
        archive.writestr('C/own-fixture.bin', b'0'*(2*1024**2))
    payload = stream.getvalue()
    original = folder/'own-local-original.zip'
    original.write_bytes(payload)
    original_hash = hashlib.sha256(payload).hexdigest()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    args = parser().parse_args(['--data-dir', str(storage.root), '--port', str(port), '--test-no-admin'])
    session = DesktopSession(args, executable=executable)

    def api(path, method='GET', body=None, *, raw=False, authenticated=True):
        headers = {'Authorization': 'Bearer '+session.token} if authenticated else {}
        data = None
        if body is not None:
            if isinstance(body, bytes):
                data, headers['Content-Type'] = body, 'application/zip'
            else:
                data, headers['Content-Type'] = json.dumps(body).encode(), 'application/json'
        request = Request(session.url+path, data=data, method=method, headers=headers)
        with urlopen(request, timeout=15) as response:
            content = response.read()
            return content if raw else json.loads(content)

    def expect_error(code, path, method='GET', body=None, **kwargs):
        try:
            api(path, method, body, **kwargs)
        except HTTPError as exc:
            assert exc.code == code, (path, exc.code, code)
        else:
            raise AssertionError(f'{path} unexpectedly succeeded; expected HTTP {code}.')

    def wait_job(ident):
        end = time.monotonic()+60
        while time.monotonic() < end:
            state = api('/api/jobs/'+ident)
            if state['status'] == 'succeeded':
                return state
            if state['status'] in ('failed', 'cancelled', 'interrupted'):
                raise AssertionError({'job': ident, 'status': state['status'], 'error': state['error']})
            time.sleep(.15)
        raise TimeoutError('Own synthetic ZIP workflow did not finish.')

    def frozen_plan(ident):
        with sqlite3.connect(storage.database, timeout=15) as connection:
            row = connection.execute('SELECT config_json FROM jobs WHERE id=?', (ident,)).fetchone()
        return json.loads(row[0])

    try:
        session.start()
        wait_ready(session)
        system = api('/api/system')
        assert system['version'] == __version__, system['version']
        assert api('/api/jobs/catalog')['test_no_admin'] is True
        first = api('/api/jobs?'+urlencode({'mode_id': mode, 'filename': 'own-upload.zip',
                    'allow_high_compression': 'false', 'case_number': 'Own-case-040', 'device_name': 'Own-device'}),
                    'POST', payload)['id']
        assert frozen_plan(first)['allow_high_compression'] is True
        first_state = wait_job(first)
        assert CLI_MARKER in first_state['log_tail']
        assert first_state['work_directory'] == str(storage.root/'work'/first)
        source_path = '/api/jobs/'+first+'/source'
        expect_error(401, source_path, authenticated=False)
        expect_error(401, source_path+'/download-ticket', 'POST', authenticated=False)
        metadata = api(source_path)
        assert metadata == {'kind': 'upload', 'filename': 'own-upload.zip', 'available': True,
                            'size': len(payload), 'reason': None}, metadata
        ticket_url = api(source_path+'/download-ticket', 'POST')['url']
        checksum, size = hashlib.sha256(), 0
        # Capability URL is minted by bearer auth above, one-use and short-lived.
        # Read in bounded chunks to exercise streaming without a browser Blob.
        with urlopen(session.url+ticket_url, timeout=15) as response:
            assert int(response.headers['Content-Length']) == len(payload)
            assert 'attachment' in response.headers['Content-Disposition']
            while chunk := response.read(64*1024):
                checksum.update(chunk)
                size += len(chunk)
        assert size == len(payload) and checksum.hexdigest() == original_hash
        expect_error(410, ticket_url, authenticated=False)

        second = api('/api/jobs/local', 'POST', {'mode_id': mode, 'path': str(original),
                     'allow_high_compression': False, 'case_number': 'Own-case-040', 'device_name': 'Second-device'})['id']
        assert frozen_plan(second)['allow_high_compression'] is True
        second_state = wait_job(second)
        assert not (storage.root/'evidence'/second).exists()
        local = api('/api/jobs/'+second+'/source')
        assert local['kind'] == 'local' and local['available'] and local['path'] == str(original)
        expect_error(409, '/api/jobs/'+second+'/source/download-ticket', 'POST')
        assert original.read_bytes() == payload

        for ident, state in ((first, first_state), (second, second_state)):
            endpoint = '/api/jobs/'+ident
            report = api(endpoint+'/report?format=json')
            html = api(endpoint+'/report', raw=True)
            assert report['input']['sha256'] == original_hash
            assert report['input']['sha1'] == hashlib.sha1(payload).hexdigest()
            assert report['configuration']['case_number'] == 'Own-case-040'
            assert report['input_inventory']['files'] == 1
            assert report['input_inventory']['files_metadata'][0]['path'] == 'C/own-fixture.bin'
            assert '<!doctype html>' in html.decode('utf-8')
            assert CLI_MARKER not in json.dumps(report) and CLI_MARKER.encode() not in html
            assert 'commands' not in report['configuration']
            assert all('command' not in item for item in report['command_runs'])
            assert all(key not in report for key in ('findings', 'finding_summaries', 'pe_details', 'indicators', 'terminal'))
            assert state['result_available'] and state['report_available']
            result = api(endpoint+'/download', raw=True)
            assert report['archive']['sha256'] == hashlib.sha256(result).hexdigest()
            with ZipFile(io.BytesIO(result)) as archive:
                assert 'KAPE-Kommandozeile.log' not in archive.namelist()
                assert 'command.log' not in archive.namelist()
                embedded = json.loads(archive.read('Aufbereitungsprotokoll.json'))
                assert CLI_MARKER not in json.dumps(embedded)

        removed = ['/api/settings/malware', '/api/settings/viewers', '/malware.js',
                   '/evidence-details.js', '/presentation.js']
        removed += ['/api/jobs/'+first+'/'+suffix for suffix in ('summary', 'indicators', 'csv', 'preview', 'viewer')]
        for path in removed:
            expect_error(404, path, raw=True)
        original.unlink()  # Own fixture only: an absent reference must be honest.
        missing = api('/api/jobs/'+second+'/source')
        assert missing['kind'] == 'local' and not missing['available'] and missing['reason']
        assert missing['path'] == str(original)
        report = {'passed': True, 'version': system['version'], 'first': first, 'second': second,
                  'checks': ['forced high compression for upload and local API false', 'source metadata auth',
                             'single-use bounded upload-original stream and SHA256 identity',
                             'local source reference only, no copy or download', 'missing local source metadata',
                             'metadata-only JSON/HTML/archive reports without CLI', 'removed routes and JS return 404']}
        (folder/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps({'passed': True, 'report': str(folder/'report.json'), 'checks': len(report['checks'])}))
        session.stop()
        end = time.monotonic()+15
        while session.poll()['alive'] and time.monotonic() < end:
            time.sleep(.15)
        assert not session.poll()['alive'], 'Own server did not stop gracefully.'
    finally:
        if session.guard:
            session.force()


if __name__ == '__main__':
    if os.name != 'nt':
        raise SystemExit('Windows only')
    main()
