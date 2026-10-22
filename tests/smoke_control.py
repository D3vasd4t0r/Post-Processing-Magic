"""Exercise the real guarded EXE tree using only self-created ZIP/PowerShell fixtures."""
import argparse
import ctypes
import hashlib
import io
import json
import socket
import time
from pathlib import Path
from urllib.request import Request, urlopen
from zipfile import ZipFile

from smoke_support import wait_ready

from forensic_app import __version__
from forensic_app.desktop_session import DesktopSession
from forensic_app.launcher import parser
from forensic_app.modes import ModeDraft, ModeStore
from forensic_app.storage import Storage


def wait(check,timeout=40):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        time.sleep(.15)
    raise TimeoutError('Own control smoke timed out')


def alive(pid):
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000,False,pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        return bool(kernel.GetExitCodeProcess(handle,ctypes.byref(code))) and code.value == 259
    finally:
        kernel.CloseHandle(handle)


def main():
    options = argparse.ArgumentParser()
    options.add_argument('--exe',type=Path,required=True)
    exe = options.parse_args().exe.resolve()
    folder = Path(__file__).resolve().parents[1]/'.local-data'/('control-smoke-'+str(time.time_ns()))
    storage = Storage(folder/'state')
    storage.initialize()
    modes = ModeStore(storage)
    modes.initialize()
    mode = modes.list_modes()[0]['id']
    script = "New-Item -ItemType Directory PostMortem -Force | Out-Null; Set-Content PostMortem/started.txt 'synthetic'; Start-Sleep -Seconds 4; Set-Content PostMortem/result.txt 'synthetic finished'"
    modes.save(mode,ModeDraft(name='Synthetic control only',effort='Medium',steps=[{'type':'powershell','script':script}]),create=False)
    stream = io.BytesIO()
    with ZipFile(stream,'w') as z:
        z.writestr('C/own.txt','Own synthetic evidence only')
    original = folder/'own-original.zip'
    original.write_bytes(stream.getvalue())
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    args = parser().parse_args(['--data-dir',str(storage.root),'--port',str(port),'--test-no-admin'])
    session = DesktopSession(args,executable=exe)

    def api(path,method='GET',body=None):
        request = Request(session.url+path,method=method,data=json.dumps(body).encode() if body else None,
                          headers={'Authorization':'Bearer '+session.token,'Content-Type':'application/json'})
        with urlopen(request,timeout=4) as response:
            return json.load(response)

    def submit():
        return api('/api/jobs/local','POST',{'mode_id':mode,'path':str(original)})['id']

    try:
        session.start()
        wait_ready(session)
        first_token = session.token
        first = submit()
        started = storage.root/'work'/first/'PostMortem/started.txt'
        wait(started.exists)
        second = submit()
        session.stop()
        assert session.poll()['stopping']
        wait(lambda: not session.poll()['alive'])
        from forensic_app.jobs import JobStore
        store = JobStore(storage)
        assert store.get(first)['status'] == 'succeeded' and store.get(first)['result_available']
        assert store.get(second)['status'] == 'queued'
        session.start()
        wait_ready(session)
        assert session.token != first_token
        assert store.get(second)['status'] == 'interrupted'
        script = "New-Item -ItemType Directory PostMortem -Force | Out-Null; $p=Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 120' -PassThru -WindowStyle Hidden; Set-Content PostMortem/child.txt $p.Id; Start-Sleep -Seconds 120"
        modes.save(mode,ModeDraft(name='Synthetic force only',effort='Medium',steps=[{'type':'powershell','script':script}]),create=False)
        forced = submit()
        child_file = storage.root/'work'/forced/'PostMortem/child.txt'
        wait(child_file.exists)
        pid = int(child_file.read_text(encoding='utf-8-sig').strip())
        assert alive(pid)
        session.force()
        wait(lambda:not alive(pid))
        assert not session.poll()['alive']
        assert store.get(forced)['status'] == 'interrupted'
        assert 'Force Shutdown' in store.get(forced)['error']
        assert hashlib.sha256(original.read_bytes()).hexdigest() == digest
        assert store.get(first)['result_available']
        session.start()
        wait_ready(session)
        assert store.get(forced)['status'] == 'interrupted'
        session.stop()
        wait(lambda:not session.poll()['alive'])
        report = {'passed':True,'version':__version__,'checks':['guarded EXE starts and reports worker',
            'graceful drain finishes running result ZIP','waiting job not executed while stopping',
            'restart rotates token and marks pending job interrupted','force kills real PowerShell descendant',
            'force marks interrupted immediately','original and finished result retained','restart never retries interrupted work']}
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(report['checks'])}))
    finally:
        if session.guard:
            session.force()


if __name__ == '__main__':
    main()
