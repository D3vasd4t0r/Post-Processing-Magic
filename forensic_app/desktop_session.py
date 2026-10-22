"""Own exactly one guarded server tree. No commands against unrelated instances."""
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
from collections import deque
from threading import Lock, Thread
from urllib.request import Request, urlopen

from forensic_app.process_guard import ProcessGuard
from forensic_app.server_preferences import PreferenceStore
from forensic_app.storage import Storage


class DesktopSession:
    def __init__(self,args,*,executable=None):
        self.args = args
        self.executable = executable
        self.root = args.data_dir.expanduser().resolve()
        self.url = ('https' if args.lan or args.tls_cert else 'http')+'://127.0.0.1:'+str(args.port)
        self.process = self.guard = None
        self.token = self.control_id = ''
        self.ready = self.stopping = False
        self.verified = False
        self.started_at = 0
        self.problem = ''
        self.output = deque(maxlen=100)
        self.reader = None
        self.output_lock = Lock()
        self.preferences = PreferenceStore(Storage(self.root))
        self.preference_revision = self.preferences.get()[1]

    def configure(self,value):
        self.preferences.save(value)

    def start(self):
        if self.process and self.process.poll() is None:
            return
        if self.guard:
            self.guard.close()
        preferences,revision = self.preferences.get()
        if revision != self.preference_revision:
            self.args.port,self.args.lan = preferences.port,preferences.lan
            self.args.tls_cert = self.args.tls_key = None
            self.preference_revision = revision
        self.url = ('https' if self.args.lan or self.args.tls_cert else 'http')+'://127.0.0.1:'+str(self.args.port)
        self.control_id = secrets.token_urlsafe(24)
        self.ready = self.stopping = False
        self.verified = False
        self.token,self.problem = '',''
        command = [str(self.executable) if self.executable else sys.executable]
        if not self.executable and not getattr(sys,'frozen',False):
            command += ['-m','forensic_app']
        command += ['--headless','--no-browser','--data-dir',str(self.root),'--port',str(self.args.port),
                    '--control-id',self.control_id]
        if self.args.lan:
            command += ['--lan']
        else:
            command += ['--local']
        if self.args.tls_cert:
            command += ['--tls-cert',str(self.args.tls_cert),'--tls-key',str(self.args.tls_key)]
        if self.args.test_no_admin:
            command += ['--test-no-admin']
        self.guard = ProcessGuard()
        try:
            self.process = subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
            self.guard.assign(int(self.process._handle))
            self.guard.resume(self.process.pid)
        except Exception:
            self.guard.close()
            if self.process and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
            raise

        def read_output():
            with self.process.stdout as stream:
                for line in iter(stream.readline,b''):
                    with self.output_lock:
                        self.output.append(line.decode('utf-8',errors='replace').rstrip())
        self.reader = Thread(target=read_output,daemon=True)
        self.reader.start()
        self.started_at = time.monotonic()

    def context(self):
        if not self.url.startswith('https:'):
            return None
        certificate = self.args.tls_cert or self.root/'config/tls/server.crt'
        return ssl.create_default_context(cafile=str(certificate))

    def api(self,path,method='GET'):
        request = Request(self.url+path,data=b'' if method=='POST' else None,method=method,
                          headers={'Authorization':'Bearer '+self.token})
        with urlopen(request,timeout=2,context=self.context()) as response:
            return json.load(response)

    def poll(self):
        alive = self.process is not None and self.process.poll() is None
        state = {'alive':alive,'ready':False,'stopping':self.stopping,'worker':False,
                 'token':'','url':self.url,'problem':self.problem,'control':{},'queue':{},
                 'restart_required':self.preferences.get()[1] != self.preference_revision}
        if not alive:
            if self.guard:
                self.guard.close()
                self.guard = None
            self.token = ''
            self.ready = False
            if self.process and self.process.returncode and not self.problem:
                self.problem = 'Server beendet (Exitcode '+str(self.process.returncode)+'). '+self.startup_log()[-1000:]
                try:
                    failure = json.loads((self.root/'logs/desktop-startup-error.json').read_text(encoding='utf-8'))
                    if failure.get('control_id') == self.control_id:
                        self.problem = 'Serverstart fehlgeschlagen: '+failure['message']
                except (OSError,ValueError,KeyError):
                    pass
            state['problem'] = self.problem
            return state
        try:
            self.token = (self.root/'config/access-token.txt').read_text(encoding='utf-8').strip()
            system = self.api('/api/system')
            if system.get('control_id') != self.control_id:
                self.token = ''
                self.ready = False
                return state
            control,queue = self.api('/api/system/control'),self.api('/api/queue')
            self.ready,self.stopping = True,control['stopping']
            self.verified = True
            state.update(ready=True,token=self.token,worker=system['capabilities']['worker'],
                         administrator=system['administrator'],control=control,queue=queue,stopping=self.stopping,runtime=system.get('runtime',{}))
        except (OSError,ValueError,KeyError) as exc:
            self.ready = False
            if time.monotonic()-self.started_at > 30:
                state['problem'] = 'Server noch nicht erreichbar: '+str(exc)
        return state

    def stop(self):
        if not self.ready:
            raise RuntimeError('Server noch nicht bereit. Bitte warten oder Force Shutdown verwenden.')
        self.api('/api/system/stop','POST')
        self.stopping = True

    def force(self):
        if not self.process or self.process.poll() is not None:
            return
        # This job handle owns only the server launched by this window, including descendants.
        if self.guard:
            self.guard.close()
            self.guard = None
        self.process.wait(timeout=5)
        self.token = ''
        self.ready = self.stopping = False
        from forensic_app.jobs import JobStore
        from forensic_app.storage import InstanceLock, Storage
        storage = Storage(self.root)
        if self.verified and storage.database.exists():
            # Never create jobs or access evidence; only mark persisted incomplete work.
            import sqlite3
            from contextlib import closing
            deadline = time.monotonic()+2
            while True:
                try:
                    with InstanceLock(storage.root):
                        with closing(sqlite3.connect(storage.database)) as c:
                            exists = c.execute("SELECT 1 FROM sqlite_master WHERE name='jobs'").fetchone()
                        if exists:
                            JobStore(storage).recover(reason='Force Shutdown: Verarbeitung unterbrochen; keine automatische Wiederholung.')
                    break
                except RuntimeError:
                    # Job-object termination is asynchronous: the bootloader can exit
                    # before Windows releases its inner server's file lock.
                    if time.monotonic()<deadline:
                        time.sleep(.05)
                        continue
                    self.problem = 'Eigener Serverprozess beendet; Datenordner bereits wieder belegt. Keine fremden Aufträge verändert.'
                    return
        self.problem = 'Force Shutdown ausgeführt. Unterbrochene Aufträge werden nicht automatisch wiederholt.'

    def startup_log(self):
        with self.output_lock:
            return '\n'.join(list(self.output))

    def log_tail(self):
        path = self.root/'logs/server.log'
        try:
            with path.open('rb') as stream:
                stream.seek(max(0,os.fstat(stream.fileno()).st_size-65536))
                text = stream.read(65536).decode('utf-8',errors='replace')
            return text
        except OSError:
            return self.startup_log()
