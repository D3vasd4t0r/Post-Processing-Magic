"""Own exactly one guarded server tree. No commands against unrelated instances."""
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
import traceback
from collections import deque
from threading import Lock, Thread
from urllib.request import Request, urlopen

from forensic_app.app_errors import AppValueError, ErrorText
from forensic_app.desktop_i18n import DesktopError, DesktopTranslations
from forensic_app.process_guard import ProcessGuard
from forensic_app.server_preferences import PreferenceStore
from forensic_app.storage import Storage


class DesktopSession:
    """Own one server process tree and verify its control identity before exposing readiness.

    Control methods run on the panel's background thread. A separate daemon reader
    captures child stdout into a locked, bounded deque; this class never calls Tk."""
    def __init__(self,args,*,executable=None):
        """Prepare process, credential and preference state without launching a server."""
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
        self.problem_i18n = None
        self.output = deque(maxlen=100)
        self.reader = None
        self.output_lock = Lock()
        self.preferences = PreferenceStore(Storage(self.root))
        self.preference_revision = self.preferences.get()[1]

    def set_problem(self,key,**parameters):
        """Store a canonical desktop message plus parameters for later UI localization."""
        self.problem = DesktopTranslations().t(key,**parameters)
        self.problem_i18n = {'key':key,'parameters':parameters,'original':self.problem,'catalog':'desktop'}

    def set_exception(self,exc):
        """Retain raw failure text and, when available, its structured translation metadata."""
        self.problem,self.problem_i18n = str(exc),None
        if isinstance(exc,DesktopError):
            self.set_problem(exc.key,**exc.parameters)
        else:
            detail = exc.text if isinstance(exc,AppValueError) else getattr(exc,'detail',None)
            if isinstance(detail,ErrorText):
                self.problem_i18n = {'key':detail.code,'parameters':detail.params,
                                     'original':self.problem,'catalog':'shared'}

    def problem_description(self):
        # A raw exception assigned by the owner must never inherit an older message.
        """Return translation metadata only while it still matches the current problem text."""
        if self.problem_i18n and self.problem_i18n['original'] == self.problem:
            return {key:value for key,value in self.problem_i18n.items() if key != 'original'}
        return None

    def configure(self,value):
        """Persist server preferences; changed port/access values take effect on a later start."""
        self.preferences.save(value)

    def start(self):
        """Launch a headless child suspended, assign its process guard, then resume it.

        A live child makes this a no-op. Each new launch clears readiness/token state and
        uses a fresh control ID; a failed guarded launch closes the guard and kills any
        remaining child before propagating the exception."""
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
                    '--control-id='+self.control_id]
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
            """Decode child output into the bounded deque under its lock until stdout closes."""
            with self.process.stdout as stream:
                for line in iter(stream.readline,b''):
                    with self.output_lock:
                        self.output.append(line.decode('utf-8',errors='replace').rstrip())
        self.reader = Thread(target=read_output,daemon=True)
        self.reader.start()
        self.started_at = time.monotonic()

    def context(self):
        """Build loopback HTTPS trust from the configured or generated server certificate."""
        if not self.url.startswith('https:'):
            return None
        certificate = self.args.tls_cert or self.root/'config/tls/server.crt'
        return ssl.create_default_context(cafile=str(certificate))

    def api(self,path,method='GET'):
        """Issue a bounded loopback JSON request using the current token and certificate context."""
        request = Request(self.url+path,data=b'' if method=='POST' else None,method=method,
                          headers={'Authorization':'Bearer '+self.token})
        with urlopen(request,timeout=2,context=self.context()) as response:
            return json.load(response)

    def poll(self):
        """Return process and authenticated service state without adopting another instance.

        The token file is read while the child is alive. Readiness is reported only when
        the system endpoint returns this launch's control ID; connection failures remain
        unready and become visible startup problems after the grace period."""
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
                self.set_problem('problem.exited',code=self.process.returncode,detail=self.startup_log()[-1000:])
                try:
                    failure = json.loads((self.root/'logs/desktop-startup-error.json').read_text(encoding='utf-8'))
                    if failure.get('control_id') == self.control_id:
                        self.set_problem('problem.startup',detail=failure['message'])
                        if isinstance(failure.get('error_code'),str) and isinstance(failure.get('error_params'),dict):
                            # Only known structured app errors are translated;
                            # older files and raw OS failure details stay intact.
                            try:
                                detail = ErrorText(failure['error_code'],**failure['error_params'])
                            except (KeyError,TypeError,ValueError):
                                pass  # Unknown/malformed metadata keeps canonical detail.
                            else:
                                self.problem_i18n['detail_i18n'] = {'key':detail.code,'parameters':detail.params}
                except (OSError,ValueError,KeyError):
                    pass
            state['problem'] = self.problem
            state['problem_i18n'] = self.problem_description()
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
            # Stack frames identify the failing operation without serializing credentials.
            diagnostic = ''.join(traceback.format_tb(exc.__traceback__)) + type(exc).__name__ + ': ' + str(exc)
            try:
                (self.root/'logs/desktop-connection-error.txt').write_text(diagnostic,encoding='utf-8')
            except OSError:
                pass
            if time.monotonic()-self.started_at > 30:
                state['problem'] = DesktopTranslations().t('problem.unreachable',detail=str(exc))
                state['problem_i18n'] = {'key':'problem.unreachable','parameters':{'detail':str(exc)}}
        if 'problem_i18n' not in state:
            state['problem_i18n'] = self.problem_description()
        return state

    def stop(self):
        """Request authenticated draining shutdown; reject calls before this session is ready."""
        if not self.ready:
            raise DesktopError('problem.not_ready')
        self.api('/api/system/stop','POST')
        self.stopping = True

    def force(self):
        """Terminate the guarded tree and mark incomplete jobs only after prior identity verification.

        Recovery waits briefly for the instance lock released by the terminating server.
        It does not read evidence or restart interrupted work, and never targets an
        unrelated process by port or executable name."""
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
                    self.set_problem('problem.folder_busy')
                    return
        self.set_problem('problem.forced')

    def startup_log(self):
        """Join the bounded captured child-output lines while holding the reader lock."""
        with self.output_lock:
            return '\n'.join(list(self.output))

    def log_tail(self):
        """Read at most 64 KiB of the technical server log, falling back to captured stdout."""
        path = self.root/'logs/server.log'
        try:
            with path.open('rb') as stream:
                stream.seek(max(0,os.fstat(stream.fileno()).st_size-65536))
                text = stream.read(65536).decode('utf-8',errors='replace')
            return text
        except OSError:
            return self.startup_log()
