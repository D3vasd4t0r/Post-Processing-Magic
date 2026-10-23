import socket
import time

import pytest

from forensic_app.desktop_session import DesktopSession
from forensic_app.launcher import parser
from forensic_app.storage import InstanceLock


def test_occupied_port_failure_is_visible_and_does_not_take_over_other_server(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        sock.listen()
        args = parser().parse_args(['--test-no-admin','--data-dir',str(tmp_path/'own'),'--port',str(sock.getsockname()[1])])
        session = DesktopSession(args)
        try:
            session.start()
            deadline = time.monotonic()+20
            while session.process.poll() is None and time.monotonic() < deadline:
                time.sleep(.1)
            state = session.poll()
            assert not state['alive'] and not state['ready']
            assert 'Serverstart fehlgeschlagen' in state['problem']
            assert sock.fileno() >= 0  # Own competing listener remains untouched.
        finally:
            if session.guard:
                session.force()


def test_unrelated_instance_is_never_accepted_or_stopped(tmp_path,monkeypatch):
    args = parser().parse_args(['--test-no-admin','--data-dir',str(tmp_path)])
    session = DesktopSession(args)
    token_path = tmp_path/'config/access-token.txt'
    token_path.parent.mkdir()
    token_path.write_text('token-of-other-instance',encoding='utf-8')
    class Process:
        def poll(self):
            return None
    session.process = Process()
    session.control_id = 'own-launch'
    calls = []
    def foreign_api(path,method='GET'):
        calls.append(path)
        return {'control_id':'other-launch'}
    monkeypatch.setattr(session,'api',foreign_api)
    assert not session.poll()['ready']
    assert session.token == ''
    with pytest.raises(RuntimeError,match='nicht bereit'):
        session.stop()
    assert calls == ['/api/system']


def test_force_never_recovers_jobs_owned_by_another_server(tmp_path):
    from forensic_app.storage import Storage
    storage = Storage(tmp_path)
    storage.initialize()
    args = parser().parse_args(['--test-no-admin','--data-dir',str(tmp_path)])
    session = DesktopSession(args)
    class Process:
        def poll(self):
            return None
        def wait(self,timeout):
            return 0
    session.process = Process()
    session.verified = True  # Own former server was ready, another now owns the directory.
    with InstanceLock(tmp_path):
        session.force()
    assert 'Keine fremden Aufträge verändert' in session.problem


def test_force_waits_for_own_async_lock_release(tmp_path,monkeypatch):
    from forensic_app.jobs import JobStore
    from forensic_app.storage import Storage
    storage = Storage(tmp_path)
    storage.initialize()
    JobStore(storage).initialize()
    args = parser().parse_args(['--test-no-admin','--data-dir',str(tmp_path)])
    session = DesktopSession(args)
    class Process:
        def poll(self): return None
        def wait(self,timeout): return 0
    session.process,session.verified = Process(),True
    attempts = []
    class DelayedLock(InstanceLock):
        def __enter__(self):
            attempts.append(True)
            if len(attempts)<3:
                raise RuntimeError('Own previous process still releasing handle')
            return super().__enter__()
    monkeypatch.setattr('forensic_app.storage.InstanceLock',DelayedLock)
    recovered = []
    monkeypatch.setattr(JobStore,'recover',lambda self,reason:recovered.append(reason))
    session.force()
    assert len(attempts) == 3 and len(recovered) == 1
    assert 'Force Shutdown' in recovered[0]


@pytest.mark.parametrize('identity',['-leading-dash','--leading-two-dashes'])
def test_control_identifier_starting_with_dash_reaches_server(tmp_path,monkeypatch,identity):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    args = parser().parse_args(['--test-no-admin','--data-dir',str(tmp_path),'--port',str(port)])
    session = DesktopSession(args)
    monkeypatch.setattr('forensic_app.desktop_session.secrets.token_urlsafe',lambda size:identity)
    try:
        session.start()
        deadline = time.monotonic()+20
        while time.monotonic()<deadline:
            state = session.poll()
            if state['ready'] or not state['alive']:
                break
            time.sleep(.1)
        assert state['ready'], state['problem']
        assert session.api('/api/system')['control_id']==identity
        session.stop()
        session.process.wait(timeout=10)
    finally:
        if session.guard:
            session.force()
            session.guard.close() if session.guard else None
