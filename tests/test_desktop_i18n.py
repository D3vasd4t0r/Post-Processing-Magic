"""Offline desktop localization contracts; all state is synthetic."""
import ast
import queue
from pathlib import Path
from string import Formatter
from types import SimpleNamespace

import pytest

from forensic_app.desktop import ServerWindow, draw_server_banner
from forensic_app.desktop_i18n import DesktopError, DesktopTranslations, catalog
from forensic_app.desktop_session import DesktopSession
from forensic_app.interface_preferences import InterfacePreferences
from forensic_app.storage import Storage


class Widget:
    def __init__(self,**values):
        self.values = values
        self.exists = True

    def configure(self,**values):
        self.values.update(values)

    def winfo_exists(self):
        return self.exists

    def set(self,value):
        self.values['value'] = value

    def get(self):
        return self.values.get('value')


def test_catalog_parity_named_parameters_and_source_keys():
    de,en = catalog('de'),catalog('en')
    assert de.keys() == en.keys()
    assert len(de) >= 70
    for key in de:
        fields = lambda text: {name for _,name,_,_ in Formatter().parse(text) if name}
        assert fields(de[key]) == fields(en[key]),key
        assert all(name.isidentifier() for name in fields(de[key]))
        assert de[key] and en[key]
    for name in ('desktop.py','desktop_session.py','windows_tray.py'):
        source = Path(__file__).parents[1]/'forensic_app'/name
        for node in ast.walk(ast.parse(source.read_text(encoding='utf-8'))):
            if (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
                    and node.func.attr in ('t','set_problem','translate') and node.args
                    and isinstance(node.args[0],ast.Constant) and isinstance(node.args[0].value,str)):
                assert node.args[0].value in de


def test_fallback_and_raw_named_values_are_not_reinterpreted():
    assert DesktopTranslations('unknown').t('action.start') == 'Server starten'
    assert DesktopTranslations('en').t('unknown.key') == 'unknown.key'
    raw = r'C:\Server startet…\{detail}\--token-secret Ä'
    assert DesktopTranslations('en').t('problem.startup',detail=raw) == 'Server startup failed: '+raw
    assert DesktopError('problem.not_ready').translated(DesktopTranslations('en').t).startswith('Server not ready')


def synthetic_window(tmp_path,monkeypatch):
    window = ServerWindow.__new__(ServerWindow)
    window.interface = InterfacePreferences(Storage(tmp_path))
    window.translations = DesktopTranslations()
    window.t = window.translations.t
    window.language = Widget(value='DE')
    window.bindings = []
    window.locale_checked = 0
    window.hero = Widget()
    window.tray = SimpleNamespace(refresh_language=lambda:None)
    window.latest = {'alive':True,'ready':True,'stopping':False,'worker':True,'problem':'',
                     'url':'http://127.0.0.1:9999','token':'raw-token','log':'raw-log',
                     'queue':{'running':['one'],'waiting':2}}
    window.server_status,window.worker_status,window.activity = Widget(),Widget(),Widget()
    window.commands = queue.Queue()
    monkeypatch.setattr('forensic_app.desktop.draw_server_banner',lambda *args:None)
    return window


def test_shared_preference_switch_updates_labels_and_status_without_commands(tmp_path,monkeypatch):
    window = synthetic_window(tmp_path,monkeypatch)
    start,dead = Widget(),Widget()
    window.bind_text(start,'action.start')
    window.bind_text(dead,'action.stop')
    dead.exists = False
    before = dict(window.latest)
    # Simulates the web API writing the same storage, not a desktop-local flag.
    InterfacePreferences(Storage(tmp_path)).update(locale='en',onboarding_dismissed=True)
    assert window.sync_language(force=True)
    assert start.values['text'] == 'Start server'
    assert window.server_status.values['text'] == '● Server running'
    assert window.worker_status.values['text'] == 'Worker: active'
    assert 'Running: 1 · Waiting: 2' in window.activity.values['text']
    assert window.language.get() == 'EN'
    assert len(window.bindings) == 1
    assert window.commands.empty()
    assert window.latest == before
    assert InterfacePreferences(Storage(tmp_path)).get()['onboarding_dismissed']
    # A fresh desktop instance reads the persisted shared setting.
    assert DesktopTranslations(window.interface.get()['locale']).t('action.stop') == 'Stop server'
    window.language.set('DE')
    window.choose_language()
    assert window.interface.get()['locale'] == 'de'
    assert window.server_status.values['text'] == '● Server läuft'
    assert window.commands.empty()


@pytest.mark.parametrize(('state','expected'),[
    ({'stopping':True},'Waiting for active work'),
    ({'ready':False},'Server starting'),
    ({'ready':False,'alive':False},'Server stopped'),
    ({'restart_required':True},'Server running'),
])
def test_dynamic_status_paths(tmp_path,monkeypatch,state,expected):
    window = synthetic_window(tmp_path,monkeypatch)
    window.translations.locale = 'en'
    window.refresh_status({**window.latest,**state})
    assert expected in window.server_status.values['text']
    if state.get('restart_required'):
        assert 'restart the server' in window.activity.values['text']


def test_problem_metadata_and_raw_errors(tmp_path,monkeypatch):
    window = synthetic_window(tmp_path,monkeypatch)
    window.translations.locale = 'en'
    raw = 'Access denied: C:\\Test\\Ä {detail}'
    window.refresh_status({**window.latest,'problem':raw})
    assert window.activity.values['text'] == raw
    window.refresh_status({**window.latest,'problem_i18n':{'key':'problem.unreachable','parameters':{'detail':raw}}})
    assert window.activity.values['text'] == 'Server not reachable yet: '+raw
    args = SimpleNamespace(data_dir=tmp_path,lan=False,tls_cert=None,port=9999)
    session = DesktopSession(args)
    session.set_problem('problem.startup',detail=raw)
    assert session.problem == 'Serverstart fehlgeschlagen: '+raw
    assert session.poll()['problem_i18n']['parameters']['detail'] == raw
    session.problem = raw
    assert session.problem_description() is None
    with pytest.raises(DesktopError) as failure:
        session.stop()
    assert failure.value.translated(window.t).startswith('Server not ready')


def test_desktop_localizes_structured_shared_errors_only(tmp_path,monkeypatch):
    from fastapi import HTTPException

    from forensic_app.app_errors import AppValueError, ErrorText
    window = synthetic_window(tmp_path,monkeypatch)
    window.translations.locale = 'en'
    key = 'error.fe2b26905bd9'  # Existing diagnostics ticket expiry.
    assert window.error_text(AppValueError(key)) == ErrorText(key).localized('en')
    assert window.error_text(HTTPException(410,ErrorText(key))) == ErrorText(key).localized('en')
    raw = OSError('OS Fehler {raw} C:\\Ä')
    assert window.error_text(raw) == str(raw)
    session = DesktopSession(SimpleNamespace(data_dir=tmp_path,lan=False,tls_cert=None,port=9999))
    session.set_exception(AppValueError(key))
    window.refresh_status({**window.latest,'problem':session.problem,'problem_i18n':session.problem_description()})
    assert window.activity.values['text'] == ErrorText(key).localized('en')
    session.set_exception(raw)
    assert session.problem == str(raw) and session.problem_description() is None


def test_tray_refresh_posts_only_existing_icon_language_message(monkeypatch):
    from forensic_app.windows_tray import TrayIcon
    calls = []
    class Post:
        def __call__(self,*args): calls.append(args)
    native = SimpleNamespace(PostMessageW=Post())
    monkeypatch.setattr('forensic_app.windows_tray.ctypes.WinDLL',lambda name:native)
    tray = TrayIcon.__new__(TrayIcon)
    tray.hwnd = 42
    tray.refresh_language()
    assert calls == [(42,0x8002,0,0)]
    tray.hwnd = None
    tray.refresh_language()
    assert len(calls) == 1


def test_startup_error_supports_structured_and_old_payloads(tmp_path,monkeypatch):
    import json

    from forensic_app.app_errors import ErrorText
    window = synthetic_window(tmp_path,monkeypatch)
    window.translations.locale = 'en'
    session = DesktopSession(SimpleNamespace(data_dir=tmp_path,lan=False,tls_cert=None,port=9999))
    session.process = SimpleNamespace(poll=lambda:1,returncode=1)
    session.control_id = 'synthetic-id'
    folder = tmp_path/'logs'
    folder.mkdir()
    key = 'error.fe2b26905bd9'
    payload = {'control_id':'synthetic-id','message':str(ErrorText(key)),'error_code':key,'error_params':{}}
    (folder/'desktop-startup-error.json').write_text(json.dumps(payload),encoding='utf-8')
    state = session.poll()
    assert state['problem'] == 'Serverstart fehlgeschlagen: '+str(ErrorText(key))
    window.refresh_status({**window.latest,**state})
    assert window.activity.values['text'] == 'Server startup failed: '+ErrorText(key).localized('en')
    raw = 'OS Fehler Ä {raw}'
    payload = {'control_id':'synthetic-id','message':raw}
    (folder/'desktop-startup-error.json').write_text(json.dumps(payload),encoding='utf-8')
    session.problem = ''
    state = session.poll()
    window.refresh_status({**window.latest,**state})
    assert window.activity.values['text'] == 'Server startup failed: '+raw
    payload.update(error_code='unknown.code',error_params={})
    (folder/'desktop-startup-error.json').write_text(json.dumps(payload),encoding='utf-8')
    session.problem = ''
    state = session.poll()
    assert 'detail_i18n' not in state['problem_i18n']
    assert state['problem'] == 'Serverstart fehlgeschlagen: '+raw


def test_banner_uses_translated_labels_and_keeps_product_name():
    class Canvas:
        def __init__(self): self.text = []
        def winfo_width(self): return 1008
        def delete(self,*args): pass
        def configure(self,**kwargs): pass
        def create_text(self,*args,**kwargs): self.text.append(kwargs['text'])
        def __getattr__(self,name): return lambda *args,**kwargs:None
    canvas = Canvas()
    draw_server_banner(canvas,True,DesktopTranslations('en').t)
    assert 'DIGITAL FORENSICS' in canvas.text
    assert 'STATIC MALWARE ANALYSIS' in canvas.text
    assert 'Post-Processing-Magic' in canvas.text
    assert 'Administrator privileges active' in canvas.text


def test_tk_dialog_switch_preserves_input_and_diagnostic_payload(tmp_path,monkeypatch):
    """Real widgets, but no server, worker, tray thread, tools or browser."""
    import threading
    import tkinter as tk
    from tkinter import ttk

    from forensic_app.launcher import parser

    class Tray:
        def __init__(self,*args,**kwargs):
            self.ready = threading.Event()
            self.error,self.hwnd = '',None
        def refresh_language(self): pass
        def close(self): pass

    monkeypatch.setattr(ServerWindow,'background',lambda self:None)
    monkeypatch.setattr('forensic_app.desktop.TrayIcon',Tray)
    root = tk.Tk()
    root.withdraw()
    args = parser().parse_args(['--test-no-admin','--data-dir',str(tmp_path)])
    window = ServerWindow(root,args)
    def descendants(widget):
        for child in widget.winfo_children():
            yield child
            yield from descendants(child)
    try:
        assert window.commands.get_nowait() == 'start'  # Existing autostart only.
        window.settings_dialog()
        settings = next(item for item in root.winfo_children() if isinstance(item,tk.Toplevel))
        entries = [item for item in descendants(settings) if isinstance(item,ttk.Entry) and not isinstance(item,ttk.Combobox)]
        entries[0].delete(0,'end')
        entries[0].insert(0,'12345')
        access = next(item for item in descendants(settings) if isinstance(item,ttk.Combobox))
        access.current(1)
        preview = {'ticket':'synthetic','files':[{'name':'synthetic.txt','bytes':42,'text':'Original ä {detail} Server startet…'}]}
        window.diagnosis_dialog(preview)
        diagnosis = next(item for item in root.winfo_children() if isinstance(item,tk.Toplevel) and item is not settings)
        window.interface.update(locale='en')
        assert window.sync_language(force=True)
        assert settings.title() == 'Server settings'
        assert diagnosis.title() == 'Diagnostics package – preview'
        assert entries[0].get() == '12345'
        assert access.current() == 1 and access.get() == 'LAN'
        assert window.buttons['browser'].cget('text') == 'Open browser'
        output = next(item for item in descendants(diagnosis) if isinstance(item,tk.Text))
        assert output.get('1.0','end-1c') == preview['files'][0]['text']
        assert window.commands.empty()
        # Validation messages and dialog labels also update with the inputs intact.
        entries[0].delete(0,'end')
        entries[0].insert(0,'invalid')
        save = next(item for item in descendants(settings) if isinstance(item,ttk.Button) and item.cget('text') == 'Save')
        save.invoke()
        assert any(isinstance(item,tk.Label) and 'Enter port' in item.cget('text') for item in descendants(settings))
        window.interface.update(locale='de')
        assert window.sync_language(force=True)
        assert settings.title() == 'Servereinstellungen'
        assert entries[0].get() == 'invalid'
        assert any(isinstance(item,tk.Label) and 'Bitte Port' in item.cget('text') for item in descendants(settings))
        assert window.commands.empty()
    finally:
        window.close()
