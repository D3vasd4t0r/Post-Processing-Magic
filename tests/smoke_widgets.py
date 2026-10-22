"""Programmatic Tk/tray component checks in a fresh synthetic application window."""
import json
import socket
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

from forensic_app.desktop import ServerWindow
from forensic_app.launcher import parser


def main():
    folder = Path(__file__).resolve().parents[1]/'.local-data'/('widget-smoke-'+str(time.time_ns()))
    folder.mkdir()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    args = parser().parse_args(['--data-dir',str(folder/'state'),'--port',str(port),'--test-no-admin'])
    root = tk.Tk()
    window = ServerWindow(root,args)
    root.title('Synthetic widget smoke – no user data')
    checks = []

    def wait(check):
        end = time.monotonic()+40
        while time.monotonic() < end:
            root.update()
            if check():
                return
            time.sleep(.05)
        raise TimeoutError('Own widget smoke timed out')

    original_confirm = messagebox.askyesno
    try:
        wait(lambda:window.latest['ready'] and window.tray.ready.is_set())
        assert not window.tray.error and window.tray.hwnd
        checks.append('native notification icon registered')
        assert window.token_value.get() and window.url_value.get()
        assert window.logs.winfo_height() > 100
        window.copy(window.token_value)
        assert root.clipboard_get() == window.latest['token']
        checks.append('live token and copy button')
        window.settings_dialog()
        root.update()
        settings_dialog = next(child for child in root.winfo_children() if isinstance(child,tk.Toplevel))
        assert settings_dialog.title() == 'Servereinstellungen'
        settings_dialog.destroy()
        checks.append('server preferences dialog renders')
        preview = window.diagnostics.preview()
        window.diagnosis_dialog(preview)
        root.update()
        diagnostic_dialog = next(child for child in root.winfo_children() if isinstance(child,tk.Toplevel))
        assert diagnostic_dialog.title() == 'Diagnosepaket – Vorschau'
        diagnostic_dialog.destroy()
        checks.append('diagnostic preview tabs render')
        window.hide()
        root.update()
        assert root.state() == 'withdrawn'
        # The tray callback queues show; no cross-thread Tk calls.
        window.tray.dispatch('show')
        wait(lambda:root.state() == 'normal')
        assert window.latest['ready']
        checks.append('hide keeps server alive and tray callback restores window')
        messagebox.askyesno = lambda *a,**kw:False
        window.action('force')
        root.update()
        assert window.latest['alive']
        checks.append('force cancellation preserves running server')
        window.action('stop')
        wait(lambda:not window.latest['alive'])
        checks.append('stop updates UI and clears access token')
        assert not window.token_value.get()
        window.action('start')
        wait(lambda:window.latest['ready'])
        messagebox.askyesno = lambda *a,**kw:True
        window.action('force')
        wait(lambda:not window.latest['alive'])
        checks.append('start and confirmed force update UI')
        report = {'passed':True,'checks':checks,'scope':'source Tk/tray components; EXE tree separately tested'}
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'report':str(folder/'report.json'),'checks':len(checks)}))
    finally:
        messagebox.askyesno = original_confirm
        window.close()


if __name__ == '__main__':
    main()
