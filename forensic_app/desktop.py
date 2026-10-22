"""Native offline server control panel, separated from the API and analysis worker."""
import logging
import queue
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from forensic_app import __version__
from forensic_app.desktop_session import DesktopSession
from forensic_app.diagnostics import Diagnostics
from forensic_app.server_preferences import PreferenceStore, ServerPreferences
from forensic_app.storage import InstanceLock, Storage
from forensic_app.windows_access import is_admin
from forensic_app.windows_tray import TrayIcon

BG, PANEL, EDGE, TEXT, MUTED, BLUE = '#07111f','#10233b','#294d70','#e7f0fc','#a7bdd6','#81c6ff'


class ServerWindow:
    def __init__(self,root,args):
        self.root,self.args = root,args
        self.commands,self.events = queue.Queue(),queue.Queue(maxsize=4)
        self.tray_events = queue.Queue()
        self.task_events = queue.Queue()
        self.diagnostics = Diagnostics(Storage(args.data_dir.expanduser().resolve()),lambda:{
            'server_running':self.latest.get('ready',False),'worker_running':self.latest.get('worker',False),'administrator':is_admin(),
            'port':self.args.port,'lan':self.args.lan,**self.latest.get('runtime',{})})
        self.latest = {'alive':False,'ready':False,'token':'','url':''}
        self.exiting = self.working = False
        self.last_log = ''
        self.closed = threading.Event()
        root.title('Post-Processing-Magic | Server '+__version__)
        root.geometry('1060x800')
        root.minsize(880,690)
        root.configure(bg=BG)
        icon = Path(__file__).parent/'assets/shield.ico'
        root.iconbitmap(str(icon))
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('TButton',background='#1b4167',foreground=TEXT,bordercolor=EDGE,
                        padding=(14,9),font=('Segoe UI',10))
        style.map('TButton',background=[('active','#295c89'),('disabled','#14283e')],
                  foreground=[('disabled','#68829c')])
        style.configure('Accent.TButton',background='#72baff',foreground='#06203a')
        style.map('Accent.TButton',background=[('active','#a1d5ff'),('disabled','#244361')])
        style.configure('Danger.TButton',background='#512338',foreground='#ffc2cb')
        outer = tk.Frame(root,bg=BG,padx=26,pady=22)
        outer.pack(fill='both',expand=True)
        hero = tk.Frame(outer,bg=PANEL,padx=24,pady=18,highlightthickness=1,highlightbackground=EDGE)
        hero.pack(fill='x')
        shield = tk.Canvas(hero,width=62,height=72,bg=PANEL,highlightthickness=0)
        shield.pack(side='left',padx=(0,20))
        shield.create_polygon(31,4,57,15,55,43,45,58,31,69,17,58,7,43,5,15,fill='#183c60',outline=BLUE,width=2)
        shield.create_line(31,21,31,48,fill=BLUE,width=2)
        shield.create_line(18,34,44,34,fill=BLUE,width=2)
        branding = tk.Frame(hero,bg=PANEL)
        branding.pack(side='left',fill='x',expand=True)
        self.label(branding,'DIGITAL FORENSICS  ·  SERVER CONTROL',size=9,color=BLUE).pack(anchor='w')
        self.label(branding,'Post-Processing-Magic',size=24,bold=True).pack(anchor='w')
        self.label(branding,'Version '+__version__+'  ·  '+('Administratorrechte aktiv' if is_admin() else 'Synthetischer Test ohne Administratorrechte'),color=MUTED).pack(anchor='w',pady=(4,0))
        status_frame = tk.Frame(outer,bg=BG)
        status_frame.pack(fill='x',pady=(18,12))
        self.server_status = self.label(status_frame,'● Server startet…',bg=BG,size=14,bold=True)
        self.server_status.pack(side='left')
        self.worker_status = self.label(status_frame,'Worker: wird geprüft',bg=BG,color=MUTED)
        self.worker_status.pack(side='right')
        self.activity = self.label(outer,'Server wird automatisch gestartet. Der Browser öffnet sich über den Button.',bg=BG,color=MUTED)
        self.activity.pack(anchor='w',pady=(0,10))
        actions = tk.Frame(outer,bg=BG)
        actions.pack(fill='x')
        self.buttons = {}
        for key,text,style_name in [('start','Server starten','Accent.TButton'),('stop','Server stoppen','TButton'),
                                    ('force','Force Shutdown','Danger.TButton'),('browser','Browser öffnen','TButton')]:
            button = ttk.Button(actions,text=text,style=style_name,command=lambda item=key:self.action(item))
            button.pack(side='left',padx=(0,10))
            self.buttons[key] = button
        maintenance = tk.Frame(outer,bg=BG)
        maintenance.pack(fill='x',pady=(10,0))
        ttk.Button(maintenance,text='Servereinstellungen…',command=self.settings_dialog).pack(side='left',padx=(0,10))
        self.diagnose_button = ttk.Button(maintenance,text='Diagnosepaket…',command=self.preview_diagnostics)
        self.diagnose_button.pack(side='left')
        self.url_value,self.token_value = tk.StringVar(),tk.StringVar()
        credentials = tk.Frame(outer,bg=PANEL,padx=18,pady=12,highlightthickness=1,highlightbackground=EDGE)
        credentials.pack(fill='x',pady=(18,14))
        credentials.columnconfigure(1,weight=1)
        for row,(title,value) in enumerate([('Serveradresse',self.url_value),('Access Token',self.token_value)]):
            self.label(credentials,title,color=MUTED).grid(row=row,column=0,sticky='w',padx=(0,16),pady=6)
            entry = tk.Entry(credentials,textvariable=value,readonlybackground='#09182a',fg=TEXT,
                             state='readonly',font=('Consolas',11),relief='flat')
            entry.grid(row=row,column=1,sticky='ew',ipady=8,pady=6)
            ttk.Button(credentials,text='Kopieren',command=lambda item=value:self.copy(item)).grid(row=row,column=2,padx=(12,0))
        heading = tk.Frame(outer,bg=BG)
        heading.pack(fill='x',pady=(0,8))
        self.label(heading,'SERVERLOGS',bg=BG,color=BLUE,bold=True,size=10).pack(side='left')
        self.follow = tk.BooleanVar(value=True)
        tk.Checkbutton(heading,text='Aktueller Ausgabe folgen',variable=self.follow,bg=BG,fg=MUTED,
                       selectcolor=PANEL,activebackground=BG,activeforeground=TEXT).pack(side='right')
        terminal = tk.Frame(outer,bg=EDGE,padx=1,pady=1)
        terminal.pack(fill='both',expand=True)
        scroll = ttk.Scrollbar(terminal)
        scroll.pack(side='right',fill='y')
        self.logs = tk.Text(terminal,bg='#050e1a',fg='#cce4ff',insertbackground=TEXT,relief='flat',
                            font=('Consolas',10),height=12,wrap='word',padx=14,pady=12,yscrollcommand=scroll.set,state='disabled')
        self.logs.pack(fill='both',expand=True)
        def scroll_logs(*values):
            self.follow.set(False)
            self.logs.yview(*values)
        scroll.configure(command=scroll_logs)
        self.logs.bind('<MouseWheel>',self.pause_follow)
        footer = tk.Frame(outer,bg=BG)
        footer.pack(fill='x',pady=(14,0))
        self.label(footer,'X minimiert in den Infobereich. Serverlogs enthalten keine Tool-Liveausgabe.',bg=BG,color=MUTED,size=9).pack(side='left')
        ttk.Button(footer,text='Beenden…',command=self.exit_requested).pack(side='right')
        self.tray = TrayIcon(icon,self.tray_events.put)
        root.protocol('WM_DELETE_WINDOW',self.hide)
        self.thread = threading.Thread(target=self.background,daemon=True)
        self.thread.start()
        self.commands.put('start')
        root.after(100,self.tick)

    def label(self,parent,text,*,bg=PANEL,color=TEXT,size=11,bold=False):
        return tk.Label(parent,text=text,bg=bg,fg=color,font=('Segoe UI',size,'bold' if bold else 'normal'),anchor='w',justify='left')

    def background(self):
        session = DesktopSession(self.args)
        try:
            while not self.closed.is_set():
                try:
                    action = self.commands.get(timeout=.6)
                    self.working = True
                    try:
                        if action == 'diagnose':
                            self.task_events.put(('diagnosis',self.diagnostics.preview()))
                        elif isinstance(action,tuple):
                            session.configure(action[1])
                            self.task_events.put(('settings_saved',None))
                        else:
                            getattr(session,action)()
                    except Exception as exc:
                        logging.getLogger(__name__).exception('Serversteuerung fehlgeschlagen')
                        session.problem = str(exc)
                        self.task_events.put(('error',str(exc)))
                    finally:
                        self.working = False
                except queue.Empty:
                    pass
                state = session.poll()
                state['log'] = session.log_tail()
                try:
                    self.events.put_nowait(state)
                except queue.Full:
                    pass
        finally:
            if session.guard:
                session.guard.close()

    def tick(self):
        if self.closed.is_set():
            return
        while not self.task_events.empty():
            kind,value = self.task_events.get_nowait()
            self.diagnose_button.configure(state='normal')
            if kind == 'diagnosis':
                self.diagnosis_dialog(value)
            elif kind == 'settings_saved':
                messagebox.showinfo('Einstellungen gespeichert','Gespeichert. Änderungen gelten nach Server stoppen und Server starten. Ein laufender Auftrag wird nicht unterbrochen.',parent=self.root)
            elif kind == 'error':
                messagebox.showerror('Aktion fehlgeschlagen',value,parent=self.root)
        while not self.tray_events.empty():
            event = self.tray_events.get_nowait()
            self.show()
            if event == 'exit':
                self.exit_requested()
        latest = None
        while not self.events.empty():
            latest = self.events.get_nowait()
        if latest is not None:
            self.latest = latest
            alive,ready,stopping = latest['alive'],latest['ready'],latest['stopping']
            title = '● Wartet auf laufende Arbeiten…' if stopping and alive else '● Server läuft' if ready else '● Server startet…' if alive else '● Server gestoppt'
            self.server_status.configure(text=title,fg='#9ed9c8' if ready and not stopping else BLUE)
            self.worker_status.configure(text='Worker: '+('aktiv' if latest['worker'] else 'gestoppt / nicht erreichbar'))
            counts = latest.get('queue',{})
            note = latest.get('problem') or ('Laufend: '+str(len(counts.get('running',[])))+' · Wartend: '+str(counts.get('waiting',0))+
                ' · Archivierungen: '+str(len(counts.get('archiving',[])))+' laufend, '+str(counts.get('archive_waiting',0))+' wartend')
            if stopping:
                note = 'Neue Aufträge gesperrt. Laufende Arbeit wird beendet, wartende Aufträge bleiben zurückgehalten.'
            elif latest.get('restart_required'):
                note = 'Neue Servereinstellungen gespeichert – zum Anwenden Server stoppen und wieder starten.'
            self.activity.configure(text=note,wraplength=970)
            self.url_value.set(latest['url'] if ready else '')
            self.token_value.set(latest['token'] if ready else '')
            for key,enabled in [('start',not alive),('stop',ready and not stopping),('force',alive),('browser',ready and not stopping)]:
                self.buttons[key].configure(state='normal' if enabled and not self.working else 'disabled')
            text = latest['log']
            if text != self.last_log:
                position = self.logs.yview()[0]
                self.logs.configure(state='normal')
                self.logs.delete('1.0','end')
                self.logs.insert('end',text)
                self.logs.configure(state='disabled')
                self.logs.yview_moveto(1 if self.follow.get() else position)
                self.last_log = text
            if self.exiting and not alive:
                self.close()
                return
        self.root.after(150,self.tick)

    def pause_follow(self,event):
        if event.delta > 0:
            self.follow.set(False)

    def copy(self,value):
        if value.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(value.get())

    def preview_diagnostics(self):
        self.diagnose_button.configure(state='disabled')
        self.commands.put('diagnose')

    def diagnosis_dialog(self,preview):
        dialog = tk.Toplevel(self.root,bg=BG)
        dialog.title('Diagnosepaket – Vorschau')
        dialog.geometry('850x650')
        dialog.transient(self.root)
        self.label(dialog,preview['message'],bg=BG,color=MUTED).pack(anchor='w',padx=16,pady=12)
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both',expand=True,padx=16)
        for item in preview['files']:
            frame = tk.Frame(notebook,bg=PANEL)
            notebook.add(frame,text=item['name']+' ('+str(item['bytes'])+' Bytes)')
            text = tk.Text(frame,bg=PANEL,fg=TEXT,wrap='word',font=('Consolas',10))
            scroll = ttk.Scrollbar(frame,command=text.yview)
            text.configure(yscrollcommand=scroll.set)
            scroll.pack(side='right',fill='y')
            text.pack(fill='both',expand=True)
            text.insert('end',item['text'])
            text.configure(state='disabled')
        actions = tk.Frame(dialog,bg=BG)
        actions.pack(fill='x',padx=16,pady=16)
        def save():
            target = filedialog.asksaveasfilename(parent=dialog,title='Diagnosepaket speichern',initialfile='Diagnosepaket.zip',defaultextension='.zip',filetypes=[('ZIP-Archiv','*.zip')])
            if not target:
                return
            try:
                data = self.diagnostics.export(preview['ticket'])
                import os
                import tempfile
                destination = Path(target)
                with tempfile.NamedTemporaryFile(dir=destination.parent,prefix='.ppm-diagnose-',delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(data)
                try:
                    os.replace(temporary,destination)
                finally:
                    temporary.unlink(missing_ok=True)
                messagebox.showinfo('Diagnosepaket gespeichert','Das ZIP wurde lokal gespeichert. Es wurde nichts versendet.',parent=dialog)
                dialog.destroy()
            except Exception as exc:
                logging.getLogger(__name__).exception('Diagnoseexport fehlgeschlagen')
                messagebox.showerror('Export fehlgeschlagen',str(exc),parent=dialog)
        ttk.Button(actions,text='ZIP speichern…',command=save).pack(side='left')
        ttk.Button(actions,text='Schließen',command=dialog.destroy).pack(side='right')

    def settings_dialog(self):
        preferences,revision = PreferenceStore(Storage(self.args.data_dir.expanduser().resolve())).get()
        if not revision:
            preferences = preferences.model_copy(update={'port':self.args.port,'lan':self.args.lan})
        dialog = tk.Toplevel(self.root,bg=BG,padx=24,pady=20)
        dialog.title('Servereinstellungen')
        dialog.transient(self.root)
        port,access,maximum,backups = (tk.StringVar(value=str(preferences.port)),tk.StringVar(value='LAN' if preferences.lan else 'Lokal'),
            tk.StringVar(value=str(preferences.log_max_bytes/1_000_000)),tk.StringVar(value=str(preferences.log_backups)))
        for title,value in [('Port',port),('Maximale Größe je Serverlog (MB, dezimal)',maximum),('Anzahl älterer Serverlogdateien (1–20)',backups)]:
            self.label(dialog,title,bg=BG).pack(anchor='w',pady=(8,2))
            ttk.Entry(dialog,textvariable=value,width=52).pack(fill='x')
        self.label(dialog,'Zugriff',bg=BG).pack(anchor='w',pady=(12,2))
        ttk.Combobox(dialog,textvariable=access,values=['Lokal','LAN'],state='readonly').pack(fill='x')
        self.label(dialog,'Lokal: nur dieser Rechner. LAN: Anmeldung und selbstsigniertes HTTPS.\nKeine automatische Firewalländerung. Änderungen gelten nach Serverneustart.\nLogrotation betrifft ausschließlich technische Serverlogs.',bg=BG,color=MUTED,size=10).pack(anchor='w',pady=16)
        error = self.label(dialog,'',bg=BG,color='#ffb7bd',size=10)
        error.pack(anchor='w')
        def save():
            try:
                value = ServerPreferences(port=int(port.get()),lan=access.get()=='LAN',log_max_bytes=int(float(maximum.get().replace(',','.'))*1_000_000),log_backups=int(backups.get()))
            except (ValueError,OverflowError):
                error.configure(text='Bitte Port 1–65535, Loggröße 0,1–100 MB und Anzahl 1–20 eingeben.')
                return
            self.commands.put(('settings',value))
            dialog.destroy()
        row = tk.Frame(dialog,bg=BG)
        row.pack(fill='x',pady=(12,0))
        ttk.Button(row,text='Speichern',command=save).pack(side='left')
        ttk.Button(row,text='Abbrechen',command=dialog.destroy).pack(side='right')

    def action(self,action):
        if action == 'browser':
            if self.latest['ready']:
                webbrowser.open(self.latest['url']+'/#token='+self.latest['token'])
            return
        if action == 'force' and not messagebox.askyesno('Force Shutdown bestätigen',
                'Server, Worker und gestartete Tools sofort beenden?\nLaufende Arbeiten werden unterbrochen und nicht automatisch wiederholt.',parent=self.root,icon='warning'):
            return
        self.commands.put(action)

    def hide(self):
        if self.tray.ready.is_set() and not self.tray.error and self.tray.hwnd:
            self.root.withdraw()
        else:
            messagebox.showinfo('Infobereich nicht verfügbar','Das Serverfenster wird stattdessen in die Taskleiste minimiert.',parent=self.root)
            self.root.iconify()

    def show(self):
        self.root.deiconify()
        self.root.lift()

    def exit_requested(self):
        if not self.latest['alive']:
            self.close()
        elif messagebox.askyesno('Server stoppen und beenden','Neue Aufträge sperren, laufende Arbeit abschließen und danach das Serverfenster beenden?',parent=self.root):
            self.exiting = True
            self.action('stop')

    def close(self):
        self.closed.set()
        self.tray.close()
        self.thread.join(timeout=3)
        self.root.destroy()


def run_panel(args):
    root = tk.Tk()
    try:
        with InstanceLock(args.data_dir.expanduser().resolve()/'config/desktop-control'):
            ServerWindow(root,args)
            root.mainloop()
        return 0
    except Exception as exc:
        logging.getLogger(__name__).exception('Serverfenster fehlgeschlagen')
        messagebox.showerror('Serverfenster konnte nicht gestartet werden',str(exc),parent=root)
        root.destroy()
        return 1
