"""Native offline server control panel, separated from the API and analysis worker."""
import logging
import queue
import sqlite3
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from forensic_app import __version__
from forensic_app.app_errors import AppValueError, ErrorText
from forensic_app.desktop_i18n import DesktopError, DesktopTranslations
from forensic_app.desktop_session import DesktopSession
from forensic_app.diagnostics import Diagnostics
from forensic_app.interface_preferences import InterfacePreferences
from forensic_app.server_preferences import PreferenceStore, ServerPreferences
from forensic_app.storage import InstanceLock, Storage
from forensic_app.windows_access import is_admin
from forensic_app.windows_tray import TrayIcon

BG, PANEL, EDGE, TEXT, MUTED, BLUE = '#07111f','#10233b','#294d70','#e7f0fc','#a7bdd6','#81c6ff'


def draw_server_banner(canvas,administrator,translate=None):
    """Blue forensic header; live status stays below the banner."""
    t = translate or DesktopTranslations().t
    canvas.delete('all')
    width=max(1,canvas.winfo_width()); scale=width/1008
    def points(values):
        return [value*scale for value in values]
    def text(x,y,value,size,color=TEXT,bold=False,wrap=None):
        options={'anchor':'nw','fill':color,'font':('Segoe UI',-max(9,round(size*scale)),'bold' if bold else 'normal')}
        if wrap is not None: options['width']=wrap*scale
        canvas.create_text(x*scale,y*scale,text=value,**options)
    canvas.configure(height=max(130,round(158*scale)))
    canvas.create_rectangle(0,0,width,180*scale,fill='#102b48',outline='')
    canvas.create_polygon(points([50,28,85,41,82,81,70,100,50,115,30,100,18,81,15,41]),fill='#193f63',outline=BLUE,width=max(2,3*scale))
    canvas.create_line(points([50,49,50,91]),fill=BLUE,width=2*scale)
    canvas.create_line(points([33,70,67,70]),fill=BLUE,width=2*scale)
    text(109,27,t('banner.forensics'),13,BLUE)
    text(109,61,'Post-Processing-Magic',27,bold=True)
    text(109,101,t('banner.control'),14,MUTED)
    text(584,61,t('banner.version',version=__version__),18,BLUE)
    text(584,101,t('banner.admin') if administrator else t('banner.synthetic'),13,MUTED,wrap=360)


class ServerWindow:
    """Tk-thread owner of the server panel and its dialogs.

    The background thread owns DesktopSession and sends snapshots through queues;
    tray callbacks enqueue actions instead of touching widgets. Closing the window
    normally hides it, while explicit exit waits for the managed server to stop."""
    def __init__(self,root,args):
        """Build widgets and queues, start the tray and control threads, then enqueue startup.

        The caller owns the Tk event loop; scheduled tick callbacks perform widget updates."""
        self.root,self.args = root,args
        self.interface = InterfacePreferences(Storage(args.data_dir.expanduser().resolve()))
        self.translations = DesktopTranslations(self.interface.get()['locale'])
        self.bindings = []
        self.locale_checked = 0
        self.t = self.translations.t
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
        outer.columnconfigure(0,weight=1)
        # Only the terminal yields height; footer controls keep their requested size.
        outer.rowconfigure(7,weight=1)
        hero = tk.Canvas(outer,bg='#102b48',height=158,highlightthickness=1,highlightbackground=EDGE,takefocus=False)
        hero.grid(row=0,column=0,sticky='ew')
        self.hero = hero
        hero.bind('<Configure>',lambda event: draw_server_banner(hero,is_admin(),self.t))
        status_frame = tk.Frame(outer,bg=BG)
        status_frame.grid(row=1,column=0,sticky='ew',pady=(18,12))
        self.server_status = self.localized_label(status_frame,'status.starting',bg=BG,size=14,bold=True)
        self.server_status.pack(side='left')
        self.worker_status = self.localized_label(status_frame,'status.worker_check',bg=BG,color=MUTED)
        self.worker_status.pack(side='right')
        self.activity = self.localized_label(outer,'activity.initial',bg=BG,color=MUTED)
        self.activity.grid(row=2,column=0,sticky='ew',pady=(0,10))
        actions = tk.Frame(outer,bg=BG)
        actions.grid(row=3,column=0,sticky='ew')
        self.buttons = {}
        for key,text,style_name in [('start',self.t('action.start'),'Accent.TButton'),('stop',self.t('action.stop'),'TButton'),
                                    ('force',self.t('action.force'),'Danger.TButton'),('browser',self.t('action.browser'),'TButton')]:
            button = ttk.Button(actions,text=text,style=style_name,command=lambda item=key:self.action(item))
            button.pack(side='left',padx=(0,10))
            self.buttons[key] = button
            self.bind_text(button,'action.'+key)
        maintenance = tk.Frame(outer,bg=BG)
        maintenance.grid(row=4,column=0,sticky='ew',pady=(10,0))
        self.localized_button(maintenance,'action.settings',self.settings_dialog).pack(side='left',padx=(0,10))
        self.diagnose_button = ttk.Button(maintenance,text=self.t('action.diagnostics'),command=self.preview_diagnostics)
        self.diagnose_button.pack(side='left')
        self.bind_text(self.diagnose_button,'action.diagnostics')
        self.localized_label(maintenance,'field.language',bg=BG,color=MUTED).pack(side='left',padx=(18,6))
        self.language = tk.StringVar(value=self.translations.locale.upper())
        chooser = ttk.Combobox(maintenance,textvariable=self.language,values=['DE','EN'],state='readonly',width=4)
        chooser.pack(side='left')
        chooser.bind('<<ComboboxSelected>>',self.choose_language)
        self.url_value,self.token_value = tk.StringVar(),tk.StringVar()
        credentials = tk.Frame(outer,bg=PANEL,padx=18,pady=12,highlightthickness=1,highlightbackground=EDGE)
        credentials.grid(row=5,column=0,sticky='ew',pady=(18,14))
        credentials.columnconfigure(1,weight=1)
        for row,(title,value) in enumerate([('field.address',self.url_value),('field.token',self.token_value)]):
            self.localized_label(credentials,title,color=MUTED).grid(row=row,column=0,sticky='w',padx=(0,16),pady=6)
            entry = tk.Entry(credentials,textvariable=value,readonlybackground='#09182a',fg=TEXT,
                             state='readonly',font=('Consolas',11),relief='flat')
            entry.grid(row=row,column=1,sticky='ew',ipady=8,pady=6)
            self.localized_button(credentials,'action.copy',lambda item=value:self.copy(item)).grid(row=row,column=2,padx=(12,0))
        heading = tk.Frame(outer,bg=BG)
        heading.grid(row=6,column=0,sticky='ew',pady=(0,8))
        self.localized_label(heading,'logs.heading',bg=BG,color=BLUE,bold=True,size=10).pack(side='left')
        self.follow = tk.BooleanVar(value=True)
        self.follow_button = tk.Checkbutton(heading,text=self.t('logs.follow'),variable=self.follow,bg=BG,fg=MUTED,
                       selectcolor=PANEL,activebackground=BG,activeforeground=TEXT)
        self.follow_button.pack(side='right')
        self.bind_text(self.follow_button,'logs.follow')
        terminal = tk.Frame(outer,bg=EDGE,padx=1,pady=1)
        terminal.grid(row=7,column=0,sticky='nsew')
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
        footer.grid(row=8,column=0,sticky='ew',pady=(14,0))
        footer.columnconfigure(0,weight=1)
        footer_note = self.localized_label(footer,'footer.note',bg=BG,color=MUTED,size=9)
        footer_note.grid(row=0,column=0,sticky='ew',padx=(0,16))
        footer_note.bind('<Configure>',lambda event: footer_note.configure(wraplength=max(1,event.width)))
        self.localized_button(footer,'action.exit',self.exit_requested).grid(row=0,column=1,sticky='e')
        self.tray = TrayIcon(icon,self.tray_events.put,translate=self.t)
        root.protocol('WM_DELETE_WINDOW',self.hide)
        self.thread = threading.Thread(target=self.background,daemon=True)
        self.thread.start()
        self.commands.put('start')
        root.after(100,self.tick)

    def bind_text(self,widget,key):
        """Register an app-label refresh callback, retaining the widget for language changes."""
        self.bindings.append((widget,lambda: widget.configure(text=self.t(key))))
        widget.configure(text=self.t(key))
        return widget

    def localized_label(self,parent,key,**options):
        """Create a label whose app-owned text participates in language refreshes."""
        return self.bind_text(self.label(parent,self.t(key),**options),key)

    def localized_button(self,parent,key,command):
        """Create a translated button while preserving its supplied action callback."""
        return self.bind_text(ttk.Button(parent,command=command),key)

    def bind_title(self,dialog,key):
        """Track a dialog title for locale changes until its widget is destroyed."""
        self.bindings.append((dialog,lambda: dialog.title(self.t(key))))
        dialog.title(self.t(key))

    def choose_language(self,event=None):
        """Persist the selected interface locale and refresh live Tk labels on this thread."""
        try:
            self.interface.update(locale=self.language.get().lower())
            self.sync_language(force=True)
        except (OSError,ValueError,sqlite3.Error) as exc:
            messagebox.showerror(self.t('error.action'),self.error_text(exc),parent=self.root)

    def error_text(self,exc):
        """Localize structured app failures while leaving unknown exception details unchanged."""
        if isinstance(exc,DesktopError):
            return exc.translated(self.t)
        if isinstance(exc,AppValueError):
            return exc.text.localized(self.translations.locale)
        detail = getattr(exc,'detail',None)
        if isinstance(detail,ErrorText):
            return detail.localized(self.translations.locale)
        return str(exc)

    def sync_language(self,force=False):
        """Refresh live label bindings from the shared interface preference at most once a second.

        This updates presentation and the tray tooltip, without restarting the server or
        rewriting raw server logs and diagnostic preview contents."""
        now = time.monotonic()
        if not force and now-self.locale_checked < 1:
            return False
        self.locale_checked = now
        try:
            locale = self.interface.get()['locale']
        except Exception:
            logging.getLogger(__name__).exception('Interface preference read failed')
            return False
        if locale == self.translations.locale:
            return False
        self.translations.locale = locale
        self.language.set(locale.upper())
        live = []
        for widget,refresh in self.bindings:
            if widget.winfo_exists():
                refresh()
                live.append((widget,refresh))
        self.bindings = live
        draw_server_banner(self.hero,is_admin(),self.t)
        self.tray.refresh_language()
        if 'stopping' in self.latest:
            self.refresh_status(self.latest)
        return True

    def refresh_status(self,latest):
        """Render a session snapshot, including structured failures, without calling the server."""
        alive,ready,stopping = latest['alive'],latest['ready'],latest['stopping']
        title = self.t('status.stopping') if stopping and alive else self.t('status.running') if ready else self.t('status.starting') if alive else self.t('status.stopped')
        self.server_status.configure(text=title,fg='#9ed9c8' if ready and not stopping else BLUE)
        self.worker_status.configure(text=self.t('status.worker',state=self.t('worker.active') if latest['worker'] else self.t('worker.stopped')))
        counts = latest.get('queue',{})
        problem = latest.get('problem_i18n')
        problem_text = latest.get('problem')
        if problem:
            parameters = dict(problem['parameters'])
            if problem.get('detail_i18n'):
                detail = problem['detail_i18n']
                parameters['detail'] = ErrorText(detail['key'],**detail['parameters']).localized(self.translations.locale)
            problem_text = ErrorText(problem['key'],**parameters).localized(self.translations.locale) if problem.get('catalog') == 'shared' else self.t(problem['key'],**parameters)
        note = problem_text or self.t('activity.counts',running=len(counts.get('running',[])),waiting=counts.get('waiting',0),archiving=len(counts.get('archiving',[])),archive_waiting=counts.get('archive_waiting',0))
        if stopping:
            note = self.t('activity.stopping')
        elif latest.get('restart_required'):
            note = self.t('activity.restart')
        self.activity.configure(text=note,wraplength=970)

    def label(self,parent,text,*,bg=PANEL,color=TEXT,size=11,bold=False):
        return tk.Label(parent,text=text,bg=bg,fg=color,font=('Segoe UI',size,'bold' if bold else 'normal'),anchor='w',justify='left')

    def background(self):
        """Serialize server-control commands and publish polled state without Tk calls.

        A bounded state queue may drop a snapshot when the UI lags. Task completions use
        a separate queue; finalization closes only this session's process guard."""
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
                        session.set_exception(exc)
                        self.task_events.put(('error',exc))
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
        """Drain task, tray and status queues on the Tk thread and schedule the next refresh.

        Only the latest pending session snapshot is rendered. A requested exit destroys
        the panel after a snapshot confirms that its server process is no longer alive."""
        if self.closed.is_set():
            return
        self.sync_language()
        while not self.task_events.empty():
            kind,value = self.task_events.get_nowait()
            self.diagnose_button.configure(state='normal')
            if kind == 'diagnosis':
                self.diagnosis_dialog(value)
            elif kind == 'settings_saved':
                messagebox.showinfo(self.t('settings.saved_title'),self.t('settings.saved'),parent=self.root)
            elif kind == 'error':
                messagebox.showerror(self.t('error.action'),self.error_text(value),parent=self.root)
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
            self.refresh_status(latest)
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
        """Stop automatic log following when the user scrolls upward with the mouse wheel."""
        if event.delta > 0:
            self.follow.set(False)

    def copy(self,value):
        """Copy a nonempty displayed value, including the token, to the Windows clipboard."""
        if value.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(value.get())

    def preview_diagnostics(self):
        """Disable duplicate preview requests and enqueue snapshot generation off the Tk thread."""
        self.diagnose_button.configure(state='disabled')
        self.commands.put('diagnose')

    def diagnosis_dialog(self,preview):
        """Display the exact diagnostic snapshot associated with a one-use export ticket.

        Saving consumes that ticket and replaces the selected destination using a
        same-directory temporary file; it does not regenerate or send the snapshot."""
        dialog = tk.Toplevel(self.root,bg=BG)
        self.bind_title(dialog,'diagnostics.title')
        dialog.geometry('850x650')
        dialog.transient(self.root)
        self.localized_label(dialog,'diagnostics.note',bg=BG,color=MUTED).pack(anchor='w',padx=16,pady=12)
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both',expand=True,padx=16)
        for item in preview['files']:
            frame = tk.Frame(notebook,bg=PANEL)
            notebook.add(frame,text=self.t('diagnostics.tab',name=item['name'],bytes=item['bytes']))
            self.bindings.append((frame,lambda f=frame,i=item: notebook.tab(f,text=self.t('diagnostics.tab',name=i['name'],bytes=i['bytes']))))
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
            target = filedialog.asksaveasfilename(parent=dialog,title=self.t('diagnostics.save_title'),initialfile=self.t('diagnostics.filename'),defaultextension='.zip',filetypes=[(self.t('file.zip'),'*.zip')])
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
                messagebox.showinfo(self.t('diagnostics.saved_title'),self.t('diagnostics.saved'),parent=dialog)
                dialog.destroy()
            except Exception as exc:
                logging.getLogger(__name__).exception('Diagnoseexport fehlgeschlagen')
                messagebox.showerror(self.t('error.export'),self.error_text(exc),parent=dialog)
        self.localized_button(actions,'action.zip',save).pack(side='left')
        self.localized_button(actions,'action.close',dialog.destroy).pack(side='right')

    def settings_dialog(self):
        """Edit persisted server preferences without restarting the current server.

        Validated values are queued to the control thread. An uninitialized preference
        record displays the active launch port and access mode as initial values."""
        preferences,revision = PreferenceStore(Storage(self.args.data_dir.expanduser().resolve())).get()
        if not revision:
            preferences = preferences.model_copy(update={'port':self.args.port,'lan':self.args.lan})
        dialog = tk.Toplevel(self.root,bg=BG,padx=24,pady=20)
        self.bind_title(dialog,'settings.title')
        dialog.transient(self.root)
        port,access,maximum,backups = (tk.StringVar(value=str(preferences.port)),tk.StringVar(value=self.t('access.lan') if preferences.lan else self.t('access.local')),
            tk.StringVar(value=str(preferences.log_max_bytes/1_000_000)),tk.StringVar(value=str(preferences.log_backups)))
        for title,value in [('field.port',port),('field.logsize',maximum),('field.backups',backups)]:
            self.localized_label(dialog,title,bg=BG).pack(anchor='w',pady=(8,2))
            ttk.Entry(dialog,textvariable=value,width=52).pack(fill='x')
        self.localized_label(dialog,'field.access',bg=BG).pack(anchor='w',pady=(12,2))
        access_box = ttk.Combobox(dialog,textvariable=access,values=[self.t('access.local'),self.t('access.lan')],state='readonly')
        access_box.current(1 if preferences.lan else 0)
        access_box.pack(fill='x')
        def refresh_access():
            index = access_box.current()
            access_box.configure(values=[self.t('access.local'),self.t('access.lan')])
            access_box.current(max(0,index))
        self.bindings.append((access_box,refresh_access))
        self.localized_label(dialog,'settings.note',bg=BG,color=MUTED,size=10).pack(anchor='w',pady=16)
        error = self.label(dialog,'',bg=BG,color='#ffb7bd',size=10)
        error.pack(anchor='w')
        def save():
            try:
                value = ServerPreferences(port=int(port.get()),lan=access_box.current()==1,log_max_bytes=int(float(maximum.get().replace(',','.'))*1_000_000),log_backups=int(backups.get()))
            except (ValueError,OverflowError):
                self.bind_text(error,'settings.invalid')
                return
            self.commands.put(('settings',value))
            dialog.destroy()
        row = tk.Frame(dialog,bg=BG)
        row.pack(fill='x',pady=(12,0))
        self.localized_button(row,'action.save',save).pack(side='left')
        self.localized_button(row,'action.cancel',dialog.destroy).pack(side='right')

    def action(self,action):
        """Open the verified browser URL or enqueue a server-control action.

        Force shutdown requires a UI confirmation here; the process-tree boundary is
        enforced by DesktopSession rather than by the button callback."""
        if action == 'browser':
            if self.latest['ready']:
                webbrowser.open(self.latest['url']+'/#token='+self.latest['token'])
            return
        if action == 'force' and not messagebox.askyesno(self.t('force.title'),
                self.t('force.confirm'),parent=self.root,icon='warning'):
            return
        self.commands.put(action)

    def hide(self):
        """Hide to the tray when its icon is ready, otherwise minimize to the taskbar."""
        if self.tray.ready.is_set() and not self.tray.error and self.tray.hwnd:
            self.root.withdraw()
        else:
            messagebox.showinfo(self.t('tray.unavailable_title'),self.t('tray.taskbar'),parent=self.root)
            self.root.iconify()

    def show(self):
        """Restore and raise the existing panel without creating another server session."""
        self.root.deiconify()
        self.root.lift()

    def exit_requested(self):
        """Ask for orderly shutdown when the owned process is alive, or close immediately."""
        if not self.latest['alive']:
            self.close()
        elif messagebox.askyesno(self.t('exit.title'),self.t('exit.confirm'),parent=self.root):
            self.exiting = True
            self.action('stop')

    def close(self):
        """Signal the control loop, close the tray, wait briefly for the thread, and destroy Tk."""
        self.closed.set()
        self.tray.close()
        self.thread.join(timeout=3)
        self.root.destroy()


def run_panel(args):
    """Run one desktop panel under a data-directory-specific control-window lock.

    Startup failures are shown in a localized dialog and returned as exit code 1;
    server ownership and shutdown remain delegated to ServerWindow/DesktopSession."""
    root = tk.Tk()
    try:
        with InstanceLock(args.data_dir.expanduser().resolve()/'config/desktop-control'):
            ServerWindow(root,args)
            root.mainloop()
        return 0
    except Exception as exc:
        logging.getLogger(__name__).exception('Serverfenster fehlgeschlagen')
        try:
            locale = InterfacePreferences(Storage(args.data_dir.expanduser().resolve())).get()['locale']
        except (OSError,ValueError,sqlite3.Error):
            locale = 'de'
        messagebox.showerror(DesktopTranslations(locale).t('error.startup'),str(exc),parent=root)
        root.destroy()
        return 1
