"""Small native notification-area icon. All Tk calls remain on the Tk thread."""
import ctypes
import threading
from ctypes import wintypes as w

from forensic_app.desktop_i18n import DesktopTranslations


class TrayIcon:
    """Own a native notification icon and hidden window on a dedicated daemon thread.

    The dispatch callback receives action names on that native thread; callers must
    marshal UI work themselves. ready signals successful creation or a captured
    startup failure, so it must be interpreted together with error and hwnd."""
    def __init__(self,icon_path,dispatch,*,translate=None):
        """Start native icon creation asynchronously; no Tk operations are performed here."""
        self.icon_path,self.dispatch = str(icon_path),dispatch
        self.translate = translate or DesktopTranslations().t
        self.ready = threading.Event()
        self.hwnd = None
        self.error = ''
        self.thread = threading.Thread(target=self._run,daemon=True)
        self.thread.start()

    def _run(self):
        """Run the native loop and expose supported startup failures through error and ready."""
        try:
            self._loop()
        except (OSError,RuntimeError,ValueError) as exc:
            self.error = str(exc)
            self.ready.set()

    def _loop(self):
        """Create the Win32 callback/window, register the icon and pump its message queue.

        The callback object is retained for the window lifetime. Finalization removes
        the icon and unregisters the class; taskbar recreation re-adds the same icon."""
        user = ctypes.WinDLL('user32',use_last_error=True)
        shell = ctypes.WinDLL('shell32',use_last_error=True)
        kernel = ctypes.WinDLL('kernel32',use_last_error=True)
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_ssize_t,w.HWND,w.UINT,w.WPARAM,w.LPARAM)

        class WindowClass(ctypes.Structure):
            _fields_ = [('style',w.UINT),('proc',callback_type),('class_extra',ctypes.c_int),('window_extra',ctypes.c_int),
                        ('instance',w.HINSTANCE),('icon',w.HICON),('cursor',w.HANDLE),('background',w.HBRUSH),
                        ('menu',w.LPCWSTR),('name',w.LPCWSTR)]

        class NotifyData(ctypes.Structure):
            _fields_ = [('size',w.DWORD),('window',w.HWND),('id',w.UINT),('flags',w.UINT),('message',w.UINT),
                        ('icon',w.HICON),('tip',w.WCHAR*128),('state',w.DWORD),('state_mask',w.DWORD),
                        ('info',w.WCHAR*256),('timeout',w.UINT),('info_title',w.WCHAR*64),('info_flags',w.DWORD),
                        ('guid',ctypes.c_ubyte*16),('balloon_icon',w.HICON)]

        user.DefWindowProcW.argtypes = [w.HWND,w.UINT,w.WPARAM,w.LPARAM]
        user.RegisterWindowMessageW.argtypes = [w.LPCWSTR]
        user.RegisterWindowMessageW.restype = w.UINT
        user.DefWindowProcW.restype = ctypes.c_ssize_t
        user.CreateWindowExW.argtypes = [w.DWORD,w.LPCWSTR,w.LPCWSTR,w.DWORD,ctypes.c_int,ctypes.c_int,
            ctypes.c_int,ctypes.c_int,w.HWND,w.HMENU,w.HINSTANCE,ctypes.c_void_p]
        user.CreateWindowExW.restype = w.HWND
        user.RegisterClassW.argtypes = [ctypes.POINTER(WindowClass)]
        user.LoadImageW.argtypes = [w.HINSTANCE,w.LPCWSTR,w.UINT,ctypes.c_int,ctypes.c_int,w.UINT]
        user.LoadImageW.restype = w.HANDLE
        user.CreatePopupMenu.restype = w.HMENU
        user.AppendMenuW.argtypes = [w.HMENU,w.UINT,ctypes.c_size_t,w.LPCWSTR]
        user.TrackPopupMenu.argtypes = [w.HMENU,w.UINT,ctypes.c_int,ctypes.c_int,ctypes.c_int,w.HWND,ctypes.c_void_p]
        user.TrackPopupMenu.restype = w.UINT
        user.DestroyMenu.argtypes = [w.HMENU]
        user.SetForegroundWindow.argtypes = [w.HWND]
        user.PostMessageW.argtypes = [w.HWND,w.UINT,w.WPARAM,w.LPARAM]
        user.DestroyWindow.argtypes = [w.HWND]
        user.DestroyIcon.argtypes = [w.HICON]
        shell.Shell_NotifyIconW.argtypes = [w.DWORD,ctypes.POINTER(NotifyData)]
        kernel.GetModuleHandleW.argtypes = [w.LPCWSTR]
        kernel.GetModuleHandleW.restype = w.HMODULE
        user.GetMessageW.argtypes = [ctypes.POINTER(w.MSG),w.HWND,w.UINT,w.UINT]
        user.DispatchMessageW.argtypes = [ctypes.POINTER(w.MSG)]
        user.DispatchMessageW.restype = ctypes.c_ssize_t
        taskbar_message = user.RegisterWindowMessageW('TaskbarCreated')
        data = NotifyData()

        def proc(hwnd,message,wp,lp):
            """Translate native window messages into queued owner actions or icon lifecycle operations."""
            if message == 0x8002:
                data.tip = self.translate('tray.tooltip')
                shell.Shell_NotifyIconW(1,ctypes.byref(data))
                return 0
            if message == taskbar_message:
                shell.Shell_NotifyIconW(0,ctypes.byref(data))
                return 0
            if message == 0x8001:
                if lp in (0x0202,0x0203):  # left release / double click
                    self.dispatch('show')
                elif lp == 0x0205:
                    point = w.POINT()
                    user.GetCursorPos(ctypes.byref(point))
                    menu = user.CreatePopupMenu()
                    try:
                        user.AppendMenuW(menu,0,1,self.translate('tray.open'))
                        user.AppendMenuW(menu,0,2,self.translate('tray.exit'))
                        user.SetForegroundWindow(hwnd)
                        chosen = user.TrackPopupMenu(menu,0x100|0x2,point.x,point.y,0,hwnd,None)
                        if chosen:
                            self.dispatch('show' if chosen == 1 else 'exit')
                        user.PostMessageW(hwnd,0,0,0)
                    finally:
                        user.DestroyMenu(menu)
                return 0
            if message == 0x0010:
                user.DestroyWindow(hwnd)
                return 0
            if message == 0x0002:
                user.PostQuitMessage(0)
                return 0
            return user.DefWindowProcW(hwnd,message,wp,lp)

        self.callback = callback_type(proc)
        instance = kernel.GetModuleHandleW(None)
        name = 'PostProcessingMagicTray'+str(id(self))
        window_class = WindowClass()
        window_class.proc,window_class.instance,window_class.name = self.callback,instance,name
        if not user.RegisterClassW(ctypes.byref(window_class)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.hwnd = user.CreateWindowExW(0,name,name,0,0,0,0,0,None,None,instance,None)
            if not self.hwnd:
                raise ctypes.WinError(ctypes.get_last_error())
            icon = user.LoadImageW(None,self.icon_path,1,32,32,0x10)
            data.size,data.window,data.id,data.flags,data.message,data.icon = ctypes.sizeof(data),self.hwnd,1,7,0x8001,icon
            data.tip = self.translate('tray.tooltip')
            if not shell.Shell_NotifyIconW(0,ctypes.byref(data)):
                raise RuntimeError(self.translate('tray.create_failed'))
            self.ready.set()
            message = w.MSG()
            while user.GetMessageW(ctypes.byref(message),None,0,0) > 0:
                user.TranslateMessage(ctypes.byref(message))
                user.DispatchMessageW(ctypes.byref(message))
        finally:
            shell.Shell_NotifyIconW(2,ctypes.byref(data))
            if data.icon:
                user.DestroyIcon(data.icon)
            user.UnregisterClassW.argtypes = [w.LPCWSTR,w.HINSTANCE]
            user.UnregisterClassW(name,instance)
            self.hwnd = None

    def refresh_language(self):
        """Only update the existing icon; native calls stay on its message thread."""
        if self.hwnd:
            user = ctypes.WinDLL('user32')
            user.PostMessageW.argtypes = [w.HWND,w.UINT,w.WPARAM,w.LPARAM]
            user.PostMessageW(self.hwnd,0x8002,0,0)

    def close(self):
        """Post window closure to the icon thread and wait at most two seconds for it to exit."""
        if self.hwnd:
            user = ctypes.WinDLL('user32')
            user.PostMessageW.argtypes = [w.HWND,w.UINT,w.WPARAM,w.LPARAM]
            user.PostMessageW(self.hwnd,0x10,0,0)
        self.thread.join(timeout=2)
