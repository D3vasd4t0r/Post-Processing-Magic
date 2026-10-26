"""Windows elevation, desktop shell access and original-file read handles.

Elevation uses the normal UAC flow. Read sharing controls file lifetime, not
content validity or process isolation; other-platform reads are ordinary binary
file contexts used by tests.
"""

import ctypes
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


def is_admin() -> bool:
    """Return whether the current Windows process has administrator privileges."""
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def interactive_desktop() -> bool:
    """Check for a non-service Windows session with an available desktop shell window."""
    if os.name != "nt":
        return False
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    session = wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)) or session.value == 0:
        return False
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.GetShellWindow.restype = wintypes.HWND
    return bool(user.GetShellWindow())


def open_explorer(folder: Path):
    # Ask the desktop shell directly, rather than spawning another elevated explorer.
    """Ask the interactive Windows shell to reveal a folder through COM shell APIs.

    The caller validates authorization and folder boundaries. No result file is
    executed here; allocated shell memory and successful COM initialization are
    released on every return path.
    """
    from ctypes import wintypes
    ole = ctypes.WinDLL('ole32', use_last_error=True)
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p,wintypes.DWORD]
    ole.CoInitializeEx.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    initialized = ole.CoInitializeEx(None,2)
    if initialized < 0 and initialized != -2147417850:
        raise OSError(f'COM-Initialisierung fehlgeschlagen: 0x{initialized & 0xffffffff:08X}')
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.SHParseDisplayName.argtypes = [ctypes.c_wchar_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p),wintypes.DWORD,ctypes.c_void_p]
    shell.SHParseDisplayName.restype = ctypes.c_long
    shell.SHOpenFolderAndSelectItems.argtypes = [ctypes.c_void_p,wintypes.UINT,ctypes.c_void_p,wintypes.DWORD]
    shell.SHOpenFolderAndSelectItems.restype = ctypes.c_long
    item = ctypes.c_void_p()
    try:
        result = shell.SHParseDisplayName(str(folder),None,ctypes.byref(item),0,None)
        if result >= 0:
            result = shell.SHOpenFolderAndSelectItems(item,0,None,0)
        if result < 0:
            raise OSError(f'Explorer meldet HRESULT 0x{result & 0xffffffff:08X}.')
    finally:
        if item.value:
            ole.CoTaskMemFree(item)
        if initialized >= 0:
            ole.CoUninitialize()


def elevate(arguments: list[str]):
    """Request UAC relaunch of the frozen EXE or Python module with supplied arguments.

    Refusal or shell failure raises PermissionError. There is no silent
    non-elevated fallback and no firewall change in this function.
    """
    parameters = arguments if getattr(sys, "frozen", False) else ["-m", "forensic_app", *arguments]
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                   ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    result = shell.ShellExecuteW(None, "runas", sys.executable, subprocess.list2cmdline(parameters), str(Path.cwd()), 0)
    if not result or result <= 32:
        raise PermissionError("Administratorstart wurde abgebrochen oder verweigert. EXE erneut starten und UAC bestätigen.")


@contextmanager
def locked_input(path: Path):
    """Yield a binary read handle for an existing original file.

    Windows FILE_SHARE_READ excludes concurrent writers and deletion while open.
    Other platforms use an ordinary read context, not an equivalent lock. Callers
    separately validate paths and captured file identity.
    """
    if os.name != "nt":
        with path.open("rb") as source:
            yield source
        return
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(descriptor, "rb") as source:
        yield source


def input_identity(source) -> dict:
    """Return size, mtime, device and inode from an open handle, not a content hash."""
    state = os.fstat(source.fileno())
    return {"size": state.st_size, "mtime_ns": state.st_mtime_ns, "device": state.st_dev, "inode": state.st_ino}
