"""Own suspended Windows process trees with kill-on-close Job Objects.

Worker and individual commands use separate guards. These native lifetime
controls support cancellation/shutdown; they are not an untrusted-code sandbox.
"""

import ctypes
from ctypes import wintypes


class BasicLimit(ctypes.Structure):
    """ctypes layout for basic Job Object limits consumed by the extended limit record."""
    _fields_ = [("user", ctypes.c_int64), ("job", ctypes.c_int64), ("flags", wintypes.DWORD),
                ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
                ("active", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]


class ExtendedLimit(ctypes.Structure):
    """ctypes layout for Job Object limits, including the kill-on-close flag."""
    _fields_ = [("basic", BasicLimit), ("io", ctypes.c_uint64*6),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


class Accounting(ctypes.Structure):
    """ctypes accounting layout used to query the number of active job processes."""
    _fields_ = [("times", ctypes.c_int64*4), ("faults", wintypes.DWORD),
                ("total", wintypes.DWORD), ("active", wintypes.DWORD), ("terminated", wintypes.DWORD)]


class ThreadEntry(ctypes.Structure):
    """ctypes Toolhelp thread-entry layout used to find suspended process threads."""
    _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("thread_id", wintypes.DWORD),
                ("process_id", wintypes.DWORD), ("priority", wintypes.LONG),
                ("delta", wintypes.LONG), ("flags", wintypes.DWORD)]


class ProcessGuard:
    """Own one native Job Object configured to kill members when its handle closes.

    Assign suspended children before resume. The owner must call close; process
    cleanup does not rely on a Python destructor.
    """
    def __init__(self):
        """Create and configure kill-on-close; close the native handle if setup fails."""
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                        wintypes.DWORD, ctypes.c_void_p]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimit()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, handle=None):
        """Assign a supplied native process handle, or the current process when omitted."""
        if not self.kernel.AssignProcessToJobObject(self.handle, handle or self.kernel.GetCurrentProcess()):
            raise ctypes.WinError(ctypes.get_last_error())

    def active(self):
        """Return the current Job Object active-process count, including descendants."""
        state = Accounting()
        if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(state), ctypes.sizeof(state), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return state.active

    def resume(self, process_id: int):
        # Popen closes its initial thread handle. Find that still-suspended thread
        # with public Win32 APIs; no executable code runs before job assignment.
        """Find and resume a thread of a process previously started suspended.

        The caller assigns the process to its guard first. Snapshot and temporary
        thread handles are closed on both success and failure.
        """
        self.kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.kernel.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        self.kernel.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        self.kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenThread.restype = wintypes.HANDLE
        self.kernel.ResumeThread.argtypes = [wintypes.HANDLE]
        self.kernel.ResumeThread.restype = wintypes.DWORD
        snapshot = self.kernel.CreateToolhelp32Snapshot(4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            found = self.kernel.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.process_id == process_id:
                    thread = self.kernel.OpenThread(2, False, entry.thread_id)
                    if not thread:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if self.kernel.ResumeThread(thread) == 0xffffffff:
                            raise ctypes.WinError(ctypes.get_last_error())
                        return
                    finally:
                        self.kernel.CloseHandle(thread)
                found = self.kernel.Thread32Next(snapshot, ctypes.byref(entry))
            raise RuntimeError("Startthread des Analyseprogramms nicht gefunden.")
        finally:
            self.kernel.CloseHandle(snapshot)

    def close(self):
        """Close this guard once; kill-on-close ends any remaining Job Object members."""
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
