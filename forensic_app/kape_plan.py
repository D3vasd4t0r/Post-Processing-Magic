"""Conservative first execution profile: one offline KAPE module command."""

import base64
import ctypes
import hashlib
import os
import re
import subprocess
from pathlib import Path, PureWindowsPath

from forensic_app.app_errors import AppValueError
from forensic_app.modes import ModeDraft


def windows_arguments(parameters: str) -> list[str]:
    if os.name != "nt":
        raise AppValueError('error.27bf8611e0e8')
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    count = ctypes.c_int()
    values = shell.CommandLineToArgvW('"kape.exe" '+parameters, ctypes.byref(count))
    if not values:
        raise AppValueError('error.1f5f5487c96e')
    try:
        return [values[index] for index in range(1, count.value)]
    finally:
        kernel.LocalFree(values)


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def file_version(path: str) -> str:
    # Read PE version resources without starting the configured executable.
    class FixedInfo(ctypes.Structure):
        _fields_ = [(key, ctypes.c_uint32) for key in (
            "signature", "structure", "version_ms", "version_ls", "product_ms", "product_ls",
            "mask", "flags", "os", "type", "subtype", "date_ms", "date_ls")]
    try:
        lib = ctypes.WinDLL("version", use_last_error=True)
        lib.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
        lib.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        lib.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
        length = lib.GetFileVersionInfoSizeW(path, None)
        if not length or length > 1024*1024:
            return "keine PE-Versionsangabe"
        buffer = ctypes.create_string_buffer(length)
        pointer, size = ctypes.c_void_p(), ctypes.c_uint32()
        if not lib.GetFileVersionInfoW(path, 0, length, buffer):
            return "nicht lesbar"
        if not lib.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(size)):
            return "keine PE-Versionsangabe"
        info = ctypes.cast(pointer, ctypes.POINTER(FixedInfo)).contents
        return f"{info.version_ms >> 16}.{info.version_ms & 65535}.{info.version_ls >> 16}.{info.version_ls & 65535}"
    except (OSError, AttributeError):
        return "nicht verfügbar"


def compile_kape(mode: dict, tools: list[dict], *, capture: bool = False) -> dict:
    draft = ModeDraft.model_validate({key: value for key, value in mode.items()
                                    if key not in ("id", "status", "executable", "slot_conflict")})
    if len(draft.steps) != 1:
        raise AppValueError('error.28da36bd6f71')
    step = draft.steps[0]
    if step.working_directory != ".":
        raise AppValueError('error.528a1bcb67d3')
    tool = next((tool for tool in tools if tool["id"] == step.tool_id), None)
    if not tool:
        raise AppValueError('error.f27263d34004')
    executable = Path(tool["path"])
    if executable.name.casefold() != "kape.exe" or not executable.is_file():
        raise AppValueError('error.0d45f3f03bf5')
    args = windows_arguments(step.parameters)
    options, index = {}, 0
    while index < len(args):
        key = args[index]
        if key in options or key not in ("--msource", "--mdest", "--module", "--gui"):
            raise AppValueError('error.a52600b8ab5b')
        if key == "--gui":
            options[key] = True
        else:
            index += 1
            if index >= len(args) or args[index].startswith("--"):
                raise AppValueError('error.d59815959f30', p0=f'{key}')
            options[key] = args[index]
        index += 1
    if not all(key in options for key in ("--msource", "--mdest", "--module")):
        raise AppValueError('error.1f3c4c853f4e')
    source = ModeDraft.job_relative_folder(options["--msource"])
    output = ModeDraft.job_relative_folder(options["--mdest"])
    if not PureWindowsPath(source).is_relative_to(PureWindowsPath(draft.extract_folder)):
        raise AppValueError('error.f098f659e8d6')
    if PureWindowsPath(output) != PureWindowsPath(draft.output_folder):
        raise AppValueError('error.24811225fc18')
    if not re.fullmatch(r"[A-Za-z0-9_!$.-]+(?:,[A-Za-z0-9_!$.-]+)*", options["--module"]):
        raise AppValueError('error.22add3add444')
    result = {"mode": {"id": mode["id"], **draft.model_dump()}, "tool": dict(tool),
              "argv": [str(executable), *args], "source": source,
              "command": subprocess.list2cmdline([str(executable), *args])}
    if capture:
        result["tool"]["sha256"] = sha256_file(executable)
        result["tool"]["version"] = file_version(str(executable))
    return result


def compile_plan(mode: dict, tools: list[dict], *, capture: bool = False) -> dict:
    draft = ModeDraft.model_validate({key: value for key, value in mode.items()
                                    if key not in ("id", "status", "executable", "slot_conflict")})
    if not draft.steps:
        raise AppValueError('error.ac5ae690f7df')
    if sum(step.type == "tool" for step in draft.steps) > 1:
        raise AppValueError('error.df194ce02a33')
    commands, engine = [], None
    for step in draft.steps:
        if step.type == "tool":
            single = {"id": mode["id"], **draft.model_dump(), "steps": [step.model_dump()]}
            compiled = compile_kape(single, tools, capture=capture)
            command = {key: compiled[key] for key in ("tool", "argv", "command", "source")}
            command["kind"] = "kape"
        else:
            if not step.script.strip():
                raise AppValueError('error.637e83bc5e94', p0=f'{step.name}')
            if engine is None:
                path = Path(os.environ.get("SystemRoot", r"C:\Windows"))/"System32"/"WindowsPowerShell"/"v1.0"/"powershell.exe"
                if not path.is_file():
                    raise AppValueError('error.73c675c5acca')
                engine = {"id": "builtin-powershell", "name": "Windows PowerShell", "path": str(path)}
                if capture:
                    engine.update(sha256=sha256_file(path), version=file_version(str(path)))
            wrapper = ("$ProgressPreference = 'SilentlyContinue'; "
                       "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
                       "$OutputEncoding = [Console]::OutputEncoding; $ErrorActionPreference = 'Stop'; "
                       "$global:LASTEXITCODE = 0; try { . {\n"+step.script+
                       "\n}; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; exit 0 } "
                       "catch { [Console]::Error.WriteLine($_.ToString()); [Console]::Error.WriteLine($_.ScriptStackTrace); exit 1 }")
            encoded = base64.b64encode(wrapper.encode("utf-16-le")).decode("ascii")
            argv = [engine["path"], "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", encoded]
            if len(subprocess.list2cmdline(argv)) > 30000:
                raise AppValueError('error.11f0109d3ff7')
            command = {"kind": "powershell", "tool": dict(engine), "argv": argv,
                       "command": 'PowerShell -NoProfile -NonInteractive\n'+step.script}
        command.update(id=step.id, name=step.name, working_directory=step.working_directory,
                       timeout_seconds=step.timeout_seconds)
        commands.append(command)
    primary = next((command for command in commands if command["kind"] == "kape"), commands[0])
    return {"mode": {"id": mode["id"], **draft.model_dump()}, "commands": commands,
            "tool": primary["tool"], "argv": primary["argv"], "source": primary.get("source", draft.extract_folder),
            "command": "\n\n".join(command["command"] for command in commands)}
