"""Single persistent-queue consumer. Never invoked from an HTTP request."""

import copy
import hashlib
import json
import logging
import os
import queue
import subprocess
import threading
import time
from pathlib import Path, PureWindowsPath

from forensic_app.app_errors import AppValueError
from forensic_app.artifacts import ArchiveQueue, make_archive, prepare_report, utc
from forensic_app.jobs import JobStore
from forensic_app.kape_plan import sha256_file
from forensic_app.modes import MAX_COMMAND_TIMEOUT_SECONDS
from forensic_app.process_guard import ProcessGuard
from forensic_app.processing_settings import ProcessingLimits
from forensic_app.queue_control import QueueControl
from forensic_app.static_analysis import prepare_sample, run_static
from forensic_app.storage import Storage
from forensic_app.windows_access import input_identity, is_admin, locked_input
from forensic_app.workspaces import job_paths
from forensic_app.zip_safety import ensure_space, extract_checked

MAX_LOG_BYTES = 16*1024**2
MAX_RUN_SECONDS = 24*60*60
logger = logging.getLogger(__name__)


class Cancelled(Exception):
    pass


class Interrupted(Exception):
    pass


def relative_path(value):
    return Path(*PureWindowsPath(value).parts)


def execute(plan, work: Path, check, emit):
    timeout_seconds = plan.get("timeout_seconds", MAX_RUN_SECONDS)
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_COMMAND_TIMEOUT_SECONDS:
        raise AppValueError('error.9c2c0a47b7e5')
    if not is_admin() and not plan.get("test_no_admin"):
        raise PermissionError("KAPE benötigt Administratorrechte. App neu starten und Windows-UAC bestätigen.")
    if sha256_file(Path(plan["tool"]["path"])) != plan["tool"]["sha256"]:
        raise AppValueError('error.2031fed8cf82')
    guard, process = ProcessGuard(), None
    chunks, started = queue.Queue(maxsize=256), time.monotonic()
    reader_stop, reader_thread = threading.Event(), None
    try:
        env = dict(os.environ)
        env["PATH"] = str(Path(plan["tool"]["path"]).parent)+os.pathsep+env.get("PATH", "")
        process = subprocess.Popen(plan["argv"], cwd=work, shell=False, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x4)  # CREATE_SUSPENDED
        guard.assign(int(process._handle))
        guard.resume(process.pid)

        def reader():
            def send(value):
                while not reader_stop.is_set():
                    try:
                        chunks.put(value, timeout=0.25)
                        return
                    except queue.Full:
                        continue
            try:
                while not reader_stop.is_set() and (chunk := os.read(process.stdout.fileno(), 4096)):
                    send(chunk)
            except OSError:
                pass
            finally:
                send(None)
        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()
        ended, length, truncated = False, 0, False
        while True:
            check()
            if time.monotonic()-started > timeout_seconds:
                raise AppValueError('error.4186d8e12fb2', p0=f'{timeout_seconds}')
            try:
                chunk = chunks.get(timeout=0.25)
                if chunk is None:
                    ended = True
                elif length < MAX_LOG_BYTES:
                    data = chunk[:MAX_LOG_BYTES-length]
                    length += len(data)
                    emit(data.decode("utf-8", errors="replace"))
                elif not truncated:
                    emit("\n[Live-Loglimit erreicht; weitere Toolausgabe wird verworfen.]\n")
                    truncated = True
            except queue.Empty:
                pass
            if process.poll() is not None and ended and guard.active() == 0:
                return process.returncode
            if int(time.monotonic()-started) % 10 == 0:
                ensure_space(work)
    finally:
        reader_stop.set()
        guard.close()  # Also terminates remaining descendants on error, cancellation or timeout.
        if process:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if reader_thread:
                reader_thread.join(timeout=2)
            process.stdout.close()


def process_job(store: JobStore, ident: str, plan: dict, stop, runner=execute):
    command_runs = []

    def check():
        if stop.is_set():
            raise Interrupted("Server wird beendet. Auftrag wird nicht automatisch wiederholt.")
        if store.get(ident)["cancel_requested"]:
            raise Cancelled("Aufbereitung wurde abgebrochen.")

    try:
        root,work,_ = job_paths(store.storage,plan,ident)
        check()
        work.mkdir(exist_ok=False)
        # Snapshot stays outside PostMortem; packaged audit is added only to the result archive.
        (work / "configuration.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        if plan.get('workspace') == 'malware':
            from forensic_app.malware_modes import compile_static, implementation_hash
            expected = compile_static(plan['mode'])
            if plan['tool'].get('sha256') != implementation_hash():
                raise AppValueError('error.ef104abdc111')
            if [(c.get('kind'),c.get('inspector'),c.get('id')) for c in plan.get('commands',[])] != [(c['kind'],c['inspector'],c['id']) for c in expected['commands']]:
                raise AppValueError('error.874f67cead3e')
            store.update(ident,status='running',phase='Einzeldatei prüfen, kopieren und hashen')
            plan = copy.deepcopy(plan)
            plan['static_input'] = prepare_sample(store,ident,plan,work,check)
        else:
            store.update(ident, status="running", phase="ZIP prüfen und entpacken")
            target = work / relative_path(plan["mode"]["extract_folder"])
            limits = ProcessingLimits.model_validate(plan.get("limits", {}))
            def extract(archive):
                extract_checked(archive, target, check, lambda text: store.log(ident, text+"\n"),
                                allow_high_compression=plan.get("allow_high_compression", False), max_extract_bytes=limits.max_extract_bytes)
            if plan.get("source_kind") == "local":
                local = plan["local_input"]
                archive_path = Path(local["path"])
                store.update(ident, phase="Lokale ZIP prüfen und hashen")
                with locked_input(archive_path) as original:
                    if input_identity(original) != {key: local[key] for key in ("size", "mtime_ns", "device", "inode")}:
                        raise AppValueError('error.750bf3977c9b')
                    checksum, sha1, read, reported = hashlib.sha256(), hashlib.sha1(), 0, 0
                    while chunk := original.read(8*1024**2):
                        check()
                        checksum.update(chunk)
                        sha1.update(chunk)
                        read += len(chunk)
                        if read-reported >= 256*1024**2:
                            store.update(ident, phase=f"Lokale ZIP hashen: {read/1024**3:.1f}/{local['size']/1024**3:.1f} GiB")
                            reported = read
                    store.update(ident, input_sha256=checksum.hexdigest(), input_sha1=sha1.hexdigest(), phase="ZIP prüfen und entpacken")
                    extract(archive_path)
            else:
                extract(root / "evidence" / ident / "Evidence.zip")
            from forensic_app.artifact_inventory import collect_inventory
            # Capture only the freshly extracted tree before any configured command.
            inventory = collect_inventory(target,check=check)
            store.update(ident,input_inventory_json=json.dumps(inventory,ensure_ascii=False))
            source = work / relative_path(plan["source"])
            if not source.is_dir():
                configured = PureWindowsPath(plan["source"])
                extraction = PureWindowsPath(plan["mode"]["extract_folder"])
                drives = [path for path in target.iterdir() if len(path.name) == 1 and path.name.isascii() and path.name.isalpha()
                          and path.is_dir() and not path.is_symlink() and not path.is_junction()]
                if configured.parent == extraction and len(configured.name) == 1 and len(drives) == 1:
                    plan = copy.deepcopy(plan)
                    resolved = str(extraction / drives[0].name)
                    plan["source_resolution"] = {"configured": plan["source"], "effective": resolved}
                    plan["source"] = resolved
                    plan["argv"][plan["argv"].index("--msource")+1] = ".\\"+resolved
                    plan["command"] = subprocess.list2cmdline(plan["argv"])
                    for command in plan.get("commands", []):
                        if command.get("kind") == "kape":
                            command["source"] = resolved
                            command["argv"][command["argv"].index("--msource")+1] = ".\\"+resolved
                            command["command"] = subprocess.list2cmdline(command["argv"])
                    if plan.get("commands"):
                        plan["command"] = "\n\n".join(command["command"] for command in plan["commands"])
                    source = drives[0]
                    store.log(ident, f"Laufwerksordner automatisch erkannt: {configured} → {resolved}. Archivnamen unverändert.\n")
                else:
                    found = ", ".join(path.name for path in drives) or "keine einzelnen Laufwerksordner"
                    raise AppValueError('error.b123dfe0057a', p0=f"{plan['source']}", p1=f'{found}')
        store.update(ident, effective_json=json.dumps(plan, ensure_ascii=False))
        (work / "effective-configuration.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        check()
        with (work / "command.log").open("w", encoding="utf-8") as log:
            emitted, truncated = 0, False
            def emit(text):
                nonlocal emitted, truncated
                encoded = text.encode("utf-8")
                if emitted >= MAX_LOG_BYTES:
                    if not truncated:
                        notice = "\n[Job-Loglimit 16 MiB erreicht; weitere Ausgabe wird verworfen.]\n"
                        log.write(notice)
                        store.log(ident, notice)
                        truncated = True
                    return
                bounded = encoded[:MAX_LOG_BYTES-emitted].decode("utf-8", errors="ignore")
                emitted += len(encoded)
                log.write(bounded)
                log.flush()
                store.log(ident, bounded)
            commands = plan.get("commands") or [plan]
            for index, command in enumerate(commands):
                check()
                directory = work / relative_path(command.get("working_directory", "."))
                if not directory.is_dir() or not directory.resolve().is_relative_to(work.resolve()):
                    raise AppValueError('error.561271236d4d', p0=f'{index + 1}', p1=f'{directory}')
                executable = dict(plan, **command)
                executable["test_no_admin"] = plan.get("test_no_admin", False)
                title = "Statische Prüfung" if command.get("kind") == "static" else "PowerShell" if command.get("kind") == "powershell" else "KAPE"
                store.update(ident, phase=title+" läuft", current_step=index, exit_code=None)
                emit(f"\nBefehl {index+1}/{len(commands)}: {command.get('name',title)}\nAufruf: {command['command']}\nArbeitsordner: {directory}\n")
                timing = {'index':index+1,'name':command.get('name',title),'command':command['command'],
                          'tool':command['tool'],'started_at_utc':utc(),'ended_at_utc':None,'exit_code':None}
                command_runs.append(timing)
                try:
                    code = run_static(executable,work,check,emit) if command.get('kind')=='static' else runner(executable, directory, check, emit)
                    timing['exit_code'] = code
                finally:
                    timing['ended_at_utc'] = utc()
                emit(f"\nBefehl {index+1}/{len(commands)} beendet, Exitcode {code}.\n")
                store.update(ident, exit_code=code)
                if title == "KAPE" and "administrator privileges not found" in store.get(ident)["log_tail"].casefold():
                    raise PermissionError(f"KAPE meldet fehlende Administratorrechte trotz Exitcode {code}. App neu starten und Windows-UAC bestätigen.")
                if code != 0:
                    raise AppValueError('error.022f1781e603', p0=f'{title}', p1=f'{index + 1}', p2=f'{code}')
                store.update(ident, completed=index+1)
        check()
        store.update(ident, phase="Ergebnis prüfen und Abschlussbericht erstellen")
        report = prepare_report(store,ident,plan,command_runs)
        if plan.get('create_zip',True):
            store.update(ident,phase="Ergebnis zippen und hashen")
            make_archive(store,ident,plan,report,check)
        store.update(ident, status="succeeded", phase="Abgeschlossen")
    except Cancelled as exc:
        store.update(ident, status="cancelled", phase="Abgebrochen", error=str(exc))
    except Interrupted as exc:
        store.update(ident, status="interrupted", phase="Unterbrochen", error=str(exc))
    except Exception as exc:
        logger.exception("Aufbereitung %s fehlgeschlagen", ident)
        store.fail(ident, exc)
    finally:
        state = store.get(ident)
        if state['status'] != 'succeeded':
            try:
                prepare_report(store,ident,plan,command_runs,error=state['error'] or state['status'])
            except Exception:
                logger.exception('Fehlerbericht für %s konnte nicht geschrieben werden',ident)


def worker_main(root: str, stop):
    # Assign the worker before starting any tools. Every descendant inherits this job;
    # a killed worker closes its handle and the OS terminates the entire remaining tree.
    lifetime = ProcessGuard()
    lifetime.assign()
    store = JobStore(Storage(Path(root)))
    queue_control = QueueControl(store.storage)
    while not stop.is_set():
        row = queue_control.claim()
        if row:
            process_job(store, row[0], json.loads(row[1]), stop)
        else:
            archive = ArchiveQueue(store)
            ident = archive.claim()
            if ident:
                archive.run(ident,stop)
            else:
                stop.wait(0.25)
