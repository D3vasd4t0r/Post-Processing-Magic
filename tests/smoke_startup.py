"""Real process/API smoke check; use only synthetic, newly created test directories.

python tests/smoke_startup.py
python tests/smoke_startup.py --exe dist/PostProcessingMagic.exe
"""

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    else:
        process.terminate()
    process.wait(timeout=15)


def get(url: str, token: str | None = None, context=None) -> tuple[int, bytes]:
    request = Request(url, headers={"Authorization": "Bearer " + token} if token else {})
    try:
        with urlopen(request, timeout=1, context=context) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--lan", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = root / ".local-data" / f"smoke-{time.time_ns()}"
    output.mkdir(parents=True)
    data = output / "data"
    command = [str(args.exe.resolve())] if args.exe else [sys.executable, "-m", "forensic_app"]
    command.append("--test-no-admin")
    if args.lan:
        command.append("--lan")
    port = free_port()
    base = f"{'https' if args.lan else 'http'}://127.0.0.1:{port}"
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    old_token = None
    checks = []
    context = None

    def fetch(path, token=None):
        return get(base + path, token, context=context)

    for attempt in range(2):
        with (output / f"server-{attempt}.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                command + ["--no-browser", "--port", str(port), "--data-dir", str(data)],
                cwd=root,
                stdout=log,
                stderr=log,
                creationflags=flags,
            )
            try:
                ready = False
                for _ in range(160):
                    if process.poll() is not None:
                        raise RuntimeError(f"Server beendet; Diagnose: {log.name}")
                    try:
                        if args.lan and context is None:
                            cert_path = data / "config" / "tls" / "server.crt"
                            if cert_path.exists():
                                context = ssl.create_default_context(cafile=str(cert_path))
                            else:
                                time.sleep(0.25)
                                continue
                        ready = fetch("/health")[0] == 200
                    except (URLError, TimeoutError, OSError):
                        pass
                    if ready:
                        break
                    time.sleep(0.25)
                assert ready, f"Server nicht bereit; Diagnose: {log.name}"
                token = (data / "config" / "access-token.txt").read_text().strip()
                assert fetch("/api/system")[0] == 401
                assert fetch("/api/system", "wrong")[0] == 401
                assert fetch("/api/system", token)[0] == 200
                status = json.loads(fetch("/api/system", token)[1])
                assert status["profiles"] == []
                assert status["capabilities"]["result_download"]
                page_status, page = fetch("/")
                assert page_status == 200 and "Startgerüst" in page.decode("utf-8")
                assert fetch("/state.sqlite3")[0] == 404
                assert fetch("/config/access-token.txt")[0] == 404
                assert fetch("/config/tls/server.key")[0] == 404
                assert fetch("/api/settings/tools")[0] == 401
                tools = json.loads(fetch("/api/settings/tools", token)[1])["tools"]
                if attempt == 0:
                    queue_request = Request(base+'/api/queue',data=b'{"paused":true}',method='PUT',
                                            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
                    with urlopen(queue_request,timeout=2,context=context) as response:
                        assert json.load(response)['paused']
                    payload = json.dumps({"name": "Smoke-Test", "path": str(output)}).encode()
                    request = Request(base + "/api/settings/tools", data=payload, method="POST",
                                      headers={"Authorization": "Bearer " + token,
                                               "Content-Type": "application/json"})
                    with urlopen(request, timeout=2, context=context) as response:
                        assert response.status == 201
                else:
                    assert json.loads(fetch('/api/queue',token)[1])['paused']
                    assert len(tools) == 1 and tools[0]["name"] == "Smoke-Test"
                if old_token:
                    assert token != old_token
                    assert fetch("/api/system", old_token)[0] == 401
                old_token = token
                duplicate = subprocess.run(
                    command + ["--no-browser", "--port", str(free_port()), "--data-dir", str(data)],
                    cwd=root, capture_output=True, timeout=45, creationflags=flags, check=False,
                )
                assert duplicate.returncode == 1, "Doppelte Instanz wurde nicht abgewiesen"
                checks.append(f"Start {attempt + 1}: Status, UI, Authentifizierung, Instanzsperre")
            finally:
                stop(process)
        # The first stop intentionally simulates an abrupt process-tree termination.
        time.sleep(0.5)
    with sqlite3.connect(data / "state.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM startup_events").fetchone()[0] == 2
    checks.append("Neustart nach hartem Stopp: Datenbank erhalten und Token erneuert")
    checks.append("Tool-Pfade werden geschützt gespeichert und bleiben nach Neustart erhalten")
    if args.lan:
        checks.append("Automatisches Self-Signed-HTTPS mit Zertifikatsprüfung über Loopback")
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        conflict = subprocess.run(
            command + ["--no-browser", "--port", str(occupied.getsockname()[1]),
                       "--data-dir", str(output / "port-conflict")],
            cwd=root, capture_output=True, timeout=45, creationflags=flags, check=False,
        )
        assert conflict.returncode == 1, "Portkonflikt wurde nicht abgewiesen"
    checks.append("Belegter Port führt zu kontrolliertem Startfehler")
    report = {
        "mode": "exe" if args.exe else "source",
        "transport": "https-self-signed" if args.lan else "http-loopback",
        "checks": checks,
        "limitations": ["Kein Browser-Autostarttest", "Kein LAN-/TLS-Test auf zweitem Gerät",
                        "Kein Test auf sauberem Windows ohne Python", "Keine Evidence-Verarbeitung"],
    }
    if args.exe:
        report["exe_sha256"] = hashlib.sha256(args.exe.read_bytes()).hexdigest()
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"passed": True, "report": str(report_path), "checks": len(checks)}))


if __name__ == "__main__":
    main()
