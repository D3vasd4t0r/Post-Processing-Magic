
import argparse
import json
import logging
import os
import secrets
import socket
import ssl
import sys
import threading
import webbrowser
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import uvicorn

from forensic_app.api import create_app
from forensic_app.app_errors import AppValueError
from forensic_app.certificates import ensure_certificate
from forensic_app.server_preferences import PreferenceStore, prune_server_logs
from forensic_app.storage import InstanceLock, Storage, default_data_dir
from forensic_app.windows_access import elevate, is_admin

logger = logging.getLogger(__name__)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Post-Processing-Magic Webserver")
    result.add_argument("--data-dir", type=Path, default=default_data_dir())
    result.add_argument("--port", type=int, default=8765)
    result.add_argument("--no-browser", action="store_true")
    result.add_argument('--headless',action='store_true',help='Nur Server ohne Desktopfenster starten')
    result.add_argument('--control-id',default='',help=argparse.SUPPRESS)
    access = result.add_mutually_exclusive_group()
    access.add_argument("--lan", action="store_true", help="LAN mit automatischem Self-Signed-HTTPS")
    access.add_argument('--local',dest='lan',action='store_false',help='Nur auf diesem Rechner erreichbar')
    result.set_defaults(lan=False)
    result.add_argument("--tls-cert", type=Path)
    result.add_argument("--tls-key", type=Path)
    result.add_argument("--test-no-admin", action="store_true", help=argparse.SUPPRESS)
    return result


def validate(args: argparse.Namespace) -> None:
    if not 1 <= args.port <= 65535:
        raise AppValueError('error.28b81d33d4c1')
    if bool(args.tls_cert) != bool(args.tls_key):
        raise AppValueError('error.939fe0f7951c')
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)


def open_when_ready(
    url: str, token: str, stop: threading.Event, certificate: Path | None = None
) -> None:
    context = ssl.create_default_context(cafile=str(certificate)) if certificate else None
    for _ in range(80):
        if stop.wait(0.25):
            return
        try:
            # Trust only the configured certificate for local readiness; never disable validation.
            with urlopen(url + "/health", timeout=0.5, context=context) as response:
                if response.status == 200:
                    webbrowser.open(url + "/#token=" + token)
                    return
        except (URLError, OSError):
            continue
    logger.warning("Browserstart nicht möglich. Serveradresse manuell öffnen: %s", url)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate(args)
        if not args.test_no_admin and not is_admin():
            elevate(list(argv) if argv is not None else sys.argv[1:])
            print("Windows-UAC bestätigen; der Server startet anschließend mit Administratorrechten.")
            return 0
        explicit = list(argv) if argv is not None else sys.argv[1:]
        preferences,_ = PreferenceStore(Storage(args.data_dir.expanduser().resolve())).get()
        if not any(item == '--port' or item.startswith('--port=') for item in explicit):
            args.port = preferences.port
        if '--lan' not in explicit and '--local' not in explicit:
            args.lan = preferences.lan
        validate(args)
        if os.name == 'nt' and not args.headless and not args.no_browser:
            from forensic_app.desktop import run_panel
            return run_panel(args)
        storage = Storage(args.data_dir.expanduser().resolve())
        with InstanceLock(storage.root):
            storage.initialize()
            preferences,_ = PreferenceStore(storage).get()
            prune_server_logs(storage,preferences.log_backups)
            if args.lan and not args.tls_cert:
                args.tls_cert, args.tls_key = ensure_certificate(storage.root / "config" / "tls")
            handler = RotatingFileHandler(
                storage.root / "logs" / "server.log",
                maxBytes=preferences.log_max_bytes,
                backupCount=preferences.log_backups,
                encoding="utf-8",
            )
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s %(levelname)s %(message)s",
                handlers=[handler,*([logging.StreamHandler()] if sys.stderr is not None else [])],
                force=True,
            )
            host = "0.0.0.0" if args.lan else "127.0.0.1"
            scheme = "https" if args.tls_cert else "http"
            url = f"{scheme}://127.0.0.1:{args.port}"
            # Bind once and pass the socket to Uvicorn. No check-then-bind port race.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind((host, args.port))
                sock.listen(128)
                token = secrets.token_urlsafe(32)
                token_path = storage.root / "config" / "access-token.txt"
                token_path.write_text(token + "\n", encoding="utf-8")
                logger.info("Server: %s | Token-Datei: %s", url, token_path)
                if args.lan:
                    logger.info(
                        "LAN: https://%s:%s | Zertifikat: %s",
                        socket.gethostname(), args.port, args.tls_cert,
                    )
                    logger.info("Self-Signed: Browser-Vertrauen muss auf jedem Gerät bestätigt werden.")
                logger.info('Server gestartet. Steuerung über Serverfenster oder Weboberfläche.')
                config = uvicorn.Config(
                    create_app(storage, token, lan=args.lan, processing=True, test_no_admin=args.test_no_admin,
                               on_shutdown=lambda: setattr(server, "should_exit", True),control_id=args.control_id,
                               runtime={'port':args.port,'lan':args.lan,'log_max_bytes':preferences.log_max_bytes,'log_backups':preferences.log_backups}),
                    host=host,
                    port=args.port,
                    workers=1,
                    loop="asyncio",
                    http="h11",
                    ws="none",
                    proxy_headers=False,
                    access_log=False,log_config=None,
                    ssl_certfile=str(args.tls_cert) if args.tls_cert else None,
                    ssl_keyfile=str(args.tls_key) if args.tls_key else None,
                )
                stop = threading.Event()
                browser_thread = None
                if not args.no_browser:
                    browser_thread = threading.Thread(
                        target=open_when_ready, args=(url, token, stop, args.tls_cert), daemon=True
                    )
                    browser_thread.start()
                try:
                    server = uvicorn.Server(config)
                    server.run(sockets=[sock])
                finally:
                    stop.set()
                    if browser_thread:
                        browser_thread.join(timeout=2)
            return 0
    except (OSError, RuntimeError, ValueError) as exc:
        if args.headless and args.control_id:
            try:
                directory = args.data_dir.expanduser().resolve()/'logs'
                directory.mkdir(parents=True,exist_ok=True)
                (directory/'desktop-startup-error.json').write_text(
                    json.dumps({'control_id':args.control_id,'message':str(exc),
                                **({'error_code':exc.text.code,'error_params':exc.text.params}
                                   if isinstance(exc,AppValueError) else {})},ensure_ascii=False),encoding='utf-8')
            except OSError:
                pass
        print(f"Start fehlgeschlagen: {exc}")
        return 1
    finally:
        logging.shutdown()

