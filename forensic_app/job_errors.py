"""Actionable job failures; retain the actual stage and traceback for diagnostics."""

import traceback

from forensic_app.app_errors import AppValueError


def describe_error(exc: BaseException, stage: str) -> dict:
    original = str(exc).strip()
    kind = "ValueError" if isinstance(exc, AppValueError) else type(exc).__name__
    message = original or ("Upload-Verbindung wurde vor Abschluss getrennt." if kind == "ClientDisconnect"
                           else "Vorgang wurde abgebrochen oder die Verbindung unterbrochen.")
    hint = "Details und letzte Toolausgabe im Tab Logs prüfen."
    if isinstance(exc, PermissionError) or "Administrator privileges not found" in message:
        hint = "App neu starten und Windows-UAC bestätigen. Unter Dienststatus muss Administrator stehen; Datei-/Ordnerrechte ebenfalls prüfen."
    elif "Quellordner" in message:
        hint = "Laufwerksordner im ZIP und --msource im Modus prüfen. Bei mehreren Laufwerken den gewünschten Ordner explizit angeben."
    elif "Kompressionsverhältnis" in message:
        hint = "Bei einer bekannten eigenen Sicherung die Option 'Hohe Kompression zulassen' aktivieren und einen neuen Lauf starten."
    elif "Speicher" in message or getattr(exc, "winerror", None) == 112 or getattr(exc, "errno", None) == 28:
        hint = "Speicherplatz auf dem Laufwerk des Datenordners freigeben. Für entpackte Daten und Ergebnis-ZIP wird zusätzlicher Platz benötigt."
    elif kind in ("ClientDisconnect", "CancelledError"):
        hint = "Für große ZIPs Quelle 'Lokale Datei auf dem Server' verwenden; der Browserupload entfällt."
    elif kind == "BadZipFile":
        hint = "ZIP auf Vollständigkeit prüfen; geteilte oder beschädigte Archive werden nicht verarbeitet."
    return {**({"error_code":exc.text.code,"error_params":exc.text.params} if isinstance(exc, AppValueError) else {}), "type": kind, "phase": stage, "message": message, "recommendation": hint,
            "traceback": "".join(traceback.format_exception(exc))[-16000:]}
