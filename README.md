# Post-Processing-Magic

Lokale, konfigurierbare Nachbearbeitung von ZIP-Evidencen unter Windows.

**Version 0.40.0:** vereinfachte Forensik-Aufbereitung. Frühere Releases bleiben separat verfügbar.

[Windows-Releases](https://github.com/D3vasd4t0r/Post-Processing-Magic/releases) · [Änderungen 0.40](docs/releases/0.40.0.md) · [Architektur](docs/ARCHITECTURE.md) · [Konfiguration](docs/CONFIGURATION.md)

## Neu in 0.40

- Eine blaue Aufbereitungsoberfläche mit fünf Seiten: Aufbereitung, Einstellungen, Logs, Ergebnisse und Feedback. Quelle, ZIP-Format, Aufwand, Fallnummer und Gerätename direkt im Formular; kein Einfach/Fortgeschritten-Umschalter.
- Vier Einstellungskategorien: Tools, Modi, Allgemein und Konfiguration. Der bestehende Baukasten mit Toolreferenzen, Parametern und freien PowerShell-Blöcken bleibt erhalten.
- Logs über einen Auftragsdropdown, Status, Arbeitsordner und scrollbares Terminal. Auf der Hauptseite bleiben Fortschritt, Fehler und Abbruch erreichbar.
- Ergebnisse nach Auftrag mit Fall/Gerät, Datum und kurzer ID. Ergebnis-ZIP, HTML-/JSON-Bericht und hochgeladenes Original bleiben eindeutig zugeordnet. Lokale ZIPs erscheinen ausschließlich als geprüfte Referenz oder als nicht verfügbar.
- Berichte enthalten Verarbeitungsmetadaten, Eingangs-/Ausgangs-SHA-1/SHA-256 sowie begrenzte Datei-/Pfadlisten und Ordner-/Dateianzahlen. Keine Toolausgaben, Kommandozeilen oder internen Inhaltsbefunde in Berichten.
- Portabler Forensik-Konfigurationsexport als Schema 4. Frühere Konfigurationen werden mit Vorschau eingelesen; entfallene Bereiche erfordern eine zusätzliche ausdrückliche Bestätigung. Speichern und Import starten keine Befehle.
- Die interne Malware-Analyse wurde entfernt; historische Daten bleiben passiv erhalten. Keine automatische Wiederaufnahme alter Analysejobs.

CSV-/XLSX-Inhaltsvorschauen, externe Ergebnis-Viewer und interne Evidenzauswertungen wurden auf ausdrücklichen Nutzerwunsch entfernt. Nutzererzeugte Toolausgaben bleiben im Ergebnisarchiv erhalten, auch bei gleichnamigen Dateien in verschiedenen Ordnern.

## Funktionsumfang

**Windows-Dienst:** Eine EXE öffnet das Serverfenster und startet Server und separaten seriellen Worker. Browser über Button öffnen, Adresse und Access Token kopieren, Server geordnet stoppen oder den eigenen Prozessbaum nach Bestätigung beenden. X minimiert in den Infobereich. UAC-Administratorstart ist auf Nutzerwunsch Standard.

**ZIP-Aufbereitung:** Upload oder lokale ZIP-Referenz, Aufwand schnell/Medium/langsam, optionale Fallnummer/Gerät, eigener Arbeitsordner und unveränderlicher Konfigurationssnapshot pro Auftrag. ZIP mit Ordner C und Entpackziel Targets ergibt Targets/C. Keine Umbenennung interner Archivpfade. Originaldateien bleiben unverändert.

**Baukasten:** Tools mit absolutem Serverpfad und Picker verwalten. Modi in Import, Verarbeitung und Export gliedern; Befehlsblöcke einfügen, verschieben und entfernen. Aktueller Runner: höchstens ein Offline-KAPE-Befehl plus freie PowerShell-Blöcke oder reine PowerShell-Abläufe. Weitere generische Toolrunner sind nicht enthalten. Die bearbeitbare KAPE-Vorlage Medium/ohne Timeline benötigt eine bewusste Toolzuordnung.

**Status und Ergebnisse:** Persistente SQLite-Queue, SSE mit echten Ereignissen, Abbruch, geschützte Downloads und auftragsbezogene Ergebnis-/Arbeitsordner. Neue Browserläufe erstellen ein Ergebnis-ZIP; bei vorhandenen älteren Aufträgen ohne ZIP bleibt eine ausdrückliche nachträgliche Archivierung möglich. Der Ansichtswechsel startet keine neue Verarbeitung.

**Betrieb:** DE/EN, Arbeitsziel für neue Aufträge, Speicherübersicht, Warteschlangenpause, gezielte Bereinigung mit Vorschau/Bestätigung, Diagnosepaket mit Vorschau, technische Logrotation, lokale Feedbackablage/-export. Referenzierte Originale bleiben bei der Bereinigung erhalten.

**Limits:** Standardmäßig 50 GiB Upload und 2 TB dezimal entpackt; unter Allgemein einstellbar und pro Auftrag eingefroren. Hohe Kompression ist für neue Aufträge erlaubt, ohne Checkbox. Pfad-, Mengen-, Größen-, Speicher- und Verschachtelungsgrenzen gelten weiterhin. Keine Unterstützung verschlüsselter oder beliebig großer ZIPs.

**Grenzen:** Ausschließlich ZIP-Eingänge mit KAPE-Targets. Keine E01-/VMDK-Verarbeitung, internen Malwareparser oder Ausführung von Eingangsdateien. Toolprogramme sind separat bereitzustellen/lizenzieren. Tools und freie PowerShell laufen mit den gewählten Administratorrechten und sind keine Sandbox. Fachliche Vollständigkeit ihrer Ergebnisse muss der Nutzer prüfen.

## Windows starten

1. Das Windows-ZIP des gewünschten Releases vollständig entpacken.
2. PostProcessingMagic.exe doppelklicken und Windows-UAC bestätigen.
3. Im Serverfenster Browser öffnen anklicken. Der aktuelle Access Token wird automatisch verwendet und lässt sich im Fenster kopieren.

Kein Python, Node, Docker, Redis oder Internet auf dem Zielrechner erforderlich. Standardadresse http://127.0.0.1:8765/, sofern kein anderer Port gespeichert ist. Daten standardmäßig unter LOCALAPPDATA/PostProcessingMagic oder im explizit gewählten Datenordner, niemals im EXE-Entpackverzeichnis.

LAN-Zugriff ist für vertrauenswürdige Netze vorgesehen und verwendet Authentifizierung sowie automatisch erzeugtes selbstsigniertes HTTPS. Keine automatische Firewall- oder Trust-Store-Änderung. Nach jedem Start gilt ein neuer Token.

## Entwicklung

Python 3.12+ unter Windows:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\build.ps1 -OutputDirectory dist/release
```

Ein erfolgreicher Python-Test ersetzt keine EXE-Abnahme. Die Releaseprüfung startet die gebaute Windows-EXE mit ausschließlich eigenen synthetischen ZIPs und Programmen; echte Evidenzen werden nur durch einen bewussten Nutzerlauf verarbeitet.

## Prüfung dieses Releases

Lokal 317 Tests bestanden, zwei Symlink-Berechtigungstests übersprungen; Ruff und JavaScript-Syntax erfolgreich. Sieben Prüfgruppen mit der gebauten Windows-EXE erfolgreich: Start, Workflow/Archive/Bereinigung, Stop/Abbruch, Wartung/HTTPS, KAPE-Dateinachweise, Konfiguration sowie Quellen/Metadatenberichte. Eigene synthetische Browserläufe, DE/EN und 390-px-Darstellung geprüft. Das ersetzt keine fachliche Nutzerabnahme echter KAPE-Ergebnisse oder einen Test mit tatsächlich 2 TB Daten.
