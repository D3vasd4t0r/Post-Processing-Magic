# Post-Processing-Magic

KI-gestütztes Entwicklungsprojekt für die lokale Nachbearbeitung von DFIR-Evidencen unter Windows.

**Dieser Entwicklungszweig: 0.25.1, experimentelle statische Malware-Analyse.** Die Versionen 0.24.0 und 0.25.0 bleiben separat verfügbar. Das Serverfenster aus 0.20 ist bereits erfolgreich abgenommen.

[Windows-Downloads und Releases](https://github.com/D3vasd4t0r/Post-Processing-Magic/releases) · [Änderungen 0.25.1](docs/releases/0.25.1.md) · [Roadmap](docs/ROADMAP.md) · [Architektur](docs/ARCHITECTURE.md)

## Neu in 0.25.1 – zentrale Einstellungen und eine Konfigurationsdatei

- Einstellungen gelten unabhängig vom aktiven Arbeitsbereich: **Tools**, **Allgemein** und **Konfiguration** gemeinsam; **Forensik-Modi** und **Malware-Module** in eigenen, jederzeit erreichbaren Kategorien.
- Nur auf der Hauptseite zwischen blauem Forensik- und rotem Malware-Bereich wechseln. Die Einstellungen zeigen immer dieselbe gemeinsame Ansicht und merken die zuletzt gewählte Kategorie.
- Ein Export enthält immer Tools, gemeinsame Verarbeitungslimits, Forensik-Modi und Malware-Module als Schema 3, auch bei leeren Bereichen. Import mit Vorschau, Bereichszählern und atomarem Anwenden; ältere Dateien bleiben lesbar.

## Statische Analyse aus 0.25.0

- Bereichswechsel: blaue Forensik mit Schild und rote statische Analyse mit Totenkopf. Eigene Formulare, Module und Auftragshistorien, gemeinsame Toolverwaltung und serieller Worker.
- Einzeldateien PDF, Office (Legacy OLE und OOXML) sowie Windows PE. Upload oder lokale Dateireferenz mit Picker, maximal 256 MiB. Signaturprüfung und neutrale Arbeitskopie, Original unverändert.
- Bearbeitbarer Malware-Baukasten mit geordneten internen Prüfungen: Metadaten/SHA-1/SHA-256, begrenzte Entropie-/Strings-Suche, PDF-Schlüsselwörter, Office-Verzeichnis ohne Entpacken und PE-Header/Sektionstabelle. Leerer Start; passende Vorschläge erscheinen erst beim Anlegen eines Moduls.
- Persistente Queue, echte abgeschlossene Schritte, SSE-Terminal, Abbruch, HTML-/JSON-Berichte und optionales Ergebnis-ZIP ohne Sample. Lokale Ergebnisanzeige und spätere Archivierung.
- Ein gemeinsames Schema 3 für beide Modulbereiche; alte Forensik-Dateien bleiben importierbar. Externe Toolreferenzen samt Parametern können als Entwurf gespeichert werden und sperren Run. PDFID-/oleid-Adapter folgen nach Abstimmung.

**Grenze:** begrenzte statische Triage, keine Malware-Erkennung oder Isolation. Keine Ausführung von Eingangsdateien, Makros, Skripten oder eingebetteten Inhalten. Kein automatischer Internetzugriff. Der bestehende Administratorstart ist keine Sandbox; externe Tools und freie PowerShell werden im Malware-Runner dieser Version nicht gestartet. [Architektur und Grenzen 0.25](docs/MALWARE_025.md).

## Wartung aus 0.24.0

- **Diagnosepaket mit Vorschau:** im Serverfenster und unter Einstellungen → Verarbeitung. App-/Systemversion, Server-/Workerstatus, Auftragszähler und bereinigte technische Ereignisse. Alle enthaltenen Texte vor dem ZIP-Export prüfen. Keine Tokens, Evidenzen, Ergebnisse, Toolbefehle/-ausgaben oder Feedbacktexte. Unbekannte Logdetails werden ausgelassen; Export entspricht exakt der Vorschau. Kein automatischer Versand.
- **Lokales Feedback:** Button oben in der Web-Leiste für Bugs, Wünsche und allgemeines Feedback. Lokal speichern, letzte 100 Einträge ansehen, bis zu 1.000 Einträge als JSON exportieren. Eingegebene Texte bleiben unverändert; keine automatischen Anhänge oder Übermittlung.
- **Servereinstellungen im Desktopfenster:** Port und lokalen/LAN-Zugriff speichern. Änderungen nach bewusstem Server-Stopp und erneutem Start. LAN verwendet Anmeldung und automatisch erzeugtes selbstsigniertes HTTPS; keine automatische Firewalländerung.
- **Technische Logrotation:** Größe pro Datei 0,1–100 MB und 1–20 ältere Dateien einstellen. Wirksam nach Serverneustart; ausschließlich technische Serverlogs. Auftragslogs, Audit und Evidencen bleiben getrennt.

## Windows starten

1. Windows-ZIP aus einem Release vollständig entpacken.
2. `PostProcessingMagic.exe` doppelklicken und Windows-UAC bestätigen.
3. Der Server startet automatisch im blauen Forensik-Fenster. **Browser öffnen** startet die angemeldete Weboberfläche.

Auf dem Zielrechner kein Python, Node, Docker, Redis oder Internet nötig. Externe Forensiktools müssen separat vorhanden und passend lizenziert sein. Standardadresse: `http://127.0.0.1:8765/`, sofern kein anderer Port gespeichert oder ausdrücklich beim Start angegeben wurde.

Das Fenster zeigt Server-/Workerstatus und Live-Serverlogs; Adresse und Access Token lassen sich kopieren. **X** minimiert in den Windows-Infobereich, Klick auf das Schild stellt es wieder her. **Server stoppen** sperrt neue Aufträge und wartet die laufende Arbeit ab. **Force Shutdown** fragt nach Bestätigung und beendet den eigenen Server-/Worker-/Toolbaum. Unterbrochene Aufträge werden gekennzeichnet und nicht automatisch wiederholt. **Beenden…** stoppt geordnet und schließt das Fenster.

Nach jedem Serverstart neuer Access Token; **Browser öffnen** verwendet automatisch den aktuellen Schlüssel. Daten standardmäßig unter `%LOCALAPPDATA%/PostProcessingMagic`, außerhalb des EXE-Entpackverzeichnisses.

## Evidence-Aufbereitung

Der Forensik-Bereich konzentriert sich weiterhin auf **ZIP-Dateien mit KAPE-Targets**. E01/VMDK erscheinen höchstens deaktiviert als geplant. Eigene ZIP wählen oder eine lokale ZIP auf dem Server referenzieren, Aufwand auswählen und **Run** klicken. Nur vollständig konfigurierte Modi sind auswählbar.

- Toolnamen und absolute Serverpfade im Browser verwalten, mit Datei-/Ordner-Picker und Pfadprüfung. Eingebundene Tools lassen sich nicht versehentlich löschen.
- Modi in **Import, Verarbeitung und Export** konfigurieren: relatives Entpackziel, geordnete Befehlsblöcke, Ergebnisordner. Schritte einfügen, verschieben und entfernen. Kein PS1-Editieren erforderlich.
- Runner derzeit: höchstens ein KAPE-Modulbefehl plus freie PowerShell-Blöcke oder reine PowerShell-Workflows. Weitere generische Toolrunner später. Eine bearbeitbare KAPE-Vorlage Medium/ohne Timeline ist vorhanden, ohne automatische Toolzuordnung.
- Jeder Auftrag hat einen eigenen Arbeitsordner und unveränderlichen Konfigurationssnapshot einschließlich Toolhash/-version. Originaldateien werden nicht verändert. ZIP-Prüfungen vor Extraktion, Größen-/Speicherlimits und lokaler Leseschutz.
- Persistente SQLite-Queue und separater serieller Worker. Live-Ausgabe, Befehlsfortschritt ohne erfundene Prozentwerte, Abbruch und geschützte Downloads.
- Ergebnis-ZIP optional direkt oder später erstellen. Lokal **Show in Explorer** als Alternative. HTML-/JSON-Abschlussbericht mit Eingangs-/Ausgabe-SHA-1/SHA-256, Befehlen, Zeiten, Fehlern und Unterordnern.
- Auftragssuche, Queue-Pause, Speicherübersicht, Arbeitslaufwerk für neue Aufträge und gezielte Bereinigung mit Vorschau. Referenzierte Originale bleiben erhalten.
- Upload standardmäßig 50 GiB, Entpacklimit 2 TB dezimal; im Browser einstellbar und pro Auftrag eingefroren.
- Tools/Modi/Befehle/Verarbeitungslimits gemeinsam als versionierte JSON-Konfiguration mit Importvorschau und Konfliktbehandlung übertragen. Keine Tokens, Evidencen oder Toolprogramme im Export. Serverlokale Port-/LAN-/Logeinstellungen und Arbeitslaufwerk sind separat.

Fachliche Vollständigkeit der Toolergebnisse muss der Nutzer prüfen. PowerShell/Tools laufen auf ausdrücklichen Nutzerwunsch mit Administratorrechten; dies ist keine Sandbox. Remotezugriff ist für vertrauenswürdige lokale Netze vorgesehen, nicht für öffentliches Internet-Hosting. Bei selbstsigniertem HTTPS muss auf dem verwendeten Gerät dem Zertifikat vertraut werden; die App ändert keinen Trust Store.

## Entwicklung und Build

Python 3.12+ unter Windows, PowerShell im Projektordner:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\build.ps1 -OutputDirectory dist/release
.\.venv\Scripts\python.exe tools/package_release.py --exe dist/release/PostProcessingMagic.exe --output release-files
```

Das Buildskript prüft pytest/Ruff und bündelt Python, Tcl/Tk und Weboberfläche per PyInstaller. EXE-Prüfungen verwenden ausschließlich selbst erzeugte Testprogramme/-archive:

```powershell
.\.venv\Scripts\python.exe tests/smoke_startup.py --exe dist/release/PostProcessingMagic.exe
.\.venv\Scripts\python.exe tests/smoke_batch.py --exe dist/release/PostProcessingMagic.exe
.\.venv\Scripts\python.exe tests/smoke_control.py --exe dist/release/PostProcessingMagic.exe
```

`--headless` bzw. der kompatible Schalter `--no-browser` starten ohne Desktopfenster. `--data-dir`, `--port`, `--local` und `--lan` sind explizite Startoptionen. Explizite Port-/Netzwerkoptionen gehen beim Programmstart gespeicherten Werten vor. Die Desktop-Start/Stop-Steuerung übernimmt anschließend bewusst neu gespeicherte Einstellungen.

## Releases

Pro Version README und `docs/releases/<Version>.md` aktualisieren sowie Versionsnummer in `pyproject.toml` und `forensic_app/__init__.py` angleichen. Der Windows-Workflow baut und prüft bei einem entsprechenden Push auf `main` den Stand und erstellt einen versionierten GitHub-Vorabrelease mit Windows-ZIP, SHA-256-Prüfsumme und Build-Paketinventar. Vorhandene Releases werden nicht überschrieben. Google Drive bleibt ein zusätzlicher Downloadkanal in Versionsordnern. Testanleitungen und aktueller Instanztoken werden direkt im Chat bereitgestellt, niemals ins Repository geschrieben.

Siehe [AGENTS.md](AGENTS.md) für Entwicklungsgrenzen und [VALIDATION.md](docs/VALIDATION.md) für die tatsächlichen Prüfungen. [MIT-Lizenz](LICENSE).
