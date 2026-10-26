# Post-Processing-Magic

Lokale, konfigurierbare Nachbearbeitung von ZIP-Evidencen unter Windows.

**Version 0.41.0:** Dokumentationsrelease auf Basis der vom Nutzer erfolgreich getesteten Version 0.40.0. Die Aufbereitungsfunktionen bleiben unverändert. Frühere Releases bleiben separat verfügbar.

[Windows-Releases](https://github.com/D3vasd4t0r/Post-Processing-Magic/releases) · [Änderungen 0.41](docs/releases/0.41.0.md) · [Code-Wiki (offline)](docs/code-wiki/index.html) · [Architektur](docs/ARCHITECTURE.md) · [Konfiguration](docs/CONFIGURATION.md)

## Neu in 0.41

- Englische Modul-, Klassen- und Funktionsdokumentation zu Schnittstellen, Datenverträgen, Transaktionen, Seiteneffekten und Prozess-/Dateilebenszyklen.
- Erklärende englische Kommentare in der Weblogik und im PowerShell-Buildskript; keine Übersetzung bestehender Nutzer-, Hilfe- oder Fehlertexte.
- Ein englisches [HTML-Code-Wiki](docs/code-wiki/index.html) zu Architektur, Quellmodulen, Verarbeitung, Konfiguration, API, Oberfläche und Entwicklung. Es öffnet direkt von der Festplatte, ohne Server oder Internet.
- Das Windows-ZIP enthält das Wiki unter **docs/code-wiki/index.html** zusammen mit README und den verlinkten Projektdokumenten. ZIP vollständig entpacken und die HTML-Datei doppelklicken.

0.41 fügt keine Funktionen, Sicherheitskorrekturen, Refactorings oder Abhängigkeiten hinzu. Python-Syntaxbäume werden nach Entfernen der Docstrings gegen 0.40 verglichen; freigegebene Ausnahmen sind die Versionsnummer und der zusätzliche Dokumentationsinhalt des Release-ZIPs. JS-/PowerShell-Änderungen sind Kommentare beziehungsweise Versionsangaben. Pydantic-/API-Docstrings können beschreibende Schema-Metadaten ergänzen.

Die Dokumentation beschreibt den vorhandenen Code. Sie ist kein Sicherheitsgutachten und erweitert keine Unterstützung für Evidenzformate oder Toolrunner. Version 0.40 wurde vom Nutzer abgenommen und wird im Berufsalltag erprobt.

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

Der Dokumentationsstand wird mit Syntaxbaum-/Kommentarvergleich, bestehenden Tests, Ruff, JavaScript-Prüfung, Windows-EXE-Prüfgruppen sowie Offline-Link- und Browserprüfung des Wikis geprüft. Die konkreten Abschlussbelege stehen in der Releasebeschreibung und [Validierung 0.41](docs/VALIDATION_041.md).

Die erfolgreiche Nutzerabnahme von 0.40 bleibt die funktionale Basis. Automatisierte Prüfungen verwenden eigene synthetische Daten; sie ersetzen keine fachliche Bewertung echter KAPE-Ergebnisse und keinen tatsächlichen 2-TB-Praxistest.

Künftige Releases und Testpakete werden ausschließlich auf GitHub veröffentlicht.
