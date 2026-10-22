# Architekturentscheidung und Review

## Grundlage

Grundlage ist die am 21.10.2026 eingefügte Konversationszusammenfassung, nicht der
Inhalt der geschützten PDF. Die Zusammenfassung erwähnt ein früheres
ForensicPostProcessor.zip; dieses Archiv liegt hier nicht vor.
Die dort genannten fertigen Funktionen wurden deshalb nicht übernommen oder geprüft.

## Aktualisierte Produktvorgabe

Nach dem Startgerüst hat der Nutzer frei konfigurierbare Modi mit geordneten
Toolaufrufen im Browser verlangt. PS1-Dateien müssen dafür nicht bearbeitet werden.
Tools und Workflows sollen gemeinsam exportierbar/importierbar sein. Das ersetzt
die ursprüngliche feste PS1-Zuordnung in diesem Dokument; die früheren Abschnitte
beschreiben die ursprüngliche Idee. Das neue Konfigurationsmodell und die
kleinen Umsetzungsschritte stehen in [CONFIGURATION.md](CONFIGURATION.md).

Aktuelle Priorisierung: V1 ausschließlich ZIP mit KAPE-Targets; E01/VMDK später.
Ab 0.8.0 verlangt der Nutzer standardmäßig Administratorrechte für die Befehle:
Launcher startet sich bei Bedarf mit dem Windows-Verb runas nach UAC-Bestätigung
neu. Server und separater Worker erben denselben erhöhten Token; kein stiller
nicht erhöhter Fallback. Der interne --test-no-admin-Schalter ist ausschließlich
für eigene synthetische Tests vorgesehen und wird im Auftragssnapshot vermerkt.
Die bisherige Entscheidung gegen Administratorstart ist damit auf Nutzerwunsch ersetzt.

ZIP-Eingänge können außerdem lokale Referenzen statt Browseruploads sein.
Windows-Dateihandle ausschließlich lesend mit FILE_SHARE_READ verhindert parallele
Schreib-/Löschzugriffe während Hash und Extraktion. Größe, Änderungszeit und
Dateiidentität werden gegen den Auftragssnapshot geprüft. Keine lokale Eingangskopie.
Entpackte Daten und Ergebnisse liegen weiterhin im eigenen Arbeitsordner.

Der Modus-Editor beschreibt ein Entpackziel, geordnete Toolreferenzen mit Parametern
und den Ordner für das abschließende Ergebnis-ZIP. Alle relativen Pfade beziehen
sich auf genau einen lokalen Arbeitsordner pro Aufbereitungs-ID. Das Eingangs-ZIP
bleibt separat erhalten. Die Konfiguration führt noch keinen Prozess aus.
Erweiterte SHA-1-/SHA-256-Prüfungen und Inhalts-Hashlisten sind ein optionaler,
späterer Meilenstein mit niedriger Priorität und blockieren V1 nicht.

## Ergänzung 0.9.0: Limits und geordnete Ausführung

ProcessingSettings speichert Upload- und Entpacklimit mit Audit in SQLite.
Standard: 50 GiB Upload und 2 TB dezimal entpackt. Der Auftrag übernimmt beim
Anlegen einen unveränderlichen Snapshot; spätere Änderungen wirken nur auf neue
Aufträge. Lokale Quellen umgehen nur das Uploadlimit. Auch Ergebnisgrößen werden
gegen das auftragsspezifische Entpacklimit geprüft. Freier Speicher, Archivanzahl,
Pfade und Kompressionsverhältnis bleiben zusätzliche unabhängige Prüfungen.

compile_plan erstellt eine geordnete commands-Liste: höchstens ein strikt
geprüfter Offline-KAPE-Aufruf, ergänzt um explizite PowerShell-Blöcke oder nur
PowerShell. Jeder Block speichert Typ, Code/Argumente und relatives Arbeitsverzeichnis.
Windows PowerShell läuft mit NoProfile, NonInteractive und Textausgabe; UTF-16LE
EncodedCommand transportiert Unicode-Code ohne Shellverkettung. Kein automatischer
ExecutionPolicy-Bypass. Enginehash und Version werden wie beim KAPE-Tool erfasst.
Jeder Block erhält einen eigenen überwachten Prozess, der Worker stoppt bei
Fehler oder Abbruch. cd verändert nur diesen Block. Ein anderer Arbeitsordner für
einen folgenden PowerShell-Block muss explizit konfiguriert und bereits vorhanden sein.
Die Befehle erben auf Nutzerwunsch Administratorrechte und sind keine Sandbox.

Die Oberfläche begrenzt die Terminalhöhe und zeigt den letzten 64-KiB-Ausschnitt;
der gespeicherte Gesamtlog ist auf 16 MiB begrenzt und herunterladbar. Manuelles
Hochscrollen pausiert das Folgen bis zum Schaltflächenklick oder Scrollen ans Ende.

## Ergänzung 0.10.0: lokale Ergebnisanzeige

GET /api/jobs/{id}/explorer prüft die Verfügbarkeit ohne Fenstereffekt; POST
fordert das Öffnen an. Beide Endpunkte benötigen den Sitzungstoken. Die echte
Client-IP muss Loopback sein; Proxyheader werden vom Launcher nicht vertraut.
Nur erfolgreich abgeschlossene Jobs sind zulässig. Der Zielordner stammt aus
dem unveränderlichen Auftragssnapshot, niemals aus einem angefragten freien Pfad.
Relative Pfadvalidierung, Existenzprüfung und Zurückweisen von Reparse Points
(auch Junctions im Auftragspfad) begrenzen das Ziel auf diesen Ergebnisordner.

Windows-Sitzungs-ID und GetShellWindow prüfen, ob ein interaktiver Explorer
verfügbar ist. ShellExecuteW startet das feste Windows-explorer.exe mit genau
einem absoluten Ordnerargument, ohne Shellkommando. Keine Ergebnisdatei ausführen.
Die Antwort bestätigt die Öffnungsanforderung, nicht die tatsächliche Sichtbarkeit
des Fensters; Shellfehler werden gemeldet. Ein erfolgreicher Aufruf wird als
Jobereignis protokolliert. Kein Einfluss auf Auftragsstatus oder gespeicherte Daten.
Die UI bietet dies auch für ältere erfolgreiche Aufträge im Logs-Tab an.

## Ergänzung 0.11.0: Speicherübersicht

GET /api/settings/storage liefert authentifiziert shutil.disk_usage des Datenordners
und die letzte Messung. POST /api/settings/storage/scan startet eine begrenzte
Metadatenmessung im HTTP-Threadpool; dies ist kein Analysejob und liest keine
Dateiinhalte. Pro Instanz verhindert eine Sperre parallele Verzeichnismessungen.
Erfasst werden ausschließlich evidence, work und results unter dem Datenordner.
Symbolische Links und Windows-Reparse-Points werden nicht verfolgt. Nicht lesbare
Einträge zählen als Fehler; Ergebnisse mit Fehlern oder überschrittenem Zeit-/
Eintragsbudget werden als teilweise erfasst ausgewiesen. Letzte Messung nur im
Speicher halten; nach Neustart neu messen. Logische Dateigrößen sind keine Messung
physisch belegter Cluster. Keine automatische Messung beim Öffnen der Einstellungen.

## Ergänzungen 0.12/0.13: Historie und Pause

Historienabfragen verwenden gebundene SQL-Parameter und JSON-Snapshotfelder.
Eine Unicode-casefold-Funktion unterstützt die wörtliche Teilstringsuche; keine
Interpretation als SQL-LIKE-Muster. Datum meint das gespeicherte UTC-Startdatum.
Zählen und seitenweises Lesen geschehen in einem Lesesnapshot. Logtails werden
erst beim Öffnen eines Auftrags geladen. Frühere/gelöschte Moduszuordnungen bleiben
anhand der Auftragssnapshots auffindbar.

queue_control speichert einen globalen Pausenzustand, queue_control_events seine
Änderungen. Der Worker übernimmt Aufträge über QueueControl.claim: BEGIN IMMEDIATE,
Pause prüfen, nächsten wartenden Auftrag atomar als laufend markieren und Ereignis
speichern. QueueControl.set nutzt dieselbe Sperre. Eine bereits erfolgte Übernahme
läuft bei späterer Pause normal weiter. PUT /api/queue ist authentifiziert und
nimmt ausschließlich einen strikten Boolean entgegen. GET liefert Zustand und
Auftragszahlen. Die Pause wird nicht in Konfigurationen exportiert. Die bisherigen
Regeln zum Markieren unterbrochener Aufträge bei Neustart bleiben bestehen.

## Ergänzung 0.14: Forensik-Design

Das lokale HTML erhält ein konsistentes blaues Thema und ein rein dekoratives
Schildmotiv als inline SVG. Hintergrundgrafik hat pointer-events:none und
aria-hidden, verändert also weder Bedienung noch den Accessibility-Baum.
Responsive CSS, Fokusmarkierungen und getrennte Fehler-/Warnfarben bleiben
Bestandteil der Darstellung. Keine zusätzlichen Assets, Bibliotheken, Requests
oder Änderungen an Jobs/API/Workflow-Konfiguration. Die spätere rote Malware-
Ansicht wird dadurch nicht implementiert oder freigegeben.

## Vorgemerkte Erweiterung nach V1: zwei Arbeitsbereiche

Später zwischen Forensik (blau, Schild) und statischer Malware-Analyse (rot,
Totenkopf) umschalten. Gemeinsame Tooldefinitionen bleiben zentral; Module,
Formatzuordnungen, Aufträge und Ergebnisreferenzen gehören jeweils zu einem
Arbeitsbereich. Diese Trennung muss auch API, Runner und Konfigurationstransfer
umfassen. Ein Wechsel der Ansicht ändert keine laufenden Aufträge.

Der Malware-Bereich nimmt einzelne Executables, PDFs oder Office-Dokumente
entgegen und übergibt sie ausschließlich als Daten an statische Analysewerkzeuge.
Kein Start der Eingangsdatei, keine Makroausführung. Eigener Auftragsordner und
konfigurierbarer Ergebnisordner mit ZIP-Download bleiben das gemeinsame Prinzip.
Vor Umsetzung Parser-Isolation und zulässige Befehlsblöcke festlegen; die aktuelle
freie PowerShell-Ausführung und Administratorvererbung nicht ungeprüft übertragen.
Details und schrittweise Abnahme: ROADMAP, späterer Meilenstein statische Malware-Analyse.
Dieser Entwurf ist noch nicht implementiert und verändert den ZIP/KAPE-V1-Umfang nicht.

## Entscheidung: Python, ein distributierbares Programm, getrennte Prozesse

Python/FastAPI passt zum gewünschten PyInstaller-Build und möglichen späteren
Python-Parsern. ASP.NET Core wäre bei verbindlicher Windows-Authentifizierung eine
gute Alternative. Eine hybride .NET/Python-Anwendung würde jetzt unnötige
Build- und Betriebsvarianten erzeugen. Diese Entscheidung ist eine Projektwahl,
keine Aussage, dass Python forensisch besser geeignet sei.

Die Ziel-EXE hat drei Rollen: Launcher, Webserver und Worker. Zunächst läuft der
Webserver im Launcherprozess; ein zweiter Workerprozess wird mit der dauerhaften
Queue ab 0.7.0 über `multiprocessing` (spawn) gestartet. `freeze_support()` schützt
die gebündelte EXE vor rekursivem Serverstart. Keine Uvicorn-Mehrprozesskonfiguration
und kein Auto-Reload im Build. Der Worker verarbeitet genau einen Auftrag gleichzeitig;
die HTTP-Schicht führt keine Analyseprogramme aus. Ein eigener EXE-Test prüft
Prozessstart, Ausgabe, Fehler und Prozessbaum-Abbruch mit selbst erzeugten Testdaten.

```text
Browser (lokal oder TLS im internen Netz)
    | HTTP API + SSE, authentifiziert
    v
EXE: Launcher + FastAPI ---- SQLite: Jobs, Ereignisse, Audit, Artefakte
    | überwacht                       ^
    v                                 |
EXE: Worker --------------------------+
    | feste Argumentlisten, Limits, Prozessbaum-Abbruch
    v
freigegebenes Profil -> Windows PowerShell / KAPE
    | Originale nur lesend, eigene Arbeitsverzeichnisse
    v
Report + Artefakte + Ergebnis-ZIP + SHA-256
```

## Was an der ursprünglichen Idee ergänzt werden sollte

1. **Evidence ist ein Satz von Dateien.** Segmentierte E01-Dateien und abhängige
   VMDK-Dateien benötigen ein Manifest, Vollständigkeitsprüfung und Hashes pro Datei.
   Snapshot- und Parent-Abhängigkeiten dürfen nicht unbemerkt fehlen.
2. **Dauerhafte Zustandsmaschine statt einfacher Queue.** Zielzustände: uploading,
   validating, queued, running, cancelling, cancelled, succeeded, failed, interrupted.
   Die Umstellung erfolgt über Transaktionen mit erlaubten Übergängen. Ein Job wird
   erst nach fertig geschriebenem Ergebnis und Manifest erfolgreich.
3. **Nachweis und Live-Anzeige unterscheiden.** stdout/stderr kann fehlerhaft oder
   manipuliert sein. Fortschrittsmarker sind Anzeigen, keine Erfolgsnachweise.
   Erfolg erfordert Exitcode, erwartete Ausgaben, deren Prüfung und Ergebnis-Hash.
4. **Reproduzierbarkeit explizit machen.** Eingangsmanifest, Profilversion,
   Skripthash, Toolversionen und effektive Parameter pro Lauf festhalten.
5. **Unterbrechung ist kein Resume.** Zunächst abgebrochene Jobs kenntlich machen;
   Wiederaufnahme erst bei profilierten, überprüfbaren Checkpoints.
6. **Keine beliebigen Kombinationen versprechen.** Geräte- und Tiefenlisten ergeben
   nicht automatisch 45 funktionsfähige Pipelines. Ein Fähigkeitskatalog bestimmt,
   welche Kombinationen validiert und freigegeben sind.
7. **Upload und Analyse konkurrieren um Speicher.** Budgets umfassen Eingänge,
   temporäre Kopien, Entpackdaten, Toolausgaben und Ergebnis-ZIP. Ein Content-Length
   reicht als Größenkontrolle nicht aus. Abgebrochene Uploads brauchen Bereinigung.

## Daten und Vertrauensgrenzen

Standardpfad unter Windows: `%LOCALAPPDATA%\PostProcessingMagic`.
Überschreibbar durch `--data-dir`. Angelegt werden `config`, `evidence`, `work`,
`results` und `logs`; SQLite liegt im Datenwurzelverzeichnis. Keine Evidence wird
als statischer Webinhalt ausgeliefert. Die UI ist im Programm gebündelt.

Das Grundgerüst erzeugt pro Start einen zufälligen Zugriffstoken. Der lokale Browser
erhält ihn im URL-Fragment, das nicht in HTTP-Anfragen übertragen wird. API-Aufrufe
nutzen einen Authorization-Header. Tokens werden nur im Sitzungsspeicher gehalten;
es gibt kein CDN. Ein Token schützt noch keine individuellen Rollen oder Fallrechte.
Dateisystemzugriff wird aktuell durch die Rechte des angemeldeten Windows-Kontos
bestimmt, nicht durch speziell eingerichtete ACLs.

Remotezugriff wird explizit über `--lan` aktiviert. Ohne eigene Zertifikatspfade
erzeugt die App ein selbstsigniertes Zertifikat und den zugehörigen Schlüssel im
Datenordner. Kein Zertifikat muss manuell vorbereitet werden. Der Browser muss dem
Zertifikat auf dem jeweiligen Gerät vertrauen; die App ändert keinen Trust Store.
Der Benutzer überträgt den Token über einen geeigneten Kanal zum anderen
Gerät. Keine automatische Portfreigabe. Der aktuelle Tokenzugang ist ein
Entwicklungsmechanismus; vor echten Mehrbenutzerfällen sind Identität, Rollen,
Fallberechtigungen und Token-/Sitzungsverwaltung erforderlich. Kein Internet-Hosting.

Die SQLite-Verbindung und die Instanzsperre sind für einen lokalen Host vorgesehen.
Ein gemeinsamer Datenordner auf SMB/NAS ist kein unterstütztes Deployment.
Web- und Workerprozess mit gleichem Benutzerkonto sind keine Sicherheitsisolation.
Ein getrenntes Dienstkonto oder eine VM braucht ein eigenes Deploymentkonzept.

## EXE und externe Tools

Onefile entpackt intern temporäre Programmdateien; veränderliche Nutzdaten müssen
außerhalb bleiben. Python wird eingebettet, PowerShell 7 und externe Forensiktools
dagegen nicht automatisch. Vor Freigabe eines Analyseprofils sind Lieferumfang,
Lizenzen, Versionen und Toolhashes zu definieren. Fehlende Tools deaktivieren das Profil.
Derzeit gibt es keinerlei freigegebene Analyseprofile und keine Toolabhängigkeit.

Toolnamen und Installationspfade werden bereits im Browser verwaltet und in SQLite
gespeichert. Datei oder Verzeichnis werden auf dem Server auf Existenz geprüft,
aber niemals probeweise ausgeführt. Änderungen haben ein separates
Konfigurationsprotokoll. Ein gespeicherter Toolpfad ist kein freigegebenes Profil;
Version, Hash und fachliche Eignung müssen vor der späteren Jobausführung geprüft werden.

Onefile ist für den ersten Startumfang geeignet. Wenn Tools, Bibliotheken und Daten
stark wachsen, kann ein signiertes portables Verzeichnis oder Installer wartbarer
werden. Der Grundsatz bleibt: einmal auf Windows bauen, auf einem kompatiblen
Windows-Ziel ohne Entwicklungsumgebung starten. Build-Lock und Windows-Abnahmetest
gehören zu jeder verteilten Version.

## Technische Referenzen

- FastAPI-Lebenszyklus: https://fastapi.tiangolo.com/advanced/events/
- Grenzen einfacher BackgroundTasks: https://fastapi.tiangolo.com/tutorial/background-tasks/
- Uvicorn-Start: https://www.uvicorn.org/deployment/
- PyInstaller-Onefile: https://pyinstaller.org/en/stable/operating-mode.html
- PyInstaller-Prozessstart: https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html
- EWF-Segmente: https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20%28EWF%29.asciidoc
- VMDK-Varianten und Backing-Dateien: https://www.qemu.org/docs/master/system/qemu-block-drivers.html
- VMDK-Extents: https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html
- Selbstsignierte Zertifikate: https://cryptography.io/en/stable/x509/tutorial/



## Ergänzung 0.15: Datenbereinigung

Authentifizierte Vorschau erzeugt ein zehn Minuten gültiges Einmalticket für genau
eine Kategorie und einen SHA-256-Fingerabdruck des Metadatenmanifests. Anwendung
verlangt ein strikt boolesches true, unveränderten Bestand und keine offenen Jobs.
BEGIN IMMEDIATE setzt eine persistente Sperre; Anlegen und Übernehmen von Jobs
prüfen dieselbe Sperre. Keine lange SQLite-Schreibtransaktion während der Löschung.
Nur bekannte UUID-Auftragsordner, keine Verknüpfungen/Junctions und keine rekursive
Löschfunktion verwenden. Dateien einzeln prüfen und entfernen, leere Ordner danach.
Alle lokal referenzierten Originalpfade sind auch innerhalb des Datenordners geschützt.
Cache schützt Ergebnisbäume, Ergebnisse löschen auch ZIPs. Historie bleibt erhalten;
result_available meldet nach Bereinigung fehlende Archive. Abgelaufene Downloadtickets
und fehlende Ergebnisse werden vor der Auslieferung abgewiesen. Audit in cleanup_events,
Teilfehler sichtbar; bei Neustart unterbrochene Bereinigung kennzeichnen und Sperre lösen.
Filesystem-Prüfungen sind keine Isolation gegen gleichzeitig handelnde lokale Administratoren.


## Ergänzung 0.16–0.19: Arbeitsziele und Ergebnisartefakte

workspace_settings speichert das serverlokale Ziel. workspace_roots registriert
je App einen anhand SQLite-Owner-UUID gekennzeichneten eigenen Ordner; Marker
.ppm-owner.json und Pfade werden beim Zugriff validiert. Kein Durchsuchen beliebiger
externer Ordner als Datenbestand, keine automatische Verschiebung. job_paths verwendet
nur das im Auftrag gespeicherte registrierte data_root oder bei alten Jobs den
ursprünglichen Datenordner. SQLite und Queue bleiben im bisherigen Datenordner.
Eingänge/Arbeitsdaten/Ergebnisse neuer Jobs verwenden gemeinsam das eingefrorene Ziel.
Ausgefallene Ziele sind Fehler, niemals Anlass für stillen Fallback auf ein anderes Laufwerk.

create_zip ist eine Option pro Run und Teil des Snapshots. Ohne ZIP kann ein Job
mit geprüftem Ergebnisordner und Bericht erfolgreich sein. archive_requests führt
spätere Archivierung persistent durch denselben seriellen Worker aus. Keine erneute
Toolausführung. Pause sperrt neue Übernahme, Abbruch erhält die abgeschlossene
Analyse und Ergebnisdateien. Restart markiert offene Archivanforderungen interrupted.
Bereinigung prüft zusätzlich Archivanforderungen; Anforderung prüft Cleanup-Sperre
innerhalb BEGIN IMMEDIATE. Höchstens 16 offene Archivanforderungen.

results/<UUID>/Abschlussbericht.html und .json liegen außerhalb der Toolausgaben.
HTML escaped sämtliche Daten und verwendet keine Skripte/externen Inhalte; nur
authentifizierter Download als Anhang. Upload und lokale Eingänge hashen SHA1 und
SHA256 gemeinsam, Archivhashes ebenfalls ein Lesedurchlauf. Unterordner sind ein
Bestandsverzeichnis am Abschlusszeitpunkt, kein Nachweis einzelner Erstellungszeiten.
Verknüpfungen im Arbeitsverzeichnis werden nicht verfolgt; Arbeitsordnerliste bei
200.000 begrenzt. HTML maximal 2.000 Einträge je Liste, JSON vollständig innerhalb
dieser Grenzen. Keine optionalen Einzeldatei-Inhaltshashes. Das ZIP enthält den Stand
vor seinem eigenen Hash; der vollständige separate Bericht enthält den fertigen Hash.
Alte Jobs ohne SHA1 werden als solche benannt, Originale nicht rückwirkend gelesen.
Results-Bereinigung löscht auch Reports; Cache schützt Ergebnisse, Reports bleiben separat.


## Desktop-Steuerung 0.20

Tk ist im Windows-Build enthalten, kein Browser-Frontend für das Serverfenster.
DesktopSession startet die gleiche EXE mit --headless/--no-browser, zunächst
CREATE_SUSPENDED, ordnet sie einem Kill-on-close-Job-Object zu und setzt sie erst
danach fort. Damit besitzt das Fenster ausschließlich seinen eigenen Serverbaum.
Worker und Toolprozesse verwenden weiterhin ihre verschachtelten Job Objects.
Eine pro Start zufällige control_id muss am authentifizierten Systemendpunkt
übereinstimmen, bevor das Fenster Serverbefehle sendet. GUI und Server haben
getrennte Instanzsperren; fremde Prozesse werden weder übernommen noch beendet.
Tk-Aufrufe bleiben im UI-Thread; Hintergrundthread pollt Status/Logs und führt
Befehle über Queues aus. Loganzeige auf 64 KiB begrenzt, kein Toolausgabe-Export.
Tray: natives Shell_NotifyIconW auf eigenem Win32-Nachrichtenthread, Rückrufe in
Tk-Queue; Explorer-Neustart meldet Icon erneut an. Bei Trayfehler bleibt das Fenster
in der Taskleiste erreichbar. X ist kein Server-Stopp.

server_control.stopping wird mit BEGIN IMMEDIATE gesetzt; Jobanlage, Archivanforderung,
Queue-Claim und Archive-Claim prüfen denselben Zustand. Web-Queue-Fortsetzen kann
Stoppen nicht aufheben. Aktive Uploads/Aufträge/Archivierungen/Bereinigung werden
abgewartet, dann Uvicorn.should_exit gesetzt. Neustart setzt den Stoppzustand zurück;
die separate Queue-Pause bleibt unverändert. Offene Jobs werden wie bisher beim
Neustart interrupted, nicht blind fortgesetzt. Force Shutdown schließt ausschließlich
den eigenen Baum-Handle und markiert unvollständige Jobs/Archive nach Prozessende.
SQLite-Historie und Eingänge/Ergebnisse bleiben erhalten; keine Dateien werden gelöscht.
Unerwarteter Prozessabbruch wird spätestens beim nächsten Serverstart erkannt.

Windowed-PyInstaller-Build ohne Konsolenfenster. Serverlog im Datenordner bleibt
maßgeblich; zusätzliche Startfehlerdatei enthält nur Fehler und control_id (kein Token).
Control-Status ist authentifiziert, LAN weiterhin selbstsigniertes HTTPS. Keine
Firewall-/Truststoreänderung. Port-/LAN-Bedienung und weitere Wartungsfeatures später.


## Wartung 0.24

Diagnoseexport verwendet eine feste Ereignis-Allowlist und exportiert keine freien
Logmeldungen. Nur Systemstatus mit expliziten Feldern, Statuszähler und normalisierte
technische Ereignisse; keine Auftrags-/Toolnamen, Pfade, Tokens, Konfigurationstexte
oder Feedbacktexte. Aktuelle technische Logdatei und bis zu drei Rotationen, je max.
64 KiB; max. 800 Ereignisse. Verknüpfungen/hart verknüpfte Logs überspringen.
Vorschau enthält alle Exporttexte, SHA256-Manifest für die Nutzdateien. In-Memory-
ZIP-Snapshot mit max. vier Vorschauen und zehn Minuten gültigem Einmalticket.
Export liest keine aktuellen Daten nach; ZIP entspricht exakt der Vorschau.
API-Endpunkte authentifiziert, native Vorschau auch bei gestopptem Server möglich.

feedback speichert Kategorie, Titel, Freitext, App-Version und UTC-Zeit lokal in
SQLite. POST-Anfrage auf 64 KiB begrenzt, Text max. 8.000 Zeichen; max. 1.000 Einträge.
Webliste zeigt letzte 100, expliziter JSON-Export alle. DOM nur textContent, keine
Ausführung, keine Anhänge, kein automatischer Versand. Nicht Teil der technischen
Diagnose oder der portablen Workflowkonfiguration.

server_preferences speichert Port, LAN-Modus, Loggröße und Aufbewahrungsanzahl als
validiertes JSON mit Revisionszähler. Nur Desktop-UI schreibt; kein Remote-Endpunkt
zum Erweitern der Netzwerkerreichbarkeit. Änderungen gelten nach bewusstem Stop/Start.
Explizite CLI-Optionen überschreiben gespeicherte Startwerte; --local als Gegenstück
zu --lan. Geänderte Revision wird beim nächsten Desktop-Serverstart übernommen.
Logrotation 100.000–100.000.000 Bytes, 1–20 ältere Dateien. Beim Serverstart unter
Instanzsperre nur überschüssige server.log.N (bis N=20) entfernen, keine Verknüpfungen
oder mehrfach hart verknüpften Dateien. Auftrags-/Audit-/Evidencebereiche unberührt.
Diese hostlokalen Einstellungen werden nicht mit Tools/Workflows exportiert.
