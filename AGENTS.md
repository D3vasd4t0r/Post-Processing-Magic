# Coding-Agent: Post-Processing-Magic

Du unterstützt die Entwicklung eines unter Windows per Doppelklick gestarteten
forensischen Nachbearbeitungsdienstes. Lies zuerst README.md, docs/ARCHITECTURE.md
und docs/ROADMAP.md. Prüfe den tatsächlichen Code, bevor du einen Meilenstein als
erledigt bezeichnest. Setze die nächsten offenen Schritte eigenständig in kleinen,
prüfbaren Änderungen um; delegiere nur auf ausdrücklichen Wunsch des Nutzers.

## Verbindliches Produktziel

- Eine auf Windows gebaute EXE startet Webserver und später den separaten Worker,
  richtet beschreibbare Datenverzeichnisse ein und öffnet die lokale Browser-UI.
- Auf dem Zielrechner kein Python, Node, Docker, Redis oder Internet erforderlich.
  Externe Analysewerkzeuge müssen separat mitgeliefert und lizenziert sein.
- Version 1 unterstützt ausschließlich ZIP-Dateien mit KAPE-Target-Evidencen.
  E01 und VMDK erscheinen höchstens deaktiviert als „in Planung“ und folgen später.
  Aufwand im Browser als Dropdown: schnell, Medium, langsam.
  Das Nutzerbeispiel verwendet „Medium“. Ältere gespeicherte Werte nicht still ändern.
- Fallnummer, Gerätename, Live-Fortschritt, Logausgabe, Abschluss-Ton und
  autorisierter Ergebnisdownload gehören zum Zielumfang.
- Im Browser gibt es Einstellungen für Toolnamen und absolute Toolpfade auf dem
  Server. Pfade lassen sich speichern, prüfen, bearbeiten und entfernen.
  Ein Datei-/Ordner-Picker unterstützt die Auswahl im Dateisystem des Servers.
  Ein gespeicherter Pfad ist noch keine Freigabe eines Analyseprofils.
- Leerer Start: Nutzer legen Modi und deren geordnete Verarbeitungsschritte im
  Browser an. Schritte referenzieren ein Tool und Argumente oder enthalten expliziten PowerShell-Code.
  Keine Bearbeitung von PS1-Dateien für die Workflowkonfiguration voraussetzen.
- Ausnahme vom leeren Start auf ausdrücklichen Nutzerwunsch: einmalig die
  bearbeitbare KAPE-Vorlage „Medium / ohne Timeline“ anlegen. Änderungen und
  Entfernen dieser Vorlage über Neustarts erhalten, keine automatische Toolzuordnung.
- Pro Evidence-Aufbereitung in genau einem eigenen lokalen Arbeitsordner denken.
  Entpackziel und Ergebnis-ZIP-Quellordner sind relative Unterordner dieses Laufs.
  Archivinterne Namen nicht umbenennen: ZIP mit C + Ziel Targets ergibt Targets/C.
- Hohe Priorität: geordnete Befehlsblöcke mit Tool-Dropdown und separaten Parametern,
  Einfügen davor/danach, Verschieben und Entfernen. Programmpfad aus Tools ergänzen.
- Den Modus-Editor in Import, Verarbeitung und Export gliedern. Der abschließend
  zu zippende Ergebnisordner steht unter Export in einer eigenen vollen Zeile.
- Ab 0.4.0 neue Modi pro Format/Aufwandsstufe eindeutig speichern. Belegte Stufen
  beim Anlegen sperren; beim Bearbeiten eigene Stufe zulassen. Prüfung und Schreiben
  in einer SQLite-Transaktion gegen gleichzeitige Anfragen schützen.
  Vorhandene doppelte Testmodi als Konflikt erhalten; Nutzer löst sie durch Änderung
  auf eine freie Stufe oder ausdrückliches Entfernen. Kein stilles Löschen/Umzuordnen.
  Die spätere Run-Hauptseite sperrt Stufen ohne gültige Befehlssammlung.
- Nach erfolgreichem „Modus speichern“ den Editor schließen, Modusliste anzeigen
  und sichtbare Erfolgsmeldung geben. Bei Speichervalidierungsfehlern Eingaben behalten.
- Alle Tool- und Workflowkonfigurationen (Modi, Schritte, Argumente, Platzhalter)
  müssen über eine versionierte Konfigurationsdatei exportiert/importiert werden
  können. Keine Tokens, privaten Schlüssel, Evidencen oder Tool-Binaries exportieren.
  Vor Import Vorschau, Validierung und Konfliktbehandlung; niemals automatisch ausführen.
- Remotezugriff verwendet automatisch erzeugte selbstsignierte Zertifikate und
  Authentifizierung; keine manuell bereitgestellten Zertifikate voraussetzen.

## Zusammenarbeit und Testiterationen

- Aktuelle Reihenfolge auf Nutzerwunsch: UI fertigstellen, gemeinsam testen,
  Feedback einarbeiten, danach jede Aufbereitungsart und Toolzuordnung einzeln besprechen.
  Keine Analyseprofile eigenmächtig festlegen oder M1 vor dieser Abstimmung beginnen.
- In jeder manuellen Testiteration immer drei Teile liefern: Änderungen/Features,
  wenige nummerierte Klickschritte mit tatsächlichem Startpfad oder geöffnetem Tab,
  und eine ausdrückliche Bitte, das Ergebnis hier im Chat zu melden.
- Bei jedem Testlauf zusätzlich Testadresse und den tatsächlichen aktuellen
  Access Token der laufenden Testinstanz direkt im Chat angeben. Token aus der
  richtigen Instanzdatei lesen, nicht in Repository oder Dokumentation festschreiben.
- Tests für den Nutzer vorbereiten. Keine Kenntnisse von Terminal, Tokenablage oder
  Buildwerkzeugen voraussetzen. Bereits laufende Nutzerinstanzen nicht still beenden.
- Kleine Schritte: pro abgeschlossenem Feature oder sinnvoller Bedienungsstrecke
  eine Testiteration. Nicht mehrere große Arbeitspakete vor dem ersten Feedback bündeln.
- Nutzerabnahme Testlauf 1 ist erfolgt: Schritte 1–5 der Toolverwaltung funktionieren.
  Auch Testlauf 2 (Path-Picker, Schritte 1–4) wurde erfolgreich bestätigt.
  Auch der Merker für den letzten Picker-Ordner wurde bestätigt.
  Nutzerabnahme 0.4.0 (eindeutige Stufen und Editor nach Speichern schließen): klappt.
  Nutzerabnahme 0.5.0 (Konfigurationstransfer): „Klapüpt mega“.
  Nutzerabnahme 0.6.0 erfolgt. Nutzer hat KAPE zugeordnet und den echten ZIP-Test
  ausdrücklich angefordert. Implementierung/Ausführung über seinen Run-Klick erlaubt.
  Der übrige Modus-Baukasten und die Gliederung funktionieren laut Nutzerfeedback.
  Die aktuelle Reihenfolge und bereits erledigte Schritte stehen in docs/ROADMAP.md.
- Hauptseite einfach halten: Datei, Format, Aufwand/Modus, Run, Fortschritt pro
  Command und insgesamt, ausklappbare Kommandozeile, danach „Download Evidences“.
  Toolverwaltung und Workflowkonfiguration gehören in Einstellungen.
- Optionale spätere Hashfunktionen haben niedrige Priorität und blockieren V1 nicht:
  SHA-1/SHA-256 der Eingangs-Evidence, ZIP-Dateihashliste per Checkbox als TXT im
  Ergebnisarchiv und Vergleich mit einem vom Nutzer angegebenen E01-Hash.
- Vor V1-Release Konfigurationsimport/-export mit allen Tools und Befehlsblöcken
  gemeinsam testen. Danach eigener Hauptmeilenstein mit einer vom Nutzer erst dann
  hochgeladenen ZIP-Testsicherung und genau einem KAPE-Befehl bis zum Ergebnisdownload.
  Die angekündigte Testsicherung vorher weder suchen noch einsehen oder untersuchen.
  Echte Testsicherung nur über vom Nutzer gestarteten Upload oder ausdrücklich
  gewählte lokale ZIP-Referenz verarbeiten. Keine vorzeitige automatische Analyse.
  Eigene Vorabtests verwenden ausschließlich selbst erzeugte Testarchive/-programme.
- Auf Nutzerkorrektur: Beim Löschen eines eingebundenen Tools warnen und betroffene
  Modi nennen. Tool NICHT löschen und Verknüpfungen NICHT lösen oder verändern.
- Ab 0.5.0 Einstellungen → Konfiguration: JSON-Export und Import mit Vorschau,
  Zusammenführen oder ausdrücklich bestätigtem Ersetzen. Automatische Sicherung
  vor Anwendung, atomare Änderung, abgelaufene/veraltete Vorschauen abweisen.
- Ab 0.6.0 Hauptseite als Oberflächentest: Dateiauswahl ohne Lesen/Upload der
  Inhalte, ZIP-Format, nur vollständig konfigurierte Stufen für Ablaufvorschau.
  Run und Ergebnisdownload bleiben gesperrt; Fortschritt niemals simulieren.
  Technischer Dienststatus gehört in die Einstellungen. Danach Nutzerfeedback
  zur Hauptoberfläche abwarten, vor Entwicklung des ausführenden Runners.
- Ab 0.7.0 erster Runner: genau ein offline KAPE-Modulbefehl, eigenes Arbeitsverzeichnis,
  begrenzter ZIP-Streaming-Upload, sichere Extraktion, persistente Queue, separater
  Worker, unveränderlicher Konfigurationssnapshot samt Toolhash/PE-Version,
  Live-Ausgabe über SSE, Abbruch über Windows Job Objects, Ergebnisprüfung/-ZIP.
  Kein Fortschrittsprozent erfinden; unbekannter KAPE-Fortschritt ist unbestimmt.
  Ein Run-Klick gibt den gewählten KAPE-Befehl explizit für diesen Auftrag frei.

## Architekturregeln

- Python 3.12+, FastAPI/Uvicorn, SQLite, lokales HTML/CSS/JavaScript, PyInstaller.
  Keine zweite Sprache und kein Frontend-Buildsystem ohne konkreten Nutzen.
- HTTP-Anfragen führen keine Analysejobs aus. Persistente SQLite-Queue und
  separater Workerprozess mit begrenzter Parallelität; kein In-Memory-Jobstore.
- SSE mit wiederaufnehmbarer Ereignisnummer ist für Fortschritt vorgesehen.
  Kommandos wie Abbruch laufen über authentifizierte HTTP-Endpunkte.
- Business-Logik von API, UI, Persistenz und Toolaufrufen trennen.
- Daten gehören unter LOCALAPPDATA/PostProcessingMagic oder in ein explizit
  konfiguriertes Datenverzeichnis, niemals ins PyInstaller-Entpackverzeichnis.
- PyInstaller-Entry-Point und Worker-Modus gegen rekursiven Prozessstart absichern.
- Nutzeränderung ab 0.8.0: EXE standardmäßig über Windows-UAC als Administrator
  starten; Worker und Tools erben diese Rechte. Verweigerte UAC nicht umgehen.
  Keine automatische Firewalländerung. --test-no-admin ausschließlich für eigene
  synthetische automatisierte Tests; nie einen echten KAPE-Test so starten.

## Forensische Grenzen

- Originaldateien nie verändern; Schreibschutzattribute allein sind keine Isolation.
- Streaming-Eingang mit Größen-/Speicherlimits, temporärem Upload, Hash und
  atomarer Finalisierung. Clientdateinamen nie als Dateipfad verwenden.
- Evidence-Sätze modellieren: E01-Segmente sowie VMDK-Descriptor/Extents/Snapshots.
  Ein Dateisuffix beweist kein gültiges oder vollständiges Format.
- Nicht vollständig implementierte Analyseprofile bleiben deaktiviert. Keine
  simulierten Fortschritte oder erfundenen forensischen Befunde.
- Die früher geplante feste PS1-Zuordnung wird durch versionierte, im Browser
  erstellte Workflowdefinitionen ersetzt. Tools per Referenz auf konfigurierte
  Programmdateien mit getrennter Argumentliste starten, nicht über zusammengesetzte
  Shell-Zeichenketten. Modi müssen ohne PS1-Bearbeitung konfigurierbar sein.
  Vor jedem Lauf eine unveränderliche Kopie der effektiven Konfiguration sowie
  Toolversion und Hash erfassen. Importierte Modi benötigen eine explizite Freigabe.
- ZIPs vor jeder Extraktion auf Traversal, absolute/UNC-Pfade, Laufwerke,
  Windows-ADS, Symlinks, Sonderdateien, Größen, Anzahl, Verhältnis und Verschachtelung
  prüfen. Original-ZIPs behalten. Bis dahin nicht extrahieren.
- Persistentes Audit mit Akteur, UTC-Zeit, Status, Hashes, Profil-/Toolversionen,
  Exitcode und Ergebnisreferenz. Live-Logs sind davon getrennt.
- Hashketten erkennen Veränderungen nur bei extern gesichertem Vertrauensanker;
  lokale Hashwerte allein beweisen weder Herkunft noch gerichtliche Verwertbarkeit.
- Bei Neustart unterbrochene Jobs kennzeichnen; nie blind erneut verarbeiten.
- Downloads, Ereignisse, Jobansichten und Abbruch serverseitig autorisieren.

## Arbeitsablauf

1. Nächsten offenen Meilenstein aus ROADMAP wählen und Annahmen benennen.
2. Vollständigen, kleinen vertikalen Ablauf implementieren.
3. Sicherheits- und Integritätsgrenzen mit synthetischen Evidencen testen.
4. `python -m pytest` und `python -m ruff check .` ausführen.
5. Bei Packaging-Änderungen Windows-EXE bauen und wirklich starten; niemals
   erfolgreichen Python-Start mit erfolgreichem EXE-Test gleichsetzen.
6. README und ROADMAP an den tatsächlichen Stand anpassen. Offene Grenzen nennen.

Build 0.11.0 fertig: Speicherübersicht, 89 Tests sowie EXE-/Browserprüfung bestanden.
Zusätzlich zwei weitere Meilensteine vor großem Nutzertest freigegeben und umgesetzt:
0.12 Auftragssuche/Filter/Paginierung und 0.13 persistente Warteschlangenpause.
Gebündelter Build 0.13 umfasst 0.10–0.13. Nutzerabnahmen aller vier Features offen.
Finale EXE dist/0.13.0-r1/PostProcessingMagic.exe, 93 Tests und EXE-/Browserprüfungen
bestanden. Startverknüpfung „Testversion 0.13 starten“ verwenden; großer gemeinsamer
Test in docs/NEXT_TEST.md. Nutzerinstanz bleibt bis Rückkehr unverändert auf 0.10.
Keine weiteren Features vor diesem gemeinsamen Test hinzufügen.
Danach ausdrücklich zusätzlich vor dem Test freigegeben: 0.14 blaue Forensik-
Oberfläche mit Schildmotiv. Gemeinsamen Testbuild/Verknüpfung auf 0.14 aktualisieren,
großen Funktionstest beibehalten und Designprüfung ergänzen. Malware bleibt später.
0.14 fertig: 93 Tests, Ruff, JavaScript und EXE-Start-/Neustarttest bestanden;
gebündelte Oberfläche visuell geprüft. Finale EXE dist/0.14.0/PostProcessingMagic.exe,
Verknüpfung „Testversion 0.14 starten“. Nutzerinstanz bleibt 0.10, Nutzerabnahmen
0.10–0.14 offen. Jetzt gemeinsamen Test abwarten, keine weiteren Features ergänzen.
Nachtrag: Nutzer hat Start angefordert; tatsächlich laufende Nutzerinstanz jetzt
0.14.0 auf Port 8767 mit Administratorrechten/Worker, Queue aktiv und leer.
Nutzertab angemeldet, Testanleitung bereit. Gemeinsame Nutzerabnahme steht aus.
Startverknüpfung im Projektordner vorbereitet, Testanleitung in docs/NEXT_TEST.md.
Nutzer gerade nicht am Laptop; Explorer-Test aus 0.10 mit Speicherübersicht bündeln.
0.10-Nutzerabnahme bleibt offen. Laufende Nutzerinstanz während der Entwicklung
beibehalten; eine notwendige Windows-UAC-Bestätigung erst bei Rückkehr durchführen.
Aktuell laufender Stand 0.10.0: lokale Ergebnisanzeige in Windows Explorer ergänzt;
83 Tests und EXE-/Browserprüfungen bestanden, Nutzerabnahme 0.10 steht aus.
Weiterhin funktionierender ZIP/KAPE-Runner mit optionalen freien
PowerShell-Blöcken, lokalem Dateiverweis, Fehlerdiagnose und Administratorstart.
Version 0.9 ist vom Nutzer erfolgreich abgenommen. Nächsten Schritt gemeinsam
auswählen; neue Ideen aus docs/BRAINSTORM.md einzeln mit Ja/Nein abstimmen.
Auswahl in docs/BRAINSTORM.md beachten: 1–4, 8–10 vormerken; 5 und 7 abgelehnt.
Idee 6 (Zeitlimit pro Block) ist eventuell und erst ganz zum Schluss erneut
anzusprechen. Abschlussbericht um Eingangs-/Ausgabehashes und erstellte Unterordner
ergänzen; E01 erst mit späterer Formatunterstützung. Zusatzwunsch 11: mehrere
Aufbereitungen gleichzeitig ganz in Zukunft, derzeit seriellen Worker beibehalten.
Vormerkungen sind keine Freigabe, alle Features sofort umzusetzen.
Der Nutzer hat kleine und mittlere echte KAPE-Tests erfolgreich bestätigt.
Uploadlimit standardmäßig 50 GiB beibehalten; Entpacklimit 2 TB dezimal.
Beide Limits in Einstellungen → Verarbeitung und im versionierten JSON-Transfer;
pro Auftrag unveränderlich erfassen. Frühere Aufträge behalten ihre Limits.
PowerShell ist ein ausdrücklicher Blocktyp ohne Toolverknüpfung. Mehrzeiliger Code,
explizites relatives Arbeitsverzeichnis, cd nur innerhalb eines Blocks; folgender
Block startet in seinem eigenen Arbeitsverzeichnis. Maximal ein KAPE-Toolblock,
beliebige geordnete PowerShell-Blöcke oder reine PowerShell-Workflows mit ZIP-Eingang.
Speichern/Import führt nichts aus; erst Run startet die ausgewählte Befehlsfolge.
Terminal mit fester Höhe, automatischem Folgen, Pause bei manuellem Hochscrollen
und Schaltfläche zum Fortsetzen. Ausgabegrenzen beibehalten, voller Log in Logs.

Spätere Nutzeridee, erst nach ZIP/KAPE-V1 umsetzen: Bereichsumschalter zwischen
blauer Forensik mit Schild und roter statischer Malware-Analyse mit Totenkopf.
Gemeinsame Toolverwaltung, getrennte Module/Modi und Auftragszuordnungen.
Malware-Eingang ist eine einzelne EXE-, PDF- oder Office-Datei, kein ZIP-Archiv.
Nur statische Parser ausführen, niemals die Eingangsdatei oder deren Makros/Code.
PDFID/oleid sind Beispiele für spätere gemeinsame Toolabstimmung. Gleicher
Baukasten, Fortschritt/Terminal und konfigurierbarer Ergebnisordner mit ZIP-Download.
Details und spätere Abnahmeschritte stehen im entsprechenden ROADMAP-Meilenstein.
Diese Vormerkung erweitert nicht den aktuellen Implementierungs-/Testumfang.

Meilenstein 0.10 durch „Ok dann los“ freigegeben: „Show in Explorer“ als lokale Alternative zum
Ergebnisdownload. Bei Bedienung direkt am Server den geprüften Ergebnisordner
des Auftrags in dessen interaktiver Windows-Sitzung öffnen, ohne Download/Kopie.
Nur für autorisierten lokalen Zugriff anbieten; entfernte Browser behalten den
Download. Keine Ergebnisdateien ausführen. Fehlende Ordner/Sitzungen verständlich
melden. Auf Hauptseite und im Logs-Tab für erfolgreiche Läufe anbieten. Vor
Nutzerabnahme EXE-/Browserprüfung mit eigenen Testdaten abschließen und Testanleitung
mit tatsächlicher Adresse/Token liefern. Andere vorgemerkte Features bleiben später.

Weitere explizite Zukunftswünsche: UX-/Design-Review-Agent oder Harness etwa für
Version 1.5/2, ausschließlich bewerten und konkrete visuelle Vorschläge mit
Screenshots/Mockups zeigen. Jede Idee einzeln vom Nutzer freigeben lassen; keine
automatischen Designänderungen. Sicherheits-Agent/Harness verbindlich für Version 2:
Code und Anwendung umfassend in isolierter Testinstallation mit eigenen Daten
prüfen, reproduzierbare Befunde/Nachtests und sichere Installations-/Betriebsanleitung
liefern. Einzelheiten in ROADMAP. Jetzt nur planen, keine Review-Agenten starten
und laufenden Nutzertest bzw. Instanz 0.14 nicht unterbrechen.

Nächster expliziter Nutzerwunsch: erst nach Abschluss des großen Tests eine
Co-Projektmanagement-/Prioritäten-Session beginnen. Dafür ist ein zusätzlicher
Co-PM-Agent innerhalb dieser Aufgabe zur Planprüfung ausdrücklich gewünscht;
jetzt noch nicht starten. Agenda/Fragen in docs/PROJECT_REVIEW.md. Testfeedback,
Prioritäten und spätere Ziele in kleinen Fragerunden besprechen, neue Ideen
einzeln mit Ja/Nein abstimmen und nächsten Meilenstein gemeinsam auswählen.
Keine automatische Roadmap-Umsetzung oder neue eigenständige Unterhaltung.


Aktualisierung 22.10.2026, 0.15.0: Nutzer bestätigt übrigen großen 0.14-Test als
funktionierend; Suchtreffer/Explorer wurden nachgebessert. Neu ausdrücklich
beauftragte Datenbereinigung (Cache/Evidences/Results) mit Vorschau, strikter
Bestätigung, lokalem Originalschutz und Sperre gegen offene/neue Jobs.
104 Tests, Ruff und EXE-/Browserprüfungen bestanden; Nutzerabnahme 0.15 offen.
Finaler Build dist/0.15.0-final, Startverknüpfung „Testversion 0.15 starten“.
Aktuelle Testanleitung docs/NEXT_TEST.md. Keine Nutzerdaten beim Agententest gelöscht.
Nach erfolgreichem Nachtest folgt das bereits gewünschte Co-Projektmanagement-Review.


Aktualisierung 22.10.2026, 0.19.0: Nutzerabnahme 0.15 erfolgt („Perfekt passt“).
Auf ausdrücklichen Wunsch vier größere Pakete vor gemeinsamem Test umgesetzt:
Arbeitsziel für neue Jobs (registrierte Ordner, keine Migration), optionales ZIP mit
separater persistenter Archivierung im seriellen Worker, HTML-/JSON-Bericht mit
Eingangs-/Archiv-SHA1/SHA256, Befehlszeiten/Tooldaten/Unterordnern und gezielte
Bereinigung je Auftrag. Arbeitsziel ist serverlokal, nicht Konfigurationsexport;
pro Job einfrieren, alte Jobs am bisherigen Ort. Pfade zentral via workspaces.job_paths.
Results umfasst auch Reports. Offene Archivierungen blockieren Cleanup. ZIP erst
auf eigenen Klick erstellen, keine erneute Analyse. 111 Tests/Ruff, Browser und
EXE-Checks bestanden. Nutzerabnahme 0.19 steht aus; docs/NEXT_TEST.md verwenden.
Separate Testinstanz .local-data/ui-v019 auf 8769 mit Tool-/Moduskonfigurationskopie,
keine Evidenzen kopiert. Bisherige ui-v021/8767 unverändert weiterlaufen lassen.
0.14 auf zusätzlichen Nutzerwunsch als ursprüngliche EXE mit Startanleitung gepackt:
dist/PostProcessingMagic-0.14.0-Windows.zip, ohne Nutzerdaten/Token.
Co-PM-Agent hat autorisiert lesend geprüft; Prioritätenfragen erst nach großem Test.


Neue spätere Vormerkung 22.10.2026: Desktop-Control-Panel bei EXE-Start mit Server
starten/stoppen, Status und Serverlogs. Noch nicht implementieren; ROADMAP beachten.
Neue Bereitstellungspräferenz: Releases auf Google Drive bereitstellen und Link
für Nutzertest geben; nur Releaseartefakte, keine Tokens/Nutzerdaten hochladen.
