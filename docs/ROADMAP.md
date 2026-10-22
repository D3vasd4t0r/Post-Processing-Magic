# Meilensteine und gemeinsame Tests

Stand: 22.10.2026. Kleine, abgeschlossene Features liefern und danach auf Nutzerfeedback
warten. Jede Testiteration enthält Änderungen/Features, Testadresse, aktuellen
Access Token, nummerierte Klickschritte und den Hinweis: Feedback hier im Chat.

## Aktueller Entscheidungsstand nach Nutzerabnahme 0.9

- Nutzerabnahme 0.15: „Perfekt passt“. Damit sind auch die nachgebesserten
  Suchtreffer/Explorer und die übrigen 0.10–0.14-Tests akzeptiert.
- Neue ausdrückliche Freigabe: während Abwesenheit vier bis fünf größere Pakete
  umsetzen, danach ein gemeinsamer großer Test. Aus bestätigten Ideen ausgewählt:
  0.16 Arbeitslaufwerk, 0.17 optionales/nachträgliches ZIP, 0.18 Abschlussbericht,
  0.19 gezielte Bereinigung pro Auftrag. Gemeinsam in Build 0.19 bereitstellen.
- Co-Projektmanagement-Agent hat nach der Abnahme auf ausdrückliche frühere Bitte
  einen lesenden Planreview durchgeführt: Pfad-Snapshot zuerst, weiterhin serieller
  Worker, Archive separat anfordern, vollständiger Bericht außerhalb des ZIPs.
  Fragen nach Zielen/Kollegen/V1-Priorität erst nach dem kommenden großen Test.
- Grenzen: keine Datenmigration, kein neues Analyseprofil, keine parallelen Jobs,
  keine E01/VMDK-/Malware-Erweiterung, keine neuen nicht abgestimmten Ideen.
- 0.19 technisch geprüft: 111 Tests, Ruff, Browserbedienung und EXE-Startup/
  Gesamtprüfung erfolgreich. Separate Nutzerinstanz auf 8769 mit Konfigurationskopie;
  bisherige Instanz auf 8767 unverändert. Gemeinsame Nutzerabnahme noch offen.
- Nutzer bestätigt am 21.10.2026: alle von ihm durchgeführten Tests erfolgreich;
  Oberfläche und Funktionen funktionieren. Version 0.9 ist damit manuell abgenommen.
  Daraus keine Prüfung eines tatsächlichen 2-TB-Archivs oder jedes Sonderfalls ableiten.
- Nächster Schritt durch „Ok dann los“ freigegeben: die bereits gewünschte
  lokale Ergebnisanzeige „Show in Explorer“ als kleines abgeschlossenes Feature 0.10.
- Nutzer ist vorübergehend nicht am Laptop: Explorer-Nutzerabnahme bleibt offen
  und wird mit dem nächsten Test gebündelt. Fortsetzung mit einem weiteren kleinen
  Meilenstein ausdrücklich erlaubt: Speicherübersicht 0.11 (bestätigte Idee 1).
  Laufende Instanz 0.10 während der Entwicklung weiterlaufen lassen; Umschalten
  auf 0.11 über Windows-UAC erst bei Rückkehr, sofern keine menschliche Bestätigung
  möglich ist. Keine Abnahme aus der Vertagung ableiten.
- Anschließend ausdrücklich zwei weitere Meilensteine vor einem gemeinsamen
  großen Nutzertest freigegeben: 0.12 Auftragssuche und 0.13 Warteschlangenpause.
  Gebündelter Build 0.13 enthält auch Explorer und Speicherübersicht. Alle vier
  Nutzerabnahmen bleiben bis zum gemeinsamen Test offen. Bestehende Instanz 0.10
  unverändert lassen; Startverknüpfung und NEXT_TEST.md für Rückkehr vorbereiten.
- Auf ausdrücklichen weiteren Wunsch vor dem Test zusätzlich Forensik-Design 0.14
  umsetzen: blaues Thema, Schild im Hintergrund und aufgearbeitete Oberfläche.
  Die rote Malware-Ansicht bleibt ausdrücklich später. Gemeinsamer Testbuild 0.14
  ersetzt 0.13 als empfohlene Testversion; bisherige Nutzerinstanz weiterlaufen lassen.
- Offen zur Auswahl: zusätzliche generische Toolrunner neben KAPE/PowerShell;
  Release-Vorbereitung mit dokumentiertem Konfigurations-Rundlauf und Prüfung auf
  einem sauberen Windows-Rechner; optionale Hashfunktionen. E01/VMDK und der
  getrennte statische Malware-Bereich bleiben spätere Erweiterungen.
- Die einzelne Nutzerauswahl steht in [BRAINSTORM.md](BRAINSTORM.md): Ja zu
  Speicherübersicht, Arbeitslaufwerk, Aufräumen, Auftragssuche, Abschlussbericht
  mit Hashwerten/Ordnerübersicht, Warteschlangenpause und optionalem Ergebnis-ZIP.
  Nein zu Auftrag wiederholen und sichtbarem Konfigurationsverlauf.
  Zeitlimit pro Block: eventuell, erst ganz zum Schluss erneut ansprechen.
  Mehrere gleichzeitige Aufbereitungen sind auf Zusatzwunsch für ganz später
  vorgemerkt. Die nächste Implementierung weiterhin gesondert auswählen.

## Abgeschlossen

- Startgerüst: Launcher, Datenordner, SQLite, Instanzsperre, Browserzugang und EXE-Build
- Toolverwaltung 0.2.0: hinzufügen, prüfen, bearbeiten und entfernen
- Token-Hilfe und Tokenanzeige nach Anmeldung
- Automatisch selbstsigniertes HTTPS für LAN-Zugriff
- **Testlauf 1 vom Nutzer bestätigt: Schritte 1–5 funktionieren.**

Technische Prüfungen und Grenzen: [VALIDATION.md](VALIDATION.md).

## Nächster Testlauf: Path-Picker (0.2.1)

- [x] „Durchsuchen…“ direkt neben dem Tool-Pfad
- [x] Dateien und Ordner auf dem Server durchsuchen, auch von einem anderen Gerät
- [x] Laufwerke, übergeordneten Ordner und Startordner öffnen
- [x] Nach Namen suchen und vollständige Datei-/Ordnerpfade direkt öffnen
- [x] Ausgewählte Datei oder aktuellen Ordner ins Formular übernehmen
- [x] Toolname vorbelegen, wenn das Namensfeld noch leer ist
- [x] Abbrechen verändert keine Formularwerte oder gespeicherten Einstellungen
- [x] Zugriff nur mit Token; Dateiinhalte werden nicht ausgeliefert
- [x] Begrenzte Verzeichnislisten und verständliche Fehlerzustände
- [x] Zwölf automatisierte Tests und Lint bestanden
- [x] EXE-Build und Browserprüfung abschließen
- [x] Nutzer testet Datei-, Ordnerauswahl und Abbrechen: Schritte 1–4 erfolgreich

### Kleine Nachbesserung 0.2.2

- Nach Auswahl und Speichern eines Tools beim nächsten Hinzufügen wieder dessen
  Ordner im Picker öffnen; mehrere Tools nacheinander ohne erneutes Navigieren
- Zuletzt gewählten Ordner im Browser-Tab über Seitenneuladen hinweg merken
- Beim Bearbeiten den aktuellen Toolpfad bevorzugen
- Bloßes Navigieren und Abbrechen überschreibt den zuletzt gewählten Ordner nicht
- Danach kurzer gemeinsamer Nachtest, bevor eigene Modi folgen

Nutzer bestätigt: Nachbesserung funktioniert.

Der neue Test-Build liegt in `dist/0.2.1/PostProcessingMagic.exe`. Eine separate
Testinstanz läuft auf `http://127.0.0.1:8767` mit `.local-data/ui-v021` als Datenordner.
Die frühere Testinstanz und deren Einstellungen wurden nicht geändert.

## Aktueller Meilenstein 0.3.0: Modi und Befehlsblöcke (hohe Priorität)

Implementiert und technisch geprüft: 24 Tests bestanden, Ruff bestanden,
Windows-EXE gebaut und im Browser gestartet. Ein gemeinsamer Nutzertest steht aus.
Vorbereitete Testkopie: „UI-Test: Befehlsbaukasten“; die Original-KAPE-Vorlage
bleibt unverändert. Es wurde kein Tool ausgeführt.

Nutzer bestätigt: übriger Baukasten funktioniert. Nachbesserung 0.3.1:
Import, Verarbeitung und Export als getrennte Kategorien; Ergebnisordner unter
Export in eigener Zeile; Aufwand als Dropdown schnell / Medium / langsam.
Anschließend kurzer gemeinsamer Nachtest, danach Import/Export der Konfiguration.

## Aktueller Regel-Meilenstein 0.4.0: eindeutige Stufen und Speichern-Abschluss

- Pro Evidence-Format jeweils höchstens ein Modus für schnell, Medium und langsam
- Beim Neuanlegen bereits belegte Stufen im Aufwand-Dropdown deaktivieren
- Beim Bearbeiten die eigene Stufe behalten können; eine anderweitig belegte
  Stufe bleibt gesperrt. Zusätzlich serverseitig und transaktional absichern.
- Bestehende doppelte Testmodi als Konflikt behandeln; keine Nutzerdefinitionen
  ohne Abstimmung löschen oder still einer anderen Aufwandsstufe zuordnen
- In der späteren Run-Hauptseite Stufen ohne gültige Befehlssammlung ausgrauen;
  bloß ein Modusname reicht für die Ausführbarkeit nicht aus
- Editor-Verfügbarkeit und Run-Verfügbarkeit unterscheiden: unbenutzte Stufen
  dürfen im Editor angelegt werden, stehen für Run erst nach vollständiger Konfiguration bereit
- Nach erfolgreichem Speichern Editor schließen und zur aktualisierten Übersicht
  scrollen; Speichervalidierungsfehler lassen den Editor und seine Eingaben offen
- Konfigurationsstatus pro ZIP-Stufe anzeigen: fehlt, unvollständig, hinterlegt oder Konflikt
- 27 automatisierte Tests und Lint bestanden; noch kein ausführender Runner
- EXE 0.4.0 und Browserprüfung abgeschlossen: erfolgreicher Speicherabschluss,
  Validierungsfehler mit erhaltenen Eingaben und deaktivierte belegte Dropdown-Stufen
- Vorhandene Testdaten enthalten doppelt langsam; schnell ist frei. Konflikt
  wird dem Nutzer angezeigt und bleibt bis zur bewussten Änderung erhalten.
- Nutzer-Rückmeldung zu 0.3.1: ansonsten funktioniert alles, Weiterarbeit autorisiert

- Leerer Start, keine automatisch freigegebenen Analyseprofile
- Modi in Einstellungen anlegen, benennen, beschreiben, bearbeiten und entfernen
- Format-/Aufwandszuordnung so festlegen, dass die spätere Hauptseite einfach bleibt
- Testlauf: Modi anlegen und nach Neuladen wiederfinden; noch keine Toolausführung
- Auf ausdrücklichen Wunsch KAPE-Vorlage „Medium / ohne Timeline“ einmalig anlegen
- ZIP-Entpackziel separat konfigurieren: Targets + C im Archiv ergibt Targets/C
- Pro Aufbereitung eigener lokaler Ordner unter work/{Aufbereitungs-ID}
- Ergebnisordner festlegen, der nach allen Befehlen später gezippt wird

### In denselben Meilenstein vorgezogen: Schritte pro Modus

- Tools referenzieren und Reihenfolge der Kommandozeilenaufrufe bestimmen
- Argumente und dokumentierte Platzhalter für Evidence, Ausgabe und Fallmetadaten
- Vorschau der effektiven Befehle; ohne PS1-Dateien zu bearbeiten
- Erst nach gemeinsamer Bestätigung festlegen, welche Tools in welchem Modus laufen
- Testlauf: kleine Schrittfolge erstellen, umsortieren und überprüfen

Für Version 1 ausschließlich ZIP (KAPE-Target). E01/VMDK sind im Dropdown als
„in Planung“ deaktiviert und werden auch beim Speichern serverseitig abgewiesen.
Der aktuelle Editor speichert reine Entwürfe. Ein eigener KAPE-Toolpfad muss vom
Nutzer zugeordnet werden; kein Programm wird aus einer Vorlage heraus gestartet.

Nutzerabnahme 0.4.0: „klappt“. Nächster kleiner Meilenstein freigegeben.

## Aktueller Meilenstein 0.5.0: Konfiguration exportieren und importieren

- Alle Tool- und Modusdefinitionen samt Schritten, Argumenten und Platzhaltern
- Versionierte JSON-Datei, Größenlimit, Vorschau und Validierung
- Konflikte bei Namen und Referenzen sichtbar behandeln; Zusammenführen/Ersetzen
- Pfade auf anderem Rechner neu zuordnen, fehlende Tools verständlich anzeigen
- Keine Tokens, Schlüssel, Evidencen oder Tool-Binaries exportieren
- Import führt keine Befehle aus
- Implementiert: Vorschau mit neuen/geänderten/entfallenden/unveränderten Einträgen,
  Zusammenführen nach stabilen IDs, bestätigtes Ersetzen, zehn Minuten gültige
  Einmal-Vorschau und Prüfung auf zwischenzeitliche Änderungen
- Automatische JSON-Sicherung vor dem Import, atomare SQLite-Transaktion und Audit
- 36 automatisierte Tests, Ruff und JavaScript-Syntaxprüfung bestanden
- EXE `dist/0.5.0/PostProcessingMagic.exe` gebaut und auf Port 8767 gestartet.
  Browserexport heruntergeladen, dieselbe Datei ausgewählt, Vorschau mit allen
  Einträgen unverändert und anschließend erfolgreicher Import mit Sicherung geprüft.
  Aktuelle Nutzerkonfiguration: zwei Tools und zwei Modi ohne Stufenkonflikt.
- Gemeinsame Nutzerabnahme des Konfigurationstransfers bestätigt: „Klapüpt mega“.
- Parametertext und Reihenfolge werden erhalten. Platzhalterauflösung bleibt ein
  eigener späterer Schritt vor der echten Ausführung.
- Testlauf: Export/Import ohne Datenverlust und mit absichtlich fehlerhafter Konfiguration
- **Release-Voraussetzung für V1:** dieser gemeinsame Test muss vor dem ersten
  Release bestanden sein; Tools und vollständige Befehlsfolge müssen erhalten bleiben

## Aktueller Meilenstein 0.6.0: Einfache Hauptoberfläche

Die Hauptseite zeigt nur den für die Nutzung nötigen Ablauf:

1. Datei auswählen/hochladen
2. Evidence-Format auswählen
3. Aufbereitungsaufwand bzw. zugeordneten Modus auswählen
4. Run starten
5. Gesamtfortschritt sehen: erledigte/gesamte Commands und aktueller Command
6. Optional „Kommandozeile anzeigen“ öffnen: tatsächlicher Aufruf und Live-Ausgabe
7. Nach erfolgreichem Abschluss „Download Evidences“ verwenden

Toolpfade, Modusdefinitionen und technische Dienstinformationen bleiben in Einstellungen.
Vorhandene Modi bestimmen die angebotenen Formate/Aufwandsstufen. Keine erfundenen
Analysefunktionen oder simulierten Fortschritte anzeigen. UI-Vorschau und echte
Verarbeitung klar unterscheiden. Vor Runner-Entwicklung die Oberfläche gemeinsam testen.

Implementiert als Oberflächentest: Dateiauswahl prüft ausschließlich Dateiname
und Dateigröße im Browser. Kein Upload, Lesen oder Extrahieren des ZIP-Inhalts.
Nur ZIP (KAPE-Target) wählbar, E01 und VMDK deaktiviert. Aufwandsstufen ohne
vollständige Befehlsfolge mit existierenden Tooldateien sowie Konflikte bleiben
ausgegraut. Ein ausgewählter konfigurierter Modus erlaubt die Ablaufvorschau:
Entpackziel, geordnete Toolaufrufe mit Parametern und Ergebnisordner.
Die Vorschau ist weder Argumentvalidierung noch Analysefreigabe.

Run und Download Evidences bleiben deaktiviert. Beide Fortschrittsanzeigen
bleiben bei null; Live-Kommandozeile zeigt „kein Befehl gestartet“.
Änderung der Datei oder Auswahl verwirft die alte Vorschau. Beim Rückweg aus
Einstellungen wird die Modusverfügbarkeit neu geprüft. Technischer Dienststatus
steht in Einstellungen → Tools. Nutzerabnahme erfolgt: „sieht super aus“.

Technisch geprüft: 36 bestehende Tests, Ruff, JavaScript-Syntaxprüfung,
EXE-Build und tatsächlicher Start. Eigene synthetische Testinstanz mit zwei
Beispielbefehlen: Dateiauswahl, gesperrte Stufen, Ablaufvorschau, Parameter und
Reihenfolge sowie Verwerfen der alten Vorschau geprüft. Keine Toolausführung.
Nutzerinstanz auf Port 8767 aktualisiert; deren unvollständige Stufen sind
erwartungsgemäß gesperrt. Eigene kleine Beispiel-ZIP für den reinen UI-Test:
`.local-data/ui-main-060/UI-Beispiel-KAPE-Target.zip`.

## Aktueller Meilenstein 0.7.0: erster echter ZIP/KAPE-Test

Nutzer hat KAPE eingebunden und ausdrücklich um echte ZIP-Aufbereitung gebeten.
Sein Modus „KAPE-Target / Medium / ohne Timeline“ ist der Stufe schnell zugeordnet;
Zuordnung und Name nicht eigenmächtig ändern. Der Test-Baukasten mit mehreren
Hilfebefehlen bleibt von der ersten Ausführung ausgeschlossen.

- Streaming-Upload bis 50 GiB, SHA-256 als Eingangsmanifest, Original-ZIP behalten
- ZIP/ZIP64 vor Extraktion auf Windows-Pfade, Links, ADS, Namenkonflikte,
  Verzeichnisgröße, Dateianzahl und Kompressionsverhältnis prüfen
- Limits: 200.000 Einträge, 200 GiB entpackt, 1000:1, maximal 64 Pfadkomponenten;
  eingebettete Archive werden als Dateien erhalten und nicht rekursiv entpackt
- Persistente SQLite-Queue, vier offene Aufträge, ein separater Workerprozess
- Genau ein kape.exe-Modulbefehl mit --msource / --mdest / --module / optional --gui;
  Quellen/Ziele müssen in den konfigurierten relativen Ordnern bleiben
- Run gibt den hinterlegten Befehl ausdrücklich für diesen Lauf frei. Konfiguration,
  Toolhash und PE-Version erfassen; Tool vor Ausführung erneut auf Änderung prüfen
- Windows Job Objects vor Prozessfreigabe zuweisen; Abbruch und 24-Stunden-Timeout
  beenden auch Unterprozesse. Neustart markiert offene Jobs als unterbrochen.
- SSE mit fortsetzbarer Ereignis-ID, Live-Log bis 16 MiB, aktuelle Anzeige 64 KiB
- Gesamtanzeige 0/1 bzw. 1/1; aktueller KAPE-Fortschritt bleibt unbestimmt
- Nach Exitcode 0 und nicht leerem Ergebnisordner ZIP mit KAPE-Ausgaben, Log und
  Aufbereitungsprotokoll erstellen. Native Downloads verwenden einen nach
  Authentifizierung erstellten Einmallink mit 120 Sekunden Gültigkeit.
- Löschversuch eingebundener Tools: sichtbare Warnung mit allen betroffenen Modi;
  Verknüpfungen und Tooldefinition bleiben ausdrücklich erhalten (Nutzerkorrektur).
- 55 automatisierte Tests bestanden. EXE-Vorabtest mit selbst kompiliertem Stub:
  erfolgreicher Ergebnisdownload, Fehlercode 7 und Abbruch samt Unterprozess geprüft.
- Echte KAPE-/ZIP-Nutzerabnahme steht aus. Keine Testsicherung vorab eingesehen.

## Aktueller Fix-Meilenstein 0.8.0

- Quellen-Dropdown Upload / lokale Datei auf dem Server mit ZIP-Path-Picker.
  Lokale Referenz ohne Upload oder Eingangskopie, auch über 50 GiB.
  Identität bei Auftragserstellung erfassen; während Hash/Extraktion ausschließlich
  lesend mit Windows-Sperre gegen paralleles Schreiben/Löschen öffnen.
- Konkreter 0.7-Fehler: Archiv-Kompressionslimit; Fehlermeldung nennt jetzt Datei,
  Verhältnis und Größen. Explizite Archivoption für bekannte stark komprimierte
  Sicherungen; übrige Entpack-/Pfad-/Speicherlimits bleiben erhalten.
- Ein einzelner Laufwerksordner G statt angefordertem C wird automatisch verwendet;
  keine Archivnamen ändern. Mehrere Kandidaten bleiben ein erklärter Fehler.
  Ursprüngliche und effektive Konfiguration getrennt protokollieren.
- KAPE meldete fehlende Administratorrechte trotz Exitcode 0. Dies wird als
  Berechtigungsfehler erkannt. Standardstart fordert UAC an; alle Befehle erben
  die erhöhten Rechte. Kein stiller Rückfall auf normalen Ausführungsmodus.
- Detaillierte Fehler mit Phase, Ursache, Hinweis und Traceback speichern;
  Logs-Tab für die letzten 50 Läufe, Diagnose-TXT und KAPE-Logdownload.
- Alte fehlgeschlagene Läufe bleiben sichtbar. Neuer-Lauf-Schaltfläche setzt nur
  die Browseransicht zurück. Authentifiziertes Dienstbeenden in Einstellungen.
- 63 automatisierte Tests bestanden; finaler EXE-Verarbeitungstest zusätzlich mit
  lokaler G-ZIP ohne Eingangskopie bestanden. UAC-Start auf Port 8767 durchgeführt;
  API und Browser bestätigen aktive Administratorrechte und verfügbaren Worker.
  Browser-Picker und Logs geprüft. Echter KAPE-Nutzertest steht aus.

## Aktueller Meilenstein 0.9.0

- Nutzerabnahme 0.8: kleine und mittlere echte KAPE-Tests erfolgreich.
- Entpacklimit standardmäßig 2 TB dezimal, Uploadlimit unverändert 50 GiB.
  Beide in Einstellungen → Verarbeitung speichern und pro Auftrag einfrieren.
- JSON-Schema 2 überträgt Limits und PowerShell-Blöcke; Schema 1 kompatibel halten.
- Terminal fester Höhe, automatisches Folgen mit Scrollpause und Fortsetzen.
- Expliziter freier PowerShell-Block ohne Tool/PS1; geordnet vor/nach KAPE oder
  allein. Relatives Arbeitsverzeichnis pro Block, cd nur innerhalb eines Blocks.
- Synthetische Funktions- und EXE-Tests; danach gemeinsame manuelle Abnahme.
- Nutzerabnahme erfolgt: Nutzer meldet alle durchgeführten Tests erfolgreich.
- Noch nicht geprüft: tatsächliches 2-TB-Archiv, Ressourcenverhalten bei dieser
  Größe und Ausführung aller frei konfigurierbaren PowerShell-Varianten.

## Danach: Verarbeitung erweitern

- Streaming-Upload, Hashes, Quotas und atomare Finalisierung
- Evidence-Sätze für E01-Segmente und VMDK-Abhängigkeiten berücksichtigen
- Persistente Zustandsmaschine, SQLite-Queue und separater Worker
- Effektive Konfiguration pro Lauf unveränderlich erfassen, Toolversionen und Hashes
- Feste Argumentlisten, Limits, Timeout und Prozessbaum-Abbruch
- Pro Command ehrlicher Fortschritt: unbekannter Fortschritt bleibt unbestimmt;
  stdout-Marker allein beweisen keinen erfolgreichen Abschluss
- SSE mit wiederaufnehmbaren Ereignissen, Ausgabe separat vom dauerhaften Audit
- Ergebnisprüfung, Manifest/Report, Ergebnis-ZIP und autorisierter Download
- Synthetischer erster Testablauf; danach jede Aufbereitungsart einzeln abnehmen

### Hauptmeilenstein vor dem ersten Release: echter ZIP/KAPE-Gesamttest

- Erst nach bestätigtem Baukasten- und Konfigurationsimport/-export-Test
- Nutzer lädt seine vorbereitete ZIP-Testsicherung selbst über die Hauptoberfläche hoch
- Testsicherung bis dahin nicht vorab suchen, öffnen, untersuchen oder zur
  Entwicklung von Sonderfällen verwenden; der Test soll den echten Uploadablauf prüfen
- Genau ein KAPE-Befehl gemäß der gemeinsam bestätigten Vorlage
- ZIP im eindeutigen Arbeitsordner entpacken, KAPE-Ende/Fehler prüfen,
  PostMortem zippen und „Download Evidences“ bis zur heruntergeladenen Datei testen
- Noch keine E01-/VMDK-Unterstützung. Echten KAPE-Lauf startet der Nutzer per Run.
- Erst dieser spätere Haupttest prüft die tatsächliche Funktionsfähigkeit des
  Verarbeitungsablaufs; ein erfolgreicher Konfigurationstest ersetzt ihn nicht

## Meilenstein 0.14: blaues Forensik-Design vor gemeinsamem Test

- Dunkelblaue Oberfläche mit hellblauen Bedienelementen, konsistenten Karten,
  Formularen, Navigation, Dialogen, Logs und Terminalfarben.
- Dekoratives Schild als dezentes Hintergrundmotiv sowie im Kopfbereich und
  neben dem Appnamen. SVG lokal im HTML, keine externen Bilder/Fonts/Downloads.
- Dekoration nicht interaktiv und vor Screenreadern verborgen. Fokusmarkierungen,
  Warn-/Fehlerfarben, deaktivierte Zustände und kleine Bildschirmbreiten berücksichtigen.
- Keine Änderung an Auftragsverarbeitung oder Konfiguration. Kein Malware-Runner,
  kein Bereichsumschalter und keine rote Ansicht in diesem Meilenstein.
- Anschließend großer gemeinsamer Nutzertest 0.10–0.14 in NEXT_TEST.md.
- 93 Tests, Ruff, JavaScript-Syntax, EXE-Build und Start-/Neustarttest bestanden.
  Finale EXE visuell mit eigenen Testdaten geprüft; Screenshot gespeichert.
  Verknüpfung 0.14 vorbereitet, Nutzerinstanz unverändert. Gemeinsame manuelle
  Abnahme einschließlich kleiner Bildschirmbreite steht aus.

## Meilenstein 0.12: Auftragssuche und Filter

- Gesamte gespeicherte Historie statt nur letzte 50 Aufträge durchsuchen.
- Suche in Dateiname und gespeichertem Modusnamen; Unicode-Groß-/Kleinschreibung
  berücksichtigen, Suchzeichen wie Prozentzeichen wörtlich behandeln.
- Status, Modus und einschließliches UTC-Datum filtern; 50 Treffer pro UI-Seite,
  Gesamtzahl sowie Vor-/Zurücknavigation. Leere Ergebnisse leeren alte Details.
- Nur Metadaten abfragen, keine Evidencen/Dateiinhalte lesen. Authentifizierung,
  Parametervalidierung und SQL-Parameterbindung beibehalten.

## Meilenstein 0.13: Warteschlange pausieren und fortsetzen

- Persistente globale Pause unter Einstellungen → Verarbeitung, Anzahl wartender
  und bereits übernommener Aufträge anzeigen. Pause gilt vor dem nächsten Auftrag,
  nicht zwischen Befehlen oder mitten im Werkzeugprozess.
- Pause und Auftragsübernahme teilen dieselbe SQLite-Schreibtransaktion, sodass
  nach bestätigter Pause kein weiterer Auftrag übernommen wird. Ein zuvor schon
  übernommener Auftrag läuft weiter. Keine parallele Verarbeitung einführen.
- Während Pause neue Aufträge entgegennehmen und als wartend darstellen;
  wartende Aufträge lassen sich ohne Fortsetzen sofort abbrechen.
- Pause bleibt nach Neustart erhalten; alte Wiederanlaufregel bleibt unverändert:
  nicht abgeschlossene Aufträge als unterbrochen markieren, niemals blind wiederholen.
- Pausenzustand ist Betriebszustand und kein Bestandteil des Tool-/Modus-Exports.
  Änderungen dauerhaft mit UTC-Zeit in queue_control_events protokollieren.
- Gemeinsamer Nutzertest mit 0.10/0.11 in NEXT_TEST.md.
- Beide zusätzlichen Meilensteine technisch geprüft: 93 Tests und finale
  EXE-Verarbeitungs-/Neustarttests bestanden; Browserablauf mit eigenen Daten
  bestätigt Suche/Pagination und Pause vor/während eines Auftrags. Verknüpfung
  für finalen Build 0.13 vorbereitet, Nutzerinstanz weiter 0.10. Keine weiteren
  Meilensteine vor dem angeforderten großen gemeinsamen Nutzertest beginnen.

## Meilenstein 0.11.0: Speicherübersicht und gebündelter Nutzertest

- Unter Einstellungen → Verarbeitung freien/belegten Speicher des Datenlaufwerks
  anzeigen. Separater Knopf misst Eingänge, Arbeitsordner und Ergebnisarchive.
- Nur Dateimetadaten lesen; keine Eingangsdateien öffnen oder extern referenzierte
  Originale durchsuchen. Reparse Points einschließlich Junctions überspringen.
- Logische Größen, Dateien/Unterordner, Zeitpunkt, übersprungene Verknüpfungen
  und Fehler anzeigen. Laufende Aufträge können Werte während der Messung ändern.
- Messung auf 10 Sekunden/500.000 Einträge begrenzen, Teilmessung als Untergrenze
  kennzeichnen; nur eine Messung gleichzeitig. Kein automatischer Verzeichnisscan
  bei jedem Seitenaufruf. GET liefert Laufwerksplatz und letzte Messung.
- Nutzer testet anschließend Speicherübersicht und Show in Explorer gemeinsam;
  Anleitung in NEXT_TEST.md. Keine zusätzliche Aufbereitung für diesen Test nötig.
- 89 Tests, Ruff, JavaScript-Syntax und gebaute EXE inklusive Verarbeitung/Neustart
  geprüft. Browserprüfung mit eigenen Metadaten erfolgreich; letzte Messung bleibt
  beim Seitenwechsel erhalten. Eigene Testinstanz wieder beendet. Startverknüpfung
  für 0.11 vorbereitet; Nutzerinstanz läuft bis Rückkehr unverändert auf 0.10.
  Gemeinsame manuelle Abnahme beider Features noch offen.

## Meilenstein 0.10.0: Ergebnisse im Windows Explorer anzeigen

Nutzerwunsch vom 21.10.2026; nach Abnahme 0.9 als nächster Schritt freigegeben.

- Nach erfolgreicher Aufbereitung neben „Download Evidences“ die lokale Alternative
  **„Show in Explorer“ / „Im Explorer anzeigen“** anbieten. Direkt am Server den
  konfigurierten Ergebnisordner öffnen, ohne Ergebnisdateien erneut herunterzuladen
  oder zu kopieren. Besonders für große Aufbereitungen vorgesehen.
- Das Explorerfenster gehört zur interaktiven Windows-Sitzung auf dem Server,
  nicht zum Dateisystem eines entfernten Browsergeräts. Funktion nur für die lokale
  Bedienung anbieten und serverseitig auf autorisierten lokalen Zugriff begrenzen;
  Remotezugriff behält den Ergebnisdownload.
- Ausschließlich den gespeicherten, geprüften Ergebnisordner des ausgewählten
  Auftrags öffnen; keine frei übergebenen Explorerpfade oder Shellbefehle ausführen.
  Dateien nur anzeigen, keine enthaltenen Programme oder Dokumente starten.
- Fehlender/bereinigter Ergebnisordner oder fehlende interaktive Windows-Sitzung:
  verständliche Meldung anzeigen. Der Download bleibt eine separate Möglichkeit.
- Für Forensik und den späteren Malware-Bereich vorsehen. Späterer Test: großer
  Ergebnisordner öffnet lokal ohne Datentransfer; Remoteaufruf öffnet kein Fenster;
  fehlender Ordner wird sauber gemeldet.
- Umsetzung: lokale Ergebnisanzeige auf Hauptseite und im Logs-Tab, Token- und
  Clientprüfung, Windows-Sitzungsprüfung, Snapshotpfad ohne Reparse Points sowie
  verständliche Fehler und Auftragsereignis. Automatisierte Tests vorhanden.
  EXE-/Browserprüfung und anschließende Nutzerabnahme separat dokumentieren.
- 83 Tests, Ruff, JavaScript-Syntaxprüfung, EXE-Verarbeitung und Start-/Neustarttest
  bestanden. Browser-Aufruf mit eigenem Ergebnisordner erfolgreich an Windows
  übergeben. Nutzertab auf Version 0.10 aktualisiert, vorhandener erfolgreicher
  Lauf im Logs-Tab für Test vorbereitet. Nutzerabnahme steht aus.

## Späterer Meilenstein nach ZIP/KAPE-V1: statische Malware-Analyse

Nutzeridee vom 21.10.2026, ausdrücklich für später vorgemerkt. Keine Umsetzung
in der aktuellen Testiteration und keine Voraussetzung für den ersten ZIP/KAPE-Release.

- Prominenter Bereichsumschalter (vom Nutzer „Kill Switch“ genannt) zwischen
  **Forensik** und **Malware-Analyse**. Forensik: blaues Thema mit Schildsymbol.
  Malware-Analyse: rotes Thema mit Totenkopfsymbol, eigene Hauptansicht und klar
  sichtbare Bereichsbezeichnung. Gemeint ist hier der Ansichts-/Bereichswechsel;
  der vorhandene Auftragsabbruch bleibt eine eigenständige Funktion.
- Gemeinsame Toolverwaltung: Toolnamen, Pfade und Änderungen zentral pflegen,
  dieselben Tools in beiden Bereichen referenzieren, keine doppelte Registrierung.
- Getrennte Modul-/Moduslisten: Forensik-Module und Malware-Analyse-Module mit
  eigener Eingangsformat-Zuordnung und getrennten Aufträgen, Arbeitsordnern und
  Ergebniszuordnungen. Ein Bereichswechsel darf keinen Auftrag starten, umwidmen
  oder abbrechen. Die Backend-Prüfung muss die Bereichszuordnung durchsetzen.
- Malware-Eingang ist genau **eine Datei**, kein ZIP-Evidence-Archiv:
  Windows-Executable, PDF oder Office-Dokument, etwa DOC/DOCX, XLS/XLSX und
  PPT/PPTX. Die genaue Liste der Office-Varianten später gemeinsam festlegen;
  Dateiendung allein reicht für die Formatprüfung nicht aus.
- Ausschließlich **statische Analyse**: die Eingangsdatei nur als Daten an die
  konfigurierten Analysewerkzeuge übergeben, niemals selbst starten. Keine Makros,
  eingebetteten Programme oder Dokumentaktionen ausführen. Das konkrete Ausführungs-
  und Isolationskonzept für Parser vor der Implementierung festlegen; das rote
  Thema allein stellt keine Isolation dar. Die bisherige freie PowerShell-Ausführung
  nicht ungeprüft als statischen Malware-Runner übernehmen.
- Als erste gemeinsam abzustimmende Beispiele PDFID für PDFs und oleid für
  Office-Dateien vormerken. Weitere Analysewerkzeuge und deren Befehle später
  einzeln mit dem Nutzer festlegen, keine fertige Toolpalette voraussetzen.
- Gleicher Baukasten und Bedienungsablauf: Datei wählen, passenden Modus wählen,
  geordnete Tool-/Befehlsblöcke mit Parametern, Run, ehrlicher Fortschritt,
  scrollbares Terminal, Fehlerdetails und Logs. Kein Ausführen beim Speichern,
  Importieren oder Umschalten.
- Pro Datei eigener lokaler Arbeitsordner; relativen Ergebnisordner konfigurieren.
  Alle darin erzeugten Ergebnisdateien nach Abschluss als ZIP zum Download anbieten.
  Unveränderte Eingangsdatei getrennt halten und nicht automatisch mit exportieren.
- Konfigurationsimport/-export auf beide Modulbereiche erweitern; gemeinsame
  Toolreferenzen und Bereichszuordnung erhalten, bestehende Forensik-Konfigurationen
  kompatibel migrieren. Import startet keine Analyse.
- Spätere Abnahme in kleinen Schritten: erst Ansichten/Umschalter und gemeinsame
  Tools, danach ein statischer PDF-Ablauf mit eigener harmloser Testdatei bis zum
  Ergebnisdownload, danach Office und Executables jeweils separat. Prüfen, dass
  kein Code der Eingangsdatei ausgeführt wird und die Bereiche getrennt bleiben.

## Vorgemerkt: Abschlussbericht mit Hashwerten und Ordnerübersicht

- Nutzer bestätigt die Berichtsidee mit Ergänzungen: lesbarer HTML-Bericht mit
  Befehlsfolge, Toolversionen, Laufzeiten, Fehlern und Ergebnisübersicht sowie
  Hashwerten der Eingangsdatei und Ausgabedatei(en) und erstellten Unterordnern.
- SHA-1/SHA-256 jeweils mit Algorithmus, Dateiname, Größe und eindeutigem Bezug
  dokumentieren. Zunächst ZIP-Eingang und Ergebnis-ZIP; E01 und andere Formate
  erst mit deren späterer Unterstützung, keine Vorziehung in ZIP/KAPE-V1.
- Bei ungezippten Ergebnissen später eine Dateiliste mit Ergebnisdatei-Hashes
  vorsehen; ein Ordner selbst hat keinen einzelnen Datei-Hash. Importierte und
  während der Verarbeitung neu erstellte Unterordner unterscheiden und relativ
  zum Auftragsordner auflisten.
- Hash des endgültigen Ergebnis-ZIPs erst nach dessen Fertigstellung berechnen
  und im separaten Abschlussbericht/Manifest bereitstellen. Keine zirkuläre
  Forderung, den Hash eines ZIPs im selben unveränderten ZIP zu speichern.
- Berichtshashes sind vorgemerkt; die optionale vollständige ZIP-Inhaltsprüfung
  per Checkbox bleibt ein eigener späterer Punkt niedriger Priorität.

## Ganz später: mehrere Aufbereitungen gleichzeitig

- Ausdrücklicher Nutzerwunsch: mehrere Aufträge parallel ausführen können.
  Aktueller serieller Worker bleibt bis zu diesem späteren Meilenstein erhalten.
- Begrenzte, konfigurierbare Parallelität; CPU, RAM, Datenträger-I/O und freien
  Platz berücksichtigen. Toolverträglichkeit prüfen, insbesondere gemeinsam
  genutzte Toolverzeichnisse und Tools mit eigener GUI oder temporären Dateien.
- Eigene Arbeitsordner, Konfigurationssnapshots, Logs, Fortschritte und Ergebnisse
  pro Auftrag. Abbruch eines Auftrags darf andere Aufträge nicht beenden.
- Persistentes, atomisches Beanspruchen von Queue-Einträgen ohne doppelte Ausführung;
  Warteschlangenpause und Neustartverhalten entsprechend erweitern und testen.
- Erst mit eigenen parallelen Testaufträgen abnehmen; keine Änderung der laufenden
  Version allein durch diese Vormerkung.

## Version 1.5 oder 2: UX-/Design-Review-Agent bzw. Harness

Expliziter Nutzerwunsch: für später vormerken, während des aktuellen Nutzertests
keinen Agenten starten und keine Oberfläche automatisch verändern. Genaue
Versionszuordnung zwischen 1.5 und 2 später gemeinsam festlegen.

- Oberfläche aus Designersicht bewerten: Komposition, Informationshierarchie,
  Abstände, Typografie, Farben/Kontraste, Konsistenz und Zusammenspiel der Ansichten.
- UX anhand konkreter Bedienungswege prüfen: erster Start, Tool-/Modusverwaltung,
  Datei auswählen, Run, Queue/Pause, Fortschritt, Fehlerbehandlung, Logs und Ergebnisse.
  Tastaturbedienung, Fokus, verständliche Beschriftungen und schmale Ansichten einbeziehen.
- Strukturierte Bewertung je Kriterium mit Begründung, beobachtetem Problem,
  Auswirkung und priorisiertem Verbesserungsvorschlag liefern.
- Für relevante Vorschläge Ist-Screenshot und visuelles Beispiel/Mockup der
  vorgeschlagenen Ansicht zeigen. Entwurf klar als Vorschau kennzeichnen, nicht
  als bereits implementierte Funktion. Nur eigene Testdaten für Beispiele verwenden.
- Nutzer entscheidet jeden Vorschlag einzeln mit Ja/Nein bzw. Freigabe. Vor einer
  Umsetzung muss ein konkreter visueller Vorschlag vorliegen. Keine automatischen
  Designänderungen, kein automatisches Veröffentlichen oder Aktivieren einer Variante.
- Abnahme: Reviewbericht, nachvollziehbare Bewertungen, Screenshots/Entwürfe und
  dokumentierte Einzelentscheidungen; nur freigegebene Änderungen anschließend
  als eigene kleine Implementierungsmeilensteine aufnehmen.

## Version 2: Sicherheits-Review-Agent bzw. Harness und sichere Betriebsanleitung

Explizit für Version 2 vorgemerkt. Umfassende technische Sicherheitsprüfung und
praktische Installations-/Betriebsempfehlungen als eigener Meilenstein, keine
Änderung an der aktuell laufenden Testinstanz durch diese Planung.

- Bedrohungsmodell und freigegebenen Prüfumfang zuerst festlegen: lokaler Zugriff,
  LAN-Betrieb, Vertrauensgrenzen zwischen Browser, API, Worker, externen Tools und
  eingehenden Evidencen. Tatsächliche Version/Build und Konfiguration dokumentieren.
- Code-/Abhängigkeitsprüfung und aktive Tests in einer isolierten eigenen
  Testinstallation mit synthetischen Dateien verbinden. Keine echten Evidencen
  oder Tokens an externe Prüfdienste übertragen; keine laufenden Nutzeraufträge
  für Belastungs-/Angriffstests verwenden.
- Prüfbereiche: Authentifizierung und Tokenablage/-rotation, Autorisierung von
  Jobs/Downloads/Events/Explorer, lokale Zugriffsbeschränkungen, Browser-Origin,
  XSS/CSRF, Konfigurationsimport, Pfad-/ZIP-Verarbeitung und Reparse Points,
  Argument-/PowerShell-Ausführung, Prozess-/Rechtetrennung, Ressourcenlimits,
  Abbruch, Audit, Datenablage, Updates und Lieferkette.
- Automatisierte Regressionstests und gezielte manuelle Prüfungen kombinieren.
  Reproduzierbare Befunde mit Schweregrad, Nachweis, betroffener Version,
  Abhilfevorschlag und anschließendem Nachtest liefern. Nicht geprüfte Bereiche,
  Grenzen und verbleibende Risiken ausdrücklich benennen; ein erfolgreicher
  Testlauf ist keine Garantie für die Abwesenheit aller Sicherheitslücken.
- Ergebnisse und erforderliche Architektur-/Konfigurationsänderungen zur
  Entscheidung vorlegen; Behebungen anschließend nachvollziehbar implementieren
  und erneut prüfen. Keine ungeprüften Schutzbehauptungen ausgeben.
- Als verbindliches Ergebnis eine verständliche, schrittweise **sichere
  Installations- und Betriebsanleitung** erstellen: unterstützte Windows-Umgebung,
  geprüfter Build/Integrität, Toolinstallation, Konten und minimale nötige Rechte,
  Ordner-ACLs und Trennung von Originalen/Arbeitsdaten, Tokenhandhabung,
  lokale/LAN-Bindung, Firewall, selbstsigniertes TLS und dessen Vertrauen,
  Logging, Updates, Backup/Wiederherstellung sowie sichere Außerbetriebnahme.
- Die Anleitung auf der tatsächlich geprüften Installation verifizieren und
  lokale Einzelplatz- und LAN-Nutzung klar unterscheiden. Den jetzigen
  Administratorstart nicht allein durch diese Vormerkung verändern.
- Abnahme: Sicherheitsbericht, ausführbare Testfälle, priorisierte Befundliste
  mit Nachtests und eine praktisch geprüfte Installations-/Betriebsanleitung.

## Später: Betrieb und Freigabe

- Individuelle Identitäten, Rollen und Fallrechte
- ACLs, eingeschränkte Workerrechte und externer Audit-Vertrauensanker
- Aufbewahrung, Löschung, Backup und Wiederherstellung
- Wiederaufnahme großer Uploads, Ressourcenbudgets und Lastmessungen
- Tests über zweites Gerät, sauberes Windows-Ziel, Signierung und Verteilung

## Optional und niedrige Priorität: erweiterte Hashfunktionen

- SHA-1 und SHA-256 der importierten Evidence auf Wunsch erzeugen
- Checkbox für ZIP-Inhaltsprüfung: Hashliste jeder enthaltenen Datei als TXT
  erstellen und dem Ergebnisarchiv beilegen; Regeln für verdächtige Archive beibehalten
- E01 später: vorgegebenen Hash samt Algorithmus und Bezugsobjekt vergleichen
  (Containerdatei, Dateisegment oder repräsentierter Datenstrom unterscheiden)
- Eingangsdatei, entpackte Dateien und Ergebnisarchiv eindeutig in der Hashliste benennen
- Diese Funktionen sind optional und keine Voraussetzung für die erste ZIP-Version

Details zum neuen Konfigurationsmodell: [CONFIGURATION.md](CONFIGURATION.md).
Es ersetzt die frühere Idee einer festen Zuordnung zu vorbereiteten PS1-Dateien.

## Fachliche Referenzen für spätere Modi

- [ZIP mit KAPE-Target: Medium ohne Timeline](KAPE_ZIP_MEDIUM.md): sicher entpacken,
  Quellwurzel `Targets\C`, Nutzer-Modulliste ausführen, Ergebnisordner `PostMortem`
  nach Abschluss als Download-ZIP bereitstellen. Seit 0.7 implementiert.


## Sammelmeilenstein 0.16–0.19, ausdrücklich freigegeben

1. Arbeitsziel für neue Jobs speichern, eigenen App-Unterordner kennzeichnen,
   pro Job unveränderlich erfassen; alle Zugriffe/Bereinigung/Speicherübersicht
   verwenden registrierte Pfade. Bestehende Aufträge unverändert lassen.
2. ZIP vor Run optional; spätere Archivierung eigene persistente Anforderung im
   seriellen Worker. Pausieren, Abbrechen, Restart und Cleanup-Sperre beachten.
3. Lesbarer HTML-/JSON-Bericht, Eingangs-/Ausgabe-ZIP SHA1/SHA256 jeweils in einem
   Lesedurchlauf, Befehlszeiten/Tooldaten/Exitcodes/Fehler und Unterordnerübersicht.
   Fehlgeschlagene Verarbeitung liefert soweit speicherbar einen Fehlerbericht.
   Separate Reports erlauben den fertigen ZIP-Hash; eingebetteter Stand erklärt dessen Fehlen.
4. Bereinigung auf ausgewählten abgeschlossenen Job beschränken, auch direkt aus
   Logs erreichbar. Kategorien, Bestätigung und Schutz lokaler Originale beibehalten.

Offene weitere Entscheidungen nach dem Test: Ziele für V1/Verteilung/Kollegen und
Prioritäten der bereits bestätigten Ideen. UX-/Security-Harness weiterhin später.


## Später: Desktop-Control-Panel beim EXE-Start

Ausdrücklicher Nutzerwunsch vom 22.10.2026: später ein kleines GUI-Fenster beim
Start der EXE, vergleichbar einem Server-Control-Panel. Schaltflächen zum Starten
und Stoppen des Servers, sichtbarer Serverstatus und laufende Serverlogs.
Serverlogs von KAPE-/Auftragsausgaben unterscheiden. Kontrolliertes Beenden und
laufende Aufträge berücksichtigen; keine UAC-Umgehung. Weiterhin ohne externes
Python/Node/Docker auf dem Zielrechner. Framework/Version später festlegen.
Nur vorgemerkt, kein Bestandteil des bereits fertigen 0.19-Testpakets.

## Release-Bereitstellung

Nutzer möchte Releases direkt auf sein Google Drive hochgeladen bekommen und
anhand des Downloadlinks testen. Nur explizite Release-Dateien (EXE/ZIP,
Start-/Testanleitung, Prüfsummen) übertragen, niemals Tokens, private Konfigurationen,
Evidenzen, Ergebnisse oder lokale Logs. Google-Drive-Verbindung und Uploadfähigkeit
prüfen, keine erfolgreiche Übertragung ohne überprüfbaren Drive-Link behaupten.


Release-Bereitstellung umgesetzt: 0.19 inklusive Prüfsumme/Testanleitung in privatem
Google-Drive-Ordner, Cloud-Inhalt verifiziert. Vorhandenen 0.14-Upload unverändert
verlinkt. Details/Links siehe RELEASES.md. Nutzerabnahme 0.19 bleibt offen.


Nachbesserung 0.19.1 aus Nutzertest: Adminstatus oberhalb der Navigation,
ZIP-Checkbox inline, lesbarer HTML-Abschlussbericht mit Tabellen (auch für ältere
separate Berichte) und zusätzlich HTML im neu erstellten ZIP. JSON bleibt zusätzlich.
Arbeitsziel-Reset leert den alten Eingabewert und zeigt Standardpfad/Status eindeutig.
Nutzer bestätigt Test 1; Tests 5–7 ausgelassen, synthetisch erneut prüfen.


Nutzerabnahme 0.19.1 am 22.10.2026: „Korrekturen waren erfolgreich“.
Adminstatus, Inline-ZIP-Checkbox, lesbarer HTML-Abschlussbericht und Standard-Reset
sind bestätigt; übriger vom Nutzer durchgeführter Test laut Rückmeldung erfolgreich.
Tests 5–7 wurden vom Nutzer ausgelassen und ausschließlich mit synthetischen Daten
technisch geprüft; keine manuelle Nutzerabnahme dieser drei Schritte behaupten.
Nächster vereinbarter Schritt: Prioritäten/Ziele gemeinsam besprechen (Co-Projektmanagement),
keine weiteren vorgemerkten Features ohne Auswahl implementieren.


## Aktuelle Planung nach interaktiver Abstimmung (22.10.2026)

Nächster freigegebener Meilenstein: Desktop-Serverfenster mit Start/Stop,
Server-/Workerstatus, Live-Serverlogs und Browser-öffnen-Schaltfläche.
EXE startet den Server automatisch; Browser ausschließlich per Button.
Reguläres Stoppen sperrt neue Aufträge, hält wartende zurück und lässt den
laufenden Auftrag bzw. die laufende Archivierung abschließen. Zusätzlich
Force Shutdown mit Bestätigung, Beenden von Worker/Tools und Kennzeichnen
unterbrochener Aufträge; keine automatische Wiederholung.
Access Token im Fenster anzeigen, Kopierbutton. X minimiert in den Windows-
Infobereich, Server läuft weiter. Keine UAC-Umgehung.
Zusätzliche generische Toolrunner vorerst zurückgestellt; Nutzer bindet später
Tools zu Testzwecken ein, Fehler dann gezielt prüfen. Feinschliff, Serverwartung
und Optik haben aktuell Vorrang; V1-Abschluss folgt nach Alltagstauglichkeit.

Weitere einzelne Entscheidungen:
- Diagnosepaket für folgenden Wartungsmeilenstein vormerken: Version,
  Dienststatus und bereinigte technische Logs, Vorschau der enthaltenen Dateien;
  ohne Tokens, Evidenzen, Ergebnisse oder Befehlsausgaben. Nicht automatisch senden.
- Sicherung/Wiederherstellung der Konfiguration im Desktopfenster zusätzlich zum
  bestehenden JSON-Transfer: später erneut besprechen, noch nicht zur Umsetzung gewählt.
- Feedbackfunktion ausdrücklich vormerken: Button oben in der Web-Navigationsleiste,
  über den Nutzer Feedback, Bugs oder Wünsche erfassen können. Ablage/Ziel und
  Versandverhalten noch gemeinsam festlegen; derzeit keine externe Übermittlung.
- Testanleitung direkt im Chat bereitstellen/verlinken, kein Dateidownload erforderlich;
  Release-Dateien in eigenen Versionsordnern auf Google Drive bereitstellen.

Die Planung ist noch im interaktiven Brainstorming; keine zusätzlichen Ideen
über diese Auswahl hinaus eigenmächtig implementieren.

Feedbackfunktion konkretisiert (22.10.2026): Feedback, Bugs und Wünsche lokal
speichern und bei Bedarf ausdrücklich zum Teilen exportieren. Kein automatischer Versand.

Wartungsidee bestätigt (22.10.2026): Größenbasierte Rotation ausschließlich
technischer Serverlogs, mit einstellbarer Anzahl aufzubewahrender Logdateien.
Für späteren Wartungsmeilenstein vormerken. Auftragslogs, Auditdaten, Evidenzen
und Ergebnisse ausdrücklich nicht automatisch über diese Funktion bereinigen.

Desktop-Serverfenster: Gestaltung am 22.10.2026 ausdrücklich bestätigt. Blaues
Forensik-Thema mit Schild, Server-/Workerstatus und Start/Stop oben; großer
scrollbarer Serverlogbereich darunter. Serveradresse und Access Token jeweils
mit Kopierbutton. Bestandteil des nächsten Meilensteins, noch nicht implementiert.

Servereinstellungen im Desktopfenster (22.10.2026): Port und Zugriff lokal/LAN
für einen folgenden Wartungsmeilenstein vormerken, ausdrücklich nicht Teil des
ersten Serverfensters. Änderungen nach bewusstem Neustart; LAN weiterhin mit
Authentifizierung und selbstsigniertem HTTPS, keine automatische Firewalländerung.


## Umsetzung 0.20.0 – Desktop-Serverfenster

Planungsrunde abgeschlossen, Umsetzung ausdrücklich freigegeben. Serverfenster,
Autostart ohne automatischen Browser, Status/Serverlogs, Adresse/Token kopieren,
geordnetes Stoppen, bestätigter Force Shutdown und Tray-X implementiert.
Eigene EXE-/Komponentenprüfungen durchgeführt; manuelle Nutzerabnahme steht aus.
Port-/LAN-Einstellungen im Fenster, Feedback, Diagnosepaket und konfigurierbare
Logrotation bleiben ausdrücklich folgende Meilensteine. Keine neuen Toolrunner.
Release im eigenen Drive-Versionsordner 0.20.0. Testanleitung direkt im Chat,
zusätzlich im Projektplan; keine Anleitung als Pflicht-Dateidownload.

0.20.0 technisch geprüft: 117 Tests/Ruff, finale EXE-Prüfungen Startup/Batch/Control und Tk-/Tray-Komponenten bestanden. Reguläre separate Testinstanz 8770 mit Konfigurationskopie gestartet; Nutzerabnahme steht aus. Testanleitung siehe NEXT_TEST und direkt im Chat. Keine nächste Erweiterung vor Feedback.

Abschließende 0.20.0-Abnahmevorbereitung: 118 Tests/Ruff bestanden, erneute EXE-Prüfungen gegen dist/0.20.0-release erfolgreich. Eigene finale Testinstanz nun 8771 mit .local-data/ui-v020-release und Konfigurationskopie; vorherigen eigenen Testserver 8770 im Leerlauf gestoppt. Alte Nutzerinstanzen unverändert. Nutzerabnahme offen, Testschritte im Chat.


Nutzerabnahme 0.20.0 am 22.10.2026: Rückmeldung zum Nachtest „klappt mega“.
Desktop-Serverfenster und dessen Teststrecke sind damit vom Nutzer als erfolgreich
bestätigt. Keine weitergehende Last-/Fremdsystem-/LAN-Abnahme daraus ableiten.
Nächsten Wartungsmeilenstein aus den vorgemerkten Punkten gemeinsam auswählen;
keine automatische Freigabe aller weiteren Ideen.


## Sammelmeilenstein 0.21–0.24 ausdrücklich freigegeben

Nutzer hat nach Auswahl Diagnosepaket zusätzlich alle vier Wartungspunkte für einen
Großtest freigegeben. Enthalten: Diagnosepaket mit Inhaltsvorschau und lokalem ZIP,
Feedbackbutton mit lokaler Speicherung/JSON-Export, Desktop-Port-/LAN-Einstellungen
und konfigurierbare technische Serverlogrotation. Keine zusätzlichen Toolrunner.
Nach dem großen Nutzertest folgt auf ausdrücklichen Wunsch wieder ein Scrum-Gespräch.

Zusätzlicher Release-Auftrag: pro Version Code nach GitHub veröffentlichen, README
um den aktuellen Funktionsumfang aktualisieren und Releasebeschreibung samt Build
bereitstellen. Repository: https://github.com/D3vasd4t0r/Post-Processing-Magic .
GitHub-Plugin wurde nach anfänglichem OAuth-Fehler verbunden, Account/Schreibrechte
bestätigt. Historie und vorhandene MIT-Lizenz erhalten. Google Drive mit eigenen
Versionsordnern zusätzlich beibehalten. Keine Tokens/Laufzeitdaten veröffentlichen.
