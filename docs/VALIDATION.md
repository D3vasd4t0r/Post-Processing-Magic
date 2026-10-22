# Validierung am 21.10.2026

## Update: Version 0.14 / blaues Forensik-Design

- Nachtrag: Auf ausdrücklichen Nutzerwunsch Version 0.14 mit bisherigem Datenordner
  auf Port 8767 gestartet. Vorher keine aktiven Jobs, SQLite gesichert und alte
  Instanz regulär beendet. API bestätigt 0.14.0, Administratorrechte, aktiven Worker
  und unpausierte leere Queue. Bestehenden Nutzertab aktualisiert/neu angemeldet,
  blaues Design auch bei 659 Pixel breiter Ansicht sichtbar. Screenshot:
  `.local-data/live-0.14-started.png`. Testanleitung zur Anzeige im Codex angefordert;
  Nutzerabnahme weiterhin offen. Keine Evidence-Aufbereitung gestartet.
- Auf ausdrücklichen Nutzerwunsch vor dem großen Test ergänzt: blaues Thema,
  dekoratives Schild im Hintergrund/Kopfbereich und am Appnamen, konsistente
  Navigation, Karten, Formulare, Dialoge, Fortschritts- und Terminalfarben.
  Rote Malware-Ansicht bleibt für später geplant.
- Nur HTML/CSS/SVG und Versionskennzeichnung geändert, keine Backend-/Joblogik.
  Keine externen Assets oder Fonts; Dekoration aria-hidden und nicht interaktiv.
- 93 pytest-Tests, Ruff, JavaScript-Syntaxprüfung und EXE-Build bestanden.
  Finale EXE: `dist/0.14.0/PostProcessingMagic.exe`.
- EXE-Start-/Neustart-/Persistenztest inklusive eingebettetem HTML und Queue-Pause
  bestanden: `.local-data/smoke-1792614133527154300/report.json`.
- Separate Source- und finale EXE-Instanz mit eigenen Testdaten visuell geprüft:
  Schildmotiv und blaue Gestaltung sichtbar; dekorative SVGs nicht im AX-Baum.
  Einstellungen/Verarbeitung und Logs erreichbar, Historie mit 56 eigenen
  Datensätzen zeigt Seitenzählung, Queue aktiv ohne wartende Aufträge.
  Screenshot der finalen EXE: `.local-data/forensic-blue-0.14.0.png`.
- Responsive Regeln und Fokusmarkierungen vorhanden. Tatsächliche Bedienung in
  schmaler Ansicht und gemeinsame Nutzerabnahme 0.10–0.14 stehen noch aus.
- Eigene Instanzen beendet. Bestehende Nutzerinstanz bleibt unverändert 0.10.0.
  Neue Verknüpfung `Testversion 0.14 starten.lnk` für bisherigen Datenordner und
  Port 8767 vorbereitet. NEXT_TEST.md auf 0.14 samt Designprüfung aktualisiert.

## Update: gebündelte Version 0.13 / Auftragssuche und Warteschlangenpause

- Zwei weitere Meilensteine ausdrücklich vor dem nächsten großen Nutzertest
  freigegeben: 0.12 Historie/Suche und 0.13 persistente Queue-Pause. Manuelle
  Nutzerabnahmen 0.10–0.13 weiterhin offen.
- 93 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden. Vier neue Tests
  mit umfangreichen Assertions für Unicode/wörtliche Suche, 66 Datensätze mit
  Pagination, kombinierte Filter/UTC-Tagesgrenzen/ungültige Parameter/Auth,
  Pause vor Übernahme, konkurrierende Claims ohne Doppelausführung, laufender
  Auftrag unverändert, sofortiger Abbruch wartender Jobs, strikter Boolean,
  Audit ohne doppelte Änderung und gespeicherter Pausenzustand nach Neustart.
- Finaler Build: `dist/0.13.0-r1/PostProcessingMagic.exe`.
- Finaler EXE-Verarbeitungstest mit ausschließlich eigenen Archiven/Programmen
  bestanden. Zusätzlich: neuer Auftrag bleibt ohne Arbeitsordner wartend, bis
  Queue fortgesetzt wird; erneute Pause während einer übernommenen Befehlsfolge
  unterbricht deren drei Befehle nicht. Ergebnisdateien und ZIP geprüft;
  Historienfilter/Pagination, Explorer-Verfügbarkeit und Speichermessung geprüft.
  Bericht: `.local-data/processing-smoke-1792611198822586600/report.json`.
- Finaler EXE-Start-/Neustart-/Persistenztest einschließlich Queue-Pause bestanden:
  `.local-data/smoke-1792611196325448800/report.json`.
- Browserprüfung mit eigenen Daten: 55 synthetische Historieneinträge, Seite 1
  zeigt 1–50, Seite 2 51–55; Suche nach Own-history-12.zip ergibt einen Treffer.
  Finale Filterdarstellung in zwei Spalten visuell geprüft.
- Browserablauf mit eigener ZIP und eigenem PowerShell-Modus: Pause, Run bleibt
  wartend, Fortsetzen, Pause während Bearbeitung, danach erfolgreich mit Download
  und Explorer verfügbar. Queue blieb pausiert und wurde anschließend wieder aktiviert.
  Screenshots: `.local-data/history-0.13.0.png`, `.local-data/queue-0.13.0.png`.
- Eigene Testinstanzen beendet. Nutzerinstanz weiterhin unverändert 0.10.0 unter
  Port 8767. Datenbank vor späterer Migration gesichert. Verknüpfung
  `Testversion 0.13 starten.lnk` mit richtigem Build, Datenordner und Port erstellt.
- Gemeinsamer großer Nutzertest in NEXT_TEST.md: Start über Windows-UAC,
  Speicher, Filter/Explorer, Queue-Pause und kleiner echter ZIP/KAPE-Lauf,
  Terminal/Ergebnisdownload sowie Konfigurationsexport/-importvorschau.

## Update: Version 0.11.0 / Speicherübersicht, Nutzertest mit 0.10 gebündelt

- 89 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden. Bekannte
  Starlette/httpx-DeprecationWarning unverändert.
- Sechs neue Tests: Byte-/Datei-/Ordnerzahlen, kein Öffnen von Dateiinhalten,
  externe lokale Originaldatei ausgeschlossen, Tokenpflicht, GET ohne Scan,
  zwischengespeicherte Messung, Zeit-/Eintragsbudget mit Teilkennzeichnung,
  parallele Messung abgewiesen, Windows-Junction übersprungen, Lesefehler erfasst.
- Finale EXE: `dist/0.11.0/PostProcessingMagic.exe`.
- EXE-Verarbeitungstest mit ausschließlich eigenen ZIPs/Testprogrammen bestanden:
  Erfolg, Fehler, Abbruch samt Unterprozess, lokaler G-Eingang, mehrere Befehle,
  Explorer-Verfügbarkeit und anschließende echte Speicher-API-Messung.
  Bericht: `.local-data/processing-smoke-1792610486239361100/report.json`.
- Start-/Neustart-/Persistenztest bestanden:
  `.local-data/smoke-1792610481335554600/report.json`.
- Separate Browserinstanz mit eigenen Testdaten: vor Scan keine Größenmessung,
  anschließend drei Bereiche mit zusammen 42,09 KiB, Zeitstempel und ohne Fehler.
  Beim Verlassen/Wiederöffnen blieb derselbe Messzeitpunkt erhalten; kein neuer
  Scan. Explorer-Schaltfläche eines früheren eigenen erfolgreichen Testlaufs
  weiterhin sichtbar und aktiviert. Screenshot: `.local-data/storage-0.11.0.png`.
- Eigene Instanz anschließend beendet. Bestehende Nutzerinstanz nicht verändert:
  Status bestätigt weiter 0.10.0 mit Administratorrechten auf Port 8767.
- Startverknüpfung `Testversion 0.11 starten.lnk` im Projektordner erzeugt, Ziel
  und Argumente geprüft. Sie verwendet den bisherigen Datenordner und Port 8767
  und öffnet nach Windows-UAC automatisch den Browser mit neuem Sitzungstoken.
  Vorher muss der bisherige Dienst ohne aktive Aufträge regulär beendet werden.
- Nutzer gerade nicht am Laptop. Kein Wechsel der Nutzerinstanz/UAC-Versuch.
  Manuelle Abnahmen 0.10 und 0.11 offen; gemeinsamer Ablauf in NEXT_TEST.md.
  Verhalten bei echten großen Beständen noch vom Nutzer zu prüfen.

## Update: Version 0.10.0 / Show in Explorer

- 83 pytest-Tests, Ruff, JavaScript-Syntaxprüfung und Windows-EXE-Build bestanden.
  Bekannte Starlette/httpx-DeprecationWarning weiterhin vorhanden.
- 15 neue Tests mit eigenen synthetischen Metadaten/Ordnern prüfen Tokenpflicht,
  lokale Öffnung und Audit, wirkungslose Verfügbarkeitsabfrage, unveränderte
  Auftragsdaten, Remote-Sperre trotz gefälschtem X-Forwarded-For, nicht erfolgreiche
  Aufträge, fehlende Ordner/Windows-Sitzung, ungültige Snapshotpfade, echte Windows-
  Junction als Umleitung und Windows-Shellfehler. Native Öffnung in Unit-Tests ersetzt.
- Finale EXE: `dist/0.10.0/PostProcessingMagic.exe`.
- EXE-Verarbeitungstest bestanden, nur eigene ZIPs/Testprogramme: Erfolg,
  Fehlercode, Unterprozess-Abbruch, lokale G-ZIP ohne Eingangskopie und geordneter
  PowerShell/KAPE-Testablauf. Explorer-Verfügbarkeit erfolgreicher Aufträge geprüft.
  Bericht: `.local-data/processing-smoke-1792609978524687700/report.json`.
- Start-/Neustart-/Persistenztest bestanden:
  `.local-data/smoke-1792609972598358000/report.json`.
- Separate Browser-Testinstanz: erfolgreichen eigenen PowerShell-Testlauf im
  Logs-Tab gewählt. Show in Explorer sichtbar/aktiv; Klick übergibt ausschließlich
  dessen PostMortem-Ordner an Windows. Shell-Aufruf erfolgreich und im Browser
  mit tatsächlichem Zielpfad bestätigt. Keine Nutzer-Evidence ausgeführt.
  Screenshot: `.local-data/explorer-fixture-0.10.0.png`.
  Die tatsächliche Explorer-Fensterdarstellung wird zusätzlich vom Nutzer geprüft.
- Bestehende Nutzerdatenbank vor Update gesichert, keine aktiven Aufträge vorhanden.
  Instanz regulär beendet und neue EXE über UAC auf Port 8767 gestartet. Status
  bestätigt 0.10.0, Administratorrechte und Worker; Limits bleiben 50 GiB / 2 TB.
- Nutzertab aktualisiert und neu angemeldet. Logs-Tab mit vorhandenem erfolgreichen
  Lauf geöffnet, Explorer-Button sichtbar und aktiviert; nicht für Nutzerergebnisse
  angeklickt. Screenshot: `.local-data/explorer-0.10.0.png`.
- Manuelle Nutzerabnahme 0.10 sowie tatsächlicher Zugriff von einem zweiten Gerät
  stehen aus. Remote-Sperre ist bislang mit simulierten Client-IP-Adressen getestet.

## Update: Version 0.9.0 / Limits, Terminal und PowerShell

- Nachtrag Nutzerabnahme: Nutzer hat alle von ihm durchgeführten Tests als
  erfolgreich bestätigt; Oberfläche und Funktionen funktionieren laut Rückmeldung.
  Einzelne Testfälle oder Archivgrößen darüber hinaus wurden nicht benannt.
- Nutzer meldet kleine und mittlere echte KAPE-Tests erfolgreich (Version 0.8).
- 68 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden. TestClient gibt
  weiterhin die bekannte Starlette/httpx-DeprecationWarning aus.
- Neue Tests: authentifizierte, strikte und persistente Limitkonfiguration;
  Limitsnapshot trotz späterer Änderung; lokale Eingänge unabhängig vom Uploadlimit;
  reale Windows-PowerShell-Prozesse mit Unicode, cd innerhalb eines Blocks,
  explizitem Arbeitsordner, Reihenfolge und Abbruch der Folge bei Fehler;
  JSON-Schema 2 sowie Rückwärtskompatibilität zu Schema 1.
- PowerShell-EncodedCommand erzeugte zunächst CLIXML-Fortschrittsmeldungen.
  ProgressPreference SilentlyContinue und Textausgabe beseitigen diese; eigener
  Regressionstest und finaler EXE-Browserlauf bestätigen lesbare Ausgabe.
- Finale EXE: `dist/0.9.0-r1/PostProcessingMagic.exe`.
- Finaler EXE-Verarbeitungstest mit ausschließlich eigenen synthetischen Daten:
  Erfolg, Fehlercode 7, Abbruch samt Kindprozess, lokale G-ZIP ohne Kopie sowie
  PowerShell → synthetisches KAPE-Testprogramm → PowerShell mit 3/3 Befehlen und
  korrekten zusätzlichen Dateien im Ergebnis-ZIP. Bericht:
  `.local-data/processing-smoke-1792605287481482500/report.json`.
- Finaler Start-/Neustart-/Persistenztest bestanden:
  `.local-data/smoke-1792605283656106700/report.json`.
- Browserprüfung auf separater Instanz mit eigener ZIP und PowerShell-Testmodus:
  neue Blockfelder sichtbar, Limit 2 → 2,1 → 2 TB gespeichert. Terminal mit 240
  Ausgabezeilen bleibt 358 Pixel hoch (inkl. Rahmen 360); folgt bis ans Ende.
  Hochscrollen pausiert trotz weiterer Ausgabe; Schaltfläche springt ans Ende.
  Finale EXE zeigt keine CLIXML-Rohdaten. Ergebnisdownload verfügbar.
- Screenshots: `.local-data/terminal-0.9.0.png` und `.local-data/limits-0.9.0.png`.
- Bestehende Nutzerdatenbank vor Update gesichert. Kein aktiver Auftrag vorhanden.
  Instanz regulär beendet, Version 0.9 über UAC auf Port 8767 gestartet.
  API bestätigt administrator=true, Worker verfügbar, Uploadlimit 53.687.091.200
  Bytes und Entpacklimit 2.000.000.000.000 Bytes. Vorhandene Tool-/Moduszuordnungen
  erhalten. Browser aktualisiert, neu angemeldet und Verarbeitungseinstellungen geöffnet.
- Reale Evidencen für diese Entwicklung durch den Coding-Agent nicht geöffnet
  oder ausgeführt. Die anschließende Nutzerabnahme 0.9 ist erfolgt (siehe Nachtrag).
  Ein tatsächliches 2-TB-Archiv und dessen Ressourcenbedarf wurden nicht getestet.


## Update: Version 0.8.0 / lokale ZIP, Diagnose, Laufwerksordner und UAC

- 63 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden.
- Neue Tests: lokale Referenz ohne Eingangskopie und unabhängig vom Uploadlimit,
  gleichzeitige Schreibzugriffe gesperrt, geänderte lokale Datei vor Verarbeitung
  zurückgewiesen, G statt C automatisch erkannt, G/H nicht automatisch geraten.
- Administrator-Fehlermeldung trotz Exitcode 0 als Fehler erkannt, Diagnose/Log-API
  authentifiziert, hohe Kompression nur nach ausdrücklicher Option zugelassen.
- Launcher-UAC vor Daten-/Serverstart sowie abgelehnte UAC ohne Fallback getestet.
- EXE-Test ausschließlich mit eigenem Programm/eigenen Archiven: Upload-Erfolg,
  Fehlercode, Abbruch inklusive Unterprozess sowie lokale ZIP mit G erfolgreich.
  Lokale Variante erzeugt keine Eingangskopie. Bericht:
  `.local-data/processing-smoke-1792602745131876600/report.json`.
- Synthetischer Neustart-/Persistenztest bestanden:
  `.local-data/smoke-1792602796742702600/report.json`.
- Alle automatischen EXE-Tests verwenden ausdrücklich --test-no-admin; das ist
  keine Bestätigung eines erhöhten echten KAPE-Laufs. Der normale Launcher fordert
  UAC an und läuft ohne Bestätigung nicht nicht-erhöht weiter.
- Geprüfte Fehler aus Nutzerläufen: Kompressionslimit und fehlende Adminrechte,
  obwohl KAPE Exitcode 0 meldete. Eingangs-Evidencen dafür nicht untersucht.
- Finaler Build: `dist/0.8.0-r1/PostProcessingMagic.exe`. Die vorherige Ausgabe
  ließ sich wegen einer Windows-Dateisperre nicht überschreiben; kein Nutzerinhalt entfernt.
- Finaler EXE-Verarbeitungstest bestanden:
  `.local-data/processing-smoke-1792603038257245800/report.json`.
  Finaler Neustart-/Persistenztest ebenfalls bestanden:
  `.local-data/smoke-1792603036080224700/report.json`.
- Bestehende Nutzerdatenbank vor Aktualisierung gesichert. Normaler Start der
  finalen EXE über UAC unter bisheriger Adresse. Lokale Status-API bestätigt
  Version 0.8.0, administrator=true sowie verfügbaren Worker.
- Browser: Adminstatus sichtbar, Quelle auf lokal umgestellt, ZIP-Path-Picker mit
  eigener kleiner Beispieldatei geprüft, Ablaufvorschau und Run-Freigabe geprüft.
  KEIN Run ausgelöst, anschließend Beispielpfad geleert und schnell vorausgewählt.
- Logs-Tab zeigt frühere Nutzerläufe und erkennt den vorhandenen KAPE-Adminfehler
  auch bei dessen Exitcode 0. Diagnose- und Logdownload-Schaltflächen vorhanden.
- Echte KAPE-Aufbereitung erfolgt erst beim nächsten vom Nutzer gestarteten Run.

## Update: Version 0.7.0 / erster ZIP/KAPE-Runner und Löschwarnung

- 55 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden.
- Tests prüfen Windows-Argumentverarbeitung, Beschränkung auf Offline-KAPE,
  Upload/Queue/Snapshot samt Toolhash, Ergebnisdownload und Audit-ZIP-Inhalt.
- Gegenproben: Traversal, Laufwerke/UNC, ADS, reservierte Namen, Sonderdateien,
  Symlinks, Namenskollisionen, Datei-/Ordnerkonflikte und Kompressionsverhältnis.
- Fehlercode, leeres Ergebnis, ungültiges ZIP, fehlender Quellordner, Abbruch und
  Neustart geben keinen erfolgreichen Download frei. Importierte eingebundene
  Tools bleiben beim Löschversuch vollständig mit ihren Modusverknüpfungen erhalten.
- EXE `dist/0.7.0/PostProcessingMagic.exe` gebaut und mit separatem spawn-Worker
  wirklich gestartet. `tests/smoke_processing.py` kompiliert ausschließlich ein
  eigenes Testprogramm namens kape.exe, erzeugt eine eigene ZIP und prüft:
  Ergebnis-ZIP über den nativen Einmallink, Exitcode 7 als Fehler sowie Abbruch
  einschließlich eines echten gestarteten Unterprozesses. Alle drei Fälle bestanden.
- Finaler Bericht: `.local-data/processing-smoke-1792585892587819300/report.json`.
- EXE-Neustart-/Token-/Persistenztest ebenfalls bestanden:
  `.local-data/smoke-1792585890062233200/report.json`.
- Nutzerkonfiguration vor Aktualisierung als SQLite-Sicherung unter config gesichert.
  Auf Port 8767 neue EXE gestartet. Browser zeigt schnell als ausführbaren KAPE-Modus,
  Medium mit mehreren Testbefehlen bleibt nachvollziehbar gesperrt.
- Browser-Löschversuch von eingebundenem pdfid geprüft: Warnung direkt am Eintrag,
  betroffener Testmodus genannt; nichts gelöscht und keine Verknüpfung verändert.
- Hauptseite für Nutzer vorbereitet. Echte KAPE-Binärdatei wurde von uns nicht
  ausgeführt und die angekündigte ZIP-Testsicherung nicht gesucht oder eingesehen.
- Echte KAPE-Abhängigkeiten, Modulergebnisse und fachliche Vollständigkeit werden
  erst im vom Nutzer gestarteten ZIP/KAPE-Gesamttest geprüft. Kein Produktionsrelease.

## Update: Version 0.6.0 / einfache Hauptoberfläche

- Bestehende 36 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden.
  Neue Änderung betrifft die Oberfläche, keine neue Verarbeitungs-API.
- EXE `dist/0.6.0/PostProcessingMagic.exe` gebaut und tatsächlich gestartet.
- Separate synthetische Testinstanz auf Port 8768: zwei reine Beispielbefehle,
  Textdatei mit .exe-Endung ausschließlich zur Metadatenprüfung, selbst erzeugte
  ZIP mit C/README.txt. Kein Toolstart und keine ZIP-Extraktion.
- Browserprüfung: Medium als konfigurierte Stufe wählbar, fehlende Stufen sowie
  E01/VMDK gesperrt; eigene Beispiel-ZIP über die Dateiauswahl ausgewählt.
- Ablaufvorschau zeigt Targets, PostMortem, zwei Befehle samt Toolpfaden,
  Parametern und Reihenfolge. Fortschritt bleibt 0 von 2. Auswahlwechsel entfernt
  alte Vorschau und sperrt Vorschau-Button. Run und Download bleiben deaktiviert.
- Separate Testinstanz anschließend beendet und deren Browser-Tab geschlossen.
- Nutzerinstanz unter bisheriger Adresse auf 0.6.0 aktualisiert. Einstellungen
  unverändert: zwei Tools und zwei Modi, beide Stufen noch unvollständig.
  Gesperrte Stufen mit Erklärung, Direktzugang zur Modusverwaltung und Rückweg
  auf Hauptseite geprüft. Hauptseite als geöffneter Testtab bereitgestellt.
- Nutzerabnahme 0.5.0 erfolgt; gemeinsamer Oberflächentest 0.6.0 steht aus.
  Die angekündigte echte ZIP-Testsicherung wurde weiterhin nicht eingesehen.

## Update: Version 0.5.0 / Konfigurationstransfer

- 36 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden
- Neue Tests: Export/Import mit stabilen Tool- und Schritt-IDs, Parametertext und
  Befehlsreihenfolge; Vorschau ohne Änderungen; automatische Sicherung und Audit
- Authentifizierung, unbekanntes Schema, ungültiges JSON, Größenlimit,
  doppelte Namen/IDs/Stufen, fehlende Toolreferenzen und Vorschau-Wiederverwendung
- Ersetzen nur nach Bestätigung; leere Konfiguration bleibt über Neustart erhalten
- Zwischenzeitliche Tooländerung invalidiert Vorschau; synthetischer SQL-Fehler
  rollt die gesamte Änderung einschließlich Audit zurück
- EXE `dist/0.5.0/PostProcessingMagic.exe` gebaut und tatsächlich gestartet.
  Bisherige Testadresse und Datenordner weiterverwendet.
- Browserexport als JSON heruntergeladen und über die Dateiauswahl zurückimportiert:
  Vorschau zeigt zwei Tools und zwei Modi unverändert, keine Konflikte.
  Anwenden erfolgreich, automatische Sicherung und Erfolgsmeldung sichtbar.
- Benutzerdefinitionen nicht geändert, kein Forensiktool ausgeführt und keine
  angekündigte ZIP-Testsicherung gesucht, eingesehen oder verarbeitet.
- Gemeinsame Nutzerabnahme und tatsächlicher Evidence-Lauf stehen weiterhin aus.

## Update: Version 0.4.0 / Speichern-Abschluss und eindeutige Stufen

- 27 pytest-Tests, Ruff und JavaScript-Syntaxprüfung bestanden
- Neue Tests: pro Format eindeutige Aufwandsstufen, Groß-/Kleinschreibung,
  Beibehaltung eigener Stufe beim Bearbeiten, Verfügbarkeit von Befehlsfolgen,
  fehlende Tooldateien und zwei gleichzeitige Versuche, dieselbe Stufe anzulegen
- Altdaten-Duplikate bleiben sichtbar und bearbeitbar, ohne neue Duplikate zuzulassen
- EXE `dist/0.4.0/PostProcessingMagic.exe` gebaut und unter bisheriger Adresse gestartet
- Im Browser einen ungültigen Ergebnisordner getestet: Editor und Eingaben erhalten
- Danach ursprünglichen Ordner PostMortem wiederhergestellt und gespeichert:
  Editor geschlossen, Übersicht und Erfolgsmeldung sichtbar, Fokus auf Listenüberschrift
- Neuer Modus: belegte Stufen Medium und langsam deaktiviert, schnell noch frei
- Vorhandene Doppelbelegung langsam als Konflikt sichtbar; nichts automatisch
  gelöscht oder umgeordnet. Keinen neuen Testmodus für diese Prüfung gespeichert.
- Kein Tool ausgeführt und keine Evidence eingesehen

## Update: Version 0.3.1 / Gliederung und Aufwand-Dropdown

- 24 bestehende pytest-Tests und Ruff bestanden; neue Windows-EXE gebaut
- Gleiche Testadresse und Datenbank weiterverwendet, Modi und Tools erhalten
- Browserprüfung: Import, Verarbeitung und Export sind getrennte Kategorien
- Ergebnisordner steht unter Export in einer eigenen vollen Zeile
- Aufwand-Dropdown zeigt schnell, Medium und langsam; testweise langsam gewählt
  und wieder auf den bisherigen Wert Medium zurückgestellt, nichts gespeichert
- Gespeicherte Altdaten mit anderen Aufwandswerten werden nicht still geändert;
  im Editor bleibt ein solcher Wert sichtbar, bis der Nutzer eine neue Stufe wählt
- Neue Eindeutigkeits-/Verfügbarkeitsregeln sind als separater nächster Meilenstein
  dokumentiert und noch nicht implementiert

## Update: Version 0.3.0 / Modus- und Befehlseditor

- 24 pytest-Tests bestanden und Ruff bestanden
- KAPE-Referenzbefehl gegen den exakt dokumentierten Nutzerbefehl geprüft
- Tests für einmalige Vorlagenanlage, dauerhafte Änderungen und Löschen,
  Modus-CRUD, E01/VMDK-Sperre, relative Entpack-/Ausgabeordner, Authentifizierung,
  Befehlsreihenfolge, Parametererhalt und Toolreferenzen bestanden
- Referenzierte Tools können nicht entfernt werden, solange ein Modus sie verwendet
- Windows-EXE gebaut unter `dist/0.3.0/PostProcessingMagic.exe`
- Bisherige Testdatenbank vor Aktualisierung in `config/before-modes-*.sqlite3`
  gesichert. Gleiche Testadresse und Datenverzeichnis weiterverwendet.
- Im Browser: Vorlage kopiert, zusätzlichen Block eingefügt, vorhandenes Tool
  ausgewählt, Parameter gesetzt, Block nach oben verschoben und Testkopie gespeichert
- Nach Seitenneuladen Testkopie, Ordner, Toolreferenz, Parameter und Reihenfolge
  wiedergefunden. KAPE-Originalvorlage bleibt unverändert und unzugeordnet.
- Sichtbare Vorschau geprüft; es wurden keine Programme ausgeführt und keine
  Evidencen hochgeladen oder untersucht.
- Testkopie „UI-Test: Befehlsbaukasten“ bleibt für den Nutzer-Test vorhanden.
- Die tatsächliche Verarbeitung und der Export/Import sind noch nicht implementiert.

## Update: Version 0.2.2 / gemerkter Auswahlordner

- Zwölf bestehende pytest-Tests und Ruff bestanden; neue EXE gebaut
- Bisherige Testinstanz unter Port 8767 mit demselben Datenverzeichnis aktualisiert
- Vorhandene Toolkonfiguration nach Aktualisierung im Browser wiedergefunden
- Im Browser eine Datei im Picker gewählt, Seite neu geladen, leeres
  Hinzufügen-Formular geöffnet und den Picker erneut geöffnet: derselbe Ordner
  wurde wieder angezeigt. Kein neuer Tool-Eintrag für diese Vorprüfung gespeichert.
- Der gemerkte Ordner gilt für denselben Browser-Tab; neue Tabs beginnen ohne
  diesen Merker. Beim Bearbeiten wird der ausgefüllte Toolpfad bevorzugt.
- Nutzer-Nachtest: Auswahl, Speichern, nächste Auswahl im gleichen Ordner.

## Update: Version 0.2.1 / Testiteration 2 (Path-Picker)

- Zwölf pytest-Tests bestanden; Ruff bestanden
- Zusätzliche Picker-Tests: Tokenpflicht, Datei-/Ordnernavigation, Namensfilter,
  Dateipfad als Einstieg, ungültige Pfade, fehlende Ordner, Berechtigungsfehler,
  begrenzte Listen und Verhalten an einer Laufwerkswurzel
- Neue EXE gebaut: `dist/0.2.1/PostProcessingMagic.exe`
- Gebaute EXE auf Port 8767 gestartet und im Browser geprüft:
  Anmeldung, Picker öffnen, `C:\Windows` öffnen, nach `notepad` suchen,
  `notepad.exe` übernehmen und Toolnamen vorbelegen; Ordner übernehmen;
  erneutes Öffnen und Abbrechen erhält die bestehenden Formularwerte.
- Keine ausgewählte Datei ausgeführt und keine Test-Tooldefinition gespeichert.
- Visuelle Prüfung im schmalen In-App-Browser; Pickerinhalt ist scrollbar.
- Separate Testdaten `.local-data/ui-v021`; frühere Nutzer-Testdaten bleiben erhalten.
- Remotezugriff von einem zweiten Gerät weiterhin ungeprüft.

## Update: Version 0.2.0 / UI-Testiteration 1

- Neun pytest-Tests bestanden; Ruff bestanden
- Zusätzliche Tests: Toolpfad-CRUD, Persistenz über Neustart, Konfigurationsprotokoll,
  Authentifizierung aller Einstellungs-Endpunkte, relative/UNC-/ungültige Pfade,
  selbstsigniertes Zertifikat mit SAN und Wiederverwendung
- Windows-EXE erneut gebaut: `dist/0.2.0/PostProcessingMagic.exe`
- `tests/smoke_startup.py --exe dist/0.2.0/PostProcessingMagic.exe --lan` bestanden:
  echte HTTPS-Verbindung zu Loopback mit Prüfung gegen das automatisch erzeugte
  Zertifikat; keine abgeschaltete Zertifikatsvalidierung. Außerdem Neustart,
  Tokenwechsel, gesperrte Dateiauslieferung und dauerhafte Toolkonfiguration geprüft.
- Bericht: `.local-data/smoke-1792576813809682000/report.json`
- Gebaute EXE zusätzlich auf Port 8766 gestartet. Im Browser Anmeldung,
  Einstellungsnavigation, Verzeichnisprüfung und Speichern des synthetischen
  Eintrags „UI-Vorprüfung“ geprüft. Die Darstellung wurde visuell kontrolliert.
- Browser-Autostart und Zugriff von einem zweiten Gerät bleiben ungeprüft.

Die folgenden Abschnitte dokumentieren den historischen Stand 0.1.

## Umgebung und Ergebnis

- Windows 11, Version 10.0.26200, x64
- Python 3.12.14; FastAPI 0.156.8; Uvicorn 0.54.0; PyInstaller 6.22.3
- `python -m pytest -q`: 6 bestanden
- `python -m ruff check .`: bestanden
- `build.ps1`: bestanden, `dist/PostProcessingMagic.exe` erstellt
- EXE-Größe: 14.519.284 Bytes
- Paketinventar des Builds: `dist/build-environment.txt`

Der Testclient gibt eine DeprecationWarning für die Verwendung von httpx mit der
installierten Starlette-Version aus. Die Tests bestehen; vor einer späteren
Aktualisierung soll der Testclient auf den dann unterstützten Transport angepasst werden.

## Tatsächlicher EXE-Start

`python tests/smoke_startup.py --exe dist/PostProcessingMagic.exe` bestanden.
Die EXE lief in neu angelegten Testdatenverzeichnissen ohne Analysewerkzeuge.
Der Test hat die gestarteten Prozessbäume anschließend beendet.

Geprüft wurden:

- Zwei echte Starts der gebündelten EXE mit HTTP-Erreichbarkeit
- Eingebettetes HTML wird ausgeliefert, einschließlich sichtbarem Hinweis auf das Startgerüst
- Ohne Token und mit falschem Token: HTTP 401; mit gültigem Token: HTTP 200
- SQLite und Token-Datei sind nicht als statische Dateien abrufbar
- Zweite Instanz im selben Datenverzeichnis wird abgewiesen
- Neustart nach erzwungenem Prozessbaum-Stopp erhält SQLite und erzeugt neuen Token
- Alter Token wird nach Neustart abgewiesen
- Belegter Port führt zu einem kontrollierten Startfehler
- Keine Analyseprofile oder Analysefähigkeiten werden behauptet

Maschinenlesbarer Bericht des ersten erfolgreichen Laufs:
`.local-data/smoke-1792575668758458300/report.json`.
Die Testdaten sind lokal und werden von Git ignoriert. Der Testcode bleibt im Repository.

## Noch nicht geprüft

- Automatischer Browserstart und visuelles Browserlayout
- TLS-Verbindung und Zertifikatsvertrauen von einem zweiten Gerät
- Windows-Firewall und Domänenumgebung
- EXE auf einem sauberen Rechner ohne installiertes Python
- Signierung, Virenscannerfreigabe und installerbasierte Verteilung
- Upload, Analysen, Worker und Downloads: noch nicht implementiert

Die Einschränkungen verhindern keine Weiterentwicklung am Grundgerüst, sind aber
bei späteren Verteilungs- und Produktivitätsaussagen ausdrücklich zu berücksichtigen.


## Nachbesserung 0.15 – 22.10.2026

104 pytest-Tests und Ruff bestanden. Elf neue Tests für getrennte Bereinigung,
Originalschutz auch innerhalb des Datenordners, strikte Bestätigung, Autorisierung,
aktive Jobs, veränderte Vorschauen, Junctions und Wiederanlauf der Bereinigungssperre.
Eigene Testdateien gelöscht; keine tatsächlichen Nutzerevidenzen/Ergebnisse gelöscht.
JavaScript-Syntax mit Node geprüft.

Windows-EXE gebaut. Erster Build: fünf Startup-Checks sowie fünf synthetische
Worker-Fälle (Erfolg, Fehler, Prozessbaumabbruch, lokale ZIP-Referenz, PowerShell-Folge).
Nach Optimierung der Metadatenprüfung finalen Build neu gebaut, erneut 104 Tests/Ruff
und fünf echte EXE-Startup-Checks bestanden. Finale EXE:
dist/0.15.0-final/PostProcessingMagic.exe.

Nutzerinstanz nach Prüfung auf offene Aufträge und SQLite-Sicherung aktualisiert.
GET /api/system bestätigt 0.15.0, administrator=true und worker=true.
Browser: Suche C-low.zip/Abgeschlossen zeigt vier hervorgehobene Karten;
Anzeigen markiert die Auswahl und zeigt deren Details. Explorer-Aufruf aus der
erhöhten EXE erzeugt ein sichtbares Windows-Explorer-Fenster zum Auftragsordner,
PostMortem ist markiert (native Accessibility bestätigt genau einen gewählten Eintrag).
Cache-/Evidences-/Results-Vorschauen im Browser geprüft und jeweils abgebrochen;
Bestätigung ohne Checkbox gesperrt. Metadatenvorschau des vorhandenen Bestands:
5.854 Cache-Dateien in rund sechs Sekunden; keine Dateiinhalte gelesen und nichts gelöscht.
Screenshot: .local-data/search-results-015.jpg. Manuelle Nutzerabnahme 0.15 steht aus.

Grenzen: kein Test auf sauberem Windows, keine Prüfung mit 2 TB oder 200.000 Dateien;
Vorschau begrenzt auf 200.000 Einträge und Zeitprüfung nach 60 Sekunden.
Lokal privilegierte konkurrierende Dateisystemmanipulation ist nicht isoliert.


## Sammelpaket 0.16–0.19 – 22.10.2026

111 pytest-Tests und Ruff bestanden, JavaScript-Syntax mit Node geprüft.
Neue Integrations-Unitfälle prüfen eingefrorene Arbeitsziele, bestehende Pfade,
SHA1/SHA256 von Eingangs-/Ergebnis-ZIP, separate/embedded Reports, Befehlszeiten,
Ergebnis ohne ZIP, späteres ZIP ohne Toolwiederholung, Pause/Abbruch, ausgewählte
Bereinigung über Arbeitsziele hinweg, unveränderte lokale Originale, nicht registrierte
oder manipulierte Arbeitsziele sowie Fehlerberichte und Authentifizierung.

Browser mit separater eigener ZIP/PowerShell-Testkonfiguration: Arbeitsziel speichern,
Run ohne ZIP erfolgreich, Report verfügbar/Download gesperrt; nachträglich ZIP
angefordert, Download verfügbar und Archivbutton wieder gesperrt. Direkter Übergang
Logs → ausgewählter Auftrag → Bereinigung geprüft; Vorschau abgebrochen.
Keine tatsächlichen Nutzerevidenzen oder Ergebnisse gelesen/analysiert/gelöscht.

Finale Windows-EXE dist/0.19.0-final/PostProcessingMagic.exe gebaut. Fünf Startup-Checks
bestanden. Eigener EXE-Gesamttest smoke_batch.py mit acht Prüfgruppen bestanden:
Ziel-Snapshot, Upload/lokaler Eingang mit Hashes, Abschluss ohne ZIP, spätere serielle
Archivierung, externe/embedded Reports und Hashvergleich am tatsächlichen ZIP,
Konfigurations-Rundlauf, gezielte Bereinigung über Arbeitsziele, Original-/Fremdjobschutz.
Berichte: .local-data/smoke-1792653165476736900/report.json und
.local-data/batch-smoke-1792653167735764800/report.json.

Separate Nutzer-Testinstanz 0.19 mit Administratorrechten und Worker auf Port 8769,
Daten ui-v019. Ausschließlich Tool-/Moduskonfiguration aus bisheriger 0.15-Instanz
übernommen: gültige Vorschau und atomarer Import. Keine Evidence kopiert/ausgeführt.
Die bisherige Instanz auf Port 8767 wurde nicht beendet. Nutzerabnahme 0.19 offen.
Kein 2-TB-/sauberer-Windows-/Mehrbenutzertest. Keine neue Format-/Toolfreigabe,
keine statische Malware-Analyse oder Parallelverarbeitung. Serverlokales Arbeitsziel
nicht portabel exportiert. Vorhandene Unterordner sind Abschlussbestand, keine
Erstellungszeit-Attestierung; HTML-Listen begrenzt, JSON ausführlicher. Lokale Hashwerte
allein beweisen keine Herkunft. Das fertige ZIP kann nicht seinen eigenen Hash enthalten.


Finaler 0.19.0-final-Build erneut mit fünf Startup- und acht Batch-Prüfgruppen
bestanden. Berichte .local-data/smoke-1792653639270525000/report.json und
.local-data/batch-smoke-1792653641389909900/report.json.
Zusätzlich fünf Worker-Fälle mit 0.19.0: Erfolg, Fehler, Prozessbaumabbruch,
lokales ZIP und PowerShell-Folge; .local-data/processing-smoke-1792653392169942900/report.json.
Abschließende UI-Ergänzung: Ergebnis-ZIP-Download direkt in Logs sowie Löschwarnung,
dass Results auch Berichte entfernt. Screenshot .local-data/features-019.jpg.
Test-Startverknüpfung verweist auf dist/0.19.0-final/PostProcessingMagic.exe.


Release-Bereitstellung 22.10.2026: 0.19 über Google-Drive-Desktop-Client übertragen,
Cloud-Dateiliste und ZIP-Inhalt geprüft. Prüfsumme/Testanleitung im selben privaten
Ordner. 0.14 bereits vorhanden, unverändert verlinkt. Drive-Client war nicht gestartet
und wurde auf ausdrücklichen Wunsch gestartet; danach Synchronisierung wieder aktiv.
Links und Prüfsumme in RELEASES.md. Keine App-/Token-/Evidence-Daten hochgeladen.


0.19.1: 111 Tests/Ruff bestanden. EXE-Startprüfung: .local-data/smoke-1792657137396153700/report.json (5). EXE-Gesamtprüfung: .local-data/batch-smoke-1792657140795595100/report.json (8). JavaScript-Syntaxprüfung bestanden. Synthetische Queuepause/Archivabbruch und Konfigurationstransfer/Bereinigung bestanden. Manuelle Nutzerabnahme offen.


## 0.20.0 Desktop-Serverfenster

118 pytest und Ruff bestanden. Finaler Windows-Windowed-Build:
dist/0.20.0-release/PostProcessingMagic.exe, Tcl/Tk und Schildicon gebündelt.
- EXE Startup (5): .local-data/smoke-1792671391518554100/report.json
- EXE Ergebnis-/Konfigurationsablauf (8): .local-data/batch-smoke-1792671395112190700/report.json
- EXE Steuerung (8): .local-data/control-smoke-1792671393552298200/report.json
- Tk/Tray-Komponenten (6): .local-data/widget-smoke-1792670764277485100/report.json
Geordnetes Stoppen schließt aktiven synthetischen Auftrag/ZIP ab, hält wartenden
zurück, Start rotiert Token und wiederholt keinen unterbrochenen Auftrag.
Force Shutdown beendet realen synthetischen PowerShell-Kindprozess; fertige
Ergebnisse und selbst erzeugte lokale Original-ZIP bleiben unverändert.
Portkonflikt liefert Startdiagnose; fremde control_id wird niemals übernommen.
Quellfenster visuell geprüft, Stopbutton bedient. EXE-Fenster gestartet und per
Fensterinventar nachgewiesen; dessen weitere Native-UI-Prüfung wurde durch
App-Freigabe-Timeout verhindert. Daher reale Tray-Klicks und abschließende EXE-
Komposition Bestandteil des Nutzernachtests. Kein sauberes Fremdsystem/LAN-Test
behauptet. Alte Nutzerinstanzen unverändert, keine echten Evidenzen verarbeitet.
Neue reguläre Testinstanz 8771: administrator=true, worker=true, null Aufträge.

Letzte Zusatzprüfung: Force-Recovery nur nach bestätigter eigener control_id und erfolgreich erworbener Server-Instanzsperre. Fremd belegter Datenordner bleibt unberührt. Finaler Release erneut mit Startup/Batch/Control geprüft.


Nutzerabnahme 0.20.0 am 22.10.2026: Rückmeldung zum Nachtest „klappt mega“.
Desktop-Serverfenster und dessen Teststrecke sind damit vom Nutzer als erfolgreich
bestätigt. Keine weitergehende Last-/Fremdsystem-/LAN-Abnahme daraus ableiten.
Nächsten Wartungsmeilenstein aus den vorgemerkten Punkten gemeinsam auswählen;
keine automatische Freigabe aller weiteren Ideen.


## Wartungs-Sammelbuild 0.24.0

129 Tests und Ruff lokal bestanden; Privacy-/Grenztests für Diagnosevorschau,
Einmaltickets, harte Verknüpfungen, Feedbackvalidierung/-persistenz, Serverpräferenzen
und Schutz der Originalbereiche. Quell-Browserprüfung: Feedback lokal gespeichert
und dargestellt, Diagnosevorschau mit allen vier Dateien. Screenshots ausschließlich
in .local-data, nicht zur Veröffentlichung.
Vorläufige EXE-Prüfungen 0.24 erfolgreich:
- .local-data/smoke-1792685610703199800/report.json (5)
- .local-data/batch-smoke-1792685614343630500/report.json (8)
- .local-data/control-smoke-1792685614187979900/report.json (8)
- .local-data/maintenance-smoke-1792685613463119000/report.json (8)
- .local-data/widget-smoke-1792684733332772300/report.json (8, Quell-Tk/Tray-Komponenten)
Maintenance: geänderter Port, selbstsigniertes HTTPS mit Zertifikatsprüfung,
Feedback nach Neustart, tatsächliche technische Logrotation, Diagnose offline und
Rückkehr zu lokalem HTTP. Nur synthetische Daten; kein Test auf fremdem Windows-Rechner.
Abschließender Build/Release wird gesondert dokumentiert. Manuelle Nutzerabnahme offen.
