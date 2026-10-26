# Großer Nutzertest 0.40.0

## Änderungen / Features

Vereinfachte blaue ZIP-Aufbereitung, vier Einstellungskategorien, auftragsbezogene Logs und Ergebnisse, Originaldownload bei Upload beziehungsweise lokale Referenz, Metadatenberichte und Forensik-Konfiguration Schema 4. Interne Malwarefunktionen entfernt, historische Daten passiv erhalten. Keine CSV-/XLSX-Vorschauen oder Evidenzauswertungen; der reduzierte Umfang ist ausdrücklich bestätigt.

## Start / Adresse / Access Token

Lokaler Teststart: vorbereitete Verknüpfung „Testversion 0.40.0 starten.lnk“ im Projektordner. Für den heruntergeladenen Release: Windows-ZIP vollständig entpacken und PostProcessingMagic.exe doppelklicken.

EXE: dist/0.40.0-final/PostProcessingMagic.exe. Neue getrennte Dateninstanz .local-data/ui-v040-release mit Kopie von vier Tooldefinitionen, zwei Forensikmodi und Limits. Keine Jobs, Evidenzen, Ergebnisse oder alten Tokens kopiert. Alte Nutzerinstanzen unverändert.

Windows-Build, 317 Tests/2 Berechtigungsskips, Ruff/JavaScript und sieben EXE-Prüfgruppen bestanden. Verknüpfung „Testversion 0.40.0 starten.lnk“ im Projektordner doppelklicken, UAC selbst bestätigen, danach im Serverfenster Browser öffnen. Vorgesehene Adresse nach Start: http://127.0.0.1:8783/. Port vor der Vorbereitung als frei geprüft.

Die reguläre Nutzerinstanz ist noch nicht gestartet. Daher gibt es noch keinen tatsächlichen aktuellen Nutzertoken oder laufende Testadresse. Bitte nach dem UAC-Start im PM-Chat „0.40 gestartet“ melden. Dann den Token aus genau dieser laufenden Instanz lesen und direkt im PM-Chat nennen. Im Serverfenster bereits sichtbar/kopierbar. Keine Entwickler-Testtokens verwenden.

## Klickschritte

1. Version und Administratorrechte im Serverfenster prüfen. Browser öffnen. Alle fünf Navigationsseiten und vier Einstellungskategorien öffnen. Feedbacktitel eintippen, weg- und zurückwechseln: Entwurf bleibt.
2. Aufbereitung: Upload/lokale ZIP wechseln. Dateifeld passt zur Quelle; Fall/Gerät und Aufwand bleiben erreichbar. Es gibt keinen Einfach/Fortgeschritten- oder Malwareumschalter.
3. Einstellungen → Tools/Modi: bestehende Einträge prüfen, Modus öffnen, Import/Verarbeitung/Export und Reihenfolge prüfen. Speichern allein startet keine Verarbeitung. Nur unterstützte vollständig konfigurierte Modi erscheinen für Run.
4. Konfiguration exportieren und Vorschau zum Zusammenführen öffnen. Schema 4 nur Forensik/Tools/Limits. Eine alte Konfiguration mit entfernten Bereichen muss zusätzlich ausdrücklich bestätigt werden; nichts automatisch ausführen. Für diesen Test keine unbekannten Dateien importieren.
5. Eigenen bereits bekannten freigegebenen ZIP/KAPE-Ablauf mit Fallnummer/Gerät über Run starten. Währenddessen zu Logs und zurück: derselbe Auftrag, echte Fortschritte, Fehler/Abbruch erreichbar. Keine echte Evidence automatisch vom Agenten verarbeiten lassen.
6. Logs: Auftrag anhand Fall/Gerät/Datum/ID wählen; Arbeitsordner und zugehörige Ausgabe prüfen. Hochscrollen pausiert das Folgen, Folgen-Button zeigt wieder aktuelle Ausgabe. Ein Wechsel darf keinen alten Log unter neuem Auftrag zeigen.
7. Ergebnisse: richtigen Auftrag öffnen. ZIP und HTML-Bericht herunterladen. Bericht mit Eingangs-/Ausgangshashes, Ordner-/Dateizahlen und Metadateninventar; keine Kommandozeile/Terminalbefunde. Bei Upload steht Originaldownload bereit. Bei lokaler Quelle nur geprüfter Referenzpfad, kein Eingangskopieren oder Download. Gleiche Fallnummern bleiben nach Datum/ID getrennt.
8. Sprache DE/EN und schmale Darstellung prüfen. Menü per Tastatur/Escape öffnen/schließen, keine abgeschnittenen Hauptaktionen. Danach regulär stoppen und neu starten; alte Nutzerinstanzen nicht beenden.

## Feedback

Ergebnisse mit Schrittnummer direkt hier beziehungsweise im Projektmanager-Chat melden, zum Beispiel „1–4 klappt, 6 zeigt falschen Log“. Darstellungsfehler gern als Screenshot. App-Feedback bleibt lokal und wird nicht automatisch übertragen. Danach gemeinsames Scrum, erst anschließend vereinbartes Code-/Sicherheitsreview und Code-Wiki.
