# Roadmap – aktueller Arbeitsstand 0.40

## Laufend: vereinfachte ZIP-Aufbereitung

Auf Nutzerauftrag im PM-Chat vom 25.10.2026 ersetzt 0.40 den verworfenen 0.32-Test. Fünf Pakete: interne Malwareanalyse entfernen; schlichte blaue Aufbereitung; vier Einstellungskategorien und Forensik-Konfigurationsdatei; auftragsbezogene Logs/Downloads/Metadatenberichte; geprüfter Windows-Build und GitHub-/Drive-Bereitstellung.

Technische Umsetzung abgeschlossen: lokal 317 Tests bestanden, zwei Symlink-Berechtigungsskips, Ruff/JavaScript und sieben EXE-Prüfgruppen erfolgreich. Eigene synthetische Browserläufe und schmale Darstellung geprüft. GitHub-/Drive-Bereitstellung und großer Nutzertest folgen; keine Nutzerabnahme vorwegnehmen.

Nutzer bestätigt am 26.10.2026 im PM-Chat ausdrücklich: „Ja, 0.40 ohne Tabellenvorschauen umsetzen“. Keine CSV-/XLSX-Vorschauen oder internen Evidenzauswertungen; ältere Erweiterungswünsche hierfür sind durch die aktuelle Entscheidung ersetzt.

Bestehende Nutzerinstanzen, Evidenzen und historische Daten bleiben erhalten. Neue automatische Tests nur mit selbst erzeugten synthetischen Daten. Keine weitere Toolzuordnung oder Analyseprofile eigenmächtig anlegen.

## Nach dem neuen großen Nutzertest

1. Feedback bearbeiten und gemeinsames Scrum zu Prioritäten/Zielen.
2. Vereinbartes Code-/Patterns-/Sicherheitsreview, Codedokumentation und lokale HTML-Code-Wiki; noch keine automatische Ausweitung dieses Sprints.
3. Spätere Formate, generische Toolrunner und parallele Aufbereitungen nur nach gesonderter Abstimmung. Aktuell ZIP und serieller Worker.

Die historische Versionsentwicklung bleibt in den vorhandenen Releasebeschreibungen nachvollziehbar; alte Featurefreigaben erweitern den aktuellen Vereinfachungsumfang nicht automatisch.
