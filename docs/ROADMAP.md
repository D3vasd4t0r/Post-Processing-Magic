# Roadmap – 0.40 abgenommen, 0.41 Dokumentation

## Nutzerabnahme 0.40

Am 26.10.2026 bestätigt der Nutzer den erfolgreichen Test von 0.40 und bezeichnet den Release als stabil. Die Anwendung wird zunächst im Berufsalltag erprobt. Der reduzierte Umfang ohne Tabellen-/Inhaltsvorschauen und interne Evidenzauswertungen bleibt verbindlich.

0.40 ist auf GitHub veröffentlicht und technisch geprüft: lokal 317 Tests bestanden / zwei Symlink-Berechtigungsskips, in GitHub-CI 319 Tests bestanden sowie Ruff und sieben EXE-Prüfgruppen erfolgreich. Alte Nutzerinstanzen und Daten bleiben erhalten.

## Aktueller Auftrag: ausschließlich Dokumentation 0.41.0

Englische Docstrings und Kommentare in den Skriptdateien, verständliche Codedokumentation und ein statisches lokales HTML-Code-Wiki unter docs/code-wiki. Wiki und verlinkte Projektdokumente kommen als Dokumentationspayload ins Release-ZIP. README und Releasehinweise werden aktualisiert.

Keine Funktionsänderungen, Refactorings, Fehler-/Sicherheitskorrekturen, Abhängigkeiten oder neuen API-/UI-Abläufe. Python-AST gegen 0.40 nach Docstringentfernung vergleichen; nur Versionskonstante und ausdrücklich freigegebener Dokumentationspayload des Packagers abweichend. JS/PowerShell nur Kommentare/Versionen. Bestehende Nutzer-, Hilfe- und Fehlertexte sowie Daten/Snapshots unverändert.

Bestehende Tests, Ruff, JS und tatsächliche EXE-/Browser-/Offline-Wikiprüfungen vor Veröffentlichung. Noch keine neue Nutzerabnahme oder Sicherheits-Auditabnahme behaupten.

## Später gesondert abstimmen

1. Rückmeldungen aus dem beruflichen Einsatz und gemeinsames Scrum.
2. Code-/Patterns-/Sicherheitsreview mit reproduzierbaren Befunden und bewusst abgestimmten Änderungen; 0.41 ist reine Dokumentation.
3. Weitere Evidenzformate, generische Toolrunner und parallele Aufbereitungen nur nach eigener Freigabe. Derzeit ZIP und serieller Worker.

## Bereitstellung

Seit 26.10.2026 auf ausdrücklichen Nutzerwunsch neue Releases und Testpakete ausschließlich auf GitHub. Keine weiteren Google-Drive-Uploads. Bereits vorhandene Drive-Dateien unverändert lassen. Keine bestehende Nutzerinstanz für einen Dokumentationsrelease stoppen.
