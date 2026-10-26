# Technische Validierung 0.40.0

Stand 26.10.2026, ausschließlich eigene synthetische Eingaben und Testprogramme.

- Lokal: 317 Tests bestanden, zwei Windows-Symlink-Berechtigungstests übersprungen. Ruff und JavaScript-Syntax erfolgreich.
- Sieben Prüfgruppen mit der tatsächlich gebauten Windows-EXE: Startup; Workflow/Arbeitsziel/Archive/Bereinigung; geordnetes Stoppen/Force Shutdown; Wartung/selbstsigniertes HTTPS; KAPE-Dateinachweise/Fehler/Abbruch; Schema-4-Konfiguration/Legacywarnung; Quellenzugriff/Downloadtickets/Metadatenberichte.
- Eigene synthetische Browserläufe: ZIP-Verarbeitung, Seitenwechsel während Run, Entwurfserhalt, gleichnamige Fälle nach Datum/ID getrennt, Quellenreferenzen und Downloads, DE/EN, vier Einstellungskategorien, 390-px-Ansicht ohne Seitenoverflow und Escape/Fokusrückgabe. Keine Browserconsolefehler.
- Gebündelte Web-/Localeassets bytegleich zum Quellstand. Entfernte Malware-/Tabellen-/Viewerparser nicht im PYZ, entfernte Webskripte nicht im EXE-Archiv.
- Regressionsfälle: passive historische Arbeitsbereiche, keine automatische Wiederaufnahme, atomare Konfigurationsänderung, sichere ZIP-Pfade, Originalschutz, Stream-/Cleanup-Grenzen, reine Berichtsmetadaten und vollständiger Erhalt gleichnamiger Nutzeroutputs.

Der letzte lokale Neuaufbau änderte ausschließlich Zeilenenden/Leerzeichen nach der visuellen Browserprüfung; die gesamte Test-/EXE-Suite und der Assetbytevergleich wurden anschließend wiederholt. Keine funktionale Änderung danach.

## Grenzen

Keine automatischen Tests mit echten Nutzer-Evidenzen. Kein tatsächlicher 2-TB-Praxistest, keine Zusicherung fachlich vollständiger KAPE-Ergebnisse und keine Isolation administrativer PowerShell-/Toolprogramme. Zwei Berechtigungsskips sind keine bestandenen Symlinktests. Native UAC-Bestätigung, reale Exploreranzeige in der Nutzersitzung und fachliche Nutzerabnahme bleiben manuell.

Lokal gebautes EXE und GitHub-CI-Build entstehen getrennt. Ihre ZIP-/EXE-Prüfsummen dürfen unterschiedlich sein; jede bereitgestellte Datei hat ihre eigene Prüfsumme. Kein Token oder Nutzerdatenbestand im Release.
