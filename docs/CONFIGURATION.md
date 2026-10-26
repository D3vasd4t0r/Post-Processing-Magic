# Konfiguration 0.40

Die vier Kategorien sind Tools, Modi, Allgemein und Konfiguration. Einstellungen speichern führt keinen Befehl aus. Erst Run startet die bewusst gewählte Befehlsfolge.

## Tools und Modi

Tools mit Namen und absolutem Serverpfad anlegen, prüfen und bearbeiten. Der Picker merkt den letzten Ordner. Das Prüfen startet kein Tool. Wird ein Tool in einem Modus verwendet, warnt Entfernen mit den betroffenen Modi und verändert weder Tool noch Referenzen.

ZIP-Modi je Aufwand schnell, Medium, langsam sind eindeutig. Belegte Slots beim Neuanlegen gesperrt, eigene Stufe beim Bearbeiten erlaubt. Altbestand mit doppelten Slots bleibt als sichtbarer Konflikt erhalten. Nur vollständig konfigurierte Stufen werden für Run freigegeben.

Import: relatives Entpackziel. Verarbeitung: geordnete Tool- oder freie PowerShell-Blöcke, einfügen/verschieben/entfernen. Export: Ergebnisordner als eigene Zeile. ZIP mit C und Ziel Targets ergibt Targets/C. Toolparameter ohne exe-Namen eingeben; Programmdatei kommt aus der Referenz. Aktueller Runner höchstens ein KAPE-Befehl plus PowerShell oder reine PowerShell. Nicht unterstützte Toolfolgen bleiben gesperrt.

PowerShell unterstützt mehrzeiligen Code, relatives Arbeitsverzeichnis und Zeitlimit. Unterordner müssen vor Verwendung existieren; cd gilt nur im eigenen Block. Neue Jobs erhalten unveränderliche Snapshots. Änderungen betreffen keine laufenden/alten Jobs.

## Portable Datei

Export Schema 4 enthält Tools, Forensikmodi einschließlich Schritten/Argumenten/Reihenfolge und gemeinsame Verarbeitungslimits. Keine Tokens, Schlüssel, Jobs, Evidenzen oder Toolprogramme. Arbeitslaufwerk, Port/LAN/Logrotation und Sprache bleiben serverlokal.

Import: Datei wählen, Zusammenführen oder ausdrücklich bestätigtes Ersetzen, Vorschau prüfen, anwenden. Validierung und Konfliktprüfung erfolgen vor atomarer Änderung; automatische Sicherung vor Anwendung. Veraltete/abgelaufene Vorschauen werden abgewiesen. Auf dem Zielsystem Toolpfade erneut prüfen und importierte Modi bewusst freigeben.

Alte Schemas 1/2/3 bleiben kontrolliert einlesbar. Enthaltene entfallene Malwarefelder lösen eine deutliche Vorschauwarnung und gesonderte Bestätigungscheckbox aus, auch wenn die Liste leer ist. Ohne Bestätigung keine Übernahme. Historische Altdaten werden weder gelöscht noch umgedeutet.

## Allgemein

Uploadlimit in GiB, Standard 50; Entpacklimit in TB dezimal, Standard 2. Hohe Kompression bei neuen Jobs immer erlaubt ohne Checkbox; andere ZIP-Grenzen gelten weiter. Limits pro Auftrag eingefroren. Arbeitsziel gilt nur für neue Jobs, keine automatische Datenmigration.

Speicher-/Queue-/Bereinigungs-/Diagnosefunktionen bleiben betriebliche Einstellungen. Vorschau vor Löschung/Diagnoseexport prüfen. Diagnose exportiert keine Toolausgaben oder Evidenzen. Feedback wird lokal gespeichert und erst auf bewussten Export geteilt.
