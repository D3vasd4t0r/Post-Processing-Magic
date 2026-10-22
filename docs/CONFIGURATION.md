# Konfiguration im Browser und Datenaustausch

Nutzervorgaben vom 21.10.2026 nach dem ersten Startgerüst.

## Aktuell ab 0.9.0

JSON-Export verwendet Schema 2 und enthält zusätzlich Verarbeitungslimits sowie
Blocktyp, PowerShell-Code und relatives Arbeitsverzeichnis. Schema-1-Dateien
bleiben importierbar; ohne Limits bleiben die aktuellen Werte erhalten. Vorschau
zeigt Limitänderungen; Änderungen der Limits machen alte Vorschauen ungültig.
Backup und atomare Anwendung schließen die Limits ein. Keine Tokens oder Evidencen.

Einstellungen → Verarbeitung: Upload in GiB (Standard 50), Entpacklimit in TB dezimal
(Standard 2 = 2.000.000.000.000 Bytes). Werte werden pro Auftrag eingefroren.

Im Modus-Editor stehen Tool-Aufruf und „Freier PowerShell-Befehl“ zur Wahl.
PowerShell benötigt keinen Tool-Eintrag und unterstützt mehrzeiligen Code. Das
Arbeitsverzeichnis ist relativ zum eigenen Auftragsordner, standardmäßig `.`;
Unterordner müssen vorher angelegt sein. cd gilt nur innerhalb eines Blocks.
KAPE bleibt im Auftragsordner `.`. Geordnete PowerShell-Blöcke vor/nach höchstens
einem KAPE-Block oder reine PowerShell-Modi sind ausführbar; andere Toolrunner
folgen später. Fehler stoppen nachfolgende Blöcke. Speichern und Import führen
nichts aus; Run startet bewusst die gewählte Befehlsfolge mit Administratorrechten.

Die folgenden Abschnitte beschreiben auch historische Editor-Zwischenstände.

## Produktmodell

Die Anwendung startet ohne vorgegebene Analysekonfiguration. Nutzer hinterlegen
Tools und bauen darauf eigene Modi mit geordneten Verarbeitungsschritten auf.
PS1-Dateien müssen für diese Anpassungen nicht editiert werden.

Auf ausdrücklichen Nutzerwunsch wird ab 0.3.0 einmalig eine bearbeitbare KAPE-Vorlage
„Medium / ohne Timeline“ angelegt. Sie ist ausschließlich ein Entwurf ohne Ausführung.
Version 1 unterstützt nur ZIP (KAPE-Target); E01 und VMDK bleiben in Planung.

Ein Tool beschreibt Name, lokale Programmdatei bzw. Installationsverzeichnis und
später seine überprüfte Version. Ein Modus enthält Name, Beschreibung und eine
Liste von Schritten. Ein Schritt referenziert ein Tool und definiert Argumente
sowie unterstützte Platzhalter für Ein- und Ausgabe. Die Reihenfolge bestimmt,
wann welches Tool aufgerufen wird. Geräte-/Evidence-Zuordnung und weitere
Bedingungen werden gemeinsam mit dem Nutzer pro Aufbereitungsart festgelegt.

Die Ausführung verwendet Programmdatei und getrennte Argumentliste; „als CMD“
bedeutet zunächst Kommandozeilenaufruf. Shell-Verkettungen, Umleitungen oder
PowerShell-Code werden nicht stillschweigend aus Freitext interpretiert. Wenn
solche Funktionen gebraucht werden, ist dafür ein expliziter Schritttyp erforderlich.
Gespeicherte Einstellungen allein starten keinen Prozess.

## Implementierter Editor ab 0.3.0

- Modi anlegen, bearbeiten, kopieren und entfernen
- Relatives Entpackziel im eigenen lokalen Arbeitsordner jeder Evidence-Aufbereitung
- Geordnete Befehlsblöcke: Toolreferenz per Dropdown, Parameter ohne Programmname
- Schritte davor/danach einfügen, nach oben/unten verschieben und entfernen
- Vorschau mit konfiguriertem Toolpfad, keine Shell- oder Programmausführung
- Ergebnisordner für das spätere abschließende ZIP festlegen
- Alles zusammen in SQLite speichern, inklusive stabiler Schritt-IDs und Reihenfolge

Ab 0.4.0 ist das Neuanlegen auf genau einen Modus pro ZIP-Aufwandsstufe begrenzt.
Bestehende doppelte Testdefinitionen werden markiert und nicht automatisch verändert.
Prüfung und Speichern einer Stufe sind transaktional; parallele Anfragen können
nicht beide dieselbe freie Stufe neu belegen. Änderungen im eigenen bisherigen
Slot bleiben möglich. Eine vorgefundene Konfliktsituation muss der Nutzer bewusst
auflösen. Die Übersicht unterscheidet fehlende, unvollständige, konfigurierte und
mehrfach belegte Stufen. Das ist keine Freigabe einer echten Programmausführung.

Beispiel: Die ZIP-Struktur enthält C. Entpackziel Targets ergibt Targets/C unter
work/{Aufbereitungs-ID}. Der KAPE-Schritt nutzt --msource .\Targets\C und
--mdest .\PostMortem. Am Ende wird künftig PostMortem gezippt. Ordner werden jetzt
noch nicht angelegt; der Runner folgt in einem späteren Testpaket.

Parameter sind aktuell gespeicherter Text. Vor echter Ausführung ist noch eine
getestete Windows-Argumentverarbeitung notwendig; Texte werden nie als freie
Shell-Befehle gestartet. Die KAPE-Vorlage wählt kein beliebiges vorhandenes Tool
automatisch aus: Der Nutzer ordnet den passenden KAPE-Toolpfad ausdrücklich zu.

## Import und Export ab 0.5.0

Eine versionierte JSON-Konfigurationsdatei transportiert zusammen:

- Tooldefinitionen mit stabilen Referenzen und Pfaden
- Eigene Modi und Zuordnungen
- Geordnete Verarbeitungsschritte, Argumente und unterstützte Platzhalter
- Künftig ergänzte Workflowoptionen innerhalb eines versionierten Schemas

Nicht enthalten sind Zugangstokens, Zertifikatsschlüssel, Evidence-Dateien, Jobs
oder die ausführbaren Forensiktools selbst. Die verwendeten Programme müssen auf
dem Zielrechner vorhanden sein; importierte Pfade können dort neu zugeordnet werden.

Unter Einstellungen → Konfiguration werden alle Tools und Modi als JSON exportiert.
Formatkennung: `post-processing-magic.configuration`, `schema_version: 1`.
Der Import akzeptiert Anfragen bis 4 MiB und validiert Schema, Pfade, Namen,
Toolreferenzen und eindeutige Format-/Aufwandsstufen. Unbekannte Felder und
Schema-Versionen werden abgewiesen. Parameter bleiben unveränderter Text;
Platzhalterauflösung und Windows-Argumentverarbeitung sind noch nicht implementiert.

Zusammenführen behält Einträge bei, aktualisiert gleiche IDs und ergänzt neue IDs.
Gleiche Namen oder bereits anderweitig belegte Stufen blockieren den Import.
Ersetzen übernimmt genau die Datei und zeigt entfallende Einträge in der Vorschau.
Es verlangt zusätzlich die ausdrückliche Bestätigung per Checkbox. Fehlende lokale
Toolpfade und unvollständige Entwürfe werden als Hinweis angezeigt; nicht mehr
vorhandene Toolreferenzen sind ein Fehler. Vorhandene Altkonflikte müssen vor
einem erfolgreichen Import im Modus-Editor aufgelöst werden.

Eine gültige Vorschau gilt zehn Minuten und genau einmal. Änderungen an der
Konfiguration seit der Vorschau erfordern eine erneute Prüfung. Vor dem Anwenden
wird eine vollständige JSON-Sicherung unter `config/backups/before-import-*.json`
angelegt. Alle Änderungen einschließlich Importprotokoll werden in einer
SQLite-Transaktion gespeichert. Die Vorschau verändert keine Konfiguration.
Import startet niemals einen Workflow. Tokens, Zertifikate, Jobs und Evidencen
werden weder importiert noch ersetzt. Die automatische Sicherung lässt sich über
denselben Dateiimport mit Vorschau wiederherstellen.

## Kleine Testpakete

1. Toolverwaltung und Tokenanzeige: Testlauf 1 vom Nutzer abgenommen.
2. Aktuell: Path-Picker für Datei-/Ordnerauswahl und Abbrechen testen.
3. Aktuell: Modi und Befehlsblöcke einschließlich KAPE-Referenz, Entpackziel,
   Reihenfolge und Ergebnisordner testen, weiterhin ohne Toolausführung.
4. Anschließend geprüfte Argumentverarbeitung und Platzhalter separat planen.
5. Konfiguration exportieren/importieren; danach Roundtrip und Konflikte testen.
6. Einfache Hauptoberfläche: Datei, Format, Aufwand, Run, Command-Fortschritt,
   ausklappbare Kommandozeile und „Download Evidences“ gemeinsam testen.
7. Aufbereitungsarten und konkrete Tools gemeinsam festlegen, dann kontrollierte
   Ausführung pro bestätigtem Ablauf implementieren.

Bei jeder Iteration: Änderungen/Features, Testadresse, aktueller Token, wenige
nummerierte Schritte und die Aufforderung, Feedback hier im Chat zu geben.
Diese Reihenfolge kann der Nutzer jederzeit anpassen. Import/Export und Hauptseite
sind vom Nutzer abgenommen. Der erste Runner ab 0.7.0 führt ausschließlich einen
KAPE-Modulbefehl aus; mehrere Schritte und andere Programme bleiben vorerst reine
Entwürfe. Windows-Argumentverarbeitung nutzt CommandLineToArgvW und startet eine
getrennte Argumentliste ohne Shell. Erlaubt sind --msource, --mdest, --module und
optional --gui. Pfadparameter sind relativ und werden mit den Ordnern im Modus
abgeglichen. Platzhalterauflösung folgt weiterhin später.

Eingebundene Tools zeigen ihre verwendenden Modi an. Ein Löschversuch warnt direkt
am Tool und bleibt serverseitig gesperrt; Verknüpfungen werden nicht automatisch gelöst.
Das gilt auch nach einem Konfigurationsimport.
