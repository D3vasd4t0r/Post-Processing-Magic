# Ideen zur einzelnen Ja/Nein-Auswahl

Stand: 21.10.2026, nach erfolgreicher Nutzerabnahme 0.9.
Nutzerauswahl vom 21.10.2026 ist unten erfasst. Der jeweilige Umsetzungsstand steht
in ROADMAP. Ja bedeutet vormerken; Priorität und nächste Umsetzung anschließend
gemeinsam bestimmen. Abgelehnte Ideen nicht einplanen. Idee 6 erst ganz zum Schluss
erneut ansprechen; die Entscheidung ist ausdrücklich noch offen.

Bereits gewünschte Punkte wie Show in Explorer, die spätere statische Malware-
Analyse und optionale Hashfunktionen stehen separat in ROADMAP und werden hier
nicht erneut zur Freigabe gestellt. Aktuelle Tests nicht unterbrechen.

| Nr. | Neue Idee | Nutzen und Umfang | Entscheidung |
| --- | --- | --- | --- |
| 1 | Speicherübersicht | Freien Platz und Speicherverbrauch von Eingängen, Arbeitsordnern und Ergebnissen in der App anzeigen; vorhandene Speicherprüfungen bleiben bestehen. | Ja – vorgemerkt |
| 2 | Arbeitslaufwerk wählen | Arbeits- und Ergebnisdaten für neue Aufträge auf ein ausgewähltes Laufwerk legen, etwa eine große SSD; bestehende Aufträge nicht automatisch verschieben. | Ja – vorgemerkt |
| 3 | Aufräumen abgeschlossener Aufträge | App-eigene Arbeitsdaten gezielt nach Auswahl und mit klarer Größenanzeige entfernen; extern referenzierte Original-Evidencen niemals löschen. Konkrete Löschbestätigung erst bei Nutzung. | Ja – vorgemerkt |
| 4 | Auftragssuche und Filter | Gespeicherte Aufträge nach Dateiname, Datum, Modus und Status durchsuchen, statt nur die letzten 50 Einträge zu sehen. | Ja – vorgemerkt |
| 5 | Auftrag erneut anlegen | Einen früheren Auftrag als Grundlage für einen neuen Lauf übernehmen. | Nein – nicht einplanen |
| 6 | Zeitlimit je Befehlsblock | Das bisher feste Laufzeitlimit pro Befehl konfigurierbar machen. | Eventuell – erst ganz zum Schluss erneut ansprechen |
| 7 | Sichtbarer Konfigurationsverlauf | Frühere gespeicherte Konfigurationsstände in der App ansehen, vergleichen und wiederherstellen. | Nein – nicht einplanen |
| 8 | Lesbarer Abschlussbericht | Lokaler HTML-Bericht mit Befehlsfolge, Toolversionen, Zeiten, Fehlern, Ergebnisübersicht, SHA-1/SHA-256 von Eingangs- und Ausgabedateien sowie erstellten Unterordnern. Keine erfundenen Analysebefunde. | Ja – mit Nutzerergänzungen vorgemerkt |
| 9 | Warteschlange pausieren | Vor dem nächsten Auftrag pausieren können; der bereits laufende Auftrag wird regulär beendet. Keine Unterbrechung mitten im Toolprozess versprechen. | Ja – vorgemerkt |
| 10 | Ergebnis-ZIP optional | Bei lokaler Ergebnisnutzung das abschließende Zippen optional überspringen und den fertigen Ordner bereitstellen; ZIP-Download dann erst nach ausdrücklich gestarteter Archivierung. | Ja – vorgemerkt |
| 11 | Mehrere Aufbereitungen gleichzeitig | Mehrere getrennte Aufträge parallel mit begrenzter Parallelität und eigenen Arbeitsordnern ausführen; Ressourcen und Toolverträglichkeit berücksichtigen. | Ja – ausdrücklicher Zusatzwunsch, ganz in Zukunft |

## Auswahl des nächsten Schritts

Show in Explorer, Speicherübersicht, Auftragssuche, Warteschlangenpause und die
Datenbereinigung bis 0.15 sind vom Nutzer bestätigt. Am 22.10.2026 hat der Nutzer
vier bis fünf größere Pakete vor dem nächsten Test ausdrücklich freigegeben.
Daraus umgesetzt in Sammelbuild 0.19: Arbeitslaufwerk (Idee 2), optionales ZIP
(Idee 10), Abschlussbericht (Idee 8) sowie gezielte Bereinigung je Auftrag (Idee 3).
Nutzerabnahme 0.19 noch offen. Abgelehnte Ideen und späte Parallelität bleiben unverändert.


## Weitere Auswahl vom 22.10.2026

- Desktop-Serverfenster: als nächster Meilenstein gewählt; Details in ROADMAP.
- Diagnosepaket mit Vorschau und bereinigten technischen Daten: Ja, später vormerken.
- Konfigurationssicherung/-wiederherstellung direkt im Desktopfenster: später erneut
  besprechen; keine zusätzliche Freigabe neben vorhandenem Import/Export.
- Feedbackbutton oben in der Web-Leiste für Feedback/Bugs/Wünsche: Ja, ausdrücklicher
  Nutzerwunsch, vormerken. Speicherort und mögliche Übermittlung noch offen.

Feedbackfunktion konkretisiert (22.10.2026): Feedback, Bugs und Wünsche lokal
speichern und bei Bedarf ausdrücklich zum Teilen exportieren. Kein automatischer Versand.

Wartungsidee bestätigt (22.10.2026): Größenbasierte Rotation ausschließlich
technischer Serverlogs, mit einstellbarer Anzahl aufzubewahrender Logdateien.
Für späteren Wartungsmeilenstein vormerken. Auftragslogs, Auditdaten, Evidenzen
und Ergebnisse ausdrücklich nicht automatisch über diese Funktion bereinigen.

Servereinstellungen im Desktopfenster (22.10.2026): Port und Zugriff lokal/LAN
für einen folgenden Wartungsmeilenstein vormerken, ausdrücklich nicht Teil des
ersten Serverfensters. Änderungen nach bewusstem Neustart; LAN weiterhin mit
Authentifizierung und selbstsigniertem HTTPS, keine automatische Firewalländerung.
