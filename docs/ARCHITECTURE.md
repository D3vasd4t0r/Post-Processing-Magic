# Architektur – ZIP-Aufbereitung 0.40

## Prozesse und Speicher

Python 3.12+, FastAPI/Uvicorn, lokales HTML/CSS/JavaScript, SQLite und PyInstaller. Die Windows-EXE startet ein natives Serverfenster. Der Server startet den separaten seriellen Worker; HTTP-Anfragen führen keine Analysebefehle aus. Entry-Point/Worker-Modus verhindern rekursive EXE-Starts. Auf dem Zielsystem sind keine Entwicklungsruntimes oder Netzwerkdienste erforderlich.

Daten liegen standardmäßig unter LOCALAPPDATA/PostProcessingMagic oder in einem expliziten Datenverzeichnis. Neue Jobs können ein registriertes anderes Arbeitslaufwerk verwenden; das wird im Job eingefroren. Bestehende Jobs behalten ihren Ort. Zentrale workspaces.job_paths löst Auftragsdaten auf. Keine Speicherung im PyInstaller-Entpackverzeichnis.

SQLite hält Queue, Ereignisse, Konfiguration, Wartungsstatus und Audit. Claims, Queuepause, Drain und Cleanup-Sperren sind transaktional. Neustart kennzeichnet unterbrochene aktuelle Jobs; kein blindes Wiederholen. Historische Jobs ausgeschlossener Arbeitsbereiche bleiben passiv und werden weder angeboten noch beansprucht oder wiederhergestellt. Sie blockieren den neuen Drain nicht.

## Verarbeitung

Version 0.40 unterstützt ausschließlich ZIP/KAPE-Target. compile_plan friert Modus, Schritte, Limits, Toolhash/-version und relevante Dateinachweise ein. Pro Job ein eigener Arbeitsordner, relatives Entpackziel und relativer Ergebnisordner. KAPE startet als Programmdatei mit getrennter Argumentliste, höchstens ein Offline-Modulbefehl. Freie PowerShell ist ein ausdrücklicher Blocktyp mit eigenem relativem Arbeitsverzeichnis und eingefrorenem Zeitlimit. cd wirkt nur innerhalb des Blocks. Kein implizites Interpretieren von Toolparametern als Shellcode.

UAC-Administratorstart ist Nutzeranforderung; Worker/Tools erben Rechte. Verweigerte UAC wird nicht umgangen. --test-no-admin gilt nur für eigene synthetische automatisierte Tests. Toolausführung ist keine Sandbox.

Upload: Streaming, Größen-/Speicherlimit, temporäre Datei, Hash und atomare Finalisierung. Clientdateinamen dienen nicht als Pfad. Lokale ZIPs werden referenziert, nicht kopiert; lesender Windows-Handle mit Identitäts-/Zeit-/Größenprüfung schützt Hash und Extraktion gegen Änderungen. Originaldateien werden nie verändert.

ZIP-Prüfung vor Extraktion: Traversal, absolute/UNC-/Laufwerkspfade, ADS, Symlinks/Reparse/Sonderdateien, Größen, Anzahl, Verhältnis und Verschachtelung. Hohe Kompression ist bei neuen Jobs immer freigegeben, ersetzt keine anderen Grenzen. Alte Snapshots behalten ihre Werte. Kein Verschlüsselungssupport.

Windows Job Objects überwachen Toolbäume und Abbruch. SSE mit wiederaufnehmbarer Ereignisnummer zeigt tatsächliche Ereignisse; unbekannter Toolfortschritt bleibt unbestimmt. Bounded Terminalausgabe und gespeicherte Logs sind vom Audit getrennt.

## Oberfläche und API

Ein blauer ZIP-Arbeitsplatz, fünf Seiten: Aufbereitung, Einstellungen, Logs, Ergebnisse, Feedback. Vier Einstellungstabs: Tools, Modi, Allgemein, Konfiguration. Keine Malwareausführung oder Bereichs-/Simple/Advanced-Steuerung. Tabelleninhaltsvorschauen, externe Ergebnis-Viewer und interne Evidenzauswertungen sind aus dem aktiven Produkt entfernt.

Aufbereitung zeigt Quelle, Format/Aufwand, Fall/Gerät, Run, echten Status/Fehler/Abbruch und Downloads. Logs wählen den Auftrag über einen paginierten Dropdown, zeigen Status, Arbeitsordner und Terminal. Ergebnisse halten auch gleiche Fallnummern über Datum/ID auseinander. Navigation beendet keine Uploads oder Aufträge. Asynchrone Antworten sind an Auswahl/Navigation gebunden, damit alte Daten keine neuen Aufträge überlagern.

Geschützte API-Endpunkte autorisieren Jobs, Ereignisse, Abbruch und Downloads serverseitig. Hochgeladene Originale werden über kurzlebige einmalige Downloadtickets gestreamt. Identität/Reparse/Hardlink/Zeitprüfung und persistente Streamlease mit Heartbeat sperren konkurrierende Bereinigung. Lokale Originale sind ausschließlich Verfügbarkeitsreferenzen, niemals automatische Originaldownloads. Große Dateien nicht als Browser-Blob puffern.

Show in Explorer erfordert lokalen autorisierten Loopbackzugriff, einen geprüften erfolgreichen Jobordner und eine interaktive Windows-Sitzung. Keine freie Pfadeingabe oder Ergebnisdateiausführung.

## Konfiguration und Bericht

Neuer Export Schema 4 nur Tools/Forensikmodi/Limits. Import akzeptiert ältere Schemas mit Vorschau, validierten Konflikten, veraltete Vorschauen ablehnen, atomar anwenden und vorher sichern. Legacy-Malwarefelder erfordern eine zusätzliche explizite Bestätigung, dass diese Bereiche nicht übernommen werden. Historische Tabellen bleiben unberührt; keine automatische Ausführung.

HTML-/JSON-Berichte verwenden eine detached, idempotente Metadaten-Allowlist, auch beim Abruf alter Forensikberichte. Eingangs-/Ausgangshashes, technische Zeiten/Exitcodes/Toolhashes, reine Datei-/Pfadlisten und Verzeichnis-/Dateizahlen. Keine Terminal-/CLI-Ausgaben, Klassifikation oder Befunde. Inventar liest keine Dateiinhalte und hat harte Eintrags-/Zeit-/Ausgabegrenzen. Fehlende alte Daten werden nicht nachanalysiert.

Ergebnis-ZIP enthält Nutzeroutputs und aktuelle Metadatenberichte, keine App-Kommandozeilenlogs oder alten App-Berichte. Originaldateien werden beim Filtern nicht gelöscht. ZIP-Hash steht im externen Abschlussbericht; der eingebettete Bericht kann den Hash seines eigenen endgültigen ZIPs nicht enthalten.

## Betrieb und Grenzen

Selbstsigniertes HTTPS bei LAN, Tokenauthentifizierung, kein automatischer Firewall-/Trust-Store-Eingriff. Token nie in Export, Diagnosepaket oder Repository. Technische Logrotation betrifft nur Serverlogs. Bereinigung verlangt Vorschau und ausdrückliche Bestätigung, respektiert offene Jobs/Archive/Downloads und lokale Originalreferenzen.

Lokale Hashwerte sind Integritätsmetadaten, kein alleiniger Herkunfts-/Gerichtsfestigkeitsbeweis. Code-/Sicherheitsreview und HTML-Code-Wiki sind erst nach dem neuen Nutzertest vorgesehen.
