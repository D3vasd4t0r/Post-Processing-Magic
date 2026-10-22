# Großer gemeinsamer Test 0.24.0

Vier ausdrücklich freigegebene Wartungspunkte: Diagnosepaket, Feedback,
Servereinstellungen Port/LAN und technische Logrotation. Danach Scrum-Gespräch.
Version 0.20 ist abgenommen. 0.24-Nutzerabnahme steht aus.

Neue getrennte Instanz geplant: http://127.0.0.1:8772/ mit .local-data/ui-v024-release.
Startverknüpfung „Testversion 0.24 starten.lnk“ im Projektordner. Nur Tool-/Modus-
Konfiguration übernehmen, keine Aufträge/Evidenzen/Ergebnisse kopieren oder analysieren.
Aktueller tatsächlicher Token ausschließlich im Chat und Serverfenster.

1. Aktives Serverfenster 0.24, Administrator/Worker aktiv. Browser öffnen.
2. Feedback oben: Bug/Wunsch/Testtext lokal speichern; schließen/öffnen, Eintrag
   bleibt erhalten. Feedback.json exportieren und eigenen Text wiederfinden.
3. Einstellungen → Verarbeitung → Diagnosepaket vorbereiten: vier Dateien und
   Inhalte ansehen, ZIP herunterladen. Keine Tokens, Pfade, Evidencen, Toolausgaben
   oder Feedbacktexte im Paket. Vorschau exakt, zehn Minuten gültig, einmaliger Export.
4. Im Serverfenster Diagnosepaket… ebenfalls ansehen und lokal speichern.
   Nach Server stoppen auch offline Vorschau prüfen, danach Server starten.
5. Servereinstellungen: Port von 8772 auf einen freien Port, z.B. 8773, speichern.
   Laufender Server bleibt erreichbar. Stop/Start übernimmt neue Adresse; Browser öffnen.
6. In Servereinstellungen Loggröße 0,1 MB und zwei ältere Dateien speichern,
   bewusst neu starten. Web-Diagnose/Systemstatus active_server zeigt 100000 und 2.
   Tatsächlichen Dateiumbruch hat der Agent synthetisch geprüft; keine langen
   KAPE-Aufträge nur zum Füllen der technischen Logs erforderlich.
7. Optional LAN: im Serverfenster LAN speichern und bewusst neu starten. Adresse
   wechselt auf HTTPS, automatisch selbstsigniertes Zertifikat. Browser-Vertrauen
   muss der Nutzer selbst bestätigen; keine automatische Firewalländerung.
   Anschließend wieder Lokal wählen und Stop/Start, wenn Remotezugriff nicht nötig.
8. Port wieder 8772, Lokal, Loggröße 2 MB / drei Dateien einstellen, Stop/Start.
   Fenster geordnet beenden und Verknüpfung erneut starten: gespeicherte Werte
   und lokales Feedback bleiben erhalten. X-/Tray-/Force-Steuerung aus 0.20 unverändert.

Feedback mit Nummern hier im Chat, danach gemeinsames Scrum-Gespräch.
Neuer Token bei jedem Start: über Browserbutton anmelden oder aus Serverfenster kopieren.
Keine echte Evidence für diesen Wartungstest erforderlich. Bestehende Nutzerinstanzen
bleiben unverändert. Keine automatische Übermittlung von Feedback/Diagnosepaketen.
