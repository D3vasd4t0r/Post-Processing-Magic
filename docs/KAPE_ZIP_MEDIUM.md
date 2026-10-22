# Nutzerbeispiel: ZIP mit KAPE-Target, Medium ohne Timeline

Vom Nutzer am 21.10.2026 als fachliches Beispiel bereitgestellt. Noch kein
ausführbarer oder freigegebener Modus. Ab Version 0.3.0 ist es als bearbeitbarer
Konfigurationsentwurf mit einem KAPE-Befehlsblock in der App enthalten.
Es wurden weder KAPE noch Module ausgeführt.

## Gewünschter Ablauf

1. ZIP-Evidence annehmen und unverändert aufbewahren.
2. In ein eigenes Jobverzeichnis entpacken, sodass das KAPE-Target unter
   `Targets\C` liegt. Den tatsächlichen ZIP-Aufbau vorher prüfen; keine Pfade
   ungeprüft übernehmen oder Dateien mit gleichem Namen blind zusammenführen.
3. KAPE mit dem unten stehenden Aufruf aus dem Jobverzeichnis starten.
4. Das Ende der Verarbeitung abwarten und Exitcode, Ausgaben und Fehler prüfen.
5. Den Ergebnisordner `PostMortem` als Ergebnis-ZIP packen, hashen und erst danach
   den autorisierten Download in der Oberfläche freigeben.

`Targets` und `PostMortem` gehören jeweils zum Job, nicht in einen gemeinsam
beschriebenen globalen Ordner. Der KAPE-Pfad soll aus den Tool-Einstellungen kommen.

## Originalbefehl des Nutzers

```text
kape.exe --msource .\Targets\C --mdest .\PostMortem --module CCMRUAFinder_RecentlyUsedApps,Chainsaw,hayabusa_OfflineEventLogs,DHParser,ObsidianForensics_Hindsight,SRUMDump,NirSoft_BrowsingHistoryView,NirSoft_FullEventLogView_PowerShell-Operational,NirSoft_FullEventLogView_ScheduledTasks,NirSoft_FullEventLogView_Security,NirSoft_FullEventLogView_System,!EZParser,LogParser,LogParser_RDPUsageEvents,NTFSLogTracker,RegRipper,PowerShell_Move-KAPEConsoleHost_history,PowerShell_MFTECmd_J-MFTParsing,PowerShell_Get-DoSvc4n6,EvtxHussar,NirSoft_TurnedOnTimesView,OneDriveExplorer --gui
```

Die Modulliste ist als exakte Nutzerreferenz zu erhalten. Keine zusätzlichen
Timeline-Schritte ergänzen. „Medium“ ist der gewünschte Modusname und wird nicht
stillschweigend mit „Normal“ oder einer anderen vordefinierten Stufe gleichgesetzt.

## Beim echten KAPE-Test gemeinsam prüfen

- Struktur der realen KAPE-Target-ZIPs und korrekte Quellwurzel
- Vorhandene KAPE-Version, Module, zusätzliche Toolabhängigkeiten und Lizenzen
- Verhalten von `--gui` im vorgesehenen Workerbetrieb; vor einer Änderung mit
  dem Nutzer abstimmen, den Referenzaufruf nicht kommentarlos verändern
- Zuverlässige Abschluss-/Fehlersignale und ob Unterprozesse noch Ausgaben schreiben
- Welche echten Fortschrittsmeldungen KAPE liefert; ohne Messsignal den laufenden
  Schritt als unbestimmt anzeigen, keine Prozentwerte erfinden
- Endgültiger ZIP-Inhalt, Verzeichnisstruktur und gewünschter Report

Die UI kann zunächst die Phasen „Entpacken“, „KAPE“, „Ergebnis packen“ und den
Gesamtstand anzeigen. Der lange KAPE-Aufruf ist ein Workflow-Schritt; die Anzahl
der aufgelisteten Module wird ohne geprüfte Ereignisse nicht als erledigte
Command-Anzahl ausgegeben. Der Ablauf ist im Modus-Editor konfigurierbar
und zusammen mit den Toolreferenzen exportierbar/importierbar. Ab 0.7.0 steht
der erste Einzelbefehls-Runner bereit. Technischer Vorabtest erfolgte mit einem
selbst kompilierten Testprogramm; echte KAPE- und ZIP-Abnahme folgt per Nutzer-Run.
