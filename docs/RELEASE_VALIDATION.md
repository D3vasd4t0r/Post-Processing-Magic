# Prüfung der Vorabversion 0.24.0

130 automatisierte Tests und Ruff bestanden. Die lokal gebaute Windows-EXE wurde mit selbst erzeugten Testdaten geprüft: Start, ZIP-Verarbeitung mit Ergebnisbericht und Bereinigung, geordnetes Stoppen, Force Shutdown einschließlich Prozessbaum und sofortiger Kennzeichnung unterbrochener Aufträge sowie Neustart ohne automatische Wiederholung.

Wartungsprüfungen bestanden: Diagnosevorschau und identischer ZIP-Export ohne sensible Inhalte, lokale Feedbackpersistenz und Export, bewusst verzögerte Übernahme der Servereinstellungen, Portwechsel, selbstsigniertes HTTPS mit Zertifikatsprüfung, tatsächliche technische Logrotation und Offline-Diagnose.

GitHub Actions baut und prüft separat einen Windows-Build vor der Veröffentlichung. Der Build auf Google Drive wurde lokal erstellt; deshalb können die Prüfsummen beider Builds voneinander abweichen. Jeweils die mitgelieferte Prüfsumme verwenden.

Die manuelle Abnahme der Wartungsfunktionen durch den Nutzer steht aus. Kein Test auf einem sauberen fremden Windows-System und keine LAN-Abnahme auf einem zweiten Gerät. Für diese Prüfungen wurden keine echten Evidenzen verarbeitet.
