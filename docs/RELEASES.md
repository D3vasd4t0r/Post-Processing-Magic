# Release-Bereitstellung auf Google Drive

Ausdrückliche Nutzerpräferenz: Releases direkt in Drive bereitstellen und mit Link testen.
Zielordner: https://drive.google.com/drive/u/0/folders/1p1jUZHZGe44Bx3yCWBhk-bIdmpcmw900
Lokaler synchronisierter Pfad: C:/Users/N0/My Drive/Post-Processing-Magic Releases.
Nur Release-ZIP, Prüfsumme und Start-/Testanleitung kopieren. Keine Konfigurationen,
Tokens, Evidenzen, Ergebnisse oder Logs. Existierende abweichende Dateien nicht überschreiben.
Nach Kopieren nicht bloß lokalen Bestand prüfen: Cloud-Ordner im Browser laden und
vollständige Datei/Archivvorschau verifizieren. Freigaben bleiben privat/eingeschränkt.

## Stand 22.10.2026

GoogleDriveFS war nicht gestartet. Installierten Client 132.0.0.0 gestartet und
laufende Prozesse geprüft. Browser-seitig erstellter Ordner wurde lokal synchronisiert.
Release 0.19 anschließend über lokalen Drive-Client übertragen, lokale Dateihashes
verglichen. Cloud bestätigt ZIP (19,9 MB), Prüfsumme und TEST-0.19.txt. ZIP-Vorschau
zeigt fünf erwartete Dateien einschließlich PostProcessingMagic.exe.

0.19: https://drive.google.com/file/d/1jzc0WoiM1YuJJ2J3ok1m1aDZrThoxGyv/view
ZIP SHA256: f6c07449233022439bd5734abd4f981775450494131ee9bdb4c73f51b4605772
Quellpaket: dist/releases/PostProcessingMagic-0.19.0-Windows.zip
Testanleitung: https://drive.google.com/file/d/1ZWL0MbS0_65HnHDu-SjqzD3KzdJjxPzt/view

0.14 war bereits in Drive vorhanden, nicht überschrieben oder erneut hochgeladen:
https://drive.google.com/file/d/1CJiTJ6d3rH8-yj7TOTHDx6aAQeGqBWhs/view
Vorschau bestätigt ursprüngliche EXE plus START.txt. Keine Prüfsumme eines anderen
lokalen 0.14-ZIP-Containers als Hash dieser vorhandenen Cloud-Datei ausgeben.

Drive-Plugin wird installiert gemeldet, aber keine Uploadtools in dieser Sitzung.
Chrome-Upload scheiterte an fehlendem Allow access to file URLs. Keine Browser-
Sicherheitseinstellung geändert; stattdessen autorisierten lokalen Drive-Client benutzt.
Cloud-Upload tatsächlich verifiziert. Screenshot .local-data/drive-releases-019.jpg.


Ausführliches Testprotokoll 0.19 mit Soll-Ergebnissen, Checkboxen und Feedbackvorlage
über den jetzt verfügbaren Google-Drive-Connector hochgeladen und Metadaten geprüft:
https://drive.google.com/file/d/1VLPk9jawyzKsuf9SB1ins5KcZuIrK8Qn/view
Lokale Quelle: dist/releases/TESTPROTOKOLL-0.19.txt. Kein Token im Dokument.


0.19.1: https://drive.google.com/file/d/1lm65xAvRbJbBdNA_gnqO9-g6aHV-6IRd/view
ZIP SHA256: baf7dfadcf98b21374b0f391f6729af019f216c9e8d77dacc8729ee5535ea9ac
Connector-Upload und Metadaten/Größe 20826028 Bytes bestätigt.


## 0.20.0

Nutzerwunsch: eigene Versionsordner; Anleitung direkt im Chat, kein erforderlicher
Anleitungsdownload. Ordner: https://drive.google.com/drive/folders/1XHvw1B6cH7nj4fNq_W2FCrbfg05FBTgN
ZIP: https://drive.google.com/file/d/15e1mxNh0k20kcbrJ8lRpgusODhgJ_9l7/view
SHA256: ecaca01dd1e90180d3885c50300cc13ffec8ad15c0a2902e7de15a53062d93e8
Lokale Quelle: dist/releases/0.20.0/PostProcessingMagic-0.20.0-Windows.zip
Größe 23752779 Bytes; Connector-Upload und Drive-Metadaten/Elternordner bestätigt.
ZIP enthält ausschließlich EXE und deren Prüfsumme, ZIP-Prüfsumme separat im Ordner.
Keine Tokens, Konfigurationen, Evidenzen, Ergebnisse oder Logs übertragen.

Abschließenden Build dist/0.20.0-release in vorhandener Drive-Datei aktualisiert (gleiche ID, keine Duplikate), Prüfsumme ebenfalls aktualisiert. Metadaten/Größe/Versionsordner nach Aktualisierung bestätigt.
