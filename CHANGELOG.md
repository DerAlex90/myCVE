# Änderungen

## 0.5.0

- Gruppierte Risiken mit erhaltenen Binärpaketen, Komponententyp-/Fixstatusfiltern und getrennten Risikozählern.
- Exakter Kernel-Kontext und getrennte Bewertung von laufenden Images, installierten Images und Entwicklungspaketen; neuer Bericht auch bei einem Kernelwechsel ausreichend.
- Gesicherte Windows-Upgrades mit Vorprüfung, privaten Dateien und automatischem Wiederherstellungsversuch ohne Entfernen der bestehenden Dienstdefinition.
- Gespeicherte erfolgreiche Feed-Resultate für Teilwiederholungen, Fortschritt, kooperativer Abbruch und nachvollziehbare Fortsetzung.
- Filtergerechter CSV-Export mit ausdrücklich wählbarem Umfang; einheitliche Authentifizierung für Daten und Downloads.
- Geschützter Betriebsstatus mit Queue und Worker-/Scheduler-Lebenszeichen; gemeinsame Scan-Erzeugung und effizientere Systemlisten.
- Automatische, auf die geöffnete Ansicht abgestimmte Aktualisierung sowie Kontrastkorrekturen aus der Laufzeitprüfung.
- Migration für vorhandene Datenbanken; [Softwareliste, Grenzen und nachgelagerte Arbeit](docs/softwareliste.md).

## 0.4.0

- Namensnennung und Copyright für Alexander Speka (DerAlex90) in README, Oberfläche, CLI und Paketen.
- Eigene Namensnennungslizenz für neue Fassungen: kostenfreie Nutzung auch kommerziell bei Erhalt der Hinweise; White Label nur nach gesonderter schriftlicher, entgeltlicher Vereinbarung.
- Frühere MIT-Rechte und fremde Lizenzhinweise bleiben ausdrücklich erhalten.
- Öffentliche Lizenzansicht und NOTICE in Python- und Agentenpaketen.

## 0.3.0

- Automatische Produktzuordnung für neue und bereits gespeicherte Inventare anhand des offiziellen NVD-CPE-Katalogs, einschließlich Herstellerprüfung und Quellenbelegen.
- Geräteübergreifender Produktcache, Fortsetzung großer Inventare und automatische Wiederholungen bei Katalogfehlern oder ungeklärten Produkten.
- Automatischer OSV-Abgleich für Ubuntu, Alpine, AlmaLinux, Rocky Linux und RHEL; Alpine-Unterpakete verwenden ihr Quellpaket.
- Windows-Versionsfallback über zusätzliche Registry-Werte, MSI-Versionen und passende lokale Datei-Produktmetadaten.
- Vergleich numerischer CPE-Versionen einschließlich vierteiliger Windows-Versionen und bekannter Architekturbezeichnungen.
- Sichtbarer Bearbeitungsstand der automatischen Zuordnung; gemeldetes Inventar bleibt unverändert gespeichert.
- Datenbankmigration markiert vorhandene Geräte zur automatischen erneuten Prüfung.

## 0.2.0

- Go-Inventar-Agent für Linux/Windows, amd64/arm64; systemd- und Windows-SCM-Dienstinstallation.
- Gerätebindung, separate widerrufbare Schreibschlüssel und einmaliger Konfigurationsdownload.
- Betriebssystem, dpkg/RPM/APK, Windows-Registry/Appx und konfigurierbare CycloneDX-SBOMs.
- Atomare Berichte, idempotente Wiederholung, lokale Wiederholungsdatei und Schutz vor veralteten/unvollständigen Erfassungen.
- Paket- und Quellversionen für Debian getrennt; Korrektur der PURL-Paketidentität bei Distributionspaketen.
- Agentenverwaltung, letzter Kontakt, Status, Berichte, Paketänderungen und sichtbare Abgleichslücken.
- Automatische Vormerkung neuer Inventare für gebündelte CVE-Abgleiche.
- Migration bestehender PostgreSQL- und nativer SQLite-Installationen; Migrationen im Python-Wheel enthalten.
- Gerätespezifische Abrufbegrenzung, geschützte Agent-Downloads und plattformübergreifende CI inklusive isoliertem Windows-Diensttest.

## 0.1.0

Erster funktionsfähiger Release mit unabhängiger Python-Bibliothek, FastAPI-API, PostgreSQL-/SQLite-Persistenz und React-Oberfläche.

- Inventarimport aus CycloneDX JSON und CSV.
- OSV-, CVE-Program-, NVD-, CISA-KEV- und öffentliche BSI-CSAF-Anbindung.
- Nachvollziehbare Paket-, CNA-, CPE- und CSAF-Bewertungen mit konservativen Grenzen.
- Alias-Zusammenführung, Quellenrevisionen, Findings und Entscheidungshistorie.
- Kontextbasierte Priorität, Bearbeitung, Suche, Filter und CSV-Export.
- Celery-/Redis-Jobs, Wiederholungsabgleich, Docker Compose, Caddy und API-Schlüssel.
- Fiktive Demo, Python-Tests, Browser-Workflows und automatisierte Zugänglichkeitsprüfung.
