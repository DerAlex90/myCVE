# Änderungen

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
