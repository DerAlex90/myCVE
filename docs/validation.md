# Validierung von Version 0.2.0

Stand: 2. November 2026. Diese Prüfung beschreibt die hier tatsächlich ausgeführten Schritte; sie ersetzt keine kontinuierliche Betriebsüberwachung.

| Prüfung | Ergebnis |
| --- | --- |
| Python-Suite mit SQLite | 72 Tests bestanden; drei optionale PostgreSQL-Tests werden ohne Verbindungsvariable ausgelassen |
| PostgreSQL-Integration, separater Schema-Namensraum | 3 Tests bestanden: JSONB/Quellen, Scan-Lock-Lebenszyklus und Agentenberichte einschließlich Inventarabdeckung |
| Ruff, Formatierung und mypy | Bestanden |
| TypeScript und Vite-Produktionsbuild | Bestanden |
| Browser-Workflows mit Chromium | 5 Tests bestanden: Finding/Belege/Entscheidung/Export, System/Import/Beobachtung, Mobilansicht, automatisierte WCAG-AA-Prüfung der Übersicht sowie Agentenregistrierung/Konfiguration/Inventarempfang/Verlauf/Widerruf |
| Go-Agent | 14 Tests bestanden, zusätzlich Race Detector und `go vet`: Paketparser, SBOMs, TLS/Weiterleitungen, Bestätigungen, persistente Wiederholung und Prozesssperren |
| Agentenpakete | Linux und Windows für amd64 und arm64 erfolgreich gebaut; Installationsdateien, Lizenzen und SHA-256-Prüfsummen enthalten |
| Echter Linux-Datensender | 1.437 installierte Pakete über HTTP an isolierte SQLite- und PostgreSQL-Server gesendet; Wiederholung ohne Duplikate, Widerruf, Tokenwechsel, Gerätebindung und Verlauf geprüft |
| Windows-Dienst | Agent und Diensttest erfolgreich querkompiliert; Installation und SCM-Laufzeittest benötigen Windows und wurden hier nicht ausgeführt. Ein entsprechender Windows-CI-Job ist definiert |
| Datenbankmigration | Bestehende Inventardaten einer unversionierten 0.1-SQLite-Datenbank beim Upgrade erhalten; PostgreSQL-Upgrade im laufenden Compose-Stack erfolgreich |
| Docker-Image | Mehrstufig gebaut und mit unprivilegiertem Anwendungsnutzer gestartet |
| Docker Compose | PostgreSQL, Redis, API, Celery Worker, Beat und Caddy gestartet; API und Datenbank gesund |
| Echter Scan durch den Compose-Stack | Inventarimport → Redis/Celery → öffentliche Quellen → PostgreSQL → Findings und Verlauf erfolgreich |
| Live-Quellen | OSV-Batch und Details, CVE Program, NVD, CISA KEV und öffentliche BSI-CSAF-Daten erfolgreich verarbeitet |
| Python-Release | Wheel und Quelldistribution gebaut; unabhängiger Wheel-Import in frischer Umgebung ohne Server-Abhängigkeiten erfolgreich |
| Paketinhalt | Keine `.env`, Datenbanken, virtuellen Umgebungen oder `node_modules` enthalten |

Die CISA-Website antwortete aus dieser Laufzeit mit HTTP 403. Der in den Belegen ausgewiesene offizielle GitHub-Spiegel lieferte den vollständigen Katalog. Die BSI-ROLIE-Feeds überschritten das normale Dokumentlimit und wurden erfolgreich gestreamt; ein passendes öffentliches WHITE-Dokument wurde verarbeitet.

Der echte Stack-Scan verwendete eine ausdrücklich angelegte Testinstallation von `idna` 3.6. Alle fünf Quellenphasen wurden erfolgreich abgeschlossen. Testdatenbanken und Demo-Daten sind nicht Teil der Release-Dateien.

Die automatisierte Zugänglichkeitsprüfung betrifft die Übersicht und ersetzt keinen vollständigen manuellen Accessibility-Audit. HTTPS mit eigener öffentlicher Domain, Backups auf fremder Infrastruktur, OpenPGP-Verifikation und Inventare oberhalb des genannten Linux-Probelaufs wurden in dieser Laufzeit nicht als Produktionsbetrieb erprobt. Die Windows-Dateien sind nicht mit Authenticode signiert. Fachliche Grenzen sind in der README und unter `matching.md` beschrieben.
