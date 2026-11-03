# Validierung von Version 0.3.0

Stand: 3. November 2026. Die Feed- und Compose-Grundprüfung aus 0.2 bleibt dokumentiert; Produktzuordnung, Migrationen, Parser und Anwendung wurden für 0.3 erneut geprüft.

| Prüfung | Ergebnis |
| --- | --- |
| Python-Suite mit SQLite | 92 Tests; vier optionale PostgreSQL-Tests werden ohne Verbindungsvariable ausgelassen |
| PostgreSQL-Integration, separater Schema-Namensraum | 4 Tests: JSONB/Quellen, Scan-Lock-Lebenszyklus, Agentenberichte und automatische Produktzuordnung einschließlich JSONB-Abdeckungsabfragen |
| Ruff, Formatierung und mypy | Bestanden |
| TypeScript und Vite-Produktionsbuild | Bestanden |
| Browser-Workflows mit Chromium | 5 Tests bestanden: Finding/Belege/Entscheidung/Export, System/Import/Beobachtung, Mobilansicht, automatisierte WCAG-AA-Prüfung der Übersicht sowie Agentenregistrierung/Konfiguration/Inventarempfang/Verlauf/Widerruf |
| Go-Agent unter Linux | 17 Tests bestanden, zusätzlich Race Detector und `go vet`: Paketparser einschließlich Alpine-Quellpaketen, Versionsmetadaten, SBOMs, TLS/Weiterleitungen, Bestätigungen, persistente Wiederholung und Prozesssperren |
| Agentenpakete | Linux und Windows für amd64 und arm64 erfolgreich gebaut; Installationsdateien, Lizenzen und SHA-256-Prüfsummen enthalten |
| Echter Linux-Datensender | 1.437 installierte Pakete über HTTP an isolierte SQLite- und PostgreSQL-Server gesendet; Wiederholung ohne Duplikate, Widerruf, Tokenwechsel, Gerätebindung und Verlauf geprüft |
| Windows | Agent und native Collector-Tests querkompiliert. Registry-Versionsfallback, echte Dateiressourcen und der SCM-Diensttest laufen zusätzlich auf dem Windows-CI-Runner; der 0.2-Dienstlauf wurde bereits erfolgreich ausgeführt |
| Automatischer Gesamtprozess | Agentenbericht → Scheduler → automatischer Scan → Finding ohne manuell gestarteten Scan geprüft |
| Echter autonomer Compose-Test | Ein Windows-Bericht im 0.2-Format ohne PURL/CPE wurde mit separatem PostgreSQL-Schema, Celery Worker und Beat automatisch zugeordnet und bis zu 15 echten NVD-Findings verarbeitet; der Scan endete erfolgreich, ohne einen Scan-API-Aufruf |
| Synthetische Flotte | 685 vorhandene Installationen ohne PURL/CPE automatisch zugeordnet; dasselbe Produkt benötigt geräteübergreifend nur eine Katalogabfrage |
| Echter CPE-Katalog | Firefox, Chrome, 7-Zip und Python automatisch identifiziert; auch vollständige Kataloge mit 10.625 beziehungsweise 22.788 Einträgen verarbeitet |
| Echter NVD-Abgleich | Beispielversionen Firefox 128.0 und 7-Zip 24.09 aus den automatisch ermittelten Produktkennungen abgefragt; auswertbare und wegen zusätzlicher Bedingungen ungeklärte Konfigurationen bleiben getrennt |
| Datenbankmigration | Unversionierte 0.1- und 0.2-Inventare bleiben erhalten; bestehende Geräte werden automatisch erneut eingeplant |
| Docker-Image | Mehrstufig gebaut und mit unprivilegiertem Anwendungsnutzer gestartet |
| Docker Compose | PostgreSQL, Redis, API, Celery Worker, Beat und Caddy gestartet; API und Datenbank gesund |
| Echter Scan durch den Compose-Stack | Inventarimport → Redis/Celery → öffentliche Quellen → PostgreSQL → Findings und Verlauf erfolgreich |
| Live-Quellen | OSV-Batch und Details, CVE Program, NVD, CISA KEV und öffentliche BSI-CSAF-Daten erfolgreich verarbeitet |
| Python-Release | Wheel und Quelldistribution gebaut; unabhängiger Wheel-Import in frischer Umgebung ohne Server-Abhängigkeiten erfolgreich |
| Paketinhalt | Keine `.env`, Datenbanken, virtuellen Umgebungen oder `node_modules` enthalten |

Die CISA-Website antwortete aus dieser Laufzeit mit HTTP 403. Der in den Belegen ausgewiesene offizielle GitHub-Spiegel lieferte den vollständigen Katalog. Die BSI-ROLIE-Feeds überschritten das normale Dokumentlimit und wurden erfolgreich gestreamt; ein passendes öffentliches WHITE-Dokument wurde verarbeitet.

Der echte Stack-Scan verwendete eine ausdrücklich angelegte Testinstallation von `idna` 3.6. Alle fünf Quellenphasen wurden erfolgreich abgeschlossen. Testdatenbanken und Demo-Daten sind nicht Teil der Release-Dateien.

Die automatisierte Zugänglichkeitsprüfung betrifft die Übersicht und ersetzt keinen vollständigen manuellen Accessibility-Audit. HTTPS mit eigener öffentlicher Domain, Backups auf fremder Infrastruktur, OpenPGP-Verifikation und Inventare oberhalb des genannten Linux-Probelaufs wurden in dieser Laufzeit nicht als Produktionsbetrieb erprobt. Die Windows-Dateien sind nicht mit Authenticode signiert. Fachliche Grenzen sind in der README und unter `matching.md` beschrieben.
