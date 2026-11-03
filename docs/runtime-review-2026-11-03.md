# Prüfung der laufenden Instanz

Stand: 3. November 2026, Europe/Berlin. Geprüft wurde die hier laufende Compose-Instanz unter `http://localhost:8080`, ausgehend von Release 0.4.0. Die ergänzenden Korrekturen werden getrennt vom bereits veröffentlichten Release zur Prüfung bereitgestellt.

## Laufzeitbefund

- PostgreSQL, Redis, API, Worker, Beat und Caddy laufen. Datenbankprüfung, Celery-Ping und regelmäßige Scheduler-Aufrufe funktionieren; die Celery-Warteschlange war leer.
- Die geschützten Verwaltungsrouten liefern ohne Schlüssel `401`. Ungültige Seitenparameter ergeben `422`, unbekannte Datensätze `404`. Bei den gezielten API-Aufrufen traten keine Serverfehler auf. Die Antwortzeiten der geprüften Lesezugriffe lagen im leeren Inventar zwischen ungefähr 2 und 53 ms.
- Zwei ältere Scans waren wegen Verbindungszeitüberschreitungen zu CISA und BSI unvollständig. Direkte Abrufe aus dem API-Container zu OSV, CVE Program, NVD, CISA KEV und den öffentlichen BSI-Metadaten funktionieren inzwischen. Ein neuer Scan über API, Redis und Worker wurde erfolgreich ohne Quellenfehler abgeschlossen.
- In der geprüften Instanz sind **keine Systeme und keine Agenten registriert**. Ein erfolgreich abgeschlossener leerer Scan sagt nichts über die Betroffenheit echter Geräte aus. Die OSV-Verbindungsprobe verwendete ein ausdrücklich gewähltes öffentliches Beispielpaket.
- Alle sechs Oberflächenbereiche lassen sich öffnen. In den geprüften Ansichten traten keine JavaScript-Fehler auf. Die Mobilansicht bei 390 px Breite hatte keinen horizontalen Überlauf.

## Bestätigte und korrigierte Probleme

| Problem | Vorher | Korrektur und Prüfung |
| --- | --- | --- |
| Hintergrundänderungen bleiben unsichtbar | Ohne bereits laufenden Scan erfolgte selbst nach 31 Sekunden keine neue Übersichtsabfrage. Agentenberichte oder extern gestartete Scans erschienen erst nach Benutzereingriff. | Sichtbare Seiten aktualisieren sich alle 15 Sekunden, bei laufenden Scans alle 4 Sekunden sowie beim erneuten Aktivieren des Tabs. Automatische Übersichtsabrufe überlappen sich nicht und pausieren bei verstecktem Tab. Browserprüfung für neue Daten und Wiederverbindung nach einem Fehler. |
| Nicht abgefragte Quelle erscheint erfolgreich | OSV erhielt bei leerem Inventar `ok`, obwohl keine Paketabfrage nötig war. | Nicht benötigte OSV-, CVE- und NVD-Abfragen erhalten `skipped`. Die Oberfläche zeigt „Kein passender Abgleich nötig“. Bekannte Meldungen werden weiterhin auch ohne aktive Installationen aktualisiert; beide Fälle sind durch Scannerprüfungen abgedeckt. |
| Zu schwache Textkontraste | Acht Kontrastverletzungen: ein Copyright-Link auf der Anmeldung, fünf Downloadgrößen und zwei Quellenlogos. | Farben mit mehr Kontrast. Automatisierte WCAG-AA-Prüfungen umfassen nun Anmeldung und alle sechs Workspace-Bereiche einschließlich der Downloadliste. |

Fehler beim automatischen Abruf und Fehler einer Benutzeraktion werden getrennt geführt. Nach erfolgreicher Wiederverbindung verschwindet die Verbindungsfehlermeldung, während eine fehlgeschlagene Benutzeraktion sichtbar bleibt.

## Weitere Verbesserungen nach Priorität

1. **Speicher und Aufbewahrung überwachen.** Zu Beginn war der Buildhost zu 90 % belegt; rund 3,1 GB waren frei. Docker-Builds mit dem hier verwendeten VFS-Treiber benötigen zusätzliche Kopien. Builds und langfristig aufbewahrte Inventar-/Quellenrevisionen brauchen getrennte Speicherplanung, Warnschwellen und regelmäßig geprüfte Backups. Das ist eine Beobachtung dieses Buildhosts; sein leeres Inventar liefert keinen Maßstab für den Speicherbedarf einer Geräteflotte.
2. **Redis-Hostkonfiguration prüfen.** Redis meldet `vm.overcommit_memory=0`. Der Betreiber sollte den dokumentierten Redis-Empfehlungen entsprechend `vm.overcommit_memory=1` auf dem zuständigen Linux-Host vorsehen. Beim Prüfen wurden keine globalen Kernelparameter geändert. Die vorhandenen Persistenzläufe funktionieren; die Warnung betrifft die Reserve für Hintergrundspeicherungen unter Speicherdruck.
3. **Systemliste mit Sammelabfragen laden.** Ein isolierter Versuch mit 500 leeren Systemen erzeugte für `GET /api/assets` 1.001 SQL-Anweisungen und dauerte etwa 248 ms auf SQLite im Speicher. Die beiden Zählabfragen je System sollten durch gruppierte Abfragen ersetzt und größere Listen paginiert werden. PostgreSQL mit Netzwerklatenz wurde für diesen Lastfall nicht gemessen.
4. **Betriebsüberwachung vervollständigen.** `/health` bestätigt derzeit die Datenbankverbindung. Worker-Erreichbarkeit, Queue-Länge, Beat-Aktivität, Quellenfehler und das Alter des letzten erfolgreichen Scans sollten gemeinsam überwacht werden. Eine grüne HTTP-Prüfung allein bestätigt keinen aktuellen Schwachstellenabgleich.

## Grenzen der Prüfung

Dies ist eine gezielte Betriebs-, API- und Browserprüfung. Die automatisierte Zugänglichkeitsprüfung ersetzt keinen vollständigen manuellen Audit. Echte Windows-Geräte, eine größere produktive Flotte, öffentliches HTTPS mit eigener Domain und die Wiederherstellung auf fremder Infrastruktur wurden in dieser Prüfung nicht ausgeführt. Die bestehenden fachlichen und Plattformprüfungen stehen unter [Validierung](validation.md).

## Prüfung der Korrekturen

Ruff einschließlich Formatprüfung, mypy und der TypeScript-/Vite-Build sind bestanden. Die lokale Python-Suite besteht mit 95 Fällen; vier PostgreSQL-Integrationstests werden ohne deren separate Testverbindung ausgelassen und laufen zusätzlich in GitHub CI. Alle acht Browserfälle bestehen, einschließlich der Prüfung aller Workspace-Seiten, der Anmeldung und der Wiederverbindung. Der vollständige Docker-Build ist erfolgreich.

Vor dem lokalen Update wurde ein PostgreSQL-Backup erstellt. Das ursprüngliche 0.4.0-Image bleibt für einen Rückwechsel verfügbar; das bereits veröffentlichte Release wird nicht überschrieben. Die Änderungen benötigen keine Datenbankmigration und ändern das Agentenprotokoll nicht.
