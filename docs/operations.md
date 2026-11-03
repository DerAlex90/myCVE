# Betrieb

## Konfiguration

`scripts/configure.py` erzeugt `.env` aus `.env.example`. Das Skript überschreibt keine vorhandene Datei. PostgreSQL-Passwort und API-Schlüssel müssen vertraulich bleiben; die Datei wird weder von Git noch vom Docker-Build übernommen.

| Variable | Standard / Bedeutung |
| --- | --- |
| `MYCVE_API_KEY` | Erforderlicher Bearer-Schlüssel im Compose-Betrieb |
| `POSTGRES_PASSWORD` | Zufällig erzeugtes Datenbankpasswort |
| `MYCVE_NVD_API_KEY` | Optionaler eigener NVD-API-Schlüssel |
| `MYCVE_SYNC_INTERVAL_HOURS` | 6; regelmäßiger vollständiger Abgleich |
| `MYCVE_BSI_MAX_DOCUMENTS` | 50; relevante CSAF-Dokumente pro Scan, Limit wird als Teilfehler sichtbar |
| `MYCVE_AGENT_REPORT_INTERVAL_SECONDS` | 21600; Intervall für neu heruntergeladene Gerätekonfigurationen |
| `MYCVE_AGENT_STALE_HOURS` | 24; Kontakt nach dieser Zeit als überfällig markieren |
| `MYCVE_AGENT_MAX_SNAPSHOTS_PER_MINUTE` | 10; neue Berichte je Gerät und Minute, identische Wiederholungen ausgenommen |
| `MYCVE_IDENTIFICATION_MAX_QUERIES` | 50; neue Produktsuchen pro Durchlauf, Fortsetzung und erneute Versuche erfolgen automatisch |
| `MYCVE_SITE_ADDRESS` | `http://localhost` |
| `MYCVE_BIND_ADDRESS` | `127.0.0.1` |
| `MYCVE_HTTP_PORT` | 8080 |
| `MYCVE_HTTPS_PORT` | 8443 |

Für native Installationen zusätzlich: `MYCVE_DATABASE_URL`, `MYCVE_REDIS_URL`, `MYCVE_FRONTEND_DIR`, `MYCVE_TASK_MODE`, `MYCVE_FEED_TIMEOUT` und `MYCVE_MAX_UPLOAD_BYTES`. Die lokale Standarddatenbank ist SQLite; im Compose-Betrieb setzt die Konfiguration PostgreSQL.

## HTTPS und Domain

Für einen eigenen Server mit DNS-Eintrag diese Werte in `.env` setzen:

```dotenv
MYCVE_SITE_ADDRESS=cve.example.org
MYCVE_BIND_ADDRESS=0.0.0.0
MYCVE_HTTP_PORT=80
MYCVE_HTTPS_PORT=443
```

Anschließend `docker compose up -d`. Caddy beantragt Zertifikate, wenn Domain und Ports erreichbar sind. Das Konto-Modell des ersten Releases ist ein gemeinsamer Workspace mit einem API-Schlüssel. Mehrere unabhängig berechtigte Nutzer und Mandanten sind nicht vorgesehen.

## Dienste und Diagnose

```bash
docker compose ps
docker compose logs --tail=100 api worker beat
docker compose exec api mycve sync
```

API und manuelle CLI-Abgleiche verwenden denselben Datenbank-Lock. Celery Beat plant standardmäßig alle sechs Stunden einen neuen Scan. Die API liefert sofort eine Job-ID; Fortschritte erscheinen unter Aktivität. Ein NVD-Abgleich kann ohne eigenen Schlüssel länger dauern. Unvollständige Abrufe sind als `partial` sichtbar.

`/health` prüft die Datenbankverbindung. Für die Betriebsüberwachung zusätzlich Worker, Redis, Beat und den letzten erfolgreichen Scan prüfen; eine gesunde API allein bestätigt keine erfolgreichen Feed-Abrufe. Die API- und Job-Fehler enthalten keine Schlüsselwerte.

## Migrationen und Updates

Der API-Entrypoint führt vor dem Start `alembic upgrade head` aus. Worker und Beat starten erst nach der API-Lebendprüfung. Vor Updates ein Backup erstellen, dann:

```bash
docker compose build
docker compose up -d
docker compose ps
```

Native Installationen führen Migrationen aus dem Repository-Verzeichnis aus: `alembic upgrade head`. Keine parallelen manuellen Migrationen starten.

## Inventar-Agenten betreiben

Unter **Inventar-Agenten** zunächst jedes Gerät einem System zuordnen, seine einmalige Konfiguration sichern und das passende Linux- oder Windows-Paket herunterladen. Der Geräte-Schlüssel erlaubt ausschließlich Inventarmeldungen dieses Systems. Den administrativen API-Schlüssel nicht auf Endgeräten hinterlegen. Installationsbefehle und die erfassten Paketquellen stehen in [der Agentenanleitung](../agent/README.md).

Für Agentenupdates das neue Paket mit der vorhandenen Konfiguration installieren; die Installer erhalten das Zustandsverzeichnis und damit die Geräte-ID. Nach einer Neuinstallation mit verlorener Geräte-ID den Schlüssel im Server ausdrücklich mit zurückgesetzter Gerätebindung erneuern. Ein widerrufener Agent kann keine Berichte mehr senden.

Der Standardabstand beträgt sechs Stunden. Nicht bestätigte Berichte bleiben auf dem Gerät gespeichert und werden erneut gesendet. Fehlgeschlagene Paketquellen bleiben als unvollständig sichtbar; ihr bisheriges Inventar wird erhalten. Nach Inventaränderungen plant Beat einen erneuten Abgleich, während weitere Änderungen desselben Zeitfensters gesammelt werden. Deshalb zusätzlich auf ausstehende Prüfungen und Collector-Fehler achten.

Ab 0.3 erfolgt die Produktzuordnung automatisch auch für vorhandene Geräte. Das Datenbankupgrade merkt deren Inventar erneut vor; neue Berichte oder manuelle Kennungen sind dafür nicht nötig. Zuerst den Server aktualisieren, anschließend Agent 0.3 auf Geräten installieren, auf denen die zusätzlichen Windows-Versionsquellen benötigt werden. Konfiguration und Geräteidentität bleiben erhalten. Die Zuordnung funktioniert bereits für von Agent 0.2 gespeicherte Hersteller-/Produkt-/Versionsdaten.

Ohne NVD-Schlüssel begrenzt der Server Abfragen auf das öffentliche NVD-Limit. Ein großes erstes Inventar benötigt deshalb mehrere automatische Durchläufe. Der Status unterscheidet ausstehende, zugeordnete, mehrdeutige, nicht zuordenbare und versionslose Einträge sowie Abruffehler. Nach Abschluss eines Berichts sind weder Inventarimporte noch ein Klick auf „Jetzt abgleichen“ erforderlich.

## Backup und Wiederherstellung

```bash
mkdir -p backups
docker compose exec -T postgres pg_dump -U mycve -d mycve -Fc > backups/mycve.dump
```

Zusätzlich `.env` geschützt und separat sichern. Für vollständige Betriebswiederherstellung auch Caddy-Zertifikatsdaten sichern. Redis und Beat halten Queue-/Planungszustand; die fachlichen Daten und die Historie liegen in PostgreSQL.

Eine Wiederherstellung erfolgt in eine bereitgestellte leere Datenbank bei gestoppter API, Worker und Beat:

```bash
docker compose stop api worker beat
docker compose exec -T postgres pg_restore -U mycve -d mycve --no-owner < backups/mycve.dump
docker compose up -d
```

Vor einer Wiederherstellung in eine bereits befüllte Datenbank ist ein eigener, bewusst geplanter Austausch nötig. Das Beispiel löscht keine vorhandenen Tabellen. Backups regelmäßig in einer separaten Installation auf Wiederherstellbarkeit prüfen.

## Netzwerk und Vertrauen

Ausgehende HTTPS-Verbindungen benötigen `api.osv.dev`, `services.nvd.nist.gov`, `www.cisa.gov`, `raw.githubusercontent.com` und `wid.cert-bund.de`. Der KEV-Fallback verwendet ausschließlich das offizielle Repository `cisagov/kev-data`. Feed-Weiterleitungen werden nicht automatisch verfolgt. BSI-Dokumente müssen unter dem öffentlichen WHITE-Pfad des bekannten Providers liegen.

In Unternehmensnetzen vorhandene HTTP(S)-Proxys und CA-Vertrauen verwenden. Der Dockerfile unterstützt optional das BuildKit-Secret `proxy_ca`; Laufzeit-CAs als schreibgeschützte Datei mit `SSL_CERT_FILE` einbinden. Zertifikatsprüfung nicht abschalten. Sitzungsgebundene Proxy-Zertifikate gehören nicht in Image-Layer oder ins Repository.

## Grenzen und Aufbewahrung

Quellenrevisionen, Finding-Ereignisse und vollständige Agentenberichte einschließlich Änderungen werden für Nachvollziehbarkeit unbegrenzt aufgehoben. Bei sechs Stunden Meldeabstand entstehen vier Berichte je Gerät und Tag, auch bei unverändertem Inventar. Für große Installationen ist eine eigene Aufbewahrungs- und Speicherplanung nötig. Die unterstützten Importgrenzen sind 10 MB und 10.000 Komponenten; Feed-Dokumente maximal 32 MB, gestreamte ROLIE-Feeds maximal 512 MB. Die fachliche Auswertung komplexer CPE-Umgebungslogik bleibt bewusst ungeklärt.
