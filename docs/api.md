# API verwenden

Alle `/api`-Routen außer `/api/config` benötigen im regulären Betrieb einen Bearer-Schlüssel. Die Konfiguration liefert nur Version, Demo-Kennzeichnung und ob eine Anmeldung erforderlich ist. Sie liefert keine Geheimnisse oder Inventardaten. Eine vollständige OpenAPI-Spezifikation ist authentifiziert unter `/api/openapi.json` abrufbar.

Ein vollständiges Beispiel aus dem Repository-Verzeichnis mit lokalem Server:

```python
import os
from pathlib import Path
import httpx

with httpx.Client(
    base_url="http://localhost:8080",
    headers={"Authorization": f"Bearer {os.environ['MYCVE_API_KEY']}"},
) as client:
    response = client.post("/api/assets", json={
        "name": "customer-api", "owner": "Platform",
        "environment": "production", "exposure": "internet", "criticality": "high",
    })
    response.raise_for_status()
    asset = response.json()
    with Path("fixtures/inventory.cdx.json").open("rb") as inventory:
        response = client.post(f"/api/assets/{asset['id']}/import", files={
            "file": ("inventory.cdx.json", inventory, "application/json"),
        })
        response.raise_for_status()
    job = client.post("/api/scans", json={"asset_id": asset["id"]})
    job.raise_for_status()
    print(job.json()["id"])
```

## Wesentliche Routen

| Methode / Pfad | Ergebnis |
| --- | --- |
| `GET /health` | Datenbank-Lebendprüfung, keine Anmeldung erforderlich |
| `GET /api/overview` | Aktuelle Zählwerte und letzter Scan |
| `GET, POST /api/assets` | Systeme auflisten / anlegen |
| `PUT /api/assets/{id}` | Systemkontext ändern und Findings neu priorisieren |
| `GET /api/assets/{id}/components` | Aktive Installationen; `limit`, `offset` |
| `POST /api/assets/{id}/import` | Multipart-Datei; `replace=true` standardmäßig |
| `POST /api/watches` | `installation_id` und `cve_id` zur gezielten Beobachtung |
| `GET /api/findings` | Filter: `search`, `status`, `priority`, `workflow`, `asset_id`, `limit`, `offset` |
| `GET /api/findings/{id}` | Matching, Quellenrevisionen und Änderungshistorie |
| `PATCH /api/findings/{id}` | `workflow` und `notes` ändern |
| `GET /api/findings/export.csv` | Alle Findings als CSV; Tabellenformeln werden neutralisiert |
| `GET /api/sources/{id}` | Gespeichertes Quellen-JSON und Prüfsumme |
| `GET, POST /api/scans` | Letzte 30 Jobs / neuen Abgleich vormerken |

Erwartete Fehler: `401` für einen fehlenden oder falschen Schlüssel, `404` für unbekannte Objekte, `409` für doppelte Systemnamen oder einen laufenden Scan, `413` für zu große Dateien und `422` für ungültige Eingaben. Ein nicht erreichbarer Hintergrunddienst ergibt `503` und einen nachvollziehbar fehlgeschlagenen Job.

Ein Scan führt in `result.sources` die Quellenzustände `ok`, `error`, `partial` und `skipped`. `skipped` bedeutet, dass kein passendes Inventar beziehungsweise keine zu aktualisierende Meldung für diese Quelle vorhanden war; es bestätigt keinen erfolgreichen Abruf. Bereits bekannte Meldungen werden auch ohne aktive Installationen erneut abgerufen.

Die API setzt keine übergreifende CORS-Freigabe und speichert keine Cookie-Sitzung. Der Browser hält den eingegebenen Schlüssel nur im `sessionStorage` des aktuellen Tabs. Die Instanz muss für den Netzbetrieb über HTTPS bereitgestellt werden.

## Risiken, Kontext und Abgleiche ab 0.5

`GET /api/findings` und `GET /api/findings/export.csv` verwenden dieselben Filter `search`, `status`, `priority`, `workflow`, `asset_id`, `component_type` und `patch_status`. `view=packages` ist für bestehende API-Clients der Standard; `view=risks` gruppiert nach interner Schwachstelle, Asset, Ökosystem, Quellpaket und Quellversion. Die Weboberfläche startet mit der Risikoansicht. Gruppierte Antworten enthalten `packages`, `package_count`, `risk_id` und den ursprünglichen Finding-Bezeichner für die Detailansicht. Komponententypen sind `runtime`, `development`, `unknown`; ein gemischtes Risiko kann als `mixed` angezeigt werden. Die ursprünglichen Paketnamen, Versionen und Architekturen bleiben erhalten.

Die Übersicht zählt in `open_findings`, `affected`, `unknown`, `kev` und `priorities` gruppierte Risiken. `package_findings` zählt die zugehörigen Pakettreffer. Die Zähler `component_types` können sich überlappen, wenn dasselbe Risiko beispielsweise ein Runtime- und ein Entwicklungspaket betrifft. `PATCH /api/findings/{id}?grouped=true` bearbeitet ausdrücklich alle Pakettreffer desselben Risikos und protokolliert jede Änderung. Ohne diesen Parameter bleibt die Bearbeitung auf das einzelne Finding beschränkt.

`patch_status` ist `available`, `unavailable` oder `unknown`. Eine leere Liste `fixed_versions` bedeutet keinen bestätigten Mangel an Patches. Der Kontext enthält `component_type`, `kernel_status`, `kernel_release` und `running_kernel`; ein Pakettreffer allein belegt keine Betroffenheit des laufenden Kernels.

Scanantworten enthalten laufend `progress` (Phase, bearbeitete Anzahl, Gesamtzahl soweit bekannt, Zeitpunkt), `heartbeat_at`, `cancel_requested` und gegebenenfalls `resume_of`. `POST /api/scans/{id}/cancel` fordert einen kooperativen Abbruch an. `POST /api/scans/{id}/resume` erstellt einen neuen Job mit Verweis auf den vorherigen und wiederverwendbaren Abrufen. Nur teilweise, fehlgeschlagene oder abgebrochene Jobs sind fortsetzbar. `POST /api/scans` mit `force_full=true` erzwingt neue Abrufe ohne Retry-Cache. Laufende oder vorgemerkte Jobs verhindern weitere gleichzeitige Starts mit `409`.

`GET /api/operations` liefert den geschützten Betriebsstatus für Datenbank, Redis/Queue, Worker und Scheduler sowie den letzten erfolgreichen und letzten aktuellen Abgleich. `GET /api/ready` verwendet dieselben Prüfungen und liefert bei Einschränkungen `503`, sonst `200`. `/health` bleibt die einfache Datenbank-/HTTP-Lebendprüfung. Auch die neuen Verwaltungsrouten verlangen den Workspace-Schlüssel.

## Öffentliche Lizenzhinweise

`GET /license` liefert den vollständigen eigenen Lizenztext als UTF-8-Klartext. `GET /api/license` liefert Autor, Copyright, Lizenzkennung, Projekt-URL und Text als JSON. Diese statischen Hinweise sind auch ohne Workspace-Schlüssel erreichbar; Inventar- und Verwaltungsrouten bleiben geschützt. Die Weboberfläche verlinkt sie aus ihrer sichtbaren Namensnennung.

`mycve license` zeigt denselben Text ohne Server-Abhängigkeiten. Agentenpakete enthalten LICENSE, NOTICE und ihre Drittanbieterhinweise; `mycve-agent license` zeigt die Namensnennung und den Verweis auf die vollständigen Bedingungen.

## Inventar-Agenten ab 0.2

Administrative Routen verwenden weiterhin den Workspace-Schlüssel:

| Methode / Pfad | Zweck |
| --- | --- |
| `GET /api/agents` | Gerät, Status, letzter Kontakt, Betriebssystem, Paketzahl, Erfassungsfehler und Abgleichslücken |
| `POST /api/agents` | `asset_id`; einmalige Antwort mit Agent und `configuration` inklusive neuem Geräteschlüssel |
| `POST /api/agents/{id}/rotate-token` | Alten Schlüssel ersetzen; optional `?reset_device=true` nach Geräte-Neuinstallation |
| `DELETE /api/agents/{id}` | Schlüssel sofort widerrufen; Daten und Berichte behalten |
| `GET /api/agents/{id}/snapshots` | Berichte mit Erfassungs-/Empfangszeit, Prüfsumme und Änderungszahlen; `limit`, `offset` |
| `GET /api/agents/{id}/snapshots/{snapshot}` | Normalisierter Bericht und Paketänderungen mit Vorher/Nachher |
| `GET /api/agents/downloads` | Verfügbare Linux-/Windows-Pakete und Größen |
| `GET /api/agents/downloads/{name}` | Authentifizierter Download eines bekannten Pakets oder `SHA256SUMS` |

**Nur** `POST /api/agent/inventory` verwendet den Geräteschlüssel. Der Agent sendet ihn als `Authorization: Bearer mycve_agent_…` sowie seine Registrierungs-ID als `X-MyCVE-Agent-ID`. Der Header muss, falls angegeben, zum Schlüssel gehören. Der Ziel-Asset wird aus der Registrierung bestimmt, nicht aus dem Bericht. Der Schlüssel darf keine der administrativen Routen nutzen.

Beispiel eines Berichts:

```json
{
  "schema_version": 1,
  "snapshot_id": "11111111-1111-4111-8111-111111111111",
  "device_id": "22222222-2222-4222-8222-222222222222",
  "collected_at": "2026-11-02T12:00:00Z",
  "agent_version": "0.3.0",
  "host": {"hostname": "example-host", "os": "linux", "architecture": "amd64"},
  "collectors": [{
    "id": "dpkg",
    "complete": true,
    "packages": [{
      "id": "example:amd64", "name": "example", "version": "1.0",
      "source_name": "example-source", "source_version": "1.0",
      "purl": "pkg:deb/debian/example-source@1.0?distro=debian-12"
    }]
  }]
}
```

`snapshot_id` bezeichnet einen unveränderlichen Bericht; identische Wiederholung ist idempotent. `device_id` bleibt im lokalen Zustandsverzeichnis erhalten und bindet den Schlüssel beim ersten Bericht. Fehlende oder unvollständige Collector-Abschnitte entfernen keine bestehenden Pakete. Ein vollständiger Abschnitt mit leerer Paketliste kann ausschließlich Pakete genau dieser Erfassungsquelle inaktiv setzen. `source_name`/`source_version` ermöglichen den Debian-Abgleich, während Binärname/-version im Inventar erhalten bleiben.

Die Antwort enthält dieselbe `snapshot_id`, `accepted`, `duplicate`, gegebenenfalls `stale`/`partial`, Änderungszahlen und den empfohlenen Berichtsabstand. Ältere Berichte können eine neuere Momentaufnahme nicht überschreiben. Eine Erfassungszeit mehr als zehn Minuten in der Zukunft ergibt `422`. Gerätetausch ohne explizite Neubindung und Berichts-ID mit verändertem Inhalt ergeben `409`. Zu viele neue Berichte ergeben `429` mit `Retry-After`; identische Wiederholungen bleiben möglich. Allgemeine Grenzen sind 10 MB, 10.000 Pakete und 20 Erfassungsquellen pro Bericht.
