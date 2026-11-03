import csv
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_services import setup_finding

from mycve.server.api import create_app
from mycve.server.config import Settings
from mycve.server.db import Installation, sessions


def asset(client, name="api"):
    result = client.post(
        "/api/assets", json={"name": name, "exposure": "internet", "criticality": "high"}
    )
    assert result.status_code == 201, result.text
    return result.json()


def test_authentication_and_secure_default(engine):
    with pytest.raises(RuntimeError, match="MYCVE_API_KEY"):
        with TestClient(
            create_app(Settings(api_key="", allow_unauthenticated=False, _env_file=None), engine)
        ):
            pass
    key = "test-key-" * 8
    with TestClient(create_app(Settings(api_key=key, _env_file=None), engine)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/config").json()["authentication_required"]
        assert client.get("/api/assets").status_code == 401
        assert (
            client.get("/api/assets", headers={"Authorization": f"Bearer {key}"}).status_code == 200
        )
        assert client.get("/api/sources/any").status_code == 401
        assert client.get("/api/openapi.json").status_code == 401


def test_asset_import_is_atomic_and_deduplicated(client, engine):
    target = asset(client)
    assert client.post("/api/assets", json={"name": "api"}).status_code == 409
    url = f"/api/assets/{target['id']}/import"
    result = client.post(
        url,
        files={
            "file": (
                "inventory.csv",
                b"name,version,ecosystem\nexample-http,2.4.1,PyPI\nexample-http,2.4.1,PyPI\n",
                "text/csv",
            )
        },
    )
    assert result.status_code == 200 and result.json()["imported"] == 1
    broken = client.post(
        url,
        files={
            "file": (
                "inventory.csv",
                b"name,version,purl\nvalid,1.0,\ninvalid,2.0,pkg:pypi/invalid@1.0\n",
                "text/csv",
            )
        },
    )
    assert broken.status_code == 422
    with sessions(engine)() as session:
        assert session.scalar(select(func.count()).select_from(Installation)) == 1
    result = client.get(f"/api/assets/{target['id']}/components").json()
    assert result["total"] == 1 and result["items"][0]["version"] == "2.4.1"


def test_watch_and_workflow_preserve_affectedness(client, engine, advisory):
    with sessions(engine)() as session:
        _, installation, _, finding = setup_finding(session, advisory)
        finding_id, installation_id = finding.id, installation.id
    response = client.post(
        "/api/watches", json={"installation_id": installation_id, "cve_id": "CVE-2024-12345"}
    )
    assert response.status_code == 201 and response.json()["finding_id"] == finding_id
    result = client.patch(
        f"/api/findings/{finding_id}",
        json={"workflow": "in_progress", "notes": "Wartungsfenster geplant"},
    )
    assert result.status_code == 200
    detail = client.get(f"/api/findings/{finding_id}").json()
    assert detail["workflow"] == "in_progress" and detail["status"] == "affected"
    assert detail["history"][0]["action"] == "workflow_updated"
    assert (
        client.patch(
            f"/api/findings/{finding_id}", json={"workflow": "resolved", "status": "not_affected"}
        ).status_code
        == 422
    )
    source = client.get(f"/api/sources/{detail['sources'][0]['id']}").json()
    assert source["payload"] == advisory and len(source["checksum"]) == 64


def test_filter_pagination_overview_and_export(client, engine, advisory):
    with sessions(engine)() as session:
        target, _, _, _ = setup_finding(session, advisory)
        target.name = "=2+3"
        session.commit()
    assert client.get("/api/findings?status=affected&limit=1").json()["total"] == 1
    assert client.get("/api/findings?offset=1").json()["items"] == []
    assert client.get("/api/findings?search=%25").json()["total"] == 0
    assert client.get("/api/findings?search=CVE-2024").json()["total"] == 1
    assert client.get("/api/findings?search=GHSA-test").json()["total"] == 1
    assert client.get("/api/overview").json()["affected"] == 1
    result = client.get("/api/findings/export.csv")
    rows = list(csv.reader(io.StringIO(result.text.lstrip("\ufeff"))))
    assert rows[1][1] == "'=2+3"
    assert result.headers["cache-control"] == "no-store"


def test_errors_and_limits(client):
    assert client.get("/api/unknown-route").status_code == 404
    assert client.get("/api/findings/absent").status_code == 404
    assert client.get("/api/assets/absent/components").status_code == 404
    assert client.get("/api/findings?limit=1000").status_code == 422
    assert (
        client.post("/api/assets", json={"name": "x", "criticality": "arbitrary"}).status_code
        == 422
    )
    assert client.post("/api/scans", json={"asset_id": "missing"}).status_code == 404


def test_context_change_reprioritizes(client, engine, advisory):
    with sessions(engine)() as session:
        target, _, vulnerability, finding = setup_finding(session, advisory)
        vulnerability.kev = True
        session.commit()
        target_id, finding_id = target.id, finding.id
    result = client.put(
        f"/api/assets/{target_id}",
        json={"name": "production-api", "exposure": "internet", "criticality": "high"},
    )
    assert result.status_code == 200
    assert client.get(f"/api/findings/{finding_id}").json()["priority"] == "P0"
