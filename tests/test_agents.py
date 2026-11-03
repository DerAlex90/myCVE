from datetime import timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from mycve.server.api import create_app
from mycve.server.config import Settings
from mycve.server.db import Agent, Installation, InventoryChange, InventorySnapshot, now, sessions


def provision(client, name="device"):
    asset = client.post("/api/assets", json={"name": name}).json()
    response = client.post("/api/agents", json={"asset_id": asset["id"]})
    assert response.status_code == 201
    data = response.json()
    headers = {
        "Authorization": "Bearer " + data["configuration"]["token"],
        "X-MyCVE-Agent-ID": data["agent"]["id"],
    }
    return asset, data, headers


def report(device_id=None, packages=None):
    return {
        "schema_version": 1,
        "snapshot_id": str(uuid4()),
        "device_id": device_id or str(uuid4()),
        "collected_at": now().isoformat(),
        "agent_version": "0.2.0",
        "host": {
            "hostname": "linux-test",
            "os": "linux",
            "architecture": "amd64",
            "distribution": "debian",
            "distribution_version": "12",
        },
        "collectors": [
            {
                "id": "dpkg",
                "complete": True,
                "packages": packages
                if packages is not None
                else [
                    {
                        "id": "example:amd64",
                        "name": "example",
                        "version": "1.0",
                        "ecosystem": "PyPI",
                    }
                ],
            }
        ],
    }


def send(client, headers, body):
    return client.post("/api/agent/inventory", headers=headers, json=body)


def test_agent_stores_system_packages_raw_history_and_only_token_hash(client, engine):
    asset, data, headers = provision(client)
    body = report()
    result = send(client, headers, body)
    assert result.status_code == 200 and result.json()["changes"] == {
        "added": 1,
        "updated": 0,
        "removed": 0,
    }
    agent = client.get("/api/agents").json()[0]
    assert agent["status"] == "online" and agent["host"]["hostname"] == "linux-test"
    assert agent["scan_pending"] and agent["packages"] == 1
    assert "token" not in agent and "token_hash" not in agent
    component = client.get(f"/api/assets/{asset['id']}/components").json()["items"][0]
    assert component["inventory"]["name"] == "example" and component["origin"].startswith("agent:")
    with sessions(engine)() as session:
        stored = session.scalar(select(Agent))
        assert stored.token_hash != data["configuration"]["token"] and len(stored.token_hash) == 64
    snapshots = client.get(f"/api/agents/{agent['id']}/snapshots").json()
    assert snapshots["total"] == 1
    detail = client.get(f"/api/agents/{agent['id']}/snapshots/{snapshots['items'][0]['id']}").json()
    assert detail["payload"]["host"] == body["host"]
    assert detail["changes"][0]["kind"] == "added"


def test_device_credentials_cannot_read_or_manage_workspace(engine):
    key = "administrator-test-key" * 3
    with TestClient(create_app(Settings(api_key=key, _env_file=None), engine)) as client:
        client.headers["Authorization"] = "Bearer " + key
        _, _, headers = provision(client)
        assert send(client, headers, report()).status_code == 200
        assert client.get("/api/assets", headers=headers).status_code == 401
        assert client.get("/api/agents", headers=headers).status_code == 401
        assert client.post("/api/scans", headers=headers, json={}).status_code == 401
        assert send(client, {"Authorization": "Bearer " + key}, report()).status_code == 401


def test_replay_is_idempotent_and_mutated_report_id_is_rejected(client, engine):
    _, _, headers = provision(client)
    body = report()
    assert send(client, headers, body).status_code == 200
    assert send(client, headers, body).json()["duplicate"]
    body["collectors"][0]["packages"][0]["version"] = "2.0"
    assert send(client, headers, body).status_code == 409
    with sessions(engine)() as session:
        assert session.scalar(select(func.count()).select_from(InventorySnapshot)) == 1
        assert session.scalar(select(func.count()).select_from(InventoryChange)) == 1


def test_version_change_removal_and_return_keep_stable_installation(client, engine):
    _, _, headers = provision(client)
    body = report()
    send(client, headers, body)
    body["snapshot_id"], body["collected_at"] = str(uuid4()), now().isoformat()
    body["collectors"][0]["packages"][0]["version"] = "2.0"
    assert send(client, headers, body).json()["changes"]["updated"] == 1
    empty = report(body["device_id"], [])
    assert send(client, headers, empty).json()["changes"]["removed"] == 1
    returned = report(body["device_id"])
    assert send(client, headers, returned).json()["changes"]["added"] == 1
    with sessions(engine)() as session:
        assert session.scalar(select(func.count()).select_from(Installation)) == 1
        assert session.scalar(select(Installation)).active


def test_partial_and_missing_collectors_never_remove_previous_inventory(client, engine):
    _, _, headers = provision(client)
    body = report()
    send(client, headers, body)
    partial = report(body["device_id"], [])
    partial["collectors"][0].update(complete=False, error="package database unavailable")
    assert send(client, headers, partial).json()["partial"]
    other = report(body["device_id"], [])
    other["collectors"][0]["id"] = "sbom:other"
    assert send(client, headers, other).json()["partial"]
    with sessions(engine)() as session:
        assert session.scalar(select(Installation)).active
        assert session.scalar(select(Agent)).last_error


def test_out_of_order_reports_cannot_overwrite_current_inventory(client):
    _, _, headers = provision(client)
    current = report()
    send(client, headers, current)
    stale = report(current["device_id"], [])
    stale["collected_at"] = (now() - timedelta(days=1)).isoformat()
    response = send(client, headers, stale)
    assert response.status_code == 200 and response.json()["stale"]
    assert client.get("/api/agents").json()[0]["packages"] == 1


def test_binding_rotation_and_revocation(client):
    _, data, headers = provision(client)
    original = report()
    send(client, headers, original)
    assert send(client, headers, report()).status_code == 409
    rotated = client.post(f"/api/agents/{data['agent']['id']}/rotate-token").json()
    new_headers = {"Authorization": "Bearer " + rotated["configuration"]["token"]}
    assert send(client, headers, original).status_code == 401
    assert send(client, new_headers, report(original["device_id"])).status_code == 200
    client.delete(f"/api/agents/{data['agent']['id']}")
    assert send(client, new_headers, report(original["device_id"])).status_code == 401
    assert client.get("/api/agents").json()[0]["status"] == "revoked"
    reset = client.post(f"/api/agents/{data['agent']['id']}/rotate-token?reset_device=true").json()
    assert (
        send(
            client, {"Authorization": "Bearer " + reset["configuration"]["token"]}, report()
        ).status_code
        == 200
    )


def test_invalid_report_is_atomic_and_future_clock_is_rejected(client, engine):
    _, _, headers = provision(client)
    body = report()
    body["collectors"][0]["packages"].append(
        {"id": "invalid", "name": "bad", "version": "2.0", "purl": "pkg:pypi/bad@1.0"}
    )
    assert send(client, headers, body).status_code == 422
    body = report()
    body["collected_at"] = (now() + timedelta(hours=1)).isoformat()
    assert send(client, headers, body).status_code == 422
    body = report()
    body["collectors"][0]["packages"] *= 2
    assert send(client, headers, body).status_code == 422
    with sessions(engine)() as session:
        assert session.scalar(select(func.count()).select_from(InventorySnapshot)) == 0
        assert session.scalar(select(func.count()).select_from(Installation)) == 0


def test_manual_and_agent_inventories_do_not_remove_each_other(client):
    asset, _, headers = provision(client)
    body = report()
    send(client, headers, body)
    url = f"/api/assets/{asset['id']}/import"
    client.post(
        url, files={"file": ("inventory.csv", b"name,version,ecosystem\nmanual,1.0,PyPI\n")}
    )
    assert client.get(f"/api/assets/{asset['id']}/components").json()["total"] == 2
    send(client, headers, report(body["device_id"], []))
    current = client.get(f"/api/assets/{asset['id']}/components").json()
    assert current["total"] == 1 and current["items"][0]["name"] == "manual"


def test_debian_binary_inventory_maps_to_source_package_for_osv(client):
    asset, _, headers = provision(client)
    body = report(
        packages=[
            {
                "id": "libbinary:amd64",
                "name": "libbinary",
                "version": "1.0+b1",
                "source_name": "source-package",
                "source_version": "1.0",
                "ecosystem": "Debian:12",
                "purl": "pkg:deb/debian/source-package@1.0?distro=debian-12",
            }
        ]
    )
    assert send(client, headers, body).status_code == 200
    item = client.get(f"/api/assets/{asset['id']}/components").json()["items"][0]
    assert item["name"] == "source-package" and item["version"] == "1.0"
    assert item["inventory"]["name"] == "libbinary" and item["inventory"]["version"] == "1.0+b1"


def test_registration_and_download_boundaries(client):
    asset, data, headers = provision(client)
    assert client.post("/api/agents", json={"asset_id": asset["id"]}).status_code == 409
    assert client.post("/api/agents", json={"asset_id": str(uuid4())}).status_code == 404
    wrong = {**headers, "X-MyCVE-Agent-ID": str(uuid4())}
    assert send(client, wrong, report()).status_code == 401
    assert client.get("/api/agents/downloads/secret.env").status_code == 404
    assert client.get(f"/api/agents/{data['agent']['id']}/snapshots/missing").status_code == 404


def test_report_rate_limit_allows_idempotent_retries(client):
    client.app.state.settings.agent_max_snapshots_per_minute = 2
    _, _, headers = provision(client)
    first = report()
    assert send(client, headers, first).status_code == 200
    assert send(client, headers, report(first["device_id"])).status_code == 200
    rejected = send(client, headers, report(first["device_id"]))
    assert rejected.status_code == 429 and rejected.headers["retry-after"] == "60"
    assert send(client, headers, first).json()["duplicate"]


def test_inventory_without_identifiers_remains_visibly_incomplete(client):
    _, _, headers = provision(client)
    body = report(
        packages=[{"id": "windows:example", "name": "Example Windows App", "version": "1.0"}]
    )
    assert send(client, headers, body).status_code == 200
    assert client.get("/api/agents").json()[0]["incomplete_packages"] == 1
    assert client.get("/api/overview").json()["incomplete_components"] == 1
