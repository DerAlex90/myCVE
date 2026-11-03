import csv
import io
from copy import deepcopy

from sqlalchemy import select
from test_agents import provision, report, send
from test_scanner import FixtureFeeds, run

from mycve.core.csaf import match_csaf
from mycve.core.models import Component
from mycve.server.db import Agent, Finding, Installation, sessions
from mycve.server.risks import group_findings


def kernel_inventory(client, engine, advisory):
    asset, _, headers = provision(client)
    client.put(
        f"/api/assets/{asset['id']}",
        json={"name": "kernel-context", "exposure": "internet", "criticality": "high"},
    )
    body = report(
        packages=[
            {
                "id": "libc-headers",
                "name": "linux-libc-dev",
                "version": "6.1.150-1",
                "source_name": "linux",
                "source_version": "6.1.150-1",
                "ecosystem": "Debian:12",
            },
            {
                "id": "running-image",
                "name": "linux-image-6.1.0-30-amd64",
                "version": "6.1.150-1",
                "source_name": "linux",
                "source_version": "6.1.150-1",
                "ecosystem": "Debian:12",
            },
        ]
    )
    body["host"]["kernel"] = "6.1.0-30-amd64"
    assert send(client, headers, body).status_code == 200
    fixture = deepcopy(advisory)
    fixture["affected"] = [
        {"package": {"ecosystem": "Debian:12", "name": "linux"}, "versions": ["6.1.150-1"]}
    ]
    assert run(sessions(engine), FixtureFeeds(fixture)).status == "succeeded"
    return asset, headers, body


def test_headers_do_not_prove_a_running_kernel_risk(client, engine, advisory):
    kernel_inventory(client, engine, advisory)
    items = client.get("/api/findings?view=packages").json()["items"]
    by_name = {item["package"]["name"]: item for item in items}
    headers = by_name["linux-libc-dev"]
    image = by_name["linux-image-6.1.0-30-amd64"]
    assert headers["status"] == "affected"
    assert headers["context"]["component_type"] == "development"
    assert headers["context"]["kernel_status"] == "development"
    assert headers["priority"] == "P2"
    assert image["context"]["kernel_status"] == "running"
    assert image["priority"] == "P0"
    risks = client.get("/api/findings?view=risks").json()
    assert risks["total"] == 1 and risks["items"][0]["package_count"] == 2
    overview = client.get("/api/overview").json()
    assert overview["open_findings"] == 1 and overview["package_findings"] == 2
    assert client.get("/api/assets").json()[0]["open_findings"] == 1
    development = client.get("/api/findings?view=risks&component_type=development").json()
    assert development["total"] == 1 and development["items"][0]["package_count"] == 1


def test_filtered_exports_and_explicit_group_workflow_keep_all_binary_details(
    client, engine, advisory
):
    kernel_inventory(client, engine, advisory)
    for view, count in [("risks", 1), ("packages", 2)]:
        response = client.get(f"/api/findings/export.csv?view={view}&status=affected")
        assert len(list(csv.reader(io.StringIO(response.text.lstrip("\ufeff"))))) == count + 1
        empty = client.get(f"/api/findings/export.csv?view={view}&search=no-such-finding")
        assert len(list(csv.reader(io.StringIO(empty.text.lstrip("\ufeff"))))) == 1
    item = client.get("/api/findings?view=risks").json()["items"][0]
    changed = client.patch(
        f"/api/findings/{item['id']}?grouped=true",
        json={"workflow": "in_progress", "notes": "Common source package"},
    )
    assert changed.status_code == 200 and changed.json()["updated"] == 2
    with sessions(engine)() as session:
        assert {row.workflow for row in session.scalars(select(Finding))} == {"in_progress"}


def test_changed_running_kernel_reassesses_unchanged_inventory(client, engine, advisory):
    _, headers, body = kernel_inventory(client, engine, advisory)
    from uuid import uuid4

    from mycve.server.db import now

    with sessions(engine)() as session:
        session.scalar(select(Agent)).scan_pending = False
        session.commit()
    body["snapshot_id"] = str(uuid4())
    body["collected_at"] = now().isoformat()
    body["host"]["kernel"] = "6.1.0-31-amd64"
    assert send(client, headers, body).status_code == 200
    with sessions(engine)() as session:
        assert session.scalar(select(Agent)).scan_pending
        image = next(
            item
            for item in session.scalars(select(Installation))
            if item.inventory["id"] == "running-image"
        )
        assert image.context["kernel_status"] == "installed"
        assert (
            session.scalar(select(Finding).where(Finding.installation_id == image.id)).priority
            == "P2"
        )


def test_empty_fixed_versions_mean_unknown_and_csaf_requires_exact_products(
    client, engine, advisory
):
    kernel_inventory(client, engine, advisory)
    assert all(
        item["patch_status"] == "unknown" for item in client.get("/api/findings").json()["items"]
    )
    component = Component(name="example", purl="pkg:pypi/example@1.0")
    document = {
        "product_tree": {
            "full_product_names": [
                {"product_id": "exact", "product_identification_helper": {"purl": component.purl}}
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2024-12345",
                "product_status": {"known_affected": ["exact"]},
                "remediations": [{"category": "no_fix_planned", "product_ids": ["other"]}],
            }
        ],
    }
    assert match_csaf(component, document, {"CVE-2024-12345"}).patch_status == "unknown"
    document["vulnerabilities"][0]["remediations"][0]["product_ids"] = ["exact"]
    assert match_csaf(component, document, {"CVE-2024-12345"}).patch_status == "unavailable"


def test_reported_volume_is_grouped_without_losing_original_rows():
    # Synthetic reproduction of the supplied counts, not the user's actual host inventory.
    rows = []
    for index in range(2777):
        rows.append(
            {
                "id": str(index),
                "vulnerability_id": str(index % 1145),
                "asset_id": "asset-a",
                "alias": f"CVE-TEST-{index % 1145}",
                "component": {"name": "source-package", "version": "1", "ecosystem": "Debian:12"},
                "package": {
                    "name": f"binary-{index}",
                    "source_name": "source-package",
                    "source_version": "1",
                },
                "context": {"component_type": "runtime"},
                "priority": "P1",
                "status": "affected",
                "workflow": "open",
            }
        )
    grouped = group_findings(rows)
    assert len(grouped) == 1145
    assert sum(item["package_count"] for item in grouped) == 2777
    other = deepcopy(rows[0])
    other["asset_id"] = "other-host"
    other["id"] = "other"
    assert len(group_findings(rows + [other])) == 1146
