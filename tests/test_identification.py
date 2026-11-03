from datetime import timedelta

import pytest
from sqlalchemy import select
from test_scanner import FixtureFeeds, run

from mycve import Component
from mycve.server.db import Agent, Asset, Finding, Installation, ProductIdentityCache, now, sessions
from mycve.server.feeds import FeedError
from mycve.server.identification import (
    coverage,
    dictionary_identity,
    effective_component,
    identify_inventory,
)


def product(vendor="mozilla", name="firefox", title="Mozilla Firefox", platform="*"):
    return {
        "cpeName": f"cpe:2.3:a:{vendor}:{name}:1.0:*:*:*:*:{platform}:*:*",
        "cpeNameId": "dictionary-id",
        "deprecated": False,
        "titles": [{"title": title + " 1.0", "lang": "en"}],
    }


class Catalog:
    def __init__(self, products=None):
        self.products = products if products is not None else [product()]
        self.queries = []
        self.fail = False

    def cpe_dictionary(self, name):
        self.queries.append(name)
        if self.fail:
            raise FeedError("NVD-CPE: HTTP 503")
        return self.products


def legacy_devices(engine, count=1):
    factory = sessions(engine)
    with factory() as session:
        for number in range(count):
            asset = Asset(name=f"legacy-windows-{number}")
            session.add(asset)
            session.flush()
            agent = Agent(
                asset_id=asset.id,
                token_hash=f"test-{number}",
                token_suffix="test",
                host={"os": "windows"},
                last_inventory_at=now(),
            )
            session.add(agent)
            session.flush()
            session.add(
                Installation(
                    asset_id=asset.id,
                    identity_key="firefox",
                    origin=f"agent:{agent.id}:windows_registry",
                    component=Component(
                        name="Mozilla Firefox 1.0 (x64 de)",
                        vendor="Mozilla Corporation",
                        version="1.0",
                    ).model_dump(),
                    inventory={"architecture": "x64"},
                )
            )
        session.commit()
    return factory


def test_existing_agents_are_identified_without_manual_ids_and_share_cache(engine):
    factory = legacy_devices(engine, 3)
    catalog = Catalog()
    with factory() as session:
        items = session.scalars(select(Installation)).all()
        originals = [item.component.copy() for item in items]
        stats = identify_inventory(session, items, catalog)
        assert stats["identified"] == 3 and stats["queries"] == 1
        assert catalog.queries == ["mozilla firefox"]
        assert [item.component for item in items] == originals
        assert coverage(session)["identified"] == 3
        for item in items:
            effective = effective_component(item)
            assert ":mozilla:firefox:1.0:" in effective.cpe
            assert ":windows:x64:" in effective.cpe
            assert item.identification["url"].startswith("https://services.nvd.nist.gov/")
        identify_inventory(session, items, catalog)
        assert len(catalog.queries) == 1
        item = items[0]
        item.component = {**item.component, "version": "2.0"}
        session.commit()
        assert effective_component(item).cpe is None
        identify_inventory(session, [item], catalog)
        assert ":firefox:2.0:" in effective_component(item).cpe
        assert len(catalog.queries) == 1


def test_names_alone_wrong_vendor_platform_and_ambiguity_cannot_confirm():
    assert dictionary_identity("firefox", "", "windows", [product()])["status"] == "unresolved"
    assert dictionary_identity("mozilla firefox", "", "windows", [product()])["status"] == "unresolved"
    assert (
        dictionary_identity("mozilla firefox", "Other Company", "windows", [product()])["status"]
        == "unresolved"
    )
    assert (
        dictionary_identity("mozilla firefox", "Mozilla", "windows", [product(platform="android")])[
            "status"
        ]
        == "unresolved"
    )
    ambiguous = [product(), product(name="firefox_other")]
    assert (
        dictionary_identity("mozilla firefox", "Mozilla", "windows", ambiguous)["status"]
        == "ambiguous"
    )


def test_catalog_failure_is_visible_retried_and_never_changes_reported_data(engine):
    factory = legacy_devices(engine)
    catalog = Catalog()
    catalog.fail = True
    with factory() as session:
        item = session.scalar(select(Installation))
        assert identify_inventory(session, [item], catalog)["error"] == 1
        assert effective_component(item).cpe is None
        assert coverage(session)["error"] == 1
        catalog.fail = False
        item.identification = {
            **item.identification,
            "next_check_at": (now() - timedelta(seconds=1)).isoformat(),
        }
        session.scalar(select(ProductIdentityCache)).expires_at = now() - timedelta(seconds=1)
        session.commit()
        assert identify_inventory(session, [item], catalog)["identified"] == 1
        assert len(catalog.queries) == 2


def test_product_budget_continues_automatically_and_missing_version_stays_unknown(engine):
    factory = legacy_devices(engine, 2)
    catalog = Catalog([product(), product(vendor="acme", name="viewer", title="Acme Viewer")])
    with factory() as session:
        items = session.scalars(select(Installation)).all()
        items[1].component = Component(name="Acme Viewer", vendor="Acme").model_dump()
        session.commit()
        stats = identify_inventory(session, items, catalog, max_queries=1)
        assert stats["queries"] == 1 and stats["pending"] == 1
        for item in items:
            if item.identification["status"] == "pending":
                item.identification = {
                    **item.identification,
                    "next_check_at": (now() - timedelta(seconds=1)).isoformat(),
                }
        session.commit()
        stats = identify_inventory(session, items, catalog, max_queries=1)
        assert stats["identified"] == 1 and stats["missing_version"] == 1
        assert len(catalog.queries) == 2
        assert items[1].identification.get("cpe") is None


@pytest.mark.parametrize(
    ("purl", "ecosystem"),
    [
        ("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-24.04", "Ubuntu:24.04"),
        ("pkg:apk/alpine/openssl@3.3.1-r0?distro=alpine-3.22.1", "Alpine:v3.22"),
        ("pkg:rpm/rocky/openssl@1:3.0.1-7.el9?distro=rocky-9.4", "Rocky Linux:9"),
        ("pkg:rpm/almalinux/openssl@3.0.1-7.el9?distro=almalinux-9", "AlmaLinux:9"),
        ("pkg:rpm/rhel/openssl@3.0.1-7.el9?distro=rhel-9.4", "Red Hat:9"),
    ],
)
def test_distribution_namespace_is_derived_automatically_without_upstream_cpe(purl, ecosystem):
    assert Component(name="openssl", purl=purl).ecosystem == ecosystem


def test_legacy_windows_inventory_discovers_and_checks_cves_automatically(engine, advisory):
    factory = legacy_devices(engine)

    class WindowsFeeds(FixtureFeeds):
        cpe_requests = 0

        def cpe_dictionary(self, name):
            assert name == "mozilla firefox"
            return [product()]

        def nvd_cpe(self, cpe):
            self.cpe_requests += 1
            assert ":mozilla:firefox:1.0:" in cpe
            return [self.nvd("CVE-2024-12345")]

        def nvd(self, alias):
            return {
                "id": alias,
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:windows:x86_64:*",
                                        "versionStartIncluding": "0.9",
                                        "versionEndExcluding": "2.0",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }

    feeds = WindowsFeeds(advisory)
    job = run(factory, feeds)
    assert job.status == "succeeded", job.error or job.result
    assert job.result["identification"]["identified"] == 1
    with factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None and finding.status == "affected"
        assert finding.checked_version == "1.0"
    assert run(factory, feeds).status == "succeeded"
    assert feeds.cpe_requests == 1


def test_old_agent_report_is_automatically_scheduled_identified_and_checked(
    client, engine, advisory, monkeypatch
):
    from test_agents import provision, report, send

    from mycve.server import tasks
    from mycve.server.config import Settings
    from mycve.server.scanner import run_scan

    _, _, headers = provision(client)
    body = report(
        packages=[
            {
                "id": "http",
                "name": "example-http",
                "version": "2.4.1",
                "purl": "pkg:pypi/example-http@2.4.1",
            }
        ]
    )
    assert send(client, headers, body).status_code == 200
    monkeypatch.setattr(tasks, "make_engine", lambda _: engine)
    monkeypatch.setattr(engine, "dispose", lambda: None)
    # This replaces only external feeds, not the timer's scan scheduling or execution.
    monkeypatch.setattr(
        tasks.scan,
        "delay",
        lambda identifier: run_scan(
            sessions(engine), Settings(_env_file=None), identifier, FixtureFeeds(advisory)
        ),
    )
    tasks.refresh_agents.run()
    findings = client.get("/api/findings").json()["items"]
    assert len(findings) == 1 and findings[0]["status"] == "affected"
    assert client.get("/api/agents").json()[0]["identification"]["identified"] == 1
