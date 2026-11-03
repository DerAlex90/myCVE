from copy import deepcopy

from sqlalchemy import func, select

from mycve import Component
from mycve.server.config import Settings
from mycve.server.db import (
    Asset,
    Finding,
    FindingEvent,
    Installation,
    ScanJob,
    SourceRecord,
    Vulnerability,
    sessions,
)
from mycve.server.feeds import FeedError
from mycve.server.scanner import run_scan
from mycve.server.services import import_components


class FixtureFeeds:
    def __init__(self, advisory):
        self.advisory = deepcopy(advisory)
        self.fail_osv = False
        self.fail_kev = False
        self.no_hits = False
        self.enriched = []

    def osv_batch(self, packages):
        if self.fail_osv:
            raise FeedError("OSV nicht erreichbar")
        return {package: [] if self.no_hits else [self.advisory["id"]] for package in packages}

    def osv_details(self, _):
        return self.advisory

    def cve(self, alias):
        self.enriched.append(alias)
        return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {"title": "Test CVE"}}}

    def nvd(self, _):
        return {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}

    def kev(self):
        if self.fail_kev:
            raise FeedError("KEV nicht erreichbar")
        return {
            "dateReleased": "2026-11-02T00:00:00Z",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2024-12345", "dueDate": "2026-11-20"}],
        }

    def bsi_documents(self, *args, **kwargs):
        return [], 0


def prepare(engine, version="2.4.1"):
    factory = sessions(engine)
    with factory() as session:
        asset = Asset(name="scan-test", exposure="internet", criticality="high")
        session.add(asset)
        session.flush()
        import_components(
            session,
            asset,
            [Component(name="example-http", ecosystem="PyPI", version=version, ref="http")],
        )
        session.commit()
    return factory


def run(factory, feeds):
    with factory() as session:
        job = ScanJob()
        session.add(job)
        session.commit()
        job_id = job.id
    run_scan(factory, Settings(_env_file=None), job_id, feeds)
    with factory() as session:
        return session.get(ScanJob, job_id)


def test_full_scan_then_repeat_is_idempotent(engine, advisory):
    factory = prepare(engine)
    feeds = FixtureFeeds(advisory)
    assert run(factory, feeds).status == "succeeded"
    assert run(factory, feeds).status == "succeeded"
    with factory() as session:
        finding = session.scalar(select(Finding))
        vulnerability = session.scalar(select(Vulnerability))
        assert finding.status == "affected" and finding.priority == "P0"
        assert vulnerability.kev and vulnerability.cvss == 9.8
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert session.scalar(select(func.count()).select_from(FindingEvent)) == 1
        assert session.scalar(select(func.count()).select_from(SourceRecord)) == 4
        assert feeds.enriched == ["CVE-2024-12345", "CVE-2024-12345"]


def test_source_failure_preserves_findings_and_kev(engine, advisory):
    factory = prepare(engine)
    feeds = FixtureFeeds(advisory)
    run(factory, feeds)
    feeds.fail_osv = feeds.fail_kev = True
    job = run(factory, feeds)
    assert job.status == "partial"
    assert job.result["sources"]["OSV"] == "error"
    with factory() as session:
        assert session.scalar(select(Finding)).status == "affected"
        assert session.scalar(select(Vulnerability)).kev


def test_empty_inventory_does_not_report_unused_sources_as_successful(engine, advisory):
    job = run(sessions(engine), FixtureFeeds(advisory))
    assert job.status == "succeeded"
    assert job.result["counts"]["packages"] == 0
    for source in ("OSV", "CVE Program", "NVD"):
        assert job.result["sources"][source] == "skipped"
    assert job.result["sources"]["CISA KEV"] == "ok"


def test_known_advisories_are_refreshed_without_active_inventory(engine, advisory):
    factory = prepare(engine)
    feeds = FixtureFeeds(advisory)
    run(factory, feeds)
    with factory() as session:
        session.scalar(select(Installation)).active = False
        session.commit()
    job = run(factory, feeds)
    assert job.status == "succeeded"
    assert job.result["counts"]["packages"] == 0
    assert job.result["counts"]["osv"] == 1
    for source in ("OSV", "CVE Program", "NVD"):
        assert job.result["sources"][source] == "ok"


def test_complete_negative_response_reassesses_old_match(engine, advisory):
    factory = prepare(engine)
    feeds = FixtureFeeds(advisory)
    run(factory, feeds)
    feeds.no_hits = True
    assert run(factory, feeds).status == "succeeded"
    with factory() as session:
        assert session.scalar(select(Finding)).status == "not_affected"


def test_unknown_version_never_becomes_confirmed(engine, advisory):
    factory = prepare(engine, version=None)
    assert run(factory, FixtureFeeds(advisory)).status == "succeeded"
    with factory() as session:
        finding = session.scalar(select(Finding))
        assert finding.status == "unknown" and finding.priority != "P0"
