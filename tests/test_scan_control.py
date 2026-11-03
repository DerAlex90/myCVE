from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import select
from test_scanner import FixtureFeeds, prepare, run

from mycve.server.config import Settings
from mycve.server.db import Base, ScanJob, make_engine, sessions
from mycve.server.jobs import ScanBusy, create_job
from mycve.server.scanner import run_scan


class CountingFeeds(FixtureFeeds):
    def __init__(self, advisory):
        super().__init__(advisory)
        self.calls = {}

    def osv_details(self, alias):
        self.calls["osv_details"] = self.calls.get("osv_details", 0) + 1
        return super().osv_details(alias)


def test_partial_retry_reuses_successful_advisories_and_retries_failed_source(engine, advisory):
    factory = prepare(engine)
    feeds = CountingFeeds(advisory)
    feeds.fail_kev = True
    first = run(factory, feeds)
    assert first.status == "partial"
    feeds.fail_kev = False
    with factory() as session:
        resumed = create_job(session, resume_id=first.id)
        resumed_id = resumed.id
    run_scan(factory, Settings(_env_file=None), resumed_id, feeds)
    with factory() as session:
        job = session.get(ScanJob, resumed_id)
        assert job.status == "succeeded"
        assert job.resume_of == first.id
        assert job.result["counts"]["cache_hits"] >= 4
    assert feeds.calls["osv_details"] == 1


def test_queued_cancel_stops_dispatch_and_resume_has_a_separate_job(
    client, engine, advisory, monkeypatch
):
    from mycve.server import scanner

    factory = prepare(engine)
    with factory() as session:
        job = create_job(session)
        identifier = job.id
    result = client.post(f"/api/scans/{identifier}/cancel")
    assert result.status_code == 202 and result.json()["status"] == "cancelled"
    real_run = scanner.run_scan
    monkeypatch.setattr(
        scanner,
        "run_scan",
        lambda factory, settings, job_id: real_run(
            factory, settings, job_id, FixtureFeeds(advisory)
        ),
    )
    resumed = client.post(f"/api/scans/{identifier}/resume")
    assert resumed.status_code == 202
    with factory() as session:
        assert session.get(ScanJob, resumed.json()["id"]).status == "succeeded"
        assert session.get(ScanJob, identifier).status == "cancelled"


def test_progress_is_committed_before_completion_and_running_cancel_is_cooperative(
    engine, advisory
):
    factory = prepare(engine)

    class CancellingFeeds(FixtureFeeds):
        def kev(self):
            with factory() as check:
                job = check.scalar(select(ScanJob).where(ScanJob.status == "running"))
                assert job.progress["phase"] == "kev"
                assert job.result["counts"]["osv"] == 1
                job.cancel_requested = True
                check.commit()
            return super().kev()

    job = run(factory, CancellingFeeds(advisory))
    assert job.status == "cancelled"
    assert job.progress["phase"] == "kev"


def test_concurrent_requests_create_only_one_active_job(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'race.db'}")
    Base.metadata.create_all(engine)
    factory = sessions(engine)
    barrier = Barrier(2)

    def attempt():
        with factory() as session:
            barrier.wait()
            try:
                create_job(session)
                return "created"
            except ScanBusy:
                session.rollback()
                return "busy"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: attempt(), range(2))) == ["busy", "created"]
    engine.dispose()


def test_readiness_requires_successful_scan_and_respects_authentication(client, engine):
    assert client.get("/api/ready").status_code == 503
    from mycve.server.db import now

    with sessions(engine)() as session:
        session.add(ScanJob(status="succeeded", completed_at=now()))
        session.commit()
    assert client.get("/api/ready").status_code == 200
    assert client.get("/api/operations").json()["checks"]["worker"]["status"] == "not_required"


def test_newer_completed_scan_prevents_automatic_resume_of_an_old_partial(engine, advisory):
    factory = prepare(engine)
    feeds = CountingFeeds(advisory)
    feeds.fail_kev = True
    old = run(factory, feeds)
    feeds.fail_kev = False
    completed = run(factory, feeds)
    assert completed.status == "succeeded"
    with factory() as session:
        job = create_job(session)
        assert job.resume_of is None and job.cache_scope != old.cache_scope
        job.status = "cancelled"
        session.commit()
        explicit = create_job(session, resume_id=old.id)
        identifier = explicit.id
    before = feeds.calls["osv_details"]
    run_scan(factory, Settings(_env_file=None), identifier, feeds)
    assert feeds.calls["osv_details"] == before + 1
