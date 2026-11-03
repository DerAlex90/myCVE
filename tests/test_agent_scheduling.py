from datetime import timedelta

from sqlalchemy import select
from test_scanner import FixtureFeeds

from mycve import Component
from mycve.server import tasks
from mycve.server.config import Settings
from mycve.server.db import Agent, Asset, ScanJob, now, sessions
from mycve.server.scanner import run_scan
from mycve.server.services import import_components


def test_agent_scheduler_batches_changes_and_respects_active_scan(engine, monkeypatch):
    # Keep the test database alive while task-owned engines are disposed.
    monkeypatch.setattr(tasks, "make_engine", lambda _: engine)
    monkeypatch.setattr(engine, "dispose", lambda: None)
    dispatched = []
    monkeypatch.setattr(tasks.scan, "delay", lambda identifier: dispatched.append(identifier))
    factory = sessions(engine)
    with factory() as session:
        asset = Asset(name="pending-agent")
        session.add(asset)
        session.flush()
        session.add(
            Agent(asset_id=asset.id, token_hash="test", token_suffix="test", scan_pending=True)
        )
        session.commit()
    tasks.refresh_agents.run()
    tasks.refresh_agents.run()
    assert len(dispatched) == 1
    with factory() as session:
        assert session.scalar(select(Agent)).scan_pending
        assert session.get(ScanJob, dispatched[0]).status == "queued"


def test_successful_global_scan_acknowledges_only_older_agent_changes(engine, advisory):
    factory = sessions(engine)
    with factory() as session:
        asset = Asset(name="scan-agent")
        session.add(asset)
        session.flush()
        import_components(
            session, asset, [Component(name="example-http", ecosystem="PyPI", version="2.4.1")]
        )
        agent = Agent(
            asset_id=asset.id,
            token_hash="test",
            token_suffix="test",
            scan_pending=True,
            last_inventory_at=now() - timedelta(seconds=1),
        )
        session.add(agent)
        job = ScanJob()
        session.add(job)
        session.commit()
        job_id = job.id
    run_scan(factory, Settings(_env_file=None), job_id, FixtureFeeds(advisory))
    with factory() as session:
        assert session.get(ScanJob, job_id).status == "succeeded"
        assert not session.scalar(select(Agent)).scan_pending
