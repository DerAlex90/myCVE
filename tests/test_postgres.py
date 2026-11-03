"""Optional integration against PostgreSQL, isolated in a disposable schema."""

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.schema import CreateSchema, DropSchema
from test_agents import provision, report, send
from test_scanner import FixtureFeeds, prepare
from test_services import setup_finding

from mycve.server.api import create_app
from mycve.server.config import Settings
from mycve.server.db import Base, Finding, ScanJob, sessions
from mycve.server.scanner import run_scan

pytestmark = pytest.mark.skipif(
    not os.getenv("MYCVE_TEST_POSTGRES_URL"),
    reason="Set MYCVE_TEST_POSTGRES_URL for PostgreSQL integration",
)


@pytest.fixture
def pg_engine():
    url = os.environ["MYCVE_TEST_POSTGRES_URL"]
    schema = "mycve_test_" + uuid4().hex
    admin = create_engine(url)
    with admin.begin() as connection:
        connection.execute(CreateSchema(schema))
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))
        admin.dispose()


def test_postgres_jsonb_and_source_history(pg_engine, advisory):
    with sessions(pg_engine)() as session:
        _, _, _, finding = setup_finding(session, advisory)
        assert session.scalar(text("SELECT payload->>'id' FROM source_records")) == advisory["id"]
        assert session.get(Finding, finding.id).status == "affected"


def test_postgres_scan_lock_released_after_run(pg_engine, advisory):
    factory = prepare(pg_engine)
    with factory() as session:
        job = ScanJob()
        session.add(job)
        session.commit()
        job_id = job.id
    run_scan(factory, Settings(_env_file=None), job_id, FixtureFeeds(advisory))
    with factory() as session:
        assert session.get(ScanJob, job_id).status == "succeeded"
        assert session.scalar(text("SELECT pg_try_advisory_lock(77103921)"))
        session.execute(text("SELECT pg_advisory_unlock(77103921)"))


def test_postgres_agent_round_trip_and_coverage_queries(pg_engine):
    with TestClient(
        create_app(Settings(api_key="", allow_unauthenticated=True, _env_file=None), pg_engine)
    ) as client:
        asset, registration, headers = provision(client)
        payload = report(
            packages=[{"id": "windows:application", "name": "Example App", "version": "1.0"}]
        )
        assert send(client, headers, payload).status_code == 200
        assert client.get("/api/agents").json()[0]["incomplete_packages"] == 1
        assert client.get("/api/overview").json()["incomplete_components"] == 1
        assert client.get(f"/api/assets/{asset['id']}/components").json()["total"] == 1
        assert (
            client.get(f"/api/agents/{registration['agent']['id']}/snapshots").json()["total"] == 1
        )


def test_postgres_automatic_product_identity_and_jsonb_coverage(pg_engine):
    from sqlalchemy import select
    from test_identification import Catalog, legacy_devices

    from mycve.server.db import Installation
    from mycve.server.identification import coverage, identify_inventory

    factory = legacy_devices(pg_engine, 2)
    with factory() as session:
        items = session.scalars(select(Installation)).all()
        assert coverage(session)["pending"] == 2
        assert identify_inventory(session, items, Catalog())["identified"] == 2
        assert coverage(session)["identified"] == 2
