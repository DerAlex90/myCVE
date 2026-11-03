"""Exercise a real 0.4 schema before adding resumable jobs and risk context."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, inspect

from mycve.server.db import Finding, ScanJob, make_engine, now, sessions
from mycve.server.migrate import migrate_schema


def test_040_upgrade_preserves_findings_and_legacy_scan_history(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
    config = Config()
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[1] / "migrations")
    )
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "c735cf38e815")
        metadata = MetaData()

        def table(name):
            return Table(name, metadata, autoload_with=connection)

        stamp = now()
        connection.execute(
            table("assets")
            .insert()
            .values(
                id="host",
                name="existing-host",
                environment="production",
                owner="",
                exposure="internal",
                criticality="medium",
                created_at=stamp,
            )
        )
        connection.execute(
            table("installations")
            .insert()
            .values(
                id="package",
                asset_id="host",
                identity_key="a" * 64,
                component={"name": "example", "version": "1"},
                origin="manual",
                inventory={},
                identification={},
                active=True,
                updated_at=stamp,
            )
        )
        connection.execute(
            table("vulnerabilities")
            .insert()
            .values(
                id="vulnerability",
                primary_alias="CVE-2024-12345",
                title="existing",
                description="",
                cvss=None,
                kev=False,
                kev_due_date=None,
                updated_at=stamp,
            )
        )
        connection.execute(
            table("findings")
            .insert()
            .values(
                id="finding",
                installation_id="package",
                vulnerability_id="vulnerability",
                status="affected",
                reason="existing evidence",
                priority="P2",
                priority_score=20,
                priority_reasons=[],
                fixed_versions=["2"],
                evidence=[],
                checked_version="1",
                workflow="in_progress",
                notes="keep this note",
                evaluated_at=stamp,
                updated_at=stamp,
            )
        )
        connection.execute(
            table("scan_jobs")
            .insert()
            .values(
                id="old-job",
                status="partial",
                asset_id=None,
                started_at=stamp,
                completed_at=stamp,
                created_at=stamp,
                result={"counts": {"osv": 3889}},
                error=None,
            )
        )
    assert "context" not in {
        column["name"] for column in inspect(engine).get_columns("installations")
    }
    migrate_schema(engine)
    with sessions(engine)() as session:
        finding = session.get(Finding, "finding")
        assert finding.notes == "keep this note" and finding.workflow == "in_progress"
        assert finding.patch_status == "available"
        legacy = session.get(ScanJob, "old-job")
        assert legacy.result["counts"]["osv"] == 3889 and legacy.progress == {}
    assert {"scan_cache", "runtime_state"}.issubset(inspect(engine).get_table_names())
    engine.dispose()
