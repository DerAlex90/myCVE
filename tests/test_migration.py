from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from mycve.server.migrate import migrate_schema


def test_upgrade_preserves_existing_unversioned_native_inventory(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "legacy.db"))
    config = Config()
    config.set_main_option("script_location", "migrations")
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "86082dd56fbe")
        connection.execute(
            text(
                "INSERT INTO assets VALUES ('asset','old-system','production','owner','internal','medium','2026-01-01')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO installations (id,asset_id,identity_key,component,active,updated_at) VALUES ('installation','asset','key','{\"name\":\"old-package\"}',1,'2026-01-01')"
            )
        )
        connection.execute(text("DROP TABLE alembic_version"))
    migrate_schema(engine)
    with engine.connect() as connection:
        row = connection.execute(text("SELECT origin,inventory FROM installations")).one()
        assert row.origin == "manual" and row.inventory == "{}"
        assert "agents" in inspect(connection).get_table_names()
        assert "scan_pending" in {
            item["name"] for item in inspect(connection).get_columns("agents")
        }
    migrate_schema(engine)
    engine.dispose()


def test_upgrade_02_inventory_is_automatically_scheduled_and_preserved(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "legacy02.db"))
    config = Config()
    config.set_main_option("script_location", "migrations")
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "ae5a55a8f79e")
        connection.execute(
            text(
                "INSERT INTO assets VALUES ('asset','old-windows','production','','internal','medium','2026-01-01')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO installations (id,asset_id,identity_key,component,origin,inventory,active,updated_at) VALUES ('installation','asset','key','{\"name\":\"Mozilla Firefox\",\"version\":\"1.0\",\"vendor\":\"Mozilla\"}','agent:agent:windows_registry','{}',1,'2026-01-01')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO agents (id,asset_id,token_hash,token_suffix,created_at,last_inventory_at,agent_version,host,collectors,scan_pending) VALUES ('agent','asset','hash','test','2026-01-01','2026-01-01','0.2.0','{\"os\":\"windows\"}','[]',0)"
            )
        )
        connection.execute(text("DROP TABLE alembic_version"))
    migrate_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT scan_pending FROM agents")) == 1
        assert connection.scalar(text("SELECT identification FROM installations")) == "{}"
        assert "product_identity_cache" in inspect(connection).get_table_names()
    engine.dispose()
