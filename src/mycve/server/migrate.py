# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Upgrade existing native/SQLite installs as well as packaged server installations."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect


def migrate_schema(engine):
    bundled = Path(__file__).resolve().parents[1] / "migrations"
    directory = bundled if bundled.is_dir() else Path(__file__).resolve().parents[3] / "migrations"
    config = Config()
    config.set_main_option("script_location", str(directory))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        if "assets" in tables and "alembic_version" not in tables:
            columns = {column["name"] for column in inspector.get_columns("installations")}
            # 0.1 native installs used create_all; stamp their known baseline before upgrading.
            if "origin" not in columns:
                command.stamp(config, "86082dd56fbe")
            elif {"agents", "inventory_snapshots", "inventory_changes"}.issubset(tables):
                command.stamp(
                    config,
                    "head"
                    if "context" in columns
                    else "c735cf38e815"
                    if "identification" in columns
                    else "ae5a55a8f79e",
                )
            else:
                raise RuntimeError(
                    "Unversionierte Datenbank hat ein unbekanntes Schema; vor Migration prüfen"
                )
        command.upgrade(config, "head")
