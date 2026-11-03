# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MYCVE_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./mycve.db"
    redis_url: str = "redis://localhost:6379/0"
    api_key: str = ""
    allow_unauthenticated: bool = False
    demo_mode: bool = False
    task_mode: str = "celery"
    nvd_api_key: str = ""
    frontend_dir: Path = Path("frontend/dist")
    sync_interval_hours: int = Field(default=6, ge=1, le=168)
    bsi_max_documents: int = Field(default=50, ge=1, le=500)
    max_upload_bytes: int = Field(default=10_000_000, ge=1, le=50_000_000)
    feed_timeout: int = Field(default=40, ge=1, le=120)
    agent_stale_hours: int = Field(default=24, ge=1, le=720)
    agent_report_interval_seconds: int = Field(default=21600, ge=300, le=604800)
    agent_releases_dir: Path = Path("dist/agent")
    agent_max_snapshots_per_minute: int = Field(default=10, ge=2, le=120)
    identification_max_queries: int = Field(default=50, ge=1, le=1000)
    scan_cache_hours: int = Field(default=6, ge=1, le=24)
