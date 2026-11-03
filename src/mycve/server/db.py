# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    false,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


def now() -> datetime:
    return datetime.now(UTC)


def uid() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


Json = JSON().with_variant(JSONB(), "postgresql")


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    environment: Mapped[str] = mapped_column(String(100), default="production")
    owner: Mapped[str] = mapped_column(String(200), default="")
    exposure: Mapped[str] = mapped_column(String(20), default="internal")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Installation(Base):
    __tablename__ = "installations"
    __table_args__ = (UniqueConstraint("asset_id", "identity_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    identity_key: Mapped[str] = mapped_column(String(64))
    component: Mapped[dict] = mapped_column(Json)
    origin: Mapped[str] = mapped_column(
        String(150), default="manual", server_default="manual", index=True
    )
    inventory: Mapped[dict] = mapped_column(Json, default=dict, server_default="{}")
    identification: Mapped[dict] = mapped_column(Json, default=dict, server_default="{}")
    context: Mapped[dict] = mapped_column(Json, default=dict, server_default="{}")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ProductIdentityCache(Base):
    __tablename__ = "product_identity_cache"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    result: Mapped[dict] = mapped_column(Json)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    primary_alias: Mapped[str] = mapped_column(String(200), index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_due_date: Mapped[str | None] = mapped_column(String(30), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Alias(Base):
    __tablename__ = "aliases"
    alias: Mapped[str] = mapped_column(String(200), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)


class SourceRecord(Base):
    __tablename__ = "source_records"
    __table_args__ = (UniqueConstraint("source", "external_id", "checksum"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    source: Mapped[str] = mapped_column(String(30))
    external_id: Mapped[str] = mapped_column(String(500))
    url: Mapped[str] = mapped_column(Text)
    checksum: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(Json)
    source_modified: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    current: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("installation_id", "vulnerability_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    installation_id: Mapped[str] = mapped_column(ForeignKey("installations.id"), index=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="unknown")
    reason: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(10), default="P2")
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    priority_reasons: Mapped[list] = mapped_column(Json, default=list)
    fixed_versions: Mapped[list] = mapped_column(Json, default=list)
    patch_status: Mapped[str] = mapped_column(
        String(20), default="unknown", server_default="unknown"
    )
    evidence: Mapped[list] = mapped_column(Json, default=list)
    checked_version: Mapped[str | None] = mapped_column(String(300), nullable=True)
    workflow: Mapped[str] = mapped_column(String(30), default="open")
    notes: Mapped[str] = mapped_column(Text, default="")
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class FindingEvent(Base):
    __tablename__ = "finding_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    action: Mapped[str] = mapped_column(String(100))
    before: Mapped[dict | None] = mapped_column(Json, nullable=True)
    after: Mapped[dict] = mapped_column(Json)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    status: Mapped[str] = mapped_column(String(30), default="queued")
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    result: Mapped[dict] = mapped_column(Json, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[dict] = mapped_column(Json, default=dict, server_default="{}")
    cache_scope: Mapped[str] = mapped_column(String(36), default=uid)
    resume_of: Mapped[str | None] = mapped_column(String(36), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanCache(Base):
    __tablename__ = "scan_cache"
    __table_args__ = (UniqueConstraint("scope", "key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scope: Mapped[str] = mapped_column(String(36), index=True)
    key: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(Json)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class RuntimeState(Base):
    __tablename__ = "runtime_state"
    name: Mapped[str] = mapped_column(String(80), primary_key=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    data: Mapped[dict] = mapped_column(Json, default=dict)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_suffix: Mapped[str] = mapped_column(String(8))
    device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_inventory_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_collected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    agent_version: Mapped[str] = mapped_column(String(100), default="")
    host: Mapped[dict] = mapped_column(Json, default=dict)
    collectors: Mapped[list] = mapped_column(Json, default=list)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_pending: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"
    __table_args__ = (UniqueConstraint("agent_id", "report_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    report_id: Mapped[str] = mapped_column(String(36))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    checksum: Mapped[str] = mapped_column(String(64))
    partial: Mapped[bool] = mapped_column(Boolean)
    changes: Mapped[dict] = mapped_column(Json, default=dict)
    payload: Mapped[dict] = mapped_column(Json)


class InventoryChange(Base):
    __tablename__ = "inventory_changes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("inventory_snapshots.id"), index=True)
    installation_id: Mapped[str] = mapped_column(ForeignKey("installations.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    before: Mapped[dict | None] = mapped_column(Json, nullable=True)
    after: Mapped[dict | None] = mapped_column(Json, nullable=True)


def make_engine(url: str):
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")

    return engine


def sessions(engine):
    return sessionmaker(engine, expire_on_commit=False)


def require[T: Base](session: Session, model: type[T], key: str) -> T:
    value = session.get(model, key)
    if value is None:
        raise LookupError(f"{model.__name__} not found")
    return value
