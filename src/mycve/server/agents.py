# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Device-scoped inventory intake. Agent credentials never grant workspace access."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mycve.core.models import Component
from mycve.server.db import (
    Agent,
    Asset,
    Finding,
    Installation,
    InventoryChange,
    InventorySnapshot,
    Vulnerability,
    now,
    require,
)
from mycve.server.identification import coverage, incomplete_filter
from mycve.server.services import checksum, evaluate


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class HostInput(StrictInput):
    hostname: str = Field(min_length=1, max_length=200)
    os: str = Field(min_length=1, max_length=30)
    architecture: str = Field(min_length=1, max_length=30)
    name: str = Field(default="", max_length=200)
    version: str = Field(default="", max_length=100)
    build: str = Field(default="", max_length=100)
    kernel: str = Field(default="", max_length=200)
    distribution: str = Field(default="", max_length=100)
    distribution_version: str = Field(default="", max_length=100)


class PackageInput(StrictInput):
    id: str = Field(min_length=1, max_length=350)
    name: str = Field(min_length=1, max_length=500)
    version: str | None = Field(default=None, max_length=300)
    publisher: str | None = Field(default=None, max_length=300)
    architecture: str | None = Field(default=None, max_length=100)
    ecosystem: str | None = Field(default=None, max_length=100)
    purl: str | None = Field(default=None, max_length=2000)
    cpe: str | None = Field(default=None, max_length=2000)
    source_name: str | None = Field(default=None, max_length=500)
    source_version: str | None = Field(default=None, max_length=300)
    version_source: str | None = Field(default=None, max_length=100)
    component_type: Literal["runtime", "development", "unknown"] = "unknown"
    kernel_release: str | None = Field(default=None, max_length=200)

    def component(self) -> Component:
        return Component(
            name=self.source_name or self.name,
            version=self.source_version or self.version,
            ecosystem=self.ecosystem,
            purl=self.purl,
            cpe=self.cpe,
            vendor=self.publisher,
        )

    @model_validator(mode="after")
    def validate_identity(self):
        self.component()
        return self


class CollectorInput(StrictInput):
    id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,100}$")
    complete: bool
    error: str | None = Field(default=None, max_length=2000)
    packages: list[PackageInput] = Field(default_factory=list, max_length=10000)

    @model_validator(mode="after")
    def validate_packages(self):
        ids = [item.id for item in self.packages]
        if len(ids) != len(set(ids)):
            raise ValueError("Paket-IDs müssen innerhalb einer Erfassung eindeutig sein")
        if self.complete and self.error:
            raise ValueError("Eine fehlgeschlagene Erfassung kann nicht vollständig sein")
        return self


class InventoryInput(StrictInput):
    schema_version: Literal[1]
    snapshot_id: UUID
    device_id: UUID
    collected_at: AwareDatetime
    agent_version: str = Field(min_length=1, max_length=100)
    host: HostInput
    collectors: list[CollectorInput] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def validate_scope(self):
        names = [item.id for item in self.collectors]
        if len(names) != len(set(names)):
            raise ValueError("Erfassungsquellen müssen eindeutig sein")
        if sum(len(item.packages) for item in self.collectors) > 10000:
            raise ValueError("Maximal 10000 Pakete pro Bericht")
        if self.collected_at > now() + timedelta(minutes=10):
            raise ValueError("Erfassungszeit liegt in der Zukunft; Systemuhr prüfen")
        return self


class AgentCreate(StrictInput):
    asset_id: UUID


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(agent: Agent) -> str:
    token = "mycve_agent_" + secrets.token_urlsafe(48)
    agent.token_hash, agent.token_suffix = token_hash(token), token[-8:]
    agent.revoked_at = None
    return token


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def serialize_agent(session, agent: Agent, settings) -> dict:
    asset = require(session, Asset, agent.asset_id)
    seen = utc(agent.last_seen_at) if agent.last_seen_at else None
    status = (
        "revoked"
        if agent.revoked_at
        else "never_seen"
        if seen is None
        else "stale"
        if seen < now() - timedelta(hours=settings.agent_stale_hours)
        else "online"
    )
    return {
        "id": agent.id,
        "asset_id": agent.asset_id,
        "asset_name": asset.name,
        "status": status,
        "token_suffix": agent.token_suffix,
        "device_id": agent.device_id,
        "host": agent.host,
        "agent_version": agent.agent_version,
        "collectors": agent.collectors,
        "last_error": agent.last_error,
        "scan_pending": agent.scan_pending,
        "identification": coverage(
            session,
            Installation.asset_id == asset.id,
            Installation.origin.like(f"agent:{agent.id}:%"),
        ),
        **{
            key: (utc(getattr(agent, key)).isoformat() if getattr(agent, key) else None)
            for key in (
                "created_at",
                "revoked_at",
                "last_seen_at",
                "last_inventory_at",
                "last_collected_at",
            )
        },
        "packages": session.scalar(
            select(func.count())
            .select_from(Installation)
            .where(
                Installation.asset_id == asset.id,
                Installation.origin.like(f"agent:{agent.id}:%"),
                Installation.active.is_(True),
            )
        ),
        "incomplete_packages": session.scalar(
            select(func.count())
            .select_from(Installation)
            .where(
                Installation.asset_id == asset.id,
                Installation.origin.like(f"agent:{agent.id}:%"),
                Installation.active.is_(True),
                incomplete_filter(),
            )
        ),
    }


def ingest_inventory(session, agent: Agent, body: InventoryInput) -> dict:
    payload = body.model_dump(mode="json", exclude_unset=True)
    digest = checksum(payload)
    previous = session.scalar(
        select(InventorySnapshot).where(
            InventorySnapshot.agent_id == agent.id,
            InventorySnapshot.report_id == str(body.snapshot_id),
        )
    )
    if previous:
        if previous.checksum != digest:
            raise HTTPException(409, "Berichts-ID wurde mit anderem Inhalt wiederverwendet")
        agent.last_seen_at = now()
        return {
            "accepted": True,
            "duplicate": True,
            "snapshot_id": previous.report_id,
            "changes": previous.changes,
        }
    if agent.device_id and agent.device_id != str(body.device_id):
        raise HTTPException(409, "Dieser Schlüssel ist bereits an ein anderes Gerät gebunden")
    agent.device_id = str(body.device_id)
    agent.last_seen_at = now()
    if agent.last_collected_at and body.collected_at <= utc(agent.last_collected_at):
        return {
            "accepted": False,
            "duplicate": False,
            "stale": True,
            "snapshot_id": str(body.snapshot_id),
        }
    previous_collectors = {item["id"] for item in agent.collectors}
    missing = previous_collectors - {item.id for item in body.collectors}
    partial = bool(missing) or any(not item.complete for item in body.collectors)
    changes = {"added": 0, "updated": 0, "removed": 0}
    kernel_changed = agent.host.get("kernel") != body.host.kernel
    host = body.host.model_dump()
    snapshot = InventorySnapshot(
        agent_id=agent.id,
        report_id=str(body.snapshot_id),
        collected_at=body.collected_at,
        checksum=digest,
        partial=partial,
        payload=payload,
    )
    session.add(snapshot)
    session.flush()
    modified = set()
    for collector in body.collectors:
        origin = f"agent:{agent.id}:{collector.id}"
        existing = {
            item.identity_key: item
            for item in session.scalars(
                select(Installation).where(
                    Installation.asset_id == agent.asset_id, Installation.origin == origin
                )
            )
        }
        retained = set()
        for package in collector.packages:
            key = checksum({"agent": agent.id, "collector": collector.id, "package": package.id})
            retained.add(key)
            metadata = package.model_dump(
                mode="json", exclude={"component_type", "kernel_release"} - package.model_fields_set
            )
            component = package.component().model_dump()
            component["platform"] = body.host.os
            installation = existing.get(key)
            before = installation.inventory if installation and installation.active else None
            kind = None
            if installation is None:
                installation = Installation(
                    asset_id=agent.asset_id,
                    identity_key=key,
                    component=component,
                    origin=origin,
                    inventory=metadata,
                )
                session.add(installation)
                session.flush()
                kind = "added"
            elif not installation.active:
                installation.active = True
                kind = "added"
            elif installation.component != component or installation.inventory != metadata:
                kind = "updated"
            if installation.component != component or installation.inventory.get(
                "architecture"
            ) != metadata.get("architecture"):
                installation.identification = {}
            installation.component, installation.inventory = component, metadata
            from mycve.server.context import package_context

            installation.context = package_context(metadata, component, host)
            if kernel_changed:
                modified.add(installation.id)
            if kind:
                installation.updated_at = now()
                changes[kind] += 1
                modified.add(installation.id)
                session.add(
                    InventoryChange(
                        snapshot_id=snapshot.id,
                        installation_id=installation.id,
                        kind=kind,
                        before=before,
                        after=metadata,
                    )
                )
        if collector.complete:
            for key, installation in existing.items():
                if key not in retained and installation.active:
                    installation.active = False
                    installation.updated_at = now()
                    changes["removed"] += 1
                    modified.add(installation.id)
                    session.add(
                        InventoryChange(
                            snapshot_id=snapshot.id,
                            installation_id=installation.id,
                            kind="removed",
                            before=installation.inventory,
                            after=None,
                        )
                    )
    session.flush()
    if modified:
        for finding in session.scalars(
            select(Finding).where(Finding.installation_id.in_(modified))
        ).all():
            evaluate(
                session,
                require(session, Installation, finding.installation_id),
                require(session, Vulnerability, finding.vulnerability_id),
            )
    snapshot.changes = changes
    if any(changes.values()) or kernel_changed:
        agent.scan_pending = True
    agent.host, agent.agent_version = body.host.model_dump(), body.agent_version
    agent.collectors = [
        {
            "id": item.id,
            "complete": item.complete,
            "error": item.error,
            "packages": len(item.packages),
        }
        for item in body.collectors
    ] + [
        {"id": name, "complete": False, "error": "Erfassungsquelle fehlt im Bericht", "packages": 0}
        for name in sorted(missing)
    ]
    errors = [
        item["error"] or f"{item['id']}: Erfassung unvollständig"
        for item in agent.collectors
        if not item["complete"]
    ]
    agent.last_error = "; ".join(errors)[:10000] or None
    agent.last_inventory_at, agent.last_collected_at = now(), body.collected_at
    return {
        "accepted": True,
        "duplicate": False,
        "snapshot_id": str(body.snapshot_id),
        "partial": partial,
        "changes": changes,
    }


def create_agent_router(authenticated, db) -> APIRouter:
    router = APIRouter()
    Db = Annotated[Session, Depends(db)]
    admin = [Depends(authenticated)]

    @router.get("/api/agents/downloads", dependencies=admin)
    def downloads(request: Request):
        root = request.app.state.settings.agent_releases_dir
        allowed = [
            "mycve-agent-linux-amd64.tar.gz",
            "mycve-agent-linux-arm64.tar.gz",
            "mycve-agent-windows-amd64.zip",
            "mycve-agent-windows-arm64.zip",
            "SHA256SUMS",
        ]
        return [
            {"name": name, "bytes": (root / name).stat().st_size}
            for name in allowed
            if (root / name).is_file()
        ]

    @router.get("/api/agents/downloads/{name}", dependencies=admin)
    def download(name: str, request: Request):
        allowed = {
            "mycve-agent-linux-amd64.tar.gz",
            "mycve-agent-linux-arm64.tar.gz",
            "mycve-agent-windows-amd64.zip",
            "mycve-agent-windows-arm64.zip",
            "SHA256SUMS",
        }
        if name not in allowed:
            raise HTTPException(404, "Agent-Paket nicht gefunden")
        path = request.app.state.settings.agent_releases_dir / name
        if not path.is_file():
            raise HTTPException(404, "Agent-Pakete zuerst mit dem Release-Build erstellen")
        return FileResponse(path, filename=name)

    @router.get("/api/agents", dependencies=admin)
    def list_agents(request: Request, session: Db):
        return [
            serialize_agent(session, agent, request.app.state.settings)
            for agent in session.scalars(select(Agent).order_by(Agent.created_at.desc()))
        ]

    def provision(request, session, agent, token):
        return {
            "agent": serialize_agent(session, agent, request.app.state.settings),
            "configuration": {
                "server_url": str(request.base_url).rstrip("/"),
                "agent_id": agent.id,
                "token": token,
                "interval_seconds": request.app.state.settings.agent_report_interval_seconds,
                "allow_insecure_localhost": False,
            },
        }

    @router.post("/api/agents", dependencies=admin, status_code=201)
    def create_agent(body: AgentCreate, request: Request, session: Db):
        asset = session.scalar(
            select(Asset).where(Asset.id == str(body.asset_id)).with_for_update()
        )
        if not asset:
            raise HTTPException(404, "System nicht gefunden")
        if session.scalar(select(Agent).where(Agent.asset_id == asset.id)):
            raise HTTPException(
                409,
                "Für dieses System besteht bereits ein Agent; Schlüssel erneuern oder widerrufen",
            )
        agent = Agent(asset_id=asset.id)
        token = issue_token(agent)
        session.add(agent)
        session.commit()
        return provision(request, session, agent, token)

    @router.post("/api/agents/{agent_id}/rotate-token", dependencies=admin)
    def rotate(agent_id: str, request: Request, session: Db, reset_device: bool = False):
        agent = session.scalar(select(Agent).where(Agent.id == agent_id).with_for_update())
        if not agent:
            raise HTTPException(404, "Agent nicht gefunden")
        token = issue_token(agent)
        if reset_device:
            agent.device_id = None
        session.commit()
        return provision(request, session, agent, token)

    @router.delete("/api/agents/{agent_id}", dependencies=admin)
    def revoke(agent_id: str, session: Db):
        agent = session.scalar(select(Agent).where(Agent.id == agent_id).with_for_update())
        if not agent:
            raise HTTPException(404, "Agent nicht gefunden")
        agent.revoked_at = now()
        session.commit()
        return {"id": agent.id, "revoked": True}

    @router.get("/api/agents/{agent_id}/snapshots", dependencies=admin)
    def snapshots(
        agent_id: str,
        session: Db,
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ):
        if not session.get(Agent, agent_id):
            raise HTTPException(404, "Agent nicht gefunden")
        query = (
            select(InventorySnapshot)
            .where(InventorySnapshot.agent_id == agent_id)
            .order_by(InventorySnapshot.received_at.desc(), InventorySnapshot.id)
        )
        return {
            "items": [
                {
                    "id": item.id,
                    "report_id": item.report_id,
                    "collected_at": utc(item.collected_at).isoformat(),
                    "received_at": utc(item.received_at).isoformat(),
                    "checksum": item.checksum,
                    "partial": item.partial,
                    "changes": item.changes,
                }
                for item in session.scalars(query.offset(offset).limit(limit))
            ],
            "total": session.scalar(select(func.count()).select_from(query.subquery())),
        }

    @router.get("/api/agents/{agent_id}/snapshots/{snapshot_id}", dependencies=admin)
    def snapshot_detail(agent_id: str, snapshot_id: str, session: Db):
        item = session.scalar(
            select(InventorySnapshot).where(
                InventorySnapshot.agent_id == agent_id, InventorySnapshot.id == snapshot_id
            )
        )
        if not item:
            raise HTTPException(404, "Inventarbericht nicht gefunden")
        events = session.scalars(
            select(InventoryChange)
            .where(InventoryChange.snapshot_id == item.id)
            .order_by(InventoryChange.id)
        ).all()
        return {
            "id": item.id,
            "checksum": item.checksum,
            "payload": item.payload,
            "changes": [
                {
                    "kind": event.kind,
                    "installation_id": event.installation_id,
                    "before": event.before,
                    "after": event.after,
                }
                for event in events
            ],
        }

    def inventory_agent(
        session: Db,
        authorization: Annotated[str | None, Header()] = None,
        x_mycve_agent_id: Annotated[str | None, Header()] = None,
    ) -> Agent:
        token = authorization.removeprefix("Bearer ") if authorization else ""
        if not token.startswith("mycve_agent_") or len(token) > 200:
            raise HTTPException(401, "Agent-Schlüssel erforderlich")
        agent = session.scalar(
            select(Agent).where(Agent.token_hash == token_hash(token)).with_for_update()
        )
        if not agent or agent.revoked_at:
            raise HTTPException(401, "Agent-Schlüssel ungültig oder widerrufen")
        if x_mycve_agent_id and x_mycve_agent_id != agent.id:
            raise HTTPException(401, "Agent-ID und Schlüssel gehören nicht zusammen")
        return agent

    AuthenticatedAgent = Annotated[Agent, Depends(inventory_agent)]

    @router.post("/api/agent/inventory")
    def receive_inventory(
        body: InventoryInput, request: Request, session: Db, agent: AuthenticatedAgent
    ):
        recent = session.scalar(
            select(func.count())
            .select_from(InventorySnapshot)
            .where(
                InventorySnapshot.agent_id == agent.id,
                InventorySnapshot.received_at > now() - timedelta(minutes=1),
            )
        )
        replay = session.scalar(
            select(InventorySnapshot.id).where(
                InventorySnapshot.agent_id == agent.id,
                InventorySnapshot.report_id == str(body.snapshot_id),
            )
        )
        if recent >= request.app.state.settings.agent_max_snapshots_per_minute and not replay:
            raise HTTPException(
                429,
                "Zu viele Inventarberichte; später erneut versuchen",
                headers={"Retry-After": "60"},
            )
        result = ingest_inventory(session, agent, body)
        session.commit()
        return {
            **result,
            "next_report_seconds": request.app.state.settings.agent_report_interval_seconds,
        }

    return router
