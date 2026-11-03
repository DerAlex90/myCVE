# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

import csv
import io
import secrets
from contextlib import asynccontextmanager
from typing import Annotated, Literal

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mycve import __version__
from mycve.core.importers import import_inventory
from mycve.legal import AUTHOR, COPYRIGHT, LICENSE_ID, PROJECT_URL, license_text
from mycve.server.agents import create_agent_router
from mycve.server.config import Settings
from mycve.server.db import (
    Alias,
    Asset,
    Base,
    Finding,
    FindingEvent,
    Installation,
    ScanJob,
    SourceRecord,
    Vulnerability,
    make_engine,
    now,
    require,
    sessions,
)
from mycve.server.identification import coverage, effective_component, incomplete_filter
from mycve.server.migrate import migrate_schema
from mycve.server.scanner import run_scan
from mycve.server.services import (
    aliases_for,
    evaluate,
    finding_snapshot,
    import_components,
    recover_stale_jobs,
    resolve_vulnerability,
)


class AssetInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=200)
    owner: str = Field(default="", max_length=200)
    environment: str = Field(default="production", min_length=1, max_length=100)
    exposure: Literal["internet", "internal", "isolated"] = "internal"
    criticality: Literal["high", "medium", "low"] = "medium"


class FindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow: Literal["open", "in_progress", "accepted", "resolved"]
    notes: str = Field(default="", max_length=10000)


class ScanInput(BaseModel):
    asset_id: str | None = None


class WatchInput(BaseModel):
    installation_id: str
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")


def create_app(settings: Settings | None = None, engine=None) -> FastAPI:
    settings = settings or Settings()
    engine = engine or make_engine(settings.database_url)
    factory = sessions(engine)

    @asynccontextmanager
    async def lifespan(_app):
        if not settings.api_key and not settings.allow_unauthenticated:
            raise RuntimeError(
                "MYCVE_API_KEY setzen oder für lokalen Betrieb MYCVE_ALLOW_UNAUTHENTICATED=true verwenden"
            )
        if engine.dialect.name == "sqlite":
            if not engine.url.database or engine.url.database == ":memory:":
                Base.metadata.create_all(engine)
            else:
                migrate_schema(engine)
        yield
        engine.dispose()

    app = FastAPI(
        title="myCVE API",
        version=__version__,
        lifespan=lifespan,
        description="Inventar, nachvollziehbare Betroffenheit, Priorisierung und Quellenhistorie.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.sessions, app.state.settings = factory, settings

    def authenticated(authorization: Annotated[str | None, Header()] = None):
        if not settings.api_key:
            if settings.allow_unauthenticated:
                return
            raise HTTPException(503, "Authentifizierung ist nicht konfiguriert")
        token = authorization.removeprefix("Bearer ") if authorization else ""
        if not secrets.compare_digest(token.encode(), settings.api_key.encode()):
            raise HTTPException(
                401, "API-Schlüssel fehlt oder ist ungültig", headers={"WWW-Authenticate": "Bearer"}
            )

    def db():
        with factory() as session:
            yield session

    Db = Annotated[Session, Depends(db)]
    auth = [Depends(authenticated)]
    app.include_router(create_agent_router(authenticated, db))

    @app.middleware("http")
    async def headers(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_upload_bytes + 100000:
            return Response("Upload zu groß", status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health(session: Db):
        session.execute(text("SELECT 1"))
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    def config():
        return {
            "authentication_required": bool(settings.api_key),
            "demo": settings.demo_mode,
            "version": __version__,
        }

    @app.get("/api/openapi.json", dependencies=auth)
    def schema():
        return app.openapi()

    @app.get("/api/license")
    def license_info():
        return {
            "author": AUTHOR,
            "copyright": COPYRIGHT,
            "license": LICENSE_ID,
            "project_url": PROJECT_URL,
            "text": license_text(),
        }

    @app.get("/license", response_class=PlainTextResponse)
    def public_license():
        return license_text()

    def asset_json(session, asset):
        return {
            "id": asset.id,
            **{
                key: getattr(asset, key)
                for key in ("name", "owner", "environment", "exposure", "criticality")
            },
            "components": session.scalar(
                select(func.count())
                .select_from(Installation)
                .where(Installation.asset_id == asset.id, Installation.active.is_(True))
            ),
            "open_findings": session.scalar(
                select(func.count())
                .select_from(Finding)
                .join(Installation)
                .where(
                    Installation.asset_id == asset.id,
                    Installation.active.is_(True),
                    Finding.status != "not_affected",
                    Finding.workflow != "resolved",
                )
            ),
        }

    @app.get("/api/assets", dependencies=auth)
    def assets(session: Db):
        return [
            asset_json(session, asset)
            for asset in session.scalars(select(Asset).order_by(Asset.name))
        ]

    @app.post("/api/assets", dependencies=auth, status_code=201)
    def create_asset(body: AssetInput, session: Db):
        asset = Asset(**body.model_dump())
        session.add(asset)
        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise HTTPException(409, "Ein System mit diesem Namen existiert bereits") from exc
        return asset_json(session, asset)

    @app.put("/api/assets/{asset_id}", dependencies=auth)
    def edit_asset(asset_id: str, body: AssetInput, session: Db):
        asset = session.get(Asset, asset_id)
        if not asset:
            raise HTTPException(404, "System nicht gefunden")
        for key, value in body.model_dump().items():
            setattr(asset, key, value)
        try:
            session.flush()
            for finding in session.scalars(
                select(Finding).join(Installation).where(Installation.asset_id == asset_id)
            ).all():
                evaluate(
                    session,
                    require(session, Installation, finding.installation_id),
                    require(session, Vulnerability, finding.vulnerability_id),
                )
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise HTTPException(409, "Ein System mit diesem Namen existiert bereits") from exc
        return asset_json(session, asset)

    @app.get("/api/assets/{asset_id}/components", dependencies=auth)
    def components(
        asset_id: str,
        session: Db,
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ):
        if not session.get(Asset, asset_id):
            raise HTTPException(404, "System nicht gefunden")
        query = (
            select(Installation)
            .where(Installation.asset_id == asset_id, Installation.active.is_(True))
            .order_by(Installation.id)
        )
        return {
            "items": [
                {
                    "id": item.id,
                    **effective_component(item).model_dump(),
                    "origin": item.origin,
                    "inventory": item.inventory,
                    "identification": item.identification,
                }
                for item in session.scalars(query.offset(offset).limit(limit))
            ],
            "total": session.scalar(select(func.count()).select_from(query.subquery())),
        }

    @app.post("/api/assets/{asset_id}/import", dependencies=auth)
    async def import_asset(
        asset_id: str, session: Db, file: UploadFile = File(), replace: bool = True
    ):
        asset = session.get(Asset, asset_id)
        if not asset:
            raise HTTPException(404, "System nicht gefunden")
        content = await file.read(settings.max_upload_bytes + 1)
        if len(content) > settings.max_upload_bytes:
            raise HTTPException(413, "Datei überschreitet die erlaubte Größe")
        try:
            parsed = import_inventory(content, file.filename or "inventory.json")
            count = import_components(session, asset, parsed, replace=replace)
            session.commit()
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            session.rollback()
            raise HTTPException(422, f"Import ungültig: {str(exc)[:500]}") from exc
        return {"imported": count, "replace": replace, "asset_id": asset_id}

    def findings_query(search="", status=None, priority=None, workflow=None, asset_id=None):
        query = (
            select(Finding, Vulnerability, Installation, Asset)
            .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
            .join(Installation, Installation.id == Finding.installation_id)
            .join(Asset, Asset.id == Installation.asset_id)
        )
        if search:
            # Escape SQL LIKE metacharacters; parameter binding handles SQL syntax.
            value = "%" + search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%"
            query = query.where(
                or_(
                    Vulnerability.primary_alias.ilike(value, escape="\\"),
                    Vulnerability.id.in_(
                        select(Alias.vulnerability_id).where(Alias.alias.ilike(value, escape="\\"))
                    ),
                    Vulnerability.title.ilike(value, escape="\\"),
                    Asset.name.ilike(value, escape="\\"),
                )
            )
        for column, value in (
            (Finding.status, status),
            (Finding.priority, priority),
            (Finding.workflow, workflow),
            (Asset.id, asset_id),
        ):
            if value:
                query = query.where(column == value)
        return query.order_by(Finding.priority, Finding.updated_at.desc(), Finding.id)

    def finding_json(session, finding, vulnerability, installation, asset):
        return {
            "id": finding.id,
            "vulnerability_id": vulnerability.id,
            "alias": vulnerability.primary_alias,
            "aliases": aliases_for(session, vulnerability.id),
            "title": vulnerability.title,
            "description": vulnerability.description,
            "cvss": vulnerability.cvss,
            "kev": vulnerability.kev,
            "kev_due_date": vulnerability.kev_due_date,
            "component": effective_component(installation).model_dump(),
            "identification": installation.identification,
            "installation_active": installation.active,
            "asset_id": asset.id,
            "asset_name": asset.name,
            "exposure": asset.exposure,
            "criticality": asset.criticality,
            **finding_snapshot(finding),
            "updated_at": finding.updated_at.isoformat(),
            "evaluated_at": finding.evaluated_at.isoformat(),
        }

    @app.get("/api/findings", dependencies=auth)
    def findings(
        session: Db,
        search: str = Query("", max_length=200),
        status: str | None = None,
        priority: str | None = None,
        workflow: str | None = None,
        asset_id: str | None = None,
        limit: int = Query(30, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        query = findings_query(search, status, priority, workflow, asset_id)
        total = session.scalar(select(func.count()).select_from(query.subquery()))
        return {
            "items": [
                finding_json(session, *row)
                for row in session.execute(query.offset(offset).limit(limit))
            ],
            "total": total,
        }

    @app.get("/api/findings/export.csv", dependencies=auth)
    def export(session: Db):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "ID",
                "System",
                "Paket",
                "Version",
                "Betroffenheit",
                "Priorität",
                "KEV",
                "CVSS",
                "Status",
                "Begründung",
            ]
        )

        def cell(value):
            value = str(value if value is not None else "")
            return (
                "'" + value
                if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r"))
                else value
            )

        for finding, vulnerability, installation, asset in session.execute(findings_query()):
            writer.writerow(
                [
                    cell(value)
                    for value in [
                        vulnerability.primary_alias,
                        asset.name,
                        installation.component["name"],
                        installation.component.get("version"),
                        finding.status,
                        finding.priority,
                        vulnerability.kev,
                        vulnerability.cvss,
                        finding.workflow,
                        finding.reason,
                    ]
                ]
            )
        return Response(
            "\ufeff" + output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="mycve-findings.csv"'},
        )

    @app.get("/api/findings/{finding_id}", dependencies=auth)
    def detail(finding_id: str, session: Db):
        row = session.execute(findings_query().where(Finding.id == finding_id)).first()
        if not row:
            raise HTTPException(404, "Finding nicht gefunden")
        result = finding_json(session, *row)
        result["history"] = [
            {
                "id": event.id,
                "action": event.action,
                "before": event.before,
                "after": event.after,
                "created_at": event.created_at.isoformat(),
            }
            for event in session.scalars(
                select(FindingEvent)
                .where(FindingEvent.finding_id == finding_id)
                .order_by(FindingEvent.created_at.desc())
            )
        ]
        result["sources"] = [
            {
                "id": record.id,
                "source": record.source,
                "external_id": record.external_id,
                "url": record.url,
                "checksum": record.checksum,
                "current": record.current,
                "source_modified": record.source_modified,
                "fetched_at": record.fetched_at.isoformat(),
                "last_seen_at": record.last_seen_at.isoformat(),
            }
            for record in session.scalars(
                select(SourceRecord)
                .where(SourceRecord.vulnerability_id == row[1].id)
                .order_by(SourceRecord.fetched_at.desc())
            )
        ]
        return result

    @app.patch("/api/findings/{finding_id}", dependencies=auth)
    def edit_finding(finding_id: str, body: FindingInput, session: Db):
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(404, "Finding nicht gefunden")
        before = finding_snapshot(finding)
        finding.workflow, finding.notes, finding.updated_at = body.workflow, body.notes, now()
        session.add(
            FindingEvent(
                finding_id=finding.id,
                action="workflow_updated",
                before=before,
                after=finding_snapshot(finding),
            )
        )
        session.commit()
        return {"id": finding.id, "workflow": finding.workflow, "notes": finding.notes}

    @app.get("/api/sources/{record_id}", dependencies=auth)
    def source(record_id: str, session: Db):
        record = session.get(SourceRecord, record_id)
        if not record:
            raise HTTPException(404, "Quelle nicht gefunden")
        return {"source": record.source, "checksum": record.checksum, "payload": record.payload}

    @app.post("/api/watches", dependencies=auth, status_code=201)
    def watch(body: WatchInput, session: Db):
        installation = session.get(Installation, body.installation_id)
        if not installation or not installation.active:
            raise HTTPException(404, "Aktive Installation nicht gefunden")
        vulnerability = resolve_vulnerability(session, [body.cve_id])
        finding = evaluate(session, installation, vulnerability)
        session.commit()
        return {"finding_id": finding.id}

    @app.get("/api/overview", dependencies=auth)
    def overview(session: Db):
        active = [
            Finding.status != "not_affected",
            Finding.workflow != "resolved",
            Installation.active.is_(True),
        ]
        query = select(Finding).join(Installation).where(*active)
        groups = dict(
            session.execute(
                select(Finding.priority, func.count())
                .join(Installation)
                .where(*active)
                .group_by(Finding.priority)
            ).all()
        )
        last = session.scalar(select(ScanJob).order_by(ScanJob.created_at.desc()))
        return {
            "assets": session.scalar(select(func.count()).select_from(Asset)),
            "components": session.scalar(
                select(func.count()).select_from(Installation).where(Installation.active.is_(True))
            ),
            "incomplete_components": session.scalar(
                select(func.count())
                .select_from(Installation)
                .where(
                    Installation.active.is_(True),
                    incomplete_filter(),
                )
            ),
            "identification": coverage(session),
            "open_findings": session.scalar(select(func.count()).select_from(query.subquery())),
            "affected": session.scalar(
                select(func.count()).select_from(
                    query.where(Finding.status == "affected").subquery()
                )
            ),
            "unknown": session.scalar(
                select(func.count()).select_from(
                    query.where(Finding.status == "unknown").subquery()
                )
            ),
            "kev": session.scalar(
                select(func.count()).select_from(
                    query.join(Vulnerability).where(Vulnerability.kev.is_(True)).subquery()
                )
            ),
            "priorities": groups,
            "last_scan": job_json(last) if last else None,
        }

    def job_json(job):
        return {
            "id": job.id,
            "status": job.status,
            "asset_id": job.asset_id,
            "created_at": job.created_at.isoformat(),
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "result": job.result,
            "error": job.error,
        }

    @app.get("/api/scans", dependencies=auth)
    def scans(session: Db):
        return [
            job_json(job)
            for job in session.scalars(
                select(ScanJob).order_by(ScanJob.created_at.desc()).limit(30)
            )
        ]

    @app.post("/api/scans", dependencies=auth, status_code=202)
    def start_scan(body: ScanInput, background: BackgroundTasks, session: Db):
        if settings.demo_mode:
            raise HTTPException(
                409,
                "Demo zeigt Beispieldaten. Für echte Scans eine eigene Installation mit eigenem Inventar starten.",
            )
        if body.asset_id and not session.get(Asset, body.asset_id):
            raise HTTPException(404, "System nicht gefunden")
        recover_stale_jobs(session)
        session.commit()
        running = session.scalar(select(ScanJob).where(ScanJob.status.in_(["queued", "running"])))
        if running:
            raise HTTPException(409, "Ein Scan ist bereits vorgemerkt oder läuft")
        job = ScanJob(asset_id=body.asset_id)
        session.add(job)
        session.commit()
        if settings.task_mode == "inline":
            background.add_task(run_scan, factory, settings, job.id)
        else:
            try:
                from mycve.server.tasks import scan

                scan.delay(job.id)
            except Exception as exc:
                job.status, job.error, job.completed_at = (
                    "failed",
                    "Hintergrunddienst nicht erreichbar; Redis und Worker prüfen",
                    now(),
                )
                session.commit()
                raise HTTPException(503, job.error) from exc
        return job_json(job)

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str):
        if path.startswith(("api/", "health/")):
            raise HTTPException(404)
        root = settings.frontend_dir.resolve()
        file = (root / path).resolve()
        if file.is_relative_to(root) and file.is_file():
            return FileResponse(file)
        index = root / "index.html"
        if index.is_file():
            return FileResponse(index)
        raise HTTPException(404, "Frontend fehlt: cd frontend && npm ci && npm run build")

    return app


app = create_app()
