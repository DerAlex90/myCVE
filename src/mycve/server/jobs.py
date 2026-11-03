# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""One serialized job-creation path for API, scheduler and CLI."""

from datetime import timedelta

from sqlalchemy import delete, select

from mycve.server.db import RuntimeState, ScanCache, ScanJob, now, uid


class ScanBusy(RuntimeError):
    pass


def heartbeat(session, name: str, data: dict | None = None):
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    insert = pg_insert if session.get_bind().dialect.name == "postgresql" else sqlite_insert
    statement = insert(RuntimeState).values(name=name, updated_at=now(), data=data or {})
    session.execute(
        statement.on_conflict_do_update(
            index_elements=[RuntimeState.name], set_={"updated_at": now(), "data": data or {}}
        )
    )


def create_job(session, *, asset_id=None, resume_id=None, reuse_partial=True, cache_hours=6):
    from mycve.server.services import recover_stale_jobs

    # The upsert takes a database row/write lock before examining active jobs.
    heartbeat(session, "scan-dispatch")
    recover_stale_jobs(session)
    if session.scalar(select(ScanJob.id).where(ScanJob.status.in_(["queued", "running"]))):
        raise ScanBusy("Ein Scan ist bereits vorgemerkt oder läuft")
    previous = None
    if resume_id:
        previous = session.get(ScanJob, resume_id)
        if not previous or previous.status not in {"partial", "failed", "cancelled"}:
            raise ValueError("Nur teilweise, fehlgeschlagene oder abgebrochene Scans fortsetzen")
        asset_id = previous.asset_id
    elif reuse_partial:
        latest = (
            select(ScanJob.id)
            .where(ScanJob.asset_id == asset_id)
            .order_by(ScanJob.created_at.desc())
            .limit(1)
            .scalar_subquery()
        )
        previous = session.scalar(
            select(ScanJob)
            .where(
                ScanJob.id == latest,
                ScanJob.asset_id == asset_id,
                ScanJob.status.in_(["partial", "failed"]),
                ScanJob.created_at >= now() - timedelta(hours=cache_hours),
            )
            .order_by(ScanJob.created_at.desc())
            .limit(1)
        )
    job = ScanJob(
        asset_id=asset_id,
        resume_of=previous.id if previous else None,
        cache_scope=(previous.cache_scope or previous.id) if previous else uid(),
    )
    session.add(job)
    session.execute(delete(ScanCache).where(ScanCache.created_at < now() - timedelta(hours=24)))
    session.commit()
    return job


def enqueue(session, settings, *, factory=None, background=None, dispatch=None, **options):
    job = create_job(session, cache_hours=settings.scan_cache_hours, **options)
    try:
        if settings.task_mode == "inline":
            from mycve.server.scanner import run_scan

            if background is not None:
                background.add_task(run_scan, factory, settings, job.id)
            else:
                run_scan(factory, settings, job.id)
        else:
            if dispatch is None:
                from mycve.server.tasks import scan

                dispatch = scan.delay
            dispatch(job.id)
    except Exception:
        session.rollback()
        job = session.get(ScanJob, job.id)
        job.status, job.error, job.completed_at = (
            "failed",
            "Hintergrunddienst nicht erreichbar; Redis und Worker prüfen",
            now(),
        )
        session.commit()
        raise RuntimeError(job.error) from None
    return job
