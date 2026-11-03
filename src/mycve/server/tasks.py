# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from datetime import timedelta

from celery import Celery
from sqlalchemy import select

from mycve.server.config import Settings
from mycve.server.db import Agent, Installation, ScanJob, make_engine, now, sessions
from mycve.server.identification import due_filter
from mycve.server.scanner import run_scan
from mycve.server.services import recover_stale_jobs

settings = Settings()
celery = Celery("mycve", broker=settings.redis_url, backend=settings.redis_url)
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    result_expires=86400,
    beat_schedule={
        "refresh-known-vulnerabilities": {
            "task": "mycve.refresh",
            "schedule": settings.sync_interval_hours * 3600,
        },
        "refresh-agent-inventory": {"task": "mycve.refresh_agents", "schedule": 60},
    },
)


@celery.task(name="mycve.scan", soft_time_limit=7000, time_limit=7200)
def scan(job_id: str):
    engine = make_engine(settings.database_url)
    try:
        run_scan(sessions(engine), settings, job_id)
    finally:
        engine.dispose()


@celery.task(name="mycve.refresh")
def refresh():
    engine = make_engine(settings.database_url)
    try:
        with sessions(engine)() as session:
            recover_stale_jobs(session)
            session.commit()
            pending = session.scalar(
                select(ScanJob).where(ScanJob.status.in_(["queued", "running"]))
            )
            if pending:
                return
            job = ScanJob()
            session.add(job)
            session.commit()
            job_id = job.id
        scan.delay(job_id)
    finally:
        engine.dispose()


@celery.task(name="mycve.refresh_agents")
def refresh_agents():
    engine = make_engine(settings.database_url)
    try:
        with sessions(engine)() as session:
            recover_stale_jobs(session)
            session.commit()
            pending = session.scalar(
                select(Agent.id).where(Agent.scan_pending.is_(True), Agent.revoked_at.is_(None))
            )
            unidentified = session.scalar(select(Installation.id).where(due_filter()).limit(1))
            running = session.scalar(
                select(ScanJob.id).where(ScanJob.status.in_(["queued", "running"]))
            )
            recent = session.scalar(
                select(ScanJob.id).where(ScanJob.created_at > now() - timedelta(minutes=5))
            )
            if (not pending and not unidentified) or running or recent:
                return
            job = ScanJob()
            session.add(job)
            session.commit()
            job_id = job.id
        scan.delay(job_id)
    finally:
        engine.dispose()
