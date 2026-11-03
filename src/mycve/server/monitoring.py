# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from datetime import UTC, timedelta

from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from mycve.server.db import RuntimeState, ScanJob, now


def operations(session, settings):
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        session.rollback()
        return {
            "status": "degraded",
            "checked_at": now().isoformat(),
            "checks": {
                "database": {"status": "error", "reason": "Datenbank nicht erreichbar"},
                **{
                    name: {"status": "unknown"}
                    for name in (
                        "redis",
                        "worker",
                        "scheduler",
                        "last_successful_scan",
                        "latest_scan",
                    )
                },
            },
        }
    checks: dict = {"database": {"status": "ok"}}
    if settings.task_mode == "inline":
        checks.update(
            {name: {"status": "not_required"} for name in ("redis", "worker", "scheduler")}
        )
    else:
        try:
            import redis

            connection = redis.Redis.from_url(
                settings.redis_url, socket_connect_timeout=1, socket_timeout=1
            )
            try:
                connection.ping()
                checks["redis"] = {"status": "ok", "queue_length": connection.llen("celery")}
            finally:
                connection.close()
        except Exception:
            checks["redis"] = {"status": "error", "reason": "Broker nicht erreichbar"}
        for name in ("worker", "scheduler"):
            state = session.get(RuntimeState, name)
            stamp = (
                state.updated_at.replace(tzinfo=UTC)
                if state and state.updated_at.tzinfo is None
                else state.updated_at
                if state
                else None
            )
            checks[name] = {
                "status": "ok" if stamp and stamp >= now() - timedelta(minutes=3) else "stale",
                "last_seen_at": stamp.isoformat() if stamp else None,
            }
    last = session.scalar(
        select(ScanJob)
        .where(ScanJob.status == "succeeded", ScanJob.asset_id.is_(None))
        .order_by(ScanJob.completed_at.desc())
        .limit(1)
    )
    stamp = (
        last.completed_at.replace(tzinfo=UTC)
        if last and last.completed_at and last.completed_at.tzinfo is None
        else last.completed_at
        if last
        else None
    )
    checks["last_successful_scan"] = {
        "status": "ok"
        if stamp and stamp >= now() - timedelta(hours=settings.sync_interval_hours * 2)
        else "stale",
        "completed_at": stamp.isoformat() if stamp else None,
    }
    latest = session.scalar(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(1))
    checks["latest_scan"] = {
        "status": "error" if latest and latest.status in {"partial", "failed"} else "ok",
        "job_status": latest.status if latest else None,
        "source_errors": latest.result.get("errors", []) if latest else [],
    }
    healthy = all(value["status"] in {"ok", "not_required"} for value in checks.values())
    return {
        "status": "ok" if healthy else "degraded",
        "checked_at": now().isoformat(),
        "checks": checks,
    }
