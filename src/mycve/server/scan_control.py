# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Persistent successful feed results and cooperative cancellation at bounded checkpoints."""

import hashlib
import json
import time
from datetime import timedelta

from sqlalchemy import func, select

from mycve.server.db import ScanCache, ScanJob, now
from mycve.server.jobs import heartbeat


class ScanCancelled(Exception):
    pass


class ScanControl:
    def __init__(self, session, job, counts, sources, errors):
        self.session, self.job = session, job
        self.counts, self.sources, self.errors = counts, sources, errors
        self.last_check = self.last_write = 0.0
        self.phase = "prepare"
        self.completed, self.total = 0, None

    def check(self, *, force=False):
        tick = time.monotonic()
        if force or tick - self.last_check >= 1:
            self.last_check = tick
            requested = self.session.scalar(
                select(ScanJob.cancel_requested).where(ScanJob.id == self.job.id)
            )
            if requested:
                raise ScanCancelled()

    def pulse(self, phase=None, completed=None, total=None, *, force=False):
        self.check(force=force)
        if phase is not None:
            self.phase = phase
        if completed is not None:
            self.completed = completed
        if phase is not None or total is not None:
            self.total = total
        tick = time.monotonic()
        if force or tick - self.last_write >= 2:
            self.last_write = tick
            stamp = now()
            self.job.heartbeat_at = stamp
            self.job.progress = {
                "phase": self.phase,
                "completed": self.completed,
                "total": self.total,
                "updated_at": stamp.isoformat(),
            }
            self.job.result = {
                "counts": dict(self.counts),
                "sources": dict(self.sources),
                "errors": list(self.errors[:100]),
            }
            heartbeat(self.session, "worker", {"job_id": self.job.id, "phase": self.phase})
            self.session.commit()


def canonical(value):
    if isinstance(value, dict):
        return {
            str(key): canonical(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, set):
        return sorted(canonical(item) for item in value)
    if isinstance(value, (tuple, list)):
        return [canonical(item) for item in value]
    return value


class CachedFeeds:
    METHODS = {
        "osv_batch",
        "osv_details",
        "cve",
        "nvd",
        "kev",
        "bsi_documents",
        "cpe_dictionary",
        "nvd_cpe",
    }

    def __init__(self, feed, session, job, control, hours):
        self.feed, self.session, self.job, self.control = feed, session, job, control
        self.hours = hours
        self.last_entry = None
        self.kev_url = getattr(feed, "kev_url", None)
        self.last_other_scan = session.scalar(
            select(func.max(ScanJob.completed_at)).where(
                ScanJob.cache_scope != job.cache_scope, ScanJob.id != job.id
            )
        )
        feed.check_cancel = control.check

    def discard_last(self):
        if self.last_entry is not None:
            self.session.delete(self.last_entry)
            self.session.commit()
            self.last_entry = None

    def __getattr__(self, name):
        method = getattr(self.feed, name)
        if name not in self.METHODS:
            return method

        def call(*args, **kwargs):
            self.control.check(force=True)
            key = hashlib.sha256(
                json.dumps(canonical([name, args, kwargs]), sort_keys=True).encode()
            ).hexdigest()
            entry = self.session.scalar(
                select(ScanCache).where(
                    ScanCache.scope == (self.job.cache_scope or self.job.id),
                    ScanCache.key == key,
                    ScanCache.created_at >= now() - timedelta(hours=self.hours),
                    *(
                        [ScanCache.created_at >= self.last_other_scan]
                        if self.last_other_scan
                        else []
                    ),
                )
            )
            if entry is not None:
                self.control.counts["cache_hits"] = self.control.counts.get("cache_hits", 0) + 1
                payload = entry.payload
                self.last_entry = entry
            else:
                self.last_entry = None
                self.control.counts["feed_requests"] = (
                    self.control.counts.get("feed_requests", 0) + 1
                )
                value = method(*args, **kwargs)
                encoded = (
                    [[list(package), ids] for package, ids in value.items()]
                    if name == "osv_batch"
                    else canonical(value)
                )
                payload = {"value": encoded, "kev_url": getattr(self.feed, "kev_url", None)}
                if len(json.dumps(payload)) <= 32_000_000:
                    # Replace an expired entry in this scope without retaining duplicate payloads.
                    old = self.session.scalar(
                        select(ScanCache).where(
                            ScanCache.scope == (self.job.cache_scope or self.job.id),
                            ScanCache.key == key,
                        )
                    )
                    if old is not None:
                        self.session.delete(old)
                        self.session.flush()
                    entry = ScanCache(
                        scope=self.job.cache_scope or self.job.id, key=key, payload=payload
                    )
                    self.session.add(entry)
                    self.session.commit()
                    self.last_entry = entry
            if name == "kev":
                self.kev_url = payload.get("kev_url") or getattr(
                    self.feed,
                    "kev_url",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                )
            self.control.pulse()
            value = payload["value"]
            return {tuple(package): ids for package, ids in value} if name == "osv_batch" else value

        return call
