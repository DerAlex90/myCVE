from sqlalchemy import select, text

from mycve.core.matching import match_osv
from mycve.core.models import Affectedness, Component, MatchResult
from mycve.server.config import Settings
from mycve.server.db import (
    Agent,
    Alias,
    Finding,
    Installation,
    ScanJob,
    SourceRecord,
    Vulnerability,
    now,
    require,
)
from mycve.server.feeds import CVE_PATTERN, KEV_URL, OSV_BASE, FeedClient, FeedError
from mycve.server.services import (
    aliases_for,
    checksum,
    evaluate,
    record_source,
    refresh_summary,
    resolve_vulnerability,
)


def run_scan(session_factory, settings: Settings, job_id: str, client: FeedClient | None = None):
    """Refresh known records as well as new matches. A failed source never clears findings."""
    with session_factory() as session:
        job = session.get(ScanJob, job_id)
        if not job or job.status != "queued":
            return
        # A dedicated PostgreSQL session lock also serializes manual/worker scans.
        lock_connection = None
        locked = False
        if session.get_bind().dialect.name == "postgresql":
            lock_connection = session.get_bind().connect()
            locked = bool(lock_connection.scalar(text("SELECT pg_try_advisory_lock(77103921)")))
            if not locked:
                lock_connection.close()
                job.status, job.error, job.completed_at = (
                    "failed",
                    "Ein anderer Scan läuft bereits",
                    now(),
                )
                session.commit()
                return
        job.status, job.started_at = "running", now()
        session.commit()
        owned_client = client is None
        client = client or FeedClient(
            timeout=settings.feed_timeout, nvd_api_key=settings.nvd_api_key
        )
        errors: list[str] = []
        counts = {"packages": 0, "osv": 0, "cve": 0, "nvd": 0, "bsi": 0, "findings": 0}
        source_states = {}

        def error(source, exc):
            errors.append(
                f"{source}: {exc}"
                if isinstance(exc, FeedError)
                else f"{source}: Quelldaten konnten nicht verarbeitet werden ({type(exc).__name__})"
            )
            source_states[source] = "error"

        try:
            query = select(Installation).where(Installation.active.is_(True))
            if job.asset_id:
                query = query.where(Installation.asset_id == job.asset_id)
            installations = session.scalars(query).all()
            inventory_before = {item.id: checksum(item.component) for item in installations}
            cpe_hits: dict[str, set[str]] = {}
            cpe_cache: dict[str, list[dict]] = {}
            # CPE lookups discover candidates for classic software independently of OSV.
            for installation in installations:
                cpe = installation.component.get("cpe")
                if not cpe:
                    continue
                try:
                    if cpe not in cpe_cache:
                        cpe_cache[cpe] = client.nvd_cpe(cpe)
                    for candidate in cpe_cache[cpe]:
                        vulnerability = resolve_vulnerability(session, [candidate["id"]])
                        record_source(
                            session,
                            vulnerability,
                            source="NVD",
                            external_id=candidate["id"],
                            payload=candidate,
                            url=f"https://nvd.nist.gov/vuln/detail/{candidate['id']}",
                            modified=candidate.get("lastModified"),
                        )
                        cpe_hits.setdefault(installation.id, set()).add(vulnerability.id)
                    source_states.setdefault("NVD", "ok")
                except (FeedError, ValueError, KeyError, TypeError) as exc:
                    error("NVD", exc)
            session.commit()
            packages = sorted(
                {
                    (
                        item.component.get("ecosystem"),
                        item.component["name"],
                        item.component.get("version"),
                    )
                    for item in installations
                    if item.component.get("ecosystem")
                },
                key=str,
            )
            counts["packages"] = len(packages)
            observations = {}
            try:
                observations = client.osv_batch(packages)
                source_states["OSV"] = "ok"
            except (FeedError, ValueError, KeyError, TypeError) as exc:
                error("OSV", exc)
            returned_ids = {alias for ids in observations.values() for alias in ids}
            tracked_ids = set(
                session.scalars(
                    select(SourceRecord.external_id).where(
                        SourceRecord.source == "OSV", SourceRecord.current.is_(True)
                    )
                )
            )
            for alias in sorted(returned_ids | tracked_ids):
                try:
                    payload = client.osv_details(alias)
                    vulnerability = resolve_vulnerability(
                        session, [payload["id"], *payload.get("aliases", [])]
                    )
                    record_source(
                        session,
                        vulnerability,
                        source="OSV",
                        external_id=payload["id"],
                        payload=payload,
                        url=OSV_BASE + "/vulns/" + payload["id"],
                        modified=payload.get("modified"),
                    )
                    counts["osv"] += 1
                except (FeedError, ValueError, KeyError, TypeError) as exc:
                    error("OSV", exc)
            session.commit()

            # Include explicit CVE watches and previously known CVEs on every refresh.
            cve_ids = {
                alias
                for alias in session.scalars(select(Alias.alias))
                if CVE_PATTERN.fullmatch(alias)
            }
            for alias in sorted(cve_ids):
                for source in ("CVE Program", "NVD"):
                    try:
                        enrichment = (
                            client.cve(alias) if source == "CVE Program" else client.nvd(alias)
                        )
                        if enrichment is not None:
                            vulnerability = resolve_vulnerability(session, [alias])
                            if source == "CVE Program":
                                url = f"https://www.cve.org/CVERecord?id={alias}"
                                modified = enrichment.get("cveMetadata", {}).get("dateUpdated")
                            else:
                                url = f"https://nvd.nist.gov/vuln/detail/{alias}"
                                modified = enrichment.get("lastModified")
                            record_source(
                                session,
                                vulnerability,
                                source=source,
                                external_id=alias,
                                payload=enrichment,
                                url=url,
                                modified=modified,
                            )
                            counts["cve" if source == "CVE Program" else "nvd"] += 1
                        source_states.setdefault(source, "ok")
                    except (FeedError, ValueError, KeyError, TypeError) as exc:
                        error(source, exc)
                session.commit()

            try:
                catalog = client.kev()
                kev = {entry["cveID"]: entry for entry in catalog["vulnerabilities"]}
                # Reset only after a complete, validated KEV catalog was received.
                for vulnerability in session.scalars(select(Vulnerability)):
                    entry = next(
                        (
                            kev[alias]
                            for alias in aliases_for(session, vulnerability.id)
                            if alias in kev
                        ),
                        None,
                    )
                    vulnerability.kev = entry is not None
                    vulnerability.kev_due_date = entry.get("dueDate") if entry else None
                    if not entry:
                        for record in session.scalars(
                            select(SourceRecord).where(
                                SourceRecord.vulnerability_id == vulnerability.id,
                                SourceRecord.source == "CISA KEV",
                                SourceRecord.current.is_(True),
                            )
                        ):
                            record.current = False
                    if entry:
                        record_source(
                            session,
                            vulnerability,
                            source="CISA KEV",
                            external_id=entry["cveID"],
                            payload=entry,
                            url=getattr(client, "kev_url", KEV_URL),
                            modified=catalog.get("dateReleased"),
                        )
                source_states["CISA KEV"] = "ok"
                session.commit()
            except (FeedError, ValueError, KeyError, TypeError) as exc:
                error("CISA KEV", exc)

            try:
                known_urls = list(
                    session.scalars(
                        select(SourceRecord.url).where(
                            SourceRecord.source == "BSI CSAF", SourceRecord.current.is_(True)
                        )
                    ).unique()
                )
                documents, skipped = client.bsi_documents(
                    cve_ids, known_urls=known_urls, limit=settings.bsi_max_documents
                )
                for url, document in documents:
                    document_id = document.get("document", {}).get("tracking", {}).get("id", url)
                    modified = (
                        document.get("document", {}).get("tracking", {}).get("current_release_date")
                    )
                    for item in document.get("vulnerabilities", []):
                        alias = item.get("cve")
                        if alias in cve_ids:
                            vulnerability = resolve_vulnerability(session, [alias])
                            record_source(
                                session,
                                vulnerability,
                                source="BSI CSAF",
                                external_id=f"{document_id}:{alias}",
                                payload=document,
                                url=url,
                                modified=modified,
                            )
                    counts["bsi"] += 1
                source_states["BSI CSAF"] = "ok"
                if skipped:
                    errors.append(
                        f"BSI CSAF: {skipped} weitere Dokumente; MYCVE_BSI_MAX_DOCUMENTS erhöhen"
                    )
                    source_states["BSI CSAF"] = "partial"
                session.commit()
            except (FeedError, ValueError, KeyError, TypeError) as exc:
                error("BSI CSAF", exc)

            # Fetch current inventory after network work so concurrent imports cannot leave an old checked version.
            session.expire_all()
            installations = session.scalars(query).all()
            if inventory_before != {item.id: checksum(item.component) for item in installations}:
                errors.append(
                    "Inventar wurde während des Scans geändert; einen weiteren Abgleich starten"
                )
                source_states["Inventar"] = "partial"
            for vulnerability in session.scalars(select(Vulnerability)):
                refresh_summary(session, vulnerability)
            session.flush()
            for installation in installations:
                component = Component.model_validate(installation.component)
                package = (component.ecosystem, component.name, component.version)
                ids = observations.get(package)
                found_vulnerabilities: set[str] = set()
                if ids is not None:
                    found_vulnerabilities = (
                        set(
                            session.scalars(
                                select(Alias.vulnerability_id).where(Alias.alias.in_(ids))
                            )
                        )
                        if ids
                        else set()
                    )
                previous = set(
                    session.scalars(
                        select(Finding.vulnerability_id).where(
                            Finding.installation_id == installation.id
                        )
                    )
                )
                for vulnerability_id in sorted(
                    found_vulnerabilities | previous | cpe_hits.get(installation.id, set())
                ):
                    vulnerability = require(session, Vulnerability, vulnerability_id)
                    observation = None
                    fixed_versions = []
                    related_osv = session.scalars(
                        select(SourceRecord).where(
                            SourceRecord.vulnerability_id == vulnerability_id,
                            SourceRecord.source == "OSV",
                            SourceRecord.current.is_(True),
                        )
                    ).all()
                    has_matching_osv = False
                    all_withdrawn = bool(related_osv) and all(
                        record.payload.get("withdrawn") for record in related_osv
                    )
                    for record in related_osv:
                        result = match_osv(component, record.payload)
                        if result.reason != "Paketidentität nicht eindeutig passend":
                            has_matching_osv = True
                            fixed_versions.extend(result.fixed_versions)
                    if ids is not None and component.version and has_matching_osv:
                        is_affected = (
                            vulnerability_id in found_vulnerabilities and not all_withdrawn
                        )
                        observation = MatchResult(
                            status=Affectedness.AFFECTED
                            if is_affected
                            else Affectedness.NOT_AFFECTED,
                            source="OSV",
                            reason="OSV bestätigt exaktes Paket und installierte Version"
                            if is_affected
                            else "Vollständige OSV-Versionsabfrage liefert diese Meldung nicht mehr",
                            fixed_versions=sorted(set(fixed_versions)),
                        )
                    evaluate(session, installation, vulnerability, observation=observation)
                    counts["findings"] += 1
            # Reevaluate other existing findings too: global sources may have changed.
            scanned = {installation.id for installation in installations}
            for finding in session.scalars(select(Finding)).all():
                if finding.installation_id not in scanned:
                    evaluate(
                        session,
                        require(session, Installation, finding.installation_id),
                        require(session, Vulnerability, finding.vulnerability_id),
                    )
            job.status = "partial" if errors else "succeeded"
            if not errors and job.asset_id is None:
                for agent in session.scalars(
                    select(Agent).where(
                        Agent.scan_pending.is_(True), Agent.last_inventory_at <= job.started_at
                    )
                ):
                    agent.scan_pending = False
            job.result = {"counts": counts, "sources": source_states, "errors": errors[:100]}
            job.completed_at = now()
            session.commit()
        except Exception as exc:
            session.rollback()
            job = session.get(ScanJob, job_id)
            job.status, job.error, job.completed_at = (
                "failed",
                f"Scan abgebrochen ({type(exc).__name__}); bereits gespeicherte Quelldaten bleiben erhalten",
                now(),
            )
            session.commit()
        finally:
            if owned_client:
                client.client.close()
            if locked:
                assert lock_connection is not None
                lock_connection.execute(text("SELECT pg_advisory_unlock(77103921)"))
                lock_connection.close()
