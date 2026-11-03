import hashlib
import json
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from mycve.core.cpe import match_nvd
from mycve.core.csaf import match_csaf
from mycve.core.cve import match_cve
from mycve.core.identity import canonical_name
from mycve.core.matching import match_osv
from mycve.core.models import Affectedness, Component, MatchResult
from mycve.core.priority import prioritize
from mycve.server.db import (
    Alias,
    Asset,
    Finding,
    FindingEvent,
    Installation,
    ScanJob,
    SourceRecord,
    Vulnerability,
    now,
    require,
)
from mycve.server.normalization import english_text, nvd_score, osv_score


def checksum(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def aliases_for(session: Session, vulnerability_id: str) -> list[str]:
    return list(
        session.scalars(
            select(Alias.alias)
            .where(Alias.vulnerability_id == vulnerability_id)
            .order_by(Alias.alias)
        )
    )


def resolve_vulnerability(session: Session, aliases: list[str]) -> Vulnerability:
    aliases = sorted(set(alias for alias in aliases if alias and len(alias) <= 200))
    if not aliases:
        raise ValueError("Meldung benötigt mindestens eine ID")
    existing = list(
        session.scalars(select(Vulnerability).join(Alias).where(Alias.alias.in_(aliases))).unique()
    )
    if existing:
        existing.sort(key=lambda item: item.id)
        target = existing[0]
        for other in existing[1:]:
            for finding in session.scalars(
                select(Finding).where(Finding.vulnerability_id == other.id)
            ).all():
                duplicate = session.scalar(
                    select(Finding).where(
                        Finding.vulnerability_id == target.id,
                        Finding.installation_id == finding.installation_id,
                    )
                )
                if duplicate:
                    session.execute(
                        update(FindingEvent)
                        .where(FindingEvent.finding_id == finding.id)
                        .values(finding_id=duplicate.id)
                    )
                    if finding.notes and finding.notes not in duplicate.notes:
                        duplicate.notes = "\n".join(filter(None, [duplicate.notes, finding.notes]))
                    order = {"open": 0, "in_progress": 1, "accepted": 2, "resolved": 3}
                    duplicate.workflow = min(
                        [duplicate.workflow, finding.workflow], key=lambda state: order[state]
                    )
                    session.delete(finding)
                else:
                    finding.vulnerability_id = target.id
            session.execute(
                update(Alias)
                .where(Alias.vulnerability_id == other.id)
                .values(vulnerability_id=target.id)
            )
            session.execute(
                update(SourceRecord)
                .where(SourceRecord.vulnerability_id == other.id)
                .values(vulnerability_id=target.id)
            )
            session.flush()
            session.delete(other)
    else:
        target = Vulnerability(primary_alias=aliases[0])
        session.add(target)
        session.flush()
    known = set(aliases_for(session, target.id))
    for alias in aliases:
        if alias not in known:
            session.add(Alias(alias=alias, vulnerability_id=target.id))
    all_aliases = sorted(known | set(aliases))
    target.primary_alias = next(
        (alias for alias in all_aliases if alias.startswith("CVE-")), all_aliases[0]
    )
    session.flush()
    return target


def record_source(
    session: Session,
    vulnerability: Vulnerability,
    *,
    source: str,
    external_id: str,
    payload: dict,
    url: str,
    modified: str | None = None,
) -> SourceRecord:
    digest = checksum(payload)
    current = list(
        session.scalars(
            select(SourceRecord).where(
                SourceRecord.source == source, SourceRecord.external_id == external_id
            )
        )
    )
    matching = None
    for record in current:
        record.current = record.checksum == digest
        if record.current:
            matching = record
    if matching:
        matching.last_seen_at = now()
        matching.url = url
        matching.vulnerability_id = vulnerability.id
        return matching
    record = SourceRecord(
        vulnerability_id=vulnerability.id,
        source=source,
        external_id=external_id,
        checksum=digest,
        payload=payload,
        url=url,
        source_modified=modified,
    )
    session.add(record)
    session.flush()
    return record


def refresh_summary(session: Session, vulnerability: Vulnerability):
    records = list(
        session.scalars(
            select(SourceRecord).where(
                SourceRecord.vulnerability_id == vulnerability.id, SourceRecord.current.is_(True)
            )
        )
    )
    titles: dict[str, str] = {}
    descriptions: dict[str, str] = {}
    scores: dict[str, list[float]] = {}
    for record in records:
        payload = record.payload
        if record.source == "OSV":
            titles["OSV"] = payload.get("summary", "")
            descriptions["OSV"] = payload.get("details", "")
            score = osv_score(payload)
            if score is not None:
                scores.setdefault("OSV", []).append(score)
        elif record.source == "NVD":
            descriptions["NVD"] = english_text(payload.get("descriptions", []))
            score = nvd_score(payload)
            if score is not None:
                scores.setdefault("NVD", []).append(score)
        elif record.source == "CVE Program":
            cna = payload.get("containers", {}).get("cna", {})
            titles["CVE Program"] = cna.get("title", "")
            descriptions["CVE Program"] = english_text(cna.get("descriptions", []))
        elif record.source == "BSI CSAF":
            titles["BSI CSAF"] = payload.get("document", {}).get("title", "")
    vulnerability.title = next(
        (titles[key] for key in ("OSV", "CVE Program", "BSI CSAF") if titles.get(key)),
        vulnerability.primary_alias,
    )
    vulnerability.description = next(
        (descriptions[key] for key in ("OSV", "CVE Program", "NVD") if descriptions.get(key)), ""
    )
    vulnerability.cvss = (
        max(scores["NVD"])
        if scores.get("NVD")
        else max(scores["OSV"])
        if scores.get("OSV")
        else None
    )
    vulnerability.updated_at = now()


def finding_snapshot(finding: Finding) -> dict:
    return {
        key: getattr(finding, key)
        for key in (
            "status",
            "reason",
            "priority",
            "priority_score",
            "priority_reasons",
            "fixed_versions",
            "checked_version",
            "workflow",
            "notes",
            "evidence",
        )
    }


def evaluate(
    session: Session,
    installation: Installation,
    vulnerability: Vulnerability,
    *,
    observation: MatchResult | None = None,
) -> Finding:
    from mycve.server.identification import effective_component

    component = effective_component(installation)
    asset = require(session, Asset, installation.asset_id)
    finding = session.scalar(
        select(Finding).where(
            Finding.installation_id == installation.id, Finding.vulnerability_id == vulnerability.id
        )
    )
    before = finding_snapshot(finding) if finding else None
    if not finding:
        finding = Finding(installation_id=installation.id, vulnerability_id=vulnerability.id)
        session.add(finding)
        session.flush()
    evidence = []
    results: list[MatchResult] = []
    records = session.scalars(
        select(SourceRecord).where(
            SourceRecord.vulnerability_id == vulnerability.id, SourceRecord.current.is_(True)
        )
    ).all()
    previous_query = next(
        (
            item
            for item in finding.evidence
            if item.get("queried_at") and item.get("source") == "OSV"
        ),
        None,
    )
    query_time = None
    if observation is None and previous_query and finding.checked_version == component.version:
        previous_checksums = {
            item["checksum"]
            for item in finding.evidence
            if item.get("source") == "OSV" and item.get("record_id")
        }
        current_checksums = {
            record.checksum
            for record in records
            if record.source == "OSV"
            and any(
                package.get("ecosystem") == component.ecosystem
                and canonical_name(component.ecosystem, package.get("name", ""))
                == canonical_name(component.ecosystem, component.name)
                for item in record.payload.get("affected", [])
                for package in [item.get("package", {})]
            )
        }
        if previous_checksums and previous_checksums == current_checksums:
            observation = MatchResult.model_validate(
                {
                    key: previous_query[key]
                    for key in ("status", "reason", "source", "confidence", "fixed_versions")
                    if key in previous_query
                }
            )
            query_time = previous_query["queried_at"]
    aliases = set(aliases_for(session, vulnerability.id))
    for record in records:
        result = None
        if record.source == "OSV":
            for affected in record.payload.get("affected", []):
                package = affected.get("package", {})
                if package.get("ecosystem") == component.ecosystem and canonical_name(
                    component.ecosystem, package.get("name", "")
                ) == canonical_name(component.ecosystem, component.name):
                    result = match_osv(component, record.payload)
                    break
        elif record.source == "NVD" and component.cpe:
            result = match_nvd(component, record.payload)
        elif record.source == "CVE Program":
            result = match_cve(component, record.payload)
        elif record.source == "BSI CSAF":
            result = match_csaf(component, record.payload, aliases)
        if result:
            # A successful exact OSV version query is stronger than an unsupported local range.
            if record.source != "OSV" or observation is None:
                results.append(result)
            evidence.append(
                {
                    **result.model_dump(mode="json"),
                    "record_id": record.id,
                    "url": record.url,
                    "checksum": record.checksum,
                    "source_modified": record.source_modified,
                }
            )
    if observation:
        results.append(observation)
        evidence.append(
            {**observation.model_dump(mode="json"), "queried_at": query_time or now().isoformat()}
        )
    if not installation.active:
        results = [
            MatchResult(
                status=Affectedness.NOT_AFFECTED,
                source="Inventar",
                reason="Installation im aktuellen Inventar nicht mehr vorhanden",
            )
        ]
    statuses = {result.status for result in results}
    if {Affectedness.AFFECTED, Affectedness.NOT_AFFECTED}.issubset(statuses):
        status, reason = (
            Affectedness.UNKNOWN,
            "Quellen widersprechen sich; manuelle Prüfung erforderlich",
        )
    elif Affectedness.AFFECTED in statuses:
        status = Affectedness.AFFECTED
        reason = next(result.reason for result in results if result.status == status)
    elif Affectedness.NOT_AFFECTED in statuses and Affectedness.UNKNOWN not in statuses:
        status = Affectedness.NOT_AFFECTED
        reason = next(result.reason for result in results if result.status == status)
    else:
        status = Affectedness.UNKNOWN
        reason = next(
            (result.reason for result in results if result.status == status),
            "Keine belastbaren Angaben für diese Installation; Version und Produktzuordnung prüfen",
        )
    priority = prioritize(
        status,
        kev=vulnerability.kev,
        cvss=vulnerability.cvss,
        exposure=asset.exposure,
        criticality=asset.criticality,
    )
    finding.status, finding.reason = str(status), reason
    finding.priority, finding.priority_score = priority.level, priority.score
    finding.priority_reasons = priority.reasons
    finding.fixed_versions = sorted(
        {version for result in results for version in result.fixed_versions}
    )
    finding.checked_version = component.version
    finding.evidence = evidence
    finding.evaluated_at = now()
    # A new affected version or a resolved finding becoming affected is reopened.
    if (
        before
        and status != Affectedness.NOT_AFFECTED
        and (before["status"] == "not_affected" or before["checked_version"] != component.version)
    ):
        finding.workflow = "open"
    after = finding_snapshot(finding)

    # Query timestamps do not create a fresh alert on an unchanged scan.
    def comparable(snapshot):
        if not snapshot:
            return None
        return {
            **snapshot,
            "evidence": [
                {k: v for k, v in item.items() if k != "queried_at"}
                for item in snapshot["evidence"]
            ],
        }

    if comparable(before) != comparable(after):
        finding.updated_at = now()
        session.add(
            FindingEvent(
                finding_id=finding.id,
                action="created" if before is None else "reevaluated",
                before=before,
                after=after,
            )
        )
    session.flush()
    return finding


def import_components(
    session: Session, asset: Asset, components: list[Component], *, replace=True
) -> int:
    existing = {
        item.identity_key: item
        for item in session.scalars(
            select(Installation).where(
                Installation.asset_id == asset.id, Installation.origin == "manual"
            )
        )
    }
    retained = set()
    for component in components:
        # bom-ref preserves identity across version changes; otherwise keep concurrent versions distinct.
        key = (
            checksum({"ref": component.ref})
            if component.ref
            else checksum(component.model_dump(exclude={"ref"}))
        )
        retained.add(key)
        installation = existing.get(key)
        if installation is None:
            installation = Installation(
                asset_id=asset.id, identity_key=key, component=component.model_dump()
            )
            session.add(installation)
            session.flush()
        else:
            if installation.component != component.model_dump():
                installation.identification = {}
            installation.component = component.model_dump()
            installation.active = True
            installation.updated_at = now()
    if replace:
        for key, installation in existing.items():
            if key not in retained:
                installation.active = False
    session.flush()
    # Immediately invalidate stale findings when the inventory changes.
    for finding in session.scalars(
        select(Finding).join(Installation).where(Installation.asset_id == asset.id)
    ).all():
        evaluate(
            session,
            require(session, Installation, finding.installation_id),
            require(session, Vulnerability, finding.vulnerability_id),
        )
    return len(retained)


def recover_stale_jobs(session: Session):
    """Hard-killed workers must not block future scheduled or manual scans forever."""
    cutoff = now() - timedelta(hours=2, minutes=5)
    for job in session.scalars(
        select(ScanJob).where(
            ScanJob.status.in_(["queued", "running"]), ScanJob.created_at < cutoff
        )
    ):
        job.status, job.completed_at = "failed", now()
        job.error = (
            "Scan-Zeitlimit überschritten oder Worker unterbrochen; erneuter Abgleich ist möglich"
        )
    session.flush()
