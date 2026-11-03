from copy import deepcopy

from sqlalchemy import func, select

from mycve import Component
from mycve.core.models import MatchResult
from mycve.server.db import Asset, Finding, FindingEvent, Installation, SourceRecord, Vulnerability
from mycve.server.services import (
    aliases_for,
    evaluate,
    import_components,
    record_source,
    refresh_summary,
    resolve_vulnerability,
)


def setup_finding(session, advisory):
    asset = Asset(name="production-api", exposure="internet", criticality="high")
    session.add(asset)
    session.flush()
    import_components(
        session,
        asset,
        [Component(name="example-http", ecosystem="PyPI", version="2.4.1", ref="http")],
    )
    installation = session.scalar(select(Installation))
    vulnerability = resolve_vulnerability(session, [advisory["id"], *advisory["aliases"]])
    record_source(
        session,
        vulnerability,
        source="OSV",
        external_id=advisory["id"],
        payload=advisory,
        url="https://api.osv.dev/v1/vulns/test",
        modified=advisory["modified"],
    )
    refresh_summary(session, vulnerability)
    finding = evaluate(session, installation, vulnerability)
    session.commit()
    return asset, installation, vulnerability, finding


def test_repeated_evaluation_has_one_finding_and_event(session, advisory):
    _, installation, vulnerability, finding = setup_finding(session, advisory)
    evaluate(session, installation, vulnerability)
    session.commit()
    assert session.scalar(select(func.count()).select_from(Finding)) == 1
    assert session.scalar(select(func.count()).select_from(FindingEvent)) == 1
    assert finding.status == "affected"
    assert aliases_for(session, vulnerability.id) == ["CVE-2024-12345", advisory["id"]]


def test_changed_source_retains_raw_revisions_and_reevaluates(session, advisory):
    _, installation, vulnerability, finding = setup_finding(session, advisory)
    revised = deepcopy(advisory)
    revised["modified"] = "2026-11-02T00:00:00Z"
    revised["affected"][0]["ranges"][0]["events"][1]["fixed"] = "2.4.0"
    record_source(
        session,
        vulnerability,
        source="OSV",
        external_id=advisory["id"],
        payload=revised,
        url="https://api.osv.dev/v1/vulns/test",
        modified=revised["modified"],
    )
    evaluate(session, installation, vulnerability)
    session.commit()
    records = session.scalars(select(SourceRecord)).all()
    assert len(records) == 2 and sum(item.current for item in records) == 1
    assert next(item for item in records if not item.current).payload == advisory
    assert finding.status == "not_affected"
    assert session.scalar(select(func.count()).select_from(FindingEvent)) == 2
    # A source reverting to an older payload still has exactly one current revision.
    record_source(
        session,
        vulnerability,
        source="OSV",
        external_id=advisory["id"],
        payload=advisory,
        url="https://api.osv.dev/v1/vulns/test",
    )
    session.flush()
    assert (
        session.scalar(
            select(func.count()).select_from(SourceRecord).where(SourceRecord.current.is_(True))
        )
        == 1
    )


def test_inventory_updates_close_and_reopen_findings(session, advisory):
    asset, installation, vulnerability, finding = setup_finding(session, advisory)
    import_components(
        session,
        asset,
        [Component(name="example-http", ecosystem="PyPI", version="2.5.0", ref="http")],
    )
    assert finding.status == "not_affected" and finding.checked_version == "2.5.0"
    assert session.scalar(select(func.count()).select_from(Installation)) == 1
    finding.workflow = "resolved"
    import_components(
        session,
        asset,
        [Component(name="example-http", ecosystem="PyPI", version="2.4.1", ref="http")],
    )
    assert finding.status == "affected" and finding.workflow == "open"
    assert evaluate(session, installation, vulnerability).id == finding.id


def test_removed_installation_keeps_finding_history(session, advisory):
    asset, installation, _, finding = setup_finding(session, advisory)
    import_components(
        session, asset, [Component(name="different", ecosystem="PyPI", version="1.0")]
    )
    assert not installation.active and finding.status == "not_affected"
    assert "nicht mehr vorhanden" in finding.reason
    assert session.scalar(select(func.count()).select_from(FindingEvent)) == 2


def test_alias_bridge_merges_findings_and_preserves_history(session, advisory):
    _, installation, first, original = setup_finding(session, advisory)
    second = resolve_vulnerability(session, ["OSV-2026-1000"])
    duplicate = evaluate(session, installation, second)
    original.notes = "Team A prüft"
    duplicate.notes = "Team B prüft"
    session.flush()
    merged = resolve_vulnerability(session, ["OSV-2026-1000", "CVE-2024-12345"])
    session.commit()
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1
    findings = session.scalars(select(Finding)).all()
    assert len(findings) == 1
    assert "Team A" in findings[0].notes and "Team B" in findings[0].notes
    assert session.scalar(select(func.count()).select_from(FindingEvent)) == 2
    assert len(aliases_for(session, merged.id)) == 3


def test_conflicting_sources_are_visible(session, advisory):
    _, installation, vulnerability, finding = setup_finding(session, advisory)
    installation.component = {**installation.component, "purl": "pkg:pypi/example-http@2.4.1"}
    document = {
        "product_tree": {
            "full_product_names": [
                {
                    "product_id": "p1",
                    "product_identification_helper": {"purl": "pkg:pypi/example-http@2.4.1"},
                }
            ]
        },
        "vulnerabilities": [
            {"cve": "CVE-2024-12345", "product_status": {"known_not_affected": ["p1"]}}
        ],
    }
    record_source(
        session,
        vulnerability,
        source="BSI CSAF",
        external_id="advisory:CVE-2024-12345",
        payload=document,
        url="https://wid.cert-bund.de/.well-known/csaf/white/example.json",
    )
    evaluate(session, installation, vulnerability)
    assert finding.status == "unknown" and "widersprechen" in finding.reason
    assert len(finding.evidence) == 2


def test_summary_uses_current_scores_including_downward_revisions(session, advisory):
    _, _, vulnerability, _ = setup_finding(session, advisory)
    for score in (9.8, 4.3):
        payload = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}}
        record_source(
            session,
            vulnerability,
            source="NVD",
            external_id="CVE-2024-12345",
            payload=payload,
            url="https://nvd.nist.gov",
        )
        refresh_summary(session, vulnerability)
        assert vulnerability.cvss == score


def test_context_edit_retains_unchanged_exact_osv_query(session, advisory):
    asset, installation, vulnerability, finding = setup_finding(session, advisory)
    evaluate(
        session,
        installation,
        vulnerability,
        observation=MatchResult(
            status="not_affected", source="OSV", reason="Complete exact OSV query has no hit"
        ),
    )
    query_time = finding.evidence[-1]["queried_at"]
    asset.exposure = "internal"
    evaluate(session, installation, vulnerability)
    assert finding.status == "not_affected"
    assert finding.evidence[-1]["queried_at"] == query_time
