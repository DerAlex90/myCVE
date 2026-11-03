# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from typing import Any

from mycve.core.identity import canonical_ecosystem, canonical_name, package_identity
from mycve.core.models import Affectedness, Component, MatchResult
from mycve.core.versions import compare_versions


def _range_contains(ecosystem: str, version: str, events: list[dict]) -> bool:
    if not events or "introduced" not in events[0]:
        raise ValueError("Unvollständiger Versionsbereich")
    active = False
    for event in events:
        if len(event) != 1:
            raise ValueError("Ungültiges OSV-Ereignis")
        key, boundary = next(iter(event.items()))
        if key == "introduced":
            if boundary == "0" or compare_versions(ecosystem, version, boundary) >= 0:
                active = True
        elif key == "fixed":
            if compare_versions(ecosystem, version, boundary) >= 0:
                active = False
        elif key == "last_affected":
            if compare_versions(ecosystem, version, boundary) > 0:
                active = False
        elif key == "limit":
            if compare_versions(ecosystem, version, boundary) >= 0:
                active = False
        else:
            raise ValueError("Unbekanntes OSV-Ereignis")
    return active


def match_osv(component: Component, advisory: dict[str, Any]) -> MatchResult:
    """Evaluate only exact package identity; a negative result is advisory-specific."""
    if not component.ecosystem:
        return MatchResult(
            status=Affectedness.UNKNOWN, reason="Paketökosystem fehlt", confidence="candidate"
        )
    matches = []
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        ecosystem, name = package.get("ecosystem"), package.get("name", "")
        if package.get("purl") and not name:
            ecosystem, name, _ = package_identity(package["purl"])
        if canonical_ecosystem(ecosystem) == component.ecosystem and canonical_name(
            ecosystem, name
        ) == canonical_name(component.ecosystem, component.name):
            matches.append(affected)
    if not matches:
        return MatchResult(
            status=Affectedness.UNKNOWN,
            reason="Paketidentität nicht eindeutig passend",
            confidence="candidate",
        )
    if advisory.get("withdrawn"):
        return MatchResult(status=Affectedness.NOT_AFFECTED, reason="Meldung zurückgezogen")
    if not component.version:
        return MatchResult(
            status=Affectedness.UNKNOWN, reason="Installierte Version fehlt", confidence="candidate"
        )
    fixed = sorted(
        {
            event["fixed"]
            for item in matches
            for value in item.get("ranges", [])
            for event in value.get("events", [])
            if "fixed" in event
        }
    )
    unknown = False
    for item in matches:
        if component.version in item.get("versions", []):
            return MatchResult(
                status=Affectedness.AFFECTED,
                reason="Version explizit als betroffen aufgeführt",
                fixed_versions=fixed,
            )
        for version_range in item.get("ranges", []):
            if version_range.get("type") not in {"SEMVER", "ECOSYSTEM"}:
                unknown = True
                continue
            try:
                if _range_contains(
                    component.ecosystem or "", component.version, version_range.get("events", [])
                ):
                    return MatchResult(
                        status=Affectedness.AFFECTED,
                        reason="Exakte Paketidentität und betroffener Versionsbereich",
                        fixed_versions=fixed,
                    )
            except (ValueError, TypeError, AttributeError):
                unknown = True
        if not item.get("ranges") and not item.get("versions"):
            unknown = True
    if unknown:
        return MatchResult(
            status=Affectedness.UNKNOWN,
            reason="Versionsbereich kann nicht sicher ausgewertet werden",
            confidence="candidate",
            fixed_versions=fixed,
        )
    return MatchResult(
        status=Affectedness.NOT_AFFECTED,
        reason="Version außerhalb der veröffentlichten betroffenen Bereiche",
        fixed_versions=fixed,
    )
