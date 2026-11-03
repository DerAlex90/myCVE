# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""CVE 5 CNA product/version assertions with explicit version schemes."""

from mycve.core.models import Affectedness, Component, MatchResult
from mycve.core.versions import compare_versions

SCHEMES = {
    "semver": "npm",
    "python": "PyPI",
    "pep440": "PyPI",
    "rpm": "RPM",
    "maven": "Maven",
    "deb": "Debian",
}
STATUSES = {
    "affected": Affectedness.AFFECTED,
    "unaffected": Affectedness.NOT_AFFECTED,
    "unknown": Affectedness.UNKNOWN,
}


def match_cve(component: Component, record: dict) -> MatchResult | None:
    if record.get("cveMetadata", {}).get("state") == "REJECTED":
        return MatchResult(
            status=Affectedness.NOT_AFFECTED,
            source="CVE Program",
            reason="CVE Program hat diese CVE zurückgezogen",
        )
    if not component.vendor:
        return None
    products = [
        item
        for item in record.get("containers", {}).get("cna", {}).get("affected", [])
        if item.get("vendor", "").casefold() == component.vendor.casefold()
        and item.get("product", "").casefold() == component.name.casefold()
    ]
    if not products:
        return None
    results = []
    for product in products:
        platforms = product.get("platforms", [])
        if platforms and not component.platform:
            results.append(Affectedness.UNKNOWN)
            continue
        if platforms and component.platform not in platforms:
            results.append(Affectedness.UNKNOWN)
            continue
        if not component.version:
            results.append(Affectedness.UNKNOWN)
            continue
        found = False
        unknown = False
        for version in product.get("versions", []):
            status = STATUSES.get(version.get("status"), Affectedness.UNKNOWN)
            if not version.get("lessThan") and not version.get("lessThanOrEqual"):
                assertion = version.get("version", "")
                if assertion in {component.version, "*"}:
                    results.append(status)
                    found = True
                elif any(char in assertion for char in ("*", "?")):
                    unknown = True
                continue
            ecosystem = SCHEMES.get(version.get("versionType", ""))
            if not ecosystem:
                unknown = True
                continue
            try:
                start = version.get("version", "*")
                lower = (
                    start in {"*", "0"}
                    or compare_versions(ecosystem, component.version, start) >= 0
                )
                end = version.get("lessThan") or version.get("lessThanOrEqual")
                upper = end == "*" or (
                    compare_versions(ecosystem, component.version, end)
                    < (1 if "lessThanOrEqual" in version else 0)
                )
                if lower and upper:
                    for change in version.get("changes", []):
                        if compare_versions(ecosystem, component.version, change["at"]) >= 0:
                            status = STATUSES.get(change["status"], Affectedness.UNKNOWN)
                    results.append(status)
                    found = True
            except (ValueError, TypeError, KeyError):
                unknown = True
        if unknown:
            results.append(Affectedness.UNKNOWN)
        if not found and not unknown:
            results.append(STATUSES.get(product.get("defaultStatus"), Affectedness.UNKNOWN))
    states = set(results)
    if len(states) != 1 or not states:
        status = Affectedness.UNKNOWN
    else:
        status = states.pop()
    return MatchResult(
        status=status,
        source="CVE Program",
        confidence="candidate" if status == Affectedness.UNKNOWN else "exact",
        reason="Hersteller, Produkt, Plattform oder Versionsbereich muss geklärt werden"
        if status == Affectedness.UNKNOWN
        else "CVE-CNA: Hersteller, Produkt und Versionsstatus stimmen überein",
    )
