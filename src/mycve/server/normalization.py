# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from cvss import CVSS2, CVSS3, CVSS4, CVSSError


def osv_score(advisory: dict) -> float | None:
    scores = []
    for severity in advisory.get("severity", []):
        score = severity.get("score", "")
        try:
            if severity.get("type") == "CVSS_V4":
                scores.append(float(CVSS4(score).base_score))
            elif severity.get("type") == "CVSS_V3":
                scores.append(float(CVSS3(score).base_score))
            elif severity.get("type") == "CVSS_V2":
                scores.append(float(CVSS2(score).base_score))
        except (ValueError, TypeError, KeyError, CVSSError):
            continue
    return max(scores) if scores else None


def nvd_score(cve: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = cve.get("metrics", {}).get(key, [])
        if values:
            return max(float(value["cvssData"]["baseScore"]) for value in values)
    return None


def english_text(items: list[dict]) -> str:
    return next(
        (item["value"] for item in items if item.get("lang") == "en"),
        items[0].get("value", "") if items else "",
    )
