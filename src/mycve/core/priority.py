from typing import Literal

from mycve.core.models import Affectedness, Priority


def prioritize(
    status: Affectedness | str,
    *,
    kev: bool = False,
    cvss: float | None = None,
    exposure: str = "internal",
    criticality: str = "medium",
) -> Priority:
    if status == Affectedness.NOT_AFFECTED:
        return Priority(level="none", score=0, reasons=["Nicht betroffen"])
    reasons = []
    score = 0
    level: Literal["P0", "P1", "P2", "P3", "none"]
    if kev:
        score += 45
        reasons.append("Bekannte Ausnutzung (CISA KEV)")
    if cvss is not None:
        score += round(cvss * 3)
        reasons.append(f"CVSS {cvss:g}")
    if exposure == "internet":
        score += 15
        reasons.append("Aus dem Internet erreichbar")
    if criticality == "high":
        score += 10
        reasons.append("Hohe Systemkritikalität")
    score = min(score, 100)
    if status == Affectedness.UNKNOWN:
        reasons.insert(0, "Betroffenheit zuerst klären")
        return Priority(level="P1" if kev else "P2", score=score, reasons=reasons)
    if kev:
        level = "P0" if exposure == "internet" or criticality == "high" else "P1"
    elif score >= 40:
        level = "P1"
    elif score >= 20:
        level = "P2"
    else:
        level = "P3"
    return Priority(
        level=level, score=score, reasons=reasons or ["Kein zusätzliches Dringlichkeitssignal"]
    )
