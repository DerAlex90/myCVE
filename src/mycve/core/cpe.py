"""Conservative NVD matching. Missing environmental context stays unknown."""

import re

from mycve.core.models import Affectedness, Component, MatchResult
from mycve.core.versions import compare_cpe_versions, compare_versions


def parse_cpe(value: str) -> list[str]:
    fields = re.split(r"(?<!\\):", value)
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        raise ValueError("CPE 2.3 mit elf Attributen erwartet")
    return [field.replace(r"\:", ":").replace(r"\_", "_") for field in fields[2:]]


def _leaves(node: dict):
    yield from node.get("cpeMatch", [])
    for child in node.get("nodes", []) + node.get("children", []):
        yield from _leaves(child)


def _complex(node: dict) -> bool:
    return bool(
        node.get("negate")
        or node.get("operator", "OR") != "OR"
        or any(not leaf.get("vulnerable", False) for leaf in node.get("cpeMatch", []))
        or any(_complex(child) for child in node.get("nodes", []) + node.get("children", []))
    )


def _attribute(value: str, index: int) -> str:
    if index == 9:
        return {
            "amd64": "x64",
            "x86_64": "x64",
            "aarch64": "arm64",
            "i386": "x86",
            "i686": "x86",
        }.get(value, value)
    return value


def match_nvd(component: Component, cve: dict) -> MatchResult:
    unknown = MatchResult(
        status=Affectedness.UNKNOWN,
        source="NVD",
        confidence="candidate",
        reason="Keine sicher passende CPE-Konfiguration",
    )
    if not component.cpe:
        return unknown
    try:
        own = parse_cpe(component.cpe)
    except ValueError:
        return unknown
    candidates = []
    for config in cve.get("configurations", []):
        for leaf in _leaves(config):
            try:
                target = parse_cpe(leaf.get("criteria", ""))
            except ValueError:
                continue
            if (
                leaf.get("vulnerable")
                and own[:3] == target[:3]
                and all(x not in {"*", "-"} for x in own[:3])
            ):
                candidates.append((config, leaf, target))
    if not candidates:
        return unknown
    undecidable = False
    for config, leaf, target in candidates:
        if _complex(config):
            undecidable = True
            continue
        # Edition, target OS, architecture etc. are part of the identity as well.
        if any(
            wanted != "*" and actual == "*"
            for actual, wanted in zip(own[4:], target[4:], strict=True)
        ):
            undecidable = True
            continue
        if any(
            wanted != "*" and _attribute(actual, index) != _attribute(wanted, index)
            for index, (actual, wanted) in enumerate(zip(own[4:], target[4:], strict=True), 4)
        ):
            continue
        version = component.version or (own[3] if own[3] not in {"*", "-"} else None)
        if not version:
            undecidable = True
            continue
        if component.version and own[3] not in {"*", "-", component.version}:
            undecidable = True
            continue
        if any(char in target[3] for char in ("?", "\\")) or (
            "*" in target[3] and target[3] != "*"
        ):
            undecidable = True
            continue
        if target[3] != "*" and target[3] != version:
            continue
        try:
            in_range = True
            for field, op in (
                ("versionStartIncluding", "ge"),
                ("versionStartExcluding", "gt"),
                ("versionEndIncluding", "le"),
                ("versionEndExcluding", "lt"),
            ):
                if field in leaf:
                    delta = (
                        compare_versions(component.ecosystem, version, leaf[field])
                        if component.ecosystem
                        else compare_cpe_versions(version, leaf[field])
                    )
                    in_range &= {
                        "ge": delta >= 0,
                        "gt": delta > 0,
                        "le": delta <= 0,
                        "lt": delta < 0,
                    }[op]
            if in_range:
                return MatchResult(
                    status=Affectedness.AFFECTED,
                    source="NVD",
                    reason="CPE-Attribute und Version stimmen mit NVD überein",
                )
        except (ValueError, TypeError):
            undecidable = True
    if undecidable:
        unknown.reason = (
            "CPE-Kandidat: Versionsschema, Plattform oder AND/NOT-Kontext muss geklärt werden"
        )
        return unknown
    return MatchResult(
        status=Affectedness.NOT_AFFECTED,
        source="NVD",
        reason="Version oder Plattform außerhalb der passenden CPE-Konfiguration",
    )
