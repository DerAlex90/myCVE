# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

import csv
import io
import json

from mycve.core.models import Component

MAX_COMPONENTS = 10000


def import_inventory(content: bytes, filename: str) -> list[Component]:
    text = content.decode("utf-8-sig")
    if filename.lower().endswith(".csv"):
        rows = list(csv.DictReader(io.StringIO(text)))
        if not rows or "name" not in rows[0]:
            raise ValueError(
                "CSV benötigt eine Kopfzeile mit name; optional version, ecosystem, purl, cpe, vendor, platform, ref"
            )
        result = [
            Component.model_validate(
                {key: value or None for key, value in row.items() if key and value}
            )
            for row in rows
        ]
    else:
        bom = json.loads(text)
        if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") not in {
            "1.4",
            "1.5",
            "1.6",
            "1.7",
        }:
            raise ValueError("CycloneDX JSON 1.4–1.7 oder CSV erwartet")
        result = []

        def walk(items: list, depth: int = 0):
            if depth > 30:
                raise ValueError("Zu viele verschachtelte Komponenten")
            for item in items:
                if len(result) >= MAX_COMPONENTS:
                    raise ValueError("Maximal 10000 Komponenten pro Import")
                result.append(
                    Component(
                        name=item.get("name", ""),
                        version=item.get("version"),
                        purl=item.get("purl"),
                        cpe=item.get("cpe"),
                        vendor=item.get("supplier", {}).get("name"),
                        ref=item.get("bom-ref"),
                    )
                )
                walk(item.get("components", []), depth + 1)

        walk(bom.get("components", []))
    if not result:
        raise ValueError("Inventar enthält keine Komponenten")
    if len(result) > MAX_COMPONENTS:
        raise ValueError("Maximal 10000 Komponenten pro Import")
    seen = set()
    unique = []
    for component in result:
        identity = (
            component.ref,
            component.purl,
            component.ecosystem,
            component.name,
            component.version,
            component.cpe,
            component.vendor,
            component.platform,
        )
        if identity not in seen:
            seen.add(identity)
            unique.append(component)
    return unique
