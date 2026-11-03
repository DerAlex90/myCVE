# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Risk grouping keeps original binary installations as evidence."""

import hashlib
import json
from collections import defaultdict


def risk_key(item: dict) -> tuple:
    component = item["component"]
    inventory = item.get("package") or component.get("inventory") or {}
    return (
        item["vulnerability_id"],
        item["asset_id"],
        component.get("ecosystem"),
        inventory.get("source_name") or component["name"],
        inventory.get("source_version") or component.get("version"),
    )


def group_findings(items: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for item in items:
        groups[risk_key(item)].append(item)
    result = []
    for key, members in groups.items():
        members.sort(key=lambda item: (item["priority"], item["id"]))
        representative = dict(members[0])
        representative["updated_at"] = max(item.get("updated_at", "") for item in members)
        states = {item["status"] for item in members}
        representative["status"] = next(
            state for state in ("affected", "unknown", "not_affected") if state in states
        )
        workflows = {item["workflow"] for item in members}
        representative["workflow"] = next(iter(workflows)) if len(workflows) == 1 else "mixed"
        patches = {item.get("patch_status", "unknown") for item in members}
        representative["patch_status"] = next(iter(patches)) if len(patches) == 1 else "unknown"
        roles = {item.get("context", {}).get("component_type", "unknown") for item in members}
        representative["component_type"] = next(iter(roles)) if len(roles) == 1 else "mixed"
        representative["risk_id"] = hashlib.sha256(json.dumps(key).encode()).hexdigest()
        representative["package_count"] = len(members)
        representative["packages"] = [
            {
                "finding_id": item["id"],
                "installation_id": item.get("installation_id"),
                **(
                    item.get("package")
                    or {
                        "name": item["component"]["name"],
                        "version": item["component"].get("version"),
                    }
                ),
                **item.get("context", {}),
                "status": item["status"],
                "priority": item["priority"],
                "workflow": item["workflow"],
                "patch_status": item.get("patch_status", "unknown"),
            }
            for item in members
        ]
        result.append(representative)
    result.sort(key=lambda item: item["updated_at"], reverse=True)
    return sorted(result, key=lambda item: item["priority"])
