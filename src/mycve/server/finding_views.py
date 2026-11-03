# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from sqlalchemy import select

from mycve.server.context import package_context
from mycve.server.db import Alias
from mycve.server.identification import effective_component
from mycve.server.risks import group_findings
from mycve.server.services import aliases_for, finding_snapshot


def finding_json(session, finding, vulnerability, installation, asset, alias_map=None):
    context = installation.context or package_context(
        installation.inventory, installation.component
    )
    return {
        "id": finding.id,
        "installation_id": installation.id,
        "vulnerability_id": vulnerability.id,
        "alias": vulnerability.primary_alias,
        "aliases": alias_map.get(vulnerability.id, [])
        if alias_map is not None
        else aliases_for(session, vulnerability.id),
        "title": vulnerability.title,
        "description": vulnerability.description,
        "cvss": vulnerability.cvss,
        "kev": vulnerability.kev,
        "kev_due_date": vulnerability.kev_due_date,
        "component": effective_component(installation).model_dump(),
        "package": installation.inventory,
        "context": context,
        "component_type": context.get("component_type", "unknown"),
        "identification": installation.identification,
        "installation_active": installation.active,
        "asset_id": asset.id,
        "asset_name": asset.name,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        **finding_snapshot(finding),
        "updated_at": finding.updated_at.isoformat(),
        "evaluated_at": finding.evaluated_at.isoformat(),
    }


def load_findings(session, query, *, view="packages", component_type=None, patch_status=None):
    rows = session.execute(query).all()
    ids = {row[1].id for row in rows}
    aliases: dict[str, list[str]] = {}
    if ids:
        for vulnerability_id, alias in session.execute(
            select(Alias.vulnerability_id, Alias.alias)
            .where(Alias.vulnerability_id.in_(ids))
            .order_by(Alias.alias)
        ):
            aliases.setdefault(vulnerability_id, []).append(alias)
    items = [
        finding_json(session, row[0], row[1], row[2], row[3], alias_map=aliases) for row in rows
    ]
    if component_type:
        items = [item for item in items if item["component_type"] == component_type]
    if patch_status:
        items = [item for item in items if item["patch_status"] == patch_status]
    return group_findings(items) if view == "risks" else items
