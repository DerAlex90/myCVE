# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Automatic, source-backed identities, separate from unmodified reported inventory."""

import hashlib
import json
import re
import unicodedata
from datetime import UTC, timedelta
from urllib.parse import urlencode

from sqlalchemy import and_, case, delete, func, or_, select

from mycve.core.cpe import parse_cpe
from mycve.core.models import Component
from mycve.server.db import Agent, Installation, ProductIdentityCache, SourceRecord, now
from mycve.server.feeds import NVD_CPE_URL, FeedError


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def fingerprint(installation: Installation) -> str:
    return digest(
        {
            "component": installation.component,
            "architecture": installation.inventory.get("architecture"),
        }
    )


def words(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).casefold().replace("®", "").replace("™", "")
    return " ".join(re.findall(r"[a-z0-9]+|\+", text))


def vendor_name(text: str) -> str:
    # Appx publishers use X.500 distinguished names.
    match = re.search(r"(?:^|,)\s*CN=([^,]+)", text, re.I)
    text = match.group(1) if match else text
    legal = {"inc", "incorporated", "corp", "corporation", "llc", "ltd", "limited", "gmbh", "co"}
    name = " ".join(part for part in words(text).split() if part not in legal)
    # Publisher/brand relationships documented with references in matching.md.
    return {
        "python software foundation": "python",
        "mozilla foundation": "mozilla",
        "the document foundation": "libreoffice",
        "igor pavlov": "7 zip",
        "win rar": "rarlab",
        "adobe systems": "adobe",
        "the git development community": "git scm",
        "git development community": "git scm",
        "openssl software foundation": "openssl",
        "openssl project": "openssl",
    }.get(name, name)


def product_search(text: str, version: str | None = None) -> str:
    if version and version not in {"*", "-"}:
        text = re.sub(
            r"(?<![\w.])(?:version\s+|v)?" + re.escape(version) + r"(?![\w.])",
            " ",
            text,
            flags=re.I,
        )
    text = re.sub(
        r"\((?:x64|x86|amd64|arm64|aarch64)(?:\s+[a-z]{2}(?:-[a-z]{2})?)?\)", " ", text, flags=re.I
    )
    text = re.sub(r"\((?:32|64)[ -]bit\)", " ", text, flags=re.I)
    return " ".join(
        unicodedata.normalize("NFKC", text).casefold().replace("®", "").replace("™", "").split()
    ).strip(" -")


def product_name(text: str, version: str | None = None) -> str:
    return words(product_search(text, version))


def dictionary_identity(name: str, publisher: str, platform: str, products: list[dict]) -> dict:
    """Only an exact product alias plus manufacturer can establish a product identity."""
    own, vendor = words(name), vendor_name(publisher)
    matches = {}
    for entry in products:
        if entry.get("deprecated"):
            continue
        try:
            fields = parse_cpe(entry["cpeName"])
        except (ValueError, KeyError) as exc:
            raise FeedError("NVD-CPE: Ungültige Kennung im Produktkatalog") from exc
        if fields[0] != "a" or fields[1] in {"*", "-"} or fields[2] in {"*", "-"}:
            continue
        cpe_vendor = vendor_name(fields[1])
        # A vendor may differ between catalog spelling and its English product title.
        titles = [
            product_name(title["title"], fields[3])
            for title in entry.get("titles", [])
            if title.get("lang") == "en"
        ]
        aliases = {words(fields[2]), words(fields[1] + " " + fields[2]), *titles}
        manufacturer_matches = bool(vendor) and vendor == cpe_vendor
        if vendor:
            # E.g. vendor "7-zip" and title "7-Zip", or publisher "VideoLAN" / product VLC.
            aliases |= {cpe_vendor + " " + alias for alias in list(aliases)}
        if not manufacturer_matches or own not in aliases:
            continue
        target = fields[8]
        if platform and target not in {"*", "-", platform}:
            continue
        identity = tuple(fields[:3])
        if identity not in matches:
            matches[identity] = {
                "cpe": entry["cpeName"],
                "cpe_id": entry.get("cpeNameId"),
                "record": entry,
            }
    candidates = list(matches.values())
    if len(candidates) == 1:
        return {
            "status": "identified",
            "reason": "Hersteller und Produkt stimmen eindeutig mit dem offiziellen NVD-CPE-Katalog überein",
            "candidates": candidates,
        }
    return {
        "status": "ambiguous" if candidates else "unresolved",
        "reason": "Mehrere passende Produkte im NVD-CPE-Katalog"
        if candidates
        else "Keine eindeutige Hersteller-/Produktzuordnung im NVD-CPE-Katalog",
        "candidates": candidates[:10],
        "candidate_count": len(candidates),
    }


def effective_component(installation: Installation) -> Component:
    component = Component.model_validate(installation.component)
    identity = installation.identification or {}
    if (
        identity.get("fingerprint") == fingerprint(installation)
        and identity.get("status") == "identified"
    ):
        component = component.model_copy(
            update={
                "cpe": component.cpe or identity.get("cpe"),
                "ecosystem": component.ecosystem or identity.get("ecosystem"),
                "platform": component.platform or identity.get("platform"),
            }
        )
    return component


def incomplete_filter():
    return and_(
        Installation.component["cpe"].as_string().is_(None),
        or_(
            Installation.component["version"].as_string().is_(None),
            and_(
                Installation.component["ecosystem"].as_string().is_(None),
                or_(
                    Installation.identification["status"].as_string().is_(None),
                    Installation.identification["status"].as_string() != "identified",
                ),
            ),
        ),
    )


def due_filter():
    return and_(
        Installation.active.is_(True),
        Installation.component["cpe"].as_string().is_(None),
        Installation.component["ecosystem"].as_string().is_(None),
        or_(
            Installation.identification["next_check_at"].as_string().is_(None),
            Installation.identification["next_check_at"].as_string() <= now().isoformat(),
        ),
    )


def coverage(session, *conditions) -> dict:
    result: dict = {
        "identified": 0,
        "pending": 0,
        "unresolved": 0,
        "ambiguous": 0,
        "missing_version": 0,
        "error": 0,
    }
    status = case(
        (Installation.component["version"].as_string().is_(None), "missing_version"),
        else_=Installation.identification["status"].as_string(),
    ).label("identification_status")
    rows = session.execute(
        select(status, func.count())
        .where(Installation.active.is_(True), *conditions, incomplete_filter())
        .group_by(status)
    )
    for status, count in rows:
        result[status if status in result else "pending"] += count
    result["identified"] = (
        session.scalar(
            select(func.count())
            .select_from(Installation)
            .where(Installation.active.is_(True), *conditions, ~incomplete_filter())
        )
        or 0
    )
    return result


def identify_inventory(session, installations, client, *, max_queries=50) -> dict:
    session.execute(
        delete(ProductIdentityCache).where(
            ProductIdentityCache.expires_at < now() - timedelta(days=7)
        )
    )
    queries, stats = (
        0,
        {
            "identified": 0,
            "pending": 0,
            "unresolved": 0,
            "ambiguous": 0,
            "missing_version": 0,
            "error": 0,
        },
    )
    # Pending/new products first; recently attempted products must not starve them.
    ordered = sorted(
        installations, key=lambda item: (item.identification.get("checked_at", ""), item.id)
    )
    for installation in ordered:
        original = fingerprint(installation)
        component = Component.model_validate(installation.component)
        previous = installation.identification or {}
        if (
            previous.get("fingerprint") == original
            and previous.get("next_check_at", "") > now().isoformat()
        ):
            stats[previous.get("status", "pending")] += 1
            continue
        platform = component.platform or ""
        if not platform and installation.origin.startswith("agent:"):
            agent = session.get(Agent, installation.origin.split(":")[1])
            platform = agent.host.get("os", "") if agent else ""
        checked = now()
        result: dict = {
            "fingerprint": original,
            "checked_at": checked.isoformat(),
            "platform": platform,
        }
        ttl = timedelta(days=7)
        if component.ecosystem or component.cpe:
            result.update(
                status="identified" if component.version or component.cpe else "missing_version",
                reason="Standardisierte Kennung aus dem Inventar automatisch übernommen",
                ecosystem=component.ecosystem,
                cpe=component.cpe,
            )
        elif component.purl and component.purl.startswith(("pkg:rpm/", "pkg:deb/", "pkg:apk/")):
            # Never reinterpret a distribution's backported version as an upstream release.
            result.update(
                status="unresolved",
                reason="Für diese Distribution ist keine eindeutige Advisory-Zuordnung verfügbar",
            )
            ttl = timedelta(days=1)
        else:
            name = product_name(component.name, component.version)
            search = product_search(component.name, component.version)
            signature = digest(
                {"name": component.name, "vendor": component.vendor, "platform": platform}
            )
            if previous.get("product_signature") == signature:
                name = previous.get("product_name", name)
                search = previous.get("product_search", search)
            result.update(product_signature=signature, product_name=name, product_search=search)
            key = digest(
                {"name": name, "vendor": vendor_name(component.vendor or ""), "platform": platform}
            )
            cache = session.get(ProductIdentityCache, key)
            if cache and cache.expires_at.replace(tzinfo=UTC) > checked:
                catalog = cache.result
            elif queries >= max_queries:
                catalog = {
                    "status": "pending",
                    "reason": "Automatische Produktzuordnung wird im nächsten Durchlauf fortgesetzt",
                }
                ttl = timedelta(minutes=5)
            else:
                queries += 1
                try:
                    products = client.cpe_dictionary(search)
                    catalog = dictionary_identity(name, component.vendor or "", platform, products)
                    catalog.update(
                        url=NVD_CPE_URL + "?" + urlencode({"keywordSearch": search}),
                        checksum=digest(products),
                        retrieved_at=checked.isoformat(),
                    )
                    cache_ttl = timedelta(days=7 if catalog["status"] == "identified" else 1)
                except (FeedError, ValueError, KeyError, TypeError) as exc:
                    catalog = {
                        "status": "error",
                        "reason": str(exc)
                        if isinstance(exc, FeedError)
                        else "NVD-CPE-Produktdaten konnten nicht verarbeitet werden",
                    }
                    cache_ttl = timedelta(minutes=15)
                if cache is None:
                    cache = ProductIdentityCache(
                        key=key, result=catalog, expires_at=checked + cache_ttl
                    )
                    session.add(cache)
                else:
                    cache.result, cache.expires_at = catalog, checked + cache_ttl
                session.flush()
            result.update(catalog)
            if catalog["status"] == "identified":
                fields = re.split(r"(?<!\\):", catalog["candidates"][0]["cpe"])[2:]
                result["product_cpe"] = ":".join(["cpe", "2.3", *fields[:3], *(["*"] * 8)])
                if component.version and re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._~-]{0,100}", component.version
                ):
                    fields = [*fields[:3], component.version, *(["*"] * 7)]
                    if platform in {"windows", "linux", "mac_os_x"}:
                        fields[8] = platform
                    architecture = installation.inventory.get("architecture", "").lower()
                    hardware = {
                        "amd64": "x64",
                        "x86_64": "x64",
                        "x64": "x64",
                        "x86": "x86",
                        "i386": "x86",
                        "i686": "x86",
                        "arm64": "arm64",
                        "aarch64": "arm64",
                    }.get(architecture)
                    if hardware:
                        fields[9] = hardware
                    result["cpe"] = ":".join(["cpe", "2.3", *fields])
                else:
                    result.update(
                        status="missing_version",
                        reason="Produkt automatisch zugeordnet; eine auswertbare installierte Version fehlt noch",
                    )
            if result["status"] in {"unresolved", "ambiguous", "missing_version"}:
                ttl = timedelta(days=1)
            elif result["status"] == "error":
                ttl = timedelta(minutes=15)
        result["next_check_at"] = (checked + ttl).isoformat()
        # Network access may overlap a new device report: do not attach an old identity.
        session.refresh(installation)
        if fingerprint(installation) != original:
            continue
        installation.identification = result
        session.commit()
        stats[result["status"]] += 1
    return {**stats, "queries": queries}


def nvd_candidates(session, client, cpe: str) -> tuple[list[dict], bool]:
    """Resume fleet batches without refetching every already-checked CPE each minute."""
    key = digest({"cpe_vulnerability_lookup": cpe})
    cache = session.get(ProductIdentityCache, key)
    if cache and cache.expires_at.replace(tzinfo=UTC) > now():
        ids = set(cache.result.get("ids", []))
        records = session.scalars(
            select(SourceRecord).where(
                SourceRecord.source == "NVD",
                SourceRecord.current.is_(True),
                SourceRecord.external_id.in_(ids),
            )
        ).all()
        if {record.external_id for record in records} == ids:
            return [record.payload for record in records], False
    records = client.nvd_cpe(cpe)
    result = {"ids": sorted({record["id"] for record in records})}
    if cache is None:
        session.add(
            ProductIdentityCache(key=key, result=result, expires_at=now() + timedelta(hours=1))
        )
    else:
        cache.result, cache.expires_at = result, now() + timedelta(hours=1)
    return records, True
