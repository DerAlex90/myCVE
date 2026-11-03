# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

import re

from packageurl import PackageURL

PURL_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "cargo": "crates.io",
    "golang": "Go",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
}


def canonical_ecosystem(ecosystem: str | None) -> str | None:
    # OSV documents Ubuntu's Pro/LTS suffixes as equivalent ecosystem names.
    if ecosystem and ecosystem.startswith("Ubuntu:"):
        return ":".join(part for part in ecosystem.split(":") if part not in {"Pro", "LTS"})
    return ecosystem


def canonical_name(ecosystem: str | None, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "NuGet":
        return name.lower()
    if ecosystem == "crates.io":
        return name.lower().replace("_", "-")
    return name


def package_identity(purl: str) -> tuple[str | None, str, str | None]:
    parsed = PackageURL.from_string(purl)
    ecosystem = PURL_ECOSYSTEMS.get(parsed.type)
    if parsed.type == "deb":
        distro = (parsed.qualifiers or {}).get("distro", "")
        if distro.startswith("debian-"):
            ecosystem = "Debian:" + distro.removeprefix("debian-")
        elif distro.startswith("ubuntu-"):
            ecosystem = "Ubuntu:" + distro.removeprefix("ubuntu-")
    if parsed.type == "apk" and parsed.namespace == "alpine":
        distro = (parsed.qualifiers or {}).get("distro", "")
        if re.fullmatch(r"alpine-\d+\.\d+(?:\.\d+)?", distro):
            ecosystem = "Alpine:v" + ".".join(distro.removeprefix("alpine-").split(".")[:2])
    if parsed.type == "rpm":
        distro = (parsed.qualifiers or {}).get("distro", "")
        for prefix, osv in (
            ("rocky-", "Rocky Linux"),
            ("almalinux-", "AlmaLinux"),
            ("rhel-", "Red Hat"),
        ):
            release = distro.removeprefix(prefix)
            if distro.startswith(prefix) and re.fullmatch(r"\d+(?:\.\d+)*", release):
                ecosystem = osv + ":" + release.split(".")[0]
    if parsed.type == "maven":
        name = f"{parsed.namespace}:{parsed.name}" if parsed.namespace else parsed.name
    elif parsed.type in {"deb", "rpm", "apk"}:
        # These namespaces identify the distribution, not part of the package name.
        name = parsed.name
    else:
        name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
    return ecosystem, canonical_name(ecosystem, name), parsed.version
