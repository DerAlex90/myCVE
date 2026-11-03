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
    if parsed.type == "maven":
        name = f"{parsed.namespace}:{parsed.name}" if parsed.namespace else parsed.name
    elif parsed.type in {"deb", "rpm", "apk"}:
        # These namespaces identify the distribution, not part of the package name.
        name = parsed.name
    else:
        name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
    return ecosystem, canonical_name(ecosystem, name), parsed.version
