"""Use ecosystem comparators. Unsupported formats never fall back to string sorting."""

import re

from packaging.version import Version
from univers import versions


def compare_versions(ecosystem: str, left: str, right: str) -> int:
    if ecosystem == "PyPI":
        py_first, py_second = Version(left), Version(right)
        return (py_first > py_second) - (py_first < py_second)
    else:
        comparator = {
            "npm": versions.SemverVersion,
            "crates.io": versions.SemverVersion,
            "Go": versions.GolangVersion,
            "Maven": versions.MavenVersion,
            "NuGet": versions.NugetVersion,
            "RubyGems": versions.RubygemsVersion,
            "Packagist": versions.ComposerVersion,
            "Debian": versions.DebianVersion,
            "Ubuntu": versions.DebianVersion,
            "Alpine": versions.AlpineLinuxVersion,
            "AlmaLinux": versions.RpmVersion,
            "Rocky Linux": versions.RpmVersion,
            "Red Hat": versions.RpmVersion,
            "RPM": versions.RpmVersion,
        }.get(ecosystem.split(":")[0])
        if comparator is None:
            raise ValueError(f"Kein Versionsvergleich für {ecosystem}")
        if ecosystem in {"npm", "crates.io"}:
            left, right = left.removeprefix("v"), right.removeprefix("v")
        first, second = comparator(left), comparator(right)
    return (first > second) - (first < second)


def compare_cpe_versions(left: str, right: str) -> int:
    """Classic software's dotted numeric versions; no guessed prerelease ordering."""
    if not all(re.fullmatch(r"\d+(?:\.\d+)*", value) for value in (left, right)):
        raise ValueError("CPE-Versionsformat ist nicht numerisch vergleichbar")
    first, second = [tuple(int(part) for part in value.split(".")) for value in (left, right)]
    length = max(len(first), len(second))
    first, second = first + (0,) * (length - len(first)), second + (0,) * (length - len(second))
    return (first > second) - (first < second)
