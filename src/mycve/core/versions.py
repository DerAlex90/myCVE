"""Use ecosystem comparators. Unsupported formats never fall back to string sorting."""

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
            "RPM": versions.RpmVersion,
        }.get(ecosystem.split(":")[0])
        if comparator is None:
            raise ValueError(f"Kein Versionsvergleich für {ecosystem}")
        if ecosystem in {"npm", "crates.io"}:
            left, right = left.removeprefix("v"), right.removeprefix("v")
        first, second = comparator(left), comparator(right)
    return (first > second) - (first < second)
