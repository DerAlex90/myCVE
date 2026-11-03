import json

import pytest

from mycve import Component, match_osv, prioritize
from mycve.core.cpe import match_nvd, parse_cpe
from mycve.core.csaf import match_csaf
from mycve.core.importers import import_inventory
from mycve.core.versions import compare_versions


@pytest.mark.parametrize(
    "version,expected",
    [
        ("2.4.1", "affected"),
        ("2.5.0", "not_affected"),
        ("2.6.0", "not_affected"),
        (None, "unknown"),
        ("invalid", "unknown"),
    ],
)
def test_osv_boundaries(advisory, version, expected):
    assert (
        match_osv(
            Component(name="example-http", ecosystem="PyPI", version=version), advisory
        ).status
        == expected
    )


def test_identity_is_not_fuzzy(advisory):
    assert (
        match_osv(
            Component(name="example-http-client", ecosystem="PyPI", version="2.4.1"), advisory
        ).status
        == "unknown"
    )
    assert (
        match_osv(Component(name="example-http", ecosystem="npm", version="2.4.1"), advisory).status
        == "unknown"
    )
    assert match_osv(Component(name="example-http", version="2.4.1"), advisory).status == "unknown"
    assert (
        match_osv(
            Component(name="Example_HTTP", ecosystem="PyPI", version="2.4.1"), advisory
        ).status
        == "affected"
    )


def test_multiple_ranges_and_reintroduction(advisory):
    advisory["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "1.0"},
        {"fixed": "2.0"},
        {"introduced": "3.0"},
        {"last_affected": "3.2"},
    ]
    for version, expected in [
        ("0.9", "not_affected"),
        ("1.0", "affected"),
        ("2.1", "not_affected"),
        ("3.2", "affected"),
        ("3.3", "not_affected"),
    ]:
        assert (
            match_osv(
                Component(name="example-http", ecosystem="PyPI", version=version), advisory
            ).status
            == expected
        )


def test_unsupported_ranges_and_withdrawal(advisory):
    component = Component(name="example-http", ecosystem="PyPI", version="2.4.1")
    advisory["affected"][0]["ranges"][0]["type"] = "GIT"
    assert match_osv(component, advisory).status == "unknown"
    advisory["affected"][0]["versions"] = ["2.4.1"]
    assert match_osv(component, advisory).status == "affected"
    advisory["withdrawn"] = "2026-10-02T00:00:00Z"
    assert match_osv(component, advisory).status == "not_affected"


@pytest.mark.parametrize(
    "ecosystem,left,right",
    [
        ("PyPI", "1.0rc1", "1.0"),
        ("npm", "1.0.0-beta.2", "1.0.0"),
        ("Go", "v1.2.0", "v1.3.0"),
        ("Maven", "1.0-rc1", "1.0"),
        ("NuGet", "1.0.0-beta", "1.0.0"),
        ("RubyGems", "1.0.pre", "1.0"),
        ("Debian:12", "1.0~rc1-1", "1.0-1"),
        ("RPM", "1.0-1", "1.0-2"),
    ],
)
def test_ecosystem_comparators(ecosystem, left, right):
    assert compare_versions(ecosystem, left, right) < 0
    assert compare_versions(ecosystem, right, left) > 0
    assert compare_versions(ecosystem, left, left) == 0


def test_debian_epoch_and_unknown_versions():
    assert compare_versions("Debian:12", "1:1.0-1", "9.0-1") > 0
    with pytest.raises(ValueError):
        compare_versions("Custom", "1", "2")


def test_purl_identity_and_version_conflicts():
    item = Component(name="ignored", purl="pkg:maven/org.example/library@1.2.0")
    assert (item.ecosystem, item.name, item.version) == ("Maven", "org.example:library", "1.2.0")
    assert Component(name="x", purl="pkg:npm/%40example/parser@1.0.0").name == "@example/parser"
    assert (
        Component(name="x", purl="pkg:deb/debian/curl@7.88?distro=debian-12").ecosystem
        == "Debian:12"
    )
    assert Component(name="x", purl="pkg:deb/debian/curl@7.88?distro=debian-12").name == "curl"
    with pytest.raises(ValueError):
        Component(name="x", version="3.0.0", purl="pkg:pypi/example@2.0.0")
    with pytest.raises(ValueError):
        Component(name="x", ecosystem="npm", purl="pkg:pypi/example@2.0.0")


def test_priority_separates_affectedness():
    assert prioritize("affected", kev=True, exposure="internet").level == "P0"
    assert prioritize("unknown", kev=True, exposure="internet").level == "P1"
    assert prioritize("affected", kev=True).level == "P1"
    assert prioritize("affected", cvss=9.8).level == "P2"
    assert prioritize("not_affected", kev=True, cvss=10, exposure="internet").level == "none"


def test_sbom_nested_and_csv_import():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": "parent", "components": [{"name": "child", "purl": "pkg:pypi/example@1.0"}]}
        ],
    }
    items = import_inventory(json.dumps(bom).encode(), "bom.json")
    assert len(items) == 2 and items[1].version == "1.0"
    assert (
        import_inventory(b"name,version,ecosystem\nexample,,PyPI\n", "inventory.csv")[0].version
        is None
    )
    with pytest.raises(ValueError):
        import_inventory(b'{"bomFormat":"SPDX"}', "wrong.json")
    with pytest.raises(ValueError):
        import_inventory(b"product,version\nexample,1.0\n", "wrong.csv")


def nvd_document(**node):
    return {
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*",
                            }
                        ],
                        **node,
                    }
                ]
            }
        ]
    }


def test_exact_cpe_and_context():
    component = Component(
        name="server", version="1.0", cpe="cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"
    )
    assert len(parse_cpe(component.cpe)) == 11
    assert match_nvd(component, nvd_document()).status == "affected"
    assert match_nvd(component, nvd_document(operator="AND")).status == "unknown"
    assert match_nvd(component, nvd_document(negate=True)).status == "unknown"
    component.version = "2.0"
    assert match_nvd(component, nvd_document()).status == "unknown"  # CPE and inventory conflict.
    component.cpe = "cpe:2.3:a:example:server:2.0:*:*:*:*:*:*:*"
    assert match_nvd(component, nvd_document()).status == "not_affected"


def test_nvd_numeric_classic_software_versions_are_comparable():
    document = nvd_document(
        cpeMatch=[
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:example:server:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "2.0",
            }
        ]
    )
    component = Component(
        name="server", version="1.0", cpe="cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"
    )
    assert match_nvd(component, document).status == "affected"
    component = Component(
        name="server", version="1.0rc1", cpe="cpe:2.3:a:example:server:1.0rc1:*:*:*:*:*:*:*"
    )
    assert match_nvd(component, document).status == "unknown"


def test_csaf_requires_exact_version():
    document = {
        "product_tree": {
            "full_product_names": [
                {
                    "name": "x",
                    "product_id": "p1",
                    "product_identification_helper": {"purl": "pkg:pypi/example@1.0"},
                }
            ]
        },
        "vulnerabilities": [
            {"cve": "CVE-2024-12345", "product_status": {"known_affected": ["p1"]}}
        ],
    }
    assert (
        match_csaf(
            Component(name="example", purl="pkg:pypi/example@1.0"), document, {"CVE-2024-12345"}
        ).status
        == "affected"
    )
    assert (
        match_csaf(
            Component(name="example", purl="pkg:pypi/example@2.0"), document, {"CVE-2024-12345"}
        )
        is None
    )
