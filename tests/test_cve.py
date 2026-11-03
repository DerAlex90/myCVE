from copy import deepcopy

from mycve import Component, match_cve


def document():
    return {
        "cveMetadata": {"state": "PUBLISHED"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Example",
                        "product": "Server",
                        "defaultStatus": "unaffected",
                        "versions": [
                            {
                                "version": "1.0.0",
                                "lessThan": "2.0.0",
                                "versionType": "semver",
                                "status": "affected",
                            }
                        ],
                    }
                ]
            }
        },
    }


def test_cna_exact_product_and_boundaries():
    for version, expected in [
        ("0.9.0", "not_affected"),
        ("1.0.0", "affected"),
        ("1.9.0", "affected"),
        ("2.0.0", "not_affected"),
        (None, "unknown"),
    ]:
        assert (
            match_cve(
                Component(name="Server", vendor="Example", version=version), document()
            ).status
            == expected
        )
    assert (
        match_cve(Component(name="Similar Server", vendor="Example", version="1.0.0"), document())
        is None
    )
    assert match_cve(Component(name="Server", version="1.0.0"), document()) is None


def test_cna_unknown_schemes_platforms_and_status_changes():
    record = document()
    affected = record["containers"]["cna"]["affected"][0]
    affected["versions"][0]["changes"] = [{"at": "1.5.0", "status": "unaffected"}]
    assert (
        match_cve(Component(name="Server", vendor="Example", version="1.6.0"), record).status
        == "not_affected"
    )
    affected["versions"][0]["versionType"] = "custom"
    assert (
        match_cve(Component(name="Server", vendor="Example", version="1.6.0"), record).status
        == "unknown"
    )
    record = deepcopy(document())
    record["containers"]["cna"]["affected"][0]["platforms"] = ["Linux"]
    assert (
        match_cve(Component(name="Server", vendor="Example", version="1.0.0"), record).status
        == "unknown"
    )
    assert (
        match_cve(
            Component(name="Server", vendor="Example", version="1.0.0", platform="Linux"), record
        ).status
        == "affected"
    )


def test_rejected_cve_remains_an_explicit_source_assertion():
    assert (
        match_cve(Component(name="any"), {"cveMetadata": {"state": "REJECTED"}}).status
        == "not_affected"
    )
