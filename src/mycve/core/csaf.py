from mycve.core.models import Affectedness, Component, MatchResult


def match_csaf(component: Component, document: dict, aliases: set[str]) -> MatchResult | None:
    products: dict[str, dict] = {}

    def walk(node):
        if isinstance(node, dict):
            if "product_id" in node:
                products[node["product_id"]] = node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document.get("product_tree", {}))
    exact = set()
    for product_id, product in products.items():
        helper = product.get("product_identification_helper", {})
        if component.purl and helper.get("purl"):
            try:
                candidate = Component(name="candidate", purl=helper["purl"])
                if (
                    candidate.version
                    and component.version
                    and (candidate.ecosystem, candidate.name, candidate.version)
                    == (component.ecosystem, component.name, component.version)
                ):
                    exact.add(product_id)
            except ValueError:
                pass
        if component.cpe and helper.get("cpe") == component.cpe and component.version:
            # Wildcard CPEs are not exact version evidence.
            from mycve.core.cpe import parse_cpe

            try:
                if parse_cpe(component.cpe)[3] == component.version:
                    exact.add(product_id)
            except ValueError:
                pass
    statuses = set()
    for vulnerability in document.get("vulnerabilities", []):
        if vulnerability.get("cve") not in aliases:
            continue
        for status, product_ids in vulnerability.get("product_status", {}).items():
            if exact.intersection(product_ids):
                statuses.add(status)
    if "known_affected" in statuses and statuses.intersection({"fixed", "known_not_affected"}):
        return MatchResult(
            status=Affectedness.UNKNOWN,
            source="BSI CSAF",
            reason="Widersprüchliche CSAF-Produktstatus",
            confidence="candidate",
        )
    if "known_affected" in statuses:
        return MatchResult(
            status=Affectedness.AFFECTED,
            source="BSI CSAF",
            reason="CSAF nennt diese exakte Produktversion als betroffen",
        )
    if statuses.intersection({"fixed", "known_not_affected"}):
        return MatchResult(
            status=Affectedness.NOT_AFFECTED,
            source="BSI CSAF",
            reason="CSAF nennt diese exakte Produktversion als behoben oder nicht betroffen",
        )
    if "under_investigation" in statuses:
        return MatchResult(
            status=Affectedness.UNKNOWN,
            source="BSI CSAF",
            reason="CSAF: Betroffenheit wird untersucht",
            confidence="candidate",
        )
    return None
