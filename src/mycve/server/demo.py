"""Explicitly fictional data; never a claim about actual CVEs or assets."""

from datetime import timedelta

from sqlalchemy import func, select

from mycve.core.models import Component
from mycve.server.db import Asset, Base, ScanJob, now
from mycve.server.migrate import migrate_schema
from mycve.server.services import (
    evaluate,
    import_components,
    record_source,
    refresh_summary,
    resolve_vulnerability,
)


def seed_demo(engine):
    from mycve.server.db import Installation, sessions

    if engine.url.database and engine.url.database != ":memory:":
        migrate_schema(engine)
    else:
        Base.metadata.create_all(engine)
    with sessions(engine)() as session:
        if session.scalar(select(func.count()).select_from(Asset)):
            return False
        examples = [
            (
                "customer-api",
                "Platform",
                "internet",
                "high",
                "production",
                "PyPI",
                "example-http",
                "2.4.1",
                "2.5.0",
                9.8,
                True,
            ),
            (
                "payment-service",
                "Payments",
                "internet",
                "high",
                "production",
                "npm",
                "@example/parser",
                "4.1.2",
                "4.2.0",
                8.1,
                False,
            ),
            (
                "analytics-worker",
                "Data",
                "internal",
                "medium",
                "production",
                "PyPI",
                "example-data",
                "1.8.0",
                "1.8.3",
                7.5,
                False,
            ),
            (
                "internal-portal",
                "IT Operations",
                "internal",
                "medium",
                "production",
                "npm",
                "example-template",
                "3.2.0",
                "3.2.4",
                6.5,
                False,
            ),
            (
                "build-runner",
                "Developer Experience",
                "internal",
                "high",
                "staging",
                "Go",
                "example.org/build",
                None,
                "1.3.0",
                9.1,
                True,
            ),
            (
                "docs-service",
                "Developer Experience",
                "isolated",
                "low",
                "staging",
                "PyPI",
                "example-docs",
                "5.0.0",
                "5.1.0",
                4.3,
                False,
            ),
        ]
        for index, (
            name,
            owner,
            exposure,
            criticality,
            environment,
            ecosystem,
            package,
            version,
            fixed,
            score,
            kev,
        ) in enumerate(examples, 1):
            asset = Asset(
                name=name,
                owner=owner,
                exposure=exposure,
                criticality=criticality,
                environment=environment,
            )
            session.add(asset)
            session.flush()
            import_components(
                session,
                asset,
                [
                    Component(
                        name=package, ecosystem=ecosystem, version=version, ref=f"demo-{index}"
                    ),
                    Component(
                        name="example-logging", ecosystem=ecosystem, version="1.0.0", ref="logging"
                    ),
                ],
            )
            installation = session.scalar(
                select(Installation)
                .where(Installation.asset_id == asset.id, Installation.component.is_not(None))
                .order_by(Installation.id)
            )
            # Select by explicit ref; UUID order has no semantic meaning.
            installation = next(
                item
                for item in session.scalars(
                    select(Installation).where(Installation.asset_id == asset.id)
                )
                if item.component.get("ref") == f"demo-{index}"
            )
            alias = f"DEMO-2026-{index:04d}"
            payload: dict = {
                "id": alias,
                "aliases": [],
                "modified": "2026-11-01T12:00:00Z",
                "summary": [
                    "Remote Code Execution im HTTP-Handler",
                    "Manipulierte Eingaben umgehen die Validierung",
                    "Unkontrollierter Ressourcenverbrauch",
                    "Cross-Site Scripting im Template-Renderer",
                    "Mögliche Codeausführung in der Build-Pipeline",
                    "Pfadprüfung erlaubt unerwartete Dateizugriffe",
                ][index - 1],
                "details": "Fiktive Meldung zur Demonstration der Oberfläche. Paketnamen, Systeme, Bewertungen und Ausnutzungssignale sind Beispieldaten und beschreiben keine reale Schwachstelle.",
                "affected": [
                    {
                        "package": {"ecosystem": ecosystem, "name": package},
                        "ranges": [
                            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}
                        ],
                    }
                ],
                "database_specific": {"mycve_demo": True},
            }
            vulnerability = resolve_vulnerability(session, [alias])
            record_source(
                session,
                vulnerability,
                source="OSV",
                external_id=alias,
                payload=payload,
                url="https://osv.dev",
                modified=payload["modified"],
            )
            refresh_summary(session, vulnerability)
            vulnerability.cvss, vulnerability.kev = score, kev
            finding = evaluate(session, installation, vulnerability)
            if index == 2:
                finding.workflow = "in_progress"
                finding.notes = "Update wird im nächsten Wartungsfenster ausgerollt."
            finding.updated_at = now() - timedelta(hours=index * 2)
        job = ScanJob(
            status="succeeded",
            started_at=now() - timedelta(minutes=6),
            completed_at=now() - timedelta(minutes=5),
            result={
                "demo": True,
                "sources": {
                    name: "demo" for name in ["OSV", "CVE Program", "NVD", "CISA KEV", "BSI CSAF"]
                },
                "counts": {"packages": 12, "findings": 6},
                "errors": [],
            },
        )
        session.add(job)
        session.commit()
    return True
