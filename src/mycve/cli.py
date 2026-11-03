import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(prog="mycve", description="Explainable vulnerability tracking")
    sub = parser.add_subparsers(dest="command", required=True)
    match = sub.add_parser("match", help="Match one component against an OSV JSON document offline")
    match.add_argument("--component", type=Path, required=True)
    match.add_argument("--advisory", type=Path, required=True)
    for name in ("serve", "demo"):
        command = sub.add_parser(name)
        command.add_argument("--host", default="127.0.0.1")
        command.add_argument("--port", type=int, default=8000)
    sub.add_parser("sync", help="Refresh feeds and findings once")
    args = parser.parse_args()
    if args.command == "match":
        from mycve import Component, match_osv

        result = match_osv(
            Component.model_validate_json(args.component.read_text()),
            json.loads(args.advisory.read_text()),
        )
        print(result.model_dump_json(indent=2))
        return
    try:
        from mycve.server.config import Settings
        from mycve.server.db import ScanJob, make_engine, sessions
    except ImportError as exc:
        raise SystemExit(
            'Server-Abhängigkeiten fehlen: pip install "mycve-tracker[server]"'
        ) from exc
    if args.command == "demo":
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            raise SystemExit("Demo ohne Authentifizierung ausschließlich auf Loopback starten")
        from mycve.server.demo import seed_demo

        settings = Settings(
            database_url="sqlite:///./demo.db",
            demo_mode=True,
            allow_unauthenticated=True,
            api_key="",
            task_mode="inline",
        )
        seed_demo(make_engine(settings.database_url))
    else:
        settings = Settings()
    if args.command == "sync":
        from mycve.server.scanner import run_scan

        engine = make_engine(settings.database_url)
        if engine.dialect.name == "sqlite":
            from mycve.server.migrate import migrate_schema

            migrate_schema(engine)
        factory = sessions(engine)
        with factory() as session:
            job = ScanJob()
            session.add(job)
            session.commit()
            job_id = job.id
        run_scan(factory, settings, job_id)
        with factory() as session:
            job = session.get(ScanJob, job_id)
            print(
                json.dumps(
                    {"status": job.status, "result": job.result, "error": job.error}, indent=2
                )
            )
            if job.status != "succeeded":
                raise SystemExit(1)
        return
    import uvicorn

    from mycve.server.api import create_app

    uvicorn.run(create_app(settings), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
