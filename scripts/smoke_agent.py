"""Run the compiled Linux agent against an isolated real HTTP server.

No inventory is sent to third-party services. The temporary server and state are
removed afterwards. The test proves intake, device identity, revocation, durable
retry and authorized server downloads without exposing device credentials.
"""

import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import create_engine, make_url
from sqlalchemy.schema import CreateSchema, DropSchema

from mycve.server.migrate import migrate_schema

root = Path(__file__).resolve().parent.parent
architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
binary = Path(
    os.environ.get("MYCVE_AGENT_BINARY", root / f"dist/agent/bin/linux-{architecture}/mycve-agent")
)
if not binary.is_file():
    raise SystemExit("Build agent packages first: cd agent && go run ./cmd/package")

with ExitStack() as resources, tempfile.TemporaryDirectory(prefix="mycve-agent-live-") as temporary:
    directory = Path(temporary)
    database_url = "sqlite:///" + str(directory / "server.db")
    postgres_url = os.environ.get("MYCVE_SMOKE_POSTGRES_URL")
    if postgres_url:
        schema = "mycve_live_" + uuid4().hex
        admin = create_engine(postgres_url)
        with admin.begin() as connection:
            connection.execute(CreateSchema(schema))

        def cleanup_schema():
            with admin.begin() as connection:
                connection.execute(DropSchema(schema, cascade=True))
            admin.dispose()

        resources.callback(cleanup_schema)
        url = make_url(postgres_url)
        database_url = url.set(
            query={**url.query, "options": "-csearch_path=" + schema}
        ).render_as_string(hide_password=False)
        prepared = create_engine(database_url)
        try:
            migrate_schema(prepared)
        finally:
            prepared.dispose()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    admin_key = secrets.token_urlsafe(48)
    environment = {
        **os.environ,
        "MYCVE_DATABASE_URL": database_url,
        "MYCVE_API_KEY": admin_key,
        "MYCVE_ALLOW_UNAUTHENTICATED": "false",
        "MYCVE_TASK_MODE": "inline",
        "MYCVE_DEMO_MODE": "false",
        "MYCVE_AGENT_RELEASES_DIR": str(root / "dist/agent"),
    }
    with (directory / "server.log").open("w") as output:
        server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "mycve.server.api:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=root,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    try:
        with httpx.Client(
            base_url=base_url,
            trust_env=False,
            timeout=30,
            headers={"Authorization": "Bearer " + admin_key},
        ) as client:
            for _ in range(100):
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.ConnectError:
                    pass
                if server.poll() is not None:
                    raise RuntimeError(
                        "Isolated server failed to start: "
                        + (directory / "server.log").read_text()[-3000:]
                    )
                time.sleep(0.1)
            else:
                raise RuntimeError("Isolated server startup timed out")
            response = client.post("/api/assets", json={"name": "isolated-agent-verification"})
            response.raise_for_status()
            asset = response.json()
            response = client.post("/api/agents", json={"asset_id": asset["id"]})
            response.raise_for_status()
            registration = response.json()
            config = {
                **registration["configuration"],
                "server_url": base_url,
                "allow_insecure_localhost": True,
                "state_dir": str(directory / "state"),
            }
            config_path = directory / "agent.json"

            def save_config():
                config_path.write_text(json.dumps(config))
                config_path.chmod(0o600)

            def once():
                return subprocess.run(
                    [str(binary), "once", "--config", str(config_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

            save_config()
            first = once()
            assert first.returncode == 0, first.stderr
            first_agent = client.get("/api/agents").json()[0]
            assert first_agent["status"] == "online" and first_agent["packages"] > 0
            second = once()
            assert second.returncode == 0, second.stderr
            current = client.get("/api/agents").json()[0]
            assert current["device_id"] == first_agent["device_id"]
            snapshots = client.get(f"/api/agents/{current['id']}/snapshots").json()
            assert snapshots["total"] == 2
            assert snapshots["items"][0]["changes"] == {"added": 0, "updated": 0, "removed": 0}
            listing = client.get(f"/api/assets/{asset['id']}/components?limit=5").json()
            assert listing["total"] == current["packages"] and listing["items"][0]["inventory"]
            assert (
                client.get(
                    "/api/assets", headers={"Authorization": "Bearer " + config["token"]}
                ).status_code
                == 401
            )
            client.delete(f"/api/agents/{current['id']}").raise_for_status()
            rejected = once()
            assert rejected.returncode != 0 and (directory / "state/pending.json").is_file()
            response = client.post(f"/api/agents/{current['id']}/rotate-token")
            response.raise_for_status()
            config["token"] = response.json()["configuration"]["token"]
            save_config()
            recovered = once()
            assert recovered.returncode == 0, recovered.stderr
            assert not (directory / "state/pending.json").exists()
            assert client.get(f"/api/agents/{current['id']}/snapshots").json()["total"] == 4
            files = client.get("/api/agents/downloads").json()
            assert len(files) == 5
            response = client.get("/api/agents/downloads/SHA256SUMS")
            response.raise_for_status()
            assert "mycve-agent-windows-amd64.zip" in response.text
            print(
                f"Live Linux agent: {current['packages']} packages stored; stable device ID, replay, revocation and retry passed."
            )
            print(
                "Server inventory, raw snapshots, change history and protected downloads verified."
            )
            print(
                "Database:",
                "PostgreSQL, isolated schema" if postgres_url else "SQLite, temporary database",
            )
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
