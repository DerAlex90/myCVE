"""Exercise a running Compose stack without displaying credentials.

Run from the repository: uv run python scripts/smoke_stack.py
Set MYCVE_SMOKE_URL for a different local Caddy URL. This creates an explicit
verification asset and contacts the configured public vulnerability sources.
"""

import os
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import dotenv_values

root = Path(__file__).resolve().parent.parent
config = dotenv_values(root / ".env")
key = os.environ.get("MYCVE_API_KEY") or config.get("MYCVE_API_KEY")
if not key:
    raise SystemExit("MYCVE_API_KEY in .env oder Umgebung erforderlich")
base_url = os.environ.get("MYCVE_SMOKE_URL", "http://localhost:8080")

with httpx.Client(
    base_url=base_url,
    timeout=30,
    headers={"Authorization": f"Bearer {key}"},
    trust_env=urlparse(base_url).hostname not in {"localhost", "127.0.0.1", "::1"},
) as client:
    response = client.get("/health")
    response.raise_for_status()
    print("API and Caddy: healthy", flush=True)
    response = client.post(
        "/api/assets",
        json={
            "name": "stack-verification",
            "owner": "Integration verification",
            "exposure": "internal",
            "criticality": "low",
        },
    )
    if response.status_code == 409:
        response = client.get("/api/assets")
        response.raise_for_status()
        asset_id = next(
            asset["id"] for asset in response.json() if asset["name"] == "stack-verification"
        )
    else:
        response.raise_for_status()
        asset_id = response.json()["id"]
    response = client.post(
        f"/api/assets/{asset_id}/import",
        files={
            "file": (
                "inventory.csv",
                b"name,version,ecosystem,purl,ref\nidna,3.6,PyPI,pkg:pypi/idna@3.6,idna\n",
                "text/csv",
            )
        },
    )
    response.raise_for_status()
    response = client.post("/api/scans", json={"asset_id": asset_id})
    response.raise_for_status()
    job_id = response.json()["id"]
    for _ in range(120):
        jobs = client.get("/api/scans")
        jobs.raise_for_status()
        job = next(job for job in jobs.json() if job["id"] == job_id)
        if job["status"] not in {"queued", "running"}:
            print("Worker scan:", job["status"], flush=True)
            print("Source states:", job["result"].get("sources", {}), flush=True)
            for error in job["result"].get("errors", []):
                print(error, flush=True)
            if job["status"] != "succeeded":
                raise SystemExit("Stack scan did not finish successfully")
            break
        time.sleep(2)
    else:
        raise SystemExit("Stack scan timed out")
    findings = client.get("/api/findings", params={"asset_id": asset_id})
    findings.raise_for_status()
    assert findings.json()["total"] >= 1, "Expected an advisory for the explicit idna 3.6 fixture"
    detail = client.get("/api/findings/" + findings.json()["items"][0]["id"])
    detail.raise_for_status()
    assert detail.json()["sources"] and detail.json()["history"]
    print("Inventory → Redis → Celery → feeds → PostgreSQL → findings/history: passed", flush=True)
