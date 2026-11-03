"""Apply the prepared About fields using an owner-authorized GitHub CLI session."""

import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Set myCVE's prepared GitHub About fields")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show proposed values without contacting GitHub"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    metadata = json.loads((root / ".github/repository-metadata.json").read_text())
    if args.dry_run:
        print(json.dumps(metadata, ensure_ascii=False, indent=2))
        return
    repository = metadata["repository"]
    updates = [
        (
            "PATCH",
            f"repos/{repository}",
            {"description": metadata["description"], "homepage": metadata["homepage"]},
        ),
        ("PUT", f"repos/{repository}/topics", {"names": metadata["topics"]}),
    ]
    try:
        for method, endpoint, payload in updates:
            subprocess.run(
                ["gh", "api", "--method", method, endpoint, "--input", "-", "--silent"],
                input=json.dumps(payload),
                text=True,
                check=True,
            )
    except FileNotFoundError:
        raise SystemExit("GitHub CLI fehlt. Anleitung: docs/github-about.md") from None
    except subprocess.CalledProcessError:
        raise SystemExit(
            "GitHub hat die Änderung abgewiesen. Der Zugang benötigt Administration-Schreibrechte; alternativ About im Browser bearbeiten. Siehe docs/github-about.md."
        ) from None
    print("GitHub-Beschreibung, Dokumentationslink und Topics aktualisiert.")


if __name__ == "__main__":
    main()
