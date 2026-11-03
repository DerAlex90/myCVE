# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Bundle tracked sources and built distributions without local inventory or secrets."""

import hashlib
import shutil
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=ROOT, check=True)
    tracked = [
        Path(p)
        for p in subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        if p
    ]
    python_files = [
        ROOT / "dist" / f"mycve_tracker-{version}-py3-none-any.whl",
        ROOT / "dist" / f"mycve_tracker-{version}.tar.gz",
    ]
    agent_files = [
        ROOT / "dist/agent" / f"mycve-agent-{platform}-{arch}.{extension}"
        for platform, extension in [("linux", "tar.gz"), ("windows", "zip")]
        for arch in ["amd64", "arm64"]
    ]
    license_bytes = (ROOT / "LICENSE").read_bytes()
    notice_bytes = (ROOT / "NOTICE").read_bytes()
    for path in python_files + agent_files:
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"Build the distribution first: {path}")
    for path in agent_files:
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                for name, expected in [("LICENSE", license_bytes), ("NOTICE", notice_bytes)]:
                    entry = next(n for n in archive.namelist() if n.endswith("/" + name))
                    if archive.read(entry) != expected:
                        raise RuntimeError(f"Incorrect {name} in {path.name}")
        else:
            with tarfile.open(path) as archive:
                for name, expected in [("LICENSE", license_bytes), ("NOTICE", notice_bytes)]:
                    member = next(m for m in archive.getmembers() if m.name.endswith("/" + name))
                    stream = archive.extractfile(member)
                    if stream is None or stream.read() != expected:
                        raise RuntimeError(f"Incorrect {name} in {path.name}")
    with zipfile.ZipFile(python_files[0]) as wheel:
        if (
            wheel.read("mycve/LICENSE") != license_bytes
            or wheel.read("mycve/NOTICE") != notice_bytes
        ):
            raise RuntimeError("Incorrect Python distribution license files")
    web_files = [p.relative_to(ROOT) for p in (ROOT / "frontend/dist").rglob("*") if p.is_file()]
    if not any(p.name == "THIRD_PARTY_NOTICES.txt" for p in web_files):
        raise RuntimeError("Build the frontend including its third-party notices first")
    files = set(
        tracked
        + web_files
        + [p.relative_to(ROOT) for p in python_files + agent_files]
        + [Path("dist/agent/SHA256SUMS")]
    )
    for path in files:
        if (
            path.name == ".env"
            or set(path.parts) & {"node_modules", ".venv", "backups", "data", "__pycache__"}
            or path.suffix in {".db", ".sqlite", ".sqlite3", ".dump", ".pyc"}
        ):
            raise RuntimeError(f"Local runtime file must not be published: {path}")
    bundle = ROOT / "dist" / f"myCVE-{version}.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files):
            archive.write(ROOT / path, f"myCVE-{version}/{path.as_posix()}")
    with zipfile.ZipFile(bundle) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Bundle checksum verification failed")
    release_dir = ROOT / "dist/releases" / f"v{version}"
    release_dir.mkdir(parents=True, exist_ok=True)
    assets = [bundle] + python_files + agent_files + [ROOT / "LICENSE", ROOT / "NOTICE"]
    expected_names = {p.name for p in assets} | {"SHA256SUMS"}
    if any(p.name not in expected_names for p in release_dir.iterdir()):
        raise RuntimeError(f"Unexpected file in release directory: {release_dir}")
    for path in assets:
        shutil.copyfile(path, release_dir / path.name)
    checksums = [
        f"{hashlib.sha256((release_dir / p.name).read_bytes()).hexdigest()}  {p.name}\n"
        for p in sorted(assets)
    ]
    (release_dir / "SHA256SUMS").write_text("".join(checksums))
    print(f"Built {release_dir.relative_to(ROOT)}: {len(assets)} assets and SHA256SUMS")


if __name__ == "__main__":
    main()
