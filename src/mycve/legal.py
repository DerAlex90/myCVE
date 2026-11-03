# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Public attribution and packaged license text; no server imports."""

from pathlib import Path

AUTHOR = "Alexander Speka (DerAlex90)"
COPYRIGHT = "Copyright (c) 2026 Alexander Speka (DerAlex90)"
LICENSE_ID = "LicenseRef-myCVE-Attribution-1.0"
PROJECT_URL = "https://github.com/DerAlex90/myCVE"


def license_text() -> str:
    bundled = Path(__file__).with_name("LICENSE")
    location = bundled if bundled.is_file() else Path(__file__).resolve().parents[2] / "LICENSE"
    return location.read_text(encoding="utf-8")
