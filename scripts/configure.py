"""Generate local secrets without printing their values or replacing existing settings."""

import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parent.parent
destination = root / ".env"
if destination.exists():
    raise SystemExit(".env existiert bereits und wurde nicht geändert.")
content = (root / ".env.example").read_text()
content = content.replace("replace-with-a-random-hex-password", secrets.token_hex(24))
content = content.replace("replace-with-a-random-api-key", secrets.token_urlsafe(48))
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w") as stream:
    stream.write(content)
print(".env mit zufälligen Zugangsdaten angelegt. Start: docker compose up --build -d")
print(
    "Anschließend http://localhost:8080 öffnen. Den API-Schlüssel aus .env zum Anmelden verwenden."
)
