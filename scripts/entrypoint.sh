#!/bin/sh
set -eu
if [ "${1:-}" = "api" ]; then
    alembic upgrade head
    exec mycve serve --host 0.0.0.0 --port 8000
fi
exec "$@"
