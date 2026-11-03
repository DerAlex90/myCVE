# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS frontend
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca; fi; \
    npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.27-alpine AS agents
RUN --mount=type=bind,source=agent,target=/src/agent,readonly \
    --mount=type=bind,source=LICENSE,target=/src/LICENSE,readonly \
    --mount=type=cache,id=mycve-go-mod,target=/go \
    --mount=type=cache,id=mycve-go-build,target=/root/.cache/go-build \
    --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    cd /src/agent && GOFLAGS=-mod=readonly go mod download \
    && GOFLAGS=-mod=readonly go run ./cmd/package --out /releases

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    MYCVE_FRONTEND_DIR=/app/frontend/dist MYCVE_DATABASE_URL=sqlite:////data/mycve.db
WORKDIR /app
COPY requirements-server.txt ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir -r requirements-server.txt
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ src/
COPY migrations/ migrations/
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir --no-deps .
COPY alembic.ini ./
COPY scripts/entrypoint.sh /usr/local/bin/mycve-entrypoint
COPY --from=frontend /web/dist/ frontend/dist/
COPY --from=agents /releases/*.zip /releases/*.tar.gz /releases/SHA256SUMS /app/dist/agent/
RUN groupadd --gid 10001 mycve && useradd --uid 10001 --gid mycve --no-create-home mycve \
    && mkdir /data && chown mycve:mycve /data && chmod -R a+rX /app \
    && chmod 0755 /usr/local/bin/mycve-entrypoint
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["mycve-entrypoint"]
CMD ["api"]
