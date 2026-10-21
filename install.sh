#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"
command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
docker compose version --short >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }
[ -f .env ] || { echo "Missing .env; copy .env.example to .env and configure it first" >&2; exit 1; }
: "${XRAYWATCH_CONTROL_URL:?set XRAYWATCH_CONTROL_URL}"
: "${XRAYWATCH_TRUST_KEY:?set XRAYWATCH_TRUST_KEY}"
XRAYWATCH_LISTEN_PORT=${XRAYWATCH_LISTEN_PORT:-18443}
XRAYWATCH_CONTROL_FALLBACK_URLS=${XRAYWATCH_CONTROL_FALLBACK_URLS:-}
escape_env() { printf '%s' "$1" | sed 's/[|&\\]/\\&/g'; }
sed -i \
  -e "s|^XRAYWATCH_CONTROL_URL=.*|XRAYWATCH_CONTROL_URL=$(escape_env "$XRAYWATCH_CONTROL_URL")|" \
  -e "s|^XRAYWATCH_CONTROL_FALLBACK_URLS=.*|XRAYWATCH_CONTROL_FALLBACK_URLS=$(escape_env "$XRAYWATCH_CONTROL_FALLBACK_URLS")|" \
  -e "s|^XRAYWATCH_TRUST_KEY=.*|XRAYWATCH_TRUST_KEY=$(escape_env "$XRAYWATCH_TRUST_KEY")|" \
  -e "s|^XRAYWATCH_LISTEN_PORT=.*|XRAYWATCH_LISTEN_PORT=$(escape_env "$XRAYWATCH_LISTEN_PORT")|" \
  .env
docker compose config >/dev/null
docker compose build
docker compose run --rm -it xraywatch-node-agent --enroll
docker compose up -d
echo "XRayWatch node agent started. Firewall rules were not changed."

