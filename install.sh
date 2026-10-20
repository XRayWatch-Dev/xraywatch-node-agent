#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"
command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
docker compose version --short >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }
[ -f .env ] || { echo "Missing .env; copy .env.example to .env and configure it first" >&2; exit 1; }
docker compose config >/dev/null
docker compose pull
docker compose run --rm -it xraywatch-node-agent --enroll
docker compose up -d
echo "XRayWatch node agent started. Firewall rules were not changed."

