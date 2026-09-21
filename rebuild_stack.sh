#!/bin/bash
set -e

# Dynamically resolve application root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

echo "=================================================="
echo " NetLanvas Stack: Teardown & Rebuild"
echo "=================================================="

cd "${SCRIPT_DIR}" || exit 1

echo "[*] Tearing down active containers and network bridges..."
docker compose down

echo "[*] Forcing clean image compilation and container recreation..."
docker compose up -d --build --force-recreate

echo "[*] Stack rebuild complete."
