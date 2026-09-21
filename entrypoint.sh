#!/bin/sh
# entrypoint.sh - Dual-path injection for bootstrap compatibility

CONFIG_DIR="/app/config"
DEFAULT_FILE="/app/static_defaults/defaults.json"

# Ensure directories exist
mkdir -p "$CONFIG_DIR"

# 1. Inject into CWD (/app/defaults.json) for application bootloader
if [ ! -f /app/defaults.json ]; then
    cp "$DEFAULT_FILE" /app/defaults.json
    echo "[DEBUG] ENTRYPOINT: Injected to /app/defaults.json"
fi

# 2. Inject into persistent volume (/app/config/defaults.json) for persistence
if [ ! -f "$CONFIG_DIR/defaults.json" ]; then
    cp "$DEFAULT_FILE" "$CONFIG_DIR/defaults.json"
    echo "[DEBUG] ENTRYPOINT: Injected to $CONFIG_DIR/defaults.json"
fi

# Run the default boot command only when no override is passed (the
# normal case -- nothing in docker-compose.yaml sets one). Otherwise
# exec whatever was given, e.g. `docker compose run netlanvas_api
# pip freeze` now actually runs pip freeze instead of silently
# ignoring it and booting the full app anyway.
if [ "$#" -eq 0 ]; then
    exec python src/main.py
else
    exec "$@"
fi
