#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "error: run with sudo"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UV_TOOL_BIN_DIR=/usr/local/sbin uv tool install "$SCRIPT_DIR"
cp "$SCRIPT_DIR/execguard.service" /etc/systemd/system/execguard.service
systemctl daemon-reload
systemctl enable execguard

if [ ! -f /etc/execguard.ini ]; then
    cp "$SCRIPT_DIR/execguard.example.ini" /etc/execguard.ini
    echo "Config created at /etc/execguard.ini — edit before starting the service."
fi

echo "Done. Run: systemctl start execguard"
