#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "error: run with sudo"; exit 1; }

systemctl disable --now execguard || true
rm -f /etc/systemd/system/execguard.service
systemctl daemon-reload
uv tool uninstall execguard

echo "Uninstalled. Config preserved at /etc/execguard.ini"
