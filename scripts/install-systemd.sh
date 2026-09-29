#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run this installer as root" >&2; exit 1; }
[ -x /usr/local/bin/cert-status ] || { echo "Install /usr/local/bin/cert-status first" >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

if ! id certstatus >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --shell /usr/bin/nologin certstatus
fi
[ "$(id -u certstatus)" -ne 0 ] || { echo "certstatus must not be root" >&2; exit 1; }

install -o root -g root -m 0644 systemd/cert-status.service /etc/systemd/system/cert-status.service
if [ ! -e /etc/cert-status.env ] && [ ! -L /etc/cert-status.env ]; then
  install -o root -g root -m 0644 .env.example /etc/cert-status.env
fi
if [ ! -e /etc/cert-status.json ] && [ ! -L /etc/cert-status.json ]; then
  install -o root -g certstatus -m 0640 config.example.json /etc/cert-status.json
fi
systemctl daemon-reload
systemctl enable --now cert-status
