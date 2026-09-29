#!/bin/sh
set -eu

REPO="${CERT_STATUS_REPO:-craigchandler/glance-cert-status}"
VERSION="${1:-latest}"
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/cert-status}"

[ "$(uname -s)" = Linux ] || { echo "Only Linux is supported" >&2; exit 1; }
[ "$#" -le 1 ] || { echo "Usage: $0 [latest|version]" >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

NAME="cert-status-linux-${ARCH}"
if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/${REPO}/releases/latest/download"
else
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' 0
trap 'exit 130' INT
trap 'exit 143' TERM

curl --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 15 --max-time 180 -o "$TMP/$NAME" "$BASE/$NAME"
curl --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 15 --max-time 180 -o "$TMP/$NAME.sha256" "$BASE/$NAME.sha256"
(
  cd "$TMP"
  sha256sum -c "$NAME.sha256"
)
install -m 0755 "$TMP/$NAME" "$INSTALL_PATH"
"$INSTALL_PATH" --version
