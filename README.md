# glance-cert-status

A small, read-only TLS certificate status service for [Glance](https://github.com/glanceapp/glance).

It periodically checks configurable HTTPS/TLS endpoints, keeps healthy certificates quiet, and shows expiring or invalid certificates in Glance and local aggregators. It requires no credentials and sends no HTTP requests or application data to monitored endpoints.

- TLS connectivity, certificate dates, hostname validity and certificate chain trust
- Global and per-target warning/critical expiry thresholds
- Glance widget with healthy details collapsed and problems expanded
- JSON `attention` array for `glance-needs-attention`
- Linux `amd64` and `arm64` release binaries

## Endpoints

The default listen address is **`127.0.0.1:8796`**.

| Endpoint | Purpose |
| --- | --- |
| `/health` | JSON summary; HTTP 503 if any target is critical, otherwise 200 (including warnings or no enabled targets) |
| `/status` | Full JSON certificate metadata and `attention` items; HTTP 200 even when a target fails |
| `/widget` | Glance extension HTML |
| `/` | Redirect to `/widget` |

A failing or expiring certificate appears in `attention`:

```json
{
  "attention": [
    {
      "name": "Example API",
      "url": "https://api.example.com",
      "status": "warning",
      "message": "expires in 18 days",
      "daysRemaining": 18,
      "notAfter": "2026-10-17T00:00:00Z"
    }
  ]
}
```

When no target needs attention, `attention` is `[]`. Individual unreachable endpoints become critical results; they do not stop the daemon. A refresh replaces the previous snapshot after all enabled targets have been checked. The first refresh completes before the HTTP listener starts. Checks run at most eight at a time, so large target lists can take multiple timeout periods to refresh.

## Configuration

The default path is `/etc/cert-status.json`; override it with `CONFIG_FILE` (in `/etc/cert-status.env` when using systemd).

```json
{
  "title": "Certificates",
  "listenAddr": "127.0.0.1:8796",
  "refreshInterval": "6h",
  "connectTimeout": "10s",
  "defaultWarningDays": 30,
  "defaultCriticalDays": 7,
  "targets": [
    {
      "name": "Website",
      "url": "https://example.com",
      "enabled": true
    },
    {
      "name": "API",
      "url": "https://api.example.com:8443",
      "warningDays": 21,
      "criticalDays": 5
    }
  ]
}
```

The values above show the global defaults. Missing or zero thresholds inherit defaults; negative values are rejected. `criticalDays` must be less than `warningDays`, including after inheritance. Expiry thresholds are inclusive and use whole remaining days rounded down for certificates that have not expired. Invalid dates, hostname mismatches, untrusted chains, trust-store errors and TLS connection failures are critical.

Durations must be positive Go durations such as `30m`, `6h` or `10s`. `connectTimeout` covers connection establishment and the TLS handshake together. `enabled` defaults to true; false skips the check. Disabled entries are still validated at startup.

URLs must use `https`, with a DNS hostname or IP address and an optional port from 1 to 65535. The default port is 443. Bracket IPv6 addresses, for example `https://[2001:db8::1]:8443`. Use ASCII/punycode DNS names. URL credentials are rejected; paths, queries and fragments are ignored and never fetched.

`serverName` optionally overrides both the certificate identity to verify and the TLS SNI name. For example, `"url": "https://192.0.2.10:8443", "serverName": "api.example.com"` connects to that IP but checks the DNS identity. IP identities are verified against IP subject alternative names; Go does not send IP literals as SNI. IPv6 interface zones are used only for dialing.

Restart the service after configuration changes.

## Install from a GitHub Release

Requires Linux, systemd, `curl`, `sha256sum`, `install`, and the system CA trust store. On Arch Linux:

```bash
sudo pacman -S --needed ca-certificates curl coreutils
```

This downloads the installer and supporting files into a temporary directory, verifies the release binary's SHA-256 checksum, installs it, and enables the service. No source checkout or Go installation is needed:

```bash
(
  set -eu
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' 0
  trap 'exit 130' INT
  trap 'exit 143' TERM
  base=https://raw.githubusercontent.com/craigchandler/glance-cert-status/main
  for file in scripts/install-release.sh scripts/install-systemd.sh systemd/cert-status.service config.example.json .env.example; do
    mkdir -p "$tmp/$(dirname "$file")"
    curl -fL --proto '=https' --proto-redir '=https' -o "$tmp/$file" "$base/$file"
  done
  sudo sh "$tmp/scripts/install-release.sh"
  sudo sh "$tmp/scripts/install-systemd.sh"
)
```

The installer creates the unprivileged `certstatus` user/group. New configuration is owned by `root:certstatus` with mode `0640`; the environment file and unit are owned by root with mode `0644`. Existing configuration and environment files, including symlinks, are preserved. The binary is installed at `/usr/local/bin/cert-status`.

The initial example targets are generic. Edit them and restart:

```bash
sudoedit /etc/cert-status.json
sudo systemctl restart cert-status
cert-status --version
systemctl status cert-status
curl -fsS http://127.0.0.1:8796/status
```

From a source checkout, the same installers can be used directly:

```bash
sudo ./scripts/install-release.sh          # latest release
# Or: sudo ./scripts/install-release.sh v0.1.0
sudo ./scripts/install-systemd.sh
```

The systemd installer may be run from any working directory and never overwrites existing `/etc/cert-status.json` or `/etc/cert-status.env`. It enables startup after reboot. Re-running it does not restart an already running service; restart explicitly after upgrades or edits.

## Glance integration

```yaml
- type: extension
  url: http://127.0.0.1:8796/widget
  cache: 30m
  allow-potentially-dangerous-html: true
```

Alternatively include `glance/cert-status.yml` according to your layout. The service supplies `Widget-Title`. Loopback addresses assume Glance and this helper share the host network namespace; a container's `127.0.0.1` refers to that container.

## Needs Attention integration

Configure `glance-needs-attention` to consume `http://127.0.0.1:8796/status` and expand the `attention` array:

```json
{
  "name": "Certificates",
  "type": "generic-json",
  "url": "http://127.0.0.1:8796/status",
  "settings": {
    "rules": [
      {
        "forEach": "attention",
        "path": "status",
        "op": "truthy",
        "severityPath": "status",
        "message": "{{name}}: {{message}}"
      }
    ]
  }
}
```

This produces an actionable item such as `Example API: expires in 6 days`.

## Build and test

Requires Go 1.22 or later. CI and releases use the current stable Go toolchain so release binaries receive runtime security fixes; `go.mod` retains the language minimum.

```bash
make check
# Or:
go test ./...
go vet ./...
go build -o cert-status ./cmd/cert-status
```

Tests use generated certificates and local loopback listeners; they require no external endpoints and do not modify the system trust store. `go test -race ./...` additionally checks concurrent state access. CI checks formatting, tests, race detection, vet, build and shell syntax.

To install a source build, run `sudo install -m 0755 cert-status /usr/local/bin/cert-status`, then `sudo ./scripts/install-systemd.sh`. Local binaries and `dist/` are ignored by Git; distribute binaries through GitHub Releases.

## Releases and upgrades

After committing and pushing the source, pushing a tag matching `v*` runs tests and vet, cross-compiles with `CGO_ENABLED=0`, embeds the tag as the version, and publishes:

```text
cert-status-linux-amd64
cert-status-linux-amd64.sha256
cert-status-linux-arm64
cert-status-linux-arm64.sha256
```

For example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Each checksum contains only the asset's basename, so `sha256sum -c cert-status-linux-amd64.sha256` works beside the downloaded binary. The workflow checks the files before publication.

To upgrade, repeat the release installation above (existing configuration is preserved), then:

```bash
sudo systemctl restart cert-status
cert-status --version
curl -fsS http://127.0.0.1:8796/status
```

With a checkout, `sudo ./scripts/install-release.sh v0.1.0` selects a specific version for installation or rollback; restart afterward. Review release notes for configuration changes before downgrading.

## Troubleshooting

- Inspect startup/configuration errors with `journalctl -u cert-status -b -n 50 --no-pager`.
- If the listener is not yet available, allow time for the initial checks. Confirm the service is running and the configured port is free.
- HTTP 503 from `/health` means at least one target is critical; read `/status` for the individual result. Warnings alone return 200.
- For timeouts, check DNS and outbound connectivity from the host. A failed target should remain visible as critical while other checks continue.
- For trust failures, check the host's CA certificates and whether the endpoint serves its intermediate chain. For private CAs, install the CA through the operating system's trust-store mechanism. Do not bypass verification.
- For date failures, check the host clock and the certificate dates. For name failures, check the URL hostname and any `serverName` override.
- The service user must be able to read the configured JSON path. The unit's `ProtectHome=true` prevents reading configuration under home directories; use `/etc`.

## Security model

TLS inspection deliberately works in three steps:

1. Establish TLS with automatic certificate validation disabled, allowing retrieval of expired, not-yet-valid, hostname-invalid and untrusted certificates.
2. Independently check dates and hostname, then verify the chain against the system CA trust store using peer certificates only as intermediates.
3. Report validation failures as critical status. **Invalid certificates are never treated as trusted.**

TLS 1.2 is the minimum. The helper sends no application data or credentials. It does not fetch missing intermediates or perform OCSP/CRL revocation checks; Go's [`x509.Verify`](https://pkg.go.dev/crypto/x509#Certificate.Verify) validates the supplied chain, not revocation status. `chainValid` reflects the full verification result, including identity and validity dates.

Configuration is trusted administrator input and cannot be changed over HTTP. Connecting to administrator-selected public or private hosts is intentional. Concurrent TLS checks and network waits are bounded. HTTP requests use header/read/write/idle timeouts and a header size limit; widget data is escaped by Go `html/template`. The systemd unit runs without root privileges or capabilities and retains access to DNS, TCP/TLS and system trust files.

There is no authentication. Keep the default localhost binding unless you deliberately provide appropriate access controls. `/status` exposes target names, URLs, hostnames, subjects, issuers, serial numbers and validity dates; exposing it beyond localhost can disclose infrastructure metadata. Checks are periodic snapshots, not continuous availability guarantees.

## License

[MIT](LICENSE), copyright (c) 2026 Craig Chandler.
