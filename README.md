# whodis

[![CI](https://github.com/Alex9001/whodis/actions/workflows/ci.yml/badge.svg)](https://github.com/Alex9001/whodis/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Alex9001/whodis?display_name=tag)](https://github.com/Alex9001/whodis/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A modern WHOIS alternative that automatically uses RDAP where traditional WHOIS falls short.**

The registry world is split between old-school WHOIS and modern RDAP. `whodis` hides that split: give it a domain, IP address, network, or ASN and it finds the right service automatically. No protocol trivia required.

Instead of dumping a wall of registry text, it turns the answer into a compact terminal dashboard. Registration facts, dates, DNS, contacts, and routing details each get the space they need.

```text
$ whodis example.com
╭─ WHODIS · DOMAIN ────────────────────────────────────────────────────────────╮
│ example.com                                                                  │
│ [RDAP] [ACTIVE] [CLIENT TRANSFER PROHIBITED]                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Registration ────────────────────────────╮  ╭─ Timeline ────────────────────╮
│ Registrar  Example Registrar Inc.         │  │ Registered  1995-08-14        │
│ Handle     2336799_DOMAIN_COM-VRSN        │  │ Expires     2026-08-13        │
│ Registry   Example Registry               │  │ Updated     2025-08-14        │
╰───────────────────────────────────────────╯  ╰───────────────────────────────╯
╭─ DNS ─────────────────────────────────────╮  ╭─ Contacts ────────────────────╮
│ DNSSEC  signed delegation                 │  │ REGISTRANT · TECHNICAL        │
│ A.IANA-SERVERS.NET                        │  │ Example Registry · id-1234    │
│ B.IANA-SERVERS.NET                        │  │                               │
╰───────────────────────────────────────────╯  ╰───────────────────────────────╯
╭─ Source ─────────────────────────────────────────────────────────────────────╮
│ rdap.example.net · IANA bootstrap · 2 notices hidden · use --details         │
╰──────────────────────────────────────────────────────────────────────────────╯
```

The dashboard adapts to the terminal: wide windows use a multi-panel mosaic, while narrow windows stack the same semantic panels into one column. Contacts stay visible but are consolidated instead of repeated. Lengthy registry notices are summarized by count; add `--details` when you want their full text and links. The flag affects only the pretty dashboard; other output formats remain unchanged.

## What you get

- **Automatic protocol selection** — RDAP for registries that support it, WHOIS where it is still needed.
- **Responsive terminal dashboard** — semantic panels reorganize themselves to use the available width without repeating the same contacts or notices.
- **Script-friendly formats** — output plain text, JSON, YAML, Markdown, or the raw registry response.
- **Direct file export** — use `--output result.json` and Whodis infers the format from the extension.
- **More than domains** — look up IPv4, IPv6, CIDR networks, and autonomous system numbers such as `AS15169`.
- **Cross-platform builds** — the same CLI is designed for Linux, macOS, and Windows.

## Install

### Linux and macOS

```bash
curl -fsSL https://github.com/Alex9001/whodis/releases/latest/download/install.sh | sh
```

The installer detects your operating system and CPU, verifies the release
checksum, and places `whodis` in `/usr/local/bin`. It asks for `sudo` only if
that directory is not writable.

### Windows

Run in PowerShell—no administrator window is required:

```powershell
irm https://github.com/Alex9001/whodis/releases/latest/download/install.ps1 | iex
```

The installer puts Whodis under your local application-data directory and adds
it to your user `PATH` without creating duplicate entries.

### With Go

If you already have Go installed:

```bash
go install github.com/Alex9001/whodis/cmd/whodis@latest
```

Go installs the binary into `GOBIN` (normally `~/go/bin`). Make sure that
directory is on `PATH`.

Prebuilt archives for every supported platform and `checksums.txt` are also
available on the [latest GitHub Release](https://github.com/Alex9001/whodis/releases/latest).

The source-built AUR package is prepared but cannot be submitted until the
maintainer's AUR account is registered. The exact one-time publication steps
are preserved in [AUR_HANDOFF.md](AUR_HANDOFF.md); after publication Arch users
will be able to install it with `yay -S whodis` or `paru -S whodis`.

## Quick start

Once installed, use it from any directory:

```bash
whodis google.com
```

## Common examples

```bash
# Domains use RDAP or WHOIS automatically
whodis example.com

# IP addresses and ASNs work the same way
whodis 8.8.8.8
whodis AS15169

# Print machine-readable data
whodis example.com --format json

# Expand registry notices in the terminal dashboard
whodis example.com --details

# Export to a file; .yaml selects YAML automatically
whodis AS15169 --output google-asn.yaml

# Get clean, unstyled terminal text
whodis example.com --format plain
```

## Command-line options

```text
whodis <target> [options]

-f, --format pretty|plain|json|yaml|markdown|raw
-o, --output <file|->
    --protocol auto|rdap|whois
    --fallback unavailable|none|any-error
    --server <endpoint>
    --timeout <duration>
    --refresh-bootstrap
    --color auto|always|never
    --details
    --force
-h, --help
    --version
```

When `--format` is omitted with `--output`, Whodis infers JSON, YAML, Markdown, or plain text from the filename. Existing files are protected unless `--force` is supplied.

## How protocol selection works

Whodis fetches and caches IANA's RDAP bootstrap registries for domains, IPv4, IPv6, and ASNs. Domain routes use the longest matching registry suffix, IP routes use the longest matching network prefix, and ASN routes use IANA's number ranges. HTTPS endpoints are preferred, and secondary endpoints are tried before switching protocols.

When IANA does not list an RDAP service for a target, Whodis asks `whois.iana.org` for the authoritative WHOIS server and follows a bounded referral chain. The first registration lookup therefore goes to the protocol known for that target instead of blindly trying services in sequence.

The default `--fallback unavailable` mode tries the alternate protocol only when the selected service is unavailable or unusable. Authoritative not-found and rate-limit responses remain visible. Use `--fallback any-error` for wider diagnostic coverage or `--fallback none` for a strict single-protocol lookup.

## Go API and future interfaces

The protocol engine is independent of terminal rendering. That keeps the same lookup and normalized result model reusable from a future Wails desktop interface or another Go application.

The public API is centered on:

```go
import "github.com/Alex9001/whodis"

client := whodis.NewClient(whodis.ClientOptions{})
route, err := client.Route(ctx, "example.com", whodis.LookupOptions{})
result, err := client.Lookup(ctx, "example.com", whodis.LookupOptions{})
```

`LookupResult` is a versioned model containing the query, routing decision, normalized registration data, notices, and registry sources. Native RDAP JSON and raw WHOIS text remain available through `--format raw`.

Additional protocols can implement `ProtocolAdapter` without coupling them to the CLI or a particular operating system.

## Development

```bash
git clone https://github.com/Alex9001/whodis.git
cd whodis
go test ./...
go vet ./...
go run ./cmd/whodis example.com
```

Tests use local normalizer and renderer fixtures; public registries are not queried during the test suite. Live checks are intentionally manual because registry availability and query limits are external conditions.

## Current limitations

The current release implements RDAP and standard port-43 WHOIS. RWhois, proprietary registration APIs, authenticated RDAP, web scraping, desktop GUI, and mobile apps are not implemented yet.

## License

MIT © 2026 Aleksandr Oreshkin. See [LICENSE](LICENSE).
