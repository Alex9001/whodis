# whodis

[![CI](https://github.com/Alex9001/whodis/actions/workflows/ci.yml/badge.svg)](https://github.com/Alex9001/whodis/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Alex9001/whodis?display_name=tag)](https://github.com/Alex9001/whodis/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A modern WHOIS alternative that automatically uses RDAP where traditional WHOIS falls short — and maps the public DNS that registration data alone cannot show.**

The registry world is split between old-school WHOIS and modern RDAP. `whodis` hides that split: give it a domain, IP address, network, or ASN and it finds the right service automatically. No protocol trivia required.

Instead of dumping a wall of registry text, it can turn the answer into a compact terminal dashboard, a hierarchical tree, a 2002-style ASCII layout, or clean plain text. Registration facts, dates, discovered DNS records, contacts, and routing details each get the space they need.

```text
$ whodis example.com
╭─ Registration ──────────────────────╮ ╭─ Contacts · 1 ───────────────────────╮
│ [CLIENT TRANSFER PROHIBITED]        │ │ REGISTRANT / TECHNICAL               │
│                                     │ │   Example Registry · id-1234         │
│ Name       example.com              │ ╰──────────────────────────────────────╯
│ Handle     2336799_DOMAIN_COM-VRSN  │
│ Registrar  Example Registrar Inc.   │ ╭─ Timeline · 3 ───────────────────────╮
╰─────────────────────────────────────╯ │ Registered  1995-08-14               │
                                        │ Expires     2026-08-13               │
╭─ DNS · 2 ───────────────────────────╮ │ Updated     2025-08-14               │
│ DNSSEC  signed delegation           │ ╰──────────────────────────────────────╯
│                                     │
│ • A.IANA-SERVERS.NET                │ ╭─ Source ─────────────────────────────╮
│ • B.IANA-SERVERS.NET                │ │ Protocol   RDAP                      │
╰─────────────────────────────────────╯ │ Authority  rdap.example.net          │
                                        │ Discovery  IANA bootstrap            │
                                        │ Notices    2 hidden · use --details  │
                                        ╰──────────────────────────────────────╯
```

The dashboard adapts to the terminal: wide windows use a multi-panel mosaic, while narrow windows stack the same semantic panels into one column. Contacts stay visible but are consolidated instead of repeated. Lengthy registry notices are summarized by count; add `--details` when you want their full text and links. The flag also expands notices in the tree and GeekBoys views; plain and machine-readable formats remain unchanged.

For domain lookups, Whodis also performs a fast public-DNS discovery pass by default and adds a full-width, terminal-friendly record grid. It finds the useful common records—addresses, mail routing, verification and policy TXT records, service records, HTTPS/SVCB records, and nameservers—without turning one lookup into an uncontrolled crawl.

## What you get

- **Automatic protocol selection** — RDAP for registries that support it, WHOIS where it is still needed.
- **DNS discovery built in** — common public DNS records appear in an adaptive grid beside registration data; JSON, YAML, Markdown, and plain text include the same structured records.
- **Four terminal views** — switch between the responsive dashboard, a semantic tree, a retro ASCII layout, and plain text.
- **Persistent preferences** — save your favorite view once and use it automatically in terminals and pipelines.
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

## Choose your view

Use `--format` to change one lookup:

```bash
whodis example.com --format dashboard  # current responsive grid
whodis example.com --format tree
whodis example.com --format geekboys
whodis example.com --format plain
```

## DNS discovery

`whodis example.com` uses your system DNS resolver to discover common public
records while the RDAP/WHOIS lookup is in progress. The dashboard puts the
records in a Type / Name / Value / TTL grid; the other terminal views adapt the
same data to their own layouts.

The scan checks the apex plus practical names such as `www`, `api`, `mail`,
`autodiscover`, DMARC/MTA-STS/TLS reporting names, common DKIM selectors, and
well-known service records. It detects wildcard responses and avoids presenting
matching guesses as confirmed hostnames. CNAME, MX, NS, SRV, HTTPS, and SVCB
targets inside the queried domain get address follow-up where applicable.

DNS does not provide a general way to list every owner name in a zone, so the
normal result is explicitly marked as a discovery scan rather than a complete
zone. Use these controls when needed:

```bash
# Keep a registration-only lookup
whodis example.com --dns off

# Use a specific recursive resolver (the default is the system resolver)
whodis example.com --resolver 1.1.1.1

# Ask the domain's authoritative nameservers for a full zone transfer.
# This is never attempted automatically and most public zones correctly refuse it.
whodis example.com --axfr
```

If an explicit AXFR is refused or unavailable, Whodis returns the normal
discovery result with a warning instead of failing the registration lookup.

The tree uses the queried target as its root without repeating it inside the
Registration panel:

```text
example.com
├── Registration
│   ├── Status
│   │   └── CLIENT TRANSFER PROHIBITED
│   ├── Handle: 2336799_DOMAIN_COM-VRSN
│   └── Registrar: Example Registrar Inc.
├── DNS · 2
│   └── Nameservers
│       ├── A.IANA-SERVERS.NET
│       └── B.IANA-SERVERS.NET
└── Source
    ├── Protocol: RDAP
    └── Discovery: IANA bootstrap
```

The headerless `geekboys` view uses responsive ASCII-only geometry inspired by
the [2002 GeekBoys community layout](https://web.archive.org/web/20020328041200/http://www.geekboys.org/):

```text
.--- Registration ---------------------+
| + CLIENT TRANSFER PROHIBITED +       |
|                                      |
| Name     : example.com               |
| Handle   : 2336799_DOMAIN_COM-VRSN   |
| Registrar: Example Registrar Inc.    |
+--------------------------------------'
```

### Make Whodis yours

Run the built-in setup wizard once to choose the view that feels right. It uses
simple numbered prompts, keeps the current answer when you press Enter, and
shows a review before it saves anything:

```bash
whodis config
```

The wizard can save three display preferences:

- Output format: automatic, dashboard, tree, GeekBoys, or plain text
- Color: automatic, always, or never
- Registry notices: automatic, compact summary, or expanded details

Automatic format keeps the best default for the situation: the dashboard in a
terminal and plain text in a pipeline. Command-line options still win for a
single lookup, so `--no-details` temporarily returns notices to their compact
summary without changing the saved preference.

For scripts, configuration management stays direct and quiet:

```bash
whodis config set format tree
whodis config set color never
whodis config set details expanded
whodis config get format       # tree
whodis config unset details    # return that preference to automatic behavior
whodis config reset            # remove every saved display preference
whodis config path             # show the platform-specific config file
```

Because `config` is a command name, query that exact target with
`whodis -- config`.

An explicit `--format` always wins. `WHODIS_FORMAT` provides a temporary format
override and can also select JSON, YAML, Markdown, or raw output. Named output
files continue to take their format from the extension. Explicit `--color`,
`--details`, and `--no-details` likewise override the saved display choices.

Whodis stores this preference in `whodis/config.json` below the operating
system's user configuration directory: normally `~/.config` on Linux,
`~/Library/Application Support` on macOS, and `%AppData%` on Windows. Use
`whodis config path` for the exact location.

## Common examples

```bash
# Domains use RDAP or WHOIS automatically
whodis example.com

# IP addresses and ASNs work the same way
whodis 8.8.8.8
whodis AS15169

# Print machine-readable data
whodis example.com --format json

# Try another terminal layout for one lookup
whodis example.com --format tree

# Make the ASCII view your default in terminals and pipelines
whodis config set format geekboys

# Choose all display defaults with numbered prompts
whodis config

# Expand registry notices for one structured terminal lookup
whodis example.com --details

# Keep the saved expanded preference, but summarize notices just this time
whodis example.com --no-details

# Export to a file; .yaml selects YAML automatically
whodis AS15169 --output google-asn.yaml

# Get clean, unstyled terminal text
whodis example.com --format plain
```

## Command-line options

```text
whodis <target> [options]
whodis config
whodis config wizard
whodis config set format auto|dashboard|tree|geekboys|plain
whodis config set color auto|always|never
whodis config set details auto|summary|expanded
whodis config get format|color|details
whodis config unset format|color|details
whodis config reset
whodis config path

-f, --format dashboard|tree|geekboys|plain|json|yaml|markdown|raw
-o, --output <file|->
    --protocol auto|rdap|whois
    --fallback unavailable|none|any-error
    --server <endpoint>
    --timeout <duration>
    --refresh-bootstrap
    --dns auto|off|scan|axfr
    --axfr
    --resolver <address>
    --color auto|always|never
    --details
    --no-details
    --force
-h, --help
    --version
```

`pretty`, `grid`, and `current` are aliases for `dashboard`; `retro` and
`geek-boys` are aliases for `geekboys`. When `--format` is omitted with
`--output`, Whodis infers JSON, YAML, Markdown, tree, GeekBoys, or plain text
from the filename. Existing files are protected unless `--force` is supplied.

`--dns auto` is the default for domains. `--dns scan` makes the same discovery
pass explicit, `--dns off` disables DNS enrichment, and `--dns axfr` is the
long form of `--axfr`. `--resolver` accepts a resolver host or IP with an
optional port (bracket IPv6 addresses when including a port). DNS enrichment is
skipped automatically for IP, CIDR, and ASN targets.

## How protocol selection works

Whodis fetches and caches IANA's RDAP bootstrap registries for domains, IPv4, IPv6, and ASNs. Domain routes use the longest matching registry suffix, IP routes use the longest matching network prefix, and ASN routes use IANA's number ranges. HTTPS endpoints are preferred, and secondary endpoints are tried before switching protocols.

When IANA does not list an RDAP service for a target, Whodis asks `whois.iana.org` for the authoritative WHOIS server and follows a bounded referral chain. The first registration lookup therefore goes to the protocol known for that target instead of blindly trying services in sequence.

The default `--fallback unavailable` mode tries the alternate protocol only when the selected service is unavailable or unusable. Authoritative not-found and rate-limit responses remain visible. Use `--fallback any-error` for wider diagnostic coverage or `--fallback none` for a strict single-protocol lookup.

## Go API and future interfaces

The protocol engine is independent of terminal rendering. That keeps the same lookup and normalized result model reusable from a future Wails desktop interface or another Go application.

The public API is centered on:

```go
import (
    "os"

    "github.com/Alex9001/whodis"
)

client := whodis.NewClient(whodis.ClientOptions{})
route, err := client.Route(ctx, "example.com", whodis.LookupOptions{})
result, err := client.Lookup(ctx, "example.com", whodis.LookupOptions{})
err = whodis.Render(os.Stdout, result, whodis.FormatTree, whodis.RenderOptions{})
```

`LookupResult` schema version 2 contains the query, routing decision, normalized registration data, DNS discovery result, notices, and registry sources. `DNSResult.Complete` is true only after a successful authoritative AXFR; ordinary scans are intentionally incomplete. Native RDAP JSON and raw WHOIS text remain available through `--format raw`.

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

The current release implements RDAP, standard port-43 WHOIS, and bounded public DNS discovery. RWhois, proprietary registration APIs, authenticated RDAP, web scraping, desktop GUI, and mobile apps are not implemented yet. A normal DNS scan cannot discover arbitrary custom hostnames or prove it has every record; only an authoritative zone transfer can be complete, and public servers commonly refuse those transfers.

## License

MIT © 2026 Aleksandr Oreshkin. See [LICENSE](LICENSE).
