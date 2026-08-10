# whodis

[![CI](https://github.com/Alex9001/whodis/actions/workflows/ci.yml/badge.svg)](https://github.com/Alex9001/whodis/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Alex9001/whodis?display_name=tag)](https://github.com/Alex9001/whodis/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A modern WHOIS alternative that automatically uses RDAP and RWhois where traditional WHOIS falls short — and maps the public DNS that registration data alone cannot show.**

The registry world is split between old-school WHOIS, modern RDAP, and delegated RWhois network directories. `whodis` hides that split: give it a domain, IP address, network, or ASN and it finds the right service automatically. No protocol trivia required.

Instead of dumping a wall of registry text, it can turn the answer into a compact terminal dashboard, a hierarchical tree, a 2002-style ASCII layout, or clean plain text. Registration facts, dates, discovered DNS records, contacts, and routing details each get the space they need.

Prefer windows and buttons? `whodis-gui` puts the same lookup engine in a focused native desktop interface for Linux, Windows, and macOS. Paste a domain, IP, ASN, or full URL, then choose **Lookup** or **Scan DNS**. Results are organized into Overview, DNS, Contacts, and Raw tabs, with a separate batch workspace for larger lists.

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

For domain lookups, use `scan` when you want a fast public-DNS discovery pass and a full-width, terminal-friendly record grid. It finds the useful common records—addresses, mail routing, verification and policy TXT records, service records, HTTPS/SVCB records, and nameservers—without turning one lookup into an uncontrolled crawl.

## What you get

- **Automatic protocol selection** — RDAP where it is available, WHOIS where it is still needed, and RWhois for delegated network records.
- **DNS discovery built in** — common public DNS records appear in an adaptive grid beside registration data; JSON, YAML, Markdown, and plain text include the same structured records.
- **Four terminal views** — switch between the responsive dashboard, a semantic tree, a retro ASCII layout, and plain text.
- **Persistent preferences** — save your favorite view once and use it automatically in terminals and pipelines.
- **Batch checks and field exports** — check many targets at once, pull only expiration dates or other registration fields, and save a clean `.txt` table.
- **Script-friendly formats** — output plain text, JSON, YAML, Markdown, or the raw registry response.
- **Direct file export** — use `--output result.json` and Whodis infers the format from the extension.
- **More than domains** — look up IPv4, IPv6, CIDR networks, and autonomous system numbers such as `AS15169`.
- **Cross-platform builds** — the same CLI is designed for Linux, macOS, and Windows.
- **A native desktop companion** — a clean Qt Widgets interface follows the host system theme and bundles its own private lookup engine; the CLI is not required.

## Install

Whodis is released as two independent applications from the same repository:

- `whodis` is the small command-line program for shells, scripts, and servers.
- `whodis-gui` is the desktop program for Linux, Windows, and macOS. It includes a private engine and does not require `whodis` on `PATH`.

### Command line

#### Linux and macOS

```bash
curl -fsSL https://github.com/Alex9001/whodis/releases/latest/download/install.sh | sh
```

The installer detects your operating system and CPU, verifies the release
checksum, and places `whodis` in `/usr/local/bin`. It asks for `sudo` only if
that directory is not writable.

#### Windows

Run in PowerShell—no administrator window is required:

```powershell
irm https://github.com/Alex9001/whodis/releases/latest/download/install.ps1 | iex
```

The installer puts Whodis under your local application-data directory and adds
it to your user `PATH` without creating duplicate entries.

#### With Go

If you already have Go installed:

```bash
go install github.com/Alex9001/whodis/cmd/whodis@latest
```

Go installs the binary into `GOBIN` (normally `~/go/bin`). Make sure that
directory is on `PATH`.

Prebuilt archives for every supported platform and `checksums.txt` are also
available on the [latest GitHub Release](https://github.com/Alex9001/whodis/releases/latest).

### Desktop app

Download the `whodis-gui` package for your system from the
[latest GitHub Release](https://github.com/Alex9001/whodis/releases/latest):

- **Linux:** download the AppImage for `amd64` or `arm64`, make it executable,
  and run it. It is self-contained and does not install the CLI.
- **Windows:** use the matching `setup.exe` for a normal per-user installation,
  or the portable ZIP when you do not want an installer.
- **macOS:** download the universal DMG, drag Whodis to Applications, then
  Control-click **Whodis** and choose **Open** on the first launch.

The first desktop packages are intentionally unsigned, so Windows SmartScreen
or macOS Gatekeeper may ask you to confirm the first launch. Signing and store
distribution can be added later without changing the application architecture.

The source-built AUR packages are prepared but cannot be submitted until the
maintainer's AUR account is registered. The exact one-time publication steps
for both packages are preserved in [AUR_HANDOFF.md](AUR_HANDOFF.md); after
publication Arch users will be able to choose `whodis`, `whodis-gui`, or both.

## Desktop interface

The main window stays deliberately small: one target field, **Lookup**,
**Scan DNS**, and **Batch**. It accepts domains, IP addresses, ASNs, and full
HTTP or HTTPS URLs; URLs are reduced to their hostname before lookup.

- **Overview** groups registration, timeline, nameservers, source, and notices.
- **DNS** shows discovered records in a sortable table.
- **Contacts** keeps registrant, administrative, and technical records readable.
- **Raw** preserves the original RDAP, WHOIS, or RWhois response.
- **Batch** imports or pastes target lists, reports progress, retries failures,
  and exports CSV, TSV, or JSON.

Advanced options expose protocol selection, fallback behavior, custom WHOIS or
RWhois authorities, resolvers, timeouts, cache refresh, and an explicitly
confirmed AXFR action. The GUI talks to a bundled private Go engine over a
versioned local protocol, so desktop code never reimplements lookup behavior
and the server-focused CLI remains free of Qt dependencies.

## Quick start

Once installed, use it from any directory:

```bash
whodis google.com
```

## Batch checks and expiration lists

Give Whodis more than one target to run a bounded concurrent batch. Use
`expires` when all you need is the expiration date, or `get` for a small
registration-data table. Text files are headered tab-separated values,
so they open cleanly in a spreadsheet and remain easy to process in a shell.

```bash
# TARGET, EXPIRATION, and ERROR columns in a compact terminal grid
whodis expires google.com yahoo.com

# Add more registration fields and save a text table
whodis get expiration,registrar,status google.com yahoo.com -o domains.txt

# One target per line; blank and # comment lines are ignored
whodis expires --input domains.txt -o expirations.txt

# Stdin works when no targets are supplied directly
printf 'google.com\nyahoo.com\n' | whodis expires
```

Batch lookups keep input order, continue when an individual target fails, and
return a nonzero status after writing the attributed error rows. Use
`--jobs 1` through `--jobs 32` to control concurrency (the default is four).

## Choose your view

Use an output shortcut to change one lookup:

```bash
whodis example.com --dashboard  # current responsive grid
whodis example.com --tree
whodis example.com --geekboys
whodis example.com --plain
```

## DNS discovery

`whodis example.com` is registration-only: it uses RDAP, WHOIS, and any
published RWhois referral as needed, then shows the nameservers supplied by the
registration authority once. Use `scan` to use your system DNS resolver for
common public records. The dashboard then puts those records in a Type / Name /
Value / TTL grid; the other terminal views adapt the same data to their own
layouts.

The scan checks the apex plus practical names such as `www`, `api`, `mail`,
`autodiscover`, DMARC/MTA-STS/TLS reporting names, common DKIM selectors, and
well-known service records. It detects wildcard responses and avoids presenting
matching guesses as confirmed hostnames. CNAME, MX, NS, SRV, HTTPS, and SVCB
targets inside the queried domain get address follow-up where applicable.

DNS does not provide a general way to list every owner name in a zone, so the
normal result is explicitly marked as a discovery scan rather than a complete
zone. Use these controls when needed:

```bash
# Discover live public records, including MX records
whodis scan example.com

# A resolver also requests discovery (the default is the system resolver)
whodis scan example.com --resolver 1.1.1.1

# Ask the domain's authoritative nameservers for a full zone transfer.
# This is never attempted automatically and most public zones correctly refuse it.
whodis axfr example.com
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
single lookup, so `--summary` temporarily returns notices to their compact
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

An explicit output shortcut always wins. `WHODIS_FORMAT` provides a temporary
format override and can also select JSON, YAML, Markdown, or raw output. Named
output files continue to take their format from the extension. Explicit
`--color`, `--details`, and `--summary` likewise override the saved display
choices.

Whodis stores this preference in `whodis/config.json` below the operating
system's user configuration directory: normally `~/.config` on Linux,
`~/Library/Application Support` on macOS, and `%AppData%` on Windows. Use
`whodis config path` for the exact location.

## Common examples

```bash
# Registration lookups choose RDAP, WHOIS, or a published RWhois referral
whodis example.com

# IP addresses and ASNs work the same way
whodis 8.8.8.8
whodis AS15169

# Print machine-readable data
whodis example.com --json

# Try another terminal layout for one lookup
whodis example.com --tree

# Make the ASCII view your default in terminals and pipelines
whodis config set format geekboys

# Choose all display defaults with numbered prompts
whodis config

# Expand registry notices for one structured terminal lookup
whodis example.com --details

# Keep the saved expanded preference, but summarize notices just this time
whodis example.com --summary

# Export to a file; .yaml selects YAML automatically
whodis AS15169 --output google-asn.yaml

# Direct RWhois requires an authority; the default TCP port is 4321
whodis rwhois 192.0.2.1 --server rwhois.example.net

# Get clean, unstyled terminal text
whodis example.com --plain
```

## Command-line options

```text
whodis [rdap|whois|rwhois] [scan|axfr|expires|get <fields>] [target ...] [options]
whodis config
whodis config wizard
whodis config set format auto|dashboard|tree|geekboys|plain
whodis config set color auto|always|never
whodis config set details auto|summary|expanded
whodis config get format|color|details
whodis config unset format|color|details
whodis config reset
whodis config path

-o, --output <file|->
-i, --input <file|->
-j, --jobs <1-32>
    --server <endpoint>
    --timeout <duration>
    --refresh
    --resolver <address>
    --color auto|always|never
    --details
    --summary
    --strict
    --try-both
    --dashboard|--tree|--geekboys|--plain|--json|--yaml|--markdown|--raw
    --force
-h, --help
    --version
```

The protocol word, when present, comes first. `scan` adds public DNS discovery;
`axfr` tries an authoritative zone transfer and still returns the ordinary scan
when transfer is unavailable; `expires` is the expiration-only projection; and
`get` takes any comma-separated combination of `expiration`, `registration`,
`updated`, `registrar`, `registry`, `status`, `nameservers`, `dnssec`, and
`protocol`. `scan` and `axfr` accept domains only. To query a target that is
itself a command word, start the target list with `--`, such as
`whodis -- scan` or `whodis whois -- scan`.

Choose at most one output shortcut. Without one, Whodis infers JSON, YAML,
Markdown, tree, GeekBoys, or plain text from `--output`; otherwise it consults
`WHODIS_FORMAT`, saved preferences, and whether output is a terminal. Existing
files are protected unless `--force` is supplied. `--raw` is limited to one
ordinary, unprojected registration lookup.

`--resolver` accepts a resolver host or IP with an optional port (bracket IPv6
addresses when including a port) and is available with `scan` or `axfr`.

## How protocol selection works

Whodis fetches and caches IANA's RDAP bootstrap registries for domains, IPv4, IPv6, and ASNs. Domain routes use the longest matching registry suffix, IP routes use the longest matching network prefix, and ASN routes use IANA's number ranges. HTTPS endpoints are preferred, and secondary endpoints are tried before switching protocols.

When IANA does not list an RDAP service for a target, Whodis asks `whois.iana.org` for the authoritative WHOIS server and follows a bounded referral chain. If that authority publishes an `rwhois://` referral, Whodis follows it automatically. For successful automatic IP and ASN RDAP lookups, Whodis also uses the RDAP `port43` hint to make a best-effort WHOIS probe for a more-specific RWhois record; a failed probe leaves the RDAP answer intact.

Automatic routing falls back only when the selected service is unavailable or unusable. Authoritative not-found and rate-limit responses remain visible. Use `--try-both` for wider diagnostic coverage or `--strict` for a strict single-protocol lookup. To force a protocol, place `rdap`, `whois`, or `rwhois` before the command; direct RWhois requires `--server`.

## Go API and interfaces

The protocol engine is independent of terminal and desktop rendering. The CLI,
native Qt desktop app, and other Go applications reuse the same lookup and
normalized result model.

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

batch, err := client.LookupBatch(ctx, []string{"example.com", "example.net"}, whodis.BatchLookupOptions{})
err = whodis.RenderBatch(os.Stdout, batch, whodis.FormatPlain, whodis.BatchRenderOptions{
    Fields: []whodis.ProjectionField{whodis.FieldExpiration},
})
```

`LookupResult` schema version 2 contains the query, routing decision, normalized registration data, DNS discovery result, notices, and registry sources. `BatchResult` schema version 1 keeps each original input beside either a result or a serializable error. `DNSResult.Complete` is true only after a successful authoritative AXFR; ordinary scans are intentionally incomplete. Native RDAP JSON, raw WHOIS, and raw RWhois responses remain available through `--raw` for one ordinary, unprojected target.

Additional protocols can implement `ProtocolAdapter` without coupling them to the CLI or a particular operating system.

## Development

```bash
git clone https://github.com/Alex9001/whodis.git
cd whodis
go test ./...
go vet ./...
go run ./cmd/whodis example.com
```

The desktop app additionally needs CMake, Ninja, Qt 6 Core/Gui/Widgets, and a
C++17 compiler. See [desktop/README.md](desktop/README.md) for local build,
test, engine-protocol, and packaging details.

Tests use local fixtures and in-memory protocol sessions; public registries are
not queried during the test suite. Live checks are intentionally manual because
registry availability and query limits are external conditions.

## Known limitations

- RWhois has no global bootstrap registry. Automatic discovery depends on an
  RDAP `port43` hint or a WHOIS `ReferralServer`; otherwise the authority must
  be supplied with `rwhois --server <host>`.
- Normal DNS discovery checks a practical set of common names and record types,
  not every possible owner name in a zone. Only a successful authoritative AXFR
  is complete, and most public nameservers refuse zone transfers.
- `get` exports the normalized registration fields listed by `whodis help get`; it
  does not yet select arbitrary JSON paths or individual DNS record types.
- Raw protocol output is available only for one unprojected target. Multi-target
  and field-selected output must use a structured or human-readable format.
- Authenticated RDAP, proprietary registry APIs, and web scraping are not
  included.
- Desktop packages are currently unsigned and are distributed directly through
  GitHub Releases; Microsoft Store, Mac App Store, and mobile builds are not
  part of the first desktop release.

## License

MIT © 2026 Aleksandr Oreshkin. See [LICENSE](LICENSE).
