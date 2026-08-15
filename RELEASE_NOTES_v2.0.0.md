# Whodis v2.0.0

Whodis v2 turns the readable RDAP/WHOIS client into a complete, scriptable
domain workstation without making the simple command harder:

```bash
whodis example.com
```

## Highlights

- One operation engine shared by the CLI and native Qt desktop app
- Operation-aware schema-v4 subjects for domains, DNS names, IPs, prefixes,
  ASNs, IDNs, URLs, wildcard owners, and reverse DNS
- Explicit `registration`, `inspect`, `dns`, and `diagnose` command families
- DNS inventory queries run concurrently with bounded resolver work
- CSV and one-report-per-line NDJSON alongside dashboard, tree, GeekBoys,
  plain, JSON, YAML, Markdown, and raw registration output
- Local sanitized snapshots, semantic diffs, and guarded live replay
- Built-in health checks, three scrutiny levels, strict custom YAML/JSON
  policies, stable exit codes, and opt-in failure webhooks
- Atomic output files and protected snapshot storage
- HTTPS/public-address defaults for automatic referrals, opt-in exceptions,
  context-aware TCP cancellation, RDAP retry/backoff, and safer TSIG secret
  sources
- GUI protocol v3, Inspect, selectable DNS types, persistent advanced
  preferences, shared-engine batch work, and visible partial errors
- Cross-platform release assets remain split into the server-friendly
  `whodis` CLI and self-contained `whodis-gui` desktop application

Snapshot files omit dedicated API-token and TSIG-secret fields. Live replay of
custom registry or resolver endpoints requires the explicit
`--allow-snapshot-endpoints` trust switch, so importing a snapshot does not
silently activate its network configuration.

## Breaking changes

- The Go module path is now `github.com/Alex9001/whodis/v2`.
- Engine JSON/YAML reports use schema version 4.
- The private GUI helper protocol is version 3 and no longer exposes the old
  registration-only `lookup` method.
- Automatic RDAP/referral routing refuses insecure HTTP and private network
  destinations unless explicitly allowed.

See [MIGRATING_TO_V2.md](MIGRATING_TO_V2.md) for field and API details.

## Compatibility

The familiar no-command registration lookup remains unchanged. `scan` remains
an alias for `inspect`, and `axfr` remains an alias for `dns transfer` so shell
history and existing command invocations keep working. The v1-style Go
registration types remain available as compatibility APIs, but new work should
use `Engine` and `Report`.

## Known boundaries

DNS has no universal record-list operation, RWhois has no global bootstrap,
diagnosis is intentionally bounded, snapshots are local rather than a hosted
scheduler, and the first v2 desktop packages are unsigned. See the README for
the full, current limitations and package verification guidance.
