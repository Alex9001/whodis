# Migrating to Whodis v2

Whodis v2 is a breaking Go-module and report-schema release. The command-line
defaults remain familiar: `whodis example.com` is still a registration lookup,
and the older `scan` and `axfr` command aliases still work.

## Go module and engine API

Change imports to the semantic-import-version path:

```go
import whodis "github.com/Alex9001/whodis/v2"
```

Use `Engine` for new integrations. It is the supported path shared by the CLI
and desktop application:

```go
engine := whodis.NewEngine(whodis.EngineOptions{})
defer engine.Close()

report, err := engine.Run(ctx, whodis.Request{
    Operation: whodis.OperationInspect,
    Target:    "example.com",
})
```

`Engine.RunBatch` handles bounded materialized batches and preserves request
order. `Engine.RunStream` accepts targets incrementally for large or generated
input sets. Reuse one engine so registration throttles, bootstrap caches, and
network transports can do their job. Independent callers retain independent
cancellation lifecycles, even when they request the same registration object.

The v1 `Client`, `LookupResult`, `Render`, and registration batch types remain
available as compatibility types, but new functionality is added to `Engine`,
`Report`, and `RenderReport`.

## Report schema v4

Machine-readable operation output now uses `schema_version: 4`.

- `Report.subject` replaces the ambiguous query shape. Its kind distinguishes
  registrable domains, general DNS owner names, IPs, prefixes, and ASNs.
- `Report.observed_at` is the observation time for the whole operation.
- Registration data is a `RegistrationResult` nested under `registration`;
  it no longer repeats the query, schema version, or retrieval time.
- DNS, diagnosis, findings, and provider-scoped errors remain independent, so
  partial results survive a failed provider.
- `Report.findings` is the canonical aggregate for diagnostic findings; the
  engine does not duplicate those entries inside `diagnosis.findings`.
- JSON and YAML always emit schema-v4 `Report`/`BatchReport` values from the
  engine path. NDJSON emits one report per line; CSV emits one target per row.

Code that decoded schema v3 should read `subject.canonical` instead of
`query.canonical` and `observed_at` instead of `retrieved_at` at report level.
Consumers should ignore unknown fields and branch on `schema_version`.

## CLI changes

The preferred operation names are explicit:

```text
whodis registration <target...>
whodis inspect <domain...>
whodis dns query|inventory|compare|trace|transfer ...
whodis diagnose <domain...>
```

Use `-f/--format` for `dashboard`, `tree`, `geekboys`, `plain`, `json`, `yaml`,
`csv`, `ndjson`, `markdown`, or `raw`. Output files are created atomically and
are not replaced unless `--force` is supplied.

Automatic RDAP and protocol referrals must use public destinations and HTTPS
by default. `--allow-private` and `--allow-insecure-http` are deliberate
per-run exceptions. Prefer `--tsig-secret-env` or `--tsig-secret-file`; the
literal secret flag exists only for command compatibility and can expose a
secret in shell history.

New local observation commands are `snapshot`, `diff`, and `check`. Exit code
`5` means a diff or policy failure; `6` means an uncertain/incomplete result.
`diff` and `check` support plain, JSON, YAML, and Markdown output plus atomic
`--output`/`--force` behavior. Live replay refuses custom endpoints stored in a
snapshot unless `--allow-snapshot-endpoints` is explicitly supplied. Check
schema-v1 rule results carry `report_index` and `subject` for batch
attribution. Existing registration exit codes retain their meanings.

## Desktop helper protocol

`whodis-gui-engine` protocol version 3 carries schema-v4 reports. Frontends
must use the `run` method; the old `lookup` method has been removed. The `hello`
capabilities include `inspect` and `schema_v4`. This protocol remains a private
desktop boundary, not a separately supported network API.
