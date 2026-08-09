# whodis

`whodis` is a cross-platform registration-data client for domains, IP address ranges, and autonomous system numbers. It selects the authoritative protocol before it queries: RDAP when IANA's bootstrap registry lists an RDAP authority, and port-43 WHOIS when it does not.

It is CLI-first. The Go lookup package has no terminal dependency, so a future Wails desktop application can use the same routing, transport, and normalized result model.

## Quick start

```bash
go build -o bin/whodis ./cmd/whodis

bin/whodis example.com
bin/whodis 8.8.8.8 --format json
bin/whodis AS15169 --output google-asn.yaml
```

The terminal default is a styled, spreadsheet-like grid with `Section`, `Field`, and `Value` columns. Use `--format plain` for unstyled text, or choose `json`, `yaml`, `markdown`, or `raw`.

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
    --force
```

When `--format` is omitted with `--output`, Whodis infers JSON, YAML, Markdown, or plain text from the file extension. Existing output files are protected until `--force` is supplied.

## Routing behavior

Whodis fetches and caches IANA's `dns.json`, `ipv4.json`, `ipv6.json`, and `asn.json` RDAP bootstrap registries, respecting HTTP cache headers. Domain routes use the longest matching registry suffix; IP routes use longest CIDR prefixes; ASN routes use IANA's number ranges. HTTPS RDAP service URLs are preferred, and secondary listed URLs are tried before any protocol fallback.

For a target without an RDAP mapping, Whodis asks `whois.iana.org` for the authoritative WHOIS referral and follows a bounded WHOIS referral chain. In automatic mode this means the first registration lookup already uses the protocol known for that target's authority.

`--fallback unavailable` is the default: it tries the alternate protocol only when the chosen service is unavailable or unusable. Authoritative not-found and rate-limit responses remain visible. Use `--fallback any-error` for diagnostic coverage, or `--fallback none` for a strict single-protocol lookup.

## Architecture and extension points

The reusable API is centered on:

```go
client := whodis.NewClient(whodis.ClientOptions{})
route, err := client.Route(ctx, "example.com", whodis.LookupOptions{})
result, err := client.Lookup(ctx, "example.com", whodis.LookupOptions{})
```

`LookupResult` is a versioned normalized model containing the query, routing decision, public registration data, notices, and the registry sources used. Native RDAP JSON and raw WHOIS text remain available through `--format raw`.

Additional in-process protocols can implement `ProtocolAdapter`; this avoids Go's platform-specific dynamic plugin mechanism and remains portable to Windows, macOS, and Linux.

## Development

```bash
go test ./...
go vet ./...
```

Tests use local normalizer and renderer fixtures; public registries are not queried during the test suite. Live checks are intentionally manual because registry availability and query limits are external conditions.

## Current scope

V1 implements RDAP and standard port-43 WHOIS for domains, IPs/CIDRs, and ASNs. RWhois and other legacy or proprietary registration systems are intentionally deferred behind the protocol-adapter boundary. Desktop GUI, authenticated RDAP, web scraping, and mobile apps are also deferred.

## License

MIT © 2026 Aleksandr Oreshkin. See [LICENSE](LICENSE).
