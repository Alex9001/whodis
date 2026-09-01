# DNS and DNSSEC

DNS operations are explicit and independent from registration.

- **Inventory** checks a maintained set of useful owner names and record types.
- **Query** accepts named or numeric types and classes.
- **Compare** normalizes answers from multiple resolvers.
- **Trace** follows delegation iteratively from a root server.
- **Transfer** explicitly attempts bounded AXFR or IXFR.

```text
whodis dns inventory example.com
whodis dns query example.com A AAAA MX HTTPS
whodis dns compare example.com A --resolver system --resolver https://1.1.1.1/dns-query
whodis dns trace example.com NS
```

Resolver URIs select UDP, TCP, DoT, DoH, DoH3, DoQ, or DNSCrypt. `--dnssec` locally validates positive signed answers against the embedded root trust anchor; authenticated denial remains indeterminate.
