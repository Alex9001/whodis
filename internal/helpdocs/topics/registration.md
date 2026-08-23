# Registration and protocols

Whodis uses IANA bootstrap data to find the authoritative RDAP service for domains, IP networks, and ASNs. When appropriate, it falls back to WHOIS and follows bounded WHOIS or RWhois referrals.

```text
whodis example.com
whodis 8.8.8.8
whodis AS15169
whodis whois example.net --strict
whodis rwhois 192.0.2.1 --server rwhois.example.net
```

Use `--server` only when you intentionally want a particular authority. `--strict` disables fallback; `--try-both` widens fallback for troubleshooting. Raw output is available only for one registration response because multi-operation reports combine independent sources.
