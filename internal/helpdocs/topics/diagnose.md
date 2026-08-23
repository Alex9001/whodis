# Domain diagnosis

Diagnose connects published DNS to bounded reachability, HTTP, TLS, SMTP, mail-policy, and advertised-service checks. It is not a generic port scanner or continuous monitor.

```text
whodis diagnose example.com
whodis diagnose example.com --trace
whodis diagnose example.com --json
```

Automatically derived destinations must be public by default. Use `--allow-private` only for an internal domain you manage. A firewall, proxy, VPN, split DNS, or missing ICMP permission can make a probe unavailable; Whodis keeps that uncertainty separate from evidence that the domain itself is broken.
