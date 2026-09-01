# Technology investigation

Investigate combines one bounded homepage response with DNS, mail, PTR, TLS, and IP-registration evidence. Technologies and providers include confidence, basis, and short inspectable evidence rather than an opaque score.

```text
whodis investigate example.com
whodis investigate example.com --research-links all
whodis investigate example.com --enrich otx --related-limit 50
```

Whodis does not execute JavaScript, fetch referenced assets, crawl pages, grade performance, or scan vulnerabilities. Research links are generated locally and open only when selected. AlienVault OTX enrichment is separate, explicit, and may use `WHODIS_OTX_API_KEY`.
