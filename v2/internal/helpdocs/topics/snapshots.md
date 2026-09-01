# Snapshots, diffs, and checks

Snapshots preserve sanitized observations for later comparison. Request IDs, timings, raw DNS packets, API tokens, and TSIG secrets are not retained.

```text
whodis inspect example.com --save --label production
whodis snapshot list
whodis diff production --live
whodis check example.com --scrutiny strict
```

Diffs ignore record order and TTL churn by default. A provider failure makes a section uncertain instead of manufacturing a removal. Checks support built-in scrutiny levels and strict YAML or JSON policies.
