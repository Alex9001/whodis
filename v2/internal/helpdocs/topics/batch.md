# Batch work and exports

Most operations accept multiple targets and use bounded concurrency while preserving input attribution. The desktop Batch window provides the same operation engine for up to 1,000 targets; use CLI streaming formats for larger jobs.

```text
whodis expires example.com example.net
whodis get expiration,registrar,status -i domains.txt -o results.csv
whodis diagnose example.com example.net --ndjson -o diagnosis.ndjson
```

Choose dashboard, tree, GeekBoys, plain text, JSON, YAML, CSV, NDJSON, Markdown, or raw output where applicable. Existing files are protected unless `--force` is supplied.
