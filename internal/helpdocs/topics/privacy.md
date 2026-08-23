# Privacy and network safety

Whodis has no account system, telemetry, or background network activity. Registration, DNS, diagnosis, and local investigation contact only services needed for the requested operation.

- Globalping remote views require an explicit option.
- Passive-DNS enrichment requires `--enrich otx`.
- Research services are not contacted until you open a generated link.
- OTX keys come from the environment and are never saved.
- Automatically derived private-network destinations are blocked unless `--allow-private` is explicitly supplied.

Reports can contain public registration contacts and infrastructure details. Review and redact output before posting it publicly.
