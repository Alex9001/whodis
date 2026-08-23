# Whodis v2.1.0

Whodis 2.1 adds evidence-backed website and infrastructure investigation to
the domain workstation. A single bounded operation now turns public web, DNS,
mail, PTR, and IP-registration observations into a concise stack profile while
keeping every conclusion traceable to its evidence.

## Highlights

- `whodis investigate example.com` summarizes detected web technologies,
  network ownership, DNS providers, and mail infrastructure.
- Technology fingerprints include category, role, confidence, and supporting
  evidence rather than presenting guesses as facts.
- Network ownership and managed hosting are reported separately, avoiding
  assumptions such as treating every Amazon-owned address as an AWS-hosted
  application.
- The native desktop app adds dedicated **Stack** and **Related** views.
- Dashboard, plain, tree, GeekBoys, JSON, YAML, Markdown, CSV, and NDJSON
  renderers understand investigation results.
- Local investigation snapshots can be saved and compared through the existing
  audit workflow.

## Optional enrichment

AlienVault OTX passive-DNS enrichment is explicitly opt-in with
`--enrich otx`. Results are capped and related hostnames are checked against
current DNS so Whodis can label observations `current`, `stale`, or `unknown`.
The optional API key is read only from `WHODIS_OTX_API_KEY` and is never stored
in configuration, reports, snapshots, or logs.

A configurable HTTPS investigation link is available for manual pivots. Whodis
displays it but never opens it automatically.

## Safety and compatibility

- Investigation does not execute JavaScript, crawl sites, scan arbitrary
  ports, or contact discovered related domains.
- Third-party enrichment is never enabled by a saved default and enriched
  reports cannot be persisted as local snapshots.
- Engine reports advance to schema version 5 and the private desktop protocol
  advances to version 4. Existing v2 registration and DNS commands retain
  their syntax; integration authors should review `MIGRATING_TO_V2.md`.

The release pipeline verifies the CLI and native GUI, race and static analysis,
security scans, installers, cross-platform packages, SBOMs, provenance, and the
multi-architecture container image before publication.
