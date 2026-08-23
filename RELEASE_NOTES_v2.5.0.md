# Whodis v2.5.0

Whodis 2.5 is the reliability and usability release for the full domain
investigation suite. It adds help inside both applications, closes private-
network gaps in target-derived probes, bounds nested work for large batches,
and expands the tests that protect release builds.

## Help inside Whodis

- `whodis help` now lists command reference and concise offline workflow
  guides for registration, DNS, diagnosis, investigation, batch work,
  snapshots, privacy, and troubleshooting.
- The native app exposes the same embedded guide catalog in a searchable,
  modeless Help window. Press **F1** even when the private engine is unavailable.
- Homepage, full documentation, and issue-reporting links are available from
  the native Help menu and open only after an explicit user action.

## Safer bounded diagnostics

- Diagnose and Investigate now apply the public-destination policy to derived
  HTTP, TLS, SMTP, MTA-STS, and DNS-advertised service connections, including
  redirects and the final dial.
- Private, loopback, link-local, documentation, and other special-use
  destinations are reported as blocked/indeterminate by default rather than as
  evidence that the domain is broken. Managed internal targets can still opt
  in with `--allow-private`.
- A shared configurable probe semaphore bounds nested network fan-out across
  simultaneous Diagnose and Investigate requests, and waiting probes respond
  to cancellation.
- Engine instances share the immutable compiled technology fingerprint catalog,
  eliminating hundreds of megabytes of repeated initialization allocation for
  embedded clients and GUI helper restarts.
- Bootstrap, RDAP, DNS-over-HTTPS, Globalping, enrichment, and MTA-STS response
  bodies have explicit size limits.

## Reliability and release confidence

- Regression coverage now includes every custom policy rule type, bootstrap
  ETag/stale-cache behavior, stream cancellation, atomic output replacement,
  GUI-engine shutdown, and the Batch-window lifecycle.
- Native Go fuzz targets cover subject/endpoints, registration text, DNS wire
  normalization, report rendering, policies, and snapshots. Representative
  engine, rendering, analysis, batch, and policy benchmarks establish a local
  baseline.
- Desktop release builds run the widget suite on Windows and macOS as well as
  Linux. Linux CI also adds an AddressSanitizer/UndefinedBehaviorSanitizer Qt
  build.
- Monthly maintenance checks run race tests, vulnerability analysis, and
  bounded fuzzing. Public-protocol compatibility checks remain manual and
  advisory so ordinary CI is deterministic and offline.
- Dependabot now keeps Go modules, GitHub Actions, and container dependencies
  visible through grouped monthly updates.

## Compatibility

- Public report schema remains version 5.
- The private GUI protocol remains version 5.
- Existing commands, formats, configuration files, and schema-v4 snapshot
  imports remain compatible.
- CLI and GUI continue to ship as independent packages so server installs do
  not acquire Qt.

The release pipeline builds and verifies the CLI and native GUI for Linux,
Windows, and macOS, then publishes checksums, SBOMs, provenance, installers,
archives, native packages, and the multi-architecture container image.
