# Whodis v2.2.0

Whodis 2.2 makes dense desktop results easier to read and puts the most useful
investigation conclusions up front. It is a focused native-GUI release; CLI
commands and machine-readable report formats remain compatible with v2.1.

## Adaptive result layouts

- Every result table and tree now wraps long values instead of clipping them.
- Columns are directly resizable and their widths are remembered separately for
  Overview, DNS, Compare, Delegation, Services, Findings, Stack, Related,
  Errors, Contacts, evidence, and batch results.
- Row heights update after a resize so long DNS values, errors, contacts, and
  technology summaries remain readable.
- The investigation Stack splitter position is remembered as well.

## Cleaner investigation workflow

- Investigations now open on Overview, where a new **Technology &
  infrastructure** section summarizes web technology, server/edge, hosting,
  network owner, DNS provider, mail, analytics/security, and other findings.
- Overview summaries use high- and medium-confidence components, remove
  duplicates, and keep the full list available in a tooltip when a category is
  condensed.
- Stack now uses a master/detail layout. Category headings organize findings;
  selecting one technology, network, link, or note shows its summary and
  evidence once in the lower pane.
- Repetitive Evidence columns and per-finding evidence children are gone.
- Manual investigation pivots are explicit buttons and are never opened in the
  background.

## Compatibility

- Public report schema remains version 5.
- The private GUI engine protocol remains version 4.
- No CLI syntax, JSON/YAML fields, snapshot format, or investigation inference
  rules changed in this release.

The release pipeline builds and verifies the CLI and native GUI for Linux,
Windows, and macOS, then publishes checksums, SBOMs, provenance, installers,
archives, native packages, and the multi-architecture container image.
