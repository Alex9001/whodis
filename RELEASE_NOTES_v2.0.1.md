# Whodis v2.0.1

Whodis 2.0.1 is the final stabilization release for the v2 domain workstation.
It fixes correctness and desktop workflow issues found during the post-release
audit without changing the command-line interface.

## Fixed

- DNS comparisons now compare each name, type, and class independently instead
  of treating `A`, `AAAA`, or other requested types as competing answers.
- The desktop Compare view shows resolver agreement, disagreement, failures,
  transport, response code, DNSSEC state, and timing.
- **Retry Failed** in the batch window updates failed rows in place and preserves
  successful results in the table and exported file.
- Desktop raw export writes the source selected in the Raw view and is offered
  only when a raw registration response exists.
- WHOIS responses over the 8 MiB safety limit now fail explicitly instead of
  being silently truncated and parsed.

## Hardening

- Desktop batches are capped at 1,000 targets; larger jobs remain available
  through the CLI's streaming formats.
- The private GUI engine no longer sends raw registration responses twice.
- Exportable GUI results now use a 64 MiB, 20-result, 30-minute bounded cache.

All CLI, race, static-analysis, installer, native GUI, packaging, and release
checks remain part of the release pipeline.
