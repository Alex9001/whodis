<!-- Update this heading and body before each stable release. The release
workflow uses this file only when the heading matches the tag. -->
# Whodis v2.5.2

Whodis 2.5.2 hardens registration target handling, makes native desktop results
substantially easier to copy and research, and adds maintainability guardrails.
CLI behavior, report schema, and the GUI engine protocol remain compatible with
2.5.1.

## Lookup reliability

- Hostname and URL normalization now rejects ambiguous AS-number prefixes while
  preserving valid domains, including compatibility cases such as
  `askjeeves.com`.
- Homepage redirect handling keeps the effective response URL without losing
  the originally requested investigation target.
- New regression, fuzz, and benchmark coverage exercises target parsing,
  redirect resolution, and bounded homepage analysis.

## Desktop result interaction

- Result grids and trees support selectable cells and multi-cell copying.
- Copy Selection and Copy Full Result are separate actions in the Edit menu and
  toolbar, with correct enabled states for the focused field.
- Research rows provide Copy and Open Link actions through their context menu;
  double-click opening remains available.
- Stack detail text, raw output, overview fields, DNS results, evidence, related
  domains, and research results can now be selected without retyping values.

## Maintenance and dependencies

- Large CLI parsing, audit-check, and custom-policy functions are divided into
  focused components with equivalent behavior and expanded tests.
- CI now prevents severe Go cyclomatic/cognitive complexity and C++ cognitive
  complexity regressions.
- Go runtime dependencies, the container build image, and pinned GitHub Actions
  have been refreshed to their reviewed Dependabot versions.

## Compatibility

- Public report schema remains version 5.
- The private GUI protocol remains version 5.
- Existing commands, formats, configuration files, and snapshot imports remain
  compatible.

The release pipeline builds and verifies the CLI and native GUI for Linux,
Windows, and macOS, then publishes checksums, SBOMs, provenance, installers,
archives, native packages, and the multi-architecture container image.
