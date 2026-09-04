<!-- Update this heading and body before each stable release. The release
workflow uses this file only when the heading matches the tag. -->
# Whodis v2.5.3

Whodis 2.5.3 introduces the expanded WHODIS identity, reorganizes the source
tree for clearer Go module boundaries, and improves release artifact auditing.
CLI behavior, report schema, and the GUI engine protocol remain compatible with
2.5.2.

## Branding and documentation

- WHODIS is now presented as Web Host Observatory Domain Investigation Suite
  in the README and the desktop About dialog.
- The README includes refreshed logo and product-preview artwork, clearer badge
  styling, and a direct link from the platform badge to installation guidance.

## Source layout

- The Go module and its packages now live under `v2/`, matching the public
  module version while retaining the existing
  `github.com/Alex9001/whodis/v2` import path.
- Contributor, security, migration, build, packaging, and CI paths have been
  updated for the new layout.

## Release integrity and maintenance

- Release SBOMs are consolidated into one versioned bundle with checksum and
  content validation, while individual SBOM files are omitted from the public
  asset set.
- Dependabot can automatically merge reviewed patch and minor updates when the
  required checks pass.
- Documentation badges have consistent styling and include the DeepWiki entry.

## Compatibility

- Public report schema remains version 5.
- The private GUI protocol remains version 5.
- Existing commands, formats, configuration files, and snapshot imports remain
  compatible.

The release pipeline builds and verifies the CLI and native GUI for Linux,
Windows, and macOS, then publishes checksums, SBOMs, provenance, installers,
archives, native packages, and the multi-architecture container image.
