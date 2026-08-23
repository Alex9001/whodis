<!-- Update this heading and body before each stable release. The release
workflow uses this file only when the heading matches the tag. -->
# Whodis v2.5.1

Whodis 2.5.1 fixes external browser links in the Linux AppImage and cleans up
the project's public documentation. CLI behavior, report schema, and the GUI
engine protocol remain compatible with 2.5.0.

## AppImage link handling

- Homepage, online documentation, and issue-reporting actions now launch the
  host system's browser from AppImage builds.
- Links inside bundled help and investigation research results use the same
  AppImage-safe launcher.
- The launcher removes AppImage library and plugin paths before starting the
  host's `xdg-open` or `gio` helper, preventing bundled Qt libraries from
  interfering with desktop integration.
- If a browser helper cannot be started, Whodis shows a clear error with a
  selectable address instead of failing silently.

## Documentation cleanup

- The README opening is more direct, labeled feature lists use colons, and
  unnecessary em dashes have been removed from the public copy.
- Historical release-note files have been replaced by one reusable release
  notes document. The release workflow uses it only when its heading matches
  the tag, preventing stale notes from reaching a release.
- AUR and community-package instructions now live as evergreen maintainer
  guides without machine-specific fingerprints or release-number pins.

## Compatibility

- Public report schema remains version 5.
- The private GUI protocol remains version 5.
- Existing commands, formats, configuration files, and snapshot imports remain
  compatible.

The release pipeline builds and verifies the CLI and native GUI for Linux,
Windows, and macOS, then publishes checksums, SBOMs, provenance, installers,
archives, native packages, and the multi-architecture container image.
