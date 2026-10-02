<!-- Update this heading and body before each stable release. The release
workflow uses this file only when the heading matches the tag. -->
# Whodis v2.5.4

Whodis 2.5.4 updates its runtime dependencies and adds AppImage catalog and
external update compatibility to the Linux desktop packages.

## Linux AppImage integration

- AppImages use versioned, architecture-specific names:
  `whodis-gui-2.5.4-x86_64.AppImage` and
  `whodis-gui-2.5.4-aarch64.AppImage`.
- Each image embeds a GitHub Releases update channel and ships a matching
  `.AppImage.zsync` sidecar for external AppImageUpdate-compatible tools.
  Stable builds track the latest stable release; prereleases use their own tag.
  No in-app updater or automatic background update check is added.
- Desktop and AppStream metadata are validated during packaging and installed
  with a filename understood by the AppImage catalog worker.
- Release gates verify update metadata, sidecar contents and exact zsync
  reconstruction, audit packaged ELF compatibility and dependencies, run the
  pinned upstream catalog worker, and capture visible x86_64 application startup
  on Ubuntu 22.04 and 24.04 without a Qt SDK.
- Both architecture builds retain X11 and Wayland smoke tests. AppImage and
  sidecar files are included in release checksums and artifact attestations.

These changes prepare Whodis for AppImage catalog submission; this release does
not itself add a listing to appimage.github.io.

## Maintenance and release verification

- Update go-runewidth, wappalyzergo, quic-go, and the Go networking, terminal,
  cryptography, system, and text dependencies.
- Update Docker Buildx, Docker build/push, QEMU, and Qt installation actions.
- Source builds now require Go 1.26 or newer; CI uses Go 1.26.8.
- The non-publishing release preflight now also builds the multi-architecture
  OCI image before release publication is allowed.

Existing CLI commands, output schemas, GUI engine protocol, configuration files,
and snapshot imports remain compatible. Desktop packages remain unsigned.
