# Whodis desktop application

`whodis-gui` is a Qt 6 Widgets application backed by the same Go lookup library
as the `whodis` CLI. The desktop package includes `whodis-gui-engine` as a
private helper; users do not need to install or run the CLI.

Qt Widgets deliberately uses the active platform style. Windows receives
standard Windows controls, Plasma can use its configured Qt platform theme,
and macOS receives the native macOS Qt style. Whodis does not replace those
controls with a custom web-style skin.

## Build locally

Install Go, CMake, Ninja, a C++17 compiler, and Qt 6.2 or newer with the Core,
Gui, Widgets, and Test development components. Then run from the repository
root:

```bash
cmake -S desktop -B build-gui -G Ninja \
  -DWHODIS_VERSION=dev \
  -DBUILD_TESTING=ON
cmake --build build-gui --parallel
ctest --test-dir build-gui --output-on-failure
```

The application and private engine are written to `build-gui/bin`. Run the app
from there so it finds the adjacent development engine:

```bash
./build-gui/bin/whodis-gui
```

Set `WHODIS_GUI_ENGINE` to an explicit helper path when testing a different
engine build.

## Local engine protocol

The GUI starts `whodis-gui-engine` as a child process. Requests and responses
are JSON-RPC 2.0 objects separated by newlines over standard input and output;
diagnostics go only to standard error. Protocol version 1 provides `hello`,
`parse`, `lookup`, `cancel`, and `export`, plus asynchronous progress
notifications. The helper is private implementation detail rather than a
second public command-line interface.

Full HTTP and HTTPS URLs are accepted by the desktop boundary and normalized to
their hostname. Lookup results use the public Whodis normalized data types, and
the helper retains a small in-memory result cache so the GUI can export without
repeating network requests.

## Release packages

One stable tag builds both applications:

- GoReleaser publishes the cross-platform `whodis` CLI archives and installers.
- Linux jobs publish amd64 and arm64 AppImages.
- Windows jobs publish amd64 and arm64 per-user installers and portable ZIPs.
- macOS publishes one universal DMG for Intel and Apple silicon.

Desktop artifacts are unsigned in the first release. The Linux AppImages and
Windows/macOS bundles include the Qt runtime and its license notices. The AUR
`whodis-gui` package builds from source and uses Arch's shared Qt package.

The release workflow publishes CLI and GUI files on the same GitHub Release,
while the AUR keeps separate `whodis` and `whodis-gui` packages so servers do
not pull a desktop stack.
