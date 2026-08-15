# Whodis desktop application

`whodis-gui` is a Qt 6 Widgets application backed by the same Go lookup library
as the `whodis` CLI. The desktop package includes `whodis-gui-engine` as a
private helper; users do not need to install or run the CLI.

The main window exposes Registration, Inspect, selectable DNS Query, and Diagnose
actions. Resolver comparison, iterative delegation tracing, and explicit zone
transfer live under Tools. Results open only the relevant Overview, DNS,
Compare, Delegation, Services, Findings, Contacts, and Raw tabs. The separate
batch workspace runs Registration, DNS Inventory, DNS Compare, or Diagnose
through the same operation engine and exports CSV, TSV, or JSON.

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
diagnostics go only to standard error. Protocol version 3 provides `hello`,
`parse`, schema-v4 `run`, `cancel`, and `export`, plus asynchronous progress
notifications. All operations use `run`; the old registration-only bridge was
removed. The helper is a private implementation detail rather than a second
public command-line interface.

Full HTTP and HTTPS URLs are accepted by the desktop boundary and normalized to
their hostname. Operation results use public Whodis report schema v4, which
keeps partial registration, DNS, diagnosis, findings, and scoped errors. The
helper retains a small in-memory result cache so the GUI can export without
repeating network requests. Retry requests replace failed reports inside their
original batch so successful rows and exports remain complete. Desktop batches
are capped at 1,000 targets, and the cache is bounded by age, count, and total
encoded size; use CLI streaming output for larger jobs. Globalping is off until
the user explicitly checks the third-party remote-probe option.

## Release packages

One stable tag builds both applications:

- GoReleaser publishes the cross-platform `whodis` CLI archives and installers.
- Linux jobs publish amd64 and arm64 AppImages.
- Windows jobs publish amd64 and arm64 per-user installers and portable ZIPs.
- macOS publishes one universal DMG for Intel and Apple silicon.

Desktop artifacts are currently unsigned. The Linux AppImages and
Windows/macOS bundles include the Qt runtime and its license notices. The AUR
`whodis-gui` package builds from source and uses Arch's shared Qt package.

The release workflow publishes CLI and GUI files on the same GitHub Release,
while the AUR keeps separate `whodis` and `whodis-gui` packages so servers do
not pull a desktop stack.
