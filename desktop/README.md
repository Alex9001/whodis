# Whodis desktop application

`whodis-gui` is a Qt 6 Widgets application backed by the same Go lookup library
as the `whodis` CLI. The desktop package includes `whodis-gui-engine` as a
private helper; users do not need to install or run the CLI.

The main window exposes Registration, Inspect, selectable DNS Query, Diagnose,
and Investigate actions. Resolver comparison, iterative delegation tracing, and
explicit zone transfer live under Tools. Results open only the relevant
Overview, Stack, Research, Related, DNS, Compare, Delegation, Services, Findings,
Contacts, and Raw tabs. The separate batch workspace also supports Investigate
through the same operation engine and exports CSV, TSV, or JSON.

Result and batch tables use wrapped, user-adjustable columns. Widths are saved
independently for each view, and row heights adapt when a column changes. An
investigation opens on Overview with categorized platform, commerce,
plugin/form, theme, optimization, and infrastructure summaries plus a compact
homepage delivery, SEO, security-header, and accessibility profile. The same
score-free homepage observations appear as deterministic rows in Findings.
Stack is a master/detail workspace: category headings organize selectable
technologies, while one lower pane shows the selected version, relationship,
confidence basis, summary, and bounded evidence. Its splitter position is also
remembered. Research links live in
their own adjustable, wrapped view grouped by domain and public IP, with one
native Open/Copy action instead of repeated buttons.

Investigate is local by default. Homepage analysis uses one bounded response;
it does not execute JavaScript, fetch referenced assets, crawl pages, calculate
browser performance metrics, or assign a score. The Core research-link catalog
is generated locally, and no listed service receives a domain or IP until the
user opens its link. Advanced offers Core, All, Off, and individual persistent
provider choices. Its OTX checkbox is an
explicit, session-only third-party opt-in and is never restored automatically.
Harmless related-result, research-link, custom-template, and endpoint
preferences may be saved; an
OTX API key is read only from `WHODIS_OTX_API_KEY`.

Whodis Help is available from the Help menu or **F1** even if the private
engine cannot start. It is a modeless, searchable native window backed by the
same embedded topic catalog as `whodis help`. The menu also provides explicit
HTTPS links to the homepage, complete online documentation, and issue tracker.

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

CI additionally compiles and exercises the widgets under AddressSanitizer and
UndefinedBehaviorSanitizer. The widget suite starts the real private engine for
cancellation and child-window lifecycle coverage while keeping network access
out of the tests.

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
diagnostics go only to standard error. Protocol version 5 provides `hello`,
`parse`, schema-v5 `run`, `cancel`, and `export`, plus asynchronous progress
notifications. All operations use `run`; the old registration-only bridge was
removed. The helper is a private implementation detail rather than a second
public command-line interface.

Full HTTP and HTTPS URLs are accepted by the desktop boundary and normalized to
their hostname. Operation results use public Whodis report schema v5, which
keeps partial registration, DNS, diagnosis, investigation, findings, and scoped errors. The
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
