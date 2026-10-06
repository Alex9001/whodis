# Native screenshot provenance

Refreshed 2026-10-06 from source commit `595274828e83935c87e0bb24dd939055e36cad1d`.

The six `whodis-gui-*.png` images render the real Qt application widgets and
current palette/chrome using Qt 6.11.2 on Linux. The main window uses 1280 × 820
logical pixels; batch uses 1280 × 900. `QT_SCALE_FACTOR=2` produces 2560 × 1640
and 2560 × 1800 files, respectively. No image was enlarged after capture.

All input is synthetic documentation data: reserved example domains, the
192.0.2.0/24 IPv4 documentation range, the 2001:db8::/32 IPv6 documentation range,
and fictional registrar, DNS, and mail records. Technology labels demonstrate
the interface; they are not a claim about the live example.com website.
No private domains, customer records, tokens, or credentials are included.

The capture harness populates the application's normal `ResultWidget` report
model and the batch response handler, then captures the native widgets. It does
not redraw the interface. Registration, DNS, diagnosis, technology evidence,
research pivots, and batch workflows are shown. Native fonts can vary by OS.
The existing CLI illustrations are separate from this native UI refresh.

Automatic GitHub Actions triggers are disabled. Screenshot refreshes and
verification run locally; do not start hosted workflows without approval.
