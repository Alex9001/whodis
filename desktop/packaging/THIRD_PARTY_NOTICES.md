# Third-party notices

Whodis GUI uses Qt 6 Core, Gui, and Widgets. Qt is available under multiple
licenses; the official Whodis desktop builds use the GNU Lesser General Public
License version 3 option. Whodis links to the Qt shared libraries and does not
modify Qt.

The distributed Windows, macOS, and AppImage packages include a `Qt-Licenses`
directory containing the GNU LGPL 3.0 and GPL 3.0 license texts.
The Arch package uses the system Qt libraries and their notices under
`/usr/share/licenses/qt6-base`.

Whodis source code and build instructions are available at
<https://github.com/Alex9001/whodis>. Qt source code is available from
<https://download.qt.io/archive/qt/>. The packaged Qt shared libraries may be
replaced with an interface-compatible build for debugging modifications, as
permitted by the LGPL.

The Whodis engine also incorporates Go libraries under permissive
licenses: miekg/dns and the Go extended libraries (BSD), quic-go and qpack
(MIT), ProjectDiscovery wappalyzergo (MIT), dnscrypt and dnsstamps (Unlicense),
go-runewidth (MIT), and yaml.v3 (MIT/Apache-style notice). Their exact license
texts are bundled in the `Go-Licenses` directory; versions are recorded by
`go.mod`, `go.sum`, and each release's generated SBOM.
