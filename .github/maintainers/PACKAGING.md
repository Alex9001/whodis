# Community package publication

GitHub Releases are the source of truth. The release workflow publishes CLI
archives, native Linux packages, GUI bundles, checksums, SBOMs, provenance, and
install scripts. If AUR account registration is unavailable, wait until it
reopens; see the [AUR publication guide](AUR.md).

After a stable release is published, generate checksum-pinned community
manifests from its `checksums.txt`:

```bash
release="$(gh release view --repo Alex9001/whodis --json tagName --jq .tagName)"
package_work="$(mktemp -d)"
gh release download "$release" --repo Alex9001/whodis \
  --pattern checksums.txt --dir "$package_work"
scripts/render-community-packages.sh "$release" \
  "$package_work/checksums.txt" "$package_work/rendered"
```

The rendered outputs are:

- `homebrew/whodis.rb` for a dedicated `Alex9001/homebrew-whodis` tap
- `scoop/whodis.json` for a dedicated Scoop bucket or upstream submission
- `nix/whodis.nix` for a Nix overlay or eventual nixpkgs submission

Inspect URLs and hashes, install from a clean package-manager environment, and
confirm `whodis --version` before publishing them. These files install only the
CLI, so Homebrew, Scoop, and Nix users do not unexpectedly pull Qt onto servers.

WinGet and Flathub require manifests/review in their own upstream repositories.
Prepare those submissions from the signed or checksum-verified v2 assets, but
do not claim availability until the upstream merge is live. AppStream metadata
for the Linux GUI is maintained at
`desktop/packaging/net.cyberbrand.whodis.metainfo.xml` and is validated in CI.

## AppImage catalog and external updates

Linux packages are built on Ubuntu 22.04 and named
`whodis-gui-<version>-x86_64.AppImage` / `whodis-gui-<version>-aarch64.AppImage`.
Each has a checksummed `.AppImage.zsync` sidecar and embedded
`gh-releases-zsync|Alex9001|whodis|latest|whodis-gui-*-<architecture>.AppImage.zsync`
update information. Prereleases use their exact tag instead of `latest`, so they
do not silently switch to the stable channel. Updates are performed by external
AppImageUpdate-compatible tools, not by the Whodis application. Users of
AppImages older than 2.5.4 must download 2.5.4 or later once manually, since those
older images do not contain an update channel.

CMake installs the source metadata as `net.cyberbrand.whodis.appdata.xml` for
older AppImage catalog workers. Before a release, update its release version and
date alongside `.github/RELEASE_NOTES.md`. The release workflow validates both
metadata files, update information and zsync reconstruction, packaged ELF symbol
ceilings (GLIBC 2.35, GLIBCXX 3.4.30, CXXABI 1.3.13), dependency resolution,
relocatable runtime paths, Ubuntu 22.04/24.04 visible startup with screenshots,
and the pinned upstream AppImage catalog worker against
the exact candidate bytes. These gates also run during non-publishing preflight.

The catalog gate only tests a local candidate; it does not submit Whodis to
AppImageHub. Any later listing submission must use the published stable release
and must not be claimed live until accepted upstream. Do not publish duplicate
AppImage aliases: catalog discovery and update patterns should select one asset
per architecture.
