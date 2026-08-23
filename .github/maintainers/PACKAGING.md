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
