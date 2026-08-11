# AUR publication handoff

The source-package templates and automation are ready for two independent AUR
packages:

- `whodis` installs the small CLI for workstations and servers.
- `whodis-gui` installs the Qt desktop app and its private engine. It does not
  depend on the CLI package.

An AUR account with its SSH key registered is the only missing requirement for
the first pushes. Both packages build from the same stable GitHub source
archive, but live in separate AUR Git repositories. The application is MIT
licensed; `packaging/aur/LICENSE` and `packaging/aur-gui/LICENSE` apply 0BSD
only to the AUR packaging files.

## Package contract

- Maintainer: `Aleksandr Oreshkin <alex@cyberbrand.net>`
- Upstream: `https://github.com/Alex9001/whodis`
- AUR repositories: `whodis.git` and `whodis-gui.git`
- AUR branch: `master`
- Architectures: `x86_64` and `aarch64`
- CLI install: `/usr/bin/whodis`
- GUI install: `/usr/bin/whodis-gui`, private engine under
  `/usr/libexec/whodis/`, desktop entry, and icon
- GUI dependency: `qt6-base`
- Minimum GUI version: `0.6.4-1`; use the newest stable release when publishing

The workstation previously had a dedicated key:

- Private key: `~/.ssh/aur_whodis` (mode `0600`; never share it)
- Public key: `~/.ssh/aur_whodis.pub`
- Fingerprint: `SHA256:rKZhT6CBWNn+12MULrVWmGMMyR34di3FEsNIWzHQaXc`

## 1. Register the account and key

1. Register and verify the account at <https://aur.archlinux.org/register>.
2. Sign in, open **My Account**, and add the complete output of:

   ```bash
   cat ~/.ssh/aur_whodis.pub
   ```

3. Confirm the fingerprint and test authentication:

   ```bash
   ssh-keygen -lf ~/.ssh/aur_whodis.pub
   ssh -i ~/.ssh/aur_whodis -o IdentitiesOnly=yes aur@aur.archlinux.org
   ```

A successful SSH test prints an AUR greeting and disconnects. If the key files
are missing, make a replacement, register its public half, and update the
fingerprint recorded above:

```bash
ssh-keygen -t ed25519 -N '' -C 'whodis AUR publishing' \
  -f ~/.ssh/aur_whodis
chmod 600 ~/.ssh/aur_whodis
```

Never commit, paste, or upload the private key. Only the `.pub` half is public.

## 2. Select a release

Use the newest stable release containing the GUI source. The current package
target is `v1.0.1`; replace it with a newer stable release if one exists when
the account is ready. Do not use a prerelease because automatic AUR publication
deliberately ignores prerelease tags.

```bash
release_tag=v1.0.1
release_version=${release_tag#v}
gh release view "$release_tag" --repo Alex9001/whodis
```

Confirm that both package names are available:

- <https://aur.archlinux.org/packages/whodis>
- <https://aur.archlinux.org/packages/whodis-gui>

If another person has created either package, stop and use the AUR ownership or
adoption process instead of pushing over their work.

Run the remaining steps from a clean upstream checkout on Arch Linux with
`base-devel`, `git`, `go`, `cmake`, `ninja`, `qt6-base`, and `namcap` installed.

## 3. Clone and render both packages

Use sibling directories so the AUR repositories cannot be confused with the
GitHub checkout. Inspect rather than overwrite either directory if it exists.

```bash
git clone -c core.sshCommand='ssh -i ~/.ssh/aur_whodis -o IdentitiesOnly=yes' \
  ssh://aur@aur.archlinux.org/whodis.git ../whodis-aur
git clone -c core.sshCommand='ssh -i ~/.ssh/aur_whodis -o IdentitiesOnly=yes' \
  ssh://aur@aur.archlinux.org/whodis-gui.git ../whodis-gui-aur

aur_release_dir="$(mktemp -d)"
gh release download "$release_tag" --repo Alex9001/whodis \
  --pattern "whodis_${release_version}_source.tar.gz" \
  --pattern checksums.txt \
  --dir "$aur_release_dir"
(
  cd "$aur_release_dir"
  grep "whodis_${release_version}_source.tar.gz$" checksums.txt | sha256sum -c -
)
source_sha256="$(sha256sum "$aur_release_dir/whodis_${release_version}_source.tar.gz" | cut -d ' ' -f 1)"

scripts/render-aur.sh "$release_version" "$source_sha256" ../whodis-aur
scripts/render-aur-gui.sh "$release_version" "$source_sha256" ../whodis-gui-aur
```

Do not publish the `.in` templates. Each rendered AUR checkout must contain only
`PKGBUILD`, `.SRCINFO`, and `LICENSE` as tracked package files.

## 4. Build and inspect

```bash
for aur_checkout in ../whodis-aur ../whodis-gui-aur; do
  (
    cd "$aur_checkout"
    makepkg --verifysource
    makepkg --printsrcinfo | diff -u .SRCINFO -
    makepkg --cleanbuild --syncdeps
    namcap PKGBUILD
    namcap ./*.pkg.tar.zst
  )
done
```

Stop on any download, checksum, compilation, test, or material `namcap` error.
Review both sets of files and confirm no private key or unrelated file is
present. Regenerate `.SRCINFO` after every metadata change.

## 5. Publish the initial repositories

```bash
git -C ../whodis-aur config user.name 'Aleksandr Oreshkin'
git -C ../whodis-aur config user.email 'alex@cyberbrand.net'
git -C ../whodis-aur add PKGBUILD .SRCINFO LICENSE
git -C ../whodis-aur commit -m "Initial release: whodis ${release_version}"
git -C ../whodis-aur push origin master

git -C ../whodis-gui-aur config user.name 'Aleksandr Oreshkin'
git -C ../whodis-gui-aur config user.email 'alex@cyberbrand.net'
git -C ../whodis-gui-aur add PKGBUILD .SRCINFO LICENSE
git -C ../whodis-gui-aur commit -m "Initial release: whodis-gui ${release_version}"
git -C ../whodis-gui-aur push origin master
```

Before each commit, `git status --short` must show exactly `PKGBUILD`,
`.SRCINFO`, and `LICENSE`. Never force-push AUR history.

## 6. Verify clean installs

Inspect both AUR web pages, then install from fresh clones:

```bash
whodis_aur_check="$(mktemp -d)"
git clone https://aur.archlinux.org/whodis.git "$whodis_aur_check"
(
  cd "$whodis_aur_check"
  makepkg --syncdeps --cleanbuild --install
  test "$(command -v whodis)" = /usr/bin/whodis
  whodis --version
  whodis example.com
)

whodis_gui_aur_check="$(mktemp -d)"
git clone https://aur.archlinux.org/whodis-gui.git "$whodis_gui_aur_check"
(
  cd "$whodis_gui_aur_check"
  makepkg --syncdeps --cleanbuild --install
  test "$(command -v whodis-gui)" = /usr/bin/whodis-gui
  test -x /usr/libexec/whodis/whodis-gui-engine
  QT_QPA_PLATFORM=offscreen timeout 5 whodis-gui || test "$?" -eq 124
)
```

The CLI version must equal `$release_version`. The offscreen GUI must remain
running until `timeout` stops it rather than fail during startup.

## 7. Enable automatic updates

Only after both initial pushes are live, store the private key as an encrypted
GitHub Actions secret:

```bash
gh secret set AUR_KEY --repo Alex9001/whodis < ~/.ssh/aur_whodis
gh secret list --repo Alex9001/whodis
```

Future stable tags update both repositories through `scripts/publish-aur.sh`
and `scripts/publish-aur-gui.sh`. Prereleases and workflow runs without
`AUR_KEY` skip publication. Never put the private key in workflows, logs,
release assets, or Git history.

## 8. Advertise the live packages

Only after the clean installs succeed, replace the README's pending AUR text
with live commands:

```bash
yay -S whodis
yay -S whodis-gui
```

Link each command to its package page, commit the README update to `main`, and
let CI finish. Do not advertise a package before its page is live.

## Recovery and key rotation

- **Permission denied:** compare the registered public key with
  `ssh-keygen -lf ~/.ssh/aur_whodis.pub`, then use `IdentitiesOnly=yes`.
- **Metadata rejected:** regenerate `.SRCINFO`, commit both metadata files, and
  push normally.
- **Compromised key:** remove it from the AUR account, run
  `gh secret delete AUR_KEY --repo Alex9001/whodis`, create and register a new
  dedicated key, and replace the secret.
- **Failed update:** do not move an existing release tag or force-push AUR.
  Correct the package and publish a new patch release.
