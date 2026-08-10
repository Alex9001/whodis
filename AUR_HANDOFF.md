# AUR publication handoff

The source-package templates and publication automation are ready. An AUR
account and its registered SSH key are the only missing pieces for the first
push. Generate `PKGBUILD` and `.SRCINFO` from the latest stable GitHub source
archive as described below; do not publish the `.in` templates or copy an old
versioned package snapshot from `packaging/aur/`.

The application is MIT-licensed. The separate `packaging/aur/LICENSE` applies
0BSD only to the AUR packaging files, as recommended by the
[AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines).

## Package contract

- AUR package: `whodis` (source-built, not `whodis-bin`)
- Maintainer: `Aleksandr Oreshkin <alex@cyberbrand.net>`
- Upstream: `https://github.com/Alex9001/whodis`
- Initial version if published now: `0.5.1-1`
- Released source SHA-256: derived and verified from the selected GitHub release below
- Architecture: `x86_64`
- Installed binary: `/usr/bin/whodis`
- Installed application license: `/usr/share/licenses/whodis/LICENSE`
- AUR branch: `master`

The original workstation already has a dedicated key:

- Private key: `~/.ssh/aur_whodis` (mode `0600`; never share it)
- Public key: `~/.ssh/aur_whodis.pub`
- Fingerprint: `SHA256:rKZhT6CBWNn+12MULrVWmGMMyR34di3FEsNIWzHQaXc`

## 1. Create the account and register the key

1. Open <https://aur.archlinux.org/register>, register, and verify the email.
2. Sign in and open **My Account**.
3. Display the existing public key:

   ```bash
   cat ~/.ssh/aur_whodis.pub
   ```

4. Copy the complete `ssh-ed25519 ...` line into the account's SSH public-key
   field and save it.
5. Confirm that the displayed fingerprint still matches this handoff:

   ```bash
   ssh-keygen -lf ~/.ssh/aur_whodis.pub
   ```

If the key files are missing, create a replacement dedicated key first:

```bash
ssh-keygen -t ed25519 -N '' -C 'whodis AUR publishing' \
  -f ~/.ssh/aur_whodis
chmod 600 ~/.ssh/aur_whodis
```

Register the replacement public key and update the fingerprint recorded in
this file. Test authentication:

```bash
ssh -i ~/.ssh/aur_whodis -o IdentitiesOnly=yes aur@aur.archlinux.org
```

A successful test prints an AUR greeting and disconnects; it does not provide
a shell. Never commit, paste, or upload the private key. Only the `.pub` half is
public.

## 2. Confirm the release and package name

Set the release to publish, then confirm it exists and is stable. `v0.5.1` is
the intended initial AUR version; replace it with a newer stable release if
publication happens later.

```bash
release_tag=v0.5.1
release_version=${release_tag#v}
gh release view "$release_tag" --repo Alex9001/whodis
```

Also open
<https://aur.archlinux.org/packages/whodis>. If another person has created that
package, stop and follow the AUR ownership/adoption process instead of pushing
over their work.

Run all remaining commands from a clean, up-to-date upstream `whodis` checkout
on Arch Linux with `base-devel`, `git`, `go`, and `namcap` installed.

## 3. Create and validate the first package

Use a sibling directory so the AUR Git repository cannot be confused with the
GitHub repository. If `../whodis-aur` already exists, inspect it instead of
deleting or overwriting it.

```bash
release_tag=${release_tag:-v0.5.1}
release_version=${release_tag#v}
git clone -c core.sshCommand='ssh -i ~/.ssh/aur_whodis -o IdentitiesOnly=yes' \
  ssh://aur@aur.archlinux.org/whodis.git ../whodis-aur

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

(
  cd ../whodis-aur
  makepkg --verifysource
  makepkg --printsrcinfo | diff -u .SRCINFO -
  makepkg --cleanbuild --syncdeps
  namcap PKGBUILD
  namcap "whodis-${release_version}-1-"*.pkg.tar.zst
)
```

Stop if downloading, checksum verification, compilation, tests, or `namcap`
reports a material error. Review `PKGBUILD`, `.SRCINFO`, and `LICENSE`; confirm
that no private key or unrelated file is present. `.SRCINFO` must always be
regenerated after package metadata changes.

## 4. Publish the initial AUR repository

```bash
git -C ../whodis-aur config user.name 'Aleksandr Oreshkin'
git -C ../whodis-aur config user.email 'alex@cyberbrand.net'
git -C ../whodis-aur status --short
git -C ../whodis-aur add PKGBUILD .SRCINFO LICENSE
git -C ../whodis-aur commit -m "Initial release: whodis ${release_version}"
git -C ../whodis-aur push origin master
```

The staged files should be exactly `PKGBUILD`, `.SRCINFO`, and `LICENSE`. Never
force-push AUR history.

## 5. Verify the published package

Open <https://aur.archlinux.org/packages/whodis>, inspect the rendered metadata,
then test from a clean Arch environment:

```bash
whodis_aur_check="$(mktemp -d)"
git clone https://aur.archlinux.org/whodis.git "$whodis_aur_check"
(
  cd "$whodis_aur_check"
  makepkg --syncdeps --cleanbuild --install
  command -v whodis
  whodis --version
  whodis google.com
)
```

`command -v whodis` must print `/usr/bin/whodis`, and the version must be
the value of `$release_version` selected above.

## 6. Enable future automatic updates

Only after the public key works and the initial AUR repository has been
published, save the private key as an encrypted GitHub Actions secret:

```bash
gh secret set AUR_KEY --repo Alex9001/whodis < ~/.ssh/aur_whodis
gh secret list --repo Alex9001/whodis
```

Confirm that only the secret name, not its value, is displayed. Future stable
`vX.Y.Z` releases update AUR with the same audited templates through
`scripts/publish-aur.sh`; prereleases and runs without `AUR_KEY` skip AUR
publication. Never place the private key in workflow files, logs, release
assets, or Git history.

## 7. Mark AUR as live in the README

After the package page and clean installation are verified, replace the
README's "publication pending" paragraph with the live commands:

````markdown
### Arch Linux (AUR)

```bash
yay -S whodis
# or: paru -S whodis
```
````

Link the heading to <https://aur.archlinux.org/packages/whodis>, commit the
README update to `main`, and let CI finish before considering the handoff
complete. Do not advertise the command before the AUR page is live.

## Recovery and key rotation

- **Permission denied:** verify that the registered public key matches
  `ssh-keygen -lf ~/.ssh/aur_whodis.pub`, then retry with
  `-o IdentitiesOnly=yes`.
- **Metadata rejected:** regenerate `.SRCINFO` with
  `makepkg --printsrcinfo > .SRCINFO`, commit both files, and push normally.
- **Compromised key:** delete its public half from the AUR account, run
  `gh secret delete AUR_KEY --repo Alex9001/whodis`, generate and register a new
  dedicated key, then replace the secret.
- **Failed update:** do not move an existing release tag or force-push AUR.
  Correct the package configuration and publish a new patch release.
