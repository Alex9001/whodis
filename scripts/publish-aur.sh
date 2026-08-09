#!/bin/sh

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: publish-aur.sh <vX.Y.Z> [checksums-file]" >&2
    exit 2
fi

tag=$1
version=${tag#v}
checksums_file=${2:-dist/checksums.txt}
aur_git_url=${WHODIS_AUR_GIT_URL:-ssh://aur@aur.archlinux.org/whodis.git}

if [ -z "${AUR_KEY:-}" ]; then
    echo "publish-aur: AUR_KEY is required" >&2
    exit 2
fi
if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "publish-aur: only stable vX.Y.Z tags may update AUR" >&2
    exit 2
fi
if [ ! -f "$checksums_file" ]; then
    echo "publish-aur: checksums file not found: $checksums_file" >&2
    exit 2
fi

source_asset="whodis_${version}_source.tar.gz"
source_sha256=$(awk -v name="$source_asset" '$2 == name { print $1; exit }' "$checksums_file")
if ! printf '%s\n' "$source_sha256" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
    echo "publish-aur: checksum not found for $source_asset" >&2
    exit 1
fi

checksums_dir=$(CDPATH= cd -- "$(dirname -- "$checksums_file")" && pwd)
source_archive="$checksums_dir/$source_asset"
if [ ! -f "$source_archive" ]; then
    echo "publish-aur: source archive not found: $source_archive" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256=$(sha256sum "$source_archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual_sha256=$(shasum -a 256 "$source_archive" | awk '{print $1}')
else
    echo "publish-aur: sha256sum or shasum is required" >&2
    exit 1
fi
if [ "$actual_sha256" != "$source_sha256" ]; then
    echo "publish-aur: source archive checksum does not match checksums.txt" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/whodis-aur-publish.XXXXXX")
cleanup() {
    rm -rf -- "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

key_file="$temporary_dir/aur_key"
umask 077
printf '%s\n' "$AUR_KEY" > "$key_file"
chmod 600 "$key_file"

export GIT_SSH_COMMAND="ssh -i $key_file -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -F /dev/null"
aur_checkout="$temporary_dir/aur"
git clone "$aur_git_url" "$aur_checkout"

"$script_dir/render-aur.sh" "$version" "$source_sha256" "$aur_checkout"
git -C "$aur_checkout" config user.name 'Aleksandr Oreshkin'
git -C "$aur_checkout" config user.email 'alex@cyberbrand.net'
git -C "$aur_checkout" add PKGBUILD .SRCINFO LICENSE

if git -C "$aur_checkout" diff --cached --quiet; then
    echo "AUR package whodis ${version}-1 is already current"
    exit 0
fi

git -C "$aur_checkout" commit -m "Update to ${tag}"
git -C "$aur_checkout" push origin HEAD:master
echo "Published whodis ${version}-1 to AUR"
