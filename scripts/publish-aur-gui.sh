#!/bin/sh

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: publish-aur-gui.sh <vX.Y.Z> [checksums-file]" >&2
    exit 2
fi

tag=$1
version=${tag#v}
checksums_file=${2:-dist/checksums.txt}
aur_git_url=${WHODIS_GUI_AUR_GIT_URL:-ssh://aur@aur.archlinux.org/whodis-gui.git}

[ -n "${AUR_KEY:-}" ] || { echo "publish-aur-gui: AUR_KEY is required" >&2; exit 2; }
printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || {
    echo "publish-aur-gui: only stable vX.Y.Z tags may update AUR" >&2
    exit 2
}
[ -f "$checksums_file" ] || { echo "publish-aur-gui: checksums file not found: $checksums_file" >&2; exit 2; }

source_asset="whodis_${version}_source.tar.gz"
source_sha256=$(awk -v name="$source_asset" '$2 == name { print $1; exit }' "$checksums_file")
printf '%s\n' "$source_sha256" | grep -Eq '^[0-9A-Fa-f]{64}$' || {
    echo "publish-aur-gui: checksum not found for $source_asset" >&2
    exit 1
}

checksums_dir=$(CDPATH= cd -- "$(dirname -- "$checksums_file")" && pwd)
source_archive="$checksums_dir/$source_asset"
[ -f "$source_archive" ] || {
    echo "publish-aur-gui: source archive not found: $source_archive" >&2
    exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256=$(sha256sum "$source_archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual_sha256=$(shasum -a 256 "$source_archive" | awk '{print $1}')
else
    echo "publish-aur-gui: sha256sum or shasum is required" >&2
    exit 1
fi
[ "$actual_sha256" = "$source_sha256" ] || {
    echo "publish-aur-gui: source archive checksum does not match checksums.txt" >&2
    exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/whodis-gui-aur-publish.XXXXXX")
cleanup() { rm -rf -- "$temporary_dir"; }
trap cleanup EXIT HUP INT TERM

key_file="$temporary_dir/aur_key"
umask 077
printf '%s\n' "$AUR_KEY" > "$key_file"
chmod 600 "$key_file"
export GIT_SSH_COMMAND="ssh -i $key_file -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -F /dev/null"
aur_checkout="$temporary_dir/aur"
git clone "$aur_git_url" "$aur_checkout"
"$script_dir/render-aur-gui.sh" "$version" "$source_sha256" "$aur_checkout"
git -C "$aur_checkout" config user.name 'Aleksandr Oreshkin'
git -C "$aur_checkout" config user.email 'alex@cyberbrand.net'
git -C "$aur_checkout" add PKGBUILD .SRCINFO LICENSE

if git -C "$aur_checkout" diff --cached --quiet; then
    echo "AUR package whodis-gui ${version}-1 is already current"
    exit 0
fi
git -C "$aur_checkout" commit -m "Update to ${tag}"
git -C "$aur_checkout" push origin HEAD:master
echo "Published whodis-gui ${version}-1 to AUR"
