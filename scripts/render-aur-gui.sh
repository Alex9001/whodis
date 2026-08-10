#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: render-aur-gui.sh <version> <source-sha256> <output-directory>" >&2
    exit 2
fi

version=${1#v}
source_sha256=$2
output_dir=$3

printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
    echo "render-aur-gui: version must be a stable semantic version" >&2
    exit 2
}
printf '%s\n' "$source_sha256" | grep -Eq '^[0-9A-Fa-f]{64}$' || {
    echo "render-aur-gui: source checksum must be a SHA-256 digest" >&2
    exit 2
}
[ -d "$output_dir" ] || {
    echo "render-aur-gui: output directory does not exist: $output_dir" >&2
    exit 2
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
template_dir="$(dirname -- "$script_dir")/packaging/aur-gui"

render() {
    input=$1
    output=$2
    temporary=$(mktemp "$output_dir/.whodis-gui-render.XXXXXX")
    sed -e "s/@PKGVER@/${version}/g" -e "s/@SHA256@/${source_sha256}/g" "$input" > "$temporary"
    chmod 0644 "$temporary"
    mv -- "$temporary" "$output"
}

render "$template_dir/PKGBUILD.in" "$output_dir/PKGBUILD"
render "$template_dir/.SRCINFO.in" "$output_dir/.SRCINFO"
cp -- "$template_dir/LICENSE" "$output_dir/LICENSE"
chmod 0644 "$output_dir/LICENSE"
echo "Rendered AUR package whodis-gui ${version}-1 in $output_dir"

