#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: render-aur.sh <version> <source-sha256> <output-directory>" >&2
    exit 2
fi

version=${1#v}
source_sha256=$2
output_dir=$3

if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "render-aur: version must be a stable semantic version" >&2
    exit 2
fi
if ! printf '%s\n' "$source_sha256" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
    echo "render-aur: source checksum must be a SHA-256 digest" >&2
    exit 2
fi
if [ ! -d "$output_dir" ]; then
    echo "render-aur: output directory does not exist: $output_dir" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname -- "$script_dir")
template_dir="$repo_root/packaging/aur"

render() {
    input=$1
    output=$2
    temporary=$(mktemp "$output_dir/.whodis-render.XXXXXX")

    if ! sed \
        -e "s/@PKGVER@/${version}/g" \
        -e "s/@SHA256@/${source_sha256}/g" \
        "$input" > "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 0644 "$temporary"
    mv -- "$temporary" "$output"
}

copy_file() {
    input=$1
    output=$2
    temporary=$(mktemp "$output_dir/.whodis-copy.XXXXXX")

    if ! cp -- "$input" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 0644 "$temporary"
    mv -- "$temporary" "$output"
}

render "$template_dir/PKGBUILD.in" "$output_dir/PKGBUILD"
render "$template_dir/.SRCINFO.in" "$output_dir/.SRCINFO"
copy_file "$template_dir/LICENSE" "$output_dir/LICENSE"

echo "Rendered AUR package whodis ${version}-1 in $output_dir"
