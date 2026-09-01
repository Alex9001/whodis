#!/bin/sh

set -eu

if [ "$#" -lt 4 ]; then
    echo "usage: bundle-sboms.sh <version> <checksums-file> <output-directory> <label=sbom-directory>..." >&2
    exit 2
fi

version=${1#v}
checksums_file=$2
output_dir=$3
shift 3

case "$version" in
    ''|*[!0-9A-Za-z._-]*)
        echo "bundle-sboms: invalid version: $version" >&2
        exit 2
        ;;
esac

for command in awk cp find grep jq sha256sum sort zip; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "bundle-sboms: required command not found: $command" >&2
        exit 1
    fi
done

[ -f "$checksums_file" ] || {
    echo "bundle-sboms: checksums file not found: $checksums_file" >&2
    exit 1
}
[ -d "$output_dir" ] || {
    echo "bundle-sboms: output directory not found: $output_dir" >&2
    exit 1
}

output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
checksums_dir=$(CDPATH= cd -- "$(dirname -- "$checksums_file")" && pwd)
checksums_file="$checksums_dir/$(basename -- "$checksums_file")"
bundle="$output_dir/whodis_${version}_sboms.zip"

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
content_dir="$work_dir/content"
list_dir="$work_dir/lists"
mkdir -p "$content_dir" "$list_dir"

total_count=0
for group in "$@"; do
    label=${group%%=*}
    source_dir=${group#*=}
    if [ "$source_dir" = "$group" ]; then
        echo "bundle-sboms: expected label=directory, got: $group" >&2
        exit 2
    fi
    case "$label" in
        ''|*[!0-9A-Za-z._-]*)
            echo "bundle-sboms: invalid group label: $label" >&2
            exit 2
            ;;
    esac
    [ -d "$source_dir" ] || {
        echo "bundle-sboms: SBOM directory not found: $source_dir" >&2
        exit 1
    }

    group_dir="$content_dir/$label"
    group_list="$list_dir/$label"
    mkdir -p "$group_dir"
    find "$source_dir" -type f -name '*.sbom.json' -print | sort > "$group_list"
    [ -s "$group_list" ] || {
        echo "bundle-sboms: no SBOM files found in $source_dir" >&2
        exit 1
    }

    while IFS= read -r sbom; do
        jq --exit-status '.packages | type == "array" and length > 0' "$sbom" >/dev/null
        grep -qi whodis "$sbom" || {
            echo "bundle-sboms: SBOM does not identify Whodis: $sbom" >&2
            exit 1
        }
        destination="$group_dir/$(basename -- "$sbom")"
        [ ! -e "$destination" ] || {
            echo "bundle-sboms: duplicate SBOM filename in $label: $(basename -- "$sbom")" >&2
            exit 1
        }
        cp "$sbom" "$destination"
        total_count=$((total_count + 1))
    done < "$group_list"
done

[ "$total_count" -gt 0 ] || {
    echo "bundle-sboms: no SBOM files were collected" >&2
    exit 1
}

rm -f -- "$bundle"
(
    cd "$content_dir"
    zip -q -r "$bundle" .
)

for group_list in "$list_dir"/*; do
    while IFS= read -r sbom; do
        rm -f -- "$sbom"
    done < "$group_list"
done

filtered_checksums="$work_dir/checksums.filtered"
updated_checksums="$work_dir/checksums.updated"
awk '$2 !~ /\.sbom\.json$/ && $2 !~ /_sboms\.zip$/ { print }' \
    "$checksums_file" > "$filtered_checksums"
bundle_hash=$(sha256sum "$bundle" | awk '{print $1}')
printf '%s  %s\n' "$bundle_hash" "$(basename -- "$bundle")" >> "$filtered_checksums"
LC_ALL=C sort -k2,2 "$filtered_checksums" > "$updated_checksums"
cp "$updated_checksums" "$checksums_file"

echo "Bundled $total_count SBOM files in $bundle"
