#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: collect-go-licenses.sh <output-directory>" >&2
    exit 2
fi

output_dir=$1
mkdir -p "$output_dir"
index_file="$output_dir/MODULES.txt"
missing_file="$output_dir/.missing"
rm -f "$missing_file"
tab=$(printf '\t')

printf '%s\n\n' \
    'Go module license material bundled with Whodis.' \
    'Exact dependency versions are recorded in go.mod, go.sum, and the release SBOM.' \
    > "$index_file"

go mod download
go list -deps -f '{{with .Module}}{{if and (not .Main) .Dir}}{{.Path}}{{"\t"}}{{.Dir}}{{end}}{{end}}' \
    ./cmd/whodis ./cmd/whodis-gui-engine | sort -u |
while IFS="$tab" read -r module module_dir; do
    [ -n "$module" ] && [ -d "$module_dir" ] || continue
    safe_module=$(printf '%s' "$module" | tr '/@:' '___')
    found=false
    copied=
    for source in \
        "$module_dir"/LICENSE "$module_dir"/LICENSE.* \
        "$module_dir"/LICENCE "$module_dir"/LICENCE.* \
        "$module_dir"/COPYING "$module_dir"/COPYING.* \
        "$module_dir"/NOTICE "$module_dir"/NOTICE.*; do
        [ -f "$source" ] || continue
        destination="${safe_module}-$(basename "$source")"
        cp "$source" "$output_dir/$destination"
        copied="${copied} ${destination}"
        found=true
    done
    if [ "$found" = true ]; then
        printf '%s:%s\n' "$module" "$copied" >> "$index_file"
    else
        printf '%s\n' "$module" >> "$missing_file"
    fi
done

if [ -f "$missing_file" ]; then
    echo "collect-go-licenses: no root license file found for:" >&2
    sed 's/^/  /' "$missing_file" >&2
    exit 1
fi

license_count=0
for license_file in "$output_dir"/*; do
    [ -f "$license_file" ] || continue
    [ "$license_file" = "$index_file" ] && continue
    license_count=$((license_count + 1))
done
[ "$license_count" -gt 0 ] || {
    echo "collect-go-licenses: no dependency licenses were collected" >&2
    exit 1
}

echo "Collected ${license_count} Go dependency license files in $output_dir"
