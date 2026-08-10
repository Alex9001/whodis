#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: collect-qt-licenses.sh <output-directory>" >&2
    exit 2
fi

output_dir=$1
license_dir=${QT_LICENSE_DIR:-}

if [ -z "$license_dir" ] && [ -n "${QT_ROOT_DIR:-}" ] && [ -d "$QT_ROOT_DIR/LICENSES" ]; then
    license_dir=$QT_ROOT_DIR/LICENSES
fi
if [ -z "$license_dir" ]; then
    for candidate in /usr/share/licenses/qt6-base /usr/share/doc/qt6-base-dev/copyright; do
        if [ -d "$candidate" ]; then
            license_dir=$candidate
            break
        fi
    done
fi

[ -n "$license_dir" ] && [ -d "$license_dir" ] || {
    echo "collect-qt-licenses: could not find the Qt license directory" >&2
    exit 1
}

mkdir -p "$output_dir"
found=false
for license_file in "$license_dir"/*; do
    [ -f "$license_file" ] || continue
    cp -- "$license_file" "$output_dir/"
    found=true
done

[ "$found" = true ] || {
    echo "collect-qt-licenses: no license files found in $license_dir" >&2
    exit 1
}

test -f "$output_dir/LGPL-3.0-only.txt" || {
    echo "collect-qt-licenses: LGPL-3.0-only.txt is missing from $license_dir" >&2
    exit 1
}
test -f "$output_dir/GPL-3.0-only.txt" || {
    echo "collect-qt-licenses: GPL-3.0-only.txt is missing from $license_dir" >&2
    exit 1
}

echo "Collected Qt licenses from $license_dir"
