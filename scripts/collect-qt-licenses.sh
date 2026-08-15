#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: collect-qt-licenses.sh <output-directory>" >&2
    exit 2
fi

output_dir=$1
license_dir=${QT_LICENSE_DIR:-}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -z "$license_dir" ] && [ -n "${QT_ROOT_DIR:-}" ] && [ -d "$QT_ROOT_DIR/LICENSES" ]; then
    license_dir=$QT_ROOT_DIR/LICENSES
fi
if [ -z "$license_dir" ]; then
    for candidate in \
        /usr/share/licenses/qt6-base \
        "$script_dir/../desktop/packaging/qt-licenses"; do
        if [ -d "$candidate" ]; then
            license_dir=$candidate
            break
        fi
    done
fi

mkdir -p "$output_dir"
found=false
if [ -n "$license_dir" ] && [ -d "$license_dir" ]; then
    for license_file in "$license_dir"/*; do
        [ -f "$license_file" ] || continue
        cp -f -- "$license_file" "$output_dir/"
        found=true
    done
fi

if [ "$found" = false ]; then
    for copyright_file in \
        /usr/share/doc/qt6-base-dev/copyright \
        /usr/share/doc/libqt6core6/copyright; do
        if [ -f "$copyright_file" ]; then
            cp -f -- "$copyright_file" "$output_dir/Qt-COPYRIGHT"
            found=true
            break
        fi
    done
    if [ -f /usr/share/common-licenses/LGPL-3 ]; then
        cp -f -- /usr/share/common-licenses/LGPL-3 "$output_dir/LGPL-3.0-only.txt"
    fi
    if [ -f /usr/share/common-licenses/GPL-3 ]; then
        cp -f -- /usr/share/common-licenses/GPL-3 "$output_dir/GPL-3.0-only.txt"
    fi
fi

[ "$found" = true ] || {
    echo "collect-qt-licenses: could not find Qt license material" >&2
    exit 1
}

test -f "$output_dir/LGPL-3.0-only.txt" || {
    echo "collect-qt-licenses: LGPL-3.0-only.txt is missing" >&2
    exit 1
}
test -f "$output_dir/GPL-3.0-only.txt" || {
    echo "collect-qt-licenses: GPL-3.0-only.txt is missing" >&2
    exit 1
}

echo "Collected Qt license material in $output_dir"
