#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: package-gui-linux.sh <version> <build-directory> <output-directory>" >&2
    exit 2
fi

version=${1#v}
build_dir=$2
output_dir=$3
linuxdeploy=${LINUXDEPLOY:-linuxdeploy}
qmake=${QMAKE:-}

command -v cmake >/dev/null 2>&1 || { echo "cmake is required" >&2; exit 1; }
command -v "$linuxdeploy" >/dev/null 2>&1 || { echo "linuxdeploy is required" >&2; exit 1; }
[ -n "$qmake" ] || qmake=qmake6
qmake=$(command -v "$qmake" || true)
[ -n "$qmake" ] && [ -x "$qmake" ] || { echo "qmake6 is required" >&2; exit 1; }
"$qmake" -query QT_VERSION | grep -Eq '^6\.' || { echo "qmake must select Qt 6" >&2; exit 1; }
export QMAKE=$qmake
[ -d "$output_dir" ] || { echo "output directory does not exist: $output_dir" >&2; exit 2; }

case "$(uname -m)" in
    x86_64|amd64) release_arch=amd64 ;;
    aarch64|arm64) release_arch=arm64 ;;
    *) echo "unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

cmake -S desktop -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DWHODIS_VERSION="$version" \
    -DBUILD_TESTING=OFF
cmake --build "$build_dir" --parallel

app_dir="$build_dir/AppDir"
cmake -E remove_directory "$app_dir"
DESTDIR="$app_dir" cmake --install "$build_dir"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$script_dir/collect-qt-licenses.sh" \
    "$app_dir/usr/share/licenses/whodis-gui/Qt-Licenses"

output="$output_dir/whodis-gui_linux_${release_arch}.AppImage"
NO_STRIP=1 OUTPUT="$output" "$linuxdeploy" \
    --appdir "$app_dir" \
    --desktop-file "$app_dir/usr/share/applications/net.cyberbrand.whodis.desktop" \
    --icon-file "$app_dir/usr/share/pixmaps/net.cyberbrand.whodis.png" \
    --plugin qt \
    --output appimage
test -f "$output"
APPIMAGE_EXTRACT_AND_RUN=1 "$output" --appimage-version >/dev/null
echo "Created $output"
