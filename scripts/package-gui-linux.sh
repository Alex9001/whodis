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

qt_plugins=$("$qmake" -query QT_INSTALL_PLUGINS)
[ -d "$qt_plugins/platforms" ] || {
    echo "Qt platform plugin directory does not exist: $qt_plugins/platforms" >&2
    exit 1
}
wayland_platform_plugins=
for plugin in libqwayland.so libqwayland-egl.so libqwayland-generic.so; do
    if [ -f "$qt_plugins/platforms/$plugin" ]; then
        if [ -n "$wayland_platform_plugins" ]; then
            wayland_platform_plugins="$wayland_platform_plugins;$plugin"
        else
            wayland_platform_plugins=$plugin
        fi
    fi
done
[ -n "$wayland_platform_plugins" ] || {
    echo "Qt Wayland platform plugins are required to build the AppImage" >&2
    exit 1
}
export EXTRA_PLATFORM_PLUGINS=$wayland_platform_plugins
export EXTRA_QT_MODULES=waylandcompositor

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
"$script_dir/collect-go-licenses.sh" \
    "$app_dir/usr/share/licenses/whodis-gui/Go-Licenses"

output="$output_dir/whodis-gui_linux_${release_arch}.AppImage"
NO_STRIP=1 OUTPUT="$output" "$linuxdeploy" \
    --appdir "$app_dir" \
    --desktop-file "$app_dir/usr/share/applications/net.cyberbrand.whodis.desktop" \
    --icon-file "$app_dir/usr/share/pixmaps/net.cyberbrand.whodis.png" \
    --plugin qt \
    --output appimage
test -f "$output"
test -f "$app_dir/usr/plugins/platforms/libqxcb.so"
wayland_platform_deployed=false
for plugin in libqwayland.so libqwayland-egl.so libqwayland-generic.so; do
    if [ -f "$app_dir/usr/plugins/platforms/$plugin" ]; then
        wayland_platform_deployed=true
        break
    fi
done
[ "$wayland_platform_deployed" = true ] || {
    echo "linuxdeploy did not bundle a Qt Wayland platform plugin" >&2
    exit 1
}
for plugin_group in \
    wayland-decoration-client \
    wayland-graphics-integration-client \
    wayland-shell-integration; do
    find "$app_dir/usr/plugins/$plugin_group" -type f -name '*.so' -print -quit |
        grep -q . || {
            echo "linuxdeploy did not bundle Qt plugin group: $plugin_group" >&2
            exit 1
        }
done
APPIMAGE_EXTRACT_AND_RUN=1 "$output" --appimage-version >/dev/null
echo "Created $output"
