#!/bin/sh

set -eu

REPOSITORY=${WHODIS_REPOSITORY:-Alex9001/whodis}
RELEASE_VERSION=${WHODIS_VERSION:-latest}
INSTALL_DIR=${BINDIR:-/usr/local/bin}
BASE_URL=${WHODIS_BASE_URL:-}

usage() {
    cat <<'EOF'
Install whodis from a GitHub release.

Usage: install.sh [options]

Options:
  --version VERSION   Release tag to install (default: latest)
  --bin-dir DIRECTORY Installation directory (default: /usr/local/bin)
  --base-url URL      Download from URL instead of GitHub Releases
  --repository OWNER/REPO
                      GitHub repository (default: Alex9001/whodis)
  -h, --help          Show this help

The same settings can be supplied through WHODIS_VERSION, BINDIR,
WHODIS_BASE_URL, and WHODIS_REPOSITORY.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { echo "whodis installer: --version requires a value" >&2; exit 2; }
            RELEASE_VERSION=$2
            shift 2
            ;;
        --bin-dir)
            [ "$#" -ge 2 ] || { echo "whodis installer: --bin-dir requires a value" >&2; exit 2; }
            INSTALL_DIR=$2
            shift 2
            ;;
        --base-url)
            [ "$#" -ge 2 ] || { echo "whodis installer: --base-url requires a value" >&2; exit 2; }
            BASE_URL=$2
            shift 2
            ;;
        --repository)
            [ "$#" -ge 2 ] || { echo "whodis installer: --repository requires a value" >&2; exit 2; }
            REPOSITORY=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "whodis installer: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[ -n "$INSTALL_DIR" ] || { echo "whodis installer: installation directory cannot be empty" >&2; exit 2; }

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "whodis installer: required command not found: $1" >&2
        exit 1
    }
}

require_command curl
require_command tar
require_command install
require_command awk

case "${WHODIS_OS:-$(uname -s)}" in
    Linux|linux) os=linux ;;
    Darwin|darwin) os=darwin ;;
    *)
        echo "whodis installer: unsupported operating system: ${WHODIS_OS:-$(uname -s)}" >&2
        exit 1
        ;;
esac

case "${WHODIS_ARCH:-$(uname -m)}" in
    x86_64|amd64|AMD64) arch=amd64 ;;
    arm64|aarch64|ARM64) arch=arm64 ;;
    *)
        echo "whodis installer: unsupported architecture: ${WHODIS_ARCH:-$(uname -m)}" >&2
        exit 1
        ;;
esac

asset="whodis_${os}_${arch}.tar.gz"

if [ -z "$BASE_URL" ]; then
    if [ "$RELEASE_VERSION" = latest ]; then
        BASE_URL="https://github.com/${REPOSITORY}/releases/latest/download"
    else
        case "$RELEASE_VERSION" in
            v*) release_tag=$RELEASE_VERSION ;;
            *) release_tag="v${RELEASE_VERSION}" ;;
        esac
        BASE_URL="https://github.com/${REPOSITORY}/releases/download/${release_tag}"
    fi
fi
BASE_URL=${BASE_URL%/}

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/whodis-install.XXXXXX")
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

download() {
    url=$1
    output=$2

    case "$url" in
        https://*)
            curl --fail --location --silent --show-error \
                --retry 3 --retry-delay 1 --proto '=https' --tlsv1.2 \
                --output "$output" "$url"
            ;;
        *)
            # Non-HTTPS URLs are accepted only through an explicit base URL.
            curl --fail --location --silent --show-error \
                --retry 3 --retry-delay 1 --output "$output" "$url"
            ;;
    esac
}

echo "Downloading whodis for ${os}/${arch}..."
download "${BASE_URL}/checksums.txt" "$tmp_dir/checksums.txt"
download "${BASE_URL}/${asset}" "$tmp_dir/$asset"

expected_checksum=$(awk -v name="$asset" '
    {
        file = $2
        sub(/^\*/, "", file)
        if (file == name) {
            print $1
            exit
        }
    }
' "$tmp_dir/checksums.txt")

case "$expected_checksum" in
    ''|*[!0-9A-Fa-f]*)
        echo "whodis installer: no valid checksum found for ${asset}" >&2
        exit 1
        ;;
esac

if [ "${#expected_checksum}" -ne 64 ]; then
    echo "whodis installer: invalid SHA-256 checksum for ${asset}" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual_checksum=$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')
else
    echo "whodis installer: sha256sum or shasum is required to verify the download" >&2
    exit 1
fi

expected_checksum=$(printf '%s' "$expected_checksum" | tr 'A-F' 'a-f')
actual_checksum=$(printf '%s' "$actual_checksum" | tr 'A-F' 'a-f')
if [ "$actual_checksum" != "$expected_checksum" ]; then
    echo "whodis installer: checksum verification failed for ${asset}" >&2
    exit 1
fi

extract_dir="$tmp_dir/extract"
mkdir "$extract_dir"
tar -xzf "$tmp_dir/$asset" -C "$extract_dir"

if [ ! -f "$extract_dir/whodis" ]; then
    echo "whodis installer: release archive does not contain whodis" >&2
    exit 1
fi

if install -d "$INSTALL_DIR" 2>/dev/null && [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "$extract_dir/whodis" "$INSTALL_DIR/whodis"
else
    require_command sudo
    echo "Installing to ${INSTALL_DIR} requires administrator privileges."
    sudo install -d "$INSTALL_DIR"
    sudo install -m 0755 "$extract_dir/whodis" "$INSTALL_DIR/whodis"
fi

echo "Installed whodis to ${INSTALL_DIR}/whodis"
case ":${PATH:-}:" in
    *:"$INSTALL_DIR":*) ;;
    *) echo "Add ${INSTALL_DIR} to PATH before running whodis." ;;
esac
