#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <version> <checksums.txt> <output-directory>" >&2
  exit 2
fi

version=${1#v}
checksums=$2
output=$3

if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "render-community-packages: version must be a stable semantic version" >&2
  exit 2
fi
if [ ! -f "$checksums" ]; then
  echo "checksums file not found: $checksums" >&2
  exit 1
fi

asset_hash() {
  value=$(awk -v asset="$1" '$2 == asset { print $1; exit }' "$checksums")
  if [ -z "$value" ]; then
    echo "checksum missing for $1" >&2
    exit 1
  fi
  if ! printf '%s\n' "$value" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
    echo "invalid SHA-256 checksum for $1" >&2
    exit 1
  fi
  printf '%s' "$value"
}

darwin_amd64=$(asset_hash whodis_darwin_amd64.tar.gz)
darwin_arm64=$(asset_hash whodis_darwin_arm64.tar.gz)
linux_amd64=$(asset_hash whodis_linux_amd64.tar.gz)
linux_arm64=$(asset_hash whodis_linux_arm64.tar.gz)
windows_amd64=$(asset_hash whodis_windows_amd64.zip)
windows_arm64=$(asset_hash whodis_windows_arm64.zip)

mkdir -p "$output/homebrew" "$output/scoop" "$output/nix"

render() {
  sed \
    -e "s/@VERSION@/$version/g" \
    -e "s/@DARWIN_AMD64_SHA256@/$darwin_amd64/g" \
    -e "s/@DARWIN_ARM64_SHA256@/$darwin_arm64/g" \
    -e "s/@LINUX_AMD64_SHA256@/$linux_amd64/g" \
    -e "s/@LINUX_ARM64_SHA256@/$linux_arm64/g" \
    -e "s/@WINDOWS_AMD64_SHA256@/$windows_amd64/g" \
    -e "s/@WINDOWS_ARM64_SHA256@/$windows_arm64/g" \
    "$1" > "$2"
}

render packaging/homebrew/whodis.rb.in "$output/homebrew/whodis.rb"
render packaging/scoop/whodis.json.in "$output/scoop/whodis.json"
render packaging/nix/whodis.nix.in "$output/nix/whodis.nix"
