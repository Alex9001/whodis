#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

check_go() {
  cd "$repo_root"
  echo "Checking Go cyclomatic complexity (maximum 50)..."
  if ! go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 \
    -ignore '_test\.go$' -over 50 .; then
    echo "Go cyclomatic complexity exceeds the project guardrail." >&2
    return 1
  fi

  echo "Checking Go cognitive complexity (maximum 75)..."
  if ! go run github.com/uudashr/gocognit/cmd/gocognit@v1.2.0 \
    -over 75 .; then
    echo "Go cognitive complexity exceeds the project guardrail." >&2
    return 1
  fi
}

check_cpp() {
  for command in cmake ninja clang++ clang-tidy; do
    if ! command -v "$command" >/dev/null 2>&1; then
      echo "Complexity check requires $command." >&2
      return 1
    fi
  done

  complexity_build_dir=$(mktemp -d)
  trap 'rm -rf -- "$complexity_build_dir"' EXIT HUP INT TERM
  cmake -S "$repo_root/desktop" -B "$complexity_build_dir" -G Ninja \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DBUILD_TESTING=OFF \
    -DWHODIS_VERSION=complexity

  echo "Checking C++ cognitive complexity (maximum 50)..."
  clang-tidy -p "$complexity_build_dir" \
    -checks='-*,readability-function-cognitive-complexity' \
    -warnings-as-errors='readability-function-cognitive-complexity' \
    -config='{CheckOptions: [{key: readability-function-cognitive-complexity.Threshold, value: 50}]}' \
    "$repo_root"/desktop/src/*.cpp
}

case "${1:-all}" in
  all)
    check_go
    check_cpp
    ;;
  go)
    check_go
    ;;
  cpp)
    check_cpp
    ;;
  *)
    echo "Usage: $0 [all|go|cpp]" >&2
    exit 2
    ;;
esac
