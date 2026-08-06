#!/bin/bash
# Run the Shellsplit libFuzzer harness. Defaults to two workers for four hours.

set -euo pipefail

WORKERS="${1:-2}"
DURATION="${2:-14400}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${FUZZ_BUILD_DIR:-$REPO_ROOT/build-fuzz}"
LOG_DIR="$SCRIPT_DIR/logs/$(date +%Y%m%d_%H%M%S)"
FUZZER_BIN="$BUILD_DIR/fuzz_shellsplit"
SEED_DIR="$SCRIPT_DIR/smoke-seeds"
SESSION_ROOT="$BUILD_DIR/fuzz-session-shellsplit"

mkdir -p "$LOG_DIR" "$SCRIPT_DIR/crashes" "$SESSION_ROOT"
SESSION_DIR="$(mktemp -d "$SESSION_ROOT/XXXXXX")"
cleanup() { rm -rf "$SESSION_DIR"; }
trap cleanup EXIT INT TERM

cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DBUILD_TESTING=OFF \
  -DSHELLCLAVE_BUILD_TOOLS=OFF \
  -DSHELLCLAVE_BUILD_FUZZERS=ON
cmake --build "$BUILD_DIR" --target fuzz_shellsplit

FUZZER_ARGS=(
  "$SESSION_DIR"
  "$SEED_DIR"
  "-artifact_prefix=$SCRIPT_DIR/crashes/tokenizer_"
  "-max_len=4096"
  "-max_total_time=$DURATION"
  "-jobs=$WORKERS"
  "-workers=$WORKERS"
  "-print_final_stats=1"
  "-rss_limit_mb=4096"
)

echo "Running $FUZZER_BIN for $DURATION seconds with $WORKERS workers"
"$FUZZER_BIN" "${FUZZER_ARGS[@]}" 2>&1 | tee "$LOG_DIR/fuzzer.log"
