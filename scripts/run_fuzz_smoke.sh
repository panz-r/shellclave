#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 6 ]; then
  echo "usage: $0 FUZZER SEEDS WORK_ROOT RUNS MAX_LEN ARTIFACT_PREFIX" >&2
  exit 2
fi

FUZZER=$1
SEEDS=$2
WORK_ROOT=$3
RUNS=$4
MAX_LEN=$5
ARTIFACT_PREFIX=$6

mkdir -p "$(dirname "$WORK_ROOT")"
mkdir -p "$(dirname "$ARTIFACT_PREFIX")"
WORK_DIR=$(mktemp -d "${WORK_ROOT}.XXXXXX")
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT INT TERM

ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=0" \
LSAN_OPTIONS="${LSAN_OPTIONS:+${LSAN_OPTIONS}:}detect_leaks=0" \
  "$FUZZER" -runs="$RUNS" -max_len="$MAX_LEN" -timeout=10 -rss_limit_mb=1024 \
  -artifact_prefix="$ARTIFACT_PREFIX" "$WORK_DIR" "$SEEDS"
