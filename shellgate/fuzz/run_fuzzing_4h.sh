#!/bin/bash
# Run fuzzing session for 4 hours with memory protection and isolation
# Matches the pattern used by shellsplit and c-dfa fuzzing
#
# Usage: ./run_fuzzing_4h.sh [workers] [duration_seconds]
# Default: 2 workers, 4 hours

set -e

WORKERS="${1:-2}"
DURATION="${2:-14400}"
MEMORY_LIMIT="${FUZZ_MEMORY_LIMIT:-8G}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${FUZZ_BUILD_DIR:-$SCRIPT_DIR/../build_fuzz}"

LOG_DIR="$SCRIPT_DIR/logs/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo "========================================"
echo "Shellgate Fuzzing Session"
echo "========================================"
echo "Fuzzer: shellgate_fuzzer"
echo "Workers: $WORKERS"
echo "Duration: $DURATION seconds"
echo "Memory limit: $MEMORY_LIMIT"
echo "Log directory: $LOG_DIR"
echo "========================================"

# Ensure crashes directory exists (libFuzzer requires it for artifact_prefix)
mkdir -p "$SCRIPT_DIR/crashes"

cleanup() {
    echo ""
    echo "========================================"
    echo "Fuzzing session ending"
    echo "========================================"
    if [ -n "$WATCHDOG_PID" ]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    # Kill the fuzzer process tree (covers systemd-run, cgroup, and direct modes)
    if [ -n "$FUZZER_PID" ]; then
        kill -TERM -- -"$FUZZER_PID" 2>/dev/null || true
        kill -TERM "$FUZZER_PID" 2>/dev/null || true
    fi
    # Fallback: kill any remaining fuzz_shellgate processes we spawned
    pkill -TERM -f "fuzz_shellgate.*corpus" 2>/dev/null || true
    sleep 1
    # Force kill anything still alive
    pkill -KILL -f "fuzz_shellgate.*corpus" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Build fuzzer if needed (uses CMake)
FUZZER_BIN="$BUILD_DIR/fuzz_shellgate"
if [ ! -f "$FUZZER_BIN" ]; then
    echo "Fuzzer not found at $FUZZER_BIN"
    echo "Building with CMake (clang required for libFuzzer)..."
    mkdir -p "$BUILD_DIR"
    cmake -S "$SCRIPT_DIR/.." -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang
    cmake --build "$BUILD_DIR" --target fuzz_shellgate
fi

# Corpus lives in tests/corpus/ — the single source of truth, committed to git
CORPUS_DIR="$SCRIPT_DIR/../tests/corpus"

FUZZER_ARGS=(
    "$CORPUS_DIR"
    "-artifact_prefix=$SCRIPT_DIR/crashes/shellgate_"
    "-max_len=4096"
    "-max_total_time=$DURATION"
    "-jobs=$WORKERS"
    "-workers=$WORKERS"
    "-print_final_stats=1"
    "-rss_limit_mb=4096"
)

if [ -f "$SCRIPT_DIR/shell_dict.txt" ]; then
    FUZZER_ARGS+=("-dict=$SCRIPT_DIR/shell_dict.txt")
fi

echo ""
echo "Starting fuzzer: $FUZZER_BIN ${FUZZER_ARGS[*]}"
echo ""

# Detect whether the fuzzer has libFuzzer linked
# libFuzzer supports -help=1; standalone driver does not (reads stdin and hangs)
HAS_LIBFUZZER=false
timeout -s KILL 3 "$FUZZER_BIN" -help=1 > /dev/null 2>&1 && HAS_LIBFUZZER=true

if [ "$HAS_LIBFUZZER" = "false" ]; then
    echo "fuzz_shellgate was built without libFuzzer (likely gcc)."
    echo "Rebuilding with clang..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cmake -S "$SCRIPT_DIR/.." -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang 2>&1
    cmake --build "$BUILD_DIR" --target fuzz_shellgate 2>&1
    # Re-check
    FUZZER_BIN="$BUILD_DIR/fuzz_shellgate"
    timeout -s KILL 3 "$FUZZER_BIN" -help=1 > /dev/null 2>&1 && HAS_LIBFUZZER=true
fi

if [ "$HAS_LIBFUZZER" = "false" ]; then
    echo "ERROR: libFuzzer still not available after clang rebuild."
    echo "Install clang with libFuzzer support."
    exit 1
fi

# Run with cgroup isolation if available, otherwise directly
# Wrap with timeout as safety net (libFuzzer should respect -max_total_time)
if [ -f "$SCRIPT_DIR/run_in_cgroup.sh" ] && [ "$(id -u)" = "0" ]; then
    timeout "$DURATION" "$SCRIPT_DIR/run_in_cgroup.sh" "$FUZZER_BIN" "${FUZZER_ARGS[@]}" > "$LOG_DIR/fuzzer.log" 2>&1 &
else
    timeout "$((DURATION + 60))" "$FUZZER_BIN" "${FUZZER_ARGS[@]}" > "$LOG_DIR/fuzzer.log" 2>&1 &
fi
FUZZER_PID=$!

# Start memory watchdog if available
if [ -f "$SCRIPT_DIR/memory_watchdog.sh" ]; then
    WATCHDOG_TARGET_PID=$FUZZER_PID "$SCRIPT_DIR/memory_watchdog.sh" 2>&1 | tee "$LOG_DIR/watchdog.log" &
    WATCHDOG_PID=$!
    echo "Watchdog PID: $WATCHDOG_PID"
fi

echo "Fuzzer PID: $FUZZER_PID"
echo ""
echo "Monitor: tail -f $LOG_DIR/fuzzer.log"
echo "Stop gracefully: kill -TERM $FUZZER_PID"
echo ""

wait "$FUZZER_PID"
FUZZER_EXIT=$?

echo ""
echo "Fuzzer exited with code: $FUZZER_EXIT"

if [ -f "$LOG_DIR/fuzzer.log" ]; then
    echo ""
    echo "Final statistics:"
    grep -E "(Done|runs|cov|corp|units|slowest|max|rss)" "$LOG_DIR/fuzzer.log" | tail -20 || true
fi

echo ""
echo "Crash summary:"
crash_count=$(find "$SCRIPT_DIR/crashes/" -type f 2>/dev/null | wc -l)
echo "  $crash_count crash files"

exit $FUZZER_EXIT
