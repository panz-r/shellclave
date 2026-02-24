#!/bin/bash
# Run fuzzing session for 4 hours with full protection
# Usage: ./run_fuzzing_4h.sh

set -e

DURATION=14400  # 4 hours in seconds
MEMORY_LIMIT="${FUZZ_MEMORY_LIMIT:-8G}"

# Create log directory
LOG_DIR="logs/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo "========================================"
echo "ShellSplit Fuzzing Session"
echo "========================================"
echo "Fuzzer: tokenizer_fuzzer"
echo "Duration: 4 hours"
echo "Memory limit: $MEMORY_LIMIT"
echo "Log directory: $LOG_DIR"
echo "========================================"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "========================================"
    echo "Fuzzing session ending"
    echo "========================================"
    # Kill watchdog if running
    if [ -n "$WATCHDOG_PID" ]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    # Show summary
    if [ -f "$LOG_DIR/crashes.log" ]; then
        echo "Crashes found: $(wc -l < "$LOG_DIR/crashes.log")"
    fi
}
trap cleanup EXIT INT TERM

# Check if fuzzer exists
if [ ! -f "./tokenizer_fuzzer" ]; then
    echo "Fuzzer not found: ./tokenizer_fuzzer"
    echo "Building..."
    make
fi

# Build fuzzer command
FUZZER_ARGS=(
    "corpus/seed"
    "-artifact_prefix=crashes/tokenizer_"
    "-max_len=4096"
    "-max_total_time=$DURATION"
    "-jobs=2"
    "-workers=2"
    "-print_final_stats=1"
    "-rss_limit_mb=4096"
)

# Note: dictionary not used - libFuzzer dictionary format incompatible

echo ""
echo "Starting fuzzer: ./tokenizer_fuzzer ${FUZZER_ARGS[*]}"
echo ""

# Start the fuzzer in cgroup
./run_in_cgroup.sh "./tokenizer_fuzzer" "${FUZZER_ARGS[@]}" 2>&1 | tee "$LOG_DIR/fuzzer.log" &
FUZZER_PID=$!

# Start memory watchdog
WATCHDOG_TARGET_PID=$FUZZER_PID ./memory_watchdog.sh 2>&1 | tee "$LOG_DIR/watchdog.log" &
WATCHDOG_PID=$!

echo "Fuzzer PID: $FUZZER_PID"
echo "Watchdog PID: $WATCHDOG_PID"
echo ""
echo "To monitor progress: tail -f $LOG_DIR/fuzzer.log"
echo "To stop gracefully: kill -TERM $FUZZER_PID"
echo ""

# Wait for fuzzer to complete
wait "$FUZZER_PID"
FUZZER_EXIT=$?

echo ""
echo "Fuzzer exited with code: $FUZZER_EXIT"

# Show final stats
if [ -f "$LOG_DIR/fuzzer.log" ]; then
    echo ""
    echo "Final statistics:"
    grep -E "(Done|runs|cov|corp|units|slowest|max|rss)" "$LOG_DIR/fuzzer.log" | tail -20 || true
fi

exit $FUZZER_EXIT
