#!/bin/bash
# Memory watchdog - proactively kills fuzzer if memory pressure is too high
# This runs in parallel with fuzzing to provide faster OOM protection than kernel OOM killer

INTERVAL="${WATCHDOG_INTERVAL:-1}"  # Check every N seconds
MEMORY_THRESHOLD="${WATCHDOG_THRESHOLD:-95}"  # Kill at % of cgroup limit
TARGET_PID="${WATCHDOG_TARGET_PID:-}"

if [ -z "$TARGET_PID" ]; then
    echo "Usage: WATCHDOG_TARGET_PID=<pid> $0"
    echo ""
    echo "Environment:"
    echo "  WATCHDOG_TARGET_PID - PID to monitor and kill if needed"
    echo "  WATCHDOG_INTERVAL - Check interval in seconds (default: 1)"
    echo "  WATCHDOG_THRESHOLD - Memory % threshold to kill at (default: 95)"
    exit 1
fi

# Get cgroup memory usage for a PID
get_cgroup_memory_usage() {
    local pid=$1
    local cgroup_path

    # Get cgroup v2 path
    cgroup_path=$(cat /proc/$pid/cgroup 2>/dev/null | grep '^0::' | cut -d: -f3)
    if [ -n "$cgroup_path" ]; then
        # cgroup v2
        local mem_current="/sys/fs/cgroup$cgroup_path/memory.current"
        local mem_max="/sys/fs/cgroup$cgroup_path/memory.max"
        if [ -f "$mem_current" ] && [ -f "$mem_max" ]; then
            local current max
            current=$(cat "$mem_current" 2>/dev/null || echo 0)
            max=$(cat "$mem_max" 2>/dev/null || echo 0)
            if [ "$max" != "0" ] && [ "$max" != "max" ]; then
                echo "$((current * 100 / max))"
                return
            fi
        fi
    fi

    # Fallback: check process RSS vs system memory
    local rss kb_total
    rss=$(cat /proc/$pid/status 2>/dev/null | grep VmRSS | awk '{print $2}')
    kb_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [ -n "$rss" ] && [ -n "$kb_total" ] && [ "$kb_total" != "0" ]; then
        echo "$((rss * 100 / kb_total))"
    else
        echo "0"
    fi
}

# Find all child PIDs
get_all_children() {
    local parent=$1
    local children
    children=$(pgrep -P "$parent" 2>/dev/null || true)
    echo "$parent $children"
    for child in $children; do
        get_all_children "$child"
    done
}

# Get total RSS of process tree
get_tree_rss() {
    local total=0
    for pid in $(get_all_children "$TARGET_PID" | tr ' ' '\n' | sort -u); do
        local rss
        rss=$(cat /proc/$pid/status 2>/dev/null | grep VmRSS | awk '{print $2}' || echo 0)
        total=$((total + rss))
    done
    echo "$total"
}

echo "Memory watchdog started for PID $TARGET_PID"
echo "Threshold: ${MEMORY_THRESHOLD}%"
echo "Interval: ${INTERVAL}s"
echo ""

KILL_SIGNAL=TERM
while true; do
    sleep "$INTERVAL"

    # Check if target still exists
    if ! kill -0 "$TARGET_PID" 2>/dev/null; then
        echo "Target PID $TARGET_PID exited, watchdog stopping"
        exit 0
    fi

    # Get memory usage percentage
    mem_pct=$(get_cgroup_memory_usage "$TARGET_PID")

    if [ "$mem_pct" -ge "$MEMORY_THRESHOLD" ]; then
        echo "WARNING: Memory usage at ${mem_pct}% (threshold: ${MEMORY_THRESHOLD}%)"

        # First try graceful shutdown
        if [ "$KILL_SIGNAL" = "TERM" ]; then
            echo "Sending SIGTERM to PID $TARGET_PID"
            kill -TERM "$TARGET_PID" 2>/dev/null || true
            KILL_SIGNAL=KILL
            sleep 2
        else
            # Force kill
            echo "Sending SIGKILL to PID $TARGET_PID and children"
            for pid in $(get_all_children "$TARGET_PID" | tr ' ' '\n' | sort -u); do
                kill -9 "$pid" 2>/dev/null || true
            done
            exit 1
        fi
    fi

    # Also check if any individual child is using too much memory
    for pid in $(get_all_children "$TARGET_PID" | tr ' ' '\n' | sort -u); do
        child_rss=$(cat /proc/$pid/status 2>/dev/null | grep VmRSS | awk '{print $2}' || echo 0)
        # If any single child uses >1.5GB, it's likely hitting the 2GB limit
        if [ "$child_rss" -gt 1500000 ]; then  # 1.5GB in KB
            echo "WARNING: Child PID $pid using ${child_rss}KB RSS"
        fi
    done
done
