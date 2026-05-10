#!/bin/bash
# Run fuzzers in a cgroup with proactive memory protection
# This script ensures memory limits are enforced BEFORE the system OOMs

set -e

# Default memory limit: 8GB
MEMORY_LIMIT="${FUZZ_MEMORY_LIMIT:-8G}"
# High-water mark for early kill (80% of limit)
MEMORY_HIGH="${FUZZ_MEMORY_HIGH:-80%}"
CGROUP_NAME="readonlybox_fuzz_$$"

# OOM score adjustment - make fuzzer processes more likely to be killed
OOM_SCORE_ADJ=1000

# Detect cgroup version
CGROUP_VERSION=1
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    CGROUP_VERSION=2
fi

cleanup_cgroup() {
    if [ "$CGROUP_VERSION" = "2" ]; then
        if [ -d "/sys/fs/cgroup/$CGROUP_NAME" ]; then
            # Kill all processes first
            if [ -f "/sys/fs/cgroup/$CGROUP_NAME/cgroup.kill" ]; then
                echo 1 > "/sys/fs/cgroup/$CGROUP_NAME/cgroup.kill" 2>/dev/null || true
            fi
            # Move any survivors out
            for pid in $(cat "/sys/fs/cgroup/$CGROUP_NAME/cgroup.procs" 2>/dev/null || true); do
                echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
            done
            rmdir "/sys/fs/cgroup/$CGROUP_NAME" 2>/dev/null || true
        fi
    else
        # cgroup v1
        for ctrl in memory cpu; do
            if [ -d "/sys/fs/cgroup/$ctrl/$CGROUP_NAME" ]; then
                # Kill all processes
                for pid in $(cat "/sys/fs/cgroup/$ctrl/$CGROUP_NAME/tasks" 2>/dev/null || true); do
                    kill -9 "$pid" 2>/dev/null || true
                done
                rmdir "/sys/fs/cgroup/$ctrl/$CGROUP_NAME" 2>/dev/null || true
            fi
        done
    fi
}

# Cleanup on exit
trap cleanup_cgroup EXIT INT TERM

setup_cgroup_v2() {
    local limit_bytes high_bytes
    # Convert to bytes
    limit_bytes=$(numfmt --from=iec "$MEMORY_LIMIT" 2>/dev/null || echo "$MEMORY_LIMIT")

    # Calculate high watermark (80% of limit for early pressure)
    if [[ "$MEMORY_HIGH" == *% ]]; then
        local pct="${MEMORY_HIGH%\%}"
        high_bytes=$((limit_bytes * pct / 100))
    else
        high_bytes=$(numfmt --from=iec "$MEMORY_HIGH" 2>/dev/null || echo "$limit_bytes")
    fi

    # Create cgroup
    mkdir -p "/sys/fs/cgroup/$CGROUP_NAME"

    # Enable memory controller
    if [ -f /sys/fs/cgroup/cgroup.subtree_control ]; then
        echo "+memory" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || {
            echo "WARNING: Could not enable memory controller in cgroup v2"
        }
    fi

    # Set memory limits
    echo "$limit_bytes" > "/sys/fs/cgroup/$CGROUP_NAME/memory.max"
    echo "$high_bytes" > "/sys/fs/cgroup/$CGROUP_NAME/memory.high"
    echo "0" > "/sys/fs/cgroup/$CGROUP_NAME/memory.swap.max"

    # Enable OOM kill for the cgroup
    if [ -f "/sys/fs/cgroup/$CGROUP_NAME/memory.oom.group" ]; then
        echo "1" > "/sys/fs/cgroup/$CGROUP_NAME/memory.oom.group"
    fi

    echo "Created cgroup v2: $CGROUP_NAME"
    echo "  memory.max: $limit_bytes ($(numfmt --to=iec $limit_bytes))"
    echo "  memory.high: $high_bytes ($(numfmt --to=iec $high_bytes))"
}

setup_cgroup_v1() {
    local limit_bytes
    limit_bytes=$(numfmt --from=iec "$MEMORY_LIMIT" 2>/dev/null || echo "$MEMORY_LIMIT")

    # Create cgroups in relevant controllers
    for ctrl in memory cpu; do
        if [ -d "/sys/fs/cgroup/$ctrl" ]; then
            mkdir -p "/sys/fs/cgroup/$ctrl/$CGROUP_NAME"
        fi
    done

    # Set memory limits
    if [ -d "/sys/fs/cgroup/memory/$CGROUP_NAME" ]; then
        echo "$limit_bytes" > "/sys/fs/cgroup/memory/$CGROUP_NAME/memory.limit_in_bytes"
        echo "0" > "/sys/fs/cgroup/memory/$CGROUP_NAME/memory.swappiness"
        # Enable OOM killer notification
        echo "1" > "/sys/fs/cgroup/memory/$CGROUP_NAME/memory.oom_control" 2>/dev/null || true
    fi

    # Set CPU limit (prevent CPU exhaustion)
    if [ -d "/sys/fs/cgroup/cpu/$CGROUP_NAME" ]; then
        # Allow 80% of one CPU - prevents runaway CPU usage
        echo "80000" > "/sys/fs/cgroup/cpu/$CGROUP_NAME/cpu.cfs_quota_us" 2>/dev/null || true
        echo "100000" > "/sys/fs/cgroup/cpu/$CGROUP_NAME/cpu.cfs_period_us" 2>/dev/null || true
    fi

    echo "Created cgroup v1: $CGROUP_NAME"
    echo "  memory.limit_in_bytes: $limit_bytes"
}

run_in_cgroup_v2() {
    # Move current shell into cgroup
    echo $$ > "/sys/fs/cgroup/$CGROUP_NAME/cgroup.procs"
    # Set OOM score to make us more killable
    echo "$OOM_SCORE_ADJ" > /proc/self/oom_score_adj 2>/dev/null || true
    # Execute the command
    exec "$@"
}

run_in_cgroup_v1() {
    # Move current shell into cgroups
    for ctrl in memory cpu; do
        if [ -d "/sys/fs/cgroup/$ctrl/$CGROUP_NAME" ]; then
            echo $$ > "/sys/fs/cgroup/$ctrl/$CGROUP_NAME/tasks"
        fi
    done
    # Set OOM score
    echo "$OOM_SCORE_ADJ" > /proc/self/oom_score_adj 2>/dev/null || true
    # Execute the command
    exec "$@"
}

# Main
if [ $# -lt 1 ]; then
    echo "Usage: $0 <command> [args...]"
    echo ""
    echo "Environment variables:"
    echo "  FUZZ_MEMORY_LIMIT - Memory limit (default: 8G)"
    echo "  FUZZ_MEMORY_HIGH - High watermark for early pressure (default: 80%)"
    echo ""
    echo "Examples:"
    echo "  $0 ./dfa_eval_fuzzer corpus/ -max_total_time=60"
    echo "  FUZZ_MEMORY_LIMIT=4G FUZZ_MEMORY_HIGH=90% $0 make run-dfa"
    exit 1
fi

# Check if we can use cgroups (need root for cgroup creation)
if [ "$(id -u)" != "0" ]; then
    echo "WARNING: cgroups require root. Trying systemd-run fallback..."
    # systemd-run provides similar protection via systemd
    exec systemd-run \
        --scope \
        --property=MemoryMax="$MEMORY_LIMIT" \
        --property=MemorySwapMax=0 \
        --property=CPUQuota=80% \
        --user \
        "$@"
fi

# Set up cgroup
if [ "$CGROUP_VERSION" = "2" ]; then
    setup_cgroup_v2
    run_in_cgroup_v2 "$@"
else
    setup_cgroup_v1
    run_in_cgroup_v1 "$@"
fi
