#!/usr/bin/env python3
"""Bound whole fuzz processes, including startup and descendant cleanup."""

import argparse
from contextlib import contextmanager, nullcontext
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


SMOKE_TIMEOUT_SECONDS = 15 * 60
STARTUP_TIMEOUT_SECONDS = 60
TERMINATE_GRACE_SECONDS = 5


def _signal_group(process, signum):
    """Signal the session we created; its disappearance is an ordinary race."""
    try:
        os.killpg(process.pid, signum)
        return True
    except ProcessLookupError:
        return False


def _finish_group(process, grace_seconds):
    # The primary process can exit before a TERM-resistant descendant. Keep
    # supervising the owned group, not just the primary Popen's return code.
    if _signal_group(process, signal.SIGTERM):
        deadline = time.monotonic() + grace_seconds
        while True:
            process.poll()  # Reap an exited primary before checking its group.
            if not _signal_group(process, 0):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _signal_group(process, signal.SIGKILL)
                break
            time.sleep(min(0.05, remaining))
    process.wait()


@contextmanager
def cancellation_scope():
    """Defer cancellation until owned processes and temporary files are gone."""
    cancelled = [0]

    def cancel(signum, _frame):
        if not cancelled[0]:
            cancelled[0] = signum

    previous = {signum: signal.signal(signum, cancel)
                for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield cancelled
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run_group(command, *, environment, timeout_seconds,
              grace_seconds=TERMINATE_GRACE_SECONDS, cancellation=None):
    """Run a valid command in a private session, retaining inherited output.

    Called on the main thread with positive finite timeout/grace values and a
    nonempty subprocess argv sequence. An unavailable executable is a genuine
    launch failure, not an invalid caller pointer/storage case. environment is
    a subprocess environment or None to inherit it. No shell is involved.
    All outcomes clean up the owned process group and reap the primary.
    Optional cancellation is the live state yielded by cancellation_scope(),
    sharing the enclosing temporary-file lifetime.
    """
    scope = (cancellation_scope() if cancellation is None
             else nullcontext(cancellation))
    with scope as cancelled:
        result = 1
        process = None
        deadline = time.monotonic() + timeout_seconds
        try:
            try:
                if not cancelled[0]:
                    process = subprocess.Popen(command, env=environment,
                                               start_new_session=True)
            except OSError as error:
                print(f"fuzz supervisor: cannot launch {command[0]}: {error}",
                      file=sys.stderr)
            while process is not None:
                if cancelled[0]:
                    print(f"fuzz supervisor: cancelled by signal {cancelled[0]}",
                          file=sys.stderr)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    print(f"fuzz supervisor: exceeded {timeout_seconds:g}s "
                          "whole-process deadline", file=sys.stderr)
                    result = 124
                    break
                try:
                    status = process.wait(timeout=min(0.1, remaining))
                    result = status if status >= 0 else 128 - status
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process is not None:
                _finish_group(process, grace_seconds)
        return 128 + cancelled[0] if cancelled[0] else result


def fuzz_environment():
    environment = os.environ.copy()
    # Bound fake-stack retention, not use-after-return detection. The separate
    # sanitizer suite retains its ordinary leak and fake-stack settings.
    for name, options in (
            ("ASAN_OPTIONS", "detect_leaks=0:min_uar_stack_size_log=16:"
             "max_uar_stack_size_log=16"),
            ("LSAN_OPTIONS", "detect_leaks=0")):
        previous = environment.get(name, "")
        environment[name] = f"{previous}:{options}" if previous else options
    return environment


def run_smoke(fuzzer, seeds, work_root, runs, max_length, artifact_prefix, *,
              timeout_seconds=SMOKE_TIMEOUT_SECONDS,
              grace_seconds=TERMINATE_GRACE_SECONDS):
    """Run bounded smoke inputs; only the generated temporary corpus is owned."""
    with cancellation_scope() as cancelled:
        root = Path(work_root)
        root.parent.mkdir(parents=True, exist_ok=True)
        Path(artifact_prefix).parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=root.name + ".",
                                         dir=root.parent) as corpus:
            result = run_group(
                [fuzzer, f"-runs={runs}", f"-max_len={max_length}", "-timeout=10",
                 "-rss_limit_mb=1024", f"-artifact_prefix={artifact_prefix}",
                 corpus, seeds],
                environment=fuzz_environment(), timeout_seconds=timeout_seconds,
                grace_seconds=grace_seconds, cancellation=cancelled)
        return 128 + cancelled[0] if cancelled[0] else result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    smoke = modes.add_parser("smoke", help="run the selected smoke corpus")
    for name in ("fuzzer", "seeds", "work_root", "runs", "max_length",
                 "artifact_prefix"):
        smoke.add_argument(name)
    startup = modes.add_parser("startup", help="run fixed startup oracles")
    startup.add_argument("fuzzer")
    startup.add_argument("artifact_prefix")
    args = parser.parse_args()
    try:
        if args.mode == "smoke":
            return run_smoke(args.fuzzer, args.seeds, args.work_root, args.runs,
                             args.max_length, args.artifact_prefix)
        Path(args.artifact_prefix).parent.mkdir(parents=True, exist_ok=True)
        return run_group(
            [args.fuzzer, "-runs=1", "-timeout=10", "-rss_limit_mb=1024",
             f"-artifact_prefix={args.artifact_prefix}"],
            environment=fuzz_environment(),
            timeout_seconds=STARTUP_TIMEOUT_SECONDS)
    except OSError as error:
        print(f"fuzz supervisor: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
