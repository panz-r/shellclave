"""Bounded, benign references for Bash's noninteractive Readline semantics.

Only the fixed scripts below are executed. No corpus or fuzz input reaches
Bash. Each reference uses a fresh shell, /dev/null instead of user inputrc,
and a private PTY, with bounded output, elapsed time, and child cleanup.
"""

import errno
import os
import pty
import select
import signal
import subprocess
import sys
import time


ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "TERM": "xterm",
    "INPUTRC": "/dev/null",
}
PROMPT = b"READLINE_READY>"
PRELUDE = (
    "unset POSIXLY_CORRECT BASH_COMPAT BASH_XTRACEFD; "
    "readonly POSIXLY_CORRECT BASH_COMPAT BASH_XTRACEFD; "
)


def run_terminal_reference(bash, script, payload, expected):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execve(bash, [bash, "--noprofile", "--norc", "-p", "-c",
                         PRELUDE + script], ENVIRONMENT)
    status = None
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.1)
            if ready:
                try:
                    data = os.read(descriptor, 4096)
                except OSError as error:
                    # Linux PTYs report EIO after the last slave closes.
                    if error.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                output.extend(data)
                if len(output) > 65536:
                    raise AssertionError("Readline reference output limit")
                if not sent and PROMPT in output:
                    # Readline has installed its terminal mode before printing
                    # the prompt. Do not race setup with a timed sleep.
                    offset = 0
                    while offset < len(payload):
                        offset += os.write(descriptor, payload[offset:])
                    sent = True
        else:
            raise AssertionError(f"Readline reference timed out: {bytes(output)!r}")
        while time.monotonic() < deadline:
            finished, status_value = os.waitpid(pid, os.WNOHANG)
            if finished:
                status = status_value
                break
            time.sleep(0.01)
        if status is None:
            raise AssertionError("Readline shell did not exit")
        if not sent or os.waitstatus_to_exitcode(status) != 0:
            raise AssertionError(f"Readline shell failed: {bytes(output)!r}")
        for marker in expected:
            if marker not in output:
                raise AssertionError(f"Missing {marker!r}: {bytes(output)!r}")
    finally:
        os.close(descriptor)
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def main():
    bash = sys.argv[1]
    readline = subprocess.run(
        [bash, "--noprofile", "--norc", "-p", "-c", "bind -l"],
        env=ENVIRONMENT, capture_output=True, timeout=5, check=False,
    )
    if readline.returncode != 0:
        print("Skipping Bash built without Readline")
        return 77
    help_read = subprocess.run(
        [bash, "--noprofile", "--norc", "-p", "-c", "help read"],
        env=ENVIRONMENT, capture_output=True, timeout=5, check=True,
    ).stdout
    modes = ["-e"]
    if b"-E" in help_read:
        modes.append("-E")
    for mode in modes:
        script = (f"read {mode} -r -p 'READLINE_READY>' value; "
                  "printf '\\nREAD_VALUE:%s\\n' \"$value\"")
        run_terminal_reference(
            bash, script, b"$(printf expanded)\x1b\x05\n",
            [b"READ_VALUE:expanded"],
        )
        script = ("exec {fd}>/dev/null; "
                  f"read {mode} -r -p 'READLINE_READY>' value; "
                  "printf '\\nREAD_VALUE:%s FD:%s\\n' \"$value\" \"$fd\"; "
                  "printf ROUTE_MARKER >&$fd")
        run_terminal_reference(
            bash, script, b"$((fd=2))\x1b\x05\n",
            [b"READ_VALUE:2 FD:2", b"ROUTE_MARKER"],
        )
    run_terminal_reference(
        bash,
        "exec {fd}>/dev/null; "
        "bind -x '\"\\C-x\":fd=2; printf BIND_MARKER'; "
        "read -e -r -p 'READLINE_READY>' value; "
        "printf '\\nREAD_VALUE:%s FD:%s\\n' \"$value\" \"$fd\"; "
        "printf ROUTE_MARKER >&$fd",
        b"\x18literal\n",
        [b"BIND_MARKER", b"READ_VALUE:literal FD:2", b"ROUTE_MARKER"],
    )
    # Ordinary read leaves substitution-looking input as data.
    run_terminal_reference(
        bash,
        "read -r -p 'READLINE_READY>' value; "
        "printf '\\nREAD_VALUE:%s\\n' \"$value\"",
        b"$(printf expanded)\n",
        [b"READ_VALUE:$(printf expanded)"],
    )
    print("Bash noninteractive Readline references passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
