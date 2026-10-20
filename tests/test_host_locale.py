"""Compare byte analysis in isolated processes with different host LC_CTYPEs."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--localedef", required=True)
    parser.add_argument("--scratch", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="host-locale-", dir=args.scratch) as scratch:
        locale = "en_US.ISO8859-1"
        target = Path(scratch) / locale
        generated = subprocess.run(
            [args.localedef, "--no-archive", "-i", "en_US", "-f",
             "ISO-8859-1", str(target)], capture_output=True, timeout=30)
        if generated.returncode:
            raise RuntimeError("host-locale tests require localedef and the en_US "
                               "and ISO-8859-1 locale sources (the locales package "
                               "on Debian/Ubuntu):\n" +
                               generated.stderr.decode(errors="backslashreplace"))
        environment = dict(os.environ, LOCPATH=scratch)
        baseline = None
        for name in ("C", "C.UTF-8", locale):
            result = subprocess.run([args.probe, name], env=environment,
                                    capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError(f"{name}: probe failed ({result.returncode})\n"
                                   f"{result.stderr.decode(errors='backslashreplace')}")
            if baseline is None:
                baseline = result.stdout
            elif baseline != result.stdout:
                raise AssertionError(f"analysis changed with host LC_CTYPE={name}\n"
                                     f"C: {baseline!r}\n{name}: {result.stdout!r}")
    print("byte analysis is identical under C, UTF-8, and ISO-8859-1 host locales")


if __name__ == "__main__":
    main()
