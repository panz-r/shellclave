#!/usr/bin/env python3
"""Process-lifetime regressions for the real smoke supervisor, without seeds."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "scripts/run_fuzz_smoke.py"
spec = importlib.util.spec_from_file_location("fuzz_supervisor", RUNNER)
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


def wait_file(path, timeout=5):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"fixture did not publish {path}")
        time.sleep(0.01)


def worker(directory, mode):
    directory = Path(directory)
    (directory / "primary.pid").write_text(str(os.getpid()))
    if mode == "signal":
        os.kill(os.getpid(), signal.SIGTERM)
    if mode in ("orphan", "resistant"):
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            (directory / "descendant.pid").write_text(str(os.getpid()))
            while True:
                signal.pause()
        wait_file(directory / "descendant.pid")
        if mode == "orphan":
            return 17
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if mode in ("hang", "resistant"):
        while True:
            signal.pause()
    return 17 if mode == "failure" else 0


def fake_fuzzer():
    directory = Path(os.environ["FUZZ_SUPERVISOR_TEST_DIR"])
    corpus = Path(sys.argv[-2])
    artifact = next(arg.split("=", 1)[1] for arg in sys.argv[1:]
                    if arg.startswith("-artifact_prefix="))
    (directory / "invocation.json").write_text(json.dumps({
        "arguments": sys.argv[1:], "corpus": str(corpus),
        "asan": os.environ.get("ASAN_OPTIONS"),
        "lsan": os.environ.get("LSAN_OPTIONS"),
    }))
    (corpus / "discovery").write_text("temporary")
    Path(artifact + "crash-fixture").write_text("preserved")
    print("fixture stdout", flush=True)
    print("fixture stderr", file=sys.stderr, flush=True)
    return worker(directory, os.environ["FUZZ_SUPERVISOR_TEST_MODE"])


def supervised_fixture(directory, mode):
    directory = Path(directory)
    os.environ["FUZZ_SUPERVISOR_TEST_DIR"] = str(directory)
    os.environ["FUZZ_SUPERVISOR_TEST_MODE"] = (
        "resistant" if mode == "cancel" else
        "orphan" if mode == "cancel-after-exit" else mode)
    os.environ["ASAN_OPTIONS"] = "symbolize=0"
    os.environ["LSAN_OPTIONS"] = "verbosity=0"
    return supervisor.run_smoke(
        str(directory / "fuzzer"), str(directory / "seeds"),
        str(directory / "work/corpus"), "1000", "8192",
        str(directory / "artifacts/fuzz_"),
        timeout_seconds=2 if mode == "resistant" else 20,
        grace_seconds=1 if mode == "cancel-after-exit" else 0.2)


class SupervisorTests(unittest.TestCase):
    build_dir = None
    probe = None

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="supervisor with spaces-", dir=self.build_dir)
        self.directory = Path(self.temporary.name)
        seeds = self.directory / "seeds"
        seeds.mkdir()
        (seeds / "selected").write_bytes(b"unchanged seed")
        # An executable fixture copy, never a chmod/edit of repository sources.
        source = Path(__file__).read_text().split("\n", 1)[1]
        fixture = self.directory / "fuzzer"
        # The fixture imports the real runner from its original repository.
        source = "\n".join(
            f"RUNNER = Path({str(RUNNER)!r})" if line.startswith("RUNNER = ")
            else line for line in source.splitlines()) + "\n"
        fixture.write_text(f"#!{sys.executable}\n" + source)
        fixture.chmod(0o700)

    def tearDown(self):
        # Safety cleanup if an assertion fails; only PIDs published by our own
        # fixture are considered. SIGKILL cannot be ignored by those workers.
        for name in ("primary.pid", "descendant.pid"):
            path = self.directory / name
            if path.exists():
                try:
                    os.kill(int(path.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.temporary.cleanup()

    def assert_no_live_workers(self):
        for name in ("primary.pid", "descendant.pid"):
            path = self.directory / name
            if not path.exists():
                continue
            pid = int(path.read_text())
            deadline = time.monotonic() + 3
            while True:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                # A killed orphan may briefly await the host reaper. It cannot
                # run, hold descriptors, or mutate the disposable corpus.
                stat = Path(f"/proc/{pid}/stat")
                try:
                    if stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                        break
                except FileNotFoundError:
                    break
                self.assertLess(time.monotonic(), deadline,
                                f"fixture worker {pid} survived cleanup")
                time.sleep(0.01)

    def run_fixture(self, mode):
        return subprocess.run(
            [sys.executable, __file__, "--supervise", str(self.directory), mode],
            capture_output=True, text=True, timeout=10)

    def check_smoke_storage(self):
        invocation = json.loads((self.directory / "invocation.json").read_text())
        self.assertFalse(Path(invocation["corpus"]).exists())
        self.assertEqual(list((self.directory / "work").iterdir()), [])
        self.assertEqual((self.directory / "seeds/selected").read_bytes(),
                         b"unchanged seed")
        self.assertEqual((self.directory / "artifacts/fuzz_crash-fixture").read_text(),
                         "preserved")
        self.assertEqual(invocation["arguments"][:4],
                         ["-runs=1000", "-max_len=8192", "-timeout=10",
                          "-rss_limit_mb=1024"])
        self.assertTrue(invocation["asan"].startswith("symbolize=0:"))
        self.assertTrue(invocation["asan"].endswith("max_uar_stack_size_log=16"))
        self.assertEqual(invocation["lsan"], "verbosity=0:detect_leaks=0")
        self.assert_no_live_workers()

    def test_success_and_diagnostic_passthrough(self):
        result = self.run_fixture("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture stdout", result.stdout)
        self.assertIn("fixture stderr", result.stderr)
        self.check_smoke_storage()

    def test_failure_passthrough(self):
        result = self.run_fixture("failure")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.check_smoke_storage()

    def test_signal_status(self):
        result = self.run_fixture("signal")
        self.assertEqual(result.returncode, 128 + signal.SIGTERM, result.stderr)
        self.check_smoke_storage()

    def test_startup_timeout_and_resistant_descendant(self):
        result = self.run_fixture("resistant")
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("whole-process deadline", result.stderr)
        self.check_smoke_storage()

    def test_descendant_after_primary_exit(self):
        result = self.run_fixture("orphan")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.check_smoke_storage()

    def test_cancellation(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                for name in ("primary.pid", "descendant.pid"):
                    (self.directory / name).unlink(missing_ok=True)
                process = subprocess.Popen(
                    [sys.executable, __file__, "--supervise",
                     str(self.directory), "cancel"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    wait_file(self.directory / "descendant.pid")
                    process.send_signal(signum)
                    _output, errors = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 128 + signum, errors)
                    self.check_smoke_storage()
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)

    def test_cancellation_during_orphan_cleanup(self):
        process = subprocess.Popen(
            [sys.executable, __file__, "--supervise",
             str(self.directory), "cancel-after-exit"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            wait_file(self.directory / "descendant.pid")
            primary = int((self.directory / "primary.pid").read_text())
            deadline = time.monotonic() + 5
            while Path(f"/proc/{primary}").exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            process.send_signal(signal.SIGTERM)
            _output, errors = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 128 + signal.SIGTERM, errors)
            self.check_smoke_storage()
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_launch_failure_cleans_temporary_corpus(self):
        result = supervisor.run_smoke(
            str(self.directory / "missing-fuzzer"), str(self.directory / "seeds"),
            str(self.directory / "work/corpus"), "1", "64",
            str(self.directory / "artifacts/fuzz_"), timeout_seconds=1)
        self.assertEqual(result, 1)
        self.assertEqual(list((self.directory / "work").iterdir()), [])
        self.assertEqual((self.directory / "seeds/selected").read_bytes(),
                         b"unchanged seed")

    def test_actual_libfuzzer_initialization_timeout(self):
        if self.probe is None:
            self.skipTest("the libFuzzer probe is built only in fuzz builds")
        environment = supervisor.fuzz_environment()
        environment["SHELLCLAVE_STARTUP_PROBE_READY"] = str(self.directory / "ready")
        result = supervisor.run_group(
            [self.probe, "-runs=1", "-timeout=10"], environment=environment,
            timeout_seconds=2, grace_seconds=0.2)
        self.assertTrue((self.directory / "ready").exists())
        self.assertEqual(result, 124)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].startswith("-runs="):
        sys.exit(fake_fuzzer())
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        sys.exit(worker(sys.argv[2], sys.argv[3]))
    if len(sys.argv) > 1 and sys.argv[1] == "--supervise":
        sys.exit(supervised_fixture(sys.argv[2], sys.argv[3]))
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-dir", required=True)
    parser.add_argument("--probe")
    args, remaining = parser.parse_known_args()
    SupervisorTests.build_dir = args.binary_dir
    Path(args.binary_dir).mkdir(parents=True, exist_ok=True)
    SupervisorTests.probe = args.probe
    unittest.main(argv=[sys.argv[0]] + remaining)
