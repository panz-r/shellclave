#!/usr/bin/env python3
"""End-to-end checks for the fixture anonymizer's public CLI contract."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("expected sanitizer and canonical fixture paths")
    sanitizer = Path(sys.argv[1])
    canonical_fixture = Path(sys.argv[2])
    records = [
        {"command": "cd /home/alice/private && ls /w/internal-project"},
        {"command": "cat /workspace/LinkedListIterator.c ✓"},
        {"command": "cd /home/alice/private && ls /w/internal-project"},
        {"command": "git clone https://alice@source.example/team/private.git"},
        {"command": "git fetch git@code.internal:team/private.git"},
        {"command": "ssh alice@builder uname -a"},
        {"command": "ssh -l alice build-worker.internal uname -a"},
        {"command": "ssh -lalice build-worker.internal uname -a"},
        {"command": "ssh -o User=alice build-worker.internal uname -a"},
        {"command": "ssh -oUser=alice build-worker.internal uname -a"},
        {"command": "sftp -o User=alice build-worker.internal"},
        {"command": "sftp -l 4096 build-worker.internal"},
        {"command": "curl https://cache.internal/releases/tool.tar.gz"},
        {"command": "ping 10.31.42.53"},
        {"command": "ssh -p 2222 build-worker.internal uname -a"},
        {"command": "ssh -- build-worker.internal uname -a"},
        {"command": "ping -c 1 2001:db8:1234::42"},
        {"command": "scp build-worker.internal:/srv/reports /tmp"},
        {"command": "rsync \"build-worker.internal:/srv/reports\" /tmp"},
        {"command": "echo build-worker.internal"},
        {"command": "git clone https://alice:opaque@source.example/team/private.git"},
        {"command": "Authorization: Bearer do-not-export"},
        {"command": "GH_TOKEN=do-not-export curl https://cache.internal"},
        {"command": "export AWS_SESSION_TOKEN=do-not-export"},
        {"command": "curl --access-token=do-not-export https://cache.internal"},
        {"command": "git -c user.name=Alice status"},
        {"command": "git config --local user.email alice@example.invalid"},
        {"command": "git config author.name Alice"},
        {"command": "rsync -e 'ssh -l alice' source /tmp"},
        {"command": "./parser_fixture_test --case comments"},
        {"command": "printf one\nprintf two"},
        {"command": "custom-sensitive command"},
        {"other": "ignored"},
    ]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "source.json"
        output = root / "fixtures.json"
        source.write_text(json.dumps(records), encoding="utf-8")
        subprocess.run(
            [sys.executable, str(sanitizer), str(source), str(output),
             "--deny", "custom-sensitive"],
            check=True,
        )
        fixture = json.loads(output.read_text(encoding="utf-8"))
        subprocess.run(
            [sys.executable, str(sanitizer), str(canonical_fixture), str(output),
             "--verify"],
            check=True,
        )
        unsafe_fixture = root / "unsafe-fixtures.json"
        unsafe_fixture.write_text(
            json.dumps(
                {
                    "format": "shellclave-command-fixtures-v1",
                    "commands": [
                        "printf safe",
                        "GH_TOKEN=do-not-export curl https://example.invalid",
                        "ssh build-worker.internal uname -a",
                    ],
                }
            ),
            encoding="utf-8",
        )
        unsafe = subprocess.run(
            [sys.executable, str(sanitizer), str(unsafe_fixture), str(output),
             "--verify"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert unsafe.returncode != 0

    assert fixture["format"] == "shellclave-command-fixtures-v1"
    assert fixture["commands"] == [
        "cd /home/user/private && ls /work/project",
        "cat /project/DataStoreIterator.c [ok]",
        "git clone https://example.invalid/org/repo.git",
        "git fetch user@example.invalid:org/repo.git",
        "ssh user@example.invalid uname -a",
        "ssh -l user example.invalid uname -a",
        "ssh -luser example.invalid uname -a",
        "ssh -o User=user example.invalid uname -a",
        "ssh -oUser=user example.invalid uname -a",
        "sftp -o User=user example.invalid",
        "sftp -l 4096 example.invalid",
        "curl https://example.invalid/org/repo",
        "ping 192.0.2.1",
        "ssh -p 2222 example.invalid uname -a",
        "ssh -- example.invalid uname -a",
        "ping -c 1 2001:db8::1",
        "scp example.invalid:/srv/reports /tmp",
        "rsync \"example.invalid:/srv/reports\" /tmp",
        "echo build-worker.internal",
        "./parser_fixture_test --case comments",
    ]
    for command in fixture["commands"]:
        assert command.isascii()
        assert "\n" not in command and "\r" not in command
        assert "alice" not in command and "builder" not in command
        assert "source.example" not in command and "10.31.42.53" not in command
        assert "2001:db8:1234::42" not in command


if __name__ == "__main__":
    main()
