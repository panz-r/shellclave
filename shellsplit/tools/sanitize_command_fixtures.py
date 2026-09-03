#!/usr/bin/env python3
"""Sanitize coding-agent shell calls into an anonymous command fixture set.

The input is a JSON list whose records contain a ``command`` field.  Source
metadata is deliberately discarded: output has only transformed command text.
The program rejects multiline payloads and commands that could contain
credentials. It then normalizes recognized paths and remote endpoint spellings
to stable, generic namespaces without changing shell syntax or quoting. The
result is ASCII-only so strict Shellgate evaluation can exercise every fixture.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path


MAX_COMMAND_BYTES = 1024
FIXTURE_FORMAT = "shellclave-command-fixtures-v1"

PATH_REPLACEMENTS = (
    ("/workspace", "/project"),
    ("/outbox", "/reports/outgoing"),
    ("/inbox", "/reports/incoming"),
    ("/handoff", "/transfer"),
)

IDENTIFYING_PATHS = (
    (re.compile(r"/home/[^/\s\"'`|&;()<>]+"), "/home/user"),
    (re.compile(r"/Users/[^/\s\"'`|&;()<>]+"), "/Users/user"),
    (re.compile(r"/w/[^/\s\"'`|&;()<>]+"), "/work/project"),
)

PROJECT_REPLACEMENTS = (
    (re.compile(r"\bLinkedListIterator\b"), "DataStoreIterator"),
    (re.compile(r"\bLinkedList\b"), "DataStore"),
    (re.compile(r"\blinked_list_private\b"), "data_store_private"),
    (re.compile(r"linked_list"), "data_store"),
    (re.compile(r"\btest_linked_list\b"), "test_data_store"),
    (re.compile(r"\bliblinked_list\b"), "libdata_store"),
    (re.compile(r"ll_"), "ds_"),
    (re.compile(r"\b[A-Z][0-9]+\b"), "batch"),
)

REJECT = re.compile(
    r"(?:"
    r"api[_-]?key|authorization|bearer\b|cookie|credential|"
    r"pass(?:word|phrase)?|private[_-]?key|secret|ssh[_-]?key|"
    r"git\s+config\s+user\.|--author|"
    r"\b(?:access[_-]?)?token\b|"
    r"\b[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*"
    r"[_-](?:token|key|secret|credential|password|passphrase)\b"
    r")",
    re.IGNORECASE,
)

# Identity values are not safe fixture material even when a command only
# configures them rather than printing them. Keep this deliberately broader
# than one spelling of `git config`: Git's `-c`, `config --local`, and similar
# forms all place the identifying key in the command text.
GIT_IDENTITY_KEY = re.compile(
    r"\b(?:user|author)\.(?:name|email)\b", re.IGNORECASE
)

# A remote-shell command passed as one quoted transport operand cannot be
# rewritten safely without parsing a second shell language. Reject it instead
# of risking a partial rewrite that leaves its user name behind.
NESTED_SSH_IDENTITY = re.compile(
    r"(?:^|\s)(?:-e|--rsh)(?:\s+|=)(?:'[^']*|\"[^\"]*)"
    r"\bssh\b[^'\"]*(?:\s-l(?:\s|[^\s'\"]+)|\s-o(?:\s|[^\s'\"])*"
    r"\buser(?:=|\s))",
    re.IGNORECASE,
)

SSH_USER_OPTION = re.compile(r"(?i:user)=(?P<value>[^\s]*)\Z")

# Reject URI userinfo before rewriting a remote. This intentionally catches an
# empty password too: a fixture set should never retain credential syntax.
CREDENTIAL_URI = re.compile(
    r"\b(?:https?|ssh|git)://[^/\s@]*:[^/\s@]*@", re.IGNORECASE
)

URI_ENDPOINT = re.compile(
    r"\b(?P<scheme>https?|ssh|git)://"
    r"(?:(?:[^/\s@]+)@)?"
    r"(?P<host>\[[^\]\s]+\]|[A-Za-z0-9.-]+)"
    r"(?::[0-9]+)?"
    r"(?P<path>/[^\s\"'`|&;()<>]*)?",
    re.IGNORECASE,
)

# scp-style source-control remotes use a required user name, avoiding an
# over-broad rewrite of ordinary colon-separated shell words.
SCP_ENDPOINT = re.compile(
    r"(?<![A-Za-z0-9_.@-])(?P<user>[A-Za-z0-9_.-]+)@"
    r"(?P<host>[A-Za-z0-9.-]+):(?P<path>[^\s\"'`|&;()<>]+)"
)

USER_HOST = re.compile(
    r"\b[A-Za-z0-9_.-]+@(?:\[[^\]\s]+\]|[A-Za-z0-9.-]+)"
)

IPV4_ADDRESS = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}"
    r"(?![A-Za-z0-9_.-])"
)

# A hostname is identifying only when an ordinary shell command gives it a
# network-endpoint role.  Replacing every dotted word would corrupt useful test
# data such as filenames, package names, and deliberately literal arguments.
HOSTNAME = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
TRANSFER_ENDPOINT = re.compile(
    r"(?P<host>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?):(?P<path>.*)\Z"
)

# This deliberately selects candidates broadly, then lets ipaddress reject
# malformed colon-separated words.  Brackets are outside the match and remain
# intact when a URI or a shell argument uses the bracketed IPv6 spelling.
IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:])(?P<value>(?:[0-9A-Fa-f]{0,4}:){2,}"
    r"[0-9A-Fa-f:]*)(?![0-9A-Fa-f:])"
)

NETWORK_HOST_COMMANDS = frozenset(
    {
        "ssh",
        "sftp",
        "ping",
        "ping6",
        "traceroute",
        "traceroute6",
        "telnet",
        "nc",
        "ncat",
        "netcat",
    }
)
TRANSFER_COMMANDS = frozenset({"scp", "rsync"})

# The value is the number of operands consumed by a standalone option. This
# is intentionally conservative: unknown options are not guessed to have an
# operand, so a following endpoint is only rewritten when it is still clearly
# an endpoint position.
HOST_OPTION_ARITY = {
    "ssh": frozenset(
        {
            "-b",
            "-c",
            "-D",
            "-E",
            "-e",
            "-F",
            "-I",
            "-i",
            "-J",
            "-l",
            "-L",
            "-m",
            "-O",
            "-o",
            "-p",
            "-Q",
            "-R",
            "-S",
            "-W",
            "-w",
            "-X",
            "-x",
        }
    ),
    "sftp": frozenset(
        {"-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-R", "-S", "-s"}
    ),
    "ping": frozenset(
        {"-c", "-I", "-i", "-M", "-m", "-p", "-Q", "-s", "-S", "-t", "-T", "-W", "-w"}
    ),
    "ping6": frozenset(
        {"-c", "-I", "-i", "-M", "-m", "-p", "-Q", "-s", "-S", "-t", "-T", "-W", "-w"}
    ),
    "traceroute": frozenset(
        {"-f", "-g", "-i", "-m", "-p", "-q", "-s", "-t", "-w", "-z"}
    ),
    "traceroute6": frozenset(
        {"-f", "-g", "-i", "-m", "-p", "-q", "-s", "-t", "-w", "-z"}
    ),
    "telnet": frozenset({"-l", "-u"}),
    "nc": frozenset({"-e", "-I", "-i", "-P", "-p", "-s", "-T", "-w", "-X", "-x"}),
    "ncat": frozenset({"-e", "-i", "-l", "-p", "-s", "-w"}),
    "netcat": frozenset({"-e", "-I", "-i", "-P", "-p", "-s", "-T", "-w", "-X", "-x"}),
}
TRANSFER_OPTION_ARITY = frozenset(
    {"-e", "-T", "-S", "-P", "--rsh", "--rsync-path", "--port"}
)
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*\Z")


def _remote_suffix(path: str | None) -> str:
    return ".git" if path and path.rstrip("/").endswith(".git") else ""


def normalize_uri_endpoint(match: re.Match[str]) -> str:
    return (
        f"{match.group('scheme').lower()}://example.invalid/org/repo"
        f"{_remote_suffix(match.group('path'))}"
    )


def normalize_scp_endpoint(match: re.Match[str]) -> str:
    return f"user@example.invalid:org/repo{_remote_suffix(match.group('path'))}"


def _shell_words(command: str) -> list[tuple[int, int, str]]:
    """Return source spans for simple shell words and command separators.

    This is deliberately not a shell parser.  It preserves quotes and escapes
    well enough to identify isolated, whole-word endpoint operands; a complex
    word is retained unchanged rather than risking a partial rewrite.
    """
    words: list[tuple[int, int, str]] = []
    index = 0
    while index < len(command):
        if command[index].isspace():
            index += 1
            continue
        start = index
        if command[index] in ";|&(){}":
            if command[index : index + 2] in {"&&", "||"}:
                index += 2
            else:
                index += 1
            words.append((start, index, "separator"))
            continue
        quote = ""
        while index < len(command):
            char = command[index]
            if quote:
                if char == "\\" and quote == '"' and index + 1 < len(command):
                    index += 2
                    continue
                if char == quote:
                    quote = ""
                index += 1
                continue
            if char in "'\"":
                quote = char
                index += 1
                continue
            if char == "\\" and index + 1 < len(command):
                index += 2
                continue
            if char.isspace() or char in ";|&(){}":
                break
            index += 1
        words.append((start, index, "word"))
    return words


def _word_payload(word: str) -> tuple[str, str] | None:
    """Return an ordinary word payload and matched outer quotes, if any."""
    if not word or "\\" in word or "$" in word or "`" in word:
        return None
    if word[0] in "'\"":
        if len(word) < 2 or word[-1] != word[0] or word.count(word[0]) != 2:
            return None
        return word[1:-1], word[0]
    if "'" in word or '"' in word:
        return None
    return word, ""


def _replace_spans(command: str, replacements: list[tuple[int, int, str]]) -> str:
    for start, end, replacement in reversed(replacements):
        command = command[:start] + replacement + command[end:]
    return command


def _normalize_ipv6_literals(command: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            ipaddress.IPv6Address(match.group("value"))
        except ValueError:
            return match.group(0)
        return "2001:db8::1"

    return IPV6_CANDIDATE.sub(replace, command)


def _is_ipv4_address(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _next_operand(words: list[tuple[int, int, str]], index: int) -> int:
    """Skip one option operand only when it is an isolated shell word."""
    if index >= len(words) or words[index][2] != "word":
        return index
    return index + 1


def _replace_ssh_user_option(value: str) -> str | None:
    """Normalize an SSH config `User=` option without changing its spelling."""
    match = SSH_USER_OPTION.fullmatch(value)
    if not match:
        return None
    return value[: match.start("value")] + "user"


def _normalize_contextual_endpoints(command: str) -> str:
    """Anonymize endpoint operands without treating arbitrary dots as hosts."""
    words = _shell_words(command)
    replacements: list[tuple[int, int, str]] = []
    index = 0
    command_start = True

    while index < len(words):
        start, end, kind = words[index]
        if kind == "separator":
            command_start = True
            index += 1
            continue
        if not command_start:
            index += 1
            continue

        payload = _word_payload(command[start:end])
        if payload is None:
            command_start = False
            index += 1
            continue
        value, _ = payload
        if ASSIGNMENT.fullmatch(value):
            index += 1
            continue
        command_name = value
        command_start = False
        index += 1

        if command_name in NETWORK_HOST_COMMANDS:
            option_arity = HOST_OPTION_ARITY[command_name]
            options_ended = False
            while index < len(words) and words[index][2] == "word":
                word_start, word_end, _ = words[index]
                operand = _word_payload(command[word_start:word_end])
                if operand is None:
                    index += 1
                    continue
                value, quote = operand
                if not options_ended and value == "--":
                    options_ended = True
                    index += 1
                    continue
                # `ssh -l` takes a login name. In contrast, `sftp -l` is a
                # bandwidth limit, so only the shared `-o User=` spelling is
                # treated as an SFTP user setting below.
                if not options_ended and command_name == "ssh" and value == "-l":
                    user_index = index + 1
                    if user_index < len(words) and words[user_index][2] == "word":
                        user_start, user_end, _ = words[user_index]
                        user_operand = _word_payload(command[user_start:user_end])
                        if user_operand is not None:
                            _, user_quote = user_operand
                            replacements.append(
                                (user_start, user_end, f"{user_quote}user{user_quote}")
                            )
                    index = _next_operand(words, user_index)
                    continue
                if not options_ended and command_name == "ssh" and value.startswith("-l") and len(value) > 2:
                    replacements.append((word_start, word_end, f"{quote}-luser{quote}"))
                    index += 1
                    continue
                if not options_ended and value == "-o":
                    option_index = index + 1
                    if option_index < len(words) and words[option_index][2] == "word":
                        option_start, option_end, _ = words[option_index]
                        option_operand = _word_payload(command[option_start:option_end])
                        if option_operand is not None:
                            option_value, option_quote = option_operand
                            normalized = _replace_ssh_user_option(option_value)
                            if normalized is not None:
                                replacements.append(
                                    (
                                        option_start,
                                        option_end,
                                        f"{option_quote}{normalized}{option_quote}",
                                    )
                                )
                    index = _next_operand(words, option_index)
                    continue
                if not options_ended and value.startswith("-o"):
                    normalized = _replace_ssh_user_option(value[2:])
                    if normalized is not None:
                        replacements.append(
                            (word_start, word_end, f"{quote}-o{normalized}{quote}")
                        )
                    index += 1
                    continue
                if not options_ended and value.startswith("-"):
                    index += 1
                    if value in option_arity:
                        index = _next_operand(words, index)
                    continue
                if HOSTNAME.fullmatch(value) and not _is_ipv4_address(value):
                    replacements.append(
                        (word_start, word_end, f"{quote}example.invalid{quote}")
                    )
                break

        elif command_name in TRANSFER_COMMANDS:
            while index < len(words) and words[index][2] == "word":
                word_start, word_end, _ = words[index]
                operand = _word_payload(command[word_start:word_end])
                index += 1
                if operand is None:
                    continue
                value, quote = operand
                if value in TRANSFER_OPTION_ARITY:
                    index = _next_operand(words, index)
                    continue
                if value.startswith("-"):
                    continue
                endpoint = TRANSFER_ENDPOINT.fullmatch(value)
                if endpoint:
                    replacements.append(
                        (
                            word_start,
                            word_end,
                            f"{quote}example.invalid:{endpoint.group('path')}{quote}",
                        )
                    )

    return _replace_spans(command, replacements)


def sanitize(command: str, deny: re.Pattern[str]) -> str | None:
    """Return an anonymous one-line command, or None when it is unsafe."""
    if not command or "\n" in command or "\r" in command:
        return None
    if (
        len(command.encode("utf-8")) > MAX_COMMAND_BYTES
        or REJECT.search(command)
        or ("git" in command.lower() and GIT_IDENTITY_KEY.search(command))
        or NESTED_SSH_IDENTITY.search(command)
        or CREDENTIAL_URI.search(command)
        or deny.search(command)
    ):
        return None

    for original, replacement in PATH_REPLACEMENTS:
        command = command.replace(original, replacement)
    for pattern, replacement in IDENTIFYING_PATHS:
        command = pattern.sub(replacement, command)
    for pattern, replacement in PROJECT_REPLACEMENTS:
        command = pattern.sub(replacement, command)
    command = URI_ENDPOINT.sub(normalize_uri_endpoint, command)
    command = SCP_ENDPOINT.sub(normalize_scp_endpoint, command)
    command = USER_HOST.sub("user@example.invalid", command)
    command = IPV4_ADDRESS.sub("192.0.2.1", command)
    command = _normalize_ipv6_literals(command)
    command = _normalize_contextual_endpoints(command)
    command = command.replace("✓", "[ok]")
    command = command.encode("ascii", "replace").decode("ascii")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in command):
        return None
    if len(command.encode("ascii")) > MAX_COMMAND_BYTES:
        return None
    return command


def verify_fixture(source: object, deny: re.Pattern[str]) -> None:
    """Reject a canonical fixture that is not already anonymous and safe."""
    if not isinstance(source, dict) or source.get("format") != FIXTURE_FORMAT:
        raise SystemExit("input must be a canonical command fixture")
    commands = source.get("commands")
    if not isinstance(commands, list) or not commands:
        raise SystemExit("canonical command fixture must contain commands")

    seen: set[str] = set()
    for index, command in enumerate(commands):
        if not isinstance(command, str):
            raise SystemExit(f"fixture command {index} must be a string")
        normalized = sanitize(command, deny)
        if normalized != command:
            raise SystemExit(f"fixture command {index} is not anonymous and safe")
        if command in seen:
            raise SystemExit(f"fixture command {index} duplicates an earlier entry")
        seen.add(command)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON export containing command records")
    parser.add_argument("output", type=Path, help="anonymous fixture JSON to write")
    parser.add_argument(
        "--deny",
        action="append",
        default=[],
        metavar="REGEX",
        help="additional case-insensitive text that rejects a source command",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify an already canonical fixture without writing output",
    )
    args = parser.parse_args()

    source = json.loads(args.input.read_text(encoding="utf-8"))
    deny = re.compile("|".join(args.deny) or r"(?!)", re.IGNORECASE)
    if args.verify:
        verify_fixture(source, deny)
        return
    if not isinstance(source, list):
        raise SystemExit("input must be a JSON list")

    commands: list[str] = []
    seen: set[str] = set()
    for record in source:
        if not isinstance(record, dict) or not isinstance(record.get("command"), str):
            continue
        command = sanitize(record["command"], deny)
        if command is not None and command not in seen:
            commands.append(command)
            seen.add(command)

    result = {
        "format": FIXTURE_FORMAT,
        "description": (
            "Anonymous, sanitized one-line shell commands for deterministic "
            "parser, classifier, integration, and benchmark fixtures. "
            "They are test data only and must never be executed by a test."
        ),
        "commands": commands,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
