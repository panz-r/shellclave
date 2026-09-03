# Command fixtures

`coding-agent-commands.json` is a realistic, anonymous collection of shell
commands for deterministic parser, classifier, integration, and benchmark
tests.  The commands are inputs only: no test may execute them.

It was produced from a private coding-agent command export with
`shellsplit/tools/sanitize_command_fixtures.py`. The sanitizer discards all
source metadata, excludes multiline and credential-bearing commands, rejects
commands longer than 1 KiB, and maps source-specific paths onto generic
namespaces such as `/project`, `/reports`, and `/work/project`. Recognized URI,
scp-style Git remote, `user@host`, and network-endpoint spellings are normalized
to stable placeholders. Literal dotted arguments are retained when they are not
network endpoints, so filenames, package names, and quoted test data preserve
their shell structure. Keep the fixture JSON free of usernames, system-specific
network endpoints, repository names, session identifiers, credentials, and
absolute paths that identify a real system.
The sanitizer also accepts repeatable `--deny REGEX` arguments for
source-specific bare one-label hosts, usernames, hostnames, or project names
that it cannot otherwise recognize. It emits ASCII-only fixture text: the known checkmark
status marker becomes `[ok]` and any other non-ASCII character becomes `?`.
This keeps every fixture valid for Shellgate's strict source-input contract.
