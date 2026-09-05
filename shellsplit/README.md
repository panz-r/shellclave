# ShellSplit

A fast shell command tokenizer and bounded parser for shell command lines.
It preserves source ranges, identifies shell features, and provides richer
allocating tokenization, abstraction, transformation, and dependency-graph
APIs.

## Overview

ShellSplit parses shell commands and extracts individual command stages for
callers that perform their own policy or pattern evaluation.

## Canonical command transport

Programmatic command flow uses canonical netargv and netseq values from
`shell_sequence.h`. The transform and abstract modules expose diagnostic
display text only; it is lossy and must not be reparsed or passed to Shelltype.

```
Input: "cat file.txt | grep pattern | sort | uniq"

Output:
  Command 1: "cat file.txt"
  Command 2: "grep pattern"
  Command 3: "sort"
  Command 4: "uniq"
```

## Quick Start

```bash
# From the repository root
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Features

| Feature | Syntax | Status |
|---------|--------|--------|
| Variables | `$VAR`, `${VAR}`, `$1`, `$?` | ✅ |
| Globbing | `*.txt`, `file?.log`, `[abc]` | ✅ |
| Pipelines | `cmd1 \| cmd2 \| cmd3` | ✅ |
| Redirection | `> file`, `< input`, `>> append` | ✅ |
| Command Substitution | `$(cmd)`, `` `cmd` `` | ✅ |
| Arithmetic Expansion | `$((expr))` | ✅ |
| Process Substitution | `<(cmd)`, `>(cmd)` | ✅ |
| Here Documents | `<<EOF`, `<<-EOF` | ✅ |
| Here Strings | `<<< word` | ✅ |
| Composition | `;`, `&&`, `||`, and pipelines | ✅ |
| Comments | `# comment` through the end of a line | ✅ |
| Background execution | `cmd & next` | ✅ |
| Parenthesized groups | `(cmd1; cmd2)` with nesting metadata | ✅ |
| Pipeline negation | `! pipeline` | ✅ |
| POSIX brace groups | `{ list; }`, including group redirections | ✅ |
| Bash extensions | `&>`, `&>>`, `$'...'`, extglob, named-FD open redirects | ✅ |
| Control Features | loops, conditionals, and `case` | detected, rejected as unsupported |

The fast parser is zero-copy and bounded rather than a complete POSIX shell
grammar. It reports parse errors and output truncation through return codes;
callers must handle those results explicitly.

Control keyword feature bits are lexical indicators only. Canonical sequence
and dependency-graph APIs reject loops, conditionals, and `case` statements as
unsupported rather than flattening bodies into unconditional execution. The
dependency graph represents simple commands, sequencing, pipelines (including
their `!` negation modifier), parenthesized and brace groups, background execution, executable
substitutions, and Bash combined redirects plus named-FD open forms
(`{fd}<file`, `{fd}>file`, `{fd}>>file`, and `{fd}<>file`). Named-FD
duplication and close forms, such as `{fd}>&1` and `{fd}>&-`, remain explicitly
unsupported. Heredoc bodies remain data. CWD metadata is propagated only through sequential lists; pipeline,
background, group, and substitution execution do not mutate the surrounding
CWD.

Extglob is recognized as Bash syntax, but a fresh Bash executor must enable
`extglob` before parsing the command (for example, `bash -O extglob`).

## Usage

```c
#include "shell_tokenizer_full.h"
#include <stdio.h>
#include <string.h>

const char input[] = "cat file | grep pattern";

// Tokenize a shell command
shell_command_t* commands;
size_t command_count;

if (shell_tokenize_commands(input, strlen(input), &commands, &command_count) ==
    SHELL_TOKENIZE_OK) {
    for (size_t i = 0; i < command_count; i++) {
        printf("Command %zu: %.*s\n", i + 1,
               (int)(commands[i].end_pos - commands[i].start_pos),
               input + commands[i].start_pos);
    }
    shell_commands_free(commands, command_count);
}
```

## File Structure

```
shellsplit/
├── include/           # Installed Shellsplit API
├── src/               # Production library implementation
├── tests/
│   └── generator/     # Test-only AST and deterministic instance generator
├── tools/             # Demonstration and command-line programs
├── fuzz/              # libFuzzer harness and local run helpers
└── docs/              # Design and syntax documentation
```
