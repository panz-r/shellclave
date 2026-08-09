# ShellSplit

A fast shell command tokenizer and bounded parser for shell command lines.
It preserves source ranges, identifies shell features, and provides richer
allocating tokenization, abstraction, transformation, and dependency-graph
APIs.

## Overview

ShellSplit parses shell commands and extracts individual command stages for
callers that perform their own policy or pattern evaluation.

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
| Control Features | loops, conditionals, and `case` | ✅ |

The fast parser is zero-copy and bounded rather than a complete POSIX shell
grammar. It reports parse errors and output truncation through return codes;
callers must handle those results explicitly.

## Usage

```c
#include "shell_tokenizer_full.h"
#include <stdio.h>

const char input[] = "cat file | grep pattern";

// Tokenize a shell command
shell_command_t* commands;
size_t command_count;

if (shell_tokenize_commands("cat file | grep pattern", &commands, &command_count)) {
    for (size_t i = 0; i < command_count; i++) {
        printf("Command %zu: %.*s\n", i + 1,
               (int)(commands[i].end_pos - commands[i].start_pos),
               input + commands[i].start_pos);
    }
    shell_free_commands(commands, command_count);
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
