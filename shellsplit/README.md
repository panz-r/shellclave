# ShellSplit

A fast shell command tokenizer that extracts clean commands for DFA validation. Supports pipeline splitting, redirection, variables, and shell features.

## Overview

ShellSplit parses shell commands and extracts individual commands for validation by the c-dfa pattern matching engine.

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

## Usage

```c
#include "shell_tokenizer.h"
#include "shell_processor.h"

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

## Integration with c-dfa

ShellSplit is designed to work with c-dfa:

1. **ShellSplit** - Tokenizes shell commands, extracts clean commands
2. **c-dfa** - Validates extracted commands against patterns

```
Shell Command → ShellSplit → Clean Commands → c-dfa Validation
```

## Documentation

See `docs/` for detailed documentation:
- `SHELL_SUPPORT_SUMMARY.md` - Feature summary
- `SHELL_SYNTAX_ANALYSIS.md` - Performance analysis
- `SUBSHELL_ANALYSIS.md` - Subshell handling

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
