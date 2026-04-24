# ShellSplit Design

## Architecture Overview

ShellSplit is a shell command tokenizer and processor that transforms raw shell commands into abstracted forms suitable for DFA matching.

### Pipeline

```
Raw Command → Fast Parser → Depgraph → Abstraction → DFA Match
```

1. **Fast Parser** (`shell_parse_fast`): Zero-copy, bounded parsing of shell commands into subcommand ranges. No malloc, fixed output buffer.

2. **Depgraph** (`shell_parse_depgraph`): Builds a command dependency graph from fast parser output. Extracts CMD nodes (commands) and DOC nodes (files, heredocs, env vars) with edges.

3. **Abstraction Engine** (`shell_abstract_command`): Transforms commands into abstracted forms ($EV_1, $AP_1, etc.) for DFA matching, while extracting elements for validation.

## Components

### Fast Parser (shell_tokenizer.h / shell_tokenizer.c)

**API:**
- `shell_parse_fast()` — Main entry point
- `shell_copy_subcommand()` — Copy subcommand to buffer
- `shell_get_subcommand()` — Get pointer to subcommand
- `shell_error_string()` — Error code to string
- `shell_get_feature_flags()` — Named bool feature extraction

**Limits:**
```c
typedef struct {
    uint32_t max_subcommands;
    uint32_t max_depth;
    bool strict_mode;
} shell_limits_t;
```

**Error codes:** SHELL_OK, SHELL_EINPUT, SHELL_ETRUNC, SHELL_EPARSE

**Feature flags:**
- SHELL_FEAT_VARS, SHELL_FEAT_GLOBS, SHELL_FEAT_SUBSHELL
- SHELL_FEAT_ARITH, SHELL_FEAT_HEREDOC, SHELL_FEAT_HERESTRING
- SHELL_FEAT_PROCESS_SUB, SHELL_FEAT_LOOPS, SHELL_FEAT_CONDITIONALS
- SHELL_FEAT_CASE, SHELL_FEAT_SUBSHELL_FILE

### Depgraph (shell_depgraph.h / shell_depgraph.c)

**API:**
- `shell_parse_depgraph()` — Build dependency graph
- `shell_dep_graph_dump()` — Debug output
- `shell_dep_validate()` — Validate graph integrity
- `shell_dep_error_string()` — Error code to string

**Limits:**
```c
typedef struct {
    uint32_t max_nodes;
    uint32_t max_edges;
    uint32_t max_tokens_per_cmd;
    uint32_t cwd_buf_size;
    bool cd_as_cmd;
} shell_dep_limits_t;
```

**Node types:** SHELL_NODE_CMD, SHELL_NODE_DOC

**Doc kinds:** SHELL_DOC_FILE, SHELL_DOC_HEREDOC, SHELL_DOC_HERESTRING, SHELL_DOC_ENVVAR

**Edge types:** SHELL_EDGE_READ, SHELL_EDGE_WRITE, SHELL_EDGE_APPEND, SHELL_EDGE_PIPE, SHELL_EDGE_ARG, SHELL_EDGE_ENV, SHELL_EDGE_SUBST, SHELL_EDGE_SEQ, SHELL_EDGE_AND, SHELL_EDGE_OR, SHELL_EDGE_CWD

**CWD handling:** cd commands resolve CWD through a deduplication buffer (fixed SHELL_DEP_CWD_BUF_SIZE bytes). The `cd_as_cmd` flag controls whether cd produces a CMD node.

### Abstraction Engine (shell_abstract.h / shell_abstract.c)

**API:**
- `shell_abstract_command()` — Full abstraction pipeline
- `shell_get_abstracted()` — Get abstracted form string
- `shell_get_elements()` — Get extracted elements
- `shell_expand_element()` — Runtime expansion with context

**Abstract types:**
- ABSTRACT_EV — Environment variable ($FOO)
- ABSTRACT_PV — Positional variable ($1)
- ABSTRACT_SV — Special variable ($?)
- ABSTRACT_AP — Absolute path (/etc)
- ABSTRACT_RP — Relative path (./foo)
- ABSTRACT_HP — Home path (~/file)
- ABSTRACT_GB — Glob (*.txt)
- ABSTRACT_CS — Command substitution ($(cmd))
- ABSTRACT_AR — Arithmetic ($((x+1)))
- ABSTRACT_STR — String literal
- ABSTRACT_REDIR — Redirect target

**Tilde expansion:** ABSTRACT_HP elements are expanded using $HOME. Note: `~user` expansion not supported.

## Strict Mode

When `strict_mode=true` in `shell_limits_t`, the fast parser rejects:
- Unterminated single or double quotes
- (Unclosed parentheses allowed — shell is lenient)

## Heredoc <<- Support

The depgraph handles `<<-` heredocs with tab stripping. The `prescan_heredocs()` function detects `<<-` markers and sets the `strip_tabs` flag. During content scanning, leading tabs are stripped from each line.

## $(<file) Support

`$(<file)` is a command substitution that reads stdin from a file. Detected in `detect_features()` by finding `<` at depth 1 inside `$(`. Sets both `SHELL_FEAT_SUBSHELL_FILE` and `SHELL_FEAT_SUBSHELL`.

## Fuzzer

LibFuzzer harness at `fuzz/tokenizer_fuzzer.cpp` tests all parsers:
- Fast parser
- Full parser
- Transformer
- Processor
- DFA extraction

Build with:
```bash
make fuzz CC=clang CXX=clang++
```

Run:
```bash
./fuzz/tokenizer_fuzzer -max_len=8192 -verbosity=1
```

## Build System

Plain Makefile — no CMake or autotools.

```bash
make          # Build all targets
make test     # Run all tests
make clean    # Remove artifacts
make coverage # Build with coverage
```

## Error Handling

All components use error code enums with corresponding string functions:
- Fast parser: `shell_error_string()`
- Depgraph: `shell_dep_error_string()`

The string functions return static strings (never NULL).