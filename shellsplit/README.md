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
| Pipelines | `cmd1 \| cmd2`, `cmd1 \|& cmd2` | ✅ |
| Redirection | `> file`, `< input`, `>> append` | ✅ |
| Command Substitution | `$(cmd)`, `` `cmd` `` | ✅ |
| Arithmetic Expansion | statically pure `$((numeric-expression))` | ✅ |
| Process Substitution | `<(cmd)`, `>(cmd)` | ✅ |
| Here Documents | `<<EOF`, `<<-EOF` | ✅ |
| Here Strings | `<<< word` | ✅ |
| Composition | `;`, `&&`, `||`, and pipelines | ✅ |
| Comments | `# comment` through the end of a line | ✅ |
| Background execution | `cmd & next` | ✅ |
| Parenthesized groups | `(cmd1; cmd2)` with nesting metadata | ✅ |
| Pipeline negation | one or more leading `!` modifiers, such as `! ! pipeline` | ✅ |
| POSIX brace groups | `{ list; }`, including group redirections | ✅ |
| Bash extensions | `&>`, `&>>`, `$'...'`, extglob, named-FD redirects, documents, duplication, and close | ✅ |
| ANSI-C quotes decoding to NUL | `$'a\\0b'` in complete-command analysis | detected, rejected as unsupported |
| Current-shell metaprogramming | static `eval`, source loaders, traps, aliases, history replay, dynamic builtin loading, `mapfile`/`readarray`, `wait -p`, and directory-stack operations | detected, rejected as unsupported |
| Unmodeled Bash syntax | `[[ … ]]`, `(( … ))`, `time` pipelines, `$"…"`, arrays and associative arrays, array-element targets, and dynamic or mutating arithmetic expansions | detected, rejected as unsupported |
| Control Features | loops, conditionals, `case`, `select`, `coproc`, and functions | detected, rejected as unsupported |
| Bash `case` fall-through | `;&`, `;;&` | detected, rejected as unsupported |

The fast parser is zero-copy and bounded rather than a complete POSIX shell
grammar. It reports parse errors and output truncation through return codes;
callers must handle those results explicitly.

Control keyword feature bits are lexical indicators only. Canonical sequence
and dependency-graph APIs reject loops, conditionals, `case`, `select`,
`coproc`, function declarations, Bash `[[ … ]]` and `(( … ))` commands,
leading `time` pipelines, and Bash `;&` / `;;&` case fall-through as
unsupported rather than flattening bodies into unconditional execution or an
incorrect argv. Shell-semantic indexed and associative array assignments,
references, declarations, and element targets are likewise rejected, as are
`mapfile`/`readarray`, `wait -p`, `pushd`/`popd`, and arithmetic expansions
that contain an identifier, quote, parameter expansion, command substitution,
or mutation.
Only numeric literals, nesting, and arithmetic operators are accepted, because
Bash recursively evaluates arithmetic variable values and substitution output
as program text. Static arithmetic nesting is bounded by Shellsplit's fixed
structural capacity; deeper expressions are rejected as unsupported rather
than consuming unbounded parser stack. An ordinary argument that merely looks
bracketed remains literal argv. Bash locale
quotes (`$"…"`) are
also rejected because their output depends on the executor locale and message
catalog, which Shellsplit does not model. ANSI-C escapes in a `${...}` operand
are accepted when they leave executable substitutions representable as raw
source spans. Escapes that change a nested command's bytes, synthesize an
expansion opener, or make quote/escape state ambiguous across the ANSI-C quote
are rejected instead of producing a misleading graph. Isolated literal bytes
such as `$'\x24'` remain supported. The
dependency graph represents simple commands, sequencing, pipelines (including
their counted `!` negation modifiers and Bash `|&` stdout-and-stderr form),
parenthesized and brace groups, background execution, executable substitutions,
and Bash combined redirects plus named-FD forms
(`{fd}<file`, `{fd}>file`, `{fd}>>file`, and `{fd}<>file`). Named-FD
documents (`{fd}<<EOF` and `{fd}<<<word`) are modelled as `FD_OPEN` edges from
the document node to the command or compound-group endpoint; the descriptor
syntax never becomes argv. The closing brace must be immediately adjacent to
the redirect operator after shell lexical processing: escaped physical line
endings may bridge it, while literal spaces and tabs leave `{fd}` as argv.
Named-FD duplication and close forms, such as `{fd}>&1` and `{fd}>&-`, and
named-FD process-substitution operands such as `{fd}< <(producer)` and
`{fd}> >(consumer)`, are setup operations. Their later exact `$fd` or `${fd}`
uses materialize the concrete route without pretending the setup itself moved
bytes. Under Bash's default `varredir_close` behavior, an open named
descriptor from an ordinary simple command with a command word or a
non-isolated brace-group redirect tail persists in the current shell; a
redirect-only or assignment-only simple command, pipeline element, background
command, and subshell do not promote a new binding beyond their private
execution scope. The right-hand member of a direct `&&` continuation sees a
left-hand `exec` descriptor table and any open named-FD allocation; ordinary
simple-command and compound-group redirects are restored before that member
runs and therefore do not leak their file or document routes. Shellsplit does
not promote a conditional binding after the continuation or across `||` and
mixed joins.
Assignment-only scalar forms, including `fd=value` and
`fd+=value`, replace the descriptor variable's visible value; a leading
assignment remains temporary for the command it decorates. A command-bearing
builtin's redirects use the existing binding before that builtin mutates the
variable; assignment-only commands can change it before redirect expansion.
A non-`exec` close remains local, while `exec {fd}>&-` persists.
Commands that mutate `shopt`'s `varredir_close`, `lastpipe`, or
`expand_aliases` options, enable POSIX mode, create a Bash nameref, or declare
a readonly variable are rejected as unsupported, rather than silently assuming
the wrong descriptor lifetime, pipeline scope, lexical command meaning, or
named-descriptor assignment result. A readonly descriptor variable can make a
later `{fd}>file` allocation fail while preserving an earlier binding; the
graph deliberately rejects that stateful source instead of maintaining a
partial shell-variable attribute model. The bare non-mutating `readonly -p`
query remains supported. An enabling `shopt -s -o posix` form (including
combined option clusters) and a dynamic selector after `set -o` or mutating
`shopt` options are also rejected: either could enable POSIX mode at runtime.
Dynamic assignment targets for
`declare`, `typeset`, `local`, and `export` are likewise unsupported because
they can expand to `POSIXLY_CORRECT=...`; a static scalar name may still have
a dynamic value, including a quoted command substitution. Declaration operands
are classified after quote removal, so quoting cannot hide a
`POSIXLY_CORRECT` assignment. An ANSI-C escape that creates the assignment
delimiter itself is rejected until that operand can be represented as borrowed
name/value source spans. `printf -v` rejects the literal
`POSIXLY_CORRECT` target and dynamic targets in both separate and attached
forms (`-v "$name"`, `-v"$name"`, and `-v${name}`).
Statically recognized
`eval`, `.`, `source`, `trap`, `alias`, `unalias`, `fc`, and `enable`
invocations are likewise rejected: they can run additional current-shell
source, defer it to a handler, replay it, or alter later command lookup after
Shellsplit has analyzed the submitted text. This model requires a known
noninteractive Bash startup state. Start Bash with `POSIXLY_CORRECT` absent
(an empty value still enables POSIX mode), then make that unset variable
readonly before evaluating submitted source. The supported basis is
`bash -p -c ...`: privileged mode ignores `BASH_ENV`, `BASHOPTS`, and
`SHELLOPTS`, and
does not import environment-defined shell functions that could shadow a
modelled builtin such as `exec`. An equivalent launcher must establish those
same option, command-lookup, and frozen-POSIX-mode properties before source
validation, including no startup aliases or traps and no disabled or shadowed
modelled builtins.

Shell roles use a static quote-removed spelling, so `e'x'ec` and
`com'mand' -p e'x'ec` retain the same descriptor semantics as plain `exec`.
Words with runtime expansion are never promoted to a builtin or descriptor
variable role. Thus this static rejection does not interpret a dynamic command
word as `eval`, `source`, or another builtin; runtime command dispatch remains
explicitly deferred. An `exec` invocation without a command operand—also with scalar
assignment or standard `exec` option prefixes—persists numeric descriptors, including
`exec 3>file`, `exec 4>&3`, and `exec 3>&-`. The graph represents these as
`FD_OPEN`/`FD_CLOSE` setup
edges; a later command only receives a concrete READ, WRITE, or SUBST edge
when it uses the descriptor as an active standard stream or duplicates it onto
one. This avoids claiming that `exec` itself transferred data or that an
unrelated command uses an auxiliary descriptor. Persistent numeric state is
passed into nested command
and process substitutions with the same capture rules as their standard
streams. When a later redirect, close, or `|&`
binding supersedes an ordinary numeric file descriptor, the graph retains an
`FD_OPEN` setup edge rather than a stale byte-flow edge; a FILE document with
no remaining effective route is marked `TRANSIENT`. Transient heredoc and
here-string documents have no `FD_OPEN` edge. Setup-only append opens carry
`FD_OPEN_APPEND`.
If a named-FD process substitution redirects away its nested inherited stream,
the graph retains an internal endpoint and the named `FD_OPEN` setup rather
than inventing byte flow; a later exact descriptor use supplies the real
`SUBST` or `WRITE` edge.
For Bash's legacy `>&word` spelling on stdout, a static pathname, a known
descriptor/close target, a named-descriptor parameter, or one complete process
substitution has an unambiguous interpretation. A decoded literal byte other
than a digit or `-` makes every expansion result pathname-valued, including
`>&literal$var`, `>&literal$((count))`, and
`>&""literal$(producer)`. Bare dynamic operands which could instead produce a
descriptor or close marker remain unsupported rather than guessed. Direct
complete glob expressions are likewise not literal proof: `>&[[:digit:]]`
remains unsupported because it can expand to a descriptor number. In contrast,
an unmatched `[` is a literal pathname byte, so `>&[$name` is represented as a
dynamic filename redirect. Direct
process substitutions retain their real direction: `>& <(producer)` is a valid
combined-output redirect but has no invented producer-to-output stream route.
Heredoc bodies remain data. CWD metadata is propagated only through sequential
lists and statically recognized direct or `command`/`builtin`-wrapped `cd`.
Pipeline, background, group, substitution, and dynamically selected command
execution do not mutate the surrounding CWD model.
Plain `cd` remains a CWD-only transition by default. A `cd` with redirects or
executable substitutions has a command endpoint: its I/O and nested commands
use the incoming CWD, and subsequent commands use the tracked destination.
The same ordinary I/O path handles `export` redirects while preserving its
assignment ENVVAR documents.
ENVVAR names are borrowed source spellings; use the graph's ENVVAR-name helpers
to compare or render their quote-removed identifiers. The ENVVAR_APPEND flag
distinguishes an appended value fragment from a replacement assignment.

Each leading `!` is retained as `pipeline_negation_count`; the compatibility
boolean `pipeline_negated` is its parity (the effective exit-status inversion).
Only horizontal whitespace and escaped physical line continuations may separate
the modifier from its pipeline. A raw newline or comment after `!` is rejected
instead of being treated as a modifier of a later command.

Extglob is recognized as Bash syntax, but a fresh Bash executor must enable
`extglob` before parsing the command (for example, `bash -O extglob`).

### Dependency-graph workspace

Dependency-graph parsing remains allocation-free, but route resolution uses
caller-owned scratch storage. Measure it once, align one reusable allocation,
and keep the command bytes, graph output, and workspace disjoint:

```c
#include <stdlib.h>

size_t workspace_size = 0;
size_t alignment = shell_dep_workspace_alignment();
shell_dep_workspace_size(NULL, &workspace_size);
void *workspace = aligned_alloc(alignment, workspace_size);

shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
limits.workspace = workspace;
limits.workspace_size = workspace_size;
shell_dep_graph_t graph;
shell_dep_error_t error = shell_dep_graph_parse(command, command_length, ".",
                                                 &limits, &graph);
free(workspace);
```

`aligned_alloc()` requires an allocation size that is a multiple of the
alignment; the current measured size has that property. Applications with a
different allocator can over-allocate and align manually. An absent,
misaligned, or undersized workspace returns `SHELL_DEP_EWORKSPACE`; overlapping
command, graph, or workspace storage returns `SHELL_DEP_EINPUT`.

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
