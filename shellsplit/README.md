# Shellsplit

Shellsplit analyzes shell source and classifies its syntax, commands, I/O,
and state relationships. It provides bounded parsing and retained-source views,
plus allocating tokenization, canonicalization, abstraction, and transformation.

Use the [shell model reference](../docs/shell-model.md) for supported behavior,
and the [security model](../SECURITY.md) for execution assumptions and application
responsibilities.

## Choose an interface

| Need | Public interface |
|---|---|
| Bounded source ranges and feature detection | [`shell_tokenizer.h`](include/shell_tokenizer.h) |
| Lexical token iteration | [`shell_tokenizer_full.h`](include/shell_tokenizer_full.h) |
| Commands and typed redirect operations | [`shell_processor.h`](include/shell_processor.h) |
| Incomplete drafts and exact heredoc framing | [`shell_source.h`](include/shell_source.h) |
| Commands, groups, descriptors, and dependency edges | [`shell_depgraph.h`](include/shell_depgraph.h) |
| Application-provided word resolution | [`shell_expand.h`](include/shell_expand.h) |
| Canonical command collections | [`shell_sequence.h`](include/shell_sequence.h) |
| Abstraction and readable transformations | [`shell_abstract.h`](include/shell_abstract.h), [`shell_transform.h`](include/shell_transform.h) |

Applications access these APIs directly. Result spans borrow immutable source
for their documented lifetime; allocating products have explicit release
functions. Required pointer and storage constraints are documented preconditions.

## Build and run

From the repository root, a library-only build uses:

```sh
cmake -S . -B build -DBUILD_TESTING=OFF -DSHELLCLAVE_BUILD_TOOLS=OFF
cmake --build build --parallel 2
```

See [Contributing](../CONTRIBUTING.md) for pinned-Bash conformance tests, fuzzing,
sanitizers, and coverage.

## Bounded parsing

```c
#include <shell_tokenizer.h>
#include <string.h>

const char command[] = "cat file.txt | grep pattern";
shell_parse_result_t parsed;
shell_limits_t limits = SHELL_LIMITS_DEFAULT;
limits.strict_mode = true;
shell_error_t error =
    shell_parse_fast(command, strlen(command), &limits, &parsed);
/* Check error before using parsed; handle truncation explicitly. */
```

The fast parser reports source ranges and lexical feature bits. Semantic
consumers apply additional supported-language checks. The
[support summary](../README.md#supported-shell-model) distinguishes supported
analysis from Shellgate's default feature mask.

## Canonical commands

`shell_build_netargv_sequence_buffer()` converts supported command source into
explicit-length canonical argv records. Programmatic consumers use these
records, while display text serves diagnostics. Empty arguments and binary
payloads keep their boundaries.

For example, `cat file.txt | grep pattern` contains two command records:
`cat`, `file.txt` and `grep`, `pattern`. Pipeline relationships belong to the
graph. See [Canonical formats](../docs/canonical-formats.md) for framing,
byte lengths, and ownership.

## Retained drafts and heredocs

`shell_parse_draft()` distinguishes COMPLETE, INCOMPLETE, INVALID, TRUNCATED,
UNSUPPORTED, and INVALID_INPUT. It retains lexical command headers, ordered
redirects, and FIFO heredoc records.
It borrows the received source and performs no heap allocation. Allocate the
fixed-capacity result outside small stacks.

A qualified prefix contains earlier complete top-level list units. Reuse it
unchanged through `shell_dep_graph_parse_with_fast()` with the exact source
prefix. Prefix qualification supports analysis of an incomplete request; the
application retains control of execution policy.

### Classifying input before dispatch

| Outcome | Application interpretation |
|---|---|
| COMPLETE | Framing and grammar are established; construct the semantic graph next |
| INCOMPLETE | Request completion or use the documented draft-recovery products |
| INVALID | A grammar error has been established; reject the entire request before dispatch |
| UNSUPPORTED | Analysis cannot establish the required judgment; the application may require explicit approval of the complete exact source |
| INVALID_INPUT | Embedded NUL prevents unchanged submission to the executor; reject the input representation |
| TRUNCATED | A resource or representation limit stopped analysis; retry within a resource budget or report the limit |

UNSUPPORTED makes no claim that Bash accepts the source. Unsupported control
constructs and high bytes in restricted code contexts use that outcome.
Ordinary words preserve literal high bytes in unquoted, escaped, and quoted
fragments, including invalid UTF-8, without normalization; source offsets and
canonical lengths count bytes. Comments admit the same literal bytes and end
at raw LF or EOF. They contribute no
semantic tokens or effects; whole-source NUL and prohibited-control/DEL checks
still apply. Syntax and builtin operand classification use fixed ASCII sets,
independent of the application's locale. Backslashes inside ordinary single
quotes are literal,
including immediately before the closing quote. Execution
uses a fixed C/POSIX or UTF-8 `LC_ALL`, made readonly by trusted startup as
specified in the [executor contract](../SECURITY.md#executor-startup).
COMPLETE establishes source grammar, not supported execution semantics. For example,
`eval 'printf ok'` still fails graph construction.

Standalone empty negation is UNSUPPORTED, including `!;` and top-level `!` at
EOF; `$(!)` is instead a syntax error. Compound-array syntax in assignment or
literal declaration-command positions is UNSUPPORTED. Misplaced forms such as
`echo a=(x)` are INVALID. Redirection operands retain their word role, including
an unquoted `!` pathname. See the reference for these lexical distinctions.
Assignment values retain their whole-word role, and a leading redirection
commits simple-command syntax: `a[0]=x a=(y)` is UNSUPPORTED, while `>out {`
is an ordinary command. Closed substitutions relying on implicit heredoc
termination are also UNSUPPORTED rather than proven syntax errors.

Use `shell_dep_graph_parse_with_fast()` with a COMPLETE result's unchanged
`prefix` and exact source span. A subsequent `SHELL_DEP_EPARSE` leaves semantic
analysis unsupported/unclassified; it is not a new syntax-error judgment.
Keep graph resource, workspace, input, and expansion errors separate. The fast
parser's `SHELL_EPARSE` is likewise coarse and cannot replace this admission
sequence. Failed source outcomes clear prefix qualification; their partial
records are not qualified analysis products.

Retain the returned status with the source product. The compiled
[source-admission example](../examples/source_admission.c) shows
the full sequence, source-sized scratch, one reused workspace, and borrowed
source lifetimes. It reports classification without executing input or granting
approval. Applications remain responsible for binding any approval to the
complete unchanged source and its execution context.

For literal heredocs, document content helpers preserve the final LF and apply
`<<-` tab removal. Expandable bodies remain templates. Draft records distinguish
raw received bytes from confirmed content and tentative delimiter lines. See
[heredoc and draft semantics](../docs/shell-model.md#heredoc-data-and-received-drafts)
and `shell_source.h` for the precise fields and recovery contract.

## Graph I/O and state facts

Graph nodes distinguish commands, groups, TIME operations, documents, endpoints,
and inherited descriptor resources. Use the graph directly for routing and state
analysis alongside policy evaluation.

CMD nodes include ordinary argv commands and literal-only arithmetic commands.
Check `cmd.kind`: arithmetic has no tokens and retains its expression span and
ZERO/NONZERO/UNKNOWN truth fact. It can select later conditional-list paths
without consuming stdin. Its explicit redirects retain setup effects. See
[arithmetic commands](../docs/shell-model.md#arithmetic-commands) for the
supported grammar, conservative proof limits and policy coverage.

For `wc -l file.txt 2>&1`, the WRITE edge whose `source_fd` is 2 targets an
inherited FD node numbered 1. In the plain command it targets FD 2. Source-order
copies preserve the selected resource: `2>&1 >out` keeps stderr on inherited
stdout, while `>out 2>&1` sends both outputs to the file.

READ/WRITE edges describe possible shell routing. FD_OPEN/FD_CLOSE retain
setup effects, including unused or replaced redirects. Path-looking argv values
have ARG relations. The [I/O reference](../docs/shell-model.md#io-resources-and-setup-effects)
explains their distinct meanings.

`cd` remains an ordinary command with incoming CWD and I/O. Its success and
failure continuations carry their own state facts. Check `cwd_known` before
reading offsets and use a FILE document's own CWD for pathname interpretation.
See [CWD and paths](../docs/shell-model.md#cwd-and-lexical-path-facts).

String conditions (`[[ word ]]`, `[[ -n word ]]`, `[[ -z word ]]`, literal and
static `*` comparisons with `=`/`==`/`!=`, and their negations) have kind
`SHELL_COMMAND_CONDITIONAL`, no argv, and retained
expression and ordered operand spans with normalized predicate metadata.
Static RHSs preserve literal quoting and active stars. Dynamic RHSs may combine
static literal text with quoted expansions, as in `"$prefix".txt`; unquoted
expansions and mixed dynamic patterns remain unsupported. Active stars use
PATTERN_MATCH/PATTERN_NOT_MATCH predicates and set glob feature metadata.
The graph exposes TRUE/FALSE/UNKNOWN predicate truth and explicit redirect
setup through `has_redirections`. Use the conditional expansion callback
purpose to supply a final string value. Redirects are
installed before nested operand substitutions; the condition body has no
stdin/stdout byte use. See [conditional semantics](../docs/shell-model.md#string-conditions).

Scalar-presence conditions (`[[ -v CONFIG ]]` and lexical negation) use the
VARIABLE_SET predicate. Static scalar names can contain quoted, escaped and
concatenated fragments. The graph uses execution-state facts, with empty
assigned values counting as set; inherited names can remain UNKNOWN. These
lookups make no expansion callback and do not read a descriptor's bytes.
The `test` and `[` builtins use the same presence facts and evaluate compound
expressions with `!`, `-a`, `-o` and parentheses. They retain ordinary argv and
policy subjects. See [variable presence](../docs/shell-model.md#scalar-variable-presence).

Filesystem predicates `-e`, `-f`, `-d`, `-L` and `-h` are supported in
conditional commands and the `test` and `[` builtins. A FILE_TEST edge
connects the command to a FILE document and identifies the possible metadata
checks. It does not claim a file-content read. Inspect the document's pathname
and CWD when authorizing the check; unresolved arguments can leave its path
or the predicate kind uncertain. See [filesystem predicates](../docs/shell-model.md#filesystem-predicates).
Other filesystem operators accepted by the `test` and `[` builtins remain
opaque and do not produce FILE_TEST edges. Unary `-a` in those builtins is an
existence alias; their grammar distinguishes it from conjunction.

## Dependency-graph workspace

The fixed per-command token capacity and default graph limit are 48. Graph
preparation also counts assignment prefixes and redirection syntax, so this
capacity is distinct from final expanded argc. Smaller graph limits remain
configurable; capacity exhaustion reports truncation. Public retained arrays
and workspace sizes depend on this capacity; rebuild consumers after updating.

Graph construction uses one temporary workspace. Allocating processor/tokenizer,
abstraction, transformation, and sequence APIs manage their own source scratch.
Allocation-free APIs accept caller scratch for delimiter normalization,
non-evicting indexed-subscript boundary records, conditional-pattern
evaluation, prepared builtin-test arguments, expression nodes and bounded
grammar projection. Obtain sufficient capacity from
`shell_source_workspace_size()` rather than estimating bytes. A public tokenizer retains facts between calls
in its supplied buffer; independent live iterators require distinct buffers.

Dependency-graph parsing uses caller-owned scratch for source analysis,
static predicate evaluation and descriptor-route resolution. Measure its fixed
prefix once, add the queried source-scratch capacity, and align one reusable
allocation. Pattern comparisons can require this tail even without heredocs.
Keep the command bytes, graph output, and workspace disjoint. Within an
application function with an existing `command` span and `command_length`:

```c
#include "shell_depgraph.h"
#include <stdlib.h>
#include <stdint.h>

size_t workspace_size = 0;
size_t alignment = shell_dep_workspace_alignment();
shell_dep_workspace_size(NULL, &workspace_size);
size_t source_scratch_size;
if (!shell_source_workspace_size(command_length, &source_scratch_size) ||
    source_scratch_size > SIZE_MAX - workspace_size)
  return 1;
workspace_size += source_scratch_size;
size_t padding = (alignment - workspace_size % alignment) % alignment;
if (padding > SIZE_MAX - workspace_size)
  return 1;
workspace_size += padding;
void *workspace = aligned_alloc(alignment, workspace_size);
if (!workspace)
  return 1;

shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
limits.workspace = workspace;
limits.workspace_size = workspace_size;
shell_dep_graph_t graph;
shell_dep_error_t error = shell_dep_graph_parse(command, command_length, ".",
                                               &limits, &graph);
free(workspace);
if (error != SHELL_DEP_OK)
  return 1;
```

`aligned_alloc()` requires an allocation size that is a multiple of the
alignment; the example rounds up after adding source scratch. Applications
with a different allocator can over-allocate and align manually. An absent,
misaligned, or undersized workspace returns `SHELL_DEP_EWORKSPACE`. Use
`shell_source_workspace_size()` to cover delimiter normalization, persistent
subscript facts, conditional-pattern storage, compiled builtin-test arguments
and expressions, and bounded ambiguous-grammar projection in the same tail.
Command bytes, configuration, workspace, and graph output must obey the
non-overlap requirements documented by the API.

## API migration

See [migration notes](../docs/migration.md) when updating an existing consumer.
