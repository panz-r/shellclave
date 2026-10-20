# ShellSplit

A fast shell command tokenizer and bounded parser for shell command lines.
It preserves source ranges, identifies shell features, and provides richer
allocating tokenization, abstraction, transformation, and dependency-graph
APIs.

[`shell_source.h`](include/shell_source.h) also retains heredoc framing,
lexical headers and ordered redirects for received drafts. Strict graph parsing
remains strict; draft analysis exposes a separately qualified prefix, never
execution approval.

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
reference_bash=$(./scripts/prepare-reference-bash)
cmake -S . -B build -DSHELLCLAVE_BASH_EXECUTABLE="$reference_bash"
cmake --build build
ctest --test-dir build --output-on-failure
```

Conformance tests use the pinned Bash reference described in the repository's
[build instructions](../README.md#requirements-and-build). Library-only builds with
`BUILD_TESTING=OFF` do not need a Bash executable or network access.

### Full-command I/O boundaries

`cd` remains an ordinary CMD node, including its possible stdout/stderr flows,
while Shellsplit tracks its CWD transition for later commands. Its own words
and redirects use the incoming CWD. The `cd_as_cmd` limits option was removed
in 0.15.0; consumers must remove that initializer and recompile.

Dependency graphs include inherited descriptor resources as `SHELL_NODE_FD`,
with their original full-command descriptor number in `node.fd.number`.
Ordinary executable commands expose potential stdin-read and stdout/stderr-write
routes even without redirects. Explicitly modeled auxiliary descriptors retain
their corresponding directions. Setup-only and unreachable bodies do not gain
ordinary standard-stream byte uses.

Sparse standard-descriptor entries retain both available directions, including
write routes on fd 0 and read routes on fd 1 or 2. Descriptor copies preserve
capabilities; the graph does not presume the access mode of an inherited OS
descriptor. Missing entries supply only the ordinary defaults. Closed and
known read-only routes never acquire a write edge merely through duplication.

For `wc -l file.txt 2>&1`, the WRITE edge whose `source_fd` is 2 targets an FD
node numbered 1. Without `2>&1` it targets FD 2. READ edges run from an FD
resource to an execution endpoint, with its local `target_fd`; WRITE edges run
the other way, with local `source_fd`. The boundary-resource side uses
`SHELL_DEP_FD_NONE`. These represent available shell routes, not knowledge of
what the executable will actually read or write.

All nested scopes share the same inherited resources. Source-order copies,
scope restoration, and captures are resolved before publication: `2>&1 >out`
leaves stderr on inherited stdout, while `>out 2>&1` routes both to the file.

Path-looking arguments have undirected `SHELL_EDGE_ARG` relations to FILE
documents. The first surviving command word is excluded: `/bin/echo hello`
and `<() /bin/echo hello` have the same argument-file relations. Assignment
prefixes and redirects likewise do not advance argv position. Quoted empty
words do, so `'' /tmp/input` retains `/tmp/input` as an argument. An unresolved
earlier word may supply argv entries; later pathname arguments remain possible,
while unresolved substitution spellings are not guessed to be pathnames.
Ordinary argument resolutions contribute zero or more canonical netargv records
without resolving command identity. Wrapper targets keep their existing outer
argument roles; use `effective_command_token` for the separately known
executable.
An ARG relation alone does not claim that the command reads or writes the file.

Byte flow includes shell-owned expansion, redirect-setup and undo diagnostics, not just
command-body I/O. They originate at the existing CMD/GROUP endpoint on fd 2,
using the stderr destination at the failure point. A failed body can therefore
still supply captured bytes: `exec 3>&-; sh -c "$(echo 2>&1 >&3)"` retains a
SUBST relation requiring inspection, whereas reversing the two redirects
leaves the capture empty. Closed or read-only stderr has no diagnostic flow.
Possible file-open and implicit asynchronous-stdin-open failures retain their
diagnostic alternatives without asserting a filesystem failure occurred.
Known readonly assignments contribute diagnostics through pre-redirection
stderr, including executable prefixes that still run their command.
Parameter and arithmetic expansion diagnostics retain that same entry stderr
for arguments and assignment values. Redirect operands and expandable heredocs
use stderr after preceding redirects, before their own operation. For example,
`sh -c "$(exec 2>&1; x=$((1/0)))"` retains the diagnostic's SUBST flow even
though the assignment has no command body. Possible expansion errors do not
require evaluation of runtime values.
Optimized `$(<word)` reads retain possible open/read diagnostics separately
from file content. An empty or ambiguous resolved filename suppresses the
content flow while preserving stderr at the expansion point. In
`sh -c "$(exec 2>&1; x=$(<"$FILE"))"`, that diagnostic can reach the outer
`sh`, even if the application resolves `$FILE` to an empty filename. Pathname
resolution alone never establishes that the read succeeds.
ENV edges represent effective assignments, not rejected attempts. A readonly
write retains syntax and diagnostics without an ENV edge; successful neighboring
assignments remain effective. Rejected temporary prefixes skip their RHS.
Assignment-only and export forms expand that RHS before rejection and retain
those executed substitution flows.
Syntactic command words do not prove executable dispatch: unquoted expansions
and quoted list selectors can yield no argv entries. When all words can vanish,
the graph retains both dispatch alternatives, including RHS execution and an
input-unit abort only on the assignment-only path. A quoted empty scalar word,
literal fragment, or a later guaranteed argument rules out that null path.
Successful argv-less stages do not contribute default body streams to inherited
resources, captures or descriptor imports. Explicit document setup and pipeline
bindings remain visible, and genuine substitutions in assignment values and redirect
operands are retained without inventing output from the enclosing null stage.
Matching compound exposures remain owned by GROUP nodes. FD resources are not
internal pipes or substitution collectors, and sharing one does not establish
an internal producer-to-consumer transfer. Inherited numbers are provenance,
not proof that two OS descriptors refer to distinct underlying objects.

Boundary nodes and edges consume the existing public capacities. A truncated
graph is not a complete account of the command's possible routes. Timing
reports use WRITE-to-FD edges too; their compact external summary lists are
derived from the retained boundary edges.

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
| Bash pipeline timing | `time pipeline`, `time -p pipeline`, including groups and empty pipelines | ✅ |
| POSIX brace groups | `{ list; }`, including group redirections | ✅ |
| Bash extensions | `&>`, `&>>`, `$'...'`, extglob, named-FD redirects, documents, duplication, and close | ✅ |
| ANSI-C quotes decoding to NUL | `$'a\\0b'` in complete-command analysis | detected, rejected as unsupported |
| Locale-dependent ANSI-C Unicode | non-ASCII `\u` / `\U` escapes | lexically recognized, rejected by semantic APIs |
| Assigning parameter defaults | `${name=word}`, `${name:=word}` | lexically recognized, rejected by semantic APIs |
| Parameter re-evaluation | `${value@P}`, indirect `${!ref}` | lexically recognized, rejected by semantic APIs |
| Escape-sensitive backticks | active legacy bodies requiring removal of an escape layer | lexically recognized, rejected by semantic and draft APIs |
| Current-shell metaprogramming | static `eval`, `let`, source loaders, traps, aliases, history replay, dynamic builtin loading, completion/Readline configuration, Readline-enabled `read`, `mapfile`/`readarray`, `wait -p`, and directory-stack operations | detected, rejected as unsupported |
| Unmodeled Bash syntax | `[[ … ]]`, `(( … ))`, `$"…"`, arrays and associative arrays, array-element targets, and dynamic or mutating arithmetic expansions | detected, rejected as unsupported |
| Control Features | loops, conditionals, `case`, `select`, `coproc`, and functions | detected, rejected as unsupported |
| Bash `case` fall-through | `;&`, `;;&` | detected, rejected as unsupported |

Heredoc delimiter words retain balanced literal parameter, arithmetic, command,
and process-substitution fragments. These fragments are not executed; Bash's
lexical normalization and command printing determine the terminating line.
Quotes inside a fragment do not by themselves disable body expansion. See
[`shell_source.h`](include/shell_source.h) and
[`shell_depgraph.h`](include/shell_depgraph.h) for exact payloads,
unfinished-input recovery, and workspace sizing with
`shell_source_workspace_size()`.

The fast parser is zero-copy and bounded rather than a complete POSIX shell
grammar. It reports parse errors and output truncation through return codes;
callers must handle those results explicitly.

Ordinary legacy backticks remain supported. Bash removes an escape layer from
their body before parsing it: backslashes before dollar signs, backticks,
backslashes, and newlines, plus double quotes when the substitution is
double-quoted. Semantic APIs reject active bodies requiring that removal rather
than treating their raw source spelling as the nested program. This includes
escaped nested backticks and continuations even inside inner single quotes.
The draft source API also returns `INVALID` for these active forms, complete or
unfinished, with no qualified prefix. Supported unfinished backticks retain
their local child headers, redirects and heredocs with exact source offsets;
closed invalid descendants cannot be repaired by completing the outer word.
Single-quoted words and quoted heredoc bodies keep backticks literal. Escapes
whose backslash survives into the nested shell remain supported. Prefer `$(…)`
for nested substitutions; its ordinary source spans need no legacy escape layer.

Control keyword feature bits are lexical indicators only. Canonical sequence
and dependency-graph APIs reject loops, conditionals, `case`, `select`,
`coproc`, function declarations, Bash `[[ … ]]` and `(( … ))` commands, and
Bash `;&` / `;;&` case fall-through as
unsupported rather than flattening bodies into unconditional execution or an
incorrect argv. Shell-semantic indexed and associative array assignments,
references, declarations, and element targets are likewise rejected, as are
`let`, `mapfile`/`readarray`, `wait -p`, `pushd`/`popd`, and arithmetic expansions
that contain an identifier, quote, parameter expansion, command substitution,
or mutation.
Only numeric literals, nesting, and arithmetic operators are accepted, because
Bash recursively evaluates arithmetic variable values and substitution output
as program text. Substring offsets and lengths (`${value:offset:length}`) use
the same restriction and set the arithmetic feature flag; `:-` remains a
default-word operator, unlike the negative-offset spelling `: -1`.
Static arithmetic nesting is bounded by Shellsplit's fixed
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
such as `$'\x24'` remain supported.
Non-ASCII ANSI-C Unicode escapes are rejected until an execution-locale
contract is supported: Bash produces different bytes for `$'\u00e9'` in the
`C` and UTF-8 locales. ASCII Unicode escapes, octal/hex byte escapes, and
non-ASCII payload bytes remain supported by isolated-word and netstring APIs.
Netstrings continue to carry
arbitrary bytes; the restriction concerns source decoding, not the encoding.
Locale-quote recognition uses complete logical words and the same scoped
expansion traversal as command substitutions. A comment or quoted literal in a
backtick child cannot hide an outer locale quote or falsely introduce one.
Heredoc delimiters undergo quote removal only; body text retains its separate
heredoc expansion rules.

Unquoted named-FD operands such as `>&$fd` observe the current IFS. Quoting
(`>&"$fd"`) bypasses splitting. Assignment and builtin changes to IFS follow
execution outcomes and shell scope; unset or digit-free IFS restores an
unchanged decimal operand. All-decimal IFS is a known ambiguous-redirect
failure. Partial or unresolved decimal splitting is rejected when encountered
by graph construction, because an allocated descriptor's exact runtime number
cannot be guessed. Lexical and canonical command processing preserve the
source spelling; they do not evaluate its runtime I/O route.

Prompt transformations (`${value@P}`) and actual indirect dereferences
(`${!ref}`) are unsupported by semantic APIs: they can re-evaluate stored data
as shell syntax and execute substitutions absent from the submitted source's
active substitution spans. An indirect value can name an array subscript even
without an array declaration. Lexical APIs retain these forms; they do not
claim that the value is ordinary, non-evaluating parameter data. Ordinary
`$value`/`${value}`, non-evaluating transformations such as `@Q` and `@E`,
name enumeration (`${!prefix*}`, `${!prefix@}`), and inert quoted/escaped
spellings remain supported. No runtime value or shell-option state is guessed.

The Bash `test` and `[` builtins also re-evaluate array subscripts in the
variable-name operand of `-v`. Semantic APIs reject these array lookups and
unresolved lookup names/operators; quoting the operand does not make that
builtin operation non-evaluating. Static scalar `-v` queries, string/file
predicates, and literal `-v` operands remain supported. Expression roles follow
Bash's argument-count disambiguation, negation, parentheses, and `-a`/`-o`
connectors. Fixed binary comparisons support quoted scalar operands within
compound expressions. When an unknown operand could instead be negation or an
opening parenthesis, a bounded set of possible expression roles keeps later
variable lookups visible, even if the ordinary-data interpretation fails.
Unknown argument cardinality is unsupported rather than guessing whether
expanded words can select a variable lookup. No predicate is executed and no
runtime variable value is resolved during this analysis.

In assignment-only commands, each RHS expansion sees preceding committed
assignments, not its own or later assignments. Temporary prefixes of executable
commands have two distinct contexts inside a later RHS substitution: ordinary
scalar argument lookup sees earlier temporary values, while redirection
expansion and IFS splitting retain the shell binding table. For example,
`IFS= X=$(producer) command` makes quoted `$IFS` empty inside the child without
changing its splitting table. Ordered IFS checkpoints and the existing
prefix-name index share the graph evaluation workspace; RHS inspection does
not replay assignment prefixes or build a duplicate effects index.

Active parameter-assignment operators (`${name=word}` and `${name:=word}`) are
recognized lexically but rejected by semantic consumers. Their conditional
writes require parameter set/null state and scalar value/attribute semantics
that are not currently modeled. Treating them merely as possible expansion
errors would miss changes to IFS and descriptor-variable bindings. This applies
inside nested defaults, substitutions, and unquoted heredocs as well. Genuinely
literal spellings (for example, `'${IFS:=0}'`) and non-mutating parameter
defaults remain supported.

The unquoted heredoc expansion scanner shares the scoped word-expansion machinery:
outer quote bytes remain data, parameter defaults retain active expansions,
and quoted parameter patterns remain literal. Quoted heredoc delimiters disable
body expansion altogether. Graph construction and anomaly stage collection
observe the same active substitutions; literal patterns never create phantom
commands. Fast-parser feature flags include active substitutions and arithmetic
in expandable bodies, and file-command substitutions remain visible inside
double quotes, so feature rejection does not depend on their outer spelling.

Nested executable substitutions carry their real heredoc, here-string, and
pipeline feature flags to the containing range; comments and quoted syntax do
not introduce those features. Each nested substitution owns its pending heredoc
queue. Parameter operands remain opaque to enclosing command delimiters.
Bash's single fd-0 file-content shortcut is recognized consistently by features
and graphs, including explicit `0<`, leading comments, and a final semicolon.
Additional commands or redirects are not that shortcut.

Lexical delimiter boundaries are indexed in bounded private scratch for the
duration of one parsing/validation operation. Nested consumers reuse those
boundaries; the index never survives a call or changes public result layouts.
Its storage is per-thread, needs no allocation in the fast parser, and accepts
only spans of that operation's immutable root source. Reused source addresses
in later calls cannot reuse old entries.
Cached facts include structural heights, so reuse consumes the same nesting
budget as a fresh walk. Semantic classification recognizes control introducers
in its own forward command-word pass and visits nested executable bodies via
the expansion walk, rather than repeatedly classifying every descendant.
Scratch ownership follows the active lexical body and its forward cursor:
completed siblings can yield slots to the current subtree while enclosing
boundaries remain live. Declaration lookahead has its own cursor, so it does
not advance a containing word's semantic traversal. Control classification
itself is not cached; its own-list pass keeps nested bodies opaque.
Nested documents inside executable substitutions retain these same rules.
Declaration scanning keeps parameter operands opaque: literal `<<` bytes in a
`${...}` word never declare another document.

The dependency graph represents simple commands, sequencing, pipelines (including
their counted `!` negation modifiers, Bash `time` operations, and the Bash
`|&` stdout-and-stderr form),
parenthesized and brace groups, background execution, executable substitutions,
and Bash combined redirects plus named-FD forms
(`{fd}<file`, `{fd}>file`, `{fd}>>file`, and `{fd}<>file`). Named-FD
documents (`{fd}<<EOF` and `{fd}<<<word`) are modelled as `FD_OPEN` edges from
the document node to the command or compound-group endpoint; the descriptor
syntax never becomes argv. The closing brace must be immediately adjacent to
the redirect operator after shell lexical processing: escaped physical line
endings may bridge it, while literal spaces and tabs leave `{fd}` as argv.
Only backslash-LF is erased while matching the descriptor identifier or an
exact `$fd`/`${fd}` reference. CR remains a significant word byte, including
before LF, and therefore cannot form an alternate continuation spelling.
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
Commands that are themselves pipeline members or background jobs keep their
descriptor and named-variable mutations private, including inside an already
isolated group. An unset or reassignment on a returning conditional path
invalidates the proof of that named binding for subsequent unconditional uses.
An explicit reallocation in the same lexical group, or after returning to an
enclosing group, restores a proved binding; conditional rebindings that retain
the name on every path preserve their alternative routes. Reallocating an
orphaned descriptor variable only after entering a deeper compound remains
unsupported because the current bounded allocator model cannot correlate that
child allocation with every surviving physical slot without inventing route
cross-products. Repeating `unset` does not close the orphaned physical
descriptor or move its allocation scope. That state remains path-local until a
successful supported reallocation replaces it.
Assignment-only scalar forms, including `fd=value` and
`fd+=value`, replace the descriptor variable's visible value; a leading
assignment remains temporary for the command it decorates. A command-bearing
builtin's redirects use the existing binding before that builtin mutates the
variable; assignment-only commands can change it before redirect expansion.
A non-`exec` close remains local, while `exec {fd}>&-` persists.
Named variables retain descriptor numbers, not copies of the original routes.
If a named allocation reuses a temporarily closed numeric slot, ordinary-command
or compound-group cleanup restores that slot's original route; later uses of
the variable follow the restored route. Each allocation consumes its own slot,
including repeated allocations to the same variable. Duplicating a descriptor
creates an independent slot holding the route active at duplication time.
Opening a named file or document route first uses Bash's lowest free descriptor
for the resource, then chooses the retained named descriptor at or above fd 10.
Thus a temporarily closed fd 10 is available to the named allocation only when
a lower descriptor can hold the resource; runtime-dependent inherited low-FD
occupancy is represented by both possible routes. Named duplication does not
need that temporary resource descriptor.
Failed setup restores numeric changes even for `exec`, while retaining named
allocations and variable assignments completed before the failure. Inferred
backing slots describe setup state, not implicit byte transfers.
Descriptor continuation analysis distinguishes returning command statuses,
input-unit abortion, and current-shell termination. Only returning paths
contribute descriptor state to a later command. A statically known descriptor
failure preserves argument and assignment-value expansions: they precede a
simple command's redirects even when their words appear later in the source.
Earlier redirect operand expansions and setup also survive, but later redirect
operands and the command or compound body are suppressed. This includes later
parameter/arithmetic termination effects, even when no command substitution
appears in that operand. Resolving its setup checkpoint does not require
exporting descriptors to a child shell. Failed redirect setup
restores numeric redirects and closes to their entry state, including those on
descriptor-only `exec`. Completed named allocations can survive a later setup
failure, but mutations from an unexecuted compound body never do. Existence is
tracked independently from read/write capability: duplicating a live read-only
FD succeeds even when writes through it, including timing reports, are
unavailable. The same outcome transfer supplies nested substitution snapshots
and final byte-flow routing. Pipeline `!` inverts
returning statuses, including redirect failures that prevent `exit` or `exec`
from running; it preserves non-returning statuses. Assignment-only writes to
known readonly startup variables
such as `UID` abort the current input unit, including later statements in its
compound bodies. An abort becomes a returning failure at a subshell
boundary. Assignment values can expand before rejection, but that simple
command's redirect operands and setup are not reached after a readonly
assignment fails. Redirects on an enclosing group are evaluated before its
body instead. Temporary assignments before an executable retain that
executable's status behavior. Runtime-dependent outcomes keep their possible
routes. At the next top-level logical input unit, Bash can resume after readonly,
arithmetic and substring errors. Compound-internal and
continuation newlines do not establish recovery boundaries; neither do newlines
inside command/process substitutions. Required-parameter failures and explicit
shell termination remain stopped. Syntax documents for unreachable assignment
redirects may be retained, but do not carry descriptor setup or byte-flow edges.
Commands that mutate shell option state through `set` or `shopt`, create a
Bash nameref, or declare a readonly variable are rejected as unsupported,
rather than silently assuming the wrong descriptor lifetime, pipeline scope,
lexical command meaning, or named-descriptor assignment result. This includes
both named and short option spellings (`set -o xtrace`, `set -x`, and
short-only `set -r`), with options recognized before later option errors.
Queries such as bare `set -o` and operands after `set --` remain supported.
Inspection forms such as `shopt -q name` and `shopt -s` without an option name
remain supported. A readonly descriptor variable can make a
later `{fd}>file` allocation fail while preserving an earlier binding; the
graph deliberately rejects that stateful source instead of maintaining a
partial shell-variable attribute model. The bare non-mutating `readonly`,
`readonly -p`, and `readonly --` queries remain supported. An enabling
`set`/`shopt` selector with runtime expansion is also rejected because it can
select an option mutation after expansion.
Builtin option classification follows operand arity, including attached
`read` operands, clustered `set` flags, and repeated `-o` selectors. Option
operand bytes are not reinterpreted as flags. Static `read` operands and fully
quoted simple scalar parameters or command/arithmetic substitutions retain one
argv entry; operands with unresolved expansion cardinality remain unsupported.
This includes attached quoted operands such as `read -p"$prompt" value`.
Readline-enabled `read -e`/`-E` remains unsupported: terminal input can be
expanded as shell source or invoke registered code even in a fresh
noninteractive shell. Ordinary `read` does not perform that re-evaluation.
Only effective option letters select this unsupported mode; e/E bytes in
prompt, delimiter, or initial-text operands are data, not flags.
If that attached expansion is empty, Bash consumes the next argv entry instead;
both interpretations are tracked without evaluating runtime data. Every `read`
variable target and variable-mode `unset` target is checked for unsupported
array-element syntax, while ordinary literals, prompt operands, function-only
and nameref-only `unset`, and proven option-error paths retain their roles.
Named-FD analysis invalidates only assigned static `read` target names (or
`REPLY` when no target is supplied); a reached write to an unresolved target
invalidates all visible bindings.
A proven invalid option, invalid numeric operand, or missing operand does not
mutate a descriptor variable. An invalid static `read` target (including the
launcher's readonly `POSIXLY_CORRECT`) stops assignment at that target, while
earlier valid targets can still be written. Literal invalid identifier prefixes
remain invalid through scalar expansion: `read -- -p"$fd" value` fails before
input or assignment, regardless of `$fd`. Captured-empty values likewise expose
invalid suffixes such as `"$fd"-`; literals across an unknown fragment do not
establish that empty-value proof. An invalid first identifier consumes no input;
an invalid later identifier retains input and only earlier assignments. A
`-t0` poll bypasses target validation, while `-n0`/`-N0` still validate targets
and assign empty strings to the valid preceding targets. An unresolved target
retains both
its writable interpretation and a rejecting interpretation: the latter keeps
only earlier assignments, never the failing target's arbitrary-name write or
any later target's write. Its failure continuation can therefore still use a
descriptor variable named later in the target list unless an earlier unresolved
target could already have overwritten it. Explicit timeout-zero `read -t0` polls
for input without assigning any target or `REPLY`; this is distinct from
`-n0`/`-N0`, which can assign empty strings. Repeated valid `-t` operands use the
last timeout, with possible-empty attached expansions retaining each possible
operand/option path. Static invalid `unset` targets cannot affect unrelated
bindings, but `unset` continues processing later targets. These decisions
stream decoded bytes without temporary argv strings or runtime expansion.
Unknown numeric `-n`, `-N`, and `-t` operands retain an early, nonassigning
invalid-number outcome alongside valid zero/nonzero values. This applies to
separate and attached operands: later overriding options cannot repair an
earlier error, nor can later `-u` validation establish a proof on that error
path. Captured allocation digits are proven valid and do not gain this error
alternative. Data operands are not subjected to numeric validation.
Whole-word numeric facts are distinct from attached-option payload facts:
`-p"$fd"` can supply prompt data as an option, but its literal `-p` prefix is
invalid when a preceding option needs a numeric operand. Unknown fragments do
not erase an already-invalid prefix. Captured-empty values refine the literal
projection without rescanning source; literal fragments on opposite sides of
an unknown expansion are not themselves proof of invalidity.
Thus `unset fd; read -n"$fd" -p"$fd" value <<<payload` and the analogous
`read -u"$fd" -n"$fd"` are modelled builtin argument failures, not unsupported
syntax. They retain only failure continuations, consume no input, and do not
assign targets, `REPLY`, or IFS. Argument expansions and redirection setup still
occur before the builtin fails.
Explicit supported `unset` targets of stable scalars establish an empty
captured value even before that variable has named an allocated descriptor.
These facts follow execution scope and outcomes; subsequent assignments or
builtin writes invalidate them. Unsetting a descriptor variable does not close
its physical FD.
Automatically updated variables retain unknown captured values: for example,
`unset _; : 1; read -n"$_" value <<<payload` can read input because Bash sets
`$_` to `1` after `:`. No general implicit-variable value evaluator is added;
ordinary numeric operands keep their possible valid and invalid outcomes,
while unresolved descriptor identities retain the existing unsupported boundary.

Named scalar binding facts live in a persistent indexed submap of each
immutable execution version, separate from physical descriptor state. A bulk
scalar write resets that submap to an unknown fallback and restores only its
prepared temporary-prefix exclusions. It does not scan future read names,
replay mutation history, close physical FDs, or change sibling versions.
Explicit writes update individual keys; setup failure restores the appropriate
pre-builtin binding version while retaining reached descriptor setup effects.
Materialization reconciles changed subtrees, and collection traces the retained
submap roots in the same bounded evaluation workspace.

The graph models builtin `read`'s selected input precisely: fd 0 by default,
or the last valid `-u` operand. Each `-u` is checked in order against the
post-redirection descriptor state; an earlier closed descriptor stops option
processing. Quoted/escaped static decimal operands and exact tracked `$fd` or
`${fd}` references are supported, attached or separate. The argument captures
the variable's entry value, before redirects can reallocate `{fd}`. Unquoted
references require an incoming IFS that cannot split decimal digits; a
temporary `IFS=... read` prefix does not affect argument expansion. Other
runtime descriptor expressions are unsupported by semantic graph parsing,
not guessed as fd 0 and not passed to the ordinary-data expansion callback.
An empty attached argument leaves `-u` waiting for the next word; a bare
unquoted empty reference disappears. A quoted separate empty argument is an
invalid descriptor. Allocation-failure alternatives preserve these distinctions.
Entry facts also refine other option operands: a successfully allocated
`-p"$fd"` cannot be empty and consume the following option as its prompt.
This includes a following separate `-u "$fd"` operand. Source-only consumers
remain conservative when competing option/FD roles require descriptor state;
graph parsing resolves those roles from its captured entry values and rejects
any reachable interpretation that remains unsupported.
Unresolved ordinary values retain their possible-empty alternatives. A `;`
after allocation still permits failure, unlike a success-guarded `&&`.
Conditional descriptor opens and closes preserve the association between
existence, byte provenance, and read validation/assignment outcomes.
Each reached `-u` validation refines the descriptor facts of that execution
version. A successful `read -u11 -n0 probe` therefore proves fd 11 exists on its
`&&` continuation, although it consumes no input bytes. Repeated `-u` operands
retain every preceding validation, not only the final input selector. Option
errors retain the proofs already established; EOF, polling, invalid targets,
and access errors do not themselves imply that a descriptor is closed.
Temporary redirects are undone before publishing continuations, so validating
a command-local fd 11 does not prove the incoming fd 11 was open.

Retained journal versions always resolve missing facts against their immutable
entry baseline. A materialized descriptor table is a representative for replay
or enumeration, not the baseline of other alternatives. For example,
`read -u11 value {fd}<<<payload` can read inherited fd 11, or the here-string if
allocation selects an initially free fd 11. Both feasible inputs are retained.
A preceding successful fd-11 probe excludes allocation-to-11 on that branch.
Recursive descriptor export and timing-report routing use the same rule.
Variable writes use the same refined option frontier: words consumed as option
data do not invalidate descriptor variables or IFS. Writes stop at the first
invalid/readonly target; earlier assignments and implicit REPLY remain visible.
Captured entry values also refine exact scalar targets, including after `--`:
an allocated descriptor expands to an invalid numeric identifier, not an
unknown writable name. An invalid first target fails before input; an invalid
later target fails after possible input and earlier assignments, leaving later
bindings unchanged. A readonly first target can instead fail after input without
writing any target; an unresolved first target retains both failure timings.
For example, `read -n0 first "$target" last <<<payload || printf fallback >marker`
retains the fallback write even though a writable `$target` can make the read
succeed. Each outcome carries its own assignment prefix through connectors,
negation and private scopes; writes from successful alternatives are not applied
to a rejecting alternative. All argument expansions precede builtin validation:
stopping target assignment does not skip substitutions in later arguments.
Known-empty unquoted targets disappear only when the whole word permits it;
adjacent empty quotes preserve an invalid empty argument.

Only the selected readable descriptor contributes READ, PIPE, or process-input
SUBST flow. Polling (`-t0`), zero counts (`-n0`/`-N0`), invalid options, and an
invalid first identifier contribute no input byte flow. A readonly identifier
can fail after reading, unlike an invalid identifier checked before input.
Zero counts can still assign targets, whereas polling leaves them unchanged.
Input errors on closed or write-only descriptors leave targets unchanged and
cannot take a successful `&&` continuation. EOF can still follow assignments.
The zero-count input probe is different: it assigns even when the probe fails;
an earlier invalid `-u` still stops before assignment. Process-substitution pipe
ends exist during word expansion, before redirection setup and `-u` validation.
They use the reference shell's descending high-FD allocation and original-pipe
fallback, rather than assuming fd 63. Temporary ends close with their command
or compound scope; duplicates retain their resource. A generated `/dev/fd/N`
argument is prompt data or an invalid read target, not an arbitrary writable
identifier. Empty, blank-only (space/tab/LF), and comment-only process bodies create no
pipe and disappear as arguments; as standalone redirect operands they fail
setup with an ambiguous pathname. This also applies inside `$(<word)`:
`value=$(< <())` is valid syntax but the file substitution fails, so its `&&`
continuation does not run. `printf '%s' "$(< <())"` still runs `printf` with an
empty argument; the substitution failure does not replace that command's
status. Newline-only bodies are valid empty substitutions, not incomplete
pipelines. Setup-only members do not make their group an fd-0 byte reader.
Process substitutions inside conditional parameter operands, such as
`${choice:+<(producer)}`, do not definitely create a descriptor. The graph
retains both executing and skipped alternatives, with one shared decision
for substitutions in that operand and parent decisions for nested operands.
Later substitutions inherit only their executing alternatives, and cleanup
closes only the pipe ends created on each path. Conditional parameter values
remain runtime data; these alternatives do not evaluate those values. A
retained graph combines feasible effects, not a claim that every substitution
runs on every execution.
Temporary descriptor state is tracked only when it can affect observable
shell routing during its command or compound lifetime. Unobserved ends retain
their graph effects without enumerating combinations of independent guards.
A later unrelated read, after those ends have closed, does not activate that
tracking. Nested FD uses, escaping duplicates, named allocations, and possible
reuse of closed standard streams retain exact descriptor alternatives. The
existing limits still fail closed when distinguishable states exhaust them.
Timing alone does not make temporary descriptor identities observable. Entry
occupancy comes from the current execution snapshot, after preceding commands
and scope restoration: an earlier temporary close, a subshell-local close, or
a successfully reopened stream does not enable tracking for unrelated later
commands. Closes and moves within an owner's lifetime remain relevant. Low
auxiliary identities likewise follow uses within that lifetime; earlier closes
still constrain allocation without becoming new observations.
The allocator keeps a bounded symbolic occupancy domain for fd 0..63. Its
first-two-free and descending high-slot search conditions remain attached to
each execution version, including paths retaining an original pipe end. It
does not enumerate inherited descriptor tables or use the total number of
substitutions in unrelated commands to select concrete identities. Anonymous
ends retain their occupancy effects; identity-aware cleanup releases them
without discarding numeric descriptor changes. Known allocations use a direct
path when their incoming bindings already prove the selected descriptor.
Named-FD allocations and temporary target/move-source saves retain those same
joint occupancy constraints. The first/second-free search and the presence of
a free low temporary slot are tested together, not by combining independent
per-FD possibilities. For example, in
`exec 3<&-; : <(:) "$(read -u3 -n0 probe && read -u11 value {fd}<<<payload)"`,
the newly allocated here-string cannot reach fd 11. A feasible inherited fd-11
input is still retained. Proving a source open restricts an execution version;
an actual open, close, or move changes its occupancy instead.
Named descriptors, process pipes, and shell saves share private symbolic
allocation selectors. The relation starts at the first relevant allocation,
not at the first process substitution. Unobserved numeric choices do not each
create another execution version. A close releases exactly the selected FD;
named variables and captured arguments keep their numeric identity after close,
including when another allocation reuses that FD. Recursive imports preserve
the same relationship. Temporary-save searches also honor a named source's
numeric minimum. Selectors whose private lifetime ends are retired, while
named values remain available. Above fd 63, the existing observed/private tail
model remains conservative rather than promising exact allocation identities.
These are three distinct concepts: a physical slot's current resource, a
variable's retained numeric value, and an internal selector constraining which
slot was chosen. Closing a named descriptor changes the first, not the second;
another variable may subsequently acquire that same slot. Recursive shells
import shared aliases as one physical identity. Closing either alias in a child
affects both there, but neither parent's binding is changed. Consuming bytes
can still advance the shared open-file description; the graph represents
possible provenance, not remaining input or predicted EOF.
Internally, each selector uses a first-high-bit choice for fd 0..63, with an
all-low choice for the abstract high tail. Every Boolean assignment has a
meaning, so equality and retirement do not depend on a separate validity
predicate. Selector choices precede their matching physical occupancy bits in
the decision ordering. Reduced-away choices remain unconstrained: assignment
images still visit those choices and change the selected physical descriptor.
For example, with fd 3 and fd 63 known free, allocate `{a}<<<first`, close
`{a}`, then allocate `{b}<<<second` through a successful `&&` chain. Both
variables retain the same number in 10..63. Closing `$a`'s slot in a child
prevents a subsequent `read -u"$b"` there from receiving `second`; rebinding
`a` does not change the value previously captured by a read argument. Without
a bound below fd 64, the high-tail approximation can retain additional routes.
This is an explicit precision limit, not evidence that every retained route
occurs in every execution.
Symbolic expressions and routing versions remain subject to the existing
workspace limits and fail closed on exhaustion. Ephemeral predicate collection
does not retain discarded expressions in the journal.
Completed event entries are released after their last consumer: a pipeline
keeps its common entry through its final stage, an asynchronous list keeps its
parent entry through launch completion, and a group keeps setup and body state
through publication. Disposed private saves release their selector and scratch
metadata; named values retain their independent numeric identity after close.
The public graph still uses the existing nodes, edges, and limits; callers
continue to obtain private storage requirements through the workspace-size API.
Failed-setup cleanup dependencies retain every `(descriptor, registration
ordinal)` pair, including repeated saves of one descriptor. Range queries must
not see only its latest registration. These persistent dependency trees are
separate from canonical descriptor facts, including during collection. Failed
setup replay inherits its caller's collection pins, keeping other read outcomes
and private entry/undo maps alive while it creates temporary failure versions.
Each redirect operation also retains its immutable entry until move publication
and restoration finish; allocator refinement may replace the caller's current
version without releasing that still-needed entry.
Recursive cleanup similarly retains each segment's input until its cached
input/output pair is published, independently of its evolving output version.
Prepared frame-membership unions are snapshot roots too: a union across paths
need not occur in any individual descriptor map.
No source replay or canonical-index reconstruction is needed to preserve those
lifetimes.
The focused `shellsplit_read_input_test --selector-lifecycle` selection checks
these alias/import cases and independently enumerates selector retirement and
scratch-compaction semantics. The production-linked test accepts the same
selection; fixed executor expectations are in
`tests/cmake/test_bash_selector_lifecycle.cmake`. These are deterministic
regressions, not additions to the tracked smoke corpus.

The trusted reference-Bash read fixtures are registered as independent
`shellsplit_bash_*` CTest cases: read input, allocation correlation, selector
lifecycle, read proofs, private read outcomes, and outcome transfers. Each
script runs exactly one fixed Bash probe with a five-second subprocess bound;
CTest gives that probe a separate ten-second outer bound. Run the complete
family with:

```sh
ctest --test-dir build \
  -R '^shellsplit_bash_(read_input|allocation_correlation|selector_lifecycle|read_proofs|private_read_outcomes|outcome_transfers)$'
```

Invoking one script directly runs only its named fixture; there is no umbrella
script whose timeout accumulates the other probes.
Descriptor-sensitive builtin outcomes preserve that correlation even with no
redirect operations. For example, after `${choice:+<(producer)}`, a successful
`read -u63 -n0 first` can enable a later fd-63 read through `&&`, but its `||`
continuation cannot borrow that successful path's pipe. This distinction does
not predict EOF or other unknown runtime outcomes of an ordinary byte read.
The same correlation applies to private pipeline stages and isolated groups:
the child returns status to its own parent-entry alternative, not the union of
all alternatives. Child redirects, assignments, and IFS changes do not escape.
An observation of an unchanged inherited descriptor can refine that particular
parent-entry alternative. This is not a child descriptor mutation: a child
pipe or local open cannot prove that the corresponding parent descriptor
exists. Observations are recorded when made, so a later child close does not
erase a valid proof about the inherited descriptor.
Synchronous command and backtick substitutions return sparse, outcome-indexed
predicates over imported descriptor bindings, read capabilities, and captured
argument value classes. Argument capture and nested outcome transfers request
only their named dependencies, lazily, from immutable imported-entry anchors.
This happens before option validation, preserving even failures before physical
FD validation. Each requested value, identity, or access role is memoized in its
execution version, including unknown facts as empty entries which export no
predicate. Local writes and child-installed pipes cannot replace entry facts.
Child entry never walks the root-wide read-name inventory, so independent
substitutions do not perform a sibling-name cross-product. Collection and
recursive rewinds retain these anchors through the existing journal-root links.
An absent-name failure cannot be applied to a successfully allocated name.
Allocation-site source spans preserve identity across construction, replay, and
nested imports; journal-local slots and decision selector IDs are not portable
allocation identities. These predicates contain borrowed identifiers,
allocation-site pointers and FD numbers, never child-local journal roots. They
are exported in stable descriptor/key order and exact conjunctions and clauses
are interned in bounded workspace scratch. Equal status alone does not merge
different binding, access, argument-value, or allocation-identity predicates.
The indexes belong only to export scratch: recursive summaries never borrow
them and parent checkpoint restoration does not retain child index mutations.
The predicates are consumed before stream-join scratch is reused, then applied
at the original word, assignment-value, or redirect-operand boundary in both
construction and route resolution. Child stdout capture is a replacement, not
an inherited-parent observation: `exec 1>&-; value=$(read -u1 -n0 probe)` remains
a valid command and cannot prove the parent's stdout open. The existing import
capture mask excludes these capture-owned observations, without suppressing
status or auxiliary-FD proofs. Conditional substitutions retain their skipped
alternative and its preceding phase status, rather than borrowing the executed
alternative's status.
Substitutions within one conditional parameter operand share the scanner's
single guarded decision, including status-only completions. Nested operands
are dominated by their parent's decision. Completed status-only guards are
retired at operand/word boundaries. A guard survives longer only when an
actually tracked process descriptor needs that decision, not merely because
its operand contains process syntax. Those guards retire with the owner's
pipe lifetime. This avoids multiplying unrelated operand choices.
Command-local numeric read-argument captures, read-write signatures, and phase
substitution statuses retire after outcome computation and restoration, before
continuation joins. A missing capture is an empty private fact, never an
inherited descriptor with the same numeric ordinal. Deferred input publication
keeps its immutable pre-cleanup root. Imported observation predicates are
separate facts and are not cleared with these local captures. Nonmutating
executables without descriptor setup reconverge to their selected entry after
consuming substitution values; their status cannot preserve a discarded private
read outcome. Reads, assignment-only commands and persistent effects retain
the predicates selecting their outcomes. Genuine fixed-pool exhaustion still
returns failure-atomic `SHELL_DEP_ETRUNC`; limits have not been raised.
Descriptor proofs always use the journal's immutable imported baseline plus
explicit branch-local facts. Materialized routing tables are representative
views, not evidence that a descriptor exists on a skipped observation path.
Ordinary and file-optimized substitutions publish aggregate status and correlated
events together: a later `$(<file)` replaces earlier substitution status just
like a parsed child, without erasing earlier observations. Empty and
blank substitutions are identity transfers, not successful commands;
comment-only `$()` is also an identity transfer, while comment-only backticks
return success in the reference Bash. Shared lexical classification, rather
than graph node count, distinguishes these cases. Blank means space, tab, LF,
and erased backslash-LF continuations. Comments end at LF; CR within a comment
is comment text. CR (including CR before LF), vertical tab and form feed outside
comments are ordinary word bytes and are retained even before LF. Only
backslash-LF is a continuation: unquoted backslash-CR quotes CR, while inside
double quotes both backslash and CR survive. These rules also apply to source
ranges, canonical argv, builtin argument decoding and transformations.
Heredoc delimiters compare exact bytes after quote removal; CR is not stripped
from a delimiter or its document. There is no source line-ending normalization.
Literal backtick fragments group delimiter spaces and operators without
creating executable children. Their internal quote-looking bytes do not
protect the body; actual outer quoting does.
Raw non-ASCII delimiter/body bytes are admitted as heredoc data, not as an
extension of the executable-source byte domain. Content helpers preserve the
body's final LF and apply `<<-` tab removal; expandable content is a template,
while quote-protected content is an exact literal payload.
Draft inspection excludes tentative closing-delimiter lines from executable
child analysis until they become confirmed body data; raw content still
retains every received byte. Unfinished parameter heads and name enumeration,
including pending selector continuations, remain append-repairable rather
than being reported as malformed. See
[`shell_source.h`](include/shell_source.h) for confirmed-content
and prefix qualification rules.
Nonempty trivia-only fast-parser input succeeds with zero ranges; zero-length
input remains invalid, and `shell_process_commands` still rejects inputs with
no command records.
Thus `a=$(false) b=$()` fails, whereas `false; value=$()` ends successfully.
The preserved value belongs to the current command's preceding substitutions,
not the previous shell command's `$?`. Assignment-only and redirect-only child
bodies remain real commands with their own completion status. The status of an
ordinary enclosing executable does not imply that a substitution succeeded.

Empty process substitutions have different argv semantics: `<()`, `>()`, and
blank/comment/continuation-only bodies, under the same byte rules above, yield
no pathname. Whole unquoted words consisting of these fragments vanish;
concatenated literal fragments remain (`a<()b` becomes `ab`), while `''<()`
preserves one empty argument.
`exec` and `exit` also consume this logical argument stream: `exec <() 3>out`
retains descriptor setup, and `(true; exit <())` inherits the prior success.
An explicit quoted empty word still occupies an argument and can fail.
Command and wrapper selection, builtin options, graph argv and canonical
builders share this classification. Lexical token/source records and
diagnostic abstraction/transformation retain the original syntax. In
particular, expansion cannot reclassify `<() name=value` as an assignment or
turn a later word into a reserved grammar prefix. Application-provided netargv
is already expanded data and is never reinterpreted as shell spelling.
Resolver eligibility likewise follows surviving argv positions, not raw token
ordinals. Elisions cannot move a `printf` format, `%n` target or protected `%b`
operand into an ordinary-data role; quoted empty arguments still occupy slots.
Callback requests retain exact original source spans.
`shellsplit_read_input_test --owner-lifetimes` selects the empty-word and
4/8/16-owner lifetime regressions, including production/supplied-fast parity
and allocation-free graph parsing.
`--semantic-words` selects the resolver/elision and semantic blank-byte
regressions, including exact CR/VT/FF canonical argv, mixed command-substitution
outcomes, and production graph/supplied-fast parity. The fixed fuzz oracles and
Shellgate tests reuse the canonical byte cases; pinned-Bash probes anchor byte
preservation and exact heredoc delimiter matching independently.
Asynchronous process substitutions do not return completion proofs.

Read target writes, implicit `REPLY`, IFS effects, and restored command-prefix
bindings likewise remain specific to each execution version. In particular,
`read -n0 -t"$timeout" fd 0>writeonly` can succeed by polling without assigning
`fd`, or assign it and fail on the nonpolling path. The latter write must not
invalidate the successful path's descriptor-variable association.
With the documented default `pipefail`/`lastpipe` settings, the final stage
determines the pipeline status; negation inverts that result and asynchronous
launch success is independent of the child's later outcome.

Bash also performs parent-side cleanup when it forks a compound command
(`(...)`, or a pipeline/background brace group). Original process-substitution
ends close in the invoking interpreter, while the new child inherits those
open FDs with an empty process-end ownership set. This is different from
publishing a child close. A foreground brace does not itself perform that
fork cleanup. Duplicates of the original descriptor remain open: for example,
copying an expansion-created fd 63 into fd 62 preserves that resource across a
later compound fork, even though the parent's original fd 63 closes. A later
pipeline stage inherits the post-cleanup parent table. Numeric descriptor
reuse does not transfer ownership of the original slot to its duplicates.

`shellsplit_read_input_test --private-outcomes` selects the outcome, isolation,
fork-cleanup, and graph-capacity regressions. The production-linked test accepts
the same selection. Fixed executor comparisons are in
`tests/cmake/test_bash_private_read_outcomes.cmake`; these execute only trusted
test programs, never corpus or fuzz input.

`--read-proofs` selects inherited-input, ordered-validation, private-projection,
recursive-export, cleanup-cache equivalence, and graph-capacity regressions.
The trusted executor comparisons are in `tests/cmake/test_bash_read_proofs.cmake`.
`--operand-classification` selects numeric/target-prefix, frozen timeout,
process-path/tilde target, captured-empty suffix, signed-scalar,
reachable-attribute, literal-target, exec/exit elision,
and pending operand regressions in both read-input test variants, including
failure-only continuations, preserved bindings, and allocation-free graph
parsing. A dedicated lazy-observation work counter verifies that independent
children scale linearly in their actual dependencies, and repeated argument
requests in one version reuse both known and unknown entry facts.

Whole-word and attached-payload numeric templates are prepared separately.
Captured allocation digits refine a sole optional sign, including permitted
numeric whitespace. Irreversible integer errors (including negative nonzero
prefixes) and completed timeout conversions survive arbitrary later fragments.
Timeout conversion is complete after six fractional digits and the seventh
character's rounding decision; its signed/wrapped zero, nonzero, or invalid
result cannot change with later suffixes. These proofs are captured before the
first opaque fragment, separately for whole integers, whole timeouts, and
attached payloads. Literal projection across unknown fragments cannot create
a frozen prefix proof; it remains available for known-empty captures.
Other general concatenations remain unknown because conversion can wrap or round.
Strict integer conversion also retains invalid literal projections after opaque
fragments, provided one argv entry is proven. `read -n"$unknown"x` and the
corresponding `-N`/`-u` operands are argument failures, not possible input reads
or unsupported descriptor lookups. This deletion-closed integer proof is not
applied to timeout suffixes or unresolved splitting.

Integer leading zeroes retain captured scalar identity: `read -u00"$fd"`
selects the same allocated descriptor, while `read -n-0"$fd"` and the
corresponding `-N`/`-u` forms fail before reading or assigning. Surrounding
integer whitespace is preserved; nonzero numeric prefixes, digit suffixes,
and timeout concatenations do not acquire an exact-FD proof. If the captured
scalar is empty, its literal numeric projection is used instead:
`unset fd; read -u0"$fd" value` reads fd 0, and its edge records numeric fd 0,
not a descriptor variable named `fd`. Expansion still precedes redirections,
even when setup subsequently allocates that same variable.

The shared word walker ends leading-tilde recognition after an opaque expansion;
`$empty~` and `${empty}~` therefore retain a literal tilde, including across
escaped newlines. Read's optional process-fragment visitor projects a guaranteed
nonempty pathname containing `/`, without evaluating its body or manufacturing
an actual path. A constant-size possible-shape bitset recognizes scalar
identifiers and a conservative `NAME[...]` envelope during the same word walk.
Opaque fragments take its wildcard closure. A proven single argument with no
accepting shape is invalid, including `pre"$unknown"-` and `"$unknown"~`.
A process path can occur inside a dynamically formed subscript; its slash must
not incorrectly establish failure in that case. Explicit array targets remain
unsupported, and ambiguous dynamic shapes retain their existing classification.
Unquoted splitting/list cardinality does not justify a single-target proof.
Numeric option roles retain conversion rules (including ignored timeout suffixes),
while prompt/delimiter roles accept pathname data. Child effects are still built
independently before builtin argument validation. Other word-walker clients
continue to reject nonempty process fragments unless explicitly supported.

Read argument capture snapshots entry values before redirect setup; it does not
perform a second semantic preflight. The reached post-setup option frontier
validates effective Readline/array selectors. Pending prompt/delimiter and numeric
operands never activate those selectors: after `unset fd`, `read -p"$fd" -e value`
reads normally, while `read -n"$fd" -e value` is an ordinary numeric failure.
An earlier descriptor error can stop the scan before a later selector. Any
reachable unsupported selector still returns `SHELL_DEP_EPARSE`, including in
recursive graphs; it is not discarded as an empty outcome or reported as capacity
exhaustion. Source-only consumers reject contextual support they cannot prove.
Recursive shells borrow path-specific immutable scalar checkpoints, so an
unset-only variable remains known-empty even when it has never named a file
descriptor. Only requested keys are queried. Physical FD imports remain
separate, and versions with identical scalar state share a scalar view rather
than obstructing descriptor-domain factoring. Child-local writes invalidate
the inherited proof normally; no variable inventory is copied or rescanned.
Successful whole-variable unsets also remove resettable predefined capabilities
in descendants: after `unset RANDOM`, `result=$(read RANDOM <<<payload)` assigns
an ordinary scalar, just as a parenthesized subshell does. Command, backtick,
and process substitutions import the path's compact capability mask in constant
space, independently of physical descriptor identities and orphan scopes.
The mask remains part of execution-version identity at conditional joins;
child-local unsets and assignments never change their parent's capabilities.
Earlier temporary assignments are visible in later RHS substitutions too;
they invalidate inherited argument-value proofs without changing physical FD
imports. Child-local binding updates supersede this inherited value shadow.

An empty exact scalar fragment selects a prepared
literal identifier: `unset empty; read -n0 other"$empty"` changes only `other`.
Target identity is looked up in the source name index during preparation;
key-only named-allocation entries do not enable read-observation tracking.
No owned target strings, whole-inventory scans, or source replay are required
for execution alternatives. The same selected identity controls attribute
validation and mutation publication, including IFS and temporary prefixes.
Value capture is independent of a competing FD role: a provably invalid numeric
prefix cannot suppress target refinement after an earlier dynamic `-u`.

`--binding-invalidation` selects unstable-value, bulk-write, scope/rollback,
and direct binding-work scaling regressions in both variants.
`--variable-lifecycle` selects predefined-variable unsets, recursive capability
inheritance, conditional joins, and child-isolation regressions in both variants.
`--zero-prefix` checks integer leading-zero refinement, empty numeric selectors,
descriptor identity through setup, and failure-atomic assignment effects.
The `--outcome-effects` and `--recursive-proofs` selections cover assignment
correlation and recursive transfers; both also run in the production-linked
test. `--transfer-regressions` checks unknown-option errors, capture isolation,
named-entry correlation, nested aliases, and bounded graph capacities in both
builds; the allocator-instrumented selection also verifies zero heap use.
`--substitution-status` checks ordinary/file completion replacement, empty-body
identity, the reference shell's comment-only backtick behavior, conditional and
nested transfers, phase ordering, zero heap use, and bounded graph capacities.
`--bounded-work` checks unchanged scaling bounds with a known FD layout, plus
bounded symbolic-pool exhaustion, supplied-fast equivalence, and workspace
recovery with unknown inherited descriptors. Symbolic capacity can be exhausted
even when a command's eventual graph would fit its node and edge limits; the
result is failure-atomic truncation, not an approximate graph.
Their trusted executor fixture is
`tests/cmake/test_bash_outcome_transfers.cmake`.
Source-only processor and anomaly-sequence builders cannot prove read-option
roles or literal target projections that depend on captured scalar values.
They reject those contextual forms conservatively. Shellgate instead reuses
complete graph acceptance when
collecting anomaly stages, so enabling scoring does not reject a supported
contextual `read`. Both cold and warm type-cache paths retain the same lexical
stage order and signatures; they do not serialize dependency-graph node order.
A truncated parse or graph establishes no such proof: Shellgate skips anomaly
scoring, cache access, and learning while retaining partial policy diagnostics
and returning an undetermined truncation result.

If graph capacity omits setup metadata, subsequent context-dependent semantic
rejection reports truncation rather than diagnosing unsupported syntax from an
incomplete snapshot. This rule applies during expansion and final routing;
unfinished graphs remain failure-atomic.
Read frontiers reuse the caller's evaluation workspace; no decoded argv, source
reparse, or copy of the descriptor table is needed per option path.
Static read arguments have one entry support check, independent of how many
descriptor alternatives reach the owner. Captured or dynamic arguments still
use their own entry version; descriptor validation and outcome refinement
remain path-specific after setup.
Completed setup roots are retained before continuation cleanup can collect the
journal. Deferred byte/report publication needs those versions even when undo
returns a different state; sibling outcomes and accumulated timing reports stay
pinned through their publication as well. A live descriptor map also retains
its process-end ownership tree: those isolated set nodes have sentinel values,
not descriptor snapshots, and remain live until shell cleanup removes the ends.
Provably infallible prepared setups (identity, numeric close/self-copy, and
temporary process-end installation) do not replay an allocation/undo program
to construct nonexistent setup-failure outcomes.
Process cleanup retains its initial occupancy comparison only when needed;
later pipes do not pin unused prefix domains. Domain imports preserve failed
results for the immutable-source batch and stop at the first failed child, so
bounded-pool exhaustion cannot cause repeated traversal of shared subtrees.
For ordinary command bodies, deferred I/O retains only a sparse union of resolved
byte routes, not dead undo/allocator history. Read and compound analysis retain
their correlated semantic versions. Descriptor-only `exec` has no body I/O to
cache; its returning descriptor state and timing reports have separate lifetimes.

Selector-dependent occupancy changes use a memoized decision-DAG image instead
of repeatedly partitioning the full domain by each possible FD. Named-source
save searches share a suffix free-count automaton. Canonical decision nodes
retain exact AVL interning with a compact-ID front cache. Computed operations
instead use a bounded four-way memo cache with full-key comparisons: eviction
only causes recomputation, never loss of semantic alternatives. Only semantic
node pressure requires scratch compaction; memo occupancy does not. Reset,
collection, and compaction invalidate memo entries before IDs can be reused.
The `--memo-cache` selection forces collisions, eviction and ID reuse, and
checks a constant comparison-work bound. The finite selector oracle checks assignment images independently of
the decision-DAG operations, including reduced-away choices, multiple high bits
with the same first choice, idempotent updates, and the high-tail choice.
Checkpoint and paired-operation scaling fixtures establish free descriptor
slots to isolate checkpoint growth; a separate capacity regression leaves
inherited occupancy unknown and checks valid, fail-closed exhaustion. These
changes do not enlarge public result types or change limits.
Fuzzer builds use `-O2` with symbols, assertions, coverage instrumentation, and
ASan/UBSan intact. Fixed startup oracles retain their 60-second whole-process
deadline (70 seconds at CTest); no smoke cases or deadlines are relaxed.
The semantic expansion traversal discovers process substitutions inside
conditional parameter words as well as standalone arguments. Nonempty bodies
create temporary pipe ends; empty/comment-only bodies do not allocate pipes.
Thus `path=${choice:+<(producer)} read value` still represents a possible
input through fd 0 if occupied high slots force the original pipe end onto
closed stdin. Conditional creation and no-creation alternatives remain distinct.
In the reference Bash's optimized `$(<word)` form, process descriptors created
while expanding the filename remain visible during the enclosing command's
remaining expansions, including later command substitutions. They close with
that command, not when the file substitution finishes.
Timeout classification follows the reference Bash's validated conversion to
unsigned seconds: `-t4294967296` polls, while `-t4294967296.5` does not.
Its whole-part conversion wraps at the reference's long width before sign
validation: `-t18446744073709551616` polls, while
`-t18446744073709551617` can consume input. Shellsplit reproduces that wrapping
with defined unsigned arithmetic, including the reference's fractional rules.
Unused file, inline-document and process input redirects retain their FD_OPEN
setup effects; they are not reads. A process-input SUBST edge is data I/O, without the
`SUBST_SHELL_WORD` data-to-code flag. These rules also apply through groups,
pipelines, background jobs, and recursive substitutions. Explicitly observed
high `-u` descriptors include Bash's temporary descriptor saves. This is a
graph-semantics refinement in 0.16.0; no new public node or edge type is needed.

`printf` likewise processes every `-v` option before its format, including
attached and quoted targets; only the last selected `-v` variable is written.
Static formats also track every `%n` scalar target, including format reuse,
width/precision operands, escaped `%%`, and `%(... )T` date formats. Empty `%n`
names are no-ops; invalid names and format errors stop subsequent writes;
`%b`'s static `\c` stops the remaining format and operands. Dynamic formats
invalidate all named-variable routes because their targets are unknown.
Formats with `%n` require single-argument data words and at most 32
effect-bearing `%n`/`%b` conversions. Dynamic write targets are unsupported.
The complete-source boundary rejects ANSI-C NUL truncation; builtin analysis
does not repeat that validation. Binary canonical data supplied directly
remains supported.
The format is compiled once into a bounded private schedule, without copying
decoded words or rescanning the format on reuse.
An unknown format escape does not hide the following conversion: `\%n`
prints a backslash and still writes its target. In contrast, a percent produced
by a numeric escape such as `\x25` is literal output, not a new conversion.
Missing operands and proven option errors do not invalidate descriptor routes.
Declaration builtins distinguish queries and assignment modes: `declare -p`,
`declare -f`, and `typeset -F` do not assign, whereas `export -p name=value`
does. Static invalid names cannot invalidate unrelated bindings, and valid
later assignments are still processed. Option errors stop the invocation;
option parsing stops at `--` or the first operand. Top-level `local` cannot
write in the supported function-free model. These builtin roles are shared
between supported-syntax validation and descriptor mutation analysis.
Declaration operands undergo quote removal and empty process-fragment elision
before assignment recognition: `export f<()d=value` and `export fd+<()=value`
write and append to `fd`. Their ENVVAR documents retain original source spans;
the logical-name accessors return the decoded identifier. The same recognition
drives descriptor invalidation, temporary-prefix handling, IFS tracking, and
integer/protected/readonly restrictions. Quoted or escaped process-looking text
stays literal. A command-position `fd<()=value` is still an executable word,
because expansion cannot create a lexical assignment prefix.
State-changing `declare`/`typeset -i` forms are unsupported: the integer
attribute makes later assignments arithmetic evaluations that can change
unrelated variables. Non-mutating queries, option errors, invalid scalar names,
and canceled `-i`/`+i` attribute requests remain supported.
Declaration assignments to Bash's predefined mutable integer names (`SECONDS`,
`RANDOM`, `SRANDOM`, `OPTIND`, and `HISTCMD`) have the same restriction unless
that invocation explicitly uses `+i`. The graph tracks a successful
whole-variable `unset` on each execution path: a later write in the same shell
then sees an ordinary scalar, while a conditional unset, an unset in another
pipeline/subshell scope, or a path join retaining the original binding remains
unsupported. Attribute-changing declarations other than the directly modeled
`+i` invocation are still outside the supported state model. These names
remain available to non-mutating declaration queries.
Reachable `read` and `printf -v` writes to these five names are also
unsupported because integer attributes can evaluate the value. Read target
capabilities are checked after captured argument roles and redirect setup:
`read -u3 RANDOM 3<&-` is a known builtin failure, not unsupported syntax.
Earlier invalid targets similarly prevent later arithmetic assignments.
`read -t0`,
`unset`, and `%n`'s fixed decimal writes do not have that arithmetic side effect.
Even `SECONDS`' initial non-evaluating setter cannot be relied on after a
declaration changes the binding, so there is no setter-specific exception.
Assignment-only writes to the same integer names are unsupported, including
redirect-only commands. Plain `NAME=value command` prefixes remain temporary;
`NAME+=value command` can evaluate arithmetic even in that position and is
unsupported for these names.
Named-FD destinations must provide a stable scalar binding. Bash's predefined
getters and automatically updated `_`, readonly names, arrays, and the executor-protected
`POSIXLY_CORRECT`, `BASH_COMPAT`, and `BASH_XTRACEFD` are unsupported
destinations. A predefined getter or array which Bash actually removes on
`unset` becomes an ordinary scalar destination on that path; automatically
recreated variables, unset-rejected arrays, readonly names, and frozen executor
variables do not.
`OPTIND` has a stable integer binding and remains a supported destination;
numeric FD allocation cannot evaluate arbitrary assignment text.
Writes by `read`, `unset`, and ordinary `declare`/`typeset` to a same-name
temporary command prefix are restored after that builtin. Export promotion,
explicit `export` assignments (including `export -n name=value`), `printf`, and
`getopts` have persistent effects instead. Redirect setup precedes builtin
writes, so a named allocation installed by that setup can survive restoration
of a temporary value.
`getopts` destinations that are predefined integers, protected variables, or
runtime-expanded names are unsupported: an option letter assigned to an integer
can recursively evaluate another variable's stored value as arithmetic.
Its optional `--`, optstring, and destination are tracked as complete words;
unresolved argv cardinality before the destination is unsupported. A quoted
runtime optstring is accepted only when every possible destination position
remains safe, including the possibility that the optstring expands to `--`.
Ordinary scalar destinations and static invalid-name/option error paths remain
supported; extra arguments after the destination are ordinary data.
Descriptor analysis invalidates only possible destination bindings and the
implicit `OPTIND`/`OPTARG` writes. Other named descriptors and IFS remain
unchanged unless IFS itself is a possible destination. Missing operands and
invalid builtin options do not write these variables; invalid or readonly
destinations can still follow implicit state updates. All of these writes
occur after redirect setup and persist through temporary command prefixes.
`exec` option errors return failure and restore temporary numeric redirects;
valid descriptor-only `exec` retains them unless scoped by a `builtin` wrapper.
Definite command replacement terminates this noninteractive shell even when
the executable cannot be found. Unresolved operands can disappear or become
options, so returning alternatives remain represented. Redirection-setup
failures are separate returning paths, not command-replacement outcomes.
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
`eval`, `let`, `.`, `source`, `trap`, `alias`, `unalias`, `fc`, `enable`,
`compgen`, `complete`, `compopt`, and `bind`
invocations are likewise rejected: they can run additional current-shell
source, defer it to a handler, replay it, or alter later command lookup after
Shellsplit has analyzed the submitted text. Quoting a `let` operand does not
make its arithmetic literal: Bash can recursively evaluate variable values
and execute substitutions in array subscripts. Static `let` invocations remain
unsupported until that separate arithmetic grammar can be modelled fully.
Completion word lists can re-expand quoted command/arithmetic substitutions;
completion callbacks and Readline key bindings can execute registered code.
The complete static builtin forms are rejected rather than pretending their
operands are inert argv data. Inspection through `command -v`/`-V` does not
invoke those builtins and remains supported.
This model targets **Bash 5.3.20**, the single pinned reference shared by CI
and pre-push verification, not a set of version-dependent dialects. Upgrades
are deliberate changes accompanied by conformance tests and model adaptations.
The caller supplies this executor; the library does not run a shell or check
its version. This model requires a known noninteractive Bash startup state.
Start Bash with `POSIXLY_CORRECT` absent
(an empty value still enables POSIX mode), clear `BASH_COMPAT` and
`BASH_XTRACEFD`, then make all three variables readonly before evaluating
submitted source. Freezing `BASH_XTRACEFD` prevents a later unset or
reassignment from closing a descriptor behind the graph; freezing
`BASH_COMPAT` prevents compatibility-level changes to the modeled semantics.
The supported basis is
`bash -p -c ...`: privileged mode ignores `BASH_ENV`, `BASHOPTS`, and
`SHELLOPTS`, and
does not import environment-defined shell functions that could shadow a
modelled builtin such as `exec`. An equivalent launcher must establish those
same option, command-lookup, and frozen-variable properties before source
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
no remaining effective route is marked `TRANSIENT`. Heredocs and here-strings
also retain reached `FD_OPEN` setup when their input is replaced or unused,
and are marked `TRANSIENT` when no byte-use or live named binding remains.
The flag does not erase setup or imply it never executed. Setup-only append
opens carry `FD_OPEN_APPEND`.
If a process substitution redirects away its nested inherited stream, its pipe
still replaces the previous descriptor route. The graph retains an internal
unconnected endpoint without inventing byte flow through the child. Numeric
uses have a one-sided `SUBST` or `WRITE` edge; persistent and named allocations
retain `FD_OPEN` setup until a later descriptor use supplies the actual flow.
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
Heredoc bodies remain data. CWD metadata is propagated through sequential lists
and statically recognized direct or `command`/`builtin`-wrapped `cd`. A
foreground brace group shares and may update its surrounding CWD; subshell,
pipeline, background, and substitution scopes do not. Dynamically selected
commands make a subsequent current-shell CWD unknown rather than inventing a
transition. Successful `cd` installs its static destination; pre-change failure
retains the entry directory. Reporting/physical failure can instead follow a
directory change; those paths join the possibilities and retain corresponding
`PWD`/`OLDPWD` effects. Thus `cd /path && command` can have a known destination,
while `cd /path; command` joins success and failure and is normally unknown.
Argumentless `cd` can also select CDPATH through a relative runtime HOME and
fail while reporting after chdir; failure does not prove CWD or bindings
unchanged in that case.
HOME, CDPATH-dependent operands, dynamic expansion, and physical `cd -P`
resolution do not produce invented static directory identities.
Every `cd` retains an ordinary command node. Its successful execution also
replaces the named-descriptor proofs for `PWD` and `OLDPWD`,
including through temporary same-name prefixes. Those runtime directory
values are not treated as proven descriptor bindings. Numeric descriptor
copies and unrelated variables remain usable. Only a reached directory change in
the current shell publishes these writes: skipped commands, invalid static
arguments, setup/pre-change failures, and isolated child scopes do not. Descriptor
variables allocated by successfully reached redirect setup still persist,
even when a later redirect or `cd` itself fails. Its I/O, words, redirects,
and nested expansions use the incoming CWD; later commands use the directory
fact selected by the outcomes reaching them.
The same ordinary I/O path handles `export` redirects while preserving its
assignment ENVVAR documents.
ENVVAR names are borrowed source spellings; use the graph's ENVVAR-name helpers
to compare or render their quote-removed identifiers. The ENVVAR_APPEND flag
distinguishes an appended value fragment from a replacement assignment.

Each leading `!` is retained as `pipeline_negation_count`; the compatibility
boolean `pipeline_negated` is its parity (the effective exit-status inversion).
Only horizontal whitespace and escaped physical line continuations may separate
the modifier from its pipeline. A raw newline or comment after `!` is rejected
instead of being treated as a modifier of a later command. An adjacent ordinary
redirection also delimits the reserved word (`!>out command`); numeric/named-FD
prefixes, process substitutions, and extglobs remain part of an ordinary word
(`!2>out`, `!{fd}>out`, `!<(producer)`, and `!(pattern)`).

Bash's reserved `time`, its `-p`/`--` formatting options, and interleaved `!`
modifiers are structural pipeline syntax rather than argv. The selected mode
is retained on every top-level member of the timed pipeline and the dependency
graph adds one TIME node for the measured pipeline. Its `report_fd` is the
shell's fd 2; the TIME edge identifies the directly measured command or group
and is not a byte-flow edge. A directly timed compound is owned by its GROUP
node; flattened inner simple commands keep only their own local timing.
Shellgate exposes the effective enclosing timing mode on its simple-command
results so application callers need not reconstruct the group relationship.
The separate `report_route` records whether the report leaves through an
inherited external descriptor, reaches a graph document/endpoint through
WRITE, APPEND, PIPE, or SUBST flow, or is discarded because the effective
descriptor is closed. A descriptor which remains open but has no write-capable
route is reported separately as `SHELL_TIME_REPORT_UNAVAILABLE`.
`SHELL_TIME_REPORT_MULTIPLE` retains every destination or descriptor alias,
including path-dependent alternatives, through `report_route_flags`,
`report_external_fds`, and outgoing
report edges; it never guesses one branch. Report routing follows Bash's
lifetime boundary: redirects local to an ordinary measured command or
multi-stage pipeline are restored first, enclosing redirects remain active,
and a descriptor-only `exec` in the reporting shell can change the
destination. A sole timed subshell or backgrounded compound group reports
inside that child scope, so its group redirects and descriptor-only `exec`
operations remain active. A timing report routed to a command or input-process
substitution's capture becomes an explicit SUBST or collector flow. A descriptor
copied from external stdout before entering that substitution still bypasses
its capture, even when later duplicated onto the child's fd 1 or fd 2.
Numeric compound redirects restore from their live saved descriptor slots in
reverse registration order when a foreground group finishes. An in-body `exec`
can overwrite a save, changing the restored route, or close it, causing that
restoration to fail and stop the remaining undo list. The target then stays
unchanged and older saves remain live. Cleanup diagnostics leave the body's
status unchanged; enclosing scopes still perform their independent cleanup.
Later redirects and redirect-operand substitutions can use saves created by
earlier redirects in the same setup. Ordinary argument substitutions precede
that setup. Direct external-command setup creates no undo saves, although it
can duplicate an enclosing group's live save onto a standard stream before
executing. Ordered descriptor journals drive both expansion snapshots and
final routing; concrete tables are derived views, not separate setup replays.
Runtime command dispatch keeps builtin and external setup versions separate,
including their scratch allocation, failure, and publication effects. An
argv-less command with an fd 0 or named-FD redirect performs setup in a child
without undo saves; negation and conditional continuations use that child's
real setup outcome. Correlated versions retain deterministic iteration order
and use indexed root membership rather than repeated list-prefix scans.
Setup failures use their own immutable, ordered cleanup program, using live
saved descriptors just like successful completion. Balanced program segments
reuse unchanged cleanup results through an indexed descriptor-dependency view;
each possible failure does not walk the accumulated undo prefix again. The
dependency view includes private saved-slot capabilities and the shared
symbolic occupancy relation, so changing either invalidates affected cached
cleanup results. Numeric prefixes whose saves cannot be observed return their
entry table directly on failure. This includes low-target setup followed by a
final high redirect: failure precedes that high target's replacement. Such
prefixes still record diagnostics through the actual preceding stderr routes,
without enumerating unobservable save/no-save histories. High-source copies,
process allocation, moves, and later failures after a high-target change retain
the ordered correlated cleanup path. Scaling regressions distinguish one forced
failure after a growing successful setup from multiple possible file-open
failures with distinct surviving named bindings. The former bounds total
descriptor-map work; the latter bounds source preparation, cleanup-program
composition, and executed undo leaves, separately from joining the distinct
symbolic outcomes. Unrelated mutation targets retain an indexed `n log n`
comparison budget across two input-size doublings, rather than scanning every
inherited binding. The snapshot and final-route journals share one cleanup
scratch pool in the caller-owned evaluation workspace. Closing or
overwriting a save during setup can therefore leave earlier temporary routes
installed after failure. Timing reports include only reached cleanup outcomes,
not an unreachable successful restoration path.
Mutations to other descriptors, copies made from temporary
descriptors, and named-FD allocations can still persist. Ordinary I/O,
substitution imports, and timing reports use these same lifetime rules.
Conditional descriptor alternatives also survive recursive substitutions.
These snapshots retain the saved descriptors' physical close-on-exec property
on each execution path. An inner descriptor-only `exec` overwrite therefore
restores an inherited shell-owned save, while explicitly closing that save
and reopening its number creates an ordinary persistent descriptor.
Resolved `exit` builtins (including `command`/`builtin` wrappers) distinguish
signed decimal status operands from redirection syntax. Valid static operands
terminate with their status byte; operandless `exit`, including `exit --`,
transfers the preceding list status into shell termination. Subshell completion
converts that termination into a returning status, while brace groups retain
it. Skipped continuations contribute no I/O or substitution flows. Setup
failure remains a returning path, and command substitutions during expansion
can replace the status inherited by an operandless exit. Runtime operands and
version-dependent numeric/extra-operand errors retain their possible outcomes.
Inherited stdin/stderr and explicitly selected auxiliary descriptors point to
their original resources, using only the final effective routes of each
command. A later redirect can therefore remove a copied byte-flow edge, while
a substitution in a later redirect operand can still read an earlier input
redirect. Such a document is not transient if that nested consumer uses it.
Timing pipes retain every surviving destination descriptor alias. Recursive
joins reserve their imported edges and deferred stream uses before copying child topology; exhausting
the bounded route or graph capacity returns truncation rather than silently
dropping a destination.

With job control disabled, Bash can supply read-only `/dev/null` as background
stdin. Its retained resource is one shared FILE DOC flagged
`SHELL_DEP_DOC_FLAG_IMPLICIT`, with a library-owned canonical pathname rather
than a source span. Explicit source `/dev/null` documents remain separate.
Only retained READ uses cause this implicit resource to be published. Bash's
implicit open is nonfatal: the graph also retains the original stdin alternative
for open failure. Copies, closes and scope restoration operate on these same
correlated route facts. Simple-command argv and assignment values expand before
this setup; redirect operands expand after it. Asynchronous compounds, timed
pipelines and AND/OR wrappers install it before their contained expansions.
Bash's interpreter-local `stdin_redir` marker and explicit redirect-instruction
classification control the exemptions; auxiliary file-input instructions can
exempt a command even when they do not target fd 0. The marker persists across
newlines within one submitted `-c` source, and isolated scope changes do not
escape to the caller's continuation. Process substitution alone is not a
background-stdin installation. Implicit routes are real flow, not explicit
redirection syntax or Shellgate redirection-fanout effects.

Top-level recovery from an input-unit abort precedes asynchronous entry and
stdin setup. The saved parent FD/CWD state is that recovered state; completing
a background unit cannot restore the preceding abort or retain child changes.
Returning parent paths observe successful asynchronous launch, not the child's
exit status. This also determines compound completion when its final list is
asynchronous; child-local AND/OR decisions still use the child's own status.

Substitution snapshots include pipeline setup before command-word expansion.
Redirect operands additionally see preceding redirects; an implicit `|&`
stderr duplication follows explicit redirects. Nested commands retain their
actual input resource even when their stdout feeds a different capture. Thus a
command substitution inside an output-process consumer can read that process
stream, and inside a pipeline stage can read the pipeline input. Descriptor-only
`exec` retains setup operations but is not treated as a byte producer or reader.
Each compound pipeline stage, including a final brace group with only an
incoming pipe, has one private execution scope. Its body shares persistent
descriptor and CWD changes, including through nested plain braces and
substitutions, without leaking those changes to the enclosing shell. Redirects
that replace the pipe do not remove that syntactic isolation.

An empty timed pipeline remains structurally visible but contributes no
policy-evaluable subcommand or implicit byte-flow edges. Its TIME node still
owns the actual report, including a report captured by command substitution.
Shellgate therefore treats a bare empty timed
pipeline as policy-neutral; an argv-less timed redirect remains an
unpolicyable redirect operation. Top-level EOF and real `;`, `&`, or newline
terminators can end an empty timed pipeline; a subshell, command-substitution,
or process-substitution `)` cannot stand in for that separator. Quoted heredoc
bodies remain literal, while executable substitutions in unquoted bodies obey
the same rule. Quoted, escaped, assignment-prefixed, redirect-prefixed,
wrapped, and post-pipe `time` words remain ordinary argv.

Extglob is recognized as Bash syntax, but a fresh Bash executor must enable
`extglob` before parsing the command (for example, `bash -O extglob`). Source
commands such as `shopt -s extglob` are rejected with all other option-state
mutations; they occur after Bash has already parsed the submitted command.

### Dependency-graph workspace

The fixed workspace also holds the operation-local lexical index. Application
expansion callbacks parse in independent contexts, including overlapping views
of the parent source, without inheriting its validation proofs or evicting its
cached boundaries. Allocating processor/tokenizer, abstraction, transformation,
and sequence APIs reserve and release their own temporary delimiter arena;
only allocation-free source APIs require caller scratch for large delimiters.

Dependency-graph parsing remains allocation-free, but route resolution uses
caller-owned scratch storage. Measure its fixed prefix once, add the queried
source-dependent delimiter capacity, and align one reusable allocation. Keep
the command bytes, graph output, and workspace disjoint:

```c
#include "shell_depgraph.h"
#include <stdlib.h>
#include <stdint.h>

size_t workspace_size = 0;
size_t alignment = shell_dep_workspace_alignment();
shell_dep_workspace_size(NULL, &workspace_size);
size_t delimiter_size;
if (!shell_source_workspace_size(command_length, &delimiter_size) ||
    delimiter_size > SIZE_MAX - workspace_size)
  return 1;
workspace_size += delimiter_size;
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
```

`aligned_alloc()` requires an allocation size that is a multiple of the
alignment; the example rounds up after adding delimiter scratch. Applications
with a different allocator can over-allocate and align manually. An absent,
misaligned, or undersized workspace returns `SHELL_DEP_EWORKSPACE`. Use
`shell_source_workspace_size()` instead of a flat-delimiter byte estimate:
grouped delimiter fragments also need workspace-backed normalization pieces.
Command bytes, configuration, workspace, and graph output must obey the non-overlap
requirements documented by the API; invalid caller storage is not inspected at
runtime.

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
