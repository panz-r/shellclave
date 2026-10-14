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
reference_bash=$(./scripts/prepare-reference-bash)
cmake -S . -B build -DSHELLCLAVE_BASH_EXECUTABLE="$reference_bash"
cmake --build build
ctest --test-dir build --output-on-failure
```

Conformance tests use the pinned Bash reference described in the repository's
[build instructions](../README.md#requirements-and-build). Library-only builds with
`BUILD_TESTING=OFF` do not need a Bash executable or network access.

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
| Escape-sensitive backticks | active legacy bodies requiring removal of an escape layer | lexically recognized, rejected by semantic APIs |
| Current-shell metaprogramming | static `eval`, `let`, source loaders, traps, aliases, history replay, dynamic builtin loading, completion/Readline configuration, Readline-enabled `read`, `mapfile`/`readarray`, `wait -p`, and directory-stack operations | detected, rejected as unsupported |
| Unmodeled Bash syntax | `[[ … ]]`, `(( … ))`, `$"…"`, arrays and associative arrays, array-element targets, and dynamic or mutating arithmetic expansions | detected, rejected as unsupported |
| Control Features | loops, conditionals, `case`, `select`, `coproc`, and functions | detected, rejected as unsupported |
| Bash `case` fall-through | `;&`, `;;&` | detected, rejected as unsupported |

The fast parser is zero-copy and bounded rather than a complete POSIX shell
grammar. It reports parse errors and output truncation through return codes;
callers must handle those results explicitly.

Ordinary legacy backticks remain supported. Bash removes an escape layer from
their body before parsing it: backslashes before dollar signs, backticks,
backslashes, and newlines, plus double quotes when the substitution is
double-quoted. Semantic APIs reject active bodies requiring that removal rather
than treating their raw source spelling as the nested program. This includes
escaped nested backticks and continuations even inside inner single quotes.
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
assignments, not its own or later assignments. Thus `IFS= X=$(producer)` gives
the substitution empty IFS, while the prefixes of an executable command still
expand against its incoming state. Ordered IFS checkpoints share the graph
evaluation workspace; RHS inspection does not replay assignment prefixes.

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
An explicit reallocation restores a proved binding; conditional rebindings that retain the
name on every path preserve their alternative routes.
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
Named-FD analysis invalidates only static `read` target names (or `REPLY` when
no target is supplied); unresolved target names invalidate all visible bindings.
A proven invalid option, invalid numeric operand, or missing operand does not
mutate a descriptor variable. An invalid static `read` target (including the
launcher's readonly `POSIXLY_CORRECT`) stops assignment at that target, while
earlier valid targets can still be written. Explicit timeout-zero `read -t0`
polls for input without assigning any target or `REPLY`; this is distinct from
`-n0`/`-N0`, which can assign empty strings. Repeated valid `-t` operands use the
last timeout, with possible-empty attached expansions retaining each possible
operand/option path. Static invalid `unset` targets cannot affect unrelated
bindings, but `unset` continues processing later targets. These decisions
stream decoded bytes without temporary argv strings or runtime expansion.
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
State-changing `declare`/`typeset -i` forms are unsupported: the integer
attribute makes later assignments arithmetic evaluations that can change
unrelated variables. Non-mutating queries, option errors, invalid scalar names,
and canceled `-i`/`+i` attribute requests remain supported.
Declaration assignments to Bash's predefined mutable integer names (`SECONDS`,
`RANDOM`, `SRANDOM`, `OPTIND`, and `HISTCMD`) have the same restriction unless
that invocation explicitly uses `+i`. A prior `unset` or attribute change is
not enough to assume the variable is now a plain scalar without modeling that
state. These names remain available to non-mutating declaration queries.
Arbitrary-text `read` and `printf -v` writes to these five names are also
unsupported because integer attributes can evaluate the value. `read -t0`,
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
destinations, even after an earlier unset or attribute change.
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
no remaining effective route is marked `TRANSIENT`. Transient heredoc and
here-string documents have no `FD_OPEN` edge. Setup-only append opens carry
`FD_OPEN_APPEND`.
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
transition.
Plain `cd` remains a node-free CWD transition by default. Its successful
execution also replaces the named-descriptor proofs for `PWD` and `OLDPWD`,
including through temporary same-name prefixes. Those runtime directory
values are not treated as proven descriptor bindings. Numeric descriptor
copies and unrelated variables remain usable. Only successful execution in
the current shell publishes these writes: skipped commands, invalid static
arguments, failed setup/execution, and isolated child scopes do not. Descriptor
variables allocated by successfully reached redirect setup still persist,
even when a later redirect or `cd` itself fails. These effects also apply when
no command node is retained.
A `cd` with redirects or executable substitutions has a command endpoint:
its I/O and nested commands
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
snapshot and final-route journals share one cleanup scratch pool in the
caller-owned evaluation workspace. Closing or
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
misaligned, or undersized workspace returns `SHELL_DEP_EWORKSPACE`. Command
bytes, configuration, workspace, and graph output must obey the non-overlap
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
