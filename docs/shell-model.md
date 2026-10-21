# Shell analysis reference

Shellsplit analyzes source, retains command relationships and I/O routes, and
reports supported semantics and resource limits. Shellgate uses that analysis
for policy classification. This reference describes behavior visible to callers;
the public headers define exact layouts, capacities, ownership, and errors.

## Executor and analysis boundaries

The modeled executor is **Bash 5.3.20**, pinned in
`scripts/reference-bash.sha256`. Each full command runs in a fresh,
noninteractive shell. The [security model](../SECURITY.md#executor-startup)
specifies the required startup preparation. Reference upgrades include
conformance tests and any required modeling corrections in one changeset.
`LC_ALL` is fixed to C/POSIX or an installed UTF-8 locale and made readonly in
trusted startup. Analysis uses byte-oriented syntax and values under this
executor contract.
The embedding application's locale does not affect syntax, builtin operand
classification, Shelltype token classification, or diagnostic byte escaping.
Those operations use explicit ASCII character sets and preserve other bytes as
data. Library calls leave the application's locale unchanged.

Shellsplit exposes several levels of analysis:

| Interface | Product |
|---|---|
| `shell_parse_fast()` | Bounded source ranges and lexical features |
| `shell_tokenizer_init()` / iteration | Lexical tokens with source spans |
| Processor and canonical builders | Command tokens, redirect metadata, and explicit-length argv records |
| `shell_parse_draft()` | Retained headers, redirects, heredoc framing, and qualified analysis prefixes |
| Dependency-graph construction | Command, group, I/O, state, timing, and substitution relationships |

Lexical feature detection can recognize syntax which semantic consumers reject.
Control constructs, functions, arrays, `[[ … ]]`, and `(( … ))` commands remain
unsupported. A feature flag is recognition, not a promise of semantic support.
Shellgate's default mask also rejects arithmetic, heredocs, and here-strings;
changing that mask enables only constructs the semantic model supports.

Control flags recognize complete unquoted lexical words after removal of
backslash-LF continuations. Punctuation and quoted or expanded fragments stay
within their word: `日本.if` and `日本''if` have no conditional flag. Standalone
keyword spellings remain lexical markers even in argument positions, so
`echo if` still has that flag. Comments, redirect operands, parameter operands,
arithmetic text and document text do not supply outer control words.
Executable substitutions are inspected in their own command context, including
when nested in those data operands.

Supported composition includes simple commands, lists, `&&`, `||`, pipelines,
`|&`, background execution, brace groups, parenthesized groups, negation, and
pipeline timing. Redirection support includes files, combined output, heredocs,
here-strings, named descriptors, duplication, moves, and closes.

Extglob requires `extglob` enabled by the executor before Bash parses source.
Shell-option mutations in submitted source are rejected. Supported arithmetic
uses numeric literals, operators, and bounded nesting. Variable
lookup, dynamic arithmetic, and mutation remain unsupported, including in
substring offsets and lengths.

## Source bytes, words, and canonical values

Source offsets count bytes. The source API classifies literal NUL as
INVALID_INPUT; DEL and prohibited non-NUL control bytes are UNSUPPORTED.
These byte restrictions are distinct from Bash syntax. Space, tab, and LF are
shell trivia; CR, vertical tab, and form feed
remain significant word bytes. Comments end at LF. Only backslash-LF is a
physical continuation; input is preserved without CRLF normalization.

An unquoted backslash protects the following byte only. In `echo \$(name)`,
the dollar is literal but the parentheses remain shell punctuation, making
the source INVALID. Quoting the entire spelling or escaping the parentheses
produces ordinary literal word content.

Ordinary literal word content, whether unquoted, escaped, single-quoted or
double-quoted, preserves high bytes exactly, including invalid UTF-8. This
applies to command names, arguments, assignment values and filenames, including
concatenated fragments such as `pre'日本'".txt"`. Offsets and lengths count source bytes;
normalization and character decoding are outside this representation.
Backslashes are literal inside ordinary single quotes. In double quotes they
escape only `$`, backtick, `"`, backslash, and newline; a backslash before any
other byte is retained. Closing quotes therefore retain the same word and
command boundaries across source, processor, graph, and diagnostic APIs.
Heredoc delimiter and body data retain their existing byte domains.

ASCII rules continue to determine variable names and shell syntax. Thus
`$name日本` expands `name` followed by literal text, `$日本` is literal text,
and `日本=value` names a command rather than an assignment. High bytes do not
introduce word boundaries or turn part of a word into a reserved word.
Command, process and supported backtick substitutions establish independent
source contexts: both `"$(printf '%s' '日本')"` and `"$(printf 日本)"` are
admitted. Arithmetic, substring arithmetic, array subscripts and parameter
selectors retain restricted code
domains even inside an enclosing quote. Ordinary parameter operands inherit
their applicable quote context, as in `${value:-日本}` or `"${value:-日本}"`.
Pattern and replacement operands also retain high bytes without evaluating
their runtime results. Comments admit literal high bytes, including invalid
UTF-8, and end at raw LF or EOF. Quotes, expansion spellings and Unicode line
separators inside a comment remain comment data. The whole-source NUL,
prohibited-control-byte and DEL restrictions still apply. Thus
`cat résumé.txt # 説明` has the same command arguments and effects as the
command without its comment; source offsets continue to refer to the original
bytes.
Canonical netstrings carry arbitrary binary payloads independently of
shell-source admission.

Raw high bytes in ANSI-C quoting remain UNSUPPORTED. ANSI-C quoting supports
static byte decoding. Complete-command semantic APIs reject escapes decoding
to NUL and locale-dependent non-ASCII Unicode escapes.
Isolated-word and canonical APIs preserve their documented byte-oriented
behavior. Locale-translated `$"…"` source is unsupported.
The source classifier also declines legacy `$[...]` arithmetic and function
declarations, including Bash names beyond ordinary identifiers, rather than
interpreting their punctuation as supported command-list grammar.

Compound-array assignment requires a lexical assignment or declaration-operand
position. Those forms are UNSUPPORTED, including unfinished array bodies.
An ordinary argument such as `echo a=(x)` is INVALID. Declaration eligibility
requires an unquoted literal command name such as `declare`; quote removal and
`command`/`builtin` wrappers do not grant it. Leading redirects preserve the
pending command-name position, while a redirect after the declaration command
ends its declaration-operand eligibility.
Indexed scalar assignments retain that role through their complete value,
including quoted and expanded fragments. Thus `a[0]=x declare a=(y)` is
UNSUPPORTED array syntax, rather than an ordinary command followed by an
invalid array argument.

Canonical netargv retains argument boundaries and explicit lengths. Graph
command tokens reflect surviving arguments; lexical tokens retain source
spelling. Empty process substitutions such as `<()` produce no pathname and
can disappear from an unquoted word. `a<()b` becomes `ab`; quoted empty
fragments preserve an argument. Expansion does not create a lexical assignment
or restore reserved-word eligibility.

For example, `<() name=value` has an executable word rather than an assignment
prefix. Assignment and redirect prefixes also commit a simple command before
its executable word: `x=1 then` invokes a word named `then`. Quote-removed
static command roles are recognized, including `e'x'ec` and `com'mand'`.
Runtime-expanded command identity remains deferred.
Likewise, `>out {` names an ordinary command word, while `{ :; } >out` is a
brace group with a trailing redirect. A list separator restores reserved-word
eligibility for the next command.

## Expansions and dynamic content

Ordinary parameters, non-mutating defaults, name enumeration, and supported
non-evaluating transformations are retained. `${name=word}`, `${name:=word}`,
`${value@P}`, actual indirect `${!ref}`, and current-shell `${ command; }` /
`${|command; }` substitutions are unsupported. Their state changes or data
re-evaluation require semantics beyond ordinary word expansion.

Command and process substitutions retain nested commands and their I/O.
Parameter operands can conditionally skip substitutions; the graph retains
feasible execution and skip outcomes. A graph is a combined analysis of possible
effects, rather than a schedule asserting every retained command runs.

Ordinary legacy backticks are supported when raw source spans faithfully
represent their executable body. Bodies requiring Bash's outer escape-layer
removal are rejected by semantic and draft APIs, complete or unfinished.
Prefer `$()` for nested substitutions needing that legacy escape behavior.

### Resolution callbacks

Use `shell_dep_graph_parse_resolved()` directly, or register
`shell_expand_word_netargv_fn` with a gate for combined evaluation. Eligible
requests identify an ordinary argument, redirect pathname, or optimized
file-substitution pathname and include known execution CWD facts.

The application supplies final canonical netargv after quote-sensitive
composition, splitting, and globbing. Return `SHELL_EXPAND_UNRESOLVED` when a
value cannot be established for every reaching state. Protected command,
assignment, builtin-state, and descriptor operands use their separate model.
An eligible source word is queried at most once; callback order follows
analysis phases. Returned bytes stay immutable through evaluation, or through
the lifetime of a standalone graph borrowing them.

Unresolved argv and pathname bits remain visible even when policy matching
succeeds. Aggregate gate flags cover retained graph commands omitted by policy
early-stop or result rendering. Capacity-truncated graphs provide partial facts.
Resolving a filename establishes its value, not whether an open succeeds.
Resolving an ordinary word also leaves substitution-inspection duties intact.

### Substitution routes

SUBST edges carry several kinds of I/O. `SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD`
marks runtime-generated shell-word content requiring inspection. File-name
resolution and ordinary process-substitution streams have distinct roles.
`cat <(producer)` consumes data; an explicit interpreter such as
`sh < <(producer)` interprets the stream as a program. The consumer determines
the use of that data.

Bash's optimized `$(<file)` uses a direct file-content route. Supported shortcut
spellings include explicit `0<`, leading comments, and a final semicolon.
Additional commands or redirects select ordinary substitution behavior.
An empty resolved filename removes the file-content route but can still leave
captured shell diagnostics requiring inspection.

Shell diagnostics can supply captured bytes even when a command body never
runs. In `exec 3>&-; sh -c "$(echo 2>&1 >&3)"`, redirect failure uses stderr
already connected to the capture. Reversing the redirects changes that route.
Parameter/arithmetic errors and rejected assignments follow their own reached
stderr context too.

## Heredoc data and received drafts

A heredoc document retains the exact body span, including its final LF.
For `cat <<'EOF'\nalpha\nEOF\n`, the literal payload is six bytes, `alpha\n`.
Use `shell_dep_doc_content_length()` and `shell_dep_doc_write_content()` for
logical content; `<<-` strips leading tabs from each physical line. CR is
preserved. A literal heredoc has `SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL`.
Expandable bodies remain source templates until runtime expansion.

Delimiter words use Bash lexical normalization and quote removal. Balanced
literal parameter, arithmetic, command, backtick, and process fragments can be
part of the delimiter without executing them. Bash prints parsed command
fragments before delimiter matching: `<<$(printf   eof)` matches `$(printf eof)`.
Internal quotes alone do not protect the body; actual outer quotation does.
Unsupported fragment grammar or locale-dependent delimiters are rejected.

In `$()` and process substitution, Bash can reserialize an unquoted ordinary
`<< -EOF` into `<<-EOF`, changing which body lines become commands. Semantic
consumers reject that unfaithful borrowed-source case. Quoted `<< '-EOF'`,
top-level `<< -EOF`, and already-strip-tabs forms retain their supported framing.

`shell_parse_draft()` accepts the entire received source and returns COMPLETE,
INCOMPLETE, INVALID, TRUNCATED, UNSUPPORTED, or INVALID_INPUT. INVALID establishes
a grammar error in a context the parser can classify. UNSUPPORTED leaves the
required judgment unclassified, including valid Bash outside the model.
INVALID_INPUT rejects embedded NUL; TRUNCATED reports a resource or
representation limit. See the [admission recipe](../shellsplit/README.md#classifying-input-before-dispatch)
for their application-level consequences. Headers retain words, assignment counts,
compound membership, and linked source-ordered redirects. FIFO heredoc records
bind each declaration, body, and terminator to its header.

Supported non-ASCII heredoc data and delimiters do not change subsequent
classifications. A missing delimiter committed by a newline, comment, or
operator is INVALID; an unfinished delimiter remains INCOMPLETE. Exhausting
the pending-document capacity is TRUNCATED, while unsupported delimiter
normalization remains UNSUPPORTED. Byte admission continues checking later
code after a missing word, without inventing another document body.

Header completeness is local: a closed child can be complete inside an open
compound or substitution. An unfinished outer construct does not repair a
malformed closed child. Nested pending redirects retain body-local recovery
without replacing the public outer diagnostic.

COMPLETE source has complete retained headers. Comments end at their raw LF,
including when the comment's last byte is a backslash. That newline still
separates commands and starts any pending heredoc bodies. Outside comments,
an unquoted backslash-LF continuation is removed before token recognition.

Redirect operators use longest-match boundaries for bare, numeric, and named
descriptors, including the clobber operator in `{fd}>|out`. Adjacent operators
remain separate: `<<<<x` is INVALID because the here-string lacks its word,
whereas `<<<<(:)` has a process-substitution operand. A final `<` or `>` in
operand position remains appendable until its lexical role is committed.

Leading indexed assignment framing preserves a balanced subscript and the complete
RHS as one word, even when the subscript contains spaces or operators. For
example, `a[1 + 2]=x a=(y)` is UNSUPPORTED, while `a[1 + 2]=x : a=(y)` has a
misplaced compound assignment and is INVALID. This is lexical classification;
array execution semantics remain unsupported.

Parameter and process substitutions inside a subscript own their internal
brackets and parentheses. For example, `a[${v:-]} + (2)]=x` retains one complete
assignment word: the `]` inside `${v:-]}` does not close the subscript. Its
lexical classification is COMPLETE; graph construction rejects the unsupported
array semantics rather than inventing an executable command.

Ordinary argument and redirect positions retain ordinary word boundaries rather
than assignment grouping.
Scalar-looking declaration operands also retain ordinary boundaries:
`declare a[1 + 2]=x` contains four words, whereas `a[1 + 2]=x` is one leading
assignment word. Declaration-position compound arrays such as `declare a=(x)`
remain UNSUPPORTED. An unresolved leading indexed candidate such as
`a[1 + (` is UNSUPPORTED: punctuation inside it cannot prove an outer
command-list error, and array recovery does not qualify a prefix.
A final backslash after the subscript remains unclassified because a following
LF can join the subscript to an assignment operator.
Quotes or escapes inside a subscript or compound body do not quote the outer
assignment spelling; `a=(x\ y)` remains UNSUPPORTED array syntax.

Subscript matching records nested matches and unfinished outcomes in private,
non-evicting source workspace. Later candidates reuse those boundaries instead
of rescanning overlapping suffixes. Source-byte scan work is linear, with
ordered boundary lookups; ordinary declaration words never scan into following
operands. `shell_source_workspace_size()` includes these records as well as
delimiter normalization. Public iterators keep their supplied workspace
exclusive until iteration ends; independent iterators require distinct buffers.

Bash can terminate a pending heredoc implicitly at a closed substitution's
EOF, with warnings. For example, `echo $(: <<EOF)` is valid Bash. The source
API returns UNSUPPORTED because exact implicit-termination framing is not
modeled. A missing delimiter word, as in `echo $(: <<)`, remains INVALID;
implicit document termination also cannot satisfy a missing redirect operand
or command after a connector. Open drafts retain their existing INCOMPLETE
recovery, and explicitly terminated documents retain exact framing.

An unfinished heredoc's raw content includes the received body prefix.
`confirmed_length` excludes a tentative final line that could still become its
delimiter. Apply the content helpers to a copy of `content` with that raw byte
length when processing confirmed data. Executable-child analysis visits only
confirmed body bytes. `body_started` distinguishes a later FIFO body whose
data has not begun.

The qualified `prefix` covers complete earlier top-level list units, excluding
an unfinished group, logical list, pipeline, word, or pending document. Pass it
unchanged, with the exact corresponding source prefix, to
`shell_dep_graph_parse_with_fast()` for analysis. Every outcome except COMPLETE
and INCOMPLETE clears prefix qualification and local header completeness.
Completing received syntax and deciding
whether a partial request may execute are application concerns.

At EOF, keywords which can acquire an ordinary suffix remain incomplete:
`echo ok; if` can become `echo ok; ifx`. A real word boundary commits unsupported
control syntax. After a compound, a pending numeric or `{name}` descriptor
prefix can acquire its redirect operator. Missing operands and unfinished
operand quotes/substitutions retain their appropriate diagnostics. See
`shell_source.h` for exact recovery fields and source-lifetime requirements.

## I/O resources and setup effects

Inherited full-command descriptors are `SHELL_NODE_FD` resources identified by
`node.fd.number`. Ordinary executable commands expose potential stdin reads
and stdout/stderr writes. READ edges run from resources to execution endpoints;
WRITE edges run from endpoints to resources. The execution side records the
local descriptor, and the boundary side uses `SHELL_DEP_FD_NONE`.

These edges describe available shell routing. Program behavior determines
whether bytes actually travel. Path-looking arguments use undirected ARG
relations; those relations establish argument dependencies rather than byte use.

For `wc -l file.txt 2>&1`, the WRITE edge with `source_fd == 2` targets inherited
FD 1. Source-order duplication preserves the route at copy time:

| Redirects | stdout | stderr |
|---|---|---|
| `2>&1 >out` | file `out` | inherited stdout |
| `>out 2>&1` | file `out` | file `out` |

Nested scopes share full-command inherited resources. Pipes, captures, and
collectors retain their own identities. Sharing a boundary FD represents
provenance; it does not establish an internal producer/consumer connection.

Descriptor-only `exec`, named allocations, overwritten inputs, and replaced
outputs retain FD_OPEN/FD_CLOSE setup operations. A setup edge establishes an
open/close effect; READ/WRITE/SUBST describe the effective use. Reached transient
documents retain their setup, including an append-open marker where applicable.
An unused redirect can still create or truncate a file.

Copies preserve descriptor capabilities. A live read-only descriptor can be
duplicated successfully while supplying no writable route. A self-copy such
as `9>&9` validates descriptor availability and retains setup outcomes.
Moves (`n>&m-`, `n<&m-`) preserve both the destination copy and reached source
close. Quotation matters: `"3"-` can select a move; `"3-"` is an ordinary word.

Temporary redirects restore in reverse registration order. Body operations can
overwrite or close Bash's save slots, changing or failing restoration. Cleanup
diagnostics use reached stderr while leaving the body status intact. Failed
setup suppresses later redirects and body effects but retains earlier argument
expansions, reached setup, and any diagnostics they produce.

### Named descriptors

Named-FD syntax uses a scalar binding and an adjacent redirect operator.
Backslash-LF can preserve that adjacency; literal whitespace cannot. Exact
`$fd`/`${fd}` uses follow the binding's selected descriptor rather than a copy
of its original route. Rebinding allocates another slot; unsetting the variable
leaves the physical descriptor open.

Ordinary command-bearing simple commands and foreground brace-group redirects
can retain named allocations. Redirect-only/assignment-only private execution,
pipeline elements, background commands, and subshells isolate their changes.
Temporary numeric restoration can change the resource a surviving named value
references. A failed later redirect preserves reached named allocations while
restoring applicable numeric redirects.

Unquoted numeric parameters observe IFS; quoted parameters avoid splitting.
Known ambiguous splitting fails setup; unresolved descriptor interpretations
are unsupported. High-descriptor occupancy and allocation alternatives remain
conservative within documented limits. Conditional reallocation states which
the bounded model cannot correlate are rejected.

### Groups, pipelines, background execution, and timing

Brace groups share state with their enclosing shell except when their pipeline
or background position requires a private scope. Parenthesized groups isolate
state. Redirecting away a pipe leaves the syntactic scope isolation intact.
`|&` duplicates stderr after explicit redirects.

Command-position and pipeline-prefix facts are maintained during forward
lexical iteration. Group and document metadata reuse those facts rather than
restarting at the command's beginning for each literal brace or redirect.
Emitting an inline-document fragment does not start a new command: the braces
in `: <<<x {` and `: <<<x }` are ordinary arguments. Real group delimiters keep
their surrounding pipeline and timing ownership.

Negation is structural pipeline syntax. `pipeline_negation_count` retains its
count and `pipeline_negated` its parity. Horizontal blanks and continuations
can separate `!` from a supported nonempty pipeline. Bash also accepts empty
negation at top-level EOF or before `;`, LF, or `&`; these unmodeled forms are
UNSUPPORTED. Backtick bodies have a top-level EOF, while `$(!)` and `( ! )`
are INVALID because their closing parenthesis does not terminate that empty
pipeline. A received open child such as `$(!` remains INCOMPLETE and can acquire
a stage or terminator before its closer. Empty timed forms such as `time !`
retain their supported timing semantics.
Ordinary words such as `!(pattern)` retain their own lexical interpretation.
An unquoted `!` used as a redirection operand is ordinary word data: `> !` and
`>!` select the same pathname and contribute no pipeline negation.

TIME nodes retain Bash pipeline timing and report routing. TIME edges identify
the measured command/group; report bytes use ordinary I/O edges. Reports can
reach inherited FDs, documents, captures, or multiple alternative destinations.
Closed and non-writable routes remain distinguishable. Command-local redirects
usually unwind before reporting; enclosing redirects and sole timed child
scopes follow their own lifetime. Empty timing pipelines remain structural and
policy-neutral; redirect-only timed operations still lack argv coverage.

Reserved `time` recognition follows the pinned Bash lexer as well as pipeline
grammar. `: | time :`, `: |& time :`, and `: |` followed by one LF and `time :`
invoke an ordinary command named `time`; it retains its arguments, including
an ordinary `{` word. After `|&` and LF, or `|` and two LFs, Bash recognizes
reserved `time`, which is invalid where a post-pipe command is required.
Comments contribute their terminating LF; removed continuations do not alter
that token history. Quoted or escaped spellings remain ordinary command words.

Background stdin can acquire a read-only `/dev/null` route, represented by a
shared implicit FILE document with a library-owned pathname. The graph retains
the incoming route as an alternative for failed implicit open. Explicit input
setup, including qualifying auxiliary-FD instructions, affects Bash's exemption
rules. Setup ordering differs between simple commands and asynchronous compound
wrappers. Background completion restores the parent's state and reports launch
status independently of the child's later exit.

## Builtins, state, and outcomes

State facts follow execution outcomes, scopes, and connectors. An earlier known
failure can suppress later effects. Ordinary runtime EOF, open failures, and
program status remain uncertain where the model lacks a proof.

Assignment-only commands normally use the last executed substitution's status.
An empty `$()` preserves that command's preceding substitution status;
comment-only backticks return success. Thus `a=$(false) b=$()` fails, while
`false; value=$()` succeeds. An argv-less redirect involving fd 0 or a named
descriptor can execute setup privately and return its setup status instead.

Earlier committed assignments are visible to later assignment RHS expansions.
Temporary executable prefixes have separate scalar-value and redirect/IFS
contexts. Rejected readonly writes retain syntax and reached diagnostics;
effective ENV edges represent successful assignments. Assignment-only errors
can abort an input unit; later top-level units may resume. Required-parameter
errors and explicit shell termination have their own stopping behavior.

`set`/`shopt` mutations, namerefs, readonly declarations, integer/array targets,
and protected executor-variable writes are unsupported. Documented inspection
forms remain available. Static `eval`, `let`, source loaders, traps, aliases,
history replay, completion/Readline configuration, dynamic builtin loading,
`mapfile`/`readarray`, `wait -p`, and directory-stack operations are rejected.
Actual indirect variable and array-subscript re-evaluation is likewise rejected.
Static scalar `test -v`/`[ -v … ]` queries and supported ordinary predicates
retain their argument-role analysis.

### Selected input and writes of read

Builtin `read` uses fd 0 or the last valid `-u` operand, validated in option
order after redirect setup. Argument values are captured before redirects.
Static decimal operands and supported exact scalar descriptor references retain
their descriptor identity. Earlier option or descriptor failures stop before
later input and assignment effects.

| Mode/outcome | Input flow and target effects |
|---|---|
| Ordinary read | Selected readable stream; possible input, EOF, and assignment outcomes |
| Timeout-zero polling | Availability test, with no input-byte or target-assignment flow |
| `-n0` / `-N0` | No input-byte flow; target effects follow the validated outcome |
| Invalid first identifier | Failure before input or target assignment |
| Later target failure | Earlier assignments and possible input remain represented |
| Readonly first target | Failure may follow input, with no successful target write |

Unknown numeric operands retain valid and invalid conversion alternatives.
Proven invalid integer prefixes/suffixes remain failures across opaque scalar
fragments when one argument is established. Whole-word and attached option
operands have separate roles: after `unset fd`, `read -p"$fd" -e value` consumes
`-e` as prompt data, while `read -n"$fd" -e value` is a numeric failure.
An effective Readline or array selector remains unsupported.

Timeout classification follows reference Bash rounding and unsigned conversion;
zero can arise through conversion as well as literal `-t0`. Polling bypasses
target assignment. Dynamic splitting/cardinality and unsupported runtime
descriptor operands are rejected where their semantics cannot be established.

Target writes, implicit REPLY, IFS changes, and descriptor-value invalidation
stay attached to their individual outcomes. Children can refine facts about
unchanged inherited descriptors through status, while child mutations remain
isolated. Process-substitution descriptors close according to scope; explicit
duplicates can survive the original end's cleanup.

### Other variable-writing builtins

`printf -v` selects its last valid target. Static formats track `%n`, format
reuse, and `%b`'s `\c` termination; dynamic formats conservatively invalidate
affected binding proofs. Dynamic write targets and unsupported array/attribute
operations are rejected. Documented conversion and resource limits still apply.

Declaration builtins distinguish inspection from writes. Empty process-fragment
elision precedes declaration operand recognition, while command-position lexical
assignment recognition stays fixed. Variable unsets and assignments update the
appropriate scalar capability and binding facts; physical descriptor lifetime
remains a separate concern.

## CWD and lexical path facts

`cd` is an ordinary command node with I/O and a CWD relation. Its arguments and
redirects use its incoming CWD. Static success installs the destination;
pre-change failure preserves entry. With initial CWD `/workspace`:

| Source | CWD of following cat |
|---|---|
| `cd /src && cat input` | `/src` |
| `cd /src \|\| cat input` | `/workspace` on the pre-change failure continuation |
| `cd /src; cat input` | Unknown across joined success/failure outcomes |
| `(cd /src && cat input); cat root` | Inner `/src`, final `/workspace` |

`cd -`, physical resolution, and CDPATH-selected directories can change CWD
before reporting failure. Argumentless `cd` can encounter that reporting path
with relative runtime HOME and CDPATH. Those failure outcomes conservatively
join CWD and invalidate applicable PWD/OLDPWD binding proofs. HOME, CDPATH,
physical resolution, and unresolved operands remain runtime-dependent facts.

Read `cwd_known` before using a stored CWD offset. FILE documents retain their
own expansion-time CWD facts. `shell_dep_doc_file_identity_write()` provides a
static lexical identity when available; its success and absolute/relative
classification matter. Normalization removes redundant separators and `.`
components while preserving `..`. Symlink resolution, existence, containment,
and race-free access require application filesystem checks.

## Workspace, lifetimes, and errors

Bounded parsing and graph construction use caller-provided or documented small
private scratch. `shell_source_workspace_size()` supplies a checked delimiter
normalization bound. Graph construction adds that scratch to the fixed aligned
`shell_dep_workspace_size()` prefix. Use `shell_dep_resolved_workspace_size()`
when resolving words. Allocating higher-level APIs reserve their own temporary
workspace and retain their failure-atomic output contracts.

Source spans borrow immutable input. Supplied-fast graph construction requires
the original source and unchanged parse result; their correspondence is a caller
precondition. Resolver payloads obey their documented extended borrowing lifetime.
Workspace may be reused after construction, while retained graph source and
resolved values remain alive. Expansion callbacks establish independent parsing
operations and keep their enclosing operation's facts intact.

Bounds and operational failures are observable. Exhausted scratch can require a
larger buffer; fixed node, edge, token, and depth limits require a smaller input
or a refused decision. Truncated products provide partial information. See the
public headers for each API's validity guarantees and retry behavior.
