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
Control constructs, functions, arrays, and wider conditional predicates remain
unsupported. A feature flag is recognition, not a promise of semantic support.
Shellgate's default mask also rejects arithmetic, conditional commands,
heredocs, and here-strings;
changing that mask enables only constructs the semantic model supports.

Control flags recognize complete unquoted lexical words after removal of
backslash-LF continuations. Punctuation and quoted or expanded fragments stay
within their word: `日本.if` and `日本''if` have no conditional flag. Standalone
keyword spellings remain lexical markers even in argument positions, so
`echo if` still has that flag. Comments, redirect operands, parameter operands,
arithmetic text and document text do not supply outer control words.
Executable substitutions are inspected in their own command context, including
when nested in those data operands.

Extglob words likewise contribute features from active variable, arithmetic,
command, file and process substitutions and ANSI-C quotes. Literal alternatives
such as `@(printf|cat)` contribute EXTGLOB without PIPELINE or control-word
features. In `@($(printf x | cat))`, the executable child contributes SUBSHELL
and PIPELINE. These rules apply to ordinary arguments and conditional operands;
quoting and escaping continue to determine which expansions are active.

Grammar recognition also requires an eligible, complete unquoted word before
expansion. In `fi$(printf x)`, `fi` is a fragment of an ordinary command word,
not a reserved closer; `$(printf x)fi` likewise has no standalone `fi` word.
Substitution output cannot turn an ordinary word into a reserved word.
This grammar role is distinct from lexical feature detection: `echo if` has
a conditional feature flag, but its argument is not a reserved word.

Supported composition includes simple commands, lists, `&&`, `||`, pipelines,
`|&`, background execution, brace groups, parenthesized groups, negation, and
pipeline timing. Redirection support includes files, combined output, heredocs,
here-strings, named descriptors, duplication, moves, and closes.

Extglob requires `extglob` enabled by the executor before Bash parses source.
Shell-option mutations in submitted source are rejected. Supported arithmetic
uses numeric literals, operators, and bounded nesting. Variable
lookup, dynamic arithmetic, and mutation remain unsupported, including in
substring offsets and lengths.

Arithmetic whitespace consists of space, tab and LF. Backslash-LF continues
the expression. CR, vertical tab and form feed remain significant bytes;
semantic consumers reject expressions that use them as whitespace, including
in skipped operands. Balanced source framing can still be COMPLETE. These
restrictions apply to arithmetic commands, expansions and substring operands;
the same bytes remain admitted as literal data in ordinary shell words.

### Arithmetic commands

`(( expression ))` supports the same literal-only arithmetic grammar as
`$(( expression ))`: numeric constants, pure operators, parentheses and nested
arithmetic expansions. Variable lookup, assignment, increment/decrement, arrays,
quoted operands and executable substitutions remain semantically unsupported.
Adjacent signs on literals, such as `1--2`, remain pure arithmetic; increment
and decrement require an lvalue, which this grammar excludes.

Numeric constants follow Bash's radix notation: a leading zero selects octal,
or hexadecimal when followed by `x` or `X`, and cannot prefix an explicit base.
Thus `2#01` is valid, while `02#1` is rejected by semantic consumers, including
in skipped operands, arithmetic expansions, substring operands and expandable
heredocs. Source framing can still classify these expressions as COMPLETE.

The source APIs retain Bash's arithmetic-versus-nested-subshell distinction;
`((printf ok); printf tail)` is a nested subshell command list.

Comparisons and shifts keep their arithmetic meaning next to parenthesized
operands: `((1<<(2)))` is one arithmetic command. Feature discovery inspects
arithmetic content under the same rules as arithmetic expansions, including
variables, arrays and executable children in semantically unsupported input.
An executable child establishes its own shell-command context, so its pipelines
and control words remain visible in lexical feature flags.

Executable child words and comments retain their byte domains. Literal high
bytes, including UTF-8 and invalid UTF-8, are admitted as ordinary child data.
For example, `(( $(printf 1; : 日本) ))` has COMPLETE source framing and
retains its child headers, while `(( $(printf 日本 &&) ))` is INVALID.
Unfinished children retain INCOMPLETE recovery and earlier qualified prefixes.
Arithmetic code itself retains restricted bytes, including at unfinished EOF.
Arithmetic with executable substitutions remains outside semantic support even
when its source framing is COMPLETE.

Arithmetic is an explicit command kind with an expression span and no argv
words. Retained headers mark it as compound. Graph CMD metadata exposes
`SHELL_COMMAND_ARITHMETIC` and expression truth independently of redirect
setup: ZERO means failure, NONZERO means success, and UNKNOWN retains both
continuations. These facts select subsequent `&&`/`||` paths and compose with
pipeline status, negation, grouping, timing and background execution.

Constant proofs use checked signed 64-bit arithmetic. Overflow, oversized
constants, division by zero, negative exponents and uncertain shifts remain
unproven. Shifts are proved only for nonnegative operands, counts below 63,
and representable results. Short-circuited operands are still checked for
supported grammar but contribute no evaluation uncertainty. An uncertain
arithmetic expansion remains uncertain even in a skipped operand, because
expansion precedes evaluation of the enclosing expression. An uncertain
evaluated operand also makes a later comma result uncertain. This is bounded
analysis; runtime arithmetic errors do not introduce partial-execution recovery.
Complete raw framing can therefore be COMPLETE even when semantic analysis
declines the expression. An unfinished arithmetic command is INCOMPLETE with
`SHELL_SOURCE_NEEDS_ARITHMETIC`.

Arithmetic consumes no stdin and produces no ordinary stdout. Input/output
redirects retain their setup effects even when no bytes use the installed
descriptor. Possible expression diagnostics use the effective stderr route;
redirect setup failures retain their own diagnostics. Named descriptors opened
by arithmetic commands follow the existing current-shell persistence rules.

Shellgate's default feature mask continues to reject arithmetic. When enabled,
pure arithmetic is policy-neutral and contributes no argv-policy subject.
Explicit arithmetic-owned redirects require separate coverage, including
unused descriptor copies; I/O on an enclosing group without a real argv
subject likewise remains undetermined. Arithmetic appears in anomaly stages
with one empty executable sentinel and an `AR` typed marker per command;
comparison and shift operands add no executable stages or substitution flags.
Applications inspect the expression and I/O through Shellsplit directly.

### String conditions

Conditional commands support `[[ word ]]`, `[[ -n word ]]`, `[[ -z word ]]`,
and literal or static star-pattern comparisons with `=`, `==` and `!=`.
Repeated unquoted `!` applies lexical negation. A bare word tests nonemptiness.
Operators are recognized from shell syntax, including escaped line continuations, before
expansion: `[[ '-n' ]]` tests a literal
string, while `[[ -n ]]` is missing its required operand and is INVALID.
Static right operands may combine unquoted literals, single-, double- and
ANSI-C-quoted fragments, escapes and active `*` characters. Concatenation and
escaped line continuations are supported: `[[ xy == 'x'"y" ]]`,
`[[ release == release ]]` and `[[ file.txt == *.txt ]]`.
An active star matches any byte sequence, including empty strings, slashes and
newlines; the whole subject must match. Quoted or escaped stars are literal:
`[[ x == "*" ]]` is false, while `[[ '*' == "*" ]]` is true.
Mixed quoting retains each fragment's meaning: `"file-"*` matches that prefix,
and `$'*'*` matches a literal star followed by any suffix. Adjacent active
stars are equivalent to one. Matching uses byte strings and bounded linear
work under the fixed executor contract, independently of the host locale.
The executor keeps `nocasematch` disabled. Lexical unary operators take
precedence over binary comparison parsing.

Dynamic right operands may combine static literal text with quoted expansions:
`[[ "$name" == "$prefix".txt ]]` and `[[ "$mode" == release-"$arch" ]]`.
Expansion-generated bytes remain literal, including `*`, `?` and brackets;
quoted command substitutions follow the same rule. Static text may contain
quoted or escaped pattern characters, but it must not contribute active
pattern syntax.
Unquoted expansions such as `$pattern`, mixed dynamic patterns such as
`"$prefix"*`, and active runtime tilde prefixes remain UNSUPPORTED. Quoting
that cancels tilde expansion is supported: `~"$suffix"` has a literal tilde,
while `~/"$suffix"` still requires tilde expansion and remains UNSUPPORTED
as a right operand.
Quoted or escaped `?`, brackets and parentheses remain literal bytes. Unquoted
`?`, `[`, and extglob syntax remain outside this increment, including an
unmatched `[` that Bash would treat literally.

Internal boolean combinations, parenthesized conditions, wider patterns, regex,
ordering/numeric comparisons and other filesystem/variable-attribute predicates
remain UNSUPPORTED.
Lists and existing outer `&&`/`||` connectors compose supported conditions.

Newlines and comments are permitted before a primary, after lexical `!`, and
after the operand of an explicit unary predicate or the right operand of a
comparison. They are not permitted between a left operand and its comparison
operator or between that operator and its right operand. A bare operand requires
the following token without an intervening newline or comment: `[[ x` followed
by a newline is INVALID, including an unfinished draft. In contrast, `[[ -n x`
followed by a newline remains INCOMPLETE until its closing delimiter arrives.
Blanks and escaped line continuations remain permitted in both forms; quoted
newlines inside an operand are string data. Comments are grammar trivia:
expansion-like text within a comment contributes no executable children,
expansion features or dependencies. Substitution validation examines the
operand spans, while the conditional parser owns comment and delimiter framing.

Operands use Bash's conditional string expansion. Word splitting, pathname
expansion and brace expansion are suppressed; `{,}` remains a literal string.
Stars are literal in unary operands and comparison left operands. Active stars
in supported comparison right operands perform pattern matching as described
above; quoted and escaped stars remain literal.
Tilde expansion remains dynamic both at the start of a word and in
assignment-shaped operands such as `name=~`, `name+=~`, `name=prefix:~` and
`arr[0]=~`. These operands are strings; they do not assign variables. Quoting or
escaping a tilde, or quoting part of its prefix before the terminating slash,
colon or word end, keeps that prefix literal: `name=~''` compares as `name=~`.
Unresolved tilde expansions retain UNKNOWN truth and the unresolved-condition
flag until the application supplies their values through the conditional
expansion callback. Existing supported
parameter, arithmetic, command, backtick and process substitutions retain their
source and dependencies. Their existing semantic restrictions still apply.
Condition syntax and values use the fixed byte rules of the executor contract.

Conditional metadata has kind `SHELL_COMMAND_CONDITIONAL`, an expression span,
`conditional_operands[2]` in source order, `conditional_operand_count`, a
normalized `conditional_predicate`, lexical `conditional_negated` parity, and
no argv. Complete unary conditions have one operand; comparisons have two.
Drafts retain the received operands, including an unfinished final word. Bare
words normalize to STRING_NONEMPTY. Comparisons with literal-only RHSs use
STRING_EQUAL or STRING_NOT_EQUAL; active static stars use PATTERN_MATCH or
PATTERN_NOT_MATCH. The expression preserves original spelling. Graph
`conditional_truth` is FALSE, TRUE or UNKNOWN
before setup/expansion failure. Static effective operand values establish
predicate truth; dynamic values remain unknown unless supplied through the existing
resolution callback. `SHELL_EXPAND_WORD_CONDITIONAL` requests one final NUL-free
string record, including `0:,` for an empty value. The callback performs the
conditional expansion and any joining of positional values; zero or multiple
records are expansion errors. Dynamic operands in literal comparisons are
queried separately; each request covers the whole original operand, including
any static prefix or suffix. Return one complete composed string rather than
values for individual fragments. Static star patterns query only a dynamic
left operand. Return ordinary final string bytes, without pattern escaping.
Callback data is never parsed as shell syntax. An unresolved value on either
side retains UNKNOWN comparison truth.

The predicate's truth refines subsequent continuations. A command substitution's
exit status does not determine the string predicate: `[[ -n $(false) ]]` is
false because its output is empty. Unresolved operand values retain both
return outcomes. This model adds no runtime partial-execution recovery.

Bash installs conditional redirects before expanding operands. The left
operand's synchronous expansions finish before the right operand is queried or
inherits descriptors. Nested substitutions retain relevant earlier descriptor
observations and installed redirects; a proven setup failure
prevents their effects. For example, in `[[ -n $(cat) ]] <<<payload`, the nested `cat`
receives the here-string. The condition itself
consumes no stdin and produces no ordinary stdout. An unflagged process SUBST
route into the conditional records its descriptor-resource dependency; the
predicate tests the generated filename string without reading that stream.
Redirect setup, diagnostic routes and process-descriptor lifetime remain
distinct from byte use.

Retained drafts expose received operands and executable children. An unfinished
committed condition uses `SHELL_SOURCE_NEEDS_CONDITIONAL`; earlier complete
top-level units can still qualify as an analysis prefix. Received EOF can split
an expected grammar token: `[[ x == "x" ]` remains INCOMPLETE until another `]`
arrives, and an operator-position `!` can still become `!=`. A final backslash
can acquire LF before, within or after an expected token. Only prefixes reaching
EOF retain this recovery: whitespace committing a lone `]`, extra literal
bytes and prohibited raw newlines retain their existing error classifications.
Partial grammar tokens do not become operand records.

Thus `printf before; [[ x == "x" ]` retains the qualified `printf before;`
prefix. An open executable substitution retains its outer incomplete-input
diagnostic and its local incomplete conditional header. A closed child commits
its received bytes: appending outside its delimiter cannot repair an unfinished
conditional token, so that child is INVALID. Strict graph and processor APIs
continue to reject incomplete source. A received final `[[` can acquire an
ordinary-word suffix and retains NEEDS_COMMAND until committed.

`SHELL_FEAT_CONDITIONALS` includes conditional commands, so the default gate
mask rejects them. With the feature enabled, a condition is policy-neutral.
Active RHS stars additionally set `SHELL_FEAT_GLOBS` and honor its rejection mask.
The condition's own redirects and uncovered enclosing-group I/O remain undetermined.
Nested executables still require argv-policy matches. Unresolved condition
values in either operand set `SG_EXPANSION_UNRESOLVED_CONDITION`, independently of unresolved
argv/paths and substitution-inspection requirements. Anomaly sequences retain
one empty executable with the `CT` marker per conditional stage.

### Filesystem predicates

Conditional commands, `test`, and `[` support the filesystem predicates `-e`
(existence), `-f` (regular file), `-d` (directory), and `-L` or `-h` (symbolic
link). The first three follow symbolic links; `-L` and `-h` inspect the link
itself. Shellsplit does not query the host filesystem: nonempty paths have
unknown truth, while an empty path is false. Lexical negation reverses truth.
For `test` and `[`, the unary `-a` alias also tests existence; argument-count
and expression grammar distinguish it from the binary `-a` conjunction.
Other filesystem operators accepted by those builtins remain opaque and do not
produce FILE_TEST edges. Applications requiring complete metadata-check
coverage must handle those operators conservatively.

A `SHELL_EDGE_FILE_TEST` edge points from the command to a FILE document. Its
flags identify possible predicate kinds; multiple flags can occur where a
dynamic builtin argument may occupy an operator position. Only words selected
as operands by a retained grammar alternative receive these relations; the
bracket terminator and words with fixed operator roles are excluded. The document
retains the source spelling and CWD, and a resolved pathname when supplied through the
expansion callback. Captured builtin argument values refresh the prepared
expression before body snapshots use it: resolving an operator to `-n` removes
filesystem alternatives, while resolving it to `-e` selects an existence check.
An unresolved lookahead can be a binary operator even after a unary-looking
word, so it cannot by itself establish a definite argument failure. Projection
preserves the expression boundary used by Bash's argument-count dispatch:
at that boundary, `-e =` tests the pathname `=`, and a lone `-e` tests a nonempty
string. Argument-count shortcuts inside parentheses consume their selected
operands directly. A fallback to general expression parsing still sees the
closing parenthesis as lookahead, including a four-argument fallback. If it
consumes that candidate closer as data, the group checks the next unconsumed
token for its actual closing parenthesis. A definite grammar failure stops
enclosing parsing; the cursor never rewinds to replay a consumed suffix. This
edge records a possible metadata check, not a content READ. Applications must
authorize such checks separately from argv-policy matching. A dynamic unresolved
path contributes `SG_EXPANSION_UNRESOLVED_PATH`. An argument callback can return
embedded NUL bytes, but such a value cannot name a filesystem path; its FILE
document retains an unresolved pathname instead of a resolved value.
Direct Shellsplit consumers receive the same pathname uncertainty through the
optional `unresolved_paths` output of `shell_dep_graph_parse_resolved()`, indexed
by the owning command. Reached predicates retain this flag if output capacity
prevents their FILE_TEST relation from being stored.
The flags `SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS`,
`SHELL_DEP_EDGE_FLAG_FILE_TEST_REGULAR`,
`SHELL_DEP_EDGE_FLAG_FILE_TEST_DIRECTORY`, and
`SHELL_DEP_EDGE_FLAG_FILE_TEST_SYMLINK` identify the individual checks.

### Scalar variable presence

`[[ -v CONFIG ]]` tests whether the statically named variable has an assigned
value. Empty strings count as set: `CONFIG=; [[ -v CONFIG ]]` is true, while
`unset CONFIG; [[ -v CONFIG ]]` is false. Static ASCII identifiers may combine
quotes, escapes and literal fragments. Dynamic names, positional-number
operands and subscript syntax remain outside this conditional increment.
An unquoted lexical `-v` selects VARIABLE_SET; `[[ '-v' ]]` retains its ordinary
string meaning. Existing negation, comments, continuation and draft rules apply.

The graph tracks SET, UNSET and UNKNOWN independently of variable contents and
physical descriptors. Successful assignments and named-descriptor allocations
establish SET.
Attempted writes to Bash's nonassignable predefined arrays (`FUNCNAME`,
`GROUPS`, `BASH_ARGC`, `BASH_ARGV`, `BASH_SOURCE` and `BASH_LINENO`) preserve
their prior presence, including UNKNOWN. Temporary prefixes and earlier
assignment RHS overlays follow the same rule. `read` can consume input and
complete earlier assignments before stopping at such a target; later targets
remain unchanged. `printf` format writes and `getopts` implicit updates retain
their independent effects. This assignment restriction is distinct from
`readonly` and does not imply an input-unit abort.
Successful whole-variable `unset` removes the special capabilities of
`FUNCNAME` and `GROUPS`, so later writes create ordinary scalars. Bash rejects
whole-variable unsets of the other four names. These capabilities follow each
execution path and the existing isolated-scope rules.
Unknown-target unsets retain uncertainty about removal of resettable
capabilities. Known operands in the same invocation still apply in argument
order, so `unset -- "$name" FUNCNAME` makes FUNCNAME an ordinary scalar regardless
of which variable the unknown operand names. When later behavior depends on
an uncertain restriction, the graph retains the assignable and nonassignable
alternatives with their corresponding continuations. Arbitrary value writes
through `read` or `printf` do not remove these capabilities.
An unknown operand in option position can instead select function unsetting
or fail option parsing; later variable unsets then remain possible effects.
Only installed temporary bindings are restored after a builtin. For example,
the ignored prefix in `FUNCNAME=value unset FUNCNAME` creates no temporary
binding, so the unset removes the original special variable. The same prefix
after successful despecialization installs an ordinary temporary scalar and
retains the existing restoration rules.
Declarations without values preserve prior presence. Existing per-outcome
write rules apply to `read`, `printf`, `getopts`, declaration assignments and
implicit state updates. In particular, `cd` assigns OLDPWD from the previous
presence of PWD on each successful execution path, and getopts can assign or
unset OPTARG. When paths with different PWD presence reach `cd`, their OLDPWD
results retain those differences and their correlations with other variables.
A temporary `PWD=` prefix supplies a set entry value to that invocation.
`getopts` updates OPTIND before assigning its destination. Its OPTARG update
comes before the destination assignment for normal options and end-of-options,
but after it for invalid options and missing arguments. Non-silent error paths
unset OPTARG after assigning the destination, including when the destination is
OPTARG itself. The graph summarizes final presence without simulating runtime
option scanning: a definite OPTARG destination is SET when every possible
optstring has a provable leading `:`, and UNKNOWN otherwise. This conservative
result also applies to non-silent invocations whose concrete outcome leaves
OPTARG set. Invalid destinations still permit implicit updates. Dynamic option
strings can fail before any update or select another destination position;
possible writes join the prior presence rather than establishing an
unconditional SET fact.
A successful named allocation establishes
SET during redirect setup, including on a continuation after a later redirect
fails. Closing the descriptor preserves that presence; unsetting its variable
removes it. Existing isolated-scope rules still determine publication.

Initial presence is SET for LC_ALL, UID, EUID, PPID, SHELLOPTS and BASHOPTS.
The executor clears POSIXLY_CORRECT, BASH_COMPAT and BASH_XTRACEFD before freezing
them, so they start UNSET. Other inherited scalar names start UNKNOWN.
Subsequent operations use their modeled mutation rules. Bare predefined array
names retain uncertainty about Bash's default-element test; this adds no
array-subscript evaluation.
Temporary command-prefix bindings are visible to a builtin and are restored
according to existing declaration-promotion rules. Brace groups share state;
isolated scopes inherit presence without publishing their writes to the parent.
The selected outcome of a presence test refines later continuations when it
implies a fact about an unchanged binding.

VARIABLE_SET retains the original operand in conditional metadata. Its
TRUE/FALSE/UNKNOWN truth comes from graph state and makes no expansion callback.
Unknown presence does not set SG_EXPANSION_UNRESOLVED_CONDITION: that flag
continues to describe unresolved expanded strings. Applications inspect the
graph's truth when they need presence certainty.

The Bash `test` and `[` builtins use these same presence facts, including
compound expressions with `!`, `-a`, `-o` and parentheses. Their grammar follows
argument count and effective argv bytes, so a quoted `'-v'` can still be an
operator. The required final `]` and the reference Bash's special handling of
small parenthesized expressions remain significant. They retain SIMPLE command
kind, argv and ordinary policy subjects; conditional metadata is not populated
for them. Internal Boolean combinations in `[[ … ]]` remain unsupported.

Pinned Bash 5.3.20's one-argument dispatch uses the invocation's first argument,
even when a parenthesized subexpression selected that dispatch. Consequently,
`test '' -o '(' x ')'` is false and `test x -a '(' '' ')'` is true. The separate
three-argument parenthesis shortcut uses its local operand: `test '(' '' ')'`
is false. The graph follows these distinctions when selecting continuations
and retaining their I/O dependencies. Literal tests establish their result
before successor construction, including when no expansion or redirect needs
a state snapshot. The same rules apply to `[ … ]`.

Builtin test evaluation is eager. Argument substitutions and reached predicates
remain represented even when another operand determines a Boolean result.
Possible predicate errors are separate from false values: `test x -o 1 -eq
invalid` fails with an argument error despite its nonempty first operand.
Known string tests and literal comparisons contribute truth; other supported
predicates remain conservative, including error alternatives where applicable.
Uncertain operator roles never produce a truth proof. Existing rejection of
potential array-subscript re-evaluation applies throughout these expressions.

The terminal predicate `test -t fd` validates a signed decimal integer, with
surrounding ASCII whitespace allowed. Invalid or overflowing operands cause a
builtin argument error; terminal status remains UNKNOWN. In general expressions
with at least four effective arguments, `-t` immediately before `-a` or `-o`
tests fd 1 and leaves that word as a connector. The full expression's argument
count controls this rule even inside parentheses; `[` excludes its closing
`]`. The ordinary small-argument dispatch and binary-operator precedence still
apply. For example, `CONFIG=; test -t -o -v CONFIG` succeeds, whereas
`CONFIG=; test -t invalid -o -v CONFIG` fails with an argument error. Dynamic
operands retain possible error and grammar alternatives, including admission's
checks for any reachable subscript reevaluation.

Small parenthesized expressions apply the same argument-count dispatch during
admission and evaluation. For example,
`test '(' -t -o ')' -o -v 'a[$(printf marker)]'` fails while requiring the inner
closing parenthesis, before evaluating `-v`; its quoted operand remains literal.
The graph accepts this source with a failure-only builtin outcome. An unsafe
lookup reached before a later argument error remains unsupported. Ordinary
argument substitutions still execute before the builtin examines its arguments,
so their dependencies remain represented even when that builtin must fail.
The same dispatch applies when a dynamic terminal operand can make the group
an alternative primary. A lookup is rejected if any viable interpretation
reaches its unsupported operand; an error proved on every path yields only a
failure continuation.

Presence queries and builtin test bodies consume no input bytes and produce
no ordinary stdout. Redirect setup, nested substitutions and possible stderr
diagnostics retain their own effects. Neither an unset variable nor a variable
holding a closed descriptor causes a synthetic fd-0 READ edge.
Filtering, read effects and scope cleanup preserve associations between presence
and descriptor facts, including when only one execution version survives.
Resource truncation remains sticky through those transformations.

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

Ordinary literal word content, whether unquoted, escaped, single-quoted,
double-quoted or ANSI-C quoted, preserves high bytes exactly, including invalid
UTF-8. This applies to command names, arguments, assignment values and filenames,
including concatenated fragments such as `pre'日本'".txt"`. Offsets and lengths count source bytes;
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

ANSI-C quotes combine literal bytes with static escape decoding:
`$'日本\t語'` contains the original Japanese bytes separated by one tab.
Concatenated fragments, assignment values and filenames use the same rules.
For the control escape `\c`, a doubled backslash is one operand: `$'日本\c\\X'`
decodes to the Japanese bytes, byte `0x1c`, and `X`. An apostrophe protected by
the consumed backslash remains literal: `$'日本\c\'X'` additionally contains
an apostrophe before `X`. Canonical arguments and heredoc delimiter
normalization use the same decoder; raw control bytes in source retain their
admission restrictions.
Arithmetic, substring arithmetic and selectors retain their restricted code
domains even when their text contains ANSI-C quotes. Complete-command semantic
APIs apply Bash's fragment-local NUL truncation: `$'before\0after'` contributes
`before`, `pre$'a\0b'post` contributes `preapost`, and an argument spelled
`$'\0'` remains present with an empty value. The complete quoted spelling still
determines lexical boundaries and source offsets. Discarded text contributes
no substitutions, builtin operands, or pathname bytes. Static file identities
and Shellgate's static path-fragment checks use the effective concatenated
value: discarded text cannot match a path fragment, while text after the
closing quote can. Surviving non-ASCII
`\u`/`\U` escapes remain locale-dependent and unsupported; an escape after
the first NUL is discarded with the rest of that fragment.
Double-quoted parameter defaults and alternates with decoded NUL, such as
`"${v:-$'a\0b'}"` and `"${v#${u:-$'a\0b'}}"`, remain semantically
unsupported. Pattern operands establish ordinary quoting for their own
fragments, but nested defaults and alternates still inherit the enclosing
double quote. Their translation can truncate parameter syntax and cause a
runtime Bash substitution error. Source
classification continues to distinguish recognized grammar from supported
semantics; this restriction adds no execution or runtime-error model.
Without decoded NUL, executable substitutions in those nested defaults remain
visible: `"${v#${u:-$'$(printf child)'}}"` contains a conditional `printf`
child. The direct pattern `"${v#$'$(printf literal)'}"` and the unquoted
`${v#${u:-$'$(printf literal)'}}` instead contain literal ANSI-C data.
The ANSI-C decoding phase also applies inside nested parameter words within
that fragment. Before a raw `$()` opener, backslash counts congruent
to 0 or 3 modulo 4 expose the opener after ANSI-C decoding and parameter-word
expansion; residues 1 and 2 keep it literal. For example,
`"${v:-$'${w:-\\\$(printf child)}'}"` contains a conditional `printf` child,
whereas the same spelling with two backslashes leaves the command text literal.
Nested operands retain their own quote and delimiter rules. After the fragment
ends, subsequent text uses its containing parameter's ordinary expansion rules.
That second expansion can concatenate a fragment value with neighboring text
and form a parameter, arithmetic, command, or process-substitution opener that
has no contiguous raw source span. Such reconstructed syntax is UNSUPPORTED,
as is expansion framing that begins in a fragment and closes outside it. For
example, `"${0:+$'$'(printf child)}"` and `"${0:+$'$'$'{PATH}'}"` are declined
rather than publishing retained products that omit the decoded expansion.
Quoted byte content, an escape that protects the candidate opener, or
intervening whitespace remains a boundary and keeps the text literal. Empty
double quotes are transparent in an inherited shell double-quoted default:
`"${0:+$'$'""(printf child)}"` reconstructs a command substitution and is
unsupported. Ordinary-word and heredoc operands preserve that quote boundary,
so `"${0#${0:+$'$'""(printf child)}}"` is supported literal text with no child
command. Empty ANSI-C fragments, including values truncated to empty by a
decoded NUL, preserve a pending opener in re-expanded words. Detection carries
only the possible final opener byte while walking fragments forward; it does
not build decoded source or rescan prefixes.
Parameter patterns establish ordinary shell-word parsing, which nested defaults
and alternates inherit until an explicit double quote intervenes. For example,
`"${0#${0:+$'<(printf child >&2)'}}"` contains a conditional process child;
the direct double-quoted default `"${0:+$'<(printf literal >&2)'}"` keeps
the process text literal. Raw process substitutions follow the same parsing
context. Within re-expanded ANSI-C text, the backslash-residue rule also applies
to `<(` and `>(`. Explicit double quotes suppress process substitution both
inside nested operands and directly within the re-expanded ANSI-C value. For
example, `"${0#${0:+$'"<(printf child >&2)"'}}"` contains no executable child.
Command and backtick substitutions still expand within that quoted text:
`"${0#${0:+$'"<(printf literal $(printf child))"'}}"` contains only the inner
`printf child` command. Closing the quote restores process-substitution
recognition for subsequent unquoted text in the same value.
Executable children are parsed independently from their retained raw bodies.
ANSI-C decoding must leave each such body byte-identical. A body containing
paired backslashes, for example
`"${v:-$'$(echo "\\\$(printf child)")'}"`, requires decoded source and is
unsupported. A single backslash before raw `$()` is unchanged by ANSI-C
decoding and remains supported; the child's own quoting then determines
whether its nested dollar is literal. Other semantic restrictions still apply.
Harmless data escapes outside an executable child's body do not require a
translated child span. For example,
`"${0#${0:+$'$(printf child >&2)\n'}}"` retains the `printf` child with its
original source offsets; the trailing `\n` belongs to the surrounding word.
The same distinction applies to backtick children and deferred heredoc words.
An escape such as `\x69` inside `printf ch\x69ld`, however, changes the retained
child body and remains unsupported, including before a discarded NUL tail.
An unquoted heredoc body has its own expansion rules, not an enclosing shell
double quote. A pattern reached directly from that heredoc phase establishes
ordinary word parsing. A nested default or alternate below that pattern can
then re-expand ANSI-C text. Re-expansion remains active for the next nested
operand; a word continues the active path, while consecutive pattern operands
require another intervening word before they regain it. In an unquoted heredoc,
`${0#${0:+${0#$'$(printf child >&2)'}}}` therefore contains a conditional
`printf` child, as do its backtick and process-substitution forms.

The phase depends on every operand boundary, not merely on having a heredoc
ancestor.
If an ordinary heredoc parameter word is selected before entering a pattern,
that pattern and its nested words cannot reactivate deferred heredoc expansion.
For example, `${0:+${0#${0:+$'$(printf child >&2)'}}}` contains no child. The
analogous ordinary unquoted or double-quoted shell word also keeps the
innermost ANSI-C fragment literal.

Within an active pattern-derived phase, decoded NUL truncates its ANSI-C
fragment without making the enclosing parameter unsupported. The discarded
tail contributes no child commands; complete substitutions before the NUL
remain visible. A NUL cutting through an expansion within that prefix remains
semantically unsupported because its translated source cannot be represented
by the retained raw span. An explicit double quote around a nested parameter
stops the deferred heredoc phase from reaching its pattern operands. For
example, `${0#"${0:+${0#$'$(printf child >&2)'}}"}` in an unquoted heredoc
contains no executable child. Immediate double-quoted defaults still expand
their own raw command and backtick substitutions. A pattern within a quoted
heredoc operand also resets the quote inheritance used by deeper defaults:
`${0:+"${0#${0:+$'$(printf child >&2)'}}"}` contains no child. The analogous
ordinary shell word `"${0#${0:+$'$(printf child >&2)'}}"` retains its child.
An explicit quote introduced after the heredoc pattern establishes its own
immediate expansion context, so `${0:+"${0#"${0:+$'$(printf child >&2)'}"}"}`
contains the child. Ordinary raw substitutions in those deeper defaults also
remain active. These distinctions apply to command, backtick and process
substitutions, with process substitution suppressed inside an explicit quote.
Closing the quoted operand
restores the parent phase for subsequent unquoted operands. The scanner saves
operand provenance separately from active ANSI-C fragment bounds, preserving
exact child source spans and restoring the containing context when a scope
closes.
Other double-quoted parameter operands retain their existing expansion
rules; encoded executable syntax requiring decoded source remains unsupported.
Octal byte escapes are truncated modulo 256: `\444` produces the same `$`
byte as `\044`. In a double-quoted parameter operand, ANSI-C decoding precedes
another expansion. A spelling such as `"${v:-$'日本\444(printf child)'}"`
therefore returns UNSUPPORTED, just like its `\x24` equivalent. This preserves
the graph's raw-source contract instead of omitting the decoded nested command.
The same escape in an ordinary ANSI-C word remains literal word data.
The standalone decoded-word APIs preserve binary bytes, including decoded NUL
and its tail. `shell_visit_static_word()` instead exposes the effective static
Bash value, including fragment truncation. Canonical source-derived argv uses
that same effective value; directly supplied binary payloads retain their
explicit lengths. Locale-translated `$"…"` source is unsupported.
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
operands. `shell_source_workspace_size()` includes these records and the other
source-analysis scratch described below. Public iterators keep their supplied
workspace exclusive until iteration ends; independent iterators require
distinct buffers.

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
stay attached to their individual outcomes. Known-empty unquoted words can
disappear without losing later target writes anywhere within the supported
command-token capacity. A later target failure retains the earlier assignments
and prevents assignment to subsequent targets. Children can refine facts about
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

The fixed command-token capacity and default graph limit are 48. Graph
preparation counts assignment prefixes, redirection operators and operands
alongside command words. Retained source headers likewise have space for 48
source words, with redirects stored separately. These are analysis resource
bounds, independent of final argv cardinality after expansion. Smaller graph
limits remain configurable; exceeding a capacity reports truncation rather
than a Bash syntax error.

Bounded parsing and graph construction use caller-provided or documented small
private scratch. `shell_source_workspace_size()` supplies a checked capacity
bound for source analysis: delimiter normalization, persistent subscript
boundaries and conditional-pattern evaluation. Graph construction adds that
scratch, including decoded builtin-test arguments, compiled expressions and
bounded ambiguous-grammar projection, to the fixed aligned
`shell_dep_workspace_size()` prefix. Patterns and builtin
tests can require this tail even without heredocs. Use
`shell_dep_resolved_workspace_size()` when resolving words. Allocating
higher-level APIs reserve their own temporary workspace and retain their
failure-atomic output contracts.

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
