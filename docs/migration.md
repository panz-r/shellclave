# API migration notes

These notes describe changes relevant to existing consumers. The public headers
define the current API; rebuild consumers after updating the library.

## Unreleased: exact conditional string comparisons

Conditional commands now support `=`, `==` and `!=` with a right operand made
entirely from single-, double- or ANSI-C-quoted fragments. Concatenation and
escaped line continuations between fragments are supported. Unquoted and
partially quoted right operands remain unsupported, even without wildcard
characters. Keep the executor's default `nocasematch` setting disabled.

Replace singular `conditional_operand` and `conditional_operand_length` fields
with `conditional_operands[2]`, `conditional_operand_lengths[2]` and
`conditional_operand_count` in graph and owned processor results. Retained
headers use `conditional_operands[2]` source spans and the same count. Complete
unary predicates have one operand; comparisons have two. Incomplete headers
retain received operands. Nonconditional entries leave these fields zero.

The shared `shell_conditional_predicate_t` describes normalized STRING_NONEMPTY,
STRING_EMPTY, STRING_EQUAL and STRING_NOT_EQUAL predicates; `conditional_negated`
records lexical `!` parity. Bare words normalize to STRING_NONEMPTY, and `=`/`==`
to STRING_EQUAL. Rebuild consumers for changed public layouts. Existing CT
anomaly records, callback purposes and feature masks are unchanged.

Each operand uses the existing CONDITIONAL callback purpose, requiring one
NUL-free string record without pattern escaping. Left operand expansions finish
before right operand value requests and descriptor imports. Unresolved values
on either side set the existing unresolved-condition flag; substitution
inspection remains independent of resolution.

Assignment-shaped conditional operands now use the shared tilde-expansion
classification, including scalar, append and indexed spellings. For example,
`[[ name=~ == 'name=~' ]]` retains UNKNOWN truth until its left operand is
resolved; it no longer compares the unexpanded spelling as a static value.
Quoted or escaped tilde prefixes remain literal. Callback eligibility and the
unresolved-condition flag follow the same classification.

Draft framing now preserves partial conditional closers and comparison operators
at received EOF, including pending backslash-LF continuations. For example,
`printf before; [[ x == "x" ]` is INCOMPLETE with NEEDS_CONDITIONAL and retains
its earlier qualified prefix. Operand metadata excludes partial grammar tokens.
Whitespace or other bytes committing an invalid token prevent this recovery.
Open substitutions retain their outer diagnostic; already-closed children with
unfinished conditional tokens remain INVALID. No additional API fields are
needed, and strict analysis still rejects incomplete source.

## Unreleased: unary conditional commands

`[[ word ]]`, `[[ -n word ]]` and `[[ -z word ]]` now have an explicit
`SHELL_COMMAND_CONDITIONAL` kind. Repeated lexical negation is supported.
Existing word expansions use conditional string semantics, with no splitting,
globbing or brace expansion. Wider conditional predicates remain unsupported.

Feature discovery now includes active expansions inside extglob words, for
ordinary arguments and conditional operands alike. Gate rejection masks apply
to those expansions and their executable children. Literal pattern alternatives
retain their existing EXTGLOB classification without introducing pipeline or
control-word features. Public feature-bit values and default masks are unchanged.

Bare-word predicates reject a newline or comment before the closing delimiter,
including in unfinished drafts. Explicit `-n`/`-z` predicates permit trailing
newlines and comments; quoted newlines and escaped continuations retain their
existing meanings. Comments inside supported conditions remain grammar trivia,
including text resembling malformed substitutions or closing delimiters.
Only actual operands contribute expansions and dependencies. Invalid input has
no qualified analysis prefix.

Retained headers, owned processor results and graph command metadata expose
conditional expression and operand spans. Graphs expose `conditional_truth`
independently of setup failure. Conditional entries have no argv; argv-only
sequences omit them, while anomaly sequences use an empty executable and `CT`.
Rebuild consumers for the new public layouts and appended enum values.

The graph field `arithmetic_has_redirections` is now `has_redirections` and
reports explicit setup for all command kinds. Update field accesses. Existing
arithmetic expression and truth fields retain their meanings.

Expansion callbacks handle the appended `SHELL_EXPAND_WORD_CONDITIONAL`
purpose by returning exactly one NUL-free canonical string record; use `0:,`
for empty. Return UNRESOLVED when a value cannot be established. Invalid
framing or cardinality returns the existing expansion error. Conditional
redirects precede operand expansion, including nested substitution execution.

The existing `SHELL_FEAT_CONDITIONALS` bit now includes `[[ … ]]`; its default
gate rejection remains enabled. Pure supported predicates are policy-neutral
when enabled, while nested argv commands retain their policy requirements.
Inspect the new `SG_EXPANSION_UNRESOLVED_CONDITION` bit alongside existing
independent result signals. Resolution does not discharge substitution inspection.

## Unreleased: arithmetic commands

Literal-only Bash arithmetic commands `(( expression ))` are now supported.
They share numeric grammar with arithmetic expansions and substring operands.
Checked constant proofs refine zero/nonzero status; uncertain evaluation keeps
both outcomes. Dynamic and mutating arithmetic remains unsupported. Source
framing remains distinct from arithmetic evaluation and its possible errors.

Arithmetic whitespace now matches Bash's space/tab/LF set. CR, vertical tab
and form feed no longer count as whitespace in commands, expansions or
substring operands. Semantic consumers reject affected expressions with
`SHELL_DEP_EPARSE` or `SHELL_PROCESS_EPARSE` and empty outputs, while balanced
source framing remains COMPLETE. This prevents false success proofs from
discarding reachable failure continuations. Ordinary word data and
backslash-LF continuation handling are unchanged.

The shared numeric scanner now rejects explicit bases with a leading zero,
such as `02#1`, rather than deriving a false zero/nonzero proof. Graph
construction returns `SHELL_DEP_EPARSE` and canonical-sequence builders return
`SHELL_PROCESS_EPARSE`, with empty outputs in both cases. Valid leading zeros
in the digits, such as `2#01`, retain their existing meaning; raw source framing
remains COMPLETE.
Feature discovery advances over consumed numeric prefixes even when they are
invalid, keeping long malformed numbers from triggering repeated suffix scans.

Arithmetic-command byte admission now follows scoped expansion rules.
Executable children admit literal high bytes in words and comments, while the
surrounding arithmetic code keeps its ASCII restriction. Admitted child data
therefore preserves COMPLETE, INVALID and INCOMPLETE grammar outcomes and
retained child headers. Arithmetic with executable substitutions remains
semantically unsupported.

Command forms now have a shared `shell_command_kind_t` discriminator. Fast
ranges, tokenized and processed commands, retained headers and graph CMD
metadata distinguish arithmetic from simple commands. Retained container
headers use GROUP. Arithmetic headers and command metadata expose expression
spans; graph CMD metadata additionally exposes expression truth and explicit
redirect presence. Arithmetic is compound syntax without argv words, not a
subshell scope. Rebuild C and C++ consumers for these public layout additions.

Processed-command arrays now retain arithmetic entries with no command tokens.
Group command intervals index that expanded collection. Argv-only sequence
builders omit arithmetic and keep their counts limited to argv records;
direct argv rendering returns an empty value. Anomaly sequences retain one
arithmetic stage with an empty raw executable and typed `[empty, AR]` signature.
Existing anomaly models remain readable; arithmetic introduces new sequences
which applications can learn through the existing anomaly API.
Arithmetic command bodies retain their arithmetic expansion context in feature
discovery, abstraction and anomaly collection. Adjacent comparisons and shifts
produce one arithmetic stage without phantom process-substitution commands.
Fast feature flags also retain nested variables and executable-child features
when the arithmetic expression is outside semantic support.

`SHELL_FEAT_ARITH` now covers commands as well as expansions; the default gate
mask remains restrictive. Enabling arithmetic makes a pure arithmetic command
policy-neutral, while its explicit redirects or uncovered enclosing-group I/O
leave policy classification undetermined. No arithmetic record is passed to
Shelltype as a fictitious executable. Incomplete arithmetic has the appended
`SHELL_SOURCE_NEEDS_ARITHMETIC` diagnostic kind. Existing token enum values
remain stable, with the arithmetic-command token appended before TYPE_COUNT.

## Unreleased: typed source admission

Comments now admit literal high bytes, including invalid UTF-8. Their existing
raw-LF/EOF boundaries and source offsets are preserved. Comment-only source is
COMPLETE and policy-neutral; comment text contributes no argv subjects or graph
effects. Whole-source NUL, prohibited-control-byte and DEL restrictions still
apply, and later syntax, unsupported code and resource limits retain their own
outcomes.

Ordinary words now admit literal high bytes in unquoted, escaped, single-quoted
and double-quoted fragments, including invalid UTF-8 and concatenations.
Both `printf '%s' 日本` and `printf '%s' '日本'` are COMPLETE and available to
semantic consumers. Canonical values and source offsets preserve exact bytes.
Parameter default and pattern operands admit the same literal data; variable
names, arithmetic and subscripts retain their restricted code domains.
ANSI-C fragments now admit the same literal bytes, including `$'日本\t語'`,
with existing escape decoding. Surviving non-ASCII Unicode escapes keep
their complete-command semantic restrictions; arithmetic and selectors keep
their restricted code domains. Incomplete quotes retain draft recovery and
original offsets. Newly admitted words proceed through the ordinary grammar
and semantic checks. For example, `printf $'日本'\ncat <<\n` is INVALID rather
than UNSUPPORTED because the later heredoc declaration has no delimiter.

ANSI-C encoded-syntax checks now share escape decoding with canonical words
and heredoc delimiters. Wrapped octal bytes such as `\444` (`$`) and `\540`
(backtick) return UNSUPPORTED when they introduce decoded syntax in parameter
operands; semantic graph consumers reject those sources. Previously, such
inputs could produce successful graphs missing the nested commands. Ordinary
ANSI-C literal words retain static value decoding, including the fragment-local
NUL truncation described below. Backslash runs in these parameter operands are
scanned in linear work, including before raw command substitutions.
Nested parameter words within re-expanded ANSI-C fragments now retain the same
two-phase backslash interpretation. This restores executable children omitted
after three backslashes and removes phantom children reported after two,
including within supported heredoc prefixes before decoded NUL. Exact source
spans and conditional ownership are preserved; the correction adds no decoded
source representation or runtime-error model.
Executable child bodies changed by that first decoding phase now return
UNSUPPORTED rather than publishing raw-source graphs with missing or phantom
grandchildren. Byte-identical child bodies retain their existing support.
For example, a single backslash before raw `$()` survives ANSI-C decoding;
the child's own quote context still determines whether that dollar is literal.

Deferred heredoc word expansion now preserves the parameter-operand path that
activated it. A pattern rooted directly in an unquoted heredoc can activate the
phase through a nested word. The next nested operand remains active; a word
continues that path, while consecutive patterns require another intervening
word before re-expansion resumes.
For example, `${0#${0:+${0#$'$(printf child >&2)'}}}` retains the conditional
`printf` child, including before a decoded NUL. By contrast, a pattern entered
after an ordinary heredoc word does not reactivate the phase:
`${0:+${0#${0:+$'$(printf child >&2)'}}}` contains no child. Process
substitutions in active ordinary-word parameter operands and their re-expanded
ANSI-C text are retained instead of being hidden by inherited quote
suppression. Explicit double quotes within the re-expanded ANSI-C value now
suppress process substitution as well; quoted `<(...)` and `>(...)` text no
longer introduces phantom commands or policy subjects. Command and backtick
substitutions inside that text remain visible.
An explicit double quote around a nested parameter stops deferred heredoc
expansion from reaching its pattern operands. The quoted heredoc expression
`${0#"${0:+${0#$'$(printf child >&2)'}}"}` therefore has no child command;
removing those quotes retains the child. Scope restoration preserves the phase
of subsequent unquoted operands. Immediate double-quoted defaults continue to
expand their raw command and backtick substitutions.
Pattern entry now resets enclosing quote inheritance specifically for heredoc
operands. A deeper default therefore cannot bypass the blocked heredoc phase
by recovering an earlier explicit quote. For example,
`${0:+"${0#${0:+$'$(printf child >&2)'}}"}` contributes no child command;
previously its retained headers, graph and policy evaluation included a phantom
`printf`. This correction also covers backticks and process substitutions,
including literal ANSI-C fragments with NUL tails. Ordinary shell-word quote
inheritance, newly introduced quotes after the pattern, raw substitutions and
subsequent sibling expansion remain supported.
These corrections apply to retained headers,
graphs, feature discovery and policy subjects through the shared scanner;
deny rules therefore see the previously missing commands. Public interfaces,
workspace contracts and the restriction on child bodies requiring decoded
source are unchanged.

Harmless ANSI-C data escapes surrounding raw command/backtick substitutions
no longer make the entire parameter operand UNSUPPORTED. For example,
`echo "${0#${0:+$'$(printf child >&2)\n'}}"` now retains the byte-identical
`printf` child. Escapes that change an executable child's body, introduce
encoded expansion syntax, or violate the existing quote-framing restrictions
remain unsupported. A complete raw child can now pass `shell_parse_fast()`
while semantic consumers reject its translated body. Successful fast parsing
establishes raw framing, not semantic support. Public interfaces and the
retained graph's raw-source contract are unchanged.

Parameter-word expansion now rejects syntax assembled across ANSI-C fragment
boundaries. This includes command and process substitutions, parameter and
arithmetic expansions, and framing that begins in a decoded fragment but ends
in neighboring source. Previously, those forms could pass source admission
while retained headers, graphs and policy subjects omitted the reconstructed
expansion. `shell_parse_fast()` can still accept their complete raw framing;
draft admission reports UNSUPPORTED and semantic consumers fail closed.
Literal controls separated by quoted content, protective escaping or
whitespace remain supported. Empty double quotes are transparent in inherited
shell double-quoted defaults, but preserve a literal boundary in ordinary-word
and heredoc operands. For example, `"${0#${0:+$'$'""(printf child)}}"` is
supported with no child, while the direct default
`"${0:+$'$'""(printf child)}"` still requires reconstructed source and remains
unsupported. These transitions use bounded forward state with unchanged public
results and workspace requirements.

Complete-source semantic inspection propagates this translated-source outcome
even when graph construction consumes a caller-supplied fast result. A
permissive result truncated before a later translated expansion therefore
produces a graph parse error with no partial graph; retained fast ranges cannot
hide unsupported semantics elsewhere in the unchanged source span.

ANSI-C control escapes now consume doubled backslash operands correctly and
preserve apostrophes protected by the consumed backslash. For example,
`$'日本\c\\X'` decodes to Japanese bytes followed by `0x1c` and `X`, without
an extra backslash; `$'日本\c\'X'` preserves the apostrophe before `X`.
This corrects canonical argument bytes and shared heredoc delimiter
normalization. Public interfaces and source-admission restrictions are
unchanged.

Source-derived ANSI-C values now truncate each fragment at the first decoded
NUL, then resume later word fragments. `pre$'a\0b'post` therefore contributes
`preapost`, and an argument spelled `$'\0'` contributes one empty argument.
Canonical argv, builtin recognition, descriptor operands, assignments, CWD/path
facts and heredoc delimiters use this effective value. Retained source spans
still include the entire spelling. Double-quoted parameter defaults and
alternates containing decoded NUL remain semantically unsupported.

`shell_visit_static_word()` now returns the effective static Bash value rather
than a binary syntax projection. Callers that require the NUL and discarded
bytes use `shell_visit_decoded_word()`, its measure/write counterparts, or
`shell_decode_word()`, whose byte-preserving contracts are unchanged. Canonical
payloads supplied directly remain binary-capable. Public signatures, result
layouts and workspace contracts are unchanged.

Control-feature detection now uses complete lexical words. Ordinary words such
as `日本.if`, `日本''if`, `x-while` and `/tmp/in` no longer trigger false
conditional, loop or case rejections under Shellgate's default feature mask.
They reach normal argv-policy matching. Keyword text in comments, redirect
operands and expansion/document data also stays out of outer control flags;
executable substitutions retain their own flags. Standalone unquoted keyword
spellings remain lexical markers, including in ordinary argument positions.
The allocating tokenizer uses the same complete-word and redirect-operand
boundaries for its lexical control metadata. Feature discovery now advances
through an incomplete process-substitution opener; syntax validation reports
the unfinished input instead of feature collection stalling on it.

Single-quoted backslashes now retain their literal meaning at closing quotes,
including before command separators. Source classification, structured
processing, and diagnostic transformations agree on these command boundaries.
Byte-oriented syntax and token classification are independent of the embedding
application's locale, including ASCII-only identifier checks, numeric operand
whitespace, case-insensitive metadata names, and diagnostic byte escaping.
No application locale initialization is required for analysis.

Executor startup must set `LC_ALL` to C/POSIX or an installed UTF-8 locale and
make it readonly. `LC_ALL` joins the protected executor-variable set alongside
`BASH_COMPAT`. Assignments and declaration/`printf`/`getopts` writes are
unsupported; modeled `read` and `unset` retain their readonly-target failure
behavior. The library relies on this fixed execution contract. Update launchers
before submitting the newly admitted source.

`shell_source_status_t` adds UNSUPPORTED and INVALID_INPUT after the existing
values, without enlarging retained result structures. Update exhaustive status
switches. INVALID now establishes a grammar error; restricted non-ASCII code,
unsupported committed constructs, and unclassified expansion forms are
UNSUPPORTED. Embedded NUL is INVALID_INPUT. Source limits remain TRUNCATED.

Empty standalone negation, including top-level `!` at EOF, is UNSUPPORTED;
unfinished parenthesized children retain recovery until their closer arrives.
Compound-array assignments in lexical assignment/declaration positions are
UNSUPPORTED rather than COMPLETE. Misplaced array forms are INVALID. An
unquoted `!` redirection operand is an ordinary word, so spaced and adjacent
forms now agree across source, processor, and graph APIs.

Indexed assignment values now retain their complete lexical word, so a
following array declaration remains UNSUPPORTED. Leading redirections end
reserved-word eligibility: `>out {` names an ordinary command. Unquoted
`echo \$(name)` is rejected as malformed parentheses; use quoting or escaped
parentheses for literal text. Replace tests that relied on the old literal
interpretation with valid quoted spellings.

Closed substitutions whose complete delimiter words rely on implicit heredoc
termination at EOF return UNSUPPORTED. Missing delimiter words and separately
proven grammar errors remain INVALID. Exact implicit-termination framing is
outside the retained-source contract; top-level and open-child recovery is
unchanged.

Comment-ending backslashes no longer hide command-separating newlines. Complete
sources retain separate complete headers, and next-line array declarations
remain UNSUPPORTED rather than becoming misplaced arguments. Post-pipe `time`
recognition now preserves Bash's token history: `|&` followed by LF and reserved
`time`, or `|` followed by two LFs and reserved `time`, is INVALID. Ordinary
commands named `time` retain their argv and literal brace arguments across fast
ranges, structured processing, and graph construction.

Fast parsing reuses forward prefix facts for group, continuation, and document
boundaries, eliminating repeated scans before literal brace arguments. Work
counters now include prefix-gap whitespace visits. Supported non-ASCII heredoc
data and delimiters no longer turn a later missing delimiter or capacity stop
into UNSUPPORTED: those outcomes remain INVALID and TRUNCATED respectively.

Redirect tokenization and source framing now share longest-match operator
boundaries. Arbitrary adjacent operators no longer merge: `<<<<x`, `>>&x`,
and `<>&3` are INVALID. Valid process-substitution operands such as `<<<<(:)`
are unchanged. Named-FD clobbering (`{fd}>|out`) is recognized consistently
with bare and numeric descriptors. Lexical tests should use valid redirect
spellings rather than the formerly combined `>>&` token.

Balanced indexed-assignment prefixes now retain their complete RHS and exact
word spans, including subscript whitespace and quoted values. Following array
declarations remain UNSUPPORTED instead of becoming false syntax errors.
Ordinary argument/redirect positions do not acquire assignment grouping.
Scalar-looking declaration operands also use ordinary word boundaries:
`declare a[1 + 2]=x` retains four words, matching Bash and the command graph.
Only leading indexed assignments can group unquoted subscript whitespace.
Escapes inside a compound-array body do not quote the outer assignment;
`a=(x\ y)` remains UNSUPPORTED array syntax.
Unresolved indexed prefixes such as `a[1 + (` are UNSUPPORTED rather than
INVALID; no array-recovery prefix is qualified.

Subscript matching now retains non-evicting nested and unfinished boundaries
in source scratch. Recompute supplied capacities with
`shell_source_workspace_size()`; its sufficient bound has increased without
enlarging public structures. Larger indexed inputs may require caller scratch
even without heredocs. Allocating APIs reserve it automatically. A public
iterator borrows its buffer exclusively through iteration, including between
`next()` calls; independent live iterators need separate buffers.
Literal braces after inline documents retain their word role through fast
parsing, structured processing, and graph construction.

In 0.17, INVALID also covered unsupported inputs and was not a reliable Bash
syntax-error classification. Strict-fast and graph parse error codes retain
their coarse meanings. Use the [source admission sequence](../shellsplit/README.md#classifying-input-before-dispatch)
to separate pre-dispatch syntax rejection from application-controlled explicit
approval of unsupported exact source. Incomplete-input prefix recovery is
unchanged; INVALID and UNSUPPORTED both clear prefix qualification.

## 0.17: retained source analysis and delimiter workspace

- Include `shell_source.h` for `shell_parse_draft()` and its retained headers,
  redirects, and heredoc records. Use its qualified prefix for partial analysis.
- `shell_dep_graph_parse_with_fast()` is public. Pass unchanged parser metadata
  and exactly its original immutable source span; graph construction reuses it.
- Add the fourth, optional limits argument to `shell_tokenizer_init()`.
  Pass `NULL` for default delimiter scratch. A supplied buffer remains borrowed
  through iteration.
- `shell_limits_t` includes optional `workspace` and `workspace_size` fields.
  Designated initializers retain zero/default values for omitted fields.
  `shell_source_workspace_size()` computes a sufficient delimiter bound.
- Add source-sized delimiter scratch after the fixed aligned graph workspace,
  or use resolved-graph sizing when appropriate. Size helpers remain the source
  of truth; avoid hard-coded workspace byte counts.
- Heredoc body spans include their final LF. Use document content helpers for
  exact literal data and `<<-` tab removal.
- Check CWD-known flags before interpreting offsets. An unguarded `cd /path;`
  joins success and failure; `cd /path &&` selects its success continuation.

## 0.15: ordinary cd commands and inherited I/O

Remove the `cd_as_cmd` limits initializer. `cd` is always a CMD node with its I/O
and CWD relationship, while directory changes remain tracked separately.

Inherited full-command streams appear as FD resources. Consume READ/WRITE
edges and their local descriptor fields when inspecting stderr/stdout routing;
command argv alone cannot describe redirects.

## Canonical byte-oriented interfaces

Current canonical APIs use explicit-length netargv, netsequence, and netpattern
views or owned buffers. Replace removed C-string transport adapters with those
interfaces; keep the enclosing length even when payloads contain NUL.
See [Canonical formats](canonical-formats.md) for encoding and ownership.
