# API migration notes

These notes describe changes relevant to existing consumers. The public headers
define the current API; rebuild consumers after updating the library.

## Unreleased: typed source admission

Ordinary single and double quotes now admit literal high bytes, including
invalid UTF-8 and concatenated fragments. `printf '%s' '日本'` is COMPLETE and
available to semantic consumers. Unquoted `printf '%s' 日本` remains
UNSUPPORTED. Canonical values and source offsets preserve exact bytes.

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
switches. INVALID now establishes a grammar error; unquoted non-ASCII source,
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
