# Shellsplit source and CWD contracts (0.17)

Applications use `shell_source.h` and `shell_depgraph.h` directly. Shellgate
does not wrap these interfaces. Shellsplit does not execute expansions, inspect
the filesystem, or approve native/atomic operations.

## Exact heredoc data

For a complete graph's `SHELL_DOC_HEREDOC`, use
`shell_dep_doc_content_length()` followed by `shell_dep_doc_write_content()`.
The payload of `cat <<'EOF'\nalpha\nEOF\n` is **six bytes**, `alpha\n`.
Empty documents have zero bytes. Carriage returns are preserved. `<<-` removes
leading tabs, not spaces. The source span retains physical tabs; the helpers
apply that removal without allocating or executing anything.

`SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL` identifies quote-protected documents.
Only those yield exact literal runtime payloads. An unquoted document is an
unevaluated template, even if it currently contains no expansion. Delimiter
matching applies quote removal and, for unquoted delimiters, backslash-LF
joining. Physical continuations inside the delimiter word do not quote it:
`EO` followed by backslash-LF and `F` still declares an expandable `EOF`
document. Real quotes or non-continuation escapes protect the body instead.
Backtick fragments in a delimiter remain literal spelling, while grouping
spaces and operators into the same word. Their internal quotes, backslashes,
and ANSI-C-looking text do not quote the body. An actual outer quote enables
quote removal across the whole delimiter spelling, as in the reference Bash.
Within an outer double quote, a literal backtick fragment still shields its
internal quote characters during lexical framing. The subsequent whole-word
quote-removal phase remains separate.
Preparation preserves Bash's phase ordering: lexical continuation removal and
protected ANSI-C translation happen before whole-word quote removal. Thus
backslash-LF inside a literal backtick fragment disappears even when that
fragment contains single-quote-looking bytes; a genuine outer single quote
still preserves those bytes. ANSI-C translation retains its protected lexical
spelling until quote removal, rather than inserting decoded bytes directly.
Protected translation truncates only its ANSI-C segment at a decoded NUL.
Raw translation inside a double-quoted parameter default instead terminates
the owning lexical word: `<<"${x:-$'\0'}"` requires the line `${x:-`.
That termination propagates through matched-pair fragments but stops at a
parsed word boundary. A NUL inside one word of a literal command fragment
does not discard its following words, redirects, or connectors. Source NUL
bytes themselves remain invalid; these rules concern decoded ANSI-C escapes.
Removed continuations also precede parameter-selector classification. A first
logical `#` after a continuation is not a pattern operator merely because the
source contains physical backslash/LF bytes. For example, `<<"${` followed by
backslash-LF and `#x:-$'a'}"` requires `${#x:-a}`, not `${#x:-'a'}`.
This distinction also preserves raw-versus-protected ANSI-C NUL handling.
These distinctions affect the terminating line and therefore which subsequent
bytes are executable commands. Blanks and escaped newlines between the heredoc
operator and its delimiter are trivia; only an adjacent dash selects `<<-`.

Balanced `${...}`, `$((...))`, legacy `$[...]`, `$()` and process-substitution
fragments also belong to the delimiter word. They are **not evaluated** there:
`${not!valid}` is literal delimiter spelling, not a rejected parameter
expansion, and `$(printf eof)` does not execute `printf`. Internal quotes do
not by themselves protect the body. For example, `<<${x:-"EOF"}` terminates
at the literal `${x:-"EOF"}` line and still allows body expansions; appending
an outer `''` instead enables whole-word quote removal and changes the
terminator to `${x:-EOF}`.

Bash lexically reprints parsed command fragments before matching the delimiter:
`<<$(printf   eof)` requires the line `$(printf eof)`, and `<<$(a 1>f)` requires
`$(a > f)` even though the two spellings have equal lengths. Shellsplit models
this printing for its supported command grammar, including groups, timing,
connectors, redirect ordering, `|&`, and deferred heredocs. Descriptor-close
tokens do not consume adjacent words: `<<$(a >&-file)` requires
`$(a file 1>&-)`. Quoted/escaped dashes follow ordinary word rules instead.
Word-form moves retain Bash's explicit source descriptor even for dynamic or
overflowing targets: `<<$(a >&$fd-)` requires `$(a 1>&$fd-)`.
This lexical printing classification does not assert runtime descriptor validity.
Last-byte/NUL facts compose as pieces are built; classifying a redirect or a
brace-group separator does not reprint nested operands to rediscover their tails.
Brace separators follow the actual printed word endings, including raw-NUL
truncation after LF or ` &`, rather than the shape of an internal rope node.
No delimiter-only command becomes a draft child header, an executable graph
node, or an application expansion callback. Control constructs and other
unmodeled syntax remain unsupported; there is no fallback to an unnormalized spelling.
Escaped physical line endings cannot disguise reserved words: a continued
`if`, `for`, or `while` is rejected just like its uninterrupted spelling.
Quoted, escaped, and suffixed lookalikes remain ordinary words.
Assignment and redirect prefixes also commit an ordinary command before its
executable word: `<<$(>f if)` requires `$(if > f)`, not a control construct.
At received EOF, `$(if` is still incomplete because appending `x)` makes an
ordinary command word; a completed unsupported construct is still rejected.
Locale-translated `$"..."` and locale-dependent ANSI-C Unicode delimiter
fragments are likewise rejected at the
draft/syntax boundary rather than assuming a translation catalog or guessing
the terminator. Single-quoted and otherwise inactive spellings stay literal.
Current-shell `${ command; }` and `${|command; }` substitutions remain
unsupported, including inside delimiters; they must not be mistaken for
ordinary parameter spelling.
A printed delimiter containing a literal LF cannot be matched by a single
physical closing line; a received draft remains incomplete at EOF.
Arithmetic matched-pair spelling is not a command printer: process-like text
inside `$((...))` or `$[...]` keeps its lexical whitespace. Dollar-command
fragments nested there still follow their own lexical rules.

One reference-Bash reserialization case is rejected by semantic consumers:
inside `$()` or process substitution, an unquoted leading-dash delimiter with
ordinary `<<` (for example `<< -EOF`) is printed back without the separating
blank. Its execution-time reparse changes it to `<<-EOF`, potentially exposing
body lines as commands. Such input cannot yield a faithful borrowed graph;
it returns a parse/unsupported-semantics error instead. Top-level `<< -EOF`,
quoted `<< '-EOF'`, and an already-strip-tabs `<<--EOF` retain their framing
and remain supported. Draft metadata describes received lexical framing, not
a promise that every complete draft has supported execution semantics.

Do not treat `doc.name` as a decoded delimiter: it is display spelling.
Raw non-ASCII bytes are accepted in heredoc delimiters and data, including
UTF-8. Ordinary executable source, including code inside an expandable heredoc,
retains the existing restricted byte domain. This is byte preservation, not
Unicode normalization or locale-dependent expansion.
Byte domains are scope-aware: `日本 $((1 + 2)) 語 ${value:1}` is a valid
expandable heredoc template. Literal text before, between and after expansions
is data, including parameter default/pattern words such as `${value:-語}` and
`${value#文}`. Arithmetic expressions, substring offsets/lengths and array
subscripts remain code. Non-ASCII code there is rejected even before a nested
`$(...)` or at an unfinished EOF. Nested executable children have their own
heredoc data islands; their bodies are not reclassified as enclosing arithmetic.
NUL, DEL, and non-whitespace control bytes remain rejected at the source
boundary, including in heredoc data.

## Received drafts and safe analysis prefixes

Call `shell_parse_draft(source, length, NULL, result)` on the entire received byte
span. Allocate the fixed-capacity `shell_source_result_t` outside small stacks;
it performs no heap allocation and borrows the unchanged source. The status is
`COMPLETE`, `INCOMPLETE`, `INVALID`, or `TRUNCATED`.

The optional `shell_limits_t` input supplies a command bound and borrowed
delimiter workspace. Delimiters are measured, then decoded once into reserved
scratch and compared without re-decoding for every body line. Small delimiters
fit private scratch. For a larger one, supply `workspace` and `workspace_size`
in those limits. Call `shell_source_workspace_size(length, &bytes)` for a
checked sufficient capacity, rather than estimating from source length.
The bound includes private normalization pieces and prepared delimiter bytes,
and accepts unaligned storage. Overflow returns false and clears `bytes`.
Flat words keep their streaming fast path; grouped words build workspace-backed
pieces, then measure and emit using the same traversal. Nested suffixes are not
reprinted for every ancestor and delimiters are not decoded per body line.
Scratch exhaustion
returns `TRUNCATED` with no qualified prefix, not `INVALID`. Retry with a larger
buffer. The same limits supply scratch to `shell_parse_fast()` and to
`shell_tokenizer_init(state, source, length, limits)`; retained results do not
own or borrow the decoded scratch after the operation finishes.

Allocating tokenization, processing, abstraction, transformation, and sequence
builders keep their existing signatures. They reserve one operation-owned
temporary arena when the source-dependent bound exceeds the small default,
reuse it throughout validation and nested processing, and release it before
returning. Allocation failure preserves each API's empty-output/`ENOMEM`
contract. There is no per-delimiter allocation fallback in the allocation-free
interfaces.
Paired anomaly rendering and Shellgate keep that same operation alive through
both stage collection and rendering, including nested heredoc substitutions.

Application expansion callbacks start independent source operations, even for
identical, shortened, or overlapping input. They do not inherit an enclosing
parse's byte-admission proof or heredoc boundaries. Graph operations retain
their lexical index in their own workspace; callback parsing can use the
bounded allocation-free default without overwriting the parent's facts.

`prefix` and `prefix_length` describe a separately syntax-qualified leading
span. An unfinished group, word, pipeline, logical list, or pending heredoc
cannot be cut into executable fragments. A completed earlier top-level list
unit can be retained. A pending pipeline prefix starts an unfinished unit even
after a separator: `echo ok; !` is `INCOMPLETE` with `NEEDS_COMMAND` and retains
only `echo ok;`. Timing keeps Bash's distinct valid empty-pipeline behavior.
An unquoted command-position keyword at received EOF is still appendable:
`echo ok; if`, `echo ok; function`, and `echo ok; [[` return `INCOMPLETE`
with `NEEDS_COMMAND`, identify the keyword in `incomplete_at`, mark its header
incomplete, and qualify only `echo ok;`. Appending `x` makes an ordinary word.
Escaped physical continuations do not commit the word. A real word boundary
(whitespace or punctuation) does: confirmed control/function/conditional syntax
remains unsupported and returns `INVALID` without a qualified prefix.
The same rule applies inside open executable children, but a closing child
delimiter commits its local final word: `echo $(if)` is `INVALID`, regardless
of anything appended outside it. Quoted, escaped, and suffixed lookalikes and
ordinary argument/redirect-operand words do not introduce reserved syntax.
Likewise, an assignment or redirection prefix starts a simple command:
`x=1 then` and `>target then` have an executable named `then`, not control
syntax. Builtin/executable-word tracking continues after those prefixes,
but reserved-word eligibility does not reopen. Strict graph parsing preserves
that same distinction.
These classifications use existing forward grammar/collection walks, not a
new full-source scan or a public result-layout extension.
For example:

```sh
cat /workspace/before.txt
cat <<EOF
cat /workspace/body.txt
```

The status is `INCOMPLETE`, the qualified prefix is only the first line, and
`body.txt` is heredoc data—not another command. Strict whole-source graph
parsing still rejects this input. To inspect the qualified prefix without
reparsing it, when `prefix_length != 0`:

```c
shell_dep_error_t error = shell_dep_graph_parse_with_fast(
    source, result->prefix_length, initial_cwd, &graph_limits,
    &result->prefix, &graph);
```

Supply the ordinary graph workspace in `graph_limits`. The source, prefix
length, and unchanged parse result must correspond exactly; this is a caller
precondition, not a request for redundant source validation. Graph construction
reuses the successful parse's byte-admission guarantee without another
whole-source validation pass. It can still reject unsupported semantics or
exhaust graph resources. An error or truncated parse is not that guarantee:
scratch exhaustion may have stopped source validation itself. Independent
application callbacks still validate their own source domains.
Prefix qualification is for analysis; it does not authorize executing a prefix
of the user's unfinished request.

`tail_start`, `need`, and `incomplete_at` locate the unqualified remainder.
`INVALID` clears prefix qualification. `TRUNCATED` makes no whole-input claim;
capacity exhaustion must never be interpreted as a complete draft.

After a closed compound, its redirection introducer may itself still be
unfinished. `echo ok; { :; } 2` and `echo ok; ( : ) {fd}` are
`INCOMPLETE/NEEDS_REDIRECT`: appending `>out` completes a valid redirect.
The location identifies the descriptor prefix, and only `echo ok;` is
qualified. `{`, `{f` and `{fd` can likewise acquire the rest of a valid named
redirector. Removed physical continuations preserve adjacency; a final
backslash uses `NEEDS_ESCAPE` until LF arrives. Real trailing whitespace,
quoted/escaped digits, invalid identifier bytes and numeric overflow cannot
be repaired this way and remain `INVALID`. Closing a substitution commits
its local final word; appending outside it cannot supply that word's operator.
An unfinished introducer belongs to its existing compound header, which spans
the received tail and is incomplete. Its words remain empty and no extra
group or redirect operation is invented. Closed child records and earlier
redirects stay unchanged, including when another compound-tail redirect is
already present. A standalone opening `{` at command position still means an
unfinished brace group, not a descriptor prefix.
Unfinished ordinary arguments after a closed compound, such as `{ :; } '`,
remain `INVALID`: completing a quote or substitution cannot turn that word
into a redirection. Quotes in genuine redirect operands remain recoverable.

Missing redirect operands are not unfinished expansions. `echo ok; cat 2>&`
returns `INCOMPLETE/NEEDS_REDIRECT`, locates the redirect, marks its header
incomplete, and qualifies only `echo ok;`. Inline blanks and escaped newlines
do not change that diagnosis. Receiving an unescaped newline, separator, or
comment before the operand makes the source `INVALID` and clears the earlier
prefix; appending outside that boundary cannot supply the missing word.
This also applies to descriptor-input copies, named descriptors and redirects
after compounds. A real unfinished operand such as `2>&"$(printf 1) tail`
instead retains its quote diagnostic and the closed `printf` child. A final
logical `<` or `>` where the operand belongs is still append-repairable as
process substitution, for both simple commands and compound tails; a physical
blank after that punctuation rules out appending `(` directly.
A trailing backslash at that boundary remains `NEEDS_ESCAPE`: it can acquire
LF before the process-substitution opener arrives.
An unfinished expansion in a redirect operand, such as `cat >$(printf out`,
is an incomplete tail just like an unfinished ordinary argument; it does not
invalidate an earlier completed list unit.
This includes duplication operands: `echo ok; cat 2>&"${fd` retains only
`echo ok;` and reports `INCOMPLETE`. Operator-owned `&` and inline trivia are
not part of the actual operand word. Public I/O spans keep their original
spelling; unfinished targets do not imply a concrete descriptor or a known
setup failure. Completed nested children remain available without duplication,
while closed malformed children still invalidate the draft.
This recovery is recursive. For example:

```sh
echo before; echo $(cat > <(printf out
```

The status is `INCOMPLETE/NEEDS_SUBSTITUTION`, `incomplete_at` identifies the
outer `$(`, and the qualified prefix is exactly `echo before;`. Appending
`))` completes the command. The same rule applies inside process substitutions
and supported backticks, with simple commands or compounds owning redirects.
Each lexical body keeps its own unfinished-word facts for grammar projection;
those local facts do not replace the enclosing construct's public diagnostic.
Retained header and redirect source offsets remain root-relative, and closed
children and previously framed I/O operations stay intact during completion.
An unfinished process-substitution operand does not invent a complete redirect
operation before its word is framed. Heredoc-owned children likewise retain
local recovery without replacing the document's pending-body diagnostic.
Receiving a child's closing delimiter commits its local grammar: malformed
closed children still invalidate the whole draft, even while an outer word or
substitution remains unfinished. Collection and grammar projection share the
same body-local state without an additional source scan or public result data.

An unfinished heredoc declaration remains one lexical heredoc token through
received EOF. Its parentheses, quotes, and operators cannot masquerade as a
following group or command. A trailing `<` or `>` can still acquire `(` and
complete a process-substitution delimiter or operand.
Likewise, `${#`, `${!`, `${!prefix*` and pending selector continuations ending
in backslash are append-repairable. They return `INCOMPLETE` and retain an
earlier qualified list unit. Appending LF can finish a selector continuation;
an already-invalid selector byte is not excused merely because EOF follows it.

## Bound headers, redirects, and framing

`headers` retain complete lexical word spans and assignment-prefix counts.
Their source spelling is not expanded argv. Compound headers are marked and
carry group depth. Each header's `first_redirect` starts its source-ordered
linked list in `redirects`; follow `next` for `redirect_count` records. A linked
list is needed because nested command headers can have redirects interleaved
with their parent's redirects. Each record reuses the processor's typed I/O
operation, including descriptor names, copies, closes, and combined outputs.

Header completeness is local: `echo ok` in `{ echo ok;` is complete while the
enclosing compound is not. Likewise, a closed command substitution within an
unfinished word or heredoc can expose complete nested headers, redirects, and
heredoc records. For example, `echo "$(printf one) tail` retains the completed
`printf one` header even though the outer quote is missing. Completing the
outer word does not create or duplicate that child. A closed substitution
with invalid grammar, such as `$(echo &&)`, instead makes the draft `INVALID`,
even inside an unfinished word; appending cannot repair that child.
Received bodies of unfinished `$()`, process substitutions and supported legacy
backticks also retain available local headers, redirects and heredoc records,
including inside expandable heredoc drafts. For example, an unfinished
`` echo "`printf one; cat <<'EOF' `` followed by `\nalpha\nEOF\n` retains both
child headers and the exact `alpha\n` payload. Closing the backtick/quote does
not duplicate those records or change their source coordinates. A closed bad
`$(echo &&)` inside an unfinished backtick makes the draft `INVALID`, with no
qualified prefix, just as it does inside an unfinished `$()` body. These
are source facts, not evidence that a child executes. An open compound's source
span extends through received EOF, rather than having a zero length.
The separately qualified top-level prefix, not a nested header's flag, decides
which source can be submitted for graph construction. A newline terminating
an empty `time` pipeline qualifies a prefix just like a semicolon; pending
binary connectors, enclosing groups, and unfinished documents still block it.

Legacy backticks which require Bash's outer escape-layer removal are not
supported borrowed source views. This includes backslash before `$`, backtick,
backslash or LF, and before `"` in a double-quoted backtick. The draft boundary
returns `INVALID` for complete **and unfinished** active forms, clearing prefix
qualification; it does not parse their raw spelling as the decoded program.
Escape facts are captured at received EOF as well as at a closing delimiter.
Escaped literal backticks, single-quoted words and quoted heredoc bodies do not
activate a substitution. Prefer `$()` when that legacy escape layer is needed.

Every `heredocs` record binds to its header and redirect. An unfinished
delimiter declaration has redirect `UINT32_MAX`, not a fabricated complete
operation. `declaration`, `delimiter_word`, `body_start`, and
`closing_delimiter` are source-relative byte coordinates. FIFO bodies are
kept separate. `header_complete`, `body_started`, and `complete` distinguish
an unfinished declaration, a received body prefix, and a received terminator.

`content` borrows the received raw body prefix and uses the same content
helpers as a graph document. If the final unterminated line could still become
the delimiter (for example `EO` for `EOF`), `delimiter_prefix` is true and
`confirmed_length` excludes that ambiguous line. To obtain confirmed logical
bytes, copy `content`, set its `value_len` to `confirmed_length`, and call the
content helpers. That length is raw source bytes before `<<-` stripping.
Code-byte admission and nested header collection inspect only confirmed body
data, not the tentative delimiter line. For example, with unquoted delimiter
`` `日本` ``, a final received line `` `日 `` remains a possible terminator,
not an unfinished program containing non-ASCII code. Completing the delimiter
produces an empty document without introducing a child header. If later input
instead makes the line body data, its active expansions are inspected normally.
The whole raw candidate remains accessible through `content` throughout.
Missing later FIFO bodies have `body_started == false`.
This also holds when an unquoted final backslash could acquire LF and join
the remaining delimiter bytes: `EO` followed by a final backslash is not yet
confirmed content for delimiter `EOF`.

A complete header proves header grammar, not that an operation runs or may be
promoted to a native write. The application must still enforce its own command
shape, literal-payload, overwrite, filesystem-coherence, and atomicity policy.
It no longer needs a second shell parser to locate those source facts.

## Conservative static CWD and path identities

For a CMD, consume `cwd_known` before `cwd_offset`; for a FILE document consume
its own CWD facts, since redirects expand in their owner's incoming directory.
Use `shell_dep_doc_file_identity_write()` for a statically decoded lexical
identity. Its boolean result and `absolute` output are significant. Relative
initial directories do not become trustworthy absolute paths merely because
of normalization. Do not perform containment/coherence checks on an unknown
offset or an unresolved dynamic pathname.

Starting at `/workspace`, the commands in
`cd /workspace/src && cat input.c 2>&1 | head -n 2 other.c` use
`/workspace/src`. The cat in `(cd /workspace/nested && cat 'a file.c'); cat root.c`
uses `/workspace/nested`, while the final cat uses `/workspace`.
`cd /workspace/src || cat input.c` uses the entry directory on failure;
`cd /workspace/src; cat input.c` is unknown because success and failure join.
This unchanged-on-failure proof is not universal: `cd -` and CDPATH-selected
directories can change directory and then fail while printing the result.
Argumentless `cd` has the same possibility when runtime HOME is relative and
CDPATH selects a directory. Thus `HOME=tmp CDPATH=/; cd >&- || command` must
not claim that the failure continuation retains its entry CWD or PWD/OLDPWD
bindings. No HOME value evaluation is implied by these conservative facts.
Physical-resolution failures can also follow a directory change. These failure
paths join possible directory facts and invalidate affected `PWD`/`OLDPWD`
binding proofs; they do not invent a known entry CWD.
Negation reverses connector outcomes, not the directory transition itself.
Subshells, pipeline stages, and background groups do not leak CWD changes to
the parent. HOME, CDPATH-dependent operands, dynamic expansion, and physical
`cd -P` resolution remain unknown rather than inventing symbolic path facts.
No filesystem existence, symlink containment, or race-free access is implied.

Graph construction borrows delimiter scratch from extra bytes in its existing
workspace, beyond the fixed `shell_dep_workspace_size()` prefix. Obtain the
extra capacity with `shell_source_workspace_size(source_length, &bytes)` and
check addition overflow when combining the two sizes. Do not substitute a
flat-delimiter byte estimate: grouped fragments also require normalization
pieces in that same scratch arena. The workspace retains the alignment
required by `shell_dep_workspace_alignment()`;
`SHELL_DEP_EWORKSPACE` requests a larger buffer, never permission to use a
partial graph. Resolved-graph sizing and Shellgate's buffer hint include this
source-dependent scratch in their existing single evaluation buffer.
The fixed prefix includes the operation's lexical index, whose lifetime spans
resolver callbacks. Always derive its size with the public helper instead of
hard-coding a byte count. Recursive implementation views reuse that index;
independent callback operations neither copy nor invalidate it.
