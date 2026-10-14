# Retained graph syntax metadata: application gap and follow-up plan

Status: proposed follow-up, not implemented. Recorded on 2026-10-14.

## Original application request

> I also have a need in our application that uses shellsplit:
> The gap is specifically in the public retained graph API. Our tests show the
> same graph for:
>
> ```sh
> wc -l file.txt
> wc -l file.txt 2>&1
> ```
>
> Yet `2>&1` changes stderr routing.
>
> Shellsplit's processor API
> (`shellclave/shellsplit/include/shell_processor.h:29`) already exposes redirect
> tokens and `has_redirections`. We need that existing metadata accessible
> alongside the graph from the same parse. My earlier wording was too broad.
>
> Can we make this easily available? How should the application access this data?
>
> We need to:
>
> Fix the P2 quadratic undo prefix
> Fill the gap for our application
>
> Can this all go into the same commit, or is the gap better in its own commit?

The request is for retained syntax metadata alongside the dependency graph, not
for a Shellgate wrapper, another whole-command parse, or a replacement graph
representation.

## Confirmed analysis

The gap is real. During review, both commands above produced the same retained
graph: a CMD node with `wc`, `-l`, and `file.txt`, a FILE node for the argument,
and their argument relation. The explicit stderr duplication was not retained
as inspectable syntax.

The graph represents semantic dependencies rather than lossless shell syntax.
In particular, CMD tokens retain argv-like words, not redirection tokens.
Aliasing an inherited descriptor need not introduce a file or pipeline
dependency. Therefore, absence of graph edges does not imply absence of
redirections. The FILE argument relation also does not itself describe the
command's runtime file access.

Relevant current interfaces:

- `shellsplit/include/shell_depgraph.h`: retained graph nodes and graph parsing
  APIs, including parsing with a supplied fast-parser result.
- `shellsplit/include/shell_processor.h`: `shell_command_info_t`, with
  `shell_tokens`, `command_tokens`, `has_redirections`, and other simple-command
  metadata; structured processor results also retain group-owned I/O operations.

The processor result is not already a borrowed graph companion. Its token text
references its owned, flattened `original_command`, and token positions are
relative to that text. Processor command/group indexes are not final graph node
IDs. Its structured executable rows also omit argv-less commands, which can
still be relevant graph nodes.

The graph's private lightweight token representation retains source spans but
does not retain full public `shell_token_t` classification. This is consequently
not just an accessor for an existing cached processor object. Implementation
must share token-boundary/classification machinery where appropriate, rather
than reinterpret private tokens or create divergent classification rules.

## Proposed interface and application usage

Offer an optional retained syntax result alongside the graph, populated during
the same graph-construction operation. Exact public names and layout remain to
be designed.

The application requests both results, traverses the graph normally, and uses
each final CMD or GROUP node ID to obtain its syntax view. That view exposes the
relevant source-order redirection tokens and syntactic metadata such as
`has_redirections`. Applications access this directly through Shellsplit.

Design constraints:

- Reuse public token and processor classification semantics. Do not introduce a
  parallel redirection vocabulary just for graph consumers.
- Borrow original immutable source bytes. Do not copy flattened command strings
  or perform a second whole-command parse to obtain the companion data.
- Retain metadata storage independently of temporary graph-construction
  workspace. The caller controls its lifetime; resetting the construction
  workspace must not invalidate retained views.
- Keep retention optional. The existing graph-only path should not acquire
  unnecessary retained allocations, token copies, or mandatory result bloat.
- Key views by final graph node IDs, including IDs remapped during recursive
  substitution imports. Preserve source coordinates with an explicitly
  documented convention.
- Preserve compound-tail redirects on their owning GROUP, not on the last
  enclosed CMD. Preserve metadata for redirect-only/argv-less commands and
  nested command, backtick, and process substitutions.
- Preserve ordering and original spelling, including quoted/escaped targets,
  descriptor duplication, moves, closes, named descriptors, and heredocs.
- Document ownership, immutable-source lifetime, initialization, aliasing, and
  supplied-parse/source relationships. Annotate required pointers with
  `SHELL_NONNULL`; do not reparse or add defensive traversals to enforce caller
  preconditions.

`has_redirections` reports syntax, not successful execution or the final
effective route. Explicit no-op duplications and redirects subsequently
overwritten must remain discoverable. Metadata must not be synthesized solely
from final graph edges, which would lose these distinctions.

Do not return borrowed data under an existing owned processor-result contract.
Specify the new result's ownership and cleanup explicitly. Likewise, do not
make the graph pretend that every explicit redirect creates a new dependency.

## Implementation plan

1. Define the minimal optional retained syntax interface, its final-node-ID
   mapping, and source/storage lifetime contract. Show how an application
   inspects the `wc` pair without a second parse.
2. Integrate retention into existing parsing/token consumption. Share the
   applicable processor token classification machinery and preserve the
   graph-only fast path. Avoid repeated source rescanning.
3. Handle group ownership, argv-less nodes, and recursive subgraph remapping
   centrally. Ensure retained metadata never references construction scratch.
4. Define failure and capacity behavior consistently with graph construction:
   outputs must not contain dangling or mismatched views after allocation,
   unsupported-syntax, or resource-limit failures. If partial graph results are
   supported, explicitly define companion alignment and truncation semantics.
5. Add public usage documentation and consumer coverage, then run formatting,
   focused tests, normal/sanitizer suites, coverage, and relevant fuzz invariants.

Required regressions:

- The two original `wc` commands retain the same dependency graph while their
  syntax views correctly differ in redirection presence and tokens.
- Graph-only and graph-plus-syntax parsing produce equivalent graphs.
- Source-order duplicate, close, self-duplicate, move, overwrite, and named-FD
  operations remain distinguishable, even when their final routes coincide.
- Group-owned redirects, redirect-only commands, nested groups, substitutions,
  process substitutions, and heredoc boundaries have the correct owners and
  final node mappings.
- Borrowed source spans and positions are correct; views survive construction
  workspace reuse for their documented retention lifetime.
- Genuine malformed-input, resource-limit, and allocation failures preserve the
  documented output contract. Tests respect caller preconditions.
- A public consumer example/test demonstrates direct Shellsplit access and
  cleanup, with the appropriate C/C++ interface checks.

## Relationship to the current P2 performance fix

The separate P2 finding concerns repeated traversal of a growing descriptor-undo
prefix in `dep_fd_correlated_setup_failures()` / `dep_fd_failure_cleanup()` in
`shellsplit/src/shell_depgraph.c`. It is metadata replay, not quadratic source
rescanning. A single owner with many possibly failing redirects exposes the
quadratic work; many short commands do not adequately test it.

That fix belongs in the current descriptor-move changeset. It must preserve
path-correlated setup failures, live saved-descriptor mutations, and interrupted
undo behavior while replacing repeated prefix replay with reusable/composed
cleanup state. Add isolated single-owner scaling regressions as well as routing
regressions; do not regain speed by restoring incorrect rollback semantics.

Recommended sequencing:

1. Finish the current changeset, including the P2 root-cause fix and its tests.
2. Implement retained syntax metadata as a separate, self-contained changeset,
   including all necessary integrations, documentation, and tests above.

Both can technically share a commit, but the metadata request addresses an
existing independent API gap, not a necessary adaptation for descriptor moves.
Separating them does not require an unusable intermediate commit. Each commit
must still completely solve its stated task and pass its verification suite.

Smoke-seed updates remain outside this plan. This document does not authorize
implementation or settle the public interface's final naming/layout.
