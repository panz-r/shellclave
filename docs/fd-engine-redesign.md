# Descriptor engine redesign

The shellsplit descriptor analysis must stay sound (every returned graph
captures all safe-execution requirements, otherwise `SHELL_DEP_EUNMODELED`)
and run in O(n log n). This note records the target design, the consumers of
the structures it removes, and how each stage is verified.

## Why

Descriptor state lives in two representations that are converted back and
forth:

- the **persistent map** in `dep_route_journal_t`: path-copying, AVL-balanced,
  hash-consed nodes (`shell_depgraph_factmap_impl.h`);
- **dense tables** (`dep_owner_routes_t`, `DEP_MAX_FD_ROUTES` entries each).

Every conversion costs O(open descriptors) and happens per owner, per
substitution and path, and at publication. The same semantics is also
simulated twice: by the snapshot frame on `snapshot_journal` during graph
construction, and by the effective-route walk on `route_journal`. Measured
before the redesign (route lookups, n units, source bytes grow 1.9× per
doubling):

| Shape | n = 8 → 16 → 32 |
|---|---|
| `exec N<input; true "$(read -uN …)"` | 27k → 85k → 290k |
| `exec N<input; cat <&N >outI` | 32k → 77k → 180k |
| `exec N<input; vI=$(true)` (imports) | 216 → 816 → 2106 |

## Target

1. **Canonical persistent state.** 32-bit keys combine an interned descriptor
   id (numeric fd, named variable, private allocation slot) with a one-bit
   facet (`dep_fd_access_t`). Values are interned route sets. The map is a
   hash-consed big-endian Patricia trie: equal states have equal roots, and
   memoized merge/join/diff skip identical subtrees, so their cost follows the
   number of differing keys. Nodes carry summary bits (named-live, scratch
   save, process-owned, may-be-open), so table-wide queries visit only
   matching keys. A missing key means the executor contract: fds 0–2
   inherited, every other numeric fd closed, names unseen.
2. **One arena across recursion.** A child parse starts from its parent's
   checkpoint root for each path. The joiner's import records are created on
   the child's first use of a key.
3. **One forward interpretation.** A single walk applies transfer functions
   root to root, records checkpoint roots at each (owner, phase) that
   expansion and publication need, and publishes each owner from its own uses.
4. **Complexity contract.** An event costs O((k + 1)·W) for the k keys it
   touches and W = 32; a merge costs O(d·W) for d differing keys; child entry
   is O(1) per path.

Semantics stay unchanged: route kinds and cause-carrying misses, the
requirement rule (`dep_required_feasible`), read evaluation and the
handled-error rule (`dep_read_status_consumed`), undo saves, and first-cause
dominance.

## Progress

**Stage 1 (canonical map) is complete.** `shellsplit/src/shell_pmap_internal.h`
implements the hash-consed Patricia trie, checked against a reference map by
`shellsplit/tests/persistent_map_test.c`. That test covers canonicity,
persistence, collection, rollback, capacity failure, and cost bounds (with
512 keys, at most 11 steps per update and 21 per differing key in a diff).
The journal stores every descriptor map in the trie. Names are interned once
per journal, so keys are integers. Every structural walk outside the map
module goes through `dep_route_map_each` or `dep_route_map_diff`. A nested
parse returns its storage with `dep_route_journal_checkpoint` and
`dep_route_journal_restore`. The golden output is byte-identical to the
baseline, and the workspace shrank from 23 946 576 to 23 866 624 bytes.
Lookups for the first shape fell from 27k to 7.4k at n = 8, but growth per
doubling is still superlinear: the dense tables, removed in stages 2 to 4,
dominate.

**Stage 2a (foundations for borrowed child state) is complete.**

- **One arena.** Both passes and every recursion level now share one
  `dep_route_arena_t`: maps, snapshots, alternative lists, names and the join
  cache. A nested parse returns its suffix through checkpoint and restore, and
  collection runs only with no checkpoint open. During the root's final walk,
  collection also keeps the live construction roots.
- **Evaluation-wide slot ids.** Allocation records live in the arena, so equal
  operations get equal private slots in both passes. Per-pass fields (frame
  membership and observations) are indexed by pass. A per-reset epoch keeps
  "reached by this pass" exact, as separate journals did.
- **Depth-tagged resources.** Resource routes (DOC, DYNAMIC with an edge,
  CAPTURE, PIPE, PIPE_INPUT, PIPE_OUTPUT) carry their graph's parse depth
  above a 24-bit index (`dep_resource_value`), so a value is unambiguous in
  any nested parse that inherits it.
- **Joiner (stage 2b.1).** Child import uses carry the resource route itself,
  and the joiner tells local from foreign resources by depth. It no longer
  merges entries into the parent's import table, and the join plan's
  import-table copy is gone.

The golden output is byte-identical at every step. The workspace is now
21 546 424 bytes.

**Stage 2b.2 (borrowed child state) is complete.**

A nested parse starts every version from its parent's version on the same
path, restricted to the fact class. Nothing is copied or translated.

- **Entry transforms.** A capture replaces its standard stream. Earlier
  assignments enter an inherited shadow set, and on assignment-only paths they
  are also present and bound to no descriptor. The path's IFS is stored when
  it differs from the inherited one. The process domain gets its capture
  adjustment. The parent pass's fact-existence flags (`ifs_seen`,
  `save_marks`) carry over.
- **Removed.** Import records, child slot adoption, `IMPORTED` routes, the
  lazy scalar-import fallback (`scalar_imports`) and the parent's
  per-descriptor export. An export now costs O(paths), not O(paths × fds).
- **Presence writers** moved into the arena like allocation records.
- **Capture precision fix.** Argument capture now adopts a private identity
  when the requirement-feasible part of a binding is one live descriptor. This
  fixes the known gap of a zero-count read of a twice-failable `{fd}`.
- **Fallbacks.** Construction and final-walk lookups fall back to the
  executor contract. The final walk's initial owner table is still the
  materialized entry state, until stage 3 removes the tables.

Golden differences: 38 sources. All are removed implicit standard-stream uses:
70 fd-0 writes and 2 fd-1 reads by commands inside substitutions. An old child
received these only when the parent's dense table happened to hold an fd-0 or
fd-1 slot, whereas a root command never does. A child now follows the root
command's rule. The list is in `build/scratch/golden/stage2b-classified.txt`.

Measured after stage 2, for the substitution shape at n = 8, 16 and 32:
route lookups were 5.3k, 14k and 41k (originally 27k, 85k and 290k);
child exports were 8, 16 and 32. The remaining superlinear growth is the dense
owner tables (stages 3 and 4).

**Stage 5 (one interpretation) is complete.**

- **5a: one semantics.** Construction and the final walk now compute the same
  executed facts for every owner. Construction completes every owner
  (`dep_snapshot_finish`), not only those an expansion queried. A test-build
  check (`dep_interpretation_fingerprint`) aborts when the final walk's facts
  differ from construction's. The comparison is of fact sets: versions that
  differ only in a pass's bookkeeping, such as setup modes, are the same
  interpretation. The convergence fixes were:
  - Pipe ends are installed once (`dep_snapshot_install_pipeline`), keyed by
    the owner. Publication resolves them through `owner_edges`
    (`dep_route_pipe`), and `DEP_ROUTE_PIPE` is gone.
  - An async owner's redirect entry applies only commits made before its
    redirections; `cd`'s `PWD` write happens after them.
  - The construction setup frame begins at the owner's first operation, even
    when the operand table resumes from an earlier checkpoint. Construction's
    setup entry is its operand table at position 0.
- **5b: the final walk consumes construction (done).**
  - **5b.2a:** construction records setup diagnostics per frame. An event's
    owner is set before it begins. A marked entry, redirect-position or
    arithmetic diagnostic is reported when its owner completes
    (`dep_snapshot_owner_diagnostics`). The convergence fixes were:
    - Construction honours the coverage barrier.
    - A known open failure follows its open.
    - A redirection is judged by all its operations
      (`dep_fd_level_outcomes`); a process substitution's own path always
      opens.
  - **5b.2b:** construction records each event's entry, executed state,
    report state and enclosing scope flow, and each group's scope,
    setup-failure and parent flows. The convergence fixes were:
    - Pipe ends are installed after the assignment-phase entry.
    - The post-redirection checkpoint gets a private table, so body process
      words cannot reach an earlier checkpoint.
    - An untouched report starts from the entry with its reached setup
      published.

    Interpretations were compared by an order-insensitive hash of their
    facts, because the passes join the same routes in a different order.
  - **5b.2c:** the final walk publishes from those records, using
    construction's prepared and effective operations. Deleted:
    - its outcome stream, begin, finish and group completion;
    - its operation list, its operation application, observation and stdin
      replay, and diagnostics;
    - `dep_sort_fd_operations`, `dep_add_dup_operations`,
      `dep_observation_pending` and `dep_snapshot_diagnostic_positions`.

    Construction's findings go to the evaluation registry
    (`dep_route_journal_t.registry`): contract violations and required open
    causes. The final walk reads construction's states under construction's
    pass and epoch, so its allocation records are visible. The returned
    observation program comes from construction's final flow.
  - **Results:** goldens and the test-build corpus scan are identical to the
    stage 4 baseline. All tests pass, including
    `paired_open_preparation_scaling`. Operation work is linear (152, 304
    and 608 at n = 8, 16 and 32). The workspace is 15.3 MB; the records add
    0.8 MB.
- **5c: one journal (done).** The final walk reads and publishes through
  construction's journal, which is now the evaluation's only journal
  (`dep_route_workspace_t.journal`). Removed:
  - the final walk's journal, with its reset and observable metadata copy;
  - its entry re-import: it takes construction's `persistent[0]` instead;
  - the per-pass allocation fields and `dep_route_journal_t.pass`;
  - the registry pointer.

  The violation flag and the open-cause registry live in that journal.
  Construction's copy-source checks register there. The root's observation
  inventory is collected in `read_inventory` before construction's journal
  receives it.

**Stage 4 (use-driven publication) is complete.** No dense descriptor table
remains in the engine.

- **Owner uses.** Each owner records its uses (`dep_owner_use_t`): the numeric
  descriptors its redirections touch, and the standard descriptors that have
  a fact in its final state. They are kept in fd order with the halves the
  last redirection assigned. Publication visits only these, and reads routes
  from the owner's final local state (`owner_local_state`,
  `dep_owner_state_route`). It never reads a materialized table.
- **Removed.**
  - `routes[]`, `scoped_routes`, `group_snapshot_routes`, `owner_initial` and
    `persistent_routes`;
  - materialization, which covers `dep_fd_materialize*` and the test-only
    reference materializer;
  - `dep_copy_routes` and every dense-table helper;
  - the named-mutation table edits;
  - the dense continuation restore, and the restore set it read;
  - `dep_owner_routes_t` itself.

  A pipe end's installed route is computed from the owner's pipe ends. The
  undo-target set is a `dep_fd_set_t`. The named-live map summary had no
  remaining reader, so it is no longer computed.
- **Golden differences:** 264 sources, all of one class. A standard descriptor
  used to keep a dense slot inherited from an earlier owner's table even when
  the owner's state held no fact for it. That slot published both directions:
  writes to the inherited fd 0, and reads from the inherited fd 1 and fd 2. A
  standard descriptor now has a use only when the owner's state configures it;
  otherwise the executor contract's directions apply. These are the same
  rules as the stage 2 class. The list is in
  `build/scratch/golden/stage4-classified.txt`; one source renumbers its
  nodes after its fd-0 write disappears.
- **Lookups**, at n = 8, 16 and 32, where n = 32 hits the graph limits:

  | shape | lookups |
  |---|---|
  | `exec N<input; true "$(read -uN …)"` | 2.8k, 6.3k, 14k |
  | `exec N<input; cat <&N >outI` | 4.5k, 10k, 23k |
  | the prior-assignment chain | 3.0k, 6.7k, 13k |
- **Workspace:** 16.9 MB to 14.5 MB.

**Stage 3 (state roots instead of dense snapshot tables) is complete.**

- **No `baseline` parameter.** A fact lookup that finds no stored key uses the
  executor contract. Named-binding visibility is a fact in the state: some
  version stores a binding for the name (`dep_route_state_stores`). Before
  removing the table fallback, the corpus and suite were run with both answers
  computed side by side; they never differed. The parameter was then removed
  from every transfer and query function, by an unused-parameter fixpoint.
  The merge cache no longer keys on it.
- **No dense snapshot tables.** A snapshot table is now its versions' roots.
  Construction no longer materializes, copies or replays operations onto dense
  tables. `dep_fd_bindings` binds a named operation's variable to a live
  descriptor from the state alone. The dense `before`/`after` views changed no
  result: the later mutation step, and failed setup, overwrite that binding on
  their paths. The tables' last readers, and `dep_apply_persistent_owner_routes`
  and its helpers, are deleted.
- **Live named documents.** A parse diffs its final versions against its entry
  versions, instead of walking every key it borrows. An entry fact is
  inherited, so it cannot name one of this graph's documents.
- **Prior assignments.** These are the temporary assignments a nested
  expansion sees. The parent applies them when it exports the expansion, so
  both of the nested parse's passes borrow the result. A later expansion of the
  same command resumes from the previous result for the same version. It
  rebases that result onto its own parent version by a fact diff, and applies
  only the names between the two positions. A command's nested entries cost
  O(assignments + differing keys) map updates in all, where they used to cost
  O(assignments) each.
- **Predefined variables.** Prefix variable resolution visits only predefined
  variables (`special`), not every prefix name.

Results:
- **Goldens:** identical to the stage 2 baseline.
- **Scaling test:** the owner-lifetime check in `read_input_test` now passes.
- **Lookups**, for the `v=${g:+$(false)<(:)$(true)}` chain at n = 4, 8 and 16:
  1.6k, 3.4k and 7.4k. They were 2.0k, 5.1k and 16k.
- **Workspace:** 19.9 MB to 16.9 MB.

The final walk still materializes owner tables for publication (stage 4).

### Stage 2b.2 design: borrowed child state

A child parse starts each of its versions from the parent version of the same
path. Nothing is copied:

- **Key classes.** A key's top bit separates scope bookkeeping from inherited
  facts. In a Patricia trie the keys sharing a prefix form one existing
  subtrie, so the child's entry state is the parent root restricted to the
  fact class: an O(W) walk that allocates nothing (`shell_pmap_restrict`).
  - Bookkeeping (cleared at entry): PRIVATE_ENTRY, PRIVATE_SCOPE,
    SUBSTITUTION_STATUS, SAVED, ENTRY, SETUP_FRAME, ALLOCATION_SLOTS,
    UNDO_ENTRY, UNDO_TARGET, UNDO_EXEC, SETUP_MODE, PROCESS_SLOT,
    PROCESS_BEFORE, numeric READ_ARGUMENT token ordinals, and transient
    numeric EFFECT_STATE.
  - Facts (inherited): READ, WRITE, BINDING, SELECTOR, SCRATCH, AVAILABLE,
    PROCESS_DOMAIN, PROCESS_OWNED, NAMED_BINDINGS, PRESENCE_MAP,
    VARIABLE_PRESENCE, IFS, STDIN_REDIR, named READ_ARGUMENT values, and the
    variable-capability EFFECT_STATE.
- **No translation.** Resource routes are depth-tagged and slots are
  evaluation-wide, so the child reads its parent's routes and slots directly.
  Import records, child-local slot adoption, the dense `baseline` table and
  the lazy scalar-import fallback all disappear. A missing key always means
  the executor contract.
- **Entry transforms, constant per path.** A capture replaces fd 0 or fd 1 with
  the capture route and adjusts the process domain. An assignment-only command
  applies its preceding temporary assignments, whose IFS value and name
  invalidations are O(k) in its own assignments.
- **Read-observation correlation (done, golden output identical).** Children
  return presence conditions only. The binding-proof machinery
  (`dep_read_observe_binding`, `INHERITED_OBSERVATION`, and the VALUE,
  IDENTITY, ACCESS and BINDING condition kinds) is gone. Two things were kept
  after measuring them:
  - the capture roles that record a read argument's descriptor at expansion;
  - the binding and read-access merge correlations, which keep a named
    descriptor's binding paired with its route and keep failed-open paths
    apart.

  Dropping the roles rejected 284 golden sources; dropping the read-access
  correlation rejected 52 ordinary named reads.

## Inventory of removed structures

### `baseline` dense tables (stage 2)

148 functions thread `const dep_owner_routes_t *baseline` (90 in
`shell_depgraph_fdflow_impl.h`, 45 in `shell_depgraph.c`, 13 elsewhere). Most
only pass it on. Real reads:

| Site | Use | Replacement |
|---|---|---|
| `dep_route_find(baseline, fd)` in the root-fact fallback (`shell_depgraph_fdflow_impl.h`, `shell_depgraph_factmap_impl.h`) | value of a key the map lacks | contract defaults, or the parent checkpoint root |
| `baseline->scalar_imports` (fact fallback, presence, `dep_read_scalar_shadowed`) | parent value map for a child | parent checkpoint root per path |
| `baseline->fd[]` loops in `dep_fd_materialize`, `dep_fd_materialize_delta`, `dep_fd_materialize_reference` | enumerate descriptors to materialize | removed with materialization (stage 3) |

Constructed by `dep_import_routes` (child entry), the snapshot frame's
`persistent[0]` table, and `owner_initial`.

### Substitution imports (stage 2)

`dep_snapshot_fd_imports` exports every snapshot descriptor, for each access
and path, into `dep_fd_imports_t` (`entries`, `index`, per-path arrays);
`dep_import_routes` copies them into the child's baseline. The joiner reads
`import_index` (`dep_fd_import_use_t`). Replacement: the parent checkpoint root
per path, plus import records created on first touch and keyed by
(checkpoint, key). Origin, process ownership, selector, places and allocation
site move into the resource that the route names.

### Snapshot tables and materialization (stage 3, done)

`dep_snapshot_phase_table` materializes a dense table per owner
(`dep_fd_materialize` / `_from`) and copies tables (`dep_copy_routes`, 19
sites); `snapshot_tables` has 29 uses. Consumers query descriptor facts at
expansion phases: operand tables (`dep_snapshot_operand_table`), process
words, assignment-phase imports, IFS, and stdin redirect. Replacement: a
checkpoint root per (owner, phase) and direct root queries.

### Publication tables (stage 4, done)

`workspace->routes[SHELL_DEP_MAX_NODES]`, `route_slots`, `route_touched` (17
uses), `route_listed`, `route_standard_mask`, `scoped_routes` (15),
`group_snapshot_routes` (11). Replacement: each owner's state root plus its
use list (redirect operands, `read -u` selections, standard descriptors).

### Second simulation (stage 5)

`snapshot_journal` and the snapshot frame's replay of the event stream,
alongside `route_journal` in `dep_resolve_effective_routes`. Replacement: one
forward interpreter producing checkpoints.

### Read-observation correlation (stage 2)

`DEP_READ_OBSERVE_VALUE/IDENTITY/ACCESS`, `dep_read_observe_binding`,
`DEP_FD_ACCESS_INHERITED_OBSERVATION`, the observation transfer program
(`dep_observation_apply`, clauses and conditions returned by substitutions
through `observe_return`), entry-fact memoization (`dep_observation_require`),
and the merge correlations on read observations. Most of it carries facts
across the parent/child boundary that stage 2 replaces, so it is removed
there. `DEP_READ_OBSERVE_PRESENCE` stays. Done in stage 2, except what the
progress notes record as kept after measurement: the VALUE, IDENTITY and
ACCESS capture roles with their observation program, and the binding and
read-access merge correlations. These are an observability index for merges,
not a read-outcome correlation; replacing them is not part of this redesign.

## Verification

### Golden graphs

A corpus of every source that the test suites pass to the public parse entry
points was harvested at the start of the redesign: 22 276 unique sources. Test
executables were linked with `-Wl,--wrap` for `shell_dep_graph_parse`,
`shell_dep_graph_parse_with_fast` and `shell_dep_graph_parse_resolved`. The
read-input suite was harvested with its owner-lifetime scaling check
neutralized, so its later sources are included.

`shellsplit_golden_graphs CORPUS` (`shellsplit/tests/golden_graphs.c`)
prints each source's status, every semantic node field, and the sorted edges,
with default limits and "/" as the initial CWD. Each stage's output must be
byte-identical to the baseline, or every difference must be classified as a
precision gain verified against the reference Bash, or a soundness fix with a
Bash reproduction. Classified differences are listed in the stage's commit
message. The baseline is never re-recorded to make a stage pass.

The corpus and baseline are too large to commit; they are kept outside the
tree and identified by hash:

| File | SHA-256 |
|---|---|
| corpus (hex, one source per line) | `5644b2c635c83e4659f5ccafee397d3ac589b57cef410c8901ca96462441ffd6` |
| baseline output | `660b180376f71d12edfb7699480f40fef4b5534b703a96b623c0569dd7c159bc` |
| stage 2 baseline (classified differences only) | `066f6f81963290ec8a860dec7cff3c7fe859af2e68ad0b76285735ccee8e0d78` |
| stage 4 baseline (classified differences only) | `b1592c9ff926e955d34e2b62f13bb734ec5b18836f833ef26de4dde4e1002182` |
| stage 6 baseline (classified differences only) | `0e6717c088fa4c4bd3a369db3ec473fec26a067ed03b10cfeae6a8bfdb9db24c` |

Node ids are construction order, which stages 1–4 do not change. If stage 5
changes it, the serializer gains a content-based relabeling before that
stage's comparison.

### Whole changeset against the public commit

The stage gate compares adjacent stages. The changeset as a whole is compared
against the public commit 4b81fd6, with the same serializer built in a
per-source forked harness, because the public engine crashes on 10 corpus
sources. Its output is `c7a8f6ee9a77936e8f811cc0866f82d5185e4e303fbd222544a0bf77b7f14975`.

1944 sources differ:
- 291 differ only through the redesign: the pre-stage-1 baseline equals
  public;
- 1554 differ only through the pre-redesign work that the baseline already
  contains;
- 99 differ through both.

Every difference is classified:
- Rejections are replayed with the pinned reference Bash in a bubblewrap
  sandbox: read-only root, private `/tmp` as the working directory, no network
  and an empty `PATH`. Several variants run, with and without input fixtures,
  stub commands exiting 0 and 1, and an unwritable working directory.
- Graph changes are compared with nodes named by content. REQUIRED and
  TRANSIENT are masked, and every remaining edge change must be explained by a
  structural reason, or else by a family whose Bash behaviour was checked by
  hand.

| Public → current | Sources | Classification |
|---|---|---|
| → EUNMODELED | 952 | from a graph (936), a public crash (7), EPARSE (6) or ETRUNC (3); below |
| crash → graph | 3 | public SIGSEGV fixed |
| ETRUNC → graph | 9 | capacity no longer exceeded (scaling) |
| graph → ETRUNC | 2 | unknown-arity `read` operands: Bash can report an invalid identifier; the capacity limit fires before the EUNMODELED verdict |
| graph → graph | 978 | below |

The 952 new rejections:

| Bash behaviour | Sources | Classification |
|---|---|---|
| reports an error | 847 | certain or possible shell-level error, including destroyed Bash saves and ambiguous redirects (stage 6) |
| reports an error only on another path | 23 | another feasible path errors (stub exit 0/1, unset/set variables, missing fixtures, unwritable cwd; for three padded sources, a first word too long to stub succeeding and undoing its redirects) |
| certain failure it does not report | 8 | empty command name (127), empty redirect target, write to closed stderr |
| rejected by design rule | 74 | explicit fd ≥ 10 may alias a save (46, one of them Bash-clean: a destroyed save reopened before its restore), dynamic `read` option (17), special-variable write (10), unquoted expansion in `read` operands (1) |

A graph change can have several reasons. "Both" counts sources that the
pre-redesign work and stages 1–6 each changed:

| Reason | Sources | Part |
|---|---|---|
| REQUIRED marking (required-open rule) | 541 + 96 | pre-redesign + both |
| standard stream used against its contract direction no longer published: a write to fd 0, a read from fd 1 or 2 | 250 + 85 | redesign (dense slot lineage, stage 4) + both |
| standard-stream use of an unreachable or redirected command removed, including the error message of a copy that fails only along a required open (stage 6) | 85 | pre-redesign |
| fds ≥ 3 closed at entry: inherited fd ≥ 3 endpoints removed | 150 + 45 | pre-redesign + both |
| setup document now TRANSIENT, its dead uses removed: a named allocation clobbered by a restore or rebind, or a read taking `-u` input | 39 + 5 | pre-redesign + both; Bash-checked on 10886, 10889, 10926; rebinds (12215) follow the documented TRANSIENT rule |
| commands after a certainly failing `read -u3` unreachable, substitution endpoint folded | 19 (23 folded) | pre-redesign; Bash: `3: invalid file descriptor` |
| a capture or time report only where a copy failed along a required open | 3 | stage 6 dominated flow |
| time report follows `exec 2>&10`, or is not emitted after `4>&2-` | 3 | precision; Bash-checked |
| process-substitution pipe on fd 0 feeds `read` | 2 | soundness fix; Bash reads `payload` |
| input on fd 12 (`cat {x}<f 12<g {x}>&-`) published | 1 | soundness fix |
| reached here-string setup on fd 3 published | 2 | contract fix (TRANSIENT contract) |

No difference is unexplained, and no known precision loss against public
remains. The redesign contributes the standard-stream direction class and the
stage 6 rules below; the other changes in semantics predate it.

#### Stage 6 precision rules

The first classification listed three precision losses. Rechecked:

- Repeated swapped moves (`: 3>&4- 4>&3-`, three sources) were not a loss.
  Their corpus spelling is padded without a newline, so the first word is a
  command whose redirects are undone after it; on its success path Bash
  reports `4: Bad file descriptor`. They are rejections with an error on
  another path.
- A reached copy or move whose source is missing on every path that reaches it,
  each time only where a required open failed, now stops its owner's setup
  (`owner_setup_stop`) instead of running the body with the copy dropped:
  `true 10>&- {f}>out 4>/missing/x || printf value >&$f` no longer publishes
  printf on stdout (Bash: `$f: Bad file descriptor`).
- A copy's outcomes now ignore source routes missing only where a failed open
  left them (`dep_required_feasible`), as reads already did. Construction marks
  those opens required (`dep_fd_copy_source_exists`), so such a failure lies
  only along a required open's failure: a dominated flow, which the trust
  invariant represents by its first cause. This fixes the empty-substitution
  family (`a=$(read -u11 -n0 probe) b=$( ) && { true 3<&11 || printf
  impossible >bad; }`, where Bash never reaches printf). The cause was never
  the empty substitution's status, which was already modeled. It also accepts
  four Bash-clean scripts that the analysis used to reject
  (`exec 3</tmp/move-in; : <&3-; cat <&3` and three group-`exec` moves), each
  now with its opens REQUIRED.

Against the stage 4 baseline these rules change 78 sources: 4 newly accepted,
the rest only drop flows along required opens' failures. Every document
required before stays required, except `/tmp/move-a` in 11528, whose failure
the script handles with `||`; the remaining requirements cover every path.
The gate now compares against `baseline-stage6.out`.

#### Stage 6 descriptor contract

Two soundness gaps older than the redesign (public accepts them too) were
found while bringing the fuzz oracles up to the contract:

- A descriptor-only `exec` discards its undo list but still runs Bash's exec
  undo list (`exec_redirection_undo_list` in Bash's redir.c): a close of each
  save it made, newest first, and a restore of each redirection target that
  was itself a close-on-exec Bash save. A persistent close of a save made by
  an enclosing frame of the same shell therefore destroys it, and the frame's
  restore fails (`{ exec 11>&-; } 3>&1 4>&1`: "11: Bad file descriptor"); a
  redirection onto a save made earlier in the same list is closed afterwards
  (`exec 3>&4 10>&4` leaves fd 10 closed). The engine modeled `exec` without
  that list, and its check for a persistent close fired only for external
  setup, which cannot reach the parent's saves. `dep_fd_exec_contract_holds`
  now decides both cases against the owner's setup entry and the shell's
  entry state (a child shell's copies of its parent's saves are never
  restored from), and an open or copy onto a descriptor at or above 10 makes
  earlier saves observable. Following the static-safety decision, a destroyed
  save has no model: the stopped-undo-list and leaked-save expectations in the
  tests became rejections. Against the stage 6 baseline this rejects 38
  corpus sources, 37 of them Bash errors (two hidden in captured or redirected
  stderr) and one Bash-clean (11750, a save closed and reopened before its
  restore).
- An unquoted brace expansion in a redirection operand yields several words,
  Bash's "ambiguous redirect" (`>file{a,b}`, `>&{{1,2}}`, `>~/{a,b}`); it is
  now a recorded file failure (`dep_word_brace_expands`). Three corpus
  sources.

The fuzz smoke (shellsplit, shelltype, shellgate, with LeakSanitizer) had
not passed since the closed-entry contract: its fixed oracles still expected
models for scripts the pinned Bash rejects. Each was checked against Bash
and now expects no model, or gets a valid spelling where it tests something
else. Five-minute sanitizer runs of the shellsplit and shellgate fuzzers are
clean.

One precision gap remains, recorded in the shellsplit fuzz oracle: when a
group's setup fails (`{ exec 3>&2; } 2>local`), the descriptors its body
would have set are not attributed to that failed open, so a later copy from
them is not excused and the script is rejected, although Bash reports to
`local` (public accepted it under its older contract).

The classification found one redesign defect, now fixed. A one-sided join of
named bindings wrote the holder `{DYNAMIC, UINT32_MAX}`, and later named
queries descended into that sentinel as a map root. Nothing in the corpus
reaches it, because the padded variant of the triggering source stops at
ETRUNC first. The unpadded variant crashed. The holder is now `{DYNAMIC, 0}`,
the form the opaque mutation already used, so the holder's value is always an
override map root. `read_input_test` carries the reproducer, which fails
under ASan without the fix. The corpus, with each padded source also run
unpadded and with a prefix command (26 088 sources), runs clean under ASan
and UBSan.

### Scaling

`shellsplit_fd_scaling_test` (`shellsplit/tests/fd_scaling_test.c`) repeats
one unit per family: opens with substitutions, opens with redirecting
commands, substitutions touching no descriptor, nested substitutions,
branch ladders over named descriptors, groups with save and restore, named
allocations, pipelines, process substitutions and here-documents. It runs
n = 4, 8, 16, 32 up to the largest size within the fixed graph capacity
(SHELL_DEP_MAX_NODES and SHELL_DEP_MAX_EDGES are compile-time bounds, so
limits cannot be raised past them), and every parse must succeed. Work is
all counted metadata work, including persistent-map steps
(SHELLSPLIT_TEST_WORK_MAP_STEPS). Each family must satisfy
`work(2n)/work(n) ≤ 2.2 × bytes(2n)/bytes(n)` and `work ≤ C·n·log2 n`, C
being its measured worst value plus a quarter. Measured growth is about
2.2× per doubling of bytes, close to linear.

### Every stage

The full test suite, the golden comparison, the reference-Bash suites, and
`shell_dep_workspace_size()`, which must not grow from its default-limits
baseline of 23 946 576 bytes. Sanitizer fuzzing ran at the end of the
redesign (stage 6).
