/* Persistent fact maps of the descriptor dataflow analysis.
 *
 * Included once, by shell_depgraph.c, at this point of its single
 * translation unit, so its definitions inline as before.
 *
 * A version of the analysis state is an immutable map from (key, access) to
 * an interned bounded set of tagged words (dep_route_set_t). Maps are
 * hash-consed Patricia tries (shell_pmap_internal.h): updates copy one
 * root-to-leaf path, versions share every unchanged subtree, equal maps have
 * equal roots, and walks over two versions visit only their differing keys.
 * Equal values are interned once. The journal owns the nodes and value
 * snapshots, and reclaims what no live root reaches by mark and sweep from
 * explicit roots. A route state is a primary version plus a bounded list of
 * alternative versions. Nothing here interprets the facts: the transfer
 * functions of shell_depgraph_fdflow_impl.h give them their meaning. */

static SHELL_NONNULL(1) bool dep_route_set_contains(const dep_route_set_t *set,
                                                    dep_fd_route_t route) {
  for (uint32_t i = 0; i < set->count; i++)
    if (set->routes[i].kind == route.kind &&
        set->routes[i].value == route.value)
      return true;
  return false;
}

static bool dep_route_set_add(dep_route_set_t *snapshot, dep_fd_route_t route) {
  if (dep_route_set_contains(snapshot, route))
    return true;
  if (snapshot->count >= SHELL_DEP_TIME_MAX_EXTERNAL_FDS) {
    snapshot->truncated = true;
    return false;
  }
  snapshot->routes[snapshot->count++] = route;
  snapshot->ready = true;
  return true;
}

static void dep_route_set_set(dep_route_set_t *snapshot, dep_fd_route_t route) {
  *snapshot = (dep_route_set_t){0};
  (void)dep_route_set_add(snapshot, route);
}

static SHELL_NONNULL(1, 3) int dep_route_name_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  const dep_route_journal_t *journal = context;
  return dep_fd_ref_compare(journal->arena->names[index],
                            *(const dep_fd_ref_t *)key);
}

/* The key of (fd, access), when the journal has seen fd's name: a map
 * cannot bind a name it has never interned. */
static SHELL_NONNULL(1, 4) bool dep_route_key_find(
    const dep_route_journal_t *journal, dep_fd_ref_t fd, dep_fd_access_t access,
    uint64_t *key) {
  if (fd.value != SHELL_DEP_FD_NAMED) {
    *key = dep_route_key_of(fd.value, access);
    return true;
  }
  uint32_t cursor = journal->arena->name_root;
  while (cursor) {
    int order = dep_route_name_compare(journal, cursor - 1, &fd);
    if (!order) {
      *key = dep_route_key_of((UINT64_C(1) << 32) + cursor, access);
      return true;
    }
    cursor = order > 0 ? journal->arena->name_index[cursor - 1].left
                       : journal->arena->name_index[cursor - 1].right;
  }
  return false;
}

/* The key of (fd, access), interning fd's name; false when the name table
 * is full. */
static SHELL_NONNULL(1,
                     4) bool dep_route_key_intern(dep_route_journal_t *journal,
                                                  dep_fd_ref_t fd,
                                                  dep_fd_access_t access,
                                                  uint64_t *key) {
  if (fd.value != SHELL_DEP_FD_NAMED) {
    *key = dep_route_key_of(fd.value, access);
    return true;
  }
  uint32_t candidate = journal->arena->name_count + 1, match = 0;
  journal->arena->name_root = shell_avl_insert(
      journal->arena->name_index, journal->arena->name_root, candidate,
      DEP_ROUTE_NAME_CAPACITY, dep_route_name_compare, journal, &fd, &match);
  if (!match)
    return false;
  if (match == candidate)
    journal->arena->names[journal->arena->name_count++] = fd;
  *key = dep_route_key_of((UINT64_C(1) << 32) + match, access);
  return true;
}
/* The interned value snapshot bound to (fd, access) in a map, a root (whose
 * named bindings and presence names live in their own submaps, below), or a
 * state's primary version; 0 when unbound. */
static SHELL_NONNULL(2) uint32_t
    dep_route_map_snapshot(uint32_t root, const dep_route_journal_t *journal,
                           dep_fd_ref_t fd, dep_fd_access_t access) {
  uint64_t key;
  uint32_t snapshot;
  if (fd.value == SHELL_DEP_FD_NAMED && access == DEP_FD_ACCESS_BINDING)
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BINDING_INVALIDATION);
  return dep_route_key_find(journal, fd, access, &key) &&
                 shell_pmap_get(&journal->arena->maps, root, key, &snapshot)
             ? snapshot
             : 0;
}

/* Ordered iteration over one map, and over the keys whose values differ
 * between two maps. Keys order by descriptor reference, then access. A
 * snapshot argument of 0 means the map does not bind the key. A visitor
 * returns false to stop the walk, which then returns false; callers that stop
 * for a reason other than failure record that reason in their context. Maps
 * are immutable, so visitors may publish new versions while walking. */
typedef struct {
  const dep_route_journal_t *journal;
  dep_route_each_visit_t each;
  dep_route_diff_visit_t diff;
  void *context;
} dep_route_walk_t;

static bool dep_route_each_leaf(void *context, uint64_t key, uint32_t value,
                                uint8_t summary) {
  (void)summary;
  const dep_route_walk_t *walk = context;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  return walk->each(walk->context, dep_route_key_fd(walk->journal, key),
                    dep_route_key_access(key), value);
}

static SHELL_NONNULL(1, 3) bool dep_route_map_each(
    const dep_route_journal_t *journal, uint32_t root,
    dep_route_each_visit_t visit, void *context) {
  dep_route_walk_t walk = {journal, visit, NULL, context};
  return shell_pmap_each(&journal->arena->maps, root, dep_route_each_leaf,
                         &walk);
}

static bool dep_route_diff_leaf(void *context, uint64_t key,
                                shell_pmap_sides_t present, uint32_t left,
                                uint32_t right) {
  const dep_route_walk_t *walk = context;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  return walk->diff(walk->context, dep_route_key_fd(walk->journal, key),
                    dep_route_key_access(key),
                    present & SHELL_PMAP_LEFT ? left : 0,
                    present & SHELL_PMAP_RIGHT ? right : 0);
}

static SHELL_NONNULL(1, 4) bool dep_route_map_diff(
    const dep_route_journal_t *journal, uint32_t left, uint32_t right,
    dep_route_diff_visit_t visit, void *context) {
  dep_route_walk_t walk = {journal, NULL, visit, context};
  return shell_pmap_diff(&journal->arena->maps, left, right,
                         dep_route_diff_leaf, &walk);
}

/* root without its scope bookkeeping (dep_route_bookkeeping): the facts a
 * forked child inherits. An existing subtrie, found without allocating. */
static SHELL_NONNULL(1) uint32_t
    dep_route_facts(const dep_route_journal_t *journal, uint32_t root) {
  return shell_pmap_restrict(&journal->arena->maps, root, 0, 62);
}

/* A missing holder is the initial, empty override map: the executor contract.
 * This is a value, not an epoch or a pointer into mutable storage. The
 * holder's value is always an override map root; its kind says what a name
 * without an override reads as: INHERITED its contract value, DYNAMIC
 * unknown. */
static SHELL_NONNULL(2) dep_fd_route_t
    dep_named_bindings(uint32_t root, const dep_route_journal_t *journal) {
  uint32_t holder = dep_route_map_snapshot(root, journal, dep_fd_numeric(0),
                                           DEP_FD_ACCESS_NAMED_BINDINGS);
  return holder ? journal->arena->snapshots[holder - 1].routes[0]
                : (dep_fd_route_t){DEP_ROUTE_INHERITED, 0};
}

static SHELL_NONNULL(2) uint32_t
    dep_presence_bindings(uint32_t root, const dep_route_journal_t *journal) {
  uint32_t holder =
      dep_route_map_snapshot(root, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                             DEP_FD_ACCESS_PRESENCE_MAP);
  return holder ? journal->arena->snapshots[holder - 1].routes[0].value : 0;
}

static SHELL_NONNULL(2) uint32_t
    dep_route_root_snapshot(uint32_t root, const dep_route_journal_t *journal,
                            dep_fd_ref_t fd, dep_fd_access_t access) {
  if (fd.value == SHELL_DEP_FD_NAMED && access == DEP_FD_ACCESS_BINDING)
    root = dep_named_bindings(root, journal).value;
  else if (access == DEP_FD_ACCESS_VARIABLE_PRESENCE)
    root = dep_presence_bindings(root, journal);
  return dep_route_map_snapshot(root, journal, fd, access);
}
/* Path-independent queries use dep_fd_raw_fact(). This helper is reserved for
 * callers already operating on the selected primary immutable version. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_route_state_snapshot(const dep_route_state_t *state,
                             const dep_route_journal_t *changes,
                             dep_fd_ref_t fd, dep_fd_access_t access) {
  return dep_route_root_snapshot(state->root, changes, fd, access);
}

static SHELL_NONNULL(1, 3) int dep_route_snapshot_compare(const void *context,
                                                          uint32_t index,
                                                          const void *pending) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  const dep_route_journal_t *journal = context;
  const dep_route_set_t *left = &journal->arena->snapshots[index],
                        *right = pending;
  if (left->count != right->count)
    return left->count < right->count ? -1 : 1;
  if (left->ready != right->ready)
    return left->ready ? 1 : -1;
  if (left->truncated != right->truncated)
    return left->truncated ? 1 : -1;
  for (uint32_t i = 0; i < left->count; i++) {
    if (left->routes[i].kind != right->routes[i].kind)
      return left->routes[i].kind < right->routes[i].kind ? -1 : 1;
    if (left->routes[i].value != right->routes[i].value)
      return left->routes[i].value < right->routes[i].value ? -1 : 1;
  }
  return 0;
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_route_set_intern(dep_route_journal_t *changes,
                         const dep_route_set_t *routes) {
  uint32_t candidate =
      changes->arena->snapshot_reuse && changes->arena->snapshot_free
          ? changes->arena->snapshot_free
          : changes->arena->snapshot_count + 1;
  uint16_t next_free = candidate <= changes->arena->snapshot_count
                           ? changes->arena->snapshot_index[candidate - 1].left
                           : 0;
  uint32_t match = 0;
  changes->arena->snapshot_root = shell_avl_insert(
      changes->arena->snapshot_index, changes->arena->snapshot_root, candidate,
      DEP_ROUTE_SNAPSHOT_CAPACITY, dep_route_snapshot_compare, changes, routes,
      &match);
  if (match == candidate) {
    if (candidate <= changes->arena->snapshot_count) {
      changes->arena->snapshot_free = next_free;
      changes->arena->snapshot_free_count--;
    } else {
      changes->arena->snapshot_count++;
    }
    changes->arena->snapshots[candidate - 1] = *routes;
    changes->arena->snapshot_allocations++;
  }
  return match;
}

/* Snapshot interning is mutable within a parse, unlike published route
 * versions. A recursive child removes only its newly interned suffix before
 * releasing borrowed child source and reclaiming workspace storage. */
/* key identifies an existing interned snapshot; callers maintain that
 * invariant. Removing a two-child node moves links, never record identities. */
static SHELL_NONNULL(1, 3) uint32_t
    dep_snapshot_index_remove(dep_route_journal_t *journal, uint32_t root,
                              const dep_route_set_t *key) {
  return shell_avl_erase(journal->arena->snapshot_index, root,
                         dep_route_snapshot_compare, journal, key);
}

/* Start an evaluation's value storage. Every journal sharing arena starts
 * afterwards; their earlier roots become invalid. */
static SHELL_NONNULL(1) void dep_route_arena_reset(dep_route_arena_t *arena) {
  shell_pmap_init(&arena->maps, arena->map_nodes, arena->map_table,
                  arena->map_marks, DEP_ROUTE_CHANGE_CAPACITY,
                  DEP_ROUTE_MAP_TABLE);
  uint32_t memo = DEP_ROUTE_UNION_MEMO;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* Tests run the analysis with a smaller table: results must not change. */
  if (shellsplit_test_union_memo_limit() &&
      shellsplit_test_union_memo_limit() < memo)
    memo = shellsplit_test_union_memo_limit();
#endif
  shell_pmap_attach_memo(&arena->maps, arena->map_memo, memo,
                         arena->map_memo_blocks);
  arena->name_root = arena->name_count = 0;
  arena->snapshot_count = 0;
  arena->snapshot_allocations = 0;
  arena->snapshot_free = arena->snapshot_free_count = 0;
  arena->snapshot_reuse = true;
  arena->snapshot_root = 0;
  arena->link_count = 0;
  arena->member_count = 0;
  arena->checkpoints = arena->epochs = 0;
  arena->allocation_root = arena->allocation_count = 0;
  arena->presence_writer_root = arena->presence_writer_count = 0;
  memset(arena->joins, 0, sizeof(arena->joins));
}

/* Start a pass over arena, which keeps its values: the other pass's roots
 * and an enclosing parse's roots stay valid. */
static SHELL_NONNULL(1, 2) void dep_route_journal_reset(
    dep_route_journal_t *journal, dep_route_arena_t *arena) {
  journal->arena = arena;
  journal->epoch = ++arena->epochs;
  journal->observable_fd_count = 0;
  journal->read_observations.root = journal->read_observations.count = 0;
  journal->read_observations.active = false;
  journal->read_observations.identity = false;
  journal->read_observations.presence = false;
  journal->scratch_observable = false;
  journal->save_marks = false;
  journal->named_closes = false;
  journal->ifs_seen = false;
  journal->diagnostics = NULL;
  journal->diagnostic_cleanup = false;
}

static SHELL_NONNULL(1) void dep_route_mark_map(dep_route_journal_t *journal,
                                                uint32_t root);

/* Immutable map versions can retain entry/undo maps as values. Mark those
 * references as well as trie nodes; historical, unreachable map versions do
 * not pin their intermediate values. Set-valued maps hold sentinel values,
 * not snapshots. */
typedef struct {
  dep_route_journal_t *journal;
  bool descriptor_facts;
} dep_route_mark_walk_t;

static void dep_route_mark_tree(dep_route_journal_t *journal, uint32_t root,
                                bool descriptor_facts);

static void dep_route_mark_leaf(void *context, uint64_t key, uint32_t value) {
  const dep_route_mark_walk_t *walk = context;
  if (!walk->descriptor_facts)
    return;
  dep_route_journal_t *journal = walk->journal;
  journal->arena->marks[value - 1] |= 16u;
  const dep_route_set_t *fact = &journal->arena->snapshots[value - 1];
  if (!fact->count)
    return;
  dep_fd_access_t access = dep_route_key_access(key);
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS ||
      access == DEP_FD_ACCESS_PRESENCE_MAP || access == DEP_FD_ACCESS_ENTRY ||
      access == DEP_FD_ACCESS_SETUP_FRAME ||
      access == DEP_FD_ACCESS_UNDO_ENTRY ||
      access == DEP_FD_ACCESS_PRIVATE_ENTRY)
    dep_route_mark_tree(journal, fact->routes[0].value, true);
  else if (access == DEP_FD_ACCESS_PROCESS_OWNED)
    /* Ownership is an isolated set of descriptor keys, with sentinel values
     * rather than snapshot IDs. Its root is live through this fact. */
    dep_route_mark_tree(journal, fact->routes[0].value, false);
}

static void dep_route_mark_tree(dep_route_journal_t *journal, uint32_t root,
                                bool descriptor_facts) {
  dep_route_mark_walk_t walk = {journal, descriptor_facts};
  shell_pmap_mark(&journal->arena->maps, root, dep_route_mark_leaf, &walk);
}

static SHELL_NONNULL(1) void dep_route_mark_map(dep_route_journal_t *journal,
                                                uint32_t root) {
  dep_route_mark_tree(journal, root, true);
}

static SHELL_NONNULL(1, 2) void dep_route_mark_state(
    dep_route_journal_t *journal, const dep_route_state_t *state) {
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root))
    dep_route_mark_map(journal, root);
}

static SHELL_NONNULL(1,
                     2) void dep_route_mark_flow(dep_route_journal_t *journal,
                                                 const dep_fd_flow_t *flow) {
  for (unsigned i = 0; i < 5; i++)
    if (flow->mask & (1u << i))
      dep_route_mark_state(journal, &flow->state[i]);
}

/* A completed root-parse prefix has no borrowed route IDs outside these
 * published tables, the execution stream, and its current local state. Reuse
 * unreachable slots without changing any live ID. Recursive construction is
 * deliberately excluded: its caller can hold an in-flight import or prefix.
 * Sweeps are amortized over a sixteenth of the change pool's allocations, or
 * a quarter of the snapshot pool's, once that pool is three quarters full. */
static SHELL_NONNULL(1) bool dep_route_collection_begin(
    dep_route_journal_t *journal) {
  /* An open checkpoint's owner holds roots no pin set lists. */
  if (journal->arena->checkpoints)
    return false;
  uint32_t route_interval = DEP_ROUTE_CHANGE_CAPACITY / 16;
  uint32_t route_available = shell_pmap_available(&journal->arena->maps);
  uint32_t snapshot_interval = DEP_ROUTE_SNAPSHOT_CAPACITY / 4;
  uint32_t snapshot_available = DEP_ROUTE_SNAPSHOT_CAPACITY -
                                journal->arena->snapshot_count +
                                journal->arena->snapshot_free_count;
  bool snapshot_pressure =
      journal->arena->snapshot_count >= DEP_ROUTE_SNAPSHOT_CAPACITY * 3 / 4 &&
      (journal->arena->snapshot_allocations >= snapshot_interval ||
       snapshot_available < DEP_ROUTE_OPERATION_CAPACITY);
  if (!snapshot_pressure &&
      !(journal->arena->maps.count >= DEP_ROUTE_CHANGE_CAPACITY * 3 / 4 &&
        (journal->arena->maps.allocations >= route_interval ||
         route_available < DEP_ROUTE_OPERATION_CAPACITY)))
    return false;
  shell_pmap_mark_begin(&journal->arena->maps);
  memset(journal->arena->marks, 0,
         journal->arena->snapshot_count * sizeof(*journal->arena->marks));
  return true;
}

/* Completed-operation collection keeps stable IDs. Dead interior records join
 * a private free list; a dead suffix also lowers the high-water mark. Rebuild
 * the free chain once after the sweep rather than unlinking arbitrary IDs. */
static SHELL_NONNULL(1) void dep_route_tree_collection_end(
    dep_route_journal_t *journal) {
  shell_pmap_sweep(&journal->arena->maps);
  /* Joins borrow route IDs without retaining their inputs or result. Any
   * route sweep can recycle those IDs, including a route-only collection
   * that does not reclaim decision nodes. */
  memset(journal->arena->joins, 0, sizeof(journal->arena->joins));
}
/* Snapshot identities are referenced by live route nodes. Keep their stable
 * IDs while reclaiming unreferenced interned values; a UINT32_MAX count marks
 * a private free slot after it has been removed from the canonical index. */
static SHELL_NONNULL(1) void dep_route_snapshot_collection_end(
    dep_route_journal_t *journal) {
  for (uint32_t i = 0; i < journal->arena->snapshot_count; i++) {
    dep_route_set_t *snapshot = &journal->arena->snapshots[i];
    if (snapshot->count == UINT32_MAX || (journal->arena->marks[i] & 16u))
      continue;
    journal->arena->snapshot_root = dep_snapshot_index_remove(
        journal, journal->arena->snapshot_root, snapshot);
    snapshot->count = UINT32_MAX;
  }
  while (journal->arena->snapshot_count &&
         journal->arena->snapshots[journal->arena->snapshot_count - 1].count ==
             UINT32_MAX)
    journal->arena->snapshot_count--;
  journal->arena->snapshot_free = journal->arena->snapshot_free_count = 0;
  for (uint32_t i = journal->arena->snapshot_count; i-- != 0;)
    if (journal->arena->snapshots[i].count == UINT32_MAX) {
      journal->arena->snapshot_index[i].left = journal->arena->snapshot_free;
      journal->arena->snapshot_free = (uint16_t)(i + 1);
      journal->arena->snapshot_free_count++;
    }
  journal->arena->snapshot_allocations = 0;
}

static SHELL_NONNULL(1, 2, 3) void dep_route_domains_collect(
    dep_route_journal_t *journal, const dep_domain_collection_t *collection,
    const dep_route_state_t *live, const dep_route_state_t *pending) {
  dep_route_workspace_t *workspace = collection->workspace;
  const dep_snapshot_frame_t *frame = collection->frame;
  if ((frame && frame != workspace->snapshot_frames) ||
      !dep_route_collection_begin(journal))
    return;
  for (const dep_domain_collection_t *pins = collection; pins;
       pins = pins->parent) {
    for (uint32_t i = 0; i < sizeof(pins->roots) / sizeof(pins->roots[0]); i++)
      if (pins->roots[i])
        dep_route_mark_state(journal, pins->roots[i]);
    for (uint32_t i = 0; i < pins->state_count; i++)
      dep_route_mark_state(journal, pins->states + i);
    if (pins->flow)
      dep_route_mark_flow(journal, pins->flow);
    if (pins->remaining) {
      dep_route_iterator_t remaining = *pins->remaining;
      uint32_t root;
      while (dep_route_next(&remaining, journal, &root))
        dep_route_mark_map(journal, root);
    }
  }
  dep_route_mark_state(journal, live);
  if (pending)
    dep_route_mark_state(journal, pending);
  /* Prepared frame membership can union slots from several execution paths.
   * No one descriptor map necessarily retains that union snapshot; allocation
   * records own it until their journal/frame is released. */
  for (uint32_t i = 0; i < journal->arena->allocation_count; i++)
    if (journal->arena->allocations[i].closed_slots)
      journal->arena->marks[journal->arena->allocations[i].closed_slots - 1] |=
          16u;
  /* Construction values stay live through the final walk, which shares
   * their arena; the final walk's slots are stale during construction. */
  for (uint32_t i = 0; i < workspace->snapshot_table_count; i++)
    dep_route_mark_state(journal, &workspace->snapshot_tables[i].alternatives);
  /* Collection runs only outside checkpoints: in the root parse, whose
   * construction frame is the first. */
  const dep_snapshot_frame_t *root_frame = &workspace->snapshot_frames[0];
  for (uint32_t i = 0; i < SHELL_DEP_MAX_NODES; i++)
    dep_route_mark_state(journal, &root_frame->capture[i]);
  for (uint32_t i = 0; i < DEP_EXECUTION_EVENT_CAPACITY; i++) {
    dep_route_mark_state(journal, &root_frame->event_entry[i]);
    dep_route_mark_state(journal, &root_frame->event_executed[i]);
    dep_route_mark_state(journal, &root_frame->event_report[i]);
    dep_route_mark_flow(journal, &root_frame->event_scope[i]);
  }
  for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++) {
    dep_route_mark_flow(journal, &root_frame->group_scope[i]);
    dep_route_mark_flow(journal, &root_frame->group_failure[i]);
    dep_route_mark_flow(journal, &root_frame->group_parent[i]);
  }
  for (uint32_t i = 0; i < workspace->snapshot_source_count; i++)
    for (uint32_t m = 0; m < DEP_PRIOR_MEMO_CAPACITY; m++)
      if (workspace->snapshot_sources[i].prior_memo[m].valid) {
        /* The parent is the memo's key: keep its id from being reused. */
        dep_route_mark_map(journal,
                           workspace->snapshot_sources[i].prior_memo[m].parent);
        dep_route_mark_map(journal,
                           workspace->snapshot_sources[i].prior_memo[m].result);
      }
  if (!frame) {
    const dep_fd_stream_t *construction =
        &workspace->snapshot_frames[0].fd_stream;
    for (uint32_t i = 0; i < SHELL_MAX_GROUPS + 1; i++)
      dep_route_mark_flow(journal, &construction->scope[i]);
    for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++) {
      dep_route_mark_flow(journal, &construction->setup_failure[i]);
      dep_route_mark_flow(journal, &construction->if_failure[i]);
      dep_route_mark_flow(journal, &construction->if_exit[i]);
    }
    for (uint32_t i = 0; i < DEP_EXECUTION_EVENT_CAPACITY; i++) {
      dep_route_mark_flow(journal, &construction->entry[i]);
      dep_route_mark_flow(journal, &construction->async_entry[i]);
      dep_route_mark_state(journal, &construction->selected[i]);
    }
    dep_route_mark_state(journal, &workspace->persistent_route_state);
    dep_route_mark_state(journal, &workspace->entry_route_state);
    for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++) {
      dep_route_mark_state(journal, &workspace->scoped_route_state[i]);
      dep_route_mark_state(journal, &workspace->group_route_state[i]);
      dep_route_mark_state(journal, &workspace->group_shell_route_state[i]);
    }
    for (uint32_t i = 0; i < SHELL_DEP_MAX_NODES; i++)
      dep_route_mark_state(journal, &workspace->owner_route_state[i]);
    for (uint32_t i = 0; i < SHELL_DEP_MAX_NODES; i++)
      dep_route_mark_state(journal, &workspace->owner_local_state[i]);
  }
  /* During construction its stream; the final walk reads construction's,
   * marked above. */
  const dep_fd_stream_t *stream = frame ? &frame->fd_stream : NULL;
  for (uint32_t i = 0; stream && i < SHELL_MAX_GROUPS + 1; i++)
    dep_route_mark_flow(journal, &stream->scope[i]);
  for (uint32_t i = 0; stream && i < SHELL_MAX_GROUPS; i++) {
    dep_route_mark_flow(journal, &stream->setup_failure[i]);
    dep_route_mark_flow(journal, &stream->if_failure[i]);
    dep_route_mark_flow(journal, &stream->if_exit[i]);
  }
  for (uint32_t i = 0; stream && i < DEP_EXECUTION_EVENT_CAPACITY; i++) {
    dep_route_mark_flow(journal, &stream->entry[i]);
    dep_route_mark_flow(journal, &stream->async_entry[i]);
    dep_route_mark_state(journal, &stream->selected[i]);
  }
  dep_route_snapshot_collection_end(journal);
  dep_route_tree_collection_end(journal);
}

static SHELL_NONNULL(1, 3) int dep_allocation_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_allocation_t *left =
      &((const dep_route_journal_t *)context)->arena->allocations[index];
  const dep_allocation_t *right = key;
  if (left->role == DEP_ALLOCATION_IMPORT ||
      right->role == DEP_ALLOCATION_IMPORT) {
    if (left->role != right->role)
      return left->role < right->role ? -1 : 1;
    return left->position < right->position ? -1
                                            : left->position != right->position;
  }
  if (left->name != right->name)
    return (uintptr_t)left->name < (uintptr_t)right->name ? -1 : 1;
  if (left->position != right->position)
    return left->position < right->position ? -1 : 1;
  if (left->role != right->role)
    return left->role < right->role ? -1 : 1;
  return left->fd < right->fd ? -1 : left->fd != right->fd;
}

/* create selects interning or lookup in the evaluation's operation index:
 * equal operations get equal private slots. A missing lookup is a meaningful
 * unreached or unsaved operation. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_allocation_key_slot(dep_route_journal_t *journal,
                            const dep_allocation_t *key, bool create) {
  if (!create) {
    uint32_t cursor = journal->arena->allocation_root;
    while (cursor) {
      int order = dep_allocation_compare(journal, cursor - 1, key);
      if (!order)
        /* An operation only the other pass reached is unreached here. */
        return journal->arena->allocations[cursor - 1].epoch == journal->epoch
                   ? SHELL_DEP_FD_MAX + cursor
                   : SHELL_DEP_FD_NONE;
      cursor = order > 0 ? journal->arena->allocation_index[cursor - 1].left
                         : journal->arena->allocation_index[cursor - 1].right;
    }
    return SHELL_DEP_FD_NONE;
  }
  uint32_t candidate = journal->arena->allocation_count + 1, match = 0;
  journal->arena->allocation_root = shell_avl_insert(
      journal->arena->allocation_index, journal->arena->allocation_root,
      candidate, DEP_ROUTE_ALLOCATION_CAPACITY, dep_allocation_compare, journal,
      key, &match);
  if (!match)
    return SHELL_DEP_FD_NONE;
  dep_allocation_t *record = &journal->arena->allocations[match - 1];
  if (match == candidate) {
    *record = *key;
    journal->arena->allocation_count++;
  } else if (record->epoch != journal->epoch) {
    record->closed_slots = key->closed_slots;
    record->observations = key->observations;
  }
  record->epoch = journal->epoch;
  return SHELL_DEP_FD_MAX + match;
}

/* Paired halves of a named open retain one binding allocation identity. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_allocation_slot(dep_route_journal_t *journal, const dep_fd_op_t *op) {
  dep_allocation_t key = {.name = op->fd_name,
                          .allocation =
                              op->pos == UINT32_MAX ? NULL : op->fd_name,
                          .name_length = op->fd_name_len,
                          .position = op->pos};
  if (op->fd_name_len)
    key.observations =
        dep_read_observation(&journal->read_observations,
                             (dep_fd_ref_t){.name = op->fd_name,
                                            .value = SHELL_DEP_FD_NAMED,
                                            .name_len = op->fd_name_len});
  return dep_allocation_key_slot(journal, &key, true);
}

static SHELL_NONNULL(1) uint32_t
    dep_allocation_selector(dep_route_journal_t *journal, uint32_t key) {
  dep_allocation_t *allocation =
      &journal->arena->allocations[key - SHELL_DEP_FD_MAX - 1];
  if (!allocation->selector) {
    /* Shared by construction and replay, and not rewound with child journals.
     * A parent/imported predicate can still reference a child's numeric IDs
     * after its journal-local allocation records have been released. */
    if (*journal->next_selector >= (INT32_MAX - 130) / 65)
      return 0;
    allocation->selector = 64 + 65 * (*journal->next_selector)++;
  }
  return allocation->selector;
}

/* Every reached explicit target save and implicit move-source save has its
 * own scratch identity, even when another redirect saved that FD earlier.
 * Numeric fd disambiguates the two targets of a same-span combined redirect;
 * a path-dependent named source keeps one identity with per-path facts. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_undo_slot(dep_route_journal_t *journal, const dep_fd_op_t *op,
                  dep_allocation_role_t role, bool create) {
  dep_allocation_t key = {
      .name = op->fd_name, .position = op->pos, .fd = op->fd, .role = role};
  return dep_allocation_key_slot(journal, &key, create);
}

/* A nested parse borrows the journal and must return exactly the storage it
 * used: take a checkpoint before it (which also stops reuse of freed ids, so
 * its allocations form suffixes), then restore it afterwards. Roots
 * published before the checkpoint stay valid. */
typedef struct {
  uint32_t maps, map_allocations, names, snapshots, snapshot_allocations;
  uint32_t links, members, allocations, depth, writers;
  bool map_reuse, snapshot_reuse;
} dep_route_checkpoint_t;

static SHELL_NONNULL(1) dep_route_checkpoint_t
    dep_route_journal_checkpoint(dep_route_journal_t *journal) {
  dep_route_checkpoint_t checkpoint = {
      .maps = journal->arena->maps.count,
      .map_allocations = journal->arena->maps.allocations,
      .names = journal->arena->name_count,
      .snapshots = journal->arena->snapshot_count,
      .snapshot_allocations = journal->arena->snapshot_allocations,
      .links = journal->arena->link_count,
      .members = journal->arena->member_count,
      .allocations = journal->arena->allocation_count,
      .depth = journal->depth,
      .writers = journal->arena->presence_writer_count,
      .map_reuse = journal->arena->maps.reuse,
      .snapshot_reuse = journal->arena->snapshot_reuse};
  journal->arena->maps.reuse = false;
  journal->arena->snapshot_reuse = false;
  journal->arena->checkpoints++;
  return checkpoint;
}

static SHELL_NONNULL(1, 2) void dep_route_journal_restore(
    dep_route_journal_t *journal, const dep_route_checkpoint_t *checkpoint) {
  while (journal->arena->allocation_count > checkpoint->allocations) {
    journal->arena->allocation_root = shell_avl_erase(
        journal->arena->allocation_index, journal->arena->allocation_root,
        dep_allocation_compare, journal,
        &journal->arena->allocations[journal->arena->allocation_count - 1]);
    journal->arena->allocation_count--;
  }
  while (journal->arena->snapshot_count > checkpoint->snapshots) {
    journal->arena->snapshot_root = dep_snapshot_index_remove(
        journal, journal->arena->snapshot_root,
        &journal->arena->snapshots[journal->arena->snapshot_count - 1]);
    journal->arena->snapshot_count--;
  }
  shell_pmap_rollback(&journal->arena->maps, checkpoint->maps);
  while (journal->arena->presence_writer_count > checkpoint->writers) {
    journal->arena->presence_writer_root = shell_avl_erase(
        journal->arena->presence_writer_index,
        journal->arena->presence_writer_root, dep_presence_writer_compare,
        journal,
        &journal->arena
             ->presence_writers[journal->arena->presence_writer_count - 1]);
    journal->arena->presence_writer_count--;
  }
  while (journal->arena->name_count > checkpoint->names) {
    journal->arena->name_root =
        shell_avl_erase(journal->arena->name_index, journal->arena->name_root,
                        dep_route_name_compare, journal,
                        &journal->arena->names[journal->arena->name_count - 1]);
    journal->arena->name_count--;
  }
  journal->arena->link_count = checkpoint->links;
  journal->arena->member_count = checkpoint->members;
  memset(journal->arena->joins, 0, sizeof(journal->arena->joins));
  journal->arena->maps.allocations = checkpoint->map_allocations;
  journal->arena->maps.reuse = checkpoint->map_reuse;
  journal->arena->snapshot_allocations = checkpoint->snapshot_allocations;
  journal->arena->snapshot_reuse = checkpoint->snapshot_reuse;
  journal->arena->checkpoints--;
  journal->depth = checkpoint->depth;
}

/* *root binds (fd, access) to snapshot, or unbinds it when snapshot is 0.
 * Values of a set-valued map (process ownership) are sentinels rather than
 * snapshot ids. False, leaving *root unchanged, when the journal is full. */
static SHELL_NONNULL(1, 2) bool dep_route_map_put(dep_route_journal_t *journal,
                                                  uint32_t *root,
                                                  dep_fd_ref_t fd,
                                                  dep_fd_access_t access,
                                                  uint32_t snapshot) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  if (fd.value == SHELL_DEP_FD_NAMED && access == DEP_FD_ACCESS_BINDING)
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BINDING_INVALIDATION);
  if (shell_pmap_available(&journal->arena->maps) < SHELL_PMAP_UPDATE_NODES)
    return false;
  uint64_t key;
  if (!snapshot)
    return !dep_route_key_find(journal, fd, access, &key) ||
           shell_pmap_erase(&journal->arena->maps, root, key);
  if (!dep_route_key_intern(journal, fd, access, &key))
    return false;
  return shell_pmap_set(&journal->arena->maps, root, key, snapshot, 0);
}

static SHELL_NONNULL(1, 2) bool dep_route_state_append_map(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes) {
  if (shell_pmap_available(&changes->arena->maps) < SHELL_PMAP_UPDATE_NODES) {
    state->truncated = true;
    return false;
  }
  uint32_t snapshot = dep_route_set_intern(changes, &routes);
  if (snapshot == 0 ||
      !dep_route_map_put(changes, &state->root, fd, access, snapshot)) {
    state->truncated = true;
    return false;
  }
  return true;
}
static SHELL_NONNULL(1, 2) bool dep_route_state_append_one(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes) {
  if (access == DEP_FD_ACCESS_VARIABLE_PRESENCE) {
    uint32_t root = dep_presence_bindings(state->root, journal);
    dep_route_state_t names = dep_route_state_single(root);
    if (!dep_route_state_append_map(&names, journal, fd, access, routes))
      return false;
    if (names.root == root)
      return true;
    dep_route_set_set(&routes,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, names.root});
    return dep_route_state_append_map(state, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_PRESENCE_MAP, routes);
  }
  if (fd.value != SHELL_DEP_FD_NAMED || access != DEP_FD_ACCESS_BINDING)
    return dep_route_state_append_map(state, journal, fd, access, routes);
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BINDING_INVALIDATION);
  dep_fd_route_t holder = dep_named_bindings(state->root, journal);
  dep_route_state_t names = dep_route_state_single(holder.value);
  if (!dep_route_state_append_map(&names, journal, fd, access, routes))
    return false;
  if (names.root == holder.value)
    return true;
  holder.value = names.root;
  dep_route_set_set(&routes, holder);
  return dep_route_state_append_map(state, journal, dep_fd_numeric(0),
                                    DEP_FD_ACCESS_NAMED_BINDINGS, routes);
}

/* An actual scalar write, not a descriptor close or restoration, supersedes
 * an inherited temporary value: the name leaves the shadow set
 * (dep_read_scalar_shadowed). A version without the set has nothing to
 * supersede. */
static SHELL_NONNULL(1, 2) bool dep_read_note_assignment(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t fd) {
  dep_route_state_t result = {0};
  dep_route_iterator_t versions = dep_route_iterator(state);
  uint32_t root;
  bool first = true;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    uint32_t marker = dep_route_state_snapshot(
        &one, journal, dep_fd_numeric(DEP_SCALAR_IMPORT_EVENT),
        DEP_FD_ACCESS_PRIVATE_ENTRY);
    if (marker) {
      dep_route_set_t fact = journal->arena->snapshots[marker - 1];
      uint32_t shadowed = fact.routes[0].value;
      if (!dep_route_map_put(journal, &shadowed, fd,
                             DEP_FD_ACCESS_READ_ARGUMENT, 0))
        return false;
      fact.routes[0].value = shadowed;
      if (shadowed != journal->arena->snapshots[marker - 1].routes[0].value &&
          !dep_route_state_append_map(&one, journal,
                                      dep_fd_numeric(DEP_SCALAR_IMPORT_EVENT),
                                      DEP_FD_ACCESS_PRIVATE_ENTRY, fact))
        return false;
    }
    if (first)
      result = one;
    else if (!dep_route_state_add_root(&result, journal, one.root))
      return false;
    first = false;
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

/* Whether some version stores a fact for (fd, access). */
static SHELL_NONNULL(1, 2) bool dep_route_state_stores(
    const dep_route_state_t *state, const dep_route_journal_t *changes,
    dep_fd_ref_t fd, dep_fd_access_t access) {
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, changes, &root))
    if (dep_route_root_snapshot(root, changes, fd, access))
      return true;
  return false;
}

static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_route_state_get_access(const dep_route_state_t *state,
                               const dep_route_journal_t *changes,
                               dep_fd_ref_t fd, dep_fd_access_t access) {
  /* A descriptor variable no version binds is not a descriptor here: its
   * expansion is the inherited text. An invalidated variable stores an
   * explicit binding, so it cannot revive an older one. */
  if (fd.value == SHELL_DEP_FD_NAMED &&
      !dep_route_state_stores(state, changes, fd, DEP_FD_ACCESS_BINDING)) {
    dep_route_set_t result = {0};
    dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value});
    result.truncated = state->truncated;
    return result;
  }
  dep_route_set_t result = dep_fd_fact(state, changes, fd, access);
  result.truncated |= state->truncated;
  return result;
}

/* added, when not NULL, makes a binding store a weak update of the domain: the
 * place may or may not have received the descriptor added, so only added's
 * possibilities join the place's occupancy. routes is then the union of
 * added with the place's prior binding. fresh says the store installs a newly
 * allocated descriptor: the place was free wherever it lands, so it held no
 * save there, and a save it is marked as possibly holding is unaffected. */
static SHELL_NONNULL(1, 2) bool dep_route_state_store_binding(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes,
    const dep_route_set_t *added, bool fresh) {
  dep_route_state_t previous = *state;
  dep_route_state_t updated = {0};
  uint32_t count = dep_route_state_count(&previous);
  dep_route_iterator_t iterator = dep_route_iterator(&previous);
  for (uint32_t i = 0; i < count; i++) {
    uint32_t root = dep_route_take(&iterator, changes);
    dep_route_state_t one = dep_route_state_single(root);
    uint32_t selector = access == DEP_FD_ACCESS_BINDING &&
                                fd.value > SHELL_DEP_FD_MAX &&
                                fd.value < SHELL_DEP_FD_NAMED
                            ? dep_route_state_snapshot(&one, changes, fd,
                                                       DEP_FD_ACCESS_SELECTOR)
                            : 0;
    if (access == DEP_FD_ACCESS_BINDING &&
        (fd.value < 64 ||
         (selector && changes->arena->snapshots[selector - 1].count))) {
      uint32_t domain[SHELL_FD_PARTS];
      for (uint32_t part = 0; part < SHELL_FD_PARTS; part++)
        domain[part] = dep_route_state_snapshot(
            &one, changes, dep_fd_numeric(part), DEP_FD_ACCESS_PROCESS_DOMAIN);
      /* The parts of a domain are stored together (dep_fd_domain_store), so a
       * stored first part means all four are present and read below. */
      if (domain[0] && changes->arena->snapshots[domain[0] - 1].count) {
        bool free = false, occupied = false;
        const dep_route_set_t *value_routes = added ? added : &routes;
        for (uint32_t route = 0; route < value_routes->count; route++) {
          dep_route_kind_t kind = value_routes->routes[route].kind;
          bool closed = kind == DEP_ROUTE_CLOSED || kind == DEP_ROUTE_ABSENT ||
                        kind == DEP_ROUTE_UNAVAILABLE;
          bool unknown = kind == DEP_ROUTE_UNSEEN || kind == DEP_ROUTE_DYNAMIC;
          free |= closed || unknown;
          occupied |= !closed;
        }
        /* An empty binding fact constrains nothing. */
        if (!value_routes->count)
          free = occupied = true;
        /* A numeric descriptor is one place. A private slot is one of its
         * possible places: the update is strong only when that is a single
         * descriptor below 64. */
        shell_fd_allocation_t places =
            selector ? dep_slot_places(&changes->arena->snapshots[selector - 1])
                     : (shell_fd_allocation_t){UINT64_C(1) << fd.value, false};
        bool exact = !added && !places.tail && places.candidates &&
                     !(places.candidates & (places.candidates - 1));
        shell_fd_partition_t partition, stored;
        for (uint32_t part = 0; part < SHELL_FD_PARTS; part++) {
          shell_fd_occupancy_t *value = &partition.part[part];
          *value =
              dep_domain_value(&changes->arena->snapshots[domain[part] - 1]);
          stored.part[part] = *value;
          if (!shell_fd_occupancy_feasible(value))
            continue;
          if (exact) {
            value->may_free = free ? value->may_free | places.candidates
                                   : value->may_free & ~places.candidates;
            value->may_occupied =
                occupied ? value->may_occupied | places.candidates
                         : value->may_occupied & ~places.candidates;
          } else {
            if (free)
              value->may_free |= places.candidates;
            if (occupied)
              value->may_occupied |= places.candidates;
          }
        }
        /* A low descriptor's change can move a path between cases. */
        if (places.candidates & SHELL_FD_LOW_INTERVAL)
          shell_fd_partition_normalize(&partition);
        else
          shell_fd_partition_refine(&partition);
        /* Only parts that changed are appended: the others are already stored,
         * as all parts of a domain are stored together. */
        for (uint32_t part = 0; part < SHELL_FD_PARTS; part++)
          if ((partition.part[part].may_free != stored.part[part].may_free ||
               partition.part[part].may_occupied !=
                   stored.part[part].may_occupied) &&
              !dep_route_state_append_one(
                  &one, changes, dep_fd_numeric(part),
                  DEP_FD_ACCESS_PROCESS_DOMAIN,
                  dep_domain_fact(partition.part[part])))
            return false;
        if (!dep_route_state_append_one(
                &one, changes, dep_fd_numeric(DEP_DOMAIN_UNION),
                DEP_FD_ACCESS_PROCESS_DOMAIN,
                dep_domain_fact(shell_fd_partition_union(&partition))))
          return false;
      }
    }
    if (!dep_route_state_append_one(&one, changes, fd, access, routes)) {
      state->truncated = true;
      return false;
    }
    /* A write to a marked place reaches the save it may hold: strongly when
     * the place is the save's only one, otherwise as a possibility. */
    if (changes->save_marks && !fresh && access <= DEP_FD_ACCESS_BINDING &&
        fd.value <= SHELL_DEP_FD_MAX) {
      uint32_t mark =
          dep_route_state_snapshot(&one, changes, fd, DEP_FD_ACCESS_SCRATCH);
      dep_route_set_t marks = mark ? changes->arena->snapshots[mark - 1]
                                   : (dep_route_set_t){.ready = true};
      for (uint32_t m = 0; m < marks.count; m++) {
        if (marks.routes[m].kind != DEP_ROUTE_ALIAS ||
            marks.routes[m].value == fd.value)
          continue;
        dep_fd_ref_t holder = dep_fd_numeric(marks.routes[m].value);
        uint32_t identity = dep_route_state_snapshot(&one, changes, holder,
                                                     DEP_FD_ACCESS_SELECTOR);
        shell_fd_allocation_t places =
            identity && changes->arena->snapshots[identity - 1].count
                ? dep_slot_places(&changes->arena->snapshots[identity - 1])
                : (shell_fd_allocation_t){0, true};
        dep_route_set_t held = routes;
        if (places.tail || fd.value >= 64 ||
            places.candidates != UINT64_C(1) << fd.value) {
          uint32_t prior =
              dep_route_state_snapshot(&one, changes, holder, access);
          if (prior)
            for (uint32_t r = 0; r < changes->arena->snapshots[prior - 1].count;
                 r++)
              if (!dep_route_set_add(
                      &held, changes->arena->snapshots[prior - 1].routes[r]))
                return false;
        }
        if (!dep_route_state_append_one(&one, changes, holder, access, held)) {
          state->truncated = true;
          return false;
        }
      }
    }
    if (i == 0)
      updated.root = one.root;
    else if (!dep_route_state_add_root(&updated, changes, one.root)) {
      state->truncated = true;
      return false;
    }
  }
  updated.truncated = previous.truncated;
  *state = updated;
  return true;
}

static SHELL_NONNULL(1, 2) bool dep_route_state_store_access(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes) {
  return dep_route_state_store_binding(state, changes, fd, access, routes, NULL,
                                       false);
}

/* Store a fact of a descriptor just allocated on fd. */
static SHELL_NONNULL(1, 2) bool dep_route_state_store_allocated(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes) {
  return dep_route_state_store_binding(state, changes, fd, access, routes, NULL,
                                       true);
}

/* Undo/process-private identities cannot be referenced after disposal.
 * The caller first closes the selected physical slot, which already updated
 * occupancy through its places; retiring then forgets only the operation's
 * places. If that operation reused a named slot, the slot keeps its own:
 * named values survive close and retain that identity. */
static SHELL_NONNULL(1,
                     2) bool dep_selector_retire(dep_route_state_t *state,
                                                 dep_route_journal_t *journal,
                                                 uint32_t slot) {
  uint32_t identity = dep_route_state_snapshot(
      state, journal, dep_fd_numeric(slot), DEP_FD_ACCESS_SELECTOR);
  if (!identity || !journal->arena->snapshots[identity - 1].count)
    return true;
  return dep_route_state_append_one(state, journal, dep_fd_numeric(slot),
                                    DEP_FD_ACCESS_SELECTOR,
                                    (dep_route_set_t){.ready = true});
}
