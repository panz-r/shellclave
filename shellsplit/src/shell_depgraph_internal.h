#ifndef SHELL_DEPGRAPH_INTERNAL_H
#define SHELL_DEPGRAPH_INTERNAL_H

#include "shell_depgraph.h"
#include "shell_tokenizer.h"

#include "shell_expand_internal.h"

/* The public supplied-fast parse contract also applies to this resolver path.
 * unresolved_paths is distinct writable storage for SHELL_DEP_MAX_NODES bytes,
 * outside the graph, workspace, resolver value entries and borrowed payloads.
 * It receives one boolean per retained graph node: an active
 * pathname expansion owned by that CMD/GROUP remained unresolved.
 * Nested pathname expansions retain their semantic owner even when a resolved
 * containing word or failed open removes the final byte-flow edge. Child joins
 * and compaction preserve these facts; unused entries are zero. */
shell_dep_error_t shell_dep_graph_parse_with_fast_resolver(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out, const shell_dep_word_resolver_t *resolver,
    uint8_t *unresolved_paths) SHELL_NONNULL(1, 5, 6, 8);

/* Identity rendering from an already decoded static FILE word. The caller
 * supplies its complete, nonempty, NUL-free payload and an unchanged document
 * from graph. This consumes the payload, not the source spelling: no word
 * classification or decoding is repeated. Storage is readable for length
 * bytes; destination may overlap it. Unknown CWD and insufficient output
 * capacity return false, zero the identity, and leave destination unchanged. */
bool shell_dep_doc_file_identity_from_decoded(
    const shell_dep_graph_t *graph, const shell_dep_doc_t *doc,
    const char *decoded, size_t length, char *destination, size_t capacity,
    shell_dep_file_identity_t *identity) SHELL_NONNULL(1, 2, 3, 5, 7);

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
/* Exercise the private append-only AVL contract at full capacity. Existing
 * keys remain discoverable; absent insertions leave every link and height
 * byte, as well as the root, unchanged. Test builds only. */
/* Exercise valid immutable state construction with 2..SHELL_DEP_MAX_NODES
 * roots. workspace has shell_dep_workspace_size() bytes at its required
 * alignment and is exclusively borrowed for this test operation. */
bool shellsplit_test_route_state_contract(void *workspace, uint32_t count)
    SHELL_NONNULL(1);
/* Fill the private journal pools to the point a collection is due, collect,
 * and check what survives: pinned facts through each kind of pin, reclaimed
 * ids and values, and continued use. No source within the graph limits can
 * fill the pools, so this drives the collector directly. workspace is as for
 * shellsplit_test_route_state_contract() and is overwritten. */
bool shellsplit_test_route_collection_contract(void *workspace)
    SHELL_NONNULL(1);
/* Check the process-substitution fork contract on hand-built states: owned
 * ends survive in the child, are closed in the parent's view, and ownership
 * moves. workspace is as above and is overwritten. */
bool shellsplit_test_process_fork_contract(void *workspace) SHELL_NONNULL(1);
/* Test-only differential oracle: execute the ordered cleanup program without
 * segment-cache reuse. The setting is local to the calling test thread. */
void shellsplit_test_failure_cleanup_reference(bool enabled);
#endif

#endif
