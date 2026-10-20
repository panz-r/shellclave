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
 * capacity return false, clear outputs, and leave destination unchanged. */
bool shell_dep_doc_file_identity_from_decoded(
    const shell_dep_graph_t *graph, const shell_dep_doc_t *doc,
    const char *decoded, size_t length, char *destination, size_t capacity,
    size_t *written, bool *absolute) SHELL_NONNULL(1, 2, 3, 5, 7, 8);

/* Normalize one decoded, nonempty, NUL-free lexical path in place. path has
 * length + 1 writable bytes and length <= UINT32_MAX. Removes single-dot and
 * redundant separator components, preserving parent components and symlinks.
 * Returns the length excluding its appended NUL. The input is prechecked;
 * this helper does not decode, classify or validate caller storage. */
size_t shell_dep_file_path_normalize(char *path, size_t length)
    SHELL_NONNULL(1);

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
/* Exercise the private append-only AVL contract at full capacity. Existing
 * keys remain discoverable; absent insertions leave every link and height
 * byte, as well as the root, unchanged. Test builds only. */
bool shellsplit_test_index_capacity_contract(void);
/* Exercise valid immutable state construction with 2..SHELL_DEP_MAX_NODES
 * roots. workspace has shell_dep_workspace_size() bytes at its required
 * alignment and is exclusively borrowed for this test operation. */
bool shellsplit_test_route_state_contract(void *workspace, uint32_t count)
    SHELL_NONNULL(1);
/* Same workspace contract; check process-allocation predicates against an
 * independent finite FD-table oracle, including original low-end fallback. */
bool shellsplit_test_process_domain_contract(void *workspace) SHELL_NONNULL(1);
/* Same workspace contract; independent rank, low-open, observation, mutation,
 * and allocation/close/reuse sequence checks for the shared symbolic domain. */
bool shellsplit_test_allocation_domain_contract(void *workspace)
    SHELL_NONNULL(1);
/* Same workspace contract; finite-table checks of selector retirement,
 * close/reuse identity and scratch collection with multiple live roots. */
bool shellsplit_test_selector_lifecycle_contract(void *workspace)
    SHELL_NONNULL(1);
/* Same workspace contract; force four-way memo collisions, eviction and reset
 * with valid completed descriptor predicates. */
bool shellsplit_test_memo_cache_contract(void *workspace) SHELL_NONNULL(1);
/* Test-only differential oracle: execute the ordered cleanup program without
 * segment-cache reuse. The setting is local to the calling test thread. */
void shellsplit_test_failure_cleanup_reference(bool enabled);
/* Differential oracle: rebuild the materialized union instead of reconciling
 * immutable deltas. Thread-local and absent from shipping builds. */
void shellsplit_test_materialization_reference(bool enabled);
#endif

#endif
