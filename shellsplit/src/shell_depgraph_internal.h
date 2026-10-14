#ifndef SHELL_DEPGRAPH_INTERNAL_H
#define SHELL_DEPGRAPH_INTERNAL_H

#include "shell_depgraph.h"
#include "shell_tokenizer.h"

#include "shell_expand_internal.h"

/* Internal zero-copy consumer of an existing fast parse, not an independent
 * parse of cmd. With non-NULL `fast`, the caller must supply the unmodified
 * result of shell_parse_fast(cmd, cmd_len, ...) for exactly these source bytes
 * and length. Use strict_mode=true for semantic graph construction. A result
 * from another source, edited metadata, or changed source bytes is INVALID
 * API USE: this function does not reparse to detect or reconcile a mismatch.
 * Parser-produced errors and truncated results retain their error/partial
 * graph handling; they are not permission to fabricate descriptors.
 *
 * `cmd` is supplied separately only because the fixed-size parse result stores
 * zero-copy offsets, not a source pointer. The source must remain alive and
 * unchanged for the lifetime of the graph, which borrows token spans from it.
 * Graph construction copies `fast` into local mutable working metadata so it
 * can derive execution ranges without modifying the caller's result; the copy
 * is not an alias-safety mechanism. `fast`, when present, and `out` must be
 * distinct. NULL `fast` delegates to shell_dep_graph_parse(). Like that API,
 * this requires caller-owned resolver workspace in limits when effective
 * routes are resolved. */
shell_dep_error_t shell_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) SHELL_NONNULL(1, 6);

/* Same source/parse/workspace contract; resolution is part of construction,
 * before effective setup outcomes and routes are committed. unresolved_paths
 * references SHELL_DEP_MAX_NODES writable bytes outside out and the graph
 * workspace. It must not overlap the resolver's returned value entries or
 * payload spans. It receives one boolean per retained graph node: an active
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
/* Exercise valid immutable state construction with 2..SHELL_DEP_MAX_NODES
 * roots. workspace has shell_dep_workspace_size() bytes at its required
 * alignment and is exclusively borrowed for this test operation. */
bool shellsplit_test_route_state_contract(void *workspace, uint32_t count)
    SHELL_NONNULL(1);
/* Test-only differential oracle: execute the ordered cleanup program without
 * segment-cache reuse. The setting is local to the calling test thread. */
void shellsplit_test_failure_cleanup_reference(bool enabled);
#endif

#endif
