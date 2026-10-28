#ifndef SHELLSPLIT_TEST_SOURCE_SCANS_H
#define SHELLSPLIT_TEST_SOURCE_SCANS_H

#include "shell_contract.h"
#include <stddef.h>

/* Charge each prefix interval and actual word-scanner transitions, not elapsed
 * time or a single nominal charge for an entire operation.
 * Available only in the instrumented test build; production has no counter. */
void shellsplit_test_source_scan_charge(size_t length);
void shellsplit_test_source_scan_reset(void);
size_t shellsplit_test_source_scan_work(void);
/* Actual physical-line byte visits, also charged to general source work. */
void shellsplit_test_line_scan_charge(size_t length);
size_t shellsplit_test_line_scan_work(void);
/* Count delimiter transitions over a selected immutable source interval.
 * This isolates repeated leaf balancing from unrelated cache collisions in
 * a large preceding prefix. Source spans reference valid immutable storage
 * until the operation completes. Reset disables the selection. */
void shellsplit_test_delimiter_watch(const char *source, size_t length)
    SHELL_NONNULL(1);
void shellsplit_test_delimiter_charge(const char *source, size_t length)
    SHELL_NONNULL(1);
size_t shellsplit_test_delimiter_work(void);

/* Count real descriptor metadata operations separately from source bytes.
 * Source-only accounting cannot detect repeated route/timer/join scans. */
typedef enum {
  SHELLSPLIT_TEST_WORK_PROCESS_ROUTES,
  SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES,
  SHELLSPLIT_TEST_WORK_IMPORT_USES,
  SHELLSPLIT_TEST_WORK_IMPORT_EXPORTS,
  SHELLSPLIT_TEST_WORK_FD_OPERATIONS,
  SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION,
  SHELLSPLIT_TEST_WORK_SCOPE_LOOKUP,
  SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP,
  SHELLSPLIT_TEST_WORK_ROUTE_ALTERNATIVES,
  SHELLSPLIT_TEST_WORK_ROUTE_MEMBERSHIP,
  SHELLSPLIT_TEST_WORK_ROUTE_OWNERSHIP,
  SHELLSPLIT_TEST_WORK_OWNER_EDGES,
  SHELLSPLIT_TEST_WORK_GROUP_EVENTS,
  SHELLSPLIT_TEST_WORK_GATE_EDGES,
  SHELLSPLIT_TEST_WORK_GATE_ARGUMENTS,
  SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS,
  SHELLSPLIT_TEST_WORK_SNAPSHOT_EDGES,
  SHELLSPLIT_TEST_WORK_TIME_PIPE_TARGETS,
  SHELLSPLIT_TEST_WORK_GATE_VIOLATION_INDEX,
  /* One charge per retained node, CMD token, and edge examined for expansion
   * uncertainty; independent of rendering, callback payload size, and stops. */
  SHELLSPLIT_TEST_WORK_GATE_EXPANSIONS,
  SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES,
  SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION,
  SHELLSPLIT_TEST_WORK_PROCESS_STRICT_PARSE,
  SHELLSPLIT_TEST_WORK_PROCESS_GROUP_REMAP,
  SHELLSPLIT_TEST_WORK_PROCESS_RANGE_BUILDS,
  SHELLSPLIT_TEST_WORK_PROCESS_GROUP_BOUNDARIES,
  /* Actual byte-domain passes and visited bytes, excluding prechecked reuse.
   * Byte visits also contribute to the general source-work counter. */
  SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES,
  SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES,
  SHELLSPLIT_TEST_WORK_SYNTAX_BODIES,
  SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES,
  SHELLSPLIT_TEST_WORK_ANOMALY_BODIES,
  SHELLSPLIT_TEST_WORK_EXEC_ANALYSIS,
  SHELLSPLIT_TEST_WORK_PREFIX_LOOKUP,
  SHELLSPLIT_TEST_WORK_ASSIGNMENT_IFS,
  SHELLSPLIT_TEST_WORK_PATH_NORMALIZATION,
  /* Actual failure-cleanup tree composition, dependency-index visits, and
   * executed undo leaves. Independent of source-byte and publication counts. */
  SHELLSPLIT_TEST_WORK_FAILURE_COMPOSITION,
  SHELLSPLIT_TEST_WORK_FAILURE_DEPENDENCIES,
  SHELLSPLIT_TEST_WORK_FAILURE_UNDO,
  /* Boundary-use indexing, group coalescing, sorting, and publication. */
  SHELLSPLIT_TEST_WORK_BOUNDARY,
  /* Owner-local stream inventory construction and actual projection visits. */
  SHELLSPLIT_TEST_WORK_OWNER_STREAMS,
  /* Actual prefix-diagnostic visits, sink indexing and publication census. */
  SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES,
  /* Prepared read-word transitions, including entry-role refinement. */
  SHELLSPLIT_TEST_WORK_READ_INPUT,
  /* Cache misses when one imported entry captures a requested named value,
   * identity or access predicate. Includes explicit unknown memo entries;
   * unrelated inventory names and repeated requests must add no work. */
  SHELLSPLIT_TEST_WORK_READ_OBSERVATIONS,
  /* Memoized selector-image subproblems, charged only on cache misses. */
  SHELLSPLIT_TEST_WORK_SELECTOR_IMAGE,
  /* Actual named binding tree visits, point updates, resets and restored
   * exclusions. Does not charge a nominal global inventory size. */
  SHELLSPLIT_TEST_WORK_BINDING_INVALIDATION,
  /* Actual raw delimiter and decoded-byte transitions, never body-line
   * counts charged as a nominal delimiter traversal. */
  SHELLSPLIT_TEST_WORK_HEREDOC_PREPARATION,
  SHELLSPLIT_TEST_WORK_COUNT
} shellsplit_test_metadata_kind_t;
void shellsplit_test_metadata_charge(shellsplit_test_metadata_kind_t kind);
size_t shellsplit_test_metadata_work(shellsplit_test_metadata_kind_t kind);

/* Record adjacent body-observation positions for one owner. Equal positions
 * retain append order; decreasing positions break sequential replay. Reset
 * through shellsplit_test_source_scan_reset(). No production instrumentation.
 */
void shellsplit_test_observation_order_record(size_t previous, size_t current);
size_t shellsplit_test_observation_order_errors(void);

#endif
