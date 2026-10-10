#ifndef SHELLGATE_TEST_FAILURES_H
#define SHELLGATE_TEST_FAILURES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "sg_anomaly.h"

void sg_test_alloc_fail_at(size_t allocation_index);
void sg_test_alloc_reset(void);
size_t sg_test_alloc_count(void);

void sg_test_anomaly_op_fail_at(size_t operation_index);
void sg_test_anomaly_op_reset(void);
size_t sg_test_anomaly_op_count(void);
bool sg_test_anomaly_op_should_fail(void);

/* Count model table lookups/traversal independently of operation faults. */
void sg_test_anomaly_work_reset(void);
size_t sg_test_anomaly_work_count(void);
void sg_test_anomaly_work_charge(void);

/* Actual matcher comparisons/transitions and decoded path bytes, independent of
 * allocator faults. Used to assert linear work rather than wall-clock time. */
void sg_test_path_work_reset(void);
size_t sg_test_path_work_count(void);
void sg_test_path_work_charge(void);
size_t sg_test_path_decoded_count(void);
void sg_test_path_decoded_charge(void);
/* Bytes measured, copied, or compared by canonical-identity construction. */
size_t sg_test_path_identity_count(void);
void sg_test_path_identity_charge(size_t bytes);

/* One-shot model-result failures for evaluator error-contract tests.  These
 * are deliberately separate from the table-operation failure counter above:
 * callers use that counter to exercise best-effort allocation degradation. */
void sg_test_anomaly_score_fail_with(sg_anomaly_status_t status);
void sg_test_anomaly_update_fail_with(sg_anomaly_status_t status);
void sg_test_anomaly_result_reset(void);
sg_anomaly_status_t sg_test_anomaly_score_take_failure(void);
sg_anomaly_status_t sg_test_anomaly_update_take_failure(void);

void sg_test_io_fail_at(size_t operation_index);
void sg_test_io_fail_at_with_errno(size_t operation_index, int error_number);
void sg_test_io_reset(void);
size_t sg_test_io_count(void);
bool sg_test_io_should_fail(void);
int sg_test_io_error_number(void);
/* Observe completed fread calls, including clean EOF. The stream is borrowed
 * only for the callback; length is the number of bytes actually read. NULL
 * disables observation. context is borrowed until reset and may be NULL. */
typedef void (*sg_test_io_read_observer_t)(FILE *stream, size_t length,
                                           void *context);
void sg_test_io_read_observer_set(sg_test_io_read_observer_t observer,
                                  void *context);
void sg_test_io_observe_read(FILE *stream, size_t length) SHELL_NONNULL(1);
/* Independent one-shot close failure for first-error/cleanup precedence. */
void sg_test_io_close_fail_with_errno(int error_number);
int sg_test_io_close_take_error(void);

/* Borrow exactly SHELL_FILE_TEMP_RANDOM_BYTES immutable entropy bytes until
 * reset; NULL selects ordinary OS entropy. This does not charge an operation.
 */
void sg_test_io_temp_random_set(const unsigned char *random);
const unsigned char *sg_test_io_temp_random_bytes(void);

/* One-shot failure of operation-local numeric locale creation. */
void sg_test_locale_fail_with_errno(int error_number);
int sg_test_locale_take_error(void);

#endif
