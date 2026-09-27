#ifndef SHELLGATE_TEST_FAILURES_H
#define SHELLGATE_TEST_FAILURES_H

#include <stdbool.h>
#include <stddef.h>

#include "sg_anomaly.h"

void sg_test_alloc_fail_at(size_t allocation_index);
void sg_test_alloc_reset(void);
size_t sg_test_alloc_count(void);

void sg_test_anomaly_op_fail_at(size_t operation_index);
void sg_test_anomaly_op_reset(void);
size_t sg_test_anomaly_op_count(void);
bool sg_test_anomaly_op_should_fail(void);

/* One-shot model-result failures for evaluator error-contract tests.  These
 * are deliberately separate from the table-operation failure counter above:
 * callers use that counter to exercise best-effort allocation degradation. */
void sg_test_anomaly_score_fail_with(sg_anomaly_status_t status);
void sg_test_anomaly_update_fail_with(sg_anomaly_status_t status);
void sg_test_anomaly_result_reset(void);
sg_anomaly_status_t sg_test_anomaly_score_take_failure(void);
sg_anomaly_status_t sg_test_anomaly_update_take_failure(void);

void sg_test_io_fail_at(size_t operation_index);
void sg_test_io_reset(void);
size_t sg_test_io_count(void);
bool sg_test_io_should_fail(void);

#endif
