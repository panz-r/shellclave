#ifndef SHELLGATE_TEST_FAILURES_H
#define SHELLGATE_TEST_FAILURES_H

#include <stdbool.h>
#include <stddef.h>

void sg_test_alloc_fail_at(size_t allocation_index);
void sg_test_alloc_reset(void);
size_t sg_test_alloc_count(void);

void sg_test_anomaly_op_fail_at(size_t operation_index);
void sg_test_anomaly_op_reset(void);
size_t sg_test_anomaly_op_count(void);
bool sg_test_anomaly_op_should_fail(void);

void sg_test_io_fail_at(size_t operation_index);
void sg_test_io_reset(void);
size_t sg_test_io_count(void);
bool sg_test_io_should_fail(void);

#endif
