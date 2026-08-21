#include "test_sg_failures.h"
#include <stdlib.h>
#include <string.h>

static size_t alloc_fail_index;
static size_t alloc_count;
static size_t anomaly_fail_index;
static size_t anomaly_count;
static size_t io_fail_index;
static size_t io_count;

static bool allocation_fails(void) {
  alloc_count++;
  return alloc_fail_index != 0 && alloc_count == alloc_fail_index;
}

void *sg_test_malloc(size_t size) {
  return allocation_fails() ? NULL : malloc(size);
}

void *sg_test_calloc(size_t count, size_t size) {
  return allocation_fails() ? NULL : calloc(count, size);
}

char *sg_test_strdup(const char *text) {
  size_t size = strlen(text) + 1;
  char *copy = sg_test_malloc(size);
  if (copy)
    memcpy(copy, text, size);
  return copy;
}

void sg_test_alloc_fail_at(size_t allocation_index) {
  alloc_fail_index = allocation_index;
  alloc_count = 0;
}

void sg_test_alloc_reset(void) {
  alloc_fail_index = 0;
  alloc_count = 0;
}

size_t sg_test_alloc_count(void) { return alloc_count; }

void sg_test_anomaly_op_fail_at(size_t operation_index) {
  anomaly_fail_index = operation_index;
  anomaly_count = 0;
}

void sg_test_anomaly_op_reset(void) {
  anomaly_fail_index = 0;
  anomaly_count = 0;
}

size_t sg_test_anomaly_op_count(void) { return anomaly_count; }

bool sg_test_anomaly_op_should_fail(void) {
  anomaly_count++;
  return anomaly_fail_index != 0 && anomaly_count == anomaly_fail_index;
}

void sg_test_io_fail_at(size_t operation_index) {
  io_fail_index = operation_index;
  io_count = 0;
}

void sg_test_io_reset(void) {
  io_fail_index = 0;
  io_count = 0;
}

size_t sg_test_io_count(void) { return io_count; }

bool sg_test_io_should_fail(void) {
  io_count++;
  return io_fail_index != 0 && io_count == io_fail_index;
}
