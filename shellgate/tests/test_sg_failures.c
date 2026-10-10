#include "test_sg_failures.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static size_t alloc_fail_index;
static size_t alloc_count;
static size_t anomaly_fail_index;
static size_t anomaly_count;
static size_t anomaly_work;
static size_t path_work;
static size_t path_decoded;
static size_t path_identity;
static sg_anomaly_status_t anomaly_score_failure;
static sg_anomaly_status_t anomaly_update_failure;
static size_t io_fail_index;
static size_t io_count;
static int io_error_number = EIO;
static int io_close_error;
static const unsigned char *io_temp_random;
static sg_test_io_read_observer_t io_read_observer;
static void *io_read_context;
static int locale_error;

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

void sg_test_anomaly_work_reset(void) { anomaly_work = 0; }
size_t sg_test_anomaly_work_count(void) { return anomaly_work; }
void sg_test_anomaly_work_charge(void) { anomaly_work++; }

void sg_test_path_work_reset(void) {
  path_work = path_decoded = path_identity = 0;
}
size_t sg_test_path_work_count(void) { return path_work; }
void sg_test_path_work_charge(void) { path_work++; }
size_t sg_test_path_decoded_count(void) { return path_decoded; }
void sg_test_path_decoded_charge(void) { path_decoded++; }
size_t sg_test_path_identity_count(void) { return path_identity; }
void sg_test_path_identity_charge(size_t bytes) { path_identity += bytes; }

void sg_test_anomaly_score_fail_with(sg_anomaly_status_t status) {
  anomaly_score_failure = status;
}

void sg_test_anomaly_update_fail_with(sg_anomaly_status_t status) {
  anomaly_update_failure = status;
}

void sg_test_anomaly_result_reset(void) {
  anomaly_score_failure = SG_ANOMALY_OK;
  anomaly_update_failure = SG_ANOMALY_OK;
}

sg_anomaly_status_t sg_test_anomaly_score_take_failure(void) {
  sg_anomaly_status_t status = anomaly_score_failure;
  anomaly_score_failure = SG_ANOMALY_OK;
  return status;
}

sg_anomaly_status_t sg_test_anomaly_update_take_failure(void) {
  sg_anomaly_status_t status = anomaly_update_failure;
  anomaly_update_failure = SG_ANOMALY_OK;
  return status;
}

void sg_test_io_fail_at(size_t operation_index) {
  sg_test_io_fail_at_with_errno(operation_index, EIO);
}

void sg_test_io_fail_at_with_errno(size_t operation_index, int error_number) {
  io_fail_index = operation_index;
  io_count = 0;
  io_error_number = error_number;
}

void sg_test_io_reset(void) {
  io_fail_index = 0;
  io_count = 0;
  io_error_number = EIO;
  io_close_error = 0;
  io_temp_random = NULL;
  io_read_observer = NULL;
  io_read_context = NULL;
}

void sg_test_io_read_observer_set(sg_test_io_read_observer_t observer,
                                  void *context) {
  io_read_observer = observer;
  io_read_context = context;
}

void sg_test_io_observe_read(FILE *stream, size_t length) {
  if (io_read_observer) {
    int saved_errno = errno;
    io_read_observer(stream, length, io_read_context);
    errno = saved_errno;
  }
}

void sg_test_io_temp_random_set(const unsigned char *random) {
  io_temp_random = random;
}

const unsigned char *sg_test_io_temp_random_bytes(void) {
  return io_temp_random;
}

size_t sg_test_io_count(void) { return io_count; }

bool sg_test_io_should_fail(void) {
  io_count++;
  return io_fail_index != 0 && io_count == io_fail_index;
}

int sg_test_io_error_number(void) { return io_error_number; }

void sg_test_io_close_fail_with_errno(int error_number) {
  io_close_error = error_number;
}

int sg_test_io_close_take_error(void) {
  int error_number = io_close_error;
  io_close_error = 0;
  return error_number;
}

void sg_test_locale_fail_with_errno(int error_number) {
  locale_error = error_number;
}

int sg_test_locale_take_error(void) {
  int error_number = locale_error;
  locale_error = 0;
  return error_number;
}
