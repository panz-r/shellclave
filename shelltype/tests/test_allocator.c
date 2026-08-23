#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "test_allocator.h"

#include <stdlib.h>
#include <string.h>

static _Thread_local size_t fail_at;
static _Thread_local size_t allocation_count;

static int should_fail(void) {
  allocation_count++;
  return fail_at != 0 && allocation_count == fail_at;
}

void st_test_alloc_fail_at(size_t allocation_index) {
  fail_at = allocation_index;
  allocation_count = 0;
}

void st_test_alloc_reset(void) {
  fail_at = 0;
  allocation_count = 0;
}

size_t st_test_alloc_count(void) { return allocation_count; }

void *st_test_malloc(size_t size) {
  return should_fail() ? NULL : malloc(size);
}

void *st_test_calloc(size_t count, size_t size) {
  return should_fail() ? NULL : calloc(count, size);
}

void *st_test_realloc(void *ptr, size_t size) {
  return should_fail() ? NULL : realloc(ptr, size);
}

char *st_test_strdup(const char *value) {
  return should_fail() ? NULL : strdup(value);
}

char *st_test_strndup(const char *value, size_t length) {
  return should_fail() ? NULL : strndup(value, length);
}
