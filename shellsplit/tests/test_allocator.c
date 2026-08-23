#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "test_allocator.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local size_t fail_at;
static _Thread_local size_t allocation_count;

static int allocation_fails(void) {
  allocation_count++;
  if (fail_at != 0 && allocation_count == fail_at) {
    errno = ENOMEM;
    return 1;
  }
  return 0;
}

void shellsplit_test_alloc_fail_at(size_t allocation_index) {
  fail_at = allocation_index;
  allocation_count = 0;
}

void shellsplit_test_alloc_reset(void) {
  fail_at = 0;
  allocation_count = 0;
}

size_t shellsplit_test_alloc_count(void) { return allocation_count; }

void *shellsplit_test_malloc(size_t size) {
  return allocation_fails() ? NULL : malloc(size);
}

void *shellsplit_test_calloc(size_t count, size_t size) {
  return allocation_fails() ? NULL : calloc(count, size);
}

void *shellsplit_test_realloc(void *pointer, size_t size) {
  return allocation_fails() ? NULL : realloc(pointer, size);
}

char *shellsplit_test_strdup(const char *value) {
  return allocation_fails() ? NULL : strdup(value);
}

char *shellsplit_test_strndup(const char *value, size_t length) {
  return allocation_fails() ? NULL : strndup(value, length);
}
