#ifndef SHELLTYPE_ALLOC_H
#define SHELLTYPE_ALLOC_H

#include <stddef.h>

/* Test builds redirect allocation calls through deterministic hooks.  The
 * production target deliberately leaves these names mapped to libc. */
#ifdef SHELLTYPE_TEST_ALLOCATOR
void *st_test_malloc(size_t size);
void *st_test_calloc(size_t count, size_t size);
void *st_test_realloc(void *ptr, size_t size);
char *st_test_strdup(const char *value);
#define malloc st_test_malloc
#define calloc st_test_calloc
#define realloc st_test_realloc
#define strdup st_test_strdup
#endif

#endif
