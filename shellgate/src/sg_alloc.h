#ifndef SHELLGATE_ALLOC_H
#define SHELLGATE_ALLOC_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef SHELLGATE_TEST_ALLOCATOR
void *sg_test_malloc(size_t size);
void *sg_test_calloc(size_t count, size_t size);
char *sg_test_strdup(const char *text);
#define malloc sg_test_malloc
#define calloc sg_test_calloc
#define strdup sg_test_strdup
#endif

#endif
