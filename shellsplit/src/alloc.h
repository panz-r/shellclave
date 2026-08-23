#ifndef SHELLSPLIT_ALLOC_H
#define SHELLSPLIT_ALLOC_H

#include <stddef.h>

#ifdef SHELLSPLIT_TEST_ALLOCATOR
void *shellsplit_test_malloc(size_t size);
void *shellsplit_test_calloc(size_t count, size_t size);
void *shellsplit_test_realloc(void *pointer, size_t size);
char *shellsplit_test_strdup(const char *value);
char *shellsplit_test_strndup(const char *value, size_t length);
#define malloc shellsplit_test_malloc
#define calloc shellsplit_test_calloc
#define realloc shellsplit_test_realloc
#define strdup shellsplit_test_strdup
#define strndup shellsplit_test_strndup
#endif

#endif
