#ifndef SHELLSPLIT_TEST_ALLOCATOR_H
#define SHELLSPLIT_TEST_ALLOCATOR_H

#include <stddef.h>

void shellsplit_test_alloc_fail_at(size_t allocation_index);
void shellsplit_test_alloc_reset(void);
size_t shellsplit_test_alloc_count(void);

#endif
