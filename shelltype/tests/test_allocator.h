#ifndef SHELLTYPE_TEST_ALLOCATOR_H
#define SHELLTYPE_TEST_ALLOCATOR_H

#include <stddef.h>

/* Fail exactly one allocation, then resume normal allocation.  Passing zero
 * disables failure injection. */
void st_test_alloc_fail_at(size_t allocation_index);
void st_test_alloc_reset(void);
size_t st_test_alloc_count(void);

#endif
