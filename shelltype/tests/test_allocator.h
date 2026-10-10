#ifndef SHELLTYPE_TEST_ALLOCATOR_H
#define SHELLTYPE_TEST_ALLOCATOR_H

#include <stddef.h>

/* Fail exactly one allocation, then resume normal allocation.  Passing zero
 * disables failure injection. */
void st_test_alloc_fail_at(size_t allocation_index);
void st_test_alloc_reset(void);
size_t st_test_alloc_count(void);
/* Cumulative requested bytes, including failed attempts and the full requested
 * capacity of each realloc, since the most recent reset/fail-at call. Tests
 * using this metric keep the total representable in size_t. */
size_t st_test_alloc_bytes(void);

/* Option-prefix comparisons and predicate evaluations in the most recent
 * suggest call on this thread, including construction of its compound index. */
size_t st_test_learner_support_work(void);

/* Byte inspections and actual strlen scan lengths since the latest CPL parse
 * on this thread, including subsequent codec work in the same conversion. */
size_t st_test_cpl_parse_work(void);

#endif
