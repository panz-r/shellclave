#ifndef SHELLTYPE_TEST_IO_H
#define SHELLTYPE_TEST_IO_H

#include <stddef.h>

void st_test_io_fail_at(size_t operation_index);
void st_test_io_crash_after(size_t operation_index);
void st_test_io_reset(void);
size_t st_test_io_count(void);
void st_test_read_fail_at(size_t line_index);
size_t st_test_read_count(void);

#endif
