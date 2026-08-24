#include "shell_netstring.h"
#include "test_allocator.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed;
static int failed;

#define TEST(name, condition)                                                  \
  do {                                                                         \
    if (condition) {                                                           \
      printf("  [PASS] %s\n", name);                                           \
      passed++;                                                                \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      failed++;                                                                \
    }                                                                          \
  } while (0)

static void test_iteration(void) {
  static const unsigned char input[] = "3:cat,0:,9:two words,";
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  TEST("initialize sequence",
       shell_netstring_iter_init(&iter, input, sizeof(input) - 1) ==
           SHELL_NETSTRING_OK);
  TEST("first record",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.record_length == 6 && view.payload_length == 3 &&
           memcmp(view.payload, "cat", 3) == 0);
  TEST("empty payload",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.record_length == 3 && view.payload_length == 0);
  TEST("spaced payload",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.payload_length == 9 &&
           memcmp(view.payload, "two words", 9) == 0);
  TEST("iterator finishes",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_DONE);
}

static void test_binary_and_nested_payloads(void) {
  static const unsigned char binary[] = {'3', ':', 'a', '\0', 'b', ',',
                                         '3', ':', '0', ':',  ',', ','};
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  TEST("binary input initializes",
       shell_netstring_iter_init(&iter, binary, sizeof(binary)) ==
           SHELL_NETSTRING_OK);
  TEST("binary payload preserved",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.payload_length == 3 && view.payload[1] == '\0');
  TEST("nested record remains opaque",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.payload_length == 3 && memcmp(view.payload, "0:,", 3) == 0);
  TEST("nested payload can be iterated",
       shell_netstring_validate(view.payload, view.payload_length, NULL) ==
           SHELL_NETSTRING_OK);
}

static void test_validation_failures(void) {
  static const struct {
    const char *input;
    shell_netstring_status_t expected;
  } cases[] = {
      {"00:,", SHELL_NETSTRING_EFORMAT},
      {"3:ab,", SHELL_NETSTRING_EFORMAT},
      {"3:abc", SHELL_NETSTRING_EFORMAT},
      {"0:", SHELL_NETSTRING_EFORMAT},
      {"3:abc,x", SHELL_NETSTRING_EFORMAT},
      {"x:abc,", SHELL_NETSTRING_EFORMAT},
      {"184467440737095516160:x,", SHELL_NETSTRING_EOVERFLOW},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    TEST("malformed framing rejected",
         shell_netstring_validate(cases[i].input, strlen(cases[i].input),
                                  NULL) == cases[i].expected);
  }
  size_t count = 99;
  TEST("empty sequence validates",
       shell_netstring_validate(NULL, 0, &count) == SHELL_NETSTRING_OK &&
           count == 0);
  TEST("null non-empty input rejected",
       shell_netstring_validate(NULL, 1, NULL) == SHELL_NETSTRING_EINPUT);
}

static void test_count_and_error_position(void) {
  static const char input[] = "1:a,2:bc,";
  static const char broken[] = "1:a,01:b,";
  size_t count = 0;
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  TEST("count validates complete sequence",
       shell_netstring_validate(input, sizeof(input) - 1, &count) ==
               SHELL_NETSTRING_OK &&
           count == 2);
  TEST("initialize broken sequence",
       shell_netstring_iter_init(&iter, broken, sizeof(broken) - 1) ==
           SHELL_NETSTRING_OK);
  TEST("prefix before malformed record succeeds",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK);
  size_t invalid_offset = iter.offset;
  TEST("error preserves invalid record position",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_EFORMAT &&
           iter.offset == invalid_offset);
}

static void test_encoding(void) {
  unsigned char record[16];
  size_t length = 0, written = 0;
  TEST("encoded length",
       shell_netstring_encoded_length(3, &length) == SHELL_NETSTRING_OK &&
           length == 6);
  TEST("encode record", shell_netstring_write(record, sizeof(record), "cat", 3,
                                              &written) == SHELL_NETSTRING_OK &&
                            written == 6 && memcmp(record, "3:cat,", 6) == 0);
  TEST("encode empty payload",
       shell_netstring_write(record, 3, NULL, 0, &written) ==
               SHELL_NETSTRING_OK &&
           written == 3 && memcmp(record, "0:,", 3) == 0);
  TEST("short output rejected",
       shell_netstring_write(record, 5, "cat", 3, NULL) ==
           SHELL_NETSTRING_EOVERFLOW);
}

static void test_stream_reader(void) {
  FILE *stream = tmpfile();
  unsigned char *record = NULL;
  size_t length = 0;
  TEST("open stream", stream != NULL);
  if (!stream)
    return;
  fputs("3:cat,0:,", stream);
  rewind(stream);
  TEST("read first stream record",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_OK &&
           length == 6 && memcmp(record, "3:cat,", 6) == 0);
  free(record);
  record = NULL;
  TEST("read empty stream record",
       shell_netstring_read_stream(stream, 3, &record, &length) ==
               SHELL_NETSTRING_OK &&
           length == 3 && memcmp(record, "0:,", 3) == 0);
  free(record);
  TEST("stream EOF", shell_netstring_read_stream(stream, 0, &record, &length) ==
                         SHELL_NETSTRING_DONE);
  fclose(stream);
}

static void test_stream_reader_allocation_failures(void) {
  FILE *stream = tmpfile();
  unsigned char *record = NULL;
  size_t length = 0;
  TEST("open allocation stream", stream != NULL);
  if (!stream)
    return;
  fputs("3:cat,", stream);

  shellsplit_test_alloc_reset();
  rewind(stream);
  TEST("stream reader allocation probe",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_OK &&
           record != NULL && length == 6 && shellsplit_test_alloc_count() == 1);
  free(record);

  record = (unsigned char *)(void *)1;
  length = SIZE_MAX;
  shellsplit_test_alloc_fail_at(1);
  rewind(stream);
  TEST("stream reader clears outputs on allocation failure",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_ENOMEM &&
           record == NULL && length == 0);
  shellsplit_test_alloc_reset();
  fclose(stream);
}

static void test_stream_reader_rejects_unallocatable_record(void) {
  FILE *stream = tmpfile();
  unsigned char *record = (unsigned char *)(void *)1;
  size_t length = SIZE_MAX;
  TEST("open overflow stream", stream != NULL);
  if (!stream)
    return;

  size_t payload_length = SIZE_MAX;
  size_t total = 0;
  while (shell_netstring_encoded_length(payload_length, &total) !=
             SHELL_NETSTRING_OK ||
         total != SIZE_MAX)
    payload_length--;
  fprintf(stream, "%zu:", payload_length);
  rewind(stream);
  TEST("stream reader rejects record without terminator space",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_EOVERFLOW &&
           record == NULL && length == 0);
  fclose(stream);
}

int main(void) {
  printf("=== Shellsplit Netstring Tests ===\n");
  test_iteration();
  test_binary_and_nested_payloads();
  test_validation_failures();
  test_count_and_error_position();
  test_encoding();
  test_stream_reader();
  test_stream_reader_allocation_failures();
  test_stream_reader_rejects_unallocatable_record();
  printf("\n%d passed, %d failed\n", passed, failed);
  return failed != 0;
}
