#include "test_source_scans.h"
#include <stdint.h>

static _Thread_local size_t scan_work;
static _Thread_local size_t line_work;
static _Thread_local uintptr_t watch_begin, watch_end;
static _Thread_local size_t delimiter_work;
static _Thread_local size_t metadata_work[SHELLSPLIT_TEST_WORK_COUNT];
static _Thread_local size_t observation_order_errors;
static _Thread_local uint32_t memo_limit;
static _Thread_local uint64_t trace_bits[SHELLSPLIT_TRACE_KINDS * 32 / 64];

void shellsplit_test_source_scan_charge(size_t length) { scan_work += length; }
void shellsplit_test_source_scan_reset(void) {
  observation_order_errors = 0;
  scan_work = 0;
  line_work = 0;
  watch_begin = watch_end = 0;
  delimiter_work = 0;
  for (size_t i = 0; i < SHELLSPLIT_TEST_WORK_COUNT; i++)
    metadata_work[i] = 0;
}
size_t shellsplit_test_source_scan_work(void) { return scan_work; }
void shellsplit_test_trace(shellsplit_test_trace_kind_t kind,
                           unsigned outcome) {
  unsigned id = (unsigned)kind * 32 + (outcome & 31u);
  trace_bits[id / 64] |= UINT64_C(1) << (id % 64);
}
void shellsplit_test_trace_reset(void) {
  for (size_t i = 0; i < sizeof(trace_bits) / sizeof(trace_bits[0]); i++)
    trace_bits[i] = 0;
}
size_t shellsplit_test_trace_events(uint16_t *events, size_t capacity) {
  size_t n = 0;
  for (unsigned id = 0; id < SHELLSPLIT_TRACE_KINDS * 32; id++)
    if ((trace_bits[id / 64] >> (id % 64)) & 1u) {
      if (n < capacity)
        events[n] = (uint16_t)id;
      n++;
    }
  return n;
}
void shellsplit_test_set_union_memo_limit(uint32_t entries) {
  memo_limit = entries;
}
uint32_t shellsplit_test_union_memo_limit(void) { return memo_limit; }
void shellsplit_test_line_scan_charge(size_t length) {
  line_work += length;
  scan_work += length;
}
size_t shellsplit_test_line_scan_work(void) { return line_work; }
void shellsplit_test_delimiter_watch(const char *source, size_t length) {
  watch_begin = (uintptr_t)source;
  watch_end = watch_begin + length;
}
void shellsplit_test_delimiter_charge(const char *source, size_t length) {
  scan_work += length;
  uintptr_t begin = (uintptr_t)source, end = begin + length;
  if (begin < watch_end && end > watch_begin) {
    uintptr_t first = begin > watch_begin ? begin : watch_begin;
    uintptr_t last = end < watch_end ? end : watch_end;
    delimiter_work += last - first;
  }
}
size_t shellsplit_test_delimiter_work(void) { return delimiter_work; }
void shellsplit_test_metadata_charge(shellsplit_test_metadata_kind_t kind) {
  metadata_work[kind]++;
}
size_t shellsplit_test_metadata_work(shellsplit_test_metadata_kind_t kind) {
  return metadata_work[kind];
}

void shellsplit_test_observation_order_record(size_t previous, size_t current) {
  observation_order_errors += current < previous;
}

size_t shellsplit_test_observation_order_errors(void) {
  return observation_order_errors;
}
