/*
 * anomaly_calibrate - Threshold calibration and ROC curve generator
 *
 * Trains the anomaly model on a corpus of normal commands, generates
 * synthetic anomalies via perturbation, evaluates at multiple thresholds,
 * and outputs ROC curve data (TPR, FPR, precision, F1, AUC).
 *
 * Usage:
 *   anomaly_calibrate -n normal.txt [options]
 *
 * Options:
 *   -n <file>   Normal commands corpus (one command per line, required)
 *   -o <file>   Output file (default: stdout)
 *   -t <s,e,i>  Threshold range: start,end,step (default: 0.0,15.0,0.5;
 *               maximum 1024 input bytes)
 *   -p <type>   Perturbation: swap|insert|substitute|shuffle|all (default: all)
 *   -N <num>    Synthetics per normal command (default: 3)
 *   -f <fmt>    Output: csv|json|text (default: csv)
 *   -s <file>   Save trained model to file
 *   -h          Show help
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sg_anomaly.h"
#include "shell_abstract.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shellgate.h"

#define MAX_TOKENS 256
#define MAX_CMDS 65536
#define MAX_SYNTHETIC (MAX_CMDS * 4)
#define MAX_THRESHOLDS 1000
#define MAX_THRESHOLD_SPEC_LENGTH 1024

/* Uncommon commands for substitution/insertion perturbations */
static const char *rare_cmds[] = {"mkfs",    "fdisk",    "dd",      "iptables",
                                  "reboot",  "shutdown", "nc",      "strace",
                                  "objdump", "gdb",      "hexdump", "base64",
                                  "strings", "nm",       "strip"};
#define NUM_RARE (sizeof(rare_cmds) / sizeof(rare_cmds[0]))

typedef enum {
  PERTURB_SWAP = 0,
  PERTURB_INSERT,
  PERTURB_SUBSTITUTE,
  PERTURB_SHUFFLE,
  PERTURB_ALL
} perturb_type_t;

#define PERTURB_KIND_COUNT 4

typedef struct {
  double threshold;
  int tp, fp, tn, fn;
  double tpr, fpr, precision, f1;
} roc_point_t;

typedef struct {
  char *raw_netseq;
  size_t raw_netseq_length;
  char *type_netseq;
  size_t type_netseq_length;
  size_t count;
  size_t source_line;
} corpus_record_t;

typedef shell_netstring_view_t netseq_span_t;

static void free_corpus(corpus_record_t *records, size_t count) {
  if (!records)
    return;
  for (size_t i = 0; i < count; i++) {
    free(records[i].raw_netseq);
    free(records[i].type_netseq);
  }
  free(records);
}

/* Shellgate uses one caller-owned buffer for the rendered result and its
 * dependency-graph workspace. Keep one growable buffer while loading a
 * corpus instead of assuming a small diagnostic buffer is sufficient. */
static bool ensure_evaluation_buffer(char **buffer, size_t *capacity,
                                     size_t command_length) {
  if (!buffer || !capacity)
    return false;
  size_t required = sg_gate_evaluate_size_hint(command_length);
  if (required == SIZE_MAX)
    return false;
  if (required <= *capacity)
    return true;
  char *grown = realloc(*buffer, required);
  if (!grown)
    return false;
  *buffer = grown;
  *capacity = required;
  return true;
}

/* The public size hint reserves the graph workspace and a useful result
 * prefix, but nested source can render more diagnostics than that prefix. A
 * truncated evaluation deliberately has no anomaly-learning side effects, so
 * it is safe to retry after growing the same caller-owned workspace. A
 * subcommand-count truncation is a fixed Shellgate output limit, not a buffer
 * shortage, and must be reported instead of retried forever. */
static sg_error_t evaluate_complete(sg_gate_t *gate, const char *command,
                                    size_t command_length, char **buffer,
                                    size_t *capacity, sg_result_t *result) {
  if (!gate || !command || !buffer || !capacity || !result ||
      !ensure_evaluation_buffer(buffer, capacity, command_length))
    return SG_ERR_MEMORY;

  for (;;) {
    sg_error_t status = sg_gate_evaluate(gate, command, command_length, *buffer,
                                         *capacity, result);
    if (status != SG_ERR_TRUNC)
      return status;
    if (result->subcommand_truncated)
      return SG_ERR_TRUNC;
    if (*capacity > SIZE_MAX / 2)
      return SG_ERR_MEMORY;
    size_t grown_capacity = *capacity * 2;
    char *grown = realloc(*buffer, grown_capacity);
    if (!grown)
      return SG_ERR_MEMORY;
    *buffer = grown;
    *capacity = grown_capacity;
  }
}

static char *trim(char *s) {
  while (isspace((unsigned char)*s))
    s++;
  if (*s == 0)
    return s;
  char *end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end))
    end--;
  end[1] = '\0';
  return s;
}

typedef enum {
  CORPUS_LINE_OK,
  CORPUS_LINE_EOF,
  CORPUS_LINE_IO,
  CORPUS_LINE_NUL,
  CORPUS_LINE_MEMORY,
} corpus_line_status_t;

/* A corpus record is one physical text line, not one fixed-size buffer read.
 * Splitting a long shell command turns one training observation into several
 * unrelated commands, so retain the whole line until its newline (or EOF).
 * Shellgate source is text; reject a raw NUL instead of silently truncating it
 * through C-string interfaces below. */
static corpus_line_status_t read_corpus_line(FILE *stream, char **line,
                                             size_t *capacity, size_t *length) {
  if (length)
    *length = 0;
  if (!stream || !line || !capacity)
    return CORPUS_LINE_IO;

  size_t used = 0;
  for (;;) {
    int current = fgetc(stream);
    if (current == EOF) {
      if (ferror(stream))
        return CORPUS_LINE_IO;
      if (used == 0)
        return CORPUS_LINE_EOF;
      break;
    }
    if (current == '\0')
      return CORPUS_LINE_NUL;
    if (current == '\n')
      break;
    if (used == SIZE_MAX - 1)
      return CORPUS_LINE_MEMORY;
    if (used + 1 >= *capacity) {
      size_t next_capacity = *capacity ? *capacity : 256;
      while (next_capacity <= used + 1) {
        if (next_capacity > SIZE_MAX / 2) {
          next_capacity = used + 2;
          break;
        }
        next_capacity *= 2;
      }
      char *grown = realloc(*line, next_capacity);
      if (!grown)
        return CORPUS_LINE_MEMORY;
      *line = grown;
      *capacity = next_capacity;
    }
    (*line)[used++] = (char)current;
  }
  if (used + 1 > *capacity) {
    char *grown = realloc(*line, used + 1);
    if (!grown)
      return CORPUS_LINE_MEMORY;
    *line = grown;
    *capacity = used + 1;
  }
  (*line)[used] = '\0';
  if (length)
    *length = used;
  return CORPUS_LINE_OK;
}

static bool collect_netseq_views(const char *netseq, size_t length,
                                 netseq_span_t *out, size_t capacity,
                                 size_t *count) {
  *count = 0;
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, netseq, length) != SHELL_NETSTRING_OK)
    return false;
  shell_netstring_status_t status;
  shell_netstring_view_t view;
  for (;;) {
    status = shell_netstring_iter_next(&iter, &view);
    if (status != SHELL_NETSTRING_OK)
      break;
    if (*count == capacity)
      return false;
    out[(*count)++] = view;
  }
  return status == SHELL_NETSTRING_DONE;
}

static bool rare_spans(const char *command, netseq_span_t *raw,
                       netseq_span_t *type, char raw_buf[64],
                       char type_buf[80]) {
  size_t length = strlen(command);
  size_t raw_written = 0;
  if (shell_netstring_write(raw_buf, 64, command, length, &raw_written) !=
      SHELL_NETSTRING_OK)
    return false;
  size_t type_written = 0;
  if (shell_netstring_write(type_buf, 80, raw_buf, raw_written,
                            &type_written) != SHELL_NETSTRING_OK)
    return false;
  *raw = (netseq_span_t){(const unsigned char *)raw_buf, raw_written, NULL, 0};
  *type =
      (netseq_span_t){(const unsigned char *)type_buf, type_written, NULL, 0};
  return true;
}

static bool render_selection(const netseq_span_t *spans, size_t count,
                             const size_t *order, const char *rare_command,
                             bool type_sequence,
                             shell_netstring_buffer_t *out) {
  if (!out)
    return false;
  *out = (shell_netstring_buffer_t){0};
  char raw_buf[64], type_buf[80];
  netseq_span_t rare_raw, rare_type;
  if (rare_command &&
      !rare_spans(rare_command, &rare_raw, &rare_type, raw_buf, type_buf))
    return false;
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    netseq_span_t span = order[i] == SIZE_MAX
                             ? (type_sequence ? rare_type : rare_raw)
                             : spans[order[i]];
    if (span.record_length > SIZE_MAX - total)
      return false;
    total += span.record_length;
  }
  if (total == SIZE_MAX)
    return false;
  out->data = malloc(total + 1);
  if (!out->data)
    return false;
  size_t used = 0;
  for (size_t i = 0; i < count; i++) {
    netseq_span_t span = order[i] == SIZE_MAX
                             ? (type_sequence ? rare_type : rare_raw)
                             : spans[order[i]];
    memcpy(out->data + used, span.record, span.record_length);
    used += span.record_length;
  }
  out->data[used] = '\0';
  out->length = used;
  return true;
}

static unsigned int rand_uint(unsigned int *state) {
  *state = *state * 1103515245u + 12345u;
  return (*state >> 16) & 0x7fff;
}

static bool netseq_span_equal(netseq_span_t left, netseq_span_t right) {
  return left.record_length == right.record_length &&
         memcmp(left.record, right.record, left.record_length) == 0;
}

static bool sequence_has_distinct_stages(const netseq_span_t *raw,
                                         const netseq_span_t *type,
                                         size_t count) {
  for (size_t left = 0; left < count; left++)
    for (size_t right = left + 1; right < count; right++)
      if (!netseq_span_equal(raw[left], raw[right]) ||
          !netseq_span_equal(type[left], type[right]))
        return true;
  return false;
}

static bool perturbation_available(perturb_type_t requested,
                                   const netseq_span_t *raw,
                                   const netseq_span_t *type, size_t count) {
  if (!raw || !type || count == 0 || count > MAX_TOKENS)
    return false;
  bool reorderable = sequence_has_distinct_stages(raw, type, count);
  switch (requested) {
  case PERTURB_SWAP:
  case PERTURB_SHUFFLE:
    return reorderable;
  case PERTURB_INSERT:
    return count < MAX_TOKENS;
  case PERTURB_SUBSTITUTE:
    /* At least one of the finite rare-command set must differ from a source
     * stage. Since the set contains distinct canonical commands, any
     * nonempty sequence has such a replacement. */
    return true;
  case PERTURB_ALL:
    return reorderable || count < MAX_TOKENS || count > 0;
  }
  return false;
}

static bool choose_rare_command(const netseq_span_t *raw,
                                const netseq_span_t *type, size_t index,
                                unsigned int *rng, const char **selected) {
  if (!raw || !type || !rng || !selected)
    return false;
  size_t start = rand_uint(rng) % NUM_RARE;
  for (size_t attempt = 0; attempt < NUM_RARE; attempt++) {
    const char *candidate = rare_cmds[(start + attempt) % NUM_RARE];
    char raw_buf[64], type_buf[80];
    netseq_span_t candidate_raw, candidate_type;
    if (!rare_spans(candidate, &candidate_raw, &candidate_type, raw_buf,
                    type_buf))
      return false;
    if (!netseq_span_equal(raw[index], candidate_raw) ||
        !netseq_span_equal(type[index], candidate_type)) {
      *selected = candidate;
      return true;
    }
  }
  return false;
}

static bool selection_changes_source(const netseq_span_t *raw,
                                     const netseq_span_t *type,
                                     size_t source_count, const size_t *order,
                                     size_t selected_count,
                                     const char *rare_command) {
  if (selected_count != source_count)
    return true;
  char raw_buf[64], type_buf[80];
  netseq_span_t rare_raw, rare_type;
  if (rare_command &&
      !rare_spans(rare_command, &rare_raw, &rare_type, raw_buf, type_buf))
    return false;
  for (size_t index = 0; index < selected_count; index++) {
    if (order[index] == SIZE_MAX) {
      if (!rare_command || !netseq_span_equal(raw[index], rare_raw) ||
          !netseq_span_equal(type[index], rare_type))
        return true;
    } else if (!netseq_span_equal(raw[index], raw[order[index]]) ||
               !netseq_span_equal(type[index], type[order[index]])) {
      return true;
    }
  }
  return false;
}

/* Perturbation: swap two command stages. */
static bool perturb_swap(size_t *order, const netseq_span_t *raw,
                         const netseq_span_t *type, size_t count,
                         unsigned int *rng) {
  if (count < 2)
    return false;
  for (size_t i = 0; i < count; i++)
    order[i] = i;
  /* Start at a deterministic random pair, then scan for a pair whose
   * canonical raw or typed stages differ. Swapping equal stages is not a
   * synthetic anomaly, even though its index permutation changed. */
  size_t a = rand_uint(rng) % count;
  size_t b = rand_uint(rng) % count;
  if (a == b)
    b = (b + 1) % count;
  if (netseq_span_equal(raw[a], raw[b]) &&
      netseq_span_equal(type[a], type[b])) {
    bool found = false;
    for (size_t offset = 0; offset < count && !found; offset++)
      for (size_t candidate = 0; candidate < count; candidate++) {
        size_t candidate_a = (a + offset) % count;
        if (candidate_a == candidate ||
            (netseq_span_equal(raw[candidate_a], raw[candidate]) &&
             netseq_span_equal(type[candidate_a], type[candidate])))
          continue;
        a = candidate_a;
        b = candidate;
        found = true;
        break;
      }
    if (!found)
      return false;
  }
  size_t tmp = order[a];
  order[a] = order[b];
  order[b] = tmp;
  return true;
}

/* Perturbation: insert a random rare command */
static bool perturb_insert(size_t *order, size_t *out_count, size_t count,
                           unsigned int *rng) {
  if (count == 0)
    return false;
  if (count >= MAX_TOKENS)
    return false;
  size_t insert_pos = rand_uint(rng) % (count + 1);
  size_t j = 0;
  for (size_t i = 0; i < count; i++) {
    if (i == insert_pos) {
      order[j++] = SIZE_MAX;
    }
    order[j++] = i;
  }
  if (insert_pos == count)
    order[j++] = SIZE_MAX;
  *out_count = j;
  return true;
}

/* Perturbation: substitute one command with a rare one */
static bool perturb_substitute(size_t *order, size_t count, unsigned int *rng) {
  if (count == 0)
    return false;
  size_t pos = rand_uint(rng) % count;
  for (size_t i = 0; i < count; i++) {
    order[i] = i == pos ? SIZE_MAX : i;
  }
  return true;
}

/* Perturbation: shuffle all tokens */
static bool perturb_shuffle(size_t *order, const netseq_span_t *raw,
                            const netseq_span_t *type, size_t count,
                            unsigned int *rng) {
  if (count < 2)
    return false;
  for (size_t i = 0; i < count; i++)
    order[i] = i;
  /* Shuffle token copies in-place using Fisher-Yates. */
  for (size_t i = count - 1; i > 0; i--) {
    size_t j = rand_uint(rng) % (i + 1);
    size_t tmp = order[i];
    order[i] = order[j];
    order[j] = tmp;
  }
  /* Check whether the represented sequence changed, not just the indices.
   * A random permutation of repeated commands can be byte-for-byte identical.
   */
  bool changed = false;
  for (size_t i = 0; i < count; i++) {
    if (!netseq_span_equal(raw[order[i]], raw[i]) ||
        !netseq_span_equal(type[order[i]], type[i])) {
      changed = true;
      break;
    }
  }
  if (!changed)
    return perturb_swap(order, raw, type, count, rng);
  return changed;
}

static bool parse_unsigned_decimal(const char *text, uintmax_t maximum,
                                   bool allow_zero, uintmax_t *out) {
  if (!text || !*text || !out)
    return false;
  uintmax_t value = 0;
  for (const unsigned char *cursor = (const unsigned char *)text; *cursor;
       cursor++) {
    if (*cursor < '0' || *cursor > '9')
      return false;
    uintmax_t digit = (uintmax_t)(*cursor - '0');
    if (value > maximum / 10 || (value == maximum / 10 && digit > maximum % 10))
      return false;
    value = value * 10 + digit;
  }
  if (!allow_zero && value == 0)
    return false;
  *out = value;
  return true;
}

static bool parse_size_option(const char *text, size_t maximum, size_t *out) {
  uintmax_t value = 0;
  if (!out || !parse_unsigned_decimal(text, maximum, false, &value))
    return false;
  *out = (size_t)value;
  return true;
}

static bool parse_seed_option(const char *text, unsigned int *out) {
  uintmax_t value = 0;
  if (!out || !parse_unsigned_decimal(text, UINT_MAX, true, &value))
    return false;
  *out = (unsigned int)value;
  return true;
}

static bool parse_threshold_range(const char *text) {
  if (!text || strlen(text) > MAX_THRESHOLD_SPEC_LENGTH)
    return false;
  errno = 0;
  char *cursor = NULL;
  double parsed_start = strtod(text, &cursor);
  if (errno != 0 || cursor == text || *cursor != ',')
    return false;
  const char *second = cursor + 1;
  errno = 0;
  double parsed_end = strtod(second, &cursor);
  if (errno != 0 || cursor == second || *cursor != ',')
    return false;
  const char *third = cursor + 1;
  errno = 0;
  double parsed_step = strtod(third, &cursor);
  if (errno != 0 || cursor == third || *cursor != '\0' ||
      !isfinite(parsed_start) || !isfinite(parsed_end) ||
      !isfinite(parsed_step) || parsed_step <= 0.0 || parsed_end < parsed_start)
    return false;
  return true;
}

/* A threshold's spelling, not its rounded double, determines whether it lies
 * on the requested grid. Store exact finite decimal values as a base-10
 * coefficient and exponent. Hexadecimal input is converted exactly as well:
 * 2^-n is 5^n * 10^-n. The 1000-point cap keeps the small-integer arithmetic
 * needed by this tool bounded without adding a multiprecision dependency. */
typedef struct {
  uint8_t *digits; /* least significant decimal digit first */
  size_t count;
  size_t capacity;
} threshold_integer_t;

typedef struct {
  threshold_integer_t coefficient;
  int64_t exponent;
  bool negative;
} threshold_exact_t;

static void threshold_exact_free(threshold_exact_t *number) {
  if (!number)
    return;
  free(number->coefficient.digits);
  *number = (threshold_exact_t){0};
}

static bool threshold_integer_reserve(threshold_integer_t *number,
                                      size_t capacity) {
  if (!number)
    return false;
  if (capacity <= number->capacity)
    return true;
  uint8_t *grown = realloc(number->digits, capacity);
  if (!grown)
    return false;
  number->digits = grown;
  number->capacity = capacity;
  return true;
}

static bool threshold_integer_zero(threshold_integer_t *number) {
  if (!threshold_integer_reserve(number, 1))
    return false;
  number->digits[0] = 0;
  number->count = 1;
  return true;
}

static bool threshold_integer_copy(threshold_integer_t *destination,
                                   const threshold_integer_t *source) {
  if (!destination || !source || !source->digits ||
      !threshold_integer_reserve(destination, source->count))
    return false;
  memcpy(destination->digits, source->digits, source->count);
  destination->count = source->count;
  return true;
}

static bool threshold_integer_multiply(threshold_integer_t *number,
                                       unsigned factor) {
  if (!number || !number->digits || number->count > SIZE_MAX - 4 ||
      !threshold_integer_reserve(number, number->count + 4))
    return false;
  unsigned carry = 0;
  for (size_t i = 0; i < number->count; i++) {
    unsigned value = (unsigned)number->digits[i] * factor + carry;
    number->digits[i] = (uint8_t)(value % 10);
    carry = value / 10;
  }
  while (carry != 0) {
    number->digits[number->count++] = (uint8_t)(carry % 10);
    carry /= 10;
  }
  while (number->count > 1 && number->digits[number->count - 1] == 0)
    number->count--;
  return true;
}

static bool threshold_integer_add_digit(threshold_integer_t *number,
                                        unsigned digit) {
  if (!number || !number->digits || number->count == SIZE_MAX ||
      !threshold_integer_reserve(number, number->count + 1))
    return false;
  unsigned carry = digit;
  for (size_t i = 0; i < number->count && carry != 0; i++) {
    unsigned value = (unsigned)number->digits[i] + carry;
    number->digits[i] = (uint8_t)(value % 10);
    carry = value / 10;
  }
  if (carry != 0)
    number->digits[number->count++] = (uint8_t)carry;
  return true;
}

static bool threshold_exact_zero(const threshold_exact_t *number) {
  return number && number->coefficient.count == 1 &&
         number->coefficient.digits[0] == 0;
}

static bool threshold_exact_copy(threshold_exact_t *destination,
                                 const threshold_exact_t *source) {
  if (!destination || !source)
    return false;
  *destination = (threshold_exact_t){.exponent = source->exponent,
                                     .negative = source->negative};
  return threshold_integer_copy(&destination->coefficient,
                                &source->coefficient);
}

static bool threshold_exact_normalize(threshold_exact_t *number) {
  if (!number || !number->coefficient.digits || number->coefficient.count == 0)
    return false;
  threshold_integer_t *coefficient = &number->coefficient;
  while (coefficient->count > 1 &&
         coefficient->digits[coefficient->count - 1] == 0)
    coefficient->count--;
  if (threshold_exact_zero(number)) {
    number->negative = false;
    number->exponent = 0;
    return true;
  }
  size_t zeros = 0;
  while (zeros < coefficient->count - 1 && coefficient->digits[zeros] == 0)
    zeros++;
  if (zeros != 0) {
    if (zeros > INT64_MAX || number->exponent > INT64_MAX - (int64_t)zeros)
      return false;
    memmove(coefficient->digits, coefficient->digits + zeros,
            coefficient->count - zeros);
    coefficient->count -= zeros;
    number->exponent += (int64_t)zeros;
  }
  return true;
}

static bool threshold_parse_exponent(const char **cursor, const char *end,
                                     char marker, int64_t *exponent,
                                     bool *overflow) {
  if (!cursor || !*cursor || !exponent || !overflow)
    return false;
  *exponent = 0;
  *overflow = false;
  if (*cursor == end ||
      (**cursor != marker && **cursor != toupper((unsigned char)marker)))
    return true;
  (*cursor)++;
  bool negative = false;
  if (*cursor < end && (**cursor == '+' || **cursor == '-'))
    negative = *(*cursor)++ == '-';
  if (*cursor == end || !isdigit((unsigned char)**cursor))
    return false;
  uint64_t value = 0;
  while (*cursor < end && isdigit((unsigned char)**cursor)) {
    unsigned digit = (unsigned)(*(*cursor)++ - '0');
    if (value > ((uint64_t)INT64_MAX - digit) / 10)
      *overflow = true;
    if (!*overflow)
      value = value * 10 + digit;
  }
  if (!*overflow)
    *exponent = negative ? -(int64_t)value : (int64_t)value;
  return true;
}

static int threshold_hex_digit(char byte) {
  if (byte >= '0' && byte <= '9')
    return byte - '0';
  if (byte >= 'a' && byte <= 'f')
    return byte - 'a' + 10;
  if (byte >= 'A' && byte <= 'F')
    return byte - 'A' + 10;
  return -1;
}

static bool threshold_exact_parse(const char *begin, const char *end,
                                  threshold_exact_t *out) {
  if (!begin || !end || !out || begin >= end)
    return false;
  *out = (threshold_exact_t){0};
  const char *cursor = begin;
  while (cursor < end && isspace((unsigned char)*cursor))
    cursor++;
  if (cursor < end && (*cursor == '+' || *cursor == '-'))
    out->negative = *cursor++ == '-';
  bool hexadecimal = end - cursor >= 2 && cursor[0] == '0' &&
                     (cursor[1] == 'x' || cursor[1] == 'X');
  if (hexadecimal)
    cursor += 2;

  size_t fractional_digits = 0;
  bool after_point = false;
  bool have_digit = false;
  char *decimal_digits = NULL;
  size_t decimal_count = 0;
  if (hexadecimal) {
    if (!threshold_integer_zero(&out->coefficient))
      return false;
  } else {
    decimal_digits = malloc((size_t)(end - cursor));
    if (!decimal_digits)
      return false;
  }
  while (cursor < end) {
    if (*cursor == '.' && !after_point) {
      after_point = true;
      cursor++;
      continue;
    }
    int digit = hexadecimal
                    ? threshold_hex_digit(*cursor)
                    : (*cursor >= '0' && *cursor <= '9' ? *cursor - '0' : -1);
    if (digit < 0)
      break;
    have_digit = true;
    if (after_point)
      fractional_digits++;
    if (hexadecimal) {
      if (!threshold_integer_multiply(&out->coefficient, 16) ||
          !threshold_integer_add_digit(&out->coefficient, (unsigned)digit))
        goto failure;
    } else {
      decimal_digits[decimal_count++] = (char)digit;
    }
    cursor++;
  }
  if (!have_digit)
    goto failure;
  int64_t parsed_exponent = 0;
  bool exponent_overflow = false;
  if (!threshold_parse_exponent(&cursor, end, hexadecimal ? 'p' : 'e',
                                &parsed_exponent, &exponent_overflow) ||
      cursor != end)
    goto failure;

  if (!hexadecimal) {
    size_t first = 0;
    while (first < decimal_count && decimal_digits[first] == 0)
      first++;
    if (first == decimal_count) {
      if (!threshold_integer_zero(&out->coefficient))
        goto failure;
    } else {
      size_t digits = decimal_count - first;
      if (!threshold_integer_reserve(&out->coefficient, digits))
        goto failure;
      out->coefficient.count = digits;
      for (size_t i = 0; i < digits; i++)
        out->coefficient.digits[i] =
            (uint8_t)decimal_digits[decimal_count - 1 - i];
    }
  }
  free(decimal_digits);
  decimal_digits = NULL;
  if (threshold_exact_zero(out))
    return threshold_exact_normalize(out);
  if (exponent_overflow || fractional_digits > INT64_MAX)
    goto failure;

  if (hexadecimal) {
    if (fractional_digits > INT64_MAX / 4 ||
        parsed_exponent < INT64_MIN + (int64_t)fractional_digits * 4)
      goto failure;
    int64_t binary_exponent = parsed_exponent - (int64_t)fractional_digits * 4;
    if (binary_exponent < 0) {
      if (binary_exponent == INT64_MIN)
        goto failure;
      for (int64_t i = 0; i < -binary_exponent; i++)
        if (!threshold_integer_multiply(&out->coefficient, 5))
          goto failure;
      out->exponent = binary_exponent;
    } else {
      for (int64_t i = 0; i < binary_exponent; i++)
        if (!threshold_integer_multiply(&out->coefficient, 2))
          goto failure;
    }
  } else {
    if (parsed_exponent < INT64_MIN + (int64_t)fractional_digits)
      goto failure;
    out->exponent = parsed_exponent - (int64_t)fractional_digits;
  }
  if (!threshold_exact_normalize(out))
    goto failure;
  return true;

failure:
  free(decimal_digits);
  threshold_exact_free(out);
  return false;
}

static uint8_t threshold_shifted_digit(const threshold_exact_t *number,
                                       size_t shift, size_t position) {
  return position >= shift && position - shift < number->coefficient.count
             ? number->coefficient.digits[position - shift]
             : 0;
}

static bool threshold_exact_shifts(const threshold_exact_t *left,
                                   const threshold_exact_t *right,
                                   size_t *left_shift, size_t *right_shift,
                                   size_t *left_length, size_t *right_length) {
  int64_t common =
      left->exponent < right->exponent ? left->exponent : right->exponent;
  uint64_t left_delta = (uint64_t)left->exponent - (uint64_t)common;
  uint64_t right_delta = (uint64_t)right->exponent - (uint64_t)common;
  if (left_delta > SIZE_MAX - left->coefficient.count ||
      right_delta > SIZE_MAX - right->coefficient.count)
    return false;
  *left_shift = (size_t)left_delta;
  *right_shift = (size_t)right_delta;
  *left_length = left->coefficient.count + *left_shift;
  *right_length = right->coefficient.count + *right_shift;
  return true;
}

static bool threshold_exact_magnitude_compare(const threshold_exact_t *left,
                                              const threshold_exact_t *right,
                                              int *comparison) {
  if (threshold_exact_zero(left)) {
    *comparison = threshold_exact_zero(right) ? 0 : -1;
    return true;
  }
  if (threshold_exact_zero(right)) {
    *comparison = 1;
    return true;
  }
  size_t left_shift, right_shift, left_length, right_length;
  if (!threshold_exact_shifts(left, right, &left_shift, &right_shift,
                              &left_length, &right_length))
    return false;
  if (left_length != right_length) {
    *comparison = left_length > right_length ? 1 : -1;
    return true;
  }
  for (size_t position = left_length; position-- > 0;) {
    uint8_t a = threshold_shifted_digit(left, left_shift, position);
    uint8_t b = threshold_shifted_digit(right, right_shift, position);
    if (a != b) {
      *comparison = a > b ? 1 : -1;
      return true;
    }
  }
  *comparison = 0;
  return true;
}

static bool threshold_exact_compare(const threshold_exact_t *left,
                                    const threshold_exact_t *right,
                                    int *comparison) {
  if (left->negative != right->negative) {
    *comparison = left->negative ? -1 : 1;
    return true;
  }
  int magnitude;
  if (!threshold_exact_magnitude_compare(left, right, &magnitude))
    return false;
  *comparison = left->negative ? -magnitude : magnitude;
  return true;
}

static bool threshold_exact_add(const threshold_exact_t *left,
                                const threshold_exact_t *right,
                                threshold_exact_t *out) {
  if (!left || !right || !out)
    return false;
  *out = (threshold_exact_t){0};
  if (threshold_exact_zero(left))
    return threshold_exact_copy(out, right);
  if (threshold_exact_zero(right))
    return threshold_exact_copy(out, left);
  size_t left_shift, right_shift, left_length, right_length;
  if (!threshold_exact_shifts(left, right, &left_shift, &right_shift,
                              &left_length, &right_length))
    return false;
  size_t length = left_length > right_length ? left_length : right_length;
  if (length == SIZE_MAX ||
      !threshold_integer_reserve(&out->coefficient, length + 1))
    return false;
  out->exponent =
      left->exponent < right->exponent ? left->exponent : right->exponent;
  out->coefficient.count = length;
  if (left->negative == right->negative) {
    unsigned carry = 0;
    out->negative = left->negative;
    for (size_t i = 0; i < length; i++) {
      unsigned value = threshold_shifted_digit(left, left_shift, i) +
                       threshold_shifted_digit(right, right_shift, i) + carry;
      out->coefficient.digits[i] = (uint8_t)(value % 10);
      carry = value / 10;
    }
    if (carry != 0)
      out->coefficient.digits[out->coefficient.count++] = (uint8_t)carry;
  } else {
    int comparison;
    if (!threshold_exact_magnitude_compare(left, right, &comparison))
      return false;
    const threshold_exact_t *larger = comparison >= 0 ? left : right;
    const threshold_exact_t *smaller = comparison >= 0 ? right : left;
    size_t larger_shift = comparison >= 0 ? left_shift : right_shift;
    size_t smaller_shift = comparison >= 0 ? right_shift : left_shift;
    out->negative = larger->negative;
    unsigned borrow = 0;
    for (size_t i = 0; i < length; i++) {
      int value = (int)threshold_shifted_digit(larger, larger_shift, i) -
                  (int)threshold_shifted_digit(smaller, smaller_shift, i) -
                  (int)borrow;
      borrow = value < 0;
      out->coefficient.digits[i] = (uint8_t)(value + (borrow ? 10 : 0));
    }
  }
  return threshold_exact_normalize(out);
}

static bool threshold_exact_multiple(const threshold_exact_t *number,
                                     size_t factor, threshold_exact_t *out) {
  *out = (threshold_exact_t){.exponent = number->exponent,
                             .negative = number->negative};
  return threshold_integer_copy(&out->coefficient, &number->coefficient) &&
         threshold_integer_multiply(&out->coefficient, (unsigned)factor) &&
         threshold_exact_normalize(out);
}

static bool threshold_exact_double(const threshold_exact_t *number,
                                   double *out) {
  if (!number || !out || number->coefficient.count > SIZE_MAX - 48)
    return false;
  size_t capacity = number->coefficient.count + 48;
  char *text = malloc(capacity);
  if (!text)
    return false;
  size_t used = 0;
  if (number->negative)
    text[used++] = '-';
  for (size_t i = number->coefficient.count; i-- > 0;)
    text[used++] = (char)('0' + number->coefficient.digits[i]);
  int length = snprintf(text + used, capacity - used, "e%lld",
                        (long long)number->exponent);
  if (length < 0 || (size_t)length >= capacity - used) {
    free(text);
    return false;
  }
  char *after = NULL;
  double value = strtod(text, &after);
  bool valid = after == text + used + (size_t)length && isfinite(value);
  free(text);
  if (!valid)
    return false;
  *out = value;
  return true;
}

/* Count using exact source values, then round each included point once for
 * scoring. No epsilon can reliably distinguish `0.1,0.3,0.1` from an end
 * deliberately spelled one representable value below the next grid point. */
static bool build_threshold_grid(const char *range_text,
                                 double thresholds[MAX_THRESHOLDS],
                                 size_t *count) {
  if (!range_text || !thresholds || !count ||
      strlen(range_text) > MAX_THRESHOLD_SPEC_LENGTH)
    return false;
  char *first_end = NULL;
  char *second_end = NULL;
  char *third_end = NULL;
  (void)strtod(range_text, &first_end);
  if (!first_end || *first_end != ',')
    return false;
  const char *second = first_end + 1;
  (void)strtod(second, &second_end);
  if (!second_end || *second_end != ',')
    return false;
  const char *third = second_end + 1;
  (void)strtod(third, &third_end);
  if (!third_end || *third_end != '\0')
    return false;

  threshold_exact_t start = {0}, end = {0}, step = {0}, range = {0};
  bool success = false;
  int comparison;
  if (!threshold_exact_parse(range_text, first_end, &start) ||
      !threshold_exact_parse(second, second_end, &end) ||
      !threshold_exact_parse(third, third_end, &step) ||
      threshold_exact_zero(&step) || step.negative ||
      !threshold_exact_compare(&start, &end, &comparison) || comparison > 0)
    goto cleanup;
  threshold_exact_t negative_start = start;
  negative_start.negative = !start.negative && !threshold_exact_zero(&start);
  if (!threshold_exact_add(&end, &negative_start, &range))
    goto cleanup;

  size_t used = 0;
  for (size_t index = 0; index <= MAX_THRESHOLDS; index++) {
    threshold_exact_t offset = {0}, point = {0};
    bool ok = threshold_exact_multiple(&step, index, &offset);
    if (ok)
      ok = threshold_exact_compare(&offset, &range, &comparison);
    if (ok && comparison > 0) {
      threshold_exact_free(&offset);
      break;
    }
    if (ok)
      ok = threshold_exact_add(&start, &offset, &point);
    double value = 0.0;
    if (ok)
      ok = threshold_exact_double(&point, &value);
    threshold_exact_free(&point);
    threshold_exact_free(&offset);
    if (!ok || used == MAX_THRESHOLDS ||
        (used != 0 && value <= thresholds[used - 1]))
      goto cleanup;
    thresholds[used++] = value;
  }
  *count = used;
  success = used != 0;

cleanup:
  threshold_exact_free(&range);
  threshold_exact_free(&step);
  threshold_exact_free(&end);
  threshold_exact_free(&start);
  return success;
}

static bool output_format_valid(const char *format) {
  return format && (strcmp(format, "csv") == 0 || strcmp(format, "json") == 0 ||
                    strcmp(format, "text") == 0);
}

/* `all` is a deterministic round-robin selection. A selected mutation can be
 * inapplicable to a short sequence, in which case try the later kinds in that
 * same cycle before declaring this record ineligible. */
static bool apply_perturbation(perturb_type_t requested, size_t sequence_index,
                               size_t *order, size_t *selected_count,
                               const netseq_span_t *raw,
                               const netseq_span_t *type, size_t count,
                               unsigned int *rng, perturb_type_t *applied) {
  if (!order || !selected_count || !rng || !applied)
    return false;
  size_t tries = requested == PERTURB_ALL ? PERTURB_KIND_COUNT : 1;
  for (size_t attempt = 0; attempt < tries; attempt++) {
    perturb_type_t kind = requested;
    if (requested == PERTURB_ALL)
      kind = (perturb_type_t)((sequence_index + attempt) % PERTURB_KIND_COUNT);
    *selected_count = count;
    bool ok = false;
    switch (kind) {
    case PERTURB_SWAP:
      ok = perturb_swap(order, raw, type, count, rng);
      break;
    case PERTURB_INSERT:
      ok = perturb_insert(order, selected_count, count, rng);
      break;
    case PERTURB_SUBSTITUTE:
      ok = perturb_substitute(order, count, rng);
      break;
    case PERTURB_SHUFFLE:
      ok = perturb_shuffle(order, raw, type, count, rng);
      break;
    case PERTURB_ALL:
      break;
    }
    if (ok) {
      *applied = kind;
      return true;
    }
  }
  return false;
}

typedef struct {
  double score;
  bool synthetic;
} auc_score_t;

static int compare_auc_score(const void *left, const void *right) {
  const auc_score_t *a = left;
  const auc_score_t *b = right;
  if (a->score < b->score)
    return -1;
  if (a->score > b->score)
    return 1;
  return 0;
}

/* Exact empirical AUC: probability that a synthetic score is greater than a
 * normal score, with half credit for ties. It is independent of the displayed
 * threshold grid and remains well-defined for infinite (but not NaN) scores. */
static bool empirical_auc(const double *normal, size_t normal_count,
                          const double *synthetic, size_t synthetic_count,
                          double *out) {
  if (!normal || !synthetic || !out || normal_count == 0 ||
      synthetic_count == 0 || normal_count > SIZE_MAX - synthetic_count)
    return false;
  size_t total = normal_count + synthetic_count;
  auc_score_t *scores = calloc(total, sizeof(*scores));
  if (!scores)
    return false;
  for (size_t i = 0; i < normal_count; i++) {
    if (isnan(normal[i])) {
      free(scores);
      return false;
    }
    scores[i] = (auc_score_t){normal[i], false};
  }
  for (size_t i = 0; i < synthetic_count; i++) {
    if (isnan(synthetic[i])) {
      free(scores);
      return false;
    }
    scores[normal_count + i] = (auc_score_t){synthetic[i], true};
  }
  qsort(scores, total, sizeof(*scores), compare_auc_score);

  double wins = 0.0;
  size_t normal_below = 0;
  for (size_t first = 0; first < total;) {
    size_t last = first;
    size_t group_normal = 0;
    size_t group_synthetic = 0;
    while (last < total && scores[last].score == scores[first].score) {
      if (scores[last].synthetic)
        group_synthetic++;
      else
        group_normal++;
      last++;
    }
    wins += (double)group_synthetic * (double)normal_below +
            0.5 * (double)group_synthetic * (double)group_normal;
    normal_below += group_normal;
    first = last;
  }
  free(scores);
  *out = wins / ((double)normal_count * (double)synthetic_count);
  return true;
}

static void print_usage(const char *prog) {
  printf("Usage: %s -n <corpus> [options]\n", prog);
  printf("Options:\n");
  printf("  -n <file>   Normal commands corpus (one per line, required)\n");
  printf("  -o <file>   Output file (default: stdout)\n");
  printf("  -t <s,e,i>  Threshold range: start,end,step (default: "
         "0.0,15.0,0.5; max %u bytes)\n",
         MAX_THRESHOLD_SPEC_LENGTH);
  printf("  -p <type>   Perturbation: swap|insert|substitute|shuffle|all "
         "(default: all)\n");
  printf("  -N <num>    Synthetics per normal command (default: 3)\n");
  printf("  -f <fmt>    Output: csv|json|text (default: csv)\n");
  printf("  -r <seed>   Perturbation RNG seed (default: current time)\n");
  printf("  -s <file>   Save trained model to file\n");
  printf("  -h          Show help\n");
}

int main(int argc, char **argv) {
  const char *normal_path = NULL;
  const char *output_path = NULL;
  const char *save_model_path = NULL;
  const char *fmt = "csv";
  const char *threshold_text = "0.0,15.0,0.5";
  double thresholds[MAX_THRESHOLDS];
  size_t num_thresholds = 0;
  perturb_type_t ptype = PERTURB_ALL;
  size_t num_synth_per_cmd = 3;
  unsigned int seed = (unsigned int)time(NULL);
  unsigned int rng = seed;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
      normal_path = argv[++i];
    } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      output_path = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      i++;
      if (strlen(argv[i]) > MAX_THRESHOLD_SPEC_LENGTH) {
        fprintf(stderr, "Threshold range exceeds the %u-byte input limit\n",
                MAX_THRESHOLD_SPEC_LENGTH);
        return 1;
      }
      if (!parse_threshold_range(argv[i])) {
        fprintf(stderr, "Invalid threshold range: %s\n", argv[i]);
        return 1;
      }
      threshold_text = argv[i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      const char *value = argv[++i];
      if (strcmp(value, "swap") == 0)
        ptype = PERTURB_SWAP;
      else if (strcmp(value, "insert") == 0)
        ptype = PERTURB_INSERT;
      else if (strcmp(value, "substitute") == 0)
        ptype = PERTURB_SUBSTITUTE;
      else if (strcmp(value, "shuffle") == 0)
        ptype = PERTURB_SHUFFLE;
      else if (strcmp(value, "all") == 0)
        ptype = PERTURB_ALL;
      else {
        fprintf(stderr, "Unknown perturbation: %s\n", value);
        return 1;
      }
    } else if (strcmp(argv[i], "-N") == 0 && i + 1 < argc) {
      if (!parse_size_option(argv[++i], MAX_SYNTHETIC, &num_synth_per_cmd)) {
        fprintf(stderr, "Invalid synthetic count: %s\n", argv[i]);
        return 1;
      }
    } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
      fmt = argv[++i];
    } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
      if (!parse_seed_option(argv[++i], &seed)) {
        fprintf(stderr, "Invalid RNG seed: %s\n", argv[i]);
        return 1;
      }
      rng = seed;
    } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      save_model_path = argv[++i];
    } else if (strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage(argv[0]);
      return 1;
    }
  }

  if (!normal_path) {
    fprintf(stderr, "Error: -n <corpus> is required\n");
    print_usage(argv[0]);
    return 1;
  }
  if (!output_format_valid(fmt)) {
    fprintf(stderr, "Unknown output format: %s\n", fmt);
    return 1;
  }
  if (!build_threshold_grid(threshold_text, thresholds, &num_thresholds)) {
    fprintf(
        stderr,
        "Threshold range exceeds the %u-point limit or cannot be represented\n",
        MAX_THRESHOLDS);
    return 1;
  }

  int exit_status = 1;
  sg_gate_t *gate = NULL;
  FILE *fp = NULL;
  FILE *out = NULL;
  corpus_record_t *normal = NULL;
  double *normal_scores = NULL;
  double *synth_scores = NULL;
  roc_point_t *roc = NULL;
  char *line = NULL;
  char *evaluation_buffer = NULL;
  size_t line_capacity = 0;
  size_t evaluation_capacity = 0;
  size_t normal_count = 0;
  size_t skipped_source_records = 0;
  size_t source_line = 0;
  size_t synthetic_ineligible_records = 0;
  size_t synthetic_target = 0;
  size_t synth_count = 0;
  size_t perturb_counts[PERTURB_KIND_COUNT] = {0};
  double auc = 0.0;
  double best_f1 = -1.0;
  double best_threshold = thresholds[0];

  gate = sg_gate_new();
  if (!gate || sg_gate_enable_anomaly(gate, 5.0, NULL) != SG_OK ||
      sg_gate_set_anomaly_update_mode(gate, false) != SG_OK ||
      sg_gate_set_anomaly_skip_on_detected(gate, false) != SG_OK) {
    fprintf(stderr, "Cannot create anomaly gate\n");
    goto cleanup;
  }

  /* A calibration corpus is declared trusted. Its observations must not be
   * self-filtered by the model currently being calibrated. */
  fp = fopen(normal_path, "r");
  if (!fp) {
    fprintf(stderr, "Cannot open %s: ", normal_path);
    perror(NULL);
    goto cleanup;
  }
  normal = calloc(MAX_CMDS, sizeof(*normal));
  if (!normal) {
    fprintf(stderr, "Cannot allocate corpus storage\n");
    goto cleanup;
  }

  while (true) {
    corpus_line_status_t line_status =
        read_corpus_line(fp, &line, &line_capacity, NULL);
    if (line_status == CORPUS_LINE_EOF)
      break;
    source_line++;
    if (line_status != CORPUS_LINE_OK) {
      const char *reason =
          line_status == CORPUS_LINE_NUL      ? "contains a NUL byte"
          : line_status == CORPUS_LINE_MEMORY ? "cannot allocate line buffer"
                                              : "cannot read input";
      fprintf(stderr, "Corpus line %zu %s\n", source_line, reason);
      goto cleanup;
    }
    char *cmd = trim(line);
    if (!*cmd)
      continue;

    shell_netstring_buffer_t raw = {0};
    shell_netstring_buffer_t type = {0};
    size_t stage_count = 0;
    shell_process_status_t sequence_status = shell_build_anomaly_netseqs_buffer(
        cmd, strlen(cmd), NULL, &raw, &type, &stage_count);
    if (sequence_status == SHELL_PROCESS_EPARSE ||
        (sequence_status == SHELL_PROCESS_OK && stage_count == 0)) {
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      skipped_source_records++;
      continue;
    }
    if (sequence_status != SHELL_PROCESS_OK) {
      fprintf(stderr, "Corpus line %zu cannot build canonical sequences\n",
              source_line);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      goto cleanup;
    }
    if (normal_count == MAX_CMDS) {
      fprintf(stderr, "Corpus exceeds the %zu-record calibration limit\n",
              (size_t)MAX_CMDS);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      goto cleanup;
    }

    sg_result_t result = {0};
    sg_error_t evaluation =
        evaluate_complete(gate, cmd, strlen(cmd), &evaluation_buffer,
                          &evaluation_capacity, &result);
    if (evaluation == SG_ERR_PARSE && result.verdict == SG_VERDICT_REJECT) {
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      skipped_source_records++;
      continue;
    }
    if (evaluation != SG_OK) {
      fprintf(stderr, "Corpus line %zu cannot complete evaluation (error %d)\n",
              source_line, (int)evaluation);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      goto cleanup;
    }
    if (result.verdict == SG_VERDICT_REJECT) {
      /* Gate-level feature rejection is unsupported calibration source, even
       * when the lower-level sequence encoder could tokenize it. */
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      skipped_source_records++;
      continue;
    }
    if (result.anomaly_update != SG_ANOMALY_UPDATE_APPLIED) {
      fprintf(stderr,
              "Corpus line %zu did not enter the anomaly model (outcome %d)\n",
              source_line, (int)result.anomaly_update);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      goto cleanup;
    }
    normal[normal_count++] =
        (corpus_record_t){(char *)raw.data, raw.length,  (char *)type.data,
                          type.length,      stage_count, source_line};
  }
  if (fclose(fp) != 0) {
    fp = NULL;
    fprintf(stderr, "Cannot close %s\n", normal_path);
    goto cleanup;
  }
  fp = NULL;

  if (skipped_source_records != 0)
    fprintf(stderr, "Skipped %zu unsupported corpus records\n",
            skipped_source_records);
  if (normal_count == 0) {
    fprintf(stderr, "No supported commands in corpus\n");
    goto cleanup;
  }
  fprintf(stderr, "Loaded %zu normal commands\n", normal_count);
  fprintf(stderr, "Model trained (vocab=%zu)\n",
          sg_gate_anomaly_vocab_size(gate));

  normal_scores = calloc(normal_count, sizeof(*normal_scores));
  if (!normal_scores) {
    fprintf(stderr, "Cannot allocate normal scores\n");
    goto cleanup;
  }
  for (size_t i = 0; i < normal_count; i++) {
    sg_anomaly_sequence_score_t score = {0};
    if (sg_gate_score_anomaly_netseq(
            gate, normal[i].raw_netseq, normal[i].raw_netseq_length,
            normal[i].type_netseq, normal[i].type_netseq_length,
            &score) != SG_OK ||
        isnan(score.combined_score)) {
      fprintf(stderr, "Cannot score canonical corpus line %zu\n",
              normal[i].source_line);
      goto cleanup;
    }
    normal_scores[i] = score.combined_score;
  }

  size_t eligible_records = 0;
  for (size_t i = 0; i < normal_count; i++) {
    netseq_span_t raw_spans[MAX_TOKENS];
    netseq_span_t type_spans[MAX_TOKENS];
    size_t raw_count = 0;
    size_t type_count = 0;
    if (normal[i].count > MAX_TOKENS ||
        !collect_netseq_views(normal[i].raw_netseq, normal[i].raw_netseq_length,
                              raw_spans, MAX_TOKENS, &raw_count) ||
        !collect_netseq_views(normal[i].type_netseq,
                              normal[i].type_netseq_length, type_spans,
                              MAX_TOKENS, &type_count) ||
        raw_count != normal[i].count || type_count != raw_count) {
      fprintf(stderr, "Canonical corpus line %zu is inconsistent\n",
              normal[i].source_line);
      goto cleanup;
    }
    if (perturbation_available(ptype, raw_spans, type_spans, raw_count))
      eligible_records++;
    else
      synthetic_ineligible_records++;
  }
  if (eligible_records == 0) {
    fprintf(stderr, "No corpus records can produce synthetic anomalies\n");
    goto cleanup;
  }
  if (num_synth_per_cmd > MAX_SYNTHETIC / eligible_records) {
    fprintf(stderr,
            "Requested synthetic anomalies exceed the %zu-record limit\n",
            (size_t)MAX_SYNTHETIC);
    goto cleanup;
  }
  synthetic_target = eligible_records * num_synth_per_cmd;
  synth_scores = calloc(synthetic_target, sizeof(*synth_scores));
  if (!synth_scores) {
    fprintf(stderr, "Cannot allocate synthetic scores\n");
    goto cleanup;
  }

  for (size_t i = 0; i < normal_count; i++) {
    netseq_span_t raw_spans[MAX_TOKENS];
    netseq_span_t type_spans[MAX_TOKENS];
    size_t raw_count = 0;
    size_t type_count = 0;
    if (!collect_netseq_views(normal[i].raw_netseq, normal[i].raw_netseq_length,
                              raw_spans, MAX_TOKENS, &raw_count) ||
        !collect_netseq_views(normal[i].type_netseq,
                              normal[i].type_netseq_length, type_spans,
                              MAX_TOKENS, &type_count) ||
        raw_count != normal[i].count || type_count != raw_count) {
      fprintf(stderr, "Canonical corpus line %zu is inconsistent\n",
              normal[i].source_line);
      goto cleanup;
    }
    if (!perturbation_available(ptype, raw_spans, type_spans, raw_count))
      continue;
    for (size_t n = 0; n < num_synth_per_cmd; n++) {
      size_t order[MAX_TOKENS + 1];
      size_t selected_count = raw_count;
      perturb_type_t applied = PERTURB_ALL;
      if (!apply_perturbation(ptype, synth_count, order, &selected_count,
                              raw_spans, type_spans, raw_count, &rng,
                              &applied)) {
        fprintf(stderr, "Corpus line %zu cannot apply perturbation\n",
                normal[i].source_line);
        goto cleanup;
      }
      const char *rare = NULL;
      for (size_t order_index = 0; order_index < selected_count;
           order_index++) {
        if (order[order_index] == SIZE_MAX) {
          bool selected_rare = false;
          if (applied == PERTURB_SUBSTITUTE) {
            selected_rare = choose_rare_command(raw_spans, type_spans,
                                                order_index, &rng, &rare);
          } else {
            rare = rare_cmds[rand_uint(&rng) % NUM_RARE];
            selected_rare = true;
          }
          if (!selected_rare) {
            fprintf(stderr, "Corpus line %zu has no distinct rare command\n",
                    normal[i].source_line);
            goto cleanup;
          }
          break;
        }
      }
      if (!selection_changes_source(raw_spans, type_spans, raw_count, order,
                                    selected_count, rare)) {
        fprintf(stderr, "Corpus line %zu produced no synthetic change\n",
                normal[i].source_line);
        goto cleanup;
      }
      shell_netstring_buffer_t raw = {0};
      shell_netstring_buffer_t type = {0};
      bool rendered = render_selection(raw_spans, selected_count, order, rare,
                                       false, &raw) &&
                      render_selection(type_spans, selected_count, order, rare,
                                       true, &type);
      if (!rendered) {
        fprintf(stderr,
                "Cannot render synthetic anomaly from corpus line %zu\n",
                normal[i].source_line);
        shell_netstring_buffer_free(&raw);
        shell_netstring_buffer_free(&type);
        goto cleanup;
      }
      sg_anomaly_sequence_score_t score = {0};
      sg_error_t score_status = sg_gate_score_anomaly_netseq(
          gate, (const char *)raw.data, raw.length, (const char *)type.data,
          type.length, &score);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      if (score_status != SG_OK || isnan(score.combined_score)) {
        fprintf(stderr, "Cannot score synthetic anomaly from corpus line %zu\n",
                normal[i].source_line);
        goto cleanup;
      }
      synth_scores[synth_count++] = score.combined_score;
      perturb_counts[applied]++;
    }
  }
  if (synth_count != synthetic_target) {
    fprintf(stderr, "Synthetic anomaly generation was incomplete\n");
    goto cleanup;
  }
  fprintf(stderr,
          "Generated %zu synthetic anomalies (swap=%zu insert=%zu "
          "substitute=%zu shuffle=%zu; seed=%u)\n",
          synth_count, perturb_counts[PERTURB_SWAP],
          perturb_counts[PERTURB_INSERT], perturb_counts[PERTURB_SUBSTITUTE],
          perturb_counts[PERTURB_SHUFFLE], seed);
  if (synthetic_ineligible_records != 0)
    fprintf(stderr, "Skipped %zu records ineligible for perturbation\n",
            synthetic_ineligible_records);

  roc = calloc(num_thresholds, sizeof(*roc));
  if (!roc) {
    fprintf(stderr, "Cannot allocate ROC output\n");
    goto cleanup;
  }
  for (size_t t = 0; t < num_thresholds; t++) {
    double threshold = thresholds[t];
    int tp = 0, fp_count = 0, tn = 0, fn = 0;
    for (size_t i = 0; i < normal_count; i++) {
      if (normal_scores[i] > threshold)
        fp_count++;
      else
        tn++;
    }
    for (size_t i = 0; i < synth_count; i++) {
      if (synth_scores[i] > threshold)
        tp++;
      else
        fn++;
    }
    roc[t].threshold = threshold;
    roc[t].tp = tp;
    roc[t].fp = fp_count;
    roc[t].tn = tn;
    roc[t].fn = fn;
    roc[t].tpr = (tp + fn > 0) ? (double)tp / (double)(tp + fn) : 0.0;
    roc[t].fpr =
        (fp_count + tn > 0) ? (double)fp_count / (double)(fp_count + tn) : 0.0;
    roc[t].precision =
        (tp + fp_count > 0) ? (double)tp / (double)(tp + fp_count) : 0.0;
    roc[t].f1 = (roc[t].precision + roc[t].tpr > 0)
                    ? 2.0 * roc[t].precision * roc[t].tpr /
                          (roc[t].precision + roc[t].tpr)
                    : 0.0;
    if (roc[t].f1 > best_f1) {
      best_f1 = roc[t].f1;
      best_threshold = threshold;
    }
  }
  if (!empirical_auc(normal_scores, normal_count, synth_scores, synth_count,
                     &auc)) {
    fprintf(stderr, "Cannot compute empirical AUC\n");
    goto cleanup;
  }

  out = output_path ? fopen(output_path, "w") : stdout;
  if (!out) {
    fprintf(stderr, "Cannot open output: %s\n", output_path);
    goto cleanup;
  }

  if (strcmp(fmt, "json") == 0) {
    fprintf(out, "{\n");
    fprintf(out, "  \"normal_count\": %zu,\n", normal_count);
    fprintf(out, "  \"anomaly_count\": %zu,\n", synth_count);
    fprintf(out, "  \"auc\": %.4f,\n", auc);
    fprintf(out, "  \"best_threshold\": %.17g,\n", best_threshold);
    fprintf(out, "  \"best_f1\": %.4f,\n", best_f1);
    fprintf(out, "  \"points\": [\n");
    for (size_t t = 0; t < num_thresholds; t++) {
      fprintf(out,
              "    {\"threshold\": %.17g, \"tp\": %d, \"fp\": %d, "
              "\"tn\": %d, \"fn\": %d, \"tpr\": %.4f, \"fpr\": %.4f, "
              "\"precision\": %.4f, \"f1\": %.4f}%s\n",
              roc[t].threshold, roc[t].tp, roc[t].fp, roc[t].tn, roc[t].fn,
              roc[t].tpr, roc[t].fpr, roc[t].precision, roc[t].f1,
              t + 1 < num_thresholds ? "," : "");
    }
    fprintf(out, "  ]\n}\n");
  } else if (strcmp(fmt, "text") == 0) {
    fprintf(out, "Threshold calibration results\n");
    fprintf(out, "Normal: %zu  Anomalies: %zu  AUC: %.4f\n", normal_count,
            synth_count, auc);
    fprintf(out, "Best threshold: %.17g (F1=%.4f)\n\n", best_threshold,
            best_f1);
    fprintf(out, "%-22s %6s %6s %6s %6s %8s %8s %10s %8s\n", "Thresh", "TP",
            "FP", "TN", "FN", "TPR", "FPR", "Prec", "F1");
    fprintf(out, "%-22s %6s %6s %6s %6s %8s %8s %10s %8s\n", "------", "--",
            "--", "--", "--", "---", "---", "----", "--");
    for (size_t t = 0; t < num_thresholds; t++) {
      fprintf(out, "%-22.17g %6d %6d %6d %6d %8.4f %8.4f %10.4f %8.4f\n",
              roc[t].threshold, roc[t].tp, roc[t].fp, roc[t].tn, roc[t].fn,
              roc[t].tpr, roc[t].fpr, roc[t].precision, roc[t].f1);
    }
  } else {
    fprintf(out, "threshold,tp,fp,tn,fn,tpr,fpr,precision,f1\n");
    for (size_t t = 0; t < num_thresholds; t++) {
      fprintf(out, "%.17g,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.4f\n", roc[t].threshold,
              roc[t].tp, roc[t].fp, roc[t].tn, roc[t].fn, roc[t].tpr,
              roc[t].fpr, roc[t].precision, roc[t].f1);
    }
    fprintf(out,
            "# normal=%zu anomaly=%zu auc=%.4f best_threshold=%.17g "
            "best_f1=%.4f\n",
            normal_count, synth_count, auc, best_threshold, best_f1);
  }
  if (fflush(out) == EOF || ferror(out)) {
    fprintf(stderr, "Cannot write calibration output\n");
    goto cleanup;
  }
  if (output_path && fclose(out) != 0) {
    out = NULL;
    fprintf(stderr, "Cannot close output: %s\n", output_path);
    goto cleanup;
  }
  out = NULL;

  /* A report is the primary calibration result. Publish it successfully
   * before attempting the optional model write; a model-save failure may
   * leave the completed report available for diagnosis. */
  if (save_model_path) {
    sg_error_t save_status = sg_gate_save_anomaly_model(gate, save_model_path);
    if (save_status != SG_OK) {
      fprintf(stderr, "Cannot save model to %s (error %d)\n", save_model_path,
              (int)save_status);
      goto cleanup;
    }
    fprintf(stderr, "Model saved to %s\n", save_model_path);
  }
  exit_status = 0;

cleanup:
  if (fp)
    fclose(fp);
  if (out && output_path)
    fclose(out);
  free(line);
  free(evaluation_buffer);
  free(roc);
  free(synth_scores);
  free(normal_scores);
  free_corpus(normal, normal_count);
  sg_gate_free(gate);
  return exit_status;
}
