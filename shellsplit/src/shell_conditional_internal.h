#ifndef SHELL_CONDITIONAL_INTERNAL_H
#define SHELL_CONDITIONAL_INTERNAL_H

#include "shell_arithmetic_internal.h"
#include "shell_contract.h"
#include "shell_file_predicate_internal.h"
#include "shell_numeric_predicate_internal.h"
#include "shell_tokenizer.h"
#include <stdbool.h>
#include <stddef.h>

typedef enum {
  SHELL_CONDITIONAL_NONE,
  SHELL_CONDITIONAL_COMPLETE,
  SHELL_CONDITIONAL_INCOMPLETE,
  SHELL_CONDITIONAL_INVALID,
  SHELL_CONDITIONAL_UNSUPPORTED,
  SHELL_CONDITIONAL_LIMIT,
} shell_conditional_frame_t;

/* Private recognition boundary for a possible command-position [[. Source is
 * immutable and readable through length; start <= length. Offsets borrow that
 * source. Wider predicates are unsupported without a Bash-validity claim.
 * after advances over every recognized construct, including received EOF.
 * Grammar-token prefixes at EOF remain INCOMPLETE only when appending can
 * complete them in their enclosing grammar. A received `]` after a completed
 * primary cannot precede a missing group `)`. The source layer owns whether
 * this received boundary is still appendable or already closed. Operands
 * exclude those partial grammar tokens. */
typedef struct {
  shell_conditional_frame_t frame;
  size_t content, end, after;
  size_t operands[2], operand_lengths[2];
  uint8_t operand_count;
  shell_conditional_predicate_t predicate;
  bool negated;
} shell_conditional_primary_t;

#define SHELL_CONDITIONAL_MAX_NODES 96
typedef enum {
  SHELL_CONDITION_PRIMARY,
  SHELL_CONDITION_NOT,
  SHELL_CONDITION_AND,
  SHELL_CONDITION_OR,
} shell_condition_operation_t;
typedef struct {
  shell_condition_operation_t operation;
  uint16_t left, right;
  shell_conditional_primary_t primary;
} shell_condition_node_t;
typedef struct {
  shell_conditional_frame_t frame;
  size_t content, end, after;
  size_t operands[2], operand_lengths[2];
  uint8_t operand_count;
  shell_conditional_predicate_t predicate;
  bool negated;
  uint16_t count, root;
  uint32_t features;
  /* A received unfinished primary is separate from the public single-primary
   * summary, so compound drafts can expose NONE without losing child spans. */
  shell_conditional_primary_t pending;
  shell_condition_node_t nodes[SHELL_CONDITIONAL_MAX_NODES];
} shell_conditional_t;

static inline bool
shell_conditional_pattern(shell_conditional_predicate_t predicate) {
  return predicate == SHELL_CONDITIONAL_PATTERN_MATCH ||
         predicate == SHELL_CONDITIONAL_PATTERN_NOT_MATCH;
}

/* Zero denotes an invalid/no predicate. Arity is a semantic property, not an
 * ordering relationship between public enum values. */
static inline unsigned
shell_conditional_arity(shell_conditional_predicate_t predicate) {
  switch (predicate) {
  case SHELL_CONDITIONAL_STRING_NONEMPTY:
  case SHELL_CONDITIONAL_STRING_EMPTY:
  case SHELL_CONDITIONAL_VARIABLE_SET:
  case SHELL_CONDITIONAL_TERMINAL:
#define FILE_ARITY(kind, name, ordinal, spelling, alias)                       \
  case SHELL_CONDITIONAL_FILE_##kind:
    SHELL_FILE_PREDICATES(FILE_ARITY)
#undef FILE_ARITY
    return 1;
  case SHELL_CONDITIONAL_STRING_EQUAL:
  case SHELL_CONDITIONAL_STRING_NOT_EQUAL:
  case SHELL_CONDITIONAL_PATTERN_MATCH:
  case SHELL_CONDITIONAL_PATTERN_NOT_MATCH:
  case SHELL_CONDITIONAL_FILE_NEWER:
  case SHELL_CONDITIONAL_FILE_OLDER:
  case SHELL_CONDITIONAL_FILE_SAME:
#define NUMERIC_ARITY(kind, spelling) case SHELL_CONDITIONAL_NUMERIC_##kind:
    SHELL_NUMERIC_COMPARISONS(NUMERIC_ARITY)
#undef NUMERIC_ARITY
    return 2;
  default:
    return 0;
  }
}

/* The definition list and compile-time ordinal checks own this range. Keep
 * these existing comparisons inline in unoptimized builds as well. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline bool
shell_conditional_file(shell_conditional_predicate_t predicate) {
  return predicate >= SHELL_CONDITIONAL_FILE_EXISTS &&
         predicate < SHELL_CONDITIONAL_FILE_EXISTS + SHELL_FILE_PREDICATE_COUNT;
}

static inline bool
shell_conditional_numeric(shell_conditional_predicate_t predicate) {
  return predicate >= SHELL_CONDITIONAL_NUMERIC_EQUAL &&
         predicate <= SHELL_CONDITIONAL_NUMERIC_GREATER_EQUAL;
}

/* Obtain one static decoded arithmetic operand or use an already captured
 * value. Active tilde prefixes require a whole-operand capture; literal
 * complement remains arithmetic. Other opaque expansions also lack a numeric
 * proof without a capture. Observer
 * names borrow decoded operation storage when an observer is provided; that
 * storage is retained for the output graph's workspace lifetime. */
shell_arithmetic_scalar_result_t shell_conditional_arithmetic_operand(
    const char *word, size_t length, const char *value, size_t value_length,
    bool resolved, shell_arithmetic_reference_fn visitor, void *context)
    SHELL_NONNULL(1);

/* source is immutable and condition is its complete conditional parse.
 * Admission visits every numeric operand, including skipped primaries; graph
 * execution qualification is separate. Scratch exhaustion remains observable
 * through the source operation. No framing or source correspondence recheck. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline SHELL_NONNULL(1, 2) bool shell_conditional_operands_unsupported(
    const char *source, const shell_conditional_t *condition) {
  for (unsigned i = 0; i < condition->count; ++i) {
    const shell_condition_node_t *node = &condition->nodes[i];
    if (node->operation != SHELL_CONDITION_PRIMARY ||
        !shell_conditional_numeric(node->primary.predicate))
      continue;
    for (unsigned operand = 0; operand < 2; ++operand) {
      shell_arithmetic_scalar_result_t facts =
          shell_conditional_arithmetic_operand(
              source + node->primary.operands[operand],
              node->primary.operand_lengths[operand], NULL, 0, false, NULL,
              NULL);
      if (!facts.result.supported)
        return true;
    }
  }
  return false;
}

static inline uint32_t
shell_conditional_features(shell_conditional_predicate_t predicate) {
  return SHELL_FEAT_CONDITIONALS |
         (shell_conditional_pattern(predicate) ? SHELL_FEAT_GLOBS : 0);
}

shell_conditional_t shell_conditional_parse(const char *source, size_t length,
                                            size_t start) SHELL_NONNULL(1);

/* Complete conditional operand, without splitting/globbing/brace expansion.
 * Static values use the shared effective fragment decoder. Dynamic values
 * include leading and assignment-shaped tilde expansion and remain unknown;
 * quoted expansions remain dynamic. The source scanner's unquoted-only view
 * is used solely for RHS admission. Neither operation executes expansion.
 * static_empty returns whether emptiness is known; its output is meaningful
 * only on success. A false return establishes neither empty nor nonempty. */
bool shell_conditional_static_empty(const char *word, size_t length,
                                    bool *empty) SHELL_NONNULL(1, 3);
bool shell_conditional_word_dynamic(const char *word, size_t length)
    SHELL_NONNULL(1);

/* Record conservative direct scalar reads in an admitted conditional word.
 * Selector traversal includes positional/special heads so their operator words
 * are visited too; only scalar value reads become ENV names. These are may-read
 * facts, not proof that each parameter operand executes on every path.
 * Executable children own their own dependencies. Names borrow source or
 * retained operation storage. The shared expansion scanner owns quote and
 * re-expansion context. False reports bounded traversal or retained-name
 * storage exhaustion. */
bool shell_conditional_visit_parameters(const char *word, size_t length,
                                        shell_arithmetic_reference_fn visitor,
                                        void *context) SHELL_NONNULL(1, 3);

/* Resolved values borrow validated NUL-free payloads. data may be NULL only
 * when length is zero; unknown values are obtained from static source or
 * remain unknown. condition is a complete supported parse of source. */
typedef struct {
  const char *data;
  size_t length;
  bool known;
} shell_conditional_value_t;

/* Return whether truth is known. Scratch exhaustion remains observable through
 * the enclosing source operation. Uses operation scratch for one static value,
 * releasing it before return. Static star patterns use projected units and a
 * KMP prefix table with linear matching work. Never executes expansion or
 * allocates a heap. */
bool shell_conditional_evaluate(const char *source,
                                const shell_conditional_primary_t *condition,
                                const shell_conditional_value_t values[2],
                                bool *truth) SHELL_NONNULL(1, 2, 3, 4);

#endif
