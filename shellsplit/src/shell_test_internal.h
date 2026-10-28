#ifndef SHELL_TEST_INTERNAL_H
#define SHELL_TEST_INTERNAL_H

#include "shell_conditional_internal.h"
#include "shell_depgraph.h"
#include "shell_test_grammar_internal.h"
#include <stdint.h>

/* Private test evaluation. Words borrow immutable source and operation-owned
 * decoded or callback values. Prepare each complete logical argument once.
 * Values, reserved nodes and operand-role masks live in source-operation
 * scratch; snapshots borrow the canonical program through that operation.
 * Concrete parsing advances one cursor through counted shortcuts and general
 * fallback. Definite grammar failures stop enclosing parsing; they do not
 * rewind to a candidate group closer or replay an already consumed suffix.
 * FALSE/TRUE are Boolean possibilities; ERROR is a builtin argument failure,
 * which remains distinct while composing eagerly evaluated expressions. */
enum {
  SHELL_TEST_FALSE = 1u,
  SHELL_TEST_TRUE = 2u,
  SHELL_TEST_ERROR_RESULT = 4u
};
typedef struct {
  const char *source, *value;
  size_t length, value_length;
  bool known;
  bool number;
  uint32_t token; /* Graph adapter argv ordinal; unused by the evaluator. */
} shell_test_value_t;

/* Install one decoded or validated callback value and prepare numeric facts
 * once, before route-state evaluation can visit the program repeatedly. */
static inline SHELL_NONNULL(1, 2) void shell_test_set_value(
    shell_test_value_t *value, const char *data, size_t length) {
  shell_test_number_t number = {0};
  for (size_t i = 0; i < length; ++i)
    shell_test_number_byte(&number, (unsigned char)data[i]);
  value->value = data;
  value->value_length = length;
  value->known = true;
  value->number = number.digits && !number.invalid;
}
typedef struct {
  uint16_t left, right;
  uint8_t operation;
} shell_test_node_t;
typedef struct shell_test_program {
  shell_test_value_t *words;
  shell_test_node_t *nodes;
  shell_test_roles_t *operand_roles;
  uint8_t *file_comparisons; /* Possible kinds at each binary operator word. */
  uint16_t count, root, word_count;
  bool active, proven_error, uncertain, bracket;
} shell_test_program_t;
typedef unsigned (*shell_test_lookup_t)(const char *name, size_t length,
                                        void *context);
typedef bool (*shell_test_assume_t)(const char *name, size_t length,
                                    unsigned presence, void *context);
typedef void (*shell_test_presence_observer_t)(const char *name, size_t length,
                                               void *context);
typedef void (*shell_test_file_observer_t)(const shell_test_value_t *word,
                                           unsigned tests, void *context);
typedef void (*shell_test_comparison_observer_t)(
    const shell_test_value_t *left, const shell_test_value_t *right,
    unsigned predicates, void *context);
#ifdef __cplusplus
extern "C" {
#endif
/* Prepare a static word value in operation scratch; dynamic words remain
 * unresolved. Returns false only on scratch exhaustion. */
bool shell_test_prepare_value(const char *source, size_t length,
                              shell_test_value_t *value) SHELL_NONNULL(1, 3);
/* words has count prepared entries, count <= SHELL_DEP_MAX_TOKENS. A NULL
 * words pointer is meaningful only when count is zero. bracket removes its
 * final, statically established ] before applying Bash argument-count rules. */
bool shell_test_compile(shell_test_value_t *words, size_t count, bool bracket,
                        shell_test_program_t *program) SHELL_NONNULL(4);
/* Refresh a program produced by shell_test_compile in its reserved storage
 * after prepared values change. Call before body snapshots read it; words
 * retain their source-token map. Returns false only on scratch exhaustion. */
bool shell_test_refresh(shell_test_program_t *program) SHELL_NONNULL(1);
/* Admission has proved that every grammar path ends in an argument error. */
void shell_test_prove_error(shell_test_program_t *program) SHELL_NONNULL(1);
/* condition is a complete supported parse of this unchanged source. The
 * program borrows decoded values from operation scratch; output storage is
 * distinct. Tree node ordinals remain stable in the compiled program. */
bool shell_test_compile_conditional(const char *source,
                                    const shell_conditional_t *condition,
                                    shell_test_program_t *program)
    SHELL_NONNULL(1, 2, 3);
/* index identifies a primary in a compiled conditional program. Presence
 * leaves retain their state lookup; other primaries install captured truth. */
void shell_test_set_condition_result(shell_test_program_t *program,
                                     unsigned index, bool known, bool truth)
    SHELL_NONNULL(1);
unsigned shell_test_evaluate(const shell_test_program_t *program,
                             shell_test_lookup_t lookup, void *context)
    SHELL_NONNULL(1, 2, 3);
/* Report static scalar lookup targets reachable in the compiled expression.
 * Names borrow decoded program values; orphaned nodes from a failed parse and
 * ordinary string operands are excluded. No source traversal or allocation. */
void shell_test_observe_presence(const shell_test_program_t *program,
                                 shell_test_presence_observer_t observer,
                                 void *context) SHELL_NONNULL(1, 2, 3);
/* Report possible filesystem predicates on grammar-selected operand words.
 * Unresolved operator roles can contribute several kinds to an operand;
 * structural/operator words and the bracket terminator are not operands. */
void shell_test_observe_files(const shell_test_program_t *program,
                              shell_test_file_observer_t observer,
                              void *context) SHELL_NONNULL(1, 2, 3);
void shell_test_observe_comparisons(const shell_test_program_t *program,
                                    shell_test_comparison_observer_t observer,
                                    void *context) SHELL_NONNULL(1, 2, 3);
/* Refine only facts implied by the desired Boolean result. Error alternatives
 * prevent false-result refinement. Callbacks own path-local fact storage. */
bool shell_test_require(const shell_test_program_t *program, unsigned desired,
                        shell_test_lookup_t lookup, shell_test_assume_t assume,
                        void *context) SHELL_NONNULL(1, 3, 4, 5);

#ifdef __cplusplus
}
#endif

#endif
