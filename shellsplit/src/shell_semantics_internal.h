#ifndef SHELL_SEMANTICS_INTERNAL_H
#define SHELL_SEMANTICS_INTERNAL_H

#include "shell_tokenizer_full.h"

struct shell_test_program;

/* shell_semantics.c owns supported-operation inspection and its observers.
 * Lexical iteration and list/draft grammar remain in shell_tokenizer_full.c;
 * byte admission and retained collection have their separate source owners. */
/* Syntax that remains lexically visible but is outside Shellclave's
 * supported Bash execution model. This includes active parameter writes, prompt
 * re-evaluation, actual indirect dereferencing, test/[ variable-name
 * re-evaluation and shell-option mutations. Complete raw expansions whose
 * meaning requires decoded child source or syntax reconstructed across
 * fragments are unsupported too; malformed and incomplete framing retain
 * their separate syntax classifications. Ordinary parameter data and
 * prefix-name enumeration remain supported.
 * Source-only consumers conservatively reject read option ambiguities which
 * graph construction can resolve from captured descriptor-variable values.
 * Scratch exhaustion can also end inspection without an unsupported finding.
 * Classification callers bind sufficient source scratch and check
 * shell_source_scratch_exhausted() before ending their source operation.
 * A false result alone does not qualify syntax or completeness. NULL with
 * zero length denotes absent source and returns true. */
bool shell_tokenizer_has_unsupported_semantics(const char *input,
                                               size_t input_length);

/* The same semantic boundary with token, read-FD, process, variable-name and
 * test-program observers. The token observer receives each lexical token,
 * including executable expansion bodies, during the existing traversal.
 * It must not mutate or retain
 * scanner-local storage; token source spans borrow the immutable input. No
 * additional source pass is performed. context is required caller-owned
 * observer storage. */
typedef void (*shell_semantic_token_observer_t)(const shell_token_t *token,
                                                void *context);
/* The same traversal reports possible -u operands (kind 1 static, 2 dynamic;
 * 0 means none, 3 observes default stdin access), and parameter fragments
 * affecting option-operand roles.
 * parameter is an exact borrowed identifier span, or NULL with length zero
 * when no exact scalar name is present. identity distinguishes descriptor
 * identity from an empty/nonempty value observation. word points at the read
 * command (kind 3) or operand in the immutable input, allowing lifetime
 * indexing without a second source traversal. Graph inspection defers
 * narrowly marked read ambiguities to its captured-value validation boundary;
 * every other unsupported feature is still rejected here. */
typedef void (*shell_semantic_read_fd_observer_t)(const char *word, uint32_t fd,
                                                  unsigned kind,
                                                  const char *parameter,
                                                  size_t parameter_length,
                                                  bool identity, void *context);
/* One complete process-expansion span per occurrence, including expansions
 * hidden inside parameter words. Called before its body is inspected, during
 * the same traversal; quoting/comments and literal heredocs are respected.
 * Empty bodies are reported too, so consumers can classify them consistently.
 * word borrows the immutable source and context is caller-owned storage. */
typedef void (*shell_semantic_process_observer_t)(const char *word,
                                                  size_t length, void *context);
/* Decoded static scalar presence names. Builtin targets are selected by the
 * compiled expression's arity/grammar; [[ -v ]] contributes its static name.
 * The variable observer may be NULL when this inventory is not requested;
 * it is independent of the test-program observer. */
typedef void (*shell_semantic_variable_observer_t)(const char *word,
                                                   size_t length,
                                                   void *context);
/* One completed test/[ program, keyed by the effective builtin's source start.
 * Values/nodes borrow source-operation scratch until operation end. program
 * is scanner-local and must be copied before return. Programs are complete and
 * non-NULL. Compilation is requested by either this or the variable observer.
 */
typedef void (*shell_semantic_test_observer_t)(
    const char *command, const struct shell_test_program *program,
    void *context);
typedef enum {
  SHELL_SEMANTIC_OK,
  SHELL_SEMANTIC_UNSUPPORTED,
  SHELL_SEMANTIC_TRUNCATED,
  SHELL_SEMANTIC_EWORKSPACE,
} shell_semantic_result_t;
/* Callback products borrow source or source-operation scratch. Non-OK results
 * may follow partial callbacks; consumers must discard incomplete inventories.
 * Admission continues after inventory capacity overflow. Confirmed unsupported
 * semantics take precedence over workspace exhaustion, then truncation.
 * Exhaustion can stop scanning before a later unsupported operation is seen. */
shell_semantic_result_t
shell_tokenizer_inspect_semantics(const char *input, size_t input_length,
                                  shell_semantic_token_observer_t observer,
                                  shell_semantic_read_fd_observer_t read_fd,
                                  shell_semantic_process_observer_t process,
                                  shell_semantic_variable_observer_t variable,
                                  shell_semantic_test_observer_t test,
                                  void *context) SHELL_NONNULL(1, 3, 4, 5, 8);

/* Inspect an already-delimited arithmetic body for array semantics. This
 * conservative query also returns true for unsupported operations in nested
 * executable bodies. NULL with zero length denotes no body and returns false.
 * Arithmetic grammar and value proofs remain in shell_arithmetic.c. */
bool shell_tokenizer_arithmetic_has_array_semantics(const char *input,
                                                    size_t input_length);

#endif
