#ifndef SHELL_SOURCE_DRAFT_INTERNAL_H
#define SHELL_SOURCE_DRAFT_INTERNAL_H

#include "shell_source.h"

typedef struct {
  uint32_t prefix_length, incomplete_at;
  shell_source_need_t need;
  shell_source_status_t failure;
  /* A complete delimiter is awaiting implicit document termination at this
   * body's EOF. This is distinct from an absent or unfinished delimiter. */
  bool heredoc_eof;
} shell_source_draft_state_t;

typedef enum {
  SHELL_SOURCE_END_RECEIVED,
  SHELL_SOURCE_END_OPEN_CHILD,
  SHELL_SOURCE_END_PARENTHESIZED,
  SHELL_SOURCE_END_BACKTICK,
} shell_source_draft_end_t;

/* Diagnostic projection of the existing list grammar. Framing collection has
 * already identified this body's unfinished words/documents in result, with
 * offsets relative to source[0..length), not the root or an enclosing word.
 * Each body supplies its own state; an empty replacement would discard the
 * lexical facts needed to recognize unfinished redirect operands. This pass
 * advances only complete top-level list boundaries and diagnoses structural
 * grammar. RECEIVED and OPEN_CHILD permit appending within this source; the
 * other contexts commit its final word. heredoc_eof comes from that body's
 * existing framing walk; a closed child may end a document implicitly, but
 * this framing is unclassified. It cannot repair other missing grammar.
 * OPEN_CHILD cannot end a received negation yet: a stage or terminator may
 * arrive before its closer. BACKTICK permits Bash's top-level empty negation
 * at EOF, whereas PARENTHESIZED requires a real terminator before its closer.
 * The caller performs strict validation once on the resulting prefix. Only
 * received EOF can extend a compound-tail descriptor prefix into a redirect;
 * local source in an already-closed child must reject that unfinished prefix.
 */
shell_source_status_t shell_source_draft_grammar(
    const char *source, size_t length, shell_source_draft_end_t end_context,
    shell_source_draft_state_t *result) SHELL_NONNULL(1, 4);

#endif
