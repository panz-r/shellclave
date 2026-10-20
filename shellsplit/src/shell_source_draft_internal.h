#ifndef SHELL_SOURCE_DRAFT_INTERNAL_H
#define SHELL_SOURCE_DRAFT_INTERNAL_H

#include "shell_source.h"

typedef struct {
  uint32_t prefix_length, incomplete_at;
  shell_source_need_t need;
} shell_source_draft_state_t;

/* Diagnostic projection of the existing list grammar. Framing collection has
 * already identified this body's unfinished words/documents in result, with
 * offsets relative to source[0..length), not the root or an enclosing word.
 * Each body supplies its own state; an empty replacement would discard the
 * lexical facts needed to recognize unfinished redirect operands. This pass
 * advances only complete top-level list boundaries and diagnoses structural
 * grammar. received_eof permits appending within this source; false means its
 * closing delimiter has already arrived, so its final word is committed. The
 * caller performs strict validation once on the resulting prefix. Only received
 * EOF can extend a compound-tail descriptor prefix into a redirect; local
 * source in an already-closed child must reject that unfinished prefix. */
shell_source_status_t
shell_source_draft_grammar(const char *source, size_t length, bool received_eof,
                           shell_source_draft_state_t *result)
    SHELL_NONNULL(1, 4);

#endif
