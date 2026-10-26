#define _POSIX_C_SOURCE 200809L
/* Word decoding, allocation and diagnostic rendering. Public declarations stay
 * in shell_processor.h; private semantic-value declarations are in
 * shell_word_internal.h, and direct emitters share the inline decoder core. */
#include "alloc.h"
#include "shell_source_internal.h"
#include "shell_word_decode_internal.h"
#include "shell_word_internal.h"
#include <stdlib.h>

typedef struct {
  bool valid;
  size_t length;
} scalar_name_t;
static SHELL_NONNULL(2) bool scalar_byte(unsigned char byte, void *context) {
  scalar_name_t *name = context;
  name->valid &= name->length++ ? shell_ascii_alnum(byte) || byte == '_'
                                : shell_ascii_alpha(byte) || byte == '_';
  return true;
}

bool shell_word_static_scalar(const char *word, size_t length) {
  scalar_name_t name = {.valid = true};
  return !shell_source_word_has_dynamic_syntax_in_context(
             word, length, SHELL_SOURCE_WORD_CONDITIONAL) &&
         shell_source_visit_decoded_word(word, length, scalar_byte, &name) &&
         name.valid && name.length != 0;
}

static SHELL_NONNULL(1, 5) shell_process_status_t
    visit_word_mode(const char *text, size_t length,
                    shell_decoded_word_visitor_t visitor, void *context,
                    size_t *decoded_length, shell_source_ansi_mode_t mode) {
  *decoded_length = 0;

  decoded_word_sink_t sink = {
      .visitor = visitor,
      .visitor_context = context,
  };
  shell_process_status_t status = decode_shell_word(text, length, &sink, mode);
  *decoded_length = sink.output_length;
  return status;
}

shell_process_status_t
shell_visit_decoded_word(const char *text, size_t length,
                         shell_decoded_word_visitor_t visitor, void *context,
                         size_t *decoded_length) {
  return visit_word_mode(text, length, visitor, context, decoded_length,
                         SHELL_SOURCE_ANSI_BYTES);
}

shell_process_status_t
shell_process_visit_word_value(const char *text, size_t length,
                               shell_decoded_word_visitor_t visitor,
                               void *context, size_t *decoded_length) {
  return visit_word_mode(text, length, visitor, context, decoded_length,
                         SHELL_SOURCE_ANSI_WORD);
}

bool shell_visit_static_word(const char *text, size_t length,
                             shell_decoded_word_visitor_t visitor,
                             void *context, size_t *decoded_length) {
  *decoded_length = 0;
  if (shell_source_word_has_dynamic_syntax(text, length))
    return false;
  return shell_process_visit_word_value(text, length, visitor, context,
                                        decoded_length) == SHELL_PROCESS_OK;
}

shell_process_status_t shell_measure_decoded_word(const char *text,
                                                  size_t length,
                                                  size_t *decoded_length) {
  return shell_visit_decoded_word(text, length, NULL, NULL, decoded_length);
}

shell_process_status_t
shell_process_measure_word_value(const char *text, size_t length,
                                 size_t *decoded_length) {
  return shell_process_visit_word_value(text, length, NULL, NULL,
                                        decoded_length);
}

shell_process_status_t shell_write_decoded_word(const char *text, size_t length,
                                                char *destination,
                                                size_t destination_size,
                                                size_t *written) {
  *written = 0;

  size_t decoded_length = 0;
  shell_process_status_t status =
      shell_measure_decoded_word(text, length, &decoded_length);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (destination_size < decoded_length)
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  decoded_word_sink_t sink = {
      .destination = destination,
      .destination_size = destination_size,
  };
  status = decode_shell_word(text, length, &sink, SHELL_SOURCE_ANSI_BYTES);
  if (status != SHELL_PROCESS_OK)
    return status;
  *written = sink.output_length;
  return SHELL_PROCESS_OK;
}

shell_process_status_t shell_process_write_word_value(const char *text,
                                                      size_t length,
                                                      char *destination,
                                                      size_t destination_size,
                                                      size_t *written) {
  *written = 0;
  decoded_word_sink_t sink = {
      .destination = destination,
      .destination_size = destination_size,
  };
  shell_process_status_t status =
      decode_shell_word(text, length, &sink, SHELL_SOURCE_ANSI_WORD);
  if (status == SHELL_PROCESS_OK)
    *written = sink.output_length;
  return status;
}

static shell_process_status_t
render_processed_word(const char *text, size_t length, char *destination,
                      size_t destination_size, size_t *written) {
  *written = 0;
  if ((destination == NULL) && (destination_size != 0))
    return SHELL_PROCESS_EINPUT;

  size_t out = 0;
  char quote = '\0';
  for (size_t i = 0; i < length;) {
    char c = text[i];
    size_t empty_after;
    if (!quote && (c == '<' || c == '>') &&
        shell_source_empty_process_fragment(text, length, i, &empty_after)) {
      i = empty_after;
      continue;
    }
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(text, length, i, '\'', NULL)) {
      decoded_word_sink_t sink = {
          .destination = destination,
          .destination_size = destination_size,
          .output_length = out,
      };
      shell_process_status_t status =
          ansi_decode_quote(text, length, &i, &sink, SHELL_SOURCE_ANSI_WORD);
      if (status != SHELL_PROCESS_OK)
        return status;
      out = sink.output_length;
      continue;
    }
    size_t dynamic_after = i;
    bool dynamic = false;
    if (quote != '\'' && c == '$' &&
        shell_source_dollar_parentheses_open(text, length, i, NULL)) {
      if (shell_source_dollar_arithmetic_open(text, length, i, NULL)) {
        dynamic = shell_source_skip_arithmetic_expansion(text, length, i,
                                                         &dynamic_after);
      } else {
        size_t open = 0;
        dynamic =
            shell_source_dollar_parentheses_open(text, length, i, &open) &&
            shell_source_find_balanced_parentheses(text, length, open,
                                                   &dynamic_after);
      }
    } else if (quote == '\0' && (c == '<' || c == '>')) {
      size_t open = 0;
      dynamic =
          shell_source_process_substitution_open(text, length, i, &open) &&
          shell_source_find_balanced_parentheses(text, length, open,
                                                 &dynamic_after);
    } else if (quote != '\'' && c == '`') {
      dynamic_after = shell_source_skip_quoted_text(text, length, i, '`');
      dynamic = dynamic_after > i + 1 && dynamic_after <= length &&
                text[dynamic_after - 1] == '`';
    }
    if (dynamic) {
      size_t dynamic_length = dynamic_after - i;
      if (out > SIZE_MAX - dynamic_length)
        return SHELL_PROCESS_EOVERFLOW;
      if (destination) {
        if (out > destination_size || dynamic_length > destination_size - out)
          return SHELL_PROCESS_EOUTPUT_LIMIT;
        memcpy(destination + out, text + i, dynamic_length);
      }
      out += dynamic_length;
      i = dynamic_after;
      continue;
    }
    unsigned char byte;
    bool protected_byte;
    if (!shell_word_literal_step(text, length, &i, &quote, &byte,
                                 &protected_byte))
      continue;
    if (out == SIZE_MAX)
      return SHELL_PROCESS_EOVERFLOW;
    if (destination) {
      if (out == destination_size)
        return SHELL_PROCESS_EOUTPUT_LIMIT;
      destination[out] = (char)byte;
    }
    out++;
  }
  *written = out;
  return SHELL_PROCESS_OK;
}

shell_process_status_t shell_measure_processed_word(const char *text,
                                                    size_t length,
                                                    size_t *processed_length) {
  return render_processed_word(text, length, NULL, 0, processed_length);
}

shell_process_status_t
shell_write_processed_word(const char *text, size_t length, char *destination,
                           size_t destination_size, size_t *written) {
  *written = 0;

  return render_processed_word(text, length, destination, destination_size,
                               written);
}

shell_process_status_t shell_decode_word(const char *text, size_t length,
                                         char **decoded,
                                         size_t *decoded_length) {
  *decoded = NULL;
  *decoded_length = 0;

  shell_process_status_t status =
      shell_measure_decoded_word(text, length, decoded_length);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (*decoded_length == SIZE_MAX) {
    *decoded_length = 0;
    return SHELL_PROCESS_EOVERFLOW;
  }
  *decoded = malloc(*decoded_length + 1);
  if (!*decoded) {
    *decoded_length = 0;
    return SHELL_PROCESS_ENOMEM;
  }
  /* The private destination is sized from the preceding measure. Decode
   * directly rather than invoking the public preflight-and-write API again. */
  decoded_word_sink_t sink = {
      .destination = *decoded,
      .destination_size = *decoded_length,
  };
  status = decode_shell_word(text, length, &sink, SHELL_SOURCE_ANSI_BYTES);
  if (status != SHELL_PROCESS_OK) {
    free(*decoded);
    *decoded = NULL;
    *decoded_length = 0;
    return status;
  }
  (*decoded)[sink.output_length] = '\0';
  return SHELL_PROCESS_OK;
}
