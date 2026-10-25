#ifndef SHELL_WORD_DECODE_INTERNAL_H
#define SHELL_WORD_DECODE_INTERNAL_H

#include "shell_word_fragment_internal.h"
#include "shell_word_internal.h"

/* Inline sinks preserve direct decoding into the final canonical buffer.
 * Allocation and public error adapters live in shell_word.c. */
typedef struct {
  char *destination;
  size_t destination_size;
  size_t output_length;
  shell_decoded_word_visitor_t visitor;
  void *visitor_context;
  bool stopped;
  shell_process_status_t error;
} decoded_word_sink_t;

static inline shell_process_status_t
decoded_word_emit(decoded_word_sink_t *sink, unsigned char value) {
  if (sink->stopped)
    return SHELL_PROCESS_OK;
  if (sink->output_length == SIZE_MAX)
    return SHELL_PROCESS_EOVERFLOW;
  if (sink->destination) {
    if (sink->output_length >= sink->destination_size)
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    sink->destination[sink->output_length] = (char)value;
  }
  size_t offset = sink->output_length++;
  if (sink->visitor && !sink->visitor(value, offset, sink->visitor_context))
    sink->stopped = true;
  return SHELL_PROCESS_OK;
}

static inline bool ansi_decode_emit(unsigned char byte, void *context) {
  decoded_word_sink_t *sink = context;
  sink->error = decoded_word_emit(sink, byte);
  return sink->error == SHELL_PROCESS_OK;
}

/* Byte decoders retain binary payloads; semantic word consumers use Bash's
 * fragment-local NUL truncation. Both modes share escape and framing rules. */
static inline SHELL_NONNULL(1, 3, 4) shell_process_status_t
    ansi_decode_quote(const char *text, size_t length, size_t *position,
                      decoded_word_sink_t *sink,
                      shell_source_ansi_mode_t mode) {
  sink->error = SHELL_PROCESS_OK;
  shell_source_ansi_facts_t facts;
  if (shell_source_decode_ansi_c_quote_impl(
          text, length, position, ansi_decode_emit, sink, mode, &facts) &&
      !facts.locale_dependent)
    return SHELL_PROCESS_OK;
  return sink->error == SHELL_PROCESS_OK ? SHELL_PROCESS_EPARSE : sink->error;
}

static inline SHELL_NONNULL(1, 3) shell_process_status_t
    decode_shell_word(const char *text, size_t length,
                      decoded_word_sink_t *sink,
                      shell_source_ansi_mode_t mode) {
  char quote = 0;
  for (size_t i = 0; i < length;) {
    char c = text[i];
    size_t after;
    if (!quote && (c == '<' || c == '>') &&
        shell_source_empty_process_fragment(text, length, i, &after)) {
      i = after;
      continue;
    }
    if (quote == 0 && c == '$' &&
        shell_source_logical_next_is(text, length, i, '\'', NULL)) {
      size_t position = i;
      shell_process_status_t status =
          ansi_decode_quote(text, length, &position, sink, mode);
      if (sink->stopped)
        return SHELL_PROCESS_OK;
      if (status != SHELL_PROCESS_OK)
        return status;
      i = position;
      continue;
    }
    unsigned char byte;
    bool protected_byte;
    if (!shell_word_literal_step(text, length, &i, &quote, &byte,
                                 &protected_byte))
      continue;
    shell_process_status_t status = decoded_word_emit(sink, byte);
    if (status != SHELL_PROCESS_OK)
      return status;
    if (sink->stopped)
      return SHELL_PROCESS_OK;
  }
  return SHELL_PROCESS_OK;
}

#endif
