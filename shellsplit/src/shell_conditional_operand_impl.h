/* Private shell_conditional.c implementation. Arithmetic word projection
 * and direct parameter observation share source framing and operation
 * scratch. Published names retain their existing source/arena lifetimes.
 * This fragment is part of the conditional translation unit, not an API. */

typedef struct {
  shell_arithmetic_reference_fn visitor;
  void *context;
  bool exhausted;
} condition_parameter_visitor_t;

/* name is a borrowed readable span of length bytes. context points to a live
 * collector; its forwarded visitor context retains the visitor's contract. */
static SHELL_NONNULL(1, 3) void condition_parameter(const char *name,
                                                    size_t length,
                                                    void *context) {
  condition_parameter_visitor_t *state = context;
  size_t bytes = 0;
  for (size_t p = 0; p < length;) {
    p = shell_source_skip_escaped_line_endings(name, length, p);
    if (p < length) {
      ++bytes;
      ++p;
    }
  }
  if (bytes != length) {
    char *decoded = shell_source_scratch_take(bytes);
    if (!decoded) {
      state->exhausted = true;
      return;
    }
    size_t written = 0;
    for (size_t p = 0; p < length;) {
      p = shell_source_skip_escaped_line_endings(name, length, p);
      if (p < length)
        decoded[written++] = name[p++];
    }
    name = decoded;
  }
  state->visitor(name, bytes, state->context);
}

bool shell_conditional_visit_parameters(const char *word, size_t length,
                                        shell_arithmetic_reference_fn visitor,
                                        void *context) {
  condition_parameter_visitor_t state = {visitor, context, false};
  shell_source_substitution_scan_t scan = {
      .parameter_visitor = condition_parameter, .parameter_context = &state};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t status;
  do {
    status = shell_source_next_word_expansion(word, length, &scan, &start,
                                              &after, &kind);
  } while (status == SHELL_SOURCE_SCAN_FOUND && !state.exhausted);
  return status == SHELL_SOURCE_SCAN_DONE && !state.exhausted;
}

/* Project active literal arithmetic expansions before interpreting the final
 * value. The original fragment cursor owns quote protection; decoded dollars
 * are data and never re-enter expansion recognition. word is a readable span
 * of length bytes; sink is initialized and unknown is writable. A NULL sink
 * destination selects measurement; the sink itself remains required. */
static SHELL_NONNULL(1, 3, 4) bool arithmetic_word(const char *word,
                                                   size_t length,
                                                   decoded_word_sink_t *sink,
                                                   bool *unknown) {
  char quote = 0;
  for (size_t i = 0; i < length;) {
    size_t open, after;
    if (!quote && word[i] == '$' &&
        shell_source_logical_next_is(word, length, i, '\'', NULL)) {
      if (ansi_decode_quote(word, length, &i, sink, SHELL_SOURCE_ANSI_WORD) !=
          SHELL_PROCESS_OK)
        return false;
      continue;
    }
    if (quote != '\'' && word[i] == '$' &&
        shell_source_dollar_arithmetic_open(word, length, i, &open)) {
      if (!shell_source_skip_arithmetic_expansion(word, length, i, &after))
        return false;
      size_t close = after - 2;
      while (close > open + 1 && word[close] != ')')
        --close;
      shell_arithmetic_result_t value =
          shell_arithmetic_analyze(word + open + 1, close - open - 1);
      if (!value.supported)
        return false;
      if (!value.known) {
        *unknown = true;
        return true;
      }
      char number[32];
      int count = snprintf(number, sizeof(number), "%" PRId64, value.value);
      for (int j = 0; j < count; ++j)
        if (decoded_word_emit(sink, (unsigned char)number[j]) !=
            SHELL_PROCESS_OK)
          return false;
      i = after;
      continue;
    }
    if (quote != '\'' &&
        ((word[i] == '$' &&
          (shell_source_skip_variable_expansion(word, length, i, &after) ||
           shell_source_dollar_parentheses_open(word, length, i, &open))) ||
         word[i] == '`')) {
      *unknown = true;
      return true;
    }
    unsigned char byte;
    bool protected_byte;
    if (shell_word_literal_step(word, length, &i, &quote, &byte,
                                &protected_byte) &&
        decoded_word_emit(sink, byte) != SHELL_PROCESS_OK)
      return false;
  }
  return true;
}

shell_arithmetic_scalar_result_t shell_conditional_arithmetic_operand(
    const char *word, size_t length, const char *value, size_t value_length,
    bool resolved, shell_arithmetic_reference_fn visitor, void *context) {
  if (resolved)
    return shell_arithmetic_analyze_scalar(value ? value : "", value_length,
                                           visitor, context);
  /* Tilde expansion precedes arithmetic interpretation. Its raw spelling
   * cannot prove complement or publish guessed scalar reads. */
  if (shell_source_conditional_has_tilde_expansion(word, length))
    return (shell_arithmetic_scalar_result_t){.result = {.supported = true},
                                              .unresolved = true};
  bool dynamic = shell_conditional_word_dynamic(word, length);
  size_t mark = shell_source_scratch_mark();
  decoded_word_sink_t measure = {0};
  bool unknown = false;
  if (!arithmetic_word(word, length, &measure, &unknown))
    return (shell_arithmetic_scalar_result_t){0};
  if (unknown) {
    /* A standalone pure expansion still has only numerical uncertainty.
     * Composed unknown text needs whole-operand resolution. */
    size_t open, after;
    const char *body = word;
    size_t size = length;
    if (size >= 2 && body[0] == '"' && body[size - 1] == '"') {
      ++body;
      size -= 2;
    }
    if (shell_source_dollar_arithmetic_open(body, size, 0, &open) &&
        shell_source_skip_arithmetic_expansion(body, size, 0, &after) &&
        after == size)
      return (shell_arithmetic_scalar_result_t){.result = {.supported = true}};
    return (shell_arithmetic_scalar_result_t){.result = {.supported = true},
                                              .unresolved = true};
  }
  size_t bytes = measure.output_length;
  char *decoded = shell_source_scratch_take(bytes + 1);
  if (!decoded)
    return (shell_arithmetic_scalar_result_t){0};
  decoded_word_sink_t output = {.destination = decoded,
                                .destination_size = bytes};
  if (!arithmetic_word(word, length, &output, &unknown)) {
    shell_source_scratch_release(mark);
    return (shell_arithmetic_scalar_result_t){0};
  }
  decoded[bytes] = 0;
  /* Publish only identifiers from the composed value: co$((1)) reads co1,
   * while unresolved source fragments above publish no guessed names. */
  shell_arithmetic_scalar_result_t result = shell_arithmetic_analyze_scalar(
      decoded, bytes, dynamic ? NULL : visitor, context);
  /* Known expansion pieces can compose a mutation token. Preserve that
   * rejection instead of weakening it to an opaque runtime interpretation. */
  if (dynamic && !result.result.supported && !result.mutation &&
      !memchr(decoded, '$', bytes) && !memchr(decoded, '\\', bytes))
    result = (shell_arithmetic_scalar_result_t){.result = {.supported = true},
                                                .unresolved = true};
  else if (dynamic && visitor && result.references)
    result = shell_arithmetic_analyze_scalar(decoded, bytes, visitor, context);
  /* Only published reference names borrow the decoded operand storage. */
  if (!visitor || !result.references)
    shell_source_scratch_release(mark);
  return result;
}
