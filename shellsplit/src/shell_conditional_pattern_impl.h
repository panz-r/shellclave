/* Private shell_conditional.c implementation, included after the common
 * decoded-value sinks. Keep RHS admission, quote-aware pattern projection,
 * scratch requirements and matching together. The evaluator owns the
 * scratch mark and release; source scanners own nested quote framing. */

/* Keep fully quoted RHSs on their existing admission path. Mixed dynamic
 * words need the additional outer-fragment proof in literal_dynamic_rhs. */
static SHELL_NONNULL(1) bool quoted_rhs(const char *s, size_t n, size_t p,
                                        size_t end) {
  bool quoted = false;
  while ((p = shell_source_skip_escaped_line_endings(s, end, p)) < end) {
    size_t after;
    if (s[p] == '$' && shell_source_logical_next_is(s, end, p, '\'', NULL)) {
      if (!shell_source_skip_complete_ansi_c_quote(s, n, p, &after))
        return false;
    } else if (s[p] == '\'' || s[p] == '"') {
      if (!shell_source_skip_complete_quoted_text(s, n, p, s[p], &after))
        return false;
    } else
      return false;
    quoted = true;
    p = after;
  }
  return quoted;
}

typedef struct {
  unsigned char byte;
  bool star;
} pattern_unit_t;

/* Source spelling includes quote/operator delimiters, covering the fixed
 * alignment padding in addition to these per-byte value reservations. */
_Static_assert(sizeof(pattern_unit_t) + sizeof(size_t) + 1 <=
                   SHELL_SOURCE_VALUE_SCRATCH_FACTOR,
               "conditional values must fit source scratch sizing");

/* units is NULL during measurement, which determines the required capacity.
 * Before emission, checked scratch reservations validate allocation arithmetic
 * and available space; units then has room for the measured projection.
 * Adjacent active stars collapse even across empty quoted fragments. */
typedef struct {
  pattern_unit_t *units;
  size_t length, run, max_run;
  bool has_star, previous_star;
} pattern_builder_t;

static SHELL_NONNULL(3) bool pattern_byte(unsigned char byte, bool quoted,
                                          void *context) {
  SHELL_SOURCE_WORD_SCAN(1);
  pattern_builder_t *builder = context;
  bool star = byte == '*' && !quoted;
  if (star && builder->previous_star)
    return true;
  if (builder->units)
    builder->units[builder->length] = (pattern_unit_t){byte, star};
  builder->length++;
  builder->has_star |= star;
  builder->previous_star = star;
  builder->run = star ? 0 : builder->run + 1;
  if (builder->run > builder->max_run)
    builder->max_run = builder->run;
  return true;
}

/* This admission boundary accepts only literal bytes and active stars.
 * Unquoted parentheses belong to wider extglob syntax in a complete word;
 * quoted/escaped pattern metacharacters are ordinary literal bytes. */
static SHELL_NONNULL(3) bool admit_pattern_byte(unsigned char byte, bool quoted,
                                                void *context) {
  if (!quoted && (byte == '?' || byte == '[' || byte == '(' || byte == ')'))
    return false;
  return pattern_byte(byte, quoted, context);
}

/* Admission of a preframed dynamic RHS requires quoted expansions and literal
 * outer fragments. Source classification supplies the expansion fact; this
 * conditional-specific walk excludes active pattern syntax. Skip complete
 * quotes through source framing: quotes and pattern bytes inside a nested
 * parameter/command belong to that expansion, not the outer RHS. Static
 * patterns retain their separate quote-aware projection below. */
static SHELL_NONNULL(1) bool literal_dynamic_rhs(const char *word,
                                                 size_t length) {
  if (shell_source_conditional_unquoted_expansion(word, length))
    return false;
  for (size_t p = 0; p < length;) {
    SHELL_SOURCE_WORD_SCAN(1);
    size_t after;
    if (word[p] == '$' &&
        shell_source_logical_next_is(word, length, p, '\'', NULL)) {
      if (!shell_source_skip_complete_ansi_c_quote(word, length, p, &after))
        return false;
      p = after;
    } else if (word[p] == '\'' || word[p] == '"') {
      if (!shell_source_skip_complete_quoted_text(word, length, p, word[p],
                                                  &after))
        return false;
      p = after;
    } else if ((word[p] == '<' || word[p] == '>') &&
               shell_source_empty_process_fragment(word, length, p, &after)) {
      p = after;
    } else {
      char quote = 0;
      unsigned char byte;
      bool protected_byte;
      if (shell_word_literal_step(word, length, &p, &quote, &byte,
                                  &protected_byte) &&
          !protected_byte && strchr("*?[()", byte))
        return false;
    }
  }
  return true;
}

static SHELL_NONNULL(1, 5) bool comparison_rhs(
    const char *s, size_t n, size_t p, size_t end,
    shell_conditional_predicate_t *predicate) {
  if (quoted_rhs(s, n, p, end))
    return true;
  if (shell_conditional_word_dynamic(s + p, end - p))
    return literal_dynamic_rhs(s + p, end - p);
  pattern_builder_t builder = {0};
  if (!shell_source_visit_quoted_word(s + p, end - p, admit_pattern_byte,
                                      &builder))
    return false;
  if (builder.has_star)
    *predicate = *predicate == SHELL_CONDITIONAL_STRING_NOT_EQUAL
                     ? SHELL_CONDITIONAL_PATTERN_NOT_MATCH
                     : SHELL_CONDITIONAL_PATTERN_MATCH;
  return true;
}

/* Precompiled units contain at least one star. prefix has max_run entries.
 * data may be NULL only for an empty subject. Anchored ends reserve disjoint
 * bytes; KMP finds each interior literal run at its earliest remaining match.
 * Each subject byte is searched at most once across runs, with linear KMP
 * fallback work. No locale state, recursion or wildcard backtracking is used.
 */
static SHELL_NONNULL(1, 5) bool match_pattern(const pattern_unit_t *units,
                                              size_t count, const char *data,
                                              size_t length, size_t *prefix) {
  size_t first = 0, last = count;
  while (!units[first].star)
    first++;
  while (!units[last - 1].star)
    last--;
  size_t suffix = count - last;
  if (first > length || suffix > length - first)
    return false;
  for (size_t i = 0; i < first; ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (units[i].byte != (unsigned char)data[i])
      return false;
  }
  size_t stop = length - suffix;
  for (size_t i = 0; i < suffix; ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (units[last + i].byte != (unsigned char)data[stop + i])
      return false;
  }
  size_t cursor = first;
  for (size_t run = first + 1; run < last - 1;) {
    size_t end = run;
    while (!units[end].star)
      end++;
    size_t size = end - run;
    prefix[0] = 0;
    for (size_t i = 1, matched = 0; i < size; ++i) {
      SHELL_SOURCE_WORD_SCAN(1);
      while (matched && units[run + i].byte != units[run + matched].byte) {
        SHELL_SOURCE_WORD_SCAN(1);
        matched = prefix[matched - 1];
      }
      if (units[run + i].byte == units[run + matched].byte)
        matched++;
      prefix[i] = matched;
    }
    size_t matched = 0;
    while (cursor < stop && matched < size) {
      SHELL_SOURCE_WORD_SCAN(1);
      unsigned char byte = (unsigned char)data[cursor++];
      while (matched && byte != units[run + matched].byte) {
        SHELL_SOURCE_WORD_SCAN(1);
        matched = prefix[matched - 1];
      }
      if (byte == units[run + matched].byte)
        matched++;
    }
    if (matched != size)
      return false;
    run = end + 1;
  }
  return true;
}

/* condition supplies an admitted static star pattern. The enclosing operation
 * releases all temporary storage at its saved mark, including on failure. */
static SHELL_NONNULL(1, 2, 3, 4) bool evaluate_pattern(
    const char *source, const shell_conditional_primary_t *condition,
    const shell_conditional_value_t *left, bool *matched) {
  const char *word = source + condition->operands[1];
  size_t length = condition->operand_lengths[1];
  pattern_builder_t measure = {0};
  if (!shell_source_visit_quoted_word(word, length, pattern_byte, &measure))
    return false;
  /* Check each array reservation before emitting measured units. Callers may
   * supply less scratch than the source workspace's sufficient size bound. */
  pattern_unit_t *units = shell_source_scratch_take_array(
      measure.length, sizeof(pattern_unit_t), _Alignof(pattern_unit_t));
  if (!units)
    return false;
  size_t *prefix = shell_source_scratch_take_array(
      measure.max_run, sizeof(size_t), _Alignof(size_t));
  if (!prefix)
    return false;
  pattern_builder_t build = {.units = units};
  if (!shell_source_visit_quoted_word(word, length, pattern_byte, &build))
    return false;
  shell_conditional_value_t subject = *left;
  if (!subject.known) {
    word = source + condition->operands[0];
    length = condition->operand_lengths[0];
    subject.length = 0;
    if (!shell_source_visit_decoded_word(word, length, measure_byte,
                                         &subject.length))
      return false;
    unsigned char *bytes = shell_source_scratch_take(subject.length);
    if (!bytes)
      return false;
    subject.data = (const char *)bytes;
    if (!shell_source_visit_decoded_word(word, length, write_byte, &bytes))
      return false;
  }
  *matched =
      match_pattern(units, build.length, subject.data, subject.length, prefix);
  return true;
}
