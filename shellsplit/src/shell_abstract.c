#define _XOPEN_SOURCE 700
#include "shell_abstract.h"
#include "alloc.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_processor_internal.h"
#include "shell_sequence.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- Internal Helpers --- */

static const char *SHELL_ABSTRACT_TYPE_NAMES[] = {
    "EV", "PV", "SV", "AP", "RP", "HP", "GB", "CS", "AR", "STR", "RD"};

static const char *SHELL_PATH_CATEGORY_NAMES[] = {
    "ROOT",    "ETC",  "VAR", "USR",   "HOME",     "TMP",
    "PROC",    "SYS",  "DEV", "OPT",   "SRV",      "RUN",
    "SYSROOT", "BOOT", "MNT", "MEDIA", "SNAPSHOT", "OTHER"};

/* --- Token Classification Helpers --- */

/* The abstract representation deliberately keeps parameter operators in the
 * source spelling, but variable metadata must name the parameter selected by
 * that spelling rather than treating the operator and its word as part of the
 * name. A prefix-name expansion is different: it has no one static parameter
 * name, so callers receive a NULL name and inspect `original` if needed. */
typedef struct {
  shell_abstract_type_t type;
  size_t name_start;
  size_t name_length;
  bool is_braced;
  bool has_static_name;
} shell_abstract_variable_info_t;

static bool abstract_special_parameter(char c) {
  return strchr("?#$-!@*", c) != NULL;
}

static bool abstract_parse_parameter_name(const char *text, size_t length,
                                          size_t position,
                                          shell_abstract_variable_info_t *out,
                                          size_t *after) {
  if (!text || !out || !after || position >= length)
    return false;

  unsigned char first = (unsigned char)text[position];
  out->name_start = position;
  if (isdigit(first)) {
    do {
      position++;
    } while (position < length && isdigit((unsigned char)text[position]));
    out->type = SHELL_ABSTRACT_PV;
  } else if (isalpha(first) || first == '_') {
    do {
      position++;
    } while (position < length &&
             (isalnum((unsigned char)text[position]) || text[position] == '_'));
    out->type = SHELL_ABSTRACT_EV;
  } else if (abstract_special_parameter((char)first)) {
    position++;
    out->type = SHELL_ABSTRACT_SV;
  } else {
    return false;
  }
  out->name_length = position - out->name_start;
  out->has_static_name = true;
  *after = position;
  return true;
}

static bool abstract_parse_variable(const char *text, size_t length,
                                    shell_abstract_variable_info_t *out) {
  if (!text || !out || length < 2 || text[0] != '$')
    return false;
  memset(out, 0, sizeof(*out));

  if (text[1] != '{') {
    size_t after = 0;
    return abstract_parse_parameter_name(text, length, 1, out, &after) &&
           after == length;
  }

  if (length < 4 || text[length - 1] != '}')
    return false;
  out->is_braced = true;
  const size_t body_end = length - 1;
  size_t position = 2;

  /* `${#}` is the special parameter, while `${#name}` is the length of the
   * named parameter. */
  if (text[position] == '#') {
    if (++position == body_end) {
      out->type = SHELL_ABSTRACT_SV;
      out->name_start = 2;
      out->name_length = 1;
      out->has_static_name = true;
      return true;
    }
    return abstract_parse_parameter_name(text, body_end, position, out,
                                         &position);
  }

  /* `${!prefix*}` and `${!prefix@}` enumerate a dynamic set. Indirection
   * otherwise still has a concrete source parameter (for example `${!name}`)
   * that is useful metadata, while `original` preserves the indirection. */
  if (text[position] == '!') {
    if (++position == body_end) {
      out->type = SHELL_ABSTRACT_SV;
      out->name_start = 2;
      out->name_length = 1;
      out->has_static_name = true;
      return true;
    }
    size_t after = 0;
    if (!abstract_parse_parameter_name(text, body_end, position, out, &after))
      return false;
    if (out->type == SHELL_ABSTRACT_EV && after + 1 == body_end &&
        (text[after] == '*' || text[after] == '@')) {
      out->has_static_name = false;
      out->name_length = 0;
    }
    return true;
  }

  size_t after = 0;
  return abstract_parse_parameter_name(text, body_end, position, out, &after);
}

/* Full-token variable tokens can retain double-quoted literal surroundings.
 * Keep their established whole-token abstraction while extracting metadata
 * from the expansion itself. Compound unquoted words reach this helper with
 * the variable span already isolated. */
static bool
abstract_variable_info_from_token(const char *text, size_t length,
                                  shell_abstract_variable_info_t *out,
                                  size_t *variable_start) {
  if (!text || !out || !variable_start)
    return false;
  *variable_start = 0;
  if (abstract_parse_variable(text, length, out))
    return true;
  if (length >= 2 && text[0] == '"' && text[length - 1] == '"' &&
      abstract_parse_variable(text + 1, length - 2, out)) {
    *variable_start = 1;
    return true;
  }

  shell_source_variable_scan_t scan = {0};
  size_t start = 0;
  size_t after = 0;
  if (!shell_source_next_variable_expansion(text, length, &scan, &start,
                                            &after) ||
      !abstract_parse_variable(text + start, after - start, out))
    return false;
  *variable_start = start;
  return true;
}

static bool abstract_variable_info(const char *text, size_t length,
                                   shell_abstract_variable_info_t *out) {
  size_t variable_start = 0;
  return abstract_variable_info_from_token(text, length, out, &variable_start);
}

static char *abstract_variable_name_copy(const char *text, size_t length,
                                         bool *has_static_name) {
  if (has_static_name)
    *has_static_name = false;
  shell_abstract_variable_info_t info = {0};
  size_t variable_start = 0;
  if (!abstract_variable_info_from_token(text, length, &info, &variable_start))
    return NULL;
  if (has_static_name)
    *has_static_name = info.has_static_name;
  return info.has_static_name ? strndup(text + variable_start + info.name_start,
                                        info.name_length)
                              : NULL;
}

/**
 * Check if string contains glob characters
 */
static bool is_glob_pattern(const char *s, size_t len) {
  if (len == 0)
    return false;

  // Must contain at least one glob char
  bool has_glob = false;
  for (size_t i = 0; i < len; i++) {
    if (s[i] == '*' || s[i] == '?' ||
        (s[i] == '[' && i + 1 < len && s[len - 1] != '[')) {
      has_glob = true;
      break;
    }
  }

  if (!has_glob)
    return false;

  // Check for path-like patterns
  if (s[0] == '/' || s[0] == '.' || s[0] == '~') {
    return true;
  }

  // Contains path separator with glob somewhere
  for (size_t i = 0; i < len; i++) {
    if (s[i] == '/' && i > 0 && i < len - 1) {
      return true;
    }
  }

  // Bare glob pattern (like *.txt)
  return has_glob;
}

/**
 * Check if string is an absolute path
 */
static bool is_absolute_path(const char *s, size_t len) {
  if (len == 0)
    return false;
  return s[0] == '/';
}

/**
 * Check if string is a relative path
 */
static bool is_relative_path(const char *s, size_t len) {
  if (len == 0)
    return false;

  // ./ or ../
  if (len >= 2 && s[0] == '.' && s[1] == '/')
    return true;
  if (len >= 3 && s[0] == '.' && s[1] == '.' && s[2] == '/')
    return true;
  if (len == 2 && s[0] == '.' && s[1] == '.')
    return true;
  if (len == 1 && s[0] == '.')
    return true;

  // Contains / but not absolute and not starting with ~
  // Use memchr instead of strchr to respect length
  if (memchr(s, '/', len) != NULL) {
    return s[0] != '~';
  }

  return false;
}

/**
 * Check if string is a home path (~ or ~user)
 */
static bool is_home_path(const char *s, size_t len) {
  if (len == 0)
    return false;
  if (s[0] == '~') {
    return len == 1 || s[1] == '/' ||
           (len >= 2 && isalpha((unsigned char)s[1]));
  }
  return false;
}

/**
 * Check if string is a short option
 */
static bool is_short_option(const char *s, size_t len) {
  if (len == 0)
    return false;
  return len >= 2 && s[0] == '-' && s[1] != '-' &&
         !isdigit((unsigned char)s[1]);
}

/**
 * Check if string is a long option
 */
static bool is_long_option(const char *s, size_t len) {
  if (len < 3)
    return false;
  return s[0] == '-' && s[1] == '-' && s[2] != '-';
}

static bool is_redirection_token(shell_token_type_t type) {
  return type == SHELL_TOKEN_REDIRECT_IN || type == SHELL_TOKEN_REDIRECT_OUT ||
         type == SHELL_TOKEN_REDIRECT_ERR ||
         type == SHELL_TOKEN_REDIRECT_APPEND ||
         type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         type == SHELL_TOKEN_REDIRECT_BOTH ||
         type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
         type == SHELL_TOKEN_HEREDOC || type == SHELL_TOKEN_HERESTRING;
}

static bool redirection_consumes_operand(const shell_token_t *token) {
  if (token->type == SHELL_TOKEN_HERESTRING ||
      token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
      token->type == SHELL_TOKEN_REDIRECT_BOTH ||
      token->type == SHELL_TOKEN_REDIRECT_BOTH_APPEND)
    return true;
  if (token->type == SHELL_TOKEN_HEREDOC || token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
}

/**
 * Classify a raw token string
 */
shell_token_type_t shell_classify_raw_token(const char *text, size_t len) {
  if (!text || len == 0)
    return SHELL_TOKEN_END;

  // Handle quoted strings
  if ((text[0] == '"' && text[len - 1] == '"') ||
      (text[0] == '\'' && text[len - 1] == '\'')) {
    return SHELL_TOKEN_ARGUMENT; // Will be treated as string in abstraction
  }

  // Arithmetic must be checked before command substitution because $((...))
  // also has the outer $(...) shape.
  if (len >= 5 && text[0] == '$' && text[1] == '(' && text[2] == '(' &&
      text[len - 1] == ')' && text[len - 2] == ')') {
    return SHELL_TOKEN_ARITHMETIC;
  }

  // Command substitution: $(...) or `...`
  if (len >= 4) {
    if (text[0] == '$' && text[1] == '(' && text[len - 1] == ')') {
      return SHELL_TOKEN_SUBSHELL;
    }
    if (text[0] == '`' && text[len - 1] == '`') {
      return SHELL_TOKEN_SUBSHELL;
    }
  }

  // Variables
  if (text[0] == '$') {
    shell_abstract_variable_info_t variable = {0};
    if (abstract_parse_variable(text, len, &variable))
      return variable.type == SHELL_ABSTRACT_EV ? SHELL_TOKEN_VARIABLE
                                                : SHELL_TOKEN_SPECIAL_VAR;
    return SHELL_TOKEN_ARGUMENT;
  }

  // Paths (before checking options since - could be a path component)
  if (is_absolute_path(text, len)) {
    return SHELL_TOKEN_ARGUMENT; // Will be classified as path in abstraction
  }
  if (is_home_path(text, len)) {
    return SHELL_TOKEN_ARGUMENT;
  }
  if (is_relative_path(text, len)) {
    return SHELL_TOKEN_ARGUMENT;
  }

  // Glob patterns
  if (is_glob_pattern(text, len)) {
    return SHELL_TOKEN_GLOB;
  }

  // Options
  if (is_long_option(text, len)) {
    return SHELL_TOKEN_ARGUMENT;
  }
  if (is_short_option(text, len)) {
    return SHELL_TOKEN_ARGUMENT;
  }

  return SHELL_TOKEN_ARGUMENT;
}

/* --- ABSTRACTION HELPERS --- */

/**
 * Create abstraction string for a type and index
 */
static char *make_abstraction(shell_abstract_type_t type, size_t index) {
  const char *type_str = SHELL_ABSTRACT_TYPE_NAMES[type];
  int needed = snprintf(NULL, 0, "$%s_%zu", type_str, index);
  if (needed < 0)
    return NULL;
  char *result = malloc((size_t)needed + 1);
  if (!result)
    return NULL;
  snprintf(result, (size_t)needed + 1, "$%s_%zu", type_str, index);
  return result;
}

/**
 * Determine abstract type from token type and classify path
 */
static shell_abstract_type_t get_abstract_type(shell_token_type_t tok_type,
                                               const char *text, size_t len) {
  // Handle known types from tokenizer directly
  switch (tok_type) {
  case SHELL_TOKEN_VARIABLE:
  case SHELL_TOKEN_VARIABLE_QUOTED:
  case SHELL_TOKEN_SPECIAL_VAR: {
    shell_abstract_variable_info_t variable = {0};
    return abstract_variable_info(text, len, &variable) ? variable.type
                                                        : SHELL_ABSTRACT_EV;
  }

  case SHELL_TOKEN_GLOB:
  case SHELL_TOKEN_EXTGLOB:
    return SHELL_ABSTRACT_GB;

  case SHELL_TOKEN_ANSI_C_QUOTED:
    return SHELL_ABSTRACT_STR;

  case SHELL_TOKEN_SUBSHELL:
  case SHELL_TOKEN_PROCESS_SUB:
    return SHELL_ABSTRACT_CS;

  case SHELL_TOKEN_ARITHMETIC:
    return SHELL_ABSTRACT_AR;

  default:
    break;
  }

  // For SHELL_TOKEN_COMMAND and SHELL_TOKEN_ARGUMENT, do path classification
  if (tok_type == SHELL_TOKEN_COMMAND || tok_type == SHELL_TOKEN_ARGUMENT) {
    // Check for quoted strings first
    if ((text[0] == '"' && text[len - 1] == '"') ||
        (text[0] == '\'' && text[len - 1] == '\'')) {
      return SHELL_ABSTRACT_STR;
    }
    // Check glob before path (path check catches relative paths with /)
    if (is_glob_pattern(text, len)) {
      return SHELL_ABSTRACT_GB;
    }
    if (is_absolute_path(text, len)) {
      return SHELL_ABSTRACT_AP;
    }
    if (is_home_path(text, len)) {
      return SHELL_ABSTRACT_HP;
    }
    if (is_relative_path(text, len)) {
      return SHELL_ABSTRACT_RP;
    }
  }

  return -1; // Not abstractable
}

/* --- BUILD ABSTRACTED COMMAND --- */

/**
 * Build the abstracted command string from sorted elements
 */
static shell_abstract_status_t
build_abstracted_command(const char *original, size_t original_length,
                         shell_abstract_element_t **elements,
                         size_t element_count, char **out) {
  *out = NULL;
  if (element_count == 0) {
    *out = strndup(original, original_length);
    return *out ? SHELL_ABSTRACT_OK : SHELL_ABSTRACT_ENOMEM;
  }

  // Compute required output size, including abstracted segments and untouched
  // spans.
  size_t output_size = 1; // null terminator
  for (size_t i = 0; i < element_count; i++) {
    size_t length = strlen(elements[i]->abstraction);
    if (length > SIZE_MAX - output_size)
      return SHELL_ABSTRACT_EOVERFLOW;
    output_size += length;
  }

  // Add non-abstracted parts
  size_t last_end = 0;
  for (size_t i = 0; i < element_count; i++) {
    if (elements[i]->start > last_end) {
      size_t length = elements[i]->start - last_end;
      if (length > SIZE_MAX - output_size)
        return SHELL_ABSTRACT_EOVERFLOW;
      output_size += length;
    }
    last_end = elements[i]->end;
  }
  if (last_end < original_length) {
    size_t length = original_length - last_end;
    if (length > SIZE_MAX - output_size)
      return SHELL_ABSTRACT_EOVERFLOW;
    output_size += length;
  }

  char *result = malloc(output_size);
  if (!result)
    return SHELL_ABSTRACT_ENOMEM;

  // Construct transformed output by merging original text and abstractions.
  size_t dst = 0;
  size_t src = 0;

  for (size_t i = 0; i < element_count; i++) {
    // Copy non-abstracted part before this element
    if (elements[i]->start > src) {
      size_t copy_len = elements[i]->start - src;
      memcpy(result + dst, original + src, copy_len);
      dst += copy_len;
    }

    // Insert abstraction
    size_t abbrev_len = strlen(elements[i]->abstraction);
    memcpy(result + dst, elements[i]->abstraction, abbrev_len);
    dst += abbrev_len;

    src = elements[i]->end;
  }

  // Copy remaining
  if (src < original_length) {
    memcpy(result + dst, original + src, original_length - src);
    dst += original_length - src;
  }

  result[dst] = '\0';
  *out = result;
  return SHELL_ABSTRACT_OK;
}

static void free_abstract_element(shell_abstract_element_t *elem) {
  if (!elem)
    return;
  free(elem->abstraction);
  free((void *)elem->original);
  switch (elem->type) {
  case SHELL_ABSTRACT_EV:
  case SHELL_ABSTRACT_PV:
  case SHELL_ABSTRACT_SV:
    free(elem->data.var.name);
    break;
  case SHELL_ABSTRACT_AP:
  case SHELL_ABSTRACT_RP:
  case SHELL_ABSTRACT_HP:
    free(elem->data.path.path);
    break;
  case SHELL_ABSTRACT_GB:
    free(elem->data.glob.pattern);
    break;
  case SHELL_ABSTRACT_CS:
  case SHELL_ABSTRACT_AR:
  case SHELL_ABSTRACT_STR:
    free(elem->data.cmd_subst.content);
    break;
  default:
    break;
  }
  free(elem->expanded);
  free(elem);
}

/* A lexer token is a complete shell word, not necessarily one atomic
 * expansion. Preserve that distinction in abstraction output: `/var/$APP`
 * contains an absolute-path prefix and a variable, while still representing
 * one argv word to the processor. */
static void compound_abstract_set_flag(shell_abstract_command_t *command,
                                       shell_abstract_type_t type) {
  if (type <= SHELL_ABSTRACT_SV) {
    command->has_variables = true;
    command->has_pos_vars = command->has_pos_vars || type == SHELL_ABSTRACT_PV;
    command->has_special_vars =
        command->has_special_vars || type == SHELL_ABSTRACT_SV;
    return;
  }

  command->has_paths = true;
  if (type == SHELL_ABSTRACT_AP) {
    command->has_abs_paths = true;
  } else if (type == SHELL_ABSTRACT_RP) {
    command->has_rel_paths = true;
  } else {
    command->has_home_paths = true;
  }
}

static bool compound_abstract_type_is_path(shell_abstract_type_t type) {
  return type == SHELL_ABSTRACT_AP || type == SHELL_ABSTRACT_RP ||
         type == SHELL_ABSTRACT_HP;
}

/* A fully quoted lone variable retains the established whole-token display
 * abstraction (`"$HOME"` becomes `$EV_1`). Quoted words with literal text or
 * more than one expansion need the compound path so each element spans exactly
 * the parameter it describes. */
static bool
token_needs_compound_variable_abstraction(const shell_token_t *tok) {
  if (!tok || !tok->start || !shell_tokenizer_token_has_variable(tok))
    return false;
  if (tok->type == SHELL_TOKEN_COMMAND || tok->type == SHELL_TOKEN_ARGUMENT)
    return true;
  if (tok->type != SHELL_TOKEN_VARIABLE_QUOTED || tok->length < 2 ||
      tok->start[0] != '"' || tok->start[tok->length - 1] != '"')
    return false;

  shell_source_variable_scan_t scan = {0};
  size_t start = 0;
  size_t after = 0;
  if (!shell_source_next_variable_expansion(tok->start, tok->length, &scan,
                                            &start, &after))
    return false;
  if (start != 1 || after != tok->length - 1)
    return true;
  return shell_source_next_variable_expansion(tok->start, tok->length, &scan,
                                              &start, &after);
}

typedef enum {
  COMPOUND_ABSTRACT_VARIABLE = 0,
  COMPOUND_ABSTRACT_SUBSTITUTION,
} compound_abstract_span_type_t;

typedef struct {
  compound_abstract_span_type_t type;
  size_t start;
  size_t after;
  shell_source_substitution_kind_t substitution_kind;
} compound_abstract_span_t;

/* Variables and substitutions may be nested in either direction. Emit only
 * top-level, non-overlapping spans: `${value:-$(id)}` remains one variable
 * element, while `x$VALUE$(id)` exposes both independently. */
typedef struct {
  const shell_token_t *token;
  shell_source_variable_scan_t variables;
  shell_source_substitution_scan_t substitutions;
  bool have_variable;
  bool have_substitution;
  size_t variable_start;
  size_t variable_after;
  size_t substitution_start;
  size_t substitution_after;
  shell_source_substitution_kind_t substitution_kind;
} compound_abstract_span_iterator_t;

static void compound_abstract_span_iterator_init(
    compound_abstract_span_iterator_t *iterator, const shell_token_t *token) {
  if (!iterator)
    return;
  *iterator = (compound_abstract_span_iterator_t){.token = token};
}

static bool compound_abstract_span_iterator_next(
    compound_abstract_span_iterator_t *iterator,
    compound_abstract_span_t *out) {
  if (!iterator || !iterator->token || !iterator->token->start || !out)
    return false;

  for (;;) {
    if (!iterator->have_variable) {
      iterator->have_variable = shell_source_next_variable_expansion(
          iterator->token->start, iterator->token->length, &iterator->variables,
          &iterator->variable_start, &iterator->variable_after);
    }
    if (!iterator->have_substitution) {
      iterator->have_substitution = shell_source_next_executable_substitution(
          iterator->token->start, iterator->token->length,
          &iterator->substitutions, &iterator->substitution_start,
          &iterator->substitution_after, &iterator->substitution_kind);
    }
    if (!iterator->have_variable && !iterator->have_substitution)
      return false;

    if (iterator->have_variable && iterator->have_substitution) {
      if (iterator->substitution_start >= iterator->variable_start &&
          iterator->substitution_after <= iterator->variable_after) {
        iterator->have_substitution = false;
        continue;
      }
      if (iterator->variable_start >= iterator->substitution_start &&
          iterator->variable_after <= iterator->substitution_after) {
        iterator->have_variable = false;
        continue;
      }
    }

    if (iterator->have_variable &&
        (!iterator->have_substitution ||
         iterator->variable_start < iterator->substitution_start)) {
      *out = (compound_abstract_span_t){
          .type = COMPOUND_ABSTRACT_VARIABLE,
          .start = iterator->variable_start,
          .after = iterator->variable_after,
      };
      iterator->have_variable = false;
      return true;
    }

    *out = (compound_abstract_span_t){
        .type = COMPOUND_ABSTRACT_SUBSTITUTION,
        .start = iterator->substitution_start,
        .after = iterator->substitution_after,
        .substitution_kind = iterator->substitution_kind,
    };
    iterator->have_substitution = false;
    return true;
  }
}

static bool compound_abstract_append(shell_abstract_command_t *command,
                                     shell_abstract_element_t **elements,
                                     size_t capacity, size_t *count,
                                     shell_abstract_type_t type,
                                     const char *text, size_t length,
                                     size_t position, bool is_quoted,
                                     size_t indices[SHELL_ABSTRACT_HP + 1]) {
  /* Only variable and path subspans reach this private helper. */
  if (*count == capacity || type > SHELL_ABSTRACT_HP)
    return false;

  size_t index = ++indices[type];
  shell_abstract_element_t *element = calloc(1, sizeof(*element));
  if (!element)
    return false;

  element->type = type;
  element->original = strndup(text, length);
  element->abstraction = make_abstraction(type, index);
  element->start = position;
  element->end = position + length;
  if (!element->original || !element->abstraction) {
    free_abstract_element(element);
    return false;
  }

  if (type <= SHELL_ABSTRACT_SV) {
    shell_abstract_variable_info_t variable = {0};
    if (!abstract_variable_info(text, length, &variable)) {
      free_abstract_element(element);
      return false;
    }
    bool has_static_name = false;
    element->data.var.name =
        abstract_variable_name_copy(text, length, &has_static_name);
    element->data.var.is_braced = variable.is_braced;
    element->data.var.is_quoted = is_quoted;
    if (has_static_name && !element->data.var.name) {
      free_abstract_element(element);
      return false;
    }
  } else {
    element->data.path.path = strndup(text, length);
    element->data.path.is_absolute = text[0] == '/';
    element->data.path.ends_with_slash = length != 0 && text[length - 1] == '/';
    if (!element->data.path.path) {
      free_abstract_element(element);
      return false;
    }
  }

  elements[(*count)++] = element;
  compound_abstract_set_flag(command, type);
  return true;
}

static bool compound_abstract_append_substitution(
    shell_abstract_command_t *command, shell_abstract_element_t **elements,
    size_t capacity, size_t *count, shell_source_substitution_kind_t kind,
    const char *text, size_t length, size_t position, size_t *index) {
  if (!command || !elements || !count || !text || !index ||
      *count == capacity || length < 2)
    return false;

  size_t content_start = kind == SHELL_SOURCE_SUBST_BACKTICK ? 1 : 2;
  if (length < content_start + 1)
    return false;
  size_t content_length = length - content_start - 1;

  shell_abstract_element_t *element = calloc(1, sizeof(*element));
  if (!element)
    return false;
  element->type = SHELL_ABSTRACT_CS;
  element->original = strndup(text, length);
  element->abstraction = make_abstraction(SHELL_ABSTRACT_CS, ++*index);
  element->start = position;
  element->end = position + length;
  element->data.cmd_subst.content =
      strndup(text + content_start, content_length);
  if (!element->original || !element->abstraction ||
      !element->data.cmd_subst.content) {
    free_abstract_element(element);
    return false;
  }
  elements[(*count)++] = element;
  command->has_cmd_subst = true;
  return true;
}

/* Literal spans between or around variable expansions remain part of the same
 * shell word. Only path-shaped spans are independently abstracted. Keep this
 * helper shared by the allocation and emission passes so a final path suffix
 * cannot be displayed without a matching abstraction element. */
static bool compound_abstract_append_literal(
    shell_abstract_command_t *command, shell_abstract_element_t **elements,
    size_t capacity, size_t *count, const shell_token_t *token, size_t start,
    size_t end, size_t indices[SHELL_ABSTRACT_HP + 1]) {
  if (!token || start > end || end > token->length)
    return false;
  if (start == end)
    return true;
  shell_abstract_type_t type = get_abstract_type(
      SHELL_TOKEN_ARGUMENT, token->start + start, end - start);
  return !compound_abstract_type_is_path(type) ||
         compound_abstract_append(
             command, elements, capacity, count, type, token->start + start,
             end - start, token->position + start, token->is_quoted, indices);
}

static bool compound_abstract_count_literal(const shell_token_t *token,
                                            size_t start, size_t end,
                                            size_t *count) {
  if (!token || !count || start > end || end > token->length)
    return false;
  if (start == end)
    return true;
  shell_abstract_type_t type = get_abstract_type(
      SHELL_TOKEN_ARGUMENT, token->start + start, end - start);
  if (!compound_abstract_type_is_path(type))
    return true;
  if (*count == SIZE_MAX)
    return false;
  (*count)++;
  return true;
}

/* Count exactly the elements emitted for a variable-bearing shell word.  The
 * allocation pass must follow the same fragment rules as emission: a single
 * word such as `/a/$X/b/$Y/c` produces three path fragments and two variables,
 * not merely one token plus two expansions. */
static bool compound_abstract_element_count(const shell_token_t *token,
                                            size_t *count) {
  if (!token || !token->start || !count)
    return false;

  size_t total = 0;
  size_t literal_start = 0;
  bool found_span = false;
  compound_abstract_span_iterator_t iterator;
  compound_abstract_span_iterator_init(&iterator, token);
  compound_abstract_span_t span;
  while (compound_abstract_span_iterator_next(&iterator, &span)) {
    if (!compound_abstract_count_literal(token, literal_start, span.start,
                                         &total))
      return false;
    if (total == SIZE_MAX)
      return false;
    total++;
    found_span = true;
    literal_start = span.after;
  }
  if (found_span && !compound_abstract_count_literal(token, literal_start,
                                                     token->length, &total))
    return false;
  *count = total;
  return true;
}

/* --- MAIN ABSTRACTION FUNCTION --- */

static shell_abstract_status_t
abstract_command_parse_impl(const char *command, size_t command_length,
                            shell_abstract_command_t **out) {
  *out = NULL;

  // Tokenize the command first
  shell_command_t *cmds = NULL;
  size_t cmd_count = 0;

  switch (shell_tokenize_commands(command, command_length, &cmds, &cmd_count)) {
  case SHELL_TOKENIZE_OK:
    break;
  case SHELL_TOKENIZE_EINPUT:
    return SHELL_ABSTRACT_EINPUT;
  case SHELL_TOKENIZE_ENOMEM:
    return SHELL_ABSTRACT_ENOMEM;
  case SHELL_TOKENIZE_EOVERFLOW:
    return SHELL_ABSTRACT_EOVERFLOW;
  case SHELL_TOKENIZE_EPARSE:
  default:
    return SHELL_ABSTRACT_EPARSE;
  }

  if (cmd_count == 0 || cmds[0].token_count == 0) {
    shell_commands_free(cmds, cmd_count);
    return SHELL_ABSTRACT_EPARSE;
  }

  // Allocate output structure for the transformed command result.
  shell_abstract_command_t *abst = calloc(1, sizeof(shell_abstract_command_t));
  if (!abst) {
    shell_commands_free(cmds, cmd_count);
    return SHELL_ABSTRACT_ENOMEM;
  }

  abst->original = strndup(command, command_length);
  if (!abst->original) {
    shell_commands_free(cmds, cmd_count);
    free(abst);
    return SHELL_ABSTRACT_ENOMEM;
  }

  // Count abstractable tokens first
  size_t max_elements = 0;
  for (size_t c = 0; c < cmd_count; c++) {
    if (cmds[c].token_count > SIZE_MAX - max_elements) {
      shell_commands_free(cmds, cmd_count);
      free((void *)abst->original);
      free(abst);
      return SHELL_ABSTRACT_EOVERFLOW;
    }
    max_elements += cmds[c].token_count;
    for (size_t i = 0; i < cmds[c].token_count; i++) {
      const shell_token_t *token = &cmds[c].tokens[i];
      if ((token->type != SHELL_TOKEN_COMMAND &&
           token->type != SHELL_TOKEN_ARGUMENT) ||
          !token->start || !shell_tokenizer_token_has_variable(token))
        continue;
      size_t compound_elements = 0;
      if (!compound_abstract_element_count(token, &compound_elements) ||
          compound_elements == 0 ||
          compound_elements - 1 > SIZE_MAX - max_elements) {
        shell_commands_free(cmds, cmd_count);
        free((void *)abst->original);
        free(abst);
        return SHELL_ABSTRACT_EOVERFLOW;
      }
      /* `max_elements` already includes this lexical token. Replace that one
       * slot with the exact number of sub-elements that emission will append.
       */
      max_elements += compound_elements - 1;
    }
  }
  if (max_elements > SIZE_MAX / sizeof(shell_abstract_element_t *)) {
    shell_commands_free(cmds, cmd_count);
    free((void *)abst->original);
    free(abst);
    return SHELL_ABSTRACT_EOVERFLOW;
  }
  shell_abstract_element_t **elements =
      calloc(max_elements, sizeof(shell_abstract_element_t *));

  if (!elements) {
    shell_commands_free(cmds, cmd_count);
    free((void *)abst->original);
    free(abst);
    return SHELL_ABSTRACT_ENOMEM;
  }

  // Indices for each abstract type
  size_t idx_ev = 0, idx_pv = 0, idx_sv = 0;
  size_t idx_ap = 0, idx_rp = 0, idx_hp = 0;
  size_t idx_gb = 0, idx_cs = 0, idx_ar = 0, idx_str = 0, idx_rd = 0;
  size_t compound_indices[SHELL_ABSTRACT_HP + 1] = {0};

  size_t element_count = 0;
  bool allocation_failed = false;

  // Process every command stage. Token positions remain absolute offsets into
  // the original expression, so one sorted element list can represent the
  // complete pipeline or conditional sequence.
  for (size_t c = 0; c < cmd_count; c++) {
    shell_command_t *cmd = &cmds[c];
    bool redirect_operand = false;
    for (size_t i = 0; i < cmd->token_count; i++) {
      shell_token_t *tok = &cmd->tokens[i];

      if (is_redirection_token(tok->type)) {
        abst->has_redirects = true;
        redirect_operand = redirection_consumes_operand(tok);
        continue;
      }

      /* A simple word may combine a literal path prefix with one or more
       * parameters. Extract those spans independently without turning the
       * containing argv word into separate shell tokens. */
      if (!redirect_operand && token_needs_compound_variable_abstraction(tok)) {
        compound_indices[SHELL_ABSTRACT_EV] = idx_ev;
        compound_indices[SHELL_ABSTRACT_PV] = idx_pv;
        compound_indices[SHELL_ABSTRACT_SV] = idx_sv;
        compound_indices[SHELL_ABSTRACT_AP] = idx_ap;
        compound_indices[SHELL_ABSTRACT_RP] = idx_rp;
        compound_indices[SHELL_ABSTRACT_HP] = idx_hp;
        bool compound = false;
        size_t literal_start = 0;
        compound_abstract_span_iterator_t iterator;
        compound_abstract_span_iterator_init(&iterator, tok);
        compound_abstract_span_t span;
        while (compound_abstract_span_iterator_next(&iterator, &span)) {
          if (!compound_abstract_append_literal(
                  abst, elements, max_elements, &element_count, tok,
                  literal_start, span.start, compound_indices)) {
            allocation_failed = true;
            break;
          }

          if (span.type == COMPOUND_ABSTRACT_VARIABLE) {
            shell_abstract_variable_info_t variable = {0};
            if (!abstract_variable_info(tok->start + span.start,
                                        span.after - span.start, &variable) ||
                !compound_abstract_append(
                    abst, elements, max_elements, &element_count, variable.type,
                    tok->start + span.start, span.after - span.start,
                    tok->position + span.start, tok->is_quoted,
                    compound_indices)) {
              allocation_failed = true;
              break;
            }
          } else if (!compound_abstract_append_substitution(
                         abst, elements, max_elements, &element_count,
                         span.substitution_kind, tok->start + span.start,
                         span.after - span.start, tok->position + span.start,
                         &idx_cs)) {
            allocation_failed = true;
            break;
          }
          compound = true;
          literal_start = span.after;
        }
        if (compound && !allocation_failed &&
            !compound_abstract_append_literal(
                abst, elements, max_elements, &element_count, tok,
                literal_start, tok->length, compound_indices))
          allocation_failed = true;
        if (allocation_failed)
          break;
        if (compound) {
          idx_ev = compound_indices[SHELL_ABSTRACT_EV];
          idx_pv = compound_indices[SHELL_ABSTRACT_PV];
          idx_sv = compound_indices[SHELL_ABSTRACT_SV];
          idx_ap = compound_indices[SHELL_ABSTRACT_AP];
          idx_rp = compound_indices[SHELL_ABSTRACT_RP];
          idx_hp = compound_indices[SHELL_ABSTRACT_HP];
          if (shell_source_word_has_executable_substitution(tok->start,
                                                            tok->length))
            abst->has_cmd_subst = true;
          redirect_operand = false;
          continue;
        }
      }

      // Get abstract type for this token
      shell_abstract_type_t ab_type =
          redirect_operand
              ? SHELL_ABSTRACT_REDIR
              : get_abstract_type(tok->type, tok->start, tok->length);
      redirect_operand = false;

      if (ab_type < 0)
        continue; // Not abstractable

      // Determine index
      size_t idx = 0;
      switch (ab_type) {
      case SHELL_ABSTRACT_EV:
        idx = ++idx_ev;
        break;
      case SHELL_ABSTRACT_PV:
        idx = ++idx_pv;
        break;
      case SHELL_ABSTRACT_SV:
        idx = ++idx_sv;
        break;
      case SHELL_ABSTRACT_AP:
        idx = ++idx_ap;
        break;
      case SHELL_ABSTRACT_RP:
        idx = ++idx_rp;
        break;
      case SHELL_ABSTRACT_HP:
        idx = ++idx_hp;
        break;
      case SHELL_ABSTRACT_GB:
        idx = ++idx_gb;
        break;
      case SHELL_ABSTRACT_CS:
        idx = ++idx_cs;
        break;
      case SHELL_ABSTRACT_AR:
        idx = ++idx_ar;
        break;
      case SHELL_ABSTRACT_STR:
        idx = ++idx_str;
        break;
      case SHELL_ABSTRACT_REDIR:
        idx = ++idx_rd;
        break;
      default:
        continue;
      }

      // Create abstract element
      shell_abstract_element_t *elem =
          calloc(1, sizeof(shell_abstract_element_t));
      if (!elem) {
        allocation_failed = true;
        break;
      }

      elem->type = ab_type;
      // Make a copy of the original token text (null-terminated)
      elem->original = strndup(tok->start, tok->length);
      elem->start = tok->position;
      elem->end = tok->position + tok->length;
      elem->abstraction = make_abstraction(ab_type, idx);

      // Extract type-specific data
      switch (ab_type) {
      case SHELL_ABSTRACT_EV:
      case SHELL_ABSTRACT_PV:
      case SHELL_ABSTRACT_SV: {
        shell_abstract_variable_info_t variable = {0};
        if (!abstract_variable_info(tok->start, tok->length, &variable)) {
          free_abstract_element(elem);
          allocation_failed = true;
          elem = NULL;
          break;
        }
        bool has_static_name = false;
        elem->data.var.name = abstract_variable_name_copy(
            tok->start, tok->length, &has_static_name);
        elem->data.var.is_braced = variable.is_braced;
        elem->data.var.is_quoted = tok->is_quoted;
        break;
      }

      case SHELL_ABSTRACT_AP:
      case SHELL_ABSTRACT_RP:
      case SHELL_ABSTRACT_HP:
        elem->data.path.path = strndup(tok->start, tok->length);
        elem->data.path.is_absolute = (tok->start[0] == '/');
        elem->data.path.ends_with_slash =
            (tok->length > 0 && tok->start[tok->length - 1] == '/');
        break;

      case SHELL_ABSTRACT_GB:
        elem->data.glob.pattern = strndup(tok->start, tok->length);
        elem->data.glob.has_slash =
            (memchr(tok->start, '/', tok->length) != NULL);
        break;

      case SHELL_ABSTRACT_CS:
        // Extract content
        if (tok->length >= 4) {
          if (tok->start[1] == '(') {
            elem->data.cmd_subst.content =
                strndup(tok->start + 2, tok->length - 3);
          } else {
            elem->data.cmd_subst.content =
                strndup(tok->start + 1, tok->length - 2);
          }
        }
        break;

      case SHELL_ABSTRACT_AR:
        // Store content if needed
        if (tok->length >= 2) {
          elem->data.cmd_subst.content =
              strndup(tok->start + 1, tok->length - 2);
        }
        break;

      case SHELL_ABSTRACT_STR:
        /* ANSI-C quotes have a `$'` opener; retain their raw payload rather
         * than decoding it so the abstraction stays a source diagnostic. */
        if (tok->type == SHELL_TOKEN_ANSI_C_QUOTED) {
          if (tok->length >= 3)
            elem->data.cmd_subst.content =
                strndup(tok->start + 2, tok->length - 3);
        } else if (tok->length >= 2) {
          elem->data.cmd_subst.content =
              strndup(tok->start + 1, tok->length - 2);
        }
        break;

      default:
        break;
      }

      if (allocation_failed)
        break;

      bool detail_ok = true;
      switch (ab_type) {
      case SHELL_ABSTRACT_EV:
      case SHELL_ABSTRACT_PV:
      case SHELL_ABSTRACT_SV: {
        shell_abstract_variable_info_t variable = {0};
        detail_ok =
            elem &&
            abstract_variable_info(tok->start, tok->length, &variable) &&
            (!variable.has_static_name || elem->data.var.name != NULL);
        break;
      }
      case SHELL_ABSTRACT_AP:
      case SHELL_ABSTRACT_RP:
      case SHELL_ABSTRACT_HP:
        detail_ok = elem->data.path.path != NULL;
        break;
      case SHELL_ABSTRACT_GB:
        detail_ok = elem->data.glob.pattern != NULL;
        break;
      case SHELL_ABSTRACT_CS:
        detail_ok = tok->length < 4 || elem->data.cmd_subst.content != NULL;
        break;
      case SHELL_ABSTRACT_AR:
        detail_ok = tok->length < 2 || elem->data.cmd_subst.content != NULL;
        break;
      case SHELL_ABSTRACT_STR:
        detail_ok =
            (tok->type == SHELL_TOKEN_ANSI_C_QUOTED ? tok->length < 3
                                                    : tok->length < 2) ||
            elem->data.cmd_subst.content != NULL;
        break;
      default:
        break;
      }

      if (elem->original && elem->abstraction && detail_ok) {
        elements[element_count++] = elem;

        if (shell_source_word_has_executable_substitution(tok->start,
                                                          tok->length))
          abst->has_cmd_subst = true;

        // Set flags
        switch (ab_type) {
        case SHELL_ABSTRACT_EV:
          abst->has_variables = true;
          break;
        case SHELL_ABSTRACT_PV:
          abst->has_pos_vars = true;
          abst->has_variables = true;
          break;
        case SHELL_ABSTRACT_SV:
          abst->has_special_vars = true;
          abst->has_variables = true;
          break;
        case SHELL_ABSTRACT_AP:
          abst->has_abs_paths = true;
          abst->has_paths = true;
          break;
        case SHELL_ABSTRACT_RP:
          abst->has_rel_paths = true;
          abst->has_paths = true;
          break;
        case SHELL_ABSTRACT_HP:
          abst->has_home_paths = true;
          abst->has_paths = true;
          break;
        case SHELL_ABSTRACT_GB:
          abst->has_globs = true;
          break;
        case SHELL_ABSTRACT_CS:
          abst->has_cmd_subst = true;
          break;
        case SHELL_ABSTRACT_AR:
          abst->has_arithmetic = true;
          break;
        case SHELL_ABSTRACT_STR:
          abst->has_strings = true;
          break;
        case SHELL_ABSTRACT_REDIR:
          break;
        default:
          break;
        }
      } else {
        free_abstract_element(elem);
        allocation_failed = true;
        break;
      }
    }
    if (allocation_failed)
      break;
  }

  if (allocation_failed) {
    abst->elements = elements;
    abst->element_count = element_count;
    shell_commands_free(cmds, cmd_count);
    shell_abstract_command_free(abst);
    return SHELL_ABSTRACT_ENOMEM;
  }

  // Set elements in result
  abst->elements = elements;
  abst->element_count = element_count;

  // Sort elements by start position
  if (element_count > 0) {
    for (size_t i = 1; i < element_count; i++) {
      shell_abstract_element_t *key = elements[i];
      size_t j = i;
      while (j > 0 && elements[j - 1]->start > key->start) {
        elements[j] = elements[j - 1];
        j--;
      }
      elements[j] = key;
    }
  }

  // Build from the owned source and the original span length. The caller's
  // raw span need not have a NUL terminator.
  shell_abstract_status_t display_status =
      build_abstracted_command(abst->original, command_length, elements,
                               element_count, &abst->display_text);
  shell_commands_free(cmds, cmd_count);

  if (display_status != SHELL_ABSTRACT_OK) {
    shell_abstract_command_free(abst);
    return display_status;
  }

  *out = abst;
  return SHELL_ABSTRACT_OK;
}

shell_abstract_status_t
shell_abstract_command_parse(const char *command, size_t command_length,
                             shell_abstract_command_t **out) {
  if (out)
    *out = NULL;
  if (!command || !out || memchr(command, '\0', command_length) != NULL)
    return SHELL_ABSTRACT_EINPUT;
  if (shell_tokenizer_has_unsupported_semantics(command, command_length))
    return SHELL_ABSTRACT_EPARSE;
  return abstract_command_parse_impl(command, command_length, out);
}

/* --- QUERY FUNCTIONS --- */

const char *
shell_abstract_command_get_display_text(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->display_text : NULL;
}

const char *
shell_abstract_command_get_source(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->original : NULL;
}

const shell_abstract_element_t *const *
shell_abstract_command_get_elements(const shell_abstract_command_t *cmd,
                                    size_t *count) {
  if (count)
    *count = 0;
  if (!cmd || !count)
    return NULL;
  *count = cmd->element_count;
  return (const shell_abstract_element_t *const *)cmd->elements;
}

shell_abstract_element_t *const *
shell_abstract_command_get_mutable_elements(shell_abstract_command_t *cmd,
                                            size_t *count) {
  if (count)
    *count = 0;
  if (!cmd || !count)
    return NULL;
  *count = cmd->element_count;
  return cmd->elements;
}

shell_abstract_element_t *
shell_abstract_command_get_element(shell_abstract_command_t *cmd,
                                   size_t index) {
  if (!cmd || index >= cmd->element_count)
    return NULL;
  return cmd->elements[index];
}

bool shell_abstract_command_has_variables(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_variables : false;
}

bool shell_abstract_command_has_pos_vars(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_pos_vars : false;
}

bool shell_abstract_command_has_special_vars(
    const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_special_vars : false;
}

bool shell_abstract_command_has_globs(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_globs : false;
}

bool shell_abstract_command_has_paths(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_paths : false;
}

bool shell_abstract_command_has_abs_paths(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_abs_paths : false;
}

bool shell_abstract_command_has_rel_paths(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_rel_paths : false;
}

bool shell_abstract_command_has_home_paths(
    const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_home_paths : false;
}

bool shell_abstract_command_has_cmd_subst(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_cmd_subst : false;
}

bool shell_abstract_command_has_redirects(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_redirects : false;
}

bool shell_abstract_command_has_arithmetic(
    const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_arithmetic : false;
}

bool shell_abstract_command_has_strings(const shell_abstract_command_t *cmd) {
  return cmd ? cmd->has_strings : false;
}

shell_abstract_element_t *
shell_abstract_command_find_element(shell_abstract_command_t *cmd,
                                    const char *abstraction) {
  if (!cmd || !abstraction)
    return NULL;

  for (size_t i = 0; i < cmd->element_count; i++) {
    if (cmd->elements[i]->abstraction &&
        strcmp(cmd->elements[i]->abstraction, abstraction) == 0) {
      return cmd->elements[i];
    }
  }

  return NULL;
}

/* --- RUNTIME EXPANSION --- */

static char *finish_expanded_path(char *path,
                                  const shell_runtime_context_t *ctx) {
  if (!path || !ctx->resolve_symlinks)
    return path;

  char *resolved = realpath(path, NULL);
  free(path);
  return resolved;
}

static char *join_path(const char *base, const char *path) {
  size_t base_len = strlen(base);
  size_t path_len = strlen(path);
  bool needs_slash = base_len > 0 && base[base_len - 1] != '/';
  size_t extra = needs_slash ? 2 : 1;
  if (base_len > SIZE_MAX - path_len || base_len + path_len > SIZE_MAX - extra)
    return NULL;
  char *result = malloc(base_len + path_len + extra);
  if (!result)
    return NULL;
  memcpy(result, base, base_len);
  size_t position = base_len;
  if (needs_slash)
    result[position++] = '/';
  memcpy(result + position, path, path_len + 1);
  return result;
}

char *shell_abstract_element_expand(shell_abstract_element_t *elem,
                                    const shell_runtime_context_t *ctx) {
  if (!elem || !ctx)
    return NULL;

  switch (elem->type) {
  case SHELL_ABSTRACT_EV:
  case SHELL_ABSTRACT_PV:
  case SHELL_ABSTRACT_SV: {
    if (!elem->data.var.name)
      return NULL;

    // Look up in environment
    if (ctx->env) {
      size_t varlen = strlen(elem->data.var.name);
      for (size_t i = 0; ctx->env[i]; i++) {
        if (strncmp(ctx->env[i], elem->data.var.name, varlen) == 0 &&
            ctx->env[i][varlen] == '=') {
          return strdup(ctx->env[i] + varlen + 1);
        }
      }
    }
    return NULL;
  }

  case SHELL_ABSTRACT_HP: {
    if (!elem->data.path.path)
      return NULL;
    const char *path = elem->data.path.path;

    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
      const char *home = NULL;
      if (ctx->env) {
        for (size_t i = 0; ctx->env[i]; i++) {
          if (strncmp(ctx->env[i], "HOME=", 5) == 0) {
            home = ctx->env[i] + 5;
            break;
          }
        }
      }
      if (!home)
        return NULL;

      if (path[1] == '\0') {
        return finish_expanded_path(strdup(home), ctx);
      }
      return finish_expanded_path(join_path(home, path + 2), ctx);
    }
    return finish_expanded_path(strdup(path), ctx);
  }

  case SHELL_ABSTRACT_AP:
  case SHELL_ABSTRACT_RP: {
    if (!elem->data.path.path)
      return NULL;

    if (!elem->data.path.is_absolute && ctx->cwd) {
      return finish_expanded_path(join_path(ctx->cwd, elem->data.path.path),
                                  ctx);
    }
    return finish_expanded_path(strdup(elem->data.path.path), ctx);
  }

  default:
    return NULL;
  }
}

bool shell_abstract_command_expand(shell_abstract_command_t *cmd,
                                   const shell_runtime_context_t *ctx) {
  if (!cmd || !ctx)
    return false;

  for (size_t i = 0; i < cmd->element_count; i++) {
    if (cmd->elements[i]->expanded) {
      free(cmd->elements[i]->expanded);
      cmd->elements[i]->expanded = NULL;
    }

    cmd->elements[i]->expanded =
        shell_abstract_element_expand(cmd->elements[i], ctx);
  }

  return true;
}

/* --- UTILITY FUNCTIONS --- */

shell_path_category_t shell_path_category_from_path(const char *resolved_path) {
  if (!resolved_path || resolved_path[0] != '/') {
    return SHELL_PATH_OTHER;
  }

  // Skip leading /
  const char *p = resolved_path + 1;
  if (*p == '\0')
    return SHELL_PATH_ROOT;

  // Find first /
  const char *slash = strchr(p, '/');
  size_t first_comp_len = slash ? (size_t)(slash - p) : strlen(p);

  // Compare first component
  if (first_comp_len == 3 && strncmp(p, "etc", 3) == 0)
    return SHELL_PATH_ETC;
  if (first_comp_len == 3 && strncmp(p, "var", 3) == 0)
    return SHELL_PATH_VAR;
  if (first_comp_len == 3 && strncmp(p, "usr", 3) == 0)
    return SHELL_PATH_USR;
  if (first_comp_len == 4 && strncmp(p, "home", 4) == 0)
    return SHELL_PATH_HOME;
  if (first_comp_len == 4 && strncmp(p, "root", 4) == 0)
    return SHELL_PATH_HOME;
  if (first_comp_len == 3 && strncmp(p, "tmp", 3) == 0)
    return SHELL_PATH_TMP;
  if (first_comp_len == 4 && strncmp(p, "proc", 4) == 0)
    return SHELL_PATH_PROC;
  if (first_comp_len == 3 && strncmp(p, "sys", 3) == 0)
    return SHELL_PATH_SYS;
  if (first_comp_len == 3 && strncmp(p, "dev", 3) == 0)
    return SHELL_PATH_DEV;
  if (first_comp_len == 3 && strncmp(p, "opt", 3) == 0)
    return SHELL_PATH_OPT;
  if (first_comp_len == 3 && strncmp(p, "srv", 3) == 0)
    return SHELL_PATH_SRV;
  if (first_comp_len == 3 && strncmp(p, "run", 3) == 0)
    return SHELL_PATH_RUN;
  if (first_comp_len == 7 && strncmp(p, "sysroot", 7) == 0)
    return SHELL_PATH_SYSROOT;
  if (first_comp_len == 4 && strncmp(p, "boot", 4) == 0)
    return SHELL_PATH_BOOT;
  if (first_comp_len == 3 && strncmp(p, "mnt", 3) == 0)
    return SHELL_PATH_MNT;
  if (first_comp_len == 5 && strncmp(p, "media", 5) == 0)
    return SHELL_PATH_MEDIA;
  if (first_comp_len == 10 && strncmp(p, ".snapshots", 10) == 0)
    return SHELL_PATH_SNAPSHOT;

  return SHELL_PATH_OTHER;
}

const char *shell_abstract_type_name(shell_abstract_type_t type) {
  if (type >= 0 && type < (int)(sizeof(SHELL_ABSTRACT_TYPE_NAMES) /
                                sizeof(SHELL_ABSTRACT_TYPE_NAMES[0]))) {
    return SHELL_ABSTRACT_TYPE_NAMES[type];
  }
  return "UNKNOWN";
}

const char *shell_path_category_name(shell_path_category_t cat) {
  if (cat >= 0 && cat < (int)(sizeof(SHELL_PATH_CATEGORY_NAMES) /
                              sizeof(SHELL_PATH_CATEGORY_NAMES[0]))) {
    return SHELL_PATH_CATEGORY_NAMES[cat];
  }
  return "UNKNOWN";
}

/* --- CLEANUP --- */

void shell_abstract_command_free(shell_abstract_command_t *cmd) {
  if (!cmd)
    return;

  free((void *)cmd->original);
  free(cmd->display_text);

  if (cmd->elements) {
    for (size_t i = 0; i < cmd->element_count; i++) {
      shell_abstract_element_t *elem = cmd->elements[i];
      free_abstract_element(elem);
    }
    free(cmd->elements);
  }

  free(cmd);
}

/* --- LIGHTWEIGHT TYPE SEQUENCE GENERATION --- */

static const char *token_abbreviation(const shell_token_t *token) {
  if (token->length >= 2 && token->start[0] == '-')
    return "OPT";
  shell_abstract_type_t type =
      get_abstract_type(token->type, token->start, token->length);
  switch (type) {
  case SHELL_ABSTRACT_EV:
    return "EV";
  case SHELL_ABSTRACT_PV:
    return "PV";
  case SHELL_ABSTRACT_SV:
    return "SV";
  case SHELL_ABSTRACT_AP:
    return "AP";
  case SHELL_ABSTRACT_RP:
    return "RP";
  case SHELL_ABSTRACT_HP:
    return "HP";
  case SHELL_ABSTRACT_GB:
    return "GB";
  case SHELL_ABSTRACT_CS:
    return "CS";
  case SHELL_ABSTRACT_AR:
    return "AR";
  case SHELL_ABSTRACT_REDIR:
    return "RD";
  case SHELL_ABSTRACT_STR:
  default:
    return "STR";
  }
}

static shell_process_status_t
shell_build_type_netseq_impl(const char *command, size_t command_length,
                             const shell_process_limits_t *limits,
                             char **netseq, size_t *netseq_length,
                             size_t *subcommand_count) {
  if (netseq)
    *netseq = NULL;
  if (netseq_length)
    *netseq_length = 0;
  if (subcommand_count)
    *subcommand_count = 0;
  if (!command || !netseq || !subcommand_count)
    return SHELL_PROCESS_EINPUT;

  shell_anomaly_stages_t stages = {0};
  shell_process_status_t status =
      shell_anomaly_stages_parse(command, command_length, limits, &stages);
  if (status != SHELL_PROCESS_OK)
    return status;

  size_t outer_length = 0;
  size_t rendered_count = 0;
  for (size_t c = 0; c < stages.count; c++) {
    shell_processed_word_iterator_t iterator;
    shell_processed_word_iterator_init(&iterator, &stages.commands[c]);
    shell_token_t word;
    if (!shell_processed_word_iterator_next(&iterator, &word)) {
      /* A redirect-only simple command has no executable. Preserve it as an
       * anomaly-only netargv whose argv[0] is the canonical empty word. */
      size_t inner_length = 0;
      size_t framed = 0;
      if (shell_netstring_encoded_length(0, &inner_length) !=
              SHELL_NETSTRING_OK ||
          shell_netstring_encoded_length(inner_length, &framed) !=
              SHELL_NETSTRING_OK ||
          outer_length > SIZE_MAX - framed) {
        status = SHELL_PROCESS_EOVERFLOW;
        goto fail_type_netseq;
      }
      outer_length += framed;
      rendered_count++;
      continue;
    }
    size_t inner_length = 0;
    size_t decoded_length = 0;
    status =
        shell_measure_decoded_word(word.start, word.length, &decoded_length);
    if (status != SHELL_PROCESS_OK)
      goto fail_type_netseq;
    if (decoded_length == 0) {
      status = SHELL_PROCESS_EPARSE;
      goto fail_type_netseq;
    }
    if (shell_netstring_encoded_length(decoded_length, &inner_length) !=
        SHELL_NETSTRING_OK) {
      status = SHELL_PROCESS_EOVERFLOW;
      goto fail_type_netseq;
    }
    while (shell_processed_word_iterator_next(&iterator, &word)) {
      const char *abbreviation = token_abbreviation(&word);
      size_t length = strlen(abbreviation);
      size_t framed = 0;
      if (shell_netstring_encoded_length(length, &framed) !=
              SHELL_NETSTRING_OK ||
          inner_length > SIZE_MAX - framed) {
        status = SHELL_PROCESS_EOVERFLOW;
        goto fail_type_netseq;
      }
      inner_length += framed;
    }
    size_t framed = 0;
    if (shell_netstring_encoded_length(inner_length, &framed) !=
        SHELL_NETSTRING_OK) {
      status = SHELL_PROCESS_EOVERFLOW;
      goto fail_type_netseq;
    }
    if (outer_length > SIZE_MAX - framed) {
      status = SHELL_PROCESS_EOVERFLOW;
      goto fail_type_netseq;
    }
    outer_length += framed;
    rendered_count++;
  }
  if (limits && (outer_length > limits->max_string_bytes ||
                 outer_length > limits->max_total_bytes)) {
    status = SHELL_PROCESS_EOUTPUT_LIMIT;
    goto fail_type_netseq;
  }
  size_t outer_allocation_size = 0;
  status = shell_process_cstring_allocation_size(outer_length,
                                                 &outer_allocation_size);
  if (status != SHELL_PROCESS_OK)
    goto fail_type_netseq;
  char *outer = malloc(outer_allocation_size);
  if (!outer) {
    status = SHELL_PROCESS_ENOMEM;
    goto fail_type_netseq;
  }
  char *position = outer;
  for (size_t c = 0; c < stages.count; c++) {
    shell_processed_word_iterator_t iterator;
    shell_processed_word_iterator_init(&iterator, &stages.commands[c]);
    shell_token_t word;
    if (!shell_processed_word_iterator_next(&iterator, &word)) {
      size_t inner_length = 0;
      size_t outer_prefix = 0;
      size_t argv0_prefix = 0;
      (void)shell_netstring_encoded_length(0, &inner_length);
      (void)shell_netstring_write_prefix(position, SIZE_MAX, inner_length,
                                         &outer_prefix);
      position += outer_prefix;
      (void)shell_netstring_write_prefix(position, SIZE_MAX, 0, &argv0_prefix);
      position += argv0_prefix;
      *position++ = ',';
      *position++ = ',';
      continue;
    }
    size_t inner_length = 0;
    size_t decoded_length = 0;
    (void)shell_measure_decoded_word(word.start, word.length, &decoded_length);
    (void)shell_netstring_encoded_length(decoded_length, &inner_length);
    shell_processed_word_iterator_t sizing = iterator;
    shell_token_t argument;
    while (shell_processed_word_iterator_next(&sizing, &argument)) {
      size_t length = strlen(token_abbreviation(&argument));
      size_t framed = 0;
      (void)shell_netstring_encoded_length(length, &framed);
      inner_length += framed;
    }
    size_t outer_prefix = 0, executable_prefix = 0;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, inner_length,
                                       &outer_prefix);
    position += outer_prefix;
    (void)shell_netstring_write_prefix(position, SIZE_MAX, decoded_length,
                                       &executable_prefix);
    position += executable_prefix;
    size_t written = 0;
    (void)shell_write_decoded_word(word.start, word.length, position,
                                   decoded_length, &written);
    position += written;
    *position++ = ',';
    while (shell_processed_word_iterator_next(&iterator, &argument)) {
      const char *abbreviation = token_abbreviation(&argument);
      size_t length = strlen(abbreviation);
      size_t prefix = 0;
      (void)shell_netstring_write_prefix(position, SIZE_MAX, length, &prefix);
      position += prefix;
      memcpy(position, abbreviation, length);
      position += length;
      *position++ = ',';
    }
    *position++ = ',';
  }
  *position = '\0';
  shell_anomaly_stages_free(&stages);
  *netseq = outer;
  if (netseq_length)
    *netseq_length = outer_length;
  *subcommand_count = rendered_count;
  return SHELL_PROCESS_OK;

fail_type_netseq:
  shell_anomaly_stages_free(&stages);
  return status;
}

shell_process_status_t
shell_build_type_netseq(const char *command, size_t command_length,
                        const shell_process_limits_t *limits, char **netseq,
                        size_t *subcommand_count) {
  size_t length = 0;
  shell_process_status_t status = shell_build_type_netseq_impl(
      command, command_length, limits, netseq, &length, subcommand_count);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (memchr(*netseq, '\0', length)) {
    free(*netseq);
    *netseq = NULL;
    *subcommand_count = 0;
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
  return SHELL_PROCESS_OK;
}

shell_process_status_t
shell_build_type_netseq_buffer(const char *command, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_netstring_buffer_t *sequence,
                               size_t *subcommand_count) {
  if (!shell_netstring_buffer_is_empty(sequence) || !subcommand_count)
    return SHELL_PROCESS_EINPUT;
  char *encoded = NULL;
  size_t length = 0;
  shell_process_status_t status = shell_build_type_netseq_impl(
      command, command_length, limits, &encoded, &length, subcommand_count);
  if (status != SHELL_PROCESS_OK)
    return status;
  sequence->data = (unsigned char *)encoded;
  sequence->length = length;
  return SHELL_PROCESS_OK;
}

static shell_process_status_t shell_build_anomaly_netseqs_impl(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, char **command_netseq,
    size_t *command_length_out, char **type_netseq, size_t *type_length_out,
    size_t *subcommand_count) {
  if (command_netseq)
    *command_netseq = NULL;
  if (command_length_out)
    *command_length_out = 0;
  if (type_netseq)
    *type_netseq = NULL;
  if (type_length_out)
    *type_length_out = 0;
  if (subcommand_count)
    *subcommand_count = 0;
  if (!command_line || !command_netseq || !type_netseq || !subcommand_count)
    return SHELL_PROCESS_EINPUT;

  shell_anomaly_stages_t stages = {0};
  shell_process_status_t status =
      shell_anomaly_stages_parse(command_line, command_length, limits, &stages);
  if (status != SHELL_PROCESS_OK)
    return status;

  size_t command_total = 0;
  size_t type_total = 0;
  size_t rendered_count = 0;
  for (size_t c = 0; c < stages.count; c++) {
    shell_processed_word_iterator_t iterator;
    shell_processed_word_iterator_init(&iterator, &stages.commands[c]);
    shell_token_t word;
    if (!shell_processed_word_iterator_next(&iterator, &word)) {
      size_t raw_record_length = 0;
      size_t type_inner_length = 0;
      size_t type_record_length = 0;
      if (shell_netstring_encoded_length(0, &raw_record_length) !=
              SHELL_NETSTRING_OK ||
          command_total > SIZE_MAX - raw_record_length ||
          shell_netstring_encoded_length(0, &type_inner_length) !=
              SHELL_NETSTRING_OK ||
          shell_netstring_encoded_length(
              type_inner_length, &type_record_length) != SHELL_NETSTRING_OK ||
          type_total > SIZE_MAX - type_record_length) {
        status = SHELL_PROCESS_EOVERFLOW;
        goto fail;
      }
      command_total += raw_record_length;
      type_total += type_record_length;
      rendered_count++;
      continue;
    }
    size_t executable_length = 0;
    status =
        shell_measure_decoded_word(word.start, word.length, &executable_length);
    if (status != SHELL_PROCESS_OK || executable_length == 0) {
      if (status == SHELL_PROCESS_OK)
        status = SHELL_PROCESS_EPARSE;
      goto fail;
    }
    size_t raw_record_length = 0;
    if (shell_netstring_encoded_length(executable_length, &raw_record_length) !=
            SHELL_NETSTRING_OK ||
        command_total > SIZE_MAX - raw_record_length) {
      status = SHELL_PROCESS_EOVERFLOW;
      goto fail;
    }
    command_total += raw_record_length;

    size_t type_inner_length = raw_record_length;
    while (shell_processed_word_iterator_next(&iterator, &word)) {
      size_t abbreviation_length = strlen(token_abbreviation(&word));
      size_t record_length = 0;
      if (shell_netstring_encoded_length(abbreviation_length, &record_length) !=
              SHELL_NETSTRING_OK ||
          type_inner_length > SIZE_MAX - record_length) {
        status = SHELL_PROCESS_EOVERFLOW;
        goto fail;
      }
      type_inner_length += record_length;
    }
    size_t type_record_length = 0;
    if (shell_netstring_encoded_length(
            type_inner_length, &type_record_length) != SHELL_NETSTRING_OK ||
        type_total > SIZE_MAX - type_record_length) {
      status = SHELL_PROCESS_EOVERFLOW;
      goto fail;
    }
    type_total += type_record_length;
    rendered_count++;
  }
  if (limits && (command_total > limits->max_string_bytes ||
                 command_total > limits->max_total_bytes ||
                 type_total > limits->max_string_bytes ||
                 type_total > limits->max_total_bytes)) {
    status = SHELL_PROCESS_EOUTPUT_LIMIT;
    goto fail;
  }

  size_t raw_allocation_size = 0;
  size_t typed_allocation_size = 0;
  status = shell_process_cstring_allocation_size(command_total,
                                                 &raw_allocation_size);
  if (status != SHELL_PROCESS_OK)
    goto fail;
  status =
      shell_process_cstring_allocation_size(type_total, &typed_allocation_size);
  if (status != SHELL_PROCESS_OK)
    goto fail;
  char *raw = malloc(raw_allocation_size);
  char *typed = malloc(typed_allocation_size);
  if (!raw || !typed) {
    free(raw);
    free(typed);
    status = SHELL_PROCESS_ENOMEM;
    goto fail;
  }

  char *raw_position = raw;
  char *type_position = typed;
  for (size_t c = 0; c < stages.count; c++) {
    shell_processed_word_iterator_t iterator;
    shell_processed_word_iterator_init(&iterator, &stages.commands[c]);
    shell_token_t word;
    if (!shell_processed_word_iterator_next(&iterator, &word)) {
      size_t prefix_length = 0;
      (void)shell_netstring_write_prefix(raw_position, SIZE_MAX, 0,
                                         &prefix_length);
      raw_position += prefix_length;
      *raw_position++ = ',';

      size_t type_inner_length = 0;
      (void)shell_netstring_encoded_length(0, &type_inner_length);
      (void)shell_netstring_write_prefix(type_position, SIZE_MAX,
                                         type_inner_length, &prefix_length);
      type_position += prefix_length;
      (void)shell_netstring_write_prefix(type_position, SIZE_MAX, 0,
                                         &prefix_length);
      type_position += prefix_length;
      *type_position++ = ',';
      *type_position++ = ',';
      continue;
    }
    size_t executable_length = 0;
    (void)shell_measure_decoded_word(word.start, word.length,
                                     &executable_length);
    size_t type_inner_length = 0;
    (void)shell_netstring_encoded_length(executable_length, &type_inner_length);
    shell_processed_word_iterator_t sizing = iterator;
    shell_token_t argument;
    while (shell_processed_word_iterator_next(&sizing, &argument)) {
      size_t abbreviation_length = strlen(token_abbreviation(&argument));
      size_t record_length = 0;
      (void)shell_netstring_encoded_length(abbreviation_length, &record_length);
      type_inner_length += record_length;
    }
    size_t prefix_length = 0;
    (void)shell_netstring_write_prefix(raw_position, SIZE_MAX,
                                       executable_length, &prefix_length);
    char *raw_payload = raw_position + prefix_length;
    size_t written = 0;
    (void)shell_write_decoded_word(word.start, word.length, raw_payload,
                                   executable_length, &written);
    raw_position = raw_payload + written;
    *raw_position++ = ',';

    size_t type_prefix_length = 0;
    (void)shell_netstring_write_prefix(type_position, SIZE_MAX,
                                       type_inner_length, &type_prefix_length);
    type_position += type_prefix_length;
    (void)shell_netstring_write_prefix(type_position, SIZE_MAX,
                                       executable_length, &prefix_length);
    char *type_payload = type_position + prefix_length;
    (void)shell_write_decoded_word(word.start, word.length, type_payload,
                                   executable_length, &written);
    type_position = type_payload + written;
    *type_position++ = ',';
    while (shell_processed_word_iterator_next(&iterator, &argument)) {
      const char *abbreviation = token_abbreviation(&argument);
      size_t abbreviation_length = strlen(abbreviation);
      (void)shell_netstring_write_prefix(type_position, SIZE_MAX,
                                         abbreviation_length, &prefix_length);
      type_position += prefix_length;
      memcpy(type_position, abbreviation, abbreviation_length);
      type_position += abbreviation_length;
      *type_position++ = ',';
    }
    *type_position++ = ',';
  }
  *raw_position = '\0';
  *type_position = '\0';
  shell_anomaly_stages_free(&stages);
  *command_netseq = raw;
  *type_netseq = typed;
  if (command_length_out)
    *command_length_out = command_total;
  if (type_length_out)
    *type_length_out = type_total;
  *subcommand_count = rendered_count;
  return SHELL_PROCESS_OK;

fail:
  shell_anomaly_stages_free(&stages);
  return status;
}

shell_process_status_t
shell_build_anomaly_netseqs(const char *command_line, size_t command_length,
                            const shell_process_limits_t *limits,
                            char **command_netseq, char **type_netseq,
                            size_t *subcommand_count) {
  if (!command_netseq || !type_netseq || command_netseq == type_netseq)
    return SHELL_PROCESS_EINPUT;
  size_t command_length_out = 0;
  size_t type_length_out = 0;
  shell_process_status_t status = shell_build_anomaly_netseqs_impl(
      command_line, command_length, limits, command_netseq, &command_length_out,
      type_netseq, &type_length_out, subcommand_count);
  if (status != SHELL_PROCESS_OK)
    return status;
  if (memchr(*command_netseq, '\0', command_length_out) ||
      memchr(*type_netseq, '\0', type_length_out)) {
    free(*command_netseq);
    free(*type_netseq);
    *command_netseq = NULL;
    *type_netseq = NULL;
    *subcommand_count = 0;
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
  return SHELL_PROCESS_OK;
}

shell_process_status_t shell_build_anomaly_netseqs_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *command,
    shell_netstring_buffer_t *type, size_t *subcommand_count) {
  if (!shell_netstring_buffer_is_empty(command) ||
      !shell_netstring_buffer_is_empty(type) || command == type)
    return SHELL_PROCESS_EINPUT;
  char *raw = NULL;
  char *typed = NULL;
  size_t raw_length = 0;
  size_t typed_length = 0;
  shell_process_status_t status = shell_build_anomaly_netseqs_impl(
      command_line, command_length, limits, &raw, &raw_length, &typed,
      &typed_length, subcommand_count);
  if (status != SHELL_PROCESS_OK)
    return status;
  command->data = (unsigned char *)raw;
  command->length = raw_length;
  type->data = (unsigned char *)typed;
  type->length = typed_length;
  return SHELL_PROCESS_OK;
}
