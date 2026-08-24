#define _XOPEN_SOURCE 700
#include "shell_abstract.h"
#include "alloc.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_tokenizer_full.h"
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- Internal Helpers --- */

static const char *ABSTRACT_TYPE_NAMES[] = {"EV", "PV", "SV", "AP",  "RP", "HP",
                                            "GB", "CS", "AR", "STR", "RD"};

static const char *PATH_CATEGORY_NAMES[] = {
    "ROOT",    "ETC",  "VAR", "USR",   "HOME",     "TMP",
    "PROC",    "SYS",  "DEV", "OPT",   "SRV",      "RUN",
    "SYSROOT", "BOOT", "MNT", "MEDIA", "SNAPSHOT", "OTHER"};

/* --- Token Classification Helpers --- */

/**
 * Check if string is a special variable ($?, $$, $#, etc.)
 */
static bool is_special_variable(const char *s, size_t len) {
  return len == 1 && strchr("?$#-!@*", s[0]) != NULL;
}

/**
 * Check if string is a positional variable ($1, $2, etc.)
 */
static bool is_positional_variable(const char *s, size_t len) {
  if (len < 2 || s[0] != '$')
    return false;

  // ${10} form
  if (s[1] == '{') {
    if (len < 4 || s[len - 1] != '}')
      return false;
    for (size_t i = 2; i < len - 1; i++) {
      if (!isdigit((unsigned char)s[i]))
        return false;
    }
    return true;
  }

  // Pure digits after $
  for (size_t i = 1; i < len; i++) {
    if (!isdigit((unsigned char)s[i]))
      return false;
  }
  return len > 1;
}

/**
 * Check if string is an environment variable reference ($VAR, ${VAR})
 */
static bool is_env_variable(const char *s, size_t len) {
  if (len < 2 || s[0] != '$')
    return false;
  if (s[1] == '{') {
    // ${VAR}
    return len >= 4 && s[len - 1] == '}';
  } else if (s[1] == '(' || s[1] == '`') {
    // Command substitution, not variable
    return false;
  } else if (isdigit((unsigned char)s[1])) {
    // Positional variable $1, $2 - handled separately
    return false;
  } else if (is_special_variable(s + 1, len - 1)) {
    // Special like $? - handled separately
    return false;
  } else {
    // $VAR
    return isalpha((unsigned char)s[1]) || s[1] == '_';
  }
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

static bool is_redirection_token(token_type_t type) {
  return type == TOKEN_REDIRECT_IN || type == TOKEN_REDIRECT_OUT ||
         type == TOKEN_REDIRECT_ERR || type == TOKEN_REDIRECT_APPEND ||
         type == TOKEN_HEREDOC || type == TOKEN_HERESTRING;
}

static bool redirection_consumes_operand(const shell_token_t *token) {
  if (token->type == TOKEN_HERESTRING)
    return true;
  if (token->type == TOKEN_HEREDOC || token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
}

/**
 * Classify a raw token string
 */
token_type_t shell_classify_raw_token(const char *text, size_t len) {
  if (!text || len == 0)
    return TOKEN_END;

  // Handle quoted strings
  if ((text[0] == '"' && text[len - 1] == '"') ||
      (text[0] == '\'' && text[len - 1] == '\'')) {
    return TOKEN_ARGUMENT; // Will be treated as string in abstraction
  }

  // Arithmetic must be checked before command substitution because $((...))
  // also has the outer $(...) shape.
  if (len >= 5 && text[0] == '$' && text[1] == '(' && text[2] == '(' &&
      text[len - 1] == ')' && text[len - 2] == ')') {
    return TOKEN_ARITHMETIC;
  }

  // Command substitution: $(...) or `...`
  if (len >= 4) {
    if (text[0] == '$' && text[1] == '(' && text[len - 1] == ')') {
      return TOKEN_SUBSHELL;
    }
    if (text[0] == '`' && text[len - 1] == '`') {
      return TOKEN_SUBSHELL;
    }
  }

  // Variables
  if (text[0] == '$') {
    if (is_positional_variable(text, len)) {
      return TOKEN_SPECIAL_VAR; // Use special var type for $1, $2
    }
    if (is_special_variable(text + 1, len - 1)) {
      return TOKEN_SPECIAL_VAR;
    }
    if (is_env_variable(text, len)) {
      return TOKEN_VARIABLE;
    }
    return TOKEN_ARGUMENT;
  }

  // Paths (before checking options since - could be a path component)
  if (is_absolute_path(text, len)) {
    return TOKEN_ARGUMENT; // Will be classified as path in abstraction
  }
  if (is_home_path(text, len)) {
    return TOKEN_ARGUMENT;
  }
  if (is_relative_path(text, len)) {
    return TOKEN_ARGUMENT;
  }

  // Glob patterns
  if (is_glob_pattern(text, len)) {
    return TOKEN_GLOB;
  }

  // Options
  if (is_long_option(text, len)) {
    return TOKEN_ARGUMENT;
  }
  if (is_short_option(text, len)) {
    return TOKEN_ARGUMENT;
  }

  return TOKEN_ARGUMENT;
}

/* --- ABSTRACTION HELPERS --- */

/**
 * Create abstraction string for a type and index
 */
static char *make_abstraction(abstract_type_t type, size_t index) {
  const char *type_str = ABSTRACT_TYPE_NAMES[type];
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
 * Extract variable name from token text
 */
static char *extract_var_name(const char *text, size_t len) {
  if (len < 2 || text[0] != '$')
    return NULL;

  // ${VAR} form
  if (text[1] == '{') {
    return strndup(text + 2, len - 3);
  }

  // Just $VAR or $1 etc
  return strndup(text + 1, len - 1);
}

/**
 * Determine abstract type from token type and classify path
 */
static abstract_type_t get_abstract_type(token_type_t tok_type,
                                         const char *text, size_t len) {
  // Handle known types from tokenizer directly
  switch (tok_type) {
  case TOKEN_VARIABLE:
  case TOKEN_VARIABLE_QUOTED:
    // Check if this is a braced positional variable: ${1}, ${10}, etc.
    if (len >= 4 && text[1] == '{' && text[len - 1] == '}') {
      // Check if the content is digits
      bool all_digits = true;
      for (size_t i = 2; i < len - 1; i++) {
        if (!isdigit((unsigned char)text[i])) {
          all_digits = false;
          break;
        }
      }
      if (all_digits) {
        return ABSTRACT_PV;
      }
      return ABSTRACT_EV; // ${VAR} - environment variable
    }
    // Check if positional variable: $1, $2, $10, etc.
    if (len >= 2 && isdigit((unsigned char)(text[1]))) {
      return ABSTRACT_PV;
    }
    // Default: environment variable $VAR
    return ABSTRACT_EV;

  case TOKEN_SPECIAL_VAR:
    // Check if positional ($1, $2) - tokenizer returns SPECIAL_VAR for these
    if (len >= 2 && isdigit((unsigned char)(text[1]))) {
      return ABSTRACT_PV;
    }
    return ABSTRACT_SV;

  case TOKEN_GLOB:
    return ABSTRACT_GB;

  case TOKEN_SUBSHELL:
  case TOKEN_PROCESS_SUB:
    return ABSTRACT_CS;

  case TOKEN_ARITHMETIC:
    return ABSTRACT_AR;

  default:
    break;
  }

  // For TOKEN_COMMAND and TOKEN_ARGUMENT, do path classification
  if (tok_type == TOKEN_COMMAND || tok_type == TOKEN_ARGUMENT) {
    // Check for quoted strings first
    if ((text[0] == '"' && text[len - 1] == '"') ||
        (text[0] == '\'' && text[len - 1] == '\'')) {
      return ABSTRACT_STR;
    }
    // Check glob before path (path check catches relative paths with /)
    if (is_glob_pattern(text, len)) {
      return ABSTRACT_GB;
    }
    if (is_absolute_path(text, len)) {
      return ABSTRACT_AP;
    }
    if (is_home_path(text, len)) {
      return ABSTRACT_HP;
    }
    if (is_relative_path(text, len)) {
      return ABSTRACT_RP;
    }
  }

  return -1; // Not abstractable
}

/* --- BUILD ABSTRACTED COMMAND --- */

/**
 * Build the abstracted command string from sorted elements
 */
static char *build_abstracted_command(const char *original,
                                      abstract_element_t **elements,
                                      size_t element_count) {
  if (!original)
    return strdup("");

  size_t orig_len = strlen(original);
  if (element_count == 0) {
    return strdup(original);
  }

  // Compute required output size, including abstracted segments and untouched
  // spans.
  size_t output_size = 1; // null terminator
  for (size_t i = 0; i < element_count; i++) {
    size_t length = strlen(elements[i]->abstraction);
    if (length > SIZE_MAX - output_size)
      return NULL;
    output_size += length;
  }

  // Add non-abstracted parts
  size_t last_end = 0;
  for (size_t i = 0; i < element_count; i++) {
    if (elements[i]->start > last_end) {
      size_t length = elements[i]->start - last_end;
      if (length > SIZE_MAX - output_size)
        return NULL;
      output_size += length;
    }
    last_end = elements[i]->end;
  }
  if (last_end < orig_len) {
    size_t length = orig_len - last_end;
    if (length > SIZE_MAX - output_size)
      return NULL;
    output_size += length;
  }

  char *result = malloc(output_size);
  if (!result)
    return NULL;

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
  if (src < orig_len) {
    memcpy(result + dst, original + src, orig_len - src);
    dst += orig_len - src;
  }

  result[dst] = '\0';
  return result;
}

static void free_abstract_element(abstract_element_t *elem) {
  if (!elem)
    return;
  free(elem->abstraction);
  free((void *)elem->original);
  switch (elem->type) {
  case ABSTRACT_EV:
  case ABSTRACT_PV:
  case ABSTRACT_SV:
    free(elem->data.var.name);
    break;
  case ABSTRACT_AP:
  case ABSTRACT_RP:
  case ABSTRACT_HP:
    free(elem->data.path.path);
    break;
  case ABSTRACT_GB:
    free(elem->data.glob.pattern);
    break;
  case ABSTRACT_CS:
  case ABSTRACT_AR:
  case ABSTRACT_STR:
    free(elem->data.cmd_subst.content);
    break;
  default:
    break;
  }
  free(elem->expanded);
  free(elem);
}

/* --- MAIN ABSTRACTION FUNCTION --- */

bool shell_abstract_command(const char *command,
                            abstracted_command_t **result) {
  if (!result)
    return false;
  *result = NULL;
  if (!command)
    return false;

  // Tokenize the command first
  shell_command_t *cmds = NULL;
  size_t cmd_count = 0;

  if (!shell_tokenize_commands(command, &cmds, &cmd_count)) {
    return false;
  }

  if (cmd_count == 0 || cmds[0].token_count == 0) {
    shell_free_commands(cmds, cmd_count);
    *result = NULL;
    return false;
  }

  // Allocate output structure for the transformed command result.
  abstracted_command_t *abst = calloc(1, sizeof(abstracted_command_t));
  if (!abst) {
    shell_free_commands(cmds, cmd_count);
    return false;
  }

  abst->original = strdup(command);
  if (!abst->original) {
    shell_free_commands(cmds, cmd_count);
    free(abst);
    return false;
  }

  // Count abstractable tokens first
  size_t max_elements = 0;
  for (size_t c = 0; c < cmd_count; c++) {
    if (cmds[c].token_count > SIZE_MAX - max_elements) {
      shell_free_commands(cmds, cmd_count);
      free((void *)abst->original);
      free(abst);
      return false;
    }
    max_elements += cmds[c].token_count;
  }
  abstract_element_t **elements =
      calloc(max_elements, sizeof(abstract_element_t *));

  if (!elements) {
    shell_free_commands(cmds, cmd_count);
    free((void *)abst->original);
    free(abst);
    return false;
  }

  // Indices for each abstract type
  size_t idx_ev = 0, idx_pv = 0, idx_sv = 0;
  size_t idx_ap = 0, idx_rp = 0, idx_hp = 0;
  size_t idx_gb = 0, idx_cs = 0, idx_ar = 0, idx_str = 0, idx_rd = 0;

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

      // Get abstract type for this token
      abstract_type_t ab_type =
          redirect_operand
              ? ABSTRACT_REDIR
              : get_abstract_type(tok->type, tok->start, tok->length);
      redirect_operand = false;

      if (ab_type < 0)
        continue; // Not abstractable

      // Determine index
      size_t idx = 0;
      switch (ab_type) {
      case ABSTRACT_EV:
        idx = ++idx_ev;
        break;
      case ABSTRACT_PV:
        idx = ++idx_pv;
        break;
      case ABSTRACT_SV:
        idx = ++idx_sv;
        break;
      case ABSTRACT_AP:
        idx = ++idx_ap;
        break;
      case ABSTRACT_RP:
        idx = ++idx_rp;
        break;
      case ABSTRACT_HP:
        idx = ++idx_hp;
        break;
      case ABSTRACT_GB:
        idx = ++idx_gb;
        break;
      case ABSTRACT_CS:
        idx = ++idx_cs;
        break;
      case ABSTRACT_AR:
        idx = ++idx_ar;
        break;
      case ABSTRACT_STR:
        idx = ++idx_str;
        break;
      case ABSTRACT_REDIR:
        idx = ++idx_rd;
        break;
      default:
        continue;
      }

      // Create abstract element
      abstract_element_t *elem = calloc(1, sizeof(abstract_element_t));
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
      case ABSTRACT_EV:
      case ABSTRACT_PV:
      case ABSTRACT_SV: {
        const char *variable = tok->start;
        size_t variable_len = tok->length;
        elem->data.var.is_quoted = tok->is_quoted;
        if (tok->is_quoted && variable_len >= 2 &&
            ((variable[0] == '"' && variable[variable_len - 1] == '"') ||
             (variable[0] == '\'' && variable[variable_len - 1] == '\''))) {
          variable++;
          variable_len -= 2;
        }
        elem->data.var.name = extract_var_name(variable, variable_len);
        elem->data.var.is_braced = variable_len >= 2 && variable[1] == '{';
        break;
      }

      case ABSTRACT_AP:
      case ABSTRACT_RP:
      case ABSTRACT_HP:
        elem->data.path.path = strndup(tok->start, tok->length);
        elem->data.path.is_absolute = (tok->start[0] == '/');
        elem->data.path.ends_with_slash =
            (tok->length > 0 && tok->start[tok->length - 1] == '/');
        break;

      case ABSTRACT_GB:
        elem->data.glob.pattern = strndup(tok->start, tok->length);
        elem->data.glob.has_slash =
            (memchr(tok->start, '/', tok->length) != NULL);
        break;

      case ABSTRACT_CS:
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

      case ABSTRACT_AR:
      case ABSTRACT_STR:
        // Store content if needed
        if (tok->length >= 2) {
          elem->data.cmd_subst.content =
              strndup(tok->start + 1, tok->length - 2);
        }
        break;

      default:
        break;
      }

      bool detail_ok = true;
      switch (ab_type) {
      case ABSTRACT_EV:
      case ABSTRACT_PV:
      case ABSTRACT_SV: {
        const char *variable = tok->start;
        size_t variable_len = tok->length;
        if (tok->is_quoted && variable_len >= 2) {
          variable++;
          variable_len -= 2;
        }
        /* A mixed quoted word is conservatively one variable-bearing element,
         * but it has no single environment name to expand. */
        detail_ok = variable_len == 0 || variable[0] != '$' ||
                    elem->data.var.name != NULL;
        break;
      }
      case ABSTRACT_AP:
      case ABSTRACT_RP:
      case ABSTRACT_HP:
        detail_ok = elem->data.path.path != NULL;
        break;
      case ABSTRACT_GB:
        detail_ok = elem->data.glob.pattern != NULL;
        break;
      case ABSTRACT_CS:
        detail_ok = tok->length < 4 || elem->data.cmd_subst.content != NULL;
        break;
      case ABSTRACT_AR:
      case ABSTRACT_STR:
        detail_ok = tok->length < 2 || elem->data.cmd_subst.content != NULL;
        break;
      default:
        break;
      }

      if (elem->original && elem->abstraction && detail_ok) {
        elements[element_count++] = elem;

        // Set flags
        switch (ab_type) {
        case ABSTRACT_EV:
          abst->has_variables = true;
          break;
        case ABSTRACT_PV:
          abst->has_pos_vars = true;
          abst->has_variables = true;
          break;
        case ABSTRACT_SV:
          abst->has_special_vars = true;
          abst->has_variables = true;
          break;
        case ABSTRACT_AP:
          abst->has_abs_paths = true;
          abst->has_paths = true;
          break;
        case ABSTRACT_RP:
          abst->has_rel_paths = true;
          abst->has_paths = true;
          break;
        case ABSTRACT_HP:
          abst->has_home_paths = true;
          abst->has_paths = true;
          break;
        case ABSTRACT_GB:
          abst->has_globs = true;
          break;
        case ABSTRACT_CS:
          abst->has_cmd_subst = true;
          break;
        case ABSTRACT_AR:
          abst->has_arithmetic = true;
          break;
        case ABSTRACT_STR:
          abst->has_strings = true;
          break;
        case ABSTRACT_REDIR:
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
    shell_free_commands(cmds, cmd_count);
    shell_abstracted_destroy(abst);
    return false;
  }

  // Set elements in result
  abst->elements = elements;
  abst->element_count = element_count;

  // Sort elements by start position
  if (element_count > 0) {
    for (size_t i = 1; i < element_count; i++) {
      abstract_element_t *key = elements[i];
      size_t j = i;
      while (j > 0 && elements[j - 1]->start > key->start) {
        elements[j] = elements[j - 1];
        j--;
      }
      elements[j] = key;
    }
  }

  // Build abstracted command string
  if (element_count == 0) {
    abst->abstracted = strdup(command);
  } else {
    abst->abstracted =
        build_abstracted_command(command, elements, element_count);
  }

  shell_free_commands(cmds, cmd_count);

  if (!abst->abstracted) {
    shell_abstracted_destroy(abst);
    return false;
  }

  *result = abst;
  return true;
}

/* --- QUERY FUNCTIONS --- */

const char *shell_get_abstracted(abstracted_command_t *cmd) {
  return cmd ? cmd->abstracted : NULL;
}

const char *shell_get_original(abstracted_command_t *cmd) {
  return cmd ? cmd->original : NULL;
}

abstract_element_t **shell_get_elements(abstracted_command_t *cmd,
                                        size_t *count) {
  if (!cmd || !count)
    return NULL;
  *count = cmd->element_count;
  return cmd->elements;
}

abstract_element_t *shell_get_element_at(abstracted_command_t *cmd,
                                         size_t index) {
  if (!cmd || index >= cmd->element_count)
    return NULL;
  return cmd->elements[index];
}

bool shell_has_variables(abstracted_command_t *cmd) {
  return cmd ? cmd->has_variables : false;
}

bool shell_has_pos_vars(abstracted_command_t *cmd) {
  return cmd ? cmd->has_pos_vars : false;
}

bool shell_has_special_vars(abstracted_command_t *cmd) {
  return cmd ? cmd->has_special_vars : false;
}

bool shell_has_globs(abstracted_command_t *cmd) {
  return cmd ? cmd->has_globs : false;
}

bool shell_has_paths(abstracted_command_t *cmd) {
  return cmd ? cmd->has_paths : false;
}

bool shell_has_abs_paths(abstracted_command_t *cmd) {
  return cmd ? cmd->has_abs_paths : false;
}

bool shell_has_rel_paths(abstracted_command_t *cmd) {
  return cmd ? cmd->has_rel_paths : false;
}

bool shell_has_home_paths(abstracted_command_t *cmd) {
  return cmd ? cmd->has_home_paths : false;
}

bool shell_has_cmd_subst(abstracted_command_t *cmd) {
  return cmd ? cmd->has_cmd_subst : false;
}

bool shell_has_redirects(abstracted_command_t *cmd) {
  return cmd ? cmd->has_redirects : false;
}

bool shell_has_arithmetic(abstracted_command_t *cmd) {
  return cmd ? cmd->has_arithmetic : false;
}

bool shell_has_strings(abstracted_command_t *cmd) {
  return cmd ? cmd->has_strings : false;
}

abstract_element_t *shell_get_element_by_abstract(abstracted_command_t *cmd,
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

static char *finish_expanded_path(char *path, runtime_context_t *ctx) {
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

char *shell_expand_element(abstract_element_t *elem, runtime_context_t *ctx) {
  if (!elem || !ctx)
    return NULL;

  switch (elem->type) {
  case ABSTRACT_EV:
  case ABSTRACT_PV:
  case ABSTRACT_SV: {
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

  case ABSTRACT_HP: {
    if (!elem->data.path.path)
      return NULL;
    const char *path = elem->data.path.path;

    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
      char *home = NULL;
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

  case ABSTRACT_AP:
  case ABSTRACT_RP: {
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

bool shell_expand_all_elements(abstracted_command_t *cmd,
                               runtime_context_t *ctx) {
  if (!cmd || !ctx)
    return false;

  for (size_t i = 0; i < cmd->element_count; i++) {
    if (cmd->elements[i]->expanded) {
      free(cmd->elements[i]->expanded);
      cmd->elements[i]->expanded = NULL;
    }

    cmd->elements[i]->expanded = shell_expand_element(cmd->elements[i], ctx);
  }

  return true;
}

/* --- UTILITY FUNCTIONS --- */

path_category_t shell_get_path_category(const char *resolved_path) {
  if (!resolved_path || resolved_path[0] != '/') {
    return PATH_OTHER;
  }

  // Skip leading /
  const char *p = resolved_path + 1;
  if (*p == '\0')
    return PATH_ROOT;

  // Find first /
  const char *slash = strchr(p, '/');
  size_t first_comp_len = slash ? (size_t)(slash - p) : strlen(p);

  // Compare first component
  if (first_comp_len == 3 && strncmp(p, "etc", 3) == 0)
    return PATH_ETC;
  if (first_comp_len == 3 && strncmp(p, "var", 3) == 0)
    return PATH_VAR;
  if (first_comp_len == 3 && strncmp(p, "usr", 3) == 0)
    return PATH_USR;
  if (first_comp_len == 4 && strncmp(p, "home", 4) == 0)
    return PATH_HOME;
  if (first_comp_len == 4 && strncmp(p, "root", 4) == 0)
    return PATH_HOME;
  if (first_comp_len == 3 && strncmp(p, "tmp", 3) == 0)
    return PATH_TMP;
  if (first_comp_len == 4 && strncmp(p, "proc", 4) == 0)
    return PATH_PROC;
  if (first_comp_len == 3 && strncmp(p, "sys", 3) == 0)
    return PATH_SYS;
  if (first_comp_len == 3 && strncmp(p, "dev", 3) == 0)
    return PATH_DEV;
  if (first_comp_len == 3 && strncmp(p, "opt", 3) == 0)
    return PATH_OPT;
  if (first_comp_len == 3 && strncmp(p, "srv", 3) == 0)
    return PATH_SRV;
  if (first_comp_len == 3 && strncmp(p, "run", 3) == 0)
    return PATH_RUN;
  if (first_comp_len == 7 && strncmp(p, "sysroot", 7) == 0)
    return PATH_SYSROOT;
  if (first_comp_len == 4 && strncmp(p, "boot", 4) == 0)
    return PATH_BOOT;
  if (first_comp_len == 3 && strncmp(p, "mnt", 3) == 0)
    return PATH_MNT;
  if (first_comp_len == 5 && strncmp(p, "media", 5) == 0)
    return PATH_MEDIA;
  if (first_comp_len == 10 && strncmp(p, ".snapshots", 10) == 0)
    return PATH_SNAPSHOT;

  return PATH_OTHER;
}

const char *shell_abstract_type_name(abstract_type_t type) {
  if (type >= 0 && type < (int)(sizeof(ABSTRACT_TYPE_NAMES) /
                                sizeof(ABSTRACT_TYPE_NAMES[0]))) {
    return ABSTRACT_TYPE_NAMES[type];
  }
  return "UNKNOWN";
}

const char *shell_path_category_name(path_category_t cat) {
  if (cat >= 0 && cat < (int)(sizeof(PATH_CATEGORY_NAMES) /
                              sizeof(PATH_CATEGORY_NAMES[0]))) {
    return PATH_CATEGORY_NAMES[cat];
  }
  return "UNKNOWN";
}

/* --- CLEANUP --- */

void shell_abstracted_destroy(abstracted_command_t *cmd) {
  if (!cmd)
    return;

  free((void *)cmd->original);
  free(cmd->abstracted);

  if (cmd->elements) {
    for (size_t i = 0; i < cmd->element_count; i++) {
      abstract_element_t *elem = cmd->elements[i];
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
  abstract_type_t type =
      get_abstract_type(token->type, token->start, token->length);
  switch (type) {
  case ABSTRACT_EV:
    return "EV";
  case ABSTRACT_PV:
    return "PV";
  case ABSTRACT_SV:
    return "SV";
  case ABSTRACT_AP:
    return "AP";
  case ABSTRACT_RP:
    return "RP";
  case ABSTRACT_HP:
    return "HP";
  case ABSTRACT_GB:
    return "GB";
  case ABSTRACT_CS:
    return "CS";
  case ABSTRACT_AR:
    return "AR";
  case ABSTRACT_REDIR:
    return "RD";
  case ABSTRACT_STR:
  default:
    return "STR";
  }
}

shell_process_status_t
shell_build_type_netseq(const char *command,
                        const shell_process_limits_t *limits, char **netseq,
                        size_t *subcommand_count) {
  if (netseq)
    *netseq = NULL;
  if (subcommand_count)
    *subcommand_count = 0;
  if (!command || !netseq || !subcommand_count)
    return SHELL_PROCESS_EINPUT;

  shell_command_info_t *commands = NULL;
  size_t count = 0;
  shell_process_status_t status =
      shell_process_command(command, limits, &commands, &count);
  if (status != SHELL_PROCESS_OK)
    return status;

  size_t outer_length = 0;
  for (size_t c = 0; c < count; c++) {
    if (commands[c].command_token_count == 0) {
      status = SHELL_PROCESS_EPARSE;
      goto fail_type_netseq;
    }
    size_t inner_length = 0;
    const shell_token_t *executable = &commands[c].command_tokens[0];
    size_t decoded_length = 0;
    status = shell_measure_decoded_word(executable->start, executable->length,
                                        &decoded_length);
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
    for (size_t i = 1; i < commands[c].command_token_count; i++) {
      const char *abbreviation =
          token_abbreviation(&commands[c].command_tokens[i]);
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
  }
  if (limits && (outer_length > limits->max_string_bytes ||
                 outer_length > limits->max_total_bytes)) {
    status = SHELL_PROCESS_EOUTPUT_LIMIT;
    goto fail_type_netseq;
  }
  char *outer = malloc(outer_length + 1);
  if (!outer) {
    status = SHELL_PROCESS_ENOMEM;
    goto fail_type_netseq;
  }
  char *position = outer;
  for (size_t c = 0; c < count; c++) {
    size_t inner_length = 0;
    const shell_token_t *executable = &commands[c].command_tokens[0];
    size_t decoded_length = 0;
    (void)shell_measure_decoded_word(executable->start, executable->length,
                                     &decoded_length);
    (void)shell_netstring_encoded_length(decoded_length, &inner_length);
    for (size_t i = 1; i < commands[c].command_token_count; i++) {
      size_t length =
          strlen(token_abbreviation(&commands[c].command_tokens[i]));
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
    (void)shell_write_decoded_word(executable->start, executable->length,
                                   position, decoded_length, &written);
    position += written;
    *position++ = ',';
    for (size_t i = 1; i < commands[c].command_token_count; i++) {
      const char *abbreviation =
          token_abbreviation(&commands[c].command_tokens[i]);
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
  shell_free_command_infos(commands, count);
  *netseq = outer;
  *subcommand_count = count;
  return SHELL_PROCESS_OK;

fail_type_netseq:
  shell_free_command_infos(commands, count);
  return status;
}
