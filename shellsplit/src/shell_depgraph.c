/*
 * shell_depgraph.c - Abstract Command Dependency Graph (ACDG)
 *
 * Zero-copy bounded-memory parser that builds a coarse-grained
 * command dependency graph from shell command strings.
 *
 * Consumes the output of the fast tokenizer (shell_parse_fast).
 */

#define _POSIX_C_SOURCE 200809L

#include "shell_depgraph.h"
#include "shell_depgraph_internal.h"
#include "shell_processor.h"
#include "shell_processor_internal.h"
#include "shell_source_internal.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Borrowed source spans must not overlap writable destinations. Compare
 * integer addresses: relational pointer comparison across objects is not
 * defined, and an unrepresentable span must fail closed. */
static bool dep_memory_spans_overlap(const void *left, size_t left_size,
                                     const void *right, size_t right_size) {
  if (!left || !right || left_size == 0 || right_size == 0)
    return false;
  uintptr_t left_begin = (uintptr_t)left;
  uintptr_t right_begin = (uintptr_t)right;
  if (left_size > UINTPTR_MAX - left_begin ||
      right_size > UINTPTR_MAX - right_begin)
    return true;
  uintptr_t left_end = left_begin + left_size;
  uintptr_t right_end = right_begin + right_size;
  return left_begin < right_end && right_begin < left_end;
}

/* --- NAME HELPERS --- */

static const char *dep_edge_names[] = {
    "READ", "WRITE",      "APPEND", "PIPE",    "ARG",
    "ENV",  "SUBST",      "SEQ",    "AND",     "OR",
    "CWD",  "BACKGROUND", "GROUP",  "FD_OPEN", "FD_CLOSE",
};

static const char *dep_node_names[] = {
    "CMD",
    "DOC",
    "GROUP",
    "ENDPOINT",
};

static const char *dep_doc_names[] = {
    "FILE",
    "HEREDOC",
    "HERESTRING",
    "ENVVAR",
};

const char *shell_dep_edge_type_name(shell_dep_edge_type_t type) {
  if ((int)type < 0 ||
      (int)type >= (int)(sizeof(dep_edge_names) / sizeof(dep_edge_names[0])))
    return "UNKNOWN";
  return dep_edge_names[type];
}

const char *shell_dep_node_type_name(shell_dep_node_type_t type) {
  if ((int)type < 0 ||
      (int)type >= (int)(sizeof(dep_node_names) / sizeof(dep_node_names[0])))
    return "UNKNOWN";
  return dep_node_names[type];
}

const char *shell_dep_doc_kind_name(shell_dep_doc_kind_t kind) {
  if ((int)kind < 0 ||
      (int)kind >= (int)(sizeof(dep_doc_names) / sizeof(dep_doc_names[0])))
    return "UNKNOWN";
  return dep_doc_names[kind];
}

static bool dep_doc_content_valid(const shell_dep_doc_t *doc) {
  return doc != NULL && (doc->value != NULL || doc->value_len == 0) &&
         (doc->flags &
          ~(SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
            SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
            SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL | SHELL_DEP_DOC_FLAG_TRANSIENT |
            SHELL_DEP_DOC_FLAG_ENVVAR_APPEND)) == 0;
}

bool shell_dep_doc_content_length(const shell_dep_doc_t *doc,
                                  size_t *content_length) {
  if (content_length)
    *content_length = 0;
  if (!content_length || !dep_doc_content_valid(doc))
    return false;
  if (!(doc->flags & SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS)) {
    *content_length = doc->value_len;
    return true;
  }

  size_t total = 0;
  bool line_start = true;
  for (uint32_t i = 0; i < doc->value_len; i++) {
    char c = doc->value[i];
    if (line_start && c == '\t')
      continue;
    if (total == SIZE_MAX)
      return false;
    total++;
    line_start = c == '\n';
  }
  *content_length = total;
  return true;
}

bool shell_dep_doc_write_content(const shell_dep_doc_t *doc, char *destination,
                                 size_t destination_size, size_t *written) {
  if (written)
    *written = 0;
  if (!written || !dep_doc_content_valid(doc))
    return false;
  size_t needed = 0;
  if (!shell_dep_doc_content_length(doc, &needed) ||
      (needed != 0 && !destination) || destination_size < needed ||
      dep_memory_spans_overlap(doc->value, doc->value_len, destination,
                               destination_size))
    return false;

  size_t out = 0;
  bool line_start = true;
  for (uint32_t i = 0; i < doc->value_len; i++) {
    char c = doc->value[i];
    if ((doc->flags & SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS) && line_start &&
        c == '\t')
      continue;
    destination[out++] = c;
    line_start = c == '\n';
  }
  *written = out;
  return true;
}

static bool dep_doc_env_assignment(const shell_dep_doc_t *doc,
                                   shell_source_byte_visitor_t visitor,
                                   void *context,
                                   shell_source_decoded_assignment_t *out) {
  if (!doc || !out || doc->kind != SHELL_DOC_ENVVAR || !doc->name ||
      !doc->value)
    return false;
  uintptr_t start = (uintptr_t)(const void *)doc->name;
  uintptr_t value = (uintptr_t)(const void *)doc->value;
  if (value <= start || value - start > UINT32_MAX ||
      doc->value_len > UINT32_MAX - (value - start))
    return false;
  size_t word_length = (size_t)(value - start) + doc->value_len;
  return shell_source_scan_decoded_assignment(doc->name, word_length, visitor,
                                              context, out) &&
         out->source_delimiter && out->equals + 1 == value - start &&
         out->name_end == doc->name_len;
}

bool shell_dep_doc_env_name_length(const shell_dep_doc_t *doc,
                                   size_t *name_length) {
  if (name_length)
    *name_length = 0;
  if (!name_length)
    return false;
  shell_source_decoded_assignment_t assignment;
  if (!dep_doc_env_assignment(doc, NULL, NULL, &assignment))
    return false;
  *name_length = assignment.name_length;
  return true;
}

typedef struct {
  char *destination;
  size_t position;
} dep_doc_env_name_sink_t;

static bool dep_doc_env_name_byte(unsigned char byte, void *context) {
  dep_doc_env_name_sink_t *sink = context;
  sink->destination[sink->position++] = (char)byte;
  return true;
}

bool shell_dep_doc_write_env_name(const shell_dep_doc_t *doc, char *destination,
                                  size_t destination_size, size_t *written) {
  if (written)
    *written = 0;
  size_t needed = 0;
  if (!written || !shell_dep_doc_env_name_length(doc, &needed) ||
      !destination || destination_size < needed)
    return false;
  uintptr_t start = (uintptr_t)(const void *)doc->name;
  uintptr_t value = (uintptr_t)(const void *)doc->value;
  size_t source_length = (size_t)(value - start) + doc->value_len;
  if (dep_memory_spans_overlap(doc->name, source_length, destination,
                               destination_size))
    return false;
  dep_doc_env_name_sink_t sink = {.destination = destination};
  shell_source_decoded_assignment_t assignment;
  if (!dep_doc_env_assignment(doc, dep_doc_env_name_byte, &sink, &assignment))
    return false;
  *written = sink.position;
  return true;
}

typedef struct {
  const char *name;
  size_t length;
  size_t position;
  bool matches;
} dep_doc_env_name_match_t;

static bool dep_doc_env_name_match_byte(unsigned char byte, void *context) {
  dep_doc_env_name_match_t *match = context;
  if (match->position >= match->length ||
      byte != (unsigned char)match->name[match->position])
    match->matches = false;
  match->position++;
  return true;
}

bool shell_dep_doc_env_name_equals(const shell_dep_doc_t *doc, const char *name,
                                   size_t name_length) {
  if (!name)
    return false;
  dep_doc_env_name_match_t match = {
      .name = name,
      .length = name_length,
      .matches = true,
  };
  shell_source_decoded_assignment_t assignment;
  return dep_doc_env_assignment(doc, dep_doc_env_name_match_byte, &match,
                                &assignment) &&
         match.matches && match.position == name_length;
}

/* --- CWD RESOLUTION --- */

static void dep_normalize_path(char *path, uint32_t len, bool collapse_parent) {
  if (len == 0)
    return;
  /* Bash's logical cd folds parent components. FILE operands must not: an
   * intermediate component may be a symlink, so `link/../out` need not name
   * the same file as `out`. Preserve `..` in file-comparison keys, including
   * where a relative path crosses its modeled CWD prefix. */
  bool absolute = path[0] == '/';
  uint32_t w = absolute ? 1 : 0;
  uint32_t r = 0;
  if (absolute)
    path[0] = '/';
  while (r < len) {
    while (r < len && path[r] == '/')
      r++;
    uint32_t start = r;
    while (r < len && path[r] != '/')
      r++;
    uint32_t component_len = r - start;
    if (component_len == 0 || (component_len == 1 && path[start] == '.'))
      continue;
    if (collapse_parent && component_len == 2 && path[start] == '.' &&
        path[start + 1] == '.') {
      uint32_t previous = w;
      while (previous > (absolute ? 1u : 0u) && path[previous - 1] != '/')
        previous--;
      bool previous_is_parent = w - previous == 2 && path[previous] == '.' &&
                                path[previous + 1] == '.';
      if (w > (absolute ? 1u : 0u) && !previous_is_parent) {
        w = previous > (absolute ? 1u : 0u) ? previous - 1 : previous;
        continue;
      }
      if (absolute)
        continue;
    }
    if (w != 0 && path[w - 1] != '/')
      path[w++] = '/';
    memmove(path + w, path + start, component_len);
    w += component_len;
  }
  if (w == 0)
    path[w++] = '.';
  path[w] = '\0';
}

typedef struct {
  bool has_nul;
  unsigned char first;
} dep_file_identity_measure_t;

static bool dep_file_identity_byte(unsigned char byte, size_t position,
                                   void *context) {
  dep_file_identity_measure_t *measure = context;
  if (position == 0)
    measure->first = byte;
  if (byte == 0)
    measure->has_nul = true;
  return true;
}

bool shell_dep_doc_file_identity_write(const shell_dep_graph_t *graph,
                                       const shell_dep_doc_t *doc,
                                       char *destination,
                                       size_t destination_size, size_t *written,
                                       bool *absolute) {
  if (written)
    *written = 0;
  if (absolute)
    *absolute = false;
  if (!graph || !doc || !destination || !written || !absolute ||
      doc->kind != SHELL_DOC_FILE || !doc->path)
    return false;
  dep_file_identity_measure_t measure = {0};
  size_t path_len = 0;
  if (!shell_visit_static_word(doc->path, doc->path_len, dep_file_identity_byte,
                               &measure, &path_len) ||
      path_len == 0 || measure.has_nul)
    return false;
  bool path_absolute = measure.first == '/';
  if (!path_absolute &&
      (!doc->cwd_known || doc->cwd_offset >= graph->cwd_buf.len))
    return false;
  const char *cwd =
      path_absolute ? NULL : graph->cwd_buf.data + doc->cwd_offset;
  const char *cwd_end =
      path_absolute ? NULL
                    : memchr(cwd, 0, graph->cwd_buf.len - doc->cwd_offset);
  if (!path_absolute && !cwd_end)
    return false;
  size_t cwd_len = path_absolute ? 0 : (size_t)(cwd_end - cwd);
  size_t prefix_len = path_absolute ? 0 : cwd_len + 1;
  if (prefix_len > SIZE_MAX - path_len - 1)
    return false;
  size_t combined_len = prefix_len + path_len;
  if (combined_len > UINT32_MAX || combined_len + 1 > destination_size ||
      dep_memory_spans_overlap(doc->path, doc->path_len, destination,
                               destination_size) ||
      (!path_absolute && dep_memory_spans_overlap(cwd, cwd_len + 1, destination,
                                                  destination_size)))
    return false;
  if (!path_absolute) {
    memcpy(destination, cwd, cwd_len);
    destination[cwd_len] = '/';
  }
  size_t decoded_len = 0;
  if (shell_write_decoded_word(doc->path, doc->path_len,
                               destination + prefix_len, path_len,
                               &decoded_len) != SHELL_PROCESS_OK ||
      decoded_len != path_len)
    return false;
  destination[combined_len] = '\0';
  dep_normalize_path(destination, (uint32_t)combined_len, false);
  *written = strlen(destination);
  *absolute = path_absolute || doc->cwd_absolute;
  return true;
}

static uint32_t cwd_resolve_dedup(shell_dep_graph_t *g, uint32_t current_offset,
                                  const char *rel, bool tilde_expanded,
                                  uint32_t effective_size, uint32_t *status) {
  if (!rel || rel[0] == '\0')
    return current_offset;
  if (current_offset >= g->cwd_buf.len)
    return current_offset;

  const char *current_cwd = g->cwd_buf.data + current_offset;
  char temp_path[SHELL_DEP_CWD_BUF_SIZE];
  size_t cur_len = strlen(current_cwd);
  size_t rel_len = strlen(rel);

  if (rel[0] == '/') {
    if (rel_len >= effective_size) {
      *status |= SHELL_DEP_STATUS_TRUNCATED;
      return current_offset;
    }
    memcpy(temp_path, rel, rel_len);
    temp_path[rel_len] = '\0';
  } else if (tilde_expanded) {
    if (rel_len >= effective_size) {
      *status |= SHELL_DEP_STATUS_TRUNCATED;
      return current_offset;
    }
    memcpy(temp_path, rel, rel_len);
    temp_path[rel_len] = '\0';
  } else {
    if (cur_len + 1 + rel_len >= effective_size) {
      *status |= SHELL_DEP_STATUS_TRUNCATED;
      return current_offset;
    }

    memcpy(temp_path, current_cwd, cur_len);
    temp_path[cur_len] = '/';
    memcpy(temp_path + cur_len + 1, rel, rel_len);
    temp_path[cur_len + 1 + rel_len] = '\0';
  }

  dep_normalize_path(temp_path, (uint32_t)strlen(temp_path), true);
  size_t norm_len = strlen(temp_path);

  size_t pos = 0;
  while (pos < g->cwd_buf.len) {
    const char *existing = g->cwd_buf.data + pos;
    size_t existing_len = strlen(existing);

    if (existing_len == norm_len &&
        memcmp(existing, temp_path, norm_len) == 0) {
      return (uint32_t)pos;
    }

    pos += existing_len + 1;
  }

  if (g->cwd_buf.len + norm_len + 1 > effective_size) {
    *status |= SHELL_DEP_STATUS_TRUNCATED;
    return current_offset;
  }

  memcpy(g->cwd_buf.data + g->cwd_buf.len, temp_path, norm_len + 1);
  uint32_t new_offset = (uint32_t)g->cwd_buf.len;
  g->cwd_buf.len += norm_len + 1;

  return new_offset;
}

/* --- LIGHTWEIGHT TOKENIZER --- */

typedef struct {
  const char *start;
  uint32_t len;
} dep_token_t;

typedef struct {
  dep_token_t tokens[SHELL_DEP_MAX_TOKENS];
  uint32_t count;
  bool malformed;
} dep_token_list_t;

static uint32_t scan_redirect_token(const char *cmd, uint32_t pos,
                                    uint32_t end) {
  /* Bash combined stdout/stderr redirections have no numeric io_number.
   * Keep the complete operator as one token so its following operand is not
   * misread as an executable command. */
  size_t combined_after = pos;
  if (shell_source_match_logical_punctuation(cmd, end, pos, "&>>",
                                             &combined_after) ||
      shell_source_match_logical_punctuation(cmd, end, pos, "&>",
                                             &combined_after))
    return (uint32_t)combined_after;
  size_t named_operator = 0;
  if (shell_source_parse_named_fd_redirect(cmd, pos, end, &named_operator)) {
    uint32_t cursor = (uint32_t)named_operator + 1;
    char operator_char = cmd[named_operator];
    cursor = (uint32_t)shell_source_skip_escaped_line_endings(cmd, end, cursor);
    if (cursor < end && cmd[cursor] == operator_char)
      cursor++;
    else if (cursor < end && ((operator_char == '<' && cmd[cursor] == '>') ||
                              (operator_char == '>' && cmd[cursor] == '|')))
      cursor++;
    /* Preserve Bash's raw close-marker boundary: `>&-file` closes the
     * descriptor with `>&-` and leaves `file` as argv. Numeric prefixes stay
     * whole-word operands so `>&123file` remains a legacy combined-output
     * pathname. */
    cursor = (uint32_t)shell_source_skip_escaped_line_endings(cmd, end, cursor);
    if (cursor < end && cmd[cursor] == '&') {
      cursor++;
      if (cursor < end && cmd[cursor] == '-')
        cursor++;
    }
    return cursor;
  }
  size_t parsed_after = 0;
  uint32_t descriptor = 0;
  shell_source_io_number_t io_number =
      shell_source_parse_io_number(cmd, pos, end, &parsed_after, &descriptor);
  if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return pos;
  uint32_t cursor =
      (uint32_t)shell_source_skip_escaped_line_endings(cmd, end, parsed_after);
  if (cursor >= end || (cmd[cursor] != '<' && cmd[cursor] != '>'))
    return pos;

  char operator_char = cmd[cursor++];
  cursor = (uint32_t)shell_source_skip_escaped_line_endings(cmd, end, cursor);
  if (cursor < end && cmd[cursor] == operator_char)
    cursor++;
  else if (cursor < end && ((operator_char == '<' && cmd[cursor] == '>') ||
                            (operator_char == '>' && cmd[cursor] == '|')))
    cursor++;
  cursor = (uint32_t)shell_source_skip_escaped_line_endings(cmd, end, cursor);
  if (cursor < end && cmd[cursor] == '&') {
    cursor++;
    if (cursor < end && cmd[cursor] == '-')
      cursor++;
  }
  return cursor;
}

/* Consume one complete source word without interpreting its expansion value.
 * The dependency graph and canonical netargv both need shell-word boundaries,
 * rather than the smaller lexical fragments used to inspect substitutions.
 * In particular, `prefix$(cmd)suffix` and `prefix<(cmd)suffix` remain one
 * argument even though their embedded command bodies are analyzed separately.
 */
static bool scan_word_token(const char *cmd, uint32_t end, uint32_t *position) {
  uint32_t pos = *position;
  while (pos < end) {
    char c = cmd[pos];
    if (c == '$' && shell_source_logical_next_is(cmd, end, pos, '{', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(cmd, end, pos, &after))
        return false;
      pos = (uint32_t)after;
      continue;
    }
    size_t extglob_after = 0;
    if (shell_source_skip_extglob(cmd, end, pos, &extglob_after)) {
      pos = (uint32_t)extglob_after;
      continue;
    }
    if (c == '\\' && pos + 1 < end) {
      /* The escaped byte is literal, so an escaped `$(` must not require a
       * matching close parenthesis. Parentheses are ordinary word bytes here.
       */
      bool cr = cmd[pos + 1] == '\r';
      pos += 2;
      if (cr && pos < end && cmd[pos] == '\n')
        pos++;
      continue;
    }
    if (c == '$' && shell_source_logical_next_is(cmd, end, pos, '\'', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(cmd, end, pos, &after))
        return false;
      pos = (uint32_t)after;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t after = shell_source_skip_quoted_text(cmd, end, pos, c);
      pos = (uint32_t)after;
      continue;
    }
    size_t open = 0;
    if (c == '$' &&
        shell_source_dollar_parentheses_open(cmd, end, pos, &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, end, open, &after))
        return false;
      pos = (uint32_t)after;
      continue;
    }
    if ((c == '<' || c == '>') &&
        shell_source_process_substitution_open(cmd, end, pos, &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, end, open, &after))
        return false;
      pos = (uint32_t)after;
      continue;
    }
    if (isspace((unsigned char)c) || c == '|' || c == ';' || c == '&' ||
        c == '<' || c == '>')
      break;
    pos++;
  }
  *position = pos;
  return true;
}

static bool scan_tokens(const char *cmd, uint32_t range_start,
                        uint32_t range_len, dep_token_list_t *out) {
  out->count = 0;
  out->malformed = false;
  uint32_t pos = range_start;
  uint32_t end = range_start + range_len;
  bool process_sub_target = false;

  while (pos < end && out->count < SHELL_DEP_MAX_TOKENS) {
    while (pos < end) {
      size_t continued = shell_source_skip_escaped_line_endings(cmd, end, pos);
      if (continued != pos) {
        pos = (uint32_t)continued;
        continue;
      }
      if (!isspace((unsigned char)cmd[pos]))
        break;
      pos++;
    }
    if (pos >= end)
      break;

    uint32_t tok_start = pos;
    uint32_t redirect_end = scan_redirect_token(cmd, pos, end);

    size_t process_open = 0;
    if ((cmd[pos] == '<' || cmd[pos] == '>') &&
        shell_source_process_substitution_open(cmd, end, pos, &process_open)) {
      /* Keep a process-substitution word as one token. This covers both a
       * whitespace-separated redirect target (`> >(cmd)`) and an ordinary
       * argument (`cmd <(producer)`), which must not become a synthetic
       * fd-0 redirect. */
      process_sub_target = false;
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, end, process_open,
                                                  &after)) {
        out->malformed = true;
        return true;
      }
      pos = (uint32_t)after;
      /* A process substitution is one fragment of a shell word, not an
       * argv boundary. Keep a literal suffix in the same borrowed span. */
      if (!scan_word_token(cmd, end, &pos)) {
        out->malformed = true;
        return true;
      }
    } else if (redirect_end != pos) {
      pos = redirect_end;
      uint32_t target = pos;
      while (target < end) {
        size_t target_continued =
            shell_source_skip_escaped_line_endings(cmd, end, target);
        if (target_continued != target) {
          target = (uint32_t)target_continued;
          continue;
        }
        if (!isspace((unsigned char)cmd[target]))
          break;
        target++;
      }
      process_sub_target =
          target < end &&
          (cmd[target] == '(' ||
           ((cmd[target] == '<' || cmd[target] == '>') &&
            shell_source_process_substitution_open(cmd, end, target, NULL)));
    } else if (process_sub_target && cmd[pos] == '(') {
      process_sub_target = false;
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, end, pos, &after)) {
        out->malformed = true;
        return true;
      }
      pos = (uint32_t)after;
    } else {
      process_sub_target = false;
      if (!scan_word_token(cmd, end, &pos)) {
        out->malformed = true;
        return true;
      }
      if (pos == tok_start) {
        size_t operator_after = 0;
        if (shell_source_match_logical_punctuation(cmd, end, pos, "|&",
                                                   &operator_after) ||
            shell_source_match_logical_punctuation(cmd, end, pos, "||",
                                                   &operator_after) ||
            shell_source_match_logical_punctuation(cmd, end, pos, "&&",
                                                   &operator_after) ||
            shell_source_match_logical_punctuation(cmd, end, pos, ">>",
                                                   &operator_after) ||
            shell_source_match_logical_punctuation(cmd, end, pos, "<<",
                                                   &operator_after))
          pos = (uint32_t)operator_after;
        else
          pos++;
      }
    }

    if (pos > tok_start && out->count < SHELL_DEP_MAX_TOKENS) {
      out->tokens[out->count].start = cmd + tok_start;
      out->tokens[out->count].len = pos - tok_start;
      out->count++;
    }
  }
  while (pos < end && isspace((unsigned char)cmd[pos]))
    pos++;
  return pos < end;
}

/* --- TOKEN CLASSIFICATION HELPERS --- */

static bool
dep_token_parse_assignment_word(const dep_token_t *tok,
                                shell_source_assignment_word_t *out) {
  return tok && tok->start &&
         shell_source_parse_scalar_assignment_word(tok->start, tok->len, out);
}

static bool dep_token_is_assignment_word(const dep_token_t *tok) {
  shell_source_assignment_word_t assignment;
  return dep_token_parse_assignment_word(tok, &assignment);
}

typedef enum {
  DEP_REDIRECT_NONE,
  DEP_REDIRECT_IN,
  DEP_REDIRECT_OUT,
  DEP_REDIRECT_APPEND,
  DEP_REDIRECT_READ_WRITE,
  DEP_REDIRECT_DUP,
  DEP_REDIRECT_HEREDOC,
  DEP_REDIRECT_BOTH,
  DEP_REDIRECT_BOTH_APPEND,
} dep_redirect_t;

static bool dep_token_is_process_substitution_word(const dep_token_t *tok) {
  return tok && shell_source_word_is_process_substitution(tok->start, tok->len);
}

static dep_redirect_t classify_redirect(const dep_token_t *tok) {
  if (!tok || !tok->start || tok->len == 0)
    return DEP_REDIRECT_NONE;
  /* Redirect tokens retain trailing escaped physical line endings in their
   * zero-copy source span. Shell grammar discards those bytes before deciding
   * whether the operator owns its next word. Classify the logical token while
   * leaving the raw span available to graph consumers. */
  size_t logical_end = shell_source_skip_escaped_line_endings_backward(
      tok->start, tok->len, tok->len);
  if (logical_end == 0)
    return DEP_REDIRECT_NONE;
  size_t operator_after = 0;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, 0, "&>",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_BOTH;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, 0, "&>>",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_BOTH_APPEND;
  size_t after = 0;
  uint32_t descriptor = 0;
  if (shell_source_parse_named_fd_redirect(tok->start, 0, logical_end,
                                           &after)) {
    if (shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                               "<", &operator_after) &&
        operator_after == logical_end)
      return DEP_REDIRECT_IN;
    if (shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                               ">", &operator_after) &&
        operator_after == logical_end)
      return DEP_REDIRECT_OUT;
    if (shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                               ">>", &operator_after) &&
        operator_after == logical_end)
      return DEP_REDIRECT_APPEND;
    if (shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                               "<>", &operator_after) &&
        operator_after == logical_end)
      return DEP_REDIRECT_READ_WRITE;
    if ((shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                                "<&", &operator_after) ||
         shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                                ">&", &operator_after)))
      return DEP_REDIRECT_DUP;
    return DEP_REDIRECT_NONE;
  }
  shell_source_io_number_t io_number = shell_source_parse_io_number(
      tok->start, 0, logical_end, &after, &descriptor);
  if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return DEP_REDIRECT_NONE;
  uint32_t pos = (uint32_t)after;
  if (pos == 0 && dep_token_is_process_substitution_word(tok))
    return DEP_REDIRECT_NONE;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, pos, "<",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_IN;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, pos, ">",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_OUT;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, pos, ">>",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_APPEND;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, pos, "<>",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_READ_WRITE;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, pos, ">|",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_OUT;
  if (shell_source_match_logical_punctuation(tok->start, logical_end, pos, "<<",
                                             &operator_after) &&
      operator_after == logical_end)
    return DEP_REDIRECT_HEREDOC;
  if ((shell_source_match_logical_punctuation(tok->start, logical_end, pos,
                                              "<&", &operator_after) ||
       shell_source_match_logical_punctuation(tok->start, logical_end, pos,
                                              ">&", &operator_after)))
    return DEP_REDIRECT_DUP;
  return DEP_REDIRECT_NONE;
}

static bool dep_named_fd_name(const dep_token_t *tok, const char **name,
                              uint32_t *name_len) {
  size_t operator_pos = 0;
  size_t name_after = 0;
  if (!tok || !name || !name_len ||
      !shell_source_parse_named_fd_redirect(tok->start, 0, tok->len,
                                            &operator_pos) ||
      !shell_source_parse_named_fd(tok->start, 0, operator_pos, &name_after) ||
      name_after < 3 || name_after > operator_pos ||
      tok->start[name_after - 1] != '}')
    return false;
  *name = tok->start + 1;
  *name_len = (uint32_t)name_after - 2;
  return true;
}

static void dep_set_named_fd(shell_dep_edge_t *edge, bool source,
                             const char *name, uint32_t name_len) {
  if (!edge)
    return;
  if (source) {
    edge->source_fd_name = name;
    edge->source_fd_name_len = name_len;
  } else {
    edge->target_fd_name = name;
    edge->target_fd_name_len = name_len;
  }
}

static uint32_t redirect_fd(const dep_token_t *tok, dep_redirect_t redirect) {
  size_t after = 0;
  uint32_t descriptor = 0;
  if (shell_source_parse_named_fd_redirect(tok->start, 0, tok->len, &after))
    return SHELL_DEP_FD_NAMED;
  if (shell_source_parse_io_number(tok->start, 0, tok->len, &after,
                                   &descriptor) == SHELL_SOURCE_IO_NUMBER_VALID)
    return descriptor;
  /* Descriptor duplication has its own redirect kind, so use the source
   * operator instead of falling through to the output default. `<&word`
   * targets stdin while `>&word` targets stdout. */
  if (redirect == DEP_REDIRECT_DUP && after < tok->len &&
      tok->start[after] == '<')
    return 0;
  return (redirect == DEP_REDIRECT_IN || redirect == DEP_REDIRECT_READ_WRITE)
             ? 0
             : 1;
}

static bool
dep_redirect_target_is_process_substitution(const dep_token_t *target) {
  return target &&
         shell_source_word_is_process_substitution(target->start, target->len);
}

static bool dep_redirect_is_legacy_combined_output(const dep_token_t *redirect,
                                                   const dep_token_t *target);

/* A process-substitution path creates a stream when the redirect opens its
 * matching descriptor side: `< <(...)` consumes the producer's stdout, while
 * `> >(...)` and `<> >(...)` send the owner's descriptor to the consumer's
 * stdin. The cross-direction spellings are valid Bash, but they do not justify
 * inventing a byte route in the dependency graph. */
static bool dep_process_substitution_is_input(dep_redirect_t redirect,
                                              const dep_token_t *target) {
  return target->start[0] == '<' &&
         (redirect == DEP_REDIRECT_IN || redirect == DEP_REDIRECT_READ_WRITE);
}

static bool dep_process_substitution_is_output(dep_redirect_t redirect,
                                               const dep_token_t *target) {
  return target->start[0] == '>' &&
         (redirect == DEP_REDIRECT_OUT || redirect == DEP_REDIRECT_APPEND ||
          redirect == DEP_REDIRECT_READ_WRITE ||
          redirect == DEP_REDIRECT_BOTH ||
          redirect == DEP_REDIRECT_BOTH_APPEND);
}

/* Bash treats $(<word) as command substitution of the file's content without
 * starting an external command. Keep it distinct from a general redirected
 * command substitution: only the single default-input redirection form is a
 * direct FILE-to-shell-word flow. */
static bool dep_file_command_substitution(const char *content,
                                          uint32_t content_len,
                                          const char **path,
                                          uint32_t *path_len) {
  dep_token_list_t tokens = {0};
  if (!content || !path || !path_len ||
      scan_tokens(content, 0, content_len, &tokens) || tokens.count != 2 ||
      tokens.tokens[0].len != 1 || tokens.tokens[0].start[0] != '<' ||
      tokens.tokens[1].len == 0)
    return false;
  *path = tokens.tokens[1].start;
  *path_len = tokens.tokens[1].len;
  return true;
}

static const char *extract_subshell_content(const dep_token_t *tok,
                                            uint32_t *out_len);

/* Return the next executable substitution at or after min_offset.  A token
 * may contain several adjacent or embedded substitutions (for example
 * "$(one)$(two)").  The old single-result helper silently dropped every
 * substitution after the first one.  Rescanning from the token start keeps
 * quote state correct while skipping complete substitutions, including their
 * nested contents. */
static bool find_subshell_at_or_after(const dep_token_t *tok,
                                      uint32_t min_offset,
                                      dep_token_t *subshell,
                                      uint32_t *span_len) {
  shell_source_substitution_scan_t scan = {0};
  shell_source_substitution_kind_t kind;
  size_t start = 0, after = 0;
  while (shell_source_next_executable_substitution(tok->start, tok->len, &scan,
                                                   &start, &after, &kind)) {
    (void)kind;
    if (start < min_offset)
      continue;
    subshell->start = tok->start + start;
    subshell->len = (uint32_t)(after - start);
    *span_len = subshell->len;
    return true;
  }
  *span_len = 0;
  return false;
}

/* A plain cd can remain a CWD-only transition. Redirect setup or executable
 * substitution needs an execution endpoint, even when cd_as_cmd is false. */
static bool dep_cd_needs_graph_node(const dep_token_list_t *tokens) {
  for (uint32_t i = 0; i < tokens->count; i++) {
    if (classify_redirect(&tokens->tokens[i]) != DEP_REDIRECT_NONE)
      return true;
    dep_token_t nested = {0};
    uint32_t span = 0;
    if (find_subshell_at_or_after(&tokens->tokens[i], 0, &nested, &span))
      return true;
  }
  return false;
}

static const char *extract_subshell_content(const dep_token_t *tok,
                                            uint32_t *out_len) {
  size_t open = 0;
  if (tok->len >= 2 &&
      ((tok->start[0] == '$' &&
        shell_source_dollar_parentheses_open(tok->start, tok->len, 0, &open)) ||
       ((tok->start[0] == '<' || tok->start[0] == '>') &&
        shell_source_process_substitution_open(tok->start, tok->len, 0,
                                               &open)))) {
    size_t after = 0;
    if (shell_source_find_balanced_parentheses(tok->start, tok->len, open,
                                               &after) &&
        after >= open + 2 && after <= tok->len) {
      *out_len = (uint32_t)(after - open - 2);
      return tok->start + open + 1;
    }
  } else if (tok->len >= 1 && tok->start[0] == '`') {
    size_t after = 0;
    if (shell_source_skip_complete_backtick(tok->start, tok->len, 0, &after)) {
      *out_len = (uint32_t)(after - 2);
      return tok->start + 1;
    }
  }
  *out_len = 0;
  return NULL;
}

typedef struct {
  const char *expected;
  size_t expected_length;
  size_t position;
  bool matches;
} dep_static_word_match_t;

static bool dep_static_word_match_byte(unsigned char byte, size_t position,
                                       void *context) {
  dep_static_word_match_t *match = context;
  if (!match)
    return false;
  if (position >= match->expected_length ||
      byte != (unsigned char)match->expected[position])
    match->matches = false;
  match->position = position + 1;
  return true;
}

/* Shell builtin roles apply after quote removal, but never after runtime
 * expansion. Keep the comparison allocation-free so route resolution can
 * recognize a static spelling such as e'x'ec without copying its word. */
static bool dep_token_static_equals(const dep_token_t *tok,
                                    const char *expected) {
  if (!tok || !tok->start || !expected)
    return false;
  dep_static_word_match_t match = {
      .expected = expected,
      .expected_length = strlen(expected),
      .matches = true,
  };
  size_t decoded_length = 0;
  return shell_visit_static_word(tok->start, tok->len,
                                 dep_static_word_match_byte, &match,
                                 &decoded_length) &&
         match.matches && match.position == match.expected_length &&
         decoded_length == match.expected_length;
}

typedef struct {
  bool starts_dash;
  size_t length;
} dep_static_dash_word_t;

static bool dep_static_dash_word_byte(unsigned char byte, size_t position,
                                      void *context) {
  dep_static_dash_word_t *word = context;
  if (!word)
    return false;
  if (position == 0)
    word->starts_dash = byte == '-';
  word->length = position + 1;
  return true;
}

static bool dep_token_static_starts_dash(const dep_token_t *tok) {
  if (!tok || !tok->start)
    return false;
  dep_static_dash_word_t word = {0};
  size_t decoded_length = 0;
  return shell_visit_static_word(tok->start, tok->len,
                                 dep_static_dash_word_byte, &word,
                                 &decoded_length) &&
         word.length == decoded_length && word.length > 0 && word.starts_dash;
}

typedef enum {
  DEP_CD_HOME,
  DEP_CD_OPERAND,
  DEP_CD_DYNAMIC,
  DEP_CD_INVALID,
} dep_cd_target_t;

typedef struct {
  bool valid;
  bool physical;
  bool attributes;
} dep_cd_option_t;

static bool dep_cd_option_byte(unsigned char byte, size_t position,
                               void *context) {
  dep_cd_option_t *option = context;
  if (position == 0) {
    option->valid = byte == '-';
  } else if (byte == 'P') {
    option->physical = true;
  } else if (byte == 'L') {
    option->physical = false;
  } else if (byte == '@') {
    option->attributes = true;
  } else if (byte != 'e') {
    option->valid = false;
  }
  return true;
}

/* Return the one pathname argument that can change CWD. Redirections do not
 * count as arguments. A provably invalid static form leaves CWD unchanged;
 * expansion-dependent arguments cannot prove that, since an expanded word may
 * become an option or disappear. Physical `-P` and attribute `-@` resolution
 * cannot be inferred from source text alone. */
static dep_cd_target_t cd_target(const dep_token_list_t *tokens,
                                 uint32_t command, const dep_token_t **operand,
                                 bool *physical) {
  bool end_options = false;
  bool dynamic = false;
  bool ambiguous = false;
  const dep_token_t *found = NULL;

  if (operand)
    *operand = NULL;
  if (physical)
    *physical = false;
  if (!tokens || command >= tokens->count)
    return DEP_CD_INVALID;
  for (uint32_t i = command + 1; i < tokens->count; i++) {
    dep_redirect_t redirect = classify_redirect(&tokens->tokens[i]);
    if (redirect != DEP_REDIRECT_NONE) {
      if (redirect != DEP_REDIRECT_DUP ||
          (i + 1 < tokens->count &&
           dep_redirect_is_legacy_combined_output(&tokens->tokens[i],
                                                  &tokens->tokens[i + 1])))
        i++;
      continue;
    }

    const dep_token_t *token = &tokens->tokens[i];
    if (dynamic)
      return ambiguous ? DEP_CD_DYNAMIC : DEP_CD_INVALID;
    bool dynamic_word =
        shell_source_word_has_dynamic_syntax(token->start, token->len);
    ambiguous = ambiguous || dynamic_word;
    /* Bash option parsing does not resume after a pathname. Any further
     * static word is a second argument, including `--` or `-P`; cd then
     * fails without changing directory. An expansion can still affect the
     * argument count, so retain the unknown state in that case. */
    if (found)
      return ambiguous ? DEP_CD_DYNAMIC : DEP_CD_INVALID;
    if (!end_options && dep_token_static_equals(token, "--")) {
      end_options = true;
      continue;
    }
    if (!end_options && dep_token_static_equals(token, "-")) {
      dynamic = true; /* `cd -` resolves through the runtime OLDPWD. */
      continue;
    }
    if (!end_options && !dynamic_word) {
      dep_cd_option_t option = {.physical = physical && *physical};
      size_t decoded_length = 0;
      if (shell_visit_static_word(token->start, token->len, dep_cd_option_byte,
                                  &option, &decoded_length) &&
          option.valid && decoded_length > 1) {
        if (option.attributes)
          return DEP_CD_DYNAMIC;
        if (physical)
          *physical = option.physical;
        continue;
      }
    }
    if (!end_options && dep_token_static_starts_dash(token))
      return ambiguous ? DEP_CD_DYNAMIC : DEP_CD_INVALID;
    found = token;
  }

  if (dynamic)
    return DEP_CD_DYNAMIC;
  if (!found)
    return DEP_CD_HOME;
  if (operand)
    *operand = found;
  return DEP_CD_OPERAND;
}

/* Locate the command word after leading assignments and redirections. A
 * wrapper-aware builtin classification must start here: `NAME=x command cd`
 * still changes the invoking shell's CWD, while redirect operands never do. */
static uint32_t dep_first_command_index(const dep_token_list_t *tokens) {
  if (!tokens)
    return UINT32_MAX;
  for (uint32_t i = 0; i < tokens->count; i++) {
    dep_redirect_t redirect = classify_redirect(&tokens->tokens[i]);
    if (redirect != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(tokens->tokens[i].start,
                                                 tokens->tokens[i].len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    if (!dep_token_is_assignment_word(&tokens->tokens[i]))
      return i;
  }
  return UINT32_MAX;
}

static bool decoded_path_indicator(unsigned char byte, size_t decoded_offset,
                                   void *context) {
  (void)decoded_offset;
  bool *found = context;
  *found = byte == '/' || byte == '.';
  return !*found;
}

static bool token_looks_like_path(const dep_token_t *tok) {
  bool found = false;
  size_t decoded_length = 0;
  return shell_visit_decoded_word(tok->start, tok->len, decoded_path_indicator,
                                  &found,
                                  &decoded_length) == SHELL_PROCESS_OK &&
         found;
}

static bool dep_redirect_is_legacy_combined_output(const dep_token_t *redirect,
                                                   const dep_token_t *target) {
  if (!redirect || !target || target->len == 0)
    return false;

  size_t after = 0;
  uint32_t descriptor = 0;
  shell_source_io_number_t source = shell_source_parse_io_number(
      redirect->start, 0, redirect->len, &after, &descriptor);
  if (source == SHELL_SOURCE_IO_NUMBER_OVERFLOW ||
      (source == SHELL_SOURCE_IO_NUMBER_VALID && descriptor != 1) ||
      (source == SHELL_SOURCE_IO_NUMBER_NONE &&
       shell_source_parse_named_fd_redirect(redirect->start, 0, redirect->len,
                                            &after)))
    return false;
  size_t operator_after = 0;
  if (!shell_source_match_logical_punctuation(redirect->start, redirect->len,
                                              after, ">&", &operator_after) ||
      operator_after != redirect->len)
    return false;

  return shell_process_classify_legacy_output_target(
             target->start, target->len) == SHELL_PROCESS_LEGACY_REDIRECT_PATH;
}

/* Decode a static cd operand into the bounded CWD resolver representation.
 * The resolver stores C strings, so decoded NUL and output overflow make the
 * destination unknowable rather than silently truncating or fabricating one. */
static bool decode_static_cwd_operand(const dep_token_t *tok, char *destination,
                                      size_t destination_size,
                                      bool *tilde_expanded, bool *truncated) {
  if (tilde_expanded)
    *tilde_expanded = false;
  if (truncated)
    *truncated = false;
  if (!tok || !destination || destination_size == 0 ||
      shell_source_word_has_dynamic_syntax_allow_tilde(tok->start, tok->len))
    return false;

  size_t decoded_length = 0;
  if (shell_measure_decoded_word(tok->start, tok->len, &decoded_length) !=
          SHELL_PROCESS_OK ||
      decoded_length == 0)
    return false;
  if (decoded_length >= destination_size) {
    if (truncated)
      *truncated = true;
    return false;
  }

  size_t written = 0;
  if (shell_write_decoded_word(tok->start, tok->len, destination,
                               destination_size - 1,
                               &written) != SHELL_PROCESS_OK ||
      written != decoded_length || memchr(destination, '\0', written) != NULL)
    return false;
  destination[written] = '\0';

  /* Only an unquoted leading tilde takes part in shell tilde expansion. */
  if (tok->start[0] != '~')
    return true;
  if (destination[0] != '~')
    return false;
  if (destination[1] == '\0') {
    if (destination_size < sizeof("$HOME")) {
      if (truncated)
        *truncated = true;
      return false;
    }
    memcpy(destination, "$HOME", sizeof("$HOME"));
    if (tilde_expanded)
      *tilde_expanded = true;
    return true;
  }
  if (destination[1] != '/')
    return false; /* ~user needs the runtime account database. */
  if (written + sizeof("$HOME") - 1 > destination_size) {
    if (truncated)
      *truncated = true;
    return false;
  }
  memmove(destination + sizeof("$HOME") - 1, destination + 1, written);
  memcpy(destination, "$HOME", sizeof("$HOME") - 1);
  if (tilde_expanded)
    *tilde_expanded = true;
  return true;
}

/* CDPATH can redirect a bare relative operand before the fallback relative to
 * the current directory. Dot-prefixed paths and an actual tilde expansion are
 * stable under that lookup. A literal `$HOME` spelling is still relative. */
static bool cwd_operand_uses_cdpath(const char *destination,
                                    bool tilde_expanded) {
  return destination && destination[0] != '\0' && destination[0] != '/' &&
         destination[0] != '.' && !tilde_expanded;
}

static bool range_is_in_group(const shell_parse_result_t *result,
                              const shell_group_t *group,
                              uint32_t range_index) {
  if (!result || !group || range_index >= result->count || group->end == 0)
    return false;
  const shell_range_t *range = &result->cmds[range_index];
  return range->start >= group->start && range->start < group->end;
}

/* A group is a pipeline member in its own right. Detect a directly preceding
 * reserved `!` instead of inheriting a nested command's modifier: in
 * `{ ! false | cat; echo; }`, only the inner pipeline is negated. */
static uint32_t group_pipeline_negation_count(const shell_group_t *group) {
  if (!group)
    return 0;
  if (group->pipeline_negation_count != 0)
    return group->pipeline_negation_count;
  return (group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 ? 1 : 0;
}

static bool group_is_pipeline_negated(const shell_group_t *group) {
  return (group_pipeline_negation_count(group) & UINT32_C(1)) != 0;
}

static int32_t find_innermost_group(const shell_parse_result_t *result,
                                    uint32_t range_index) {
  int32_t found = -1;
  uint32_t found_span = UINT32_MAX;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (!range_is_in_group(result, group, range_index))
      continue;
    uint32_t span = group->end - group->start;
    if (span < found_span) {
      found = (int32_t)i;
      found_span = span;
    }
  }
  return found;
}

static int32_t find_finished_group(const shell_parse_result_t *result,
                                   uint32_t range_index, uint32_t boundary) {
  int32_t found = -1;
  uint32_t latest_end = 0;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->end <= boundary && group->end >= latest_end &&
        range_is_in_group(result, group, range_index)) {
      found = (int32_t)i;
      latest_end = group->end;
    }
  }
  return found;
}

static int32_t find_pipe_input_group(const shell_parse_result_t *result,
                                     uint32_t source_range,
                                     uint32_t target_range) {
  if (source_range >= result->count || target_range >= result->count)
    return -1;
  uint32_t source_end =
      result->cmds[source_range].start + result->cmds[source_range].len;
  int32_t found = -1;
  uint32_t found_span = 0;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->start < source_end ||
        !range_is_in_group(result, group, target_range))
      continue;
    uint32_t span = group->end - group->start;
    if (span > found_span) {
      found = (int32_t)i;
      found_span = span;
    }
  }
  return found;
}

/* A compound group gains execution context from syntax outside its closing
 * delimiter.  The fast range for that control token belongs to the final
 * child, so recover the aggregate relation before child state is evaluated. */
typedef struct {
  bool isolated;
  bool backgrounded;
  bool cwd_initialized;
  uint32_t cwd_offset;
  bool cwd_known;
  bool cwd_absolute;
} dep_group_exec_t;

static void dep_prepare_group_execution(const char *command,
                                        uint32_t command_length,
                                        const shell_parse_result_t *result,
                                        dep_group_exec_t *groups) {
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    groups[i].isolated = group->kind == SHELL_GROUP_SUBSHELL;

    size_t position = shell_source_skip_inline_continuations(
        command, command_length, group->end);
    for (;;) {
      size_t after =
          shell_source_skip_redirect(command, position, command_length);
      if (after == position)
        break;
      position = shell_source_skip_inline_continuations(command, command_length,
                                                        after);
    }
    if (position >= command_length)
      continue;
    bool is_or = shell_source_match_logical_punctuation(command, command_length,
                                                        position, "||", NULL);
    bool is_and = shell_source_match_logical_punctuation(
        command, command_length, position, "&&", NULL);
    if (command[position] == '|' && !is_or) {
      groups[i].isolated = true;
    } else if (command[position] == '&' && !is_and) {
      groups[i].isolated = true;
      groups[i].backgrounded = true;
    }
  }
}

static int32_t dep_range_isolated_group(const shell_parse_result_t *result,
                                        const dep_group_exec_t *groups,
                                        uint32_t range_index) {
  int32_t group = find_innermost_group(result, range_index);
  while (group >= 0) {
    if (groups[group].isolated)
      return group;
    uint16_t parent = result->groups[group].parent;
    group = parent == UINT16_MAX ? -1 : (int32_t)parent;
  }
  return -1;
}

static bool dep_range_is_backgrounded(const shell_parse_result_t *result,
                                      const dep_group_exec_t *groups,
                                      uint32_t range_index) {
  if (result->cmds[range_index].features & SHELL_FEAT_BACKGROUND)
    return true;
  int32_t group = find_innermost_group(result, range_index);
  while (group >= 0) {
    if (groups[group].backgrounded)
      return true;
    uint16_t parent = result->groups[group].parent;
    group = parent == UINT16_MAX ? -1 : (int32_t)parent;
  }
  return false;
}

static void dep_initialize_group_cwd(const shell_parse_result_t *result,
                                     dep_group_exec_t *groups, uint32_t group,
                                     uint32_t global_offset, bool global_known,
                                     bool global_absolute) {
  dep_group_exec_t *context = &groups[group];
  if (context->cwd_initialized)
    return;

  uint32_t offset = global_offset;
  bool known = global_known;
  bool absolute = global_absolute;
  uint16_t parent = result->groups[group].parent;
  while (parent != UINT16_MAX) {
    if (groups[parent].isolated) {
      dep_initialize_group_cwd(result, groups, parent, global_offset,
                               global_known, global_absolute);
      offset = groups[parent].cwd_offset;
      known = groups[parent].cwd_known;
      absolute = groups[parent].cwd_absolute;
      break;
    }
    parent = result->groups[parent].parent;
  }
  context->cwd_offset = offset;
  context->cwd_known = known;
  context->cwd_absolute = absolute;
  context->cwd_initialized = true;
}

static int32_t find_preceding_group(const shell_parse_result_t *result,
                                    const char *command, uint32_t position) {
  int32_t found = -1;
  uint32_t latest_end = 0;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->end > position || group->end < latest_end)
      continue;
    if (shell_source_skip_inline_continuations(command, position, group->end) ==
        position) {
      found = (int32_t)i;
      latest_end = group->end;
    }
  }
  return found;
}

/* True when the source between a completed simple-command range and a later
 * redirect-only fast range contains only that command's continuing redirect
 * list.  A physical newline or comment cannot be skipped here: both begin a
 * new shell command, while horizontal space and escaped line endings remain
 * part of the same command. */
static bool command_redirect_tail(const char *command, uint32_t start,
                                  uint32_t end) {
  size_t position = start;
  while (position < end) {
    position = shell_source_skip_inline_continuations(command, end, position);
    if (position == end)
      return true;
    size_t after = shell_source_skip_redirect(command, position, end);
    if (after == position)
      return false;
    position = after;
  }
  return true;
}

/* Fast-parser ranges may start at the redirect operator, leaving an adjacent
 * io_number (for example the `3` in `cmd 3<<<word`) at the end of the prior
 * simple-command range.  That decimal prefix is redirect syntax only when it
 * touches the following operator.  Treat it as part of the continued
 * redirect list without allowing a newline, comment, or ordinary word to
 * bridge two independent commands. */
static bool command_redirect_tail_to_range(const char *command, uint32_t start,
                                           const shell_range_t *range) {
  if (!command || !range)
    return false;
  /* Fast ranges may end at the backslash byte while the following range
   * starts after its escaped line ending. Normalize that split before either
   * tail scanner examines an adjacent io_number. */
  if (start > 0 && start < range->start && command[start - 1] == '\\') {
    if (command[start] == '\n') {
      start++;
    } else if (command[start] == '\r') {
      start++;
      if (start < range->start && command[start] == '\n')
        start++;
    }
  }
  if (command_redirect_tail(command, start, range->start))
    return true;
  if (range->len == 0 ||
      (command[range->start] != '<' && command[range->start] != '>'))
    return false;

  size_t position =
      shell_source_skip_inline_continuations(command, range->start, start);
  while (position < range->start) {
    size_t after = shell_source_skip_redirect(command, position, range->start);
    if (after != position) {
      position =
          shell_source_skip_inline_continuations(command, range->start, after);
      continue;
    }
    size_t descriptor_after = position;
    uint32_t descriptor = 0;
    if (shell_source_parse_io_number(command, position, range->start,
                                     &descriptor_after, &descriptor) ==
            SHELL_SOURCE_IO_NUMBER_VALID &&
        descriptor_after == range->start)
      return true;
    size_t named_after = 0;
    return shell_source_parse_named_fd(command, position, range->start,
                                       &named_after) &&
           shell_source_skip_escaped_line_endings(command, range->start,
                                                  named_after) == range->start;
  }
  return true;
}

/* A group redirect list may contain several operations before a heredoc
 * declaration or a redirect-only fast-parser range. All bytes between the
 * group delimiter and that point must be redirect syntax; otherwise the
 * nearest completed group is not the execution owner. */
static int32_t find_trailing_redirect_group(const shell_parse_result_t *result,
                                            const char *command,
                                            uint32_t position) {
  int32_t found = -1;
  uint32_t latest_end = 0;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->end > position || group->end < latest_end)
      continue;
    size_t cursor = group->end;
    bool redirects_only = false;
    while (cursor < position) {
      cursor =
          shell_source_skip_inline_continuations(command, position, cursor);
      if (cursor == position)
        break;
      size_t after = shell_source_skip_redirect(command, cursor, position);
      if (after == cursor) {
        size_t named_after = 0;
        if (!shell_source_parse_named_fd(command, cursor, position,
                                         &named_after) ||
            shell_source_skip_escaped_line_endings(command, position,
                                                   named_after) != position) {
          redirects_only = false;
          break;
        }
        redirects_only = true;
        cursor = named_after;
        continue;
      }
      redirects_only = true;
      cursor = after;
    }
    if (redirects_only && cursor == position) {
      found = (int32_t)i;
      latest_end = group->end;
    }
  }
  return found;
}

static int32_t find_following_group(const shell_parse_result_t *result,
                                    const char *command, uint32_t position) {
  int32_t found = -1;
  uint32_t earliest_start = UINT32_MAX;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->start < position || group->start >= earliest_start)
      continue;
    if (shell_source_skip_inline_continuations(command, group->start,
                                               position) == group->start) {
      found = (int32_t)i;
      earliest_start = group->start;
    }
  }
  return found;
}

/* --- HEREDOC PRE-SCAN --- */

typedef struct {
  uint32_t marker_idx;
  /* `pending` retains the raw shell word for shared quote-removal matching;
   * `delimiter` is the most useful borrowed display span for consumers. */
  shell_source_pending_heredoc_t pending;
  const char *delimiter;
  uint32_t delimiter_len;
  bool literal;
  uint32_t line_end;
  uint32_t content_start_pos;
  uint32_t content_end_pos;
  uint32_t body_after_pos;
  bool has_source_span;
  bool document_built;
  int32_t cmd_node_idx;
  int32_t group_idx;
} heredoc_info_t;

/* Fast-parser inline-document ranges begin at `<<` or `<<<`, excluding an
 * optional POSIX io_number immediately before them. Recover that descriptor
 * from source so effective-route resolution can distinguish `3<<EOF` and
 * `3<<<word` from ordinary stdin. A command-word digit suffix is not an
 * io_number. */
static uint32_t inline_document_io_number_start(const char *cmd,
                                                uint32_t marker_start) {
  return (uint32_t)shell_source_io_number_start_before(cmd, marker_start,
                                                       marker_start);
}

static uint32_t inline_document_target_fd(const char *cmd,
                                          uint32_t marker_start) {
  if (shell_source_named_fd_start_before(cmd, marker_start, marker_start) !=
      marker_start)
    return SHELL_DEP_FD_NAMED;
  uint32_t digit_start = inline_document_io_number_start(cmd, marker_start);
  if (digit_start == marker_start)
    return 0;
  size_t after = 0;
  uint32_t descriptor = 0;
  bool valid = shell_source_parse_io_number(cmd, digit_start, marker_start,
                                            &after, &descriptor) ==
                   SHELL_SOURCE_IO_NUMBER_VALID &&
               after == marker_start;
  return valid ? descriptor : 0;
}

static bool inline_document_named_fd_name(const char *cmd,
                                          uint32_t marker_start,
                                          const char **name,
                                          uint32_t *name_len) {
  if (name)
    *name = NULL;
  if (name_len)
    *name_len = 0;
  if (!cmd || !name || !name_len)
    return false;
  uint32_t start = (uint32_t)shell_source_named_fd_start_before(
      cmd, marker_start, marker_start);
  if (start == marker_start)
    return false;
  size_t after = 0;
  if (!shell_source_parse_named_fd(cmd, start, marker_start, &after) ||
      after < 3 || after > marker_start || cmd[after - 1] != '}')
    return false;
  *name = cmd + start + 1;
  *name_len = (uint32_t)after - start - 2;
  return *name_len != 0;
}

static uint32_t prescan_heredocs(const char *cmd, size_t cmd_len,
                                 const shell_parse_result_t *result,
                                 heredoc_info_t *heredocs,
                                 uint32_t max_heredocs, bool *skip) {
  uint32_t hcount = 0;
  for (uint32_t i = 0; i < result->count; i++)
    skip[i] = false;

  for (uint32_t i = 0; i < result->count && hcount < max_heredocs; i++) {
    if (!(result->cmds[i].type & SHELL_TYPE_HEREDOC))
      continue;

    heredoc_info_t *hd = &heredocs[hcount];
    hd->marker_idx = i;
    hd->cmd_node_idx = -1;
    hd->group_idx = -1;
    hd->document_built = false;
    skip[i] = true;

    size_t delimiter = 0;
    size_t marker_end = result->cmds[i].start + result->cmds[i].len;
    if (!shell_source_match_logical_punctuation(
            cmd, marker_end, result->cmds[i].start, "<<", &delimiter) ||
        shell_source_match_logical_punctuation(
            cmd, marker_end, result->cmds[i].start, "<<<", NULL) ||
        !shell_source_parse_heredoc_delimiter(cmd, marker_end, &delimiter,
                                              &hd->pending))
      continue;

    hd->literal = shell_source_heredoc_delimiter_is_quoted(&hd->pending);
    hd->delimiter = hd->pending.word;
    hd->delimiter_len = (uint32_t)hd->pending.word_length;
    /* Preserve the existing concise public delimiter span for the common
     * fully quoted spelling. Mixed quoted words still borrow their raw span;
     * the shared source scanner supplies their semantic comparison. */
    if (hd->delimiter_len >= 2 &&
        (hd->delimiter[0] == '\'' || hd->delimiter[0] == '"') &&
        hd->delimiter[hd->delimiter_len - 1] == hd->delimiter[0]) {
      hd->delimiter++;
      hd->delimiter_len -= 2;
    }

    uint32_t mend = result->cmds[i].start + result->cmds[i].len;
    hd->line_end = (uint32_t)shell_source_line_end(cmd, cmd_len, mend);
    hd->content_start_pos = 0;
    hd->content_end_pos = 0;
    hd->body_after_pos = 0;
    hd->has_source_span = false;
    hcount++;
  }

  /* Heredocs consume bodies in marker order. Recover physical source spans
   * rather than relying on fast-parser ranges, which do not retain leading
   * `<<-` tabs and cannot encode shared-header ordering. */
  for (uint32_t h = 0; h < hcount; h++) {
    heredoc_info_t *hd = &heredocs[h];
    uint32_t body_start = hd->line_end < cmd_len ? hd->line_end + 1 : cmd_len;
    if (h > 0 && heredocs[h - 1].line_end == hd->line_end &&
        heredocs[h - 1].has_source_span)
      body_start = heredocs[h - 1].body_after_pos;

    for (uint32_t line = body_start; line < cmd_len;) {
      if (shell_source_line_is_heredoc_delimiter(cmd, cmd_len, line,
                                                 &hd->pending)) {
        hd->content_start_pos = body_start;
        hd->content_end_pos = line;
        hd->body_after_pos =
            (uint32_t)shell_source_next_line(cmd, cmd_len, line);
        hd->has_source_span = true;
        for (uint32_t i = hd->marker_idx + 1; i < result->count; i++) {
          if (result->cmds[i].start >= body_start &&
              result->cmds[i].start < hd->body_after_pos)
            skip[i] = true;
        }
        break;
      }
      uint32_t next = (uint32_t)shell_source_next_line(cmd, cmd_len, line);
      if (next <= line)
        break;
      line = next;
    }
    if (!hd->has_source_span) {
      /* The permissive parser treats an unfinished heredoc as opaque data to
       * EOF. Never turn its body into dependency commands. Strict callers
       * reject this form before graph construction. */
      for (uint32_t i = hd->marker_idx + 1; i < result->count; i++) {
        if (result->cmds[i].start > hd->line_end)
          skip[i] = true;
      }
    }
  }

  return hcount;
}

/* --- NODE/EDGE BUILDER HELPERS --- */

/* Keep every constructed edge fully initialized. Graph outputs may be reused
 * by callers, so leaving a new metadata field untouched would otherwise leak
 * state from the preceding parse into a semantically unrelated edge. */
static void dep_init_edge(shell_dep_edge_t *edge, uint32_t from, uint32_t to,
                          shell_dep_edge_type_t type, shell_dep_edge_dir_t dir,
                          uint32_t source_fd, uint32_t target_fd) {
  *edge = (shell_dep_edge_t){
      .from = from,
      .to = to,
      .type = type,
      .dir = dir,
      .flags = SHELL_DEP_EDGE_FLAG_NONE,
      .source_fd = source_fd,
      .target_fd = target_fd,
  };
}

/* A FILE node keeps its original redirect spelling for diagnostics, but its
 * name is runtime-derived whenever ordinary shell expansion participates.
 * Command substitutions are only one such form: parameter, arithmetic, glob,
 * brace, tilde, and process substitutions are equally non-static names. */
static bool dep_file_name_is_dynamic(const char *path, uint32_t path_len) {
  return shell_source_redirect_word_has_dynamic_path_syntax(path, path_len);
}

static void dep_file_doc_set_cwd(shell_dep_graph_t *graph, uint32_t document,
                                 uint32_t cwd_offset, bool cwd_known,
                                 bool cwd_absolute) {
  if (document >= graph->node_count ||
      graph->nodes[document].type != SHELL_NODE_DOC ||
      graph->nodes[document].doc.kind != SHELL_DOC_FILE)
    return;
  shell_dep_doc_t *doc = &graph->nodes[document].doc;
  doc->cwd_known = cwd_known && cwd_offset < graph->cwd_buf.len;
  doc->cwd_offset = doc->cwd_known ? cwd_offset : 0;
  doc->cwd_absolute = doc->cwd_known && cwd_absolute;
}

static void dep_file_doc_set_owner_cwd(shell_dep_graph_t *graph,
                                       uint32_t document, uint32_t owner,
                                       const uint32_t *group_nodes,
                                       const dep_group_exec_t *groups,
                                       uint32_t group_count) {
  if (owner >= graph->node_count)
    return;
  if (graph->nodes[owner].type == SHELL_NODE_CMD) {
    dep_file_doc_set_cwd(graph, document, graph->nodes[owner].cmd.cwd_offset,
                         graph->nodes[owner].cmd.cwd_known,
                         graph->nodes[owner].cmd.cwd_absolute);
    return;
  }
  if (graph->nodes[owner].type != SHELL_NODE_GROUP)
    return;
  for (uint32_t group = 0; group < group_count; group++)
    if (group_nodes[group] == owner) {
      dep_file_doc_set_cwd(graph, document, groups[group].cwd_offset,
                           groups[group].cwd_known, groups[group].cwd_absolute);
      return;
    }
}

static bool add_doc_file(shell_dep_graph_t *g, uint32_t max_nodes,
                         uint32_t max_edges, const char *path,
                         uint32_t path_len, uint32_t cmd_idx,
                         shell_dep_edge_type_t etype, shell_dep_edge_dir_t edir,
                         dep_redirect_t redir, uint32_t fd, uint32_t *status,
                         uint32_t *document_index) {
  if (document_index)
    *document_index = UINT32_MAX;
  if (g->node_count >= max_nodes || g->edge_count >= max_edges) {
    *status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }
  uint32_t document = g->node_count++;
  shell_dep_node_t *fn = &g->nodes[document];
  fn->type = SHELL_NODE_DOC;
  fn->doc.kind = SHELL_DOC_FILE;
  fn->doc.path = path;
  fn->doc.path_len = path_len;
  fn->doc.cwd_offset = 0;
  fn->doc.cwd_known = false;
  fn->doc.cwd_absolute = false;
  fn->doc.name = NULL;
  fn->doc.name_len = 0;
  fn->doc.value = NULL;
  fn->doc.value_len = 0;
  fn->doc.flags = SHELL_DEP_DOC_FLAG_NONE;
  if (dep_file_name_is_dynamic(path, path_len))
    fn->doc.flags |= SHELL_DEP_DOC_FLAG_DYNAMIC_NAME;

  shell_dep_edge_t *e = &g->edges[g->edge_count++];
  dep_init_edge(e, 0, 0, etype, edir, SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
  e->flags = etype == SHELL_EDGE_SUBST ? SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD
                                       : SHELL_DEP_EDGE_FLAG_NONE;

  if (etype == SHELL_EDGE_SUBST || redir == DEP_REDIRECT_IN) {
    e->from = document;
    e->to = cmd_idx;
    if (etype != SHELL_EDGE_SUBST)
      e->target_fd = fd;
  } else {
    e->from = cmd_idx;
    e->to = document;
    e->source_fd = fd;
  }
  if (etype == SHELL_EDGE_SUBST && g->nodes[e->from].type != SHELL_NODE_DOC)
    e->source_fd = fd;

  if (document_index)
    *document_index = document;
  return true;
}

/* `&>word` and `&>>word` open one file and bind both stdout and stderr to
 * that same open description. Keep one document node and two descriptor
 * edges; duplicating the document would imply two unrelated opens and loses
 * the shell relation. */
static bool add_doc_file_both_output(shell_dep_graph_t *g, uint32_t max_nodes,
                                     uint32_t max_edges, const char *path,
                                     uint32_t path_len, uint32_t cmd_idx,
                                     shell_dep_edge_type_t etype,
                                     uint32_t *status,
                                     uint32_t *document_index) {
  uint32_t document = UINT32_MAX;
  if (max_edges < 2 || g->edge_count > max_edges - 2 ||
      !add_doc_file(g, max_nodes, max_edges, path, path_len, cmd_idx, etype,
                    SHELL_DIR_FORWARD, DEP_REDIRECT_OUT, 1, status, &document))
    return false;
  shell_dep_edge_t *edge = &g->edges[g->edge_count++];
  dep_init_edge(edge, cmd_idx, document, etype, SHELL_DIR_FORWARD, 2,
                SHELL_DEP_FD_NONE);
  if (document_index)
    *document_index = document;
  return true;
}

/* `<>word` opens one descriptor for input and output. Keep one FILE document
 * with two syntactic edges; effective descriptor routing later preserves both
 * directions independently. */
static bool add_doc_file_read_write(shell_dep_graph_t *g, uint32_t max_nodes,
                                    uint32_t max_edges, const char *path,
                                    uint32_t path_len, uint32_t cmd_idx,
                                    uint32_t fd, uint32_t *status,
                                    uint32_t *document_index) {
  if (document_index)
    *document_index = UINT32_MAX;
  if (g->node_count >= max_nodes || max_edges < 2 ||
      g->edge_count > max_edges - 2) {
    *status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }
  uint32_t document = g->node_count++;
  shell_dep_node_t *node = &g->nodes[document];
  node->type = SHELL_NODE_DOC;
  node->doc.kind = SHELL_DOC_FILE;
  node->doc.path = path;
  node->doc.path_len = path_len;
  node->doc.cwd_offset = 0;
  node->doc.cwd_known = false;
  node->doc.cwd_absolute = false;
  node->doc.name = NULL;
  node->doc.name_len = 0;
  node->doc.value = NULL;
  node->doc.value_len = 0;
  node->doc.flags = SHELL_DEP_DOC_FLAG_NONE;
  if (dep_file_name_is_dynamic(path, path_len))
    node->doc.flags |= SHELL_DEP_DOC_FLAG_DYNAMIC_NAME;

  dep_init_edge(&g->edges[g->edge_count++], document, cmd_idx, SHELL_EDGE_READ,
                SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE, fd);
  dep_init_edge(&g->edges[g->edge_count++], cmd_idx, document, SHELL_EDGE_WRITE,
                SHELL_DIR_FORWARD, fd, SHELL_DEP_FD_NONE);
  if (document_index)
    *document_index = document;
  return true;
}

/* A Bash named-descriptor redirect records descriptor setup, not a claim that
 * the command itself reads or writes that descriptor. Its orientation still
 * matters: `<` supplies the named descriptor from the file, `>` and `>>`
 * open it for output, and `<>` establishes both directions against one open
 * FILE document. */
static bool add_doc_file_named_fd_open(shell_dep_graph_t *g, uint32_t max_nodes,
                                       uint32_t max_edges, const char *path,
                                       uint32_t path_len, uint32_t cmd_idx,
                                       dep_redirect_t redir,
                                       const char *fd_name,
                                       uint32_t fd_name_len, uint32_t *status,
                                       uint32_t *document_index) {
  if (redir != DEP_REDIRECT_READ_WRITE) {
    bool added = add_doc_file(g, max_nodes, max_edges, path, path_len, cmd_idx,
                              SHELL_EDGE_FD_OPEN, SHELL_DIR_FORWARD, redir,
                              SHELL_DEP_FD_NAMED, status, document_index);
    if (added && redir == DEP_REDIRECT_APPEND)
      g->edges[g->edge_count - 1].flags = SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND;
    if (added)
      dep_set_named_fd(&g->edges[g->edge_count - 1], redir != DEP_REDIRECT_IN,
                       fd_name, fd_name_len);
    return added;
  }

  if (document_index)
    *document_index = UINT32_MAX;
  if (g->node_count >= max_nodes || max_edges < 2 ||
      g->edge_count > max_edges - 2) {
    *status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }

  uint32_t document = g->node_count++;
  shell_dep_node_t *node = &g->nodes[document];
  node->type = SHELL_NODE_DOC;
  node->doc.kind = SHELL_DOC_FILE;
  node->doc.path = path;
  node->doc.path_len = path_len;
  node->doc.cwd_offset = 0;
  node->doc.cwd_known = false;
  node->doc.cwd_absolute = false;
  node->doc.name = NULL;
  node->doc.name_len = 0;
  node->doc.value = NULL;
  node->doc.value_len = 0;
  node->doc.flags = SHELL_DEP_DOC_FLAG_NONE;
  if (dep_file_name_is_dynamic(path, path_len))
    node->doc.flags |= SHELL_DEP_DOC_FLAG_DYNAMIC_NAME;

  dep_init_edge(&g->edges[g->edge_count++], document, cmd_idx,
                SHELL_EDGE_FD_OPEN, SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE,
                SHELL_DEP_FD_NAMED);
  dep_init_edge(&g->edges[g->edge_count++], cmd_idx, document,
                SHELL_EDGE_FD_OPEN, SHELL_DIR_FORWARD, SHELL_DEP_FD_NAMED,
                SHELL_DEP_FD_NONE);
  dep_set_named_fd(&g->edges[g->edge_count - 2], false, fd_name, fd_name_len);
  dep_set_named_fd(&g->edges[g->edge_count - 1], true, fd_name, fd_name_len);
  if (document_index)
    *document_index = document;
  return true;
}

static bool add_doc_envvar(shell_dep_graph_t *g, uint32_t max_nodes,
                           uint32_t max_edges, const char *name,
                           uint32_t name_len, const char *value,
                           uint32_t value_len, bool append, uint32_t cmd_idx,
                           uint32_t *status) {
  if (g->node_count >= max_nodes || g->edge_count >= max_edges) {
    *status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }
  shell_dep_node_t *en = &g->nodes[g->node_count++];
  en->type = SHELL_NODE_DOC;
  en->doc.kind = SHELL_DOC_ENVVAR;
  en->doc.name = name;
  en->doc.name_len = name_len;
  en->doc.value = value;
  en->doc.value_len = value_len;
  en->doc.flags =
      append ? SHELL_DEP_DOC_FLAG_ENVVAR_APPEND : SHELL_DEP_DOC_FLAG_NONE;
  en->doc.path = NULL;
  en->doc.path_len = 0;

  shell_dep_edge_t *e = &g->edges[g->edge_count++];
  dep_init_edge(e, g->node_count - 1, cmd_idx, SHELL_EDGE_ENV,
                SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);

  return true;
}

/* A redirection on a compound group applies to that compound command, not to
 * each member. Keep the real I/O endpoint in the graph and represent
 * containment separately with GROUP edges. */
static bool add_document_read(shell_dep_graph_t *g, uint32_t max_nodes,
                              uint32_t max_edges, uint32_t owner_idx,
                              shell_dep_doc_kind_t kind, const char *name,
                              uint32_t name_len, const char *value,
                              uint32_t value_len, uint32_t target_fd,
                              uint8_t flags, uint32_t *status,
                              uint32_t *document_index) {
  if (owner_idx >= g->node_count || g->node_count >= max_nodes ||
      g->edge_count >= max_edges) {
    *status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }

  uint32_t document_idx = g->node_count++;
  if (document_index)
    *document_index = document_idx;
  shell_dep_node_t *document = &g->nodes[document_idx];
  document->type = SHELL_NODE_DOC;
  document->doc.kind = kind;
  document->doc.name = name;
  document->doc.name_len = name_len;
  document->doc.value = value;
  document->doc.value_len = value_len;
  document->doc.flags = flags;
  document->doc.path = NULL;
  document->doc.path_len = 0;

  shell_dep_edge_t *edge = &g->edges[g->edge_count++];
  shell_dep_edge_type_t edge_type =
      target_fd == SHELL_DEP_FD_NAMED ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_READ;
  dep_init_edge(edge, document_idx, owner_idx, edge_type, SHELL_DIR_FORWARD,
                SHELL_DEP_FD_NONE, target_fd);
  return true;
}

/* A pipeline supplies fd 0 to its right-hand command or compound group. A
 * source-order redirect of that descriptor replaces the pipe input, so retain
 * only the actual document-to-owner flow. This runs after heredoc ownership is
 * resolved because its document edge is discovered after the command ranges. */
/* A dependency graph is useful only when its I/O edges describe the effective
 * descriptor bindings, not every redirect spelling.  The parser builds the
 * convenient syntactic document edges first, then this bounded resolver
 * applies each owner's operations in source order and materializes its final
 * descriptor routes. */
static void dep_add_edge(shell_dep_graph_t *graph, uint32_t from, uint32_t to,
                         shell_dep_edge_type_t type, uint32_t source_fd,
                         uint32_t target_fd);

typedef enum {
  /* An unmentioned descriptor retains the stream inherited by the parsed
   * command. Keep its original descriptor identity: `1>&2` is not stdout
   * inheritance, while `2>&1; 1>&2` is. */
  DEP_ROUTE_INHERITED = 0,
  /* A descriptor was allocated, but this direction was never opened. It is
   * distinct from an explicit close: Bash permits copying it as descriptor
   * setup even though a later operation in this direction will fail. */
  DEP_ROUTE_UNAVAILABLE,
  /* Closing a descriptor is distinct from never mentioning it. It has no
   * graph edge, but must suppress inferred substitution topology. */
  DEP_ROUTE_CLOSED,
  DEP_ROUTE_DOC,
  DEP_ROUTE_PIPE,
  DEP_ROUTE_DYNAMIC,
  /* A recursively parsed execution scope inherited a concrete named
   * descriptor from its caller. The route is materialized against the
   * caller's original document or endpoint when that child graph is joined. */
  DEP_ROUTE_IMPORTED,
} dep_route_kind_t;

typedef struct {
  uint32_t value;
  /* A named Bash descriptor is identified by its logical variable spelling,
   * not by the shared SHELL_DEP_FD_NAMED sentinel. */
  const char *name;
  uint32_t name_len;
} dep_fd_ref_t;

static dep_fd_ref_t dep_fd_numeric(uint32_t value) {
  return (dep_fd_ref_t){value, NULL, 0};
}

/* Named redirection spellings use the same escaped-physical-line-ending
 * normalization as their source parser. Compare logical identifier bytes so
 * `{f\\\nd}`, `{f\\\r\nd}`, and `{f\\\rd}` are never confused with another
 * name solely because the source happens to be physically wrapped. */
static bool dep_fd_name_next_byte(const char *name, uint32_t name_len,
                                  uint32_t *position, unsigned char *byte) {
  if (!name || !position || !byte)
    return false;
  size_t cursor = *position;
  if (cursor > name_len)
    return false;
  cursor = shell_source_skip_escaped_line_endings(name, name_len, cursor);
  if (cursor > name_len)
    return false;
  *position = (uint32_t)cursor;
  if (cursor == name_len)
    return false;
  *byte = (unsigned char)name[cursor++];
  *position = (uint32_t)cursor;
  return true;
}

static bool dep_fd_name_equal(const char *left, uint32_t left_len,
                              const char *right, uint32_t right_len) {
  uint32_t left_position = 0;
  uint32_t right_position = 0;
  unsigned char left_byte = 0;
  unsigned char right_byte = 0;
  bool have_left = false;
  bool have_right = false;
  do {
    have_left =
        dep_fd_name_next_byte(left, left_len, &left_position, &left_byte);
    have_right =
        dep_fd_name_next_byte(right, right_len, &right_position, &right_byte);
    if (have_left != have_right || (have_left && left_byte != right_byte))
      return false;
  } while (have_left);
  return true;
}

static bool dep_fd_ref_equal(dep_fd_ref_t left, dep_fd_ref_t right) {
  if (left.value != right.value)
    return false;
  if (left.value != SHELL_DEP_FD_NAMED)
    return true;
  return left.name && right.name &&
         dep_fd_name_equal(left.name, left.name_len, right.name,
                           right.name_len);
}

typedef struct {
  dep_route_kind_t kind;
  /* The inherited descriptor for DEP_ROUTE_INHERITED, otherwise an edge or
   * pipe index for materialized routes. */
  uint32_t value;
} dep_fd_route_t;

typedef struct {
  dep_fd_ref_t fd;
  dep_fd_route_t read_route;
  dep_fd_route_t write_route;
} dep_fd_route_entry_t;

#define DEP_MAX_FD_ROUTES (SHELL_DEP_MAX_EDGES + 8)

typedef struct {
  /* A descriptor may support both directions (`<>file`). Keep them separate:
   * a later output route must not erase the input relation to the same file. */
  dep_fd_route_entry_t fd[DEP_MAX_FD_ROUTES];
  uint32_t fd_count;
} dep_owner_routes_t;

typedef struct {
  dep_fd_ref_t fd;
  dep_fd_route_t read_route;
  dep_fd_route_t write_route;
  /* Read and write bindings may come from different parent graphs.  Keep
   * their provenance separate so a locally rebound half of a bidirectional
   * descriptor cannot make the other half appear local as well. */
  const shell_dep_graph_t *read_origin;
  const shell_dep_graph_t *write_origin;
} dep_fd_import_t;

typedef struct {
  dep_fd_import_t entries[DEP_MAX_FD_ROUTES];
  uint32_t count;
} dep_fd_imports_t;

typedef struct {
  uint32_t owner;
  uint32_t fd;
  uint8_t access;
  uint32_t import_index;
} dep_fd_import_use_t;

typedef struct dep_route_workspace dep_route_workspace_t;

/* Recursive graphs need one small piece of information that is deliberately
 * not public graph topology: whether each execution endpoint still exposes
 * the external streams inherited by the containing substitution. The parser
 * uses it only while joining recursive graphs; callers continue to consume
 * the graph's concrete READ/WRITE/PIPE/SUBST edges. */
typedef struct {
  bool stdin_inherited[SHELL_DEP_MAX_NODES];
  bool stdout_inherited[SHELL_DEP_MAX_NODES];
  /* Private join metadata: public graph edges remain the sole externally
   * visible representation of inherited descriptor byte flow. */
  dep_fd_imports_t fd_imports;
  dep_fd_import_use_t fd_import_uses[SHELL_DEP_MAX_EDGES];
  uint32_t fd_import_use_count;
} dep_subgraph_streams_t;

/* Structural parsing discovers a recursive shell before the enclosing graph
 * has completed route resolution.  Keep the source metadata required to
 * replay only the descriptor state visible at that exact expansion point. */
typedef struct {
  const char *cmd;
  uint32_t cmd_len;
  const shell_parse_result_t *fast;
  const uint32_t *node_range;
  const uint32_t *group_node;
  const dep_group_exec_t *group_exec;
  const bool *group_entered;
  dep_route_workspace_t *workspace;
} dep_parse_context_t;

static bool dep_expansion_cwd_known(const shell_dep_graph_t *graph,
                                    const dep_parse_context_t *context,
                                    uint32_t owner) {
  if (!graph || !context || owner >= graph->node_count)
    return false;
  if (graph->nodes[owner].type == SHELL_NODE_CMD)
    return graph->nodes[owner].cmd.cwd_known;
  if (graph->nodes[owner].type == SHELL_NODE_GROUP)
    for (uint32_t group = 0; group < context->fast->group_count; group++)
      if (context->group_node[group] == owner)
        return context->group_exec[group].cwd_known;
  return false;
}

static bool dep_expansion_cwd_absolute(const shell_dep_graph_t *graph,
                                       const dep_parse_context_t *context,
                                       uint32_t owner) {
  if (!graph || !context || owner >= graph->node_count)
    return false;
  if (graph->nodes[owner].type == SHELL_NODE_CMD)
    return graph->nodes[owner].cmd.cwd_absolute;
  if (graph->nodes[owner].type == SHELL_NODE_GROUP)
    for (uint32_t group = 0; group < context->fast->group_count; group++)
      if (context->group_node[group] == owner)
        return context->group_exec[group].cwd_absolute;
  return false;
}

enum {
  DEP_ENDPOINT_TERMINAL_PIPE = 1,
  /* A named-FD process substitution can have no inherited nested endpoint:
   * its pipe still exists, but it has no byte-flow relation until a later
   * symbolic descriptor use materializes one. */
  DEP_ENDPOINT_UNCONNECTED_PROCESS_SUBSTITUTION = 2,
  /* Internal raw-pipe marker, consumed before the public graph is returned. */
  DEP_EDGE_FLAG_PIPE_STDERR = 1 << 7,
};

typedef enum {
  DEP_FD_OP_DOCUMENT,
  DEP_FD_OP_DYNAMIC,
  DEP_FD_OP_DUP,
  DEP_FD_OP_CLOSE,
} dep_fd_op_kind_t;

typedef enum {
  DEP_FD_ACCESS_READ = 1 << 0,
  DEP_FD_ACCESS_WRITE = 1 << 1,
  DEP_FD_ACCESS_BOTH = DEP_FD_ACCESS_READ | DEP_FD_ACCESS_WRITE,
} dep_fd_access_t;

typedef struct {
  uint32_t pos;
  dep_fd_op_kind_t kind;
  uint32_t fd;
  uint32_t target_fd;
  const char *fd_name;
  uint32_t fd_name_len;
  const char *target_fd_name;
  uint32_t target_fd_name_len;
  uint32_t edge_index;
  dep_fd_access_t access;
} dep_fd_op_t;

typedef struct {
  uint32_t owner;
  dep_fd_op_t op;
} dep_fd_transition_t;

/* The effective-route pass needs the final descriptor view for every graph
 * owner while it materializes routes, but it must neither reserve this bound
 * on every caller stack nor allocate it implicitly. Callers provide one
 * reusable workspace for the duration of a parse. Isolated descriptor scopes
 * remain lazy overlays because most commands have none. */
struct dep_route_workspace {
  dep_owner_routes_t routes[SHELL_DEP_MAX_NODES];
  /* Two bits per final owner/route entry record whether that owner itself
   * assigned its read or write half. This is emission provenance, not part of
   * the inherited descriptor table. */
  uint8_t route_touched[SHELL_DEP_MAX_NODES][(DEP_MAX_FD_ROUTES + 3) / 4];
  dep_owner_routes_t scoped_routes[SHELL_MAX_GROUPS];
  bool scoped_routes_active[SHELL_MAX_GROUPS];
  /* Recursive expansion and final resolution use these at different times
   * for each containing group's evolving descriptor table. Keep the bounded
   * scratch in the caller-owned workspace, not on a parser stack. */
  dep_owner_routes_t group_snapshot_routes[SHELL_MAX_GROUPS];
  bool group_snapshot_routes_ready[SHELL_MAX_GROUPS];
  /* Named setup has a deliberately different lifetime from a numeric FD_OPEN:
   * retain its document only while the resolver's final persistent table still
   * contains a route to it.  Keep this short-lived bookkeeping with the rest
   * of the caller-provided route workspace. */
  bool named_setup_documents[SHELL_DEP_MAX_NODES];
  bool live_named_documents[SHELL_DEP_MAX_NODES];
  shell_dep_edge_t original_edges[SHELL_DEP_MAX_EDGES];
  dep_fd_transition_t fd_transitions[SHELL_DEP_MAX_EDGES];
  shell_dep_edge_t pipes[SHELL_DEP_MAX_EDGES];
  dep_fd_op_t ops[SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS];
  dep_fd_ref_t named_allocations[SHELL_DEP_MAX_EDGES];
  uint32_t named_allocation_positions[SHELL_DEP_MAX_EDGES];
};

size_t shell_dep_workspace_alignment(void) {
  return _Alignof(dep_route_workspace_t);
}

bool shell_dep_workspace_size(const shell_dep_limits_t *limits,
                              size_t *workspace_size) {
  (void)limits;
  if (!workspace_size)
    return false;
  *workspace_size = sizeof(dep_route_workspace_t);
  return true;
}

static bool dep_is_execution_node(const shell_dep_graph_t *graph,
                                  uint32_t node) {
  return node < graph->node_count &&
         (graph->nodes[node].type == SHELL_NODE_CMD ||
          graph->nodes[node].type == SHELL_NODE_GROUP);
}

static dep_fd_route_entry_t *dep_route_slot(dep_fd_route_entry_t *entries,
                                            uint32_t *count, dep_fd_ref_t fd,
                                            bool create) {
  for (uint32_t i = 0; i < *count; i++)
    if (dep_fd_ref_equal(entries[i].fd, fd))
      return &entries[i];
  if (!create || *count >= DEP_MAX_FD_ROUTES)
    return NULL;
  entries[*count].fd = fd;
  entries[*count].read_route = (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value};
  entries[*count].write_route = (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value};
  return &entries[(*count)++];
}

static bool dep_route_assign(dep_fd_route_entry_t *entries, uint32_t *count,
                             dep_fd_ref_t fd, dep_fd_access_t access,
                             dep_fd_route_t route) {
  dep_fd_route_entry_t *slot = dep_route_slot(entries, count, fd, true);
  if (!slot)
    return false;
  if (access & DEP_FD_ACCESS_READ)
    slot->read_route = route;
  if (access & DEP_FD_ACCESS_WRITE)
    slot->write_route = route;
  return true;
}

/* `{name}>file` assigns a fresh numeric descriptor to `name`: it replaces,
 * rather than augments, the variable's earlier descriptor. A `<>` redirect
 * emits two operations at the same source position, so its caller resets
 * once and installs its read and write halves independently. */
static bool dep_route_reset_named(dep_owner_routes_t *routes, dep_fd_ref_t fd) {
  return routes &&
         dep_route_assign(routes->fd, &routes->fd_count, fd, DEP_FD_ACCESS_BOTH,
                          (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
}

static dep_fd_import_t *dep_fd_import_slot(dep_fd_imports_t *imports,
                                           dep_fd_ref_t fd, bool create) {
  if (!imports)
    return NULL;
  for (uint32_t i = 0; i < imports->count; i++)
    if (dep_fd_ref_equal(imports->entries[i].fd, fd))
      return &imports->entries[i];
  if (!create || imports->count >= DEP_MAX_FD_ROUTES)
    return NULL;
  dep_fd_import_t *slot = &imports->entries[imports->count++];
  *slot = (dep_fd_import_t){
      .fd = fd,
      .read_route = {DEP_ROUTE_INHERITED, fd.value},
      .write_route = {DEP_ROUTE_INHERITED, fd.value},
      .read_origin = NULL,
      .write_origin = NULL,
  };
  return slot;
}

/* The syntactic graph carries source-order setup relations by edge index.
 * Import their routes into a nested shell's private state; the joiner later
 * materializes each actual use against the original parent resource. */
static void dep_import_routes(dep_owner_routes_t *routes,
                              const dep_fd_imports_t *imports) {
  if (!routes || !imports)
    return;
  for (uint32_t i = 0; i < imports->count; i++) {
    const dep_fd_import_t *item = &imports->entries[i];
    if (item->read_route.kind == DEP_ROUTE_IMPORTED)
      dep_route_assign(routes->fd, &routes->fd_count, item->fd,
                       DEP_FD_ACCESS_READ,
                       (dep_fd_route_t){DEP_ROUTE_IMPORTED, i});
    else
      dep_route_assign(routes->fd, &routes->fd_count, item->fd,
                       DEP_FD_ACCESS_READ, item->read_route);
    if (item->write_route.kind == DEP_ROUTE_IMPORTED)
      dep_route_assign(routes->fd, &routes->fd_count, item->fd,
                       DEP_FD_ACCESS_WRITE,
                       (dep_fd_route_t){DEP_ROUTE_IMPORTED, i});
    else
      dep_route_assign(routes->fd, &routes->fd_count, item->fd,
                       DEP_FD_ACCESS_WRITE, item->write_route);
  }
}

static bool dep_record_fd_import_use(dep_subgraph_streams_t *streams,
                                     uint32_t owner, uint32_t fd,
                                     dep_fd_access_t access,
                                     uint32_t import_index) {
  if (!streams || streams->fd_import_use_count >= SHELL_DEP_MAX_EDGES)
    return false;
  streams->fd_import_uses[streams->fd_import_use_count++] =
      (dep_fd_import_use_t){owner, fd, access, import_index};
  return true;
}

static int32_t dep_merge_fd_import(dep_fd_imports_t *destination,
                                   const dep_fd_import_t *source) {
  if (!destination || !source)
    return -1;
  for (uint32_t i = 0; i < destination->count; i++)
    if (destination->entries[i].read_origin == source->read_origin &&
        destination->entries[i].write_origin == source->write_origin &&
        dep_fd_ref_equal(destination->entries[i].fd, source->fd) &&
        destination->entries[i].read_route.kind == source->read_route.kind &&
        destination->entries[i].read_route.value == source->read_route.value &&
        destination->entries[i].write_route.kind == source->write_route.kind &&
        destination->entries[i].write_route.value == source->write_route.value)
      return (int32_t)i;
  if (destination->count >= DEP_MAX_FD_ROUTES)
    return -1;
  destination->entries[destination->count] = *source;
  return (int32_t)destination->count++;
}

/* Recursive substitution plumbing owns one standard stream. Do not import a
 * parent redirect for that stream: `$(...)` and `<(...)` capture child stdout,
 * while `>(...)` supplies child stdin. Other persistent descriptors, including
 * stderr and auxiliary numeric FDs, remain available to the child. */
static void dep_fd_import_restore_inherited(dep_fd_imports_t *imports,
                                            uint32_t fd,
                                            dep_fd_access_t access) {
  if (!imports)
    return;
  dep_fd_ref_t ref = dep_fd_numeric(fd);
  dep_fd_import_t *slot = dep_fd_import_slot(imports, ref, false);
  if (!slot)
    return;
  if (access & DEP_FD_ACCESS_READ) {
    slot->read_route = (dep_fd_route_t){DEP_ROUTE_INHERITED, fd};
    slot->read_origin = NULL;
  }
  if (access & DEP_FD_ACCESS_WRITE) {
    slot->write_route = (dep_fd_route_t){DEP_ROUTE_INHERITED, fd};
    slot->write_origin = NULL;
  }
}

static dep_fd_route_t dep_route_get(const dep_fd_route_entry_t *entries,
                                    uint32_t count, dep_fd_ref_t fd,
                                    dep_fd_access_t access) {
  for (uint32_t i = 0; i < count; i++)
    if (dep_fd_ref_equal(entries[i].fd, fd))
      return access == DEP_FD_ACCESS_READ ? entries[i].read_route
                                          : entries[i].write_route;
  return (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value};
}

static bool dep_route_inherits(const dep_owner_routes_t *routes, uint32_t fd,
                               dep_fd_access_t access) {
  dep_fd_route_t route =
      dep_route_get(routes->fd, routes->fd_count, dep_fd_numeric(fd), access);
  return route.kind == DEP_ROUTE_INHERITED && route.value == fd;
}

static const char *dep_document_source(const shell_dep_node_t *node) {
  if (node->type != SHELL_NODE_DOC)
    return NULL;
  if (node->doc.kind == SHELL_DOC_FILE)
    return node->doc.path;
  if (node->doc.kind == SHELL_DOC_HEREDOC)
    return node->doc.name;
  return node->doc.value;
}

/* Descriptor values emitted by Bash's `{name}` allocation are ordinary shell
 * variables.  This graph layer deliberately recognizes only a complete,
 * optionally double-quoted reference: evaluating `${fd:-3}`, indirection, or
 * a concatenated shell word would require a separate value analysis and must
 * not silently become a descriptor route. */
static bool dep_parse_fd_parameter(const char *text, uint32_t start,
                                   uint32_t end, const char **name,
                                   uint32_t *name_len) {
  if (name)
    *name = NULL;
  if (name_len)
    *name_len = 0;
  size_t parsed_start = 0;
  size_t parsed_end = 0;
  if (!shell_source_parse_named_fd_parameter(text, start, end, &parsed_start,
                                             &parsed_end) ||
      parsed_start > UINT32_MAX || parsed_end > UINT32_MAX)
    return false;
  *name = text + parsed_start;
  *name_len = (uint32_t)(parsed_end - parsed_start);
  return true;
}

static bool dep_parse_dup_redirect(const dep_token_t *token, uint32_t *fd,
                                   uint32_t *target_fd, const char **fd_name,
                                   uint32_t *fd_name_len,
                                   const char **target_fd_name,
                                   uint32_t *target_fd_name_len, bool *close,
                                   dep_fd_access_t *access) {
  if (!token || !fd || !target_fd || !fd_name || !fd_name_len ||
      !target_fd_name || !target_fd_name_len || !close || !access ||
      token->len < 2)
    return false;
  size_t after = 0;
  uint32_t value = 0;
  *fd_name = NULL;
  *fd_name_len = 0;
  *target_fd_name = NULL;
  *target_fd_name_len = 0;
  *fd = SHELL_DEP_FD_NONE;
  shell_source_io_number_t source_number =
      shell_source_parse_io_number(token->start, 0, token->len, &after, &value);
  if (source_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return false;
  uint32_t pos = (uint32_t)after;
  if (source_number == SHELL_SOURCE_IO_NUMBER_NONE &&
      shell_source_parse_named_fd_redirect(token->start, 0, token->len,
                                           &after)) {
    size_t name_after = 0;
    if (!shell_source_parse_named_fd(token->start, 0, after, &name_after) ||
        name_after < 3 || name_after > after ||
        token->start[name_after - 1] != '}')
      return false;
    *fd = SHELL_DEP_FD_NAMED;
    *fd_name = token->start + 1;
    *fd_name_len = (uint32_t)name_after - 2;
    pos = (uint32_t)after;
  }
  if (pos >= token->len ||
      (token->start[pos] != '<' && token->start[pos] != '>'))
    return false;
  bool input = token->start[pos] == '<';
  if (*fd != SHELL_DEP_FD_NAMED)
    *fd =
        source_number == SHELL_SOURCE_IO_NUMBER_NONE ? (input ? 0 : 1) : value;
  *access = input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE;
  pos++;
  pos = (uint32_t)shell_source_skip_escaped_line_endings(token->start,
                                                         token->len, pos);
  if (pos >= token->len || token->start[pos++] != '&')
    return false;
  pos = (uint32_t)shell_source_skip_escaped_line_endings(token->start,
                                                         token->len, pos);
  if (pos == token->len - 1 && token->start[pos] == '-') {
    *close = true;
    *target_fd = SHELL_DEP_FD_NONE;
    return true;
  }
  size_t target_after = 0;
  shell_source_io_number_t target_number = shell_source_parse_io_number(
      token->start, pos, token->len, &target_after, &value);
  if (target_number == SHELL_SOURCE_IO_NUMBER_VALID &&
      target_after == token->len) {
    *target_fd = value;
    *close = false;
    return true;
  }
  if (dep_parse_fd_parameter(token->start, pos, token->len, target_fd_name,
                             target_fd_name_len)) {
    *target_fd = SHELL_DEP_FD_NAMED;
    *close = false;
    return true;
  }
  shell_process_fd_target_t target = shell_process_classify_static_fd_target(
      token->start + pos, token->len - pos, &value);
  if (target == SHELL_PROCESS_FD_TARGET_FD) {
    *target_fd = value;
    *close = false;
    return true;
  }
  if (target == SHELL_PROCESS_FD_TARGET_CLOSE) {
    *target_fd = SHELL_DEP_FD_NONE;
    *close = true;
    return true;
  }
  return false;
}

static bool dep_add_dup_operations(const char *cmd, uint32_t start,
                                   uint32_t length, dep_fd_op_t *ops,
                                   uint32_t *op_count, uint32_t op_capacity,
                                   bool *invalid) {
  if (invalid)
    *invalid = false;
  dep_token_list_t tokens = {0};
  if (scan_tokens(cmd, start, length, &tokens))
    return false;
  for (uint32_t i = 0; i < tokens.count; i++) {
    bool close;
    uint32_t fd;
    uint32_t target_fd;
    dep_fd_access_t access;
    const char *fd_name = NULL;
    uint32_t fd_name_len = 0;
    const char *target_fd_name = NULL;
    uint32_t target_fd_name_len = 0;
    if (!dep_parse_dup_redirect(&tokens.tokens[i], &fd, &target_fd, &fd_name,
                                &fd_name_len, &target_fd_name,
                                &target_fd_name_len, &close, &access)) {
      const dep_token_t *redirect = &tokens.tokens[i];
      dep_redirect_t kind = classify_redirect(redirect);
      if (kind == DEP_REDIRECT_DUP && i + 1 < tokens.count &&
          dep_redirect_is_legacy_combined_output(redirect,
                                                 &tokens.tokens[i + 1])) {
        /* The main graph pass emits both FILE operations for this spelling.
         * It is not a descriptor duplication for effective-route purposes. */
        i++;
        continue;
      }
      bool bare_operand = kind == DEP_REDIRECT_DUP && redirect->len >= 2 &&
                          redirect->start[redirect->len - 1] == '&';
      if (!bare_operand)
        continue;
      if (++i >= tokens.count) {
        if (invalid)
          *invalid = true;
        return true;
      }
      const dep_token_t *target = &tokens.tokens[i];
      if (dep_parse_fd_parameter(target->start, 0, target->len, &target_fd_name,
                                 &target_fd_name_len)) {
        target_fd = SHELL_DEP_FD_NAMED;
        close = false;
      } else {
        shell_process_fd_target_t target_kind =
            shell_process_classify_static_fd_target(target->start, target->len,
                                                    &target_fd);
        if (target_kind == SHELL_PROCESS_FD_TARGET_CLOSE) {
          target_fd = SHELL_DEP_FD_NONE;
          close = true;
        } else if (target_kind == SHELL_PROCESS_FD_TARGET_FD) {
          close = false;
        } else {
          if (invalid)
            *invalid = true;
          return true;
        }
      }
      size_t operator_pos = 0;
      uint32_t ignored_fd = 0;
      shell_source_io_number_t source_number = shell_source_parse_io_number(
          redirect->start, 0, redirect->len, &operator_pos, &ignored_fd);
      if (source_number == SHELL_SOURCE_IO_NUMBER_NONE &&
          shell_source_parse_named_fd_redirect(redirect->start, 0,
                                               redirect->len, &operator_pos)) {
        /* `operator_pos` now names the direction byte. */
      }
      access =
          operator_pos < redirect->len && redirect->start[operator_pos] == '<'
              ? DEP_FD_ACCESS_READ
              : DEP_FD_ACCESS_WRITE;
      fd = redirect_fd(redirect, kind);
      if (fd == SHELL_DEP_FD_NAMED &&
          !dep_named_fd_name(redirect, &fd_name, &fd_name_len)) {
        if (invalid)
          *invalid = true;
        return true;
      }
    }
    if (*op_count >= op_capacity)
      return false;
    ops[(*op_count)++] = (dep_fd_op_t){
        (uint32_t)(tokens.tokens[i].start - cmd),
        close ? DEP_FD_OP_CLOSE : DEP_FD_OP_DUP,
        fd,
        target_fd,
        fd_name,
        fd_name_len,
        target_fd_name,
        target_fd_name_len,
        UINT32_MAX,
        close ? DEP_FD_ACCESS_BOTH : access,
    };
  }
  return true;
}

/* Process substitutions are descriptor routes just like file redirects. They
 * have already contributed their graph edges before effective routing runs;
 * retain the source position here so a later redirect, close, or duplicate
 * can replace or copy that route without leaving a stale PIPE edge behind. */
static bool dep_add_process_substitution_operations(
    const char *cmd, uint32_t start, uint32_t length, uint32_t owner,
    const shell_dep_graph_t *graph, const shell_dep_edge_t *original_edges,
    uint32_t original_edge_count, bool *used_edges, bool *dynamic_edges,
    dep_fd_op_t *ops, uint32_t *op_count, uint32_t op_capacity) {
  dep_token_list_t tokens = {0};
  if (scan_tokens(cmd, start, length, &tokens))
    return false;

  for (uint32_t token = 0; token < tokens.count; token++) {
    const dep_token_t *redirect = &tokens.tokens[token];
    dep_redirect_t kind = classify_redirect(redirect);
    if (kind == DEP_REDIRECT_DUP && token + 1 < tokens.count &&
        dep_redirect_is_legacy_combined_output(redirect,
                                               &tokens.tokens[token + 1]))
      kind = DEP_REDIRECT_BOTH;
    if (kind == DEP_REDIRECT_DUP || kind == DEP_REDIRECT_NONE)
      continue;
    if (++token >= tokens.count)
      break;
    const dep_token_t *target = &tokens.tokens[token];
    if ((kind != DEP_REDIRECT_IN && kind != DEP_REDIRECT_OUT &&
         kind != DEP_REDIRECT_APPEND && kind != DEP_REDIRECT_READ_WRITE &&
         kind != DEP_REDIRECT_BOTH && kind != DEP_REDIRECT_BOTH_APPEND) ||
        !dep_redirect_target_is_process_substitution(target))
      continue;

    bool input = dep_process_substitution_is_input(kind, target);
    bool output = dep_process_substitution_is_output(kind, target);
    if (!input && !output)
      continue;
    uint32_t fd = redirect_fd(redirect, kind);
    const char *fd_name = NULL;
    uint32_t fd_name_len = 0;
    if (fd == SHELL_DEP_FD_NAMED &&
        !dep_named_fd_name(redirect, &fd_name, &fd_name_len))
      return false;
    bool combined = output && (kind == DEP_REDIRECT_BOTH ||
                               kind == DEP_REDIRECT_BOTH_APPEND);
    uint32_t route_fds[2] = {fd, 2};
    uint32_t edge_indices[2] = {UINT32_MAX, UINT32_MAX};
    uint32_t route_count = combined ? 2 : 1;
    for (uint32_t route = 0; route < route_count; route++) {
      for (uint32_t edge = 0; edge < original_edge_count; edge++) {
        if (used_edges[edge])
          continue;
        const shell_dep_edge_t *item = &original_edges[edge];
        bool matches =
            output
                ? (item->type == SHELL_EDGE_WRITE ||
                   item->type == SHELL_EDGE_FD_OPEN) &&
                      item->from == owner &&
                      item->source_fd == route_fds[route] &&
                      item->to < graph->node_count &&
                      graph->nodes[item->to].type == SHELL_NODE_ENDPOINT
                : (item->type == SHELL_EDGE_SUBST ||
                   item->type == SHELL_EDGE_FD_OPEN) &&
                      item->to == owner && item->target_fd == route_fds[route];
        if (matches) {
          edge_indices[route] = edge;
          break;
        }
      }
    }
    /* A syntactically valid substitution with no executable endpoint does not
     * create a graph route. Keep the parser's empty-subgraph behavior rather
     * than manufacturing a relation for it here. */
    if (edge_indices[0] == UINT32_MAX &&
        (!combined || edge_indices[1] == UINT32_MAX))
      continue;
    /* `&>` and its legacy spelling join stdout and stderr to one collector.
     * They still need two independently replaceable descriptor routes: a
     * later `>file`, `2>file`, close, or duplication affects only its own fd.
     * Do not accept a partially constructed combined route at a capacity
     * boundary. */
    if ((combined &&
         (edge_indices[0] == UINT32_MAX || edge_indices[1] == UINT32_MAX)) ||
        *op_count > op_capacity || route_count > op_capacity - *op_count)
      return false;
    for (uint32_t route = 0; route < route_count; route++) {
      uint32_t edge_index = edge_indices[route];
      used_edges[edge_index] = true;
      /* A named process-substitution route is setup state until an ordinary
       * descriptor copies it. Keep its symbolic edge visible; only numeric
       * routes are replaced by the resolver's effective-edge materialization.
       */
      dynamic_edges[edge_index] = route_fds[route] != SHELL_DEP_FD_NAMED;
      ops[(*op_count)++] =
          (dep_fd_op_t){(uint32_t)(target->start - cmd),
                        DEP_FD_OP_DYNAMIC,
                        route_fds[route],
                        SHELL_DEP_FD_NONE,
                        fd_name,
                        fd_name_len,
                        NULL,
                        0,
                        edge_index,
                        output ? DEP_FD_ACCESS_WRITE : DEP_FD_ACCESS_READ};
    }
  }
  return true;
}

static void dep_sort_fd_operations(dep_fd_op_t *ops, uint32_t count) {
  for (uint32_t i = 1; i < count; i++) {
    dep_fd_op_t item = ops[i];
    uint32_t j = i;
    while (j > 0 && ops[j - 1].pos > item.pos) {
      ops[j] = ops[j - 1];
      j--;
    }
    ops[j] = item;
  }
}

/* A duplicate following a close in the same redirect list is a runtime
 * failure for that command, but it does not make the source structurally
 * unsupported. Keep the command graph (with its transient setup) instead of
 * conflating that local failure with a later use of a persistently closed
 * descriptor. */
static bool dep_fd_closed_earlier_in_owner(const dep_fd_op_t *ops,
                                           uint32_t current, dep_fd_ref_t fd) {
  if (!ops)
    return false;
  for (uint32_t i = 0; i < current; i++) {
    dep_fd_ref_t candidate = {ops[i].fd, ops[i].fd_name, ops[i].fd_name_len};
    if (ops[i].kind == DEP_FD_OP_CLOSE && dep_fd_ref_equal(candidate, fd) &&
        ops[i].pos < ops[current].pos)
      return true;
  }
  return false;
}

typedef struct {
  bool valid;
  bool saw_dash;
  bool functions;
  bool variables;
  bool nameref;
  size_t length;
} dep_unset_option_t;

static bool dep_unset_option_byte(unsigned char byte, size_t position,
                                  void *context) {
  dep_unset_option_t *option = context;
  if (!option)
    return false;
  if (position == 0) {
    option->saw_dash = byte == '-';
    option->valid = option->saw_dash;
  } else if (byte == 'f') {
    option->functions = true;
  } else if (byte == 'v') {
    option->variables = true;
  } else if (byte == 'n') {
    option->nameref = true;
  } else {
    option->valid = false;
  }
  option->length = position + 1;
  return true;
}

/* `unset -f` acts on functions while `unset -n` acts only on namerefs. A
 * `{name}` redirect creates an ordinary scalar variable, so neither option
 * removes its descriptor binding. `-f` and `-v` together are a Bash error and
 * leave state unchanged. */
static bool dep_token_parse_unset_option(const dep_token_t *tok,
                                         dep_unset_option_t *option) {
  if (option)
    *option = (dep_unset_option_t){0};
  if (!tok || !tok->start || !option ||
      shell_source_word_has_dynamic_syntax(tok->start, tok->len))
    return false;
  size_t decoded_length = 0;
  return shell_visit_decoded_word(tok->start, tok->len, dep_unset_option_byte,
                                  option,
                                  &decoded_length) == SHELL_PROCESS_OK &&
         option->valid && option->saw_dash && option->length > 1 &&
         option->length == decoded_length;
}

typedef struct {
  bool valid;
  bool saw_dash;
  bool tail_is_argv0;
  bool argv0_needs_word;
  size_t length;
} dep_exec_option_t;

static bool dep_exec_option_byte(unsigned char byte, size_t position,
                                 void *context) {
  dep_exec_option_t *option = context;
  if (!option)
    return false;
  if (position == 0) {
    option->saw_dash = byte == '-';
    option->valid = option->saw_dash;
  } else if (option->tail_is_argv0) {
    option->argv0_needs_word = false;
  } else if (byte == 'c' || byte == 'l') {
    /* no argument */
  } else if (byte == 'a') {
    /* `-a name` and `-aname` are both accepted. The remaining bytes, if any,
     * are argv[0] rather than more option letters. */
    option->tail_is_argv0 = true;
    option->argv0_needs_word = true;
  } else {
    option->valid = false;
  }
  option->length = position + 1;
  return true;
}

static bool dep_token_is_exec_option(const dep_token_t *tok,
                                     bool *needs_argv0) {
  if (needs_argv0)
    *needs_argv0 = false;
  if (!tok || !tok->start || !needs_argv0 ||
      shell_source_word_has_dynamic_syntax(tok->start, tok->len))
    return false;
  dep_exec_option_t option = {0};
  size_t decoded_length = 0;
  if (shell_visit_decoded_word(tok->start, tok->len, dep_exec_option_byte,
                               &option, &decoded_length) != SHELL_PROCESS_OK ||
      !option.valid || !option.saw_dash || option.length <= 1 ||
      option.length != decoded_length)
    return false;
  *needs_argv0 = option.argv0_needs_word;
  return true;
}

static const dep_token_t *
dep_effective_static_builtin(const dep_token_list_t *tokens, uint32_t command,
                             uint32_t *effective_command, bool *dynamic_target,
                             bool *exec_persistent,
                             shell_dep_command_wrapper_t *wrapper_kind);

static bool dep_owner_is_persistent_exec(const char *cmd,
                                         const shell_range_t *range) {
  if (!cmd || !range)
    return false;
  dep_token_list_t tokens = {0};
  if (scan_tokens(cmd, range->start, range->len, &tokens))
    return false;

  uint32_t command = UINT32_MAX;
  for (uint32_t i = 0; i < tokens.count; i++) {
    dep_redirect_t redirect = classify_redirect(&tokens.tokens[i]);
    if (redirect != DEP_REDIRECT_NONE) {
      bool legacy_combined =
          redirect == DEP_REDIRECT_DUP && i + 1 < tokens.count &&
          dep_redirect_is_legacy_combined_output(&tokens.tokens[i],
                                                 &tokens.tokens[i + 1]);
      if ((redirect != DEP_REDIRECT_DUP || legacy_combined) &&
          i + 1 < tokens.count)
        i++;
      else if (redirect == DEP_REDIRECT_DUP && tokens.tokens[i].len >= 2 &&
               tokens.tokens[i].start[tokens.tokens[i].len - 1] == '&' &&
               i + 1 < tokens.count)
        i++;
      continue;
    }
    if (!dep_token_is_assignment_word(&tokens.tokens[i])) {
      command = i;
      break;
    }
  }
  if (command == UINT32_MAX)
    return false;

  bool dynamic_target = false;
  bool persistent = false;
  uint32_t effective_command = command;
  const dep_token_t *target = dep_effective_static_builtin(
      &tokens, command, &effective_command, &dynamic_target, &persistent, NULL);
  if (!target || dynamic_target || !persistent ||
      !dep_token_static_equals(target, "exec"))
    return false;

  bool parse_options = true;
  bool option_needs_name = false;
  for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
    dep_redirect_t redirect = classify_redirect(&tokens.tokens[i]);
    if (redirect != DEP_REDIRECT_NONE) {
      bool legacy_combined =
          redirect == DEP_REDIRECT_DUP && i + 1 < tokens.count &&
          dep_redirect_is_legacy_combined_output(&tokens.tokens[i],
                                                 &tokens.tokens[i + 1]);
      if ((redirect != DEP_REDIRECT_DUP || legacy_combined) &&
          i + 1 < tokens.count)
        i++;
      else if (redirect == DEP_REDIRECT_DUP && tokens.tokens[i].len >= 2 &&
               tokens.tokens[i].start[tokens.tokens[i].len - 1] == '&' &&
               i + 1 < tokens.count)
        i++;
      continue;
    }
    if (option_needs_name) {
      option_needs_name = false;
      continue;
    }
    if (parse_options && dep_token_static_equals(&tokens.tokens[i], "--")) {
      parse_options = false;
      continue;
    }
    if (parse_options && dep_token_static_starts_dash(&tokens.tokens[i])) {
      bool needs_argv0 = false;
      if (!dep_token_is_exec_option(&tokens.tokens[i], &needs_argv0))
        return false;
      option_needs_name = needs_argv0;
      continue;
    }
    return false;
  }
  return !option_needs_name;
}

/* A redirect-only simple command has no command lifetime to carry a Bash
 * `{name}` allocation beyond its own redirection list. A compound group and
 * an ordinary simple command with at least one command word retain an open
 * binding for the rest of their selected execution scope under Bash's default
 * `varredir_close` behavior. For an isolated group that scope is private;
 * dep_owner_named_scope() prevents it from escaping to the parent shell. */
static bool dep_owner_persists_named_binding(const shell_dep_graph_t *graph,
                                             uint32_t owner) {
  if (!dep_is_execution_node(graph, owner))
    return false;
  return graph->nodes[owner].type == SHELL_NODE_GROUP ||
         (graph->nodes[owner].type == SHELL_NODE_CMD &&
          graph->nodes[owner].cmd.token_count != 0);
}

/* Copy a descriptor table when entering a scope or publishing a proven AND
 * continuation. Ordinary persistence instead replays only touched routes. */
static void dep_copy_routes(dep_owner_routes_t *destination,
                            const dep_owner_routes_t *source) {
  if (!destination || !source)
    return;
  destination->fd_count = source->fd_count;
  memcpy(destination->fd, source->fd,
         source->fd_count * sizeof(destination->fd[0]));
}

static void dep_mark_owner_route_touched(dep_route_workspace_t *workspace,
                                         uint32_t owner,
                                         const dep_owner_routes_t *state,
                                         dep_fd_ref_t fd,
                                         dep_fd_access_t access) {
  if (!workspace || !state || owner >= SHELL_DEP_MAX_NODES)
    return;
  for (uint32_t route = 0; route < state->fd_count; route++) {
    if (!dep_fd_ref_equal(state->fd[route].fd, fd))
      continue;
    workspace->route_touched[owner][route / 4] |=
        (uint8_t)((uint8_t)access << (2 * (route % 4)));
    return;
  }
}

static dep_fd_access_t
dep_owner_route_touched(const dep_route_workspace_t *workspace, uint32_t owner,
                        uint32_t route) {
  return (dep_fd_access_t)((workspace->route_touched[owner][route / 4] >>
                            (2 * (route % 4))) &
                           DEP_FD_ACCESS_BOTH);
}

/* With Bash's default `varredir_close` setting, a `{name}` allocation on an
 * ordinary current-shell command survives that command, but a close does not.
 * Apply only the names which a non-close operation assigned; this keeps an
 * earlier binding alive across `: {name}>&-`, while allowing a later rebind in
 * the same redirect list to replace it. */
static bool dep_merge_persistent_named_routes(dep_owner_routes_t *persistent,
                                              const dep_owner_routes_t *state,
                                              const dep_fd_op_t *ops,
                                              uint32_t op_count) {
  if (!persistent || !state || !ops)
    return false;
  for (uint32_t op = 0; op < op_count; op++) {
    const dep_fd_op_t *item = &ops[op];
    if (item->fd != SHELL_DEP_FD_NAMED || item->kind == DEP_FD_OP_CLOSE)
      continue;
    dep_fd_ref_t fd = {SHELL_DEP_FD_NAMED, item->fd_name, item->fd_name_len};
    const dep_fd_route_entry_t *source = NULL;
    for (uint32_t entry = 0; entry < state->fd_count; entry++)
      if (dep_fd_ref_equal(state->fd[entry].fd, fd)) {
        source = &state->fd[entry];
        break;
      }
    if (!source)
      continue;
    dep_fd_route_entry_t *destination =
        dep_route_slot(persistent->fd, &persistent->fd_count, fd, true);
    if (!destination)
      return false;
    *destination = *source;
  }
  return true;
}

/* A direct `&&` successor runs in the same shell, but an ordinary redirect is
 * scoped to the command or compound group which owns it.  `exec` is the sole
 * ordinary command that persists its complete descriptor table.  Bash's
 * `{name}` syntax is the other exception: it assigns a descriptor number to a
 * shell variable, so that named binding remains available to a proven success
 * successor even when the preceding owner is not `exec`.
 *
 * Start from the enclosing persistent table and overlay only those named
 * bindings.  A close is deliberately not overlaid: with Bash's default
 * `varredir_close` behaviour, `: {name}>&-` closes that invocation's
 * descriptor without unsetting an earlier persistent name.  A missing source
 * binding, in contrast, records that the predecessor assigned or invalidated
 * the variable and must remove the inherited route. */
static bool dep_route_entry_is_closed(const dep_fd_route_entry_t *entry) {
  return entry && entry->read_route.kind == DEP_ROUTE_CLOSED &&
         entry->write_route.kind == DEP_ROUTE_CLOSED;
}

static const dep_fd_route_entry_t *
dep_find_named_route(const dep_owner_routes_t *routes, dep_fd_ref_t fd) {
  if (!routes || fd.value != SHELL_DEP_FD_NAMED)
    return NULL;
  for (uint32_t route = 0; route < routes->fd_count; route++)
    if (dep_fd_ref_equal(routes->fd[route].fd, fd))
      return &routes->fd[route];
  return NULL;
}

/* `exec` is a shell builtin for descriptor lifetime, but when it has a
 * command operand it replaces the shell with that external executable. Keep
 * its execution target separate from the builtin-role interpretation above.
 * Redirection operands and `-a`'s argv[0] do not name the executable. */
static const dep_token_t *dep_static_exec_target(const dep_token_list_t *tokens,
                                                 uint32_t command,
                                                 bool *unresolved) {
  if (unresolved)
    *unresolved = false;
  if (!tokens || !unresolved || command >= tokens->count)
    return NULL;
  bool options = true;
  bool needs_argv0 = false;
  for (uint32_t i = command + 1; i < tokens->count; i++) {
    const dep_token_t *word = &tokens->tokens[i];
    if (classify_redirect(word) != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(word->start, word->len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    if (needs_argv0) {
      needs_argv0 = false;
      continue;
    }
    if (shell_source_word_has_dynamic_syntax(word->start, word->len)) {
      *unresolved = true;
      return NULL;
    }
    if (options && dep_token_static_equals(word, "--")) {
      options = false;
      continue;
    }
    if (options && dep_token_static_starts_dash(word)) {
      if (!dep_token_is_exec_option(word, &needs_argv0))
        *unresolved = true;
      if (*unresolved)
        return NULL;
      continue;
    }
    return word;
  }
  return NULL;
}

static bool dep_overlay_open_named_routes(dep_owner_routes_t *destination,
                                          const dep_owner_routes_t *state) {
  if (!destination || !state)
    return false;
  for (uint32_t route = 0; route < state->fd_count; route++) {
    const dep_fd_route_entry_t *source = &state->fd[route];
    if (source->fd.value != SHELL_DEP_FD_NAMED ||
        dep_route_entry_is_closed(source))
      continue;
    dep_fd_route_entry_t *slot = dep_route_slot(
        destination->fd, &destination->fd_count, source->fd, true);
    if (!slot)
      return false;
    *slot = *source;
  }
  return true;
}

static bool
dep_merge_and_success_named_routes(dep_owner_routes_t *destination,
                                   const dep_owner_routes_t *state) {
  if (!destination || !state)
    return false;

  for (uint32_t route = 0; route < destination->fd_count;) {
    dep_fd_route_entry_t *current = &destination->fd[route];
    if (current->fd.value != SHELL_DEP_FD_NAMED) {
      route++;
      continue;
    }
    const dep_fd_route_entry_t *source =
        dep_find_named_route(state, current->fd);
    if (!source) {
      memmove(current, current + 1,
              (destination->fd_count - route - 1) * sizeof(*current));
      destination->fd_count--;
      continue;
    }
    if (!dep_route_entry_is_closed(source))
      *current = *source;
    route++;
  }

  return dep_overlay_open_named_routes(destination, state);
}

/* A conditional-list member must never promote descriptor state into the
 * ordinary current-shell table: a later sequence command can run without the
 * member having run. */
static bool dep_owner_touches_branch_boundary(const shell_dep_edge_t *edges,
                                              uint32_t edge_count,
                                              uint32_t owner) {
  for (uint32_t edge = 0; edge < edge_count; edge++)
    if ((edges[edge].from == owner || edges[edge].to == owner) &&
        (edges[edge].type == SHELL_EDGE_AND ||
         edges[edge].type == SHELL_EDGE_OR))
      return true;
  return false;
}

/* `&&` is a success continuation, but an AND-OR list is left-associative.
 * In `a || setup && use`, `use` can run after `a` succeeds even though
 * `setup` was skipped.  A direct AND edge therefore carries descriptor state
 * only when neither endpoint also has an incoming OR edge.  That admits a
 * contiguous success chain (`a && setup && use`) while keeping OR joins
 * conservative without attempting general boolean symbolic execution. */
static bool dep_owner_and_success_predecessor(const shell_dep_edge_t *edges,
                                              uint32_t edge_count,
                                              uint32_t owner,
                                              uint32_t *predecessor) {
  uint32_t candidate = UINT32_MAX;
  if (!edges || !predecessor)
    return false;
  for (uint32_t edge = 0; edge < edge_count; edge++) {
    const shell_dep_edge_t *item = &edges[edge];
    if (item->type == SHELL_EDGE_AND && item->to == owner) {
      if (candidate != UINT32_MAX || item->from == owner)
        return false;
      candidate = item->from;
    }
  }
  if (candidate == UINT32_MAX)
    return false;
  for (uint32_t edge = 0; edge < edge_count; edge++) {
    const shell_dep_edge_t *item = &edges[edge];
    if (item->type == SHELL_EDGE_OR &&
        (item->to == owner || item->to == candidate))
      return false;
  }
  *predecessor = candidate;
  return true;
}

/* A compound GROUP can be a pipeline member even when the group's own range
 * has no pipeline feature bit.  Test graph topology as well as range-local
 * scope so an AND successor never inherits a descriptor table from a forked
 * pipeline/background execution endpoint. */
static bool
dep_owner_has_private_execution_boundary(const shell_dep_edge_t *edges,
                                         uint32_t edge_count, uint32_t owner) {
  if (!edges)
    return false;
  for (uint32_t edge = 0; edge < edge_count; edge++)
    if ((edges[edge].from == owner || edges[edge].to == owner) &&
        (edges[edge].type == SHELL_EDGE_PIPE ||
         edges[edge].type == SHELL_EDGE_BACKGROUND))
      return true;
  return false;
}

static bool dep_identifier_byte_valid(unsigned char byte, size_t position) {
  return position == 0 ? isalpha(byte) || byte == '_'
                       : isalnum(byte) || byte == '_';
}

typedef struct {
  bool valid;
  size_t length;
} dep_static_identifier_t;

static bool dep_static_identifier_byte(unsigned char byte, size_t position,
                                       void *context) {
  dep_static_identifier_t *identifier = context;
  if (!identifier)
    return false;
  if (!dep_identifier_byte_valid(byte, position))
    identifier->valid = false;
  identifier->length = position + 1;
  return true;
}

/* A named-FD route stores the physical `{name}` source span, while a builtin
 * operand arrives as an already-isolated shell word. Compare them after their
 * respective quote/continuation removal without allocating a transient name.
 * This lets `unset 'fd'` and `printf -v f'd'` affect exactly `{fd}`. */
typedef struct {
  const char *name;
  uint32_t name_len;
  uint32_t name_position;
  bool valid;
  bool matches;
  size_t length;
} dep_named_route_target_t;

static bool dep_named_route_target_byte(unsigned char byte, size_t position,
                                        void *context) {
  dep_named_route_target_t *target = context;
  if (!target)
    return false;
  if (!dep_identifier_byte_valid(byte, position))
    target->valid = false;
  if (target->matches) {
    unsigned char expected = 0;
    if (!dep_fd_name_next_byte(target->name, target->name_len,
                               &target->name_position, &expected) ||
        expected != byte)
      target->matches = false;
  }
  target->length = position + 1;
  return true;
}

static bool dep_token_is_static_identifier(const dep_token_t *token) {
  if (!token || !token->start ||
      shell_source_word_has_dynamic_syntax(token->start, token->len))
    return false;
  dep_static_identifier_t identifier = {.valid = true};
  size_t decoded_length = 0;
  return shell_visit_decoded_word(token->start, token->len,
                                  dep_static_identifier_byte, &identifier,
                                  &decoded_length) == SHELL_PROCESS_OK &&
         identifier.valid && identifier.length != 0 &&
         identifier.length == decoded_length;
}

static bool dep_token_matches_named_route(const dep_token_t *token,
                                          const char *name, uint32_t name_len) {
  if (!token || !token->start || !name ||
      shell_source_word_has_dynamic_syntax(token->start, token->len))
    return false;
  dep_named_route_target_t target = {
      .name = name,
      .name_len = name_len,
      .valid = true,
      .matches = true,
  };
  size_t decoded_length = 0;
  if (shell_visit_decoded_word(token->start, token->len,
                               dep_named_route_target_byte, &target,
                               &decoded_length) != SHELL_PROCESS_OK ||
      !target.valid || target.length == 0 || target.length != decoded_length)
    return false;
  unsigned char trailing = 0;
  return target.matches &&
         !dep_fd_name_next_byte(name, name_len, &target.name_position,
                                &trailing);
}

static void dep_remove_named_route_token(dep_owner_routes_t *routes,
                                         const dep_token_t *token) {
  if (!routes || !token)
    return;
  for (uint32_t route = 0; route < routes->fd_count;) {
    dep_fd_ref_t ref = routes->fd[route].fd;
    if (ref.value != SHELL_DEP_FD_NAMED ||
        !dep_token_matches_named_route(token, ref.name, ref.name_len)) {
      route++;
      continue;
    }
    memmove(&routes->fd[route], &routes->fd[route + 1],
            (routes->fd_count - route - 1) * sizeof(routes->fd[0]));
    routes->fd_count--;
  }
}

typedef enum {
  DEP_STATIC_ASSIGNMENT_NONE,
  DEP_STATIC_ASSIGNMENT_VALID,
  DEP_STATIC_ASSIGNMENT_INVALID,
} dep_static_assignment_t;

/* Declaration builtins parse `name=value` and `name+=value` after quote
 * removal. Distinguish a static plain declaration (which only observes a
 * value) from a proved assignment and from a dynamic or malformed argument
 * that could rewrite an arbitrary descriptor variable. */
static dep_static_assignment_t
dep_token_static_assignment(const dep_token_t *token) {
  if (!token || !token->start)
    return DEP_STATIC_ASSIGNMENT_INVALID;
  shell_source_decoded_assignment_t assignment;
  if (shell_source_scan_decoded_assignment(token->start, token->len, NULL, NULL,
                                           &assignment))
    return assignment.source_delimiter ? DEP_STATIC_ASSIGNMENT_VALID
                                       : DEP_STATIC_ASSIGNMENT_INVALID;
  return dep_token_is_static_identifier(token) ? DEP_STATIC_ASSIGNMENT_NONE
                                               : DEP_STATIC_ASSIGNMENT_INVALID;
}

static bool dep_assignment_matches_named_route(const dep_token_t *token,
                                               const char *name,
                                               uint32_t name_len) {
  if (!token || !token->start || !name)
    return false;
  shell_source_assignment_word_t assignment;
  if (!dep_token_parse_assignment_word(token, &assignment))
    return false;
  return dep_token_matches_named_route(
      &(dep_token_t){token->start, assignment.name_end}, name, name_len);
}

typedef struct {
  const char *name;
  uint32_t name_len;
  uint32_t name_position;
  bool matches;
} dep_static_assignment_route_target_t;

static bool dep_static_assignment_route_target_byte(unsigned char byte,
                                                    void *context) {
  dep_static_assignment_route_target_t *target = context;
  if (!target)
    return false;
  if (target->matches) {
    unsigned char expected = 0;
    if (!dep_fd_name_next_byte(target->name, target->name_len,
                               &target->name_position, &expected) ||
        expected != byte)
      target->matches = false;
  }
  return true;
}

static bool dep_static_assignment_matches_named_route(const dep_token_t *token,
                                                      const char *name,
                                                      uint32_t name_len) {
  if (!token || !token->start || !name)
    return false;
  dep_static_assignment_route_target_t target = {
      .name = name,
      .name_len = name_len,
      .matches = true,
  };
  shell_source_decoded_assignment_t assignment;
  if (!shell_source_scan_decoded_assignment(
          token->start, token->len, dep_static_assignment_route_target_byte,
          &target, &assignment) ||
      !assignment.source_delimiter)
    return false;
  unsigned char trailing = 0;
  return target.matches &&
         !dep_fd_name_next_byte(name, name_len, &target.name_position,
                                &trailing);
}

static void dep_remove_named_assignment_route(dep_owner_routes_t *routes,
                                              const dep_token_t *token,
                                              bool static_assignment) {
  if (!routes || !token)
    return;
  for (uint32_t route = 0; route < routes->fd_count;) {
    dep_fd_ref_t ref = routes->fd[route].fd;
    if (ref.value != SHELL_DEP_FD_NAMED ||
        !(static_assignment ? dep_static_assignment_matches_named_route(
                                  token, ref.name, ref.name_len)
                            : dep_assignment_matches_named_route(
                                  token, ref.name, ref.name_len))) {
      route++;
      continue;
    }
    memmove(&routes->fd[route], &routes->fd[route + 1],
            (routes->fd_count - route - 1) * sizeof(routes->fd[0]));
    routes->fd_count--;
  }
}

static void dep_clear_named_routes(dep_owner_routes_t *routes) {
  if (!routes)
    return;
  for (uint32_t route = 0; route < routes->fd_count;) {
    if (routes->fd[route].fd.value != SHELL_DEP_FD_NAMED) {
      route++;
      continue;
    }
    memmove(&routes->fd[route], &routes->fd[route + 1],
            (routes->fd_count - route - 1) * sizeof(routes->fd[0]));
    routes->fd_count--;
  }
}

typedef enum {
  DEP_PRINTF_WORD_FORMAT,
  DEP_PRINTF_WORD_END_OPTIONS,
  DEP_PRINTF_WORD_V_SEPARATE,
  DEP_PRINTF_WORD_V_ATTACHED,
  DEP_PRINTF_WORD_V_INVALID,
  DEP_PRINTF_WORD_DYNAMIC,
} dep_printf_word_t;

typedef struct {
  bool v_prefix;
  bool identifier_valid;
  size_t length;
} dep_printf_word_scan_t;

static bool dep_printf_word_byte(unsigned char byte, size_t position,
                                 void *context) {
  dep_printf_word_scan_t *scan = context;
  if (!scan)
    return false;
  if (position == 0)
    scan->v_prefix = byte == '-';
  else if (position == 1)
    scan->v_prefix = scan->v_prefix && byte == 'v';
  else if (scan->v_prefix && !dep_identifier_byte_valid(byte, position - 2))
    scan->identifier_valid = false;
  scan->length = position + 1;
  return true;
}

/* `printf` has exactly one assignment option. It is recognized only before
 * the format operand, accepts both `-v name` and `-vname`, and is disabled by
 * `--`. Decode static spelling rather than copying it so quoted and continued
 * option forms share the same behavior as ordinary builtin recognition. */
static dep_printf_word_t dep_classify_printf_word(const dep_token_t *token) {
  if (!token || !token->start ||
      shell_source_word_has_dynamic_syntax(token->start, token->len))
    return DEP_PRINTF_WORD_DYNAMIC;
  if (dep_token_static_equals(token, "--"))
    return DEP_PRINTF_WORD_END_OPTIONS;
  dep_printf_word_scan_t scan = {.identifier_valid = true};
  size_t decoded_length = 0;
  if (shell_visit_decoded_word(token->start, token->len, dep_printf_word_byte,
                               &scan, &decoded_length) != SHELL_PROCESS_OK ||
      scan.length != decoded_length)
    return DEP_PRINTF_WORD_DYNAMIC;
  if (!scan.v_prefix)
    return DEP_PRINTF_WORD_FORMAT;
  if (scan.length == 2)
    return DEP_PRINTF_WORD_V_SEPARATE;
  return scan.identifier_valid ? DEP_PRINTF_WORD_V_ATTACHED
                               : DEP_PRINTF_WORD_V_INVALID;
}

typedef struct {
  const char *name;
  uint32_t name_len;
  uint32_t name_position;
  bool matches;
  size_t length;
} dep_printf_attached_target_t;

static bool dep_printf_attached_target_byte(unsigned char byte, size_t position,
                                            void *context) {
  dep_printf_attached_target_t *target = context;
  if (!target)
    return false;
  if ((position == 0 && byte != '-') || (position == 1 && byte != 'v'))
    target->matches = false;
  if (position >= 2 && target->matches) {
    unsigned char expected = 0;
    if (!dep_fd_name_next_byte(target->name, target->name_len,
                               &target->name_position, &expected) ||
        expected != byte)
      target->matches = false;
  }
  target->length = position + 1;
  return true;
}

static bool dep_printf_attached_matches_named_route(const dep_token_t *token,
                                                    const char *name,
                                                    uint32_t name_len) {
  if (!token || !token->start || !name)
    return false;
  dep_printf_attached_target_t target = {
      .name = name,
      .name_len = name_len,
      .matches = true,
  };
  size_t decoded_length = 0;
  if (shell_visit_decoded_word(token->start, token->len,
                               dep_printf_attached_target_byte, &target,
                               &decoded_length) != SHELL_PROCESS_OK ||
      target.length != decoded_length || target.length < 3)
    return false;
  unsigned char trailing = 0;
  return target.matches &&
         !dep_fd_name_next_byte(name, name_len, &target.name_position,
                                &trailing);
}

static void dep_remove_printf_attached_named_route(dep_owner_routes_t *routes,
                                                   const dep_token_t *token) {
  if (!routes || !token)
    return;
  for (uint32_t route = 0; route < routes->fd_count;) {
    dep_fd_ref_t ref = routes->fd[route].fd;
    if (ref.value != SHELL_DEP_FD_NAMED ||
        !dep_printf_attached_matches_named_route(token, ref.name,
                                                 ref.name_len)) {
      route++;
      continue;
    }
    memmove(&routes->fd[route], &routes->fd[route + 1],
            (routes->fd_count - route - 1) * sizeof(routes->fd[0]));
    routes->fd_count--;
  }
}

/* `command` and `builtin` execute their static target in the current shell.
 * Use Shellsplit's shared wrapper state machine so this graph cannot disagree
 * with the source semantic gate about nested wrappers, inspection forms, or
 * the lifetime of a wrapped `exec` redirect. */
static const dep_token_t *
dep_effective_static_builtin(const dep_token_list_t *tokens, uint32_t command,
                             uint32_t *effective_command, bool *dynamic_target,
                             bool *exec_persistent,
                             shell_dep_command_wrapper_t *wrapper_kind) {
  if (dynamic_target)
    *dynamic_target = false;
  if (effective_command)
    *effective_command = command;
  if (exec_persistent)
    *exec_persistent = false;
  if (wrapper_kind)
    *wrapper_kind = SHELL_DEP_COMMAND_DIRECT;
  if (!tokens || !effective_command || !dynamic_target ||
      command >= tokens->count)
    return NULL;

  const dep_token_t *candidate = &tokens->tokens[command];
  shell_source_wrapper_state_t wrapper = {0};
  shell_source_wrapper_step_t step =
      shell_source_wrapper_start(&wrapper, candidate->start, candidate->len);
  if (step == SHELL_SOURCE_WRAPPER_DYNAMIC_TARGET) {
    *dynamic_target = true;
    return NULL;
  }
  if (step == SHELL_SOURCE_WRAPPER_STATIC_TARGET) {
    *effective_command = command;
    if (exec_persistent)
      *exec_persistent = wrapper.exec_persistent;
    return candidate;
  }
  if (step != SHELL_SOURCE_WRAPPER_MORE)
    return NULL;

  for (uint32_t i = command + 1; i < tokens->count; i++) {
    const dep_token_t *word = &tokens->tokens[i];
    dep_redirect_t redirect = classify_redirect(word);
    if (redirect != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(word->start, word->len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    shell_source_wrapper_kind_t final_wrapper = wrapper.kind;
    step = shell_source_wrapper_consume(&wrapper, word->start, word->len);
    if (step == SHELL_SOURCE_WRAPPER_DYNAMIC_TARGET) {
      *dynamic_target = true;
      return NULL;
    }
    if (step == SHELL_SOURCE_WRAPPER_MORE)
      continue;
    if (step != SHELL_SOURCE_WRAPPER_STATIC_TARGET)
      return NULL;
    *effective_command = i;
    if (exec_persistent)
      *exec_persistent = wrapper.exec_persistent;
    if (wrapper_kind)
      *wrapper_kind = final_wrapper == SHELL_SOURCE_WRAPPER_BUILTIN
                          ? SHELL_DEP_COMMAND_BUILTIN
                          : SHELL_DEP_COMMAND_SEARCH;
    return word;
  }
  return NULL;
}

typedef enum {
  DEP_NAMED_MUTATION_BEFORE_REDIRECT,
  DEP_NAMED_MUTATION_AFTER_COMMAND,
} dep_named_mutation_phase_t;

/* A redirect and its operand are not arguments to the builtin. Keep this
 * distinction identical across all descriptor-variable mutation families. */
static bool dep_skip_builtin_redirect(const dep_token_list_t *tokens,
                                      uint32_t *index) {
  const dep_token_t *word = &tokens->tokens[*index];
  if (classify_redirect(word) == DEP_REDIRECT_NONE)
    return false;
  if (shell_source_redirection_consumes_word(word->start, word->len) &&
      *index + 1 < tokens->count)
    (*index)++;
  return true;
}

static void dep_invalidate_assigned_named_routes(
    dep_owner_routes_t *routes, const char *cmd, const shell_range_t *range,
    dep_named_mutation_phase_t phase) {
  if (!routes || !cmd || !range)
    return;
  dep_token_list_t tokens = {0};
  if (scan_tokens(cmd, range->start, range->len, &tokens))
    return;

  uint32_t command = UINT32_MAX;
  for (uint32_t token = 0; token < tokens.count; token++) {
    const dep_token_t *word = &tokens.tokens[token];
    dep_redirect_t redirect = classify_redirect(word);
    if (redirect != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(word->start, word->len) &&
          token + 1 < tokens.count)
        token++;
      continue;
    }
    if (!dep_token_is_assignment_word(word)) {
      command = token;
      break;
    }
  }

  /* A leading assignment is temporary when a command word follows. In
   * particular, Bash expands that command's redirect list against the
   * pre-existing descriptor-variable binding. An assignment-only command,
   * however, changes the current shell variable and invalidates just that
   * logical named-FD route. Defer mutation until the command shape is known
   * so the two cases cannot be confused. */
  if (command == UINT32_MAX) {
    if (phase != DEP_NAMED_MUTATION_BEFORE_REDIRECT)
      return;
    for (uint32_t token = 0; token < tokens.count; token++) {
      const dep_token_t *word = &tokens.tokens[token];
      dep_redirect_t redirect = classify_redirect(word);
      if (redirect != DEP_REDIRECT_NONE) {
        if (shell_source_redirection_consumes_word(word->start, word->len) &&
            token + 1 < tokens.count)
          token++;
        continue;
      }
      if (dep_token_is_assignment_word(word))
        dep_remove_named_assignment_route(routes, word, false);
    }
    return;
  }
  if (phase != DEP_NAMED_MUTATION_AFTER_COMMAND)
    return;
  bool dynamic_builtin = false;
  uint32_t effective_command = command;
  const dep_token_t *builtin = dep_effective_static_builtin(
      &tokens, command, &effective_command, &dynamic_builtin, NULL, NULL);
  if (dynamic_builtin) {
    dep_clear_named_routes(routes);
    return;
  }
  if (!builtin)
    return;
  shell_source_builtin_kind_t builtin_kind =
      shell_source_static_builtin_kind(builtin->start, builtin->len);
  if (builtin_kind == SHELL_SOURCE_BUILTIN_UNSET) {
    bool options = true;
    bool function_mode = false;
    bool nameref_mode = false;
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *target = &tokens.tokens[i];
      if (options && dep_token_static_equals(target, "--")) {
        options = false;
        continue;
      }
      if (options && dep_token_static_starts_dash(target)) {
        dep_unset_option_t option;
        if (!dep_token_parse_unset_option(target, &option) ||
            (option.functions && option.variables))
          return;
        function_mode = function_mode || option.functions;
        nameref_mode = nameref_mode || option.nameref;
        continue;
      }
      options = false;
      if (function_mode || nameref_mode)
        continue;
      if (!dep_token_is_static_identifier(target)) {
        /* A dynamic or malformed target may name any descriptor variable
         * after runtime expansion. Clear rather than preserving a route
         * through an unproved mutation. */
        dep_clear_named_routes(routes);
        return;
      }
      dep_remove_named_route_token(routes, target);
    }
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_PRINTF) {
    bool target_expected = false;
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *word = &tokens.tokens[i];
      dep_printf_word_t kind = dep_classify_printf_word(word);
      if (target_expected) {
        if (kind == DEP_PRINTF_WORD_DYNAMIC)
          dep_clear_named_routes(routes);
        else if (dep_token_is_static_identifier(word))
          dep_remove_named_route_token(routes, word);
        /* A static invalid variable name makes Bash printf fail before it
         * writes any variable. Preserve the proven routes: treating its
         * runtime error as an unknown mutation loses real later I/O. */
        return;
      }
      if (kind == DEP_PRINTF_WORD_DYNAMIC) {
        dep_clear_named_routes(routes);
        return;
      }
      /* An attached static spelling such as `-v9` is an option error, not a
       * write to an unknown variable. It terminates printf without changing
       * any named-FD binding. */
      if (kind == DEP_PRINTF_WORD_V_INVALID)
        return;
      if (kind == DEP_PRINTF_WORD_END_OPTIONS || kind == DEP_PRINTF_WORD_FORMAT)
        return;
      if (kind == DEP_PRINTF_WORD_V_ATTACHED) {
        dep_remove_printf_attached_named_route(routes, word);
        return;
      }
      target_expected = true;
    }
    if (target_expected)
      dep_clear_named_routes(routes);
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_EXPORT ||
      builtin_kind == SHELL_SOURCE_BUILTIN_DECLARE ||
      builtin_kind == SHELL_SOURCE_BUILTIN_TYPESET ||
      builtin_kind == SHELL_SOURCE_BUILTIN_LOCAL ||
      builtin_kind == SHELL_SOURCE_BUILTIN_READONLY) {
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *argument = &tokens.tokens[i];
      if (dep_token_static_starts_dash(argument))
        continue;
      dep_static_assignment_t assignment =
          dep_token_static_assignment(argument);
      if (assignment == DEP_STATIC_ASSIGNMENT_NONE)
        continue;
      if (assignment == DEP_STATIC_ASSIGNMENT_INVALID) {
        dep_clear_named_routes(routes);
        continue;
      }
      dep_remove_named_assignment_route(routes, argument, true);
    }
    return;
  }

  /* These accepted builtins can assign an arbitrary scalar shell variable in
   * the current shell. Their target grammar is deliberately outside descriptor
   * analysis; discarding every visible named binding is the safe alternative
   * to routing a later `$fd` through stale state. Array-producing and
   * callback-bearing builtin forms are rejected by the shared semantic gate. */
  if (builtin_kind == SHELL_SOURCE_BUILTIN_READ ||
      builtin_kind == SHELL_SOURCE_BUILTIN_GETOPTS ||
      builtin_kind == SHELL_SOURCE_BUILTIN_LET) {
    dep_clear_named_routes(routes);
  }
}

/* Return the execution scope for an owner. A subshell, pipeline group, and
 * asynchronous group each receives a private descriptor table which starts as
 * a snapshot of its parent table. A bare pipeline/background command has no
 * shared child list, so `one_shot` keeps its imported state private without
 * allocating a persistent scope. A non-isolated brace group's trailing
 * redirects execute in its enclosing shell. An isolated group's redirects,
 * including a subshell's own trailing list, execute in that group's private
 * shell and must therefore use the group itself as their scope. */
static int32_t dep_owner_named_scope(const shell_dep_graph_t *graph,
                                     const shell_parse_result_t *fast,
                                     const dep_group_exec_t *groups,
                                     const uint32_t *node_range,
                                     const uint32_t *group_node, uint32_t owner,
                                     bool *one_shot) {
  if (one_shot)
    *one_shot = false;
  if (!graph || !fast || !groups || !node_range || !group_node ||
      owner >= graph->node_count)
    return -1;

  int32_t group = -1;
  if (graph->nodes[owner].type == SHELL_NODE_CMD &&
      node_range[owner] != UINT32_MAX && node_range[owner] < fast->count) {
    group = find_innermost_group(fast, node_range[owner]);
  } else if (graph->nodes[owner].type == SHELL_NODE_GROUP) {
    for (uint32_t i = 0; i < fast->group_count; i++)
      if (group_node[i] == owner) {
        if (groups[i].isolated) {
          group = (int32_t)i;
        } else {
          uint16_t parent = fast->groups[i].parent;
          group = parent == UINT16_MAX ? -1 : (int32_t)parent;
        }
        break;
      }
  }
  while (group >= 0) {
    if (groups[group].isolated)
      return group;
    uint16_t parent = fast->groups[group].parent;
    group = parent == UINT16_MAX ? -1 : (int32_t)parent;
  }

  if (graph->nodes[owner].type == SHELL_NODE_CMD &&
      node_range[owner] != UINT32_MAX && node_range[owner] < fast->count) {
    const shell_range_t *range = &fast->cmds[node_range[owner]];
    if (graph->nodes[owner].cmd.backgrounded ||
        (range->features & (SHELL_FEAT_PIPELINE | SHELL_FEAT_BACKGROUND)) !=
            0) {
      if (one_shot)
        *one_shot = true;
    }
  }
  return -1;
}

/* Return the immediate compound execution owner whose redirect list applies
 * to this owner. This is distinct from the named-FD persistence scope above:
 * an ordinary brace-group redirect is temporary, yet it still supplies the
 * descriptor table inherited by every command in that group. */
static int32_t dep_owner_enclosing_group(const shell_dep_graph_t *graph,
                                         const shell_parse_result_t *fast,
                                         const uint32_t *node_range,
                                         const uint32_t *group_node,
                                         uint32_t owner) {
  if (!graph || !fast || !node_range || !group_node ||
      owner >= graph->node_count)
    return -1;
  if (graph->nodes[owner].type == SHELL_NODE_CMD &&
      node_range[owner] != UINT32_MAX && node_range[owner] < fast->count)
    return find_innermost_group(fast, node_range[owner]);
  if (graph->nodes[owner].type != SHELL_NODE_GROUP)
    return -1;
  for (uint32_t group = 0; group < fast->group_count; group++) {
    if (group_node[group] != owner)
      continue;
    return fast->groups[group].parent == UINT16_MAX
               ? -1
               : (int32_t)fast->groups[group].parent;
  }
  return -1;
}

static bool dep_route_owned_by_enclosing_group(
    const shell_dep_graph_t *graph, const shell_parse_result_t *fast,
    const uint32_t *node_range, const uint32_t *group_node, uint32_t owner,
    const shell_dep_edge_t *original) {
  for (int32_t group = dep_owner_enclosing_group(graph, fast, node_range,
                                                 group_node, owner);
       group >= 0;) {
    uint32_t group_owner = group_node[group];
    if (original->from == group_owner || original->to == group_owner)
      return true;
    uint16_t parent = fast->groups[group].parent;
    group = parent == UINT16_MAX ? -1 : (int32_t)parent;
  }
  return false;
}

/* A member of a brace group is conditional when any enclosing group is a
 * member of an AND-OR list. The child must not publish its named descriptor
 * mutations into the unconditional shell table merely because it has no
 * control edge of its own. */
static bool dep_owner_is_conditionally_scoped(
    const shell_dep_graph_t *graph, const shell_parse_result_t *fast,
    const uint32_t *node_range, const uint32_t *group_node,
    const shell_dep_edge_t *edges, uint32_t edge_count, uint32_t owner) {
  if (dep_owner_touches_branch_boundary(edges, edge_count, owner))
    return true;
  int32_t group =
      dep_owner_enclosing_group(graph, fast, node_range, group_node, owner);
  while (group >= 0) {
    uint32_t group_owner = group_node[group];
    if (group_owner < graph->node_count &&
        dep_owner_touches_branch_boundary(edges, edge_count, group_owner))
      return true;
    group = fast->groups[group].parent == UINT16_MAX
                ? -1
                : (int32_t)fast->groups[group].parent;
  }
  return false;
}

static int32_t dep_named_scope_parent(const shell_parse_result_t *fast,
                                      const dep_group_exec_t *groups,
                                      uint32_t group) {
  if (!fast || !groups || group >= fast->group_count)
    return -1;
  uint16_t parent = fast->groups[group].parent;
  while (parent != UINT16_MAX) {
    if (groups[parent].isolated)
      return (int32_t)parent;
    parent = fast->groups[parent].parent;
  }
  return -1;
}

static uint32_t dep_owner_source_start(const shell_dep_graph_t *graph,
                                       const shell_parse_result_t *fast,
                                       const uint32_t *node_range,
                                       const uint32_t *group_node,
                                       const char *cmd, uint32_t owner) {
  if (!graph || !fast || !node_range || !group_node || !cmd ||
      owner >= graph->node_count)
    return UINT32_MAX;
  if (graph->nodes[owner].type == SHELL_NODE_CMD &&
      node_range[owner] != UINT32_MAX && node_range[owner] < fast->count)
    return fast->cmds[node_range[owner]].start;
  if (graph->nodes[owner].type == SHELL_NODE_GROUP)
    for (uint32_t group = 0; group < fast->group_count; group++)
      if (group_node[group] == owner)
        return fast->groups[group].start;
  return UINT32_MAX;
}

/* Read the connector at an owner's own source opening. A group's first child
 * may inherit a connector from outside the group, and a nested child may
 * inherit one from an outer group, so its fast-range type is not reliable. */
static shell_dep_edge_type_t
dep_snapshot_source_predecessor_type(const dep_parse_context_t *context,
                                     uint32_t start) {
  size_t before = shell_source_skip_list_trivia_backward(
      context->cmd, context->cmd_len, start);
  before = shell_source_skip_escaped_line_endings_backward(
      context->cmd, context->cmd_len, before);
  while (before != 0 && context->cmd[before - 1] == '!') {
    before = shell_source_skip_list_trivia_backward(
        context->cmd, context->cmd_len, before - 1);
    before = shell_source_skip_escaped_line_endings_backward(
        context->cmd, context->cmd_len, before);
  }
  if (before >= 2 && context->cmd[before - 1] == '&' &&
      context->cmd[before - 2] == '&')
    return SHELL_EDGE_AND;
  if (before >= 2 && context->cmd[before - 1] == '|' &&
      context->cmd[before - 2] == '|')
    return SHELL_EDGE_OR;
  return SHELL_EDGE_SEQ;
}

static shell_dep_edge_type_t
dep_snapshot_group_predecessor_type(const dep_parse_context_t *context,
                                    uint32_t group) {
  return dep_snapshot_source_predecessor_type(
      context, context->fast->groups[group].start);
}

/* Recursive parsing can request a descriptor snapshot before the outer graph
 * has emitted every control edge. Use stable source and tokenizer metadata. */
static shell_dep_edge_type_t
dep_snapshot_owner_predecessor_type(const dep_parse_context_t *context,
                                    uint32_t owner) {
  if (!context || !context->fast || !context->node_range || owner == UINT32_MAX)
    return SHELL_EDGE_SEQ;
  if (owner < SHELL_DEP_MAX_NODES && context->node_range[owner] != UINT32_MAX &&
      context->node_range[owner] < context->fast->count)
    return dep_snapshot_source_predecessor_type(
        context, context->fast->cmds[context->node_range[owner]].start);
  for (uint32_t group = 0; group < context->fast->group_count; group++)
    if (context->group_node[group] == owner)
      return dep_snapshot_group_predecessor_type(context, group);
  return SHELL_EDGE_SEQ;
}

static uint32_t dep_group_trailing_end(const char *cmd, uint32_t cmd_len,
                                       uint32_t start) {
  size_t pos = start;
  while (pos < cmd_len) {
    pos = shell_source_skip_inline_continuations(cmd, cmd_len, pos);
    size_t after = shell_source_skip_redirect(cmd, pos, cmd_len);
    if (after == pos)
      break;
    pos = after;
  }
  return (uint32_t)pos;
}

static shell_dep_edge_type_t
dep_snapshot_group_successor_type(const dep_parse_context_t *context,
                                  uint32_t group) {
  const shell_group_t *descriptor = &context->fast->groups[group];
  size_t after =
      dep_group_trailing_end(context->cmd, context->cmd_len, descriptor->end);
  after = shell_source_skip_list_trivia(context->cmd, context->cmd_len, after);
  if (shell_source_match_logical_punctuation(context->cmd, context->cmd_len,
                                             after, "&&", NULL))
    return SHELL_EDGE_AND;
  if (shell_source_match_logical_punctuation(context->cmd, context->cmd_len,
                                             after, "||", NULL))
    return SHELL_EDGE_OR;
  return SHELL_EDGE_SEQ;
}

static bool
dep_snapshot_group_is_conditional(const dep_parse_context_t *context,
                                  uint32_t group) {
  return dep_snapshot_group_predecessor_type(context, group) ==
             SHELL_EDGE_AND ||
         dep_snapshot_group_predecessor_type(context, group) == SHELL_EDGE_OR ||
         dep_snapshot_group_successor_type(context, group) == SHELL_EDGE_AND ||
         dep_snapshot_group_successor_type(context, group) == SHELL_EDGE_OR;
}

typedef enum {
  /* Command arguments expand before the simple command's redirections. */
  DEP_SNAPSHOT_COMMAND_WORD,
  /* A redirect operand expands while its redirect list is applied
   * left-to-right, after preceding redirects but before its own operation. */
  DEP_SNAPSHOT_REDIRECT_OPERAND,
} dep_snapshot_phase_t;

static bool dep_named_scope_is_visible(const shell_parse_result_t *fast,
                                       const dep_group_exec_t *groups,
                                       int32_t candidate, int32_t current) {
  if (candidate < 0)
    return true;
  while (current >= 0) {
    if (candidate == current)
      return true;
    current = dep_named_scope_parent(fast, groups, (uint32_t)current);
  }
  return false;
}

static bool dep_is_direct_io_edge(const shell_dep_graph_t *graph,
                                  const shell_dep_edge_t *edge,
                                  uint32_t *owner);

/* Gather the descriptor operations which have an already-constructed
 * syntactic edge. A nested shell needs the complete state of earlier `exec`
 * redirects, not only dynamically allocated names. */
static bool dep_snapshot_fd_operations(const shell_dep_graph_t *graph,
                                       const dep_parse_context_t *context,
                                       uint32_t owner, dep_fd_op_t *ops,
                                       uint32_t *op_count,
                                       uint32_t op_capacity) {
  if (!graph || !context || !context->cmd || !context->fast || !ops ||
      !op_count)
    return false;
  *op_count = 0;
  bool used_edges[SHELL_DEP_MAX_EDGES] = {false};
  bool dynamic_edges[SHELL_DEP_MAX_EDGES] = {false};
  bool invalid_dup = false;

  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    uint32_t edge_owner = UINT32_MAX;
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (!dep_is_direct_io_edge(graph, item, &edge_owner) ||
        edge_owner != owner || *op_count >= op_capacity)
      continue;
    uint32_t document = item->type == SHELL_EDGE_READ ? item->from : item->to;
    if (document >= graph->node_count ||
        graph->nodes[document].type != SHELL_NODE_DOC)
      continue;
    const char *source = dep_document_source(&graph->nodes[document]);
    if (!source)
      return false;
    ops[(*op_count)++] = (dep_fd_op_t){
        (uint32_t)(source - context->cmd),
        DEP_FD_OP_DOCUMENT,
        item->type == SHELL_EDGE_READ ? item->target_fd : item->source_fd,
        SHELL_DEP_FD_NONE,
        item->type == SHELL_EDGE_READ ? item->target_fd_name
                                      : item->source_fd_name,
        item->type == SHELL_EDGE_READ ? item->target_fd_name_len
                                      : item->source_fd_name_len,
        NULL,
        0,
        edge,
        item->type == SHELL_EDGE_READ ? DEP_FD_ACCESS_READ
                                      : DEP_FD_ACCESS_WRITE,
    };
  }

  /* A FILE-backed named allocation is represented as FD_OPEN until a later
   * symbolic duplication materializes byte flow.  Preserve its raw edge
   * index so an imported child can join directly to that parent resource. */
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type != SHELL_EDGE_FD_OPEN || *op_count >= op_capacity)
      continue;
    bool input = item->target_fd == SHELL_DEP_FD_NAMED && item->to == owner;
    bool output = item->source_fd == SHELL_DEP_FD_NAMED && item->from == owner;
    if (!input && !output)
      continue;
    uint32_t document = input ? item->from : item->to;
    if (document >= graph->node_count ||
        graph->nodes[document].type != SHELL_NODE_DOC)
      continue;
    const char *source = dep_document_source(&graph->nodes[document]);
    if (!source)
      return false;
    ops[(*op_count)++] = (dep_fd_op_t){
        (uint32_t)(source - context->cmd),
        DEP_FD_OP_DOCUMENT,
        SHELL_DEP_FD_NAMED,
        SHELL_DEP_FD_NONE,
        input ? item->target_fd_name : item->source_fd_name,
        input ? item->target_fd_name_len : item->source_fd_name_len,
        NULL,
        0,
        edge,
        input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE,
    };
  }

  if (graph->nodes[owner].type == SHELL_NODE_CMD &&
      context->node_range[owner] != UINT32_MAX &&
      context->node_range[owner] < context->fast->count) {
    const shell_range_t *range =
        &context->fast->cmds[context->node_range[owner]];
    if (!dep_add_process_substitution_operations(
            context->cmd, range->start, range->len, owner, graph, graph->edges,
            graph->edge_count, used_edges, dynamic_edges, ops, op_count,
            op_capacity) ||
        !dep_add_dup_operations(context->cmd, range->start, range->len, ops,
                                op_count, op_capacity, &invalid_dup))
      return false;
  } else if (graph->nodes[owner].type == SHELL_NODE_GROUP) {
    for (uint32_t group = 0; group < context->fast->group_count; group++) {
      if (context->group_node[group] != owner)
        continue;
      const shell_group_t *descriptor = &context->fast->groups[group];
      uint32_t trailing_end = dep_group_trailing_end(
          context->cmd, context->cmd_len, descriptor->end);
      uint32_t trailing_len = trailing_end - descriptor->end;
      if (!dep_add_process_substitution_operations(
              context->cmd, descriptor->end, trailing_len, owner, graph,
              graph->edges, graph->edge_count, used_edges, dynamic_edges, ops,
              op_count, op_capacity) ||
          !dep_add_dup_operations(context->cmd, descriptor->end, trailing_len,
                                  ops, op_count, op_capacity, &invalid_dup))
        return false;
      break;
    }
  }
  if (invalid_dup)
    return false;
  dep_sort_fd_operations(ops, *op_count);
  return true;
}

static bool dep_snapshot_apply_fd_operations(dep_owner_routes_t *state,
                                             const dep_fd_op_t *ops,
                                             uint32_t op_count,
                                             uint32_t before_position) {
  if (!state || !ops)
    return false;
  dep_fd_ref_t allocations[SHELL_DEP_MAX_TOKENS * 3] = {0};
  uint32_t allocation_positions[SHELL_DEP_MAX_TOKENS * 3] = {0};
  uint32_t allocation_count = 0;
  for (uint32_t i = 0; i < op_count; i++) {
    const dep_fd_op_t *item = &ops[i];
    if (item->pos >= before_position)
      continue;
    dep_fd_ref_t source = {item->fd, item->fd_name, item->fd_name_len};
    if (source.value == SHELL_DEP_FD_NAMED &&
        (!source.name || source.name_len == 0))
      return false;
    dep_fd_ref_t target = {item->target_fd, item->target_fd_name,
                           item->target_fd_name_len};
    bool self_rebind =
        item->kind == DEP_FD_OP_DUP && dep_fd_ref_equal(source, target);
    dep_fd_route_t saved_read = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
    dep_fd_route_t saved_write = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
    if (self_rebind) {
      dep_fd_route_entry_t *slot =
          dep_route_slot(state->fd, &state->fd_count, target, false);
      if (!slot)
        return false;
      saved_read = slot->read_route;
      saved_write = slot->write_route;
    }

    if (source.value == SHELL_DEP_FD_NAMED && item->kind != DEP_FD_OP_CLOSE) {
      bool seen = false;
      for (uint32_t allocation = 0; allocation < allocation_count; allocation++)
        if (allocation_positions[allocation] == item->pos &&
            dep_fd_ref_equal(allocations[allocation], source)) {
          seen = true;
          break;
        }
      if (!seen) {
        if (!dep_route_reset_named(state, source) ||
            allocation_count >= sizeof(allocations) / sizeof(allocations[0]))
          return false;
        allocations[allocation_count] = source;
        allocation_positions[allocation_count++] = item->pos;
      }
    }

    if (item->kind == DEP_FD_OP_DOCUMENT || item->kind == DEP_FD_OP_DYNAMIC) {
      dep_route_kind_t kind =
          item->kind == DEP_FD_OP_DOCUMENT ? DEP_ROUTE_DOC : DEP_ROUTE_DYNAMIC;
      if (!dep_route_assign(state->fd, &state->fd_count, source, item->access,
                            (dep_fd_route_t){kind, item->edge_index}))
        return false;
      continue;
    }
    if (item->kind == DEP_FD_OP_CLOSE) {
      if (source.value == SHELL_DEP_FD_NAMED &&
          dep_route_slot(state->fd, &state->fd_count, source, false) == NULL)
        return false;
      if (!dep_route_assign(state->fd, &state->fd_count, source,
                            DEP_FD_ACCESS_BOTH,
                            (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX}))
        return false;
      continue;
    }

    if (target.value == SHELL_DEP_FD_NAMED && !self_rebind &&
        dep_route_slot(state->fd, &state->fd_count, target, false) == NULL)
      return false;
    dep_fd_route_t read = self_rebind
                              ? saved_read
                              : dep_route_get(state->fd, state->fd_count,
                                              target, DEP_FD_ACCESS_READ);
    dep_fd_route_t write = self_rebind
                               ? saved_write
                               : dep_route_get(state->fd, state->fd_count,
                                               target, DEP_FD_ACCESS_WRITE);
    bool closed_locally = dep_fd_closed_earlier_in_owner(ops, i, target);
    if (((item->access & DEP_FD_ACCESS_READ) != 0 &&
         read.kind == DEP_ROUTE_CLOSED && !closed_locally) ||
        ((item->access & DEP_FD_ACCESS_WRITE) != 0 &&
         write.kind == DEP_ROUTE_CLOSED && !closed_locally) ||
        (target.value == SHELL_DEP_FD_NAMED &&
         source.value != SHELL_DEP_FD_NAMED &&
         (((item->access & DEP_FD_ACCESS_READ) != 0 &&
           read.kind == DEP_ROUTE_UNAVAILABLE) ||
          ((item->access & DEP_FD_ACCESS_WRITE) != 0 &&
           write.kind == DEP_ROUTE_UNAVAILABLE))))
      return false;
    if (!dep_route_assign(state->fd, &state->fd_count, source,
                          DEP_FD_ACCESS_READ, read) ||
        !dep_route_assign(state->fd, &state->fd_count, source,
                          DEP_FD_ACCESS_WRITE, write))
      return false;
  }
  return true;
}

static bool dep_snapshot_export_route(dep_fd_imports_t *imports,
                                      dep_fd_ref_t fd, dep_fd_access_t access,
                                      dep_fd_route_t route,
                                      const shell_dep_graph_t *origin) {
  dep_fd_import_t *slot = dep_fd_import_slot(imports, fd, true);
  if (!slot)
    return false;
  dep_fd_route_t *destination =
      access == DEP_FD_ACCESS_READ ? &slot->read_route : &slot->write_route;
  const shell_dep_graph_t **destination_origin =
      access == DEP_FD_ACCESS_READ ? &slot->read_origin : &slot->write_origin;
  if (route.kind == DEP_ROUTE_DOC || route.kind == DEP_ROUTE_DYNAMIC) {
    *destination = (dep_fd_route_t){DEP_ROUTE_IMPORTED, route.value};
    *destination_origin = origin;
    return true;
  }
  if (route.kind == DEP_ROUTE_IMPORTED) {
    if (route.value >= imports->count)
      return false;
    const dep_fd_import_t *source = &imports->entries[route.value];
    if (access == DEP_FD_ACCESS_READ) {
      *destination = source->read_route;
      *destination_origin = source->read_origin;
    } else {
      *destination = source->write_route;
      *destination_origin = source->write_origin;
    }
    return true;
  }
  *destination = route;
  *destination_origin = NULL;
  return true;
}

static bool dep_group_owner_entered(const dep_parse_context_t *context,
                                    uint32_t owner) {
  if (!context->group_entered)
    return false;
  for (uint32_t group = 0; group < context->fast->group_count; group++)
    if (context->group_node[group] == owner)
      return context->group_entered[group];
  return false;
}

/* A group entry table is a snapshot, not a permanent overlay. Replay only
 * mutations made by a completed owner into the shell and each active group
 * table. Copying the owner's whole table would export temporary group-tail
 * redirects and command-local redirects into the surrounding shell. */
static bool dep_apply_persistent_owner_routes(
    dep_owner_routes_t *destination, const dep_owner_routes_t *executed,
    const dep_fd_op_t *ops, uint32_t op_count, bool descriptor_exec,
    bool named_binding, const char *cmd, const shell_range_t *range) {
  if (range) {
    dep_invalidate_assigned_named_routes(destination, cmd, range,
                                         DEP_NAMED_MUTATION_BEFORE_REDIRECT);
  }
  if (descriptor_exec) {
    for (uint32_t op = 0; op < op_count; op++) {
      dep_fd_ref_t fd = {ops[op].fd, ops[op].fd_name, ops[op].fd_name_len};
      const dep_fd_route_entry_t *source = NULL;
      for (uint32_t entry = 0; entry < executed->fd_count; entry++)
        if (dep_fd_ref_equal(executed->fd[entry].fd, fd)) {
          source = &executed->fd[entry];
          break;
        }
      if (!source)
        continue;
      dep_fd_route_entry_t *slot =
          dep_route_slot(destination->fd, &destination->fd_count, fd, true);
      if (!slot)
        return false;
      *slot = *source;
    }
  } else if (named_binding) {
    if (!dep_merge_persistent_named_routes(destination, executed, ops,
                                           op_count))
      return false;
  }
  /* A builtin may overwrite the descriptor variable after its own redirect
   * list installed a fresh named binding. The binding is real for this
   * command's I/O, but it must not survive into the next command. */
  if (range)
    dep_invalidate_assigned_named_routes(destination, cmd, range,
                                         DEP_NAMED_MUTATION_AFTER_COMMAND);
  return true;
}

/* Reconstruct the descriptor state visible at one expansion point.
 * Parsing discovers children before the final resolver runs, so scanning raw
 * FD_OPEN edges is unsound: it accidentally sees a same-command allocation,
 * a close not yet materialized, and non-persistent redirections. Replay
 * completed visible owners and their persistent effects, then optionally the
 * preceding operations in the current redirect list. */
static shell_dep_error_t dep_snapshot_fd_imports(
    const shell_dep_graph_t *graph, const dep_subgraph_streams_t *streams,
    const dep_parse_context_t *context, uint32_t current_owner,
    uint32_t position, dep_snapshot_phase_t phase, dep_fd_imports_t *imports) {
  if (!graph || !context || !context->cmd || !context->fast || !imports ||
      current_owner >= graph->node_count)
    return SHELL_DEP_EPARSE;
  *imports = streams ? streams->fd_imports : (dep_fd_imports_t){0};

  dep_owner_routes_t persistent_state = {0};
  dep_owner_routes_t and_state = {0};
  uint32_t and_owner = UINT32_MAX;
  int32_t and_scope = INT32_MIN;
  int32_t and_group = INT32_MIN;
  /* A compound redirect list is installed before the group's body executes,
   * even though it follows the closing delimiter in source text.  Keep that
   * temporary table separate from the shell's persistent table: children and
   * nested substitutions inherit it, but an ordinary group redirect must not
   * escape the group. */
  dep_owner_routes_t *group_state =
      context->workspace ? context->workspace->group_snapshot_routes : NULL;
  bool *group_state_ready =
      context->workspace ? context->workspace->group_snapshot_routes_ready
                         : NULL;
  if (context->fast->group_count != 0 && (!group_state || !group_state_ready))
    return SHELL_DEP_EWORKSPACE;
  if (group_state) {
    memset(group_state, 0, sizeof(*group_state) * SHELL_MAX_GROUPS);
    memset(group_state_ready, 0, sizeof(*group_state_ready) * SHELL_MAX_GROUPS);
  }
  dep_import_routes(&persistent_state, imports);
  bool current_one_shot = false;
  int32_t current_scope = dep_owner_named_scope(
      graph, context->fast, context->group_exec, context->node_range,
      context->group_node, current_owner, &current_one_shot);
  uint32_t owners[SHELL_DEP_MAX_NODES];
  uint32_t owner_count = 0;
  for (uint32_t owner = 0; owner < graph->node_count; owner++)
    if (dep_is_execution_node(graph, owner) &&
        ((graph->nodes[owner].type == SHELL_NODE_CMD &&
          context->node_range[owner] != UINT32_MAX &&
          context->node_range[owner] < context->fast->count) ||
         (graph->nodes[owner].type == SHELL_NODE_GROUP &&
          dep_group_owner_entered(context, owner))))
      owners[owner_count++] = owner;
  for (uint32_t i = 1; i < owner_count; i++) {
    uint32_t item = owners[i];
    uint32_t item_start =
        dep_owner_source_start(graph, context->fast, context->node_range,
                               context->group_node, context->cmd, item);
    uint32_t j = i;
    while (j > 0) {
      uint32_t prior = owners[j - 1];
      uint32_t prior_start =
          dep_owner_source_start(graph, context->fast, context->node_range,
                                 context->group_node, context->cmd, prior);
      if (prior_start <= item_start)
        break;
      owners[j] = prior;
      j--;
    }
    owners[j] = item;
  }

  for (uint32_t index = 0; index < owner_count; index++) {
    uint32_t owner = owners[index];
    uint32_t start =
        dep_owner_source_start(graph, context->fast, context->node_range,
                               context->group_node, context->cmd, owner);
    if (owner != current_owner && start >= position)
      continue;
    bool one_shot = false;
    int32_t scope = dep_owner_named_scope(
        graph, context->fast, context->group_exec, context->node_range,
        context->group_node, owner, &one_shot);
    if (!dep_named_scope_is_visible(context->fast, context->group_exec, scope,
                                    current_scope))
      continue;

    int32_t enclosing_group = dep_owner_enclosing_group(
        graph, context->fast, context->node_range, context->group_node, owner);
    int32_t owned_group = -1;
    if (graph->nodes[owner].type == SHELL_NODE_GROUP)
      for (uint32_t group = 0; group < context->fast->group_count; group++)
        if (context->group_node[group] == owner) {
          owned_group = (int32_t)group;
          break;
        }

    shell_dep_edge_type_t predecessor_type =
        dep_snapshot_owner_predecessor_type(context, owner);
    bool receives_and_state = !one_shot && predecessor_type == SHELL_EDGE_AND &&
                              and_owner != UINT32_MAX && and_scope == scope &&
                              and_group == enclosing_group;
    const dep_owner_routes_t *incoming = &persistent_state;
    if (group_state && enclosing_group >= 0 &&
        enclosing_group < SHELL_MAX_GROUPS &&
        group_state_ready[enclosing_group])
      incoming = &group_state[enclosing_group];
    if (receives_and_state)
      incoming = &and_state;
    shell_dep_edge_type_t successor_type = SHELL_EDGE_SEQ;
    if (owned_group >= 0) {
      successor_type =
          dep_snapshot_group_successor_type(context, (uint32_t)owned_group);
    } else if (index + 1 < owner_count &&
               dep_owner_enclosing_group(
                   graph, context->fast, context->node_range,
                   context->group_node, owners[index + 1]) == enclosing_group) {
      successor_type =
          dep_snapshot_owner_predecessor_type(context, owners[index + 1]);
    }
    bool conditional = predecessor_type == SHELL_EDGE_AND ||
                       predecessor_type == SHELL_EDGE_OR ||
                       successor_type == SHELL_EDGE_AND ||
                       successor_type == SHELL_EDGE_OR;
    bool ancestor_conditional = false;
    for (int32_t group = enclosing_group; group >= 0;) {
      ancestor_conditional |=
          dep_snapshot_group_is_conditional(context, (uint32_t)group);
      uint16_t parent = context->fast->groups[group].parent;
      group = parent == UINT16_MAX ? -1 : (int32_t)parent;
    }
    /* An owner reached through `||` may be skipped while its AND successor
     * still runs because the earlier left-associative list already succeeded.
     * Do not make its descriptor table a success-chain candidate. */
    bool publishes_and_state = !one_shot && predecessor_type != SHELL_EDGE_OR &&
                               successor_type == SHELL_EDGE_AND;
    if (owner == current_owner) {
      /* A command-word expansion sees the descriptor table inherited by this
       * owner, including a proven AND-success predecessor, but not its own
       * redirect list. Redirect operands additionally replay preceding
       * redirects in source order below. */
      persistent_state = *incoming;
      if (graph->nodes[owner].type == SHELL_NODE_CMD)
        dep_invalidate_assigned_named_routes(
            &persistent_state, context->cmd,
            &context->fast->cmds[context->node_range[owner]],
            DEP_NAMED_MUTATION_BEFORE_REDIRECT);
      if (phase != DEP_SNAPSHOT_REDIRECT_OPERAND)
        continue;
      dep_owner_routes_t partial = persistent_state;
      dep_fd_op_t ops[SHELL_DEP_MAX_TOKENS * 3] = {0};
      uint32_t op_count = 0;
      if (!dep_snapshot_fd_operations(graph, context, owner, ops, &op_count,
                                      sizeof(ops) / sizeof(ops[0])) ||
          !dep_snapshot_apply_fd_operations(&partial, ops, op_count, position))
        return SHELL_DEP_EPARSE;
      persistent_state = partial;
      continue;
    }
    if (one_shot) {
      and_owner = UINT32_MAX;
      continue;
    }

    bool descriptor_exec = false;
    if (graph->nodes[owner].type == SHELL_NODE_CMD) {
      if (context->node_range[owner] == UINT32_MAX ||
          context->node_range[owner] >= context->fast->count)
        continue;
      const shell_range_t *range =
          &context->fast->cmds[context->node_range[owner]];
      descriptor_exec = dep_owner_is_persistent_exec(context->cmd, range);
    } else if (graph->nodes[owner].type != SHELL_NODE_GROUP) {
      continue;
    }

    dep_owner_routes_t executed = *incoming;
    if (graph->nodes[owner].type == SHELL_NODE_CMD)
      dep_invalidate_assigned_named_routes(
          &executed, context->cmd,
          &context->fast->cmds[context->node_range[owner]],
          DEP_NAMED_MUTATION_BEFORE_REDIRECT);
    dep_fd_op_t ops[SHELL_DEP_MAX_TOKENS * 3] = {0};
    uint32_t op_count = 0;
    if (!dep_snapshot_fd_operations(graph, context, owner, ops, &op_count,
                                    sizeof(ops) / sizeof(ops[0])) ||
        !dep_snapshot_apply_fd_operations(&executed, ops, op_count, UINT32_MAX))
      return SHELL_DEP_EPARSE;
    if (graph->nodes[owner].type == SHELL_NODE_CMD)
      dep_invalidate_assigned_named_routes(
          &executed, context->cmd,
          &context->fast->cmds[context->node_range[owner]],
          DEP_NAMED_MUTATION_AFTER_COMMAND);

    if (group_state && owned_group >= 0) {
      group_state[owned_group] = executed;
      group_state_ready[owned_group] = true;
    }
    const shell_range_t *range =
        graph->nodes[owner].type == SHELL_NODE_CMD
            ? &context->fast->cmds[context->node_range[owner]]
            : NULL;
    bool named_binding = dep_owner_persists_named_binding(graph, owner);
    if (!conditional && !ancestor_conditional &&
        !dep_apply_persistent_owner_routes(&persistent_state, &executed, ops,
                                           op_count, descriptor_exec,
                                           named_binding, context->cmd, range))
      return SHELL_DEP_EPARSE;
    if (!conditional && group_state) {
      for (int32_t group = enclosing_group; group >= 0;) {
        bool parent_one_shot = false;
        int32_t parent_scope = dep_owner_named_scope(
            graph, context->fast, context->group_exec, context->node_range,
            context->group_node, context->group_node[group], &parent_one_shot);
        if (parent_scope != scope || !group_state_ready[group])
          break;
        if (!dep_apply_persistent_owner_routes(
                &group_state[group], &executed, ops, op_count, descriptor_exec,
                named_binding, context->cmd, range))
          return SHELL_DEP_EPARSE;
        uint16_t parent = context->fast->groups[group].parent;
        group = parent == UINT16_MAX ? -1 : (int32_t)parent;
      }
    }
    if (publishes_and_state) {
      if (descriptor_exec) {
        dep_copy_routes(&and_state, &executed);
      } else {
        dep_copy_routes(&and_state, incoming);
        if (!dep_merge_and_success_named_routes(&and_state, &executed))
          return SHELL_DEP_EPARSE;
      }
      and_owner = owner;
      and_scope = scope;
      and_group = enclosing_group;
    } else {
      and_owner = UINT32_MAX;
      and_group = INT32_MIN;
    }
  }

  for (uint32_t entry = 0; entry < persistent_state.fd_count; entry++) {
    const dep_fd_route_entry_t *item = &persistent_state.fd[entry];
    if (!dep_snapshot_export_route(imports, item->fd, DEP_FD_ACCESS_READ,
                                   item->read_route, graph) ||
        !dep_snapshot_export_route(imports, item->fd, DEP_FD_ACCESS_WRITE,
                                   item->write_route, graph))
      return SHELL_DEP_EPARSE;
  }
  return SHELL_DEP_OK;
}

static bool dep_is_direct_io_edge(const shell_dep_graph_t *graph,
                                  const shell_dep_edge_t *edge,
                                  uint32_t *owner) {
  if ((edge->type == SHELL_EDGE_READ &&
       graph->nodes[edge->from].type == SHELL_NODE_DOC &&
       dep_is_execution_node(graph, edge->to)) ||
      ((edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND) &&
       dep_is_execution_node(graph, edge->from) &&
       graph->nodes[edge->to].type == SHELL_NODE_DOC)) {
    *owner = edge->type == SHELL_EDGE_READ ? edge->to : edge->from;
    return true;
  }
  return false;
}

/* Find the document endpoint of a syntactic redirect/setup edge. FD_OPEN
 * duplication edges deliberately have no document endpoint. */
static uint32_t dep_edge_document_index(const shell_dep_graph_t *graph,
                                        const shell_dep_edge_t *edge) {
  if (!graph || !edge)
    return UINT32_MAX;
  uint32_t document = UINT32_MAX;
  if (edge->type == SHELL_EDGE_READ)
    document = edge->from;
  else if (edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND)
    document = edge->to;
  else if (edge->type == SHELL_EDGE_FD_OPEN) {
    if (edge->from < graph->node_count &&
        graph->nodes[edge->from].type == SHELL_NODE_DOC)
      document = edge->from;
    else if (edge->to < graph->node_count &&
             graph->nodes[edge->to].type == SHELL_NODE_DOC)
      document = edge->to;
  }
  return document < graph->node_count &&
                 graph->nodes[document].type == SHELL_NODE_DOC
             ? document
             : UINT32_MAX;
}

/* A named FD_OPEN remains meaningful only if the final persistent descriptor
 * table still reaches its original document. Historical setup edges alone are
 * not enough: `exec {fd}>out; exec {fd}>&-` has opened `out`, but has retired
 * that binding before any ordinary byte flow can use it. */
static void dep_mark_transient_documents(
    shell_dep_graph_t *graph, const shell_dep_edge_t *original_edges,
    uint32_t original_edge_count, const dep_owner_routes_t *persistent_routes,
    bool *named_setup_documents, bool *live_named_documents) {
  if (!graph || !original_edges || !persistent_routes ||
      !named_setup_documents || !live_named_documents)
    return;

  memset(named_setup_documents, 0,
         SHELL_DEP_MAX_NODES * sizeof(named_setup_documents[0]));
  memset(live_named_documents, 0,
         SHELL_DEP_MAX_NODES * sizeof(live_named_documents[0]));
  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    const shell_dep_edge_t *original = &original_edges[edge];
    if (original->source_fd != SHELL_DEP_FD_NAMED &&
        original->target_fd != SHELL_DEP_FD_NAMED)
      continue;
    uint32_t document = dep_edge_document_index(graph, original);
    if (document != UINT32_MAX)
      named_setup_documents[document] = true;
  }

  for (uint32_t entry = 0; entry < persistent_routes->fd_count; entry++) {
    const dep_fd_route_entry_t *binding = &persistent_routes->fd[entry];
    if (binding->fd.value != SHELL_DEP_FD_NAMED)
      continue;
    const dep_fd_route_t routes[] = {binding->read_route, binding->write_route};
    for (uint32_t access = 0; access < sizeof(routes) / sizeof(routes[0]);
         access++) {
      const dep_fd_route_t route = routes[access];
      if (route.kind != DEP_ROUTE_DOC || route.value >= original_edge_count)
        continue;
      uint32_t document =
          dep_edge_document_index(graph, &original_edges[route.value]);
      if (document != UINT32_MAX && named_setup_documents[document])
        live_named_documents[document] = true;
    }
  }

  for (uint32_t node = 0; node < graph->node_count; node++) {
    shell_dep_node_t *document = &graph->nodes[node];
    if (document->type != SHELL_NODE_DOC)
      continue;
    bool effective = false;
    bool numeric_setup = false;
    for (uint32_t edge_index = 0; edge_index < graph->edge_count;
         edge_index++) {
      const shell_dep_edge_t *edge = &graph->edges[edge_index];
      effective =
          effective || ((edge->type == SHELL_EDGE_READ && edge->from == node) ||
                        ((edge->type == SHELL_EDGE_WRITE ||
                          edge->type == SHELL_EDGE_APPEND) &&
                         edge->to == node));
      if (edge->type != SHELL_EDGE_FD_OPEN ||
          (edge->from != node && edge->to != node))
        continue;
      uint32_t fd = edge->from == node ? edge->target_fd : edge->source_fd;
      numeric_setup = numeric_setup || fd != SHELL_DEP_FD_NAMED;
    }
    bool retired_named_setup =
        named_setup_documents[node] && !live_named_documents[node];
    if (document->doc.kind == SHELL_DOC_FILE) {
      if (!effective && (numeric_setup || retired_named_setup))
        document->doc.flags |= SHELL_DEP_DOC_FLAG_TRANSIENT;
    } else if ((document->doc.kind == SHELL_DOC_HEREDOC ||
                document->doc.kind == SHELL_DOC_HERESTRING) &&
               !effective && !live_named_documents[node]) {
      document->doc.flags |= SHELL_DEP_DOC_FLAG_TRANSIENT;
    }
  }
}

static bool dep_add_resolved_edge_refs(shell_dep_graph_t *graph,
                                       uint32_t max_edges, uint32_t from,
                                       uint32_t to, shell_dep_edge_type_t type,
                                       dep_fd_ref_t source_fd,
                                       dep_fd_ref_t target_fd, uint8_t flags) {
  if (graph->edge_count >= max_edges) {
    graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }
  dep_add_edge(graph, from, to, type, source_fd.value, target_fd.value);
  shell_dep_edge_t *edge = &graph->edges[graph->edge_count - 1];
  edge->flags = flags;
  if (source_fd.value == SHELL_DEP_FD_NAMED)
    dep_set_named_fd(edge, true, source_fd.name, source_fd.name_len);
  if (target_fd.value == SHELL_DEP_FD_NAMED)
    dep_set_named_fd(edge, false, target_fd.name, target_fd.name_len);
  return true;
}

/* An output process substitution creates its collector before source-order
 * descriptor routing is resolved. If a later redirect or close replaces that
 * descriptor, the nested command still executes but receives no payload from
 * the outer command. Remove the now-unfed collector and its SUBST edge rather
 * than reporting an imaginary dynamic-content flow. A named FD_OPEN binding
 * is retained as a descriptor setup endpoint even before a later `$name`
 * copy provides actual bytes. */
static bool dep_prune_unfed_endpoints(shell_dep_graph_t *graph,
                                      dep_subgraph_streams_t *streams) {
  bool discard[SHELL_DEP_MAX_NODES] = {false};
  bool any_discarded = false;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (graph->nodes[node].type != SHELL_NODE_ENDPOINT ||
        graph->nodes[node].endpoint.reserved != 0)
      continue;
    bool has_write = false;
    bool has_setup = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *current = &graph->edges[edge];
      has_write = has_write ||
                  (current->type == SHELL_EDGE_WRITE && current->to == node);
      has_setup = has_setup || (current->type == SHELL_EDGE_FD_OPEN &&
                                (current->from == node || current->to == node));
    }
    discard[node] = !has_write && !has_setup;
    any_discarded = any_discarded || discard[node];
  }
  if (!any_discarded)
    return true;

  uint32_t remap[SHELL_DEP_MAX_NODES];
  uint32_t kept_nodes = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    remap[node] = discard[node] ? UINT32_MAX : kept_nodes++;

  /* fd_import_uses records a child command node by its current graph index.
   * Validate and remap every owner before changing the graph: retaining a
   * discarded or non-executable owner would otherwise materialize a
   * descriptor relation on the wrong command after compaction. */
  if (streams) {
    if (streams->fd_import_use_count > SHELL_DEP_MAX_EDGES)
      return false;
    for (uint32_t use = 0; use < streams->fd_import_use_count; use++) {
      uint32_t owner = streams->fd_import_uses[use].owner;
      if (owner >= graph->node_count || discard[owner] ||
          !dep_is_execution_node(graph, owner))
        return false;
    }
  }

  uint32_t kept_edges = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    shell_dep_edge_t current = graph->edges[edge];
    if (discard[current.from] || discard[current.to])
      continue;
    current.from = remap[current.from];
    current.to = remap[current.to];
    graph->edges[kept_edges++] = current;
  }
  graph->edge_count = kept_edges;

  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (discard[node])
      continue;
    shell_dep_node_t current = graph->nodes[node];
    if (current.type == SHELL_NODE_CMD) {
      if (current.cmd.pipe_stdin_source != UINT32_MAX)
        current.cmd.pipe_stdin_source = remap[current.cmd.pipe_stdin_source];
      if (current.cmd.pipe_stdin_target != UINT32_MAX)
        current.cmd.pipe_stdin_target = remap[current.cmd.pipe_stdin_target];
      if (current.cmd.pipe_stdout_source != UINT32_MAX)
        current.cmd.pipe_stdout_source = remap[current.cmd.pipe_stdout_source];
      if (current.cmd.pipe_stdout_target != UINT32_MAX)
        current.cmd.pipe_stdout_target = remap[current.cmd.pipe_stdout_target];
    }
    if (current.type == SHELL_NODE_GROUP && current.group.parent != UINT32_MAX)
      current.group.parent = remap[current.group.parent];
    graph->nodes[remap[node]] = current;
  }
  if (streams) {
    bool stdin_inherited[SHELL_DEP_MAX_NODES] = {false};
    bool stdout_inherited[SHELL_DEP_MAX_NODES] = {false};
    for (uint32_t node = 0; node < graph->node_count; node++) {
      if (discard[node])
        continue;
      stdin_inherited[remap[node]] = streams->stdin_inherited[node];
      stdout_inherited[remap[node]] = streams->stdout_inherited[node];
    }
    for (uint32_t use = 0; use < streams->fd_import_use_count; use++)
      streams->fd_import_uses[use].owner =
          remap[streams->fd_import_uses[use].owner];
    memcpy(streams->stdin_inherited, stdin_inherited,
           sizeof(streams->stdin_inherited));
    memcpy(streams->stdout_inherited, stdout_inherited,
           sizeof(streams->stdout_inherited));
  }
  graph->node_count = kept_nodes;
  return true;
}

static shell_dep_error_t dep_resolve_effective_routes(
    shell_dep_graph_t *graph, const char *cmd, uint32_t cmd_len,
    const shell_parse_result_t *fast, const uint32_t *node_range,
    const uint32_t *group_node, const dep_group_exec_t *group_exec,
    uint32_t max_nodes, uint32_t max_edges, dep_subgraph_streams_t *streams,
    const dep_fd_imports_t *imports, void *workspace_memory,
    size_t workspace_size) {
  /* Route tables used to occupy more than two MiB on every parse stack. The
   * graph already has bounded capacities, but a caller should not need a
   * multi-megabyte thread stack merely to resolve it. */
  if (!workspace_memory ||
      (uintptr_t)workspace_memory % _Alignof(dep_route_workspace_t) != 0 ||
      workspace_size < sizeof(dep_route_workspace_t))
    return SHELL_DEP_EWORKSPACE;
  dep_route_workspace_t *workspace = workspace_memory;
  dep_owner_routes_t *routes = workspace->routes;
  dep_owner_routes_t persistent_routes = {0};
  memset(workspace->scoped_routes_active, 0,
         sizeof(workspace->scoped_routes_active));
  memset(workspace->group_snapshot_routes_ready, 0,
         sizeof(workspace->group_snapshot_routes_ready));
  bool resolved_owner[SHELL_DEP_MAX_NODES] = {false};
  bool local_owner[SHELL_DEP_MAX_NODES] = {false};
  shell_dep_edge_t *original_edges = workspace->original_edges;
  dep_fd_transition_t *fd_transitions = workspace->fd_transitions;
  shell_dep_edge_t *pipes = workspace->pipes;
  dep_fd_op_t *ops = workspace->ops;
  dep_fd_ref_t *named_allocations = workspace->named_allocations;
  uint32_t *named_allocation_positions = workspace->named_allocation_positions;
  const uint32_t op_capacity = SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS;
  dep_import_routes(&persistent_routes, imports);
  for (uint32_t node = 0; node < graph->node_count; node++)
    local_owner[node] = graph->nodes[node].type == SHELL_NODE_CMD &&
                        node_range[node] != UINT32_MAX &&
                        node_range[node] < fast->count;
  for (uint32_t group = 0; group < fast->group_count; group++)
    if (group_node[group] != UINT32_MAX &&
        group_node[group] < graph->node_count)
      local_owner[group_node[group]] = true;
  uint32_t original_edge_count = graph->edge_count;
  memcpy(original_edges, graph->edges,
         original_edge_count * sizeof(original_edges[0]));
  bool used_dynamic_edges[SHELL_DEP_MAX_EDGES] = {false};
  bool dynamic_route_edges[SHELL_DEP_MAX_EDGES] = {false};
  bool persistent_setup_edges[SHELL_DEP_MAX_EDGES] = {false};
  uint32_t fd_transition_count = 0;
  uint32_t pipe_count = 0;
  uint32_t owner_order[SHELL_DEP_MAX_NODES];
  uint32_t owner_count = 0;

  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    const shell_dep_edge_t *item = &original_edges[edge];
    if (item->type != SHELL_EDGE_PIPE ||
        !dep_is_execution_node(graph, item->from) ||
        !dep_is_execution_node(graph, item->to) || !local_owner[item->from] ||
        !local_owner[item->to])
      continue;
    if (pipe_count < SHELL_DEP_MAX_EDGES)
      pipes[pipe_count++] = *item;
  }

  for (uint32_t owner = 0; owner < graph->node_count; owner++)
    if (dep_is_execution_node(graph, owner) && local_owner[owner])
      owner_order[owner_count++] = owner;
  for (uint32_t i = 1; i < owner_count; i++) {
    uint32_t item = owner_order[i];
    uint32_t item_start =
        dep_owner_source_start(graph, fast, node_range, group_node, cmd, item);
    uint32_t j = i;
    while (j > 0) {
      uint32_t prior = owner_order[j - 1];
      uint32_t prior_start = dep_owner_source_start(graph, fast, node_range,
                                                    group_node, cmd, prior);
      if (prior_start <= item_start)
        break;
      owner_order[j] = prior;
      j--;
    }
    owner_order[j] = item;
  }

  for (uint32_t owner_index = 0; owner_index < owner_count; owner_index++) {
    uint32_t owner = owner_order[owner_index];
    resolved_owner[owner] = true;
    uint32_t op_count = 0;
    uint32_t named_allocation_count = 0;
    bool invalid_dup = false;
    dep_owner_routes_t *state = &routes[owner];
    memset(state, 0, sizeof(*state));
    memset(workspace->route_touched[owner], 0,
           sizeof(workspace->route_touched[owner]));
    bool one_shot_scope = false;
    int32_t named_scope =
        dep_owner_named_scope(graph, fast, group_exec, node_range, group_node,
                              owner, &one_shot_scope);
    dep_owner_routes_t *persistent = &persistent_routes;
    if (named_scope >= 0) {
      if (!workspace->scoped_routes_active[named_scope]) {
        memset(&workspace->scoped_routes[named_scope], 0,
               sizeof(workspace->scoped_routes[named_scope]));
        workspace->scoped_routes_active[named_scope] = true;
        int32_t parent_scope =
            dep_named_scope_parent(fast, group_exec, (uint32_t)named_scope);
        dep_copy_routes(&workspace->scoped_routes[named_scope],
                        parent_scope >= 0 &&
                                workspace->scoped_routes_active[parent_scope]
                            ? &workspace->scoped_routes[parent_scope]
                            : &persistent_routes);
      }
      persistent = &workspace->scoped_routes[named_scope];
    }
    bool conditional_scope = dep_owner_is_conditionally_scoped(
        graph, fast, node_range, group_node, original_edges,
        original_edge_count, owner);
    int32_t enclosing_group =
        dep_owner_enclosing_group(graph, fast, node_range, group_node, owner);
    const dep_owner_routes_t *scope_incoming = persistent;
    if (enclosing_group >= 0 &&
        workspace->group_snapshot_routes_ready[enclosing_group])
      scope_incoming = &workspace->group_snapshot_routes[enclosing_group];
    uint32_t and_predecessor = UINT32_MAX;
    bool receives_and_state =
        !one_shot_scope &&
        dep_owner_and_success_predecessor(original_edges, original_edge_count,
                                          owner, &and_predecessor) &&
        and_predecessor < graph->node_count && resolved_owner[and_predecessor];
    if (receives_and_state) {
      bool predecessor_one_shot = false;
      int32_t predecessor_scope =
          dep_owner_named_scope(graph, fast, group_exec, node_range, group_node,
                                and_predecessor, &predecessor_one_shot);
      /* A direct AND successor inherits the current shell's successful
       * descriptor table, not a private child scope.  Do not export an
       * isolated, piped, or backgrounded predecessor through this shortcut. */
      receives_and_state =
          !predecessor_one_shot &&
          !dep_owner_has_private_execution_boundary(
              original_edges, original_edge_count, and_predecessor) &&
          predecessor_scope == named_scope;
    }
    dep_owner_routes_t and_success_routes = {0};
    const dep_owner_routes_t *incoming = scope_incoming;
    if (receives_and_state) {
      bool predecessor_exec =
          graph->nodes[and_predecessor].type == SHELL_NODE_CMD &&
          node_range[and_predecessor] != UINT32_MAX &&
          node_range[and_predecessor] < fast->count &&
          dep_owner_is_persistent_exec(
              cmd, &fast->cmds[node_range[and_predecessor]]);
      if (predecessor_exec) {
        dep_copy_routes(&and_success_routes, &routes[and_predecessor]);
      } else {
        dep_copy_routes(&and_success_routes, scope_incoming);
        if (!dep_merge_and_success_named_routes(&and_success_routes,
                                                &routes[and_predecessor])) {
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
          return SHELL_DEP_ETRUNC;
        }
      }
      /* The predecessor's own I/O still uses its pre-builtin routes. Its
       * success continuation, unlike that I/O, sees completed builtin
       * variable mutations. Keep this copy separate from routes[] because
       * the second pass uses those entries to materialize byte-flow edges. */
      if (graph->nodes[and_predecessor].type == SHELL_NODE_CMD &&
          node_range[and_predecessor] != UINT32_MAX &&
          node_range[and_predecessor] < fast->count)
        dep_invalidate_assigned_named_routes(
            &and_success_routes, cmd, &fast->cmds[node_range[and_predecessor]],
            DEP_NAMED_MUTATION_AFTER_COMMAND);
      incoming = &and_success_routes;
    }
    /* `exec` changes its current shell's descriptor table whenever it runs.
     * In a conditional list that table is only available to a proven `&&`
     * success continuation; it must not be promoted into `persistent`. */
    bool descriptor_exec =
        !one_shot_scope && graph->nodes[owner].type == SHELL_NODE_CMD &&
        node_range[owner] != UINT32_MAX && node_range[owner] < fast->count &&
        dep_owner_is_persistent_exec(cmd, &fast->cmds[node_range[owner]]);
    bool persistent_exec = descriptor_exec && !conditional_scope;
    /* Every child shell inherits descriptors visible at its creation point.
     * Only its changes are private. A conditional member can instead start
     * from a verified AND predecessor, but still cannot alter the ordinary
     * persistent table. */
    dep_copy_routes(state, incoming);
    const shell_range_t *owner_range =
        graph->nodes[owner].type == SHELL_NODE_CMD &&
                node_range[owner] != UINT32_MAX &&
                node_range[owner] < fast->count
            ? &fast->cmds[node_range[owner]]
            : NULL;
    if (owner_range)
      dep_invalidate_assigned_named_routes(state, cmd, owner_range,
                                           DEP_NAMED_MUTATION_BEFORE_REDIRECT);

    for (uint32_t pipe = 0; pipe < pipe_count; pipe++) {
      if (pipes[pipe].from == owner &&
          !dep_route_assign(state->fd, &state->fd_count,
                            dep_fd_numeric(pipes[pipe].source_fd),
                            DEP_FD_ACCESS_WRITE,
                            (dep_fd_route_t){DEP_ROUTE_PIPE, pipe}))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (pipes[pipe].to == owner &&
          !dep_route_assign(state->fd, &state->fd_count,
                            dep_fd_numeric(pipes[pipe].target_fd),
                            DEP_FD_ACCESS_READ,
                            (dep_fd_route_t){DEP_ROUTE_PIPE, pipe}))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    }

    for (uint32_t edge = 0; edge < original_edge_count; edge++) {
      uint32_t edge_owner = UINT32_MAX;
      if (!dep_is_direct_io_edge(graph, &original_edges[edge], &edge_owner) ||
          edge_owner != owner)
        continue;
      const shell_dep_edge_t *item = &original_edges[edge];
      const shell_dep_node_t *document =
          &graph->nodes[item->type == SHELL_EDGE_READ ? item->from : item->to];
      const char *source = dep_document_source(document);
      if (!source || op_count >= op_capacity) {
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        continue;
      }
      ops[op_count++] = (dep_fd_op_t){
          (uint32_t)(source - cmd),
          DEP_FD_OP_DOCUMENT,
          item->type == SHELL_EDGE_READ ? item->target_fd : item->source_fd,
          SHELL_DEP_FD_NONE,
          item->type == SHELL_EDGE_READ ? item->target_fd_name
                                        : item->source_fd_name,
          item->type == SHELL_EDGE_READ ? item->target_fd_name_len
                                        : item->source_fd_name_len,
          NULL,
          0,
          edge,
          item->type == SHELL_EDGE_READ ? DEP_FD_ACCESS_READ
                                        : DEP_FD_ACCESS_WRITE,
      };
    }

    /* FD_OPEN is the syntax-preserving representation for a named binding.
     * Add it to the private route table too, so a later `>&"$name"` can copy
     * its concrete file/document route onto an ordinary descriptor without
     * treating the symbolic descriptor itself as command-byte flow. */
    for (uint32_t edge = 0; edge < original_edge_count; edge++) {
      const shell_dep_edge_t *item = &original_edges[edge];
      if (item->type != SHELL_EDGE_FD_OPEN || op_count >= op_capacity)
        continue;
      bool input = item->target_fd == SHELL_DEP_FD_NAMED && item->to == owner;
      bool output =
          item->source_fd == SHELL_DEP_FD_NAMED && item->from == owner;
      if (!input && !output)
        continue;
      uint32_t document = input ? item->from : item->to;
      if (document >= graph->node_count ||
          graph->nodes[document].type != SHELL_NODE_DOC)
        continue;
      const char *source = dep_document_source(&graph->nodes[document]);
      if (!source) {
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        continue;
      }
      ops[op_count++] = (dep_fd_op_t){
          (uint32_t)(source - cmd),
          DEP_FD_OP_DOCUMENT,
          SHELL_DEP_FD_NAMED,
          SHELL_DEP_FD_NONE,
          input ? item->target_fd_name : item->source_fd_name,
          input ? item->target_fd_name_len : item->source_fd_name_len,
          NULL,
          0,
          edge,
          input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE,
      };
    }

    if (graph->nodes[owner].type == SHELL_NODE_CMD &&
        node_range[owner] != UINT32_MAX && node_range[owner] < fast->count) {
      const shell_range_t *range = &fast->cmds[node_range[owner]];
      if (!dep_add_process_substitution_operations(
              cmd, range->start, range->len, owner, graph, original_edges,
              original_edge_count, used_dynamic_edges, dynamic_route_edges, ops,
              &op_count, op_capacity))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (!dep_add_dup_operations(cmd, range->start, range->len, ops, &op_count,
                                  op_capacity, &invalid_dup))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (invalid_dup) {
        return SHELL_DEP_EPARSE;
      }
    } else if (graph->nodes[owner].type == SHELL_NODE_GROUP) {
      for (uint32_t group = 0; group < fast->group_count; group++) {
        if (group_node[group] != owner)
          continue;
        const shell_group_t *descriptor = &fast->groups[group];
        uint32_t trailing_end =
            dep_group_trailing_end(cmd, cmd_len, descriptor->end);
        uint32_t trailing_len = trailing_end - descriptor->end;
        if (!dep_add_process_substitution_operations(
                cmd, descriptor->end, trailing_len, owner, graph,
                original_edges, original_edge_count, used_dynamic_edges,
                dynamic_route_edges, ops, &op_count, op_capacity) ||
            !dep_add_dup_operations(cmd, descriptor->end, trailing_len, ops,
                                    &op_count, op_capacity, &invalid_dup))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        if (invalid_dup) {
          return SHELL_DEP_EPARSE;
        }
        break;
      }
    }

    dep_sort_fd_operations(ops, op_count);
    for (uint32_t op = 0; op < op_count; op++) {
      dep_fd_op_t *item = &ops[op];
      dep_fd_ref_t source = {item->fd, item->fd_name, item->fd_name_len};
      dep_fd_ref_t target = {item->target_fd, item->target_fd_name,
                             item->target_fd_name_len};
      bool self_rebind = item->kind == DEP_FD_OP_DUP &&
                         source.value == SHELL_DEP_FD_NAMED &&
                         target.value == SHELL_DEP_FD_NAMED &&
                         dep_fd_ref_equal(source, target);
      dep_fd_route_t saved_read = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
      dep_fd_route_t saved_write = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
      if (self_rebind) {
        dep_fd_route_entry_t *slot =
            dep_route_slot(state->fd, &state->fd_count, target, false);
        if (!slot)
          return SHELL_DEP_EPARSE;
        saved_read = slot->read_route;
        saved_write = slot->write_route;
      }
      /* A named-FD declaration assigns a new descriptor value. Do not let a
       * previous `$name` binding supply a direction that the new redirect did
       * not open. The two halves of `<>` share a source position and must
       * instead form one bidirectional allocation. */
      if (item->fd == SHELL_DEP_FD_NAMED && item->kind != DEP_FD_OP_CLOSE) {
        dep_fd_ref_t named = {SHELL_DEP_FD_NAMED, item->fd_name,
                              item->fd_name_len};
        bool seen = false;
        for (uint32_t i = 0; i < named_allocation_count; i++)
          if (named_allocation_positions[i] == item->pos &&
              dep_fd_ref_equal(named_allocations[i], named)) {
            seen = true;
            break;
          }
        if (!seen) {
          if (!dep_route_reset_named(state, named))
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
          if (named_allocation_count < SHELL_DEP_MAX_EDGES) {
            named_allocations[named_allocation_count] = named;
            named_allocation_positions[named_allocation_count++] = item->pos;
          } else {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
          }
        }
      }
      /* An explicit close affects this command even when it is not a
       * persistent `exec` transition. Preserve that real I/O state in the
       * graph; ordinary nonpersistent duplications still need no setup edge
       * beyond their routing effect. */
      if (item->kind == DEP_FD_OP_CLOSE ||
          (item->kind == DEP_FD_OP_DUP &&
           (item->fd == SHELL_DEP_FD_NAMED || descriptor_exec))) {
        if (fd_transition_count >= SHELL_DEP_MAX_EDGES)
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        else
          fd_transitions[fd_transition_count++] =
              (dep_fd_transition_t){owner, *item};
      }
      if (item->kind == DEP_FD_OP_DOCUMENT) {
        if (!dep_route_assign(
                state->fd, &state->fd_count,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                item->access,
                (dep_fd_route_t){DEP_ROUTE_DOC, item->edge_index}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else if (item->kind == DEP_FD_OP_DYNAMIC) {
        if (!dep_route_assign(
                state->fd, &state->fd_count,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                item->access,
                (dep_fd_route_t){DEP_ROUTE_DYNAMIC, item->edge_index}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else if (item->kind == DEP_FD_OP_CLOSE) {
        if (item->fd == SHELL_DEP_FD_NAMED &&
            dep_route_slot(state->fd, &state->fd_count, source, false) == NULL)
          return SHELL_DEP_EPARSE;
        if (!dep_route_assign(state->fd, &state->fd_count, source,
                              DEP_FD_ACCESS_BOTH,
                              (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else {
        if (target.value == SHELL_DEP_FD_NAMED && !self_rebind &&
            dep_route_slot(state->fd, &state->fd_count, target, false) ==
                NULL) {
          return SHELL_DEP_EPARSE;
        }
        dep_fd_route_t copied_read =
            self_rebind ? saved_read
                        : dep_route_get(state->fd, state->fd_count, target,
                                        DEP_FD_ACCESS_READ);
        dep_fd_route_t copied_write =
            self_rebind ? saved_write
                        : dep_route_get(state->fd, state->fd_count, target,
                                        DEP_FD_ACCESS_WRITE);
        bool closed_locally = dep_fd_closed_earlier_in_owner(ops, op, target);
        if (((item->access & DEP_FD_ACCESS_READ) != 0 &&
             copied_read.kind == DEP_ROUTE_CLOSED && !closed_locally) ||
            ((item->access & DEP_FD_ACCESS_WRITE) != 0 &&
             copied_write.kind == DEP_ROUTE_CLOSED && !closed_locally) ||
            (target.value == SHELL_DEP_FD_NAMED &&
             source.value != SHELL_DEP_FD_NAMED &&
             (((item->access & DEP_FD_ACCESS_READ) != 0 &&
               copied_read.kind == DEP_ROUTE_UNAVAILABLE) ||
              ((item->access & DEP_FD_ACCESS_WRITE) != 0 &&
               copied_write.kind == DEP_ROUTE_UNAVAILABLE))))
          return SHELL_DEP_EPARSE;
        /* `exec` changes the descriptor table for a later command; it does
         * not itself consume or produce bytes through a copied imported
         * descriptor. A non-`exec` redirection belongs to the current command
         * and is the point where the recursive join must materialize flow. */
        if (!descriptor_exec && (item->access & DEP_FD_ACCESS_READ) != 0 &&
            copied_read.kind == DEP_ROUTE_IMPORTED &&
            !dep_record_fd_import_use(streams, owner, item->fd,
                                      DEP_FD_ACCESS_READ, copied_read.value))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        if (!descriptor_exec && (item->access & DEP_FD_ACCESS_WRITE) != 0 &&
            copied_write.kind == DEP_ROUTE_IMPORTED &&
            !dep_record_fd_import_use(streams, owner, item->fd,
                                      DEP_FD_ACCESS_WRITE, copied_write.value))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        /* Duplication into a named descriptor aliases the source descriptor
         * as a whole.  The `<&`/`>&` spelling selects the operation, not the
         * capabilities retained by its result.  Preserve both routes so an
         * output alias can later be used for output and an input alias can
         * later be used for input; unavailable routes remain unavailable. */
        dep_fd_access_t copied_access = DEP_FD_ACCESS_BOTH;
        if (!dep_route_assign(
                state->fd, &state->fd_count,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                copied_access & DEP_FD_ACCESS_READ, copied_read) ||
            !dep_route_assign(
                state->fd, &state->fd_count,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                copied_access & DEP_FD_ACCESS_WRITE, copied_write))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      }
    }
    /* Bash `|&` is shorthand for a normal stdout pipe followed by `2>&1`.
     * Apply it after every explicit redirect owned by this command or group;
     * seeding fd 2 as a second pipe before redirect processing is wrong for
     * forms such as `cmd 2>err |& next`. */
    for (uint32_t pipe = 0; pipe < pipe_count; pipe++) {
      if (pipes[pipe].from != owner ||
          (pipes[pipe].flags & DEP_EDGE_FLAG_PIPE_STDERR) == 0)
        continue;
      dep_fd_route_t copied_read = dep_route_get(
          state->fd, state->fd_count, dep_fd_numeric(1), DEP_FD_ACCESS_READ);
      dep_fd_route_t copied_write = dep_route_get(
          state->fd, state->fd_count, dep_fd_numeric(1), DEP_FD_ACCESS_WRITE);
      if (!dep_route_assign(state->fd, &state->fd_count, dep_fd_numeric(2),
                            DEP_FD_ACCESS_READ, copied_read) ||
          !dep_route_assign(state->fd, &state->fd_count, dep_fd_numeric(2),
                            DEP_FD_ACCESS_WRITE, copied_write))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      dep_mark_owner_route_touched(workspace, owner, state, dep_fd_numeric(2),
                                   DEP_FD_ACCESS_BOTH);
    }
    for (uint32_t op = 0; op < op_count; op++) {
      dep_fd_access_t access = ops[op].kind == DEP_FD_OP_DOCUMENT ||
                                       ops[op].kind == DEP_FD_OP_DYNAMIC
                                   ? ops[op].access
                                   : DEP_FD_ACCESS_BOTH;
      dep_mark_owner_route_touched(
          workspace, owner, state,
          (dep_fd_ref_t){ops[op].fd, ops[op].fd_name, ops[op].fd_name_len},
          access);
    }
    streams->stdin_inherited[owner] =
        dep_route_inherits(state, 0, DEP_FD_ACCESS_READ);
    streams->stdout_inherited[owner] =
        dep_route_inherits(state, 1, DEP_FD_ACCESS_WRITE);

    if (descriptor_exec) {
      for (uint32_t op = 0; op < op_count; op++)
        if ((ops[op].kind == DEP_FD_OP_DOCUMENT ||
             ops[op].kind == DEP_FD_OP_DYNAMIC) &&
            ops[op].fd != SHELL_DEP_FD_NAMED &&
            ops[op].edge_index < original_edge_count)
          persistent_setup_edges[ops[op].edge_index] = true;
    }
    bool named_binding = dep_owner_persists_named_binding(graph, owner);
    if (!one_shot_scope && !conditional_scope &&
        !dep_apply_persistent_owner_routes(persistent, state, ops, op_count,
                                           persistent_exec, named_binding, cmd,
                                           owner_range)) {
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      return SHELL_DEP_ETRUNC;
    }
    if (graph->nodes[owner].type == SHELL_NODE_GROUP)
      for (uint32_t group = 0; group < fast->group_count; group++)
        if (group_node[group] == owner) {
          /* Preserve the full effective table. The group-tail routes may be
           * copied by a later in-body exec even though their byte-flow edge
           * belongs to the group endpoint, not every child. */
          dep_copy_routes(&workspace->group_snapshot_routes[group], state);
          workspace->group_snapshot_routes_ready[group] = true;
          break;
        }
    if (!one_shot_scope && !dep_owner_touches_branch_boundary(
                               original_edges, original_edge_count, owner)) {
      for (int32_t group = enclosing_group; group >= 0;) {
        bool parent_one_shot = false;
        int32_t parent_scope = dep_owner_named_scope(
            graph, fast, group_exec, node_range, group_node, group_node[group],
            &parent_one_shot);
        if (parent_scope != named_scope ||
            !workspace->group_snapshot_routes_ready[group])
          break;
        if (!dep_apply_persistent_owner_routes(
                &workspace->group_snapshot_routes[group], state, ops, op_count,
                descriptor_exec, named_binding, cmd, owner_range)) {
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
          return SHELL_DEP_ETRUNC;
        }
        uint16_t parent = fast->groups[group].parent;
        group = parent == UINT16_MAX ? -1 : (int32_t)parent;
      }
    }
  }

  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!local_owner[owner] || graph->nodes[owner].type != SHELL_NODE_CMD)
      continue;
    shell_dep_cmd_t *command = &graph->nodes[owner].cmd;
    command->pipe_stdin_source = UINT32_MAX;
    command->pipe_stdin_target = UINT32_MAX;
    command->pipe_stdout_source = UINT32_MAX;
    command->pipe_stdout_target = UINT32_MAX;
    const dep_owner_routes_t *state = &routes[owner];
    dep_fd_route_t input = dep_route_get(state->fd, state->fd_count,
                                         dep_fd_numeric(0), DEP_FD_ACCESS_READ);
    dep_fd_route_t output = dep_route_get(
        state->fd, state->fd_count, dep_fd_numeric(1), DEP_FD_ACCESS_WRITE);
    if (input.kind == DEP_ROUTE_PIPE && input.value < pipe_count) {
      command->pipe_stdin_source = pipes[input.value].from;
      command->pipe_stdin_target = pipes[input.value].to;
    }
    if (output.kind == DEP_ROUTE_PIPE && output.value < pipe_count) {
      command->pipe_stdout_source = pipes[output.value].from;
      command->pipe_stdout_target = pipes[output.value].to;
    }
  }

  uint32_t kept = 0;
  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    uint32_t owner = UINT32_MAX;
    bool direct_io =
        dep_is_direct_io_edge(graph, &original_edges[edge], &owner) &&
        owner < graph->node_count && local_owner[owner];
    if ((original_edges[edge].type == SHELL_EDGE_PIPE &&
         original_edges[edge].from < graph->node_count &&
         original_edges[edge].to < graph->node_count &&
         local_owner[original_edges[edge].from] &&
         local_owner[original_edges[edge].to]) ||
        dynamic_route_edges[edge] || direct_io)
      continue;
    graph->edges[kept++] = original_edges[edge];
  }
  graph->edge_count = kept;

  /* Descriptor duplication and close are shell setup operations. A symbolic
   * descriptor has no fixed numeric byte route until a later use, while a
   * persistent numeric `exec` operation changes the shell's later FD state.
   * Both remain visible without pretending that setup transfers bytes. */
  for (uint32_t transition = 0; transition < fd_transition_count;
       transition++) {
    const dep_fd_transition_t *item = &fd_transitions[transition];
    dep_fd_ref_t source = {item->op.fd, item->op.fd_name, item->op.fd_name_len};
    if (item->op.kind == DEP_FD_OP_CLOSE) {
      dep_add_resolved_edge_refs(
          graph, max_edges, item->owner, item->owner, SHELL_EDGE_FD_CLOSE,
          source, dep_fd_numeric(SHELL_DEP_FD_NONE), SHELL_DEP_EDGE_FLAG_NONE);
    } else {
      dep_add_resolved_edge_refs(
          graph, max_edges, item->owner, item->owner, SHELL_EDGE_FD_OPEN,
          (dep_fd_ref_t){item->op.target_fd, item->op.target_fd_name,
                         item->op.target_fd_name_len},
          source, SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP);
    }
  }

  /* Redirections are evaluated in source order even if a later redirect,
   * close, or Bash `|&` descriptor copy replaces their final byte route. Keep
   * that setup relation as FD_OPEN for FILE documents instead of retaining a
   * stale READ/WRITE edge. The original direct edge and the final route have a
   * one-to-one identity, so this does not grow the bounded graph. */
  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    uint32_t owner = UINT32_MAX;
    if (!dep_is_direct_io_edge(graph, &original_edges[edge], &owner) ||
        owner >= graph->node_count || !resolved_owner[owner])
      continue;
    const shell_dep_edge_t *original = &original_edges[edge];
    uint32_t document =
        original->type == SHELL_EDGE_READ ? original->from : original->to;
    if (document >= graph->node_count ||
        graph->nodes[document].type != SHELL_NODE_DOC ||
        graph->nodes[document].doc.kind != SHELL_DOC_FILE)
      continue;

    const dep_owner_routes_t *state = &routes[owner];
    bool effective = false;
    for (uint32_t fd = 0; fd < state->fd_count; fd++) {
      dep_fd_route_t route = original->type == SHELL_EDGE_READ
                                 ? state->fd[fd].read_route
                                 : state->fd[fd].write_route;
      effective =
          effective || (route.kind == DEP_ROUTE_DOC && route.value == edge);
    }
    if (effective && !persistent_setup_edges[edge])
      continue;

    uint8_t flags = original->type == SHELL_EDGE_APPEND
                        ? SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND
                        : SHELL_DEP_EDGE_FLAG_NONE;
    if (original->type == SHELL_EDGE_READ) {
      dep_add_resolved_edge_refs(
          graph, max_edges, document, owner, SHELL_EDGE_FD_OPEN,
          dep_fd_numeric(SHELL_DEP_FD_NONE),
          (dep_fd_ref_t){original->target_fd, original->target_fd_name,
                         original->target_fd_name_len},
          flags);
    } else {
      dep_add_resolved_edge_refs(
          graph, max_edges, owner, document, SHELL_EDGE_FD_OPEN,
          (dep_fd_ref_t){original->source_fd, original->source_fd_name,
                         original->source_fd_name_len},
          dep_fd_numeric(SHELL_DEP_FD_NONE), flags);
    }
  }

  /* A persistent process-substitution descriptor is setup, just like a
   * persistent file descriptor. Keep the endpoint relation visible without
   * claiming that `exec` itself transferred bytes. */
  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    if (!persistent_setup_edges[edge])
      continue;
    const shell_dep_edge_t *original = &original_edges[edge];
    if (original->type == SHELL_EDGE_WRITE &&
        original->from < graph->node_count &&
        original->to < graph->node_count &&
        graph->nodes[original->to].type == SHELL_NODE_ENDPOINT) {
      dep_add_resolved_edge_refs(
          graph, max_edges, original->from, original->to, SHELL_EDGE_FD_OPEN,
          dep_fd_numeric(original->source_fd),
          dep_fd_numeric(SHELL_DEP_FD_NONE), original->flags);
    } else if (original->type == SHELL_EDGE_SUBST &&
               original->from < graph->node_count &&
               original->to < graph->node_count) {
      dep_add_resolved_edge_refs(
          graph, max_edges, original->from, original->to, SHELL_EDGE_FD_OPEN,
          dep_fd_numeric(original->source_fd),
          dep_fd_numeric(original->target_fd), original->flags);
    }
  }

  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!resolved_owner[owner])
      continue;
    /* A persistent `exec` changes descriptor state but does not itself
     * consume or produce bytes through inherited or duplicated routes. */
    if (graph->nodes[owner].type == SHELL_NODE_CMD &&
        node_range[owner] != UINT32_MAX && node_range[owner] < fast->count &&
        dep_owner_is_persistent_exec(cmd, &fast->cmds[node_range[owner]]))
      continue;
    const dep_owner_routes_t *state = &routes[owner];
    for (uint32_t i = 0; i < state->fd_count; i++) {
      if (state->fd[i].fd.value == SHELL_DEP_FD_NAMED)
        continue;
      const dep_fd_route_t route[2] = {state->fd[i].read_route,
                                       state->fd[i].write_route};
      for (uint32_t access = 0; access < 2; access++) {
        if (route[access].kind != DEP_ROUTE_DOC &&
            route[access].kind != DEP_ROUTE_DYNAMIC)
          continue;
        uint32_t original_edge = route[access].value;
        const shell_dep_edge_t *original = &original_edges[original_edge];
        dep_fd_access_t direction =
            access == 0 ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE;
        if ((dep_owner_route_touched(workspace, owner, i) & direction) == 0 &&
            dep_route_owned_by_enclosing_group(graph, fast, node_range,
                                               group_node, owner, original))
          continue;
        /* FD_OPEN flags describe only the retained setup edge. When a later
         * descriptor use materializes that setup as READ, WRITE, APPEND, or
         * SUBST, the byte-flow edge must carry only flags valid for its new
         * type. */
        uint8_t resolved_flags = original->type == SHELL_EDGE_FD_OPEN
                                     ? SHELL_DEP_EDGE_FLAG_NONE
                                     : original->flags;
        if (persistent_setup_edges[original_edge] &&
            ((original->from == owner || original->to == owner) ||
             state->fd[i].fd.value > 2))
          continue;
        if (route[access].kind == DEP_ROUTE_DOC &&
            (original->type == SHELL_EDGE_READ ||
             (original->type == SHELL_EDGE_FD_OPEN &&
              original->target_fd == SHELL_DEP_FD_NAMED))) {
          dep_add_resolved_edge_refs(graph, max_edges, original->from, owner,
                                     SHELL_EDGE_READ,
                                     dep_fd_numeric(SHELL_DEP_FD_NONE),
                                     state->fd[i].fd, resolved_flags);
        } else if (route[access].kind == DEP_ROUTE_DOC) {
          shell_dep_edge_type_t type = original->type;
          if (type == SHELL_EDGE_FD_OPEN) {
            type = original->source_fd == SHELL_DEP_FD_NAMED
                       ? ((original->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND)
                              ? SHELL_EDGE_APPEND
                              : SHELL_EDGE_WRITE)
                       : SHELL_EDGE_READ;
          }
          dep_add_resolved_edge_refs(
              graph, max_edges, owner, original->to, type, state->fd[i].fd,
              dep_fd_numeric(SHELL_DEP_FD_NONE), resolved_flags);
        } else if (original->type == SHELL_EDGE_SUBST ||
                   (original->type == SHELL_EDGE_FD_OPEN &&
                    original->target_fd == SHELL_DEP_FD_NAMED)) {
          dep_add_resolved_edge_refs(graph, max_edges, original->from, owner,
                                     SHELL_EDGE_SUBST,
                                     dep_fd_numeric(original->source_fd),
                                     state->fd[i].fd, resolved_flags);
        } else {
          shell_dep_edge_type_t type = original->type == SHELL_EDGE_FD_OPEN
                                           ? SHELL_EDGE_WRITE
                                           : original->type;
          dep_add_resolved_edge_refs(
              graph, max_edges, owner, original->to, type, state->fd[i].fd,
              dep_fd_numeric(SHELL_DEP_FD_NONE), resolved_flags);
        }
      }
    }
  }

  for (uint32_t pipe = 0; pipe < pipe_count; pipe++) {
    const shell_dep_edge_t *original = &pipes[pipe];
    const dep_owner_routes_t *source = &routes[original->from];
    const dep_owner_routes_t *target = &routes[original->to];
    bool has_target = false;
    for (uint32_t in = 0; in < target->fd_count; in++)
      has_target =
          has_target || (target->fd[in].read_route.kind == DEP_ROUTE_PIPE &&
                         target->fd[in].read_route.value == pipe);
    uint32_t terminal = UINT32_MAX;
    for (uint32_t out = 0; out < source->fd_count; out++) {
      if (source->fd[out].write_route.kind != DEP_ROUTE_PIPE ||
          source->fd[out].write_route.value != pipe)
        continue;
      if (!has_target) {
        if (terminal == UINT32_MAX) {
          if (graph->node_count >= max_nodes) {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            continue;
          }
          terminal = graph->node_count++;
          graph->nodes[terminal].type = SHELL_NODE_ENDPOINT;
          graph->nodes[terminal].endpoint.reserved = DEP_ENDPOINT_TERMINAL_PIPE;
        }
        dep_add_resolved_edge_refs(graph, max_edges, original->from, terminal,
                                   SHELL_EDGE_PIPE, source->fd[out].fd,
                                   dep_fd_numeric(0), SHELL_DEP_EDGE_FLAG_NONE);
        continue;
      }
      for (uint32_t in = 0; in < target->fd_count; in++) {
        if (target->fd[in].read_route.kind != DEP_ROUTE_PIPE ||
            target->fd[in].read_route.value != pipe)
          continue;
        dep_add_resolved_edge_refs(
            graph, max_edges, original->from, original->to, SHELL_EDGE_PIPE,
            source->fd[out].fd, target->fd[in].fd, SHELL_DEP_EDGE_FLAG_NONE);
      }
    }
  }

  dep_mark_transient_documents(
      graph, original_edges, original_edge_count, &persistent_routes,
      workspace->named_setup_documents, workspace->live_named_documents);
  if (!dep_prune_unfed_endpoints(graph, streams))
    return SHELL_DEP_EPARSE;
  return SHELL_DEP_OK;
}

typedef enum {
  DEP_SUBST_SHELL_WORD = 0,
  DEP_SUBST_DYNAMIC_NAME,
  DEP_SUBST_PROCESS_INPUT,
  DEP_SUBST_PROCESS_OUTPUT,
  DEP_SUBST_PROCESS_WORD,
} dep_subst_kind_t;

typedef struct {
  uint32_t nodes[SHELL_DEP_MAX_NODES];
  uint32_t count;
} dep_endpoint_list_t;

static shell_dep_error_t shell_dep_graph_parse_impl(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    bool initial_cwd_known, bool initial_cwd_absolute,
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams, const dep_fd_imports_t *imports);

/* Structural group membership is represented exclusively by GROUP edges.
 * Source ranges also cover recursively parsed substitutions, which execute as
 * independent graphs and must not inherit an enclosing group's descriptors.
 * Follow only containment edges so endpoint selection and Shellgate's view of
 * group-owned streams agree with the graph's actual topology. */
static bool dep_group_contains_node(const shell_dep_graph_t *graph,
                                    uint32_t group_node, uint32_t target_node) {
  if (group_node >= graph->node_count || target_node >= graph->node_count ||
      graph->nodes[group_node].type != SHELL_NODE_GROUP)
    return false;

  bool visited[SHELL_DEP_MAX_NODES] = {false};
  uint32_t pending[SHELL_DEP_MAX_NODES];
  uint32_t pending_count = 0;
  visited[group_node] = true;
  pending[pending_count++] = group_node;
  while (pending_count > 0) {
    uint32_t current = pending[--pending_count];
    for (uint32_t edge_index = 0; edge_index < graph->edge_count;
         edge_index++) {
      const shell_dep_edge_t *edge = &graph->edges[edge_index];
      if (edge->type != SHELL_EDGE_GROUP || edge->from != current ||
          edge->to >= graph->node_count)
        continue;
      if (edge->to == target_node)
        return true;
      if (graph->nodes[edge->to].type == SHELL_NODE_GROUP &&
          !visited[edge->to]) {
        visited[edge->to] = true;
        pending[pending_count++] = edge->to;
      }
    }
  }
  return false;
}

static bool dep_group_contains_command(const shell_dep_graph_t *graph,
                                       uint32_t group_node,
                                       uint32_t command_node) {
  return command_node < graph->node_count &&
         graph->nodes[command_node].type == SHELL_NODE_CMD &&
         dep_group_contains_node(graph, group_node, command_node);
}

static bool dep_command_is_grouped(const shell_dep_graph_t *graph,
                                   uint32_t command_node) {
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_GROUP &&
        dep_group_contains_command(graph, i, command_node))
      return true;
  return false;
}

static bool dep_node_has_edge(const shell_dep_graph_t *graph, uint32_t node,
                              shell_dep_edge_type_t type, bool outgoing,
                              uint32_t fd) {
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type != type || (outgoing ? edge->from : edge->to) != node)
      continue;
    uint32_t edge_fd = outgoing ? edge->source_fd : edge->target_fd;
    if (fd == SHELL_DEP_FD_NONE || edge_fd == fd)
      return true;
  }
  return false;
}

/* A command reaches the enclosing substitution stream only when neither it
 * nor a containing group redirects its stdout away or feeds it to an internal
 * pipeline stage. This intentionally models descriptor topology, not whether
 * a particular executable happens to emit bytes at runtime. A SUBST edge
 * leaving a command carries its stdout into a shell word; that stream ends at
 * the receiving command and must not also bypass it into an enclosing word. */
static bool
dep_command_stdout_reaches_substitution(const shell_dep_graph_t *graph,
                                        const dep_subgraph_streams_t *streams,
                                        uint32_t command_node) {
  if (!streams->stdout_inherited[command_node] ||
      /* This command already feeds an inner substitution. Its bytes end at
       * that shell-consumption boundary and must not bypass it into the
       * enclosing substitution. */
      dep_node_has_edge(graph, command_node, SHELL_EDGE_SUBST, true,
                        UINT32_MAX))
    return false;
  for (uint32_t i = 0; i < graph->node_count; i++) {
    if (graph->nodes[i].type != SHELL_NODE_GROUP ||
        !dep_group_contains_command(graph, i, command_node))
      continue;
    if (!streams->stdout_inherited[i])
      return false;
  }
  return true;
}

static void
dep_collect_substitution_outputs(const shell_dep_graph_t *graph,
                                 const dep_subgraph_streams_t *streams,
                                 dep_endpoint_list_t *outputs) {
  outputs->count = 0;
  /* A top-level group is an execution endpoint. Do not replace it with its
   * members: its existing containment and pipe edges retain that provenance. */
  for (uint32_t i = 0; i < graph->node_count; i++) {
    if (graph->nodes[i].type != SHELL_NODE_GROUP ||
        graph->nodes[i].group.parent != UINT32_MAX ||
        !streams->stdout_inherited[i] ||
        dep_node_has_edge(graph, i, SHELL_EDGE_SUBST, true, UINT32_MAX))
      continue;
    bool member_reaches_output = false;
    for (uint32_t command = 0; command < graph->node_count; command++)
      if (graph->nodes[command].type == SHELL_NODE_CMD &&
          dep_group_contains_command(graph, i, command) &&
          dep_command_stdout_reaches_substitution(graph, streams, command)) {
        member_reaches_output = true;
        break;
      }
    if (member_reaches_output)
      outputs->nodes[outputs->count++] = i;
  }
  for (uint32_t i = 0; i < graph->node_count; i++) {
    if (graph->nodes[i].type == SHELL_NODE_CMD &&
        !dep_command_is_grouped(graph, i) &&
        dep_command_stdout_reaches_substitution(graph, streams, i))
      outputs->nodes[outputs->count++] = i;
  }
}

/* The stdin side of an output process substitution is owned by the first
 * pipeline stage, or by each unpiped list member that still inherits fd 0.
 * A top-level group remains a single sink endpoint for its contents. */
static void
dep_collect_substitution_inputs(const shell_dep_graph_t *graph,
                                const dep_subgraph_streams_t *streams,
                                dep_endpoint_list_t *inputs) {
  inputs->count = 0;
  for (uint32_t i = 0; i < graph->node_count; i++) {
    if (graph->nodes[i].type != SHELL_NODE_GROUP ||
        graph->nodes[i].group.parent != UINT32_MAX ||
        !streams->stdin_inherited[i])
      continue;
    bool member_receives_input = false;
    for (uint32_t command = 0; command < graph->node_count; command++)
      if (graph->nodes[command].type == SHELL_NODE_CMD &&
          dep_group_contains_command(graph, i, command) &&
          streams->stdin_inherited[command]) {
        member_receives_input = true;
        break;
      }
    if (member_receives_input)
      inputs->nodes[inputs->count++] = i;
  }
  for (uint32_t i = 0; i < graph->node_count; i++) {
    if (graph->nodes[i].type != SHELL_NODE_CMD ||
        dep_command_is_grouped(graph, i) || !streams->stdin_inherited[i] ||
        /* A recursively parsed producer can otherwise appear as an ungrouped
         * command. Its stdout already feeds a substitution and it is not an
         * execution endpoint for the enclosing output-process target. */
        dep_node_has_edge(graph, i, SHELL_EDGE_SUBST, true, UINT32_MAX))
      continue;
    inputs->nodes[inputs->count++] = i;
  }
}

static void dep_add_edge(shell_dep_graph_t *graph, uint32_t from, uint32_t to,
                         shell_dep_edge_type_t type, uint32_t source_fd,
                         uint32_t target_fd) {
  shell_dep_edge_t *edge = &graph->edges[graph->edge_count++];
  dep_init_edge(edge, from, to, type, SHELL_DIR_FORWARD, source_fd, target_fd);
}

static void dep_add_subst_edge(shell_dep_graph_t *graph, uint32_t from,
                               uint32_t to, uint32_t source_fd,
                               uint32_t target_fd, dep_subst_kind_t kind) {
  dep_add_edge(graph, from, to, SHELL_EDGE_SUBST, source_fd, target_fd);
  graph->edges[graph->edge_count - 1].flags =
      kind == DEP_SUBST_SHELL_WORD
          ? SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD
          : (kind == DEP_SUBST_DYNAMIC_NAME
                 ? SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME
                 : SHELL_DEP_EDGE_FLAG_NONE);
}

static void dep_append_subgraph(shell_dep_graph_t *out,
                                const shell_dep_graph_t *subgraph,
                                dep_subgraph_streams_t *out_streams,
                                const dep_subgraph_streams_t *subgraph_streams,
                                uint32_t node_offset,
                                uint32_t cwd_offset_shift) {
  memcpy(out->cwd_buf.data + out->cwd_buf.len, subgraph->cwd_buf.data,
         subgraph->cwd_buf.len);
  out->cwd_buf.len += subgraph->cwd_buf.len;
  for (uint32_t i = 0; i < subgraph->node_count; i++) {
    out->nodes[out->node_count] = subgraph->nodes[i];
    out_streams->stdin_inherited[out->node_count] =
        subgraph_streams->stdin_inherited[i];
    out_streams->stdout_inherited[out->node_count] =
        subgraph_streams->stdout_inherited[i];
    if (out->nodes[out->node_count].type == SHELL_NODE_CMD) {
      out->nodes[out->node_count].cmd.cwd_offset += cwd_offset_shift;
      if (out->nodes[out->node_count].cmd.pipe_stdin_source != UINT32_MAX)
        out->nodes[out->node_count].cmd.pipe_stdin_source += node_offset;
      if (out->nodes[out->node_count].cmd.pipe_stdin_target != UINT32_MAX)
        out->nodes[out->node_count].cmd.pipe_stdin_target += node_offset;
      if (out->nodes[out->node_count].cmd.pipe_stdout_source != UINT32_MAX)
        out->nodes[out->node_count].cmd.pipe_stdout_source += node_offset;
      if (out->nodes[out->node_count].cmd.pipe_stdout_target != UINT32_MAX)
        out->nodes[out->node_count].cmd.pipe_stdout_target += node_offset;
    } else if (out->nodes[out->node_count].type == SHELL_NODE_DOC &&
               out->nodes[out->node_count].doc.kind == SHELL_DOC_FILE &&
               out->nodes[out->node_count].doc.cwd_known)
      out->nodes[out->node_count].doc.cwd_offset += cwd_offset_shift;
    else if (out->nodes[out->node_count].type == SHELL_NODE_GROUP &&
             out->nodes[out->node_count].group.parent != UINT32_MAX)
      out->nodes[out->node_count].group.parent += node_offset;
    out->node_count++;
  }
  for (uint32_t i = 0; i < subgraph->edge_count; i++) {
    shell_dep_edge_t *copy = &out->edges[out->edge_count++];
    *copy = subgraph->edges[i];
    copy->from += node_offset;
    copy->to += node_offset;
  }
}

/* Resolve child uses of a parent-owned descriptor after the child nodes have
 * been appended. The child parser intentionally keeps no cloned DOC or
 * ENDPOINT node: this join adds the actual READ/WRITE/SUBST edge to the
 * original parent resource. */
static bool
dep_materialize_fd_import_uses(shell_dep_graph_t *out, uint32_t max_edges,
                               uint32_t node_offset,
                               dep_subgraph_streams_t *out_streams,
                               const dep_subgraph_streams_t *subgraph_streams) {
  if (!out || !subgraph_streams)
    return false;
  for (uint32_t i = 0; i < subgraph_streams->fd_import_use_count; i++) {
    const dep_fd_import_use_t *use = &subgraph_streams->fd_import_uses[i];
    if (use->import_index >= subgraph_streams->fd_imports.count ||
        use->owner >= SHELL_DEP_MAX_NODES)
      return false;
    const dep_fd_import_t *import =
        &subgraph_streams->fd_imports.entries[use->import_index];
    dep_fd_route_t route = use->access == DEP_FD_ACCESS_READ
                               ? import->read_route
                               : import->write_route;
    const shell_dep_graph_t *origin = use->access == DEP_FD_ACCESS_READ
                                          ? import->read_origin
                                          : import->write_origin;
    if (node_offset > UINT32_MAX - use->owner)
      return false;
    if (origin != out) {
      int32_t import_index =
          dep_merge_fd_import(&out_streams->fd_imports, import);
      if (import_index < 0 ||
          !dep_record_fd_import_use(out_streams, node_offset + use->owner,
                                    use->fd, (dep_fd_access_t)use->access,
                                    (uint32_t)import_index))
        return false;
      continue;
    }
    if (route.kind != DEP_ROUTE_IMPORTED || route.value >= out->edge_count)
      continue;
    const shell_dep_edge_t *original = &out->edges[route.value];
    uint32_t child = node_offset + use->owner;
    if (child >= out->node_count)
      return false;
    if (use->access == DEP_FD_ACCESS_READ) {
      shell_dep_edge_type_t type =
          original->type == SHELL_EDGE_FD_OPEN &&
                  original->from < out->node_count &&
                  out->nodes[original->from].type != SHELL_NODE_DOC
              ? SHELL_EDGE_SUBST
          : original->type == SHELL_EDGE_FD_OPEN ? SHELL_EDGE_READ
                                                 : original->type;
      if ((type != SHELL_EDGE_READ && type != SHELL_EDGE_SUBST) ||
          original->from >= out->node_count)
        return false;
      dep_add_resolved_edge_refs(
          out, max_edges, original->from, child, type,
          dep_fd_numeric(original->source_fd), dep_fd_numeric(use->fd),
          type == SHELL_EDGE_SUBST ? original->flags
                                   : SHELL_DEP_EDGE_FLAG_NONE);
    } else {
      shell_dep_edge_type_t type = original->type;
      if (type == SHELL_EDGE_FD_OPEN)
        type = (original->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0
                   ? SHELL_EDGE_APPEND
                   : SHELL_EDGE_WRITE;
      if ((type != SHELL_EDGE_WRITE && type != SHELL_EDGE_APPEND) ||
          original->to >= out->node_count)
        return false;
      dep_add_resolved_edge_refs(
          out, max_edges, child, original->to, type, dep_fd_numeric(use->fd),
          dep_fd_numeric(original->target_fd), SHELL_DEP_EDGE_FLAG_NONE);
    }
  }
  return (out->status & SHELL_DEP_STATUS_TRUNCATED) == 0;
}

/* `>(consumer)` used as an ordinary shell word gives the outer program a
 * writable path. The shell syntax does not itself establish a write from a
 * particular outer descriptor, so preserve the nested command graph without
 * inventing a SUBST or WRITE relation. */
static bool dep_append_disconnected_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *subgraph,
    const dep_subgraph_streams_t *subgraph_streams) {
  if (subgraph->node_count > max_nodes - out->node_count ||
      subgraph->edge_count > max_edges - out->edge_count ||
      subgraph->cwd_buf.len > effective_cwd_buf_size - out->cwd_buf.len)
    return false;
  uint32_t node_offset = out->node_count;
  uint32_t cwd_offset_shift = (uint32_t)out->cwd_buf.len;
  dep_append_subgraph(out, subgraph, out_streams, subgraph_streams, node_offset,
                      cwd_offset_shift);
  return dep_materialize_fd_import_uses(out, max_edges, node_offset,
                                        out_streams, subgraph_streams);
}

/* Copy one parsed substitution and wire its actual stream topology into the
 * parent graph. Word and input-process substitutions carry nested output to
 * the parent; output-process substitutions carry the parent's redirected fd
 * to nested stdin. A collector is only needed when one direct SUBST edge
 * would conceal several producers or descriptor routing. If a named-FD
 * process substitution has no exposed nested stream, retain its raw pipe as
 * FD_OPEN setup so a later symbolic duplication can materialize real flow. */
static bool dep_connect_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *subgraph,
    const dep_subgraph_streams_t *subgraph_streams, uint32_t consumer_node,
    dep_subst_kind_t kind, uint32_t producer_fd,
    const dep_fd_ref_t *named_setup_fd) {
  dep_endpoint_list_t endpoints;
  if (kind == DEP_SUBST_PROCESS_OUTPUT)
    dep_collect_substitution_inputs(subgraph, subgraph_streams, &endpoints);
  else
    dep_collect_substitution_outputs(subgraph, subgraph_streams, &endpoints);

  bool needs_collector =
      kind == DEP_SUBST_PROCESS_OUTPUT || endpoints.count > 1;
  bool retain_unconnected =
      endpoints.count == 0 && named_setup_fd != NULL &&
      (kind == DEP_SUBST_PROCESS_INPUT || kind == DEP_SUBST_PROCESS_OUTPUT);
  uint32_t extra_nodes =
      (endpoints.count > 0 && needs_collector) || retain_unconnected ? 1 : 0;
  uint32_t extra_edges = 0;
  if (endpoints.count == 1 && !needs_collector) {
    extra_edges = 1;
  } else if (endpoints.count > 0 && kind == DEP_SUBST_PROCESS_OUTPUT) {
    extra_edges = 1 + endpoints.count; /* producer WRITE plus collector SUBST */
  } else if (endpoints.count > 1) {
    extra_edges = endpoints.count + 1; /* producer WRITEs plus one SUBST */
  } else if (retain_unconnected) {
    extra_edges = 1; /* named FD_OPEN setup for the retained raw pipe */
  }

  if (subgraph->node_count > max_nodes - out->node_count ||
      subgraph->edge_count > max_edges - out->edge_count ||
      extra_nodes > max_nodes - out->node_count - subgraph->node_count ||
      extra_edges > max_edges - out->edge_count - subgraph->edge_count ||
      subgraph->cwd_buf.len > effective_cwd_buf_size - out->cwd_buf.len)
    return false;

  uint32_t node_offset = out->node_count;
  uint32_t cwd_offset_shift = (uint32_t)out->cwd_buf.len;
  dep_append_subgraph(out, subgraph, out_streams, subgraph_streams, node_offset,
                      cwd_offset_shift);
  if (!dep_materialize_fd_import_uses(out, max_edges, node_offset, out_streams,
                                      subgraph_streams))
    return false;
  if (endpoints.count == 0) {
    if (!retain_unconnected)
      return true;
    uint32_t endpoint = out->node_count++;
    out->nodes[endpoint].type = SHELL_NODE_ENDPOINT;
    out->nodes[endpoint].endpoint.reserved =
        DEP_ENDPOINT_UNCONNECTED_PROCESS_SUBSTITUTION;
    if (kind == DEP_SUBST_PROCESS_INPUT) {
      return dep_add_resolved_edge_refs(
          out, max_edges, endpoint, consumer_node, SHELL_EDGE_FD_OPEN,
          dep_fd_numeric(SHELL_DEP_FD_NONE), *named_setup_fd,
          SHELL_DEP_EDGE_FLAG_NONE);
    }
    return dep_add_resolved_edge_refs(out, max_edges, consumer_node, endpoint,
                                      SHELL_EDGE_FD_OPEN, *named_setup_fd,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      SHELL_DEP_EDGE_FLAG_NONE);
  }

  if (!needs_collector) {
    dep_add_subst_edge(out, node_offset + endpoints.nodes[0], consumer_node, 1,
                       kind == DEP_SUBST_PROCESS_INPUT ? producer_fd
                                                       : SHELL_DEP_FD_NONE,
                       kind);
    return true;
  }

  uint32_t collector = out->node_count++;
  out->nodes[collector].type = SHELL_NODE_ENDPOINT;
  out->nodes[collector].endpoint.reserved = 0;
  if (kind == DEP_SUBST_PROCESS_OUTPUT) {
    dep_add_edge(out, consumer_node, collector, SHELL_EDGE_WRITE, producer_fd,
                 SHELL_DEP_FD_NONE);
    for (uint32_t i = 0; i < endpoints.count; i++)
      dep_add_subst_edge(out, collector, node_offset + endpoints.nodes[i],
                         SHELL_DEP_FD_NONE, 0, DEP_SUBST_PROCESS_OUTPUT);
  } else {
    for (uint32_t i = 0; i < endpoints.count; i++)
      dep_add_edge(out, node_offset + endpoints.nodes[i], collector,
                   SHELL_EDGE_WRITE, 1, SHELL_DEP_FD_NONE);
    dep_add_subst_edge(out, collector, consumer_node, SHELL_DEP_FD_NONE,
                       kind == DEP_SUBST_PROCESS_INPUT ? producer_fd
                                                       : SHELL_DEP_FD_NONE,
                       kind);
  }
  return true;
}

/* A process-substitution redirect operand is one contiguous shell word:
 * `>(command)` or `<(command)`. Keep recursive routing in one place so a
 * redirect-only record owned by a completed group has the same semantics as a
 * redirect attached to an ordinary command. Named-descriptor forms retain
 * FD_OPEN setup; a later symbolic duplication is what materializes their real
 * byte route. */
static shell_dep_error_t dep_connect_redirect_process_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const dep_token_t *redirect_token, dep_redirect_t redirect,
    const dep_token_t *target, const char *cwd,
    const shell_dep_limits_t *limits, uint32_t depth,
    const dep_parse_context_t *context, uint32_t consumer_node, bool *handled) {
  *handled = false;
  if (redirect != DEP_REDIRECT_IN && redirect != DEP_REDIRECT_OUT &&
      redirect != DEP_REDIRECT_APPEND && redirect != DEP_REDIRECT_READ_WRITE &&
      redirect != DEP_REDIRECT_BOTH && redirect != DEP_REDIRECT_BOTH_APPEND)
    return SHELL_DEP_OK;

  if (!dep_redirect_target_is_process_substitution(target))
    return SHELL_DEP_OK;

  *handled = true;
  uint32_t sub_len = 0;
  const char *sub_content = extract_subshell_content(target, &sub_len);
  if (!sub_content)
    return SHELL_DEP_EPARSE;
  shell_dep_graph_t subgraph = {0};
  dep_subgraph_streams_t subgraph_streams = {0};
  dep_fd_imports_t fd_imports = {0};
  if (!context)
    return SHELL_DEP_EPARSE;
  shell_dep_error_t snapshot_error =
      dep_snapshot_fd_imports(out, out_streams, context, consumer_node,
                              (uint32_t)(redirect_token->start - context->cmd),
                              DEP_SNAPSHOT_REDIRECT_OPERAND, &fd_imports);
  if (snapshot_error != SHELL_DEP_OK)
    return snapshot_error;
  if (target->start[0] == '<')
    dep_fd_import_restore_inherited(&fd_imports, 1, DEP_FD_ACCESS_WRITE);
  else if (target->start[0] == '>')
    dep_fd_import_restore_inherited(&fd_imports, 0, DEP_FD_ACCESS_READ);
  shell_dep_error_t error = shell_dep_graph_parse_impl(
      sub_content, sub_len, cwd,
      dep_expansion_cwd_known(out, context, consumer_node),
      dep_expansion_cwd_absolute(out, context, consumer_node), limits,
      depth + 1, NULL, &subgraph, &subgraph_streams, &fd_imports);
  if (error == SHELL_DEP_EPARSE || error == SHELL_DEP_EINPUT)
    return SHELL_DEP_EPARSE;
  if (error == SHELL_DEP_ETRUNC)
    out->status |= SHELL_DEP_STATUS_TRUNCATED;
  if (error != SHELL_DEP_OK || subgraph.node_count == 0)
    return SHELL_DEP_OK;

  bool input = dep_process_substitution_is_input(redirect, target);
  bool output = dep_process_substitution_is_output(redirect, target);
  uint32_t redirected_fd = redirect_fd(redirect_token, redirect);
  const char *named_fd_name = NULL;
  uint32_t named_fd_name_len = 0;
  dep_fd_ref_t named_setup_fd = {0};
  const dep_fd_ref_t *named_setup = NULL;
  if ((input || output) && redirected_fd == SHELL_DEP_FD_NAMED) {
    if (!dep_named_fd_name(redirect_token, &named_fd_name, &named_fd_name_len))
      return SHELL_DEP_EPARSE;
    named_setup_fd =
        (dep_fd_ref_t){SHELL_DEP_FD_NAMED, named_fd_name, named_fd_name_len};
    named_setup = &named_setup_fd;
  }
  uint32_t connection_edge_base = out->edge_count;
  bool connected = false;
  if (input) {
    connected = dep_connect_substitution(
        out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
        &subgraph, &subgraph_streams, consumer_node, DEP_SUBST_PROCESS_INPUT,
        redirected_fd, named_setup);
  } else if (output) {
    uint32_t edge_base = out->edge_count;
    bool combined =
        redirect == DEP_REDIRECT_BOTH || redirect == DEP_REDIRECT_BOTH_APPEND;
    /* A combined output redirect needs one extra edge after connecting the
     * process substitution: stderr joins stdout's collector. Reserve it
     * before the nested connection, rather than reporting a complete graph
     * that has silently lost the second descriptor at the capacity boundary. */
    uint32_t connect_max_edges = max_edges;
    if (combined && out->edge_count < max_edges)
      connect_max_edges--;
    if (!combined || out->edge_count < max_edges)
      connected = dep_connect_substitution(
          out, max_nodes, connect_max_edges, effective_cwd_buf_size,
          out_streams, &subgraph, &subgraph_streams, consumer_node,
          DEP_SUBST_PROCESS_OUTPUT, combined ? 1 : redirected_fd, named_setup);
    if (connected && combined &&
        (out->status & SHELL_DEP_STATUS_TRUNCATED) == 0) {
      /* Process-output substitutions always use a collector. Add stderr to
       * the same collector as stdout; the nested consumer still executes once.
       */
      uint32_t collector = UINT32_MAX;
      for (uint32_t i = edge_base; i < out->edge_count; i++) {
        const shell_dep_edge_t *edge = &out->edges[i];
        if (edge->type == SHELL_EDGE_WRITE && edge->from == consumer_node &&
            edge->source_fd == 1 &&
            out->nodes[edge->to].type == SHELL_NODE_ENDPOINT) {
          collector = edge->to;
          break;
        }
      }
      if (collector == UINT32_MAX || out->edge_count >= max_edges) {
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else {
        dep_add_edge(out, consumer_node, collector, SHELL_EDGE_WRITE, 2,
                     SHELL_DEP_FD_NONE);
      }
    }
  } else {
    connected = dep_append_disconnected_substitution(
        out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
        &subgraph, &subgraph_streams);
  }
  if (!connected)
    out->status |= SHELL_DEP_STATUS_TRUNCATED;
  if (connected && named_setup) {
    /* The helper has just appended the direct route or its collector. A named
     * descriptor allocation alone does not transfer bytes, so retain it as
     * FD_OPEN setup rather than a false WRITE/SUBST relation. Mark every
     * endpoint with its distinct source name despite the shared public
     * sentinel. */
    for (uint32_t edge = connection_edge_base; edge < out->edge_count; edge++) {
      shell_dep_edge_t *item = &out->edges[edge];
      if (input && item->type == SHELL_EDGE_SUBST &&
          item->to == consumer_node && item->target_fd == SHELL_DEP_FD_NAMED) {
        item->type = SHELL_EDGE_FD_OPEN;
        dep_set_named_fd(item, false, named_fd_name, named_fd_name_len);
      }
      if (output && item->type == SHELL_EDGE_WRITE &&
          item->from == consumer_node &&
          item->source_fd == SHELL_DEP_FD_NAMED) {
        item->type = SHELL_EDGE_FD_OPEN;
        dep_set_named_fd(item, true, named_fd_name, named_fd_name_len);
      }
    }
  }
  return SHELL_DEP_OK;
}

static shell_dep_error_t dep_connect_word_substitutions_kind(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const dep_token_t *word, const char *cwd, const shell_dep_limits_t *limits,
    uint32_t depth, const dep_parse_context_t *context,
    uint32_t expansion_owner, uint32_t snapshot_position,
    dep_snapshot_phase_t snapshot_phase, uint32_t consumer_node,
    dep_subst_kind_t kind);

/* Bash's $(<word) has no external command at its outer level: it reads the
 * resolved word as a file. A static word is one DOC→SUBST flow; a dynamic
 * word first receives an explicitly tagged filename-selection flow. */
static shell_dep_error_t dep_connect_file_command_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const char *content, uint32_t content_len, const char *cwd,
    const shell_dep_limits_t *limits, uint32_t depth,
    const dep_parse_context_t *context, uint32_t expansion_owner,
    uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
    uint32_t consumer_node, dep_subst_kind_t consumer_kind, bool *handled) {
  *handled = false;
  const char *file_path = NULL;
  uint32_t file_path_len = 0;
  if (!dep_file_command_substitution(content, content_len, &file_path,
                                     &file_path_len))
    return SHELL_DEP_OK;
  *handled = true;

  dep_token_t operand = {file_path, file_path_len};
  if (dep_redirect_target_is_process_substitution(&operand)) {
    uint32_t sub_len = 0;
    const char *sub_content = extract_subshell_content(&operand, &sub_len);
    if (!sub_content)
      return SHELL_DEP_EPARSE;
    shell_dep_graph_t subgraph = {0};
    dep_subgraph_streams_t subgraph_streams = {0};
    dep_fd_imports_t fd_imports = {0};
    if (!context)
      return SHELL_DEP_EPARSE;
    shell_dep_error_t snapshot_error =
        dep_snapshot_fd_imports(out, out_streams, context, expansion_owner,
                                snapshot_position, snapshot_phase, &fd_imports);
    if (snapshot_error != SHELL_DEP_OK)
      return snapshot_error;
    if (operand.start[0] == '<')
      dep_fd_import_restore_inherited(&fd_imports, 1, DEP_FD_ACCESS_WRITE);
    else if (operand.start[0] == '>')
      dep_fd_import_restore_inherited(&fd_imports, 0, DEP_FD_ACCESS_READ);
    shell_dep_error_t error = shell_dep_graph_parse_impl(
        sub_content, sub_len, cwd,
        dep_expansion_cwd_known(out, context, expansion_owner),
        dep_expansion_cwd_absolute(out, context, expansion_owner), limits,
        depth + 1, NULL, &subgraph, &subgraph_streams, &fd_imports);
    if (error == SHELL_DEP_EPARSE || error == SHELL_DEP_EINPUT)
      return SHELL_DEP_EPARSE;
    if (error == SHELL_DEP_ETRUNC)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
    if (error != SHELL_DEP_OK || subgraph.node_count == 0)
      return SHELL_DEP_OK;

    bool connected =
        operand.start[0] == '<'
            ? dep_connect_substitution(out, max_nodes, max_edges,
                                       effective_cwd_buf_size, out_streams,
                                       &subgraph, &subgraph_streams,
                                       consumer_node, consumer_kind, 1, NULL)
            : dep_append_disconnected_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size,
                  out_streams, &subgraph, &subgraph_streams);
    if (!connected)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
    return SHELL_DEP_OK;
  }

  uint32_t document_node = UINT32_MAX;
  if (!add_doc_file(out, max_nodes, max_edges, file_path, file_path_len,
                    consumer_node, SHELL_EDGE_SUBST, SHELL_DIR_FORWARD,
                    DEP_REDIRECT_IN, SHELL_DEP_FD_NONE, &out->status,
                    &document_node))
    return SHELL_DEP_OK;
  out->edges[out->edge_count - 1].flags =
      consumer_kind == DEP_SUBST_SHELL_WORD
          ? SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD
          : (consumer_kind == DEP_SUBST_DYNAMIC_NAME
                 ? SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME
                 : SHELL_DEP_EDGE_FLAG_NONE);

  return dep_connect_word_substitutions_kind(
      out, max_nodes, max_edges, effective_cwd_buf_size, out_streams, &operand,
      cwd, limits, depth, context, expansion_owner, snapshot_position,
      snapshot_phase, document_node, DEP_SUBST_DYNAMIC_NAME);
}

/* Heredoc expansion follows neither shell-word quoting nor normal token
 * boundaries: quotes in an unquoted body are ordinary bytes, while only the
 * documented backslash escapes suppress an expansion marker. */
static bool dep_find_heredoc_substitution(const char *text, uint32_t length,
                                          uint32_t offset,
                                          dep_token_t *subshell,
                                          uint32_t *span) {
  for (uint32_t pos = offset; pos < length; pos++) {
    if (text[pos] == '\\' && pos + 1 < length) {
      char next = text[pos + 1];
      if (next == '$' || next == '`' || next == '\\' || next == '\n' ||
          next == '\r') {
        pos++;
        continue;
      }
    }
    /* Arithmetic expansion is active in an unquoted heredoc, but it is not a
     * command-substitution stream. Keep `$((1 + 2))` from creating a phantom
     * SUBST edge while still exposing any executable substitution nested in
     * its expression. */
    if (text[pos] == '$' &&
        shell_source_dollar_arithmetic_open(text, length, pos, NULL)) {
      size_t after = 0;
      size_t content_start = 0;
      size_t content_length = 0;
      if (!shell_source_arithmetic_content(text, length, pos, &content_start,
                                           &content_length, &after)) {
        *span = 0;
        return true;
      }
      dep_token_t arithmetic = {text + content_start, (uint32_t)content_length};
      dep_token_t nested;
      uint32_t nested_span = 0;
      if (find_subshell_at_or_after(&arithmetic, 0, &nested, &nested_span)) {
        *subshell = nested;
        *span = nested_span;
        return true;
      }
      pos = (uint32_t)after - 1;
      continue;
    }
    if (text[pos] != '`' &&
        (text[pos] != '$' ||
         !shell_source_dollar_parentheses_open(text, length, pos, NULL)))
      continue;
    dep_token_t candidate = {text + pos, length - pos};
    uint32_t candidate_span = 0;
    dep_token_t found;
    if (!find_subshell_at_or_after(&candidate, 0, &found, &candidate_span)) {
      *subshell = candidate;
      *span = 0;
      return true;
    }
    *subshell = found;
    *span = candidate_span;
    return true;
  }
  *span = 0;
  return false;
}

static shell_dep_error_t dep_connect_heredoc_substitutions(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const char *content, uint32_t content_len, const char *cwd,
    const shell_dep_limits_t *limits, uint32_t depth,
    const dep_parse_context_t *context, uint32_t expansion_owner,
    uint32_t snapshot_position, uint32_t document_node) {
  uint32_t offset = 0;
  while (offset < content_len) {
    dep_token_t token;
    uint32_t span = 0;
    if (!dep_find_heredoc_substitution(content, content_len, offset, &token,
                                       &span))
      break;
    if (span == 0)
      return SHELL_DEP_EPARSE;
    uint32_t sub_len = 0;
    const char *sub_content = extract_subshell_content(&token, &sub_len);
    if (!sub_content)
      return SHELL_DEP_EPARSE;
    if (sub_len > 0) {
      bool file_handled = false;
      shell_dep_error_t file_error = SHELL_DEP_OK;
      if (token.start[0] == '$')
        file_error = dep_connect_file_command_substitution(
            out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
            sub_content, sub_len, cwd, limits, depth, context, expansion_owner,
            snapshot_position, DEP_SNAPSHOT_REDIRECT_OPERAND, document_node,
            DEP_SUBST_SHELL_WORD, &file_handled);
      if (file_error != SHELL_DEP_OK)
        return file_error;
      if (!file_handled) {
        shell_dep_graph_t subgraph = {0};
        dep_subgraph_streams_t subgraph_streams = {0};
        dep_fd_imports_t fd_imports = {0};
        if (!context)
          return SHELL_DEP_EPARSE;
        shell_dep_error_t snapshot_error = dep_snapshot_fd_imports(
            out, out_streams, context, expansion_owner, snapshot_position,
            DEP_SNAPSHOT_REDIRECT_OPERAND, &fd_imports);
        if (snapshot_error != SHELL_DEP_OK)
          return snapshot_error;
        dep_fd_import_restore_inherited(&fd_imports, 1, DEP_FD_ACCESS_WRITE);
        shell_dep_error_t error = shell_dep_graph_parse_impl(
            sub_content, sub_len, cwd,
            dep_expansion_cwd_known(out, context, expansion_owner),
            dep_expansion_cwd_absolute(out, context, expansion_owner), limits,
            depth + 1, NULL, &subgraph, &subgraph_streams, &fd_imports);
        if (error == SHELL_DEP_EPARSE || error == SHELL_DEP_EINPUT)
          return SHELL_DEP_EPARSE;
        if (error == SHELL_DEP_ETRUNC)
          out->status |= SHELL_DEP_STATUS_TRUNCATED;
        if (error == SHELL_DEP_OK && subgraph.node_count > 0 &&
            !dep_connect_substitution(
                out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
                &subgraph, &subgraph_streams, document_node,
                DEP_SUBST_SHELL_WORD, 1, NULL))
          out->status |= SHELL_DEP_STATUS_TRUNCATED;
      }
    }
    uint32_t relative = (uint32_t)(token.start - content);
    if (span > content_len - relative)
      return SHELL_DEP_EPARSE;
    offset = relative + span;
  }
  return SHELL_DEP_OK;
}

/* Analyze expansion-bearing words wherever shell syntax can consume them. The
 * caller supplies the semantic consumer: ordinary words and expandable
 * documents feed a shell execution context, while a redirection operand feeds
 * the FILE document whose runtime pathname it selects. */
static shell_dep_error_t dep_connect_word_substitutions_kind(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const dep_token_t *word, const char *cwd, const shell_dep_limits_t *limits,
    uint32_t depth, const dep_parse_context_t *context,
    uint32_t expansion_owner, uint32_t snapshot_position,
    dep_snapshot_phase_t snapshot_phase, uint32_t consumer_node,
    dep_subst_kind_t kind) {
  uint32_t offset = 0;
  dep_token_t subshell;
  uint32_t span = 0;
  while (find_subshell_at_or_after(word, offset, &subshell, &span)) {
    uint32_t sub_len = 0;
    const char *sub_content = extract_subshell_content(&subshell, &sub_len);
    if (!sub_content)
      return SHELL_DEP_EPARSE;
    if (sub_len > 0) {
      bool file_handled = false;
      shell_dep_error_t file_error = SHELL_DEP_OK;
      if (subshell.start[0] == '$')
        file_error = dep_connect_file_command_substitution(
            out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
            sub_content, sub_len, cwd, limits, depth, context, expansion_owner,
            snapshot_position, snapshot_phase, consumer_node, kind,
            &file_handled);
      if (file_error != SHELL_DEP_OK)
        return file_error;
      if (!file_handled) {
        shell_dep_graph_t subgraph = {0};
        dep_subgraph_streams_t subgraph_streams = {0};
        dep_fd_imports_t fd_imports = {0};
        if (!context)
          return SHELL_DEP_EPARSE;
        shell_dep_error_t snapshot_error = dep_snapshot_fd_imports(
            out, out_streams, context, expansion_owner, snapshot_position,
            snapshot_phase, &fd_imports);
        if (snapshot_error != SHELL_DEP_OK)
          return snapshot_error;
        if (subshell.start[0] == '$' || subshell.start[0] == '<')
          dep_fd_import_restore_inherited(&fd_imports, 1, DEP_FD_ACCESS_WRITE);
        else if (subshell.start[0] == '>')
          dep_fd_import_restore_inherited(&fd_imports, 0, DEP_FD_ACCESS_READ);
        shell_dep_error_t error = shell_dep_graph_parse_impl(
            sub_content, sub_len, cwd,
            dep_expansion_cwd_known(out, context, expansion_owner),
            dep_expansion_cwd_absolute(out, context, expansion_owner), limits,
            depth + 1, NULL, &subgraph, &subgraph_streams, &fd_imports);
        if (error == SHELL_DEP_EPARSE || error == SHELL_DEP_EINPUT)
          return SHELL_DEP_EPARSE;
        if (error == SHELL_DEP_ETRUNC)
          out->status |= SHELL_DEP_STATUS_TRUNCATED;
        if (error == SHELL_DEP_OK && subgraph.node_count > 0) {
          /* Process substitution contributes a generated descriptor pathname,
           * not its stream bytes, to a composite filename. Retain its commands
           * without claiming that stdout supplies the FILE document's name. */
          bool disconnected =
              subshell.start[0] == '>' ||
              (subshell.start[0] == '<' && kind == DEP_SUBST_DYNAMIC_NAME);
          bool connected =
              !disconnected ||
              dep_append_disconnected_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size,
                  out_streams, &subgraph, &subgraph_streams);
          if (!disconnected)
            connected = dep_connect_substitution(
                out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
                &subgraph, &subgraph_streams, consumer_node,
                subshell.start[0] == '<' ? DEP_SUBST_PROCESS_WORD : kind, 1,
                NULL);
          if (!connected)
            out->status |= SHELL_DEP_STATUS_TRUNCATED;
        }
      }
    }
    uint32_t relative = (uint32_t)(subshell.start - word->start);
    if (span == 0 || relative > word->len - span)
      return SHELL_DEP_EPARSE;
    offset = relative + span;
  }
  return SHELL_DEP_OK;
}

static shell_dep_error_t dep_connect_word_substitutions(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const dep_token_t *word, const char *cwd, const shell_dep_limits_t *limits,
    uint32_t depth, const dep_parse_context_t *context,
    uint32_t expansion_owner, uint32_t snapshot_position,
    dep_snapshot_phase_t snapshot_phase, uint32_t consumer_node) {
  return dep_connect_word_substitutions_kind(
      out, max_nodes, max_edges, effective_cwd_buf_size, out_streams, word, cwd,
      limits, depth, context, expansion_owner, snapshot_position,
      snapshot_phase, consumer_node, DEP_SUBST_SHELL_WORD);
}

typedef struct {
  const char *value;
  uint32_t value_len;
  uint32_t target_fd;
  const char *target_fd_name;
  uint32_t target_fd_name_len;
} dep_group_herestring_t;

/* The fast parser deliberately does not emit synthetic ranges for here-strings
 * redirected from a just-closed compound group. Recover every source-local
 * here-string in that trailing redirect list. They must retain source order:
 * a later redirect can replace one descriptor while leaving another live. */
static uint32_t scan_group_herestrings(const char *cmd, uint32_t cmd_len,
                                       const shell_group_t *group,
                                       dep_group_herestring_t *items,
                                       uint32_t capacity, bool *complete) {
  *complete = true;
  if (!cmd || !group || !items || group->end > cmd_len) {
    *complete = false;
    return 0;
  }

  uint32_t end = dep_group_trailing_end(cmd, cmd_len, group->end);
  uint32_t position = group->end;
  uint32_t count = 0;
  while (position < end) {
    position =
        (uint32_t)shell_source_skip_inline_continuations(cmd, end, position);
    if (position == end)
      break;

    size_t operator_after = 0;
    uint32_t fd = 0;
    shell_source_io_number_t io_number =
        shell_source_parse_io_number(cmd, position, end, &operator_after, &fd);
    if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
      break;
    uint32_t operator_pos = (uint32_t)operator_after;
    bool explicit_fd = io_number == SHELL_SOURCE_IO_NUMBER_VALID;
    if (!explicit_fd && shell_source_parse_named_fd_redirect(cmd, position, end,
                                                             &operator_after)) {
      operator_pos = (uint32_t)operator_after;
      fd = SHELL_DEP_FD_NAMED;
      explicit_fd = true;
    }
    size_t here_string_after = 0;
    if (shell_source_match_logical_punctuation(cmd, end, operator_pos, "<<<",
                                               &here_string_after)) {
      uint32_t operand = (uint32_t)shell_source_skip_inline_continuations(
          cmd, end, here_string_after);
      size_t after = operand;
      if (!shell_source_skip_shell_word(cmd, end, operand, &after) ||
          after == operand || after > UINT32_MAX || count == capacity) {
        *complete = false;
        return count;
      }
      const char *fd_name = NULL;
      uint32_t fd_name_len = 0;
      if (fd == SHELL_DEP_FD_NAMED &&
          !inline_document_named_fd_name(cmd, operator_pos, &fd_name,
                                         &fd_name_len)) {
        *complete = false;
        return count;
      }
      items[count++] =
          (dep_group_herestring_t){cmd + operand, (uint32_t)(after - operand),
                                   explicit_fd ? fd : 0, fd_name, fd_name_len};
      position = (uint32_t)after;
      continue;
    }

    size_t after = shell_source_skip_redirect(cmd, position, end);
    if (after == position)
      break;
    position = (uint32_t)after;
  }
  return count;
}

typedef enum {
  DEP_GROUP_EVENT_REDIRECT,
  DEP_GROUP_EVENT_HERESTRING,
  DEP_GROUP_EVENT_HEREDOC,
} dep_group_event_kind_t;

typedef struct {
  uint32_t position;
  uint32_t owner;
  uint32_t document;
  dep_group_event_kind_t kind;
  dep_redirect_t redirect;
  dep_token_t redirect_token;
  dep_token_t target;
  const char *content;
  uint32_t content_len;
} dep_group_redirect_event_t;

static bool dep_group_event_append(dep_group_redirect_event_t *events,
                                   uint32_t *count, uint32_t capacity,
                                   dep_group_redirect_event_t event) {
  if (!events || !count || *count >= capacity)
    return false;
  events[(*count)++] = event;
  return true;
}

static void dep_group_events_sort(dep_group_redirect_event_t *events,
                                  uint32_t count) {
  for (uint32_t i = 1; i < count; i++) {
    dep_group_redirect_event_t item = events[i];
    uint32_t j = i;
    while (j > 0 && events[j - 1].position > item.position) {
      events[j] = events[j - 1];
      j--;
    }
    events[j] = item;
  }
}

/* A fast-parser here-string range can be emitted after some group redirect
 * prefixes, while other spellings are omitted entirely. The group-tail scan
 * is the canonical source for that redirect list, so avoid processing an
 * emitted range a second time. */
static bool
range_starts_in_group_trailing_redirect_list(const shell_parse_result_t *result,
                                             const char *cmd, uint32_t cmd_len,
                                             uint32_t position) {
  if (!result || !cmd)
    return false;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->end > position || group->end > cmd_len)
      continue;
    uint32_t end = dep_group_trailing_end(cmd, cmd_len, group->end);
    if (position < end)
      return true;
  }
  return false;
}

/* Older caller-supplied fast results may separate a descriptor immediately
 * adjacent to a here-string into a synthetic SIMPLE range. Numeric and named
 * descriptors are redirect syntax, never executable argv. */
static bool range_is_herestring_fd_prefix(const char *cmd,
                                          const shell_range_t *range,
                                          const shell_range_t *next) {
  if (!cmd || !range || !next || range->type != SHELL_TYPE_SIMPLE ||
      !(next->type & SHELL_TYPE_HERESTRING) || range->len == 0 ||
      range->start + range->len != next->start)
    return false;
  bool numeric = true;
  for (uint32_t pos = 0; pos < range->len; pos++)
    if (!isdigit((unsigned char)cmd[range->start + pos]))
      numeric = false;
  if (numeric)
    return true;
  size_t after = 0;
  return shell_source_parse_named_fd(cmd, range->start, next->start, &after) &&
         shell_source_skip_escaped_line_endings(cmd, next->start, after) ==
             next->start;
}

/* --- MAIN PARSER --- */

static bool dep_fast_command_type_valid(uint16_t type) {
  switch (type) {
  case SHELL_TYPE_SIMPLE:
  case SHELL_TYPE_PIPELINE:
  case SHELL_TYPE_AND:
  case SHELL_TYPE_OR:
  case SHELL_TYPE_SEMICOLON:
  case SHELL_TYPE_HEREDOC:
  case SHELL_TYPE_HERESTRING:
  case SHELL_TYPE_SUBSTITUTION:
  case SHELL_TYPE_BACKGROUND:
    return true;
  default:
    return false;
  }
}

/* A pipeline range starts after its source delimiter and any legal list
 * continuation trivia. Supplied fast metadata is an internal optimisation
 * boundary, not an authority over source spelling: validate the mode against
 * that delimiter before graph routing consumes it. */
static bool dep_pipeline_mode_from_source(const char *cmd, uint32_t length,
                                          uint32_t start,
                                          shell_pipe_mode_t *mode) {
  if (!cmd || !mode)
    return false;
  start = (uint32_t)shell_source_skip_list_trivia_backward(cmd, length, start);
  if (start == 0)
    return false;

  uint32_t logical_end =
      (uint32_t)shell_source_skip_escaped_line_endings_backward(cmd, length,
                                                                start);
  if (logical_end == 0)
    return false;
  if (cmd[logical_end - 1] == '&') {
    uint32_t before_ampersand =
        (uint32_t)shell_source_skip_escaped_line_endings_backward(
            cmd, length, logical_end - 1);
    if (before_ampersand == 0 || cmd[before_ampersand - 1] != '|')
      return false;
    uint32_t before_pipe =
        (uint32_t)shell_source_skip_escaped_line_endings_backward(
            cmd, length, before_ampersand - 1);
    if (before_pipe > 0 && cmd[before_pipe - 1] == '|')
      return false;
    *mode = SHELL_PIPE_MODE_STDOUT_AND_STDERR;
    return true;
  }
  if (cmd[logical_end - 1] != '|')
    return false;
  uint32_t before_pipe =
      (uint32_t)shell_source_skip_escaped_line_endings_backward(
          cmd, length, logical_end - 1);
  if (before_pipe > 0 && cmd[before_pipe - 1] == '|')
    return false;
  *mode = SHELL_PIPE_MODE_STDOUT;
  return true;
}

static uint32_t dep_pipeline_range_anchor(const shell_parse_result_t *fast,
                                          const bool *group_live,
                                          uint32_t range_index) {
  uint32_t anchor = fast->cmds[range_index].start;
  for (uint32_t i = 0; i < fast->group_count; i++) {
    const shell_group_t *group = &fast->groups[i];
    if (group_live[i] && group->command_count != 0 &&
        group->first_command == range_index && group->start < anchor)
      anchor = group->start;
  }
  return anchor;
}

static bool dep_fast_group_is_ancestor(const shell_parse_result_t *fast,
                                       const bool *group_live,
                                       uint32_t ancestor, uint32_t group) {
  while (group < fast->group_count && group_live[group]) {
    uint16_t parent = fast->groups[group].parent;
    if (parent == UINT16_MAX)
      return false;
    if (parent == ancestor)
      return true;
    group = parent;
  }
  return false;
}

/* `shell_dep_graph_parse_with_fast()` is internal, but its supplied metadata
 * still crosses a module boundary. Validate every count before fixed-size
 * indexing. A parser-produced incomplete group has end == 0; retain the
 * established partial-graph contract for that one recoverable condition by
 * disabling the descriptor and marking the result truncated. All other
 * structural contradictions are unsafe to interpret and fail closed. */
static bool dep_prepare_fast_result(shell_parse_result_t *fast, const char *cmd,
                                    uint32_t command_length) {
  const uint32_t valid_status = SHELL_STATUS_TRUNCATED | SHELL_STATUS_ERROR;
  const uint32_t valid_features =
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_SUBSHELL |
      SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
      SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
      SHELL_FEAT_CASE | SHELL_FEAT_SUBSHELL_FILE | SHELL_FEAT_PIPELINE |
      SHELL_FEAT_GROUP | SHELL_FEAT_BACKGROUND | SHELL_FEAT_EXTGLOB |
      SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_ARRAY | SHELL_FEAT_NAMED_FD |
      SHELL_FEAT_COMBINED_REDIRECT;
  bool group_live[SHELL_MAX_GROUPS] = {false};

  if (!fast || fast->count > SHELL_MAX_SUBCOMMANDS ||
      fast->group_count > SHELL_MAX_GROUPS ||
      (fast->status & ~valid_status) != 0)
    return false;

  uint32_t previous_end = 0;
  for (uint32_t i = 0; i < fast->count; i++) {
    shell_range_t *range = &fast->cmds[i];
    if (range->len == 0 || range->start > command_length ||
        range->len > command_length - range->start ||
        range->start < previous_end ||
        !dep_fast_command_type_valid(range->type) ||
        (range->features & ~valid_features) != 0 ||
        (range->modifiers & ~SHELL_CMD_MOD_PIPE_NEGATED) != 0 ||
        (range->pipeline_negation_count != 0 &&
         (range->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) == 0) ||
        range->pipe_input_mode > SHELL_PIPE_MODE_STDOUT_AND_STDERR ||
        (range->group_kinds & ~(SHELL_GROUP_BRACE | SHELL_GROUP_SUBSHELL)) != 0)
      return false;
    bool accepts_pipe_input = range->type == SHELL_TYPE_PIPELINE ||
                              (range->type & SHELL_TYPE_HEREDOC) != 0 ||
                              (range->type & SHELL_TYPE_HERESTRING) != 0;
    if (!accepts_pipe_input) {
      if (range->pipe_input_mode != SHELL_PIPE_MODE_NONE)
        return false;
    }
    if (range->pipeline_negation_count == 0 &&
        (range->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0)
      range->pipeline_negation_count = 1;
    previous_end = range->start + range->len;
  }

  for (uint32_t i = 0; i < fast->group_count; i++) {
    shell_group_t *group = &fast->groups[i];
    if (group->end == 0) {
      *group = (shell_group_t){.parent = UINT16_MAX};
      fast->status |= SHELL_STATUS_TRUNCATED;
      continue;
    }
    if (group->start >= group->end || group->end > command_length ||
        group->first_command > fast->count ||
        group->command_count > fast->count - group->first_command ||
        (group->kind != SHELL_GROUP_BRACE &&
         group->kind != SHELL_GROUP_SUBSHELL) ||
        (group->modifiers & ~SHELL_CMD_MOD_PIPE_NEGATED) != 0 ||
        (group->pipeline_negation_count != 0 &&
         (group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) == 0) ||
        (group->parent != UINT16_MAX && group->parent >= i))
      return false;
    if (group->pipeline_negation_count == 0 &&
        (group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0)
      group->pipeline_negation_count = 1;
    group_live[i] = true;
  }

  for (uint32_t i = 0; i < fast->group_count; i++) {
    shell_group_t *group = &fast->groups[i];
    if (!group_live[i] || group->parent == UINT16_MAX)
      continue;
    if (!group_live[group->parent]) {
      *group = (shell_group_t){.parent = UINT16_MAX};
      group_live[i] = false;
      fast->status |= SHELL_STATUS_TRUNCATED;
      continue;
    }
    const shell_group_t *parent = &fast->groups[group->parent];
    uint32_t group_last = (uint32_t)group->first_command + group->command_count;
    uint32_t parent_last =
        (uint32_t)parent->first_command + parent->command_count;
    if (group->start < parent->start || group->end > parent->end ||
        group->first_command < parent->first_command ||
        group_last > parent_last)
      return false;
  }

  for (uint32_t i = 0; i < fast->group_count; i++) {
    const shell_group_t *group = &fast->groups[i];
    if (!group_live[i])
      continue;
    uint32_t last = (uint32_t)group->first_command + group->command_count;
    for (uint32_t command = group->first_command; command < last; command++) {
      const shell_range_t *range = &fast->cmds[command];
      if (range->start < group->start || range->len > group->end - range->start)
        return false;
    }
    for (uint32_t other = i + 1; other < fast->group_count; other++) {
      const shell_group_t *candidate = &fast->groups[other];
      if (!group_live[other] || candidate->end <= group->start ||
          group->end <= candidate->start)
        continue;
      bool group_contains_candidate =
          group->start <= candidate->start && candidate->end <= group->end;
      bool candidate_contains_group =
          candidate->start <= group->start && group->end <= candidate->end;
      if (!group_contains_candidate && !candidate_contains_group)
        return false;
      uint32_t ancestor = group_contains_candidate ? i : other;
      uint32_t child = group_contains_candidate ? other : i;
      if (!dep_fast_group_is_ancestor(fast, group_live, ancestor, child))
        return false;
    }
  }

  for (uint32_t i = 0; i < fast->count; i++) {
    shell_range_t *range = &fast->cmds[i];
    if (range->type != SHELL_TYPE_PIPELINE &&
        range->pipe_input_mode == SHELL_PIPE_MODE_NONE)
      continue;
    shell_pipe_mode_t source_mode;
    uint32_t anchor = dep_pipeline_range_anchor(fast, group_live, i);
    if (i == 0 || !dep_pipeline_mode_from_source(cmd, command_length, anchor,
                                                 &source_mode))
      return false;
    /* Normal pipelines historically left this zero-initialised in some
     * manually supplied results. Preserve that compatibility, but never
     * infer the distinct `|&` behaviour. */
    if (range->pipe_input_mode == SHELL_PIPE_MODE_NONE &&
        source_mode == SHELL_PIPE_MODE_STDOUT)
      range->pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
    if (range->pipe_input_mode != source_mode)
      return false;
  }
  return true;
}

/* Redirect-only simple commands are real shell execution operations even
 * though they have no argv. Retain a zero-token CMD node so file and dynamic
 * descriptor edges have an honest owner rather than being assigned to the
 * preceding command. */
static uint32_t dep_add_empty_command(shell_dep_graph_t *out,
                                      uint32_t max_nodes, uint32_t *node_range,
                                      uint32_t range_index,
                                      const shell_range_t *range,
                                      uint32_t cwd_offset, bool cwd_known,
                                      bool cwd_absolute, bool backgrounded) {
  if (out->node_count >= max_nodes) {
    out->status |= SHELL_DEP_STATUS_TRUNCATED;
    return UINT32_MAX;
  }
  uint32_t node_index = out->node_count++;
  shell_dep_node_t *node = &out->nodes[node_index];
  memset(node, 0, sizeof(*node));
  node_range[node_index] = range_index;
  node->type = SHELL_NODE_CMD;
  node->cmd.cwd_offset = cwd_offset;
  node->cmd.group_depth = range->group_depth;
  node->cmd.group_kinds = range->group_kinds;
  node->cmd.backgrounded = backgrounded;
  node->cmd.pipeline_negation_count = range->pipeline_negation_count;
  node->cmd.pipeline_negated =
      (node->cmd.pipeline_negation_count & UINT32_C(1)) != 0;
  node->cmd.cwd_known = cwd_known && range->type != SHELL_TYPE_AND &&
                        range->type != SHELL_TYPE_OR;
  node->cmd.cwd_absolute = node->cmd.cwd_known && cwd_absolute;
  return node_index;
}

/* Inline documents are structural stages.  Their range type records the
 * document itself, so recover a preceding list connector from source instead
 * of silently treating every non-pipeline document as a sequence. */
static shell_dep_edge_type_t
dep_document_predecessor_type(const char *cmd, uint32_t command_length,
                              const shell_range_t *range) {
  if (range->pipe_input_mode != SHELL_PIPE_MODE_NONE)
    return SHELL_EDGE_PIPE;
  uint32_t start = (uint32_t)shell_source_skip_list_trivia_backward(
      cmd, command_length, range->start);
  uint32_t logical_end =
      (uint32_t)shell_source_skip_escaped_line_endings_backward(
          cmd, command_length, start);
  if (logical_end == 0)
    return SHELL_EDGE_SEQ;
  if (cmd[logical_end - 1] == '&') {
    uint32_t before = (uint32_t)shell_source_skip_escaped_line_endings_backward(
        cmd, command_length, logical_end - 1);
    if (before > 0 && cmd[before - 1] == '&')
      return SHELL_EDGE_AND;
    return SHELL_EDGE_BACKGROUND;
  }
  if (cmd[logical_end - 1] == '|') {
    uint32_t before = (uint32_t)shell_source_skip_escaped_line_endings_backward(
        cmd, command_length, logical_end - 1);
    if (before > 0 && cmd[before - 1] == '|')
      return SHELL_EDGE_OR;
  }
  return SHELL_EDGE_SEQ;
}

static shell_dep_error_t shell_dep_graph_parse_impl(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    bool initial_cwd_known, bool initial_cwd_absolute,
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams, const dep_fd_imports_t *imports) {
  dep_subgraph_streams_t ignored_streams = {0};
  dep_fd_imports_t initial_imports = imports ? *imports : (dep_fd_imports_t){0};
  if (!streams)
    streams = &ignored_streams;
  memset(streams, 0, sizeof(*streams));
  streams->fd_imports = initial_imports;
  if (!cmd || !out || cmd_len == 0) {
    if (out) {
      out->node_count = 0;
      out->edge_count = 0;
      out->status = SHELL_DEP_STATUS_ERROR;
      out->cwd_buf.len = 0;
    }
    return SHELL_DEP_EINPUT;
  }

  /* The graph borrows token spans from cmd throughout route resolution. Do not
   * clear `out` first: an aliased output or workspace must be rejected without
   * corrupting storage the caller still owns. */
  if (dep_memory_spans_overlap(cmd, cmd_len, out, sizeof(*out)))
    return SHELL_DEP_EINPUT;

  /* `initial_cwd` is a borrowed C string just like command bytes are a
   * borrowed span. Measure it before clearing graph storage so an input that
   * aliases either writable destination can be rejected atomically. */
  const char *init_cwd = initial_cwd ? initial_cwd : ".";
  size_t init_cwd_length = strlen(init_cwd);
  if (init_cwd_length == SIZE_MAX)
    return SHELL_DEP_EINPUT;

  /* The internal fast result is borrowed only at entry.  Snapshot it before
   * any error path clears `out`: callers may legitimately reuse overlapping
   * backing storage for this short-lived input and the graph result. */
  shell_parse_result_t fast_result;
  bool has_provided_fast = provided_fast != NULL;
  if (has_provided_fast)
    fast_result = *provided_fast;

  /* All graph offsets and traversal indices are 32-bit.  Reject an
   * unrepresentable length before the whitespace scan below can narrow it. */
  if (cmd_len > UINT32_MAX) {
    out->node_count = 0;
    out->edge_count = 0;
    out->status = SHELL_DEP_STATUS_ERROR;
    out->cwd_buf.len = 0;
    return SHELL_DEP_EINPUT;
  }

  if (depth > 16) {
    out->node_count = 0;
    out->edge_count = 0;
    out->status = SHELL_DEP_STATUS_ERROR;
    out->cwd_buf.len = 0;
    return SHELL_DEP_EPARSE;
  }

  /* Caller-owned limits may reside in scratch or even graph storage. Keep
   * every recursive parse on a stable snapshot before either is written. */
  shell_dep_limits_t local_limits = limits ? *limits : SHELL_DEP_LIMITS_DEFAULT;
  limits = &local_limits;

  if (dep_memory_spans_overlap(cmd, cmd_len, limits->workspace,
                               limits->workspace_size) ||
      dep_memory_spans_overlap(out, sizeof(*out), limits->workspace,
                               limits->workspace_size) ||
      dep_memory_spans_overlap(init_cwd, init_cwd_length + 1, out,
                               sizeof(*out)) ||
      dep_memory_spans_overlap(init_cwd, init_cwd_length + 1, limits->workspace,
                               limits->workspace_size))
    return SHELL_DEP_EINPUT;

  uint32_t max_nodes = limits->max_nodes;
  if (max_nodes > SHELL_DEP_MAX_NODES)
    max_nodes = SHELL_DEP_MAX_NODES;
  uint32_t max_edges = limits->max_edges;
  if (max_edges > SHELL_DEP_MAX_EDGES)
    max_edges = SHELL_DEP_MAX_EDGES;
  uint32_t max_tokens = limits->max_tokens_per_cmd;
  if (max_tokens > SHELL_DEP_MAX_TOKENS)
    max_tokens = SHELL_DEP_MAX_TOKENS;
  uint32_t effective_cwd_buf_size =
      limits->cwd_buf_size > 0 ? limits->cwd_buf_size : SHELL_DEP_CWD_BUF_SIZE;
  if (effective_cwd_buf_size > SHELL_DEP_CWD_BUF_SIZE)
    effective_cwd_buf_size = SHELL_DEP_CWD_BUF_SIZE;

  /* A CWD entry always needs at least one byte for its NUL terminator and one
   * byte for the root representation.  Do not let the later subtraction
   * underflow for an explicitly undersized caller bound. */
  if (effective_cwd_buf_size < 2) {
    out->node_count = 0;
    out->edge_count = 0;
    out->status = SHELL_DEP_STATUS_ERROR;
    out->cwd_buf.len = 0;
    return SHELL_DEP_EINPUT;
  }

  out->node_count = 0;
  out->edge_count = 0;
  out->status = 0;
  out->cwd_buf.len = 0;

  shell_error_t fast_err;
  if (has_provided_fast) {
    fast_err = (fast_result.status & SHELL_STATUS_ERROR)       ? SHELL_EPARSE
               : (fast_result.status & SHELL_STATUS_TRUNCATED) ? SHELL_ETRUNC
                                                               : SHELL_OK;
  } else {
    /* The public graph API promises a complete structural model, never a
     * graph for a permissively parsed prefix.  Internal callers may provide
     * already-validated fast metadata explicitly when that distinction is
     * required. */
    const shell_limits_t strict_fast_limits = {
        .max_subcommands = SHELL_MAX_SUBCOMMANDS,
        .strict_mode = true,
    };
    fast_err =
        shell_parse_fast(cmd, cmd_len, &strict_fast_limits, &fast_result);
  }
  if (!dep_prepare_fast_result(&fast_result, cmd, (uint32_t)cmd_len)) {
    out->node_count = 0;
    out->edge_count = 0;
    out->status = SHELL_DEP_STATUS_ERROR;
    out->cwd_buf.len = 0;
    return SHELL_DEP_EPARSE;
  }
  bool whitespace_only = true;
  for (uint32_t i = 0; i < cmd_len; i++) {
    if (!isspace((unsigned char)cmd[i])) {
      whitespace_only = false;
      break;
    }
  }
  if (whitespace_only) {
    out->status = 0;
    return SHELL_DEP_OK;
  }
  if (fast_err == SHELL_EPARSE && fast_result.count == 0) {
    out->status = SHELL_DEP_STATUS_ERROR;
    return SHELL_DEP_EPARSE;
  }
  if (fast_err == SHELL_EPARSE) {
    out->status = SHELL_DEP_STATUS_ERROR;
    return SHELL_DEP_EPARSE;
  }
  if (shell_tokenizer_has_unsupported_semantics(cmd, cmd_len)) {
    out->status = SHELL_DEP_STATUS_ERROR;
    return SHELL_DEP_EPARSE;
  }
  out->status = fast_result.status;

  if (fast_result.count == 0)
    return SHELL_DEP_OK;

  bool skip_buf[SHELL_MAX_SUBCOMMANDS];
  heredoc_info_t heredocs[SHELL_DEP_MAX_HEREDOCS];
  uint32_t hcount = prescan_heredocs(cmd, cmd_len, &fast_result, heredocs,
                                     SHELL_DEP_MAX_HEREDOCS, skip_buf);
  uint32_t heredoc_count = 0;
  for (uint32_t i = 0; i < fast_result.count; i++)
    if (fast_result.cmds[i].type & SHELL_TYPE_HEREDOC)
      heredoc_count++;
  if (heredoc_count > SHELL_DEP_MAX_HEREDOCS)
    out->status |= SHELL_DEP_STATUS_TRUNCATED;

  /* Initialize CWD buffer - copy initial_cwd as first entry */
  memset(&out->cwd_buf, 0, sizeof(out->cwd_buf));
  size_t init_len = init_cwd_length;
  if (init_len >= effective_cwd_buf_size) {
    init_len = effective_cwd_buf_size - 1;
    out->status |= SHELL_DEP_STATUS_TRUNCATED;
  }
  memcpy(out->cwd_buf.data, init_cwd, init_len);
  out->cwd_buf.data[init_len] = '\0';
  if (strcmp(init_cwd, ".") != 0) {
    dep_normalize_path(out->cwd_buf.data, init_len, true);
  }
  init_len = strlen(out->cwd_buf.data);
  out->cwd_buf.len = init_len + 1;
  uint32_t cwd_offset = 0;
  bool cwd_known = initial_cwd_known;
  bool cwd_absolute = initial_cwd_absolute;

  int32_t last_cmd_idx = -1;
  uint32_t node_range[SHELL_DEP_MAX_NODES];
  for (uint32_t i = 0; i < SHELL_DEP_MAX_NODES; i++)
    node_range[i] = UINT32_MAX;
  uint32_t group_node[SHELL_MAX_GROUPS];
  for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++)
    group_node[i] = UINT32_MAX;
  for (uint32_t i = 0; i < fast_result.group_count; i++) {
    const shell_group_t *group = &fast_result.groups[i];
    if (group->end <= group->start || group->end > cmd_len) {
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
      continue;
    }
    if (out->node_count >= max_nodes) {
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
      break;
    }
    uint32_t node_index = out->node_count++;
    group_node[i] = node_index;
    shell_dep_node_t *node = &out->nodes[node_index];
    node->type = SHELL_NODE_GROUP;
    node->group.start = cmd + group->start;
    node->group.length = group->end - group->start;
    node->group.kind = group->kind;
    node->group.pipeline_negation_count = group_pipeline_negation_count(group);
    node->group.pipeline_negated = group_is_pipeline_negated(group);
    node->group.parent =
        group->parent == UINT16_MAX || group_node[group->parent] == UINT32_MAX
            ? UINT32_MAX
            : group_node[group->parent];
    if (node->group.parent != UINT32_MAX) {
      if (out->edge_count >= max_edges) {
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
        /* A retained parent index promises a containment edge. If the edge
         * limit prevents recording it, detach this partial node rather than
         * exposing a graph which fails its own structural validation. */
        node->group.parent = UINT32_MAX;
      } else {
        dep_init_edge(&out->edges[out->edge_count++], node->group.parent,
                      node_index, SHELL_EDGE_GROUP, SHELL_DIR_FORWARD,
                      SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
      }
    }
  }

  dep_group_exec_t group_exec[SHELL_MAX_GROUPS] = {0};
  dep_prepare_group_execution(cmd, (uint32_t)cmd_len, &fast_result, group_exec);
  dep_route_workspace_t *route_workspace = NULL;
  if (limits->workspace &&
      limits->workspace_size >= sizeof(dep_route_workspace_t) &&
      (uintptr_t)limits->workspace % _Alignof(dep_route_workspace_t) == 0)
    route_workspace = limits->workspace;
  bool group_entered[SHELL_MAX_GROUPS] = {false};
  const dep_parse_context_t parse_context = {
      cmd,        (uint32_t)cmd_len, &fast_result,  node_range,
      group_node, group_exec,        group_entered, route_workspace,
  };

  /* A compound command's trailing redirects are installed before its body
   * runs, although their source spelling follows the closing delimiter.
   * Materialize the complete redirect table first, then evaluate executable
   * operands in source order. Nested command/process substitutions in the
   * body consequently see the same descriptor state Bash installs before
   * entering the group. */
  bool prebuilt_group_tail[SHELL_MAX_SUBCOMMANDS] = {false};
  dep_group_redirect_event_t group_events[SHELL_DEP_MAX_EDGES];
  uint32_t group_event_count = 0;
  for (uint32_t si = 0; si < fast_result.count; si++) {
    const shell_range_t *range = &fast_result.cmds[si];
    if ((range->type & (SHELL_TYPE_HEREDOC | SHELL_TYPE_HERESTRING)) != 0)
      continue;

    dep_token_list_t tokens = {0};
    if (scan_tokens(cmd, range->start, range->len, &tokens) ||
        tokens.malformed || tokens.count == 0)
      continue;

    bool redirect_only = true;
    for (uint32_t token = 0; token < tokens.count;) {
      dep_redirect_t redirect = classify_redirect(&tokens.tokens[token]);
      if (redirect == DEP_REDIRECT_NONE) {
        redirect_only = false;
        break;
      }
      token += shell_source_redirection_consumes_word(
                   tokens.tokens[token].start, tokens.tokens[token].len)
                   ? 2
                   : 1;
    }
    if (!redirect_only)
      continue;

    int32_t group = find_preceding_group(&fast_result, cmd, range->start);
    if (group < 0)
      group = find_trailing_redirect_group(&fast_result, cmd, range->start);
    if (group < 0 || group_node[group] == UINT32_MAX)
      continue;

    prebuilt_group_tail[si] = true;
    for (uint32_t token = 0; token < tokens.count;) {
      const dep_token_t *operator_token = &tokens.tokens[token];
      dep_redirect_t redirect = classify_redirect(operator_token);
      if (redirect == DEP_REDIRECT_NONE) {
        token++;
        continue;
      }
      bool consumes_word = shell_source_redirection_consumes_word(
          operator_token->start, operator_token->len);
      if (redirect == DEP_REDIRECT_DUP && consumes_word &&
          token + 1 < tokens.count &&
          dep_redirect_is_legacy_combined_output(operator_token,
                                                 &tokens.tokens[token + 1]))
        redirect = DEP_REDIRECT_BOTH;
      if (redirect == DEP_REDIRECT_DUP) {
        token += consumes_word && token + 1 < tokens.count ? 2 : 1;
        continue;
      }
      if (!consumes_word || token + 1 >= tokens.count) {
        token++;
        continue;
      }

      const dep_token_t *target = &tokens.tokens[token + 1];
      bool direct_process = dep_redirect_target_is_process_substitution(target);
      uint32_t document = UINT32_MAX;
      bool added = true;
      if (!direct_process) {
        uint32_t fd = redirect_fd(operator_token, redirect);
        if (fd == SHELL_DEP_FD_NAMED) {
          const char *fd_name = NULL;
          uint32_t fd_name_len = 0;
          if (!dep_named_fd_name(operator_token, &fd_name, &fd_name_len)) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }
          added = add_doc_file_named_fd_open(
              out, max_nodes, max_edges, target->start, target->len,
              group_node[group], redirect, fd_name, fd_name_len, &out->status,
              &document);
        } else if (redirect == DEP_REDIRECT_READ_WRITE) {
          added = add_doc_file_read_write(
              out, max_nodes, max_edges, target->start, target->len,
              group_node[group], fd, &out->status, &document);
        } else if (redirect == DEP_REDIRECT_BOTH ||
                   redirect == DEP_REDIRECT_BOTH_APPEND) {
          added = add_doc_file_both_output(
              out, max_nodes, max_edges, target->start, target->len,
              group_node[group],
              redirect == DEP_REDIRECT_BOTH_APPEND ? SHELL_EDGE_APPEND
                                                   : SHELL_EDGE_WRITE,
              &out->status, &document);
        } else {
          shell_dep_edge_type_t type =
              redirect == DEP_REDIRECT_IN
                  ? SHELL_EDGE_READ
                  : (redirect == DEP_REDIRECT_APPEND ? SHELL_EDGE_APPEND
                                                     : SHELL_EDGE_WRITE);
          added = add_doc_file(out, max_nodes, max_edges, target->start,
                               target->len, group_node[group], type,
                               SHELL_DIR_FORWARD, redirect, fd, &out->status,
                               &document);
        }
      }
      if (!added) {
        if (out->status & SHELL_DEP_STATUS_TRUNCATED)
          return SHELL_DEP_ETRUNC;
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
      if ((direct_process || shell_source_word_has_executable_substitution(
                                 target->start, target->len)) &&
          !dep_group_event_append(
              group_events, &group_event_count,
              (uint32_t)(sizeof(group_events) / sizeof(group_events[0])),
              (dep_group_redirect_event_t){
                  (uint32_t)(operator_token->start - cmd), group_node[group],
                  document, DEP_GROUP_EVENT_REDIRECT, redirect, *operator_token,
                  *target, NULL, 0}))
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
      token += 2;
    }
  }

  /* Here-strings and here-documents in a compound redirect list are also
   * installed before its body. Add all their document edges before expanding
   * any operand so each expansion can replay earlier operations by source
   * position, regardless of which fast-parser range carried the marker. */
  for (uint32_t group = 0; group < fast_result.group_count; group++) {
    if (group_node[group] == UINT32_MAX)
      continue;
    dep_group_herestring_t items[SHELL_DEP_MAX_EDGES];
    bool complete = true;
    uint32_t count = scan_group_herestrings(
        cmd, (uint32_t)cmd_len, &fast_result.groups[group], items,
        sizeof(items) / sizeof(items[0]), &complete);
    if (!complete)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
    for (uint32_t index = 0; index < count; index++) {
      const dep_group_herestring_t *item = &items[index];
      uint32_t document = UINT32_MAX;
      if (!add_document_read(out, max_nodes, max_edges, group_node[group],
                             SHELL_DOC_HERESTRING, NULL, 0, item->value,
                             item->value_len, item->target_fd,
                             SHELL_DEP_DOC_FLAG_NONE, &out->status,
                             &document)) {
        if (out->status & SHELL_DEP_STATUS_TRUNCATED)
          return SHELL_DEP_ETRUNC;
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
      if (item->target_fd == SHELL_DEP_FD_NAMED)
        dep_set_named_fd(&out->edges[out->edge_count - 1], false,
                         item->target_fd_name, item->target_fd_name_len);
      if (!dep_group_event_append(
              group_events, &group_event_count,
              (uint32_t)(sizeof(group_events) / sizeof(group_events[0])),
              (dep_group_redirect_event_t){(uint32_t)(item->value - cmd),
                                           group_node[group],
                                           document,
                                           DEP_GROUP_EVENT_HERESTRING,
                                           DEP_REDIRECT_NONE,
                                           {0},
                                           {item->value, item->value_len},
                                           item->value,
                                           item->value_len}))
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
    }
  }

  for (uint32_t h = 0; h < hcount; h++) {
    heredoc_info_t *hd = &heredocs[h];
    if (!hd->has_source_span || hd->marker_idx >= fast_result.count)
      continue;
    const shell_range_t *marker = &fast_result.cmds[hd->marker_idx];
    int32_t group = find_preceding_group(&fast_result, cmd, marker->start);
    if (group < 0)
      group = find_trailing_redirect_group(&fast_result, cmd, marker->start);
    if (group < 0 || group_node[group] == UINT32_MAX)
      continue;
    uint32_t content_length = hd->content_end_pos - hd->content_start_pos;
    const char *content = content_length ? cmd + hd->content_start_pos : NULL;
    if (content_length && content[content_length - 1] == '\n')
      content_length--;
    uint32_t document = UINT32_MAX;
    uint32_t marker_start = marker->start;
    uint32_t target_fd = inline_document_target_fd(cmd, marker_start);
    uint8_t flags = hd->pending.strip_tabs
                        ? SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS
                        : SHELL_DEP_DOC_FLAG_NONE;
    if (hd->literal)
      flags |= SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL;
    if (!add_document_read(out, max_nodes, max_edges, group_node[group],
                           SHELL_DOC_HEREDOC, hd->delimiter, hd->delimiter_len,
                           content, content_length, target_fd, flags,
                           &out->status, &document)) {
      if (out->status & SHELL_DEP_STATUS_TRUNCATED)
        return SHELL_DEP_ETRUNC;
      out->node_count = 0;
      out->edge_count = 0;
      out->status = SHELL_DEP_STATUS_ERROR;
      out->cwd_buf.len = 0;
      return SHELL_DEP_EPARSE;
    }
    if (target_fd == SHELL_DEP_FD_NAMED) {
      const char *fd_name = NULL;
      uint32_t fd_name_len = 0;
      if (!inline_document_named_fd_name(cmd, marker_start, &fd_name,
                                         &fd_name_len)) {
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
      dep_set_named_fd(&out->edges[out->edge_count - 1], false, fd_name,
                       fd_name_len);
    }
    hd->group_idx = group;
    hd->document_built = true;
    if (!hd->literal && content_length != 0 &&
        !dep_group_event_append(
            group_events, &group_event_count,
            (uint32_t)(sizeof(group_events) / sizeof(group_events[0])),
            (dep_group_redirect_event_t){marker_start,
                                         group_node[group],
                                         document,
                                         DEP_GROUP_EVENT_HEREDOC,
                                         DEP_REDIRECT_NONE,
                                         {0},
                                         {0},
                                         content,
                                         content_length}))
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
  }

  dep_group_events_sort(group_events, group_event_count);
  /* Redirect documents were installed above, but their operands execute at
   * group entry, after preceding commands and before the first body command.
   * A final iteration enters even a valid zero-range group. */
  for (uint32_t si = 0; si <= fast_result.count; si++) {
    uint32_t boundary =
        si < fast_result.count ? fast_result.cmds[si].start : (uint32_t)cmd_len;
    for (uint32_t group = 0; group < fast_result.group_count; group++) {
      if (group_entered[group] || group_node[group] == UINT32_MAX ||
          fast_result.groups[group].start > boundary)
        continue;

      int32_t isolated = (int32_t)group;
      while (isolated >= 0 && !group_exec[isolated].isolated) {
        uint16_t parent = fast_result.groups[isolated].parent;
        isolated = parent == UINT16_MAX ? -1 : (int32_t)parent;
      }
      uint32_t *event_cwd_offset = &cwd_offset;
      bool *event_cwd_known = &cwd_known;
      bool *event_cwd_absolute = &cwd_absolute;
      if (isolated >= 0) {
        dep_initialize_group_cwd(&fast_result, group_exec, (uint32_t)isolated,
                                 cwd_offset, cwd_known, cwd_absolute);
        event_cwd_offset = &group_exec[isolated].cwd_offset;
        event_cwd_known = &group_exec[isolated].cwd_known;
        event_cwd_absolute = &group_exec[isolated].cwd_absolute;
      }
      shell_dep_edge_type_t predecessor =
          dep_snapshot_group_predecessor_type(&parse_context, group);
      if (predecessor == SHELL_EDGE_AND || predecessor == SHELL_EDGE_OR)
        *event_cwd_known = false;
      group_exec[group].cwd_offset = *event_cwd_offset;
      group_exec[group].cwd_known = *event_cwd_known;
      group_exec[group].cwd_absolute = *event_cwd_absolute;
      group_entered[group] = true;

      /* Trailing group redirects were prebuilt before the group's execution
       * CWD was known. Capture the operand context now, before nested body
       * substitutions or descriptor-route rewrites can change edge owners. */
      for (uint32_t edge_index = 0; edge_index < out->edge_count;
           edge_index++) {
        const shell_dep_edge_t *edge = &out->edges[edge_index];
        uint32_t document = UINT32_MAX;
        if (edge->from == group_node[group])
          document = edge->to;
        else if (edge->to == group_node[group])
          document = edge->from;
        if (document != UINT32_MAX)
          dep_file_doc_set_cwd(out, document, *event_cwd_offset,
                               *event_cwd_known, *event_cwd_absolute);
      }

      const char *event_cwd = out->cwd_buf.data + *event_cwd_offset;
      for (uint32_t event_index = 0; event_index < group_event_count;
           event_index++) {
        const dep_group_redirect_event_t *event = &group_events[event_index];
        if (event->owner != group_node[group])
          continue;
        shell_dep_error_t event_error = SHELL_DEP_OK;
        if (event->kind == DEP_GROUP_EVENT_REDIRECT) {
          bool handled = false;
          event_error = dep_connect_redirect_process_substitution(
              out, max_nodes, max_edges, effective_cwd_buf_size, streams,
              &event->redirect_token, event->redirect, &event->target,
              event_cwd, limits, depth, &parse_context, event->owner, &handled);
          if (event_error == SHELL_DEP_OK && !handled &&
              event->document != UINT32_MAX)
            event_error = dep_connect_word_substitutions_kind(
                out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                &event->target, event_cwd, limits, depth, &parse_context,
                event->owner, (uint32_t)(event->redirect_token.start - cmd),
                DEP_SNAPSHOT_REDIRECT_OPERAND, event->document,
                DEP_SUBST_DYNAMIC_NAME);
        } else if (event->kind == DEP_GROUP_EVENT_HERESTRING) {
          event_error = dep_connect_word_substitutions(
              out, max_nodes, max_edges, effective_cwd_buf_size, streams,
              &event->target, event_cwd, limits, depth, &parse_context,
              event->owner, event->position, DEP_SNAPSHOT_REDIRECT_OPERAND,
              event->document);
        } else {
          event_error = dep_connect_heredoc_substitutions(
              out, max_nodes, max_edges, effective_cwd_buf_size, streams,
              event->content, event->content_len, event_cwd, limits, depth,
              &parse_context, event->owner, event->position, event->document);
        }
        if (event_error != SHELL_DEP_OK) {
          out->node_count = 0;
          out->edge_count = 0;
          out->status = SHELL_DEP_STATUS_ERROR;
          out->cwd_buf.len = 0;
          return event_error;
        }
      }
    }
    if (si == fast_result.count)
      break;
    if (skip_buf[si]) {
      if (fast_result.cmds[si].type & SHELL_TYPE_HEREDOC) {
        for (uint32_t h = 0; h < hcount; h++) {
          if (heredocs[h].marker_idx == si) {
            heredocs[h].cmd_node_idx = last_cmd_idx;
            heredocs[h].group_idx = find_preceding_group(
                &fast_result, cmd, fast_result.cmds[si].start);
            if (heredocs[h].group_idx < 0) {
              uint32_t redirect_start =
                  (uint32_t)shell_source_io_number_start_before(
                      cmd, cmd_len, fast_result.cmds[si].start);
              if (redirect_start != fast_result.cmds[si].start)
                heredocs[h].group_idx =
                    find_preceding_group(&fast_result, cmd, redirect_start);
            }
            if (heredocs[h].group_idx < 0)
              heredocs[h].group_idx = find_trailing_redirect_group(
                  &fast_result, cmd, fast_result.cmds[si].start);
            if (heredocs[h].group_idx < 0)
              heredocs[h].group_idx = find_following_group(
                  &fast_result, cmd,
                  fast_result.cmds[si].start + fast_result.cmds[si].len);
            /* A redirection list may contain several heredoc markers. Only
             * the first is textually adjacent to the closing brace; later
             * markers inherit that brace group's document fan-out. */
            if (heredocs[h].group_idx < 0) {
              for (uint32_t previous = 0; previous < h; previous++) {
                if (heredocs[previous].line_end == heredocs[h].line_end &&
                    heredocs[previous].group_idx >= 0) {
                  heredocs[h].group_idx = heredocs[previous].group_idx;
                  break;
                }
              }
            }

            /* A heredoc marker emitted as its own fast range normally
             * continues the preceding simple command. If a real list boundary
             * intervenes, retain an argv-less command node for that separate
             * redirection operation instead of attaching its document to the
             * prior command or compound group. */
            if (heredocs[h].group_idx < 0) {
              const shell_range_t *marker = &fast_result.cmds[si];
              uint32_t marker_owner = UINT32_MAX;
              if (last_cmd_idx >= 0) {
                uint32_t previous = (uint32_t)last_cmd_idx;
                uint32_t previous_range = node_range[previous];
                if (previous_range != UINT32_MAX) {
                  const shell_range_t *previous_source =
                      &fast_result.cmds[previous_range];
                  uint32_t previous_end =
                      previous_source->start + previous_source->len;
                  if (previous_end <= marker->start &&
                      command_redirect_tail_to_range(cmd, previous_end, marker))
                    marker_owner = previous;
                }
              }
              if (marker_owner == UINT32_MAX) {
                int32_t isolated =
                    dep_range_isolated_group(&fast_result, group_exec, si);
                uint32_t marker_cwd_offset = cwd_offset;
                bool marker_cwd_known = cwd_known;
                bool marker_cwd_absolute = cwd_absolute;
                shell_dep_edge_type_t marker_predecessor =
                    dep_document_predecessor_type(cmd, (uint32_t)cmd_len,
                                                  marker);
                if (marker_predecessor == SHELL_EDGE_AND ||
                    marker_predecessor == SHELL_EDGE_OR)
                  marker_cwd_known = false;
                if (isolated >= 0) {
                  dep_initialize_group_cwd(&fast_result, group_exec,
                                           (uint32_t)isolated, cwd_offset,
                                           cwd_known, cwd_absolute);
                  marker_cwd_offset = group_exec[isolated].cwd_offset;
                  marker_cwd_known = group_exec[isolated].cwd_known;
                  marker_cwd_absolute = group_exec[isolated].cwd_absolute;
                }
                marker_owner = dep_add_empty_command(
                    out, max_nodes, node_range, si, marker, marker_cwd_offset,
                    marker_cwd_known, marker_cwd_absolute,
                    dep_range_is_backgrounded(&fast_result, group_exec, si));
                if (marker_owner != UINT32_MAX) {
                  if (last_cmd_idx >= 0) {
                    if (out->edge_count < max_edges) {
                      uint32_t control_from = (uint32_t)last_cmd_idx;
                      if (marker->pipe_input_mode != SHELL_PIPE_MODE_NONE) {
                        int32_t source_group = find_finished_group(
                            &fast_result, node_range[control_from],
                            marker->start);
                        if (source_group >= 0 &&
                            group_node[source_group] != UINT32_MAX)
                          control_from = group_node[source_group];
                      }
                      shell_dep_edge_t *edge = &out->edges[out->edge_count++];
                      dep_init_edge(edge, control_from, marker_owner,
                                    marker_predecessor, SHELL_DIR_FORWARD,
                                    SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
                      if (edge->type == SHELL_EDGE_PIPE) {
                        edge->source_fd = 1;
                        edge->target_fd = 0;
                        if (marker->pipe_input_mode ==
                            SHELL_PIPE_MODE_STDOUT_AND_STDERR)
                          edge->flags = DEP_EDGE_FLAG_PIPE_STDERR;
                      }
                    } else {
                      out->status |= SHELL_DEP_STATUS_TRUNCATED;
                    }
                  }
                  last_cmd_idx = (int32_t)marker_owner;
                  if (marker_predecessor == SHELL_EDGE_AND ||
                      marker_predecessor == SHELL_EDGE_OR)
                    cwd_known = false;
                }
              }
              heredocs[h].cmd_node_idx =
                  marker_owner == UINT32_MAX ? -1 : (int32_t)marker_owner;
            }
          }
        }
      }
      continue;
    }

    const shell_range_t *range = &fast_result.cmds[si];
    uint32_t rstart = range->start;
    uint32_t rlen = range->len;
    if (prebuilt_group_tail[si])
      continue;
    int32_t isolated_group =
        dep_range_isolated_group(&fast_result, group_exec, si);
    uint32_t *range_cwd_offset = &cwd_offset;
    bool *range_cwd_known = &cwd_known;
    bool *range_cwd_absolute = &cwd_absolute;
    if (isolated_group >= 0) {
      dep_initialize_group_cwd(&fast_result, group_exec,
                               (uint32_t)isolated_group, cwd_offset, cwd_known,
                               cwd_absolute);
      range_cwd_offset = &group_exec[isolated_group].cwd_offset;
      range_cwd_known = &group_exec[isolated_group].cwd_known;
      range_cwd_absolute = &group_exec[isolated_group].cwd_absolute;
    }
    bool range_backgrounded =
        dep_range_is_backgrounded(&fast_result, group_exec, si);

    if ((range->type & SHELL_TYPE_HERESTRING) &&
        range_starts_in_group_trailing_redirect_list(&fast_result, cmd,
                                                     (uint32_t)cmd_len, rstart))
      continue;
    if (si + 1 < fast_result.count &&
        range_is_herestring_fd_prefix(cmd, range, &fast_result.cmds[si + 1]))
      continue;

    if (range->type & SHELL_TYPE_HERESTRING) {
      const char *marker = cmd + rstart;
      uint32_t mlen = rlen;
      uint32_t pos =
          (uint32_t)shell_source_skip_inline_continuations(marker, mlen, 3);

      const char *word = marker + pos;
      uint32_t word_len = mlen - pos;

      uint32_t owner = UINT32_MAX;
      if (last_cmd_idx >= 0) {
        uint32_t previous = (uint32_t)last_cmd_idx;
        uint32_t previous_range = node_range[previous];
        if (previous_range != UINT32_MAX) {
          const shell_range_t *previous_source =
              &fast_result.cmds[previous_range];
          uint32_t previous_end = previous_source->start + previous_source->len;
          if (previous_end <= rstart &&
              command_redirect_tail_to_range(cmd, previous_end, range))
            owner = previous;
        }
      }
      if (owner == UINT32_MAX) {
        shell_dep_edge_type_t predecessor =
            dep_document_predecessor_type(cmd, (uint32_t)cmd_len, range);
        bool document_cwd_known = *range_cwd_known;
        if (predecessor == SHELL_EDGE_AND || predecessor == SHELL_EDGE_OR)
          document_cwd_known = false;
        owner = dep_add_empty_command(out, max_nodes, node_range, si, range,
                                      *range_cwd_offset, document_cwd_known,
                                      *range_cwd_absolute, range_backgrounded);
        if (owner == UINT32_MAX)
          continue;
        if (last_cmd_idx >= 0) {
          if (out->edge_count < max_edges) {
            uint32_t control_from = (uint32_t)last_cmd_idx;
            if (range->pipe_input_mode != SHELL_PIPE_MODE_NONE) {
              int32_t source_group = find_finished_group(
                  &fast_result, node_range[control_from], range->start);
              if (source_group >= 0 && group_node[source_group] != UINT32_MAX)
                control_from = group_node[source_group];
            }
            shell_dep_edge_t *edge = &out->edges[out->edge_count++];
            dep_init_edge(edge, control_from, owner, predecessor,
                          SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE,
                          SHELL_DEP_FD_NONE);
            if (edge->type == SHELL_EDGE_PIPE) {
              edge->source_fd = 1;
              edge->target_fd = 0;
              if (range->pipe_input_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR)
                edge->flags = DEP_EDGE_FLAG_PIPE_STDERR;
            }
          } else {
            out->status |= SHELL_DEP_STATUS_TRUNCATED;
          }
        }
        last_cmd_idx = (int32_t)owner;
        if (predecessor == SHELL_EDGE_AND || predecessor == SHELL_EDGE_OR)
          *range_cwd_known = false;
      }

      uint32_t document = UINT32_MAX;
      if (add_document_read(out, max_nodes, max_edges, owner,
                            SHELL_DOC_HERESTRING, NULL, 0, word, word_len,
                            inline_document_target_fd(cmd, rstart),
                            SHELL_DEP_DOC_FLAG_NONE, &out->status, &document)) {
        if (inline_document_target_fd(cmd, rstart) == SHELL_DEP_FD_NAMED) {
          const char *fd_name = NULL;
          uint32_t fd_name_len = 0;
          if (!inline_document_named_fd_name(cmd, rstart, &fd_name,
                                             &fd_name_len)) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }
          dep_set_named_fd(&out->edges[out->edge_count - 1], false, fd_name,
                           fd_name_len);
        }
        dep_token_t here_word = {word, word_len};
        shell_dep_error_t expansion_error = dep_connect_word_substitutions(
            out, max_nodes, max_edges, effective_cwd_buf_size, streams,
            &here_word, out->cwd_buf.data + *range_cwd_offset, limits, depth,
            &parse_context, owner, rstart, DEP_SNAPSHOT_REDIRECT_OPERAND,
            document);
        if (expansion_error == SHELL_DEP_EPARSE) {
          out->node_count = 0;
          out->edge_count = 0;
          out->status = SHELL_DEP_STATUS_ERROR;
          out->cwd_buf.len = 0;
          return SHELL_DEP_EPARSE;
        }
      }
      continue;
    }

    /* The fast parser may end this range at the backslash of an escaped
     * physical line ending, with the following redirect range beginning after
     * LF/CRLF. That backslash is grammar, not a trailing argv word. */
    uint32_t token_length = rlen;
    uint32_t range_end = rstart + rlen;
    if (token_length != 0 && range_end < cmd_len &&
        cmd[range_end - 1] == '\\' &&
        (cmd[range_end] == '\n' || cmd[range_end] == '\r'))
      token_length--;

    dep_token_list_t tokens;
    if (scan_tokens(cmd, rstart, token_length, &tokens))
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
    if (tokens.malformed) {
      out->node_count = 0;
      out->edge_count = 0;
      out->status = SHELL_DEP_STATUS_ERROR;
      out->cwd_buf.len = 0;
      return SHELL_DEP_EPARSE;
    }

    if (tokens.count == 0)
      continue;

    uint32_t command = dep_first_command_index(&tokens);
    uint32_t effective_command = command;
    bool dynamic_command = false;
    shell_dep_command_wrapper_t effective_wrapper = SHELL_DEP_COMMAND_DIRECT;
    const dep_token_t *effective_builtin =
        command == UINT32_MAX
            ? NULL
            : dep_effective_static_builtin(&tokens, command, &effective_command,
                                           &dynamic_command, NULL,
                                           &effective_wrapper);
    bool is_cd =
        effective_builtin && dep_token_static_equals(effective_builtin, "cd");

    /* An enclosing isolated group owns its own mutable CWD state. Only a
     * simple command that itself runs asynchronously or as a pipeline element
     * suppresses a visible current-shell transition. */
    bool cwd_isolated = (range->features & SHELL_FEAT_BACKGROUND) != 0;
    bool next_conditional = false;
    if (si + 1 < fast_result.count) {
      uint16_t next_type = fast_result.cmds[si + 1].type;
      next_conditional =
          next_type == SHELL_TYPE_AND || next_type == SHELL_TYPE_OR;
      cwd_isolated = cwd_isolated || next_type == SHELL_TYPE_PIPELINE ||
                     next_type == SHELL_TYPE_BACKGROUND ||
                     next_type == SHELL_TYPE_SUBSTITUTION;
    }
    if (range->type == SHELL_TYPE_AND || range->type == SHELL_TYPE_OR)
      *range_cwd_known = false;

    uint32_t cd_next_cwd_offset = *range_cwd_offset;
    bool cd_next_cwd_known = *range_cwd_known;
    bool cd_next_cwd_absolute = *range_cwd_absolute;
    if (is_cd) {
      /* cd's arguments and redirects expand before it changes directory.
       * Compute the next state now, but build any graph-visible effects with
       * the incoming state below. */
      const dep_token_t *cd_operand = NULL;
      bool cd_physical = false;
      dep_cd_target_t cd_target_kind =
          cd_target(&tokens, effective_command, &cd_operand, &cd_physical);
      if (cd_physical && cd_target_kind != DEP_CD_INVALID)
        cd_target_kind = DEP_CD_DYNAMIC;
      if (cd_target_kind == DEP_CD_OPERAND && !cwd_isolated &&
          cd_next_cwd_known) {
        char arg_buf[256];
        bool tilde_expanded = false;
        bool truncated = false;
        if (!decode_static_cwd_operand(cd_operand, arg_buf, sizeof(arg_buf),
                                       &tilde_expanded, &truncated)) {
          cd_next_cwd_known = false;
          if (truncated)
            out->status |= SHELL_DEP_STATUS_TRUNCATED;
        } else if (cwd_operand_uses_cdpath(arg_buf, tilde_expanded)) {
          cd_next_cwd_known = false;
        } else {
          if (arg_buf[0] == '/')
            cd_next_cwd_absolute = true;
          else if (tilde_expanded)
            cd_next_cwd_absolute = false;
          uint32_t status_before = out->status;
          cd_next_cwd_offset = cwd_resolve_dedup(
              out, cd_next_cwd_offset, arg_buf, tilde_expanded,
              effective_cwd_buf_size, &out->status);
          if ((out->status & ~status_before) != 0)
            cd_next_cwd_known = false;
        }
      } else if (cd_target_kind == DEP_CD_HOME && !cwd_isolated &&
                 cd_next_cwd_known) {
        cd_next_cwd_absolute = false;
        cd_next_cwd_offset =
            cwd_resolve_dedup(out, cd_next_cwd_offset, "$HOME", true,
                              effective_cwd_buf_size, &out->status);
      } else if (cd_target_kind == DEP_CD_DYNAMIC && !cwd_isolated &&
                 cd_next_cwd_known) {
        cd_next_cwd_known = false;
      }
      if (next_conditional)
        cd_next_cwd_known = false;
      if (!limits->cd_as_cmd && !dep_cd_needs_graph_node(&tokens)) {
        *range_cwd_offset = cd_next_cwd_offset;
        *range_cwd_known = cd_next_cwd_known;
        *range_cwd_absolute = cd_next_cwd_absolute;
        continue;
      }
    }

    /* A runtime command word can resolve to Bash's `cd` through a direct or
     * wrapped invocation. Preserve the command node but do not attach later
     * relative paths to a CWD the graph cannot prove. */
    if (dynamic_command && !cwd_isolated)
      *range_cwd_known = false;
    if (dynamic_command && next_conditional)
      *range_cwd_known = false;

    bool is_redirect_only = true;
    {
      uint32_t t = 0;
      while (t < tokens.count) {
        dep_redirect_t r = classify_redirect(&tokens.tokens[t]);
        if (r != DEP_REDIRECT_NONE) {
          /* The lexer keeps a bare duplication target such as `>&$fd` in
           * the following word token.  Use the shared source rule for every
           * redirection family so that word is never mistaken for argv while
           * deciding whether this range is a group redirect tail. */
          t += shell_source_redirection_consumes_word(tokens.tokens[t].start,
                                                      tokens.tokens[t].len)
                   ? 2
                   : 1;
        } else {
          is_redirect_only = false;
          break;
        }
      }
    }

    int32_t trailing_group = -1;
    if (is_redirect_only && tokens.count > 0) {
      trailing_group = find_preceding_group(&fast_result, cmd, rstart);
      if (trailing_group < 0)
        trailing_group =
            find_trailing_redirect_group(&fast_result, cmd, rstart);
    }
    bool follows_inline_command = false;
    uint32_t prior_command = UINT32_MAX;
    if (is_redirect_only && tokens.count > 0 && last_cmd_idx >= 0) {
      prior_command = (uint32_t)last_cmd_idx;
      uint32_t prior_range = node_range[prior_command];
      if (prior_range != UINT32_MAX) {
        const shell_range_t *previous = &fast_result.cmds[prior_range];
        uint32_t previous_end = previous->start + previous->len;
        follows_inline_command =
            previous_end <= rstart &&
            command_redirect_tail_to_range(cmd, previous_end, range);
      }
    }

    if ((trailing_group >= 0 && group_node[trailing_group] != UINT32_MAX) ||
        follows_inline_command) {
      uint32_t t = 0;
      while (t < tokens.count) {
        dep_redirect_t redir = classify_redirect(&tokens.tokens[t]);
        t++;
        if (redir == DEP_REDIRECT_DUP && t < tokens.count &&
            dep_redirect_is_legacy_combined_output(&tokens.tokens[t - 1],
                                                   &tokens.tokens[t]))
          redir = DEP_REDIRECT_BOTH;
        if (redir == DEP_REDIRECT_DUP) {
          /* `>&$name` is lexed as a redirect followed by a shell word.  That
           * word is a duplication operand, not a zero-copy command token. */
          if (shell_source_redirection_consumes_word(
                  tokens.tokens[t - 1].start, tokens.tokens[t - 1].len) &&
              t < tokens.count)
            t++;
          continue;
        }
        if (t < tokens.count && redir != DEP_REDIRECT_NONE) {
          const dep_token_t *target = &tokens.tokens[t];
          /* A syntactically continuous redirect list after a completed group
           * belongs to the group execution endpoint. A redirect-only range
           * after any list boundary instead becomes its own zero-token CMD
           * node below; it must never be projected onto the prior command. */
          uint32_t owner =
              trailing_group >= 0 ? group_node[trailing_group] : prior_command;

          bool handled_process = false;
          shell_dep_error_t process_error =
              dep_connect_redirect_process_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                  &tokens.tokens[t - 1], redir, target,
                  out->cwd_buf.data + *range_cwd_offset, limits, depth,
                  &parse_context, owner, &handled_process);
          if (process_error == SHELL_DEP_EPARSE) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }
          if (handled_process) {
            t++;
            continue;
          }

          uint32_t fd = redirect_fd(&tokens.tokens[t - 1], redir);
          uint32_t document = UINT32_MAX;
          bool document_added = false;
          if (fd == SHELL_DEP_FD_NAMED) {
            const char *fd_name = NULL;
            uint32_t fd_name_len = 0;
            if (!dep_named_fd_name(&tokens.tokens[t - 1], &fd_name,
                                   &fd_name_len)) {
              out->node_count = 0;
              out->edge_count = 0;
              out->status = SHELL_DEP_STATUS_ERROR;
              out->cwd_buf.len = 0;
              return SHELL_DEP_EPARSE;
            }
            document_added = add_doc_file_named_fd_open(
                out, max_nodes, max_edges, target->start, target->len, owner,
                redir, fd_name, fd_name_len, &out->status, &document);
          } else if (redir == DEP_REDIRECT_READ_WRITE) {
            document_added = add_doc_file_read_write(
                out, max_nodes, max_edges, target->start, target->len, owner,
                fd, &out->status, &document);
          } else if (redir == DEP_REDIRECT_BOTH ||
                     redir == DEP_REDIRECT_BOTH_APPEND) {
            document_added = add_doc_file_both_output(
                out, max_nodes, max_edges, target->start, target->len, owner,
                redir == DEP_REDIRECT_BOTH_APPEND ? SHELL_EDGE_APPEND
                                                  : SHELL_EDGE_WRITE,
                &out->status, &document);
          } else {
            shell_dep_edge_type_t etype =
                redir == DEP_REDIRECT_IN
                    ? SHELL_EDGE_READ
                    : (redir == DEP_REDIRECT_APPEND ? SHELL_EDGE_APPEND
                                                    : SHELL_EDGE_WRITE);
            document_added = add_doc_file(
                out, max_nodes, max_edges, target->start, target->len, owner,
                etype, SHELL_DIR_FORWARD, redir, fd, &out->status, &document);
          }
          if (document_added)
            dep_file_doc_set_owner_cwd(out, document, owner, group_node,
                                       group_exec, fast_result.group_count);
          if (document_added &&
              dep_connect_word_substitutions_kind(
                  out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                  target, out->cwd_buf.data + *range_cwd_offset, limits, depth,
                  &parse_context, owner,
                  (uint32_t)(tokens.tokens[t - 1].start - cmd),
                  DEP_SNAPSHOT_REDIRECT_OPERAND, document,
                  DEP_SUBST_DYNAMIC_NAME) == SHELL_DEP_EPARSE) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }
        }
        t++;
      }
      continue;
    }

    bool is_export = effective_builtin &&
                     dep_token_static_equals(effective_builtin, "export");

    if (out->node_count >= max_nodes) {
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
      return SHELL_DEP_ETRUNC;
    }

    uint32_t cmd_node_idx = out->node_count;
    shell_dep_node_t *node = &out->nodes[out->node_count++];
    node_range[cmd_node_idx] = si;
    node->type = SHELL_NODE_CMD;
    node->cmd.cwd_offset = *range_cwd_offset;
    node->cmd.group_depth = range->group_depth;
    node->cmd.group_kinds = range->group_kinds;
    node->cmd.backgrounded = range_backgrounded;
    node->cmd.pipeline_negation_count = range->pipeline_negation_count;
    node->cmd.pipeline_negated =
        (node->cmd.pipeline_negation_count & UINT32_C(1)) != 0;
    node->cmd.cwd_known = *range_cwd_known && range->type != SHELL_TYPE_AND &&
                          range->type != SHELL_TYPE_OR;
    node->cmd.cwd_absolute = node->cmd.cwd_known && *range_cwd_absolute;
    node->cmd.token_count = 0;
    node->cmd.effective_command_token = 0;
    node->cmd.effective_command_known = false;
    node->cmd.effective_command_wrapper = SHELL_DEP_COMMAND_DIRECT;
    if (tokens.count > max_tokens)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;

    if (is_cd) {
      if (out->edge_count < max_edges)
        dep_init_edge(&out->edges[out->edge_count++], cmd_node_idx,
                      cmd_node_idx, SHELL_EDGE_CWD, SHELL_DIR_FORWARD,
                      SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
      else
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
    }

    uint32_t ti = 0;

    while (ti < tokens.count) {
      const dep_token_t *etok = &tokens.tokens[ti];
      shell_source_assignment_word_t assignment;
      if (!dep_token_parse_assignment_word(etok, &assignment))
        break;
      add_doc_envvar(out, max_nodes, max_edges, etok->start,
                     assignment.name_end, etok->start + assignment.equals + 1,
                     etok->len - assignment.equals - 1, assignment.append,
                     cmd_node_idx, &out->status);
      dep_token_t value = {etok->start + assignment.equals + 1,
                           etok->len - assignment.equals - 1};
      if (dep_connect_word_substitutions(
              out, max_nodes, max_edges, effective_cwd_buf_size, streams,
              &value, out->cwd_buf.data + *range_cwd_offset, limits, depth,
              &parse_context, cmd_node_idx, range->start,
              DEP_SNAPSHOT_COMMAND_WORD, cmd_node_idx) == SHELL_DEP_EPARSE) {
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
      ti++;
    }

    bool found_command = false;
    while (ti < tokens.count) {
      const dep_token_t *tok = &tokens.tokens[ti];
      dep_redirect_t redir = classify_redirect(tok);

      if (redir != DEP_REDIRECT_NONE) {
        if (redir == DEP_REDIRECT_DUP && ti + 1 < tokens.count &&
            dep_redirect_is_legacy_combined_output(tok, &tokens.tokens[ti + 1]))
          redir = DEP_REDIRECT_BOTH;
        ti++;
        if (redir == DEP_REDIRECT_DUP) {
          /* Keep the bare symbolic duplication target out of argv.  The
           * effective-route pass below validates and resolves it atomically. */
          if (shell_source_redirection_consumes_word(tok->start, tok->len) &&
              ti < tokens.count)
            ti++;
          continue;
        }
        if (ti < tokens.count) {
          const dep_token_t *target = &tokens.tokens[ti];
          bool handled_process = false;
          shell_dep_error_t process_error =
              dep_connect_redirect_process_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                  tok, redir, target, out->cwd_buf.data + *range_cwd_offset,
                  limits, depth, &parse_context, cmd_node_idx,
                  &handled_process);
          if (process_error == SHELL_DEP_EPARSE) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }
          if (handled_process) {
            ti++;
            continue;
          }

          uint32_t fd = redirect_fd(tok, redir);
          uint32_t document = UINT32_MAX;
          bool document_added = false;
          if (fd == SHELL_DEP_FD_NAMED) {
            const char *fd_name = NULL;
            uint32_t fd_name_len = 0;
            if (!dep_named_fd_name(tok, &fd_name, &fd_name_len)) {
              out->node_count = 0;
              out->edge_count = 0;
              out->status = SHELL_DEP_STATUS_ERROR;
              out->cwd_buf.len = 0;
              return SHELL_DEP_EPARSE;
            }
            document_added = add_doc_file_named_fd_open(
                out, max_nodes, max_edges, target->start, target->len,
                cmd_node_idx, redir, fd_name, fd_name_len, &out->status,
                &document);
          } else if (redir == DEP_REDIRECT_READ_WRITE) {
            document_added = add_doc_file_read_write(
                out, max_nodes, max_edges, target->start, target->len,
                cmd_node_idx, fd, &out->status, &document);
          } else if (redir == DEP_REDIRECT_BOTH ||
                     redir == DEP_REDIRECT_BOTH_APPEND) {
            document_added = add_doc_file_both_output(
                out, max_nodes, max_edges, target->start, target->len,
                cmd_node_idx,
                redir == DEP_REDIRECT_BOTH_APPEND ? SHELL_EDGE_APPEND
                                                  : SHELL_EDGE_WRITE,
                &out->status, &document);
          } else {
            shell_dep_edge_type_t etype =
                redir == DEP_REDIRECT_IN
                    ? SHELL_EDGE_READ
                    : (redir == DEP_REDIRECT_APPEND ? SHELL_EDGE_APPEND
                                                    : SHELL_EDGE_WRITE);
            document_added = add_doc_file(
                out, max_nodes, max_edges, target->start, target->len,
                cmd_node_idx, etype, SHELL_DIR_FORWARD, redir, fd, &out->status,
                &document);
          }
          if (document_added)
            dep_file_doc_set_cwd(out, document, node->cmd.cwd_offset,
                                 node->cmd.cwd_known, node->cmd.cwd_absolute);
          shell_dep_error_t expansion_error =
              document_added
                  ? dep_connect_word_substitutions_kind(
                        out, max_nodes, max_edges, effective_cwd_buf_size,
                        streams, target, out->cwd_buf.data + *range_cwd_offset,
                        limits, depth, &parse_context, cmd_node_idx,
                        (uint32_t)(tok->start - cmd),
                        DEP_SNAPSHOT_REDIRECT_OPERAND, document,
                        DEP_SUBST_DYNAMIC_NAME)
                  : SHELL_DEP_OK;
          if (expansion_error == SHELL_DEP_EPARSE) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }
        }
        ti++;
        continue;
      }

      /* Export assignments remain ENVVAR documents, but their surrounding
       * redirect list and other words use the ordinary command graph. */
      shell_source_decoded_assignment_t export_assignment;
      if (is_export && ti > effective_command &&
          shell_source_scan_decoded_assignment(tok->start, tok->len, NULL, NULL,
                                               &export_assignment) &&
          export_assignment.source_delimiter) {
        add_doc_envvar(out, max_nodes, max_edges, tok->start,
                       export_assignment.name_end,
                       tok->start + export_assignment.equals + 1,
                       tok->len - export_assignment.equals - 1,
                       export_assignment.append, cmd_node_idx, &out->status);
        if (dep_connect_word_substitutions(
                out, max_nodes, max_edges, effective_cwd_buf_size, streams, tok,
                out->cwd_buf.data + *range_cwd_offset, limits, depth,
                &parse_context, cmd_node_idx, range->start,
                DEP_SNAPSHOT_COMMAND_WORD, cmd_node_idx) == SHELL_DEP_EPARSE) {
          out->node_count = 0;
          out->edge_count = 0;
          out->status = SHELL_DEP_STATUS_ERROR;
          out->cwd_buf.len = 0;
          return SHELL_DEP_EPARSE;
        }
        if (node->cmd.token_count < max_tokens) {
          uint32_t idx = node->cmd.token_count++;
          node->cmd.tokens[idx] = tok->start;
          node->cmd.token_lens[idx] = tok->len;
        }
        ti++;
        continue;
      }

      uint32_t subshell_offset = 0;
      dep_token_t subshell_token;
      uint32_t subshell_span = 0;
      bool had_subshell = false;
      while (find_subshell_at_or_after(tok, subshell_offset, &subshell_token,
                                       &subshell_span)) {
        had_subshell = true;
        uint32_t sub_len = 0;
        const char *sub_content =
            extract_subshell_content(&subshell_token, &sub_len);
        const char *sub_cwd_str = out->cwd_buf.data + *range_cwd_offset;
        if (!sub_content) {
          /* An unterminated command or process substitution cannot have a
           * trustworthy dynamic-flow topology. Reject it rather than keeping
           * the outer command and silently omitting a possible SUBST edge. */
          out->node_count = 0;
          out->edge_count = 0;
          out->status = SHELL_DEP_STATUS_ERROR;
          out->cwd_buf.len = 0;
          return SHELL_DEP_EPARSE;
        }
        if (sub_content && sub_len > 0) {
          bool file_handled = false;
          shell_dep_error_t file_error = SHELL_DEP_OK;
          if (subshell_token.start[0] == '$')
            file_error = dep_connect_file_command_substitution(
                out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                sub_content, sub_len, sub_cwd_str, limits, depth,
                &parse_context, cmd_node_idx, range->start,
                DEP_SNAPSHOT_COMMAND_WORD, cmd_node_idx, DEP_SUBST_SHELL_WORD,
                &file_handled);
          if (file_error == SHELL_DEP_EPARSE ||
              file_error == SHELL_DEP_EINPUT) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }
          if (!file_handled) {
            shell_dep_graph_t sub_graph;
            memset(&sub_graph, 0, sizeof(sub_graph));
            dep_subgraph_streams_t subgraph_streams = {0};
            dep_fd_imports_t fd_imports = {0};
            shell_dep_error_t snapshot_error = dep_snapshot_fd_imports(
                out, streams, &parse_context, cmd_node_idx, range->start,
                DEP_SNAPSHOT_COMMAND_WORD, &fd_imports);
            if (snapshot_error != SHELL_DEP_OK) {
              out->node_count = 0;
              out->edge_count = 0;
              out->status = SHELL_DEP_STATUS_ERROR;
              out->cwd_buf.len = 0;
              return snapshot_error;
            }
            if (subshell_token.start[0] == '$' ||
                subshell_token.start[0] == '<')
              dep_fd_import_restore_inherited(&fd_imports, 1,
                                              DEP_FD_ACCESS_WRITE);
            else if (subshell_token.start[0] == '>')
              dep_fd_import_restore_inherited(&fd_imports, 0,
                                              DEP_FD_ACCESS_READ);
            shell_dep_error_t sub_err = shell_dep_graph_parse_impl(
                sub_content, sub_len, sub_cwd_str, node->cmd.cwd_known,
                node->cmd.cwd_absolute, limits, depth + 1, NULL, &sub_graph,
                &subgraph_streams, &fd_imports);
            if (sub_err == SHELL_DEP_EPARSE || sub_err == SHELL_DEP_EINPUT) {
              out->node_count = 0;
              out->edge_count = 0;
              out->status = SHELL_DEP_STATUS_ERROR;
              out->cwd_buf.len = 0;
              return SHELL_DEP_EPARSE;
            }
            if (sub_err == SHELL_DEP_ETRUNC)
              out->status |= SHELL_DEP_STATUS_TRUNCATED;
            if (sub_err == SHELL_DEP_OK && sub_graph.node_count > 0) {
              bool connected =
                  subshell_token.start[0] != '>' ||
                  dep_append_disconnected_substitution(
                      out, max_nodes, max_edges, effective_cwd_buf_size,
                      streams, &sub_graph, &subgraph_streams);
              if (subshell_token.start[0] != '>')
                connected = dep_connect_substitution(
                    out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                    &sub_graph, &subgraph_streams, cmd_node_idx,
                    subshell_token.start[0] == '<' ? DEP_SUBST_PROCESS_WORD
                                                   : DEP_SUBST_SHELL_WORD,
                    1, NULL);
              if (!connected)
                out->status |= SHELL_DEP_STATUS_TRUNCATED;
            }
          }
        }

        uint32_t relative_start = (uint32_t)(subshell_token.start - tok->start);
        if (subshell_span == 0 || relative_start > tok->len - subshell_span)
          break;
        subshell_offset = relative_start + subshell_span;
      }

      if (had_subshell) {
        /* Netargv preserves source shell words, including a process
         * substitution descriptor. Its runtime pathname is dynamic, but
         * dropping the source spelling would change the argument count. */
        if (node->cmd.token_count < max_tokens) {
          uint32_t idx = node->cmd.token_count++;
          node->cmd.tokens[idx] = tok->start;
          node->cmd.token_lens[idx] = tok->len;
        }
        ti++;
        continue;
      }

      if (!found_command)
        found_command = true;

      if (node->cmd.token_count < max_tokens) {
        uint32_t idx = node->cmd.token_count++;
        node->cmd.tokens[idx] = tok->start;
        node->cmd.token_lens[idx] = tok->len;
      }

      if (found_command && ti > 0 && token_looks_like_path(tok)) {
        if (out->node_count < max_nodes && out->edge_count < max_edges) {
          shell_dep_node_t *an = &out->nodes[out->node_count++];
          an->type = SHELL_NODE_DOC;
          an->doc.kind = SHELL_DOC_FILE;
          an->doc.path = tok->start;
          an->doc.path_len = tok->len;
          an->doc.cwd_offset = node->cmd.cwd_known ? node->cmd.cwd_offset : 0;
          an->doc.cwd_known = node->cmd.cwd_known;
          an->doc.cwd_absolute = node->cmd.cwd_absolute;
          an->doc.name = NULL;
          an->doc.name_len = 0;
          an->doc.value = NULL;
          an->doc.value_len = 0;
          an->doc.flags = SHELL_DEP_DOC_FLAG_NONE;

          dep_init_edge(&out->edges[out->edge_count++], cmd_node_idx,
                        out->node_count - 1, SHELL_EDGE_ARG, SHELL_DIR_UNDIR,
                        SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
        } else
          out->status |= SHELL_DEP_STATUS_TRUNCATED;
      }

      ti++;
    }

    const dep_token_t *execution_target = effective_builtin;
    shell_dep_command_wrapper_t execution_wrapper = effective_wrapper;
    if (effective_builtin &&
        dep_token_static_equals(effective_builtin, "exec")) {
      bool unresolved = false;
      const dep_token_t *exec_target =
          dep_static_exec_target(&tokens, effective_command, &unresolved);
      if (exec_target) {
        execution_target = exec_target;
        execution_wrapper = SHELL_DEP_COMMAND_EXEC;
      } else if (unresolved) {
        execution_target = NULL;
      }
    }
    if (execution_target)
      for (uint32_t token = 0; token < node->cmd.token_count; token++)
        if (node->cmd.tokens[token] == execution_target->start &&
            node->cmd.token_lens[token] == execution_target->len) {
          node->cmd.effective_command_token = token;
          node->cmd.effective_command_known = true;
          node->cmd.effective_command_wrapper = execution_wrapper;
          break;
        }

    int32_t member_group = find_innermost_group(&fast_result, si);
    if (member_group >= 0 && group_node[member_group] != UINT32_MAX) {
      if (out->edge_count >= max_edges) {
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else {
        dep_init_edge(&out->edges[out->edge_count++], group_node[member_group],
                      cmd_node_idx, SHELL_EDGE_GROUP, SHELL_DIR_FORWARD,
                      SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
      }
    }
    if (last_cmd_idx >= 0 && out->edge_count < max_edges) {
      uint16_t stype = range->type;
      uint32_t control_from = (uint32_t)last_cmd_idx;
      uint32_t control_to = cmd_node_idx;
      if (stype == SHELL_TYPE_PIPELINE || stype == SHELL_TYPE_AND ||
          stype == SHELL_TYPE_OR || stype == SHELL_TYPE_BACKGROUND) {
        int32_t source_group = find_finished_group(
            &fast_result, node_range[(uint32_t)last_cmd_idx], range->start);
        if (source_group >= 0 && group_node[source_group] != UINT32_MAX)
          control_from = group_node[source_group];
        if (node_range[(uint32_t)last_cmd_idx] != UINT32_MAX) {
          int32_t target_group = find_pipe_input_group(
              &fast_result, node_range[(uint32_t)last_cmd_idx], si);
          if (target_group >= 0 && group_node[target_group] != UINT32_MAX)
            control_to = group_node[target_group];
        }
      }
      shell_dep_edge_type_t edge_type = SHELL_EDGE_SEQ;
      if (stype == (1u << 8))
        edge_type = SHELL_EDGE_PIPE;
      else if (stype == (1u << 9))
        edge_type = SHELL_EDGE_AND;
      else if (stype == (1u << 10))
        edge_type = SHELL_EDGE_OR;
      else if (stype == SHELL_TYPE_BACKGROUND)
        edge_type = SHELL_EDGE_BACKGROUND;
      shell_dep_edge_t *edge = &out->edges[out->edge_count++];
      dep_init_edge(edge, control_from, control_to, edge_type,
                    SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
      if (edge->type == SHELL_EDGE_PIPE) {
        edge->source_fd = 1;
        edge->target_fd = 0;
        if (range->pipe_input_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR)
          edge->flags = DEP_EDGE_FLAG_PIPE_STDERR;
      }

    } else if (last_cmd_idx >= 0)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;

    if (si + 1 < fast_result.count &&
        (fast_result.cmds[si + 1].type == SHELL_TYPE_AND ||
         fast_result.cmds[si + 1].type == SHELL_TYPE_OR))
      *range_cwd_known = false;
    last_cmd_idx = (int32_t)cmd_node_idx;
    if (is_cd) {
      *range_cwd_offset = cd_next_cwd_offset;
      *range_cwd_known = cd_next_cwd_known;
      *range_cwd_absolute = cd_next_cwd_absolute;
    }
  }

  for (uint32_t h = 0; h < hcount; h++) {
    heredoc_info_t *hd = &heredocs[h];
    if (!hd->has_source_span)
      continue;
    if (hd->document_built)
      continue;
    if (hd->group_idx < 0 && hd->marker_idx < fast_result.count) {
      const shell_range_t *marker = &fast_result.cmds[hd->marker_idx];
      hd->group_idx =
          find_following_group(&fast_result, cmd, marker->start + marker->len);
      if (hd->group_idx < 0)
        hd->group_idx =
            find_trailing_redirect_group(&fast_result, cmd, marker->start);
    }
    if (hd->cmd_node_idx < 0 &&
        (hd->group_idx < 0 || group_node[hd->group_idx] == UINT32_MAX))
      continue;

    uint32_t content_start = hd->content_start_pos;
    uint32_t content_end = hd->content_end_pos;

    uint32_t content_len = 0;
    const char *content_ptr = NULL;
    if (content_end > content_start) {
      content_ptr = cmd + content_start;
      content_len = content_end - content_start;
      if (content_len > 0 && content_ptr[content_len - 1] == '\n')
        content_len--;
    }

    uint32_t owner =
        hd->cmd_node_idx < 0 ? UINT32_MAX : (uint32_t)hd->cmd_node_idx;
    if (hd->group_idx >= 0 && group_node[hd->group_idx] != UINT32_MAX)
      owner = group_node[hd->group_idx];
    uint8_t flags = hd->pending.strip_tabs
                        ? SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS
                        : SHELL_DEP_DOC_FLAG_NONE;
    if (hd->literal)
      flags |= SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL;
    uint32_t document = UINT32_MAX;
    uint32_t marker_start = fast_result.cmds[hd->marker_idx].start;
    if (!add_document_read(out, max_nodes, max_edges, owner, SHELL_DOC_HEREDOC,
                           hd->delimiter, hd->delimiter_len, content_ptr,
                           content_len,
                           inline_document_target_fd(cmd, marker_start), flags,
                           &out->status, &document))
      continue;
    if (inline_document_target_fd(cmd, marker_start) == SHELL_DEP_FD_NAMED) {
      const char *fd_name = NULL;
      uint32_t fd_name_len = 0;
      if (!inline_document_named_fd_name(cmd, marker_start, &fd_name,
                                         &fd_name_len)) {
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
      dep_set_named_fd(&out->edges[out->edge_count - 1], false, fd_name,
                       fd_name_len);
    }
    if (hd->literal || content_len == 0)
      continue;
    shell_dep_error_t expansion_error = dep_connect_heredoc_substitutions(
        out, max_nodes, max_edges, effective_cwd_buf_size, streams, content_ptr,
        content_len, out->cwd_buf.data + cwd_offset, limits, depth,
        &parse_context, owner, marker_start, document);
    if (expansion_error == SHELL_DEP_EPARSE) {
      out->node_count = 0;
      out->edge_count = 0;
      out->status = SHELL_DEP_STATUS_ERROR;
      out->cwd_buf.len = 0;
      return SHELL_DEP_EPARSE;
    }
  }

  /* Whitespace and comment-only input has no descriptor owners, so it has no
   * effective routes to resolve and needs no caller workspace. */
  if (out->node_count == 0)
    return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                      : SHELL_DEP_OK;

  shell_dep_error_t route_error = dep_resolve_effective_routes(
      out, cmd, (uint32_t)cmd_len, &fast_result, node_range, group_node,
      group_exec, max_nodes, max_edges, streams, &streams->fd_imports,
      limits->workspace, limits->workspace_size);
  if (route_error != SHELL_DEP_OK) {
    out->node_count = 0;
    out->edge_count = 0;
    out->status = SHELL_DEP_STATUS_ERROR;
    out->cwd_buf.len = 0;
    return route_error;
  }
  return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                    : SHELL_DEP_OK;
}

shell_dep_error_t shell_dep_graph_parse(const char *cmd, size_t cmd_len,
                                        const char *initial_cwd,
                                        const shell_dep_limits_t *limits,
                                        shell_dep_graph_t *out) {
  return shell_dep_graph_parse_impl(cmd, cmd_len, initial_cwd, true,
                                    initial_cwd && initial_cwd[0] == '/',
                                    limits, 0, NULL, out, NULL, NULL);
}

shell_dep_error_t shell_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) {
  if (!fast)
    return shell_dep_graph_parse(cmd, cmd_len, initial_cwd, limits, out);
  return shell_dep_graph_parse_impl(cmd, cmd_len, initial_cwd, true,
                                    initial_cwd && initial_cwd[0] == '/',
                                    limits, 0, fast, out, NULL, NULL);
}

/* --- GRAPH UTILITIES --- */

static void dep_dump_escaped_span(FILE *fp, const char *value,
                                  uint32_t length) {
  if (!fp || !value)
    return;
  for (uint32_t i = 0; i < length; i++) {
    unsigned char byte = (unsigned char)value[i];
    if (byte == '\\')
      fputs("\\\\", fp);
    else if (byte == '"')
      fputs("\\\"", fp);
    else if (byte == '\n')
      fputs("\\n", fp);
    else if (byte == '\r')
      fputs("\\r", fp);
    else if (isprint(byte))
      fputc(byte, fp);
    else
      fprintf(fp, "\\x%02x", byte);
  }
}

void shell_dep_graph_dump(const shell_dep_graph_t *g, FILE *fp) {
  fprintf(fp, "Graph: %u nodes, %u edges, status=0x%x\n", g->node_count,
          g->edge_count, g->status);

  fprintf(fp, "Nodes:\n");
  for (uint32_t i = 0; i < g->node_count; i++) {
    const shell_dep_node_t *n = &g->nodes[i];
    if (n->type == SHELL_NODE_CMD) {
      fprintf(fp, "  [%u] CMD cwd=\"%s\"", i,
              n->cmd.cwd_offset < g->cwd_buf.len
                  ? g->cwd_buf.data + n->cmd.cwd_offset
                  : "?");
      if (n->cmd.pipeline_negation_count != 0)
        fprintf(fp, " negation-count=%u%s", n->cmd.pipeline_negation_count,
                n->cmd.pipeline_negated ? " negated" : "");
      fprintf(fp, " tokens=[");
      for (uint32_t j = 0; j < n->cmd.token_count; j++) {
        if (j > 0)
          fprintf(fp, ", ");
        fprintf(fp, "\"%.*s\"", n->cmd.token_lens[j], n->cmd.tokens[j]);
      }
      fprintf(fp, "]\n");
    } else if (n->type == SHELL_NODE_GROUP) {
      fprintf(fp, "  [%u] GROUP span=\"%.*s\" parent=%u", i, n->group.length,
              n->group.start ? n->group.start : "", n->group.parent);
      if (n->group.pipeline_negation_count != 0)
        fprintf(fp, " negation-count=%u%s", n->group.pipeline_negation_count,
                n->group.pipeline_negated ? " negated" : "");
      fprintf(fp, "\n");
    } else if (n->type == SHELL_NODE_ENDPOINT) {
      const char *endpoint_kind =
          n->endpoint.reserved == DEP_ENDPOINT_TERMINAL_PIPE
              ? " terminal-pipe"
              : (n->endpoint.reserved ==
                         DEP_ENDPOINT_UNCONNECTED_PROCESS_SUBSTITUTION
                     ? " unconnected-process-substitution"
                     : "");
      fprintf(fp, "  [%u] ENDPOINT%s\n", i, endpoint_kind);
    } else {
      fprintf(fp, "  [%u] DOC %s", i, shell_dep_doc_kind_name(n->doc.kind));
      if (n->doc.kind == SHELL_DOC_FILE && n->doc.path) {
        fprintf(fp, " path=\"%.*s\"", n->doc.path_len, n->doc.path);
      } else if (n->doc.kind == SHELL_DOC_ENVVAR) {
        fprintf(fp, " name=\"%.*s\" value=\"%.*s\"", n->doc.name_len,
                n->doc.name ? n->doc.name : "", n->doc.value_len,
                n->doc.value ? n->doc.value : "");
      } else if (n->doc.kind == SHELL_DOC_HEREDOC) {
        fprintf(fp, " delim=\"%.*s\" content=\"%.*s\"", n->doc.name_len,
                n->doc.name ? n->doc.name : "", n->doc.value_len,
                n->doc.value ? n->doc.value : "");
      } else if (n->doc.kind == SHELL_DOC_HERESTRING && n->doc.value) {
        fprintf(fp, " content=\"%.*s\"", n->doc.value_len, n->doc.value);
      }
      fprintf(fp, "\n");
    }
  }

  fprintf(fp, "Edges:\n");
  for (uint32_t i = 0; i < g->edge_count; i++) {
    const shell_dep_edge_t *e = &g->edges[i];
    const char *arrow = e->dir == SHELL_DIR_FORWARD ? "->"
                        : e->dir == SHELL_DIR_UNDIR ? "<>"
                                                    : "<->";
    fprintf(fp, "  [%u] %s[%u:%u] %s %u %s %u", i,
            shell_dep_edge_type_name(e->type), e->source_fd, e->target_fd,
            arrow, e->from, arrow, e->to);
    if (e->source_fd_name) {
      fputs(" source-name=\"", fp);
      dep_dump_escaped_span(fp, e->source_fd_name, e->source_fd_name_len);
      fputc('"', fp);
    }
    if (e->target_fd_name) {
      fputs(" target-name=\"", fp);
      dep_dump_escaped_span(fp, e->target_fd_name, e->target_fd_name_len);
      fputc('"', fp);
    }
    if (e->flags != SHELL_DEP_EDGE_FLAG_NONE)
      fprintf(fp, " flags=0x%x", e->flags);
    fputc('\n', fp);
  }
}

/* Keep FD_OPEN's setup forms disjoint.  Consumers distinguish a descriptor
 * duplication from a document/endpoint setup edge, so accepting a duplicate
 * flag on an otherwise ordinary edge would make one graph carry two
 * contradictory meanings. */
static bool dep_fd_open_edge_form_valid(const shell_dep_edge_t *edge,
                                        shell_dep_node_type_t from,
                                        shell_dep_node_type_t to) {
  if (!edge)
    return false;
  bool from_execution = from == SHELL_NODE_CMD || from == SHELL_NODE_GROUP;
  bool to_execution = to == SHELL_NODE_CMD || to == SHELL_NODE_GROUP;
  bool duplicate = (edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0;
  bool append = (edge->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0;
  if (duplicate)
    return edge->flags == SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP && from_execution &&
           to_execution && edge->from == edge->to &&
           edge->source_fd != SHELL_DEP_FD_NONE &&
           edge->target_fd != SHELL_DEP_FD_NONE;

  bool document_output = from_execution && to == SHELL_NODE_DOC &&
                         edge->source_fd != SHELL_DEP_FD_NONE &&
                         edge->target_fd == SHELL_DEP_FD_NONE;
  if (append)
    return edge->flags == SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND && document_output;
  if (edge->flags != SHELL_DEP_EDGE_FLAG_NONE)
    return false;

  return document_output ||
         (from == SHELL_NODE_DOC && to_execution &&
          edge->source_fd == SHELL_DEP_FD_NONE &&
          edge->target_fd != SHELL_DEP_FD_NONE) ||
         (from_execution && to == SHELL_NODE_ENDPOINT &&
          edge->source_fd != SHELL_DEP_FD_NONE &&
          edge->target_fd == SHELL_DEP_FD_NONE) ||
         (from == SHELL_NODE_ENDPOINT && to_execution &&
          edge->source_fd == SHELL_DEP_FD_NONE &&
          edge->target_fd != SHELL_DEP_FD_NONE) ||
         (from_execution && to_execution && edge->from != edge->to &&
          edge->source_fd != SHELL_DEP_FD_NONE &&
          edge->target_fd != SHELL_DEP_FD_NONE);
}

shell_dep_graph_validation_t
shell_dep_graph_validate(const shell_dep_graph_t *g) {
  shell_dep_graph_validation_t r = {0};
  r.valid = true;

  if (!g) {
    r.valid = false;
    snprintf(r.errors[0].msg, sizeof(r.errors[0].msg), "graph is NULL");
    r.error_count = 1;
    return r;
  }

  /* Counts are caller-controlled fields in front of fixed arrays. Validate
   * every bound before the node and edge walks below so this diagnostic helper
   * is safe even for a wholly corrupt graph. */
  if (g->node_count > SHELL_DEP_MAX_NODES ||
      g->edge_count > SHELL_DEP_MAX_EDGES ||
      g->cwd_buf.len > SHELL_DEP_CWD_BUF_SIZE) {
    r.valid = false;
    if (g->node_count > SHELL_DEP_MAX_NODES) {
      snprintf(r.errors[r.error_count++].msg, 96,
               "node_count %u exceeds capacity %u", g->node_count,
               SHELL_DEP_MAX_NODES);
    }
    if (g->edge_count > SHELL_DEP_MAX_EDGES &&
        r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS) {
      snprintf(r.errors[r.error_count++].msg, 96,
               "edge_count %u exceeds capacity %u", g->edge_count,
               SHELL_DEP_MAX_EDGES);
    }
    if (g->cwd_buf.len > SHELL_DEP_CWD_BUF_SIZE &&
        r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS) {
      snprintf(r.errors[r.error_count++].msg, 96,
               "cwd_buf.len %zu exceeds capacity %u", g->cwd_buf.len,
               SHELL_DEP_CWD_BUF_SIZE);
    }
    return r;
  }

  for (uint32_t i = 0;
       i < g->node_count && r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS;
       i++) {
    const shell_dep_node_t *n = &g->nodes[i];
    if (n->type > SHELL_NODE_ENDPOINT) {
      r.valid = false;
      snprintf(r.errors[r.error_count].msg, 96, "node %u: invalid node type %u",
               i, n->type);
      r.error_count++;
      continue;
    }
    if (n->type == SHELL_NODE_CMD) {
      if (n->cmd.cwd_offset >= g->cwd_buf.len) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "CMD node %u: cwd_offset %u >= cwd_buf.len %zu", i,
                 n->cmd.cwd_offset, g->cwd_buf.len);
        r.error_count++;
      } else if (memchr(g->cwd_buf.data + n->cmd.cwd_offset, '\0',
                        g->cwd_buf.len - n->cmd.cwd_offset) == NULL) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "CMD node %u: cwd at offset %u is not NUL-terminated", i,
                 n->cmd.cwd_offset);
        r.error_count++;
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          ((n->cmd.effective_command_known &&
            n->cmd.effective_command_token >= n->cmd.token_count) ||
           n->cmd.effective_command_wrapper > SHELL_DEP_COMMAND_EXEC)) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "CMD node %u: invalid effective command", i);
        r.error_count++;
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          n->cmd.cwd_absolute && !n->cmd.cwd_known) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "CMD node %u: absolute CWD is not known", i);
        r.error_count++;
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          (((n->cmd.pipe_stdin_source == UINT32_MAX) !=
            (n->cmd.pipe_stdin_target == UINT32_MAX)) ||
           ((n->cmd.pipe_stdout_source == UINT32_MAX) !=
            (n->cmd.pipe_stdout_target == UINT32_MAX)) ||
           (n->cmd.pipe_stdin_source != UINT32_MAX &&
            (n->cmd.pipe_stdin_source >= g->node_count ||
             !dep_is_execution_node(g, n->cmd.pipe_stdin_source))) ||
           (n->cmd.pipe_stdin_target != UINT32_MAX &&
            (n->cmd.pipe_stdin_target >= g->node_count ||
             !dep_is_execution_node(g, n->cmd.pipe_stdin_target))) ||
           (n->cmd.pipe_stdout_source != UINT32_MAX &&
            (n->cmd.pipe_stdout_source >= g->node_count ||
             !dep_is_execution_node(g, n->cmd.pipe_stdout_source))) ||
           (n->cmd.pipe_stdout_target != UINT32_MAX &&
            (n->cmd.pipe_stdout_target >= g->node_count ||
             !dep_is_execution_node(g, n->cmd.pipe_stdout_target))))) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "CMD node %u: invalid effective pipe owner", i);
        r.error_count++;
      }
    } else if (n->type == SHELL_NODE_DOC) {
      const shell_dep_doc_t *doc = &n->doc;
      const uint8_t known_flags =
          SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
          SHELL_DEP_DOC_FLAG_DYNAMIC_NAME | SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL |
          SHELL_DEP_DOC_FLAG_TRANSIENT | SHELL_DEP_DOC_FLAG_ENVVAR_APPEND;
      bool spans_valid = (doc->path != NULL || doc->path_len == 0) &&
                         (doc->name != NULL || doc->name_len == 0) &&
                         (doc->value != NULL || doc->value_len == 0);
      bool kind_valid =
          doc->kind >= SHELL_DOC_FILE && doc->kind <= SHELL_DOC_ENVVAR;
      bool shape_valid = false;
      if (kind_valid) {
        switch (doc->kind) {
        case SHELL_DOC_FILE:
          shape_valid = doc->path != NULL && doc->path_len > 0 &&
                        doc->name == NULL && doc->name_len == 0 &&
                        doc->value == NULL && doc->value_len == 0 &&
                        (doc->flags & ~(SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
                                        SHELL_DEP_DOC_FLAG_TRANSIENT)) == 0;
          break;
        case SHELL_DOC_HEREDOC:
          shape_valid = doc->path == NULL && doc->path_len == 0 &&
                        doc->name != NULL &&
                        (doc->flags & ~(SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
                                        SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL |
                                        SHELL_DEP_DOC_FLAG_TRANSIENT)) == 0;
          break;
        case SHELL_DOC_HERESTRING:
          shape_valid = doc->path == NULL && doc->path_len == 0 &&
                        doc->name == NULL && doc->name_len == 0 &&
                        (doc->flags & ~(SHELL_DEP_DOC_FLAG_TRANSIENT)) == 0;
          break;
        case SHELL_DOC_ENVVAR:
          shape_valid = doc->path == NULL && doc->path_len == 0 &&
                        doc->name != NULL && doc->name_len > 0 &&
                        (doc->flags & ~SHELL_DEP_DOC_FLAG_ENVVAR_APPEND) == 0;
          break;
        }
      }
      if (!kind_valid || !spans_valid || (doc->flags & ~known_flags) != 0 ||
          !shape_valid) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "DOC node %u: invalid kind, flags, or payload shape", i);
        r.error_count++;
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          doc->kind == SHELL_DOC_FILE &&
          ((doc->cwd_absolute && !doc->cwd_known) ||
           (doc->cwd_known && (doc->cwd_offset >= g->cwd_buf.len ||
                               !memchr(g->cwd_buf.data + doc->cwd_offset, 0,
                                       g->cwd_buf.len - doc->cwd_offset))))) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "DOC node %u: invalid file CWD", i);
        r.error_count++;
      }
    } else if (n->type == SHELL_NODE_GROUP) {
      if (n->group.kind != SHELL_GROUP_BRACE &&
          n->group.kind != SHELL_GROUP_SUBSHELL) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "GROUP node %u: invalid kind %u", i, n->group.kind);
        r.error_count++;
        continue;
      }
      if (!n->group.start || n->group.length == 0) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "GROUP node %u: empty source span", i);
        r.error_count++;
        continue;
      }
      if (n->group.parent != UINT32_MAX) {
        bool has_parent_edge = false;
        if (n->group.parent < g->node_count && n->group.parent != i &&
            g->nodes[n->group.parent].type == SHELL_NODE_GROUP) {
          for (uint32_t edge = 0; edge < g->edge_count; edge++) {
            const shell_dep_edge_t *candidate = &g->edges[edge];
            if (candidate->type == SHELL_EDGE_GROUP &&
                candidate->from == n->group.parent && candidate->to == i &&
                candidate->dir == SHELL_DIR_FORWARD &&
                candidate->flags == SHELL_DEP_EDGE_FLAG_NONE &&
                candidate->source_fd == SHELL_DEP_FD_NONE &&
                candidate->target_fd == SHELL_DEP_FD_NONE) {
              has_parent_edge = true;
              break;
            }
          }
        }
        if (!has_parent_edge) {
          r.valid = false;
          snprintf(r.errors[r.error_count].msg, 96,
                   "GROUP node %u: invalid parent %u or containment edge", i,
                   n->group.parent);
          r.error_count++;
        }
      }
    } else if (n->type == SHELL_NODE_ENDPOINT) {
      if (n->endpoint.reserved != 0 &&
          n->endpoint.reserved != DEP_ENDPOINT_TERMINAL_PIPE &&
          n->endpoint.reserved !=
              DEP_ENDPOINT_UNCONNECTED_PROCESS_SUBSTITUTION) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "ENDPOINT node %u: unknown endpoint flags %u", i,
                 n->endpoint.reserved);
        r.error_count++;
        continue;
      }
      if (n->endpoint.reserved ==
          DEP_ENDPOINT_UNCONNECTED_PROCESS_SUBSTITUTION) {
        bool input_direction = false;
        bool output_direction = false;
        bool has_setup = false;
        bool topology_valid = true;
        for (uint32_t edge = 0; edge < g->edge_count; edge++) {
          const shell_dep_edge_t *current = &g->edges[edge];
          if (current->from == i) {
            bool setup = current->type == SHELL_EDGE_FD_OPEN &&
                         current->source_fd == SHELL_DEP_FD_NONE &&
                         current->target_fd == SHELL_DEP_FD_NAMED &&
                         dep_is_execution_node(g, current->to);
            bool flow = current->type == SHELL_EDGE_SUBST &&
                        current->source_fd == SHELL_DEP_FD_NONE &&
                        dep_is_execution_node(g, current->to);
            topology_valid = topology_valid && (setup || flow);
            input_direction = true;
            has_setup = has_setup || setup;
          }
          if (current->to == i) {
            bool setup = current->type == SHELL_EDGE_FD_OPEN &&
                         current->source_fd == SHELL_DEP_FD_NAMED &&
                         current->target_fd == SHELL_DEP_FD_NONE &&
                         dep_is_execution_node(g, current->from);
            bool flow = current->type == SHELL_EDGE_WRITE &&
                        current->source_fd != SHELL_DEP_FD_NONE &&
                        current->target_fd == SHELL_DEP_FD_NONE &&
                        dep_is_execution_node(g, current->from);
            topology_valid = topology_valid && (setup || flow);
            output_direction = true;
            has_setup = has_setup || setup;
          }
        }
        if (!topology_valid || !has_setup ||
            input_direction == output_direction) {
          r.valid = false;
          snprintf(r.errors[r.error_count].msg, 96,
                   "ENDPOINT node %u: invalid unconnected substitution "
                   "topology",
                   i);
          r.error_count++;
        }
        continue;
      }
      bool has_producer = false;
      bool has_setup = false;
      bool has_consumer = false;
      bool topology_valid = true;
      for (uint32_t edge = 0; edge < g->edge_count; edge++) {
        const shell_dep_edge_t *current = &g->edges[edge];
        if (current->to == i) {
          bool producer = n->endpoint.reserved == DEP_ENDPOINT_TERMINAL_PIPE
                              ? current->type == SHELL_EDGE_PIPE
                              : current->type == SHELL_EDGE_WRITE;
          bool setup = n->endpoint.reserved == 0 &&
                       current->type == SHELL_EDGE_FD_OPEN &&
                       current->source_fd != SHELL_DEP_FD_NONE;
          topology_valid = topology_valid && (producer || setup);
          has_producer = has_producer || producer;
          has_setup = has_setup || setup;
        }
        if (current->from == i) {
          bool consumer = n->endpoint.reserved == 0 &&
                          (current->type == SHELL_EDGE_SUBST ||
                           (current->type == SHELL_EDGE_FD_OPEN &&
                            current->target_fd != SHELL_DEP_FD_NONE));
          topology_valid = topology_valid && consumer;
          has_consumer = has_consumer || consumer;
        }
      }
      if (!topology_valid || (!has_producer && !has_setup) ||
          (n->endpoint.reserved != DEP_ENDPOINT_TERMINAL_PIPE &&
           !has_consumer)) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "ENDPOINT node %u: valid=%d producers=%d consumers=%d", i,
                 topology_valid, has_producer, has_consumer);
        r.error_count++;
      }
    }
  }

  for (uint32_t i = 0;
       i < g->edge_count && r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS;
       i++) {
    const shell_dep_edge_t *e = &g->edges[i];

    if (e->from >= g->node_count || e->to >= g->node_count) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96, "OOB: from=%u to=%u nodes=%u",
               e->from, e->to, g->node_count);
      r.error_count++;
      continue;
    }

    if (e->type > SHELL_EDGE_FD_CLOSE || e->dir > SHELL_DIR_UNDIR) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96,
               "invalid edge type %u or direction %u", e->type, e->dir);
      r.error_count++;
      continue;
    }

    if ((e->source_fd != SHELL_DEP_FD_NONE &&
         e->source_fd != SHELL_DEP_FD_NAMED &&
         e->source_fd > SHELL_DEP_FD_MAX) ||
        (e->target_fd != SHELL_DEP_FD_NONE &&
         e->target_fd != SHELL_DEP_FD_NAMED &&
         e->target_fd > SHELL_DEP_FD_MAX)) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96,
               "descriptor outside supported range: source=%u target=%u",
               e->source_fd, e->target_fd);
      r.error_count++;
      continue;
    }

    bool source_name_valid =
        e->source_fd == SHELL_DEP_FD_NAMED
            ? e->source_fd_name != NULL && e->source_fd_name_len != 0
            : e->source_fd_name == NULL && e->source_fd_name_len == 0;
    bool target_name_valid =
        e->target_fd == SHELL_DEP_FD_NAMED
            ? e->target_fd_name != NULL && e->target_fd_name_len != 0
            : e->target_fd_name == NULL && e->target_fd_name_len == 0;
    if (!source_name_valid || !target_name_valid) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96,
               "named descriptor is missing or has stray name metadata");
      r.error_count++;
      continue;
    }

    if ((e->flags & ~(SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                      SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME |
                      SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND |
                      SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP)) != 0 ||
        ((e->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
         (e->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) ||
        ((e->flags & (SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                      SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME)) != 0 &&
         e->type != SHELL_EDGE_SUBST) ||
        ((e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0 &&
         e->type != SHELL_EDGE_FD_OPEN) ||
        ((e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0 &&
         e->type != SHELL_EDGE_FD_OPEN) ||
        ((e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0 &&
         (e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0)) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96, "invalid flags %#x for %s edge",
               e->flags, shell_dep_edge_type_name(e->type));
      r.error_count++;
      continue;
    }

    bool edge_form = e->type == SHELL_EDGE_ARG
                         ? e->dir == SHELL_DIR_UNDIR &&
                               e->source_fd == SHELL_DEP_FD_NONE &&
                               e->target_fd == SHELL_DEP_FD_NONE
                         : e->dir == SHELL_DIR_FORWARD;
    if (!edge_form) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96,
               "invalid direction or descriptors for %s edge",
               shell_dep_edge_type_name(e->type));
      r.error_count++;
      continue;
    }

    shell_dep_node_type_t ft = g->nodes[e->from].type;
    shell_dep_node_type_t tt = g->nodes[e->to].type;

    bool ok = true;
    switch (e->type) {
    case SHELL_EDGE_PIPE:
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP) &&
           (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP ||
            (tt == SHELL_NODE_ENDPOINT && g->nodes[e->to].endpoint.reserved ==
                                              DEP_ENDPOINT_TERMINAL_PIPE)) &&
           e->source_fd != SHELL_DEP_FD_NONE &&
           e->target_fd != SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_SUBST:
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP ||
            ft == SHELL_NODE_ENDPOINT ||
            (ft == SHELL_NODE_DOC &&
             g->nodes[e->from].doc.kind == SHELL_DOC_FILE)) &&
           (((ft == SHELL_NODE_ENDPOINT || ft == SHELL_NODE_DOC) &&
             e->source_fd == SHELL_DEP_FD_NONE) ||
            ((ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP) &&
             e->source_fd != SHELL_DEP_FD_NONE));
      if ((e->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) {
        ok = ok && tt == SHELL_NODE_DOC &&
             g->nodes[e->to].doc.kind == SHELL_DOC_FILE &&
             (g->nodes[e->to].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) !=
                 0 &&
             e->target_fd == SHELL_DEP_FD_NONE;
      } else if ((e->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) {
        ok = ok &&
             (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP ||
              (tt == SHELL_NODE_DOC &&
               (g->nodes[e->to].doc.kind == SHELL_DOC_HEREDOC ||
                g->nodes[e->to].doc.kind == SHELL_DOC_HERESTRING))) &&
             e->target_fd == SHELL_DEP_FD_NONE;
      } else {
        /* Unflagged SUBST represents process-substitution descriptor routing.
         * It reaches an execution endpoint and may carry that target fd. */
        ok = ok && (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP);
      }
      break;
    case SHELL_EDGE_SEQ:
    case SHELL_EDGE_AND:
    case SHELL_EDGE_OR:
    case SHELL_EDGE_BACKGROUND:
      /* Compound groups are aggregate command nodes at composition
       * boundaries, so a control edge may enter or leave either a simple
       * command or a group. */
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP) &&
           (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP) &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_GROUP:
      ok = ft == SHELL_NODE_GROUP &&
           (tt == SHELL_NODE_GROUP || tt == SHELL_NODE_CMD) &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE &&
           (tt != SHELL_NODE_GROUP || g->nodes[e->to].group.parent == e->from);
      break;
    case SHELL_EDGE_READ:
      ok = ft == SHELL_NODE_DOC &&
           (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP) &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd != SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_WRITE:
    case SHELL_EDGE_APPEND:
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP) &&
           (tt == SHELL_NODE_DOC || tt == SHELL_NODE_ENDPOINT) &&
           e->source_fd != SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_FD_OPEN:
      ok =
          dep_fd_open_edge_form_valid(e, ft, tt) && e->dir == SHELL_DIR_FORWARD;
      break;
    case SHELL_EDGE_FD_CLOSE:
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP) && ft == tt &&
           e->from == e->to && e->source_fd != SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE &&
           e->flags == SHELL_DEP_EDGE_FLAG_NONE && e->dir == SHELL_DIR_FORWARD;
      break;
    case SHELL_EDGE_ENV:
      ok = (ft == SHELL_NODE_DOC && tt == SHELL_NODE_CMD) &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_ARG:
      ok = ((ft == SHELL_NODE_CMD && tt == SHELL_NODE_DOC) ||
            (ft == SHELL_NODE_DOC && tt == SHELL_NODE_CMD));
      break;
    case SHELL_EDGE_CWD:
      ok = (ft == SHELL_NODE_CMD && tt == SHELL_NODE_CMD) &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE;
      break;
    default:
      ok = false;
      break;
    }

    if (!ok) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96,
               "type mismatch: %s(%s)->%s(%s) for %s edge",
               shell_dep_node_type_name(ft),
               ft == SHELL_NODE_DOC
                   ? shell_dep_doc_kind_name(g->nodes[e->from].doc.kind)
                   : "",
               shell_dep_node_type_name(tt),
               tt == SHELL_NODE_DOC
                   ? shell_dep_doc_kind_name(g->nodes[e->to].doc.kind)
                   : "",
               shell_dep_edge_type_name(e->type));
      r.error_count++;
    }
  }

  return r;
}

const char *shell_dep_error_string(shell_dep_error_t err) {
  switch (err) {
  case SHELL_DEP_OK:
    return "OK";
  case SHELL_DEP_EINPUT:
    return "Invalid input";
  case SHELL_DEP_ETRUNC:
    return "Truncated (limits exceeded)";
  case SHELL_DEP_EPARSE:
    return "Parse error";
  case SHELL_DEP_EWORKSPACE:
    return "Resolver workspace unavailable";
  default:
    return "Unknown error";
  }
}
