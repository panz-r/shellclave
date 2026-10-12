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
#include "shell_builtin_internal.h"
#include "shell_depgraph_internal.h"
#include "shell_netstring.h"
#include "shell_pipeline_internal.h"
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

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#define DEP_METADATA_WORK(kind) shellsplit_test_metadata_charge(kind)
#else
#define DEP_METADATA_WORK(kind) ((void)0)
#endif

/* --- NAME HELPERS --- */

static const char *dep_edge_names[] = {
    "READ",  "WRITE",   "APPEND",   "PIPE", "ARG", "ENV",
    "SUBST", "SEQ",     "AND",      "OR",   "CWD", "BACKGROUND",
    "GROUP", "FD_OPEN", "FD_CLOSE", "TIME",
};

static const char *dep_node_names[] = {
    "CMD", "DOC", "GROUP", "ENDPOINT", "TIME",
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

static SHELL_NONNULL(1) bool dep_doc_content_valid(const shell_dep_doc_t *doc) {
  return (doc->value != NULL || doc->value_len == 0) &&
         (doc->flags &
          ~(SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
            SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
            SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL | SHELL_DEP_DOC_FLAG_TRANSIENT |
            SHELL_DEP_DOC_FLAG_ENVVAR_APPEND |
            SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
            SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) == 0;
}

bool shell_dep_doc_content_length(const shell_dep_doc_t *doc,
                                  size_t *content_length) {
  *content_length = 0;
  if (!dep_doc_content_valid(doc))
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
  *written = 0;
  if (!dep_doc_content_valid(doc))
    return false;
  size_t needed = 0;
  if (!shell_dep_doc_content_length(doc, &needed) ||
      (needed != 0 && !destination) || destination_size < needed)
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

static SHELL_NONNULL(1, 4) bool dep_doc_env_assignment(
    const shell_dep_doc_t *doc, shell_source_byte_visitor_t visitor,
    void *context, shell_source_decoded_assignment_t *out) {
  if (doc->kind != SHELL_DOC_ENVVAR || !doc->name || !doc->value)
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
  *name_length = 0;

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
  *written = 0;
  size_t needed = 0;
  if (!shell_dep_doc_env_name_length(doc, &needed) || destination_size < needed)
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

static size_t dep_normalize_path(char *path, uint32_t len,
                                 bool collapse_parent) {
  if (len == 0)
    return 0;
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
    while (r < len && path[r] == '/') {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PATH_NORMALIZATION);
      r++;
    }
    uint32_t start = r;
    while (r < len && path[r] != '/') {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PATH_NORMALIZATION);
      r++;
    }
    uint32_t component_len = r - start;
    if (component_len == 0 || (component_len == 1 && path[start] == '.'))
      continue;
    if (collapse_parent && component_len == 2 && path[start] == '.' &&
        path[start + 1] == '.') {
      uint32_t previous = w;
      while (previous > (absolute ? 1u : 0u) && path[previous - 1] != '/') {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PATH_NORMALIZATION);
        previous--;
      }
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
  return w;
}

size_t shell_dep_file_path_normalize(char *path, size_t length) {
  return dep_normalize_path(path, (uint32_t)length, false);
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

typedef struct {
  const char *cwd;
  size_t cwd_len;
  size_t prefix_len;
  size_t combined_len;
  bool path_absolute;
} dep_file_identity_layout_t;

/* Identity availability and output-capacity boundary, shared by source-word
 * and predecoded consumers. Known CWD metadata references an installed pool
 * string by caller contract; do not revalidate parser-produced storage here.
 * No destination writes occur until this succeeds. */
static SHELL_NONNULL(1, 2, 6) bool dep_file_identity_plan(
    const shell_dep_graph_t *graph, const shell_dep_doc_t *doc,
    unsigned char first, size_t path_len, size_t destination_size,
    dep_file_identity_layout_t *layout) {
  bool path_absolute = first == '/';
  if (!path_absolute && !doc->cwd_known)
    return false;
  const char *cwd =
      path_absolute ? NULL : graph->cwd_buf.data + doc->cwd_offset;
  size_t cwd_len = path_absolute ? 0 : strlen(cwd);
  size_t prefix_len = path_absolute ? 0 : cwd_len + 1;
  if (prefix_len > SIZE_MAX - path_len - 1)
    return false;
  size_t combined_len = prefix_len + path_len;
  if (combined_len > UINT32_MAX || combined_len + 1 > destination_size)
    return false;
  *layout = (dep_file_identity_layout_t){cwd, cwd_len, prefix_len, combined_len,
                                         path_absolute};
  return true;
}

static SHELL_NONNULL(1, 2, 3, 4, 5) void dep_file_identity_finish(
    const shell_dep_doc_t *doc, const dep_file_identity_layout_t *layout,
    char *destination, size_t *written, bool *absolute) {
  if (!layout->path_absolute) {
    memcpy(destination, layout->cwd, layout->cwd_len);
    destination[layout->cwd_len] = '/';
  }
  destination[layout->combined_len] = '\0';
  *written =
      dep_normalize_path(destination, (uint32_t)layout->combined_len, false);
  *absolute = layout->path_absolute || doc->cwd_absolute;
}

bool shell_dep_doc_file_identity_from_decoded(const shell_dep_graph_t *graph,
                                              const shell_dep_doc_t *doc,
                                              const char *decoded,
                                              size_t length, char *destination,
                                              size_t capacity, size_t *written,
                                              bool *absolute) {
  *written = 0;
  *absolute = false;
  dep_file_identity_layout_t layout;
  if (!dep_file_identity_plan(graph, doc, (unsigned char)decoded[0], length,
                              capacity, &layout))
    return false;
  /* Copy the payload first: it may already occupy destination, before the
   * recorded CWD prefix is inserted. */
  memmove(destination + layout.prefix_len, decoded, length);
  dep_file_identity_finish(doc, &layout, destination, written, absolute);
  return true;
}

static SHELL_NONNULL(3) bool dep_file_identity_write_byte(unsigned char byte,
                                                          size_t position,
                                                          void *context) {
  char *destination = context;
  destination[position] = (char)byte;
  return true;
}

bool shell_dep_doc_file_identity_write(const shell_dep_graph_t *graph,
                                       const shell_dep_doc_t *doc,
                                       char *destination,
                                       size_t destination_size, size_t *written,
                                       bool *absolute) {
  *written = 0;
  *absolute = false;
  if ((doc->kind != SHELL_DOC_FILE) || (!doc->path))
    return false;
  if (doc->flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)
    return false;
  if (doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH) {
    return shell_dep_doc_file_identity_from_decoded(
        graph, doc, doc->value, doc->value_len, destination, destination_size,
        written, absolute);
  }
  if (doc->flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME)
    return false;
  dep_file_identity_measure_t measure = {0};
  size_t path_len = 0;
  if (shell_visit_decoded_word(doc->path, doc->path_len, dep_file_identity_byte,
                               &measure, &path_len) != SHELL_PROCESS_OK ||
      path_len == 0 || measure.has_nul)
    return false;
  dep_file_identity_layout_t layout;
  if (!dep_file_identity_plan(graph, doc, measure.first, path_len,
                              destination_size, &layout))
    return false;
  /* The measure pass validated the immutable word. Write it without another
   * measure pass, preserving destination atomicity on every failure above. */
  size_t decoded_len = 0;
  (void)shell_visit_decoded_word(doc->path, doc->path_len,
                                 dep_file_identity_write_byte,
                                 destination + layout.prefix_len, &decoded_len);
  dep_file_identity_finish(doc, &layout, destination, written, absolute);
  return true;
}

/* current_offset references an installed pool entry. Absolute and symbolic
 * HOME-rooted targets do not read that entry; relative targets require a known
 * incoming directory. effective_size is the validated pool bound. */
static SHELL_NONNULL(1, 3, 6) uint32_t
    cwd_resolve_dedup(shell_dep_graph_t *g, uint32_t current_offset,
                      const char *rel, bool tilde_expanded,
                      uint32_t effective_size, uint32_t *status) {
  if (rel[0] == '\0')
    return current_offset;

  char temp_path[SHELL_DEP_CWD_BUF_SIZE];
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
    const char *current_cwd = g->cwd_buf.data + current_offset;
    size_t cur_len = strlen(current_cwd);
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
  if (shell_source_parse_named_fd_redirect_at_word_start(cmd, pos, end,
                                                         &named_operator)) {
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
  /* Instrument complete source passes, not just successful token probes. */
  SHELL_SOURCE_WORD_SCAN(range_len);
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
    /* Inline document ranges remain separate for document construction, but
     * belong to this execution stage. They must not become argv or FILE
     * redirects when a stage resumes its ordinary words after the marker. */
    size_t operator_pos = pos;
    uint32_t ignored_fd = 0;
    bool named_prefix = shell_source_parse_named_fd_redirect_at_word_start(
        cmd, pos, end, &operator_pos);
    shell_source_io_number_t numeric_prefix = SHELL_SOURCE_IO_NUMBER_NONE;
    if (!named_prefix)
      numeric_prefix = shell_source_parse_io_number(cmd, pos, end,
                                                    &operator_pos, &ignored_fd);
    operator_pos =
        shell_source_skip_escaped_line_endings(cmd, end, operator_pos);
    if (numeric_prefix != SHELL_SOURCE_IO_NUMBER_OVERFLOW &&
        shell_source_match_logical_punctuation(cmd, end, operator_pos, "<<",
                                               NULL)) {
      size_t after = shell_source_skip_redirect(cmd, pos, end);
      if (after <= pos) {
        out->malformed = true;
        return true;
      }
      pos = (uint32_t)after;
      continue;
    }

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
    if (shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                               "<&", &operator_after) ||
        shell_source_match_logical_punctuation(tok->start, logical_end, after,
                                               ">&", &operator_after))
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
  if (shell_source_match_logical_punctuation(tok->start, logical_end, pos, "<&",
                                             &operator_after) ||
      shell_source_match_logical_punctuation(tok->start, logical_end, pos, ">&",
                                             &operator_after))
    return DEP_REDIRECT_DUP;
  return DEP_REDIRECT_NONE;
}

/* Token helpers borrow live source spans from scan_tokens(). Output pointers
 * name writable storage; decoded-word visitors receive their live scan context.
 * They inspect shell spelling, not the validity of caller-owned storage. */
static SHELL_NONNULL(1, 2, 3) bool dep_named_fd_name(const dep_token_t *tok,
                                                     const char **name,
                                                     uint32_t *name_len) {
  size_t operator_pos = 0;
  size_t name_after = 0;
  if (!shell_source_parse_named_fd_redirect(tok->start, 0, tok->len,
                                            &operator_pos) ||
      !shell_source_parse_named_fd(tok->start, 0, operator_pos, &name_after) ||
      name_after < 3 || name_after > operator_pos ||
      tok->start[name_after - 1] != '}')
    return false;
  *name = tok->start + 1;
  *name_len = (uint32_t)name_after - 2;
  return true;
}

/* edge is a live graph edge; name borrows name_len source bytes. */
static SHELL_NONNULL(1, 3) void dep_set_named_fd(shell_dep_edge_t *edge,
                                                 bool source, const char *name,
                                                 uint32_t name_len) {
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
  size_t start, end;
  if (!shell_source_file_substitution(content, content_len, &start, &end))
    return false;
  *path = content + start;
  *path_len = (uint32_t)(end - start);
  return true;
}

static const char *extract_subshell_content(const dep_token_t *tok,
                                            uint32_t *out_len);

/* Iterate a borrowed lexical token with one caller-owned scanner initialized
 * to zero for that token. Keeping its state preserves quote/parameter scopes
 * between substitutions without rescanning previously visited source. */
static SHELL_NONNULL(1, 2, 3) shell_source_scan_status_t
    dep_next_word_substitution(const dep_token_t *tok,
                               shell_source_substitution_scan_t *scan,
                               dep_token_t *subshell) {
  shell_source_substitution_kind_t kind;
  size_t start = 0, after = 0;
  shell_source_scan_status_t status = shell_source_next_executable_substitution(
      tok->start, tok->len, scan, &start, &after, &kind);
  if (status == SHELL_SOURCE_SCAN_FOUND) {
    subshell->start = tok->start + start;
    subshell->len = (uint32_t)(after - start);
  }
  return status;
}

/* A plain cd can remain a CWD-only transition. Redirect setup or executable
 * substitution needs an execution endpoint, even when cd_as_cmd is false. */
static bool dep_cd_needs_graph_node(const dep_token_list_t *tokens) {
  for (uint32_t i = 0; i < tokens->count; i++) {
    if (classify_redirect(&tokens->tokens[i]) != DEP_REDIRECT_NONE)
      return true;
    dep_token_t nested = {0};
    shell_source_substitution_scan_t scan = {0};
    if (dep_next_word_substitution(&tokens->tokens[i], &scan, &nested) ==
        SHELL_SOURCE_SCAN_FOUND)
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

static SHELL_NONNULL(3) bool dep_static_word_match_byte(unsigned char byte,
                                                        size_t position,
                                                        void *context) {
  dep_static_word_match_t *match = context;
  if (position >= match->expected_length ||
      byte != (unsigned char)match->expected[position])
    match->matches = false;
  match->position = position + 1;
  return true;
}

/* Shell builtin roles apply after quote removal, but never after runtime
 * expansion. Keep the comparison allocation-free so route resolution can
 * recognize a static spelling such as e'x'ec without copying its word. */
static SHELL_NONNULL(1, 2) bool dep_token_static_equals(const dep_token_t *tok,
                                                        const char *expected) {
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

static SHELL_NONNULL(3) bool dep_static_dash_word_byte(unsigned char byte,
                                                       size_t position,
                                                       void *context) {
  dep_static_dash_word_t *word = context;
  if (position == 0)
    word->starts_dash = byte == '-';
  word->length = position + 1;
  return true;
}

static SHELL_NONNULL(1) bool dep_token_static_starts_dash(
    const dep_token_t *tok) {
  dep_static_dash_word_t word = {0};
  size_t decoded_length = 0;
  return shell_visit_static_word(tok->start, tok->len,
                                 dep_static_dash_word_byte, &word,
                                 &decoded_length) &&
         word.length == decoded_length && word.length > 0 && word.starts_dash;
}

/* A redirect and its operand are not arguments to the builtin. tokens is a
 * prepared command and index names one of its tokens. */
static SHELL_NONNULL(1, 2) bool dep_skip_builtin_redirect(
    const dep_token_list_t *tokens, uint32_t *index) {
  const dep_token_t *word = &tokens->tokens[*index];
  if (classify_redirect(word) == DEP_REDIRECT_NONE)
    return false;
  if (shell_source_redirection_consumes_word(word->start, word->len) &&
      *index + 1 < tokens->count)
    (*index)++;
  return true;
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

static SHELL_NONNULL(3) bool dep_cd_option_byte(unsigned char byte,
                                                size_t position,
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
 * cannot be inferred from source text alone.
 * Required prepared command tokens and outputs; command indexes their
 * effective cd word. Redirect operands have the same ownership as all other
 * builtin arguments, including separated numeric/named duplication targets. */
static SHELL_NONNULL(1, 3, 4) dep_cd_target_t
    cd_target(const dep_token_list_t *tokens, uint32_t command,
              const dep_token_t **operand, bool *physical) {
  bool end_options = false;
  bool dynamic = false;
  bool ambiguous = false;
  const dep_token_t *found = NULL;

  *operand = NULL;
  *physical = false;
  for (uint32_t i = command + 1; i < tokens->count; i++) {
    if (dep_skip_builtin_redirect(tokens, &i))
      continue;

    const dep_token_t *token = &tokens->tokens[i];
    if (dynamic)
      return ambiguous ? DEP_CD_DYNAMIC : DEP_CD_INVALID;
    bool dynamic_word =
        shell_source_argument_has_dynamic_syntax(token->start, token->len);
    ambiguous = ambiguous || dynamic_word;
    /* Bash option parsing does not resume after a pathname. Any further
     * static word is a second argument, including `--` or `-P`; cd then
     * fails without changing directory. An expansion can still affect the
     * argument count, so retain the unknown state in that case. */
    if (found)
      return ambiguous ? DEP_CD_DYNAMIC : DEP_CD_INVALID;
    if (!dynamic_word && dep_token_static_equals(token, ""))
      return DEP_CD_INVALID; /* An empty pathname cannot change directory. */
    if (!end_options && dep_token_static_equals(token, "--")) {
      end_options = true;
      continue;
    }
    if (!end_options && dep_token_static_equals(token, "-")) {
      dynamic = true; /* `cd -` resolves through the runtime OLDPWD. */
      continue;
    }
    if (!end_options && !dynamic_word) {
      dep_cd_option_t option = {.physical = *physical};
      size_t decoded_length = 0;
      if (shell_visit_static_word(token->start, token->len, dep_cd_option_byte,
                                  &option, &decoded_length) &&
          option.valid && decoded_length > 1) {
        if (option.attributes)
          return DEP_CD_DYNAMIC;
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
  *operand = found;
  return DEP_CD_OPERAND;
}

/* Locate the command word after leading assignments and redirections. A
 * wrapper-aware builtin classification must start here: `NAME=x command cd`
 * still changes the invoking shell's CWD, while redirect operands never do.
 * For an argv-less command the same walk covers its complete redirect list:
 * fd 0 (even a self-dup) and named targets select Bash's setup child. Other
 * commands ignore that output. Inline-document descriptors complete it later.
 */
static SHELL_NONNULL(1, 2, 3) uint32_t
    dep_first_command_index(const dep_token_list_t *tokens,
                            uint32_t *assignment_stop, bool *isolated_setup) {
  *assignment_stop = UINT32_MAX;
  *isolated_setup = false;
  for (uint32_t i = 0; i < tokens->count; i++) {
    dep_redirect_t redirect = classify_redirect(&tokens->tokens[i]);
    if (redirect != DEP_REDIRECT_NONE) {
      uint32_t fd = redirect_fd(&tokens->tokens[i], redirect);
      *isolated_setup |= fd == 0 || fd == SHELL_DEP_FD_NAMED;
      if (shell_source_redirection_consumes_word(tokens->tokens[i].start,
                                                 tokens->tokens[i].len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    shell_source_assignment_word_t assignment;
    const dep_token_t *word = &tokens->tokens[i];
    if (!shell_source_parse_scalar_assignment_word(word->start, word->len,
                                                   &assignment)) {
      *assignment_stop = UINT32_MAX; /* Executable prefixes are temporary. */
      return i;
    }
    if (*assignment_stop == UINT32_MAX &&
        (shell_builtin_name_properties(tokens->tokens[i].start,
                                       assignment.name_end) &
         SHELL_VARIABLE_READONLY))
      *assignment_stop = i;
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

/* bytes is a complete, readable decoded record, including for length zero. */
static SHELL_NONNULL(1) bool dep_bytes_look_like_path(const char *bytes,
                                                      size_t length) {
  return memchr(bytes, '/', length) != NULL ||
         memchr(bytes, '.', length) != NULL;
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
 * destination unknowable rather than silently truncating or fabricating one.
 * tok is a parser-owned word; destination has destination_size writable bytes.
 * tilde_expanded and truncated are optional outputs. */
static SHELL_NONNULL(1, 2) bool decode_static_cwd_operand(
    const dep_token_t *tok, char *destination, size_t destination_size,
    bool *tilde_expanded, bool *truncated) {
  if (tilde_expanded)
    *tilde_expanded = false;
  if (truncated)
    *truncated = false;
  shell_source_word_expansion_t expansion = shell_source_word_expansion(
      tok->start, tok->len, SHELL_SOURCE_WORD_ARGUMENT);
  if (destination_size == 0 || expansion.dynamic)
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

  /* Quote removal cannot create a tilde expansion point. Classification also
   * handles escaped line endings before and inside the logical prefix. */
  if (!expansion.leading_tilde)
    return true;
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

/* A group is a pipeline member in its own right. Detect a directly preceding
 * reserved `!` instead of inheriting a nested command's modifier: in
 * `{ ! false | cat; echo; }`, only the inner pipeline is negated. */
static SHELL_NONNULL(1) uint32_t
    group_pipeline_negation_count(const shell_group_t *group) {
  if (group->pipeline_negation_count != 0)
    return group->pipeline_negation_count;
  return (group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 ? 1 : 0;
}

static SHELL_NONNULL(1) bool group_is_pipeline_negated(
    const shell_group_t *group) {
  return (group_pipeline_negation_count(group) & UINT32_C(1)) != 0;
}

static int32_t dep_range_group(const shell_pipeline_index_t *index,
                               uint32_t range_index) {
  uint16_t group = index->containing_group[range_index];
  return group == UINT16_MAX ? -1 : (int32_t)group;
}

/* Recover a compound's aggregate execution scope before evaluating its body.
 * Both incoming and outgoing pipeline membership create one private scope;
 * the body's commands must still share persistent descriptor and CWD state. */
typedef struct {
  bool isolated;
  bool backgrounded;
  bool inherited_background;
  /* Prepared with the compound's redirect operations. Numeric self-dup is
   * a Bash no-op, including on a closed descriptor, and cannot fail setup. */
  bool setup_can_fail;
  /* Parent-before-child preparation makes both lookups constant-time. */
  int32_t isolated_scope;
  int32_t parent_scope;
  uint32_t cwd_offset;
  bool cwd_known;
  bool cwd_absolute;
  uint32_t entry_cwd_offset;
  bool entry_cwd_known;
  bool entry_cwd_absolute;
} dep_group_exec_t;

static void dep_prepare_group_execution(const char *command,
                                        uint32_t command_length,
                                        const shell_parse_result_t *result,
                                        const shell_pipeline_index_t *index,
                                        dep_group_exec_t *groups) {
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    shell_pipeline_group_context_t context = shell_pipeline_group_context(
        command, command_length, result, index, group);
    groups[i].isolated = group->kind == SHELL_GROUP_SUBSHELL ||
                         context.pipeline_member || context.backgrounded;
    groups[i].backgrounded = context.backgrounded;
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_SCOPE_LOOKUP);
    int32_t parent =
        group->parent == UINT16_MAX ? -1 : groups[group->parent].isolated_scope;
    groups[i].parent_scope = parent;
    groups[i].isolated_scope = groups[i].isolated ? (int32_t)i : parent;
    groups[i].inherited_background =
        context.backgrounded || (group->parent != UINT16_MAX &&
                                 groups[group->parent].inherited_background);
  }
}

static bool dep_range_is_backgrounded(const shell_parse_result_t *result,
                                      const shell_pipeline_index_t *index,
                                      const dep_group_exec_t *groups,
                                      uint32_t range_index) {
  if (result->cmds[range_index].features & SHELL_FEAT_BACKGROUND)
    return true;
  int32_t group = dep_range_group(index, range_index);
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_SCOPE_LOOKUP);
  return group >= 0 && groups[group].inherited_background;
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
} heredoc_info_t;

/* The lexical stream supplies the descriptor span of a validated document
 * redirect. Do not reconstruct its word boundary from arbitrary source. */
static SHELL_NONNULL(1) uint32_t
    inline_document_target_fd(const char *cmd, uint32_t prefix_start,
                              uint32_t marker_start) {
  if (prefix_start != marker_start && cmd[prefix_start] == '{')
    return SHELL_DEP_FD_NAMED;
  if (prefix_start == marker_start)
    return 0;
  size_t after = 0;
  uint32_t descriptor = 0;
  bool valid = shell_source_parse_io_number(cmd, prefix_start, marker_start,
                                            &after, &descriptor) ==
                   SHELL_SOURCE_IO_NUMBER_VALID &&
               after == marker_start;
  return valid ? descriptor : 0;
}

/* Called only for a lexically recognized named descriptor prefix. */
static SHELL_NONNULL(1, 4, 5) void inline_document_named_fd_name(
    const char *cmd, uint32_t start, uint32_t marker_start, const char **name,
    uint32_t *name_len) {
  size_t after = 0;
  shell_source_parse_named_fd_at_word_start(cmd, start, marker_start, &after);
  *name = cmd + start + 1;
  *name_len = (uint32_t)after - start - 2;
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
static SHELL_NONNULL(1) uint8_t
    dep_file_name_flags(const char *path, uint32_t path_len) {
  return shell_source_argument_has_dynamic_syntax(path, path_len)
             ? SHELL_DEP_DOC_FLAG_DYNAMIC_NAME
             : SHELL_DEP_DOC_FLAG_NONE;
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

/* Initialize a FILE syntax artifact; its setup/flow edge is a separate phase.
 */
static SHELL_NONNULL(1, 2) void dep_init_file_document(shell_dep_node_t *node,
                                                       const char *path,
                                                       uint32_t path_len) {
  node->type = SHELL_NODE_DOC;
  node->doc = (shell_dep_doc_t){.kind = SHELL_DOC_FILE,
                                .path = path,
                                .path_len = path_len,
                                .flags = dep_file_name_flags(path, path_len)};
}

/* Retain a path-looking ordinary argument as an undirected relation. A
 * non-NULL decoded span is one already validated expansion record and may
 * contain arbitrary argv bytes except NUL, which cannot name a filesystem
 * path and is filtered by the caller. NULL decoded selects source spelling.
 * owner is an installed command; source and command are its unchanged spans
 * and metadata. A decoded path is nonempty and immutable for graph lifetime. */
static SHELL_NONNULL(1, 5, 8) bool dep_add_argument_document(
    shell_dep_graph_t *graph, uint32_t max_nodes, uint32_t max_edges,
    uint32_t owner, const dep_token_t *source, const char *decoded,
    uint32_t decoded_length, const shell_dep_cmd_t *command) {
  if (graph->node_count >= max_nodes || graph->edge_count >= max_edges) {
    graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }
  uint32_t document = graph->node_count++;
  dep_init_file_document(&graph->nodes[document], source->start, source->len);
  shell_dep_doc_t *doc = &graph->nodes[document].doc;
  doc->cwd_offset = command->cwd_known ? command->cwd_offset : 0;
  doc->cwd_known = command->cwd_known;
  doc->cwd_absolute = command->cwd_absolute;
  if (decoded) {
    doc->value = decoded;
    doc->value_len = decoded_length;
    doc->flags = (uint8_t)((doc->flags & ~SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) |
                           SHELL_DEP_DOC_FLAG_RESOLVED_PATH);
  }
  dep_init_edge(&graph->edges[graph->edge_count++], owner, document,
                SHELL_EDGE_ARG, SHELL_DIR_UNDIR, SHELL_DEP_FD_NONE,
                SHELL_DEP_FD_NONE);
  return true;
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
  dep_init_file_document(fn, path, path_len);

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
  dep_init_file_document(node, path, path_len);

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
  dep_init_file_document(node, path, path_len);

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
                           uint32_t value_len, bool append, bool active,
                           uint32_t cmd_idx, uint32_t *status) {
  if (g->node_count >= max_nodes || (active && g->edge_count >= max_edges)) {
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

  if (active) {
    shell_dep_edge_t *e = &g->edges[g->edge_count++];
    dep_init_edge(e, g->node_count - 1, cmd_idx, SHELL_EDGE_ENV,
                  SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
  }

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
                              uint32_t *document_index, bool active) {
  if (owner_idx >= g->node_count || g->node_count >= max_nodes ||
      (active && g->edge_count >= max_edges)) {
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

  if (active) {
    shell_dep_edge_t *edge = &g->edges[g->edge_count++];
    shell_dep_edge_type_t edge_type =
        target_fd == SHELL_DEP_FD_NAMED ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_READ;
    dep_init_edge(edge, document_idx, owner_idx, edge_type, SHELL_DIR_FORWARD,
                  SHELL_DEP_FD_NONE, target_fd);
  }
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
  /* A skipped allocation has no descriptor, unlike a live descriptor with
   * no capability in this direction. Used only in private flow versions. */
  DEP_ROUTE_ABSENT,
  /* No allocation or mutation has established a variable fact in this scope.
   * This is not an explicitly invalidated (DYNAMIC) descriptor variable. */
  DEP_ROUTE_UNSEEN,
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
  /* A stream installed by this recursive substitution, not an external
   * descriptor with the same number. Imports retain its owning graph. */
  DEP_ROUTE_CAPTURE,
  /* Source-aware pipeline resources used before the parent has completed
   * construction. value names the pipeline's input/output execution owner. */
  DEP_ROUTE_PIPE_INPUT,
  DEP_ROUTE_PIPE_OUTPUT,
  /* A variable contains a descriptor number, not a snapshot of its bytes.
   * The target is numeric or a private allocation slot above FD_MAX. Slot
   * facts never contain aliases, so resolution is exactly one indexed hop. */
  DEP_ROUTE_ALIAS,
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
 * name solely because the source happens to be physically wrapped.
 * name is NULL only for a zero-length name. Outputs are required, and
 * *position <= name_len. The returned position remains within that span. */
static SHELL_NONNULL(3, 4) bool dep_fd_name_next_byte(const char *name,
                                                      uint32_t name_len,
                                                      uint32_t *position,
                                                      unsigned char *byte) {
  size_t cursor = *position;
  if (cursor == name_len)
    return false;
  cursor = shell_source_skip_escaped_line_endings(name, name_len, cursor);
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
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
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

/* One-based AVL links into an append-only record array. The index does not
 * own records: comparison callbacks receive the pending key separately.
 * A failed capacity insertion leaves the existing index unchanged. */
typedef struct {
  uint32_t left, right;
  uint8_t height;
} dep_index_node_t;

typedef int (*dep_index_compare_t)(const void *, uint32_t, const void *);

static int dep_fd_ref_compare(dep_fd_ref_t a, dep_fd_ref_t b);

static SHELL_NONNULL(1) unsigned dep_index_height(const dep_index_node_t *nodes,
                                                  uint32_t root) {
  return root ? nodes[root - 1].height : 0;
}

static SHELL_NONNULL(1) int dep_index_balance(dep_index_node_t *nodes,
                                              uint32_t root) {
  dep_index_node_t *node = &nodes[root - 1];
  unsigned left = dep_index_height(nodes, node->left);
  unsigned right = dep_index_height(nodes, node->right);
  node->height = (uint8_t)(1 + (left > right ? left : right));
  return (int)left - (int)right;
}

static SHELL_NONNULL(1) uint32_t
    dep_index_rotate(dep_index_node_t *nodes, uint32_t root, bool left) {
  dep_index_node_t *node = &nodes[root - 1];
  uint32_t next = left ? node->right : node->left;
  dep_index_node_t *pivot = &nodes[next - 1];
  if (left) {
    node->right = pivot->left;
    pivot->left = root;
  } else {
    node->left = pivot->right;
    pivot->right = root;
  }
  dep_index_balance(nodes, root);
  dep_index_balance(nodes, next);
  return next;
}

static SHELL_NONNULL(1) uint32_t
    dep_index_rebalance(dep_index_node_t *nodes, uint32_t root) {
  dep_index_node_t *node = &nodes[root - 1];
  int balance = dep_index_balance(nodes, root);
  if (balance > 1) {
    if (dep_index_balance(nodes, node->left) < 0)
      node->left = dep_index_rotate(nodes, node->left, true);
    return dep_index_rotate(nodes, root, false);
  }
  if (balance < -1) {
    if (dep_index_balance(nodes, node->right) > 0)
      node->right = dep_index_rotate(nodes, node->right, false);
    return dep_index_rotate(nodes, root, true);
  }
  return root;
}

static SHELL_NONNULL(1, 5, 6, 7, 8) uint32_t
    dep_index_insert(dep_index_node_t *nodes, uint32_t root, uint32_t candidate,
                     uint32_t capacity, dep_index_compare_t compare,
                     const void *context, const void *key, uint32_t *match) {
  if (!root) {
    if (candidate > capacity)
      return 0;
    *match = candidate;
    nodes[candidate - 1] = (dep_index_node_t){.height = 1};
    return candidate;
  }
  int order = compare(context, root - 1, key);
  if (!order) {
    *match = root;
    return root;
  }
  dep_index_node_t *node = &nodes[root - 1];
  if (order > 0)
    node->left = dep_index_insert(nodes, node->left, candidate, capacity,
                                  compare, context, key, match);
  else
    node->right = dep_index_insert(nodes, node->right, candidate, capacity,
                                   compare, context, key, match);
  return dep_index_rebalance(nodes, root);
}

/* Remove a known member without moving record identities. The caller keeps
 * record keys unchanged until removal completes. Both helpers receive a
 * nonempty subtree; erase's key is present in that subtree. */
static SHELL_NONNULL(1, 3) uint32_t
    dep_index_extract_first(dep_index_node_t *nodes, uint32_t root,
                            uint32_t *first) {
  dep_index_node_t *node = &nodes[root - 1];
  if (!node->left) {
    *first = root;
    return node->right;
  }
  node->left = dep_index_extract_first(nodes, node->left, first);
  return dep_index_rebalance(nodes, root);
}

static SHELL_NONNULL(1, 3, 4, 5) uint32_t
    dep_index_erase(dep_index_node_t *nodes, uint32_t root,
                    dep_index_compare_t compare, const void *context,
                    const void *key) {
  dep_index_node_t *node = &nodes[root - 1];
  int order = compare(context, root - 1, key);
  if (order > 0)
    node->left = dep_index_erase(nodes, node->left, compare, context, key);
  else if (order < 0)
    node->right = dep_index_erase(nodes, node->right, compare, context, key);
  else {
    if (!node->left)
      return node->right;
    if (!node->right)
      return node->left;
    uint32_t first = 0;
    uint32_t right = dep_index_extract_first(nodes, node->right, &first);
    nodes[first - 1].left = node->left;
    nodes[first - 1].right = right;
    root = first;
  }
  return dep_index_rebalance(nodes, root);
}

#define DEP_MAX_FD_ROUTES (SHELL_DEP_MAX_EDGES + 8)

typedef struct {
  /* A descriptor may support both directions (`<>file`). Keep them separate:
   * a later output route must not erase the input relation to the same file. */
  dep_fd_route_entry_t fd[DEP_MAX_FD_ROUTES];
  uint32_t fd_count;
  /* Keys and dense slots are indexed together. Scope copies retain this
   * index; removals update it instead of rebuilding or rescanning the table. */
  dep_index_node_t index[DEP_MAX_FD_ROUTES];
  uint32_t root;
} dep_owner_routes_t;

typedef struct {
  dep_fd_ref_t fd;
  /* One record per direction and alternative, rather than one representative
   * route per descriptor. A copied route retains its resource's original
   * graph, even across several nested substitutions. */
  dep_fd_route_t route;
  const shell_dep_graph_t *origin;
  uint8_t access;
  /* Joining grandchildren may append provenance records for deferred uses.
   * Those records are not additional bindings inherited by this shell. */
  bool inherited;
} dep_fd_import_t;

#define DEP_MAX_FD_IMPORTS (DEP_MAX_FD_ROUTES * 3)

typedef struct {
  dep_fd_import_t entries[DEP_MAX_FD_IMPORTS];
  dep_index_node_t index[DEP_MAX_FD_IMPORTS];
  uint32_t root;
  uint32_t count;
  /* IFS expansion facts inherited by a nested execution scope. */
  uint32_t ifs;
} dep_fd_imports_t;

typedef struct {
  uint32_t owner;
  uint32_t fd;
  uint8_t access;
  uint32_t import_index;
} dep_fd_import_use_t;

typedef struct dep_route_workspace dep_route_workspace_t;
typedef struct dep_snapshot_frame dep_snapshot_frame_t;

/* Construction-time identity for the descriptor route created by one
 * process-substitution redirect operand.  Several operands may have the same
 * owner and descriptor, so route resolution must use source identity rather
 * than claiming the first compatible graph edge.  This journal is private to
 * one recursive parse; copied child graphs have already resolved their own
 * routes before they are joined. */
typedef struct {
  uint32_t position;
  uint32_t edge;
  dep_fd_ref_t fd;
  uint32_t next;
  uint8_t access;
} dep_process_route_t;

typedef struct {
  dep_process_route_t entries[SHELL_DEP_MAX_EDGES];
  /* One-based owner-local chains. Appending a route never requires a search;
   * snapshot cursors consume only the newly installed operations. */
  uint32_t first[SHELL_DEP_MAX_NODES];
  uint32_t last[SHELL_DEP_MAX_NODES];
  uint32_t count;
} dep_process_route_map_t;

typedef struct {
  uint32_t owner;
  uint32_t fd;
  uint32_t anchor;
  uint8_t access;
} dep_stream_use_t;

/* Phase-local substitution transfers. The incoming bit denotes a path on
 * which no substitution ran; the two low bits denote returning outcomes. */
typedef struct {
  uint8_t phase[3];
  /* Bash executes an argv-less stdin/named-FD redirect list in a child.
   * Assignment commits still belong to the parent. This is syntax-local,
   * independent of whether setup reaches every operation or changes an FD. */
  bool isolated_setup;
  bool setup_expansion_failure;
} dep_expansion_status_t;

/* Uses of a substitution's own capture stream and deferred parent pipelines
 * retain descriptor and execution-context provenance until their join. */
typedef struct {
  dep_stream_use_t capture_uses[SHELL_DEP_MAX_EDGES];
  dep_index_node_t capture_index[SHELL_DEP_MAX_EDGES];
  uint32_t capture_root;
  uint32_t capture_use_count;
  dep_stream_use_t pipe_uses[SHELL_DEP_MAX_EDGES];
  dep_index_node_t pipe_index[SHELL_DEP_MAX_EDGES];
  uint32_t pipe_root;
  uint32_t pipe_use_count;
  /* Semantic expansion facts, independent of effective descriptor edges.
   * Child joins and endpoint compaction use the same node mapping as streams.
   * Recursive results live in the existing caller-owned workspace. */
  uint8_t unresolved_paths[SHELL_DEP_MAX_NODES];
  /* Completed child-shell status, consumed before its stream slot is reused. */
  uint8_t status;
  /* Private join metadata: public graph edges remain the sole externally
   * visible representation of inherited descriptor byte flow. */
  dep_fd_imports_t fd_imports;
  dep_fd_import_use_t fd_import_uses[SHELL_DEP_MAX_EDGES];
  dep_index_node_t fd_import_use_index[SHELL_DEP_MAX_EDGES];
  uint32_t fd_import_use_count;
  uint32_t fd_import_use_root;
  /* Shared scratch is used only between a completed child parse and its join.
   * Recursive parsing therefore never needs to retain another join plan. */
  struct dep_import_join *join;
} dep_subgraph_streams_t;

/* Recursive parses need their graph and deferred-stream result concurrently
 * while the parent joins them. Keep one bounded slot per nesting level in the
 * caller-owned evaluation workspace rather than multiplying large automatic
 * objects (and sanitizer redzones) on the C call stack. */
typedef struct {
  shell_dep_graph_t graph;
  dep_subgraph_streams_t streams;
} dep_recursive_parse_t;

typedef struct dep_import_join {
  dep_fd_imports_t imports;
  uint32_t import_indices[SHELL_DEP_MAX_EDGES];
  dep_stream_use_t endpoints[SHELL_DEP_MAX_EDGES];
  dep_index_node_t endpoint_index[SHELL_DEP_MAX_EDGES];
  dep_stream_use_t pipe_targets[SHELL_DEP_MAX_EDGES];
  dep_index_node_t pipe_target_index[SHELL_DEP_MAX_EDGES];
  uint32_t group_parent[SHELL_DEP_MAX_NODES];
  uint32_t capture_first_child[SHELL_DEP_MAX_NODES];
  uint32_t capture_next_child[SHELL_DEP_MAX_NODES];
  uint32_t capture_first_use[SHELL_DEP_MAX_NODES];
  uint32_t capture_next_use[SHELL_DEP_MAX_EDGES];
  uint32_t capture_resource[SHELL_DEP_MAX_EDGES];
  uint32_t capture_endpoint[SHELL_DEP_MAX_EDGES];
  dep_index_node_t capture_resource_index[SHELL_DEP_MAX_EDGES];
  uint32_t capture_outermost[SHELL_DEP_MAX_EDGES];
} dep_import_join_t;

/* Structural parsing discovers a recursive shell before the enclosing graph
 * has completed route resolution.  Keep the source metadata required to
 * replay only the descriptor state visible at that exact expansion point. */
typedef struct {
  const char *cmd;
  uint32_t cmd_len;
  const shell_parse_result_t *fast;
  const shell_execution_map_t *execution;
  const uint32_t *node_range;
  const uint32_t *range_node;
  const uint32_t *group_node;
  const uint32_t *node_group;
  const dep_group_exec_t *group_exec;
  uint8_t *event_static_status;
  /* Command outcomes after successful setup, before pipeline negation.
   * Prepared alongside the aggregate status; never recovered by rescanning. */
  uint8_t *event_body_status;
  dep_expansion_status_t *expansion_status;
  /* Prepared cd argument analysis, shared by CWD transitions and implicit
   * variable effects. Collapsed commands retain effects without graph nodes. */
  const bool *range_cd_writes;
  /* First setup operation which cannot succeed. Earlier expansions/setup
   * remain observable; the command body and later operands do not run. */
  uint32_t *owner_setup_stop;
  const uint32_t *owner_assignment_stop;
  bool effects_active;
  bool input_unit_recovery;
  dep_process_route_map_t *process_routes;
  dep_route_workspace_t *workspace;
  dep_snapshot_frame_t *snapshot;
  const shell_dep_word_resolver_t *resolver;
  uint8_t *unresolved_paths;
} dep_parse_context_t;

/* Required construction context and a retained CMD/GROUP owner with its
 * inverse map already installed. */
static SHELL_NONNULL(1, 2) bool dep_expansion_cwd_known(
    const shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t owner) {
  if (graph->nodes[owner].type == SHELL_NODE_CMD)
    return graph->nodes[owner].cmd.cwd_known;
  return context->group_exec[context->node_group[owner]].entry_cwd_known;
}

static SHELL_NONNULL(1, 2) bool dep_expansion_cwd_absolute(
    const shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t owner) {
  if (graph->nodes[owner].type == SHELL_NODE_CMD)
    return graph->nodes[owner].cmd.cwd_absolute;
  return context->group_exec[context->node_group[owner]].entry_cwd_absolute;
}

enum {
  DEP_ENDPOINT_TERMINAL_PIPE = 1,
  /* A pipe resource, distinct from a producer-to-consumer collector. It may
   * have only readers, only writers, or both, including a bidirectional open.
   * No direct child-to-parent transfer is implied by sharing this resource. */
  DEP_ENDPOINT_PROCESS_PIPE = 2,
  /* Internal raw-pipe marker, consumed before the public graph is returned. */
  DEP_EDGE_FLAG_PIPE_STDERR = 1 << 7,
  /* Bash's `{name}` allocator searches only the varredir descriptor range. */
  DEP_BASH_VARREDIR_MIN_FD = 10,
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
  /* Private journal fact: live allocation, failed-setup absence, or unknown
   * variable value. Not a capability and never exported to the public graph. */
  DEP_FD_ACCESS_BINDING = 1 << 2,
  /* Private allocator candidates left by reached closes. */
  DEP_FD_ACCESS_AVAILABLE = 1 << 3,
  /* Command-local Bash redirection undo descriptors and the numeric targets
   * already assigned an undo slot. */
  DEP_FD_ACCESS_SAVED = 1 << 5,
  DEP_FD_ACCESS_LOW_STATE = 1 << 6,
  DEP_FD_ACCESS_ENTRY = 1 << 7,
  DEP_FD_ACCESS_PERSISTENT = 1 << 8,
  /* Operation-keyed pre-close version, retained separately for each path. */
  DEP_FD_ACCESS_CLOSE_ENTRY = 1 << 9,
  DEP_FD_ACCESS_CLOSE_SLOTS = 1 << 10,
  DEP_FD_ACCESS_SAVE_FRAME = 1 << 11,
  /* Expansion context, not a descriptor capability. Stored under numeric key
   * zero in the same immutable execution journal; never materialized as I/O. */
  DEP_FD_ACCESS_IFS = 1 << 12,
} dep_fd_access_t;

/* Possible/certain decimal separators suffice for allocated descriptor
 * expansion. Unknown values may contain any digit. SELF records a descriptor
 * allocated into IFS: its unquoted expansion necessarily splits itself. */
enum {
  DEP_IFS_DIGITS = 0x3ff,
  DEP_IFS_CERTAIN_SHIFT = 10,
  DEP_IFS_SELF = 1 << 20
};

enum {
  DEP_STATUS_MAY_SUCCEED = 1u << 0,
  DEP_STATUS_MAY_FAIL = 1u << 1,
  DEP_STATUS_EITHER = DEP_STATUS_MAY_SUCCEED | DEP_STATUS_MAY_FAIL,
  DEP_STATUS_TERMINAL_SUCCESS = 1u << 2,
  DEP_STATUS_TERMINAL_FAILURE = 1u << 3,
  DEP_STATUS_ABORT_FAILURE = 1u << 4,
  DEP_STATUS_TERMINAL =
      DEP_STATUS_TERMINAL_SUCCESS | DEP_STATUS_TERMINAL_FAILURE,
  DEP_STATUS_STOP = DEP_STATUS_TERMINAL | DEP_STATUS_ABORT_FAILURE,
  /* Private command transfer, never a completed-flow outcome: operandless
   * exit terminates with the status of the path that actually reaches it. */
  DEP_STATUS_EXIT_INCOMING = 1u << 5,
  /* Identity transfer for a phase with no executed command substitution. */
  DEP_EXPANSION_INCOMING = 1u << 7,
};

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
  /* Prepared once per resource batch, then reused by every replay. */
  bool resets_descriptor;
  /* Source-local close history, prepared once for static duplication syntax. */
  bool target_closed_locally;
  bool target_unquoted;
  /* FILE expansion is resolved after the source operation can first be
   * indexed. Borrow the live public flag byte so every immutable replay sees
   * the final known-failure fact without rescanning or patching cached ops. */
  const uint8_t *document_flags;
} dep_fd_op_t;

/* Every redirect replaces the descriptor as a whole. Access describes the
 * byte-flow capability of an open, not which half of an old descriptor may
 * survive. Duplication aliases both capabilities regardless of <&/>&. */
static bool dep_fd_op_persists(const dep_fd_op_t *op, bool descriptor_exec,
                               bool named_binding) {
  return descriptor_exec || (named_binding && op->fd == SHELL_DEP_FD_NAMED &&
                             op->kind != DEP_FD_OP_CLOSE);
}

static SHELL_NONNULL(1) bool dep_fd_op_numeric_self_dup(const dep_fd_op_t *op) {
  return op->kind == DEP_FD_OP_DUP && op->fd <= SHELL_DEP_FD_MAX &&
         op->fd == op->target_fd;
}

static SHELL_NONNULL(1) bool dep_fd_op_saves_numeric(const dep_fd_op_t *op) {
  return op->fd <= SHELL_DEP_FD_MAX && !dep_fd_op_numeric_self_dup(op);
}

/* Numeric compound redirects save descriptor slots for restoration at group
 * exit. Named allocations are persistent and self-duplication is a Bash no-op,
 * so neither creates a saved slot. The existing effective group table holds
 * the in-frame state; publication across a frame must leave saved slots alone.
 */
typedef struct {
  /* At most two slots per bounded redirect token (combined output). */
  uint32_t fds[SHELL_DEP_MAX_TOKENS * 2];
  /* UINT32_MAX restores the scope entry. A named close records its private
   * operation key, whose journal facts select each path's pre-close version. */
  uint32_t undo_roots[SHELL_DEP_MAX_TOKENS * 2];
  dep_index_node_t index[SHELL_DEP_MAX_TOKENS * 2];
  uint32_t root;
  uint32_t count;
} dep_redirect_frame_t;

typedef struct {
  uint32_t fds[DEP_MAX_FD_ROUTES];
  uint32_t undo_roots[DEP_MAX_FD_ROUTES];
  dep_index_node_t index[DEP_MAX_FD_ROUTES];
  uint32_t root, count;
} dep_restore_set_t;

typedef struct {
  const shell_parse_result_t *fast;
  const dep_redirect_frame_t *frames;
  int32_t source_group;
  int32_t destination_group;
  const dep_restore_set_t *restored;
} dep_route_publication_t;

typedef struct {
  uint32_t owner;
  dep_fd_op_t op;
} dep_fd_transition_t;

typedef enum {
  DEP_NAMED_EFFECT_TOKEN,
  DEP_NAMED_EFFECT_STATIC_ASSIGNMENT,
  DEP_NAMED_EFFECT_PRINTF_ATTACHED,
} dep_named_effect_kind_t;

typedef struct {
  dep_token_t token;
  dep_named_effect_kind_t kind;
} dep_named_effect_t;

/* Cumulative IFS assignment effects, ordered by commit boundary. An RHS
 * imports only the preceding checkpoint; no assignment prefix is replayed. */
typedef struct {
  const char *after;
  uint32_t value;
  bool append;
} dep_assignment_ifs_t;

/* Borrowed logical identifiers, indexed once per command. */
typedef struct {
  dep_token_t names[SHELL_DEP_MAX_TOKENS];
  dep_index_node_t index[SHELL_DEP_MAX_TOKENS];
  uint32_t root, count;
} dep_prefix_assignment_set_t;

typedef enum {
  DEP_EXEC_NONE,
  DEP_EXEC_DESCRIPTORS,
  DEP_EXEC_OPTION_ERROR,
  DEP_EXEC_REPLACE,
  DEP_EXEC_RUNTIME,
} dep_exec_kind_t;

typedef struct {
  dep_exec_kind_t kind;
  dep_token_t target;
  bool persistent_redirects;
  uint8_t outcomes;
} dep_exec_analysis_t;

/* Prepared command effects borrow immutable source spans. No route
 * publication needs to tokenize or classify the command again. */
typedef struct {
  dep_named_effect_t effects[SHELL_DEP_MAX_TOKENS];
  uint32_t count;
  bool clear;
  bool before_redirect;
  /* cd's implicit variable writes follow successful execution only. Ordinary
   * mutating builtins may write even when they subsequently return failure. */
  bool success_only;
  /* NULL means arbitrary writes can affect every visible binding. A retained
   * index excludes command-prefix bindings restored after this builtin. */
  const dep_prefix_assignment_set_t *restored_prefixes;
  bool ifs_write, ifs_append;
  bool ifs_maybe_unset;
  uint32_t ifs;
} dep_named_mutations_t;

/* cd changes variable contents, not the open descriptors they used to name.
 * Reuse this prepared effect set for retained and collapsed commands. */
static const dep_named_mutations_t dep_cd_mutations = {
    .effects = {{{"PWD", 3}, DEP_NAMED_EFFECT_TOKEN},
                {{"OLDPWD", 6}, DEP_NAMED_EFFECT_TOKEN}},
    .count = 2,
    .success_only = true};

typedef struct {
  uint32_t target;
  uint32_t end;
  int32_t context_group;
  int32_t target_group;
  bool target_scope;
  bool target_shell_state;
} dep_time_boundary_t;

typedef struct {
  dep_fd_route_t routes[SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
  uint32_t count;
  bool ready;
  bool truncated;
} dep_route_set_t;

typedef struct {
  dep_fd_ref_t fd;
  /* Immutable AVL node: versions share untouched subtrees, not a history
   * tail which every lookup must rescan. */
  uint32_t snapshot;
  uint32_t left, right;
  uint8_t height;
  dep_fd_access_t access;
} dep_route_change_t;

typedef struct {
  uint32_t root;
  uint32_t next;
} dep_route_alternative_t;

typedef struct {
  uint32_t left, right, result;
  const dep_owner_routes_t *baseline;
} dep_route_join_t;

/* Route alternatives and path-dependent descriptor identities are separate
 * dimensions.  The public report can expose at most 16 alternative sinks,
 * while a shell may conditionally alter many more unrelated descriptors
 * before one is copied into fd 2. Use an immutable workspace tree so state
 * copies share unchanged subtrees without allocating or copying a full
 * descriptor table per compound
 * group. The journal budgets bounded AVL paths per state update; it retains
 * live descriptor identities, never chains of shadowed changes. Several
 * versions per maximum source operation; exhausting either pool fails closed as
 * graph truncation rather than changing a report route silently. */
#define DEP_ROUTE_OPERATION_CAPACITY                                           \
  (SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS)
#define DEP_ROUTE_CHANGE_CAPACITY (DEP_ROUTE_OPERATION_CAPACITY * 32)
#define DEP_ROUTE_SNAPSHOT_CAPACITY (DEP_ROUTE_OPERATION_CAPACITY * 4)
typedef struct {
  const char *name;
  uint32_t position;
  /* Union for frame membership, not path-dependent restoration facts. */
  uint32_t closed_slots;
} dep_allocation_t;

typedef struct {
  dep_route_change_t entries[DEP_ROUTE_CHANGE_CAPACITY];
  dep_route_alternative_t alternatives[DEP_ROUTE_CHANGE_CAPACITY];
  dep_route_set_t snapshots[DEP_ROUTE_SNAPSHOT_CAPACITY];
  dep_index_node_t snapshot_index[DEP_ROUTE_SNAPSHOT_CAPACITY];
  uint32_t snapshot_root;
  uint32_t count;
  uint32_t alternative_count;
  uint32_t snapshot_count;
  /* Allocation identity is independent of the variable's current spelling.
   * Intern source operations once; paired opens and prefix versions reuse it.
   * Private slot numbers occupy the domain excluded from public io_numbers. */
  dep_allocation_t allocations[DEP_ROUTE_OPERATION_CAPACITY];
  dep_index_node_t allocation_index[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t allocation_root, allocation_count;
  /* Numeric descriptor spellings whose identity can be observed by this
   * parse. Named allocations need exact aliases only at these points; gaps are
   * represented by the operation's private allocation identity. Prepared once
   * from source-indexed operations before final route replay. */
  uint32_t observable_fds[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t observable_fd_count;
  bool observe_undo;
  bool named_closes;
  bool ifs_seen;
  /* Immutable map joins recur at outcome and scope boundaries. Reuse them
   * rather than traversing an unchanged descriptor map at every boundary. */
  dep_route_join_t joins[DEP_ROUTE_OPERATION_CAPACITY];
} dep_route_journal_t;

static SHELL_NONNULL(1, 3) int dep_allocation_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key);

/* Only descriptors whose route changed need an entry. Keeping
 * this sparse avoids multiplying the full descriptor table by every group
 * while still letting later duplications carry alternatives into fd 2. */
/* At most one independently selected route version per retained graph owner.
 * This is an internal control/allocation product, not the public fd-report
 * alternative bound. */
enum { DEP_ROUTE_STATE_CAPACITY = SHELL_DEP_MAX_NODES };

typedef struct {
  /* One-based tree roots in dep_route_journal_t; zero is an empty map. A
   * zero-initialized value represents one empty state. Distinct roots preserve
   * descriptor correlation across control and allocation alternatives until
   * graph routes are materialized. */
  uint32_t root;
  /* One-based immutable list in dep_route_journal_t. */
  uint32_t alternative_head;
  uint8_t alternative_count;
  bool truncated;
  bool correlated;
} dep_route_state_t;

static SHELL_NONNULL(1) uint32_t
    dep_route_state_count(const dep_route_state_t *state) {
  return (uint32_t)state->alternative_count + 1;
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_route_state_root(const dep_route_state_t *state,
                         const dep_route_journal_t *journal, uint32_t index) {
  if (index == 0)
    return state->root;
  uint32_t link = state->alternative_head;
  while (--index)
    link = journal->alternatives[link - 1].next;
  return journal->alternatives[link - 1].root;
}

static SHELL_NONNULL(1, 2) bool dep_route_state_add_root(
    dep_route_state_t *state, dep_route_journal_t *journal, uint32_t root) {
  uint32_t count = dep_route_state_count(state);
  for (uint32_t i = 0; i < count; i++)
    if (dep_route_state_root(state, journal, i) == root)
      return true;
  if (count == DEP_ROUTE_STATE_CAPACITY ||
      journal->alternative_count == DEP_ROUTE_CHANGE_CAPACITY) {
    state->truncated = true;
    return false;
  }
  journal->alternatives[journal->alternative_count] =
      (dep_route_alternative_t){root, state->alternative_head};
  state->alternative_head = ++journal->alternative_count;
  state->alternative_count++;
  return true;
}

static dep_route_state_t dep_route_state_single(uint32_t root) {
  return (dep_route_state_t){.root = root};
}

enum { DEP_PARSE_DEPTH_LIMIT = SHELL_SOURCE_MAX_EXECUTABLE_NESTING };
#define DEP_SNAPSHOT_TABLE_CAPACITY                                            \
  (2 * SHELL_DEP_MAX_NODES + 3 * (DEP_PARSE_DEPTH_LIMIT + 1))

/* Live construction state is separate from final-resolution scratch, but is
 * part of the same evaluation workspace. Tables retain scope/owner entries and
 * changed redirect-operand boundaries, not individual word substitutions.
 * Alternatives share immutable tree roots. A child parse checkpoints these
 * pools and releases only its own suffix. */
typedef struct {
  dep_owner_routes_t routes;
  dep_route_state_t alternatives;
} dep_snapshot_table_t;

typedef struct {
  dep_token_list_t tokens;
  dep_named_mutations_t mutations;
  dep_prefix_assignment_set_t prefix_assignments;
  dep_exec_analysis_t exec;
  /* Assignment-only effects are indexed by identifier. The first commit for
   * a name invalidates its incoming allocation; RHS snapshots need only that
   * commit's position, not a replay or a full descriptor table per value. */
  dep_index_node_t assignment_index[SHELL_DEP_MAX_TOKENS];
  uint32_t assignment_root;
  dep_assignment_ifs_t assignment_ifs[SHELL_DEP_MAX_TOKENS];
  uint32_t assignment_ifs_count, assignment_ifs_cursor;
  uint32_t redirect_entry_table;
  dep_fd_op_t ops[SHELL_DEP_MAX_TOKENS * 3];
  dep_index_node_t op_index[SHELL_DEP_MAX_TOKENS * 3];
  uint32_t op_root;
  /* Operand checkpoints and deferred heredoc boundaries share the owner's
   * incoming table. Append-only operations are consumed only over the delta
   * between checkpoints, never by replaying an entire redirect prefix. */
  uint32_t checkpoint_position[SHELL_DEP_MAX_TOKENS * 3];
  uint32_t checkpoint_table[SHELL_DEP_MAX_TOKENS * 3];
  dep_index_node_t checkpoint_index[SHELL_DEP_MAX_TOKENS * 3];
  uint32_t checkpoint_root, checkpoint_count;
  uint32_t op_count;
  uint32_t edge_cursor;
  uint32_t process_route_cursor;
  bool deferred_document;
  bool prepared;
} dep_snapshot_source_t;

typedef struct {
  uint32_t owner;
  uint32_t start;
} dep_ordered_owner_t;

#define DEP_EXECUTION_EVENT_CAPACITY (SHELL_MAX_GROUPS + SHELL_MAX_SUBCOMMANDS)

/* A bounded product of execution outcome and lexical CWD. Distinct outcomes
 * must not lose their directory correlation before an AND-OR join. */
typedef struct {
  uint32_t offset;
  bool known, absolute;
} dep_cwd_state_t;

typedef struct {
  dep_cwd_state_t state[5];
  uint8_t mask;
} dep_cwd_flow_t;

/* Outcomes share immutable route/binding versions, not five full descriptor
 * tables per event. Only paths selected by the next connector are joined. */
typedef struct {
  dep_route_state_t state[5];
  uint8_t mask;
} dep_fd_flow_t;

typedef struct {
  dep_fd_flow_t scope[SHELL_MAX_GROUPS + 1];
  dep_fd_flow_t entry[DEP_EXECUTION_EVENT_CAPACITY];
  dep_route_state_t selected[DEP_EXECUTION_EVENT_CAPACITY];
  dep_fd_flow_t setup_failure[SHELL_MAX_GROUPS];
  uint32_t pipeline_event[SHELL_MAX_GROUPS + 1];
  uint32_t input_unit;
} dep_fd_stream_t;

/* Private status cursor over the existing execution events. Group completion
 * replaces its provisional status with its body's final AND-OR result. Empty
 * or collapsed stages stay unknown; no source or graph rescanning is needed. */
typedef struct {
  uint8_t status[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t execution[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t scoped_execution[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t entry_status[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t incoming[SHELL_MAX_GROUPS];
  uint32_t last[SHELL_MAX_GROUPS + 1];
  uint32_t group_event[SHELL_MAX_GROUPS];
  uint32_t active[SHELL_MAX_GROUPS];
  uint32_t depth, cursor;
} dep_control_stream_t;

/* Original edges are immutable during effective-route resolution. Build
 * source-ordered owner lists once, then visit only that owner's operations. */
typedef struct {
  uint32_t io_head[SHELL_DEP_MAX_NODES];
  uint32_t named_head[SHELL_DEP_MAX_NODES];
  uint32_t io_next[SHELL_DEP_MAX_EDGES];
  uint32_t pipe_out[SHELL_DEP_MAX_NODES];
  uint32_t pipe_in[SHELL_DEP_MAX_NODES];
  uint32_t pipe_next_out[SHELL_DEP_MAX_EDGES];
  uint32_t pipe_next_in[SHELL_DEP_MAX_EDGES];
  bool private_execution[SHELL_DEP_MAX_NODES];
  bool effective_document[SHELL_DEP_MAX_EDGES];
} dep_owner_edge_index_t;

struct dep_snapshot_frame {
  /* Append-only construction edges are indexed once across all owners.
   * One-based links let the frame's zero initialization represent empty lists.
   */
  uint32_t edge_cursor;
  uint32_t io_head[SHELL_DEP_MAX_NODES], io_tail[SHELL_DEP_MAX_NODES];
  uint32_t io_next[SHELL_DEP_MAX_EDGES];
  dep_ordered_owner_t owners[DEP_EXECUTION_EVENT_CAPACITY];
  uint32_t previous_same_scope[DEP_EXECUTION_EVENT_CAPACITY];
  uint32_t event_index[DEP_EXECUTION_EVENT_CAPACITY];
  uint32_t owner_count;
  uint32_t cursor;
  uint32_t persistent[SHELL_MAX_GROUPS + 1];
  dep_redirect_frame_t redirect_frames[SHELL_MAX_GROUPS];
  dep_control_stream_t control;
  uint8_t local_execution[SHELL_DEP_MAX_NODES];
  uint8_t execution[SHELL_DEP_MAX_NODES];
  uint32_t current_table;
  uint32_t current_owner;
  uint32_t cached_entry[SHELL_DEP_MAX_NODES];
  uint32_t prepared_source[SHELL_DEP_MAX_NODES];
  uint32_t active_groups[SHELL_MAX_GROUPS];
  uint32_t active_group_count;
  bool initialized;
  bool control_initialized;
  dep_fd_stream_t fd_stream;
  uint32_t cwd_groups[SHELL_MAX_GROUPS];
  uint32_t cwd_depth;
  dep_cwd_flow_t cwd_scope[SHELL_MAX_GROUPS + 1];
  dep_cwd_flow_t cwd_entry[DEP_EXECUTION_EVENT_CAPACITY];
  /* Biased source event of each scope's current pipeline entry. All stages
   * share its selected CWD and skipped alternatives; no stage-chain walks. */
  uint32_t cwd_pipeline_event[SHELL_MAX_GROUPS + 1];
  uint32_t cwd_input_unit;
  bool cwd_initialized;
};

/* The effective-route pass needs the final descriptor view for every graph
 * owner while it materializes routes, but it must neither reserve this bound
 * on every caller stack nor allocate it implicitly. Callers provide one
 * reusable workspace for the duration of a parse. Isolated descriptor scopes
 * remain lazy overlays because most commands have none. */
struct dep_route_workspace {
  dep_import_join_t import_join;
  /* A publication finishes before any recursive parse. Reuse this indexed
   * restoration view for concrete and alternative route publication. */
  dep_restore_set_t restored;
  dep_snapshot_table_t snapshot_tables[DEP_SNAPSHOT_TABLE_CAPACITY];
  uint32_t snapshot_table_count;
  dep_route_journal_t snapshot_journal;
  dep_snapshot_frame_t snapshot_frames[DEP_PARSE_DEPTH_LIMIT + 1];
  /* One additional slot receives the rejected parse that exceeds the public
   * nesting limit. Index zero is unused because the root graph is caller
   * storage. */
  dep_recursive_parse_t recursive[DEP_PARSE_DEPTH_LIMIT + 2];
  dep_snapshot_source_t snapshot_sources[SHELL_DEP_MAX_NODES];
  uint32_t snapshot_source_count;
  dep_owner_routes_t routes[SHELL_DEP_MAX_NODES];
  dep_owner_routes_t owner_initial;
  dep_fd_stream_t fd_stream;
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
  dep_redirect_frame_t group_redirect_frames[SHELL_MAX_GROUPS];
  /* Named setup has a deliberately different lifetime from a numeric FD_OPEN:
   * retain its document only while the resolver's final persistent table still
   * contains a route to it.  Keep this short-lived bookkeeping with the rest
   * of the caller-provided route workspace. */
  bool named_setup_documents[SHELL_DEP_MAX_NODES];
  bool live_named_documents[SHELL_DEP_MAX_NODES];
  shell_dep_edge_t original_edges[SHELL_DEP_MAX_EDGES];
  dep_owner_edge_index_t owner_edges;
  dep_fd_transition_t fd_transitions[SHELL_DEP_MAX_EDGES];
  shell_dep_edge_t pipes[SHELL_DEP_MAX_EDGES];
  /* Destination slices are prepared with the resolved pipe join. Reports
   * consume only their pipe's targets, never search unrelated graph edges. */
  dep_stream_use_t time_pipe_targets[SHELL_DEP_MAX_EDGES];
  uint32_t time_pipe_start[SHELL_DEP_MAX_EDGES];
  uint32_t time_pipe_count[SHELL_DEP_MAX_EDGES];
  uint32_t time_pipe_target_count;
  dep_fd_op_t ops[SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS];
  dep_fd_op_t op_scratch[SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS];
  dep_route_set_t time_reports[SHELL_DEP_MAX_NODES];
  dep_route_set_t persistent_time_routes;
  dep_route_set_t scoped_time_routes[SHELL_MAX_GROUPS];
  bool scoped_time_routes_ready[SHELL_MAX_GROUPS];
  dep_route_set_t group_time_routes[SHELL_MAX_GROUPS];
  bool group_time_routes_ready[SHELL_MAX_GROUPS];
  dep_route_state_t persistent_route_state;
  dep_route_state_t scoped_route_state[SHELL_MAX_GROUPS];
  dep_route_state_t group_route_state[SHELL_MAX_GROUPS];
  dep_route_state_t group_shell_route_state[SHELL_MAX_GROUPS];
  dep_route_journal_t route_journal;
  /* Effective read/write alternatives at each owner, including command-local
   * redirects. This reuses the descriptor journal so ordinary byte-flow and
   * shell-owned timing reports cannot disagree at conditional joins. */
  dep_route_state_t owner_route_state[SHELL_DEP_MAX_NODES];
  dep_route_set_t group_shell_time_routes[SHELL_MAX_GROUPS];
  bool group_shell_time_routes_ready[SHELL_MAX_GROUPS];
  uint32_t original_edge_count;
  uint32_t pipe_count;
};

size_t shell_dep_workspace_alignment(void) {
  return _Alignof(dep_route_workspace_t);
}

bool shell_dep_workspace_size(const shell_dep_limits_t *limits,
                              size_t *workspace_size) {
  (void)limits;

  *workspace_size = sizeof(dep_route_workspace_t);
  return true;
}

bool shell_dep_resolved_workspace_size(size_t command_length,
                                       const shell_dep_limits_t *limits,
                                       size_t *workspace_size) {
  size_t cache_size, graph_size;
  *workspace_size = 0;
  size_t alignment = shell_dep_workspace_alignment();
  if (!shell_expand_cache_size(command_length, &cache_size) ||
      !shell_dep_workspace_size(limits, &graph_size) ||
      cache_size > SIZE_MAX - graph_size - alignment)
    return false;
  *workspace_size = cache_size + graph_size + alignment;
  return true;
}

/* limits owns the validated workspace inherited from the root parse. The
 * requested depth is in [1, DEP_PARSE_DEPTH_LIMIT + 1]; the last slot is used
 * only to return the documented over-depth parse error atomically. */
static SHELL_NONNULL(1) dep_recursive_parse_t *dep_recursive_parse_prepare(
    const shell_dep_limits_t *limits, uint32_t depth) {
  dep_route_workspace_t *workspace = limits->workspace;
  dep_recursive_parse_t *frame = &workspace->recursive[depth];
  memset(frame, 0, sizeof(*frame));
  return frame;
}

/* Recursive callers build inherited descriptor facts directly in the child
 * stream's import table. Preserve that one field while clearing the child's
 * output journals; non-aliasing root callers retain the ordinary copy-in
 * contract. */
static SHELL_NONNULL(1) void dep_subgraph_streams_begin(
    dep_subgraph_streams_t *streams, const dep_fd_imports_t *imports) {
  if (imports == &streams->fd_imports) {
    const size_t imports_begin = offsetof(dep_subgraph_streams_t, fd_imports);
    const size_t imports_end = imports_begin + sizeof(streams->fd_imports);
    memset(streams, 0, imports_begin);
    memset((char *)streams + imports_end, 0, sizeof(*streams) - imports_end);
    streams->status = DEP_STATUS_MAY_SUCCEED;
    return;
  }
  memset(streams, 0, sizeof(*streams));
  streams->status = DEP_STATUS_MAY_SUCCEED;
  if (imports)
    streams->fd_imports = *imports;
}

static bool dep_is_execution_node(const shell_dep_graph_t *graph,
                                  uint32_t node) {
  return node < graph->node_count &&
         (graph->nodes[node].type == SHELL_NODE_CMD ||
          graph->nodes[node].type == SHELL_NODE_GROUP);
}

static SHELL_NONNULL(1, 3) int dep_route_key_compare(const void *context,
                                                     uint32_t index,
                                                     const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  const dep_owner_routes_t *routes = context;
  return dep_fd_ref_compare(routes->fd[index].fd, *(const dep_fd_ref_t *)key);
}

static SHELL_NONNULL(1) const dep_fd_route_entry_t *dep_route_find(
    const dep_owner_routes_t *routes, dep_fd_ref_t fd) {
  uint32_t root = routes->root;
  while (root) {
    int order = dep_route_key_compare(routes, root - 1, &fd);
    if (!order)
      return &routes->fd[root - 1];
    root = order > 0 ? routes->index[root - 1].left
                     : routes->index[root - 1].right;
  }
  return NULL;
}

static SHELL_NONNULL(1) dep_fd_route_entry_t *dep_route_slot(
    dep_owner_routes_t *routes, dep_fd_ref_t fd, bool create) {
  if (!create) {
    const dep_fd_route_entry_t *found = dep_route_find(routes, fd);
    return found ? &routes->fd[found - routes->fd] : NULL;
  }
  uint32_t candidate = routes->fd_count + 1, match = 0;
  routes->root = dep_index_insert(routes->index, routes->root, candidate,
                                  DEP_MAX_FD_ROUTES, dep_route_key_compare,
                                  routes, &fd, &match);
  if (!match)
    return NULL;
  if (match == candidate)
    routes->fd[routes->fd_count++] = (dep_fd_route_entry_t){
        fd, {DEP_ROUTE_INHERITED, fd.value}, {DEP_ROUTE_INHERITED, fd.value}};
  return &routes->fd[match - 1];
}

/* slot names an existing record. Order is not semantic: swap the last record
 * into its hole and update just those two indexed identities. */
static SHELL_NONNULL(1) void dep_route_remove(dep_owner_routes_t *routes,
                                              uint32_t slot) {
  dep_fd_ref_t fd = routes->fd[slot].fd;
  routes->root = dep_index_erase(routes->index, routes->root,
                                 dep_route_key_compare, routes, &fd);
  uint32_t last = routes->fd_count - 1;
  if (slot != last) {
    fd = routes->fd[last].fd;
    routes->root = dep_index_erase(routes->index, routes->root,
                                   dep_route_key_compare, routes, &fd);
    routes->fd[slot] = routes->fd[last];
    uint32_t match = 0;
    routes->root = dep_index_insert(routes->index, routes->root, slot + 1,
                                    DEP_MAX_FD_ROUTES, dep_route_key_compare,
                                    routes, &fd, &match);
  }
  routes->fd_count--;
}

static SHELL_NONNULL(1) bool dep_route_assign(dep_owner_routes_t *routes,
                                              dep_fd_ref_t fd,
                                              dep_fd_access_t access,
                                              dep_fd_route_t route) {
  dep_fd_route_entry_t *slot = dep_route_slot(routes, fd, true);
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
static SHELL_NONNULL(1) bool dep_route_reset(dep_owner_routes_t *routes,
                                             dep_fd_ref_t fd) {
  return dep_route_assign(routes, fd, DEP_FD_ACCESS_BOTH,
                          (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
}

static SHELL_NONNULL(1, 3,
                     4) void dep_import_order(const dep_fd_imports_t *imports,
                                              uint32_t root, uint32_t *order,
                                              uint32_t *count);

/* The syntactic graph carries source-order setup relations by edge index.
 * Import their routes into a nested shell's private state; the joiner later
 * materializes each actual use against the original parent resource.
 * routes is an empty destination; imports may be NULL for a root shell. */
static SHELL_NONNULL(1) bool dep_import_routes(
    dep_owner_routes_t *routes, const dep_fd_imports_t *imports) {
  if (!imports)
    return true;
  uint32_t order[DEP_MAX_FD_IMPORTS], count = 0;
  dep_import_order(imports, imports->root, order, &count);
  for (uint32_t i = 0; i < count;) {
    uint32_t first = order[i++];
    const dep_fd_import_t *item = &imports->entries[first];
    while (i < count && imports->entries[order[i]].access == item->access &&
           dep_fd_ref_equal(imports->entries[order[i]].fd, item->fd)) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
      if (order[i] < first)
        first = order[i];
      i++;
    }
    item = &imports->entries[first];
    if (item->access == DEP_FD_ACCESS_BINDING)
      continue;
    dep_fd_route_entry_t *slot = dep_route_slot(routes, item->fd, true);
    if (!slot)
      return false;
    dep_fd_route_t route = item->origin
                               ? (dep_fd_route_t){DEP_ROUTE_IMPORTED, first}
                               : item->route;
    if (item->access == DEP_FD_ACCESS_READ)
      slot->read_route = route;
    else
      slot->write_route = route;
  }
  return true;
}

static SHELL_NONNULL(1, 3) int dep_fd_import_use_compare(const void *context,
                                                         uint32_t index,
                                                         const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  const dep_subgraph_streams_t *streams = context;
  const dep_fd_import_use_t *a = &streams->fd_import_uses[index], *b = key;
  if (a->owner != b->owner)
    return a->owner < b->owner ? -1 : 1;
  if (a->fd != b->fd)
    return a->fd < b->fd ? -1 : 1;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  const dep_fd_import_t *left = &streams->fd_imports.entries[a->import_index];
  const dep_fd_import_t *right = &streams->fd_imports.entries[b->import_index];
  if (left->origin != right->origin)
    return (uintptr_t)left->origin < (uintptr_t)right->origin ? -1 : 1;
  if (left->route.kind != right->route.kind)
    return left->route.kind < right->route.kind ? -1 : 1;
  return left->route.value < right->route.value
             ? -1
             : left->route.value != right->route.value;
}

/* The recorder establishes uniqueness once. Capacity preflight and join
 * materialization subsequently iterate this same unique plan, with no second
 * deduplication. Keys use resource provenance rather than an import slot:
 * distinct aliases can refer to the same route. */
static SHELL_NONNULL(1) bool dep_record_fd_import_use(
    dep_subgraph_streams_t *streams, uint32_t owner, uint32_t fd,
    dep_fd_access_t access, uint32_t import_index) {
  dep_fd_import_use_t key = {
      .owner = owner, .fd = fd, .access = access, .import_index = import_index};
  uint32_t candidate = streams->fd_import_use_count + 1, match = 0;
  streams->fd_import_use_root = dep_index_insert(
      streams->fd_import_use_index, streams->fd_import_use_root, candidate,
      SHELL_DEP_MAX_EDGES, dep_fd_import_use_compare, streams, &key, &match);
  if (!match)
    return false;
  if (match == candidate)
    streams->fd_import_uses[streams->fd_import_use_count++] = key;
  return true;
}

static int dep_fd_ref_compare(dep_fd_ref_t a, dep_fd_ref_t b) {
  if (a.value != b.value)
    return a.value < b.value ? -1 : 1;
  if (a.value != SHELL_DEP_FD_NAMED)
    return 0;
  uint32_t ap = 0, bp = 0;
  unsigned char ab = 0, bb = 0;
  for (;;) {
    bool av = dep_fd_name_next_byte(a.name, a.name_len, &ap, &ab);
    bool bv = dep_fd_name_next_byte(b.name, b.name_len, &bp, &bb);
    if (av != bv)
      return av ? 1 : -1;
    if (!av)
      return 0;
    if (ab != bb)
      return ab < bb ? -1 : 1;
  }
}

static SHELL_NONNULL(1, 3) int dep_import_compare(const void *context,
                                                  uint32_t index,
                                                  const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  const dep_fd_imports_t *imports = context;
  const dep_fd_import_t *a = &imports->entries[index], *b = key;
  int order = dep_fd_ref_compare(a->fd, b->fd);
  if (order)
    return order;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  if (a->origin != b->origin)
    return (uintptr_t)a->origin < (uintptr_t)b->origin ? -1 : 1;
  if (a->route.kind != b->route.kind)
    return a->route.kind < b->route.kind ? -1 : 1;
  return a->route.value < b->route.value ? -1
                                         : a->route.value != b->route.value;
}

static SHELL_NONNULL(1, 2) int32_t
    dep_merge_fd_import(dep_fd_imports_t *destination,
                        const dep_fd_import_t *source) {
  uint32_t candidate = destination->count + 1, match = 0;
  destination->root = dep_index_insert(
      destination->index, destination->root, candidate, DEP_MAX_FD_IMPORTS,
      dep_import_compare, destination, source, &match);
  if (!match)
    return -1;
  if (match == candidate) {
    destination->entries[destination->count] = *source;
    destination->entries[destination->count++].inherited = false;
  }
  return (int32_t)match - 1;
}

/* In-order import iteration groups bindings by descriptor and access. Records
 * stay in insertion order for provenance IDs; this traversal never scans a
 * descriptor's unrelated imports. */
static SHELL_NONNULL(1, 3,
                     4) void dep_import_order(const dep_fd_imports_t *imports,
                                              uint32_t root, uint32_t *order,
                                              uint32_t *count) {
  if (!root)
    return;
  dep_import_order(imports, imports->index[root - 1].left, order, count);
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  if (imports->entries[root - 1].inherited)
    order[(*count)++] = root - 1;
  dep_import_order(imports, imports->index[root - 1].right, order, count);
}

/* Recursive substitution plumbing owns one standard stream. Do not import a
 * parent redirect for that stream: `$(...)` and `<(...)` capture child stdout,
 * while `>(...)` supplies child stdin. Other persistent descriptors, including
 * stderr and auxiliary numeric FDs, remain available to the child. imports is
 * an initialized substitution snapshot; fd is its captured standard stream and
 * access is READ or WRITE. Capacity exhaustion remains an operational failure.
 */
static SHELL_NONNULL(1) bool dep_fd_import_install_capture(
    dep_fd_imports_t *imports, uint32_t fd, dep_fd_access_t access) {
  dep_fd_ref_t ref = dep_fd_numeric(fd);
  uint8_t present = 0;
  for (uint32_t i = 0; i < imports->count; i++)
    if (imports->entries[i].inherited &&
        dep_fd_ref_equal(imports->entries[i].fd, ref))
      present |= imports->entries[i].access;
  uint32_t missing = (present & DEP_FD_ACCESS_READ ? 0u : 1u) +
                     (present & DEP_FD_ACCESS_WRITE ? 0u : 1u) +
                     (present & DEP_FD_ACCESS_BINDING ? 0u : 1u);
  if (missing > DEP_MAX_FD_IMPORTS - imports->count)
    return false;
  for (uint32_t direction = DEP_FD_ACCESS_READ;
       direction <= DEP_FD_ACCESS_BINDING; direction <<= 1) {
    dep_fd_route_t route =
        direction == DEP_FD_ACCESS_BINDING
            ? (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX}
        : direction == access
            ? (dep_fd_route_t){DEP_ROUTE_CAPTURE, fd}
            : (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
    for (uint32_t i = 0; i < imports->count; i++) {
      dep_fd_import_t *slot = &imports->entries[i];
      if (slot->inherited && dep_fd_ref_equal(slot->fd, ref) &&
          slot->access == direction) {
        slot->route = route;
        slot->origin = NULL;
      }
    }
    if ((present & direction) == 0)
      imports->entries[imports->count++] = (dep_fd_import_t){
          .fd = ref, .route = route, .access = direction, .inherited = true};
  }
  /* Capture replacement changes indexed keys. Rebuild once after the two
   * standard-stream capabilities have been installed, not once per use. */
  imports->root = 0;
  for (uint32_t i = 0; i < imports->count; i++) {
    uint32_t match = 0;
    imports->root = dep_index_insert(imports->index, imports->root, i + 1,
                                     DEP_MAX_FD_IMPORTS, dep_import_compare,
                                     imports, &imports->entries[i], &match);
  }
  return true;
}

static SHELL_NONNULL(1) dep_fd_route_t
    dep_route_get(const dep_owner_routes_t *routes, dep_fd_ref_t fd,
                  dep_fd_access_t access) {
  const dep_fd_route_entry_t *found = dep_route_find(routes, fd);
  if (found) {
    dep_fd_route_t route =
        access == DEP_FD_ACCESS_READ ? found->read_route : found->write_route;
    if (route.kind == DEP_ROUTE_ALIAS) {
      found = dep_route_find(routes, dep_fd_numeric(route.value));
      return found ? (access == DEP_FD_ACCESS_READ ? found->read_route
                                                   : found->write_route)
                   : (dep_fd_route_t){DEP_ROUTE_INHERITED, route.value};
    }
    return route;
  }
  return (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value};
}

static SHELL_NONNULL(1, 3) int dep_stream_compare(const void *context,
                                                  uint32_t index,
                                                  const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  const dep_stream_use_t *uses = context, *a = &uses[index], *b = key;
  if (a->anchor != b->anchor)
    return a->anchor < b->anchor ? -1 : 1;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  if (a->owner != b->owner)
    return a->owner < b->owner ? -1 : 1;
  if (a->fd != b->fd)
    return a->fd < b->fd ? -1 : 1;
  return 0;
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_record_stream_use(
    dep_stream_use_t *uses, uint32_t *count, dep_index_node_t *index,
    uint32_t *root, uint32_t owner, uint32_t fd, dep_fd_access_t access,
    uint32_t anchor) {
  dep_stream_use_t key = {owner, fd, anchor, access};
  uint32_t candidate = *count + 1, match = 0;
  *root = dep_index_insert(index, *root, candidate, SHELL_DEP_MAX_EDGES,
                           dep_stream_compare, uses, &key, &match);
  if (!match)
    return false;
  if (match == candidate)
    uses[(*count)++] = key;
  return true;
}

/* Visit only uses of this parent pipe side. The stream index is ordered by
 * anchor/access first, making this O(log U + matching uses), not a scan of all
 * other pipelines' deferred uses for each pipe. */
static SHELL_NONNULL(1, 6, 7, 8, 9) bool dep_collect_pipe_uses(
    const dep_subgraph_streams_t *streams, uint32_t root, uint32_t anchor,
    dep_fd_access_t access, uint32_t pipe, dep_stream_use_t *uses,
    uint32_t *count, dep_index_node_t *index, uint32_t *output_root) {
  if (!root)
    return true;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  const dep_stream_use_t *item = &streams->pipe_uses[root - 1];
  const dep_index_node_t *node = &streams->pipe_index[root - 1];
  if (item->anchor > anchor ||
      (item->anchor == anchor && item->access > access))
    return dep_collect_pipe_uses(streams, node->left, anchor, access, pipe,
                                 uses, count, index, output_root);
  if (item->anchor < anchor ||
      (item->anchor == anchor && item->access < access))
    return dep_collect_pipe_uses(streams, node->right, anchor, access, pipe,
                                 uses, count, index, output_root);
  return dep_collect_pipe_uses(streams, node->left, anchor, access, pipe, uses,
                               count, index, output_root) &&
         dep_record_stream_use(uses, count, index, output_root, item->owner,
                               item->fd, access, pipe) &&
         dep_collect_pipe_uses(streams, node->right, anchor, access, pipe, uses,
                               count, index, output_root);
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
                                   dep_fd_access_t *access,
                                   bool *target_unquoted) {
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
  *target_unquoted = false;
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
    *target_unquoted = token->start[pos] != '"';
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

static bool
dep_add_prepared_dup_operations(const char *cmd, dep_token_list_t tokens,
                                dep_fd_op_t *ops, uint32_t *op_count,
                                uint32_t op_capacity, bool *invalid) {
  if (invalid)
    *invalid = false;
  for (uint32_t i = 0; i < tokens.count; i++) {
    bool close;
    uint32_t fd;
    uint32_t target_fd;
    dep_fd_access_t access;
    const char *fd_name = NULL;
    uint32_t fd_name_len = 0;
    const char *target_fd_name = NULL;
    uint32_t target_fd_name_len = 0;
    bool target_unquoted = false;
    if (!dep_parse_dup_redirect(&tokens.tokens[i], &fd, &target_fd, &fd_name,
                                &fd_name_len, &target_fd_name,
                                &target_fd_name_len, &close, &access,
                                &target_unquoted)) {
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
        target_unquoted = target->start[0] != '"';
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
        false,
        false,
        target_unquoted,
        NULL,
    };
  }
  return true;
}

static bool dep_add_dup_operations(const char *cmd, uint32_t start,
                                   uint32_t length, dep_fd_op_t *ops,
                                   uint32_t *op_count, uint32_t op_capacity,
                                   bool *invalid) {
  dep_token_list_t tokens = {0};
  if (scan_tokens(cmd, start, length, &tokens))
    return false;
  return dep_add_prepared_dup_operations(cmd, tokens, ops, op_count,
                                         op_capacity, invalid);
}

/* Process substitutions are descriptor routes just like file redirects. They
 * have already contributed their graph edges before effective routing runs;
 * retain the source position here so a later redirect, close, or duplicate
 * can replace or copy that route without leaving a stale PIPE edge behind. */
/* NULL cursor replays the complete list. NULL dynamic_edges omits the final
 * resolver's edge-replacement bookkeeping when preparing snapshot operations.
 */
static SHELL_NONNULL(2, 5, 6) bool dep_add_prepared_process_operations(
    uint32_t owner, const dep_process_route_map_t *process_routes,
    uint32_t *cursor, bool *dynamic_edges, dep_fd_op_t *ops, uint32_t *op_count,
    uint32_t op_capacity) {
  uint32_t route = cursor && *cursor != 0
                       ? process_routes->entries[*cursor - 1].next
                       : process_routes->first[owner];
  for (; route != 0; route = process_routes->entries[route - 1].next) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
    const dep_process_route_t *binding = &process_routes->entries[route - 1];
    if (*op_count == op_capacity)
      return false;
    /* Named routes remain visible setup; only numeric routes are replaced
     * by effective byte-flow materialization. */
    if (dynamic_edges)
      dynamic_edges[binding->edge] = binding->fd.value != SHELL_DEP_FD_NAMED;
    ops[(*op_count)++] = (dep_fd_op_t){binding->position,
                                       DEP_FD_OP_DYNAMIC,
                                       binding->fd.value,
                                       SHELL_DEP_FD_NONE,
                                       binding->fd.name,
                                       binding->fd.name_len,
                                       NULL,
                                       0,
                                       binding->edge,
                                       binding->access,
                                       false,
                                       false,
                                       false,
                                       NULL};
    if (cursor)
      *cursor = route;
  }
  return true;
}

static SHELL_NONNULL(1, 3) int dep_fd_operation_compare(const void *context,
                                                        uint32_t index,
                                                        const void *pending) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_fd_op_t *ops = context;
  const dep_fd_op_t *key = pending;
  if (ops[index].pos != key->pos)
    return ops[index].pos < key->pos ? -1 : 1;
  return dep_fd_ref_compare(
      (dep_fd_ref_t){ops[index].fd, ops[index].fd_name, ops[index].fd_name_len},
      (dep_fd_ref_t){key->fd, key->fd_name, key->fd_name_len});
}

/* Stable merge ordering preserves paired opens. Scratch addresses count
 * records and does not alias ops; both belong to the evaluation workspace. */
static SHELL_NONNULL(1, 3) void dep_sort_fd_operations(dep_fd_op_t *ops,
                                                       uint32_t count,
                                                       dep_fd_op_t *scratch) {
  for (uint32_t width = 1; width < count; width *= 2) {
    for (uint32_t begin = 0; begin < count; begin += 2 * width) {
      uint32_t middle = begin + width < count ? begin + width : count;
      uint32_t end = middle + width < count ? middle + width : count;
      uint32_t left = begin, right = middle;
      for (uint32_t out = begin; out < end; out++) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
        scratch[out] =
            right == end || (left < middle && ops[left].pos <= ops[right].pos)
                ? ops[left++]
                : ops[right++];
      }
    }
    memcpy(ops, scratch, count * sizeof(*ops));
  }
}

/* A newly discovered resource contributes all halves of its open together.
 * Existing prepared operations belong to earlier resources or static dup/close
 * syntax, so incremental snapshot preparation indexes only the new suffix.
 * The caller supplies at most SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS
 * operations. Every replay subsequently reads the prepared reset decision. */
static SHELL_NONNULL(1) void dep_prepare_fd_operation_resets(dep_fd_op_t *ops,
                                                             uint32_t count) {
  dep_index_node_t seen[SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS];
  uint32_t root = 0;
  for (uint32_t i = 0; i < count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    uint32_t match = 0;
    root = dep_index_insert(seen, root, i + 1, count, dep_fd_operation_compare,
                            ops, &ops[i], &match);
    ops[i].resets_descriptor =
        match == i + 1 && ops[i].kind != DEP_FD_OP_CLOSE &&
        (ops[i].fd == SHELL_DEP_FD_NAMED || ops[i].kind != DEP_FD_OP_DUP);
  }
}

/* A duplicate following a close in the same redirect list is a runtime
 * failure for that command, but it does not make the source structurally
 * unsupported. Keep the command graph (with its transient setup) instead of
 * conflating that local failure with a later use of a persistently closed
 * descriptor. */
static SHELL_NONNULL(1, 3) int dep_closed_fd_compare(const void *context,
                                                     uint32_t index,
                                                     const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_fd_op_t *ops = context;
  return dep_fd_ref_compare(
      (dep_fd_ref_t){ops[index].fd, ops[index].fd_name, ops[index].fd_name_len},
      *(const dep_fd_ref_t *)key);
}

/* Static dup/close records are in source order. Index the first close of each
 * descriptor once; resource discovery cannot change this syntax-local fact. */
static SHELL_NONNULL(1) void dep_prepare_fd_close_history(dep_fd_op_t *ops,
                                                          uint32_t count) {
  dep_index_node_t closed[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t root = 0;
  for (uint32_t i = 0; i < count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    dep_fd_op_t *op = &ops[i];
    if (op->kind == DEP_FD_OP_CLOSE) {
      dep_fd_ref_t fd = {op->fd, op->fd_name, op->fd_name_len};
      uint32_t match;
      root = dep_index_insert(closed, root, i + 1, count, dep_closed_fd_compare,
                              ops, &fd, &match);
    } else if (op->kind == DEP_FD_OP_DUP) {
      dep_fd_ref_t fd = {op->target_fd, op->target_fd_name,
                         op->target_fd_name_len};
      uint32_t cursor = root;
      while (cursor) {
        int order = dep_closed_fd_compare(ops, cursor - 1, &fd);
        if (!order) {
          op->target_closed_locally = ops[cursor - 1].pos < op->pos;
          break;
        }
        cursor = order > 0 ? closed[cursor - 1].left : closed[cursor - 1].right;
      }
    }
  }
}

static SHELL_NONNULL(1) bool dep_fd_op_self_rebind(const dep_fd_op_t *op) {
  return op->kind == DEP_FD_OP_DUP && op->fd == SHELL_DEP_FD_NAMED &&
         op->target_fd == SHELL_DEP_FD_NAMED &&
         dep_fd_ref_equal((dep_fd_ref_t){op->fd, op->fd_name, op->fd_name_len},
                          (dep_fd_ref_t){op->target_fd, op->target_fd_name,
                                         op->target_fd_name_len});
}

typedef struct {
  bool valid;
  bool saw_dash;
  bool tail_is_argv0;
  bool attached_static;
  bool attached_dynamic;
  bool dynamic;
  bool unresolved;
  bool end_options;
  size_t length;
} dep_exec_option_t;

static SHELL_NONNULL(2) bool dep_exec_option_byte(unsigned char byte,
                                                  void *context) {
  dep_exec_option_t *option = context;
  if (option->unresolved)
    return true;
  size_t position = option->length++;
  if (position == 0) {
    option->saw_dash = byte == '-';
    option->valid = option->saw_dash;
  } else if (option->tail_is_argv0) {
    option->attached_static = true;
  } else if (!option->valid) {
    option->end_options = false;
  } else if (byte == 'c' || byte == 'l') {
    /* no argument */
  } else if (byte == 'a') {
    /* `-a name` and `-aname` are both accepted. The remaining bytes, if any,
     * are argv[0] rather than more option letters. */
    option->tail_is_argv0 = true;
  } else {
    option->end_options = position == 1 && byte == '-';
    option->valid = false;
  }
  return true;
}

static SHELL_NONNULL(1) void dep_exec_option_dynamic(void *context) {
  dep_exec_option_t *option = context;
  option->dynamic = true;
  if (option->tail_is_argv0)
    option->attached_dynamic = true;
  else
    option->unresolved = true;
}

/* tokens is a scanned list and command indexes its command word. The required
 * outputs are writable; optional exec_persistent/wrapper_kind may be NULL. */
static SHELL_NONNULL(1, 3, 4) const dep_token_t *dep_effective_static_builtin(
    const dep_token_list_t *tokens, uint32_t command,
    uint32_t *effective_command, bool *dynamic_target, bool *exec_persistent,
    shell_dep_command_wrapper_t *wrapper_kind);

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
static SHELL_NONNULL(1,
                     2) void dep_copy_routes(dep_owner_routes_t *destination,
                                             const dep_owner_routes_t *source) {
  destination->fd_count = source->fd_count;
  destination->root = source->root;
  memcpy(destination->fd, source->fd,
         source->fd_count * sizeof(destination->fd[0]));
  memcpy(destination->index, source->index,
         source->fd_count * sizeof(destination->index[0]));
}

/* workspace/state are prepared resolver tables and owner is a retained local
 * execution node. Missing route entries have semantic meaning: untouched FD. */
static SHELL_NONNULL(1, 3) void dep_mark_owner_route_touched(
    dep_route_workspace_t *workspace, uint32_t owner,
    const dep_owner_routes_t *state, dep_fd_ref_t fd, dep_fd_access_t access) {
  const dep_fd_route_entry_t *slot = dep_route_find(state, fd);
  if (slot) {
    uint32_t route = (uint32_t)(slot - state->fd);
    unsigned shift = 2 * (route % 4);
    workspace->route_touched[owner][route / 4] =
        (uint8_t)((workspace->route_touched[owner][route / 4] &
                   ~(DEP_FD_ACCESS_BOTH << shift)) |
                  ((uint8_t)access << shift));
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
/* Required prepared tables; ops may be NULL only for an empty span. */
static SHELL_NONNULL(1, 2) bool dep_merge_persistent_named_routes(
    dep_owner_routes_t *persistent, const dep_owner_routes_t *state,
    const dep_fd_op_t *ops, uint32_t op_count) {
  for (uint32_t op = 0; op < op_count; op++) {
    const dep_fd_op_t *item = &ops[op];
    if (!dep_fd_op_persists(item, false, true))
      continue;
    dep_fd_ref_t fd = {SHELL_DEP_FD_NAMED, item->fd_name, item->fd_name_len};
    const dep_fd_route_entry_t *source = dep_route_find(state, fd);
    if (!source)
      continue;
    dep_fd_route_entry_t *destination = dep_route_slot(persistent, fd, true);
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

/* `exec` is a shell builtin for descriptor lifetime, but when it has a
 * command operand it replaces the shell with that external executable. Keep
 * its execution target separate from the builtin-role interpretation above.
 * Redirection operands and `-a`'s argv[0] do not name the executable. */
/* A bounded union of argv roles is reconciled once. A quoted scalar alias is
 * one operand even when empty; an empty attached alias instead exposes the
 * next word to -a. Unknown cardinality retains all applicable paths, but does
 * not stop analysis of later guaranteed operands. Replacement identity and
 * returning outcomes are separate. Redirection setup has its own outcomes. */
static SHELL_NONNULL(1) dep_exec_analysis_t
    dep_analyze_exec(const dep_token_list_t *tokens, uint32_t command,
                     bool persistent) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_EXEC_ANALYSIS);
  dep_exec_analysis_t result = {.kind = DEP_EXEC_DESCRIPTORS,
                                .persistent_redirects = persistent,
                                .outcomes = DEP_STATUS_MAY_SUCCEED};
  enum { OPTIONS = 1u, ALIAS = 2u, OPERAND = 4u };
  unsigned phases = OPTIONS;
  uint8_t outcomes = 0;
  bool have_target = false, unknown_target = false;
  for (uint32_t i = command + 1; i < tokens->count; i++) {
    const dep_token_t *word = &tokens->tokens[i];
    if (classify_redirect(word) != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(word->start, word->len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    dep_exec_option_t option = {0};
    bool single = shell_builtin_visit_single_word(
        word->start, word->len, dep_exec_option_byte, dep_exec_option_dynamic,
        &option);
    unsigned next = 0;
    bool replacement = false;
    if (!single) {
      /* The word can disappear, consume an alias, supply flags, or introduce
       * an executable. No runtime value or expansion result is guessed. */
      if (phases & (OPTIONS | ALIAS)) {
        next |= OPTIONS | ALIAS | OPERAND;
        outcomes |= DEP_STATUS_MAY_FAIL;
      }
      if (phases & OPERAND)
        next |= OPERAND;
      replacement = phases != 0;
      unknown_target |= replacement;
    } else {
      if (phases & ALIAS)
        next |= OPTIONS;
      replacement = (phases & OPERAND) != 0;
      if (phases & OPTIONS) {
        if (option.dynamic && option.unresolved) {
          if (option.length != 0 && !option.saw_dash)
            replacement = true; /* A fixed non-option prefix. */
          else if (option.length > 1 && !option.valid && !option.end_options)
            outcomes |= DEP_STATUS_MAY_FAIL;
          else {
            next |= OPTIONS | ALIAS | OPERAND;
            outcomes |= DEP_STATUS_MAY_FAIL;
            replacement = true;
          }
        } else if (!option.saw_dash || option.length <= 1) {
          replacement = true;
        } else if (option.end_options && option.length == 2) {
          next |= OPERAND;
        } else if (!option.valid) {
          outcomes |= DEP_STATUS_MAY_FAIL;
        } else if (option.tail_is_argv0) {
          if (option.attached_static || option.attached_dynamic)
            next |= OPTIONS;
          if (!option.attached_static)
            next |= ALIAS;
        } else {
          next |= OPTIONS;
        }
      }
      if (replacement) {
        if (option.dynamic ||
            (have_target && result.target.start != word->start))
          unknown_target = true;
        else {
          result.target = *word;
          have_target = true;
        }
      }
    }
    if (replacement)
      outcomes |= DEP_STATUS_TERMINAL;
    phases = next;
    if (!phases)
      break;
  }
  if (phases & ALIAS)
    outcomes |= DEP_STATUS_MAY_FAIL;
  if (phases & (OPTIONS | OPERAND))
    outcomes |= DEP_STATUS_MAY_SUCCEED;
  result.outcomes = outcomes;
  result.persistent_redirects =
      persistent && (outcomes & DEP_STATUS_MAY_SUCCEED) != 0;
  if (outcomes == DEP_STATUS_TERMINAL && !unknown_target && have_target) {
    result.kind = DEP_EXEC_REPLACE;
  } else if (outcomes == DEP_STATUS_MAY_FAIL) {
    result.kind = DEP_EXEC_OPTION_ERROR;
  } else if (outcomes != DEP_STATUS_MAY_SUCCEED) {
    result.kind = DEP_EXEC_RUNTIME;
  }
  return result;
}

/* Every retained CMD has construction metadata recorded before its operands
 * are expanded. GROUP nodes have no exec analysis. */
static SHELL_NONNULL(1) const dep_exec_analysis_t *dep_owner_exec(
    const dep_parse_context_t *context, uint32_t owner) {
  return &context->workspace
              ->snapshot_sources[context->snapshot->prepared_source[owner]]
              .exec;
}

/* A named-FD route stores the physical `{name}` source span, while a builtin
 * operand arrives as an already-isolated shell word. Compare them after their
 * respective quote/continuation removal without allocating a transient name.
 * This lets `unset 'fd'` and `printf -v f'd'` affect exactly `{fd}`. */
typedef struct {
  const char *name;
  uint32_t name_len;
  uint32_t name_position;
  unsigned skip;
  int order;
} dep_named_route_target_t;

static SHELL_NONNULL(3) bool dep_named_route_target_byte(unsigned char byte,
                                                         size_t position,
                                                         void *context) {
  (void)position;
  dep_named_route_target_t *target = context;
  if (target->skip) {
    target->skip--;
    return true;
  }
  unsigned char expected = 0;
  if (!dep_fd_name_next_byte(target->name, target->name_len,
                             &target->name_position, &expected))
    target->order = -1;
  else if (expected != byte)
    target->order = expected < byte ? -1 : 1;
  return target->order == 0;
}

static SHELL_NONNULL(2) bool dep_named_assignment_target_byte(
    unsigned char byte, void *context) {
  return dep_named_route_target_byte(byte, 0, context);
}

/* Mutation collection has already proved a static identifier target. Decode
 * only for indexed comparison, not for repeated validation or materialization.
 * assignment selects just the name preceding = or +=; skip removes printf's
 * already-classified -v prefix. No scan visits unrelated descriptor names. */
static SHELL_NONNULL(1, 2) const dep_fd_route_entry_t *dep_find_named_target(
    const dep_owner_routes_t *routes, const dep_token_t *token, bool assignment,
    unsigned skip) {
  uint32_t root = routes->root;
  while (root) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    dep_fd_ref_t ref = routes->fd[root - 1].fd;
    int order;
    if (ref.value != SHELL_DEP_FD_NAMED)
      order = ref.value < SHELL_DEP_FD_NAMED ? -1 : 1;
    else {
      dep_named_route_target_t target = {
          .name = ref.name, .name_len = ref.name_len, .skip = skip};
      if (assignment) {
        shell_source_decoded_assignment_t ignored;
        (void)shell_source_scan_decoded_assignment(
            token->start, token->len, dep_named_assignment_target_byte, &target,
            &ignored);
      } else {
        size_t ignored;
        (void)shell_visit_decoded_word(token->start, token->len,
                                       dep_named_route_target_byte, &target,
                                       &ignored);
      }
      order = target.order;
      unsigned char trailing = 0;
      if (!order && dep_fd_name_next_byte(ref.name, ref.name_len,
                                          &target.name_position, &trailing))
        order = 1;
    }
    if (!order) {
      return &routes->fd[root - 1];
    }
    root = order > 0 ? routes->index[root - 1].left
                     : routes->index[root - 1].right;
  }
  return NULL;
}

/* Command-prefix assignments are temporary unless the effective declaration
 * builtin promotes the same name into the current shell. Index their logical
 * identifier spellings once while locating the command word, then resolve
 * declaration operands in O(log n) without copying names or rescanning every
 * prefix for every operand. */
static SHELL_NONNULL(1, 3) int dep_prefix_assignment_compare_word(
    const dep_prefix_assignment_set_t *assignments, uint32_t index,
    const dep_token_t *word, bool assignment) {
  const dep_token_t *expected = &assignments->names[index];
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PREFIX_LOOKUP);
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  dep_named_route_target_t target = {.name = expected->start,
                                     .name_len = expected->len};
  if (assignment) {
    shell_source_decoded_assignment_t ignored;
    (void)shell_source_scan_decoded_assignment(word->start, word->len,
                                               dep_named_assignment_target_byte,
                                               &target, &ignored);
  } else {
    size_t ignored;
    (void)shell_visit_decoded_word(
        word->start, word->len, dep_named_route_target_byte, &target, &ignored);
  }
  unsigned char trailing = 0;
  if (!target.order && dep_fd_name_next_byte(target.name, target.name_len,
                                             &target.name_position, &trailing))
    target.order = 1;
  return target.order;
}

static SHELL_NONNULL(1,
                     3) int dep_prefix_assignment_compare(const void *context,
                                                          uint32_t index,
                                                          const void *key) {
  return dep_prefix_assignment_compare_word(context, index, key, false);
}

static SHELL_NONNULL(1, 2) void dep_prefix_assignment_insert(
    dep_prefix_assignment_set_t *assignments, const dep_token_t *name) {
  uint32_t candidate = assignments->count + 1;
  uint32_t match = 0;
  assignments->root = dep_index_insert(
      assignments->index, assignments->root, candidate, SHELL_DEP_MAX_TOKENS,
      dep_prefix_assignment_compare, assignments, name, &match);
  if (match == candidate)
    assignments->names[assignments->count++] = *name;
}

static SHELL_NONNULL(1, 2) bool dep_prefix_assignment_contains_kind(
    const dep_prefix_assignment_set_t *assignments, const dep_token_t *name,
    bool assignment) {
  uint32_t root = assignments->root;
  while (root) {
    int order = dep_prefix_assignment_compare_word(assignments, root - 1, name,
                                                   assignment);
    if (!order)
      return true;
    root = order > 0 ? assignments->index[root - 1].left
                     : assignments->index[root - 1].right;
  }
  return false;
}

static SHELL_NONNULL(1, 2) bool dep_prefix_assignment_contains(
    const dep_prefix_assignment_set_t *assignments, const dep_token_t *name) {
  return dep_prefix_assignment_contains_kind(assignments, name, false);
}

static SHELL_NONNULL(1,
                     2) void dep_remove_named_target(dep_owner_routes_t *routes,
                                                     const dep_token_t *token,
                                                     bool assignment,
                                                     unsigned skip) {
  const dep_fd_route_entry_t *target =
      dep_find_named_target(routes, token, assignment, skip);
  if (target)
    dep_route_remove(routes, (uint32_t)(target - routes->fd));
}

/* Prepared static mutation targets are looked up by key. NULL means that
 * this effect does not change a currently visible named binding. */
static SHELL_NONNULL(1, 2) const dep_fd_route_entry_t *dep_named_effect_target(
    const dep_owner_routes_t *routes, const dep_named_effect_t *effect) {
  return dep_find_named_target(
      routes, &effect->token,
      effect->kind == DEP_NAMED_EFFECT_STATIC_ASSIGNMENT,
      effect->kind == DEP_NAMED_EFFECT_PRINTF_ATTACHED ? 2 : 0);
}

static SHELL_NONNULL(1) bool dep_named_mutation_affects(
    const dep_named_mutations_t *mutations, dep_fd_ref_t fd) {
  return fd.value == SHELL_DEP_FD_NAMED &&
         (!mutations->restored_prefixes ||
          !dep_prefix_assignment_contains(
              mutations->restored_prefixes,
              &(dep_token_t){fd.name, fd.name_len}));
}

static SHELL_NONNULL(1, 2) void dep_clear_named_routes(
    dep_owner_routes_t *routes, const dep_named_mutations_t *mutations) {
  for (uint32_t route = 0; route < routes->fd_count;) {
    if (!dep_named_mutation_affects(mutations, routes->fd[route].fd)) {
      route++;
      continue;
    }
    dep_route_remove(routes, route);
  }
}

/* `command` and `builtin` execute their static target in the current shell.
 * Use Shellsplit's shared wrapper state machine so this graph cannot disagree
 * with the source semantic gate about nested wrappers, inspection forms, or
 * the lifetime of a wrapped `exec` redirect. */
static SHELL_NONNULL(1, 3, 4) const dep_token_t *dep_effective_static_builtin(
    const dep_token_list_t *tokens, uint32_t command,
    uint32_t *effective_command, bool *dynamic_target, bool *exec_persistent,
    shell_dep_command_wrapper_t *wrapper_kind) {
  *dynamic_target = false;
  *effective_command = command;
  if (exec_persistent)
    *exec_persistent = false;
  if (wrapper_kind)
    *wrapper_kind = SHELL_DEP_COMMAND_DIRECT;

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

typedef struct {
  uint32_t digits;
  bool value, format;
} dep_ifs_value_scan_t;

static SHELL_NONNULL(3) bool dep_ifs_value_byte(unsigned char byte,
                                                size_t offset, void *context) {
  (void)offset;
  dep_ifs_value_scan_t *scan = context;
  if (!scan->value) {
    scan->value = byte == '=';
    return true;
  }
  if (byte >= '0' && byte <= '9')
    scan->digits |= 1u << (byte - '0');
  scan->format |= byte == '%' || byte == '\\';
  return true;
}

static uint32_t dep_ifs_known(uint32_t digits) {
  return digits | (digits << DEP_IFS_CERTAIN_SHIFT);
}

static SHELL_NONNULL(1) void dep_ifs_note(dep_named_mutations_t *mutations,
                                          uint32_t value, bool append) {
  if (append && mutations->ifs_write)
    mutations->ifs |= value;
  else {
    mutations->ifs = value;
    mutations->ifs_append = append;
  }
  mutations->ifs_write = true;
}

/* A prepared target is a readable source span, not an optional token slot. */
static SHELL_NONNULL(1) bool dep_effect_is_ifs(const char *text,
                                               uint32_t length,
                                               dep_named_effect_kind_t kind) {
  dep_named_route_target_t target = {
      .name = "IFS",
      .name_len = 3,
      .skip = kind == DEP_NAMED_EFFECT_PRINTF_ATTACHED ? 2 : 0};
  if (kind == DEP_NAMED_EFFECT_STATIC_ASSIGNMENT) {
    shell_source_decoded_assignment_t ignored;
    (void)shell_source_scan_decoded_assignment(
        text, length, dep_named_assignment_target_byte, &target, &ignored);
  } else {
    size_t ignored;
    (void)shell_visit_decoded_word(text, length, dep_named_route_target_byte,
                                   &target, &ignored);
  }
  return !target.order && target.name_position == 3;
}

static SHELL_NONNULL(1, 2) bool dep_ifs_note_assignment(
    dep_named_mutations_t *mutations, const dep_token_t *word) {
  dep_named_effect_t effect = {*word, DEP_NAMED_EFFECT_STATIC_ASSIGNMENT};
  if (!dep_effect_is_ifs(effect.token.start, effect.token.len, effect.kind))
    return false;
  shell_source_decoded_assignment_t assignment;
  (void)shell_source_scan_decoded_assignment(word->start, word->len, NULL, NULL,
                                             &assignment);
  dep_ifs_value_scan_t scan = {0};
  size_t ignored;
  bool known =
      !shell_source_argument_has_dynamic_syntax(word->start, word->len) &&
      shell_visit_decoded_word(word->start, word->len, dep_ifs_value_byte,
                               &scan, &ignored) == SHELL_PROCESS_OK;
  dep_ifs_note(mutations, known ? dep_ifs_known(scan.digits) : DEP_IFS_DIGITS,
               assignment.append);
  return true;
}

/* Prepared tokens are source-ordered, preclassified command words (at most
 * SHELL_DEP_MAX_TOKENS). The required checkpoint destination has that many
 * entries; its borrowed commit boundaries share the tokens' source lifetime. */
static SHELL_NONNULL(1, 2, 3, 4, 5) void dep_prepare_named_mutations(
    dep_named_mutations_t *mutations, const dep_token_list_t *prepared,
    dep_prefix_assignment_set_t *prefix_assignments,
    dep_assignment_ifs_t *assignment_ifs, uint32_t *assignment_ifs_count,
    bool cd_writes) {
  *mutations = (dep_named_mutations_t){0};
  *prefix_assignments = (dep_prefix_assignment_set_t){0};
  *assignment_ifs_count = 0;
  const dep_token_list_t tokens = *prepared;
  dep_named_mutations_t prefix_ifs = {0};
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
    shell_source_assignment_word_t assignment;
    if (!shell_source_parse_scalar_assignment_word(word->start, word->len,
                                                   &assignment)) {
      command = token;
      break;
    }
    dep_token_t name = {word->start, (uint32_t)assignment.name_end};
    dep_prefix_assignment_insert(prefix_assignments, &name);
    if (dep_ifs_note_assignment(&prefix_ifs, word)) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ASSIGNMENT_IFS);
      assignment_ifs[(*assignment_ifs_count)++] = (dep_assignment_ifs_t){
          word->start + word->len, prefix_ifs.ifs, prefix_ifs.ifs_append};
    }
  }

  /* A leading assignment is temporary when a command word follows. In
   * particular, Bash expands that command's redirect list against the
   * pre-existing descriptor-variable binding. An assignment-only command,
   * however, changes the current shell variable and invalidates just that
   * logical named-FD route. Defer mutation until the command shape is known
   * so the two cases cannot be confused. */
  if (command == UINT32_MAX) {
    mutations->before_redirect = true;
    mutations->ifs_write = prefix_ifs.ifs_write;
    mutations->ifs_append = prefix_ifs.ifs_append;
    mutations->ifs = prefix_ifs.ifs;
    for (uint32_t token = 0; token < tokens.count; token++) {
      const dep_token_t *word = &tokens.tokens[token];
      dep_redirect_t redirect = classify_redirect(word);
      if (redirect != DEP_REDIRECT_NONE) {
        if (shell_source_redirection_consumes_word(word->start, word->len) &&
            token + 1 < tokens.count)
          token++;
        continue;
      }
      shell_source_assignment_word_t assignment;
      if (shell_source_parse_scalar_assignment_word(word->start, word->len,
                                                    &assignment))
        mutations->effects[mutations->count++] = (dep_named_effect_t){
            {word->start, assignment.name_end}, DEP_NAMED_EFFECT_TOKEN};
    }
    return;
  }
  bool dynamic_builtin = false;
  uint32_t effective_command = command;
  const dep_token_t *builtin = dep_effective_static_builtin(
      &tokens, command, &effective_command, &dynamic_builtin, NULL, NULL);
  if (dynamic_builtin) {
    mutations->clear = true;
    dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
    return;
  }
  if (!builtin)
    return;
  if (cd_writes) {
    /* Runtime pathname values replace these variable bindings, not their
     * numeric descriptors. Bash retains these implicit writes even through
     * same-name temporary prefixes. cd argument validity was prepared once
     * during construction, before either route stream consumes its effects. */
    *mutations = dep_cd_mutations;
    return;
  }
  shell_source_builtin_kind_t builtin_kind =
      shell_source_static_builtin_kind(builtin->start, builtin->len);
  if (builtin_kind == SHELL_SOURCE_BUILTIN_UNSET) {
    mutations->restored_prefixes = prefix_assignments;
    shell_builtin_unset_t state = {.options = true};
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *target = &tokens.tokens[i];
      unsigned roles =
          shell_builtin_unset_word(&state, target->start, target->len);
      if (!(roles & SHELL_BUILTIN_ROLE_WRITE))
        continue;
      if (roles & SHELL_BUILTIN_ROLE_DYNAMIC) {
        /* Only unresolved runtime expansion can name an unrelated binding.
         * Static invalid targets fail individually; unset continues with its
         * remaining operands. */
        mutations->clear = true;
        mutations->ifs_maybe_unset = !prefix_ifs.ifs_write;
        continue;
      }
      if (!dep_prefix_assignment_contains(prefix_assignments, target)) {
        dep_named_effect_t effect = {*target, DEP_NAMED_EFFECT_TOKEN};
        mutations->effects[mutations->count++] = effect;
        if (dep_effect_is_ifs(effect.token.start, effect.token.len,
                              effect.kind))
          dep_ifs_note(mutations, 0, false);
      }
    }
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_READ) {
    mutations->restored_prefixes = prefix_assignments;
    shell_builtin_read_t state = {.writing = SHELL_READ_OPTIONS};
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *target = &tokens.tokens[i];
      unsigned roles =
          shell_builtin_read_word(&state, target->start, target->len);
      if (!(roles & SHELL_BUILTIN_ROLE_WRITE))
        continue;
      if (roles & SHELL_BUILTIN_ROLE_DYNAMIC) {
        mutations->clear = true;
        if (!prefix_ifs.ifs_write)
          dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
        return;
      }
      if (!dep_prefix_assignment_contains(prefix_assignments, target)) {
        dep_named_effect_t effect = {*target, DEP_NAMED_EFFECT_TOKEN};
        mutations->effects[mutations->count++] = effect;
        if (dep_effect_is_ifs(effect.token.start, effect.token.len,
                              effect.kind))
          dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
      }
    }
    /* Only a surviving writing path with no target can assign REPLY. Missing
     * operands, proven errors and timeout-zero polling cannot. */
    if (shell_builtin_read_default_write(&state) &&
        !dep_prefix_assignment_contains(prefix_assignments,
                                        &(dep_token_t){"REPLY", 5}))
      mutations->effects[mutations->count++] = (dep_named_effect_t){
          {.start = "REPLY", .len = 5}, DEP_NAMED_EFFECT_TOKEN};
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_PRINTF) {
    shell_builtin_printf_t state = {0};
    dep_named_effect_t pending = {0};
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *word = &tokens.tokens[i];
      unsigned roles =
          shell_builtin_printf_word(&state, word->start, word->len);
      if (roles & SHELL_BUILTIN_ROLE_DYNAMIC) {
        mutations->clear = true;
        dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
        return;
      }
      if ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
          state.phase == SHELL_PRINTF_OPTIONS)
        pending =
            (dep_named_effect_t){*word, roles & SHELL_BUILTIN_ROLE_ATTACHED
                                            ? DEP_NAMED_EFFECT_PRINTF_ATTACHED
                                            : DEP_NAMED_EFFECT_TOKEN};
      if (roles & SHELL_BUILTIN_ROLE_WRITE) {
        dep_named_effect_t effect =
            roles & SHELL_BUILTIN_ROLE_FORMAT
                ? pending
                : (dep_named_effect_t){*word, DEP_NAMED_EFFECT_TOKEN};
        mutations->effects[mutations->count++] = effect;
        bool writes_ifs;
        /* FORMAT writes require printf's earlier TARGET event. The shared
         * builtin state machine guarantees pending has that target; symbolic
         * analysis cannot correlate its role bits across loop iterations. */
#ifdef __clang_analyzer__
        __attribute__((suppress))
#endif
        writes_ifs = dep_effect_is_ifs(effect.token.start, effect.token.len,
                                       effect.kind);
        if (writes_ifs) {
          dep_ifs_value_scan_t scan = {.value = true};
          size_t ignored;
          bool known = (roles & SHELL_BUILTIN_ROLE_FORMAT) &&
                       !shell_source_argument_has_dynamic_syntax(word->start,
                                                                 word->len) &&
                       shell_visit_decoded_word(word->start, word->len,
                                                dep_ifs_value_byte, &scan,
                                                &ignored) == SHELL_PROCESS_OK &&
                       !scan.format;
          dep_ifs_note(mutations,
                       known ? dep_ifs_known(scan.digits) : DEP_IFS_DIGITS,
                       false);
        }
      }
    }
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_EXPORT ||
      builtin_kind == SHELL_SOURCE_BUILTIN_DECLARE ||
      builtin_kind == SHELL_SOURCE_BUILTIN_TYPESET ||
      builtin_kind == SHELL_SOURCE_BUILTIN_LOCAL ||
      builtin_kind == SHELL_SOURCE_BUILTIN_READONLY) {
    shell_builtin_declaration_t state = {
        .kind = builtin_kind,
        .options = true,
        .promotes_prefix = builtin_kind == SHELL_SOURCE_BUILTIN_EXPORT};
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *argument = &tokens.tokens[i];
      unsigned roles = shell_builtin_declaration_word(&state, argument->start,
                                                      argument->len);
      if (roles & SHELL_BUILTIN_ROLE_WRITE) {
        /* WRITE is a static scalar assignment; the semantic boundary has
         * already rejected unresolved declaration targets. */
        /* export assignments always modify the outer binding; ordinary
         * declaration assignments modify only a shadowing prefix unless -x
         * promoted that binding. Compare the source-aligned identifier, not
         * the entire assignment operand. */
        if (builtin_kind == SHELL_SOURCE_BUILTIN_EXPORT ||
            (roles & SHELL_BUILTIN_ROLE_PROMOTES_PREFIX) ||
            !dep_prefix_assignment_contains_kind(prefix_assignments, argument,
                                                 true)) {
          mutations->effects[mutations->count++] = (dep_named_effect_t){
              *argument, DEP_NAMED_EFFECT_STATIC_ASSIGNMENT};
          dep_ifs_note_assignment(mutations, argument);
        }
      } else if ((roles & SHELL_BUILTIN_ROLE_PROMOTES_PREFIX) &&
                 dep_prefix_assignment_contains(prefix_assignments, argument)) {
        mutations->effects[mutations->count++] =
            (dep_named_effect_t){*argument, DEP_NAMED_EFFECT_TOKEN};
        if (dep_effect_is_ifs(argument->start, argument->len,
                              DEP_NAMED_EFFECT_TOKEN)) {
          mutations->ifs_write = prefix_ifs.ifs_write;
          mutations->ifs_append = prefix_ifs.ifs_append;
          mutations->ifs = prefix_ifs.ifs;
        }
      }
    }
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_GETOPTS) {
    shell_builtin_getopts_t state = {.phases = SHELL_GETOPTS_OPTIONS};
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_builtin_redirect(&tokens, &i))
        continue;
      const dep_token_t *target = &tokens.tokens[i];
      unsigned roles =
          shell_builtin_getopts_word(&state, target->start, target->len);
      if (roles & SHELL_BUILTIN_ROLE_WRITE) {
        mutations->effects[mutations->count++] =
            (dep_named_effect_t){*target, DEP_NAMED_EFFECT_TOKEN};
        if (dep_effect_is_ifs(target->start, target->len,
                              DEP_NAMED_EFFECT_TOKEN))
          dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
      }
    }
    /* getopts updates its implicit state before assigning the destination,
     * even if that destination is invalid or readonly. These writes persist
     * through temporary command prefixes, just like its explicit assignment.
     * A completed invocation has at least a command, optstring and target,
     * leaving two effect slots beyond its possible destination words. */
    if (state.phases & SHELL_GETOPTS_DATA) {
      mutations->effects[mutations->count++] =
          (dep_named_effect_t){{"OPTIND", 6}, DEP_NAMED_EFFECT_TOKEN};
      mutations->effects[mutations->count++] =
          (dep_named_effect_t){{"OPTARG", 6}, DEP_NAMED_EFFECT_TOKEN};
    }
  }
}

/* Required preclassified effects and destination; phase selects when the
 * command changes its shell's variable bindings. */
static SHELL_NONNULL(1, 2) void dep_apply_named_mutations(
    dep_owner_routes_t *routes, const dep_named_mutations_t *mutations,
    dep_named_mutation_phase_t phase) {
  if (mutations->before_redirect !=
      (phase == DEP_NAMED_MUTATION_BEFORE_REDIRECT))
    return;
  if (mutations->clear) {
    dep_clear_named_routes(routes, mutations);
    return;
  }
  for (uint32_t i = 0; i < mutations->count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
    const dep_named_effect_t *effect = &mutations->effects[i];
    switch (effect->kind) {
    case DEP_NAMED_EFFECT_TOKEN:
      dep_remove_named_target(routes, &effect->token, false, 0);
      break;
    case DEP_NAMED_EFFECT_STATIC_ASSIGNMENT:
      dep_remove_named_target(routes, &effect->token, true, 0);
      break;
    case DEP_NAMED_EFFECT_PRINTF_ATTACHED:
      dep_remove_named_target(routes, &effect->token, false, 2);
      break;
    }
  }
}

/* These owner helpers accept only local execution nodes. A command owner has
 * its range in node_range; a group owner has its descriptor in node_group.
 * Graph construction establishes both inverse maps before any helper call.
 *
 * Return the execution scope for an owner. A subshell, pipeline group, and
 * asynchronous group each receives a private descriptor table which starts as
 * a snapshot of its parent table. A bare pipeline/background command has no
 * shared child list, so `one_shot` keeps its imported state private without
 * allocating a persistent scope. A non-isolated brace group's trailing
 * redirects execute in its enclosing shell. An isolated group's redirects,
 * including a subshell's own trailing list, execute in that group's private
 * shell and must therefore use the group itself as their scope. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6, 8) int32_t dep_owner_named_scope(
    const shell_dep_graph_t *graph, const shell_parse_result_t *fast,
    const shell_pipeline_index_t *pipeline, const dep_group_exec_t *groups,
    const uint32_t *node_range, const uint32_t *node_group, uint32_t owner,
    bool *one_shot) {
  *one_shot = false;

  int32_t group = -1;
  if (graph->nodes[owner].type == SHELL_NODE_CMD) {
    group = dep_range_group(pipeline, node_range[owner]);
    /* Local pipeline/background commands run in another shell even when
     * their enclosing compound already has a private persistent scope.
     * Aggregated cmd.backgrounded includes ancestor background state and
     * must not make every command in an asynchronous group's body one-shot. */
    *one_shot = pipeline->local_process[node_range[owner]];
  } else {
    uint32_t owned = node_group[owner];
    if (groups[owned].isolated) {
      group = (int32_t)owned;
    } else {
      uint16_t parent = fast->groups[owned].parent;
      group = parent == UINT16_MAX ? -1 : (int32_t)parent;
    }
  }
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_SCOPE_LOOKUP);
  return group < 0 ? -1 : groups[group].isolated_scope;
}

/* Return the immediate compound execution owner whose redirect list applies
 * to this owner. This is distinct from the named-FD persistence scope above:
 * an ordinary brace-group redirect is temporary, yet it still supplies the
 * descriptor table inherited by every command in that group. */
static int32_t dep_owner_enclosing_group(const shell_dep_graph_t *graph,
                                         const shell_parse_result_t *fast,
                                         const shell_pipeline_index_t *pipeline,
                                         const uint32_t *node_range,
                                         const uint32_t *node_group,
                                         uint32_t owner) {
  if (graph->nodes[owner].type == SHELL_NODE_CMD)
    return dep_range_group(pipeline, node_range[owner]);
  uint16_t parent = fast->groups[node_group[owner]].parent;
  return parent == UINT16_MAX ? -1 : (int32_t)parent;
}

static bool dep_route_owned_by_enclosing_group(
    const shell_dep_graph_t *graph, const shell_parse_result_t *fast,
    const shell_pipeline_index_t *pipeline, const uint32_t *node_range,
    const uint32_t *node_group, uint32_t owner,
    const shell_dep_edge_t *original) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_OWNERSHIP);
  int32_t enclosing = dep_owner_enclosing_group(graph, fast, pipeline,
                                                node_range, node_group, owner);
  if (enclosing < 0)
    return false;
  /* Parser group intervals are properly nested. Test membership against the
   * immediate enclosing interval rather than walking every ancestor for
   * every inherited descriptor route. node_group maps local GROUP endpoints;
   * imported substitution groups have no membership in this parse. Neither
   * public metadata nor source reparsing is needed. */
  const shell_group_t *inside = &fast->groups[enclosing];
  const uint32_t endpoints[] = {original->from, original->to};
  for (size_t i = 0; i < sizeof(endpoints) / sizeof(endpoints[0]); i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_OWNERSHIP);
    uint32_t endpoint = endpoints[i];
    if (graph->nodes[endpoint].type != SHELL_NODE_GROUP)
      continue;
    uint32_t group = node_group[endpoint];
    if (group == UINT32_MAX)
      continue;
    const shell_group_t *ancestor = &fast->groups[group];
    if (ancestor->start <= inside->start && inside->end <= ancestor->end)
      return true;
  }
  return false;
}

static int32_t dep_named_scope_parent(const shell_parse_result_t *fast,
                                      const dep_group_exec_t *groups,
                                      uint32_t group) {
  (void)fast;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_SCOPE_LOOKUP);
  return groups[group].parent_scope;
}

static uint32_t dep_owner_source_start(const shell_dep_graph_t *graph,
                                       const shell_parse_result_t *fast,
                                       const uint32_t *node_range,
                                       const uint32_t *node_group,
                                       uint32_t owner) {
  if (graph->nodes[owner].type == SHELL_NODE_CMD)
    return fast->cmds[node_range[owner]].start;
  return fast->groups[node_group[owner]].start;
}

/* The private forward index records local connectors. Inherited fast range
 * types can describe the outer group's connector instead of this owner. */
static shell_dep_edge_type_t dep_snapshot_connector_type(uint16_t connector) {
  if (connector == SHELL_TYPE_AND)
    return SHELL_EDGE_AND;
  if (connector == SHELL_TYPE_OR)
    return SHELL_EDGE_OR;
  return SHELL_EDGE_SEQ;
}

static shell_dep_edge_type_t
dep_snapshot_group_predecessor_type(const dep_parse_context_t *context,
                                    uint32_t group) {
  return dep_snapshot_connector_type(
      context->execution->pipeline.group_connector[group]);
}

static int dep_ordered_owner_compare(const void *left, const void *right) {
  const dep_ordered_owner_t *a = left;
  const dep_ordered_owner_t *b = right;
  if (a->start != b->start)
    return a->start < b->start ? -1 : 1;
  if (a->owner != b->owner)
    return a->owner < b->owner ? -1 : 1;
  return 0;
}

typedef enum {
  /* Command arguments expand before the simple command's redirections. */
  DEP_SNAPSHOT_COMMAND_WORD,
  /* An assignment-only RHS sees earlier commits, never its own commit. */
  DEP_SNAPSHOT_ASSIGNMENT_VALUE,
  /* A redirect operand expands while its redirect list is applied
   * left-to-right, after preceding redirects but before its own operation. */
  DEP_SNAPSHOT_REDIRECT_OPERAND,
  /* Internal completion consumes the full setup without exporting imports. */
  DEP_SNAPSHOT_SETUP,
} dep_snapshot_phase_t;

static SHELL_NONNULL(1) uint32_t
    dep_owner_event(const dep_parse_context_t *context, uint32_t owner);

/* Compose one reached word's transfer with its phase, without depending on
 * the order in which assignment and redirect syntax is visited. */
static SHELL_NONNULL(1) void dep_record_substitution_status(
    const dep_parse_context_t *context, uint32_t owner,
    dep_snapshot_phase_t phase, uint8_t status, bool conditional) {
  uint8_t *prior =
      &context->expansion_status[dep_owner_event(context, owner)].phase[phase];
  *prior = status | (conditional ? *prior : 0);
}

/* Expansion errors belong to their executing shell. Null-command assignments
 * expand before the setup child exists; only redirect-phase errors return to
 * the parent as setup failure. The caller has established phase reachability.
 */
static SHELL_NONNULL(1) void dep_record_expansion_error(
    const dep_parse_context_t *context, uint32_t owner,
    dep_snapshot_phase_t phase, uint8_t errors) {
  uint32_t event = dep_owner_event(context, owner);
  dep_expansion_status_t *expansion = &context->expansion_status[event];
  if (phase == DEP_SNAPSHOT_REDIRECT_OPERAND && expansion->isolated_setup)
    expansion->setup_expansion_failure |= errors != 0;
  else
    context->event_static_status[event] |= errors;
}

/* All phases have been expanded for this event. Bash's assignment-only
 * commands expand their assignments before redirects, irrespective of where
 * the assignments occur in the source. A phase with no substitution preserves
 * the preceding status, including conditional expansion alternatives. */
static SHELL_NONNULL(1) uint8_t
    dep_expansion_status(const dep_parse_context_t *context, uint32_t event,
                         uint8_t incoming) {
  const dep_expansion_status_t *expansion = &context->expansion_status[event];
  for (unsigned phase = 0; phase < 3; phase++) {
    uint8_t status = expansion->phase[phase];
    incoming = (status & DEP_STATUS_EITHER) |
               ((status & DEP_EXPANSION_INCOMING) ? incoming : 0);
  }
  return incoming;
}

/* All assignment/redirect phases have been analyzed. A null-command child
 * returns the result of setup, not the status of its last substitution.
 * File/descriptor failures are composed separately by the setup machinery. */
static SHELL_NONNULL(1) uint8_t
    dep_null_command_status(const dep_parse_context_t *context,
                            uint32_t event) {
  const dep_expansion_status_t *expansion = &context->expansion_status[event];
  if (expansion->isolated_setup)
    return DEP_STATUS_MAY_SUCCEED |
           (expansion->setup_expansion_failure ? DEP_STATUS_MAY_FAIL : 0);
  return dep_expansion_status(context, event, DEP_STATUS_MAY_SUCCEED);
}

/* A child terminates locally: exit/expansion abort becomes a return from its
 * substitution, never termination of the enclosing shell. */
static uint8_t dep_substitution_status(uint8_t status) {
  return (status & DEP_STATUS_EITHER) |
         ((status & DEP_STATUS_TERMINAL_SUCCESS) ? DEP_STATUS_MAY_SUCCEED : 0) |
         ((status & (DEP_STATUS_TERMINAL_FAILURE | DEP_STATUS_ABORT_FAILURE))
              ? DEP_STATUS_MAY_FAIL
              : 0);
}

static SHELL_NONNULL(1, 3) int dep_assignment_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  const dep_snapshot_source_t *source = context;
  const dep_token_t *name = &source->mutations.effects[index].token;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
  return dep_fd_ref_compare(
      (dep_fd_ref_t){SHELL_DEP_FD_NAMED, name->start, name->len},
      *(const dep_fd_ref_t *)key);
}

/* Indexed first-commit lookup over preclassified identifier spans. Required
 * source and fd; position is an RHS boundary in the original source. */
static SHELL_NONNULL(1, 2) bool dep_assignment_precedes(
    const dep_snapshot_source_t *source, const char *cmd, dep_fd_ref_t fd,
    uint32_t position) {
  uint32_t root = source->assignment_root;
  while (root) {
    int order = dep_assignment_compare(source, root - 1, &fd);
    if (!order)
      return (uint32_t)(source->mutations.effects[root - 1].token.start - cmd) <
             position;
    root = order > 0 ? source->assignment_index[root - 1].left
                     : source->assignment_index[root - 1].right;
  }
  return false;
}

/* Complete setup after its resources and operand expansions are constructed.
 * This is semantic execution analysis, not validation of the supplied parse.
 * Later snapshots reuse these ordered checkpoints. Optional may_fail receives
 * source-level setup uncertainty (FILE/process opens and nontrivial dup/close
 * operations); definite failures are recorded in owner_setup_stop. */
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_complete_owner_setup(const shell_dep_graph_t *graph,
                             const dep_subgraph_streams_t *streams,
                             const dep_parse_context_t *context, uint32_t owner,
                             bool *may_fail);

static bool dep_is_direct_io_edge(const shell_dep_graph_t *graph,
                                  const shell_dep_edge_t *edge,
                                  uint32_t *owner);
static SHELL_NONNULL(1, 2) uint32_t
    dep_edge_document_index(const shell_dep_graph_t *graph,
                            const shell_dep_edge_t *edge);

static SHELL_NONNULL(1, 2) void dep_snapshot_index_edges(
    const shell_dep_graph_t *graph, dep_snapshot_frame_t *frame) {
  for (; frame->edge_cursor < graph->edge_count; frame->edge_cursor++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_SNAPSHOT_EDGES);
    uint32_t edge = frame->edge_cursor, owner;
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (!dep_is_direct_io_edge(graph, item, &owner)) {
      if (item->type != SHELL_EDGE_FD_OPEN)
        continue;
      uint32_t document;
      if (item->target_fd == SHELL_DEP_FD_NAMED) {
        owner = item->to;
        document = item->from;
      } else if (item->source_fd == SHELL_DEP_FD_NAMED) {
        owner = item->from;
        document = item->to;
      } else {
        continue;
      }
      if (graph->nodes[document].type != SHELL_NODE_DOC)
        continue;
    }
    frame->io_next[edge] = 0;
    if (frame->io_tail[owner])
      frame->io_next[frame->io_tail[owner] - 1] = edge + 1;
    else
      frame->io_head[owner] = edge + 1;
    frame->io_tail[owner] = edge + 1;
  }
}

/* Gather the descriptor operations which have an already-constructed
 * syntactic edge. A nested shell needs the complete state of earlier `exec`
 * redirects, not only dynamically allocated names. */
static SHELL_NONNULL(1,
                     3) int dep_snapshot_operation_compare(const void *context,
                                                           uint32_t index,
                                                           const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_snapshot_source_t *source = context;
  uint32_t pending = *(const uint32_t *)key;
  if (source->ops[index].pos != source->ops[pending].pos)
    return source->ops[index].pos < source->ops[pending].pos ? -1 : 1;
  return index < pending ? -1 : index != pending;
}

/* The operation tree retains stable identities as construction adds resources.
 * Only the requested source interval is visited, including its search paths. */
static SHELL_NONNULL(1, 5, 6) void dep_snapshot_operation_range(
    const dep_snapshot_source_t *source, uint32_t root, uint32_t begin,
    uint32_t end, dep_fd_op_t *ops, uint32_t *count) {
  if (!root)
    return;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_fd_op_t *op = &source->ops[root - 1];
  const dep_index_node_t *node = &source->op_index[root - 1];
  if (op->pos >= begin)
    dep_snapshot_operation_range(source, node->left, begin, end, ops, count);
  if (op->pos >= begin && op->pos < end)
    ops[(*count)++] = *op;
  if (op->pos < end)
    dep_snapshot_operation_range(source, node->right, begin, end, ops, count);
}

/* Bash performs this duplication after all explicit setup, not before operand
 * expansion. The private end position keeps it out of operand checkpoints. */
static dep_fd_op_t dep_pipe_both_operation(void) {
  return (dep_fd_op_t){.pos = UINT32_MAX - 1,
                       .kind = DEP_FD_OP_DUP,
                       .fd = 2,
                       .target_fd = 1,
                       .edge_index = UINT32_MAX,
                       .access = DEP_FD_ACCESS_WRITE,
                       .target_closed_locally = true};
}

/* Construction already owns the complete tokenization of a retained command.
 * Record that bounded value once; later descriptor snapshots must not rescan a
 * narrower fast-parser fragment and silently lose attached redirects. */
static SHELL_NONNULL(1, 3) bool dep_snapshot_record_owner_tokens(
    const dep_parse_context_t *context, uint32_t owner,
    const dep_token_list_t *tokens) {
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_route_workspace_t *workspace = context->workspace;
  uint32_t slot = frame->prepared_source[owner];
  if (slot == UINT32_MAX) {
    if (workspace->snapshot_source_count == SHELL_DEP_MAX_NODES)
      return false;
    slot = workspace->snapshot_source_count++;
    frame->prepared_source[owner] = slot;
    workspace->snapshot_sources[slot] = (dep_snapshot_source_t){0};
    workspace->snapshot_sources[slot].redirect_entry_table = UINT32_MAX;
  }
  workspace->snapshot_sources[slot].tokens = *tokens;
  return true;
}

static SHELL_NONNULL(1) bool dep_owner_pipe_both(
    const dep_parse_context_t *context, uint32_t owner) {
  uint32_t range = context->node_range[owner];
  shell_source_compound_tail_t tail =
      range < context->fast->count
          ? shell_source_parse_compound_tail(context->cmd, context->cmd_len,
                                             context->execution->end[range])
          : context->execution->pipeline.group_tail[context->node_group[owner]];
  return tail.has_pipeline &&
         tail.pipe_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR;
}

static SHELL_NONNULL(1, 2, 4) bool dep_snapshot_fd_operations(
    const shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t owner, dep_snapshot_source_t **prepared) {
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_route_workspace_t *workspace = context->workspace;
  dep_snapshot_index_edges(graph, frame);
  uint32_t slot = frame->prepared_source[owner];
  uint32_t prepared_count =
      slot == UINT32_MAX ? 0 : workspace->snapshot_sources[slot].op_count;
  if (slot == UINT32_MAX) {
    if (workspace->snapshot_source_count == SHELL_DEP_MAX_NODES)
      return false;
    slot = workspace->snapshot_source_count++;
    frame->prepared_source[owner] = slot;
    dep_snapshot_source_t *source = &workspace->snapshot_sources[slot];
    *source = (dep_snapshot_source_t){0};
    source->redirect_entry_table = UINT32_MAX;
  }
  dep_snapshot_source_t *source = &workspace->snapshot_sources[slot];
  if (!source->prepared) {
    if (graph->nodes[owner].type == SHELL_NODE_GROUP) {
      uint32_t group = context->node_group[owner];
      uint32_t start = context->fast->groups[group].end;
      uint32_t length =
          context->execution->pipeline.group_tail[group].redirect_end - start;
      if (scan_tokens(context->cmd, start, length, &source->tokens))
        return false;
    }
    bool invalid_dup = false;
    bool stopped = context->owner_assignment_stop[owner] != UINT32_MAX;
    if ((!stopped &&
         !dep_add_prepared_dup_operations(
             context->cmd, source->tokens, source->ops, &source->op_count,
             sizeof(source->ops) / sizeof(source->ops[0]), &invalid_dup)) ||
        invalid_dup)
      return false;
    if (dep_owner_pipe_both(context, owner)) {
      if (source->op_count == sizeof(source->ops) / sizeof(source->ops[0]))
        return false;
      source->ops[source->op_count++] = dep_pipe_both_operation();
    }
    dep_prepare_fd_close_history(source->ops, source->op_count);
    if (graph->nodes[owner].type == SHELL_NODE_CMD) {
      dep_token_list_t mutations = source->tokens;
      if (stopped)
        mutations.count = context->owner_assignment_stop[owner];
      dep_prepare_named_mutations(
          &source->mutations, &mutations, &source->prefix_assignments,
          source->assignment_ifs, &source->assignment_ifs_count,
          context->range_cd_writes[context->node_range[owner]]);
      if (source->mutations.before_redirect) {
        for (uint32_t effect = 0; effect < source->mutations.count; effect++) {
          const dep_token_t *name = &source->mutations.effects[effect].token;
          dep_fd_ref_t key = {SHELL_DEP_FD_NAMED, name->start, name->len};
          uint32_t match = 0;
          source->assignment_root = dep_index_insert(
              source->assignment_index, source->assignment_root, effect + 1,
              SHELL_DEP_MAX_TOKENS, dep_assignment_compare, source, &key,
              &match);
        }
      }
    }
    source->prepared = true;
  }
  uint32_t cursor = source->edge_cursor
                        ? frame->io_next[source->edge_cursor - 1]
                        : frame->io_head[owner];
  for (; cursor; cursor = frame->io_next[cursor - 1]) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_SNAPSHOT_EDGES);
    uint32_t edge = cursor - 1;
    const shell_dep_edge_t *item = &graph->edges[edge];
    bool input = item->type == SHELL_EDGE_READ ||
                 (item->type == SHELL_EDGE_FD_OPEN && item->to == owner);
    uint32_t document = input ? item->from : item->to;
    const char *spelling = dep_document_source(&graph->nodes[document]);
    if (!spelling ||
        source->op_count == sizeof(source->ops) / sizeof(source->ops[0]))
      return false;
    source->deferred_document =
        source->deferred_document ||
        graph->nodes[document].doc.kind == SHELL_DOC_HEREDOC;
    dep_fd_op_t *operation = &source->ops[source->op_count++];
    *operation = (dep_fd_op_t){
        (uint32_t)(spelling - context->cmd),
        DEP_FD_OP_DOCUMENT,
        input ? item->target_fd : item->source_fd,
        SHELL_DEP_FD_NONE,
        input ? item->target_fd_name : item->source_fd_name,
        input ? item->target_fd_name_len : item->source_fd_name_len,
        NULL,
        0,
        edge,
        input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE,
        false,
        false,
        false,
        NULL};
    operation->document_flags = &graph->nodes[document].doc.flags;
    source->edge_cursor = cursor;
  }
  if (!dep_add_prepared_process_operations(
          owner, context->process_routes, &source->process_route_cursor, NULL,
          source->ops, &source->op_count,
          sizeof(source->ops) / sizeof(source->ops[0])))
    return false;
  if (source->op_count != prepared_count) {
    dep_prepare_fd_operation_resets(source->ops + prepared_count,
                                    source->op_count - prepared_count);
    for (uint32_t i = prepared_count; i < source->op_count; i++) {
      uint32_t match;
      source->op_root =
          dep_index_insert(source->op_index, source->op_root, i + 1,
                           sizeof(source->ops) / sizeof(source->ops[0]),
                           dep_snapshot_operation_compare, source, &i, &match);
    }
  }
  *prepared = source;
  return true;
}
/* ops is the source-ordered interval selected by the operation index. */
static SHELL_NONNULL(1, 2) bool dep_snapshot_apply_fd_operations(
    dep_owner_routes_t *state, const dep_fd_op_t *ops, uint32_t op_count) {
  for (uint32_t i = 0; i < op_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    const dep_fd_op_t *item = &ops[i];
    if (dep_fd_op_numeric_self_dup(item))
      continue;
    dep_fd_ref_t source = {item->fd, item->fd_name, item->fd_name_len};
    dep_fd_ref_t target = {item->target_fd, item->target_fd_name,
                           item->target_fd_name_len};
    bool self_rebind = dep_fd_op_self_rebind(item);
    dep_fd_route_t saved_read = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
    dep_fd_route_t saved_write = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
    if (self_rebind) {
      dep_fd_route_entry_t *slot = dep_route_slot(state, target, false);
      if (!slot)
        return false;
      saved_read = slot->read_route;
      saved_write = slot->write_route;
    }

    if (item->resets_descriptor && !dep_route_reset(state, source))
      return false;

    if (item->kind == DEP_FD_OP_DOCUMENT || item->kind == DEP_FD_OP_DYNAMIC) {
      dep_route_kind_t kind =
          item->kind == DEP_FD_OP_DOCUMENT ? DEP_ROUTE_DOC : DEP_ROUTE_DYNAMIC;
      if (!dep_route_assign(state, source, item->access,
                            (dep_fd_route_t){kind, item->edge_index}))
        return false;
      continue;
    }
    if (item->kind == DEP_FD_OP_CLOSE) {
      if (source.value == SHELL_DEP_FD_NAMED &&
          dep_route_slot(state, source, false) == NULL)
        return false;
      if (!dep_route_assign(state, source, DEP_FD_ACCESS_BOTH,
                            (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX}))
        return false;
      continue;
    }

    if (target.value == SHELL_DEP_FD_NAMED && !self_rebind &&
        dep_route_slot(state, target, false) == NULL)
      return false;
    dep_fd_route_t read =
        self_rebind ? saved_read
                    : dep_route_get(state, target, DEP_FD_ACCESS_READ);
    dep_fd_route_t write =
        self_rebind ? saved_write
                    : dep_route_get(state, target, DEP_FD_ACCESS_WRITE);
    bool closed_locally = item->target_closed_locally;
    if (((item->access & DEP_FD_ACCESS_READ) != 0 &&
         read.kind == DEP_ROUTE_CLOSED && !closed_locally) ||
        ((item->access & DEP_FD_ACCESS_WRITE) != 0 &&
         write.kind == DEP_ROUTE_CLOSED && !closed_locally))
      return false;
    if (!dep_route_assign(state, source, DEP_FD_ACCESS_READ, read) ||
        !dep_route_assign(state, source, DEP_FD_ACCESS_WRITE, write))
      return false;
  }
  return true;
}

static SHELL_NONNULL(1, 2) bool dep_import_route_alternatives(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_fd_imports_t *imports);
static bool dep_publication_restores_fd(const dep_route_publication_t *view,
                                        dep_fd_ref_t fd);
static SHELL_NONNULL(1, 2, 3) dep_route_set_t
    dep_route_state_get_access(const dep_route_state_t *state,
                               const dep_route_journal_t *changes,
                               const dep_owner_routes_t *baseline,
                               dep_fd_ref_t fd, dep_fd_access_t access);
/* Required prepared route tables and journal. ops addresses op_count prepared
 * operations; NULL is permitted only for an empty operation span.
 */
static SHELL_NONNULL(1, 2, 3) bool dep_route_state_apply(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_owner_routes_t *baseline, const dep_fd_op_t *ops,
    uint32_t op_count, bool begin_frame);
static SHELL_NONNULL(1, 2, 3) dep_route_set_t
    dep_fd_fact(const dep_route_state_t *state,
                const dep_route_journal_t *journal,
                const dep_owner_routes_t *baseline, dep_fd_ref_t fd,
                dep_fd_access_t access);
static SHELL_NONNULL(1, 2, 3) dep_route_set_t
    dep_fd_raw_fact(const dep_route_state_t *state,
                    const dep_route_journal_t *journal,
                    const dep_owner_routes_t *baseline, dep_fd_ref_t fd,
                    dep_fd_access_t access);
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool dep_fd_materialize_from(
    const dep_route_state_t *state, const dep_route_state_t *previous,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_owner_routes_t *source, dep_owner_routes_t *destination);
static SHELL_NONNULL(1, 2, 3, 4) uint8_t
    dep_fd_operation_outcomes(const dep_fd_op_t *op,
                              const dep_route_state_t *state,
                              const dep_route_journal_t *journal,
                              const dep_owner_routes_t *baseline);
/* Required prepared tables and journal. ops may be NULL only when op_count is
 * zero. Conditional joins and redirect-frame restoration belong to the
 * outcome stream, not to publication of one completed setup. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_route_state_publish(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_owner_routes_t *executed, const dep_route_state_t *executed_state,
    const dep_owner_routes_t *entry_baseline, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec, bool named_binding);
static bool dep_restore_continuation_route_state(
    dep_route_state_t *continuation, dep_route_journal_t *changes,
    const dep_route_state_t *destination_state,
    const dep_owner_routes_t *destination,
    const dep_route_publication_t *publication);

static SHELL_NONNULL(1, 2) bool dep_route_state_store_access(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes);
static void dep_route_set_set(dep_route_set_t *snapshot, dep_fd_route_t route);

static uint32_t dep_ifs_join(uint32_t left, uint32_t right) {
  uint32_t possible = (left | right) & DEP_IFS_DIGITS;
  uint32_t certain = (left & right) &
                     ((DEP_IFS_DIGITS << DEP_IFS_CERTAIN_SHIFT) | DEP_IFS_SELF);
  return possible | certain;
}

static SHELL_NONNULL(1, 2, 3) uint32_t
    dep_ifs_get(const dep_route_state_t *state,
                const dep_route_journal_t *journal,
                const dep_owner_routes_t *baseline) {
  if (!journal->ifs_seen)
    return 0;
  /* Preserve allocation/control correlation until this actual expansion
   * boundary. The digit fact itself needs only a bounded lattice, not a list
   * of IFS strings or descriptor alternatives. */
  uint32_t value = 0;
  for (uint32_t path = 0; path < dep_route_state_count(state); path++) {
    dep_route_state_t one =
        dep_route_state_single(dep_route_state_root(state, journal, path));
    dep_route_set_t fact = dep_fd_raw_fact(
        &one, journal, baseline, dep_fd_numeric(0), DEP_FD_ACCESS_IFS);
    uint32_t next = fact.routes[0].value;
    value = path ? dep_ifs_join(value, next) : next;
  }
  return value;
}

static SHELL_NONNULL(1, 2) bool dep_ifs_store(dep_route_state_t *state,
                                              dep_route_journal_t *journal,
                                              uint32_t value) {
  if (!journal->ifs_seen && !value)
    return true;
  journal->ifs_seen = true;
  dep_route_set_t fact = {0};
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, value});
  return dep_route_state_store_access(state, journal, dep_fd_numeric(0),
                                      DEP_FD_ACCESS_IFS, fact);
}

static SHELL_NONNULL(1, 2, 3,
                     4) bool dep_ifs_copy(dep_route_state_t *destination,
                                          const dep_route_state_t *source,
                                          dep_route_journal_t *journal,
                                          const dep_owner_routes_t *baseline) {
  uint32_t value = dep_ifs_get(source, journal, baseline);
  return value == dep_ifs_get(destination, journal, baseline) ||
         dep_ifs_store(destination, journal, value);
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_ifs_apply(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline,
    const dep_named_mutations_t *mutations) {
  if (!mutations->ifs_write && !mutations->ifs_maybe_unset)
    return true;
  uint32_t value = mutations->ifs_write ? mutations->ifs
                                        : dep_ifs_get(state, journal, baseline);
  if (mutations->ifs_write && mutations->ifs_append)
    value |= dep_ifs_get(state, journal, baseline);
  if (mutations->ifs_maybe_unset)
    value = dep_ifs_join(value, 0);
  return dep_ifs_store(state, journal, value);
}

/* Zero: expansion is unchanged. One: it necessarily produces no usable
 * descriptor. Two: decimal splitting could change the selected descriptor;
 * without an exact runtime number this source is outside route analysis. */
static SHELL_NONNULL(1, 2, 3, 4) unsigned dep_fd_ifs_expansion(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline) {
  if (!op->target_unquoted)
    return 0;
  uint32_t value = dep_ifs_get(state, journal, baseline);
  if (!(value & DEP_IFS_DIGITS))
    return 0;
  if (((value >> DEP_IFS_CERTAIN_SHIFT) & DEP_IFS_DIGITS) == DEP_IFS_DIGITS ||
      ((value & DEP_IFS_SELF) &&
       dep_fd_name_equal(op->target_fd_name, op->target_fd_name_len, "IFS", 3)))
    return 1;
  return 2;
}

/* Pipes are installed before expansion/redirection. Their stable source
 * owners are available even when the corresponding control edge is emitted
 * only after this owner's nested substitutions have been joined. */
static bool dep_snapshot_install_pipeline(dep_owner_routes_t *routes,
                                          dep_route_state_t *alternatives,
                                          dep_route_journal_t *changes,
                                          const dep_parse_context_t *context,
                                          uint32_t owner, bool *pipe_both) {
  /* Source lookup needs no node type: groups have no node_range entry. */
  uint32_t range = context->node_range[owner];
  bool input;
  shell_source_compound_tail_t tail;
  if (range < context->fast->count) {
    input = context->execution->pipeline.range_connector[range] ==
            SHELL_TYPE_PIPELINE;
    tail = shell_source_parse_compound_tail(context->cmd, context->cmd_len,
                                            context->execution->end[range]);
  } else {
    uint32_t group = context->node_group[owner];
    input = context->execution->pipeline.group_connector[group] ==
            SHELL_TYPE_PIPELINE;
    tail = context->execution->pipeline.group_tail[group];
  }
  *pipe_both =
      tail.has_pipeline && tail.pipe_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR;
  for (uint32_t fd = 0; fd <= 1; fd++) {
    if ((fd == 0 && !input) || (fd == 1 && !tail.has_pipeline))
      continue;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
         access <<= 1) {
      dep_fd_route_t route = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
      if (fd == 0 && access == DEP_FD_ACCESS_READ)
        route = (dep_fd_route_t){DEP_ROUTE_PIPE_INPUT, owner};
      if (fd == 1 && access == DEP_FD_ACCESS_WRITE)
        route = (dep_fd_route_t){DEP_ROUTE_PIPE_OUTPUT, owner};
      dep_route_set_t set = {0};
      dep_route_set_set(&set, route);
      if (!dep_route_assign(routes, dep_fd_numeric(fd), (dep_fd_access_t)access,
                            route) ||
          !dep_route_state_store_access(alternatives, changes,
                                        dep_fd_numeric(fd),
                                        (dep_fd_access_t)access, set))
        return false;
    }
    dep_route_set_t live = {0};
    dep_route_set_set(&live, (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
    if (!dep_route_state_store_access(alternatives, changes, dep_fd_numeric(fd),
                                      DEP_FD_ACCESS_BINDING, live))
      return false;
  }
  return true;
}

static bool dep_snapshot_export_route(dep_fd_imports_t *imports,
                                      dep_fd_ref_t fd, dep_fd_access_t access,
                                      dep_fd_route_t route,
                                      const shell_dep_graph_t *origin,
                                      const dep_fd_imports_t *inherited) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_EXPORTS);
  dep_fd_import_t item = {.fd = fd, .route = route, .access = access};
  if (access == DEP_FD_ACCESS_BINDING) {
    /* Presence is not byte provenance. Keep its proof unchanged across a
     * child shell instead of inferring it from independently joined modes. */
  } else if (route.kind == DEP_ROUTE_DOC || route.kind == DEP_ROUTE_DYNAMIC) {
    item.route.kind = DEP_ROUTE_IMPORTED;
    item.origin = origin;
  } else if (route.kind == DEP_ROUTE_CAPTURE ||
             route.kind == DEP_ROUTE_PIPE_INPUT ||
             route.kind == DEP_ROUTE_PIPE_OUTPUT) {
    item.origin = origin;
  } else if (route.kind == DEP_ROUTE_IMPORTED) {
    if (!inherited || route.value >= inherited->count)
      return false;
    item.route = inherited->entries[route.value].route;
    item.origin = inherited->entries[route.value].origin;
  }
  int32_t index = dep_merge_fd_import(imports, &item);
  if (index < 0)
    return false;
  imports->entries[index].inherited = true;
  return true;
}

static SHELL_NONNULL(1, 3) int dep_numeric_fd_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES);
  uint32_t stored = ((const uint32_t *)context)[index];
  uint32_t fd = *(const uint32_t *)key;
  return stored < fd ? -1 : stored != fd;
}

/* ops is a prepared interval; NULL is meaningful only for an empty span. */
static SHELL_NONNULL(1) bool dep_redirect_frame_record(
    dep_redirect_frame_t *frame, const dep_fd_op_t *ops, uint32_t op_count) {
  *frame = (dep_redirect_frame_t){0};
  for (uint32_t op = 0; op < op_count; op++) {
    uint32_t fd = ops[op].fd;
    if (!dep_fd_op_saves_numeric(ops + op))
      continue;
    uint32_t candidate = frame->count + 1, match = 0;
    frame->root =
        dep_index_insert(frame->index, frame->root, candidate,
                         sizeof(frame->fds) / sizeof(frame->fds[0]),
                         dep_numeric_fd_compare, frame->fds, &fd, &match);
    if (!match)
      return false;
    if (match == candidate) {
      frame->undo_roots[frame->count] = UINT32_MAX;
      frame->fds[frame->count++] = fd;
    }
  }
  return true;
}

/* Numeric aliases of a named close are real temporary slots too. Slot
 * identities come from the reached operation, never from a later variable
 * spelling or another traversal of the redirect list. */
static SHELL_NONNULL(1, 2) bool dep_redirect_frame_aliases(
    dep_redirect_frame_t *frame, const dep_route_journal_t *journal,
    const dep_fd_op_t *ops, uint32_t op_count) {
  for (uint32_t op = 0; op < op_count; op++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES);
    if (ops[op].fd != SHELL_DEP_FD_NAMED || ops[op].kind != DEP_FD_OP_CLOSE)
      continue;
    dep_allocation_t key = {.name = ops[op].fd_name, .position = ops[op].pos};
    uint32_t cursor = journal->allocation_root;
    while (cursor) {
      int order = dep_allocation_compare(journal, cursor - 1, &key);
      if (!order)
        break;
      cursor = order > 0 ? journal->allocation_index[cursor - 1].left
                         : journal->allocation_index[cursor - 1].right;
    }
    if (!cursor || !journal->allocations[cursor - 1].closed_slots)
      continue;
    const dep_route_set_t *slots =
        &journal->snapshots[journal->allocations[cursor - 1].closed_slots - 1];
    for (uint32_t slot = 0; slot < slots->count; slot++) {
      uint32_t fd = slots->routes[slot].value, candidate = frame->count + 1;
      uint32_t match = 0;
      frame->root =
          dep_index_insert(frame->index, frame->root, candidate,
                           sizeof(frame->fds) / sizeof(frame->fds[0]),
                           dep_numeric_fd_compare, frame->fds, &fd, &match);
      if (!match)
        return false;
      if (match == candidate) {
        frame->undo_roots[frame->count] = SHELL_DEP_FD_MAX + cursor;
        frame->fds[frame->count++] = fd;
      }
    }
  }
  return true;
}

static SHELL_NONNULL(1) bool dep_publication_crosses_group(
    const dep_route_publication_t *view, int32_t group) {
  if (group < 0)
    return false;
  /* Stop at a common ancestor, including when a continuation enters a sibling
   * group. Only frames actually exited may restore their saved descriptors. */
  if (view->destination_group < 0)
    return true;
  const shell_group_t *source = &view->fast->groups[group];
  const shell_group_t *destination =
      &view->fast->groups[view->destination_group];
  return destination->start < source->start || destination->end > source->end;
}

/* Prepare each crossed frame once for this actual scope transition. All
 * publication helpers consume this shared immutable membership view. */
static SHELL_NONNULL(1, 2) bool dep_prepare_publication(
    dep_route_publication_t *view, dep_restore_set_t *restored) {
  restored->root = restored->count = 0;
  view->restored = restored;
  for (int32_t group = view->source_group;
       dep_publication_crosses_group(view, group);) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES);
    const dep_redirect_frame_t *frame = &view->frames[group];
    for (uint32_t i = 0; i < frame->count; i++) {
      uint32_t fd = frame->fds[i], candidate = restored->count + 1, match = 0;
      restored->root = dep_index_insert(
          restored->index, restored->root, candidate, DEP_MAX_FD_ROUTES,
          dep_numeric_fd_compare, restored->fds, &fd, &match);
      if (!match)
        return false;
      restored->undo_roots[match - 1] = frame->undo_roots[i];
      if (match == candidate)
        restored->fds[restored->count++] = fd;
    }
    uint16_t parent = view->fast->groups[group].parent;
    group = parent == UINT16_MAX ? -1 : (int32_t)parent;
  }
  return true;
}

/* NULL view means no crossed redirect frame. fd is a prepared identity. */
static bool dep_publication_restores_fd(const dep_route_publication_t *view,
                                        dep_fd_ref_t fd) {
  if (!view || fd.value == SHELL_DEP_FD_NAMED)
    return false;
  const dep_restore_set_t *restored = view->restored;
  uint32_t cursor = restored->root;
  while (cursor) {
    int order = dep_numeric_fd_compare(restored->fds, cursor - 1, &fd.value);
    if (!order)
      return true;
    cursor = order > 0 ? restored->index[cursor - 1].left
                       : restored->index[cursor - 1].right;
  }
  return false;
}

/* A successful predecessor's complete table is useful inside its group, but
 * a continuation outside that group sees restored numeric slots. Restore only
 * crossed frames; unshadowed exec mutations and named bindings still survive.
 */
static bool
dep_restore_continuation_routes(dep_owner_routes_t *continuation,
                                const dep_owner_routes_t *destination,
                                const dep_route_publication_t *publication) {
  for (uint32_t i = 0; i < publication->restored->count; i++) {
    dep_fd_ref_t fd = dep_fd_numeric(publication->restored->fds[i]);
    if (!dep_route_assign(continuation, fd, DEP_FD_ACCESS_READ,
                          dep_route_get(destination, fd, DEP_FD_ACCESS_READ)) ||
        !dep_route_assign(continuation, fd, DEP_FD_ACCESS_WRITE,
                          dep_route_get(destination, fd, DEP_FD_ACCESS_WRITE)))
      return false;
  }
  return true;
}

/* Replay a completed owner's prepared effects into its immediate scope, not
 * every ancestor. Compound completion later exports the accumulated table
 * with its temporary redirect frame restored. ops may be NULL only for zero
 * op_count; publication may be NULL when no redirect frame is exited. */
static SHELL_NONNULL(1, 2, 7) bool dep_apply_persistent_owner_routes(
    dep_owner_routes_t *destination, const dep_owner_routes_t *executed,
    const dep_fd_op_t *ops, uint32_t op_count, bool descriptor_exec,
    bool named_binding, const dep_named_mutations_t *mutations,
    const dep_route_publication_t *publication) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
  dep_apply_named_mutations(destination, mutations,
                            DEP_NAMED_MUTATION_BEFORE_REDIRECT);
  if (descriptor_exec) {
    for (uint32_t op = 0; op < op_count; op++) {
      dep_fd_ref_t fd = {ops[op].fd, ops[op].fd_name, ops[op].fd_name_len};
      if (dep_publication_restores_fd(publication, fd))
        continue;
      const dep_fd_route_entry_t *source = dep_route_find(executed, fd);
      if (!source)
        continue;
      dep_fd_route_entry_t *slot = dep_route_slot(destination, fd, true);
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
  dep_apply_named_mutations(destination, mutations,
                            DEP_NAMED_MUTATION_AFTER_COMMAND);
  return true;
}

typedef enum {
  DEP_EXECUTION_UNSET = 0,
  DEP_EXECUTION_NEVER,
  DEP_EXECUTION_MAYBE,
  DEP_EXECUTION_ALWAYS,
} dep_execution_certainty_t;

/* Negation changes returning pipeline status, never an input-unit abort or
 * the status with which an exit/expansion error terminates its shell. */
static uint8_t dep_status_negate(uint8_t status) {
  return (status & (DEP_STATUS_STOP | DEP_STATUS_EXIT_INCOMING)) |
         ((status & DEP_STATUS_MAY_SUCCEED) ? DEP_STATUS_MAY_FAIL : 0) |
         ((status & DEP_STATUS_MAY_FAIL) ? DEP_STATUS_MAY_SUCCEED : 0);
}

/* The resolved static builtin has Bash's fixed status even with operands or
 * command/builtin wrappers. Query wrappers and external paths are not builtin
 * targets. Redirect setup and expansion termination are composed separately;
 * exec replacement retains its own terminal outcomes. */
static SHELL_NONNULL(1) uint8_t
    dep_static_command_status(const dep_token_t *command) {
  uint8_t status = DEP_STATUS_EITHER;
  if (dep_token_static_equals(command, "true") ||
      dep_token_static_equals(command, ":"))
    status = DEP_STATUS_MAY_SUCCEED;
  else if (dep_token_static_equals(command, "false"))
    status = DEP_STATUS_MAY_FAIL;
  return status;
}

typedef struct {
  unsigned long long magnitude;
  size_t length;
  unsigned phase;
  bool negative, digits, invalid, dynamic, end_options, help;
} dep_exit_operand_t;

/* Bash's exit number is signed decimal in the signed-long-long range, with
 * optional ASCII whitespace/sign. Its process status is the low byte. Decode
 * quote fragments directly; never allocate an argv string or parse it twice.
 */
static SHELL_NONNULL(2) bool dep_exit_operand_byte(unsigned char byte,
                                                   void *context) {
  dep_exit_operand_t *operand = context;
  size_t position = operand->length++;
  operand->end_options &= position < 2 && byte == (unsigned char)"--"[position];
  operand->help &= position < 6 && byte == (unsigned char)"--help"[position];
  bool space = byte == ' ' || (byte >= '\t' && byte <= '\r');
  if (operand->phase == 0 && space)
    return true;
  if (operand->phase == 0 && (byte == '+' || byte == '-')) {
    operand->negative = byte == '-';
    operand->phase = 1;
    return true;
  }
  if (operand->digits && space) {
    operand->phase = 2;
    return true;
  }
  if (operand->phase == 2 || byte < '0' || byte > '9') {
    operand->invalid = true;
    return true;
  }
  operand->phase = 1;
  operand->digits = true;
  unsigned digit = byte - '0';
  unsigned long long limit = (unsigned long long)LLONG_MAX + operand->negative;
  if (operand->magnitude > (limit - digit) / 10)
    operand->invalid = true;
  else
    operand->magnitude = operand->magnitude * 10 + digit;
  return true;
}

static SHELL_NONNULL(1) void dep_exit_operand_dynamic(void *context) {
  ((dep_exit_operand_t *)context)->dynamic = true;
}

/* tokens is a complete scanned simple command; command is its resolved exit
 * builtin, after wrappers. Redirect operators/operands are not argv. Unknown
 * expansion cardinality retains a bounded union of operand roles. Numeric
 * errors/extra operands have changed behavior across Bash releases: retain
 * both returning failure and failure termination, not a fabricated success.
 * Redirect/expansion failures are composed separately by construction. */
static SHELL_NONNULL(1) uint8_t
    dep_analyze_exit(const dep_token_list_t *tokens, uint32_t command) {
  enum { OPTIONS = 1u, OPERAND = 2u, SUCCESS = 4u, FAILURE = 8u };
  unsigned phases = OPTIONS;
  uint8_t outcomes = 0;
  for (uint32_t i = command + 1; i < tokens->count && phases; i++) {
    const dep_token_t *word = &tokens->tokens[i];
    if (classify_redirect(word) != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(word->start, word->len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    dep_exit_operand_t operand = {.end_options = true, .help = true};
    bool single = shell_builtin_visit_single_word(
        word->start, word->len, dep_exit_operand_byte, dep_exit_operand_dynamic,
        &operand);
    unsigned next = single ? 0 : phases;
    if (phases & (SUCCESS | FAILURE))
      outcomes |= DEP_STATUS_MAY_FAIL | DEP_STATUS_TERMINAL_FAILURE;
    if (phases & (OPTIONS | OPERAND)) {
      if (!single || operand.dynamic) {
        next |= SUCCESS | FAILURE;
        outcomes |= DEP_STATUS_MAY_FAIL | DEP_STATUS_TERMINAL_FAILURE;
        if (phases & OPTIONS) {
          next |= OPERAND;
          outcomes |= DEP_STATUS_MAY_SUCCEED; /* --help */
        }
      } else if ((phases & OPTIONS) && operand.end_options &&
                 operand.length == 2) {
        next |= OPERAND;
        if (phases & OPERAND)
          outcomes |= DEP_STATUS_MAY_FAIL | DEP_STATUS_TERMINAL_FAILURE;
      } else if ((phases & OPTIONS) && operand.help && operand.length == 6) {
        outcomes |= DEP_STATUS_MAY_SUCCEED;
        if (phases & OPERAND)
          outcomes |= DEP_STATUS_MAY_FAIL | DEP_STATUS_TERMINAL_FAILURE;
      } else if (!operand.invalid && operand.digits) {
        next |= (operand.magnitude & 255u) == 0 ? SUCCESS : FAILURE;
      } else
        outcomes |= DEP_STATUS_MAY_FAIL | DEP_STATUS_TERMINAL_FAILURE;
    }
    phases = next;
  }
  if (phases & (OPTIONS | OPERAND))
    outcomes |= DEP_STATUS_EXIT_INCOMING;
  if (phases & SUCCESS)
    outcomes |= DEP_STATUS_TERMINAL_SUCCESS;
  if (phases & FAILURE)
    outcomes |= DEP_STATUS_TERMINAL_FAILURE;
  return outcomes;
}

/* Resolve a private command transfer using only executing incoming paths.
 * Completed control/CWD/FD flows contain concrete outcomes, never this flag. */
static uint8_t dep_status_resolve(uint8_t status, uint8_t incoming) {
  uint8_t resolved = status & (DEP_STATUS_EITHER | DEP_STATUS_STOP);
  if (status & DEP_STATUS_EXIT_INCOMING) {
    if (incoming & DEP_STATUS_MAY_SUCCEED)
      resolved |= DEP_STATUS_TERMINAL_SUCCESS;
    if (incoming & DEP_STATUS_MAY_FAIL)
      resolved |= DEP_STATUS_TERMINAL_FAILURE;
  }
  return resolved;
}

/* One transfer description for both control outcomes and their CWD payloads.
 * Each source bit maps to completed-scope bits; added outcomes occur at entry,
 * before the body runs. group is an indexed, validated source group. */
typedef struct {
  uint8_t outcome[5];
  uint8_t added;
} dep_group_completion_t;

/* A collapsed group has no graph owner and therefore cannot carry owner-local
 * setup state. Retained groups use their owner's first known setup failure. */
static SHELL_NONNULL(1) bool dep_group_setup_stopped(
    const dep_parse_context_t *context, uint32_t group) {
  uint32_t owner = context->group_node[group];
  return owner != UINT32_MAX && context->owner_setup_stop[owner] != UINT32_MAX;
}

static SHELL_NONNULL(1) dep_group_completion_t
    dep_group_completion(const dep_parse_context_t *context, uint32_t group) {
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  const shell_group_t *descriptor = &context->fast->groups[group];
  bool isolated_process =
      pipeline->group_tail[group].has_pipeline ||
      pipeline->group_connector[group] == SHELL_TYPE_PIPELINE ||
      context->group_exec[group].backgrounded;
  uint8_t added = context->event_static_status[group] & DEP_STATUS_STOP;
  if (context->group_exec[group].setup_can_fail)
    added |= DEP_STATUS_MAY_FAIL;
  dep_group_completion_t result = {0};
  for (unsigned i = 0; i < 5; i++) {
    uint8_t outcome = (uint8_t)(1u << i);
    if (descriptor->kind == SHELL_GROUP_SUBSHELL) {
      if (outcome == DEP_STATUS_TERMINAL_SUCCESS)
        outcome = DEP_STATUS_MAY_SUCCEED;
      else if (outcome &
               (DEP_STATUS_TERMINAL_FAILURE | DEP_STATUS_ABORT_FAILURE))
        outcome = DEP_STATUS_MAY_FAIL;
    }
    /* Setup runs outside this compound's negation. A child shell converts
     * setup termination to a return, but negation only inverts body returns.
     * An enclosing compound may still negate that returned setup failure. */
    if (added & (1u << i))
      result.added |= outcome;
    if (isolated_process)
      outcome = DEP_STATUS_EITHER;
    else if (group_is_pipeline_negated(descriptor))
      outcome = dep_status_negate(outcome);
    result.outcome[i] = outcome;
  }
  if (isolated_process)
    result.added = DEP_STATUS_EITHER;
  if (dep_group_setup_stopped(context, group))
    memset(result.outcome, 0, sizeof(result.outcome));
  return result;
}

static SHELL_NONNULL(1) uint8_t
    dep_group_completed_status(const dep_group_completion_t *completion,
                               uint8_t body) {
  uint8_t result = completion->added;
  for (unsigned i = 0; i < 5; i++)
    if (body & (1u << i))
      result |= completion->outcome[i];
  return result;
}

/* Evaluate returning, input-unit-aborting and shell-terminating outcomes.
 * Only returning paths reach another statement in this unit. The event stream
 * handles top-level recovery boundaries; child-shell completion converts both
 * aborts and termination into returning statuses.
 * This is enough to distinguish an always-taken `true &&`/`false ||` member,
 * an impossible member, and a runtime-dependent member without executing the
 * command. It also preserves left associativity: skipped commands carry the
 * accumulated list status rather than contributing their own static status. */
static SHELL_NONNULL(4) dep_execution_certainty_t
    dep_control_decision(uint8_t command_status,
                         shell_dep_edge_type_t connector, uint8_t incoming,
                         uint8_t *result_status) {
  uint8_t terminal = incoming & DEP_STATUS_STOP;
  bool can_run = (incoming & DEP_STATUS_EITHER) != 0;
  bool can_skip = terminal != 0;
  uint8_t status = terminal;
  if (connector == SHELL_EDGE_AND || connector == SHELL_EDGE_OR) {
    can_run = connector == SHELL_EDGE_AND
                  ? (incoming & DEP_STATUS_MAY_SUCCEED) != 0
                  : (incoming & DEP_STATUS_MAY_FAIL) != 0;
    bool returns_without_running =
        connector == SHELL_EDGE_AND ? (incoming & DEP_STATUS_MAY_FAIL) != 0
                                    : (incoming & DEP_STATUS_MAY_SUCCEED) != 0;
    can_skip |= returns_without_running;
    if (returns_without_running)
      status |= connector == SHELL_EDGE_AND ? DEP_STATUS_MAY_FAIL
                                            : DEP_STATUS_MAY_SUCCEED;
  }
  if (can_run) {
    uint8_t run = connector == SHELL_EDGE_AND  ? DEP_STATUS_MAY_SUCCEED
                  : connector == SHELL_EDGE_OR ? DEP_STATUS_MAY_FAIL
                                               : DEP_STATUS_EITHER;
    status |= dep_status_resolve(command_status, incoming & run);
  }
  *result_status = status;
  return can_run ? (can_skip ? DEP_EXECUTION_MAYBE : DEP_EXECUTION_ALWAYS)
                 : DEP_EXECUTION_NEVER;
}

static dep_execution_certainty_t
dep_execution_compose(dep_execution_certainty_t inner,
                      dep_execution_certainty_t outer) {
  if (inner == DEP_EXECUTION_NEVER || outer == DEP_EXECUTION_NEVER)
    return DEP_EXECUTION_NEVER;
  if (inner == DEP_EXECUTION_ALWAYS && outer == DEP_EXECUTION_ALWAYS)
    return DEP_EXECUTION_ALWAYS;
  return DEP_EXECUTION_MAYBE;
}

/* Construction tables have scope lifetime, while journal entries are immutable
 * until the owning parse returns. Child final resolution uses other scratch. */
static SHELL_NONNULL(1) uint32_t
    dep_snapshot_table_allocate(dep_route_workspace_t *workspace) {
  if (workspace->snapshot_table_count == DEP_SNAPSHOT_TABLE_CAPACITY)
    return UINT32_MAX;
  uint32_t slot = workspace->snapshot_table_count++;
  workspace->snapshot_tables[slot].routes.fd_count = 0;
  workspace->snapshot_tables[slot].routes.root = 0;
  workspace->snapshot_tables[slot].alternatives = (dep_route_state_t){0};
  return slot;
}

static SHELL_NONNULL(1) dep_route_state_t
    dep_snapshot_alternatives(const dep_snapshot_table_t *table) {
  return table->alternatives;
}

static SHELL_NONNULL(1, 2) bool dep_snapshot_table_publish(
    dep_snapshot_table_t *table, const dep_route_state_t *alternatives) {
  if (alternatives->truncated)
    return false;
  table->alternatives = *alternatives;
  return true;
}

static SHELL_NONNULL(1,
                     3) int dep_snapshot_checkpoint_compare(const void *context,
                                                            uint32_t index,
                                                            const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_snapshot_source_t *source = context;
  uint32_t position = *(const uint32_t *)key;
  return source->checkpoint_position[index] < position
             ? -1
             : source->checkpoint_position[index] != position;
}

/* Return the nearest earlier checkpoint, or an exact boundary when requested.
 * Zero is an absent tree member, not a table slot. */
static SHELL_NONNULL(1) uint32_t
    dep_snapshot_checkpoint_find(const dep_snapshot_source_t *source,
                                 uint32_t position, bool exact) {
  uint32_t cursor = source->checkpoint_root, previous = 0;
  while (cursor) {
    int order = dep_snapshot_checkpoint_compare(source, cursor - 1, &position);
    if (!order)
      return cursor;
    if (order < 0) {
      previous = cursor;
      cursor = source->checkpoint_index[cursor - 1].right;
    } else {
      cursor = source->checkpoint_index[cursor - 1].left;
    }
  }
  return exact ? 0 : previous;
}

static SHELL_NONNULL(1) bool dep_snapshot_checkpoint_record(
    dep_snapshot_source_t *source, uint32_t position, uint32_t table) {
  uint32_t capacity =
      sizeof(source->checkpoint_table) / sizeof(source->checkpoint_table[0]);
  uint32_t candidate = source->checkpoint_count + 1, match;
  source->checkpoint_root = dep_index_insert(
      source->checkpoint_index, source->checkpoint_root, candidate, capacity,
      dep_snapshot_checkpoint_compare, source, &position, &match);
  if (!match)
    return false;
  if (match == candidate) {
    source->checkpoint_position[source->checkpoint_count] = position;
    source->checkpoint_table[source->checkpoint_count++] = table;
  }
  return true;
}

/* Redirect operands arrive in source order except for deferred heredoc bodies.
 * Their document operations were installed before any expansion, so crossing
 * a heredoc also records its pre-open state. Later body inspection can use that
 * boundary directly, even though its marker starts before the delimiter span.
 * Newly discovered file/process operations precede neither an already expanded
 * operand nor a crossed heredoc: construction installs them at their operand.
 */
static SHELL_NONNULL(1, 2, 3, 6, 7) shell_dep_error_t
    dep_snapshot_operand_table(
        const shell_dep_graph_t *graph, dep_route_workspace_t *workspace,
        dep_snapshot_source_t *source, uint32_t entry_table, uint32_t position,
        uint32_t *result, const dep_parse_context_t *context, uint32_t owner) {
  /* All successful assignment-only commits precede redirect expansion. Cache
   * this one phase entry separately from the immutable command/RHS entry. */
  if (source->mutations.before_redirect && source->mutations.count) {
    if (source->redirect_entry_table == UINT32_MAX) {
      uint32_t table = dep_snapshot_table_allocate(workspace);
      if (table == UINT32_MAX)
        return SHELL_DEP_ETRUNC;
      dep_copy_routes(&workspace->snapshot_tables[table].routes,
                      &workspace->snapshot_tables[entry_table].routes);
      dep_apply_named_mutations(&workspace->snapshot_tables[table].routes,
                                &source->mutations,
                                DEP_NAMED_MUTATION_BEFORE_REDIRECT);
      dep_route_state_t alternatives =
          dep_snapshot_alternatives(&workspace->snapshot_tables[entry_table]);
      if (!dep_ifs_apply(&alternatives, &workspace->snapshot_journal,
                         &workspace->snapshot_tables[entry_table].routes,
                         &source->mutations))
        return SHELL_DEP_ETRUNC;
      if (!dep_snapshot_table_publish(&workspace->snapshot_tables[table],
                                      &alternatives))
        return SHELL_DEP_ETRUNC;
      source->redirect_entry_table = table;
    }
    entry_table = source->redirect_entry_table;
  }
  uint32_t previous = dep_snapshot_checkpoint_find(source, position, false);
  if (previous && source->checkpoint_position[previous - 1] == position) {
    *result = source->checkpoint_table[previous - 1];
    return SHELL_DEP_OK;
  }
  uint32_t cursor = source->op_root, following = 0;
  while (cursor) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    if (source->ops[cursor - 1].pos >= position) {
      following = cursor;
      cursor = source->op_index[cursor - 1].left;
    } else {
      cursor = source->op_index[cursor - 1].right;
    }
  }
  if (following) {
    const dep_fd_op_t *op = &source->ops[following - 1];
    if (op->kind == DEP_FD_OP_DOCUMENT &&
        graph->nodes[dep_edge_document_index(graph,
                                             &graph->edges[op->edge_index])]
                .doc.kind == SHELL_DOC_HEREDOC) {
      uint32_t checkpoint = dep_snapshot_checkpoint_find(source, op->pos, true);
      if (checkpoint) {
        *result = source->checkpoint_table[checkpoint - 1];
        return SHELL_DEP_OK;
      }
    }
  }
  uint32_t begin = previous ? source->checkpoint_position[previous - 1] : 0;
  uint32_t incoming =
      previous ? source->checkpoint_table[previous - 1] : entry_table;
  dep_snapshot_table_t *tables = workspace->snapshot_tables;
  uint32_t count = 0;
  dep_fd_op_t *ops = workspace->op_scratch;
  dep_snapshot_operation_range(source, source->op_root, begin, position, ops,
                               &count);
  if (!count) {
    if (!dep_snapshot_checkpoint_record(source, position, incoming))
      return SHELL_DEP_ETRUNC;
    *result = incoming;
    return SHELL_DEP_OK;
  }
  uint32_t batch = 0;
  for (uint32_t end = 0; end <= count; end++) {
    bool heredoc = end < count && ops[end].kind == DEP_FD_OP_DOCUMENT &&
                   graph->nodes[dep_edge_document_index(
                                    graph, &graph->edges[ops[end].edge_index])]
                           .doc.kind == SHELL_DOC_HEREDOC;
    if (end != count && !heredoc)
      continue;
    uint32_t boundary = end == count ? position : ops[end].pos;
    if (end == batch) {
      if (!dep_snapshot_checkpoint_record(source, boundary, incoming))
        return SHELL_DEP_ETRUNC;
      continue;
    }
    uint32_t table = dep_snapshot_table_allocate(workspace);
    if (table == UINT32_MAX)
      return SHELL_DEP_ETRUNC;
    dep_copy_routes(&tables[table].routes, &tables[incoming].routes);
    dep_route_state_t alternatives =
        dep_snapshot_alternatives(&tables[incoming]);
    for (uint32_t op = batch; op < end; op++) {
      if (ops[op].pos >= context->owner_setup_stop[owner])
        break;
      unsigned expansion = dep_fd_ifs_expansion(ops + op, &alternatives,
                                                &workspace->snapshot_journal,
                                                &tables[incoming].routes);
      if (expansion == 2)
        return SHELL_DEP_EPARSE;
      uint8_t outcomes = dep_fd_operation_outcomes(ops + op, &alternatives,
                                                   &workspace->snapshot_journal,
                                                   &tables[incoming].routes);
      if (!(outcomes & DEP_STATUS_MAY_SUCCEED)) {
        /* A previously unavailable symbolic operand remains outside the
         * supported binding contract. A known numeric close, a close within
         * this setup, and the implicit pipe duplication are supported runtime
         * failures. */
        if (!expansion && !ops[op].target_closed_locally &&
            ops[op].target_fd == SHELL_DEP_FD_NAMED)
          return SHELL_DEP_EPARSE;
        context->owner_setup_stop[owner] = ops[op].pos;
        break;
      }
      if (!dep_snapshot_apply_fd_operations(&tables[table].routes, ops + op, 1))
        return SHELL_DEP_EPARSE;
      dep_route_state_t previous_state = alternatives;
      if (!dep_route_state_apply(&alternatives, &workspace->snapshot_journal,
                                 &tables[incoming].routes, ops + op, 1,
                                 !previous && op == 0))
        return SHELL_DEP_ETRUNC;
      if (!dep_fd_materialize_from(
              &alternatives, &previous_state, &workspace->snapshot_journal,
              &tables[incoming].routes, &tables[table].routes,
              &tables[table].routes))
        return SHELL_DEP_ETRUNC;
    }
    if (!dep_snapshot_table_publish(&tables[table], &alternatives) ||
        !dep_snapshot_checkpoint_record(source, boundary, table))
      return SHELL_DEP_ETRUNC;
    incoming = table;
    batch = end;
  }
  *result = incoming;
  return SHELL_DEP_OK;
}

static SHELL_NONNULL(1) uint32_t
    dep_snapshot_event_owner(const dep_parse_context_t *context,
                             uint32_t event) {
  return event < SHELL_MAX_GROUPS
             ? context->group_node[event]
             : context->range_node[event - SHELL_MAX_GROUPS];
}

/* Required retained owner with its inverse source map installed. Outcomes
 * belong to source events, so collapsed commands participate without nodes. */
static SHELL_NONNULL(1) uint32_t
    dep_owner_event(const dep_parse_context_t *context, uint32_t owner) {
  return context->node_group[owner] != UINT32_MAX
             ? context->node_group[owner]
             : SHELL_MAX_GROUPS + context->node_range[owner];
}

/* Consume completed structural scopes before entering the next owner. */
static SHELL_NONNULL(1) bool dep_snapshot_complete_groups(
    const dep_parse_context_t *context, uint32_t before_position);

/* Both construction snapshots and final routing consume this same outcome
 * product. baseline is the immutable imported table for this parse. */
static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_begin(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    dep_route_state_t *selected);
static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_materialize(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_owner_routes_t *destination);
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool dep_fd_materialize_from(
    const dep_route_state_t *state, const dep_route_state_t *previous,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_owner_routes_t *source, dep_owner_routes_t *destination);
static SHELL_NONNULL(1, 2, 4, 5, 6, 7, 8, 13, 15) bool dep_fd_finish_owner(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_owner_routes_t *incoming, const dep_owner_routes_t *executed,
    const dep_route_state_t *executed_state, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec, bool named_binding,
    const dep_named_mutations_t *mutations, dep_route_state_t *report_state,
    const dep_route_state_t *setup_entry);

static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_complete_group(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t group,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_redirect_frame_t *frames);
static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_finish(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    const dep_fd_flow_t *executed, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline);

/* Required unretained simple-command event and its selected entry version.
 * Both route streams transfer collapsed commands through this shared path. */
static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_finish_collapsed(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_route_state_t *selected);

static SHELL_NONNULL(1) int32_t
    dep_snapshot_event_group(const dep_parse_context_t *context,
                             uint32_t event) {
  if (event >= SHELL_MAX_GROUPS)
    return dep_range_group(&context->execution->pipeline,
                           event - SHELL_MAX_GROUPS);
  uint16_t parent = context->fast->groups[event].parent;
  return parent == UINT16_MAX ? -1 : (int32_t)parent;
}

/* A compound is an execution stage in its parent's list even when every
 * command in its body is collapsed. Share this stage stream with snapshot
 * replay instead of recovering connectors from the last retained CMD.
 * owners/previous each provide DEP_EXECUTION_EVENT_CAPACITY elements; the
 * validated parse bounds the stream to that many groups plus ranges. */
static SHELL_NONNULL(1, 2, 3, 4) void dep_execution_events(
    const dep_parse_context_t *context, dep_ordered_owner_t *owners,
    uint32_t *previous, uint32_t *count) {
  *count = 0;
  for (uint32_t group = 0; group < context->fast->group_count; group++)
    owners[(*count)++] =
        (dep_ordered_owner_t){group, context->fast->groups[group].start};
  for (uint32_t range = 0; range < context->fast->count; range++)
    if (context->execution->owner[range] == range &&
        context->execution->stage[range]) {
      owners[(*count)++] = (dep_ordered_owner_t){
          SHELL_MAX_GROUPS + range, context->fast->cmds[range].start};
    }
  qsort(owners, *count, sizeof(*owners), dep_ordered_owner_compare);
  uint32_t last[SHELL_MAX_GROUPS + 1];
  for (uint32_t i = 0; i <= SHELL_MAX_GROUPS; i++)
    last[i] = UINT32_MAX;
  for (uint32_t begin = 0; begin < *count;) {
    uint32_t end = begin + 1;
    while (end < *count && owners[end].start == owners[begin].start)
      end++;
    for (uint32_t i = begin; i < end; i++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
      previous[i] =
          last[dep_snapshot_event_group(context, owners[i].owner) + 1];
    }
    for (uint32_t i = begin; i < end; i++) {
      uint32_t scope =
          (uint32_t)(dep_snapshot_event_group(context, owners[i].owner) + 1);
      if (last[scope] == UINT32_MAX ||
          owners[last[scope]].start != owners[i].start)
        last[scope] = i;
    }
    begin = end;
  }
}

static SHELL_NONNULL(1) void dep_control_stream_initialize(
    dep_control_stream_t *stream) {
  memset(stream, 0, sizeof(*stream));
  for (uint32_t scope = 0; scope <= SHELL_MAX_GROUPS; scope++)
    stream->last[scope] = UINT32_MAX;
}

/* Events before limit have completed construction, so their static command
 * status is available. A final resolver can consume the same stream after all
 * construction. The source-ordered stack closes each compound once. */
static SHELL_NONNULL(1, 2, 3, 4) void dep_control_stream_advance(
    const dep_parse_context_t *context, dep_control_stream_t *stream,
    const dep_ordered_owner_t *events, const uint32_t *previous,
    uint32_t limit) {
  /* Entry can be queried before constructing the current command's words.
   * Its reachability is fixed, but its outcome is committed from completed
   * construction before the next event consumes it. */
  if (stream->cursor) {
    uint32_t index = stream->cursor - 1;
    uint32_t event = events[index].owner;
    if (event >= SHELL_MAX_GROUPS) {
      uint8_t status = context->event_static_status[event];
      dep_control_decision(status,
                           dep_snapshot_connector_type(
                               context->execution->pipeline
                                   .range_connector[event - SHELL_MAX_GROUPS]),
                           stream->entry_status[index], &stream->status[index]);
      if (context->execution->pipeline
              .range_connector[event - SHELL_MAX_GROUPS] ==
          SHELL_TYPE_PIPELINE) {
        if (stream->execution[index] == DEP_EXECUTION_NEVER)
          stream->status[index] = stream->entry_status[index];
        else if (stream->execution[index] == DEP_EXECUTION_MAYBE)
          stream->status[index] |= stream->entry_status[index];
      }
    }
  }
  while (stream->cursor < limit) {
    uint32_t index = stream->cursor;
    while (stream->depth) {
      uint32_t group = stream->active[stream->depth - 1];
      if (context->execution->pipeline.group_tail[group].redirect_end >
          events[index].start)
        break;
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
      stream->depth--;
      uint32_t last = stream->last[group + 1];
      uint8_t body =
          last == UINT32_MAX ? DEP_STATUS_EITHER : stream->status[last];
      dep_group_completion_t completion = dep_group_completion(context, group);
      body = dep_group_completed_status(&completion, body);
      const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
      uint32_t event = stream->group_event[group];
      dep_control_decision(body,
                           dep_snapshot_group_predecessor_type(context, group),
                           stream->incoming[group], &stream->status[event]);
      if (pipeline->group_connector[group] == SHELL_TYPE_PIPELINE) {
        if (stream->execution[event] == DEP_EXECUTION_NEVER)
          stream->status[event] = stream->incoming[group];
        else if (stream->execution[event] == DEP_EXECUTION_MAYBE)
          stream->status[event] |= stream->incoming[group];
      }
    }
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
    uint32_t event = events[index].owner;
    int32_t scope = dep_snapshot_event_group(context, event);
    uint8_t incoming;
    if (previous[index] != UINT32_MAX)
      incoming = stream->status[previous[index]];
    else if (scope < 0)
      incoming = DEP_STATUS_EITHER;
    else {
      /* A compound's first command inherits the entering list status. Group
       * setup does not introduce an arbitrary status on its successful path. */
      shell_dep_edge_type_t entry_connector =
          dep_snapshot_group_predecessor_type(context, (uint32_t)scope);
      uint8_t run = entry_connector == SHELL_EDGE_AND  ? DEP_STATUS_MAY_SUCCEED
                    : entry_connector == SHELL_EDGE_OR ? DEP_STATUS_MAY_FAIL
                                                       : DEP_STATUS_EITHER;
      incoming = stream->incoming[scope] & run;
      if (incoming)
        incoming = dep_expansion_status(context, (uint32_t)scope, incoming);
    }
    if (context->input_unit_recovery && previous[index] != UINT32_MAX &&
        dep_snapshot_event_group(context, event) < 0) {
      const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
      uint32_t predecessor = events[previous[index]].owner;
      uint32_t unit =
          event < SHELL_MAX_GROUPS
              ? pipeline->group_input_unit[event]
              : pipeline->range_input_unit[event - SHELL_MAX_GROUPS];
      uint32_t prior_unit =
          predecessor < SHELL_MAX_GROUPS
              ? pipeline->group_input_unit[predecessor]
              : pipeline->range_input_unit[predecessor - SHELL_MAX_GROUPS];
      if (unit != prior_unit && (incoming & DEP_STATUS_ABORT_FAILURE))
        incoming = (incoming & ~DEP_STATUS_ABORT_FAILURE) | DEP_STATUS_MAY_FAIL;
    }
    uint8_t status = context->event_static_status[event];
    stream->entry_status[index] = incoming;
    shell_dep_edge_type_t connector =
        event < SHELL_MAX_GROUPS
            ? dep_snapshot_group_predecessor_type(context, event)
            : dep_snapshot_connector_type(
                  context->execution->pipeline
                      .range_connector[event - SHELL_MAX_GROUPS]);
    stream->execution[index] = (uint8_t)dep_control_decision(
        status, connector, incoming, &stream->status[index]);
    uint16_t source_connector =
        event < SHELL_MAX_GROUPS
            ? context->execution->pipeline.group_connector[event]
            : context->execution->pipeline
                  .range_connector[event - SHELL_MAX_GROUPS];
    if (source_connector == SHELL_TYPE_PIPELINE &&
        previous[index] != UINT32_MAX) {
      /* Every stage enters with its pipeline, not with the return status of
       * the preceding stage. A skipped first stage cannot launch later ones. */
      stream->execution[index] = stream->execution[previous[index]];
      if (stream->execution[index] == DEP_EXECUTION_NEVER)
        stream->status[index] = incoming;
      else if (stream->execution[index] == DEP_EXECUTION_MAYBE)
        stream->status[index] |= incoming;
    }
    stream->scoped_execution[index] =
        (uint8_t)(scope < 0
                      ? (dep_execution_certainty_t)stream->execution[index]
                      : dep_execution_compose(
                            (dep_execution_certainty_t)stream->execution[index],
                            (dep_execution_certainty_t)stream->scoped_execution
                                [stream->group_event[scope]]));
    if (scope >= 0) {
      uint32_t scope_owner = context->group_node[scope];
      if (scope_owner != UINT32_MAX &&
          context->owner_setup_stop[scope_owner] != UINT32_MAX)
        stream->scoped_execution[index] = DEP_EXECUTION_NEVER;
    }
    stream->last[scope + 1] = index;
    if (event < SHELL_MAX_GROUPS) {
      stream->group_event[event] = index;
      stream->incoming[event] = incoming;
      stream->active[stream->depth++] = event;
    }
    stream->cursor++;
  }
}

static SHELL_NONNULL(1, 2) void dep_execution_control_edges(
    shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t max_edges) {
  dep_ordered_owner_t owners[DEP_EXECUTION_EVENT_CAPACITY];
  uint32_t previous[DEP_EXECUTION_EVENT_CAPACITY], count;
  dep_execution_events(context, owners, previous, &count);
  uint32_t retained[DEP_EXECUTION_EVENT_CAPACITY];
  for (uint32_t i = 0; i < count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
    uint32_t event = owners[i].owner;
    uint32_t target = dep_snapshot_event_owner(context, event);
    uint32_t source =
        previous[i] == UINT32_MAX ? UINT32_MAX : retained[previous[i]];
    retained[i] = target == UINT32_MAX ? source : target;
    if (target == UINT32_MAX || source == UINT32_MAX)
      continue;
    uint16_t connector =
        event < SHELL_MAX_GROUPS
            ? context->execution->pipeline.group_connector[event]
            : context->execution->pipeline
                  .range_connector[event - SHELL_MAX_GROUPS];
    shell_dep_edge_type_t type = dep_snapshot_connector_type(connector);
    if (connector == SHELL_TYPE_PIPELINE)
      type = SHELL_EDGE_PIPE;
    else if (connector == SHELL_TYPE_BACKGROUND)
      type = SHELL_EDGE_BACKGROUND;
    if (graph->edge_count == max_edges) {
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      return;
    }
    shell_dep_edge_t *edge = &graph->edges[graph->edge_count++];
    dep_init_edge(edge, source, target, type, SHELL_DIR_FORWARD,
                  SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
    if (type == SHELL_EDGE_PIPE) {
      edge->source_fd = 1;
      edge->target_fd = 0;
      bool both =
          event < SHELL_MAX_GROUPS
              ? shell_source_match_logical_punctuation(
                    context->cmd, context->cmd_len,
                    context->execution->pipeline.group_connector_start[event],
                    "|&", NULL)
              : context->fast->cmds[event - SHELL_MAX_GROUPS].pipe_input_mode ==
                    SHELL_PIPE_MODE_STDOUT_AND_STDERR;
      if (both)
        edge->flags = DEP_EDGE_FLAG_PIPE_STDERR;
    }
  }
}

/* A group's body can expand before graph construction emits its outer control
 * edge. Use the already indexed source connector, not that incomplete edge
 * stream, while sharing the resolver's AND-OR status composition. */
static SHELL_NONNULL(1) dep_execution_certainty_t
    dep_snapshot_control_state(const dep_parse_context_t *context,
                               uint32_t index) {
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_control_stream_advance(context, &frame->control, frame->owners,
                             frame->previous_same_scope, index + 1);
  return (dep_execution_certainty_t)frame->control.execution[index];
}

/* Initialize the source event index independently of descriptor snapshots.
 * Entry reachability must not allocate route tables or freeze a provisional
 * command outcome. The parse frame is cleared once at parse entry. */
static SHELL_NONNULL(1) void dep_construction_control_initialize(
    const dep_parse_context_t *context) {
  dep_snapshot_frame_t *frame = context->snapshot;
  if (frame->control_initialized)
    return;
  dep_control_stream_initialize(&frame->control);
  dep_execution_events(context, frame->owners, frame->previous_same_scope,
                       &frame->owner_count);
  for (uint32_t i = 0; i < frame->owner_count; i++)
    frame->event_index[frame->owners[i].owner] = i;
  frame->control_initialized = true;
}

static SHELL_NONNULL(1) dep_execution_certainty_t
    dep_event_execution(const dep_parse_context_t *context, uint32_t event) {
  dep_construction_control_initialize(context);
  dep_snapshot_frame_t *frame = context->snapshot;
  uint32_t index = frame->event_index[event];
  (void)dep_snapshot_control_state(context, index);
  dep_execution_certainty_t execution =
      (dep_execution_certainty_t)frame->control.scoped_execution[index];
  if (!context->effects_active)
    execution = DEP_EXECUTION_NEVER;
  return execution;
}

/* Entry reachability is distinct from completion of this owner's setup.
 * Arguments and assignment values expand before its redirections; redirect
 * operands stop only after the failing operation. Enclosing failed setup is
 * already reflected in dep_event_execution. Preserve entry certainty for the
 * descriptor journal even when this owner's body cannot run. */
static SHELL_NONNULL(1) bool dep_owner_phase_active(
    const dep_parse_context_t *context, uint32_t owner,
    dep_snapshot_phase_t phase, uint32_t position) {
  dep_execution_certainty_t execution =
      dep_event_execution(context, dep_owner_event(context, owner));
  context->snapshot->execution[owner] = (uint8_t)execution;
  return execution != DEP_EXECUTION_NEVER &&
         (phase == DEP_SNAPSHOT_COMMAND_WORD ||
          phase == DEP_SNAPSHOT_ASSIGNMENT_VALUE ||
          position <= context->owner_setup_stop[owner]);
}

static dep_cwd_state_t dep_cwd_join(dep_cwd_state_t a, dep_cwd_state_t b) {
  if (!a.known || !b.known || a.offset != b.offset ||
      a.absolute != b.absolute) {
    a.known = false;
    a.absolute = false;
  }
  return a;
}

/* outcome is a prechecked status-bit index in [0, 5). */
static SHELL_NONNULL(1) void dep_cwd_add(dep_cwd_flow_t *flow, unsigned outcome,
                                         dep_cwd_state_t state) {
  uint8_t bit = (uint8_t)(1u << outcome);
  flow->state[outcome] =
      (flow->mask & bit) ? dep_cwd_join(flow->state[outcome], state) : state;
  flow->mask |= bit;
}

/* A missing path leaves the diagnostic directory unchanged. Only present
 * outcomes contribute to a real expansion context. */
static SHELL_NONNULL(1) dep_cwd_state_t
    dep_cwd_selected(const dep_cwd_flow_t *flow, uint8_t mask,
                     dep_cwd_state_t fallback) {
  bool found = false;
  for (unsigned i = 0; i < 5; i++)
    if (flow->mask & mask & (1u << i)) {
      fallback =
          found ? dep_cwd_join(fallback, flow->state[i]) : flow->state[i];
      found = true;
    }
  return fallback;
}

/* Construction has begun this event and installed its pipeline entry index.
 * The validated source metadata supplies the scope and connector relation. */
static SHELL_NONNULL(1) uint8_t
    dep_cwd_run_mask(const dep_parse_context_t *context, uint32_t event) {
  uint16_t source_connector =
      event < SHELL_MAX_GROUPS
          ? context->execution->pipeline.group_connector[event]
          : context->execution->pipeline
                .range_connector[event - SHELL_MAX_GROUPS];
  if (source_connector == SHELL_TYPE_PIPELINE)
    event =
        context->snapshot
            ->cwd_pipeline_event[dep_snapshot_event_group(context, event) + 1] -
        1;
  shell_dep_edge_type_t connector =
      event < SHELL_MAX_GROUPS
          ? dep_snapshot_group_predecessor_type(context, event)
          : dep_snapshot_connector_type(
                context->execution->pipeline
                    .range_connector[event - SHELL_MAX_GROUPS]);
  return connector == SHELL_EDGE_AND  ? DEP_STATUS_MAY_SUCCEED
         : connector == SHELL_EDGE_OR ? DEP_STATUS_MAY_FAIL
                                      : DEP_STATUS_EITHER;
}

/* Save the pre-command alternatives and select only paths that execute this
 * stage. Called once per source event, before its words or redirects expand. */
static SHELL_NONNULL(1, 3, 4,
                     5) void dep_cwd_begin(const dep_parse_context_t *context,
                                           uint32_t event, uint32_t *offset,
                                           bool *known, bool *absolute) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
  dep_snapshot_frame_t *frame = context->snapshot;
  uint32_t scope = (uint32_t)(dep_snapshot_event_group(context, event) + 1);
  dep_cwd_state_t incoming = {*offset, *known, *absolute};
  if (!frame->cwd_initialized) {
    frame->cwd_scope[0].mask = DEP_STATUS_EITHER;
    frame->cwd_scope[0].state[0] = frame->cwd_scope[0].state[1] = incoming;
    frame->cwd_initialized = true;
  }
  dep_cwd_flow_t *flow = &frame->cwd_scope[scope];
  if (scope == 0) {
    const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
    uint32_t unit = event < SHELL_MAX_GROUPS
                        ? pipeline->group_input_unit[event]
                        : pipeline->range_input_unit[event - SHELL_MAX_GROUPS];
    if (context->input_unit_recovery && unit != frame->cwd_input_unit &&
        (flow->mask & DEP_STATUS_ABORT_FAILURE)) {
      dep_cwd_add(flow, 1, flow->state[4]);
      flow->mask &= (uint8_t)~DEP_STATUS_ABORT_FAILURE;
    }
    frame->cwd_input_unit = unit;
  }
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  uint16_t connector =
      event < SHELL_MAX_GROUPS
          ? pipeline->group_connector[event]
          : pipeline->range_connector[event - SHELL_MAX_GROUPS];
  if (connector == SHELL_TYPE_PIPELINE) {
    frame->cwd_entry[event] =
        frame->cwd_entry[frame->cwd_pipeline_event[scope] - 1];
  } else {
    frame->cwd_entry[event] = *flow;
    bool outgoing = event < SHELL_MAX_GROUPS
                        ? pipeline->group_tail[event].has_pipeline
                        : pipeline->range_successor[event - SHELL_MAX_GROUPS] ==
                              SHELL_TYPE_PIPELINE;
    frame->cwd_pipeline_event[scope] = outgoing ? event + 1 : 0;
  }
  flow = &frame->cwd_entry[event];
  uint8_t run = dep_cwd_run_mask(context, event);
  incoming = dep_cwd_selected(flow, run, incoming);
  *offset = incoming.offset;
  *known = incoming.known;
  *absolute = incoming.absolute;
  if (event < SHELL_MAX_GROUPS) {
    dep_cwd_flow_t *body = &frame->cwd_scope[event + 1];
    body->mask = flow->mask & run;
    body->state[0] = body->state[1] = incoming;
  }
}

/* Return skipped outcomes unchanged, and replace only executing outcomes.
 * Shell-terminating paths remain separate from returning continuations. */
static SHELL_NONNULL(1,
                     3) void dep_cwd_finish(const dep_parse_context_t *context,
                                            uint32_t event,
                                            const dep_cwd_flow_t *executed) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
  dep_snapshot_frame_t *frame = context->snapshot;
  const dep_cwd_flow_t *entry = &frame->cwd_entry[event];
  uint8_t run = dep_cwd_run_mask(context, event);
  dep_cwd_flow_t result = *entry;
  result.mask &= (uint8_t)~run;
  if (entry->mask & run)
    for (unsigned i = 0; i < 5; i++)
      if (executed->mask & (1u << i))
        dep_cwd_add(&result, i, executed->state[i]);
  if (executed->mask & DEP_STATUS_EXIT_INCOMING)
    for (unsigned i = 0; i < 2; i++)
      if (entry->mask & run & (1u << i))
        dep_cwd_add(&result, i + 2, entry->state[i]);
  frame->cwd_scope[dep_snapshot_event_group(context, event) + 1] = result;
}

/* event is a begun simple-command source event, not a group event. */
static SHELL_NONNULL(1) void dep_cwd_finish_command(
    const dep_parse_context_t *context, uint32_t event,
    dep_cwd_state_t candidate) {
  dep_cwd_flow_t executed = {.mask = context->event_static_status[event]};
  dep_cwd_state_t stopped =
      dep_cwd_selected(&context->snapshot->cwd_entry[event],
                       dep_cwd_run_mask(context, event), candidate);
  uint32_t owner = context->range_node[event - SHELL_MAX_GROUPS];
  if ((owner != UINT32_MAX && context->owner_setup_stop[owner] != UINT32_MAX) ||
      context->execution->pipeline
          .local_process[context->execution->owner[event - SHELL_MAX_GROUPS]])
    candidate = stopped;
  for (unsigned i = 0; i < 5; i++)
    executed.state[i] = i < 2 ? candidate : stopped;
  dep_cwd_finish(context, event, &executed);
}

/* Close each group once, composing its outcome-indexed CWD into the parent.
 * Terminating branches never pollute a returning continuation. */
static SHELL_NONNULL(1, 2, 4, 5, 6) void dep_complete_cwd_groups(
    const dep_parse_context_t *context, dep_group_exec_t *groups,
    uint32_t before, uint32_t *offset, bool *known, bool *absolute) {
  dep_snapshot_frame_t *frame = context->snapshot;
  while (frame->cwd_depth) {
    uint32_t group = frame->cwd_groups[frame->cwd_depth - 1];
    if (context->execution->pipeline.group_tail[group].redirect_end > before)
      break;
    frame->cwd_depth--;
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GROUP_EVENTS);
    dep_cwd_flow_t body = frame->cwd_scope[group + 1];
    dep_cwd_state_t entry = {groups[group].entry_cwd_offset,
                             groups[group].entry_cwd_known,
                             groups[group].entry_cwd_absolute};
    dep_group_completion_t completion = dep_group_completion(context, group);
    dep_cwd_flow_t completed = {0};
    for (unsigned i = 0; i < 5; i++) {
      if (completion.added & (1u << i))
        dep_cwd_add(&completed, i, entry);
      if (body.mask & (1u << i)) {
        dep_cwd_state_t state = groups[group].isolated ? entry : body.state[i];
        for (unsigned target = 0; target < 5; target++)
          if (completion.outcome[i] & (1u << target))
            dep_cwd_add(&completed, target, state);
      }
    }
    dep_cwd_finish(context, group, &completed);
    uint32_t *destination_offset = offset;
    bool *destination_known = known, *destination_absolute = absolute;
    uint16_t parent = context->fast->groups[group].parent;
    if (parent != UINT16_MAX) {
      destination_offset = &groups[parent].cwd_offset;
      destination_known = &groups[parent].cwd_known;
      destination_absolute = &groups[parent].cwd_absolute;
    }
    dep_cwd_state_t continued = dep_cwd_selected(
        &frame->cwd_scope[parent == UINT16_MAX ? 0 : parent + 1],
        DEP_STATUS_EITHER,
        (dep_cwd_state_t){*destination_offset, *destination_known,
                          *destination_absolute});
    *destination_offset = continued.offset;
    *destination_known = continued.known;
    *destination_absolute = continued.absolute;
  }
}

/* inherited is NULL at a root parse with no inherited descriptor imports. */
static SHELL_NONNULL(1) bool dep_snapshot_frame_initialize(
    const dep_parse_context_t *context, const dep_fd_imports_t *inherited) {
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_route_workspace_t *workspace = context->workspace;
  dep_construction_control_initialize(context);
  for (uint32_t i = 0; i <= SHELL_MAX_GROUPS; i++)
    frame->persistent[i] = UINT32_MAX;
  frame->current_owner = UINT32_MAX;
  for (uint32_t owner = 0; owner < SHELL_DEP_MAX_NODES; owner++) {
    frame->cached_entry[owner] = UINT32_MAX;
  }
  frame->persistent[0] = dep_snapshot_table_allocate(workspace);
  frame->current_table = dep_snapshot_table_allocate(workspace);
  if (frame->current_table == UINT32_MAX)
    return false;
  dep_snapshot_table_t *root =
      &workspace->snapshot_tables[frame->persistent[0]];
  dep_route_state_t alternatives = {0};
  if (!dep_import_routes(&root->routes, inherited) ||
      !dep_import_route_alternatives(&alternatives,
                                     &workspace->snapshot_journal, inherited) ||
      !dep_snapshot_table_publish(root, &alternatives))
    return false;
  frame->fd_stream.scope[0].mask = DEP_STATUS_EITHER;
  frame->fd_stream.scope[0].state[0] = frame->fd_stream.scope[0].state[1] =
      alternatives;
  frame->initialized = true;
  return true;
}

/* Advance the construction stream only to this owner. Earlier owners are
 * committed once; repeated argv substitutions share the same inherited table.
 * Assignment RHS imports arrive in source order per owner; repeated nested
 * substitutions in one RHS use that same assignment boundary. Redirect
 * operands add only preceding operations to that entry snapshot. This advances
 * semantic setup and returns its cached table; it does not export descriptors
 * merely to establish whether an expansion can execute. */
static SHELL_NONNULL(1, 3, 7) shell_dep_error_t
    dep_snapshot_phase_table(const shell_dep_graph_t *graph,
                             const dep_subgraph_streams_t *streams,
                             const dep_parse_context_t *context,
                             uint32_t current_owner, uint32_t position,
                             dep_snapshot_phase_t phase, uint32_t *table) {
  const dep_fd_imports_t *inherited = streams ? &streams->fd_imports : NULL;
  dep_route_workspace_t *workspace = context->workspace;
  dep_route_journal_t *changes = &workspace->snapshot_journal;
  dep_snapshot_frame_t *frame = context->snapshot;
  if (!frame->initialized && !dep_snapshot_frame_initialize(context, inherited))
    return SHELL_DEP_ETRUNC;
  dep_snapshot_table_t *tables = workspace->snapshot_tables;
  const dep_owner_routes_t *baseline = &tables[frame->persistent[0]].routes;
  bool historical = frame->cached_entry[current_owner] != UINT32_MAX;
  dep_snapshot_table_t *entry =
      &tables[historical ? frame->cached_entry[current_owner]
                         : frame->current_table];

  while (!historical && frame->current_owner != current_owner) {
    if (frame->current_owner != UINT32_MAX) {
      uint32_t owner = frame->current_owner;
      uint32_t event = dep_owner_event(context, owner);
      if (frame->execution[owner] != DEP_EXECUTION_NEVER) {
        dep_snapshot_source_t *prepared;
        uint32_t op_count = 0, completed;
        if (!dep_snapshot_fd_operations(graph, context, owner, &prepared))
          return SHELL_DEP_EPARSE;
        dep_snapshot_operation_range(prepared, prepared->op_root, 0, UINT32_MAX,
                                     workspace->ops, &op_count);
        shell_dep_error_t error = dep_snapshot_operand_table(
            graph, workspace, prepared, (uint32_t)(entry - tables), UINT32_MAX,
            &completed, context, owner);
        if (error != SHELL_DEP_OK)
          return error;
        dep_owner_routes_t executed, pipeline;
        dep_copy_routes(&executed, &tables[completed].routes);
        dep_route_state_t alternatives =
            dep_snapshot_alternatives(&tables[completed]);
        dep_copy_routes(&pipeline, &entry->routes);
        dep_route_state_t ignored = dep_snapshot_alternatives(entry);
        if (prepared->mutations.before_redirect &&
            !dep_ifs_apply(&ignored, changes, &entry->routes,
                           &prepared->mutations))
          return SHELL_DEP_ETRUNC;
        bool pipe_both = false;
        if (!dep_snapshot_install_pipeline(&pipeline, &ignored, changes,
                                           context, owner, &pipe_both))
          return SHELL_DEP_ETRUNC;
        bool descriptor_exec =
            event >= SHELL_MAX_GROUPS && prepared->exec.persistent_redirects;
        if (event < SHELL_MAX_GROUPS) {
          if (!dep_redirect_frame_record(&frame->redirect_frames[event],
                                         workspace->ops, op_count) ||
              !dep_redirect_frame_aliases(&frame->redirect_frames[event],
                                          changes, workspace->ops, op_count))
            return SHELL_DEP_ETRUNC;
          frame->active_groups[frame->active_group_count++] = event;
        }
        if (!dep_fd_finish_owner(context, &frame->fd_stream, event, changes,
                                 baseline, &entry->routes, &executed,
                                 &alternatives, workspace->ops, op_count,
                                 descriptor_exec,
                                 dep_owner_persists_named_binding(graph, owner),
                                 &prepared->mutations, NULL, &ignored))
          return SHELL_DEP_ETRUNC;
      } else {
        dep_fd_flow_t none = {0};
        if (!dep_fd_finish(context, &frame->fd_stream, event, &none, changes,
                           baseline))
          return SHELL_DEP_ETRUNC;
      }
      bool deferred =
          frame->prepared_source[owner] != UINT32_MAX
              ? workspace->snapshot_sources[frame->prepared_source[owner]]
                    .deferred_document
              : event >= SHELL_MAX_GROUPS &&
                    (context->fast->cmds[event - SHELL_MAX_GROUPS].features &
                     SHELL_FEAT_HEREDOC);
      if (deferred) {
        frame->cached_entry[owner] = frame->current_table;
        frame->current_table = dep_snapshot_table_allocate(workspace);
        if (frame->current_table == UINT32_MAX)
          return SHELL_DEP_ETRUNC;
        entry = &tables[frame->current_table];
      }
    }

    uint32_t owner = UINT32_MAX;
    while (frame->cursor < frame->owner_count) {
      uint32_t index = frame->cursor++;
      uint32_t event = frame->owners[index].owner;
      SHELL_PIPELINE_WORK();
      if (!dep_snapshot_complete_groups(context, frame->owners[index].start))
        return SHELL_DEP_ETRUNC;
      dep_route_state_t selected;
      if (!dep_fd_begin(context, &frame->fd_stream, event, changes, baseline,
                        &selected))
        return SHELL_DEP_ETRUNC;
      owner = dep_snapshot_event_owner(context, event);
      if (owner == UINT32_MAX) {
        if (!dep_fd_finish_collapsed(context, &frame->fd_stream, event, changes,
                                     baseline, &selected))
          return SHELL_DEP_ETRUNC;
        continue;
      }
      dep_execution_certainty_t local =
          dep_snapshot_control_state(context, index);
      int32_t enclosing = dep_snapshot_event_group(context, event);
      frame->local_execution[owner] = (uint8_t)local;
      frame->execution[owner] =
          context->effects_active
              ? (uint8_t)(enclosing < 0
                              ? local
                              : dep_execution_compose(
                                    local,
                                    (dep_execution_certainty_t)frame->execution
                                        [context->group_node[enclosing]]))
              : DEP_EXECUTION_NEVER;
      if (enclosing >= 0) {
        uint32_t enclosing_owner = context->group_node[enclosing];
        if (enclosing_owner != UINT32_MAX &&
            context->owner_setup_stop[enclosing_owner] != UINT32_MAX)
          frame->execution[owner] = DEP_EXECUTION_NEVER;
      }
      dep_route_state_t previous = dep_snapshot_alternatives(entry);
      if (!(previous.root || entry->routes.fd_count)
              ? !dep_fd_materialize(&selected, changes, baseline,
                                    &entry->routes)
              : !dep_fd_materialize_from(&selected, &previous, changes,
                                         baseline, &entry->routes,
                                         &entry->routes))
        return SHELL_DEP_ETRUNC;
      bool pipe_both = false;
      if (frame->execution[owner] != DEP_EXECUTION_NEVER &&
          !dep_snapshot_install_pipeline(&entry->routes, &selected, changes,
                                         context, owner, &pipe_both))
        return SHELL_DEP_ETRUNC;
      dep_snapshot_source_t *prepared;
      if (frame->execution[owner] != DEP_EXECUTION_NEVER &&
          !dep_snapshot_fd_operations(graph, context, owner, &prepared))
        return SHELL_DEP_EPARSE;
      if (!dep_snapshot_table_publish(entry, &selected))
        return SHELL_DEP_ETRUNC;
      break;
    }
    frame->current_owner = owner;
  }

  if (phase == DEP_SNAPSHOT_REDIRECT_OPERAND || phase == DEP_SNAPSHOT_SETUP) {
    dep_snapshot_source_t *prepared;
    if (!dep_snapshot_fd_operations(graph, context, current_owner, &prepared))
      return SHELL_DEP_EPARSE;
    return dep_snapshot_operand_table(graph, workspace, prepared,
                                      (uint32_t)(entry - tables), position,
                                      table, context, current_owner);
  }
  *table = (uint32_t)(entry - tables);
  return SHELL_DEP_OK;
}

/* Recursive expansions request an import from one of the three expansion
 * phases, not SETUP. Reuse the established checkpoint; exporting descriptors
 * is separate from resolving the operand's reachability. */
static SHELL_NONNULL(1, 3, 7) shell_dep_error_t dep_snapshot_fd_imports(
    const shell_dep_graph_t *graph, const dep_subgraph_streams_t *streams,
    const dep_parse_context_t *context, uint32_t current_owner,
    uint32_t position, dep_snapshot_phase_t phase, dep_fd_imports_t *imports) {
  *imports = (dep_fd_imports_t){0};
  uint32_t table;
  shell_dep_error_t error = dep_snapshot_phase_table(
      graph, streams, context, current_owner, position, phase, &table);
  if (error != SHELL_DEP_OK)
    return error;
  const dep_fd_imports_t *inherited = streams ? &streams->fd_imports : NULL;
  dep_route_workspace_t *workspace = context->workspace;
  dep_route_journal_t *changes = &workspace->snapshot_journal;
  dep_snapshot_frame_t *frame = context->snapshot;
  const dep_snapshot_table_t *entry = &workspace->snapshot_tables[table];
  const dep_owner_routes_t *snapshot = &entry->routes;
  dep_route_state_t alternatives = dep_snapshot_alternatives(entry);
  imports->ifs = dep_ifs_get(&alternatives, changes, snapshot);
  if (phase == DEP_SNAPSHOT_ASSIGNMENT_VALUE) {
    dep_snapshot_source_t *source =
        &workspace->snapshot_sources[frame->prepared_source[current_owner]];
    if (source->mutations.before_redirect) {
      while (source->assignment_ifs_cursor < source->assignment_ifs_count &&
             source->assignment_ifs[source->assignment_ifs_cursor].after <=
                 context->cmd + position) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ASSIGNMENT_IFS);
        source->assignment_ifs_cursor++;
      }
      if (source->assignment_ifs_cursor) {
        const dep_assignment_ifs_t *prefix =
            &source->assignment_ifs[source->assignment_ifs_cursor - 1];
        imports->ifs = prefix->value | (prefix->append ? imports->ifs : 0);
      }
    }
  }
  for (uint32_t i = 0; i < snapshot->fd_count; i++) {
    const dep_fd_route_entry_t *item = &snapshot->fd[i];
    if (item->fd.value > SHELL_DEP_FD_MAX &&
        item->fd.value != SHELL_DEP_FD_NAMED)
      continue;
    if (phase == DEP_SNAPSHOT_ASSIGNMENT_VALUE &&
        dep_assignment_precedes(
            &workspace->snapshot_sources[frame->prepared_source[current_owner]],
            context->cmd, item->fd, position))
      continue;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_BINDING;
         access <<= 1) {
      dep_route_set_t routes = dep_fd_raw_fact(
          &alternatives, changes, snapshot, item->fd, (dep_fd_access_t)access);
      /* Physical aliases remain associations in the child. Abstract slot
       * IDs are local to this journal; export their resolved provenance. */
      bool abstract = false;
      for (uint32_t route = 0; route < routes.count; route++)
        abstract |= routes.routes[route].kind == DEP_ROUTE_ALIAS &&
                    routes.routes[route].value > SHELL_DEP_FD_MAX;
      if (abstract)
        routes = dep_fd_fact(&alternatives, changes, snapshot, item->fd,
                             (dep_fd_access_t)access);
      if (routes.truncated)
        return SHELL_DEP_ETRUNC;
      for (uint32_t route = 0; route < routes.count; route++)
        if (!dep_snapshot_export_route(imports, item->fd,
                                       (dep_fd_access_t)access,
                                       routes.routes[route], graph, inherited))
          return SHELL_DEP_ETRUNC;
    }
  }
  return SHELL_DEP_OK;
}
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_complete_owner_setup(const shell_dep_graph_t *graph,
                             const dep_subgraph_streams_t *streams,
                             const dep_parse_context_t *context, uint32_t owner,
                             bool *may_fail) {
  if (may_fail)
    *may_fail = false;
  if (graph->status & SHELL_DEP_STATUS_TRUNCATED)
    return SHELL_DEP_OK;
  if (!dep_owner_phase_active(context, owner, DEP_SNAPSHOT_SETUP, UINT32_MAX))
    return SHELL_DEP_OK;
  dep_snapshot_source_t *prepared;
  if (!dep_snapshot_fd_operations(graph, context, owner, &prepared))
    return SHELL_DEP_EPARSE;
  bool can_stop = false;
  for (uint32_t op = 0; op < prepared->op_count; op++) {
    const dep_fd_op_t *item = &prepared->ops[op];
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    can_stop = can_stop || item->kind == DEP_FD_OP_DUP;
    if (!may_fail || dep_fd_op_numeric_self_dup(item) ||
        (item->kind == DEP_FD_OP_CLOSE && item->fd != SHELL_DEP_FD_NAMED))
      continue;
    /* Inline document materialization retains the graph's successful-setup
     * model. Its expansion errors are recorded separately, in the shell that
     * executes them. File and process opens still depend on runtime I/O. */
    if (item->kind != DEP_FD_OP_DOCUMENT ||
        graph->nodes[dep_edge_document_index(graph,
                                             &graph->edges[item->edge_index])]
                .doc.kind == SHELL_DOC_FILE)
      *may_fail = true;
  }
  if (!can_stop)
    return SHELL_DEP_OK;
  uint32_t table;
  return dep_snapshot_phase_table(graph, streams, context, owner, UINT32_MAX,
                                  DEP_SNAPSHOT_SETUP, &table);
}

/* Record a reached FILE operand's known failure, whether its spelling was
 * statically empty or the resolver produced an unusable pathname. A file
 * command substitution fails in its child, not the enclosing command setup.
 * word/document/owner are the installed operand and its execution owner. */
static SHELL_NONNULL(1, 2, 3) void dep_record_file_failure(
    shell_dep_graph_t *graph, const dep_parse_context_t *context,
    const dep_token_t *word, uint32_t owner,
    shell_expand_word_purpose_t purpose, uint32_t document) {
  graph->nodes[document].doc.flags |= SHELL_DEP_DOC_FLAG_EXPANSION_FAILED;
  if (purpose == SHELL_EXPAND_WORD_REDIRECT_PATH) {
    uint32_t position = (uint32_t)(word->start - context->cmd);
    if (position < context->owner_setup_stop[owner])
      context->owner_setup_stop[owner] = position;
  }
}

/* Resolve one parser-owned source word at its semantic expansion point. The
 * optional bridge validates application bytes before this layer sees them;
 * graph construction only consumes its immutable metadata. Ordinary words
 * use the call to populate the shared cache. FILE words additionally retain
 * one decoded pathname, or record the shell's known ambiguous/empty redirect
 * failure so descriptor replay can stop at that operation. */
static SHELL_NONNULL(1, 2, 3, 4) shell_dep_error_t
    dep_resolve_word(shell_dep_graph_t *graph,
                     const dep_parse_context_t *context,
                     const dep_token_t *word, const char *cwd, uint32_t owner,
                     shell_expand_word_purpose_t purpose, bool eligible,
                     uint32_t document, const shell_dep_word_value_t **result) {
  if (result)
    *result = NULL;
  /* FILE initialization records whether syntax is dynamic. Decode static
   * operands only when reached, before the optional resolver. In particular,
   * prebuilt group documents must not advertise failure to descriptor replay
   * before their operand executes. Static paths need no callback/cache entry.
   */
  if (eligible && purpose != SHELL_EXPAND_WORD_ARGUMENT &&
      !(graph->nodes[document].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME)) {
    size_t decoded_length;
    if (shell_measure_decoded_word(word->start, word->len, &decoded_length) ==
            SHELL_PROCESS_OK &&
        decoded_length == 0)
      dep_record_file_failure(graph, context, word, owner, purpose, document);
    return SHELL_DEP_OK;
  }
  if (!context->resolver)
    return SHELL_DEP_OK;
  const shell_dep_node_t *owner_node = &graph->nodes[owner];
  const char *owner_source;
  size_t owner_length;
  if (owner_node->type == SHELL_NODE_CMD) {
    const shell_range_t *range =
        &context->fast->cmds[context->node_range[owner]];
    owner_source = context->cmd + range->start;
    owner_length = range->len;
  } else {
    owner_source = owner_node->group.start;
    owner_length = owner_node->group.length;
  }
  shell_dep_expand_request_t request = {
      .word = word->start,
      .word_length = word->len,
      .owner = owner_source,
      .owner_length = owner_length,
      .cwd = cwd,
      .cwd_known = dep_expansion_cwd_known(graph, context, owner),
      .cwd_absolute = dep_expansion_cwd_absolute(graph, context, owner),
      .purpose = purpose,
      .eligible = eligible,
  };
  const shell_dep_word_value_t *value =
      context->resolver->expand(&request, context->resolver->context);
  if (!value)
    return SHELL_DEP_EPARSE;
  if (result)
    *result = value;
  if (eligible && purpose != SHELL_EXPAND_WORD_ARGUMENT && value->dynamic &&
      !value->resolved)
    context->unresolved_paths[owner] = true;
  if (!eligible || purpose == SHELL_EXPAND_WORD_ARGUMENT || !value->resolved)
    return SHELL_DEP_OK;

  shell_dep_doc_t *doc = &graph->nodes[document].doc;
  if (value->count != 1 || value->first_length == 0) {
    dep_record_file_failure(graph, context, word, owner, purpose, document);
    return SHELL_DEP_OK;
  }
  if (value->first_length > UINT32_MAX)
    return SHELL_DEP_ETRUNC;
  doc->value = value->first;
  doc->value_len = (uint32_t)value->first_length;
  doc->flags = (uint8_t)((doc->flags & ~SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) |
                         SHELL_DEP_DOC_FLAG_RESOLVED_PATH);
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
static SHELL_NONNULL(1, 2) uint32_t
    dep_edge_document_index(const shell_dep_graph_t *graph,
                            const shell_dep_edge_t *edge) {
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

/* Visit each outcome's named identities once; no joined cache or historical
 * setup representative can decide liveness for a different branch. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6, 8) void dep_mark_live_named_tree(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *original_edges,
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, const bool *named_setup_documents,
    uint32_t original_edge_count, bool *live_named_documents, uint32_t root) {
  if (!root)
    return;
  const dep_route_change_t *change = &journal->entries[root - 1];
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
  dep_mark_live_named_tree(graph, original_edges, state, journal, baseline,
                           named_setup_documents, original_edge_count,
                           live_named_documents, change->left);
  if (change->fd.value == SHELL_DEP_FD_NAMED &&
      change->access == DEP_FD_ACCESS_BINDING) {
    dep_route_set_t bindings = dep_fd_fact(state, journal, baseline, change->fd,
                                           DEP_FD_ACCESS_BINDING);
    bool live = false;
    for (uint32_t i = 0; i < bindings.count; i++)
      live |= bindings.routes[i].kind == DEP_ROUTE_INHERITED;
    if (live)
      for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
           access <<= 1) {
        dep_route_set_t routes = dep_fd_fact(
            state, journal, baseline, change->fd, (dep_fd_access_t)access);
        for (uint32_t i = 0; i < routes.count; i++) {
          dep_fd_route_t route = routes.routes[i];
          if (route.kind != DEP_ROUTE_DOC || route.value >= original_edge_count)
            continue;
          uint32_t document =
              dep_edge_document_index(graph, &original_edges[route.value]);
          if (document != UINT32_MAX && named_setup_documents[document])
            live_named_documents[document] = true;
        }
      }
  }
  dep_mark_live_named_tree(graph, original_edges, state, journal, baseline,
                           named_setup_documents, original_edge_count,
                           live_named_documents, change->right);
}

/* A named FD_OPEN remains meaningful only if the final persistent descriptor
 * table still reaches its original document. Historical setup edges alone are
 * not enough: `exec {fd}>out; exec {fd}>&-` has opened `out`, but has retired
 * that binding before any ordinary byte flow can use it. */
static SHELL_NONNULL(1, 2, 4, 5, 6, 7, 8) void dep_mark_transient_documents(
    shell_dep_graph_t *graph, const shell_dep_edge_t *original_edges,
    uint32_t original_edge_count, const dep_fd_flow_t *final,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    bool *named_setup_documents, bool *live_named_documents) {
  bool effective_documents[SHELL_DEP_MAX_NODES] = {false};
  bool numeric_setup_documents[SHELL_DEP_MAX_NODES] = {false};
  memset(named_setup_documents, 0,
         SHELL_DEP_MAX_NODES * sizeof(named_setup_documents[0]));
  memset(live_named_documents, 0,
         SHELL_DEP_MAX_NODES * sizeof(live_named_documents[0]));
  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    const shell_dep_edge_t *original = &original_edges[edge];
    if (original->source_fd != SHELL_DEP_FD_NAMED &&
        original->target_fd != SHELL_DEP_FD_NAMED)
      continue;
    uint32_t document = dep_edge_document_index(graph, original);
    if (document != UINT32_MAX)
      named_setup_documents[document] = true;
  }

  for (unsigned outcome = 0; outcome < 5; outcome++)
    if (final->mask & (1u << outcome))
      dep_mark_live_named_tree(graph, original_edges, &final->state[outcome],
                               journal, baseline, named_setup_documents,
                               original_edge_count, live_named_documents,
                               final->state[outcome].root);

  /* Accumulate document use and numeric setup in one graph pass. The old
   * per-document edge search made a graph with D documents and E edges cost
   * O(D*E), despite both relations being simple endpoint properties. */
  for (uint32_t edge_index = 0; edge_index < graph->edge_count; edge_index++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    const shell_dep_edge_t *edge = &graph->edges[edge_index];
    if (edge->type == SHELL_EDGE_READ &&
        graph->nodes[edge->from].type == SHELL_NODE_DOC)
      effective_documents[edge->from] = true;
    else if ((edge->type == SHELL_EDGE_WRITE ||
              edge->type == SHELL_EDGE_APPEND) &&
             graph->nodes[edge->to].type == SHELL_NODE_DOC)
      effective_documents[edge->to] = true;
    if (edge->type != SHELL_EDGE_FD_OPEN)
      continue;
    if (graph->nodes[edge->from].type == SHELL_NODE_DOC &&
        edge->target_fd != SHELL_DEP_FD_NAMED)
      numeric_setup_documents[edge->from] = true;
    if (edge->to != edge->from &&
        graph->nodes[edge->to].type == SHELL_NODE_DOC &&
        edge->source_fd != SHELL_DEP_FD_NAMED)
      numeric_setup_documents[edge->to] = true;
  }

  for (uint32_t node = 0; node < graph->node_count; node++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    shell_dep_node_t *document = &graph->nodes[node];
    if (document->type != SHELL_NODE_DOC)
      continue;
    bool effective = effective_documents[node];
    bool retired_named_setup =
        named_setup_documents[node] && !live_named_documents[node];
    if (document->doc.kind == SHELL_DOC_FILE) {
      if (!effective && (numeric_setup_documents[node] || retired_named_setup))
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
  /* A name is present exactly for a preconstructed named descriptor; numeric
   * and absent endpoints carry NULL. Project that semantic discriminator. */
  if (source_fd.name)
    dep_set_named_fd(edge, true, source_fd.name, source_fd.name_len);
  if (target_fd.name)
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
  bool fed[SHELL_DEP_MAX_NODES] = {false};
  bool retained[SHELL_DEP_MAX_NODES] = {false};
  bool setup[SHELL_DEP_MAX_NODES] = {false};
  bool any_discarded = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *current = &graph->edges[edge];
    if (current->type == SHELL_EDGE_WRITE)
      fed[current->to] = retained[current->to] = true;
    if (current->type == SHELL_EDGE_SUBST)
      retained[current->from] = true;
    if (current->type == SHELL_EDGE_FD_OPEN) {
      retained[current->from] = retained[current->to] = true;
      setup[current->from] = setup[current->to] = true;
    }
  }
  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (graph->nodes[node].type != SHELL_NODE_ENDPOINT ||
        graph->nodes[node].endpoint.reserved == DEP_ENDPOINT_TERMINAL_PIPE)
      continue;
    /* A collector needs input or setup; an unconnected raw pipe needs any
     * surviving descriptor use. Retire overwritten numeric raw pipes too. */
    discard[node] =
        graph->nodes[node].endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE
            ? !retained[node]
            : !fed[node] && !setup[node];
    any_discarded = any_discarded || discard[node];
  }
  if (!any_discarded)
    return true;

  uint32_t remap[SHELL_DEP_MAX_NODES];
  uint32_t kept_nodes = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    remap[node] = discard[node] ? UINT32_MAX : kept_nodes++;

  /* Deferred stream uses record executions and TIME producers by their current
   * graph indices. Validate every owner and pipeline anchor before compaction:
   * retaining a discarded or unsupported owner would otherwise materialize a
   * descriptor relation on the wrong node after compaction. */
  if (streams) {
    if (streams->fd_import_use_count > SHELL_DEP_MAX_EDGES ||
        streams->capture_use_count > SHELL_DEP_MAX_EDGES ||
        streams->pipe_use_count > SHELL_DEP_MAX_EDGES)
      return false;
    for (uint32_t use = 0; use < streams->fd_import_use_count; use++) {
      uint32_t owner = streams->fd_import_uses[use].owner;
      if (owner >= graph->node_count || discard[owner] ||
          (!dep_is_execution_node(graph, owner) &&
           graph->nodes[owner].type != SHELL_NODE_TIME))
        return false;
    }
    for (uint32_t list = 0; list < 2; list++) {
      const dep_stream_use_t *uses =
          list == 0 ? streams->capture_uses : streams->pipe_uses;
      uint32_t count =
          list == 0 ? streams->capture_use_count : streams->pipe_use_count;
      for (uint32_t use = 0; use < count; use++) {
        uint32_t owner = uses[use].owner;
        if (owner >= graph->node_count || discard[owner] ||
            (!dep_is_execution_node(graph, owner) &&
             graph->nodes[owner].type != SHELL_NODE_TIME))
          return false;
        if (list != 0 && (uses[use].anchor >= graph->node_count ||
                          discard[uses[use].anchor] ||
                          !dep_is_execution_node(graph, uses[use].anchor)))
          return false;
      }
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
      if (current.cmd.pipeline_time_id != 0)
        current.cmd.pipeline_time_id =
            remap[current.cmd.pipeline_time_id - 1] + 1;
      if (current.cmd.pipe_stdin_source != UINT32_MAX)
        current.cmd.pipe_stdin_source = remap[current.cmd.pipe_stdin_source];
      if (current.cmd.pipe_stdin_target != UINT32_MAX)
        current.cmd.pipe_stdin_target = remap[current.cmd.pipe_stdin_target];
      if (current.cmd.pipe_stdout_source != UINT32_MAX)
        current.cmd.pipe_stdout_source = remap[current.cmd.pipe_stdout_source];
      if (current.cmd.pipe_stdout_target != UINT32_MAX)
        current.cmd.pipe_stdout_target = remap[current.cmd.pipe_stdout_target];
    }
    if (current.type == SHELL_NODE_GROUP) {
      if (current.group.pipeline_time_id != 0)
        current.group.pipeline_time_id =
            remap[current.group.pipeline_time_id - 1] + 1;
      if (current.group.parent != UINT32_MAX)
        current.group.parent = remap[current.group.parent];
    }
    graph->nodes[remap[node]] = current;
    if (streams)
      streams->unresolved_paths[remap[node]] = streams->unresolved_paths[node];
  }
  if (streams) {
    for (uint32_t use = 0; use < streams->fd_import_use_count; use++)
      streams->fd_import_uses[use].owner =
          remap[streams->fd_import_uses[use].owner];
    for (uint32_t use = 0; use < streams->capture_use_count; use++)
      streams->capture_uses[use].owner =
          remap[streams->capture_uses[use].owner];
    for (uint32_t use = 0; use < streams->pipe_use_count; use++) {
      streams->pipe_uses[use].owner = remap[streams->pipe_uses[use].owner];
      streams->pipe_uses[use].anchor = remap[streams->pipe_uses[use].anchor];
    }
  }
  graph->node_count = kept_nodes;
  return true;
}

static uint32_t dep_collect_time_boundaries(
    const shell_dep_graph_t *graph, const char *cmd, uint32_t command_length,
    const shell_parse_result_t *fast, const shell_pipeline_index_t *pipeline,
    const uint32_t *node_range, const uint32_t *range_node,
    const uint32_t *node_group, const uint32_t *group_node,
    const dep_group_exec_t *group_exec, dep_time_boundary_t *boundaries,
    uint32_t capacity);

static bool dep_add_pipeline_time_nodes(
    shell_dep_graph_t *graph, const char *cmd, uint32_t command_length,
    const shell_parse_result_t *fast, const shell_pipeline_index_t *pipeline,
    const uint32_t *range_node, const uint32_t *group_node, uint32_t max_nodes,
    uint32_t max_edges, dep_route_workspace_t *workspace,
    dep_subgraph_streams_t *streams);
static void dep_finalize_time_report_route(shell_dep_graph_t *graph,
                                           uint32_t timer,
                                           uint32_t retained_graph_routes);

/* A timing report executes in the shell which owns the reserved prefix, after
 * the measured pipeline's temporary redirect frame has been restored. An
 * enclosing compound redirect is still active, so prefer that group's evolving
 * snapshot; otherwise use the persistent table for the current shell. */
static const dep_route_set_t *
dep_time_report_context_snapshot(const dep_route_workspace_t *workspace,
                                 const dep_time_boundary_t *boundary) {
  if (boundary->target_scope && boundary->target_group >= 0 &&
      boundary->target_group < SHELL_MAX_GROUPS &&
      workspace->group_time_routes_ready[boundary->target_group])
    return &workspace->group_time_routes[boundary->target_group];
  if (boundary->target_shell_state && boundary->target_group >= 0 &&
      boundary->target_group < SHELL_MAX_GROUPS &&
      workspace->group_shell_time_routes_ready[boundary->target_group])
    return &workspace->group_shell_time_routes[boundary->target_group];
  if (boundary->context_group >= 0 &&
      boundary->context_group < SHELL_MAX_GROUPS &&
      workspace->group_time_routes_ready[boundary->context_group])
    return &workspace->group_time_routes[boundary->context_group];
  return &workspace->persistent_time_routes;
}

static bool dep_route_set_add(dep_route_set_t *snapshot, dep_fd_route_t route) {
  for (uint32_t i = 0; i < snapshot->count; i++)
    if (snapshot->routes[i].kind == route.kind &&
        snapshot->routes[i].value == route.value)
      return true;
  if (snapshot->count >= SHELL_DEP_TIME_MAX_EXTERNAL_FDS) {
    snapshot->truncated = true;
    return false;
  }
  snapshot->routes[snapshot->count++] = route;
  snapshot->ready = true;
  return true;
}

static void dep_route_set_set(dep_route_set_t *snapshot, dep_fd_route_t route) {
  *snapshot = (dep_route_set_t){0};
  (void)dep_route_set_add(snapshot, route);
}

static SHELL_NONNULL(2) const dep_route_change_t *dep_route_root_change(
    uint32_t root, const dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access) {
  uint32_t cursor = root;
  while (cursor != 0) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    const dep_route_change_t *change = &changes->entries[cursor - 1];
    int order = dep_fd_ref_compare(change->fd, fd);
    if (order == 0)
      order = change->access < access ? -1 : change->access != access;
    if (order == 0)
      return change;
    cursor = order > 0 ? change->left : change->right;
  }
  return NULL;
}

/* Path-independent queries use dep_fd_raw_fact(). This helper is reserved for
 * callers already operating on the selected primary immutable version. */
static SHELL_NONNULL(1, 2) const dep_route_change_t *dep_route_state_change(
    const dep_route_state_t *state, const dep_route_journal_t *changes,
    dep_fd_ref_t fd, dep_fd_access_t access) {
  return dep_route_root_change(state->root, changes, fd, access);
}

static SHELL_NONNULL(1, 2) bool dep_route_state_has_change(
    const dep_route_state_t *state, const dep_route_journal_t *changes,
    dep_fd_ref_t fd, dep_fd_access_t access) {
  uint32_t count = dep_route_state_count(state);
  for (uint32_t path = 0; path < count; path++)
    if (dep_route_root_change(dep_route_state_root(state, changes, path),
                              changes, fd, access))
      return true;
  return false;
}

static SHELL_NONNULL(1, 3) int dep_route_snapshot_compare(const void *context,
                                                          uint32_t index,
                                                          const void *pending) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  const dep_route_journal_t *journal = context;
  const dep_route_set_t *left = &journal->snapshots[index], *right = pending;
  if (left->count != right->count)
    return left->count < right->count ? -1 : 1;
  if (left->ready != right->ready)
    return left->ready ? 1 : -1;
  if (left->truncated != right->truncated)
    return left->truncated ? 1 : -1;
  for (uint32_t i = 0; i < left->count; i++) {
    if (left->routes[i].kind != right->routes[i].kind)
      return left->routes[i].kind < right->routes[i].kind ? -1 : 1;
    if (left->routes[i].value != right->routes[i].value)
      return left->routes[i].value < right->routes[i].value ? -1 : 1;
  }
  return 0;
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_route_set_intern(dep_route_journal_t *changes,
                         const dep_route_set_t *routes) {
  uint32_t candidate = changes->snapshot_count + 1, match = 0;
  changes->snapshot_root =
      dep_index_insert(changes->snapshot_index, changes->snapshot_root,
                       candidate, DEP_ROUTE_SNAPSHOT_CAPACITY,
                       dep_route_snapshot_compare, changes, routes, &match);
  if (match == candidate) {
    changes->snapshots[changes->snapshot_count++] = *routes;
  }
  return match;
}

/* Snapshot interning is mutable within a parse, unlike published route
 * versions. A recursive child removes only its newly interned suffix before
 * releasing borrowed child source and reclaiming workspace storage. */
/* key identifies an existing interned snapshot; callers maintain that
 * invariant. Removing a two-child node moves links, never record identities. */
static SHELL_NONNULL(1, 3) uint32_t
    dep_snapshot_index_remove(dep_route_journal_t *journal, uint32_t root,
                              const dep_route_set_t *key) {
  return dep_index_erase(journal->snapshot_index, root,
                         dep_route_snapshot_compare, journal, key);
}

static SHELL_NONNULL(1) void dep_route_journal_reset(
    dep_route_journal_t *journal) {
  journal->count = 0;
  journal->snapshot_count = 0;
  journal->snapshot_root = 0;
  journal->alternative_count = 0;
  journal->allocation_root = journal->allocation_count = 0;
  journal->observable_fd_count = 0;
  journal->observe_undo = false;
  journal->named_closes = false;
  journal->ifs_seen = false;
  memset(journal->joins, 0, sizeof(journal->joins));
}

static SHELL_NONNULL(1) void dep_route_journal_rewind(
    dep_route_journal_t *journal, uint32_t nodes, uint32_t snapshots,
    uint32_t alternatives, uint32_t allocations);

static SHELL_NONNULL(1, 3) int dep_allocation_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_allocation_t *left =
      &((const dep_route_journal_t *)context)->allocations[index];
  const dep_allocation_t *right = key;
  if (left->name != right->name)
    return (uintptr_t)left->name < (uintptr_t)right->name ? -1 : 1;
  return left->position < right->position ? -1
                                          : left->position != right->position;
}

/* op is one successfully reached, prepared allocation. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_allocation_slot(dep_route_journal_t *journal, const dep_fd_op_t *op) {
  dep_allocation_t key = {.name = op->fd_name, .position = op->pos};
  uint32_t candidate = journal->allocation_count + 1, match = 0;
  journal->allocation_root =
      dep_index_insert(journal->allocation_index, journal->allocation_root,
                       candidate, DEP_ROUTE_OPERATION_CAPACITY,
                       dep_allocation_compare, journal, &key, &match);
  if (match == candidate)
    journal->allocations[journal->allocation_count++] = key;
  return match ? SHELL_DEP_FD_MAX + match : SHELL_DEP_FD_NONE;
}

static SHELL_NONNULL(1) void dep_route_journal_rewind(
    dep_route_journal_t *journal, uint32_t nodes, uint32_t snapshots,
    uint32_t alternatives, uint32_t allocations) {
  while (journal->allocation_count > allocations) {
    journal->allocation_root =
        dep_index_erase(journal->allocation_index, journal->allocation_root,
                        dep_allocation_compare, journal,
                        &journal->allocations[journal->allocation_count - 1]);
    journal->allocation_count--;
  }
  while (journal->snapshot_count > snapshots) {
    journal->snapshot_root = dep_snapshot_index_remove(
        journal, journal->snapshot_root,
        &journal->snapshots[journal->snapshot_count - 1]);
    journal->snapshot_count--;
  }
  journal->count = nodes;
  journal->alternative_count = alternatives;
  memset(journal->joins, 0, sizeof(journal->joins));
}

static SHELL_NONNULL(1) unsigned dep_route_tree_height(
    const dep_route_journal_t *journal, uint32_t root) {
  return root ? journal->entries[root - 1].height : 0;
}

static SHELL_NONNULL(1) int dep_route_tree_balance(dep_route_journal_t *journal,
                                                   uint32_t root) {
  dep_route_change_t *node = &journal->entries[root - 1];
  unsigned left = dep_route_tree_height(journal, node->left);
  unsigned right = dep_route_tree_height(journal, node->right);
  node->height = (uint8_t)(1 + (left > right ? left : right));
  return (int)left - (int)right;
}

static SHELL_NONNULL(1) int dep_route_tree_skew(
    const dep_route_journal_t *journal, uint32_t root) {
  const dep_route_change_t *node = &journal->entries[root - 1];
  return (int)dep_route_tree_height(journal, node->left) -
         (int)dep_route_tree_height(journal, node->right);
}

/* append preflights one update's maximum path/rotation storage. Only freshly
 * cloned nodes may be mutated; all published roots remain immutable. */
static SHELL_NONNULL(1) uint32_t
    dep_route_tree_clone(dep_route_journal_t *journal, uint32_t root) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  journal->entries[journal->count] = journal->entries[root - 1];
  return ++journal->count;
}

static SHELL_NONNULL(1) uint32_t
    dep_route_tree_rotate(dep_route_journal_t *journal, uint32_t root,
                          bool left) {
  dep_route_change_t *node = &journal->entries[root - 1];
  uint32_t next =
      dep_route_tree_clone(journal, left ? node->right : node->left);
  dep_route_change_t *pivot = &journal->entries[next - 1];
  if (left) {
    node->right = pivot->left;
    pivot->left = root;
  } else {
    node->left = pivot->right;
    pivot->right = root;
  }
  dep_route_tree_balance(journal, root);
  dep_route_tree_balance(journal, next);
  return next;
}

static SHELL_NONNULL(1) uint32_t
    dep_route_tree_set(dep_route_journal_t *journal, uint32_t root,
                       dep_fd_ref_t fd, dep_fd_access_t access,
                       uint32_t snapshot) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  if (!root) {
    journal->entries[journal->count] = (dep_route_change_t){
        .fd = fd, .snapshot = snapshot, .height = 1, .access = access};
    return ++journal->count;
  }
  const dep_route_change_t *old = &journal->entries[root - 1];
  int order = dep_fd_ref_compare(old->fd, fd);
  if (!order)
    order = old->access < access ? -1 : old->access != access;
  if (!order && old->snapshot == snapshot)
    return root;
  uint32_t next = 0;
  if (order) {
    uint32_t child = order > 0 ? old->left : old->right;
    next = dep_route_tree_set(journal, child, fd, access, snapshot);
    if (next == child)
      return root;
  }
  root = dep_route_tree_clone(journal, root);
  dep_route_change_t *node = &journal->entries[root - 1];
  if (!order)
    node->snapshot = snapshot;
  else if (order > 0)
    node->left = next;
  else
    node->right = next;
  int balance = dep_route_tree_balance(journal, root);
  if (balance > 1) {
    if (dep_route_tree_skew(journal, node->left) < 0) {
      node->left = dep_route_tree_clone(journal, node->left);
      node->left = dep_route_tree_rotate(journal, node->left, true);
    }
    return dep_route_tree_rotate(journal, root, false);
  }
  if (balance < -1) {
    if (dep_route_tree_skew(journal, node->right) > 0) {
      node->right = dep_route_tree_clone(journal, node->right);
      node->right = dep_route_tree_rotate(journal, node->right, false);
    }
    return dep_route_tree_rotate(journal, root, true);
  }
  return root;
}

static SHELL_NONNULL(1, 2) bool dep_route_state_append_one(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes) {
  if (dep_route_tree_height(changes, state->root) + 5 >
      DEP_ROUTE_CHANGE_CAPACITY - changes->count) {
    state->truncated = true;
    return false;
  }
  uint32_t snapshot = dep_route_set_intern(changes, &routes);
  if (snapshot == 0) {
    state->truncated = true;
    return false;
  }
  state->root = dep_route_tree_set(changes, state->root, fd, access, snapshot);
  return true;
}

static SHELL_NONNULL(1, 2, 3) dep_route_set_t
    dep_route_state_get_access(const dep_route_state_t *state,
                               const dep_route_journal_t *changes,
                               const dep_owner_routes_t *baseline,
                               dep_fd_ref_t fd, dep_fd_access_t access) {
  /* An invalidated descriptor variable cannot revive an older binding from
   * the alternative journal. Reallocation installs a baseline slot before
   * its new alternatives are queried. */
  const dep_fd_route_entry_t *slot = dep_route_find(baseline, fd);
  bool visible = fd.value != SHELL_DEP_FD_NAMED || slot != NULL;
  if (!visible) {
    dep_route_set_t result = {0};
    dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value});
    result.truncated = state->truncated;
    return result;
  }
  dep_route_set_t result = dep_fd_fact(state, changes, baseline, fd, access);
  result.truncated |= state->truncated;
  return result;
}

static SHELL_NONNULL(1, 2) bool dep_route_state_store_access(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes) {
  dep_route_state_t previous = *state;
  dep_route_state_t updated = {0};
  uint32_t count = dep_route_state_count(&previous);
  for (uint32_t i = 0; i < count; i++) {
    dep_route_state_t one =
        dep_route_state_single(dep_route_state_root(&previous, changes, i));
    if (!dep_route_state_append_one(&one, changes, fd, access, routes)) {
      state->truncated = true;
      return false;
    }
    if (i == 0)
      updated.root = one.root;
    else if (!dep_route_state_add_root(&updated, changes, one.root)) {
      state->truncated = true;
      return false;
    }
  }
  updated.truncated = previous.truncated;
  updated.correlated = previous.correlated;
  *state = updated;
  return true;
}

/* Imports use one provenance record per route alternative. Seed the concrete
 * table with the first outcome, and retain all outcomes in the same journal
 * used by ordinary descriptor replay. */
static SHELL_NONNULL(1, 2) bool dep_import_route_alternatives(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_fd_imports_t *imports) {
  if (!imports)
    return true;
  if (imports->ifs && !dep_ifs_store(state, changes, imports->ifs))
    return false;
  uint32_t order[DEP_MAX_FD_IMPORTS], count = 0;
  dep_import_order(imports, imports->root, order, &count);
  for (uint32_t i = 0; i < count;) {
    const dep_fd_import_t *first = &imports->entries[order[i]];
    dep_route_set_t routes = {.ready = true};
    do {
      uint32_t index = order[i++];
      const dep_fd_import_t *item = &imports->entries[index];
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
      dep_route_set_add(
          &routes, item->origin ? (dep_fd_route_t){DEP_ROUTE_IMPORTED, index}
                                : item->route);
    } while (i < count && imports->entries[order[i]].access == first->access &&
             dep_fd_ref_equal(imports->entries[order[i]].fd, first->fd));
    if (routes.truncated ||
        ((routes.count > 1 || first->access == DEP_FD_ACCESS_BINDING) &&
         !dep_route_state_store_access(state, changes, first->fd,
                                       (dep_fd_access_t)first->access, routes)))
      return false;
  }
  return true;
}

static dep_route_set_t dep_route_state_get(const dep_route_state_t *state,
                                           const dep_route_journal_t *changes,
                                           const dep_owner_routes_t *baseline,
                                           dep_fd_ref_t fd) {
  return dep_route_state_get_access(state, changes, baseline, fd,
                                    DEP_FD_ACCESS_WRITE);
}

/* Replay successful setup against its immutable entry. Duplications copy
 * capabilities, not absence: absence makes setup fail before replacement.
 * The outcome stream separately retains those failed setup prefixes. */
static SHELL_NONNULL(1) bool dep_allocation_remove_candidate(
    dep_route_set_t *available, uint32_t fd) {
  for (uint32_t i = 0; i < available->count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    if (available->routes[i].value == fd) {
      memmove(available->routes + i, available->routes + i + 1,
              (available->count - i - 1) * sizeof(available->routes[0]));
      available->count--;
      return true;
    }
  }
  return false;
}

typedef struct {
  bool may_be_free;
  bool may_be_occupied;
} dep_fd_occupancy_t;

static SHELL_NONNULL(1, 2, 3) dep_fd_occupancy_t
    dep_fd_occupancy(const dep_route_state_t *state,
                     const dep_route_journal_t *journal,
                     const dep_owner_routes_t *baseline, uint32_t fd) {
  dep_route_set_t binding = dep_fd_fact(
      state, journal, baseline, dep_fd_numeric(fd), DEP_FD_ACCESS_BINDING);
  dep_fd_occupancy_t result = {0};
  for (uint32_t route = 0; route < binding.count; route++) {
    switch (binding.routes[route].kind) {
    case DEP_ROUTE_CLOSED:
    case DEP_ROUTE_ABSENT:
    case DEP_ROUTE_UNAVAILABLE:
      result.may_be_free = true;
      break;
    case DEP_ROUTE_UNSEEN:
    case DEP_ROUTE_DYNAMIC:
      result.may_be_free = true;
      result.may_be_occupied = true;
      break;
    default:
      result.may_be_occupied = true;
      break;
    }
  }
  return result;
}

/* Select the possible descriptor at one Bash lowest-free rank. Observable
 * numeric spellings retain their exact identity. Unmentioned intervals are one
 * private identity because no later source operation can distinguish members
 * of that interval. rank is one or two. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_allocation_rank_slots(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_route_set_t *numeric, uint32_t rank,
    bool *abstract) {
  bool possible[2] = {true, false};
  uint32_t previous = DEP_BASH_VARREDIR_MIN_FD;
  for (uint32_t i = 0; i < journal->observable_fd_count; i++) {
    uint32_t fd = journal->observable_fds[i];
    if (fd < DEP_BASH_VARREDIR_MIN_FD)
      continue;
    if (fd > previous) {
      uint32_t gap = fd - previous;
      bool expanded[2] = {possible[0], possible[1]};
      for (uint32_t count = 0; count < rank; count++) {
        if (!possible[count])
          continue;
        *abstract = true;
        uint32_t added = rank - 1 - count;
        if (added > gap)
          added = gap;
        for (uint32_t free_count = 1; free_count <= added; free_count++)
          expanded[count + free_count] = true;
      }
      possible[0] = expanded[0];
      possible[1] = expanded[1];
    }

    dep_fd_occupancy_t occupancy =
        dep_fd_occupancy(state, journal, baseline, fd);
    bool next[2] = {false, false};
    for (uint32_t count = 0; count < rank; count++) {
      if (!possible[count])
        continue;
      if (occupancy.may_be_occupied)
        next[count] = true;
      if (!occupancy.may_be_free)
        continue;
      if (count + 1 == rank) {
        if (!dep_route_set_add(numeric, (dep_fd_route_t){DEP_ROUTE_ALIAS, fd}))
          return false;
      } else {
        next[count + 1] = true;
      }
    }
    possible[0] = next[0];
    possible[1] = next[1];
    if (fd == UINT32_MAX)
      break;
    previous = fd + 1;
  }
  for (uint32_t count = 0; count < rank; count++)
    *abstract |= possible[count];
  return true;
}

typedef struct {
  dep_route_set_t slots[2];
  bool resource;
} dep_named_allocation_choices_t;

/* Low-descriptor occupancy determines whether Bash's temporary file open
 * consumes a high slot. A previous allocation path can refine that state. */
static SHELL_NONNULL(1, 2, 3) unsigned dep_fd_low_modes(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline) {
  bool low_free = false, low_full = true;
  for (uint32_t fd = 0; fd < DEP_BASH_VARREDIR_MIN_FD; fd++) {
    dep_fd_occupancy_t occupancy =
        dep_fd_occupancy(state, journal, baseline, fd);
    low_free |= occupancy.may_be_free;
    low_full &= occupancy.may_be_occupied;
  }
  dep_route_set_t mode = dep_fd_raw_fact(state, journal, baseline,
                                         dep_fd_numeric(SHELL_DEP_FD_NONE),
                                         DEP_FD_ACCESS_LOW_STATE);
  if (mode.count == 1) {
    low_free &= mode.routes[0].value == 0;
    low_full &= mode.routes[0].value == 1;
  }
  return (low_free ? 1u : 0u) | (low_full ? 2u : 0u);
}

static SHELL_NONNULL(1, 2, 3, 4, 6) bool dep_allocation_rank_choices(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, const dep_fd_op_t *op, uint32_t rank,
    dep_route_set_t *slots) {
  dep_route_set_t numeric = {0};
  bool abstract = false;
  if (!dep_allocation_rank_slots(state, journal, baseline, &numeric, rank,
                                 &abstract))
    return false;
  uint32_t private_slot = dep_allocation_slot(journal, op);
  if (private_slot == SHELL_DEP_FD_NONE)
    return false;
  if (abstract && !dep_route_set_add(
                      slots, (dep_fd_route_t){DEP_ROUTE_ALIAS, private_slot}))
    return false;
  for (uint32_t candidate = 0; candidate < numeric.count; candidate++)
    if (!dep_route_set_add(slots, numeric.routes[candidate]))
      return false;
  return slots->count != 0;
}

static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_named_allocation_choices(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, const dep_fd_op_t *op,
    dep_named_allocation_choices_t *choices) {
  if (op->kind == DEP_FD_OP_DUP) {
    if (!dep_allocation_rank_choices(state, journal, baseline, op, 1,
                                     &choices->slots[0]))
      return false;
    dep_route_set_t available = dep_fd_raw_fact(
        state, journal, baseline, dep_fd_numeric(SHELL_DEP_FD_NONE),
        DEP_FD_ACCESS_AVAILABLE);
    for (uint32_t candidate = 0; candidate < available.count; candidate++)
      if (available.routes[candidate].kind == DEP_ROUTE_ALIAS &&
          available.routes[candidate].value > SHELL_DEP_FD_MAX &&
          !dep_route_set_add(&choices->slots[0], available.routes[candidate]))
        return false;
  } else {
    /* Bash opens the resource first, duplicates it with F_DUPFD starting at
     * 10, and closes the temporary open. A low temporary fd leaves the first
     * high slot free; a high temporary fd consumes it, so the retained slot
     * is the second free high fd. */
    unsigned modes = dep_fd_low_modes(state, journal, baseline);
    bool low_free = (modes & 1u) != 0, low_full = (modes & 2u) != 0;
    choices->resource = true;
    if ((low_free && !dep_allocation_rank_choices(state, journal, baseline, op,
                                                  1, &choices->slots[0])) ||
        (low_full && !dep_allocation_rank_choices(state, journal, baseline, op,
                                                  2, &choices->slots[1])))
      return false;
    dep_route_set_t available = dep_fd_raw_fact(
        state, journal, baseline, dep_fd_numeric(SHELL_DEP_FD_NONE),
        DEP_FD_ACCESS_AVAILABLE);
    for (uint32_t candidate = 0; candidate < available.count; candidate++) {
      if (available.routes[candidate].kind != DEP_ROUTE_ALIAS ||
          available.routes[candidate].value <= SHELL_DEP_FD_MAX)
        continue;
      if (low_free &&
          !dep_route_set_add(&choices->slots[0], available.routes[candidate]))
        return false;
    }
  }
  if (!choices->slots[0].count && !choices->slots[1].count)
    return false;
  return true;
}

/* Bash preserves each live numeric redirect target in a private descriptor
 * before changing it. The saved marker prevents a repeated target in the same
 * redirect list from acquiring another undo slot. Unknown inherited targets
 * retain both the no-save and saved possibilities in one bounded route set.
 * rank is 1/2 for a constrained low-FD mode or 0 for their bounded union. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_prepare_numeric_undo(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, const dep_fd_op_t *op, uint32_t rank) {
  if (!dep_fd_op_saves_numeric(op) || !journal->observe_undo ||
      !journal->observable_fd_count)
    return true;
  dep_fd_ref_t target = dep_fd_numeric(op->fd);
  dep_route_set_t saved =
      dep_fd_raw_fact(state, journal, baseline, target, DEP_FD_ACCESS_SAVED);
  dep_route_set_t frame =
      dep_fd_raw_fact(state, journal, baseline,
                      dep_fd_numeric(SHELL_DEP_FD_NONE), DEP_FD_ACCESS_ENTRY);
  dep_route_set_t saved_frame = dep_fd_raw_fact(
      state, journal, baseline, target, DEP_FD_ACCESS_SAVE_FRAME);
  if (saved.count && saved_frame.count == 1 &&
      saved_frame.routes[0].value == frame.routes[0].value)
    return true;

  dep_route_set_t binding =
      dep_fd_fact(state, journal, baseline, target, DEP_FD_ACCESS_BINDING);
  bool may_be_free = false, may_be_live = false;
  for (uint32_t route = 0; route < binding.count; route++) {
    switch (binding.routes[route].kind) {
    case DEP_ROUTE_CLOSED:
    case DEP_ROUTE_ABSENT:
    case DEP_ROUTE_UNAVAILABLE:
      may_be_free = true;
      break;
    case DEP_ROUTE_UNSEEN:
    case DEP_ROUTE_DYNAMIC:
      may_be_free = may_be_live = true;
      break;
    default:
      may_be_live = true;
      break;
    }
  }

  dep_route_set_t undo = {0};
  if (may_be_live) {
    dep_route_set_t slots = {0};
    dep_route_state_t occupied = *state;
    dep_route_set_t live = {0};
    dep_route_set_set(&live, (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
    if (!dep_route_state_store_access(&occupied, journal, target,
                                      DEP_FD_ACCESS_BINDING, live) ||
        !dep_allocation_rank_choices(&occupied, journal, baseline, op,
                                     rank ? rank : 1, &slots) ||
        (!rank && !dep_allocation_rank_choices(&occupied, journal, baseline, op,
                                               2, &slots)))
      return false;
    for (uint32_t slot = 0; slot < slots.count; slot++)
      if (!dep_route_set_add(&undo, slots.routes[slot]))
        return false;
    /* Saved descriptors have the target's capabilities and occupy their
     * physical slots during setup. Store them per slot, not as one global
     * route set bounded by the public report's sixteen sinks. */
    for (uint32_t slot = 0; slot < slots.count; slot++) {
      dep_fd_ref_t scratch = dep_fd_numeric(slots.routes[slot].value);
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
        dep_route_set_t routes =
            access == DEP_FD_ACCESS_BINDING
                ? live
                : dep_fd_raw_fact(state, journal, baseline, target,
                                  (dep_fd_access_t)access);
        if (slots.count > 1 || may_be_free) {
          dep_route_set_t prior = dep_fd_raw_fact(
              state, journal, baseline, scratch, (dep_fd_access_t)access);
          for (uint32_t route = 0; route < prior.count; route++)
            if (!dep_route_set_add(&routes, prior.routes[route]))
              return false;
        }
        if (!dep_route_state_store_access(state, journal, scratch,
                                          (dep_fd_access_t)access, routes))
          return false;
      }
    }
  }
  if (may_be_free &&
      !dep_route_set_add(&undo, (dep_fd_route_t){DEP_ROUTE_ABSENT, UINT32_MAX}))
    return false;
  return dep_route_state_store_access(state, journal, target,
                                      DEP_FD_ACCESS_SAVED, undo) &&
         dep_route_state_store_access(state, journal, target,
                                      DEP_FD_ACCESS_SAVE_FRAME, frame);
}

static SHELL_NONNULL(1, 2, 3) bool dep_route_state_apply_one(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_owner_routes_t *baseline_before, const dep_fd_op_t *ops,
    uint32_t op_count, const dep_fd_route_t *allocated) {
  if (op_count == 0)
    return !route_state->truncated;
  dep_route_state_t after = *route_state;
  bool complete = true;

  for (uint32_t i = 0; i < op_count; i++) {
    const dep_fd_op_t *op = &ops[i];
    dep_route_state_t before_operation = after;
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    dep_fd_ref_t target = {op->fd, op->fd_name, op->fd_name_len};
    dep_route_set_t available = dep_fd_raw_fact(
        &after, changes, baseline_before, dep_fd_numeric(SHELL_DEP_FD_NONE),
        DEP_FD_ACCESS_AVAILABLE);
    dep_route_set_t slots = {0};
    bool named = target.value == SHELL_DEP_FD_NAMED;
    bool indirect =
        named && (changes->observable_fd_count || changes->named_closes);
    if (named && op->resets_descriptor) {
      dep_route_set_set(
          &slots, indirect
                      ? *allocated
                      : (dep_fd_route_t){DEP_ROUTE_ALIAS, SHELL_DEP_FD_NAMED});
    } else if (named) {
      slots = dep_fd_raw_fact(&after, changes, baseline_before, target,
                              DEP_FD_ACCESS_READ);
      dep_route_set_t identities = {0};
      for (uint32_t slot = 0; slot < slots.count; slot++)
        if (slots.routes[slot].kind == DEP_ROUTE_ALIAS &&
            !dep_route_set_add(&identities, slots.routes[slot]))
          return false;
      /* Imported variables may not retain an abstract slot identity. Adopt
       * one once, before a close or the second half of a paired open. */
      if (!identities.count && op->kind != DEP_FD_OP_CLOSE) {
        indirect = false;
      } else if (!identities.count) {
        uint32_t slot = dep_allocation_slot(changes, op);
        if (slot == SHELL_DEP_FD_NONE)
          return false;
        for (uint32_t access = DEP_FD_ACCESS_READ;
             access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
          dep_route_set_t entry =
              dep_fd_raw_fact(&after, changes, baseline_before, target,
                              (dep_fd_access_t)access);
          if (!dep_route_state_store_access(&after, changes,
                                            dep_fd_numeric(slot),
                                            (dep_fd_access_t)access, entry))
            return false;
        }
        before_operation = after;
        dep_route_set_set(&slots, (dep_fd_route_t){DEP_ROUTE_ALIAS, slot});
      } else
        slots = identities;
    } else {
      dep_route_set_set(&slots,
                        (dep_fd_route_t){DEP_ROUTE_ALIAS, target.value});
    }
    if (named && !indirect)
      dep_route_set_set(&slots,
                        (dep_fd_route_t){DEP_ROUTE_ALIAS, SHELL_DEP_FD_NAMED});
    if (named && op->kind == DEP_FD_OP_CLOSE) {
      uint32_t allocation = dep_allocation_slot(changes, op);
      if (allocation == SHELL_DEP_FD_NONE)
        return false;
      dep_allocation_t *record =
          &changes->allocations[allocation - SHELL_DEP_FD_MAX - 1];
      dep_route_set_t all_slots = slots;
      if (record->closed_slots) {
        const dep_route_set_t *prior =
            &changes->snapshots[record->closed_slots - 1];
        for (uint32_t slot = 0; slot < prior->count; slot++)
          if (!dep_route_set_add(&all_slots, prior->routes[slot]))
            return false;
      }
      uint32_t snapshot = dep_route_set_intern(changes, &all_slots);
      if (!snapshot)
        return false;
      changes->allocations[allocation - SHELL_DEP_FD_MAX - 1].closed_slots =
          snapshot;
      dep_route_set_t entry = {0};
      dep_route_set_set(
          &entry, (dep_fd_route_t){DEP_ROUTE_INHERITED, before_operation.root});
      if (!dep_route_state_store_access(&after, changes,
                                        dep_fd_numeric(allocation),
                                        DEP_FD_ACCESS_CLOSE_ENTRY, entry) ||
          !dep_route_state_store_access(&after, changes,
                                        dep_fd_numeric(allocation),
                                        DEP_FD_ACCESS_CLOSE_SLOTS, slots))
        return false;
    }
    dep_route_set_t copied_routes[2] = {0};
    if (op->kind == DEP_FD_OP_DUP) {
      dep_fd_ref_t source = {op->target_fd, op->target_fd_name,
                             op->target_fd_name_len};
      if (dep_fd_op_numeric_self_dup(op))
        continue;
      for (unsigned direction = 0; direction < 2; direction++) {
        dep_route_set_t source_routes =
            dep_fd_fact(&after, changes, baseline_before, source,
                        direction ? DEP_FD_ACCESS_WRITE : DEP_FD_ACCESS_READ);
        for (uint32_t route = 0; route < source_routes.count; route++)
          if (source_routes.routes[route].kind != DEP_ROUTE_ABSENT &&
              source_routes.routes[route].kind != DEP_ROUTE_CLOSED &&
              !dep_route_set_add(&copied_routes[direction],
                                 source_routes.routes[route]))
            return false;
        copied_routes[direction].truncated = source_routes.truncated;
      }
    }
    if (op->resets_descriptor) {
      dep_route_set_t unavailable = {0};
      dep_route_set_set(&unavailable,
                        (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
      for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
           access <<= 1)
        if (!dep_route_state_store_access(
                &after, changes,
                named && !indirect ? target
                                   : dep_fd_numeric(slots.routes[0].value),
                (dep_fd_access_t)access, unavailable))
          return false;
    }

    dep_fd_access_t operation_access =
        op->kind == DEP_FD_OP_DUP || op->kind == DEP_FD_OP_CLOSE
            ? DEP_FD_ACCESS_BOTH
            : op->access;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
         access <<= 1) {
      if ((operation_access & access) == 0)
        continue;
      dep_route_set_t routes = {0};
      if (op->kind == DEP_FD_OP_DUP) {
        routes = copied_routes[access == DEP_FD_ACCESS_READ ? 0 : 1];
      } else if (op->kind == DEP_FD_OP_DOCUMENT ||
                 op->kind == DEP_FD_OP_DYNAMIC) {
        dep_route_set_set(&routes,
                          (dep_fd_route_t){op->kind == DEP_FD_OP_DOCUMENT
                                               ? DEP_ROUTE_DOC
                                               : DEP_ROUTE_DYNAMIC,
                                           op->edge_index});
      } else {
        dep_route_set_set(&routes,
                          (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX});
      }
      complete = complete && !routes.truncated;
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        dep_fd_ref_t fd = named && !indirect
                              ? target
                              : dep_fd_numeric(slots.routes[slot].value);
        dep_route_set_t installed = routes;
        if (slots.count > 1 && (slots.routes[slot].value <= SHELL_DEP_FD_MAX ||
                                op->kind == DEP_FD_OP_CLOSE)) {
          dep_route_set_t prior =
              dep_fd_raw_fact(&before_operation, changes, baseline_before, fd,
                              (dep_fd_access_t)access);
          for (uint32_t route = 0; route < prior.count; route++)
            if (!dep_route_set_add(&installed, prior.routes[route]))
              return false;
        }
        if (!dep_route_state_store_access(&after, changes, fd,
                                          (dep_fd_access_t)access, installed))
          return false;
      }
    }
    {
      dep_route_set_t bound = {0};
      dep_route_set_set(&bound, (dep_fd_route_t){op->kind == DEP_FD_OP_CLOSE
                                                     ? DEP_ROUTE_CLOSED
                                                     : DEP_ROUTE_INHERITED,
                                                 UINT32_MAX});
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        uint32_t value = slots.routes[slot].value;
        dep_route_set_t installed = bound;
        dep_fd_ref_t fd = named && !indirect ? target : dep_fd_numeric(value);
        if (slots.count > 1 &&
            (value <= SHELL_DEP_FD_MAX || op->kind == DEP_FD_OP_CLOSE)) {
          dep_route_set_t prior =
              dep_fd_raw_fact(&before_operation, changes, baseline_before, fd,
                              DEP_FD_ACCESS_BINDING);
          for (uint32_t route = 0; route < prior.count; route++)
            if (!dep_route_set_add(&installed, prior.routes[route]))
              return false;
        }
        if (!dep_route_state_store_access(&after, changes, fd,
                                          DEP_FD_ACCESS_BINDING, installed))
          return false;
        if (value >= DEP_BASH_VARREDIR_MIN_FD && value != SHELL_DEP_FD_NAMED) {
          if (op->kind == DEP_FD_OP_CLOSE) {
            /* Overflow matters only when a later allocation needs more
             * alternatives than the route budget, not for a plain close. */
            (void)dep_route_set_add(&available,
                                    (dep_fd_route_t){DEP_ROUTE_ALIAS, value});
          } else {
            /* Every candidate represented by this allocation is unavailable
             * to a later allocation in the same redirect list. It is either
             * the retained named slot, or the transient file-open slot which
             * Bash must consume before choosing the retained slot. */
            dep_allocation_remove_candidate(&available, value);
          }
        }
      }
    }
    if (named && indirect)
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1)
        if (!dep_route_state_store_access(&after, changes, target,
                                          (dep_fd_access_t)access, slots))
          return false;
    if (!dep_route_state_store_access(&after, changes,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_AVAILABLE, available))
      return false;
    if (named && op->resets_descriptor &&
        dep_fd_name_equal(op->fd_name, op->fd_name_len, "IFS", 3) &&
        !dep_ifs_store(&after, changes, DEP_IFS_DIGITS | DEP_IFS_SELF))
      return false;
  }
  *route_state = after;
  return complete && !route_state->truncated;
}

/* A named allocation is one ordered physical choice, not a union of aliases.
 * Replay every feasible choice against its own immutable map so later closes,
 * reopens, and duplications retain the route correlation. Ordinary redirect
 * operations update each existing allocation path independently. */
static SHELL_NONNULL(1, 2, 3) bool dep_route_state_apply(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_owner_routes_t *baseline_before, const dep_fd_op_t *ops,
    uint32_t op_count, bool begin_frame) {
  dep_route_state_t current = *route_state;
  if (begin_frame && op_count &&
      (changes->named_closes ||
       (changes->observe_undo && changes->observable_fd_count))) {
    dep_route_state_t framed = {0};
    uint32_t count = dep_route_state_count(&current);
    for (uint32_t path = 0; path < count; path++) {
      uint32_t root = dep_route_state_root(&current, changes, path);
      dep_route_state_t one = dep_route_state_single(root);
      dep_route_set_t entry = {0};
      dep_route_set_set(&entry, (dep_fd_route_t){DEP_ROUTE_INHERITED, root});
      if (!dep_route_state_store_access(&one, changes,
                                        dep_fd_numeric(SHELL_DEP_FD_NONE),
                                        DEP_FD_ACCESS_ENTRY, entry))
        return false;
      if (path == 0)
        framed.root = one.root;
      else if (!dep_route_state_add_root(&framed, changes, one.root))
        return false;
    }
    framed.correlated = current.correlated;
    current = framed;
  }
  for (uint32_t op_index = 0; op_index < op_count; op_index++) {
    const dep_fd_op_t *op = &ops[op_index];
    dep_route_state_t next = {0};
    bool have_next = false;
    uint32_t path_count = dep_route_state_count(&current);
    for (uint32_t path = 0; path < path_count; path++) {
      dep_route_state_t one =
          dep_route_state_single(dep_route_state_root(&current, changes, path));
      one.correlated = current.correlated;
      if (!(dep_fd_operation_outcomes(op, &one, changes, baseline_before) &
            DEP_STATUS_MAY_SUCCEED))
        continue;
      uint32_t undo_rank = 1;
      if (op->fd != SHELL_DEP_FD_NAMED && op->resets_descriptor &&
          (op->kind == DEP_FD_OP_DOCUMENT || op->kind == DEP_FD_OP_DYNAMIC) &&
          changes->observe_undo && changes->observable_fd_count) {
        unsigned modes = dep_fd_low_modes(&one, changes, baseline_before);
        dep_fd_occupancy_t target =
            dep_fd_occupancy(&one, changes, baseline_before, op->fd);
        if (modes == 3 && target.may_be_free) {
          /* Unknown inherited targets include the no-save path as well.
           * Keep their bounded scratch-slot union rather than multiplying
           * indistinguishable inherited-occupancy histories. */
          undo_rank = 0;
        } else {
          for (uint32_t mode = 0; mode < 2; mode++) {
            if (!(modes & (1u << mode)))
              continue;
            dep_route_state_t branch = one;
            dep_route_set_t low = {0};
            dep_route_set_set(&low,
                              (dep_fd_route_t){DEP_ROUTE_INHERITED, mode});
            if (!dep_route_state_store_access(&branch, changes,
                                              dep_fd_numeric(SHELL_DEP_FD_NONE),
                                              DEP_FD_ACCESS_LOW_STATE, low) ||
                !dep_prepare_numeric_undo(&branch, changes, baseline_before, op,
                                          mode + 1) ||
                !dep_route_state_apply_one(&branch, changes, baseline_before,
                                           op, 1, NULL))
              return false;
            if (op->fd < DEP_BASH_VARREDIR_MIN_FD && target.may_be_free &&
                !dep_route_state_store_access(
                    &branch, changes, dep_fd_numeric(SHELL_DEP_FD_NONE),
                    DEP_FD_ACCESS_LOW_STATE, (dep_route_set_t){.ready = true}))
              return false;
            branch.correlated = one.correlated || modes == 3;
            if (!have_next) {
              next = branch;
              have_next = true;
            } else if (!dep_route_state_add_root(&next, changes, branch.root)) {
              return false;
            }
          }
          continue;
        }
      }
      if (op->fd != SHELL_DEP_FD_NAMED &&
          !dep_prepare_numeric_undo(&one, changes, baseline_before, op,
                                    undo_rank))
        return false;
      if (op->fd == SHELL_DEP_FD_NAMED && op->resets_descriptor &&
          (changes->observable_fd_count || changes->named_closes)) {
        dep_named_allocation_choices_t choices = {0};
        if (!dep_named_allocation_choices(&one, changes, baseline_before, op,
                                          &choices))
          return false;
        for (uint32_t mode = 0; mode < 2; mode++)
          for (uint32_t slot = 0; slot < choices.slots[mode].count; slot++) {
            dep_fd_route_t selected = choices.slots[mode].routes[slot];
            dep_route_state_t branch = one;
            if (choices.resource) {
              dep_route_set_t low = {0};
              dep_route_set_set(&low,
                                (dep_fd_route_t){DEP_ROUTE_INHERITED, mode});
              if (!dep_route_state_store_access(
                      &branch, changes, dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_LOW_STATE, low))
                return false;
            }
            branch.correlated =
                one.correlated ||
                choices.slots[0].count + choices.slots[1].count > 1;
            if (!dep_route_state_apply_one(&branch, changes, baseline_before,
                                           op, 1, &selected))
              return false;
            if (!have_next) {
              next = branch;
              have_next = true;
            } else if (!dep_route_state_add_root(&next, changes, branch.root)) {
              return false;
            }
          }
      } else {
        dep_route_set_t mode = dep_fd_raw_fact(
            &one, changes, baseline_before, dep_fd_numeric(SHELL_DEP_FD_NONE),
            DEP_FD_ACCESS_LOW_STATE);
        if (mode.count && op->fd < DEP_BASH_VARREDIR_MIN_FD &&
            !dep_fd_op_numeric_self_dup(op)) {
          dep_route_set_t low = {0};
          dep_route_set_set(&low, (dep_fd_route_t){DEP_ROUTE_INHERITED, 0});
          if (op->kind != DEP_FD_OP_CLOSE &&
              !dep_route_set_add(&low,
                                 (dep_fd_route_t){DEP_ROUTE_INHERITED, 1}))
            return false;
          if (!dep_route_state_store_access(&one, changes,
                                            dep_fd_numeric(SHELL_DEP_FD_NONE),
                                            DEP_FD_ACCESS_LOW_STATE, low))
            return false;
        }
        if (!dep_route_state_apply_one(&one, changes, baseline_before, op, 1,
                                       NULL))
          return false;
        if (!have_next) {
          next = one;
          have_next = true;
        } else if (!dep_route_state_add_root(&next, changes, one.root)) {
          return false;
        }
      }
    }
    current = next;
  }
  *route_state = current;
  return !route_state->truncated;
}

static SHELL_NONNULL(1) dep_fd_ref_t
    dep_fd_operation_target(const dep_fd_op_t *op) {
  return (dep_fd_ref_t){op->fd, op->fd_name, op->fd_name_len};
}

/* Publish completed mutations, not a replay against the destination table:
 * a duplication can read a temporary group route even when its target survives
 * the group. The outcome stream handles joins and restoration separately. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_route_state_publish_one(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_owner_routes_t *executed, const dep_route_state_t *executed_state,
    const dep_owner_routes_t *entry_baseline, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec, bool named_binding) {
  dep_owner_routes_t touched = {0}, temporary = {0};
  dep_route_set_t available = dep_fd_raw_fact(
      route_state, changes, entry_baseline, dep_fd_numeric(SHELL_DEP_FD_NONE),
      DEP_FD_ACCESS_AVAILABLE);
  bool allocation_changed = false;
  for (uint32_t i = 0; i < op_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
    const dep_fd_op_t *op = &ops[i];
    dep_fd_ref_t target = dep_fd_operation_target(op);
    if (!descriptor_exec && dep_fd_op_saves_numeric(op) &&
        !dep_route_slot(&temporary, target, true))
      return false;
    if (target.value == SHELL_DEP_FD_NAMED && op->kind == DEP_FD_OP_CLOSE) {
      uint32_t allocation = dep_allocation_slot(changes, op);
      if (allocation == SHELL_DEP_FD_NONE)
        return false;
      dep_route_set_t saved = dep_fd_raw_fact(executed_state, changes, executed,
                                              dep_fd_numeric(allocation),
                                              DEP_FD_ACCESS_CLOSE_ENTRY);
      dep_route_state_t close_entry = {.root = saved.routes[0].value};
      dep_route_set_t old = dep_fd_raw_fact(executed_state, changes, executed,
                                            dep_fd_numeric(allocation),
                                            DEP_FD_ACCESS_CLOSE_SLOTS);
      for (uint32_t slot = 0; slot < old.count; slot++) {
        if (old.routes[slot].kind != DEP_ROUTE_ALIAS)
          continue;
        dep_fd_ref_t fd = dep_fd_numeric(old.routes[slot].value);
        if (!descriptor_exec && !dep_route_find(&temporary, fd))
          for (uint32_t access = DEP_FD_ACCESS_READ;
               access <= DEP_FD_ACCESS_BINDING; access <<= 1)
            if (!dep_route_state_store_access(
                    route_state, changes, fd, (dep_fd_access_t)access,
                    dep_fd_raw_fact(&close_entry, changes, entry_baseline, fd,
                                    (dep_fd_access_t)access)))
              return false;
        if (!dep_route_slot(descriptor_exec ? &touched : &temporary, fd, true))
          return false;
      }
      if (!descriptor_exec)
        for (uint32_t access = DEP_FD_ACCESS_READ;
             access <= DEP_FD_ACCESS_BINDING; access <<= 1)
          if (!dep_route_state_store_access(
                  route_state, changes, target, (dep_fd_access_t)access,
                  dep_fd_raw_fact(&close_entry, changes, entry_baseline, target,
                                  (dep_fd_access_t)access)))
            return false;
    }
    if (!dep_fd_op_persists(op, descriptor_exec, named_binding))
      continue;
    dep_fd_route_entry_t *touch = dep_route_slot(&touched, target, true);
    if (!touch) {
      route_state->truncated = true;
      return false;
    }
    if (descriptor_exec && target.value <= SHELL_DEP_FD_MAX)
      touch->read_route = (dep_fd_route_t){DEP_ROUTE_IMPORTED, i + 1};
    if (target.value == SHELL_DEP_FD_NAMED && op->resets_descriptor) {
      uint32_t slot = dep_allocation_slot(changes, op);
      if (slot == SHELL_DEP_FD_NONE)
        return false;
      if (dep_route_state_has_change(executed_state, changes,
                                     dep_fd_numeric(slot),
                                     DEP_FD_ACCESS_BINDING) &&
          !dep_route_slot(&touched, dep_fd_numeric(slot), true))
        return false;
    }
  }
  for (uint32_t i = 0; i < touched.fd_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
    if (dep_route_find(&temporary, touched.fd[i].fd))
      continue;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_BINDING;
         access <<= 1) {
      dep_route_set_t routes =
          dep_fd_raw_fact(executed_state, changes, executed, touched.fd[i].fd,
                          (dep_fd_access_t)access);
      if (touched.fd[i].fd.value == SHELL_DEP_FD_NAMED)
        for (uint32_t slot = 0; slot < routes.count; slot++) {
          if (routes.routes[slot].kind != DEP_ROUTE_ALIAS)
            continue;
          dep_fd_ref_t fd = dep_fd_numeric(routes.routes[slot].value);
          if ((fd.value <= SHELL_DEP_FD_MAX || descriptor_exec ||
               dep_route_find(&touched, fd)) &&
              !dep_route_find(&temporary, fd) &&
              !dep_route_state_store_access(
                  route_state, changes, fd, (dep_fd_access_t)access,
                  dep_fd_raw_fact(executed_state, changes, executed, fd,
                                  (dep_fd_access_t)access)))
            return false;
          if (fd.value <= SHELL_DEP_FD_MAX && !dep_route_find(&temporary, fd))
            allocation_changed |=
                dep_allocation_remove_candidate(&available, fd.value);
        }
      if (!dep_route_state_store_access(route_state, changes, touched.fd[i].fd,
                                        (dep_fd_access_t)access, routes))
        return false;
    }
  }
  for (uint32_t operation = 0; operation < op_count; operation++) {
    if (!dep_fd_op_saves_numeric(ops + operation))
      continue;
    dep_route_set_t undo =
        dep_fd_raw_fact(executed_state, changes, executed,
                        dep_fd_numeric(ops[operation].fd), DEP_FD_ACCESS_SAVED);
    bool optional_undo = undo.count > 1;
    for (uint32_t slot = 0; slot < undo.count; slot++) {
      if (undo.routes[slot].kind != DEP_ROUTE_ALIAS)
        continue;
      dep_fd_ref_t fd = dep_fd_numeric(undo.routes[slot].value);
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
        dep_route_set_t disposed = {0};
        dep_route_set_set(&disposed,
                          (dep_fd_route_t){access == DEP_FD_ACCESS_BINDING
                                               ? DEP_ROUTE_CLOSED
                                               : DEP_ROUTE_ABSENT,
                                           UINT32_MAX});
        if (optional_undo) {
          const dep_fd_route_entry_t *last = dep_route_find(&touched, fd);
          bool numeric = last && last->read_route.kind == DEP_ROUTE_IMPORTED;
          /* A prior explicit close remains closed on the no-save path too.
           * Do not retain the temporary saved copy itself as a post-cleanup
           * alternative. A later explicit open, conversely, can survive on
           * paths which allocated their undo descriptor elsewhere. */
          dep_route_set_t retained =
              numeric && ops[last->read_route.value - 1].kind == DEP_FD_OP_CLOSE
                  ? disposed
                  : dep_fd_raw_fact(numeric ? executed_state : route_state,
                                    changes,
                                    numeric ? executed : entry_baseline, fd,
                                    (dep_fd_access_t)access);
          for (uint32_t route = 0; route < retained.count; route++)
            if (!dep_route_set_add(&disposed, retained.routes[route]))
              return false;
        }
        if (!dep_route_state_store_access(route_state, changes, fd,
                                          (dep_fd_access_t)access, disposed))
          return false;
      }
    }
  }
  if (descriptor_exec) {
    available = dep_fd_raw_fact(executed_state, changes, executed,
                                dep_fd_numeric(SHELL_DEP_FD_NONE),
                                DEP_FD_ACCESS_AVAILABLE);
    allocation_changed = true;
  }
  if (allocation_changed &&
      !dep_route_state_store_access(route_state, changes,
                                    dep_fd_numeric(SHELL_DEP_FD_NONE),
                                    DEP_FD_ACCESS_AVAILABLE, available))
    return false;
  return !route_state->truncated &&
         dep_ifs_copy(route_state, executed_state, changes, entry_baseline);
}

static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_route_state_publish(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_owner_routes_t *executed, const dep_route_state_t *executed_state,
    const dep_owner_routes_t *entry_baseline, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec, bool named_binding) {
  dep_route_state_t entry = *route_state;
  if (op_count == 0)
    return !entry.truncated &&
           dep_ifs_copy(route_state, executed_state, changes, entry_baseline);
  dep_route_state_t published = {0};
  bool have_published = false;
  uint32_t entry_count = dep_route_state_count(&entry);
  uint32_t executed_count = dep_route_state_count(executed_state);
  uint32_t pairs = executed_count;
  for (uint32_t pair = 0; pair < pairs; pair++) {
    dep_route_state_t executed_branch = dep_route_state_single(
        dep_route_state_root(executed_state, changes, pair));
    dep_route_set_t saved =
        dep_fd_raw_fact(&executed_branch, changes, entry_baseline,
                        dep_fd_numeric(SHELL_DEP_FD_NONE), DEP_FD_ACCESS_ENTRY);
    uint32_t original =
        saved.count == 1
            ? saved.routes[0].value
            : dep_route_state_root(&entry, changes,
                                   entry_count == executed_count ? pair : 0);
    dep_route_state_t branch = dep_route_state_single(original);
    branch.correlated = entry.correlated || executed_state->correlated;
    if (!dep_route_state_publish_one(&branch, changes, executed,
                                     &executed_branch, entry_baseline, ops,
                                     op_count, descriptor_exec, named_binding))
      return false;
    bool restores_low = false;
    for (uint32_t op = 0; op < op_count; op++)
      restores_low |= !descriptor_exec &&
                      ops[op].fd < DEP_BASH_VARREDIR_MIN_FD &&
                      dep_fd_op_saves_numeric(ops + op);
    dep_route_set_t low = dep_fd_raw_fact(&executed_branch, changes, executed,
                                          dep_fd_numeric(SHELL_DEP_FD_NONE),
                                          DEP_FD_ACCESS_LOW_STATE);
    dep_route_set_t old_low = dep_fd_raw_fact(&branch, changes, entry_baseline,
                                              dep_fd_numeric(SHELL_DEP_FD_NONE),
                                              DEP_FD_ACCESS_LOW_STATE);
    if (!restores_low && (low.count || old_low.count) &&
        !dep_route_state_store_access(&branch, changes,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_LOW_STATE, low))
      return false;
    if (!have_published) {
      published = branch;
      have_published = true;
    } else if (!dep_route_state_add_root(&published, changes, branch.root)) {
      return false;
    }
  }
  *route_state = published;
  return !route_state->truncated;
}

/* Apply one prepared undo frame. Variables keep their slot associations;
 * restoring slots changes all their uses without traversing the names. Only
 * restored candidates are reconciled: persistent body effects remain intact.
 */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool dep_fd_restore_slots_one(
    dep_route_state_t *state, const dep_route_state_t *entry,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const uint32_t *fds, const uint32_t *undo_roots, uint32_t count) {
  dep_route_set_t available = dep_fd_raw_fact(state, journal, baseline,
                                              dep_fd_numeric(SHELL_DEP_FD_NONE),
                                              DEP_FD_ACCESS_AVAILABLE);
  dep_route_set_t original = dep_fd_raw_fact(entry, journal, baseline,
                                             dep_fd_numeric(SHELL_DEP_FD_NONE),
                                             DEP_FD_ACCESS_AVAILABLE);
  bool restored_low = false;
  for (uint32_t i = 0; i < count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES);
    dep_fd_ref_t fd = dep_fd_numeric(fds[i]);
    dep_route_state_t saved = *entry;
    if (undo_roots[i] != UINT32_MAX) {
      dep_fd_ref_t operation = dep_fd_numeric(undo_roots[i]);
      dep_route_set_t slots = dep_fd_raw_fact(
          state, journal, baseline, operation, DEP_FD_ACCESS_CLOSE_SLOTS);
      bool closed = false;
      for (uint32_t slot = 0; slot < slots.count; slot++)
        closed |= slots.routes[slot].kind == DEP_ROUTE_ALIAS &&
                  slots.routes[slot].value == fd.value;
      if (!closed)
        continue;
      dep_route_set_t before = dep_fd_raw_fact(
          state, journal, baseline, operation, DEP_FD_ACCESS_CLOSE_ENTRY);
      saved = (dep_route_state_t){.root = before.routes[0].value};
    }
    restored_low |= fd.value < DEP_BASH_VARREDIR_MIN_FD;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_BINDING;
         access <<= 1)
      if (!dep_route_state_store_access(
              state, journal, fd, (dep_fd_access_t)access,
              dep_fd_raw_fact(&saved, journal, baseline, fd,
                              (dep_fd_access_t)access)))
        return false;
    (void)dep_allocation_remove_candidate(&available, fd.value);
    for (uint32_t candidate = 0; candidate < original.count; candidate++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
      if (original.routes[candidate].value == fd.value)
        (void)dep_route_set_add(&available, original.routes[candidate]);
    }
  }
  if (restored_low) {
    dep_route_set_t mode = dep_fd_raw_fact(state, journal, baseline,
                                           dep_fd_numeric(SHELL_DEP_FD_NONE),
                                           DEP_FD_ACCESS_LOW_STATE);
    if (mode.count &&
        !dep_route_state_store_access(
            state, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
            DEP_FD_ACCESS_LOW_STATE, (dep_route_set_t){.ready = true}))
      return false;
  }
  return !count || dep_route_state_store_access(
                       state, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                       DEP_FD_ACCESS_AVAILABLE, available);
}

static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool dep_fd_restore_slots(
    dep_route_state_t *state, const dep_route_state_t *entry,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const uint32_t *fds, const uint32_t *undo_roots, uint32_t count) {
  dep_route_state_t restored = {0};
  uint32_t paths = dep_route_state_count(state);
  for (uint32_t path = 0; path < paths; path++) {
    dep_route_state_t one =
        dep_route_state_single(dep_route_state_root(state, journal, path));
    one.correlated = state->correlated;
    if (!dep_fd_restore_slots_one(&one, entry, journal, baseline, fds,
                                  undo_roots, count))
      return false;
    if (path == 0)
      restored = one;
    else if (!dep_route_state_add_root(&restored, journal, one.root))
      return false;
  }
  *state = restored;
  return true;
}

static bool dep_restore_continuation_route_state(
    dep_route_state_t *continuation, dep_route_journal_t *changes,
    const dep_route_state_t *destination_state,
    const dep_owner_routes_t *destination,
    const dep_route_publication_t *publication) {
  return dep_fd_restore_slots(continuation, destination_state, changes,
                              destination, publication->restored->fds,
                              publication->restored->undo_roots,
                              publication->restored->count);
}

static dep_route_set_t
dep_time_report_for_fd2(const dep_route_state_t *state,
                        const dep_route_journal_t *changes,
                        const dep_owner_routes_t *baseline) {
  return dep_route_state_get(state, changes, baseline, dep_fd_numeric(2));
}

/* Flow versions use an immutable baseline. Unlike command-local lookup,
 * binding visibility is an explicit journal fact, not a mutable-table test. */
static SHELL_NONNULL(2, 3) dep_route_set_t
    dep_fd_raw_root_fact(uint32_t root, const dep_route_journal_t *journal,
                         const dep_owner_routes_t *baseline, dep_fd_ref_t fd,
                         dep_fd_access_t access) {
  const dep_route_change_t *change =
      dep_route_root_change(root, journal, fd, access);
  if (change)
    return journal->snapshots[change->snapshot - 1];
  if (access == DEP_FD_ACCESS_IFS) {
    dep_route_set_t result = {0};
    dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_INHERITED, 0});
    return result;
  }
  if (access == DEP_FD_ACCESS_AVAILABLE)
    return (dep_route_set_t){.ready = true};
  if (access == DEP_FD_ACCESS_SAVED || access == DEP_FD_ACCESS_SAVE_FRAME)
    return (dep_route_set_t){.ready = true};
  if (access == DEP_FD_ACCESS_LOW_STATE || access == DEP_FD_ACCESS_ENTRY ||
      access == DEP_FD_ACCESS_PERSISTENT ||
      access == DEP_FD_ACCESS_CLOSE_ENTRY ||
      access == DEP_FD_ACCESS_CLOSE_SLOTS)
    return (dep_route_set_t){.ready = true};
  const dep_fd_route_entry_t *slot = dep_route_find(baseline, fd);
  dep_route_set_t result = {0};
  if (!slot && fd.value > SHELL_DEP_FD_MAX && fd.value < SHELL_DEP_FD_NAMED) {
    dep_route_set_set(&result, (dep_fd_route_t){access == DEP_FD_ACCESS_BINDING
                                                    ? DEP_ROUTE_UNAVAILABLE
                                                    : DEP_ROUTE_ABSENT,
                                                UINT32_MAX});
    return result;
  }
  dep_fd_route_t route =
      access == DEP_FD_ACCESS_BINDING
          ? (dep_fd_route_t){slot || (fd.value != SHELL_DEP_FD_NAMED &&
                                      fd.value < 3)
                                 ? DEP_ROUTE_INHERITED
                                 : DEP_ROUTE_UNSEEN,
                             UINT32_MAX}
      : slot ? (access == DEP_FD_ACCESS_READ ? slot->read_route
                                             : slot->write_route)
             : (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value};
  dep_route_set_set(&result, route);
  return result;
}

static SHELL_NONNULL(1, 2, 3) dep_route_set_t
    dep_fd_raw_fact(const dep_route_state_t *state,
                    const dep_route_journal_t *journal,
                    const dep_owner_routes_t *baseline, dep_fd_ref_t fd,
                    dep_fd_access_t access) {
  dep_route_set_t result = {.ready = true, .truncated = state->truncated};
  uint32_t count = dep_route_state_count(state);
  for (uint32_t path = 0; path < count; path++) {
    dep_route_set_t one =
        dep_fd_raw_root_fact(dep_route_state_root(state, journal, path),
                             journal, baseline, fd, access);
    result.truncated |= one.truncated;
    for (uint32_t route = 0; route < one.count; route++)
      if (!dep_route_set_add(&result, one.routes[route]))
        return result;
  }
  return result;
}

static SHELL_NONNULL(1, 2, 3) dep_route_set_t
    dep_fd_fact(const dep_route_state_t *state,
                const dep_route_journal_t *journal,
                const dep_owner_routes_t *baseline, dep_fd_ref_t fd,
                dep_fd_access_t access) {
  dep_route_set_t result = {.ready = true, .truncated = state->truncated};
  uint32_t count = dep_route_state_count(state);
  for (uint32_t path = 0; path < count; path++) {
    uint32_t root = dep_route_state_root(state, journal, path);
    dep_route_set_t raw =
        dep_fd_raw_root_fact(root, journal, baseline, fd, access);
    result.truncated |= raw.truncated;
    for (uint32_t i = 0; i < raw.count; i++) {
      dep_fd_route_t route = raw.routes[i];
      if (route.kind != DEP_ROUTE_ALIAS) {
        (void)dep_route_set_add(&result, route);
        continue;
      }
      /* Resolve the association within its own version before taking the
       * public union. A slot from another allocation path is not its route. */
      dep_route_set_t slots = dep_fd_raw_root_fact(
          root, journal, baseline, dep_fd_numeric(route.value), access);
      result.truncated |= slots.truncated;
      for (uint32_t slot = 0; slot < slots.count; slot++)
        (void)dep_route_set_add(&result, slots.routes[slot]);
    }
  }
  return result;
}

static SHELL_NONNULL(1, 2,
                     3) bool dep_fd_bound(const dep_route_state_t *state,
                                          const dep_route_journal_t *journal,
                                          const dep_owner_routes_t *baseline,
                                          dep_fd_ref_t fd) {
  if (fd.value != SHELL_DEP_FD_NAMED)
    return true;
  dep_route_set_t facts =
      dep_fd_raw_fact(state, journal, baseline, fd, DEP_FD_ACCESS_BINDING);
  bool live = false;
  for (uint32_t i = 0; i < facts.count; i++) {
    if (facts.routes[i].kind == DEP_ROUTE_DYNAMIC ||
        facts.routes[i].kind == DEP_ROUTE_UNSEEN)
      return false;
    live |= facts.routes[i].kind == DEP_ROUTE_INHERITED ||
            facts.routes[i].kind == DEP_ROUTE_ALIAS;
  }
  return live;
}

/* Concrete replay needs one usable representative. The journal still carries
 * every alternative, including paths on which this direction is unavailable
 * or closed; those must not make a possibly valid duplication fail parsing. */
static dep_fd_route_t dep_fd_representative(dep_route_set_t routes) {
  for (uint32_t i = 0; i < routes.count; i++)
    if (routes.routes[i].kind != DEP_ROUTE_CLOSED &&
        routes.routes[i].kind != DEP_ROUTE_UNAVAILABLE &&
        routes.routes[i].kind != DEP_ROUTE_ABSENT)
      return routes.routes[i];
  return routes.routes[0];
}

/* The concrete table is a replay representative, not the authoritative union.
 * Keep usable physical associations, so numeric restoration remains visible;
 * skip an association whose direction is unavailable on every route version.
 * All actual alternatives remain in the immutable journal. */
static SHELL_NONNULL(1, 2, 3) dep_fd_route_t
    dep_fd_materialized_route(const dep_route_state_t *state,
                              const dep_route_journal_t *journal,
                              const dep_owner_routes_t *baseline,
                              dep_fd_ref_t fd, dep_fd_access_t access) {
  dep_route_set_t raw = dep_fd_raw_fact(state, journal, baseline, fd, access);
  for (uint32_t i = 0; i < raw.count; i++) {
    dep_fd_route_t route = raw.routes[i];
    if (route.kind != DEP_ROUTE_ALIAS) {
      if (route.kind != DEP_ROUTE_CLOSED && route.kind != DEP_ROUTE_ABSENT &&
          route.kind != DEP_ROUTE_UNAVAILABLE)
        return route;
      continue;
    }
    dep_route_set_t actual = dep_fd_raw_fact(
        state, journal, baseline, dep_fd_numeric(route.value), access);
    for (uint32_t j = 0; j < actual.count; j++)
      if (actual.routes[j].kind != DEP_ROUTE_CLOSED &&
          actual.routes[j].kind != DEP_ROUTE_ABSENT &&
          actual.routes[j].kind != DEP_ROUTE_UNAVAILABLE)
        return route;
  }
  return dep_fd_representative(raw);
}

static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge_key(
    dep_route_state_t *result, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, uint32_t left_root, uint32_t right_root,
    dep_fd_ref_t fd, dep_fd_access_t access, uint32_t left_snapshot,
    uint32_t right_snapshot) {
  dep_route_set_t routes =
      left_snapshot
          ? journal->snapshots[left_snapshot - 1]
          : dep_fd_raw_root_fact(left_root, journal, baseline, fd, access);
  dep_route_set_t additional =
      right_snapshot
          ? journal->snapshots[right_snapshot - 1]
          : dep_fd_raw_root_fact(right_root, journal, baseline, fd, access);
  uint32_t old_count = routes.count;
  if (access == DEP_FD_ACCESS_IFS) {
    uint32_t value =
        dep_ifs_join(routes.routes[0].value, additional.routes[0].value);
    if (value == routes.routes[0].value)
      return true;
    dep_route_set_set(&routes, (dep_fd_route_t){DEP_ROUTE_INHERITED, value});
    return dep_route_state_append_one(result, journal, fd, access, routes);
  }
  /* An unrefined occupancy fact represents both modes, not an empty set.
   * Joining it with a constrained path must remain unrefined. */
  if (access == DEP_FD_ACCESS_LOW_STATE &&
      (!routes.count || !additional.count)) {
    if (!routes.count)
      return true;
    return dep_route_state_append_one(result, journal, fd, access,
                                      (dep_route_set_t){.ready = true});
  }
  if (access == DEP_FD_ACCESS_BINDING) {
    bool unknown = false, unseen = false, live = false;
    for (unsigned side = 0; side < 2; side++) {
      const dep_route_set_t *facts = side ? &additional : &routes;
      for (uint32_t i = 0; i < facts->count; i++) {
        unknown |= facts->routes[i].kind == DEP_ROUTE_DYNAMIC;
        unseen |= facts->routes[i].kind == DEP_ROUTE_UNSEEN;
        live |= facts->routes[i].kind == DEP_ROUTE_INHERITED ||
                facts->routes[i].kind == DEP_ROUTE_ALIAS;
      }
    }
    if (unknown || (unseen && live)) {
      if (routes.count == 1 && routes.routes[0].kind == DEP_ROUTE_DYNAMIC)
        return true;
      dep_route_set_set(&routes,
                        (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
      return dep_route_state_append_one(result, journal, fd, access, routes);
    }
  }
  for (uint32_t i = 0; i < additional.count; i++)
    if (!dep_route_set_add(&routes, additional.routes[i]))
      return false;
  if (routes.count == old_count)
    return true;
  return dep_route_state_append_one(result, journal, fd, access, routes);
}

/* Join two exact immutable maps. This deliberately collapses ordinary
 * control-flow alternatives into per-descriptor route sets; allocation
 * alternatives are kept exact while operations are replayed, then use the
 * same bounded public union when execution outcomes meet. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge_tree(
    dep_route_state_t *result, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, uint32_t left_root, uint32_t right_root,
    uint32_t root, uint32_t other_root, bool missing_only) {
  if (!root || root == other_root)
    return true;
  dep_route_change_t change = journal->entries[root - 1];
  const dep_route_change_t *other =
      other_root ? &journal->entries[other_root - 1] : NULL;
  if (other && (dep_fd_ref_compare(change.fd, other->fd) != 0 ||
                change.access != other->access))
    other =
        dep_route_root_change(other_root, journal, change.fd, change.access);
  if (!other)
    other = dep_route_root_change(missing_only ? left_root : right_root,
                                  journal, change.fd, change.access);
  if (other == &journal->entries[root - 1])
    return true;
  bool same_key = other != NULL;
  if (!dep_fd_merge_tree(result, journal, baseline, left_root, right_root,
                         change.left, other ? other->left : 0, missing_only))
    return false;
  if ((!missing_only && (!same_key || change.snapshot != other->snapshot)) ||
      (missing_only && !same_key &&
       !dep_route_root_change(left_root, journal, change.fd, change.access))) {
    if (!dep_fd_merge_key(
            result, journal, baseline, left_root, right_root, change.fd,
            change.access,
            missing_only ? (other ? other->snapshot : 0) : change.snapshot,
            missing_only ? change.snapshot : (other ? other->snapshot : 0)))
      return false;
  }
  return dep_fd_merge_tree(result, journal, baseline, left_root, right_root,
                           change.right, other ? other->right : 0,
                           missing_only);
}

static SHELL_NONNULL(1) dep_route_join_t *dep_fd_join_cache(
    dep_route_journal_t *journal, uint32_t left, uint32_t right) {
  uint32_t low = left < right ? left : right;
  uint32_t high = left < right ? right : left;
  size_t bucket =
      ((size_t)low * 2654435761u + high) % DEP_ROUTE_OPERATION_CAPACITY;
  return &journal->joins[bucket];
}

static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge_root(
    dep_route_state_t *destination, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, uint32_t source_root) {
  if (destination->root == source_root)
    return true;
  uint32_t left_root = destination->root;
  uint32_t low = left_root < source_root ? left_root : source_root;
  uint32_t high = left_root < source_root ? source_root : left_root;
  dep_route_join_t *cached = dep_fd_join_cache(journal, left_root, source_root);
  if (cached->baseline == baseline && cached->left == low &&
      cached->right == high) {
    destination->root = cached->result;
    return true;
  }
  if (!dep_fd_merge_tree(destination, journal, baseline, left_root, source_root,
                         left_root, source_root, false) ||
      !dep_fd_merge_tree(destination, journal, baseline, left_root, source_root,
                         source_root, left_root, true))
    return false;
  *cached = (dep_route_join_t){low, high, destination->root, baseline};
  return true;
}

static SHELL_NONNULL(1, 2, 3,
                     4) bool dep_fd_merge(dep_route_state_t *destination,
                                          const dep_route_state_t *source,
                                          dep_route_journal_t *journal,
                                          const dep_owner_routes_t *baseline) {
  if (destination->truncated || source->truncated)
    return false;
  if (destination->correlated || source->correlated) {
    destination->correlated = true;
    for (uint32_t path = 0; path < dep_route_state_count(source); path++)
      if (!dep_route_state_add_root(
              destination, journal,
              dep_route_state_root(source, journal, path)))
        return false;
    return true;
  }
  dep_route_state_t collapsed = dep_route_state_single(destination->root);
  uint32_t destination_count = dep_route_state_count(destination);
  for (uint32_t path = 1; path < destination_count; path++)
    if (!dep_fd_merge_root(&collapsed, journal, baseline,
                           dep_route_state_root(destination, journal, path)))
      return false;
  uint32_t count = dep_route_state_count(source);
  for (uint32_t path = 0; path < count; path++)
    if (!dep_fd_merge_root(&collapsed, journal, baseline,
                           dep_route_state_root(source, journal, path)))
      return false;
  *destination = collapsed;
  return true;
}

static SHELL_NONNULL(1, 4,
                     5) bool dep_fd_add(dep_fd_flow_t *flow, unsigned outcome,
                                        dep_route_state_t state,
                                        dep_route_journal_t *journal,
                                        const dep_owner_routes_t *baseline) {
  uint8_t bit = (uint8_t)(1u << outcome);
  if (flow->mask & bit) {
    if (!dep_fd_merge(&flow->state[outcome], &state, journal, baseline))
      return false;
  } else {
    flow->state[outcome] = state;
    flow->mask |= bit;
  }
  return true;
}

static SHELL_NONNULL(1, 3, 4, 5) bool dep_fd_select(
    const dep_fd_flow_t *flow, uint8_t mask, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_route_state_t *selected) {
  bool found = false;
  *selected = (dep_route_state_t){0};
  for (unsigned i = 0; i < 5; i++)
    if (flow->mask & mask & (1u << i)) {
      if (found) {
        if (!dep_fd_merge(selected, &flow->state[i], journal, baseline))
          return false;
      } else {
        *selected = flow->state[i];
        found = true;
      }
    }
  return true;
}

/* Concrete caches hold one immutable version. They are not a new control-flow
 * join: the next semantic consumer selects and joins its required outcomes. */
static SHELL_NONNULL(1, 2) dep_route_state_t
    dep_fd_point_version(const dep_fd_flow_t *flow,
                         const dep_route_state_t *fallback) {
  for (unsigned outcome = 0; outcome < 5; outcome++)
    if (flow->mask & (1u << outcome))
      return flow->state[outcome];
  return *fallback;
}

static SHELL_NONNULL(1, 2) uint8_t
    dep_fd_run_mask(const dep_parse_context_t *context,
                    const dep_fd_stream_t *stream, uint32_t event) {
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  uint16_t connector =
      event < SHELL_MAX_GROUPS
          ? pipeline->group_connector[event]
          : pipeline->range_connector[event - SHELL_MAX_GROUPS];
  if (connector == SHELL_TYPE_PIPELINE) {
    event =
        stream->pipeline_event[dep_snapshot_event_group(context, event) + 1] -
        1;
    connector = event < SHELL_MAX_GROUPS
                    ? pipeline->group_connector[event]
                    : pipeline->range_connector[event - SHELL_MAX_GROUPS];
  }
  return connector == SHELL_TYPE_AND  ? DEP_STATUS_MAY_SUCCEED
         : connector == SHELL_TYPE_OR ? DEP_STATUS_MAY_FAIL
                                      : DEP_STATUS_EITHER;
}

static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_begin(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    dep_route_state_t *selected) {
  uint32_t scope = (uint32_t)(dep_snapshot_event_group(context, event) + 1);
  dep_fd_flow_t *flow = &stream->scope[scope];
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  if (scope == 0) {
    uint32_t unit = event < SHELL_MAX_GROUPS
                        ? pipeline->group_input_unit[event]
                        : pipeline->range_input_unit[event - SHELL_MAX_GROUPS];
    if (context->input_unit_recovery && unit != stream->input_unit &&
        (flow->mask & DEP_STATUS_ABORT_FAILURE)) {
      if (!dep_fd_add(flow, 1, flow->state[4], journal, baseline))
        return false;
      flow->mask &= (uint8_t)~DEP_STATUS_ABORT_FAILURE;
    }
    stream->input_unit = unit;
  }
  uint16_t connector =
      event < SHELL_MAX_GROUPS
          ? pipeline->group_connector[event]
          : pipeline->range_connector[event - SHELL_MAX_GROUPS];
  if (connector == SHELL_TYPE_PIPELINE) {
    stream->entry[event] = stream->entry[stream->pipeline_event[scope] - 1];
  } else {
    stream->entry[event] = *flow;
    bool outgoing = event < SHELL_MAX_GROUPS
                        ? pipeline->group_tail[event].has_pipeline
                        : pipeline->range_successor[event - SHELL_MAX_GROUPS] ==
                              SHELL_TYPE_PIPELINE;
    stream->pipeline_event[scope] = outgoing ? event + 1 : 0;
  }
  if (!dep_fd_select(&stream->entry[event],
                     dep_fd_run_mask(context, stream, event), journal, baseline,
                     selected))
    return false;
  stream->selected[event] = *selected;
  return true;
}

static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_finish(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    const dep_fd_flow_t *executed, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline) {
  const dep_fd_flow_t *entry = &stream->entry[event];
  uint8_t run = dep_fd_run_mask(context, stream, event);
  dep_fd_flow_t result = *entry;
  result.mask &= (uint8_t)~run;
  if (entry->mask & run)
    for (unsigned i = 0; i < 5; i++)
      if ((executed->mask & (1u << i)) &&
          !dep_fd_add(&result, i, executed->state[i], journal, baseline))
        return false;
  if (executed->mask & DEP_STATUS_EXIT_INCOMING)
    for (unsigned i = 0; i < 2; i++)
      if ((entry->mask & run & (1u << i)) &&
          !dep_fd_add(&result, i + 2, entry->state[i], journal, baseline))
        return false;
  stream->scope[dep_snapshot_event_group(context, event) + 1] = result;
  return true;
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_materialize_tree(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_owner_routes_t *destination,
    uint32_t root) {
  if (!root)
    return true;
  const dep_route_change_t *change = &journal->entries[root - 1];
  if (!dep_fd_materialize_tree(state, journal, baseline, destination,
                               change->left))
    return false;
  if (change->access <= DEP_FD_ACCESS_BINDING &&
      dep_fd_bound(state, journal, baseline, change->fd)) {
    dep_fd_route_entry_t *slot = dep_route_slot(destination, change->fd, true);
    if (!slot)
      return false;
    slot->read_route = dep_fd_materialized_route(
        state, journal, baseline, change->fd, DEP_FD_ACCESS_READ);
    slot->write_route = dep_fd_materialized_route(
        state, journal, baseline, change->fd, DEP_FD_ACCESS_WRITE);
  }
  return dep_fd_materialize_tree(state, journal, baseline, destination,
                                 change->right);
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_materialize(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_owner_routes_t *destination) {
  destination->fd_count = destination->root = 0;
  for (uint32_t i = 0; i < baseline->fd_count; i++) {
    dep_fd_ref_t fd = baseline->fd[i].fd;
    if (dep_fd_bound(state, journal, baseline, fd)) {
      dep_fd_route_entry_t *slot = dep_route_slot(destination, fd, true);
      if (!slot)
        return false;
      slot->read_route = dep_fd_materialized_route(state, journal, baseline, fd,
                                                   DEP_FD_ACCESS_READ);
      slot->write_route = dep_fd_materialized_route(state, journal, baseline,
                                                    fd, DEP_FD_ACCESS_WRITE);
    }
  }
  if (state->truncated)
    return false;
  uint32_t count = dep_route_state_count(state);
  for (uint32_t path = 0; path < count; path++)
    if (!dep_fd_materialize_tree(state, journal, baseline, destination,
                                 dep_route_state_root(state, journal, path)))
      return false;
  return true;
}

/* Reconcile immutable map versions by shared subtree identity. Ordinary
 * straight-line updates touch only their AVL paths, not every inherited FD.
 * Tree rotations fall back to the changed subtree, never source replay. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_fd_materialize_delta(
    const dep_route_state_t *state, const dep_route_state_t *previous,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    dep_owner_routes_t *destination, uint32_t root, uint32_t old_root,
    bool reverse) {
  if (!root || root == old_root)
    return true;
  const dep_route_change_t *change = &journal->entries[root - 1];
  const dep_route_change_t *old =
      old_root ? &journal->entries[old_root - 1] : NULL;
  if (old && (dep_fd_ref_compare(change->fd, old->fd) != 0 ||
              change->access != old->access))
    old = dep_route_root_change(old_root, journal, change->fd, change->access);
  if (!old)
    old = dep_route_state_change(reverse ? state : previous, journal,
                                 change->fd, change->access);
  if (old == change)
    return true;
  bool same_key = old && dep_fd_ref_compare(change->fd, old->fd) == 0 &&
                  change->access == old->access;
  if (!dep_fd_materialize_delta(state, previous, journal, baseline, destination,
                                change->left, same_key ? old->left : 0,
                                reverse))
    return false;
  const dep_route_change_t *prior =
      same_key ? old
               : dep_route_state_change(reverse ? state : previous, journal,
                                        change->fd, change->access);
  if (change->access <= DEP_FD_ACCESS_BINDING &&
      (!prior || prior->snapshot != change->snapshot)) {
    dep_fd_route_entry_t *slot = dep_route_slot(destination, change->fd, false);
    if (!dep_fd_bound(state, journal, baseline, change->fd)) {
      if (slot)
        dep_route_remove(destination, (uint32_t)(slot - destination->fd));
    } else {
      slot = dep_route_slot(destination, change->fd, true);
      if (!slot)
        return false;
      slot->read_route = dep_fd_materialized_route(
          state, journal, baseline, change->fd, DEP_FD_ACCESS_READ);
      slot->write_route = dep_fd_materialized_route(
          state, journal, baseline, change->fd, DEP_FD_ACCESS_WRITE);
    }
  }
  return dep_fd_materialize_delta(state, previous, journal, baseline,
                                  destination, change->right,
                                  same_key ? old->right : 0, reverse);
}

/* destination may be source for an in-place scope advance. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool dep_fd_materialize_from(
    const dep_route_state_t *state, const dep_route_state_t *previous,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_owner_routes_t *source, dep_owner_routes_t *destination) {
  if (state->alternative_count || previous->alternative_count)
    return dep_fd_materialize(state, journal, baseline, destination);
  if (destination != source)
    dep_copy_routes(destination, source);
  return !state->truncated &&
         dep_fd_materialize_delta(state, previous, journal, baseline,
                                  destination, state->root, previous->root,
                                  false) &&
         dep_fd_materialize_delta(state, previous, journal, baseline,
                                  destination, previous->root, state->root,
                                  true);
}

/* Record changes in the proof domain as well as route changes. A removed
 * binding must remain absent in every later version until reallocated. */
static SHELL_NONNULL(1, 2, 3, 4, 7) bool dep_fd_bindings(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *before, const dep_owner_routes_t *after,
    const dep_fd_op_t *ops, uint32_t op_count,
    const dep_named_mutations_t *mutations) {
  /* Allocations come only from this owner's prepared operations. Ordinary
   * numeric commands must not search every inherited descriptor variable. */
  for (uint32_t i = 0; i < op_count; i++) {
    if (ops[i].fd != SHELL_DEP_FD_NAMED)
      continue;
    dep_fd_ref_t fd = {ops[i].fd, ops[i].fd_name, ops[i].fd_name_len};
    dep_route_set_t bound = {0};
    const dep_fd_route_entry_t *slot = dep_route_find(after, fd);
    dep_route_set_t existing =
        dep_fd_raw_fact(state, journal, before, fd, DEP_FD_ACCESS_BINDING);
    if (slot && existing.routes[0].kind == DEP_ROUTE_ALIAS)
      continue;
    dep_route_set_set(
        &bound, (dep_fd_route_t){
                    slot ? (slot->read_route.kind == DEP_ROUTE_CLOSED &&
                                    slot->write_route.kind == DEP_ROUTE_CLOSED
                                ? DEP_ROUTE_CLOSED
                                : DEP_ROUTE_INHERITED)
                         : DEP_ROUTE_DYNAMIC,
                    UINT32_MAX});
    if (!dep_route_state_store_access(state, journal, fd, DEP_FD_ACCESS_BINDING,
                                      bound))
      return false;
  }
  uint32_t targets = mutations->clear ? before->fd_count : mutations->count;
  for (uint32_t i = 0; i < targets; i++) {
    const dep_fd_route_entry_t *target =
        mutations->clear
            ? &before->fd[i]
            : dep_named_effect_target(before, &mutations->effects[i]);
    if (!target)
      continue;
    dep_fd_ref_t fd = target->fd;
    if (!dep_named_mutation_affects(mutations, fd) || dep_route_find(after, fd))
      continue;
    dep_route_set_t bound = {0};
    dep_route_set_set(&bound, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
    if (!dep_route_state_store_access(state, journal, fd, DEP_FD_ACCESS_BINDING,
                                      bound))
      return false;
  }
  return mutations->before_redirect ||
         dep_ifs_apply(state, journal, before, mutations);
}

/* Only a not-yet-established allocation may become known absent when skipped.
 * An explicitly invalidated variable is UNKNOWN and must stay that way. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_mark_absent(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_fd_ref_t fd) {
  dep_route_set_t fact =
      dep_fd_fact(state, journal, baseline, fd, DEP_FD_ACCESS_BINDING);
  if (fact.routes[0].kind != DEP_ROUTE_UNSEEN)
    return true;
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_ABSENT, UINT32_MAX});
  for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
       access <<= 1)
    if (!dep_route_state_store_access(state, journal, fd,
                                      (dep_fd_access_t)access, fact))
      return false;
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
  return dep_route_state_store_access(state, journal, fd, DEP_FD_ACCESS_BINDING,
                                      fact);
}

/* Successful descriptor setup proves existence independently of access mode.
 * A self-dup is a no-op, even when closed. Inherited numeric descriptors may
 * be closed by the caller; document/pipe capabilities prove an installed FD.
 */
static SHELL_NONNULL(1, 2, 3, 4) uint8_t
    dep_fd_operation_outcomes(const dep_fd_op_t *op,
                              const dep_route_state_t *state,
                              const dep_route_journal_t *journal,
                              const dep_owner_routes_t *baseline) {
  if (op->kind == DEP_FD_OP_DOCUMENT && op->document_flags &&
      (*op->document_flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED))
    return DEP_STATUS_MAY_FAIL;
  if (dep_fd_ifs_expansion(op, state, journal, baseline) == 1)
    return DEP_STATUS_MAY_FAIL;
  if (op->kind == DEP_FD_OP_CLOSE) {
    if (op->fd != SHELL_DEP_FD_NAMED)
      return DEP_STATUS_MAY_SUCCEED;
    dep_fd_ref_t target = {op->fd, op->fd_name, op->fd_name_len};
    dep_route_set_t facts = dep_fd_raw_fact(state, journal, baseline, target,
                                            DEP_FD_ACCESS_BINDING);
    uint8_t outcomes = 0;
    for (uint32_t i = 0; i < facts.count; i++) {
      if (facts.routes[i].kind == DEP_ROUTE_UNAVAILABLE ||
          facts.routes[i].kind == DEP_ROUTE_ABSENT)
        outcomes |= DEP_STATUS_MAY_FAIL;
      else if (facts.routes[i].kind == DEP_ROUTE_UNSEEN ||
               facts.routes[i].kind == DEP_ROUTE_DYNAMIC)
        outcomes |= DEP_STATUS_EITHER;
      else
        outcomes |= DEP_STATUS_MAY_SUCCEED;
    }
    return outcomes;
  }
  if (op->kind != DEP_FD_OP_DUP)
    return DEP_STATUS_EITHER;
  dep_fd_ref_t target = {op->fd, op->fd_name, op->fd_name_len};
  dep_fd_ref_t source = {op->target_fd, op->target_fd_name,
                         op->target_fd_name_len};
  if (target.value != SHELL_DEP_FD_NAMED && dep_fd_ref_equal(target, source))
    return DEP_STATUS_MAY_SUCCEED;
  dep_route_set_t facts =
      dep_fd_fact(state, journal, baseline, source, DEP_FD_ACCESS_BINDING);
  uint8_t outcomes = 0;
  for (uint32_t i = 0; i < facts.count; i++) {
    if (facts.routes[i].kind == DEP_ROUTE_UNAVAILABLE ||
        facts.routes[i].kind == DEP_ROUTE_ABSENT ||
        facts.routes[i].kind == DEP_ROUTE_CLOSED)
      outcomes |= DEP_STATUS_MAY_FAIL;
    else if (facts.routes[i].kind == DEP_ROUTE_UNSEEN ||
             facts.routes[i].kind == DEP_ROUTE_DYNAMIC)
      outcomes |= DEP_STATUS_EITHER;
    else
      outcomes |= DEP_STATUS_MAY_SUCCEED;
  }
  return outcomes;
}

/* Join one changed capability/proof slot. Callers already know which prepared
 * operations differ, so a prefix join need not walk the whole descriptor map.
 */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_join_slot(
    dep_route_state_t *destination, const dep_route_state_t *source,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    dep_fd_ref_t fd, dep_fd_access_t access) {
  dep_route_set_t routes =
      dep_fd_raw_fact(destination, journal, baseline, fd, access);
  dep_route_set_t other =
      dep_fd_raw_fact(source, journal, baseline, fd, access);
  for (uint32_t i = 0; i < other.count; i++)
    if (!dep_route_set_add(&routes, other.routes[i]))
      return false;
  return dep_route_state_store_access(destination, journal, fd, access, routes);
}

/* Failed numeric redirects and closes are rolled back, even for exec. A newly
 * allocated named descriptor and its variable assignment survive. This is a
 * setup-failure lifetime, distinct from publication after successful setup. */
static SHELL_NONNULL(1) bool dep_fd_failure_persists(const dep_fd_op_t *op,
                                                     bool named_binding) {
  return named_binding && op->fd == SHELL_DEP_FD_NAMED &&
         op->kind != DEP_FD_OP_CLOSE;
}

/* Publish one newly reached allocation, retaining its indirection. The
 * indexed undo set includes only numeric changes already reached in setup;
 * later redirects cannot retroactively acquire a restoration frame. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool dep_fd_publish_allocation(
    dep_route_state_t *destination, const dep_route_state_t *local,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_fd_op_t *op, const dep_owner_routes_t *undo) {
  if (op->resets_descriptor &&
      dep_fd_name_equal(op->fd_name, op->fd_name_len, "IFS", 3) &&
      !dep_ifs_store(destination, journal, DEP_IFS_DIGITS | DEP_IFS_SELF))
    return false;
  dep_fd_ref_t name = dep_fd_operation_target(op);
  uint32_t allocated = dep_allocation_slot(journal, op);
  if (allocated == SHELL_DEP_FD_NONE)
    return false;
  dep_route_set_t available = dep_fd_raw_fact(destination, journal, baseline,
                                              dep_fd_numeric(SHELL_DEP_FD_NONE),
                                              DEP_FD_ACCESS_AVAILABLE);
  bool consumed = false;
  for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_BINDING;
       access <<= 1) {
    dep_route_set_t raw = dep_fd_raw_fact(local, journal, baseline, name,
                                          (dep_fd_access_t)access);
    for (uint32_t slot = 0; slot < raw.count; slot++) {
      if (raw.routes[slot].kind != DEP_ROUTE_ALIAS)
        continue;
      dep_fd_ref_t fd = dep_fd_numeric(raw.routes[slot].value);
      if ((fd.value == allocated || fd.value <= SHELL_DEP_FD_MAX) &&
          !dep_route_find(undo, fd)) {
        if (!dep_route_state_store_access(
                destination, journal, fd, (dep_fd_access_t)access,
                dep_fd_raw_fact(local, journal, baseline, fd,
                                (dep_fd_access_t)access)))
          return false;
        if (fd.value <= SHELL_DEP_FD_MAX)
          consumed |= dep_allocation_remove_candidate(&available, fd.value);
      }
    }
    if (!dep_route_state_store_access(destination, journal, name,
                                      (dep_fd_access_t)access, raw))
      return false;
  }
  return !consumed ||
         dep_route_state_store_access(destination, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_AVAILABLE, available);
}

/* Allocation paths carry their own failure-prefix publication root. Each
 * reached operation advances it once, so a failure neither cross-products
 * unrelated versions nor replays an ever-growing redirect prefix. */
static SHELL_NONNULL(1, 2, 3, 7, 8) bool dep_fd_correlated_setup_failures(
    const dep_route_state_t *entry, dep_route_journal_t *journal,
    const dep_owner_routes_t *incoming, const dep_fd_op_t *ops,
    uint32_t op_count, bool named_binding, dep_fd_flow_t *failures,
    const dep_route_state_t *setup_entry) {
  *failures = (dep_fd_flow_t){0};
  dep_route_state_t local = {0};
  uint32_t count = dep_route_state_count(setup_entry);
  for (uint32_t path = 0; path < count; path++) {
    dep_route_state_t one = dep_route_state_single(
        dep_route_state_root(setup_entry, journal, path));
    dep_route_state_t persistent = one;
    if (dep_route_state_count(entry) == 1)
      persistent.root = entry->root;
    if (!dep_ifs_copy(&persistent, &one, journal, incoming))
      return false;
    for (uint32_t op = 0; op < op_count; op++)
      if (ops[op].fd == SHELL_DEP_FD_NAMED && ops[op].resets_descriptor &&
          !dep_fd_mark_absent(&persistent, journal, incoming,
                              dep_fd_operation_target(ops + op)))
        return false;
    dep_route_set_t saved = {0};
    dep_route_set_set(&saved,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, persistent.root});
    if (!dep_route_state_store_access(&one, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_PERSISTENT, saved))
      return false;
    if (path == 0)
      local = one;
    else if (!dep_route_state_add_root(&local, journal, one.root))
      return false;
  }
  local.correlated = true;
  dep_owner_routes_t undo = {0};
  bool restores_low = false;
  for (uint32_t begin = 0; begin < op_count;) {
    uint32_t end = begin + 1;
    while (end < op_count && ops[end].pos == ops[begin].pos)
      end++;
    dep_route_state_t next = {0};
    bool have_next = false;
    for (uint32_t op = begin; op < end; op++) {
      if (dep_fd_op_saves_numeric(ops + op)) {
        if (!dep_route_slot(&undo, dep_fd_numeric(ops[op].fd), true))
          return false;
        restores_low |= ops[op].fd < DEP_BASH_VARREDIR_MIN_FD;
      }
    }
    for (uint32_t path = 0; path < dep_route_state_count(&local); path++) {
      dep_route_state_t one =
          dep_route_state_single(dep_route_state_root(&local, journal, path));
      one.correlated = true;
      dep_route_set_t saved = dep_fd_raw_fact(&one, journal, incoming,
                                              dep_fd_numeric(SHELL_DEP_FD_NONE),
                                              DEP_FD_ACCESS_PERSISTENT);
      dep_route_state_t persistent =
          dep_route_state_single(saved.routes[0].value);
      persistent.correlated = true;
      uint8_t outcomes =
          dep_fd_operation_outcomes(ops + begin, &one, journal, incoming);
      if ((outcomes & DEP_STATUS_MAY_FAIL) &&
          !dep_fd_add(failures, 1, persistent, journal, incoming))
        return false;
      if (!(outcomes & DEP_STATUS_MAY_SUCCEED))
        continue;
      if (!dep_route_state_apply(&one, journal, incoming, ops + begin,
                                 end - begin, begin == 0))
        return false;
      for (uint32_t branch = 0; branch < dep_route_state_count(&one);
           branch++) {
        dep_route_state_t applied =
            dep_route_state_single(dep_route_state_root(&one, journal, branch));
        applied.correlated = true;
        dep_route_state_t published = persistent;
        for (uint32_t op = begin; op < end; op++)
          if (dep_fd_failure_persists(ops + op, named_binding) &&
              !dep_fd_publish_allocation(&published, &applied, journal,
                                         incoming, ops + op, &undo))
            return false;
        dep_route_set_t low = dep_fd_raw_fact(&applied, journal, incoming,
                                              dep_fd_numeric(SHELL_DEP_FD_NONE),
                                              DEP_FD_ACCESS_LOW_STATE);
        if (!restores_low && low.count &&
            !dep_route_state_store_access(&published, journal,
                                          dep_fd_numeric(SHELL_DEP_FD_NONE),
                                          DEP_FD_ACCESS_LOW_STATE, low))
          return false;
        dep_route_set_set(
            &saved, (dep_fd_route_t){DEP_ROUTE_INHERITED, published.root});
        if (!dep_route_state_store_access(&applied, journal,
                                          dep_fd_numeric(SHELL_DEP_FD_NONE),
                                          DEP_FD_ACCESS_PERSISTENT, saved))
          return false;
        if (!have_next) {
          next = applied;
          have_next = true;
        } else if (!dep_route_state_add_root(&next, journal, applied.root))
          return false;
      }
    }
    if (!have_next)
      break;
    local = next;
    begin = end;
  }
  return true;
}

/* Consume each prepared redirect batch once. Keep immutable prefix versions;
 * never copy a growing descriptor table or replay the source for each failure.
 * Preserve surviving named allocations; numeric setup is rolled back. */
static SHELL_NONNULL(1, 2, 3, 4, 9, 10, 11) bool dep_fd_setup_failures(
    const dep_route_state_t *entry, dep_route_journal_t *journal,
    const dep_owner_routes_t *incoming, const dep_route_state_t *completed,
    const dep_fd_op_t *ops, uint32_t op_count, bool descriptor_exec,
    bool named_binding, const dep_named_mutations_t *mutations,
    dep_fd_flow_t *failures, const dep_route_state_t *setup_entry) {
  /* Numeric-only setup has no surviving prefix publication: every failure
   * returns the entry version itself. Do not manufacture an equivalent map
   * by undoing the completed tree, which loses shared identity and makes
   * successive conditional failures merge ever-growing descriptor tables. */
  bool numeric_only = !mutations->count && !mutations->clear;
  for (uint32_t op = 0; op < op_count; op++)
    numeric_only &= ops[op].fd != SHELL_DEP_FD_NAMED;
  if (numeric_only) {
    *failures = (dep_fd_flow_t){0};
    failures->state[1] = *entry;
    if (!dep_ifs_copy(&failures->state[1], setup_entry, journal, incoming))
      return false;
    dep_route_state_t local = *setup_entry;
    for (uint32_t begin = 0; begin < op_count;) {
      uint32_t end = begin + 1;
      while (end < op_count && ops[end].pos == ops[begin].pos)
        end++;
      uint8_t outcomes =
          dep_fd_operation_outcomes(ops + begin, &local, journal, incoming);
      if (outcomes & DEP_STATUS_MAY_FAIL)
        failures->mask = DEP_STATUS_MAY_FAIL;
      if (!(outcomes & DEP_STATUS_MAY_SUCCEED) || end == op_count)
        break;
      if (!dep_route_state_apply(&local, journal, incoming, ops + begin,
                                 end - begin, begin == 0))
        return false;
      begin = end;
    }
    return true;
  }
  bool single_allocation = op_count && !mutations->count && !mutations->clear &&
                           ops[0].fd == SHELL_DEP_FD_NAMED &&
                           ops[0].resets_descriptor;
  for (uint32_t op = 1; op < op_count; op++)
    single_allocation &= ops[op].pos == ops[0].pos;
  if (single_allocation) {
    *failures = (dep_fd_flow_t){0};
    uint8_t outcomes =
        dep_fd_operation_outcomes(ops, setup_entry, journal, incoming);
    if (outcomes & DEP_STATUS_MAY_FAIL) {
      failures->mask = DEP_STATUS_MAY_FAIL;
      failures->state[1] = *entry;
      if (!dep_fd_mark_absent(&failures->state[1], journal, incoming,
                              dep_fd_operation_target(ops)))
        return false;
    }
    return true;
  }
  if (entry->correlated || completed->correlated)
    return dep_fd_correlated_setup_failures(entry, journal, incoming, ops,
                                            op_count, named_binding, failures,
                                            setup_entry);
  dep_route_state_t local = *setup_entry, persistent = *entry;
  dep_owner_routes_t undo = {0};
  *failures = (dep_fd_flow_t){0};
  /* Keep the completed tree's key layout, restoring only changed values. Both
   * outcome versions then share their unchanged subtrees even across AVL
   * rotations caused by this owner's new identities. */
  failures->state[1] = *completed;
  if (!dep_ifs_copy(&failures->state[1], setup_entry, journal, incoming) ||
      !dep_ifs_copy(&persistent, setup_entry, journal, incoming))
    return false;
  if (!dep_route_state_store_access(
          &failures->state[1], journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
          DEP_FD_ACCESS_AVAILABLE,
          dep_fd_raw_fact(entry, journal, incoming,
                          dep_fd_numeric(SHELL_DEP_FD_NONE),
                          DEP_FD_ACCESS_AVAILABLE)))
    return false;
  for (uint32_t i = 0; i < op_count; i++) {
    if (!dep_fd_op_persists(ops + i, descriptor_exec, named_binding))
      continue;
    dep_fd_ref_t fd = {ops[i].fd, ops[i].fd_name, ops[i].fd_name_len};
    if (fd.value == SHELL_DEP_FD_NAMED) {
      dep_route_set_t old =
          dep_fd_raw_fact(entry, journal, incoming, fd, DEP_FD_ACCESS_READ);
      for (uint32_t slot = 0; slot < old.count; slot++) {
        if (old.routes[slot].kind != DEP_ROUTE_ALIAS)
          continue;
        dep_fd_ref_t backing = dep_fd_numeric(old.routes[slot].value);
        for (uint32_t access = DEP_FD_ACCESS_READ;
             access <= DEP_FD_ACCESS_BINDING; access <<= 1)
          if (!dep_route_state_store_access(
                  &failures->state[1], journal, backing,
                  (dep_fd_access_t)access,
                  dep_fd_raw_fact(entry, journal, incoming, backing,
                                  (dep_fd_access_t)access)))
            return false;
      }
    }
    uint32_t last = DEP_FD_ACCESS_BINDING;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= last; access <<= 1)
      if (!dep_route_state_store_access(
              &failures->state[1], journal, fd, (dep_fd_access_t)access,
              dep_fd_raw_fact(entry, journal, incoming, fd,
                              (dep_fd_access_t)access)))
        return false;
    if (fd.value == SHELL_DEP_FD_NAMED &&
        !dep_fd_mark_absent(&failures->state[1], journal, incoming, fd))
      return false;
  }
  if (!mutations->before_redirect) {
    uint32_t targets = mutations->clear ? incoming->fd_count : mutations->count;
    for (uint32_t i = 0; i < targets; i++) {
      const dep_fd_route_entry_t *target =
          mutations->clear
              ? &incoming->fd[i]
              : dep_named_effect_target(incoming, &mutations->effects[i]);
      if (!target)
        continue;
      dep_fd_ref_t fd = target->fd;
      if (dep_named_mutation_affects(mutations, fd) &&
          !dep_route_state_store_access(
              &failures->state[1], journal, fd, DEP_FD_ACCESS_BINDING,
              dep_fd_raw_fact(entry, journal, incoming, fd,
                              DEP_FD_ACCESS_BINDING)))
        return false;
    }
  }
  uint32_t pending = 0;
  for (uint32_t begin = 0; begin < op_count;) {
    uint32_t end = begin + 1;
    while (end < op_count && ops[end].pos == ops[begin].pos)
      end++;
    uint8_t outcomes =
        dep_fd_operation_outcomes(ops + begin, &local, journal, incoming);
    if (outcomes & DEP_STATUS_MAY_FAIL) {
      uint32_t ifs = dep_ifs_get(&persistent, journal, incoming);
      if (failures->mask)
        ifs = dep_ifs_join(ifs,
                           dep_ifs_get(&failures->state[1], journal, incoming));
      if (!dep_ifs_store(&failures->state[1], journal, ifs))
        return false;
      for (uint32_t i = pending; i < begin; i++) {
        if (!dep_fd_failure_persists(ops + i, named_binding))
          continue;
        dep_fd_ref_t fd = {ops[i].fd, ops[i].fd_name, ops[i].fd_name_len};
        uint32_t last = DEP_FD_ACCESS_BINDING;
        for (uint32_t access = DEP_FD_ACCESS_READ; access <= last; access <<= 1)
          if (!(failures->mask
                    ? dep_fd_join_slot(&failures->state[1], &persistent,
                                       journal, incoming, fd,
                                       (dep_fd_access_t)access)
                    : dep_route_state_store_access(
                          &failures->state[1], journal, fd,
                          (dep_fd_access_t)access,
                          dep_fd_raw_fact(&persistent, journal, incoming, fd,
                                          (dep_fd_access_t)access))))
            return false;
      }
      if (!(failures->mask
                ? dep_fd_join_slot(&failures->state[1], &persistent, journal,
                                   incoming, dep_fd_numeric(SHELL_DEP_FD_NONE),
                                   DEP_FD_ACCESS_AVAILABLE)
                : dep_route_state_store_access(
                      &failures->state[1], journal,
                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_AVAILABLE,
                      dep_fd_raw_fact(&persistent, journal, incoming,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_AVAILABLE))))
        return false;
      pending = begin;
      failures->mask = DEP_STATUS_MAY_FAIL;
    }
    if (!(outcomes & DEP_STATUS_MAY_SUCCEED))
      break;
    if (!dep_route_state_apply(&local, journal, incoming, ops + begin,
                               end - begin, begin == 0))
      return false;
    for (uint32_t i = begin; i < end; i++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
      if (dep_fd_op_saves_numeric(ops + i) &&
          !dep_route_slot(&undo, dep_fd_numeric(ops[i].fd), true))
        return false;
      if (!dep_fd_failure_persists(ops + i, named_binding))
        continue;
      if (!dep_fd_publish_allocation(&persistent, &local, journal, incoming,
                                     ops + i, &undo))
        return false;
      uint32_t slot = dep_allocation_slot(journal, ops + i);
      if (slot == SHELL_DEP_FD_NONE)
        return false;
      dep_fd_ref_t fd = dep_fd_numeric(slot);
      if (dep_route_state_has_change(&local, journal, fd,
                                     DEP_FD_ACCESS_BINDING))
        for (uint32_t access = DEP_FD_ACCESS_READ;
             access <= DEP_FD_ACCESS_BINDING; access <<= 1)
          if (!dep_route_state_store_access(
                  &failures->state[1], journal, fd, (dep_fd_access_t)access,
                  dep_fd_raw_fact(&local, journal, incoming, fd,
                                  (dep_fd_access_t)access)))
            return false;
    }
    begin = end;
  }
  return true;
}

/* report_state is optional. For a directly timed exec it receives the local
 * returning outcomes, excluding skipped predecessors and child publication.
 */
static SHELL_NONNULL(1, 2, 4, 5, 6, 7, 8, 13, 15) bool dep_fd_finish_owner(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_owner_routes_t *incoming, const dep_owner_routes_t *executed,
    const dep_route_state_t *executed_state, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec, bool named_binding,
    const dep_named_mutations_t *mutations, dep_route_state_t *report_state,
    const dep_route_state_t *setup_entry) {
  dep_route_state_t selected = stream->selected[event];
  uint32_t all_op_count = op_count;
  uint32_t stop =
      context->owner_setup_stop[dep_snapshot_event_owner(context, event)];
  op_count = 0;
  while (op_count < all_op_count && ops[op_count].pos < stop)
    op_count++;
  if (event < SHELL_MAX_GROUPS) {
    dep_fd_flow_t *body = &stream->scope[event + 1];
    *body = (dep_fd_flow_t){
        .mask = !dep_group_setup_stopped(context, event) &&
                        (stream->entry[event].mask &
                         dep_fd_run_mask(context, stream, event))
                    ? stream->entry[event].mask &
                          dep_fd_run_mask(context, stream, event)
                    : 0};
    if (body->mask)
      body->mask = dep_expansion_status(context, event, body->mask);
    dep_route_state_t local = *executed_state;
    if (!dep_fd_bindings(&local, journal, incoming, executed, ops, op_count,
                         mutations))
      return false;
    body->state[0] = body->state[1] = local;
    dep_fd_flow_t *failure = &stream->setup_failure[event];
    dep_route_state_t persistent = selected;
    if (!dep_route_state_publish(&persistent, journal, executed, &local,
                                 incoming, ops, op_count, false, true) ||
        !dep_fd_bindings(&persistent, journal, incoming, executed, ops,
                         op_count, mutations) ||
        !dep_fd_setup_failures(&selected, journal, incoming, &persistent, ops,
                               all_op_count, false, true, mutations, failure,
                               setup_entry))
      return false;
    if (!failure->mask && !dep_fd_add(failure, 1, selected, journal, baseline))
      return false;
    return true;
  }
  uint32_t range = event - SHELL_MAX_GROUPS;
  bool private = context->execution->pipeline.local_process[range];
  dep_route_state_t continued = selected;
  if (!private) {
    dep_owner_routes_t persistent;
    dep_copy_routes(&persistent, incoming);
    if (!dep_route_state_publish(&continued, journal, executed, executed_state,
                                 incoming, ops, op_count, descriptor_exec,
                                 named_binding) ||
        !dep_apply_persistent_owner_routes(&persistent, executed, ops, op_count,
                                           descriptor_exec, named_binding,
                                           mutations, NULL) ||
        !dep_fd_bindings(&continued, journal, incoming, &persistent, ops,
                         op_count, mutations))
      return false;
  }
  dep_fd_flow_t failures;
  if (!dep_fd_setup_failures(&selected, journal, incoming, &continued, ops,
                             all_op_count, descriptor_exec, named_binding,
                             mutations, &failures, setup_entry))
    return false;
  uint8_t body_status = context->event_body_status[event];
  if (private)
    body_status = DEP_STATUS_EITHER;
  dep_route_state_t failed_body = continued;
  bool runtime_exec =
      descriptor_exec &&
      dep_owner_exec(context, context->range_node[range])->kind ==
          DEP_EXEC_RUNTIME;
  if (!private && (runtime_exec || mutations->success_only)) {
    /* Runtime exec option errors do not retain numeric redirects. Likewise,
     * failed cd execution preserves PWD/OLDPWD while keeping any descriptor
     * variables allocated during its successful redirect setup. */
    dep_owner_routes_t persistent;
    dep_named_mutations_t no_mutations = {0};
    const dep_named_mutations_t *failed_mutations =
        mutations->success_only ? &no_mutations : mutations;
    dep_copy_routes(&persistent, incoming);
    failed_body = selected;
    if (!dep_route_state_publish(
            &failed_body, journal, executed, executed_state, incoming, ops,
            op_count, descriptor_exec && !runtime_exec, named_binding) ||
        !dep_apply_persistent_owner_routes(&persistent, executed, ops, op_count,
                                           descriptor_exec && !runtime_exec,
                                           named_binding, failed_mutations,
                                           NULL) ||
        !dep_fd_bindings(&failed_body, journal, incoming, &persistent, ops,
                         op_count, failed_mutations))
      return false;
  }
  bool negated = context->fast->cmds[range].pipeline_negation_count & 1u;
  dep_fd_flow_t outcomes = {.mask = negated ? dep_status_negate(body_status)
                                            : body_status};
  outcomes.mask |= context->event_static_status[event] & DEP_STATUS_STOP;
  if (context->owner_setup_stop[context->range_node[range]] != UINT32_MAX)
    outcomes.mask = context->event_static_status[event] & DEP_STATUS_STOP;
  for (unsigned i = 0; i < 5; i++)
    outcomes.state[i] = i < 2 ? continued : selected;
  outcomes.state[negated ? 0 : 1] = failed_body;
  if (failures.mask &&
      !dep_fd_add(&outcomes, negated ? 0 : 1,
                  private ? selected : failures.state[1], journal, baseline))
    return false;
  if (report_state) {
    /* A timer inside a child sees that child's exec redirects, even though
     * they are not published into its parent's continuation. */
    *report_state = *executed_state;
    if ((body_status & DEP_STATUS_MAY_FAIL) &&
        !dep_fd_merge(report_state, &failed_body, journal, baseline))
      return false;
    if (failures.mask &&
        !dep_fd_merge(report_state, &failures.state[1], journal, baseline))
      return false;
  }
  return dep_fd_finish(context, stream, event, &outcomes, journal, baseline);
}

static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_finish_collapsed(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_route_state_t *selected) {
  dep_fd_flow_t outcomes = {.mask = context->event_static_status[event]};
  for (unsigned i = 0; i < 5; i++)
    outcomes.state[i] = *selected;
  uint32_t range = event - SHELL_MAX_GROUPS;
  unsigned success = context->fast->cmds[range].pipeline_negation_count & 1u;
  if (context->range_cd_writes[range] && context->effects_active &&
      (outcomes.mask & (1u << success)) &&
      (stream->entry[event].mask & dep_fd_run_mask(context, stream, event))) {
    /* Change only the two variable proofs. Numeric copies remain live and
     * skipped/failure outcomes keep their immutable incoming version. No
     * tokenization, full route-table copy or binding-table scan is needed. */
    dep_route_set_t unknown = {0};
    dep_route_set_set(&unknown,
                      (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
    for (uint32_t i = 0; i < dep_cd_mutations.count; i++) {
      const dep_token_t *name = &dep_cd_mutations.effects[i].token;
      if (!dep_route_state_store_access(
              &outcomes.state[success], journal,
              (dep_fd_ref_t){SHELL_DEP_FD_NAMED, name->start, name->len},
              DEP_FD_ACCESS_BINDING, unknown))
        return false;
    }
  }
  return dep_fd_finish(context, stream, event, &outcomes, journal, baseline);
}

/* An allocation skipped only because this compound's setup failed is known
 * absent, not an arbitrary variable value. Joining absence with the successful
 * allocation retains its possible routes, but invents no route on absence.
 * Explicit reassignment/unset remains unknown and still invalidates proof. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_setup_absences(
    dep_route_state_t *failed, const dep_route_state_t *body,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    uint32_t root, uint32_t entry_root) {
  if (!root || root == entry_root)
    return true;
  dep_route_change_t change = journal->entries[root - 1];
  const dep_route_change_t *entry =
      entry_root ? &journal->entries[entry_root - 1] : NULL;
  bool same_key = entry && dep_fd_ref_compare(change.fd, entry->fd) == 0 &&
                  change.access == entry->access;
  if (!dep_fd_setup_absences(failed, body, journal, baseline, change.left,
                             same_key ? entry->left : 0))
    return false;
  if (change.access == DEP_FD_ACCESS_BINDING &&
      dep_fd_fact(body, journal, baseline, change.fd, DEP_FD_ACCESS_BINDING)
              .routes[0]
              .kind == DEP_ROUTE_INHERITED &&
      dep_fd_fact(failed, journal, baseline, change.fd, DEP_FD_ACCESS_BINDING)
              .routes[0]
              .kind == DEP_ROUTE_UNSEEN) {
    if (!dep_fd_mark_absent(failed, journal, baseline, change.fd))
      return false;
  }
  return dep_fd_setup_absences(failed, body, journal, baseline, change.right,
                               same_key ? entry->right : 0);
}

static SHELL_NONNULL(1, 2, 4, 5, 6) bool dep_fd_complete_group(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t group,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    const dep_redirect_frame_t *frames) {
  dep_fd_flow_t body = stream->scope[group + 1], completed = {0};
  dep_group_completion_t completion = dep_group_completion(context, group);
  dep_route_state_t entry = stream->selected[group];
  dep_route_state_t failed = stream->setup_failure[group].state[1];
  dep_route_state_t body_names;
  if (completion.added &&
      (!dep_fd_select(&body, DEP_STATUS_EITHER | DEP_STATUS_STOP, journal,
                      baseline, &body_names) ||
       !dep_fd_setup_absences(&failed, &body_names, journal, baseline,
                              body_names.root, entry.root)))
    return false;
  if (context->group_exec[group].isolated)
    failed = entry;
  for (unsigned i = 0; i < 5; i++) {
    if ((completion.added & (1u << i)) &&
        !dep_fd_add(&completed, i, failed, journal, baseline))
      return false;
    if (!(body.mask & (1u << i)))
      continue;
    dep_route_state_t state =
        context->group_exec[group].isolated ? entry : body.state[i];
    if (!context->group_exec[group].isolated &&
        !dep_fd_restore_slots(&state, &entry, journal, baseline,
                              frames[group].fds, frames[group].undo_roots,
                              frames[group].count))
      return false;
    for (unsigned target = 0; target < 5; target++)
      if ((completion.outcome[i] & (1u << target)) &&
          !dep_fd_add(&completed, target, state, journal, baseline))
        return false;
  }
  return dep_fd_finish(context, stream, group, &completed, journal, baseline);
}

/* Restore the completed body's temporary numeric frame for its shell-owned
 * timing report. Continuations are transferred separately by dep_fd_stream. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) bool dep_publish_completed_scope(
    dep_owner_routes_t *destination, dep_route_state_t *destination_state,
    const dep_owner_routes_t *completed,
    const dep_route_state_t *completed_state, dep_route_journal_t *journal,
    const dep_route_publication_t *publication) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
  dep_owner_routes_t restored;
  dep_copy_routes(&restored, completed);
  dep_route_state_t alternatives = *completed_state;
  if (!dep_restore_continuation_routes(&restored, destination, publication) ||
      !dep_restore_continuation_route_state(
          &alternatives, journal, destination_state, destination, publication))
    return false;
  dep_copy_routes(destination, &restored);
  *destination_state = alternatives;
  return true;
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_complete_route_group(
    dep_route_workspace_t *workspace, const dep_parse_context_t *context,
    dep_owner_routes_t *root, const dep_owner_routes_t *baseline,
    uint32_t group) {
  uint16_t raw_parent = context->fast->groups[group].parent;
  int32_t parent = raw_parent == UINT16_MAX ? -1 : (int32_t)raw_parent;
  dep_route_publication_t publication = {context->fast,
                                         workspace->group_redirect_frames,
                                         (int32_t)group, parent, NULL};
  if (!dep_prepare_publication(&publication, &workspace->restored))
    return false;
  dep_owner_routes_t *completed = &workspace->group_snapshot_routes[group];
  dep_route_state_t *completed_state = &workspace->group_route_state[group];
  if (context->fast->groups[group].pipeline_time_mode != SHELL_PIPE_TIME_NONE) {
    if (!dep_fd_select(&workspace->fd_stream.scope[group + 1],
                       DEP_STATUS_EITHER | DEP_STATUS_STOP,
                       &workspace->route_journal, baseline, completed_state))
      return false;
  } else {
    *completed_state = dep_fd_point_version(
        &workspace->fd_stream.scope[group + 1], completed_state);
  }
  if (!dep_fd_materialize(completed_state, &workspace->route_journal, baseline,
                          completed))
    return false;
  workspace->group_time_routes[group] = dep_time_report_for_fd2(
      completed_state, &workspace->route_journal, completed);
  if (workspace->group_shell_time_routes_ready[group]) {
    if (!dep_publish_completed_scope(&workspace->scoped_routes[group],
                                     &workspace->group_shell_route_state[group],
                                     completed, completed_state,
                                     &workspace->route_journal, &publication))
      return false;
    workspace->group_shell_time_routes[group] = dep_time_report_for_fd2(
        &workspace->group_shell_route_state[group], &workspace->route_journal,
        &workspace->scoped_routes[group]);
    if (dep_group_completion(context, group).added & DEP_STATUS_MAY_FAIL) {
      /* This foreground timer still reports when its compound setup fails.
       * That path retains the setup prefix, not any body descriptor effects. */
      dep_route_set_t failed =
          dep_fd_fact(&workspace->fd_stream.setup_failure[group].state[1],
                      &workspace->route_journal, baseline, dep_fd_numeric(2),
                      DEP_FD_ACCESS_WRITE);
      for (uint32_t route = 0; route < failed.count; route++)
        if (!dep_route_set_add(&workspace->group_shell_time_routes[group],
                               failed.routes[route]))
          return false;
    }
  }
  if (!dep_fd_complete_group(context, &workspace->fd_stream, group,
                             &workspace->route_journal, baseline,
                             workspace->group_redirect_frames))
    return false;
  dep_owner_routes_t *destination =
      parent >= 0 ? &workspace->group_snapshot_routes[parent] : root;
  dep_route_state_t *destination_state =
      parent >= 0 ? &workspace->group_route_state[parent]
                  : &workspace->persistent_route_state;
  *destination_state = dep_fd_point_version(
      &workspace->fd_stream.scope[parent + 1], destination_state);
  if (!dep_fd_materialize(destination_state, &workspace->route_journal,
                          baseline, destination))
    return false;
  if (parent >= 0) {
    workspace->group_time_routes[parent] = dep_time_report_for_fd2(
        destination_state, &workspace->route_journal, destination);
  } else {
    workspace->persistent_time_routes = dep_time_report_for_fd2(
        destination_state, &workspace->route_journal, destination);
  }
  return true;
}

static SHELL_NONNULL(1) bool dep_snapshot_complete_groups(
    const dep_parse_context_t *context, uint32_t before_position) {
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_route_workspace_t *workspace = context->workspace;
  const dep_owner_routes_t *baseline =
      &workspace->snapshot_tables[frame->persistent[0]].routes;
  while (frame->active_group_count) {
    uint32_t group = frame->active_groups[frame->active_group_count - 1];
    if (context->execution->pipeline.group_tail[group].redirect_end >
        before_position)
      break;
    frame->active_group_count--;
    if (!dep_fd_complete_group(context, &frame->fd_stream, group,
                               &workspace->snapshot_journal, baseline,
                               frame->redirect_frames))
      return false;
  }
  return true;
}

static SHELL_NONNULL(1, 2, 4) void dep_capture_due_time_reports(
    dep_route_workspace_t *workspace, const dep_time_boundary_t *boundaries,
    uint32_t boundary_count, uint32_t *cursor, uint32_t before_position) {
  /* Boundaries are ordered once, and each completion is consumed once. The
   * owner stream is source ordered too, including nested compound owners. */
  while (*cursor < boundary_count) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
    const dep_time_boundary_t *boundary = &boundaries[*cursor];
    if (boundary->end > before_position)
      break;
    /* A direct stage can already have captured its connector-specific route;
     * completion supplies only the report still awaiting its group context. */
    if (!workspace->time_reports[boundary->target].ready)
      workspace->time_reports[boundary->target] =
          *dep_time_report_context_snapshot(workspace, boundary);
    (*cursor)++;
  }
}

static int dep_time_boundary_compare(const void *left, const void *right) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
  const dep_time_boundary_t *a = left, *b = right;
  if (a->end != b->end)
    return a->end < b->end ? -1 : 1;
  return a->target < b->target ? -1 : a->target != b->target;
}

static int dep_numeric_value_compare(const void *left, const void *right) {
  uint32_t a = *(const uint32_t *)left;
  uint32_t b = *(const uint32_t *)right;
  return a < b ? -1 : a != b;
}

typedef struct {
  uint32_t fds[DEP_ROUTE_OPERATION_CAPACITY];
  bool read[DEP_ROUTE_OPERATION_CAPACITY];
  dep_index_node_t index[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t root, count;
  bool overflow;
  bool observe_undo;
  bool named_closes;
  bool named_fds;
  uint32_t numeric_redirects;
  const char *pending_operand;
} dep_observable_inventory_t;

static SHELL_NONNULL(1, 3) int dep_observable_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  const dep_observable_inventory_t *inventory = context;
  uint32_t value = inventory->fds[index], other = *(const uint32_t *)key;
  return value < other ? -1 : value != other;
}

static SHELL_NONNULL(1) void dep_inventory_add(
    dep_observable_inventory_t *inventory, uint32_t fd, bool read) {
  if (fd < DEP_BASH_VARREDIR_MIN_FD || fd > SHELL_DEP_FD_MAX)
    return;
  uint32_t candidate = inventory->count + 1, match = 0;
  inventory->root =
      dep_index_insert(inventory->index, inventory->root, candidate,
                       DEP_ROUTE_OPERATION_CAPACITY, dep_observable_compare,
                       inventory, &fd, &match);
  if (!match)
    inventory->overflow = true;
  else {
    if (match == candidate) {
      inventory->fds[inventory->count] = fd;
      inventory->read[inventory->count++] = false;
    }
    inventory->read[match - 1] |= read;
  }
}

/* The semantic boundary already visits root and expansion-body tokens.
 * Collect observable numeric identities there, before any operand snapshot
 * needs allocation decisions. This is metadata extraction, not another parse
 * or a later replay of the source for each named descriptor. */
static SHELL_NONNULL(1, 2) void dep_observe_descriptor_token(
    const shell_token_t *token, void *context) {
  dep_observable_inventory_t *inventory = context;
  if (inventory->pending_operand &&
      token->start >= inventory->pending_operand) {
    uint32_t fd = 0;
    if (shell_process_classify_static_fd_target(
            token->start, token->length, &fd) == SHELL_PROCESS_FD_TARGET_FD)
      dep_inventory_add(inventory, fd, true);
  }
  inventory->pending_operand = NULL;
  bool redirect = token->type == SHELL_TOKEN_REDIRECT_IN ||
                  token->type == SHELL_TOKEN_REDIRECT_OUT ||
                  token->type == SHELL_TOKEN_REDIRECT_ERR ||
                  token->type == SHELL_TOKEN_REDIRECT_APPEND ||
                  token->type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
                  token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
                  token->type == SHELL_TOKEN_HEREDOC ||
                  token->type == SHELL_TOKEN_HERESTRING;
  if (!redirect) {
    if (token->type == SHELL_TOKEN_SEMICOLON ||
        token->type == SHELL_TOKEN_AND || token->type == SHELL_TOKEN_OR ||
        token->type == SHELL_TOKEN_PIPE ||
        token->type == SHELL_TOKEN_PIPE_BOTH ||
        token->type == SHELL_TOKEN_GROUP_START ||
        token->type == SHELL_TOKEN_SUBSHELL_START ||
        token->type == SHELL_TOKEN_GROUP_END ||
        token->type == SHELL_TOKEN_SUBSHELL_END)
      inventory->numeric_redirects = 0;
    return;
  }
  size_t after = 0;
  uint32_t fd = 0;
  if (shell_source_parse_io_number(token->start, 0, token->length, &after,
                                   &fd) == SHELL_SOURCE_IO_NUMBER_VALID) {
    dep_inventory_add(inventory, fd, false);
    inventory->observe_undo |=
        fd >= DEP_BASH_VARREDIR_MIN_FD && inventory->numeric_redirects != 0;
    inventory->numeric_redirects++;
  } else if (shell_source_parse_named_fd_redirect(token->start, 0,
                                                  token->length, &after)) {
    inventory->observe_undo = true;
    inventory->named_fds = true;
    dep_token_t raw = {.start = token->start, .len = (uint32_t)token->length};
    inventory->named_closes |= classify_redirect(&raw) == DEP_REDIRECT_DUP;
  } else {
    inventory->numeric_redirects++;
  }
  dep_token_t raw = {.start = token->start, .len = (uint32_t)token->length};
  uint32_t source, target, source_len, target_len;
  const char *source_name, *target_name;
  bool close, target_unquoted;
  dep_fd_access_t access;
  if (dep_parse_dup_redirect(&raw, &source, &target, &source_name, &source_len,
                             &target_name, &target_len, &close, &access,
                             &target_unquoted)) {
    inventory->named_closes |= source == SHELL_DEP_FD_NAMED && close;
    dep_inventory_add(inventory, source, false);
    dep_inventory_add(inventory, target, true);
  } else if (classify_redirect(&raw) == DEP_REDIRECT_DUP) {
    /* A separated duplication operand is the next lexical word. Whitespace
     * is outside the redirect token, so retain its source frontier. */
    inventory->pending_operand = token->start + token->length;
  }
}

/* Reuse the inventory collected by the source validation boundary. Numeric
 * writes need distinguishable allocation identities only when a named
 * variable can expose their numbers; otherwise only later numeric reads can
 * observe a Bash undo-slot collision. */
static SHELL_NONNULL(1) void dep_prepare_observable_fds(
    dep_route_workspace_t *workspace) {
  dep_route_journal_t *journal = &workspace->route_journal;
  journal->observable_fd_count =
      workspace->snapshot_journal.observable_fd_count;
  journal->observe_undo = workspace->snapshot_journal.observe_undo;
  journal->named_closes = workspace->snapshot_journal.named_closes;
  memcpy(journal->observable_fds, workspace->snapshot_journal.observable_fds,
         journal->observable_fd_count * sizeof(journal->observable_fds[0]));
}

/* Source/context and inverse maps belong to this construction. Workspace was
 * validated at entry; streams and process_routes are prepared destinations. */
static SHELL_NONNULL(1, 2, 4, 5, 6, 7, 8, 9, 10, 13, 15, 16,
                     17) shell_dep_error_t
    dep_resolve_effective_routes(
        shell_dep_graph_t *graph, const char *cmd, uint32_t cmd_len,
        const shell_parse_result_t *fast,
        const shell_pipeline_index_t *pipeline, const uint32_t *node_range,
        const uint32_t *range_node, const uint32_t *node_group,
        const uint32_t *group_node, const dep_group_exec_t *group_exec,
        uint32_t max_nodes, uint32_t max_edges, dep_subgraph_streams_t *streams,
        const dep_fd_imports_t *imports,
        const dep_process_route_map_t *process_routes,
        dep_route_workspace_t *workspace, const dep_parse_context_t *context) {
  /* Route tables used to occupy more than two MiB on every parse stack. The
   * graph already has bounded capacities, but a caller should not need a
   * multi-megabyte thread stack merely to resolve it. */
  dep_owner_routes_t *routes = workspace->routes;
  dep_owner_routes_t persistent_routes = {0};
  dep_owner_routes_t flow_baseline;
  dep_fd_stream_t *fd_stream = &workspace->fd_stream;
  memset(fd_stream, 0, sizeof(*fd_stream));
  memset(workspace->scoped_routes_active, 0,
         sizeof(workspace->scoped_routes_active));
  memset(workspace->group_snapshot_routes_ready, 0,
         sizeof(workspace->group_snapshot_routes_ready));
  bool resolved_owner[SHELL_DEP_MAX_NODES] = {false};
  bool local_owner[SHELL_DEP_MAX_NODES] = {false};
  bool empty_timing_owner[SHELL_DEP_MAX_NODES] = {false};
  shell_dep_edge_t *original_edges = workspace->original_edges;
  dep_fd_transition_t *fd_transitions = workspace->fd_transitions;
  shell_dep_edge_t *pipes = workspace->pipes;
  dep_owner_edge_index_t *owner_edges = &workspace->owner_edges;
  memset(owner_edges, 0, sizeof(*owner_edges));
  for (uint32_t node = 0; node < graph->node_count; node++) {
    owner_edges->io_head[node] = UINT32_MAX;
    owner_edges->named_head[node] = UINT32_MAX;
    owner_edges->pipe_in[node] = UINT32_MAX;
    owner_edges->pipe_out[node] = UINT32_MAX;
  }
  dep_fd_op_t *ops = workspace->ops;
  const uint32_t op_capacity = SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS;
  dep_time_boundary_t time_boundaries[SHELL_DEP_MAX_NODES] = {0};
  uint32_t time_boundary_count = dep_collect_time_boundaries(
      graph, cmd, cmd_len, fast, pipeline, node_range, range_node, node_group,
      group_node, group_exec, time_boundaries, SHELL_DEP_MAX_NODES);
  qsort(time_boundaries, time_boundary_count, sizeof(time_boundaries[0]),
        dep_time_boundary_compare);
  /* Each directly timed target owns exactly one boundary. Keep an owner
   * lookup beside the completion stream instead of rescanning that stream
   * for every group, conditional stage, and descriptor-only exec. */
  uint32_t target_time_boundary[SHELL_DEP_MAX_NODES] = {0};
  for (uint32_t i = 0; i < time_boundary_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
    target_time_boundary[time_boundaries[i].target] = i + 1;
  }
  uint32_t time_boundary_cursor = 0;
  memset(workspace->time_reports, 0, sizeof(workspace->time_reports));
  memset(workspace->scoped_time_routes_ready, 0,
         sizeof(workspace->scoped_time_routes_ready));
  memset(workspace->group_time_routes_ready, 0,
         sizeof(workspace->group_time_routes_ready));
  memset(workspace->group_shell_time_routes_ready, 0,
         sizeof(workspace->group_shell_time_routes_ready));
  memset(workspace->group_redirect_frames, 0,
         sizeof(workspace->group_redirect_frames));
  workspace->persistent_route_state = (dep_route_state_t){0};
  memset(workspace->scoped_route_state, 0,
         sizeof(workspace->scoped_route_state));
  memset(workspace->group_route_state, 0, sizeof(workspace->group_route_state));
  memset(workspace->group_shell_route_state, 0,
         sizeof(workspace->group_shell_route_state));
  dep_route_journal_reset(&workspace->route_journal);
  dep_prepare_observable_fds(workspace);
  memset(workspace->owner_route_state, 0, sizeof(workspace->owner_route_state));
  if (!dep_import_routes(&persistent_routes, imports) ||
      !dep_import_route_alternatives(&workspace->persistent_route_state,
                                     &workspace->route_journal, imports))
    return SHELL_DEP_ETRUNC;
  workspace->persistent_time_routes =
      dep_time_report_for_fd2(&workspace->persistent_route_state,
                              &workspace->route_journal, &persistent_routes);
  dep_copy_routes(&flow_baseline, &persistent_routes);
  fd_stream->scope[0].mask = DEP_STATUS_EITHER;
  fd_stream->scope[0].state[0] = fd_stream->scope[0].state[1] =
      workspace->persistent_route_state;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    local_owner[node] = graph->nodes[node].type == SHELL_NODE_CMD &&
                        node_range[node] != UINT32_MAX &&
                        node_range[node] < fast->count;
    empty_timing_owner[node] =
        local_owner[node] && shell_pipeline_range_is_empty_timing(
                                 cmd, &fast->cmds[node_range[node]]);
  }
  for (uint32_t group = 0; group < fast->group_count; group++)
    if (group_node[group] != UINT32_MAX &&
        group_node[group] < graph->node_count)
      local_owner[group_node[group]] = true;
  uint32_t original_edge_count = graph->edge_count;
  workspace->original_edge_count = original_edge_count;
  memcpy(original_edges, graph->edges,
         original_edge_count * sizeof(original_edges[0]));
  bool dynamic_route_edges[SHELL_DEP_MAX_EDGES] = {false};
  bool persistent_setup_edges[SHELL_DEP_MAX_EDGES] = {false};
  bool reached_named_opens[SHELL_DEP_MAX_EDGES] = {false};
  uint32_t fd_transition_count = 0;
  uint32_t pipe_count = 0;
  dep_ordered_owner_t owner_order[SHELL_DEP_MAX_NODES];
  uint32_t owner_count = 0;
  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    const shell_dep_edge_t *item = &original_edges[edge];
    if (item->type == SHELL_EDGE_PIPE || item->type == SHELL_EDGE_BACKGROUND) {
      owner_edges->private_execution[item->from] = true;
      owner_edges->private_execution[item->to] = true;
    }
    if (item->type != SHELL_EDGE_PIPE ||
        !dep_is_execution_node(graph, item->from) ||
        !dep_is_execution_node(graph, item->to) || !local_owner[item->from] ||
        !local_owner[item->to])
      continue;
    if (pipe_count < SHELL_DEP_MAX_EDGES)
      pipes[pipe_count++] = *item;
  }

  for (uint32_t edge = original_edge_count; edge-- > 0;) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    const shell_dep_edge_t *item = &original_edges[edge];
    uint32_t owner = UINT32_MAX;
    uint32_t *head = NULL;
    if (dep_is_direct_io_edge(graph, item, &owner)) {
      head = &owner_edges->io_head[owner];
    } else if (item->type == SHELL_EDGE_FD_OPEN) {
      if (item->target_fd == SHELL_DEP_FD_NAMED &&
          graph->nodes[item->from].type == SHELL_NODE_DOC)
        owner = item->to;
      else if (item->source_fd == SHELL_DEP_FD_NAMED &&
               graph->nodes[item->to].type == SHELL_NODE_DOC)
        owner = item->from;
      if (owner != UINT32_MAX)
        head = &owner_edges->named_head[owner];
    }
    if (head) {
      owner_edges->io_next[edge] = *head;
      *head = edge;
    }
  }
  for (uint32_t pipe = pipe_count; pipe-- > 0;) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    uint32_t from = pipes[pipe].from, to = pipes[pipe].to;
    owner_edges->pipe_next_out[pipe] = owner_edges->pipe_out[from];
    owner_edges->pipe_out[from] = pipe;
    owner_edges->pipe_next_in[pipe] = owner_edges->pipe_in[to];
    owner_edges->pipe_in[to] = pipe;
  }

  for (uint32_t owner = 0; owner < graph->node_count; owner++)
    if (dep_is_execution_node(graph, owner) && local_owner[owner]) {
      owner_order[owner_count].owner = owner;
      owner_order[owner_count].start =
          dep_owner_source_start(graph, fast, node_range, node_group, owner);
      owner_count++;
    }
  qsort(owner_order, owner_count, sizeof(*owner_order),
        dep_ordered_owner_compare);
  dep_ordered_owner_t control_events[DEP_EXECUTION_EVENT_CAPACITY];
  uint32_t control_previous[DEP_EXECUTION_EVENT_CAPACITY], control_count;
  dep_execution_events(context, control_events, control_previous,
                       &control_count);
  uint32_t control_event[SHELL_DEP_MAX_NODES];
  for (uint32_t i = 0; i < control_count; i++) {
    uint32_t owner = dep_snapshot_event_owner(context, control_events[i].owner);
    if (owner != UINT32_MAX)
      control_event[owner] = i;
  }
  dep_control_stream_t control;
  dep_control_stream_initialize(&control);
  uint8_t control_execution[SHELL_DEP_MAX_NODES] = {0};
  uint32_t fd_event_cursor = 0;
  uint32_t active_groups[SHELL_MAX_GROUPS];
  uint32_t active_group_count = 0;

  for (uint32_t owner_index = 0; owner_index < owner_count; owner_index++) {
    uint32_t owner = owner_order[owner_index].owner;
    uint32_t event = control_event[owner];
    while (fd_event_cursor <= event) {
      uint32_t source_event = control_events[fd_event_cursor].owner;
      uint32_t start = control_events[fd_event_cursor++].start;
      while (active_group_count &&
             pipeline->group_tail[active_groups[active_group_count - 1]]
                     .redirect_end <= start) {
        uint32_t completed = active_groups[--active_group_count];
        if (!dep_complete_route_group(workspace, context, &persistent_routes,
                                      &flow_baseline, completed))
          return SHELL_DEP_ETRUNC;
      }
      dep_route_state_t selected;
      if (!dep_fd_begin(context, fd_stream, source_event,
                        &workspace->route_journal, &flow_baseline, &selected))
        return SHELL_DEP_ETRUNC;
      if (dep_snapshot_event_owner(context, source_event) == UINT32_MAX) {
        if (!dep_fd_finish_collapsed(context, fd_stream, source_event,
                                     &workspace->route_journal, &flow_baseline,
                                     &selected))
          return SHELL_DEP_ETRUNC;
      }
    }
    dep_control_stream_advance(context, &control, control_events,
                               control_previous, event + 1);
    dep_execution_certainty_t local_execution =
        (dep_execution_certainty_t)control.execution[event];
    dep_execution_certainty_t owner_execution = local_execution;
    int32_t control_group = dep_owner_enclosing_group(
        graph, fast, pipeline, node_range, node_group, owner);
    if (control_group >= 0 && group_node[control_group] < graph->node_count)
      owner_execution = dep_execution_compose(
          local_execution, (dep_execution_certainty_t)
                               control_execution[group_node[control_group]]);
    if (!context->effects_active)
      owner_execution = DEP_EXECUTION_NEVER;
    if (control_group >= 0 &&
        dep_group_setup_stopped(context, (uint32_t)control_group))
      owner_execution = DEP_EXECUTION_NEVER;
    control_execution[owner] = (uint8_t)owner_execution;
    uint32_t owner_start = owner_order[owner_index].start;
    dep_capture_due_time_reports(workspace, time_boundaries,
                                 time_boundary_count, &time_boundary_cursor,
                                 owner_start);
    resolved_owner[owner] = true;
    uint32_t op_count = 0;
    bool invalid_dup = false;
    dep_owner_routes_t *state = &routes[owner];
    memset(state, 0, sizeof(*state));
    memset(workspace->route_touched[owner], 0,
           sizeof(workspace->route_touched[owner]));
    if (owner_execution == DEP_EXECUTION_NEVER) {
      /* Syntax owners stay in the graph, but no descriptor setup, expansion
       * resource, publication, or timer report executes at this entry. */
      workspace->time_reports[owner] =
          (dep_route_set_t){.routes = {{DEP_ROUTE_UNAVAILABLE, UINT32_MAX}},
                            .count = 1,
                            .ready = true};
      dep_fd_flow_t none = {0};
      if (!dep_fd_finish(context, fd_stream, dep_owner_event(context, owner),
                         &none, &workspace->route_journal, &flow_baseline))
        return SHELL_DEP_ETRUNC;
      continue;
    }
    bool one_shot_scope = false;
    int32_t named_scope =
        dep_owner_named_scope(graph, fast, pipeline, group_exec, node_range,
                              node_group, owner, &one_shot_scope);
    int32_t enclosing_group = dep_owner_enclosing_group(
        graph, fast, pipeline, node_range, node_group, owner);
    dep_owner_routes_t *persistent = &persistent_routes;
    if (named_scope >= 0) {
      if (!workspace->scoped_routes_active[named_scope]) {
        memset(&workspace->scoped_routes[named_scope], 0,
               sizeof(workspace->scoped_routes[named_scope]));
        workspace->scoped_routes_active[named_scope] = true;
        int32_t parent_scope =
            dep_named_scope_parent(fast, group_exec, (uint32_t)named_scope);
        bool effective_parent =
            enclosing_group >= 0 &&
            workspace->group_snapshot_routes_ready[enclosing_group];
        dep_copy_routes(&workspace->scoped_routes[named_scope],
                        effective_parent
                            ? &workspace->group_snapshot_routes[enclosing_group]
                        : parent_scope >= 0 &&
                                workspace->scoped_routes_active[parent_scope]
                            ? &workspace->scoped_routes[parent_scope]
                            : &persistent_routes);
        int32_t report_parent =
            dep_named_scope_parent(fast, group_exec, (uint32_t)named_scope);
        workspace->scoped_route_state[named_scope] =
            effective_parent ? workspace->group_route_state[enclosing_group]
            : report_parent >= 0 &&
                    workspace->scoped_time_routes_ready[report_parent]
                ? workspace->scoped_route_state[report_parent]
                : workspace->persistent_route_state;
        workspace->scoped_time_routes[named_scope] = dep_time_report_for_fd2(
            &workspace->scoped_route_state[named_scope],
            &workspace->route_journal, &workspace->scoped_routes[named_scope]);
        workspace->scoped_time_routes_ready[named_scope] = true;
      }
      persistent = &workspace->scoped_routes[named_scope];
    }
    bool publishes_to_group = enclosing_group >= 0 &&
                              !(graph->nodes[owner].type == SHELL_NODE_GROUP &&
                                group_exec[node_group[owner]].isolated);
    if (publishes_to_group)
      persistent = &workspace->group_snapshot_routes[enclosing_group];
    /* Entry is selected by list outcome, including setup-failure and stopped
     * paths. There is no special direct-AND shortcut or mutable-scope guess. */
    dep_owner_routes_t selected_routes;
    dep_route_state_t selected_state =
        fd_stream->selected[dep_owner_event(context, owner)];
    dep_route_state_t scope_version =
        publishes_to_group ? workspace->group_route_state[enclosing_group]
        : named_scope >= 0 ? workspace->scoped_route_state[named_scope]
                           : workspace->persistent_route_state;
    if (!dep_fd_materialize_from(&selected_state, &scope_version,
                                 &workspace->route_journal, &flow_baseline,
                                 persistent, &selected_routes))
      return SHELL_DEP_ETRUNC;
    const dep_owner_routes_t *incoming = &selected_routes;
    /* `exec` changes its current shell's descriptor table whenever it runs.
     * In a conditional list that table is only available to a proven `&&`
     * success continuation; it must not be promoted into `persistent`. */
    bool descriptor_exec = graph->nodes[owner].type == SHELL_NODE_CMD &&
                           dep_owner_exec(context, owner)->persistent_redirects;
    /* Every child shell inherits descriptors visible at its creation point.
     * Only its changes are private. A conditional member can instead start
     * from a verified AND predecessor, but still cannot alter the ordinary
     * persistent table. */
    dep_copy_routes(state, incoming);
    dep_token_list_t owner_tokens = {0};
    dep_named_mutations_t empty_mutations = {0};
    const dep_named_mutations_t *mutations = &empty_mutations;
    if (graph->nodes[owner].type == SHELL_NODE_CMD) {
      dep_snapshot_source_t *prepared;
      if (!dep_snapshot_fd_operations(graph, context, owner, &prepared))
        return SHELL_DEP_EPARSE;
      owner_tokens = prepared->tokens;
      mutations = &prepared->mutations;
    }
    dep_apply_named_mutations(state, mutations,
                              DEP_NAMED_MUTATION_BEFORE_REDIRECT);

    for (uint32_t pipe = owner_edges->pipe_out[owner]; pipe != UINT32_MAX;
         pipe = owner_edges->pipe_next_out[pipe]) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
      if ((!dep_route_reset(state, dep_fd_numeric(pipes[pipe].source_fd)) ||
           !dep_route_assign(state, dep_fd_numeric(pipes[pipe].source_fd),
                             DEP_FD_ACCESS_WRITE,
                             (dep_fd_route_t){DEP_ROUTE_PIPE, pipe})))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    }
    for (uint32_t pipe = owner_edges->pipe_in[owner]; pipe != UINT32_MAX;
         pipe = owner_edges->pipe_next_in[pipe]) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
      if ((!dep_route_reset(state, dep_fd_numeric(pipes[pipe].target_fd)) ||
           !dep_route_assign(state, dep_fd_numeric(pipes[pipe].target_fd),
                             DEP_FD_ACCESS_READ,
                             (dep_fd_route_t){DEP_ROUTE_PIPE, pipe})))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    }
    workspace->owner_initial = *state;

    for (uint32_t edge = owner_edges->io_head[owner]; edge != UINT32_MAX;
         edge = owner_edges->io_next[edge]) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
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
          false,
          false,
          false,
          &document->doc.flags,
      };
    }

    /* FD_OPEN is the syntax-preserving representation for a named binding.
     * Add it to the private route table too, so a later `>&"$name"` can copy
     * its concrete file/document route onto an ordinary descriptor without
     * treating the symbolic descriptor itself as command-byte flow. */
    for (uint32_t edge = owner_edges->named_head[owner]; edge != UINT32_MAX;
         edge = owner_edges->io_next[edge]) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
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
          false,
          false,
          false,
          &graph->nodes[document].doc.flags,
      };
    }

    if (graph->nodes[owner].type == SHELL_NODE_CMD &&
        node_range[owner] != UINT32_MAX && node_range[owner] < fast->count) {
      if (!dep_add_prepared_process_operations(owner, process_routes, NULL,
                                               dynamic_route_edges, ops,
                                               &op_count, op_capacity))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (context->owner_assignment_stop[owner] == UINT32_MAX &&
          !dep_add_prepared_dup_operations(cmd, owner_tokens, ops, &op_count,
                                           op_capacity, &invalid_dup))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (invalid_dup) {
        return SHELL_DEP_EPARSE;
      }
    } else if (graph->nodes[owner].type == SHELL_NODE_GROUP) {
      uint32_t group = node_group[owner];
      if (group != UINT32_MAX) {
        const shell_group_t *descriptor = &fast->groups[group];
        uint32_t trailing_end = pipeline->group_tail[group].redirect_end;
        uint32_t trailing_len = trailing_end - descriptor->end;
        if (!dep_add_prepared_process_operations(owner, process_routes, NULL,
                                                 dynamic_route_edges, ops,
                                                 &op_count, op_capacity) ||
            !dep_add_dup_operations(cmd, descriptor->end, trailing_len, ops,
                                    &op_count, op_capacity, &invalid_dup))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        if (invalid_dup) {
          return SHELL_DEP_EPARSE;
        }
      }
    }

    if (dep_owner_pipe_both(context, owner)) {
      if (op_count == op_capacity)
        return SHELL_DEP_ETRUNC;
      ops[op_count++] = dep_pipe_both_operation();
    }
    dep_sort_fd_operations(ops, op_count, workspace->op_scratch);
    dep_prepare_fd_operation_resets(ops, op_count);
    dep_prepare_fd_close_history(ops, op_count);
    if (graph->nodes[owner].type == SHELL_NODE_GROUP &&
        node_group[owner] != UINT32_MAX &&
        !dep_redirect_frame_record(
            &workspace->group_redirect_frames[node_group[owner]], ops,
            op_count))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    for (uint32_t op = 0; op < op_count; op++) {
      dep_fd_op_t *item = &ops[op];
      if (item->pos >= context->owner_setup_stop[owner])
        break;
      if (item->kind == DEP_FD_OP_DOCUMENT && item->fd == SHELL_DEP_FD_NAMED)
        reached_named_opens[item->edge_index] = true;
      if (dep_fd_op_numeric_self_dup(item))
        continue;
      dep_fd_ref_t source = {item->fd, item->fd_name, item->fd_name_len};
      dep_fd_ref_t target = {item->target_fd, item->target_fd_name,
                             item->target_fd_name_len};
      bool self_rebind = dep_fd_op_self_rebind(item);
      dep_fd_route_t saved_read = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
      dep_fd_route_t saved_write = {DEP_ROUTE_UNAVAILABLE, UINT32_MAX};
      if (self_rebind) {
        dep_fd_route_entry_t *slot = dep_route_slot(state, target, false);
        if (!slot)
          return SHELL_DEP_EPARSE;
        saved_read = slot->read_route;
        saved_write = slot->write_route;
      }
      /* A named-FD declaration assigns a new descriptor value. Do not let a
       * previous `$name` binding supply a direction that the new redirect did
       * not open. The two halves of `<>` share a source position and must
       * instead form one bidirectional allocation. */
      if (item->resets_descriptor && !dep_route_reset(state, source))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
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
                state,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                item->access,
                (dep_fd_route_t){DEP_ROUTE_DOC, item->edge_index}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else if (item->kind == DEP_FD_OP_DYNAMIC) {
        if (!dep_route_assign(
                state,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                item->access,
                (dep_fd_route_t){DEP_ROUTE_DYNAMIC, item->edge_index}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else if (item->kind == DEP_FD_OP_CLOSE) {
        if (item->fd == SHELL_DEP_FD_NAMED &&
            dep_route_slot(state, source, false) == NULL)
          return SHELL_DEP_EPARSE;
        if (!dep_route_assign(state, source, DEP_FD_ACCESS_BOTH,
                              (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else {
        if (target.value == SHELL_DEP_FD_NAMED && !self_rebind &&
            dep_route_slot(state, target, false) == NULL) {
          return SHELL_DEP_EPARSE;
        }
        dep_fd_route_t copied_read =
            self_rebind ? saved_read
                        : dep_route_get(state, target, DEP_FD_ACCESS_READ);
        dep_fd_route_t copied_write =
            self_rebind ? saved_write
                        : dep_route_get(state, target, DEP_FD_ACCESS_WRITE);
        bool closed_locally = item->target_closed_locally;
        if (((item->access & DEP_FD_ACCESS_READ) != 0 &&
             copied_read.kind == DEP_ROUTE_CLOSED && !closed_locally) ||
            ((item->access & DEP_FD_ACCESS_WRITE) != 0 &&
             copied_write.kind == DEP_ROUTE_CLOSED && !closed_locally))
          return SHELL_DEP_EPARSE;
        /* Duplication into a named descriptor aliases the source descriptor
         * as a whole.  The `<&`/`>&` spelling selects the operation, not the
         * capabilities retained by its result.  Preserve both routes so an
         * output alias can later be used for output and an input alias can
         * later be used for input; unavailable routes remain unavailable. */
        dep_fd_access_t copied_access = DEP_FD_ACCESS_BOTH;
        if (!dep_route_assign(
                state,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                copied_access & DEP_FD_ACCESS_READ, copied_read) ||
            !dep_route_assign(
                state,
                (dep_fd_ref_t){item->fd, item->fd_name, item->fd_name_len},
                copied_access & DEP_FD_ACCESS_WRITE, copied_write))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      }
    }
    if (descriptor_exec) {
      for (uint32_t op = 0; op < op_count; op++)
        if ((ops[op].kind == DEP_FD_OP_DOCUMENT ||
             ops[op].kind == DEP_FD_OP_DYNAMIC) &&
            ops[op].fd != SHELL_DEP_FD_NAMED &&
            ops[op].edge_index < original_edge_count)
          persistent_setup_edges[ops[op].edge_index] = true;
    }
    bool named_binding = dep_owner_persists_named_binding(graph, owner);
    dep_route_state_t *scope_route_state =
        publishes_to_group ? &workspace->group_route_state[enclosing_group]
        : named_scope >= 0 ? &workspace->scoped_route_state[named_scope]
                           : &workspace->persistent_route_state;
    dep_route_state_t owner_time_state = selected_state;
    dep_route_state_t incoming_time_context = selected_state;
    dep_route_state_t local_route_state = selected_state;
    for (unsigned direction = 0; direction < 2; direction++) {
      for (uint32_t pipe = direction ? owner_edges->pipe_out[owner]
                                     : owner_edges->pipe_in[owner];
           pipe != UINT32_MAX;
           pipe = direction ? owner_edges->pipe_next_out[pipe]
                            : owner_edges->pipe_next_in[pipe]) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
        uint32_t fd = direction ? pipes[pipe].source_fd : pipes[pipe].target_fd;
        for (uint32_t access = DEP_FD_ACCESS_READ;
             access <= DEP_FD_ACCESS_WRITE; access <<= 1) {
          dep_route_set_t installed = {0};
          dep_route_set_set(&installed, dep_route_get(&workspace->owner_initial,
                                                      dep_fd_numeric(fd),
                                                      (dep_fd_access_t)access));
          if (!dep_route_state_store_access(
                  &local_route_state, &workspace->route_journal,
                  dep_fd_numeric(fd), (dep_fd_access_t)access, installed))
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        }
        dep_route_set_t live = {0};
        dep_route_set_set(&live,
                          (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
        if (!dep_route_state_store_access(
                &local_route_state, &workspace->route_journal,
                dep_fd_numeric(fd), DEP_FD_ACCESS_BINDING, live))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      }
    }
    if (mutations->before_redirect &&
        !dep_ifs_apply(&local_route_state, &workspace->route_journal,
                       &workspace->owner_initial, mutations))
      return SHELL_DEP_ETRUNC;
    dep_route_state_t setup_entry = local_route_state;
    uint32_t reached_op_count = 0;
    while (reached_op_count < op_count &&
           ops[reached_op_count].pos < context->owner_setup_stop[owner])
      reached_op_count++;
    if (!dep_route_state_apply(&local_route_state, &workspace->route_journal,
                               &workspace->owner_initial, ops, reached_op_count,
                               true))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    if (!dep_fd_materialize_from(&local_route_state, &setup_entry,
                                 &workspace->route_journal,
                                 &workspace->owner_initial, state, state))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    /* Byte-use selection is distinct from setup replacement. A numeric close
     * removes a previous explicit use; a named allocation never adds one just
     * because its backing slot happens to have that numeric identity. Record
     * against the final materialized layout, which remains stable thereafter.
     */
    for (uint32_t op = 0; op < reached_op_count; op++) {
      const dep_fd_op_t *item = ops + op;
      if (item->fd <= SHELL_DEP_FD_MAX)
        dep_mark_owner_route_touched(
            workspace, owner, state, dep_fd_numeric(item->fd),
            item->kind == DEP_FD_OP_CLOSE ? 0 : DEP_FD_ACCESS_BOTH);
      else if (item->kind == DEP_FD_OP_CLOSE) {
        uint32_t allocation =
            dep_allocation_slot(&workspace->route_journal, item);
        if (allocation == SHELL_DEP_FD_NONE)
          return SHELL_DEP_ETRUNC;
        const dep_allocation_t *saved =
            &workspace->route_journal
                 .allocations[allocation - SHELL_DEP_FD_MAX - 1];
        const dep_route_set_t *slots =
            &workspace->route_journal.snapshots[saved->closed_slots - 1];
        for (uint32_t slot = 0; slot < slots->count; slot++)
          if (slots->routes[slot].kind == DEP_ROUTE_ALIAS)
            dep_mark_owner_route_touched(
                workspace, owner, state,
                dep_fd_numeric(slots->routes[slot].value), 0);
      }
    }
    if (graph->nodes[owner].type == SHELL_NODE_GROUP &&
        !dep_redirect_frame_aliases(
            &workspace->group_redirect_frames[node_group[owner]],
            &workspace->route_journal, ops, reached_op_count))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    /* Success continuations retain exec mutations and named allocations,
     * but never numeric command-local redirects. Replay locally first so a
     * persistent allocation may copy a temporary descriptor in this list. */
    if (!dep_route_state_publish(&owner_time_state, &workspace->route_journal,
                                 state, &local_route_state, incoming, ops,
                                 reached_op_count, descriptor_exec,
                                 named_binding))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    uint32_t source_event = dep_owner_event(context, owner);
    if (!dep_fd_finish_owner(
            context, fd_stream, source_event, &workspace->route_journal,
            &flow_baseline, incoming, state, &local_route_state, ops, op_count,
            descriptor_exec, named_binding, mutations,
            descriptor_exec ? &owner_time_state : NULL, &setup_entry))
      return SHELL_DEP_ETRUNC;
    if (source_event >= SHELL_MAX_GROUPS) {
      /* Keep a concrete table for this selected version, not an eager union
       * of success, failure and stopped paths. The next owner selects its
       * actual connector outcomes before materializing their delta. */
      dep_route_state_t continued = dep_fd_point_version(
          &fd_stream->scope[enclosing_group + 1], &selected_state);
      if (!dep_fd_materialize_from(&continued, &selected_state,
                                   &workspace->route_journal, &flow_baseline,
                                   incoming, persistent))
        return SHELL_DEP_ETRUNC;
      *scope_route_state = continued;
    }
    if (graph->nodes[owner].type == SHELL_NODE_GROUP) {
      uint32_t group = node_group[owner];
      /* Preserve the full effective table. The group-tail routes may be
       * copied by a later in-body exec even though their byte-flow edge
       * belongs to the group endpoint, not every child. */
      dep_copy_routes(&workspace->group_snapshot_routes[group], state);
      workspace->group_snapshot_routes_ready[group] = true;
      workspace->group_route_state[group] = local_route_state;
      workspace->group_time_routes[group] =
          dep_time_report_for_fd2(&workspace->group_route_state[group],
                                  &workspace->route_journal, state);
      workspace->group_time_routes_ready[group] = true;
      active_groups[active_group_count++] = group;
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
      uint32_t boundary = target_time_boundary[owner];
      bool needs_shell_report_state =
          boundary != 0 && time_boundaries[boundary - 1].target_shell_state;
      if (needs_shell_report_state) {
        workspace->group_shell_route_state[group] = owner_time_state;
        /* A directly timed foreground brace is not an isolated named-FD
         * scope, so its otherwise-unused scoped slot can hold the shell's
         * pre-tail descriptor view. Descendant isolated groups use their
         * own group indices, and scoped_routes_active[group] deliberately
         * remains false. This avoids another full route table per group. */
        dep_copy_routes(&workspace->scoped_routes[group], incoming);
        workspace->group_shell_time_routes[group] = dep_time_report_for_fd2(
            &workspace->group_shell_route_state[group],
            &workspace->route_journal, &workspace->scoped_routes[group]);
        workspace->group_shell_time_routes_ready[group] = true;
      }
    }
    if (!descriptor_exec && graph->nodes[owner].type == SHELL_NODE_CMD) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
      if (target_time_boundary[owner] != 0 &&
          !workspace->time_reports[owner].ready)
        workspace->time_reports[owner] = dep_time_report_for_fd2(
            &incoming_time_context, &workspace->route_journal, incoming);
    }
    /* When a directly timed descriptor-only exec is itself a conditional-list
     * member, its mutation is not safe to publish into the unconditional shell
     * table. The report nevertheless follows that mutation on every path where
     * this timed pipeline executes, so retain its completed local table. */
    if (descriptor_exec) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
      uint32_t boundary = target_time_boundary[owner];
      if (boundary != 0 &&
          (!one_shot_scope || time_boundaries[boundary - 1].target_scope) &&
          !workspace->time_reports[owner].ready) {
        dep_route_set_t reports = dep_time_report_for_fd2(
            &owner_time_state, &workspace->route_journal, state);
        workspace->time_reports[owner] = reports;
      }
    }

    workspace->owner_route_state[owner] = local_route_state;

    /* Mark this owner's direct document redirects from its indexed syntax
     * edges. Searching the completed FD table here cost O(owner_count * fd
     * count), even though every candidate document was already known. */
    for (uint32_t edge = owner_edges->io_head[owner]; edge != UINT32_MAX;
         edge = owner_edges->io_next[edge]) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
      const shell_dep_edge_t *original = &original_edges[edge];
      bool input = original->type == SHELL_EDGE_READ;
      dep_fd_ref_t fd =
          dep_fd_numeric(input ? original->target_fd : original->source_fd);
      dep_fd_route_t route = dep_route_get(
          state, fd, input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE);
      if (route.kind == DEP_ROUTE_DOC && route.value == edge)
        owner_edges->effective_document[edge] = true;
    }

    if ((descriptor_exec || named_binding) && !one_shot_scope) {
      dep_route_set_t *scope_reports =
          publishes_to_group ? &workspace->group_time_routes[enclosing_group]
          : named_scope >= 0 ? &workspace->scoped_time_routes[named_scope]
                             : &workspace->persistent_time_routes;
      *scope_reports = dep_time_report_for_fd2(
          scope_route_state, &workspace->route_journal, persistent);
    }
  }
  /* Trailing collapsed stages publish implicit variable effects as well as
   * their list outcomes before a containing scope completes. */
  while (fd_event_cursor < control_count) {
    uint32_t event = control_events[fd_event_cursor].owner;
    uint32_t start = control_events[fd_event_cursor++].start;
    while (active_group_count &&
           pipeline->group_tail[active_groups[active_group_count - 1]]
                   .redirect_end <= start) {
      uint32_t completed = active_groups[--active_group_count];
      if (!dep_complete_route_group(workspace, context, &persistent_routes,
                                    &flow_baseline, completed))
        return SHELL_DEP_ETRUNC;
    }
    dep_route_state_t selected;
    if (!dep_fd_begin(context, fd_stream, event, &workspace->route_journal,
                      &flow_baseline, &selected))
      return SHELL_DEP_ETRUNC;
    if (!dep_fd_finish_collapsed(context, fd_stream, event,
                                 &workspace->route_journal, &flow_baseline,
                                 &selected))
      return SHELL_DEP_ETRUNC;
  }
  while (active_group_count) {
    uint32_t completed = active_groups[--active_group_count];
    if (!dep_complete_route_group(workspace, context, &persistent_routes,
                                  &flow_baseline, completed))
      return SHELL_DEP_ETRUNC;
  }

  dep_capture_due_time_reports(workspace, time_boundaries, time_boundary_count,
                               &time_boundary_cursor, UINT32_MAX);

  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!local_owner[owner] || graph->nodes[owner].type != SHELL_NODE_CMD)
      continue;
    shell_dep_cmd_t *command = &graph->nodes[owner].cmd;
    command->pipe_stdin_source = UINT32_MAX;
    command->pipe_stdin_target = UINT32_MAX;
    command->pipe_stdout_source = UINT32_MAX;
    command->pipe_stdout_target = UINT32_MAX;
    const dep_owner_routes_t *state = &routes[owner];
    dep_fd_route_t input =
        dep_route_get(state, dep_fd_numeric(0), DEP_FD_ACCESS_READ);
    dep_fd_route_t output =
        dep_route_get(state, dep_fd_numeric(1), DEP_FD_ACCESS_WRITE);
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
    const shell_dep_edge_t *original = &original_edges[edge];
    /* Named FILE opens are setup effects, not final byte routes. Retain only
     * the operations reached before this owner's failed redirect. Earlier
     * successful allocations survive even if a later operation fails. */
    if (original->type == SHELL_EDGE_FD_OPEN &&
        ((original->source_fd == SHELL_DEP_FD_NAMED &&
          local_owner[original->from] &&
          graph->nodes[original->to].type == SHELL_NODE_DOC) ||
         (original->target_fd == SHELL_DEP_FD_NAMED &&
          local_owner[original->to] &&
          graph->nodes[original->from].type == SHELL_NODE_DOC)) &&
        !reached_named_opens[edge])
      continue;
    bool effect = original->type == SHELL_EDGE_READ ||
                  original->type == SHELL_EDGE_WRITE ||
                  original->type == SHELL_EDGE_APPEND ||
                  original->type == SHELL_EDGE_ENV ||
                  original->type == SHELL_EDGE_SUBST ||
                  original->type == SHELL_EDGE_FD_OPEN ||
                  original->type == SHELL_EDGE_FD_CLOSE ||
                  original->type == SHELL_EDGE_CWD;
    if (effect && ((local_owner[original->from] &&
                    control_execution[original->from] == DEP_EXECUTION_NEVER) ||
                   (local_owner[original->to] &&
                    control_execution[original->to] == DEP_EXECUTION_NEVER)))
      continue;
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
        owner >= graph->node_count || !resolved_owner[owner] ||
        control_execution[owner] == DEP_EXECUTION_NEVER)
      continue;
    const shell_dep_edge_t *original = &original_edges[edge];
    uint32_t document =
        original->type == SHELL_EDGE_READ ? original->from : original->to;
    if (document >= graph->node_count ||
        graph->nodes[document].type != SHELL_NODE_DOC ||
        graph->nodes[document].doc.kind != SHELL_DOC_FILE)
      continue;

    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    const char *spelling = dep_document_source(&graph->nodes[document]);
    if (spelling &&
        (uint32_t)(spelling - cmd) >= context->owner_setup_stop[owner])
      continue;
    if (context->owner_setup_stop[owner] == UINT32_MAX &&
        owner_edges->effective_document[edge] && !persistent_setup_edges[edge])
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
    if (!resolved_owner[owner] ||
        control_execution[owner] == DEP_EXECUTION_NEVER ||
        context->owner_setup_stop[owner] != UINT32_MAX)
      continue;
    /* Empty timing targets only anchor structural edges. TIME owns the
     * report flow. A persistent `exec` likewise changes descriptor state
     * without itself consuming or producing bytes through those routes. */
    if (empty_timing_owner[owner] ||
        (graph->nodes[owner].type == SHELL_NODE_CMD &&
         dep_owner_exec(context, owner)->kind == DEP_EXEC_DESCRIPTORS))
      continue;
    const dep_owner_routes_t *state = &routes[owner];
    for (uint32_t i = 0; i < state->fd_count; i++) {
      if (state->fd[i].fd.value > SHELL_DEP_FD_MAX)
        continue;
      for (uint32_t access = 0; access < 2; access++) {
        dep_route_state_t owner_state = workspace->owner_route_state[owner];
        dep_fd_access_t direction =
            access == 0 ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE;
        dep_route_set_t alternatives =
            dep_route_state_get_access(&owner_state, &workspace->route_journal,
                                       state, state->fd[i].fd, direction);
        if (alternatives.truncated)
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        for (uint32_t alternative = 0; alternative < alternatives.count;
             alternative++) {
          dep_fd_route_t route = alternatives.routes[alternative];
          if (route.kind == DEP_ROUTE_CAPTURE) {
            if ((state->fd[i].fd.value <= 2 ||
                 (dep_owner_route_touched(workspace, owner, i) & direction) !=
                     0) &&
                !dep_record_stream_use(
                    streams->capture_uses, &streams->capture_use_count,
                    streams->capture_index, &streams->capture_root, owner,
                    state->fd[i].fd.value, direction, route.value))
              graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            continue;
          }
          if (route.kind == DEP_ROUTE_IMPORTED) {
            /* Standard streams are implicit uses. Auxiliary descriptors only
             * transfer bytes when this owner explicitly redirects them. Do
             * this after replay so replaced or closed aliases emit no flow. */
            if ((state->fd[i].fd.value <= 2 ||
                 (dep_owner_route_touched(workspace, owner, i) & direction) !=
                     0) &&
                !dep_record_fd_import_use(streams, owner, state->fd[i].fd.value,
                                          direction, route.value))
              graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            continue;
          }
          if (route.kind != DEP_ROUTE_DOC && route.kind != DEP_ROUTE_DYNAMIC)
            continue;
          /* Allocation backing slots are descriptor state, not implicit byte
           * uses. As with imported/capture routes, only standard streams or
           * explicitly redirected auxiliary descriptors transfer bytes. */
          if (state->fd[i].fd.value > 2 &&
              (dep_owner_route_touched(workspace, owner, i) & direction) == 0)
            continue;
          uint32_t original_edge = route.value;
          if (original_edge >= original_edge_count) {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            continue;
          }
          const shell_dep_edge_t *original = &original_edges[original_edge];
          if ((dep_owner_route_touched(workspace, owner, i) & direction) == 0 &&
              dep_route_owned_by_enclosing_group(graph, fast, pipeline,
                                                 node_range, node_group, owner,
                                                 original))
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
          if (route.kind == DEP_ROUTE_DOC &&
              (original->type == SHELL_EDGE_READ ||
               (original->type == SHELL_EDGE_FD_OPEN &&
                original->target_fd == SHELL_DEP_FD_NAMED))) {
            dep_add_resolved_edge_refs(graph, max_edges, original->from, owner,
                                       SHELL_EDGE_READ,
                                       dep_fd_numeric(SHELL_DEP_FD_NONE),
                                       state->fd[i].fd, resolved_flags);
          } else if (route.kind == DEP_ROUTE_DOC) {
            shell_dep_edge_type_t type = original->type;
            if (type == SHELL_EDGE_FD_OPEN) {
              type =
                  original->source_fd == SHELL_DEP_FD_NAMED
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
  }

  workspace->time_pipe_target_count = 0;
  for (uint32_t pipe = 0; pipe < pipe_count; pipe++) {
    const shell_dep_edge_t *original = &pipes[pipe];
    dep_stream_use_t *sources = workspace->import_join.endpoints;
    dep_stream_use_t *targets = workspace->import_join.pipe_targets;
    dep_index_node_t *source_index = workspace->import_join.endpoint_index;
    dep_index_node_t *target_index = workspace->import_join.pipe_target_index;
    uint32_t source_root = 0, target_root = 0;
    uint32_t source_count = 0, target_count = 0;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
         access <<= 1) {
      uint32_t owner =
          access == DEP_FD_ACCESS_READ ? original->to : original->from;
      if (context->owner_setup_stop[owner] != UINT32_MAX)
        continue;
      dep_stream_use_t *uses = access == DEP_FD_ACCESS_READ ? targets : sources;
      uint32_t *count =
          access == DEP_FD_ACCESS_READ ? &target_count : &source_count;
      dep_index_node_t *index =
          access == DEP_FD_ACCESS_READ ? target_index : source_index;
      uint32_t *root =
          access == DEP_FD_ACCESS_READ ? &target_root : &source_root;
      const dep_owner_routes_t *state = &routes[owner];
      dep_route_state_t alternatives = workspace->owner_route_state[owner];
      for (uint32_t fd = 0; fd < state->fd_count; fd++) {
        if (empty_timing_owner[owner] ||
            state->fd[fd].fd.value > SHELL_DEP_FD_MAX ||
            (state->fd[fd].fd.value > 2 &&
             (dep_owner_route_touched(workspace, owner, fd) & access) == 0))
          continue;
        dep_route_set_t choices = dep_route_state_get_access(
            &alternatives, &workspace->route_journal, state, state->fd[fd].fd,
            (dep_fd_access_t)access);
        for (uint32_t choice = 0; choice < choices.count; choice++)
          if (choices.routes[choice].kind == DEP_ROUTE_PIPE &&
              choices.routes[choice].value == pipe &&
              !dep_record_stream_use(uses, count, index, root, owner,
                                     state->fd[fd].fd.value,
                                     (dep_fd_access_t)access, pipe))
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      }
      if (!dep_collect_pipe_uses(streams, streams->pipe_root, owner,
                                 (dep_fd_access_t)access, pipe, uses, count,
                                 index, root))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    }
    workspace->time_pipe_start[pipe] = workspace->time_pipe_target_count;
    workspace->time_pipe_count[pipe] = 0;
    for (uint32_t in = 0; in < target_count; in++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_PIPE_TARGETS);
      if (workspace->time_pipe_target_count == SHELL_DEP_MAX_EDGES) {
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        break;
      }
      workspace->time_pipe_targets[workspace->time_pipe_target_count++] =
          targets[in];
      workspace->time_pipe_count[pipe]++;
    }
    uint32_t terminal = UINT32_MAX;
    for (uint32_t out = 0; out < source_count; out++) {
      bool complete = true;
      if (target_count == 0) {
        if (terminal == UINT32_MAX) {
          if (graph->node_count >= max_nodes) {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            if (graph->nodes[sources[out].owner].type == SHELL_NODE_TIME)
              graph->nodes[sources[out].owner].time.report_route_flags |=
                  SHELL_TIME_REPORT_ROUTE_UNKNOWN;
            continue;
          }
          terminal = graph->node_count++;
          graph->nodes[terminal].type = SHELL_NODE_ENDPOINT;
          graph->nodes[terminal].endpoint.reserved = DEP_ENDPOINT_TERMINAL_PIPE;
          if (workspace->time_pipe_target_count < SHELL_DEP_MAX_EDGES) {
            workspace->time_pipe_targets[workspace->time_pipe_target_count++] =
                (dep_stream_use_t){terminal, 0, pipe, DEP_FD_ACCESS_READ};
            workspace->time_pipe_count[pipe]++;
          } else {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
          }
        }
        complete = dep_add_resolved_edge_refs(
            graph, max_edges, sources[out].owner, terminal, SHELL_EDGE_PIPE,
            dep_fd_numeric(sources[out].fd), dep_fd_numeric(0),
            SHELL_DEP_EDGE_FLAG_NONE);
      } else {
        for (uint32_t in = 0; in < target_count; in++)
          complete =
              dep_add_resolved_edge_refs(
                  graph, max_edges, sources[out].owner, targets[in].owner,
                  SHELL_EDGE_PIPE, dep_fd_numeric(sources[out].fd),
                  dep_fd_numeric(targets[in].fd), SHELL_DEP_EDGE_FLAG_NONE) &&
              complete;
      }
      if (!complete && graph->nodes[sources[out].owner].type == SHELL_NODE_TIME)
        graph->nodes[sources[out].owner].time.report_route_flags |=
            SHELL_TIME_REPORT_ROUTE_UNKNOWN;
    }
  }

  /* Imported timing routes may fan out to several pipe aliases. Summaries
   * count retained edges and deferred capture/import uses, never promises. */
  uint32_t retained_reports[SHELL_DEP_MAX_NODES] = {0};
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (graph->nodes[item->from].type == SHELL_NODE_TIME &&
        item->type != SHELL_EDGE_TIME)
      retained_reports[item->from]++;
  }
  for (uint32_t use = 0; use < streams->capture_use_count; use++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
    retained_reports[streams->capture_uses[use].owner]++;
  }
  for (uint32_t use = 0; use < streams->fd_import_use_count; use++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
    retained_reports[streams->fd_import_uses[use].owner]++;
  }
  for (uint32_t timer = 0; timer < graph->node_count; timer++) {
    if (graph->nodes[timer].type != SHELL_NODE_TIME)
      continue;
    uint32_t retained = retained_reports[timer];
    if (retained == 0)
      graph->nodes[timer].time.report_route_flags &=
          ~SHELL_TIME_REPORT_ROUTE_GRAPH;
    dep_finalize_time_report_route(graph, timer, retained);
  }

  workspace->pipe_count = pipe_count;

  dep_mark_transient_documents(graph, original_edges, original_edge_count,
                               &fd_stream->scope[0], &workspace->route_journal,
                               &flow_baseline, workspace->named_setup_documents,
                               workspace->live_named_documents);
  streams->status = fd_stream->scope[0].mask;
  /* TIME nodes consume the just-resolved descriptor snapshots. Add their
   * report flow before endpoint pruning so concrete endpoint indices and
   * imported-route owners are compacted together with the rest of the graph. */
  if (!dep_add_pipeline_time_nodes(graph, cmd, cmd_len, fast, pipeline,
                                   range_node, group_node, max_nodes, max_edges,
                                   workspace, streams))
    return SHELL_DEP_EPARSE;
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
  uint32_t nodes[SHELL_DEP_MAX_EDGES];
  uint32_t fds[SHELL_DEP_MAX_EDGES];
  uint32_t count;
} dep_endpoint_list_t;

static shell_dep_error_t shell_dep_graph_parse_impl(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    bool initial_cwd_known, bool initial_cwd_absolute,
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams, const dep_fd_imports_t *imports,
    bool effects_active, const shell_dep_word_resolver_t *resolver);

/* Capture membership is a resource relation, not a guess based on a command's
 * stdout role. Nested producers can read an enclosing process stream while
 * writing into a different command-word capture. Preserve every final alias
 * and alternative; coalesce structural members only when their group exposes
 * that same descriptor of this capture resource. */
static SHELL_NONNULL(1,
                     3) int dep_capture_resource_compare(const void *context,
                                                         uint32_t index,
                                                         const void *pending) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  const dep_stream_use_t *uses = context;
  const dep_stream_use_t *key = pending;
  const dep_stream_use_t *use = &uses[index];
  if (use->anchor != key->anchor)
    return use->anchor < key->anchor ? -1 : 1;
  if (use->access != key->access)
    return use->access < key->access ? -1 : 1;
  if (use->fd != key->fd)
    return use->fd < key->fd ? -1 : 1;
  return 0;
}

static SHELL_NONNULL(1, 2, 4) void dep_collect_capture_endpoints(
    const shell_dep_graph_t *graph, const dep_subgraph_streams_t *streams,
    dep_fd_access_t access, dep_endpoint_list_t *endpoints) {
  endpoints->count = 0;
  dep_import_join_t *scratch = streams->join;
  for (uint32_t i = 0; i < graph->node_count; i++) {
    scratch->group_parent[i] = UINT32_MAX;
    scratch->capture_first_child[i] = UINT32_MAX;
    scratch->capture_next_child[i] = UINT32_MAX;
    scratch->capture_first_use[i] = UINT32_MAX;
  }
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type == SHELL_EDGE_GROUP) {
      scratch->group_parent[edge->to] = edge->from;
      scratch->capture_next_child[edge->to] =
          scratch->capture_first_child[edge->from];
      scratch->capture_first_child[edge->from] = edge->to;
    }
  }
  uint32_t resource_root = 0;
  for (uint32_t i = 0; i < streams->capture_use_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
    const dep_stream_use_t *use = &streams->capture_uses[i];
    if (use->access != access)
      continue;
    uint32_t match = 0;
    resource_root = dep_index_insert(
        scratch->capture_resource_index, resource_root, i + 1,
        streams->capture_use_count, dep_capture_resource_compare,
        streams->capture_uses, use, &match);
    scratch->capture_resource[i] = match - 1;
    scratch->capture_outermost[match - 1] = UINT32_MAX;
    scratch->capture_next_use[i] = scratch->capture_first_use[use->owner];
    scratch->capture_first_use[use->owner] = i;
  }
  /* Maintain the outermost exposure of each resource during one traversal of
   * the structural forest. A leaf never searches its ancestors. TIME nodes
   * without GROUP membership remain roots and retain their own endpoint. */
  for (uint32_t root_node = 0; root_node < graph->node_count; root_node++) {
    if (scratch->group_parent[root_node] != UINT32_MAX)
      continue;
    uint32_t node = root_node;
    for (;;) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
      bool group = graph->nodes[node].type == SHELL_NODE_GROUP;
      for (uint32_t i = scratch->capture_first_use[node]; i != UINT32_MAX;
           i = scratch->capture_next_use[i]) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
        uint32_t resource = scratch->capture_resource[i];
        if (group && scratch->capture_outermost[resource] == UINT32_MAX)
          scratch->capture_outermost[resource] = node;
        scratch->capture_endpoint[i] =
            scratch->capture_outermost[resource] == UINT32_MAX
                ? node
                : scratch->capture_outermost[resource];
      }
      if (scratch->capture_first_child[node] != UINT32_MAX) {
        node = scratch->capture_first_child[node];
        continue;
      }
      for (;;) {
        for (uint32_t i = scratch->capture_first_use[node]; i != UINT32_MAX;
             i = scratch->capture_next_use[i]) {
          DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
          uint32_t resource = scratch->capture_resource[i];
          if (scratch->capture_outermost[resource] == node)
            scratch->capture_outermost[resource] = UINT32_MAX;
        }
        if (node == root_node)
          break;
        if (scratch->capture_next_child[node] != UINT32_MAX) {
          node = scratch->capture_next_child[node];
          break;
        }
        node = scratch->group_parent[node];
      }
      if (node == root_node)
        break;
    }
  }
  uint32_t root = 0, count = 0;
  /* Keep the original use order when rendering the reconciled endpoints. */
  for (uint32_t i = 0; i < streams->capture_use_count; i++) {
    const dep_stream_use_t *use = &streams->capture_uses[i];
    if (use->access != access ||
        graph->nodes[use->owner].type == SHELL_NODE_GROUP)
      continue;
    dep_record_stream_use(scratch->endpoints, &count, scratch->endpoint_index,
                          &root, scratch->capture_endpoint[i], use->fd, access,
                          use->anchor);
  }
  for (uint32_t i = 0; i < count; i++) {
    endpoints->nodes[i] = scratch->endpoints[i].owner;
    endpoints->fds[i] = scratch->endpoints[i].fd;
  }
  endpoints->count = count;
}

static SHELL_NONNULL(1) void dep_add_edge(shell_dep_graph_t *graph,
                                          uint32_t from, uint32_t to,
                                          shell_dep_edge_type_t type,
                                          uint32_t source_fd,
                                          uint32_t target_fd) {
  shell_dep_edge_t *edge = &graph->edges[graph->edge_count++];
  dep_init_edge(edge, from, to, type, SHELL_DIR_FORWARD, source_fd, target_fd);
}

static SHELL_NONNULL(1) void dep_add_subst_edge(shell_dep_graph_t *graph,
                                                uint32_t from, uint32_t to,
                                                uint32_t source_fd,
                                                uint32_t target_fd,
                                                dep_subst_kind_t kind) {
  dep_add_edge(graph, from, to, SHELL_EDGE_SUBST, source_fd, target_fd);
  graph->edges[graph->edge_count - 1].flags =
      kind == DEP_SUBST_SHELL_WORD
          ? SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD
          : (kind == DEP_SUBST_DYNAMIC_NAME
                 ? SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME
                 : SHELL_DEP_EDGE_FLAG_NONE);
}

static SHELL_NONNULL(1, 2, 5, 6) void dep_append_subgraph(
    shell_dep_graph_t *out, const shell_dep_graph_t *subgraph,
    uint32_t node_offset, uint32_t cwd_offset_shift,
    dep_subgraph_streams_t *out_streams,
    const dep_subgraph_streams_t *subgraph_streams) {
  memcpy(out->cwd_buf.data + out->cwd_buf.len, subgraph->cwd_buf.data,
         subgraph->cwd_buf.len);
  out->cwd_buf.len += subgraph->cwd_buf.len;
  for (uint32_t i = 0; i < subgraph->node_count; i++) {
    out_streams->unresolved_paths[node_offset + i] =
        subgraph_streams->unresolved_paths[i];
    out->nodes[out->node_count] = subgraph->nodes[i];
    if (out->nodes[out->node_count].type == SHELL_NODE_CMD) {
      out->nodes[out->node_count].cmd.cwd_offset += cwd_offset_shift;
      if (out->nodes[out->node_count].cmd.pipeline_time_id != 0)
        out->nodes[out->node_count].cmd.pipeline_time_id += node_offset;
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
    else if (out->nodes[out->node_count].type == SHELL_NODE_GROUP) {
      if (out->nodes[out->node_count].group.pipeline_time_id != 0)
        out->nodes[out->node_count].group.pipeline_time_id += node_offset;
      if (out->nodes[out->node_count].group.parent != UINT32_MAX)
        out->nodes[out->node_count].group.parent += node_offset;
    }
    out->node_count++;
  }
  for (uint32_t i = 0; i < subgraph->edge_count; i++) {
    shell_dep_edge_t *copy = &out->edges[out->edge_count++];
    *copy = subgraph->edges[i];
    copy->from += node_offset;
    copy->to += node_offset;
  }
}

/* Import edges are part of the recursive join's capacity contract, not a
 * second best-effort append after copying child topology. In particular a
 * TIME node must never be retained with a report summary whose imported flow
 * was dropped for lack of space. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_fd_import_edge_count(
    const shell_dep_graph_t *out, const dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *subgraph, const dep_subgraph_streams_t *streams,
    uint32_t *count) {
  *count = 0;
  if (streams->fd_import_use_count > SHELL_DEP_MAX_EDGES ||
      out_streams->fd_import_use_count > SHELL_DEP_MAX_EDGES ||
      out_streams->capture_use_count > SHELL_DEP_MAX_EDGES ||
      out_streams->pipe_use_count > SHELL_DEP_MAX_EDGES)
    return false;
  /* A copied child has fresh owner indices. Each distinct use therefore
   * consumes a new metadata slot, even when it needs no public edge yet.
   * Stage imported identities as well, so a failed join never leaves copied
   * TIME nodes promising a capture or pipe route that was not retained. */
  dep_import_join_t *plan = out_streams->join;
  plan->imports = out_streams->fd_imports;
  uint32_t captures = 0, pipes = 0, foreign = 0;
  for (uint32_t i = 0; i < streams->fd_import_use_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
    const dep_fd_import_use_t *use = &streams->fd_import_uses[i];
    if (use->import_index >= streams->fd_imports.count ||
        use->owner >= subgraph->node_count)
      return false;
    const dep_fd_import_t *import =
        &streams->fd_imports.entries[use->import_index];
    if (import->origin != out) {
      if (!import->origin)
        return false;
      int32_t index = dep_merge_fd_import(&plan->imports, import);
      if (index < 0)
        return false;
      plan->import_indices[i] = (uint32_t)index;
      foreign++;
      continue;
    }
    if (import->route.kind == DEP_ROUTE_CAPTURE) {
      captures++;
      continue;
    }
    if (import->route.kind == DEP_ROUTE_PIPE_INPUT ||
        import->route.kind == DEP_ROUTE_PIPE_OUTPUT) {
      if (import->route.value >= out->node_count ||
          !dep_is_execution_node(out, import->route.value))
        return false;
      pipes++;
      continue;
    }
    if (import->route.kind != DEP_ROUTE_IMPORTED ||
        import->route.value >= out->edge_count)
      return false;
    (*count)++;
  }
  return captures <= SHELL_DEP_MAX_EDGES - out_streams->capture_use_count &&
         pipes <= SHELL_DEP_MAX_EDGES - out_streams->pipe_use_count &&
         foreign <= SHELL_DEP_MAX_EDGES - out_streams->fd_import_use_count;
}

/* Resolve child uses of a parent-owned descriptor after the child nodes have
 * been appended. The child parser intentionally keeps no cloned DOC or
 * ENDPOINT node: this join adds the actual READ/WRITE/SUBST edge to the
 * original parent resource. */
static SHELL_NONNULL(1, 4, 5) bool dep_materialize_fd_import_uses(
    shell_dep_graph_t *out, uint32_t max_edges, uint32_t node_offset,
    dep_subgraph_streams_t *out_streams,
    const dep_subgraph_streams_t *subgraph_streams) {
  /* Capacity preflight has already interned every foreign identity. Commit
   * that plan once; emission consumes its IDs without another identity search.
   */
  out_streams->fd_imports = out_streams->join->imports;
  for (uint32_t i = 0; i < subgraph_streams->fd_import_use_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
    const dep_fd_import_use_t *use = &subgraph_streams->fd_import_uses[i];
    if (use->import_index >= subgraph_streams->fd_imports.count ||
        use->owner >= SHELL_DEP_MAX_NODES)
      return false;
    const dep_fd_import_t *import =
        &subgraph_streams->fd_imports.entries[use->import_index];
    dep_fd_route_t route = import->route;
    const shell_dep_graph_t *origin = import->origin;
    if (node_offset > UINT32_MAX - use->owner)
      return false;
    if (origin != out) {
      uint32_t import_index = out_streams->join->import_indices[i];
      if (!dep_record_fd_import_use(out_streams, node_offset + use->owner,
                                    use->fd, (dep_fd_access_t)use->access,
                                    import_index))
        return false;
      continue;
    }
    uint32_t child = node_offset + use->owner;
    if (child >= out->node_count)
      return false;
    if (route.kind == DEP_ROUTE_CAPTURE) {
      if (!dep_record_stream_use(
              out_streams->capture_uses, &out_streams->capture_use_count,
              out_streams->capture_index, &out_streams->capture_root, child,
              use->fd, (dep_fd_access_t)use->access, route.value))
        return false;
      continue;
    }
    if (route.kind == DEP_ROUTE_PIPE_INPUT ||
        route.kind == DEP_ROUTE_PIPE_OUTPUT) {
      if (!dep_record_stream_use(
              out_streams->pipe_uses, &out_streams->pipe_use_count,
              out_streams->pipe_index, &out_streams->pipe_root, child, use->fd,
              (dep_fd_access_t)use->access, route.value))
        return false;
      continue;
    }
    if (route.kind != DEP_ROUTE_IMPORTED || route.value >= out->edge_count)
      return false;
    const shell_dep_edge_t *original = &out->edges[route.value];
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
static SHELL_NONNULL(1, 5, 6, 7) bool dep_append_disconnected_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *subgraph,
    const dep_subgraph_streams_t *subgraph_streams) {
  uint32_t import_edges = 0;
  if (!dep_fd_import_edge_count(out, out_streams, subgraph, subgraph_streams,
                                &import_edges) ||
      subgraph->node_count > max_nodes - out->node_count ||
      subgraph->edge_count > max_edges - out->edge_count ||
      import_edges > max_edges - out->edge_count - subgraph->edge_count ||
      subgraph->cwd_buf.len > effective_cwd_buf_size - out->cwd_buf.len)
    return false;
  uint32_t node_offset = out->node_count;
  uint32_t cwd_offset_shift = (uint32_t)out->cwd_buf.len;
  dep_append_subgraph(out, subgraph, node_offset, cwd_offset_shift, out_streams,
                      subgraph_streams);
  return dep_materialize_fd_import_uses(out, max_edges, node_offset,
                                        out_streams, subgraph_streams);
}

/* Copy one parsed substitution and wire its actual stream topology into the
 * parent graph. Word and input-process substitutions carry nested output to
 * the parent; output-process substitutions carry the parent's redirected fd
 * to nested stdin. A collector is only needed when one direct SUBST edge
 * would conceal several producers or descriptor routing. A process redirect
 * installs its pipe even without an exposed child stream. Preserve that pipe
 * so it replaces the previous descriptor route. `route_edge`, when supplied,
 * receives the installed parent-facing edge directly, without rediscovery. */
static SHELL_NONNULL(1, 5, 6, 7) bool dep_connect_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *subgraph,
    const dep_subgraph_streams_t *subgraph_streams, uint32_t consumer_node,
    dep_subst_kind_t kind, uint32_t producer_fd,
    const dep_fd_ref_t *named_setup_fd, uint32_t *route_edge) {
  dep_endpoint_list_t endpoints;
  dep_collect_capture_endpoints(subgraph, subgraph_streams,
                                kind == DEP_SUBST_PROCESS_OUTPUT
                                    ? DEP_FD_ACCESS_READ
                                    : DEP_FD_ACCESS_WRITE,
                                &endpoints);

  bool needs_collector =
      kind == DEP_SUBST_PROCESS_OUTPUT || endpoints.count > 1;
  bool retain_unconnected =
      endpoints.count == 0 &&
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
    extra_edges = 1; /* descriptor installation for the retained raw pipe */
  }

  uint32_t import_edges = 0;
  if (!dep_fd_import_edge_count(out, out_streams, subgraph, subgraph_streams,
                                &import_edges) ||
      subgraph->node_count > max_nodes - out->node_count ||
      subgraph->edge_count > max_edges - out->edge_count ||
      extra_nodes > max_nodes - out->node_count - subgraph->node_count ||
      extra_edges > max_edges - out->edge_count - subgraph->edge_count ||
      import_edges >
          max_edges - out->edge_count - subgraph->edge_count - extra_edges ||
      subgraph->cwd_buf.len > effective_cwd_buf_size - out->cwd_buf.len)
    return false;

  uint32_t node_offset = out->node_count;
  uint32_t cwd_offset_shift = (uint32_t)out->cwd_buf.len;
  dep_append_subgraph(out, subgraph, node_offset, cwd_offset_shift, out_streams,
                      subgraph_streams);
  if (!dep_materialize_fd_import_uses(out, max_edges, node_offset, out_streams,
                                      subgraph_streams))
    return false;
  if (endpoints.count == 0) {
    if (!retain_unconnected)
      return true;
    uint32_t endpoint = out->node_count++;
    out->nodes[endpoint].type = SHELL_NODE_ENDPOINT;
    out->nodes[endpoint].endpoint.reserved = DEP_ENDPOINT_PROCESS_PIPE;
    dep_fd_ref_t fd =
        named_setup_fd ? *named_setup_fd : dep_fd_numeric(producer_fd);
    if (route_edge)
      *route_edge = out->edge_count;
    if (kind == DEP_SUBST_PROCESS_INPUT) {
      return dep_add_resolved_edge_refs(
          out, max_edges, endpoint, consumer_node,
          named_setup_fd ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_SUBST,
          dep_fd_numeric(SHELL_DEP_FD_NONE), fd, SHELL_DEP_EDGE_FLAG_NONE);
    }
    return dep_add_resolved_edge_refs(
        out, max_edges, consumer_node, endpoint,
        named_setup_fd ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_WRITE, fd,
        dep_fd_numeric(SHELL_DEP_FD_NONE), SHELL_DEP_EDGE_FLAG_NONE);
  }

  if (!needs_collector) {
    uint32_t producer = node_offset + endpoints.nodes[0];
    uint32_t source_fd = endpoints.fds[0];
    if (route_edge)
      *route_edge = out->edge_count;
    dep_add_subst_edge(out, producer, consumer_node, source_fd,
                       kind == DEP_SUBST_PROCESS_INPUT ? producer_fd
                                                       : SHELL_DEP_FD_NONE,
                       kind);
    return true;
  }

  uint32_t collector = out->node_count++;
  out->nodes[collector].type = SHELL_NODE_ENDPOINT;
  out->nodes[collector].endpoint.reserved = 0;
  if (kind == DEP_SUBST_PROCESS_OUTPUT) {
    if (route_edge)
      *route_edge = out->edge_count;
    dep_add_edge(out, consumer_node, collector, SHELL_EDGE_WRITE, producer_fd,
                 SHELL_DEP_FD_NONE);
    for (uint32_t i = 0; i < endpoints.count; i++)
      dep_add_subst_edge(out, collector, node_offset + endpoints.nodes[i],
                         SHELL_DEP_FD_NONE, endpoints.fds[i],
                         DEP_SUBST_PROCESS_OUTPUT);
  } else {
    for (uint32_t i = 0; i < endpoints.count; i++) {
      uint32_t producer = node_offset + endpoints.nodes[i];
      uint32_t source_fd = endpoints.fds[i];
      dep_add_edge(out, producer, collector, SHELL_EDGE_WRITE, source_fd,
                   SHELL_DEP_FD_NONE);
    }
    if (route_edge)
      *route_edge = out->edge_count;
    dep_add_subst_edge(out, collector, consumer_node, SHELL_DEP_FD_NONE,
                       kind == DEP_SUBST_PROCESS_INPUT ? producer_fd
                                                       : SHELL_DEP_FD_NONE,
                       kind);
  }
  return true;
}

static SHELL_NONNULL(1) void dep_record_process_substitution_route(
    dep_process_route_map_t *routes, uint32_t edge, uint32_t owner,
    uint32_t position, bool input, dep_fd_ref_t fd) {
  /* Each recorded installation owns a graph edge, so the bounded edge
   * capacity also guarantees journal capacity. */
  uint32_t slot = ++routes->count;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
  routes->entries[slot - 1] = (dep_process_route_t){
      position, edge, fd, 0, input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE};
  if (routes->last[owner] != 0)
    routes->entries[routes->last[owner] - 1].next = slot;
  else
    routes->first[owner] = slot;
  routes->last[owner] = slot;
}

/* Cross-direction and read/write opens need resource identity independently
 * of the child's capture direction. Both peers can read the same pipe or
 * write the same pipe; neither case is a transfer between those peers.
 * The caller supplies a parsed child, its completed stream metadata, and
 * three UINT32_MAX parent-edge slots (read, write, combined stderr).
 * Reserve the entire join and installation before changing the graph. */
static SHELL_NONNULL(1, 5, 6, 7, 10, 11) bool dep_install_process_pipe(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t cwd_capacity, dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *child, const dep_subgraph_streams_t *streams,
    uint32_t owner, bool child_writes, const dep_fd_ref_t *fd,
    uint32_t parent_edges[3], dep_fd_access_t access, bool combined) {
  dep_endpoint_list_t endpoints;
  dep_collect_capture_endpoints(
      child, streams, child_writes ? DEP_FD_ACCESS_WRITE : DEP_FD_ACCESS_READ,
      &endpoints);
  uint32_t parent_count = (access & DEP_FD_ACCESS_READ ? 1u : 0u) +
                          (access & DEP_FD_ACCESS_WRITE ? 1u : 0u) +
                          (combined ? 1u : 0u);
  uint32_t import_edges = 0;
  if (!dep_fd_import_edge_count(out, out_streams, child, streams,
                                &import_edges) ||
      child->node_count + 1 > max_nodes - out->node_count ||
      child->edge_count > max_edges - out->edge_count ||
      endpoints.count + parent_count >
          max_edges - out->edge_count - child->edge_count ||
      import_edges > max_edges - out->edge_count - child->edge_count -
                         endpoints.count - parent_count ||
      child->cwd_buf.len > cwd_capacity - out->cwd_buf.len)
    return false;
  uint32_t offset = out->node_count;
  dep_append_subgraph(out, child, offset, (uint32_t)out->cwd_buf.len,
                      out_streams, streams);
  if (!dep_materialize_fd_import_uses(out, max_edges, offset, out_streams,
                                      streams))
    return false;
  uint32_t pipe = out->node_count++;
  out->nodes[pipe].type = SHELL_NODE_ENDPOINT;
  out->nodes[pipe].endpoint.reserved = DEP_ENDPOINT_PROCESS_PIPE;
  for (uint32_t i = 0; i < endpoints.count; i++) {
    if (child_writes)
      dep_add_edge(out, offset + endpoints.nodes[i], pipe, SHELL_EDGE_WRITE,
                   endpoints.fds[i], SHELL_DEP_FD_NONE);
    else
      dep_add_subst_edge(out, pipe, offset + endpoints.nodes[i],
                         SHELL_DEP_FD_NONE, endpoints.fds[i],
                         DEP_SUBST_PROCESS_OUTPUT);
  }
  bool named = fd->value == SHELL_DEP_FD_NAMED;
  if (access & DEP_FD_ACCESS_READ) {
    parent_edges[0] = out->edge_count;
    dep_add_resolved_edge_refs(out, max_edges, pipe, owner,
                               named ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_SUBST,
                               dep_fd_numeric(SHELL_DEP_FD_NONE), *fd,
                               SHELL_DEP_EDGE_FLAG_NONE);
  }
  if (access & DEP_FD_ACCESS_WRITE) {
    parent_edges[1] = out->edge_count;
    dep_add_resolved_edge_refs(out, max_edges, owner, pipe,
                               named ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_WRITE,
                               *fd, dep_fd_numeric(SHELL_DEP_FD_NONE),
                               SHELL_DEP_EDGE_FLAG_NONE);
  }
  if (combined) {
    parent_edges[2] = out->edge_count;
    dep_add_edge(out, owner, pipe, SHELL_EDGE_WRITE, 2, SHELL_DEP_FD_NONE);
  }
  return true;
}

/* A failed construction step leaves routes awaiting resolution, so its graph
 * cannot be exposed as completed topology or resumed after a partial snapshot.
 * The caller supplies a non-success construction result. Empty/invalid nested
 * source is a parse failure; capacity exhaustion is not a syntax error. Root
 * input validation remains responsible for public EINPUT handling. */
static SHELL_NONNULL(1) shell_dep_error_t
    dep_stop_graph_construction(shell_dep_graph_t *out,
                                shell_dep_error_t error) {
  if (error == SHELL_DEP_EINPUT)
    error = SHELL_DEP_EPARSE;
  out->node_count = 0;
  out->edge_count = 0;
  out->cwd_buf.len = 0;
  out->status = error == SHELL_DEP_ETRUNC ? SHELL_DEP_STATUS_TRUNCATED
                                          : SHELL_DEP_STATUS_ERROR;
  return error;
}

/* A process-substitution redirect operand is one contiguous shell word:
 * `>(command)` or `<(command)`. Keep recursive routing in one place so a
 * redirect-only record owned by a completed group has the same semantics as a
 * redirect attached to an ordinary command. Named-descriptor forms retain
 * FD_OPEN setup; a later symbolic duplication is what materializes their real
 * byte route. */
static SHELL_NONNULL(1, 5, 6, 8, 9, 10, 12, 14) shell_dep_error_t
    dep_connect_redirect_process_substitution(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const dep_token_t *redirect_token, dep_redirect_t redirect,
        const dep_token_t *target, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t consumer_node,
        bool *handled) {
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
  dep_recursive_parse_t *child = dep_recursive_parse_prepare(limits, depth + 1);
  shell_dep_graph_t *subgraph = &child->graph;
  dep_subgraph_streams_t *subgraph_streams = &child->streams;
  dep_fd_imports_t *fd_imports = &child->streams.fd_imports;
  uint32_t position = (uint32_t)(redirect_token->start - context->cmd);
  bool active = dep_owner_phase_active(context, consumer_node,
                                       DEP_SNAPSHOT_REDIRECT_OPERAND, position);
  shell_dep_error_t snapshot_error =
      !active
          ? SHELL_DEP_OK
          : dep_snapshot_fd_imports(out, out_streams, context, consumer_node,
                                    position, DEP_SNAPSHOT_REDIRECT_OPERAND,
                                    fd_imports);
  if (snapshot_error != SHELL_DEP_OK)
    return snapshot_error;
  active =
      active && dep_owner_phase_active(context, consumer_node,
                                       DEP_SNAPSHOT_REDIRECT_OPERAND, position);
  if (active &&
      !dep_fd_import_install_capture(
          fd_imports, target->start[0] == '>' ? 0 : 1,
          target->start[0] == '>' ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE))
    return SHELL_DEP_ETRUNC;
  shell_dep_error_t error = shell_dep_graph_parse_impl(
      sub_content, sub_len, cwd,
      dep_expansion_cwd_known(out, context, consumer_node),
      dep_expansion_cwd_absolute(out, context, consumer_node), limits,
      depth + 1, NULL, subgraph, subgraph_streams, fd_imports, active,
      context->resolver);
  if (error != SHELL_DEP_OK)
    return error;
  if (subgraph->node_count == 0)
    return SHELL_DEP_OK;

  if (!active)
    return dep_append_disconnected_substitution(
               out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
               subgraph, subgraph_streams)
               ? SHELL_DEP_OK
               : SHELL_DEP_ETRUNC;

  bool input = dep_process_substitution_is_input(redirect, target);
  bool output = dep_process_substitution_is_output(redirect, target);
  uint32_t redirected_fd = redirect_fd(redirect_token, redirect);
  const char *named_fd_name = NULL;
  uint32_t named_fd_name_len = 0;
  dep_fd_ref_t named_setup_fd = {0};
  const dep_fd_ref_t *named_setup = NULL;
  if (redirected_fd == SHELL_DEP_FD_NAMED) {
    if (!dep_named_fd_name(redirect_token, &named_fd_name, &named_fd_name_len))
      return SHELL_DEP_EPARSE;
    named_setup_fd =
        (dep_fd_ref_t){SHELL_DEP_FD_NAMED, named_fd_name, named_fd_name_len};
    named_setup = &named_setup_fd;
  }
  uint32_t route_edge = UINT32_MAX, second_route_edge = UINT32_MAX;
  bool combined =
      redirect == DEP_REDIRECT_BOTH || redirect == DEP_REDIRECT_BOTH_APPEND;
  if ((!input && !output) || redirect == DEP_REDIRECT_READ_WRITE) {
    dep_fd_access_t access =
        redirect == DEP_REDIRECT_READ_WRITE ? DEP_FD_ACCESS_BOTH
        : redirect == DEP_REDIRECT_IN       ? DEP_FD_ACCESS_READ
                                            : DEP_FD_ACCESS_WRITE;
    dep_fd_ref_t fd = named_setup
                          ? *named_setup
                          : dep_fd_numeric(combined ? 1 : redirected_fd);
    uint32_t parent_edges[3] = {UINT32_MAX, UINT32_MAX, UINT32_MAX};
    if (!dep_install_process_pipe(
            out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
            subgraph, subgraph_streams, consumer_node, target->start[0] == '<',
            &fd, parent_edges, access, combined))
      return SHELL_DEP_ETRUNC;
    uint32_t position = (uint32_t)(target->start - context->cmd);
    for (unsigned i = 0; i < 3; i++)
      if (parent_edges[i] != UINT32_MAX)
        dep_record_process_substitution_route(
            context->process_routes, parent_edges[i], consumer_node, position,
            i == 0, i == 2 ? dep_fd_numeric(2) : fd);
    return SHELL_DEP_OK;
  }
  bool connected = false;
  if (input) {
    connected = dep_connect_substitution(
        out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
        subgraph, subgraph_streams, consumer_node, DEP_SUBST_PROCESS_INPUT,
        redirected_fd, named_setup, &route_edge);
  } else {
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
          out_streams, subgraph, subgraph_streams, consumer_node,
          DEP_SUBST_PROCESS_OUTPUT, combined ? 1 : redirected_fd, named_setup,
          &route_edge);
    if (connected && combined &&
        (out->status & SHELL_DEP_STATUS_TRUNCATED) == 0) {
      /* Process-output substitutions always use a collector. Add stderr to
       * the same collector as stdout; the nested consumer still executes once.
       */
      uint32_t collector = out->edges[route_edge].to;
      second_route_edge = out->edge_count;
      dep_add_edge(out, consumer_node, collector, SHELL_EDGE_WRITE, 2,
                   SHELL_DEP_FD_NONE);
    }
  }
  if (!connected)
    return SHELL_DEP_ETRUNC;
  if (connected && named_setup) {
    /* The helper has just appended the direct route or its collector. A named
     * descriptor allocation alone does not transfer bytes, so retain it as
     * FD_OPEN setup rather than a false WRITE/SUBST relation. Mark every
     * endpoint with its distinct source name despite the shared public
     * sentinel. */
    shell_dep_edge_t *item = &out->edges[route_edge];
    item->type = SHELL_EDGE_FD_OPEN;
    dep_set_named_fd(item, output, named_fd_name, named_fd_name_len);
  }
  if (connected && (input || output)) {
    uint32_t position = (uint32_t)(target->start - context->cmd);
    dep_record_process_substitution_route(
        context->process_routes, route_edge, consumer_node, position, input,
        named_setup ? *named_setup
                    : dep_fd_numeric(combined ? 1 : redirected_fd));
    if (second_route_edge != UINT32_MAX)
      dep_record_process_substitution_route(context->process_routes,
                                            second_route_edge, consumer_node,
                                            position, false, dep_fd_numeric(2));
  }
  return SHELL_DEP_OK;
}

static SHELL_NONNULL(1, 5, 6, 7, 8, 10) shell_dep_error_t
    dep_connect_word_substitutions_kind(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const dep_token_t *word, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
        uint32_t consumer_node, dep_subst_kind_t kind);

static SHELL_NONNULL(1, 5, 6, 7, 8, 10) shell_dep_error_t
    dep_connect_expansions_kind(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const dep_token_t *word, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
        uint32_t consumer_node, dep_subst_kind_t kind, bool heredoc,
        bool syntax_only);

/* Bash's $(<word) has no external command at its outer level: it reads the
 * resolved word as a file. A static word is one DOC→SUBST flow; a dynamic
 * word first receives an explicitly tagged filename-selection flow. */
static SHELL_NONNULL(1, 5, 6, 8, 9, 11, 18, 19) shell_dep_error_t
    dep_connect_file_command_substitution(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const char *content, uint32_t content_len, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
        uint32_t consumer_node, dep_subst_kind_t consumer_kind,
        bool syntax_only, bool *handled, uint8_t *status) {
  *handled = false;
  *status = DEP_STATUS_EITHER;
  const char *file_path = NULL;
  uint32_t file_path_len = 0;
  if (!dep_file_command_substitution(content, content_len, &file_path,
                                     &file_path_len))
    return SHELL_DEP_OK;
  *handled = true;

  dep_token_t operand = {file_path, file_path_len};
  bool active =
      !syntax_only && dep_owner_phase_active(context, expansion_owner,
                                             snapshot_phase, snapshot_position);
  if (dep_redirect_target_is_process_substitution(&operand)) {
    uint32_t sub_len = 0;
    const char *sub_content = extract_subshell_content(&operand, &sub_len);
    if (!sub_content)
      return SHELL_DEP_EPARSE;
    dep_recursive_parse_t *child =
        dep_recursive_parse_prepare(limits, depth + 1);
    shell_dep_graph_t *subgraph = &child->graph;
    dep_subgraph_streams_t *subgraph_streams = &child->streams;
    dep_fd_imports_t *fd_imports = &child->streams.fd_imports;
    shell_dep_error_t snapshot_error =
        !active ? SHELL_DEP_OK
                : dep_snapshot_fd_imports(out, out_streams, context,
                                          expansion_owner, snapshot_position,
                                          snapshot_phase, fd_imports);
    if (snapshot_error != SHELL_DEP_OK)
      return snapshot_error;
    active =
        active && dep_owner_phase_active(context, expansion_owner,
                                         snapshot_phase, snapshot_position);
    if (active &&
        !dep_fd_import_install_capture(
            fd_imports, operand.start[0] == '>' ? 0 : 1,
            operand.start[0] == '>' ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE))
      return SHELL_DEP_ETRUNC;
    shell_dep_error_t error = shell_dep_graph_parse_impl(
        sub_content, sub_len, cwd,
        dep_expansion_cwd_known(out, context, expansion_owner),
        dep_expansion_cwd_absolute(out, context, expansion_owner), limits,
        depth + 1, NULL, subgraph, subgraph_streams, fd_imports, active,
        context->resolver);
    if (error != SHELL_DEP_OK)
      return error;
    if (subgraph->node_count == 0)
      return SHELL_DEP_OK;

    bool connected =
        active && operand.start[0] == '<'
            ? dep_connect_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size,
                  out_streams, subgraph, subgraph_streams, consumer_node,
                  consumer_kind, 1, NULL, NULL)
            : dep_append_disconnected_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size,
                  out_streams, subgraph, subgraph_streams);
    return connected ? SHELL_DEP_OK : SHELL_DEP_ETRUNC;
  }

  if (active && snapshot_phase == DEP_SNAPSHOT_REDIRECT_OPERAND) {
    uint32_t table;
    shell_dep_error_t error =
        dep_snapshot_phase_table(out, out_streams, context, expansion_owner,
                                 snapshot_position, snapshot_phase, &table);
    if (error != SHELL_DEP_OK)
      return error;
    active = dep_owner_phase_active(context, expansion_owner, snapshot_phase,
                                    snapshot_position);
  }
  uint32_t document_node = UINT32_MAX;
  uint32_t flow_edge = UINT32_MAX;
  if (!active) {
    if (out->node_count == max_nodes)
      return SHELL_DEP_ETRUNC;
    document_node = out->node_count++;
    dep_init_file_document(&out->nodes[document_node], file_path,
                           file_path_len);
  } else if (!add_doc_file(out, max_nodes, max_edges, file_path, file_path_len,
                           consumer_node, SHELL_EDGE_SUBST, SHELL_DIR_FORWARD,
                           DEP_REDIRECT_IN, SHELL_DEP_FD_NONE, &out->status,
                           &document_node))
    return SHELL_DEP_ETRUNC;
  else
    flow_edge = out->edge_count - 1;
  /* Expansion callers borrow cwd from this graph's CWD pool. The operand
   * is resolved before the enclosing command or group's body executes. */
  dep_file_doc_set_cwd(
      out, document_node, (uint32_t)(cwd - out->cwd_buf.data),
      dep_expansion_cwd_known(out, context, expansion_owner),
      dep_expansion_cwd_absolute(out, context, expansion_owner));
  shell_dep_error_t resolution_error = dep_resolve_word(
      out, context, &operand, cwd, expansion_owner,
      SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH, active, document_node, NULL);
  if (resolution_error != SHELL_DEP_OK)
    return resolution_error;
  if (active && (out->nodes[document_node].doc.flags &
                 SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) {
    /* `$(<word)` is an expansion local to its enclosing word. A known failed
     * open yields no bytes, but nested substitutions in the pathname still
     * execute and remain connected below. */
    out->edge_count = flow_edge;
    *status = DEP_STATUS_MAY_FAIL;
  } else if (active)
    out->edges[flow_edge].flags =
        consumer_kind == DEP_SUBST_SHELL_WORD
            ? SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD
            : (consumer_kind == DEP_SUBST_DYNAMIC_NAME
                   ? SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME
                   : SHELL_DEP_EDGE_FLAG_NONE);

  /* Pathname substitutions execute inside this file substitution. Their
   * status/termination cannot replace its eventual open status or escape into
   * the parent shell. Preserve only their graph effects here. */
  uint32_t event = dep_owner_event(context, expansion_owner);
  dep_expansion_status_t saved = context->expansion_status[event];
  uint8_t saved_static = context->event_static_status[event];
  shell_dep_error_t error = dep_connect_expansions_kind(
      out, max_nodes, max_edges, effective_cwd_buf_size, out_streams, &operand,
      cwd, limits, depth, context, expansion_owner, snapshot_position,
      snapshot_phase, document_node, DEP_SUBST_DYNAMIC_NAME, false,
      syntax_only);
  context->expansion_status[event] = saved;
  context->event_static_status[event] = saved_static;
  return error;
}

/* Analyze expansion-bearing words wherever shell syntax can consume them. The
 * caller supplies the semantic consumer: ordinary words and expandable
 * documents feed a shell execution context, while a redirection operand feeds
 * the FILE document whose runtime pathname it selects. */
static SHELL_NONNULL(1, 5, 6, 7, 8, 10) shell_dep_error_t
    dep_connect_expansions_kind(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const dep_token_t *word, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
        uint32_t consumer_node, dep_subst_kind_t kind, bool heredoc,
        bool syntax_only) {
  bool active =
      !syntax_only && dep_owner_phase_active(context, expansion_owner,
                                             snapshot_phase, snapshot_position);
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc, .suppress_process = heredoc}};
  dep_token_t subshell;
  shell_source_scan_status_t scan_status =
      dep_next_word_substitution(word, &scan, &subshell);
  /* A parameter/arithmetic-only word can stop the shell without yielding a
   * child substitution. Establish its redirect checkpoint before publishing
   * any expansion effect. Plain words need neither a checkpoint nor imports;
   * nested substitutions below reuse this checkpoint when exporting FDs. */
  if (active && snapshot_phase == DEP_SNAPSHOT_REDIRECT_OPERAND &&
      (scan_status == SHELL_SOURCE_SCAN_FOUND ||
       scan.has_expansion_termination || scan.has_expansion_abort)) {
    uint32_t table;
    shell_dep_error_t error =
        dep_snapshot_phase_table(out, out_streams, context, expansion_owner,
                                 snapshot_position, snapshot_phase, &table);
    if (error != SHELL_DEP_OK)
      return error;
    active = dep_owner_phase_active(context, expansion_owner, snapshot_phase,
                                    snapshot_position);
  }
  while (scan_status == SHELL_SOURCE_SCAN_FOUND) {
    uint8_t substitution_status = DEP_STATUS_MAY_SUCCEED;
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
            snapshot_position, snapshot_phase, consumer_node, kind, syntax_only,
            &file_handled, &substitution_status);
      if (file_error != SHELL_DEP_OK)
        return file_error;
      if (file_handled)
        active =
            active && dep_owner_phase_active(context, expansion_owner,
                                             snapshot_phase, snapshot_position);
      if (!file_handled) {
        dep_recursive_parse_t *child =
            dep_recursive_parse_prepare(limits, depth + 1);
        shell_dep_graph_t *subgraph = &child->graph;
        dep_subgraph_streams_t *subgraph_streams = &child->streams;
        dep_fd_imports_t *fd_imports = &child->streams.fd_imports;
        shell_dep_error_t snapshot_error =
            !active
                ? SHELL_DEP_OK
                : dep_snapshot_fd_imports(out, out_streams, context,
                                          expansion_owner, snapshot_position,
                                          snapshot_phase, fd_imports);
        if (snapshot_error != SHELL_DEP_OK)
          return snapshot_error;
        active =
            active && dep_owner_phase_active(context, expansion_owner,
                                             snapshot_phase, snapshot_position);
        if (active && !dep_fd_import_install_capture(
                          fd_imports, subshell.start[0] == '>' ? 0 : 1,
                          subshell.start[0] == '>' ? DEP_FD_ACCESS_READ
                                                   : DEP_FD_ACCESS_WRITE))
          return SHELL_DEP_ETRUNC;
        shell_dep_error_t error = shell_dep_graph_parse_impl(
            sub_content, sub_len, cwd,
            dep_expansion_cwd_known(out, context, expansion_owner),
            dep_expansion_cwd_absolute(out, context, expansion_owner), limits,
            depth + 1, NULL, subgraph, subgraph_streams, fd_imports, active,
            context->resolver);
        if (error != SHELL_DEP_OK)
          return error;
        substitution_status = dep_substitution_status(subgraph_streams->status);
        if (subgraph->node_count > 0) {
          /* A process substitution in a filename or document operand
           * contributes a descriptor pathname, not its stream bytes. Retain
           * its commands without inventing stdout-to-document byte flow. */
          bool disconnected =
              !active || subshell.start[0] == '>' ||
              (subshell.start[0] == '<' &&
               (kind == DEP_SUBST_DYNAMIC_NAME ||
                out->nodes[consumer_node].type == SHELL_NODE_DOC));
          bool connected =
              !disconnected ||
              dep_append_disconnected_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size,
                  out_streams, subgraph, subgraph_streams);
          if (!disconnected)
            connected = dep_connect_substitution(
                out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
                subgraph, subgraph_streams, consumer_node,
                subshell.start[0] == '<' ? DEP_SUBST_PROCESS_WORD : kind, 1,
                NULL, NULL);
          if (!connected)
            return SHELL_DEP_ETRUNC;
        }
      }
    }
    if (active && (subshell.start[0] == '$' || subshell.start[0] == '`'))
      dep_record_substitution_status(context, expansion_owner, snapshot_phase,
                                     substitution_status,
                                     scan.scope.conditional);
    scan_status = dep_next_word_substitution(word, &scan, &subshell);
  }
  if (active)
    dep_record_expansion_error(
        context, expansion_owner, snapshot_phase,
        (scan.has_expansion_termination ? DEP_STATUS_TERMINAL_FAILURE : 0) |
            (scan.has_expansion_abort ? DEP_STATUS_ABORT_FAILURE : 0));
  return scan_status == SHELL_SOURCE_SCAN_MALFORMED ? SHELL_DEP_EPARSE
                                                    : SHELL_DEP_OK;
}

static SHELL_NONNULL(1, 5, 6, 7, 8, 10) shell_dep_error_t
    dep_connect_word_substitutions_kind(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const dep_token_t *word, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
        uint32_t consumer_node, dep_subst_kind_t kind) {
  return dep_connect_expansions_kind(
      out, max_nodes, max_edges, effective_cwd_buf_size, out_streams, word, cwd,
      limits, depth, context, expansion_owner, snapshot_position,
      snapshot_phase, consumer_node, kind, false, false);
}

/* Inspect an operand whose execution is known not to occur. Required retained
 * owner; consumer identity is unused for dynamic effects in this mode. */
static SHELL_NONNULL(1, 5, 6, 7, 8, 10) shell_dep_error_t
    dep_inspect_skipped_operand(shell_dep_graph_t *out, uint32_t max_nodes,
                                uint32_t max_edges, uint32_t cwd_size,
                                dep_subgraph_streams_t *streams,
                                const dep_token_t *operand, const char *cwd,
                                const shell_dep_limits_t *limits,
                                uint32_t depth,
                                const dep_parse_context_t *context,
                                uint32_t owner) {
  return dep_connect_expansions_kind(
      out, max_nodes, max_edges, cwd_size, streams, operand, cwd, limits, depth,
      context, owner, (uint32_t)(operand->start - context->cmd),
      DEP_SNAPSHOT_REDIRECT_OPERAND, owner, DEP_SUBST_SHELL_WORD, false, true);
}

/* Use the same scoped stream and route construction as ordinary words, but
 * with heredoc-root quoting. Only active expansions introduce graph nodes. */
static SHELL_NONNULL(1, 5, 6, 8, 9, 11) shell_dep_error_t
    dep_connect_heredoc_substitutions(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const char *content, uint32_t content_len, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, uint32_t document_node) {
  dep_token_t body = {content, content_len};
  return dep_connect_expansions_kind(
      out, max_nodes, max_edges, effective_cwd_buf_size, out_streams, &body,
      cwd, limits, depth, context, expansion_owner, snapshot_position,
      DEP_SNAPSHOT_REDIRECT_OPERAND, document_node, DEP_SUBST_SHELL_WORD, true,
      false);
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

/* Installed document spans belong to this command's execution stage. Advance
 * their declaration cursor alongside ordinary operands, so setup expands in
 * source order and current-shell status is known before the command finishes.
 * Lexical feature flags also include child-shell expansions; only the scoped
 * expansion walker may establish substitution status for this owner.
 * UINT32_MAX drains the remaining declarations at the end of the stage. */
static SHELL_NONNULL(1, 5, 6, 7, 9, 10, 11, 12) shell_dep_error_t
    dep_expand_inline_documents(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t cwd_size, dep_subgraph_streams_t *streams, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, const shell_range_t *declarations,
        const uint32_t *documents, uint32_t *cursor, uint32_t range_owner,
        uint32_t owner, uint32_t position) {
  while (*cursor < context->fast->count &&
         context->execution->owner[*cursor] == range_owner) {
    uint32_t fragment = *cursor;
    const shell_range_t *range = &declarations[fragment];
    if (range->start > position)
      break;
    (*cursor)++;
    uint32_t document = documents[fragment];
    if (document == UINT32_MAX ||
        context->owner_assignment_stop[owner] != UINT32_MAX)
      continue;
    const shell_dep_doc_t *doc = &out->nodes[document].doc;
    shell_dep_error_t error = SHELL_DEP_OK;
    if (doc->kind == SHELL_DOC_HEREDOC) {
      if (!(doc->flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL) && doc->value_len)
        error = dep_connect_heredoc_substitutions(
            out, max_nodes, max_edges, cwd_size, streams, doc->value,
            doc->value_len, cwd, limits, depth, context, owner, range->start,
            document);
    } else {
      dep_token_t word = {doc->value, doc->value_len};
      error = dep_connect_word_substitutions(
          out, max_nodes, max_edges, cwd_size, streams, &word, cwd, limits,
          depth, context, owner, range->start, DEP_SNAPSHOT_REDIRECT_OPERAND,
          document);
    }
    if (error != SHELL_DEP_OK)
      return error;
  }
  return SHELL_DEP_OK;
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
/* cmd addresses end bytes; group and end come from the same pipeline index. */
static SHELL_NONNULL(1, 3, 4, 6) uint32_t
    scan_group_herestrings(const char *cmd, uint32_t end,
                           const shell_group_t *group,
                           dep_group_herestring_t *items, uint32_t capacity,
                           bool *complete) {
  *complete = true;
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
    if (!explicit_fd && shell_source_parse_named_fd_redirect_at_word_start(
                            cmd, position, end, &operator_after)) {
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
      if (fd == SHELL_DEP_FD_NAMED)
        inline_document_named_fd_name(cmd, position, operator_pos, &fd_name,
                                      &fd_name_len);
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
  DEP_GROUP_EVENT_DUP_OPERAND,
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
  if (*count >= capacity)
    return false;
  events[(*count)++] = event;
  return true;
}

static SHELL_NONNULL(1, 2) int dep_group_event_compare(const void *left,
                                                       const void *right) {
  const dep_group_redirect_event_t *a = left, *b = right;
  return a->position < b->position ? -1 : a->position != b->position;
}

/* Mark only words whose expansion cannot alter shell dispatch or builtin
 * state. Redirect operands and assignment prefixes are handled by their own
 * phases. Unknown dispatch remains unresolved. printf data is ordinary argv
 * except state-controlling %b operands in %n formats; those, its options,
 * destination and format retain their semantic roles. */
static SHELL_NONNULL(1, 6, 7) void dep_prepare_expandable_arguments(
    const dep_token_list_t *tokens, uint32_t command,
    uint32_t effective_command, bool dynamic_command,
    const dep_token_t *effective_builtin, const dep_exec_analysis_t *exec,
    bool eligible[SHELL_DEP_MAX_TOKENS]) {
  memset(eligible, 0, SHELL_DEP_MAX_TOKENS * sizeof(eligible[0]));
  if (command == UINT32_MAX || dynamic_command || !effective_builtin)
    return;

  shell_source_builtin_kind_t kind = shell_source_static_builtin_kind(
      effective_builtin->start, effective_builtin->len);
  if (dep_token_static_equals(effective_builtin, "cd") ||
      dep_token_static_equals(effective_builtin, "exit") ||
      dep_token_static_equals(effective_builtin, "return") ||
      dep_token_static_equals(effective_builtin, "break") ||
      dep_token_static_equals(effective_builtin, "continue") ||
      dep_token_static_equals(effective_builtin, "shift") ||
      dep_token_static_equals(effective_builtin, "umask") ||
      dep_token_static_equals(effective_builtin, "ulimit") ||
      dep_token_static_equals(effective_builtin, "kill") ||
      dep_token_static_equals(effective_builtin, "type") ||
      dep_token_static_equals(effective_builtin, "hash") ||
      dep_token_static_equals(effective_builtin, "help") ||
      dep_token_static_equals(effective_builtin, "jobs") ||
      dep_token_static_equals(effective_builtin, "fg") ||
      dep_token_static_equals(effective_builtin, "bg") ||
      dep_token_static_equals(effective_builtin, "disown") ||
      dep_token_static_equals(effective_builtin, "dirs"))
    return;
  uint32_t ordinary_after = UINT32_MAX;
  if (kind == SHELL_SOURCE_BUILTIN_EXEC && exec->kind == DEP_EXEC_REPLACE) {
    for (uint32_t i = effective_command + 1; i < tokens->count; i++)
      if (tokens->tokens[i].start == exec->target.start &&
          tokens->tokens[i].len == exec->target.len) {
        ordinary_after = i;
        break;
      }
  } else if (kind == SHELL_SOURCE_BUILTIN_NONE) {
    ordinary_after = effective_command;
  }

  if (ordinary_after != UINT32_MAX) {
    for (uint32_t i = ordinary_after + 1; i < tokens->count; i++) {
      dep_redirect_t redirect = classify_redirect(&tokens->tokens[i]);
      if (redirect != DEP_REDIRECT_NONE) {
        if (shell_source_redirection_consumes_word(tokens->tokens[i].start,
                                                   tokens->tokens[i].len) &&
            i + 1 < tokens->count)
          i++;
        continue;
      }
      eligible[i] = true;
    }
    return;
  }

  if (kind != SHELL_SOURCE_BUILTIN_PRINTF)
    return;
  shell_builtin_printf_t state = {0};
  for (uint32_t i = effective_command + 1; i < tokens->count; i++) {
    dep_redirect_t redirect = classify_redirect(&tokens->tokens[i]);
    if (redirect != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(tokens->tokens[i].start,
                                                 tokens->tokens[i].len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    shell_builtin_printf_phase_t phase = state.phase;
    unsigned roles = shell_builtin_printf_word(&state, tokens->tokens[i].start,
                                               tokens->tokens[i].len);
    eligible[i] =
        phase == SHELL_PRINTF_DATA &&
        !(roles & (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE |
                   SHELL_BUILTIN_ROLE_UNSUPPORTED | SHELL_BUILTIN_ROLE_DYNAMIC |
                   SHELL_BUILTIN_ROLE_CONTROL));
  }
}

/* --- MAIN PARSER --- */

static bool dep_source_is_whitespace(const char *cmd, uint32_t length) {
  for (uint32_t i = 0; i < length; i++)
    if (cmd[i] != ' ' && cmd[i] != '\t' && cmd[i] != '\n' && cmd[i] != '\r')
      return false;
  return true;
}

/* Parser metadata is trusted. Capacity truncation can leave open compound
 * descriptors; disable those (and their descendants) before building a partial
 * graph. Parent indices precede children in parser-produced results. */
static void dep_prepare_partial_groups(shell_parse_result_t *fast) {
  for (uint32_t i = 0; i < fast->group_count; i++) {
    shell_group_t *group = &fast->groups[i];
    if (group->end == 0 ||
        (group->parent != UINT16_MAX && fast->groups[group->parent].end == 0)) {
      *group = (shell_group_t){.parent = UINT16_MAX};
      fast->status |= SHELL_STATUS_TRUNCATED;
    }
  }
}

static SHELL_NONNULL(1) uint32_t
    dep_pipeline_range_at_or_after(const shell_parse_result_t *fast,
                                   uint32_t cursor, uint32_t member_limit,
                                   size_t source_start) {
  while (cursor < member_limit && fast->cmds[cursor].start < source_start)
    cursor++;
  return cursor;
}

static SHELL_NONNULL(1, 2) void dep_set_command_time_owner(
    shell_dep_graph_t *graph, const uint32_t *range_node, uint32_t range,
    uint32_t timer) {
  uint32_t node = range_node[range];
  if (node != UINT32_MAX)
    graph->nodes[node].cmd.pipeline_time_id = timer + 1;
}

static SHELL_NONNULL(1, 2) void dep_set_group_time_owner(
    shell_dep_graph_t *graph, const uint32_t *group_node, uint32_t group,
    uint32_t timer) {
  if (group_node[group] != UINT32_MAX)
    graph->nodes[group_node[group]].group.pipeline_time_id = timer + 1;
}

/* Walk later members of one syntactic pipeline within an explicit lexical
 * bound. Actual PIPE edges cannot provide this relation: a member may redirect
 * the relevant descriptor while remaining part of the timed shell pipeline.
 * The same walk computes the source extent and assigns owners so those two
 * views cannot diverge. */
static SHELL_NONNULL(2, 4, 5) uint32_t dep_walk_timed_pipeline(
    shell_dep_graph_t *graph, const char *cmd, uint32_t command_length,
    const shell_parse_result_t *fast, const shell_pipeline_index_t *pipeline,
    const uint32_t *range_node, const uint32_t *group_node, uint32_t cursor,
    uint32_t member_limit, uint32_t end, shell_pipeline_time_mode_t mode,
    uint32_t timer, bool assign_owners) {
  shell_pipeline_stage_t stage;
  while (shell_pipeline_next(cmd, command_length, fast, pipeline, member_limit,
                             &cursor, &end, &stage)) {
    const shell_group_t *group = stage.group;
    if (group) {
      if (group->pipeline_time_mode != mode)
        break;
      uint32_t group_index = (uint32_t)(group - fast->groups);
      if (graph && assign_owners)
        dep_set_group_time_owner(graph, group_node, group_index, timer);
      continue;
    }
    const shell_range_t *range = &fast->cmds[stage.range];
    if (range->pipeline_time_mode != mode)
      break;
    if (graph && assign_owners)
      dep_set_command_time_owner(graph, range_node, stage.range, timer);
  }
  return end;
}

static SHELL_NONNULL(
    1, 2, 4, 5, 6,
    7) void dep_set_following_pipeline_time_owners(shell_dep_graph_t *graph,
                                                   const char *cmd,
                                                   uint32_t command_length,
                                                   const shell_parse_result_t
                                                       *fast,
                                                   const shell_pipeline_index_t
                                                       *pipeline,
                                                   const uint32_t *range_node,
                                                   const uint32_t *group_node,
                                                   uint32_t cursor,
                                                   uint32_t member_limit,
                                                   uint32_t end,
                                                   shell_pipeline_time_mode_t
                                                       mode,
                                                   uint32_t timer) {
  (void)dep_walk_timed_pipeline(graph, cmd, command_length, fast, pipeline,
                                range_node, group_node, cursor, member_limit,
                                end, mode, timer, true);
}

/* Follow flattened fast ranges while treating one compound descriptor as one
 * outer pipeline member. Its trailing redirects are part of that member and
 * may separate its enclosed range interval from the next pipe stage. Inner
 * commands must not truncate the source span or acquire their containing
 * group's timing mode. */
static SHELL_NONNULL(1, 3, 4) uint32_t
    dep_timed_pipeline_end(const char *cmd, uint32_t command_length,
                           const shell_parse_result_t *fast,
                           const shell_pipeline_index_t *pipeline,
                           uint32_t cursor, uint32_t member_limit, uint32_t end,
                           shell_pipeline_time_mode_t mode) {
  return dep_walk_timed_pipeline(NULL, cmd, command_length, fast, pipeline,
                                 NULL, NULL, cursor, member_limit, end, mode, 0,
                                 false);
}

static SHELL_NONNULL(1, 2, 4, 5, 6, 7, 8, 9, 10, 11) uint32_t
    dep_collect_time_boundaries(
        const shell_dep_graph_t *graph, const char *cmd,
        uint32_t command_length, const shell_parse_result_t *fast,
        const shell_pipeline_index_t *pipeline, const uint32_t *node_range,
        const uint32_t *range_node, const uint32_t *node_group,
        const uint32_t *group_node, const dep_group_exec_t *group_exec,
        dep_time_boundary_t *boundaries, uint32_t capacity) {
  uint32_t count = 0;
  for (uint32_t group = 0; group < fast->group_count; group++) {
    const shell_group_t *descriptor = &fast->groups[group];
    uint32_t target = group_node[group];
    if (descriptor->pipeline_time_mode == SHELL_PIPE_TIME_NONE ||
        !descriptor->pipeline_time_direct || target == UINT32_MAX ||
        count >= capacity)
      continue;
    shell_source_compound_tail_t tail = pipeline->group_tail[group];
    uint32_t cursor = descriptor->first_command + descriptor->command_count;
    uint32_t member_limit = shell_pipeline_group_limit(fast, descriptor);
    uint32_t end = (uint32_t)tail.redirect_end;
    if (tail.has_pipeline)
      cursor = dep_pipeline_range_at_or_after(fast, cursor, member_limit,
                                              tail.next_stage);
    else
      cursor = member_limit;
    end = dep_timed_pipeline_end(
        cmd, command_length, fast, pipeline, cursor, member_limit, end,
        (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode);
    bool single_stage = !tail.has_pipeline;
    boundaries[count++] = (dep_time_boundary_t){
        target,
        end,
        dep_owner_enclosing_group(graph, fast, pipeline, node_range, node_group,
                                  target),
        (int32_t)group,
        single_stage && (descriptor->kind == SHELL_GROUP_SUBSHELL ||
                         group_exec[group].backgrounded),
        single_stage && descriptor->kind == SHELL_GROUP_BRACE &&
            !group_exec[group].backgrounded,
    };
  }
  for (uint32_t range = 0; range < fast->count; range++) {
    const shell_range_t *descriptor = &fast->cmds[range];
    if (descriptor->pipeline_time_mode == SHELL_PIPE_TIME_NONE ||
        !descriptor->pipeline_time_direct || count >= capacity)
      continue;
    uint32_t target = range_node[range];
    if (target == UINT32_MAX)
      continue;
    uint32_t member_limit = shell_pipeline_range_limit(fast, pipeline, range);
    uint32_t end = dep_timed_pipeline_end(
        cmd, command_length, fast, pipeline, range + 1, member_limit,
        descriptor->start + descriptor->len,
        (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode);
    uint32_t cursor = range + 1;
    uint32_t stage_end = descriptor->start + descriptor->len;
    shell_pipeline_stage_t next;
    bool single_stage =
        !shell_pipeline_next(cmd, command_length, fast, pipeline, member_limit,
                             &cursor, &stage_end, &next);
    boundaries[count++] = (dep_time_boundary_t){
        target,
        end,
        dep_owner_enclosing_group(graph, fast, pipeline, node_range, node_group,
                                  target),
        -1,
        single_stage && graph->nodes[target].cmd.backgrounded,
        false,
    };
  }
  return count;
}

static SHELL_NONNULL(1) bool dep_time_record_external_fd(shell_dep_time_t *time,
                                                         uint32_t fd) {
  for (uint32_t i = 0; i < time->report_external_fd_count; i++)
    if (time->report_external_fds[i] == fd)
      return true;
  if (time->report_external_fd_count >= SHELL_DEP_TIME_MAX_EXTERNAL_FDS)
    return false;
  time->report_external_fds[time->report_external_fd_count++] = fd;
  return true;
}

static SHELL_NONNULL(1, 4, 5) bool dep_materialize_one_time_report_route(
    shell_dep_graph_t *graph, uint32_t timer, uint32_t max_edges,
    dep_route_workspace_t *workspace, dep_subgraph_streams_t *streams,
    dep_fd_route_t route) {
  shell_dep_time_t *time = &graph->nodes[timer].time;
  if (route.kind == DEP_ROUTE_CAPTURE) {
    if (!dep_record_stream_use(
            streams->capture_uses, &streams->capture_use_count,
            streams->capture_index, &streams->capture_root, timer,
            time->report_fd, DEP_FD_ACCESS_WRITE, route.value))
      return false;
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_GRAPH;
    return true;
  }
  if (route.kind == DEP_ROUTE_INHERITED) {
    if (!dep_time_record_external_fd(time, route.value))
      return false;
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_EXTERNAL;
    return true;
  }
  if (route.kind == DEP_ROUTE_CLOSED) {
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_CLOSED;
    return true;
  }
  if (route.kind == DEP_ROUTE_UNAVAILABLE) {
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_UNAVAILABLE;
    return true;
  }
  if (route.kind == DEP_ROUTE_IMPORTED) {
    if (!dep_record_fd_import_use(streams, timer, time->report_fd,
                                  DEP_FD_ACCESS_WRITE, route.value))
      return false;
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_GRAPH;
    return true;
  }
  if (route.kind == DEP_ROUTE_PIPE) {
    if (route.value >= workspace->pipe_count)
      return false;
    uint32_t start = workspace->time_pipe_start[route.value];
    uint32_t count = workspace->time_pipe_count[route.value];
    for (uint32_t i = 0; i < count; i++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_PIPE_TARGETS);
      const dep_stream_use_t *target = &workspace->time_pipe_targets[start + i];
      if (!dep_add_resolved_edge_refs(
              graph, max_edges, timer, target->owner, SHELL_EDGE_PIPE,
              dep_fd_numeric(time->report_fd), dep_fd_numeric(target->fd),
              SHELL_DEP_EDGE_FLAG_NONE))
        return false;
      time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_GRAPH;
    }
    return count != 0;
  }
  if (route.kind != DEP_ROUTE_DOC && route.kind != DEP_ROUTE_DYNAMIC)
    return false;
  if (route.value >= workspace->original_edge_count)
    return false;
  const shell_dep_edge_t *original = &workspace->original_edges[route.value];
  shell_dep_edge_type_t type = original->type;
  if (type == SHELL_EDGE_FD_OPEN)
    type = (original->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0
               ? SHELL_EDGE_APPEND
               : SHELL_EDGE_WRITE;
  if ((type != SHELL_EDGE_WRITE && type != SHELL_EDGE_APPEND) ||
      original->to >= graph->node_count ||
      !dep_add_resolved_edge_refs(graph, max_edges, timer, original->to, type,
                                  dep_fd_numeric(time->report_fd),
                                  dep_fd_numeric(SHELL_DEP_FD_NONE),
                                  SHELL_DEP_EDGE_FLAG_NONE))
    return false;
  time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_GRAPH;
  return true;
}

/* Summarize what was actually retained in the bounded graph. The input
 * snapshot may contain more alternatives than max_edges permits, so its count
 * cannot determine the public route after materialization. */
static SHELL_NONNULL(1) void dep_finalize_time_report_route(
    shell_dep_graph_t *graph, uint32_t timer, uint32_t retained_graph_routes) {
  shell_dep_time_t *time = &graph->nodes[timer].time;
  bool has_closed =
      (time->report_route_flags & SHELL_TIME_REPORT_ROUTE_CLOSED) != 0;
  bool has_unavailable =
      (time->report_route_flags & SHELL_TIME_REPORT_ROUTE_UNAVAILABLE) != 0;
  bool has_unknown =
      (time->report_route_flags & SHELL_TIME_REPORT_ROUTE_UNKNOWN) != 0;
  uint32_t alternatives = retained_graph_routes +
                          time->report_external_fd_count +
                          (has_closed ? 1u : 0u) + (has_unavailable ? 1u : 0u) +
                          (has_unknown ? 1u : 0u);

  time->report_target_fd = SHELL_DEP_FD_NONE;
  if (alternatives > 1) {
    time->report_route = SHELL_TIME_REPORT_MULTIPLE;
  } else if (has_unknown) {
    time->report_route = SHELL_TIME_REPORT_UNKNOWN;
  } else if (time->report_external_fd_count == 1) {
    time->report_route = SHELL_TIME_REPORT_EXTERNAL;
    time->report_target_fd = time->report_external_fds[0];
  } else if (retained_graph_routes == 1) {
    time->report_route = SHELL_TIME_REPORT_GRAPH;
  } else if (has_unavailable) {
    time->report_route = SHELL_TIME_REPORT_UNAVAILABLE;
  } else if (has_closed) {
    time->report_route = SHELL_TIME_REPORT_CLOSED;
  } else {
    /* An unmaterialized deferred stream is a missing route, not a close. */
    time->report_route = SHELL_TIME_REPORT_UNKNOWN;
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_UNKNOWN;
    graph->status |= SHELL_DEP_STATUS_TRUNCATED;
  }
}

static SHELL_NONNULL(1, 4, 5) bool dep_materialize_time_report_route(
    shell_dep_graph_t *graph, uint32_t timer, uint32_t max_edges,
    dep_route_workspace_t *workspace, dep_subgraph_streams_t *streams,
    dep_route_set_t snapshot) {
  shell_dep_time_t *time = &graph->nodes[timer].time;
  time->report_target_fd = SHELL_DEP_FD_NONE;
  time->report_route = SHELL_TIME_REPORT_UNKNOWN;
  time->report_route_flags = SHELL_TIME_REPORT_ROUTE_NONE;
  time->report_external_fd_count = 0;
  if (!snapshot.ready || snapshot.count == 0) {
    time->report_route_flags = SHELL_TIME_REPORT_ROUTE_UNKNOWN;
    return false;
  }

  bool complete = !snapshot.truncated;
  uint32_t retained_graph_routes = 0;
  for (uint32_t i = 0; i < snapshot.count; i++) {
    dep_fd_route_t route = snapshot.routes[i];
    uint32_t before_edges = graph->edge_count;
    uint32_t before_imports = streams->fd_import_use_count;
    uint32_t before_captures = streams->capture_use_count;
    if (!dep_materialize_one_time_report_route(graph, timer, max_edges,
                                               workspace, streams, route)) {
      complete = false;
    }
    retained_graph_routes += graph->edge_count - before_edges;
    retained_graph_routes += streams->fd_import_use_count - before_imports +
                             streams->capture_use_count - before_captures;
  }
  if (!complete)
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_UNKNOWN;
  dep_finalize_time_report_route(graph, timer, retained_graph_routes);
  return complete;
}

/* Add one shell-owned timing operation for every reserved `time` pipeline.
 * Route resolution deliberately runs first so the TIME node can materialize
 * the shell-owned report route without becoming an executable descriptor
 * owner. */
static SHELL_NONNULL(1, 2, 4, 5, 6, 7, 10, 11) bool dep_add_pipeline_time_nodes(
    shell_dep_graph_t *graph, const char *cmd, uint32_t command_length,
    const shell_parse_result_t *fast, const shell_pipeline_index_t *pipeline,
    const uint32_t *range_node, const uint32_t *group_node, uint32_t max_nodes,
    uint32_t max_edges, dep_route_workspace_t *workspace,
    dep_subgraph_streams_t *streams) {
  for (uint32_t group = 0; group < fast->group_count; group++) {
    const shell_group_t *descriptor = &fast->groups[group];
    if (descriptor->pipeline_time_mode == SHELL_PIPE_TIME_NONE ||
        !descriptor->pipeline_time_direct || group_node[group] == UINT32_MAX)
      continue;
    shell_source_compound_tail_t tail = pipeline->group_tail[group];
    uint32_t cursor = descriptor->first_command + descriptor->command_count;
    uint32_t member_limit = shell_pipeline_group_limit(fast, descriptor);
    uint32_t end = (uint32_t)tail.redirect_end;
    if (tail.has_pipeline)
      cursor = dep_pipeline_range_at_or_after(fast, cursor, member_limit,
                                              tail.next_stage);
    else
      cursor = member_limit;
    end = dep_timed_pipeline_end(
        cmd, command_length, fast, pipeline, cursor, member_limit, end,
        (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode);
    if (descriptor->start >= end || end > command_length ||
        graph->node_count >= max_nodes || graph->edge_count >= max_edges) {
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      continue;
    }
    uint32_t timer = graph->node_count++;
    graph->nodes[timer] = (shell_dep_node_t){
        .type = SHELL_NODE_TIME,
        .time = {.start = cmd + descriptor->start,
                 .length = end - descriptor->start,
                 .mode =
                     (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode,
                 .report_fd = 2,
                 .report_target_fd = SHELL_DEP_FD_NONE,
                 .report_route = SHELL_TIME_REPORT_UNKNOWN},
    };
    dep_init_edge(&graph->edges[graph->edge_count++], timer, group_node[group],
                  SHELL_EDGE_TIME, SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE,
                  SHELL_DEP_FD_NONE);
    if (!dep_materialize_time_report_route(
            graph, timer, max_edges, workspace, streams,
            workspace->time_reports[group_node[group]]))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    dep_set_group_time_owner(graph, group_node, group, timer);
    dep_set_following_pipeline_time_owners(
        graph, cmd, command_length, fast, pipeline, range_node, group_node,
        cursor, member_limit, descriptor->end,
        (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode, timer);
  }

  for (uint32_t range = 0; range < fast->count; range++) {
    const shell_range_t *descriptor = &fast->cmds[range];
    if (descriptor->pipeline_time_mode == SHELL_PIPE_TIME_NONE ||
        !descriptor->pipeline_time_direct)
      continue;

    uint32_t target = range_node[range];
    uint32_t start = descriptor->start;
    uint32_t member_limit = shell_pipeline_range_limit(fast, pipeline, range);
    uint32_t end = dep_timed_pipeline_end(
        cmd, command_length, fast, pipeline, range + 1, member_limit,
        start + descriptor->len,
        (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode);
    bool empty_pipeline = shell_pipeline_range_is_empty_timing(cmd, descriptor);
    if (empty_pipeline)
      start = end;
    if (target == UINT32_MAX || (!empty_pipeline && start >= end) ||
        end > command_length || graph->node_count >= max_nodes ||
        graph->edge_count >= max_edges) {
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      continue;
    }
    uint32_t timer = graph->node_count++;
    graph->nodes[timer] = (shell_dep_node_t){
        .type = SHELL_NODE_TIME,
        .time = {.start = cmd + start,
                 .length = end - start,
                 .mode =
                     (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode,
                 .report_fd = 2,
                 .report_target_fd = SHELL_DEP_FD_NONE,
                 .report_route = SHELL_TIME_REPORT_UNKNOWN},
    };
    dep_init_edge(&graph->edges[graph->edge_count++], timer, target,
                  SHELL_EDGE_TIME, SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE,
                  SHELL_DEP_FD_NONE);
    if (!dep_materialize_time_report_route(graph, timer, max_edges, workspace,
                                           streams,
                                           workspace->time_reports[target]))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    dep_set_command_time_owner(graph, range_node, range, timer);
    dep_set_following_pipeline_time_owners(
        graph, cmd, command_length, fast, pipeline, range_node, group_node,
        range + 1, member_limit, descriptor->start + descriptor->len,
        (shell_pipeline_time_mode_t)descriptor->pipeline_time_mode, timer);
  }

  return true;
}

static SHELL_NONNULL(1, 9, 10) shell_dep_error_t shell_dep_graph_parse_raw(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    bool initial_cwd_known, bool initial_cwd_absolute,
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams, const dep_fd_imports_t *imports,
    bool effects_active, const shell_dep_word_resolver_t *resolver) {
  /* Root callers supply a distinct borrowed import table. Recursive callers
   * prepare imports in their depth-indexed stream frame so the large table is
   * never another automatic object. */
  dep_subgraph_streams_begin(streams, imports);
  if (cmd_len == 0) {

    out->node_count = 0;
    out->edge_count = 0;
    out->status = SHELL_DEP_STATUS_ERROR;
    out->cwd_buf.len = 0;

    return SHELL_DEP_EINPUT;
  }

  /* `initial_cwd` is a borrowed C string just like command bytes are a
   * borrowed span. */
  const char *init_cwd = initial_cwd ? initial_cwd : ".";
  size_t init_cwd_length = strlen(init_cwd);

  /* Graph construction derives execution ranges and partial-group metadata
   * from the immutable parser result. Keep that working state local rather
   * than modifying the caller's parse result. */
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

  if (depth > DEP_PARSE_DEPTH_LIMIT) {
    out->node_count = 0;
    out->edge_count = 0;
    out->status = SHELL_DEP_STATUS_ERROR;
    out->cwd_buf.len = 0;
    return SHELL_DEP_EPARSE;
  }

  shell_dep_limits_t default_limits;
  if (!limits) {
    default_limits = SHELL_DEP_LIMITS_DEFAULT;
    limits = &default_limits;
  }

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
  dep_prepare_partial_groups(&fast_result);
  if (dep_source_is_whitespace(cmd, (uint32_t)cmd_len)) {
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
  dep_observable_inventory_t observable = {0};
  if (shell_tokenizer_inspect_semantics(
          cmd, cmd_len, dep_observe_descriptor_token, &observable)) {
    out->status = SHELL_DEP_STATUS_ERROR;
    return SHELL_DEP_EPARSE;
  }
  if (observable.overflow) {
    out->status = SHELL_DEP_STATUS_TRUNCATED;
    return SHELL_DEP_ETRUNC;
  }
  out->status = fast_result.status;

  if (fast_result.count == 0)
    return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                      : SHELL_DEP_OK;

  /* Reject unavailable scratch once after syntax and empty-source handling.
   * Internal consumers below rely on this aligned, sufficiently sized buffer.
   */
  if (depth == 0 &&
      (!limits->workspace ||
       limits->workspace_size < sizeof(dep_route_workspace_t) ||
       (uintptr_t)limits->workspace % _Alignof(dep_route_workspace_t) != 0)) {
    out->status = SHELL_DEP_STATUS_ERROR;
    return SHELL_DEP_EWORKSPACE;
  }

  bool skip_buf[SHELL_MAX_SUBCOMMANDS];
  heredoc_info_t heredocs[SHELL_DEP_MAX_HEREDOCS];
  uint32_t hcount = prescan_heredocs(cmd, cmd_len, &fast_result, heredocs,
                                     SHELL_DEP_MAX_HEREDOCS, skip_buf);
  shell_execution_map_t execution;
  shell_execution_map_build(cmd, cmd_len, &fast_result, &execution);
  /* Document parsers need the exact lexical operator/operand span, whereas
   * descriptor snapshots and command creation need a complete stage. Keep
   * those views separate, including when a document is the first fragment. */
  shell_range_t lexical_documents[SHELL_MAX_SUBCOMMANDS];
  uint32_t stage_document[SHELL_MAX_SUBCOMMANDS];
  uint32_t heredoc_count = 0;
  for (uint32_t i = 0; i < fast_result.count; i++) {
    lexical_documents[i] = fast_result.cmds[i];
    stage_document[i] = UINT32_MAX;
    if (fast_result.cmds[i].type & SHELL_TYPE_HEREDOC)
      heredoc_count++;
    /* map_build initialized every entry below this unchanged parsed count.
     * The analyzer loses that relationship between its two loop traversals. */
#ifdef __clang_analyzer__
    __attribute__((suppress))
#endif
    if (execution.owner[i] == i && execution.stage[i])
      fast_result.cmds[i] = shell_execution_range(&fast_result, &execution, i);
  }
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

  uint32_t node_range[SHELL_DEP_MAX_NODES];
  for (uint32_t i = 0; i < SHELL_DEP_MAX_NODES; i++)
    node_range[i] = UINT32_MAX;
  uint32_t range_node[SHELL_MAX_SUBCOMMANDS];
  for (uint32_t i = 0; i < SHELL_MAX_SUBCOMMANDS; i++)
    range_node[i] = UINT32_MAX;
  uint32_t node_group[SHELL_DEP_MAX_NODES];
  for (uint32_t i = 0; i < SHELL_DEP_MAX_NODES; i++)
    node_group[i] = UINT32_MAX;
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
    node_group[node_index] = i;
    shell_dep_node_t *node = &out->nodes[node_index];
    node->type = SHELL_NODE_GROUP;
    node->group.start = cmd + group->start;
    node->group.length = group->end - group->start;
    node->group.kind = group->kind;
    node->group.pipeline_negation_count = group_pipeline_negation_count(group);
    node->group.pipeline_negated = group_is_pipeline_negated(group);
    node->group.pipeline_time_mode =
        (shell_pipeline_time_mode_t)group->pipeline_time_mode;
    node->group.pipeline_time_id = 0;
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
  dep_prepare_group_execution(cmd, (uint32_t)cmd_len, &fast_result,
                              &execution.pipeline, group_exec);
  uint8_t event_static_status[DEP_EXECUTION_EVENT_CAPACITY];
  memset(event_static_status, DEP_STATUS_EITHER, sizeof(event_static_status));
  uint8_t event_body_status[DEP_EXECUTION_EVENT_CAPACITY];
  memset(event_body_status, DEP_STATUS_EITHER, sizeof(event_body_status));
  dep_expansion_status_t expansion_status[DEP_EXECUTION_EVENT_CAPACITY] = {0};
  for (uint32_t event = 0; event < DEP_EXECUTION_EVENT_CAPACITY; event++)
    memset(expansion_status[event].phase, DEP_EXPANSION_INCOMING,
           sizeof(expansion_status[event].phase));
  bool range_cd_writes[SHELL_MAX_SUBCOMMANDS] = {false};
  uint32_t owner_assignment_stop[SHELL_DEP_MAX_NODES];
  uint32_t owner_setup_stop[SHELL_DEP_MAX_NODES];
  for (uint32_t node = 0; node < SHELL_DEP_MAX_NODES; node++)
    owner_assignment_stop[node] = owner_setup_stop[node] = UINT32_MAX;
  dep_process_route_map_t process_routes = {0};
  dep_route_workspace_t *route_workspace = limits->workspace;
  streams->join = &route_workspace->import_join;
  if (depth == 0) {
    route_workspace->snapshot_table_count = 0;
    dep_route_journal_reset(&route_workspace->snapshot_journal);
    uint32_t retained = 0;
    for (uint32_t i = 0; i < observable.count; i++)
      if (observable.named_fds || observable.read[i])
        observable.fds[retained++] = observable.fds[i];
    observable.count = retained;
    qsort(observable.fds, observable.count, sizeof(observable.fds[0]),
          dep_numeric_value_compare);
    route_workspace->snapshot_journal.observable_fd_count = observable.count;
    route_workspace->snapshot_journal.observe_undo = observable.observe_undo;
    route_workspace->snapshot_journal.named_closes = observable.named_closes;
    memcpy(route_workspace->snapshot_journal.observable_fds, observable.fds,
           observable.count * sizeof(observable.fds[0]));
    route_workspace->snapshot_source_count = 0;
  }
  memset(&route_workspace->snapshot_frames[depth], 0,
         sizeof(route_workspace->snapshot_frames[depth]));
  for (uint32_t owner = 0; owner < SHELL_DEP_MAX_NODES; owner++) {
    route_workspace->snapshot_frames[depth].cached_entry[owner] = UINT32_MAX;
    route_workspace->snapshot_frames[depth].prepared_source[owner] = UINT32_MAX;
  }
  const dep_parse_context_t parse_context = {
      .cmd = cmd,
      .cmd_len = (uint32_t)cmd_len,
      .fast = &fast_result,
      .execution = &execution,
      .node_range = node_range,
      .range_node = range_node,
      .group_node = group_node,
      .node_group = node_group,
      .group_exec = group_exec,
      .event_static_status = event_static_status,
      .event_body_status = event_body_status,
      .expansion_status = expansion_status,
      .range_cd_writes = range_cd_writes,
      .owner_assignment_stop = owner_assignment_stop,
      .owner_setup_stop = owner_setup_stop,
      .effects_active = effects_active,
      .input_unit_recovery = depth == 0,
      .process_routes = &process_routes,
      .workspace = route_workspace,
      .snapshot = &route_workspace->snapshot_frames[depth],
      .resolver = resolver,
      .unresolved_paths = streams->unresolved_paths,
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

    uint16_t trailing_group = execution.pipeline.trailing_group[si];
    int32_t group = trailing_group == UINT16_MAX ? -1 : trailing_group;
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
        uint32_t source_fd = redirect_fd(operator_token, redirect);
        uint32_t target_fd = SHELL_DEP_FD_NONE;
        bool self =
            consumes_word && token + 1 < tokens.count &&
            source_fd != SHELL_DEP_FD_NAMED &&
            shell_process_classify_static_fd_target(
                tokens.tokens[token + 1].start, tokens.tokens[token + 1].len,
                &target_fd) == SHELL_PROCESS_FD_TARGET_FD &&
            source_fd == target_fd;
        if (!self)
          group_exec[group].setup_can_fail = true;
        if (consumes_word && token + 1 < tokens.count &&
            !dep_group_event_append(
                group_events, &group_event_count,
                (uint32_t)(sizeof(group_events) / sizeof(group_events[0])),
                (dep_group_redirect_event_t){
                    (uint32_t)(operator_token->start - cmd), group_node[group],
                    UINT32_MAX, DEP_GROUP_EVENT_DUP_OPERAND, redirect,
                    *operator_token, tokens.tokens[token + 1], NULL, 0}))
          out->status |= SHELL_DEP_STATUS_TRUNCATED;
        token += consumes_word && token + 1 < tokens.count ? 2 : 1;
        continue;
      }
      if (!consumes_word || token + 1 >= tokens.count) {
        token++;
        continue;
      }

      const dep_token_t *target = &tokens.tokens[token + 1];
      group_exec[group].setup_can_fail = true;
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
      /* Static operands also have setup semantics: quote removal can produce
       * an empty filename. Process every pathname at group entry, not while
       * prebuilding its syntax document. */
      if (!dep_group_event_append(
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
        cmd, execution.pipeline.group_tail[group].redirect_end,
        &fast_result.groups[group], items, sizeof(items) / sizeof(items[0]),
        &complete);
    if (count)
      group_exec[group].setup_can_fail = true;
    if (!complete)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
    for (uint32_t index = 0; index < count; index++) {
      const dep_group_herestring_t *item = &items[index];
      uint32_t document = UINT32_MAX;
      if (!add_document_read(out, max_nodes, max_edges, group_node[group],
                             SHELL_DOC_HERESTRING, NULL, 0, item->value,
                             item->value_len, item->target_fd,
                             SHELL_DEP_DOC_FLAG_NONE, &out->status, &document,
                             true)) {
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
    const shell_range_t *marker = &lexical_documents[hd->marker_idx];
    uint16_t trailing_group = execution.pipeline.trailing_group[hd->marker_idx];
    int32_t group = trailing_group == UINT16_MAX ? -1 : trailing_group;
    if (group < 0 || group_node[group] == UINT32_MAX)
      continue;
    uint32_t content_length = hd->content_end_pos - hd->content_start_pos;
    group_exec[group].setup_can_fail = true;
    const char *content = content_length ? cmd + hd->content_start_pos : NULL;
    if (content_length && content[content_length - 1] == '\n')
      content_length--;
    uint32_t document = UINT32_MAX;
    uint32_t marker_start = marker->start;
    uint32_t prefix_start = execution.pipeline.document_start[hd->marker_idx];
    uint32_t target_fd =
        inline_document_target_fd(cmd, prefix_start, marker_start);
    uint8_t flags = hd->pending.strip_tabs
                        ? SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS
                        : SHELL_DEP_DOC_FLAG_NONE;
    if (hd->literal)
      flags |= SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL;
    if (!add_document_read(out, max_nodes, max_edges, group_node[group],
                           SHELL_DOC_HEREDOC, hd->delimiter, hd->delimiter_len,
                           content, content_length, target_fd, flags,
                           &out->status, &document, true)) {
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
      inline_document_named_fd_name(cmd, prefix_start, marker_start, &fd_name,
                                    &fd_name_len);
      dep_set_named_fd(&out->edges[out->edge_count - 1], false, fd_name,
                       fd_name_len);
    }
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

  qsort(group_events, group_event_count, sizeof(group_events[0]),
        dep_group_event_compare);
  uint32_t group_event_head[SHELL_MAX_GROUPS];
  uint32_t group_event_next[SHELL_DEP_MAX_EDGES];
  uint32_t group_file_head[SHELL_MAX_GROUPS];
  uint32_t group_file_next[SHELL_DEP_MAX_EDGES];
  for (uint32_t group = 0; group < fast_result.group_count; group++) {
    group_event_head[group] = UINT32_MAX;
    group_file_head[group] = UINT32_MAX;
  }
  for (uint32_t event = group_event_count; event-- > 0;) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GROUP_EVENTS);
    uint32_t group = node_group[group_events[event].owner];
    group_event_next[event] = group_event_head[group];
    group_event_head[group] = event;
  }
  for (uint32_t edge = out->edge_count; edge-- > 0;) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GROUP_EVENTS);
    const shell_dep_edge_t *item = &out->edges[edge];
    uint32_t group = node_group[item->from], document = item->to;
    if (group == UINT32_MAX) {
      group = node_group[item->to];
      document = item->from;
    }
    if (group == UINT32_MAX || out->nodes[document].type != SHELL_NODE_DOC ||
        out->nodes[document].doc.kind != SHELL_DOC_FILE)
      continue;
    group_file_next[edge] = group_file_head[group];
    group_file_head[group] = edge;
  }
  uint32_t group_entry_cursor = 0;
  /* Redirect documents were installed above, but their operands execute at
   * group entry, after preceding commands and before the first body command.
   * A final iteration enters even a valid zero-range group. */
  for (uint32_t si = 0; si <= fast_result.count; si++) {
    uint32_t boundary =
        si < fast_result.count ? fast_result.cmds[si].start : (uint32_t)cmd_len;
    /* Parser groups are in lexical entry order (parents before children). */
    while (group_entry_cursor < fast_result.group_count &&
           fast_result.groups[group_entry_cursor].start <= boundary) {
      uint32_t group = group_entry_cursor++;
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GROUP_EVENTS);
      if (group_node[group] == UINT32_MAX)
        continue;

      dep_complete_cwd_groups(&parse_context, group_exec,
                              fast_result.groups[group].start, &cwd_offset,
                              &cwd_known, &cwd_absolute);
      uint16_t parent = fast_result.groups[group].parent;
      uint32_t *event_cwd_offset = &cwd_offset;
      bool *event_cwd_known = &cwd_known;
      bool *event_cwd_absolute = &cwd_absolute;
      if (parent != UINT16_MAX) {
        event_cwd_offset = &group_exec[parent].cwd_offset;
        event_cwd_known = &group_exec[parent].cwd_known;
        event_cwd_absolute = &group_exec[parent].cwd_absolute;
      }
      dep_cwd_begin(&parse_context, group, event_cwd_offset, event_cwd_known,
                    event_cwd_absolute);
      group_exec[group].cwd_offset = *event_cwd_offset;
      group_exec[group].cwd_known = *event_cwd_known;
      group_exec[group].cwd_absolute = *event_cwd_absolute;
      group_exec[group].entry_cwd_offset = *event_cwd_offset;
      group_exec[group].entry_cwd_known = *event_cwd_known;
      group_exec[group].entry_cwd_absolute = *event_cwd_absolute;

      /* Trailing group redirects were prebuilt before the group's execution
       * CWD was known. Capture the operand context now, before nested body
       * substitutions or descriptor-route rewrites can change edge owners. */
      for (uint32_t edge_index = group_file_head[group];
           edge_index != UINT32_MAX; edge_index = group_file_next[edge_index]) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GROUP_EVENTS);
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
      parse_context.snapshot->cwd_groups[parse_context.snapshot->cwd_depth++] =
          group;
      for (uint32_t event_index = group_event_head[group];
           event_index != UINT32_MAX;
           event_index = group_event_next[event_index]) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GROUP_EVENTS);
        const dep_group_redirect_event_t *event = &group_events[event_index];
        shell_dep_error_t event_error = SHELL_DEP_OK;
        if (event->kind == DEP_GROUP_EVENT_REDIRECT) {
          bool handled = false;
          event_error = dep_connect_redirect_process_substitution(
              out, max_nodes, max_edges, effective_cwd_buf_size, streams,
              &event->redirect_token, event->redirect, &event->target,
              event_cwd, limits, depth, &parse_context, event->owner, &handled);
          if (event_error == SHELL_DEP_OK && !handled &&
              event->document != UINT32_MAX)
            event_error = dep_resolve_word(
                out, &parse_context, &event->target, event_cwd, event->owner,
                SHELL_EXPAND_WORD_REDIRECT_PATH,
                dep_owner_phase_active(&parse_context, event->owner,
                                       DEP_SNAPSHOT_REDIRECT_OPERAND,
                                       event->position),
                event->document, NULL);
          if (event_error == SHELL_DEP_OK && !handled &&
              event->document != UINT32_MAX)
            event_error = dep_connect_word_substitutions_kind(
                out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                &event->target, event_cwd, limits, depth, &parse_context,
                event->owner, (uint32_t)(event->redirect_token.start - cmd),
                DEP_SNAPSHOT_REDIRECT_OPERAND, event->document,
                DEP_SUBST_DYNAMIC_NAME);
        } else if (event->kind == DEP_GROUP_EVENT_DUP_OPERAND) {
          if (!dep_owner_phase_active(&parse_context, event->owner,
                                      DEP_SNAPSHOT_REDIRECT_OPERAND,
                                      event->position))
            event_error = dep_inspect_skipped_operand(
                out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                &event->target, event_cwd, limits, depth, &parse_context,
                event->owner);
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
        if (event_error != SHELL_DEP_OK)
          return dep_stop_graph_construction(out, event_error);
      }
      shell_dep_error_t setup_error = dep_complete_owner_setup(
          out, streams, &parse_context, group_node[group], NULL);
      if (setup_error != SHELL_DEP_OK)
        return dep_stop_graph_construction(out, setup_error);
      /* CWD entry precedes redirect expansion; its initial body state already
       * stores the selected directory in both returning slots. A command
       * substitution may have replaced the status, but not that directory. */
      if (parse_context.snapshot->cwd_scope[group + 1].mask)
        parse_context.snapshot->cwd_scope[group + 1].mask =
            dep_expansion_status(
                &parse_context, group,
                parse_context.snapshot->cwd_scope[group + 1].mask);
      if (parse_context.snapshot->fd_stream.scope[group + 1].mask)
        parse_context.snapshot->fd_stream.scope[group + 1].mask =
            dep_expansion_status(
                &parse_context, group,
                parse_context.snapshot->fd_stream.scope[group + 1].mask);
    }
    dep_complete_cwd_groups(&parse_context, group_exec, boundary, &cwd_offset,
                            &cwd_known, &cwd_absolute);
    if (si == fast_result.count)
      break;
    /* Non-owner fragments and compound document tails are already attached to
     * their execution owner. Opaque heredoc bodies never become commands. */
    if (execution.owner[si] != si ||
        (skip_buf[si] && (!execution.stage[si] ||
                          !shell_execution_document(&lexical_documents[si]))))
      continue;
    const shell_range_t *range = &fast_result.cmds[si];
    uint32_t rstart = range->start;
    uint32_t rlen = range->len;
    if (prebuilt_group_tail[si] ||
        (shell_execution_document(&lexical_documents[si]) &&
         execution.pipeline.trailing_group[si] != UINT16_MAX))
      continue;
    int32_t cwd_group = dep_range_group(&execution.pipeline, si);
    uint32_t *range_cwd_offset = &cwd_offset;
    bool *range_cwd_known = &cwd_known;
    bool *range_cwd_absolute = &cwd_absolute;
    if (cwd_group >= 0) {
      range_cwd_offset = &group_exec[cwd_group].cwd_offset;
      range_cwd_known = &group_exec[cwd_group].cwd_known;
      range_cwd_absolute = &group_exec[cwd_group].cwd_absolute;
    }
    bool range_backgrounded = dep_range_is_backgrounded(
        &fast_result, &execution.pipeline, group_exec, si);

    /* The fast parser may end this range at the backslash of an escaped
     * physical line ending, with the following redirect range beginning after
     * LF/CRLF. That backslash is grammar, not a trailing argv word. */
    uint32_t token_length = rlen;
    uint32_t range_end = rstart + rlen;
    bool empty_timed_pipeline =
        shell_pipeline_range_is_empty_timing(cmd, range);
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

    if (empty_timed_pipeline)
      tokens = (dep_token_list_t){0};
    if (tokens.count == 0 && !empty_timed_pipeline &&
        !shell_execution_document(&lexical_documents[si]))
      continue;

    uint32_t assignment_stop;
    bool isolated_setup;
    uint32_t command =
        dep_first_command_index(&tokens, &assignment_stop, &isolated_setup);
    uint32_t effective_command = command;
    bool dynamic_command = false;
    bool exec_persistent = false;
    shell_dep_command_wrapper_t effective_wrapper = SHELL_DEP_COMMAND_DIRECT;
    const dep_token_t *effective_builtin =
        command == UINT32_MAX
            ? NULL
            : dep_effective_static_builtin(&tokens, command, &effective_command,
                                           &dynamic_command, &exec_persistent,
                                           &effective_wrapper);
    dep_exec_analysis_t exec_analysis = {0};
    if (effective_builtin && dep_token_static_equals(effective_builtin, "exec"))
      exec_analysis =
          dep_analyze_exec(&tokens, effective_command, exec_persistent);
    bool is_cd =
        effective_builtin && dep_token_static_equals(effective_builtin, "cd");
    const dep_token_t *cd_operand = NULL;
    bool cd_physical = false;
    dep_cd_target_t cd_target_kind = DEP_CD_INVALID;
    if (is_cd) {
      cd_target_kind =
          cd_target(&tokens, effective_command, &cd_operand, &cd_physical);
      range_cd_writes[si] = cd_target_kind != DEP_CD_INVALID;
    }

    /* An enclosing isolated group owns its own mutable CWD state. Only a
     * simple command that itself runs asynchronously or as a pipeline element
     * suppresses a visible current-shell transition. */
    bool cwd_isolated = execution.pipeline.local_process[execution.owner[si]];
    uint16_t successor = execution.pipeline.range_successor[si];
    bool next_conditional =
        successor == SHELL_TYPE_AND || successor == SHELL_TYPE_OR;
    uint32_t source_event = SHELL_MAX_GROUPS + si;
    expansion_status[source_event].isolated_setup =
        command == UINT32_MAX && isolated_setup;
    dep_execution_certainty_t source_execution =
        dep_event_execution(&parse_context, source_event);
    bool active = source_execution != DEP_EXECUTION_NEVER;
    dep_cwd_begin(&parse_context, source_event, range_cwd_offset,
                  range_cwd_known, range_cwd_absolute);

    uint32_t cd_next_cwd_offset = *range_cwd_offset;
    bool cd_next_cwd_known = *range_cwd_known;
    bool cd_next_cwd_absolute = *range_cwd_absolute;
    if (is_cd && active) {
      /* cd's arguments and redirects expand before it changes directory.
       * Compute the next state now, but build any graph-visible effects with
       * the incoming state below. */
      if (cd_physical && cd_target_kind != DEP_CD_INVALID)
        cd_target_kind = DEP_CD_DYNAMIC;
      if (cd_target_kind == DEP_CD_OPERAND && !cwd_isolated) {
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
        } else if (arg_buf[0] == '/' || tilde_expanded || cd_next_cwd_known) {
          if (arg_buf[0] == '/' || tilde_expanded)
            cd_next_cwd_known = true;
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
      if (next_conditional && cd_target_kind != DEP_CD_INVALID)
        cd_next_cwd_known = false;
    }

    /* Timing and process/conditional stages need a graph endpoint even when
     * plain cd commands normally collapse. Collapse is independent of entry
     * certainty; only the centralized commit may change tracked CWD. */
    if (is_cd && !limits->cd_as_cmd &&
        range->pipeline_time_mode == SHELL_PIPE_TIME_NONE && !cwd_isolated &&
        execution.pipeline.range_connector[si] != SHELL_TYPE_AND &&
        execution.pipeline.range_connector[si] != SHELL_TYPE_OR &&
        !next_conditional &&
        (range->features & (SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING)) == 0 &&
        !dep_cd_needs_graph_node(&tokens)) {
      if (cd_target_kind == DEP_CD_INVALID) {
        event_body_status[source_event] = DEP_STATUS_MAY_FAIL;
        event_static_status[source_event] = range->pipeline_negation_count & 1u
                                                ? DEP_STATUS_MAY_SUCCEED
                                                : DEP_STATUS_MAY_FAIL;
      }
      dep_cwd_finish_command(&parse_context, source_event,
                             (dep_cwd_state_t){cd_next_cwd_offset,
                                               cd_next_cwd_known,
                                               cd_next_cwd_absolute});
      continue;
    }

    /* A runtime command may resolve to `cd`, but its words and redirects
     * still expand in the incoming directory. Commit uncertainty only after
     * constructing this stage, just like a statically known cd transition. */
    bool dynamic_cwd_transition =
        dynamic_command && (!cwd_isolated || next_conditional);

    bool is_export = effective_builtin &&
                     dep_token_static_equals(effective_builtin, "export");

    if (out->node_count >= max_nodes) {
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
      return SHELL_DEP_ETRUNC;
    }

    uint32_t cmd_node_idx = out->node_count;
    shell_dep_node_t *node = &out->nodes[out->node_count++];
    node_range[cmd_node_idx] = si;
    range_node[si] = cmd_node_idx;
    node->type = SHELL_NODE_CMD;
    node->cmd.pipe_stdin_source = UINT32_MAX;
    node->cmd.pipe_stdin_target = UINT32_MAX;
    node->cmd.pipe_stdout_source = UINT32_MAX;
    node->cmd.pipe_stdout_target = UINT32_MAX;
    node->cmd.cwd_offset = *range_cwd_offset;
    node->cmd.group_depth = range->group_depth;
    node->cmd.group_kinds = range->group_kinds;
    node->cmd.backgrounded = range_backgrounded;
    node->cmd.pipeline_negation_count = range->pipeline_negation_count;
    node->cmd.pipeline_negated =
        (node->cmd.pipeline_negation_count & UINT32_C(1)) != 0;
    node->cmd.pipeline_time_mode =
        (shell_pipeline_time_mode_t)range->pipeline_time_mode;
    node->cmd.pipeline_time_id = 0;
    node->cmd.cwd_known = *range_cwd_known;
    node->cmd.cwd_absolute = node->cmd.cwd_known && *range_cwd_absolute;
    node->cmd.token_count = 0;
    node->cmd.effective_command_token = 0;
    node->cmd.effective_command_known = false;
    node->cmd.effective_command_wrapper = SHELL_DEP_COMMAND_DIRECT;
    owner_assignment_stop[cmd_node_idx] = assignment_stop;
    if (!dep_snapshot_record_owner_tokens(&parse_context, cmd_node_idx,
                                          &tokens)) {
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
      return SHELL_DEP_ETRUNC;
    }
    route_workspace
        ->snapshot_sources[parse_context.snapshot
                               ->prepared_source[cmd_node_idx]]
        .exec = exec_analysis;
    bool command_word_active = dep_owner_phase_active(
        &parse_context, cmd_node_idx, DEP_SNAPSHOT_COMMAND_WORD, range->start);
    if (tokens.count > max_tokens)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;

    bool expandable_arguments[SHELL_DEP_MAX_TOKENS];
    const shell_dep_word_value_t *argument_values[SHELL_DEP_MAX_TOKENS] = {0};
    dep_prepare_expandable_arguments(&tokens, command, effective_command,
                                     dynamic_command, effective_builtin,
                                     &exec_analysis, expandable_arguments);
    if (command != UINT32_MAX) {
      for (uint32_t word = command; word < tokens.count; word++) {
        const dep_token_t *argument = &tokens.tokens[word];
        dep_redirect_t redirect = classify_redirect(argument);
        if (redirect != DEP_REDIRECT_NONE) {
          if (shell_source_redirection_consumes_word(argument->start,
                                                     argument->len) &&
              word + 1 < tokens.count)
            word++;
          continue;
        }
        shell_dep_error_t resolution_error =
            dep_resolve_word(out, &parse_context, argument,
                             out->cwd_buf.data + *range_cwd_offset,
                             cmd_node_idx, SHELL_EXPAND_WORD_ARGUMENT,
                             command_word_active && expandable_arguments[word],
                             UINT32_MAX, &argument_values[word]);
        if (resolution_error != SHELL_DEP_OK)
          return dep_stop_graph_construction(out, resolution_error);
      }
    }

    /* Install each inline document once before expanding later redirect
     * operands. Snapshot phases still exclude these own redirects from argv
     * expansion and exclude later redirects from earlier operand expansion. */
    for (uint32_t fragment = si;
         fragment < fast_result.count && execution.owner[fragment] == si;
         fragment++) {
      const shell_range_t *document_range = &lexical_documents[fragment];
      if (!shell_execution_document(document_range))
        continue;
      uint32_t marker = document_range->start;
      const char *value = NULL, *name = NULL;
      uint32_t value_len = 0, name_len = 0;
      uint8_t flags = SHELL_DEP_DOC_FLAG_NONE;
      shell_dep_doc_kind_t kind = SHELL_DOC_HERESTRING;
      if (document_range->type == SHELL_TYPE_HERESTRING) {
        size_t after = 0;
        if (!shell_source_match_logical_punctuation(cmd, cmd_len, marker, "<<<",
                                                    &after))
          continue;
        after = shell_source_skip_inline_continuations(
            cmd, document_range->start + document_range->len, after);
        value = cmd + after;
        value_len =
            document_range->start + document_range->len - (uint32_t)after;
      } else {
        kind = SHELL_DOC_HEREDOC;
        heredoc_info_t *hd = NULL;
        for (uint32_t h = 0; h < hcount; h++)
          if (heredocs[h].marker_idx == fragment)
            hd = &heredocs[h];
        if (!hd || !hd->has_source_span || hd->document_built)
          continue;
        name = hd->delimiter;
        name_len = hd->delimiter_len;
        value = cmd + hd->content_start_pos;
        value_len = hd->content_end_pos - hd->content_start_pos;
        if (value_len != 0 && value[value_len - 1] == '\n')
          value_len--;
        if (hd->literal)
          flags |= SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL;
        if (hd->pending.strip_tabs)
          flags |= SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS;
      }
      uint32_t prefix_start = execution.pipeline.document_start[fragment];
      uint32_t fd = inline_document_target_fd(cmd, prefix_start, marker);
      /* Inline documents are absent from the owner's ordinary token list.
       * Complete the classification here, before expanding any operands. */
      if (command == UINT32_MAX && (fd == 0 || fd == SHELL_DEP_FD_NAMED))
        expansion_status[source_event].isolated_setup = true;
      if (!add_document_read(out, max_nodes, max_edges, cmd_node_idx, kind,
                             name, name_len, value, value_len, fd, flags,
                             &out->status, &stage_document[fragment],
                             active && assignment_stop == UINT32_MAX))
        continue;
      if (active && fd == SHELL_DEP_FD_NAMED && assignment_stop == UINT32_MAX) {
        const char *fd_name = NULL;
        uint32_t fd_name_len = 0;
        inline_document_named_fd_name(cmd, prefix_start, marker, &fd_name,
                                      &fd_name_len);
        dep_set_named_fd(&out->edges[out->edge_count - 1], false, fd_name,
                         fd_name_len);
      }
    }

    if (is_cd && active) {
      if (out->edge_count < max_edges)
        dep_init_edge(&out->edges[out->edge_count++], cmd_node_idx,
                      cmd_node_idx, SHELL_EDGE_CWD, SHELL_DIR_FORWARD,
                      SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
      else
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
    }

    uint32_t ti = 0;
    uint32_t document_cursor = si;
    bool readonly_assignment = assignment_stop != UINT32_MAX;

    bool found_command = false;
    while (ti < tokens.count) {
      const dep_token_t *tok = &tokens.tokens[ti];
      shell_dep_error_t document_error = dep_expand_inline_documents(
          out, max_nodes, max_edges, effective_cwd_buf_size, streams,
          out->cwd_buf.data + *range_cwd_offset, limits, depth, &parse_context,
          lexical_documents, stage_document, &document_cursor, si, cmd_node_idx,
          (uint32_t)(tok->start - cmd));
      if (document_error != SHELL_DEP_OK)
        return dep_stop_graph_construction(out, document_error);
      dep_redirect_t redir = classify_redirect(tok);

      if (redir != DEP_REDIRECT_NONE) {
        if (readonly_assignment || !active) {
          /* Keep the FILE spelling as syntax, without setup or byte flow.
           * No operand expansion or process endpoint is executed here. */
          bool consumes =
              shell_source_redirection_consumes_word(tok->start, tok->len);
          if (!active && consumes && ti + 1 < tokens.count) {
            shell_dep_error_t error = dep_inspect_skipped_operand(
                out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                &tokens.tokens[ti + 1], out->cwd_buf.data + *range_cwd_offset,
                limits, depth, &parse_context, cmd_node_idx);
            if (error != SHELL_DEP_OK)
              return dep_stop_graph_construction(out, error);
          }
          if (consumes && ti + 1 < tokens.count && redir != DEP_REDIRECT_DUP) {
            if (out->node_count == max_nodes)
              out->status |= SHELL_DEP_STATUS_TRUNCATED;
            else {
              uint32_t document = out->node_count++;
              dep_init_file_document(&out->nodes[document],
                                     tokens.tokens[ti + 1].start,
                                     tokens.tokens[ti + 1].len);
              dep_file_doc_set_cwd(out, document, node->cmd.cwd_offset,
                                   node->cmd.cwd_known, node->cmd.cwd_absolute);
            }
          }
          ti += consumes ? 2 : 1;
          continue;
        }
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
          if (process_error != SHELL_DEP_OK)
            return dep_stop_graph_construction(out, process_error);
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
          shell_dep_error_t resolution_error =
              document_added
                  ? dep_resolve_word(
                        out, &parse_context, target,
                        out->cwd_buf.data + *range_cwd_offset, cmd_node_idx,
                        SHELL_EXPAND_WORD_REDIRECT_PATH,
                        dep_owner_phase_active(&parse_context, cmd_node_idx,
                                               DEP_SNAPSHOT_REDIRECT_OPERAND,
                                               (uint32_t)(tok->start - cmd)),
                        document, NULL)
                  : SHELL_DEP_OK;
          if (resolution_error != SHELL_DEP_OK)
            return dep_stop_graph_construction(out, resolution_error);
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
          if (expansion_error != SHELL_DEP_OK)
            return dep_stop_graph_construction(out, expansion_error);
        }
        ti++;
        continue;
      }

      /* Prefix assignments can be interleaved with redirects. Use the command
       * index already established above, rather than ending assignment handling
       * at the first redirect or interpreting a later assignment as argv. */
      if (command == UINT32_MAX || ti < command) {
        shell_source_assignment_word_t assignment;
        (void)shell_source_parse_scalar_assignment_word(tok->start, tok->len,
                                                        &assignment);
        add_doc_envvar(out, max_nodes, max_edges, tok->start,
                       assignment.name_end, tok->start + assignment.equals + 1,
                       tok->len - assignment.equals - 1, assignment.append,
                       active && ti < assignment_stop, cmd_node_idx,
                       &out->status);
        if (ti > assignment_stop) {
          ti++;
          continue;
        }
        dep_token_t value = {tok->start + assignment.equals + 1,
                             tok->len - assignment.equals - 1};
        shell_dep_error_t expansion_error = dep_connect_word_substitutions(
            out, max_nodes, max_edges, effective_cwd_buf_size, streams, &value,
            out->cwd_buf.data + *range_cwd_offset, limits, depth,
            &parse_context, cmd_node_idx, (uint32_t)(tok->start - cmd),
            DEP_SNAPSHOT_ASSIGNMENT_VALUE, cmd_node_idx);
        if (expansion_error != SHELL_DEP_OK)
          return dep_stop_graph_construction(out, expansion_error);
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
        add_doc_envvar(
            out, max_nodes, max_edges, tok->start, export_assignment.name_end,
            tok->start + export_assignment.equals + 1,
            tok->len - export_assignment.equals - 1, export_assignment.append,
            active, cmd_node_idx, &out->status);
        shell_dep_error_t expansion_error = dep_connect_word_substitutions(
            out, max_nodes, max_edges, effective_cwd_buf_size, streams, tok,
            out->cwd_buf.data + *range_cwd_offset, limits, depth,
            &parse_context, cmd_node_idx, range->start,
            DEP_SNAPSHOT_COMMAND_WORD, cmd_node_idx);
        if (expansion_error != SHELL_DEP_OK)
          return dep_stop_graph_construction(out, expansion_error);
        if (node->cmd.token_count < max_tokens) {
          uint32_t idx = node->cmd.token_count++;
          node->cmd.tokens[idx] = tok->start;
          node->cmd.token_lens[idx] = tok->len;
        }
        ti++;
        continue;
      }

      shell_source_substitution_scan_t subshell_scan = {0};
      shell_source_scan_status_t subshell_status;
      dep_token_t subshell_token;
      bool had_subshell = false;
      while ((subshell_status = dep_next_word_substitution(tok, &subshell_scan,
                                                           &subshell_token)) ==
             SHELL_SOURCE_SCAN_FOUND) {
        uint8_t substitution_status = DEP_STATUS_MAY_SUCCEED;
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
                false, &file_handled, &substitution_status);
          if (file_error != SHELL_DEP_OK)
            return dep_stop_graph_construction(out, file_error);
          if (!file_handled) {
            dep_recursive_parse_t *child =
                dep_recursive_parse_prepare(limits, depth + 1);
            shell_dep_graph_t *subgraph = &child->graph;
            dep_subgraph_streams_t *subgraph_streams = &child->streams;
            dep_fd_imports_t *fd_imports = &child->streams.fd_imports;
            shell_dep_error_t snapshot_error =
                !active ? SHELL_DEP_OK
                        : dep_snapshot_fd_imports(out, streams, &parse_context,
                                                  cmd_node_idx, range->start,
                                                  DEP_SNAPSHOT_COMMAND_WORD,
                                                  fd_imports);
            if (snapshot_error != SHELL_DEP_OK)
              return dep_stop_graph_construction(out, snapshot_error);
            if (active &&
                !dep_fd_import_install_capture(
                    fd_imports, subshell_token.start[0] == '>' ? 0 : 1,
                    subshell_token.start[0] == '>' ? DEP_FD_ACCESS_READ
                                                   : DEP_FD_ACCESS_WRITE))
              return dep_stop_graph_construction(out, SHELL_DEP_ETRUNC);
            shell_dep_error_t sub_err = shell_dep_graph_parse_impl(
                sub_content, sub_len, sub_cwd_str, node->cmd.cwd_known,
                node->cmd.cwd_absolute, limits, depth + 1, NULL, subgraph,
                subgraph_streams, fd_imports, active, parse_context.resolver);
            if (sub_err != SHELL_DEP_OK)
              return dep_stop_graph_construction(out, sub_err);
            substitution_status =
                dep_substitution_status(subgraph_streams->status);
            if (subgraph->node_count > 0) {
              bool connected =
                  (active && subshell_token.start[0] != '>') ||
                  dep_append_disconnected_substitution(
                      out, max_nodes, max_edges, effective_cwd_buf_size,
                      streams, subgraph, subgraph_streams);
              if (active && subshell_token.start[0] != '>')
                connected = dep_connect_substitution(
                    out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                    subgraph, subgraph_streams, cmd_node_idx,
                    subshell_token.start[0] == '<' ? DEP_SUBST_PROCESS_WORD
                                                   : DEP_SUBST_SHELL_WORD,
                    1, NULL, NULL);
              if (!connected)
                return dep_stop_graph_construction(out, SHELL_DEP_ETRUNC);
            }
          }
        }
        if (active &&
            (subshell_token.start[0] == '$' || subshell_token.start[0] == '`'))
          dep_record_substitution_status(
              &parse_context, cmd_node_idx, DEP_SNAPSHOT_COMMAND_WORD,
              substitution_status, subshell_scan.scope.conditional);
      }

      if (subshell_status == SHELL_SOURCE_SCAN_MALFORMED) {
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
      dep_record_expansion_error(
          &parse_context, cmd_node_idx, DEP_SNAPSHOT_COMMAND_WORD,
          (subshell_scan.has_expansion_termination ? DEP_STATUS_TERMINAL_FAILURE
                                                   : 0) |
              (subshell_scan.has_expansion_abort ? DEP_STATUS_ABORT_FAILURE
                                                 : 0));

      /* Keep substitution topology above, but use the same argv and resolved
       * FILE relations as every other word. Unresolved substitution spellings
       * are not guessed to be pathname arguments. */
      if (!found_command && !had_subshell)
        found_command = true;

      if (node->cmd.token_count < max_tokens) {
        uint32_t idx = node->cmd.token_count++;
        node->cmd.tokens[idx] = tok->start;
        node->cmd.token_lens[idx] = tok->len;
      }

      if (found_command && ti > 0) {
        const shell_dep_word_value_t *value = argument_values[ti];
        if (value && value->resolved) {
          shell_netstring_iter_t iter;
          (void)shell_netstring_iter_init(&iter, value->netargv, value->length);
          shell_netstring_view_t view;
          while (shell_netstring_iter_next(&iter, &view) ==
                 SHELL_NETSTRING_OK) {
            if (!dep_bytes_look_like_path((const char *)view.payload,
                                          view.payload_length) ||
                memchr(view.payload, 0, view.payload_length))
              continue;
            if (view.payload_length > UINT32_MAX)
              return dep_stop_graph_construction(out, SHELL_DEP_ETRUNC);
            if (!dep_add_argument_document(
                    out, max_nodes, max_edges, cmd_node_idx, tok,
                    (const char *)view.payload, (uint32_t)view.payload_length,
                    &node->cmd))
              break;
          }
        } else if (!had_subshell && token_looks_like_path(tok)) {
          (void)dep_add_argument_document(out, max_nodes, max_edges,
                                          cmd_node_idx, tok, NULL, 0,
                                          &node->cmd);
        }
      }

      ti++;
    }

    shell_dep_error_t document_error = dep_expand_inline_documents(
        out, max_nodes, max_edges, effective_cwd_buf_size, streams,
        out->cwd_buf.data + *range_cwd_offset, limits, depth, &parse_context,
        lexical_documents, stage_document, &document_cursor, si, cmd_node_idx,
        UINT32_MAX);
    if (document_error != SHELL_DEP_OK)
      return dep_stop_graph_construction(out, document_error);

    const dep_token_t *execution_target = effective_builtin;
    shell_dep_command_wrapper_t execution_wrapper = effective_wrapper;
    if (exec_analysis.kind != DEP_EXEC_NONE) {
      if (exec_analysis.kind == DEP_EXEC_REPLACE) {
        execution_target = &exec_analysis.target;
        execution_wrapper = SHELL_DEP_COMMAND_EXEC;
      } else if (exec_analysis.kind == DEP_EXEC_RUNTIME) {
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

    /* Status proof is construction metadata, not a reason to rescan graph
     * edges later. Keep ordinary return outcomes distinct from expansion,
     * exit, and command-replacement outcomes that terminate this shell. */
    if (!cwd_isolated) {
      uint8_t expansion_outcomes =
          event_static_status[source_event] & DEP_STATUS_STOP;
      uint8_t outcomes =
          command == UINT32_MAX
              ? dep_null_command_status(&parse_context, source_event)
              : DEP_STATUS_EITHER;
      if (effective_builtin)
        outcomes = dep_static_command_status(effective_builtin);
      if (is_cd && cd_target_kind == DEP_CD_INVALID)
        outcomes = DEP_STATUS_MAY_FAIL;
      if (exec_analysis.kind != DEP_EXEC_NONE)
        outcomes = exec_analysis.outcomes;
      else if (effective_builtin &&
               dep_token_static_equals(effective_builtin, "exit")) {
        outcomes = dep_analyze_exit(&tokens, effective_command);
        if (outcomes & DEP_STATUS_EXIT_INCOMING) {
          uint8_t expanded = dep_expansion_status(&parse_context, source_event,
                                                  DEP_EXPANSION_INCOMING);
          outcomes =
              (outcomes & (uint8_t)~DEP_STATUS_EXIT_INCOMING) |
              ((expanded & DEP_EXPANSION_INCOMING) ? DEP_STATUS_EXIT_INCOMING
                                                   : 0) |
              ((expanded & DEP_STATUS_MAY_SUCCEED) ? DEP_STATUS_TERMINAL_SUCCESS
                                                   : 0) |
              ((expanded & DEP_STATUS_MAY_FAIL) ? DEP_STATUS_TERMINAL_FAILURE
                                                : 0);
        }
      }
      /* A readonly assignment with no executable aborts this input unit.
       * A temporary prefix assignment before an executable does not:
       * Bash can still execute that command and return its status. Assignment
       * values can expand before rejection, but this simple command's redirect
       * operands and setup are not reached after a readonly assignment fails.
       */
      if (command == UINT32_MAX && readonly_assignment)
        outcomes = DEP_STATUS_ABORT_FAILURE;
      event_body_status[source_event] = outcomes;
      /* Apply local pipeline negation after every command phase has contributed
       * its outcomes. Only returning paths are inverted; exit, replacement and
       * expansion/assignment termination retain their shell exit status. */
      if (node->cmd.pipeline_negated)
        outcomes = dep_status_negate(outcomes);
      event_static_status[source_event] = outcomes | expansion_outcomes;
    } else
      /* Pipeline/background members terminate their child, not this list. */
      event_static_status[source_event] = DEP_STATUS_EITHER;

    bool setup_may_fail;
    shell_dep_error_t setup_error = dep_complete_owner_setup(
        out, streams, &parse_context, cmd_node_idx, &setup_may_fail);
    if (setup_error != SHELL_DEP_OK)
      return dep_stop_graph_construction(out, setup_error);
    if (!cwd_isolated && setup_may_fail)
      event_static_status[source_event] |= node->cmd.pipeline_negated
                                               ? DEP_STATUS_MAY_SUCCEED
                                               : DEP_STATUS_MAY_FAIL;
    if (!cwd_isolated && owner_setup_stop[cmd_node_idx] != UINT32_MAX) {
      uint8_t failure = node->cmd.pipeline_negated ? DEP_STATUS_MAY_SUCCEED
                                                   : DEP_STATUS_MAY_FAIL;
      event_static_status[source_event] =
          failure | (event_static_status[source_event] & DEP_STATUS_STOP);
    }

    int32_t member_group = dep_range_group(&execution.pipeline, si);
    if (member_group >= 0 && group_node[member_group] != UINT32_MAX) {
      if (out->edge_count >= max_edges) {
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else {
        dep_init_edge(&out->edges[out->edge_count++], group_node[member_group],
                      cmd_node_idx, SHELL_EDGE_GROUP, SHELL_DIR_FORWARD,
                      SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
      }
    }
    bool setup_completed = owner_setup_stop[cmd_node_idx] == UINT32_MAX;
    if (is_cd && active && setup_completed) {
      *range_cwd_offset = cd_next_cwd_offset;
      *range_cwd_known = cd_next_cwd_known;
      *range_cwd_absolute = cd_next_cwd_absolute;
    }
    if (dynamic_cwd_transition && active && setup_completed)
      *range_cwd_known = false;
    dep_cwd_finish_command(&parse_context, source_event,
                           (dep_cwd_state_t){*range_cwd_offset,
                                             *range_cwd_known,
                                             *range_cwd_absolute});
  }

  dep_execution_control_edges(out, &parse_context, max_edges);

  streams->status = parse_context.snapshot->cwd_initialized
                        ? parse_context.snapshot->cwd_scope[0].mask
                        : DEP_STATUS_MAY_SUCCEED;

  /* Whitespace and comment-only input has no descriptor owners, so it has no
   * effective routes to resolve and needs no caller workspace. */
  if (out->node_count == 0)
    return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                      : SHELL_DEP_OK;

  shell_dep_error_t route_error = dep_resolve_effective_routes(
      out, cmd, (uint32_t)cmd_len, &fast_result, &execution.pipeline,
      node_range, range_node, node_group, group_node, group_exec, max_nodes,
      max_edges, streams, &streams->fd_imports, &process_routes,
      route_workspace, &parse_context);
  if (route_error != SHELL_DEP_OK)
    return dep_stop_graph_construction(out, route_error);
  return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                    : SHELL_DEP_OK;
}

/* A capacity stop can occur before the parent resolves a copied child's
 * deferred report stream. Public partial graphs must describe retained edges,
 * not a child-local promise awaiting that join. Keep the missing route explicit
 * as UNKNOWN, rather than misclassifying it as external or closed. */
static SHELL_NONNULL(1) shell_dep_error_t
    dep_finish_public_graph(shell_dep_graph_t *graph,
                            shell_dep_error_t status) {
  if (status != SHELL_DEP_ETRUNC)
    return status;
  uint32_t retained_reports[SHELL_DEP_MAX_NODES] = {0};
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
    if (graph->edges[edge].type != SHELL_EDGE_TIME)
      retained_reports[graph->edges[edge].from]++;
  }
  for (uint32_t timer = 0; timer < graph->node_count; timer++) {
    if (graph->nodes[timer].type != SHELL_NODE_TIME)
      continue;
    shell_dep_time_t *time = &graph->nodes[timer].time;
    uint32_t retained = retained_reports[timer];
    bool missing =
        (time->report_route_flags & SHELL_TIME_REPORT_ROUTE_GRAPH) &&
        (retained == 0 ||
         (time->report_route == SHELL_TIME_REPORT_MULTIPLE &&
          time->report_route_flags == SHELL_TIME_REPORT_ROUTE_GRAPH &&
          retained < 2));
    if (missing)
      time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_UNKNOWN;
    if (retained == 0)
      time->report_route_flags &= ~SHELL_TIME_REPORT_ROUTE_GRAPH;
    dep_finalize_time_report_route(graph, timer, retained);
  }
  return status;
}

/* Construction state has recursive scope lifetime; final resolution is
 * scratch. Checkpoint only pool tails, never copy or replay a parent's tables.
 * Active recursive calls follow a descriptor snapshot; inactive calls retain
 * syntax without importing executable routes. Both inherit the workspace
 * validated at root entry.
 */
static SHELL_NONNULL(1, 9, 10) shell_dep_error_t shell_dep_graph_parse_impl(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    bool initial_cwd_known, bool initial_cwd_absolute,
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams, const dep_fd_imports_t *imports,
    bool effects_active, const shell_dep_word_resolver_t *resolver) {
  if (depth == 0)
    return shell_dep_graph_parse_raw(cmd, cmd_len, initial_cwd,
                                     initial_cwd_known, initial_cwd_absolute,
                                     limits, depth, provided_fast, out, streams,
                                     imports, effects_active, resolver);
  dep_route_workspace_t *workspace = limits->workspace;
  uint32_t tables = workspace->snapshot_table_count;
  uint32_t changes = workspace->snapshot_journal.count;
  uint32_t snapshots = workspace->snapshot_journal.snapshot_count;
  uint32_t alternatives = workspace->snapshot_journal.alternative_count;
  uint32_t allocations = workspace->snapshot_journal.allocation_count;
  uint32_t sources = workspace->snapshot_source_count;
  shell_dep_error_t status = shell_dep_graph_parse_raw(
      cmd, cmd_len, initial_cwd, initial_cwd_known, initial_cwd_absolute,
      limits, depth, provided_fast, out, streams, imports, effects_active,
      resolver);
  workspace->snapshot_table_count = tables;
  dep_route_journal_rewind(&workspace->snapshot_journal, changes, snapshots,
                           alternatives, allocations);
  workspace->snapshot_source_count = sources;
  return status;
}

shell_dep_error_t shell_dep_graph_parse(const char *cmd, size_t cmd_len,
                                        const char *initial_cwd,
                                        const shell_dep_limits_t *limits,
                                        shell_dep_graph_t *out) {
  shell_source_operation_begin(cmd, cmd_len);
  dep_subgraph_streams_t streams;
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      limits, 0, NULL, out, &streams, NULL, true, NULL);
  shell_source_operation_end();
  return dep_finish_public_graph(out, status);
}

shell_dep_error_t shell_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) {
  if (!fast)
    return shell_dep_graph_parse(cmd, cmd_len, initial_cwd, limits, out);
  shell_source_operation_begin(cmd, cmd_len);
  dep_subgraph_streams_t streams;
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      limits, 0, fast, out, &streams, NULL, true, NULL);
  shell_source_operation_end();
  return dep_finish_public_graph(out, status);
}

/* --- GRAPH UTILITIES --- */

shell_dep_error_t shell_dep_graph_parse_resolved(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, shell_dep_graph_t *out,
    shell_expand_word_netargv_fn expand, void *context,
    uint8_t *unresolved_paths) {
  if (unresolved_paths)
    memset(unresolved_paths, 0, SHELL_DEP_MAX_NODES);
  size_t required;
  if (cmd_len == 0 || cmd_len > UINT32_MAX ||
      !shell_dep_resolved_workspace_size(cmd_len, limits, &required)) {
    dep_stop_graph_construction(out, SHELL_DEP_EPARSE);
    return SHELL_DEP_EINPUT;
  }
  if (!limits || !limits->workspace || limits->workspace_size < required ||
      (uintptr_t)limits->workspace % shell_dep_workspace_alignment() != 0)
    return dep_stop_graph_construction(out, SHELL_DEP_EWORKSPACE);

  shell_expand_cache_t cache;
  void *graph_workspace;
  size_t graph_workspace_size;
  if (!shell_expand_cache_init(expand, context, cmd, cmd_len, false,
                               limits->workspace, limits->workspace_size,
                               &cache, &graph_workspace, &graph_workspace_size))
    return dep_stop_graph_construction(out, SHELL_DEP_EWORKSPACE);
  shell_dep_limits_t graph_limits = *limits;
  graph_limits.workspace = graph_workspace;
  graph_limits.workspace_size = graph_workspace_size;
  shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
  shell_source_operation_begin(cmd, cmd_len);
  dep_subgraph_streams_t streams;
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      &graph_limits, 0, NULL, out, &streams, NULL, true, &resolver);
  shell_source_operation_end();
  if (cache.error != SHELL_DEP_OK)
    return dep_stop_graph_construction(out, cache.error);
  if (unresolved_paths &&
      (status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC))
    memcpy(unresolved_paths, streams.unresolved_paths, out->node_count);
  return dep_finish_public_graph(out, status);
}

shell_dep_error_t shell_dep_graph_parse_with_fast_resolver(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out, const shell_dep_word_resolver_t *resolver,
    uint8_t *unresolved_paths) {
  shell_source_operation_begin(cmd, cmd_len);
  dep_subgraph_streams_t streams;
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      limits, 0, fast, out, &streams, NULL, true, resolver);
  memset(unresolved_paths, 0, SHELL_DEP_MAX_NODES * sizeof(*unresolved_paths));
  if (status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC)
    memcpy(unresolved_paths, streams.unresolved_paths,
           out->node_count * sizeof(*unresolved_paths));
  shell_source_operation_end();
  return dep_finish_public_graph(out, status);
}

static SHELL_NONNULL(1, 2) void dep_dump_escaped_span(FILE *fp,
                                                      const char *value,
                                                      uint32_t length) {
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
      if (n->cmd.pipeline_time_mode != SHELL_PIPE_TIME_NONE) {
        fprintf(fp, " timed=%s",
                n->cmd.pipeline_time_mode == SHELL_PIPE_TIME_POSIX ? "posix"
                                                                   : "default");
        if (n->cmd.pipeline_time_id != 0)
          fprintf(fp, " time-node=%u", n->cmd.pipeline_time_id - 1);
        else
          fputs(" time-node=missing", fp);
      }
      fprintf(fp, " tokens=[");
      for (uint32_t j = 0; j < n->cmd.token_count; j++) {
        if (j > 0)
          fprintf(fp, ", ");
        fputc('"', fp);
        dep_dump_escaped_span(fp, n->cmd.tokens[j], n->cmd.token_lens[j]);
        fputc('"', fp);
      }
      fprintf(fp, "]\n");
    } else if (n->type == SHELL_NODE_GROUP) {
      fprintf(fp, "  [%u] GROUP span=\"", i);
      dep_dump_escaped_span(fp, n->group.start, n->group.length);
      fprintf(fp, "\" parent=%u", n->group.parent);
      if (n->group.pipeline_negation_count != 0)
        fprintf(fp, " negation-count=%u%s", n->group.pipeline_negation_count,
                n->group.pipeline_negated ? " negated" : "");
      if (n->group.pipeline_time_mode != SHELL_PIPE_TIME_NONE) {
        fprintf(fp, " timed=%s",
                n->group.pipeline_time_mode == SHELL_PIPE_TIME_POSIX
                    ? "posix"
                    : "default");
        if (n->group.pipeline_time_id != 0)
          fprintf(fp, " time-node=%u", n->group.pipeline_time_id - 1);
        else
          fputs(" time-node=missing", fp);
      }
      fprintf(fp, "\n");
    } else if (n->type == SHELL_NODE_ENDPOINT) {
      const char *endpoint_kind =
          n->endpoint.reserved == DEP_ENDPOINT_TERMINAL_PIPE
              ? " terminal-pipe"
              : (n->endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE
                     ? " process-substitution-pipe"
                     : "");
      fprintf(fp, "  [%u] ENDPOINT%s\n", i, endpoint_kind);
    } else if (n->type == SHELL_NODE_TIME) {
      static const char *const route_names[] = {
          "external", "graph", "closed", "unavailable", "unknown", "multiple"};
      const char *route = n->time.report_route <= SHELL_TIME_REPORT_MULTIPLE
                              ? route_names[n->time.report_route]
                              : "invalid";
      fprintf(fp, "  [%u] TIME mode=%s report-fd=%u route=%s", i,
              n->time.mode == SHELL_PIPE_TIME_POSIX ? "posix" : "default",
              n->time.report_fd, route);
      if (n->time.report_route == SHELL_TIME_REPORT_EXTERNAL)
        fprintf(fp, " target-fd=%u", n->time.report_target_fd);
      if (n->time.report_route == SHELL_TIME_REPORT_MULTIPLE) {
        fprintf(fp,
                " route-flags=%#x external-fds=", n->time.report_route_flags);
        for (uint32_t fd = 0; fd < n->time.report_external_fd_count; fd++)
          fprintf(fp, "%s%u", fd ? "," : "", n->time.report_external_fds[fd]);
      }
      fputs(" span=\"", fp);
      dep_dump_escaped_span(fp, n->time.start, n->time.length);
      fprintf(fp, "\"\n");
    } else {
      fprintf(fp, "  [%u] DOC %s", i, shell_dep_doc_kind_name(n->doc.kind));
      if (n->doc.kind == SHELL_DOC_FILE && n->doc.path) {
        fprintf(fp, " path=\"");
        dep_dump_escaped_span(fp, n->doc.path, n->doc.path_len);
        fputc('"', fp);
        if (n->doc.flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH) {
          fprintf(fp, " resolved=\"");
          dep_dump_escaped_span(fp, n->doc.value, n->doc.value_len);
          fputc('"', fp);
        } else if (n->doc.flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED) {
          fputs(" expansion-failed", fp);
        }
      } else if (n->doc.kind == SHELL_DOC_ENVVAR) {
        fprintf(fp, " name=\"");
        dep_dump_escaped_span(fp, n->doc.name, n->doc.name_len);
        fprintf(fp, "\" value=\"");
        dep_dump_escaped_span(fp, n->doc.value, n->doc.value_len);
        fputc('"', fp);
      } else if (n->doc.kind == SHELL_DOC_HEREDOC) {
        fprintf(fp, " delim=\"");
        dep_dump_escaped_span(fp, n->doc.name, n->doc.name_len);
        fprintf(fp, "\" content=\"");
        dep_dump_escaped_span(fp, n->doc.value, n->doc.value_len);
        fputc('"', fp);
      } else if (n->doc.kind == SHELL_DOC_HERESTRING && n->doc.value) {
        fprintf(fp, " content=\"");
        dep_dump_escaped_span(fp, n->doc.value, n->doc.value_len);
        fputc('"', fp);
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
static SHELL_NONNULL(1) bool dep_fd_open_edge_form_valid(
    const shell_dep_edge_t *edge, shell_dep_node_type_t from,
    shell_dep_node_type_t to) {
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

static bool dep_time_owner_valid(const shell_dep_graph_t *graph,
                                 shell_pipeline_time_mode_t mode,
                                 uint32_t time_id) {
  if (mode == SHELL_PIPE_TIME_NONE)
    return time_id == 0;
  if (time_id == 0)
    return (graph->status & SHELL_DEP_STATUS_TRUNCATED) != 0;
  uint32_t timer = time_id - 1;
  return timer < graph->node_count &&
         graph->nodes[timer].type == SHELL_NODE_TIME &&
         graph->nodes[timer].time.mode == mode;
}

typedef struct {
  bool edge_in_bounds[SHELL_DEP_MAX_EDGES];
  bool group_parent_edge[SHELL_DEP_MAX_NODES];
  uint32_t time_target[SHELL_DEP_MAX_NODES];
  uint32_t time_target_count[SHELL_DEP_MAX_NODES];
  uint32_t time_target_timer_count[SHELL_DEP_MAX_NODES];
  uint32_t time_report_flow_count[SHELL_DEP_MAX_NODES];
  bool time_topology_valid[SHELL_DEP_MAX_NODES];
  bool endpoint_input_direction[SHELL_DEP_MAX_NODES];
  bool endpoint_output_direction[SHELL_DEP_MAX_NODES];
  bool endpoint_has_producer[SHELL_DEP_MAX_NODES];
  bool endpoint_has_setup[SHELL_DEP_MAX_NODES];
  bool endpoint_has_consumer[SHELL_DEP_MAX_NODES];
  bool endpoint_topology_valid[SHELL_DEP_MAX_NODES];
  uint32_t control_head[SHELL_DEP_MAX_NODES];
  uint32_t control_next[SHELL_DEP_MAX_EDGES];
  uint32_t control_indegree[SHELL_DEP_MAX_NODES];
} dep_validation_index_t;

static bool dep_validation_control_edge(shell_dep_edge_type_t type) {
  return type == SHELL_EDGE_SEQ || type == SHELL_EDGE_AND ||
         type == SHELL_EDGE_OR || type == SHELL_EDGE_PIPE ||
         type == SHELL_EDGE_BACKGROUND || type == SHELL_EDGE_GROUP;
}

/* This is the validation boundary for caller-supplied graph contents. Build
 * topology summaries only after each edge endpoint is known to be in bounds;
 * later node validation can then consume those summaries without rescanning
 * the edge array or dereferencing an untrusted endpoint. */
static SHELL_NONNULL(1, 2) void dep_validation_index_build(
    const shell_dep_graph_t *graph, dep_validation_index_t *index) {
  memset(index, 0, sizeof(*index));
  for (uint32_t node = 0; node < graph->node_count; node++) {
    index->time_target[node] = UINT32_MAX;
    index->time_topology_valid[node] = true;
    index->endpoint_topology_valid[node] = true;
    index->control_head[node] = UINT32_MAX;
  }

  for (uint32_t edge_index = 0; edge_index < graph->edge_count; edge_index++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
    const shell_dep_edge_t *edge = &graph->edges[edge_index];
    if (edge->from >= graph->node_count || edge->to >= graph->node_count)
      continue;
    index->edge_in_bounds[edge_index] = true;

    const shell_dep_node_t *from = &graph->nodes[edge->from];
    const shell_dep_node_t *to = &graph->nodes[edge->to];
    if (edge->type == SHELL_EDGE_GROUP && to->type == SHELL_NODE_GROUP &&
        to->group.parent == edge->from && edge->dir == SHELL_DIR_FORWARD &&
        edge->flags == SHELL_DEP_EDGE_FLAG_NONE &&
        edge->source_fd == SHELL_DEP_FD_NONE &&
        edge->target_fd == SHELL_DEP_FD_NONE)
      index->group_parent_edge[edge->to] = true;

    if (from->type == SHELL_NODE_TIME) {
      if (edge->type == SHELL_EDGE_TIME) {
        index->time_target[edge->from] = edge->to;
        index->time_target_count[edge->from]++;
        if (to->type == SHELL_NODE_CMD || to->type == SHELL_NODE_GROUP)
          index->time_target_timer_count[edge->to]++;
      } else {
        bool report_flow =
            (edge->type == SHELL_EDGE_WRITE ||
             edge->type == SHELL_EDGE_APPEND || edge->type == SHELL_EDGE_PIPE ||
             edge->type == SHELL_EDGE_SUBST) &&
            edge->source_fd == from->time.report_fd;
        index->time_topology_valid[edge->from] =
            index->time_topology_valid[edge->from] && report_flow;
        index->time_report_flow_count[edge->from] += report_flow ? 1u : 0u;
      }
    }
    if (to->type == SHELL_NODE_TIME)
      index->time_topology_valid[edge->to] = false;

    if (from->type == SHELL_NODE_ENDPOINT) {
      uint32_t endpoint = edge->from;
      if (from->endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE) {
        bool setup = edge->type == SHELL_EDGE_FD_OPEN &&
                     edge->source_fd == SHELL_DEP_FD_NONE &&
                     edge->target_fd != SHELL_DEP_FD_NONE &&
                     dep_is_execution_node(graph, edge->to);
        bool flow = edge->type == SHELL_EDGE_SUBST &&
                    edge->source_fd == SHELL_DEP_FD_NONE &&
                    edge->target_fd != SHELL_DEP_FD_NAMED &&
                    edge->target_fd != SHELL_DEP_FD_NONE &&
                    dep_is_execution_node(graph, edge->to);
        index->endpoint_topology_valid[endpoint] =
            index->endpoint_topology_valid[endpoint] && (setup || flow);
        index->endpoint_input_direction[endpoint] = true;
      } else {
        bool consumer = from->endpoint.reserved == 0 &&
                        (edge->type == SHELL_EDGE_SUBST ||
                         (edge->type == SHELL_EDGE_FD_OPEN &&
                          edge->target_fd != SHELL_DEP_FD_NONE));
        index->endpoint_topology_valid[endpoint] =
            index->endpoint_topology_valid[endpoint] && consumer;
        index->endpoint_has_consumer[endpoint] =
            index->endpoint_has_consumer[endpoint] || consumer;
      }
    }
    if (to->type == SHELL_NODE_ENDPOINT) {
      uint32_t endpoint = edge->to;
      if (to->endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE) {
        bool setup = edge->type == SHELL_EDGE_FD_OPEN &&
                     edge->source_fd != SHELL_DEP_FD_NONE &&
                     edge->target_fd == SHELL_DEP_FD_NONE &&
                     dep_is_execution_node(graph, edge->from);
        bool flow = edge->type == SHELL_EDGE_WRITE &&
                    edge->source_fd != SHELL_DEP_FD_NONE &&
                    edge->source_fd != SHELL_DEP_FD_NAMED &&
                    edge->target_fd == SHELL_DEP_FD_NONE &&
                    (dep_is_execution_node(graph, edge->from) ||
                     from->type == SHELL_NODE_TIME);
        index->endpoint_topology_valid[endpoint] =
            index->endpoint_topology_valid[endpoint] && (setup || flow);
        index->endpoint_output_direction[endpoint] = true;
      } else {
        bool producer = to->endpoint.reserved == DEP_ENDPOINT_TERMINAL_PIPE
                            ? edge->type == SHELL_EDGE_PIPE
                            : edge->type == SHELL_EDGE_WRITE;
        bool setup = to->endpoint.reserved == 0 &&
                     edge->type == SHELL_EDGE_FD_OPEN &&
                     edge->source_fd != SHELL_DEP_FD_NONE;
        index->endpoint_topology_valid[endpoint] =
            index->endpoint_topology_valid[endpoint] && (producer || setup);
        index->endpoint_has_producer[endpoint] =
            index->endpoint_has_producer[endpoint] || producer;
        index->endpoint_has_setup[endpoint] =
            index->endpoint_has_setup[endpoint] || setup;
      }
    }

    if (dep_validation_control_edge(edge->type) &&
        edge->dir == SHELL_DIR_FORWARD) {
      index->control_next[edge_index] = index->control_head[edge->from];
      index->control_head[edge->from] = edge_index;
      index->control_indegree[edge->to]++;
    }
  }
}

static SHELL_NONNULL(1, 2) bool dep_validation_control_acyclic(
    const shell_dep_graph_t *graph, const dep_validation_index_t *index) {
  uint32_t indegree[SHELL_DEP_MAX_NODES];
  uint32_t queue[SHELL_DEP_MAX_NODES];
  memcpy(indegree, index->control_indegree,
         graph->node_count * sizeof(indegree[0]));
  uint32_t head = 0;
  uint32_t tail = 0;
  uint32_t visited = 0;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
    if (indegree[node] == 0)
      queue[tail++] = node;
  }
  while (head < tail) {
    uint32_t node = queue[head++];
    visited++;
    for (uint32_t edge = index->control_head[node]; edge != UINT32_MAX;
         edge = index->control_next[edge]) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
      uint32_t target = graph->edges[edge].to;
      if (--indegree[target] == 0)
        queue[tail++] = target;
    }
  }
  return visited == graph->node_count;
}

shell_dep_graph_validation_t
shell_dep_graph_validate(const shell_dep_graph_t *g) {
  shell_dep_graph_validation_t r = {0};
  r.valid = true;

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

  dep_validation_index_t index;
  dep_validation_index_build(g, &index);

  for (uint32_t i = 0;
       i < g->node_count && r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS;
       i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
    const shell_dep_node_t *n = &g->nodes[i];
    if (n->type > SHELL_NODE_TIME) {
      r.valid = false;
      snprintf(r.errors[r.error_count].msg, 96, "node %u: invalid node type %u",
               i, n->type);
      r.error_count++;
      continue;
    }
    if (n->type == SHELL_NODE_CMD) {
      if (n->cmd.token_count > SHELL_DEP_MAX_TOKENS) {
        r.valid = false;
        snprintf(r.errors[r.error_count++].msg, 96,
                 "CMD node %u: token_count %u exceeds capacity %u", i,
                 n->cmd.token_count, SHELL_DEP_MAX_TOKENS);
        continue;
      }
      if (n->cmd.pipeline_negated !=
          ((n->cmd.pipeline_negation_count & 1u) != 0)) {
        r.valid = false;
        snprintf(r.errors[r.error_count++].msg, 96,
                 "CMD node %u: inconsistent pipeline negation", i);
        if (r.error_count == SHELL_DEP_MAX_VALIDATE_ERRORS)
          continue;
      }
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
          n->cmd.pipeline_time_mode > SHELL_PIPE_TIME_POSIX) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "CMD node %u: invalid pipeline time mode %u", i,
                 (unsigned)n->cmd.pipeline_time_mode);
        r.error_count++;
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          n->cmd.pipeline_time_mode <= SHELL_PIPE_TIME_POSIX &&
          !dep_time_owner_valid(g, n->cmd.pipeline_time_mode,
                                n->cmd.pipeline_time_id)) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "CMD node %u: invalid pipeline time owner %u", i,
                 n->cmd.pipeline_time_id);
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
          SHELL_DEP_DOC_FLAG_TRANSIENT | SHELL_DEP_DOC_FLAG_ENVVAR_APPEND |
          SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
          SHELL_DEP_DOC_FLAG_EXPANSION_FAILED;
      bool spans_valid = (doc->path != NULL || doc->path_len == 0) &&
                         (doc->name != NULL || doc->name_len == 0) &&
                         (doc->value != NULL || doc->value_len == 0);
      bool kind_valid =
          doc->kind >= SHELL_DOC_FILE && doc->kind <= SHELL_DOC_ENVVAR;
      bool shape_valid = false;
      if (kind_valid) {
        switch (doc->kind) {
        case SHELL_DOC_FILE:
          shape_valid =
              doc->path != NULL && doc->path_len > 0 && doc->name == NULL &&
              doc->name_len == 0 &&
              (doc->flags & ~(SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
                              SHELL_DEP_DOC_FLAG_TRANSIENT |
                              SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
                              SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) == 0 &&
              !((doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH) &&
                (doc->flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) &&
              (!(doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)
                   ? doc->value == NULL && doc->value_len == 0
                   : doc->value != NULL && doc->value_len > 0 &&
                         !(doc->flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) &&
                         memchr(doc->value, 0, doc->value_len) == NULL);
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
      if (n->group.pipeline_negated !=
          ((n->group.pipeline_negation_count & 1u) != 0)) {
        r.valid = false;
        snprintf(r.errors[r.error_count++].msg, 96,
                 "GROUP node %u: inconsistent pipeline negation", i);
        continue;
      }
      if (n->group.pipeline_time_mode > SHELL_PIPE_TIME_POSIX) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "GROUP node %u: invalid pipeline time mode %u", i,
                 (unsigned)n->group.pipeline_time_mode);
        r.error_count++;
        continue;
      }
      if (!dep_time_owner_valid(g, n->group.pipeline_time_mode,
                                n->group.pipeline_time_id)) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "GROUP node %u: invalid pipeline time owner %u", i,
                 n->group.pipeline_time_id);
        r.error_count++;
        continue;
      }
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
        bool has_parent_edge =
            n->group.parent < g->node_count && n->group.parent != i &&
            g->nodes[n->group.parent].type == SHELL_NODE_GROUP &&
            index.group_parent_edge[i];
        if (!has_parent_edge) {
          r.valid = false;
          snprintf(r.errors[r.error_count].msg, 96,
                   "GROUP node %u: invalid parent %u or containment edge", i,
                   n->group.parent);
          r.error_count++;
        }
      }
    } else if (n->type == SHELL_NODE_TIME) {
      uint32_t target = index.time_target[i];
      uint32_t target_count = index.time_target_count[i];
      uint32_t report_flow_count = index.time_report_flow_count[i];
      bool topology_valid = index.time_topology_valid[i];
      shell_pipeline_time_mode_t target_mode = SHELL_PIPE_TIME_NONE;
      bool target_valid = target < g->node_count;
      if (target_valid && g->nodes[target].type == SHELL_NODE_CMD)
        target_mode = g->nodes[target].cmd.pipeline_time_mode;
      else if (target_valid && g->nodes[target].type == SHELL_NODE_GROUP)
        target_mode = g->nodes[target].group.pipeline_time_mode;
      else
        target_valid = false;
      uint32_t target_timer_count =
          target_valid ? index.time_target_timer_count[target] : 0;
      bool empty_pipeline = n->time.length == 0 && target_valid &&
                            g->nodes[target].type == SHELL_NODE_CMD &&
                            g->nodes[target].cmd.token_count == 0;
      uint32_t target_time_id = 0;
      if (target_valid && g->nodes[target].type == SHELL_NODE_CMD)
        target_time_id = g->nodes[target].cmd.pipeline_time_id;
      else if (target_valid && g->nodes[target].type == SHELL_NODE_GROUP)
        target_time_id = g->nodes[target].group.pipeline_time_id;
      bool report_route_valid = false;
      if (n->time.report_external_fd_count > SHELL_DEP_TIME_MAX_EXTERNAL_FDS) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "TIME node %u: too many external report descriptors", i);
        r.error_count++;
        continue;
      }
      bool has_external = n->time.report_external_fd_count != 0;
      bool has_graph = report_flow_count != 0;
      bool has_closed =
          (n->time.report_route_flags & SHELL_TIME_REPORT_ROUTE_CLOSED) != 0;
      bool has_unavailable = (n->time.report_route_flags &
                              SHELL_TIME_REPORT_ROUTE_UNAVAILABLE) != 0;
      bool has_unknown =
          (n->time.report_route_flags & SHELL_TIME_REPORT_ROUTE_UNKNOWN) != 0;
      uint32_t expected_flags =
          (has_external ? SHELL_TIME_REPORT_ROUTE_EXTERNAL : 0) |
          (has_graph ? SHELL_TIME_REPORT_ROUTE_GRAPH : 0) |
          (has_closed ? SHELL_TIME_REPORT_ROUTE_CLOSED : 0) |
          (has_unavailable ? SHELL_TIME_REPORT_ROUTE_UNAVAILABLE : 0) |
          (has_unknown ? SHELL_TIME_REPORT_ROUTE_UNKNOWN : 0);
      bool report_flags_valid =
          n->time.report_route_flags == expected_flags &&
          (!has_unknown || (g->status & SHELL_DEP_STATUS_TRUNCATED) != 0);
      for (uint32_t fd = 0; fd < n->time.report_external_fd_count; fd++) {
        report_flags_valid =
            report_flags_valid &&
            n->time.report_external_fds[fd] <= SHELL_DEP_FD_MAX;
        for (uint32_t prior = 0; prior < fd; prior++)
          report_flags_valid =
              report_flags_valid && n->time.report_external_fds[prior] !=
                                        n->time.report_external_fds[fd];
      }
      switch (n->time.report_route) {
      case SHELL_TIME_REPORT_EXTERNAL:
        report_route_valid =
            report_flow_count == 0 &&
            n->time.report_target_fd <= SHELL_DEP_FD_MAX &&
            n->time.report_external_fd_count == 1 &&
            n->time.report_external_fds[0] == n->time.report_target_fd &&
            n->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_EXTERNAL;
        break;
      case SHELL_TIME_REPORT_GRAPH:
        report_route_valid =
            report_flow_count == 1 &&
            n->time.report_target_fd == SHELL_DEP_FD_NONE &&
            n->time.report_external_fd_count == 0 &&
            n->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_GRAPH;
        break;
      case SHELL_TIME_REPORT_CLOSED:
        report_route_valid =
            report_flow_count == 0 &&
            n->time.report_target_fd == SHELL_DEP_FD_NONE &&
            n->time.report_external_fd_count == 0 &&
            n->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_CLOSED;
        break;
      case SHELL_TIME_REPORT_UNAVAILABLE:
        report_route_valid =
            report_flow_count == 0 &&
            n->time.report_target_fd == SHELL_DEP_FD_NONE &&
            n->time.report_external_fd_count == 0 &&
            n->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_UNAVAILABLE;
        break;
      case SHELL_TIME_REPORT_UNKNOWN:
        report_route_valid =
            report_flow_count == 0 &&
            n->time.report_target_fd == SHELL_DEP_FD_NONE &&
            n->time.report_external_fd_count == 0 &&
            n->time.report_route_flags == SHELL_TIME_REPORT_ROUTE_UNKNOWN &&
            (g->status & SHELL_DEP_STATUS_TRUNCATED) != 0;
        break;
      case SHELL_TIME_REPORT_MULTIPLE:
        report_route_valid =
            report_flow_count + n->time.report_external_fd_count +
                    (has_closed ? 1u : 0u) + (has_unavailable ? 1u : 0u) +
                    (has_unknown ? 1u : 0u) >=
                2 &&
            n->time.report_target_fd == SHELL_DEP_FD_NONE;
        break;
      default:
        report_route_valid = false;
        break;
      }
      if (!n->time.start || (n->time.length == 0 && !empty_pipeline) ||
          n->time.mode < SHELL_PIPE_TIME_DEFAULT ||
          n->time.mode > SHELL_PIPE_TIME_POSIX || n->time.report_fd != 2 ||
          !report_route_valid || !report_flags_valid || !topology_valid ||
          target_count != 1 || !target_valid || target_mode != n->time.mode ||
          target_timer_count != 1 || target_time_id != i + 1) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "TIME node %u: invalid mode, span, report fd, or target", i);
        r.error_count++;
      }
    } else if (n->type == SHELL_NODE_ENDPOINT) {
      if (n->endpoint.reserved != 0 &&
          n->endpoint.reserved != DEP_ENDPOINT_TERMINAL_PIPE &&
          n->endpoint.reserved != DEP_ENDPOINT_PROCESS_PIPE) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "ENDPOINT node %u: unknown endpoint flags %u", i,
                 n->endpoint.reserved);
        r.error_count++;
        continue;
      }
      if (n->endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE) {
        bool input_direction = index.endpoint_input_direction[i];
        bool output_direction = index.endpoint_output_direction[i];
        bool topology_valid = index.endpoint_topology_valid[i];
        if (!topology_valid || (!input_direction && !output_direction)) {
          r.valid = false;
          snprintf(r.errors[r.error_count].msg, 96,
                   "ENDPOINT node %u: invalid process-pipe "
                   "topology",
                   i);
          r.error_count++;
        }
        continue;
      }
      bool has_producer = index.endpoint_has_producer[i];
      bool has_setup = index.endpoint_has_setup[i];
      bool has_consumer = index.endpoint_has_consumer[i];
      bool topology_valid = index.endpoint_topology_valid[i];
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
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
    const shell_dep_edge_t *e = &g->edges[i];

    if (!index.edge_in_bounds[i]) {
      r.valid = false;
      r.errors[r.error_count].edge_idx = i;
      snprintf(r.errors[r.error_count].msg, 96, "OOB: from=%u to=%u nodes=%u",
               e->from, e->to, g->node_count);
      r.error_count++;
      continue;
    }

    if (e->type > SHELL_EDGE_TIME || e->dir > SHELL_DIR_UNDIR) {
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
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP ||
            ft == SHELL_NODE_TIME) &&
           (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP ||
            (tt == SHELL_NODE_ENDPOINT && g->nodes[e->to].endpoint.reserved ==
                                              DEP_ENDPOINT_TERMINAL_PIPE)) &&
           e->source_fd != SHELL_DEP_FD_NONE &&
           e->target_fd != SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_SUBST:
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP ||
            ft == SHELL_NODE_ENDPOINT || ft == SHELL_NODE_TIME ||
            (ft == SHELL_NODE_DOC &&
             g->nodes[e->from].doc.kind == SHELL_DOC_FILE)) &&
           (((ft == SHELL_NODE_ENDPOINT || ft == SHELL_NODE_DOC) &&
             e->source_fd == SHELL_DEP_FD_NONE) ||
            ((ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP ||
              ft == SHELL_NODE_TIME) &&
             e->source_fd != SHELL_DEP_FD_NONE));
      if ((e->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) {
        /* Resolution removes name uncertainty, not the filename-selection
         * dependency. A failed open also retains expansions reached first. */
        ok = ok && tt == SHELL_NODE_DOC &&
             g->nodes[e->to].doc.kind == SHELL_DOC_FILE &&
             (g->nodes[e->to].doc.flags &
              (SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
               SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
               SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) != 0 &&
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
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP ||
            ft == SHELL_NODE_TIME) &&
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
    case SHELL_EDGE_TIME:
      ok = ft == SHELL_NODE_TIME &&
           (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP) &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE &&
           e->flags == SHELL_DEP_EDGE_FLAG_NONE && e->dir == SHELL_DIR_FORWARD;
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

  if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
      !dep_validation_control_acyclic(g, &index)) {
    r.valid = false;
    snprintf(r.errors[r.error_count].msg, 96,
             "control topology contains a cycle");
    r.error_count++;
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
  case SHELL_DEP_EEXPAND:
    return "Word resolution failed";
  default:
    return "Unknown error";
  }
}
