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
#include "shell_source_scan_work_internal.h"
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
/* Count persistent-map structural steps (shell_pmap_internal.h). */
#define SHELL_PMAP_WORK()                                                      \
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_MAP_STEPS)
#endif
#include "shell_arithmetic_internal.h"
#include "shell_ascii.h"
#include "shell_avl_index_internal.h"
#include "shell_builtin_internal.h"
#include "shell_conditional_internal.h"
#include "shell_depgraph_internal.h"
#include "shell_fd_occupancy_internal.h"
#include "shell_netstring.h"
#include "shell_pipeline_internal.h"
#include "shell_pmap_internal.h"
#include "shell_processor.h"
#include "shell_processor_internal.h"
#include "shell_semantics_internal.h"
#include "shell_source_admission_internal.h"
#include "shell_source_internal.h"
#include "shell_test_internal.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include "shell_word_internal.h"
#include <limits.h>
#include <stdarg.h>
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
    "READ", "WRITE",      "APPEND",       "PIPE",      "ARG",
    "ENV",  "SUBST",      "SEQ",          "AND",       "OR",
    "CWD",  "BACKGROUND", "GROUP",        "FD_OPEN",   "FD_CLOSE",
    "TIME", "FILE_TEST",  "FILE_COMPARE", "FILE_LEFT", "FILE_RIGHT",
};

static const char *dep_node_names[] = {
    "CMD", "DOC", "GROUP", "ENDPOINT", "TIME", "FD", "FILE_COMPARISON",
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
  if (doc->flags & SHELL_DEP_DOC_FLAG_IMPLICIT)
    return doc->kind == SHELL_DOC_FILE &&
           doc->flags == SHELL_DEP_DOC_FLAG_IMPLICIT && doc->value == NULL &&
           doc->value_len == 0;
  return (doc->value != NULL || doc->value_len == 0) &&
         (doc->flags &
          ~(SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
            SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
            SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL | SHELL_DEP_DOC_FLAG_TRANSIENT |
            SHELL_DEP_DOC_FLAG_ENVVAR_APPEND |
            SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
            SHELL_DEP_DOC_FLAG_EXPANSION_FAILED |
            SHELL_DEP_DOC_FLAG_IMPLICIT)) == 0;
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

  if (doc->kind == SHELL_DOC_ENVVAR && !doc->value) {
    *name_length = doc->name_len;
    return true;
  }
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
  if (doc->kind == SHELL_DOC_ENVVAR && !doc->value) {
    memcpy(destination, doc->name, needed);
    *written = needed;
    return true;
  }
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
  if (doc->kind == SHELL_DOC_ENVVAR && !doc->value)
    return doc->name_len == name_length &&
           (!name_length || !memcmp(doc->name, name, name_length));
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
  unsigned char first;
} dep_file_identity_measure_t;

static bool dep_file_identity_byte(unsigned char byte, size_t position,
                                   void *context) {
  dep_file_identity_measure_t *measure = context;
  if (position == 0)
    measure->first = byte;
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

static SHELL_NONNULL(1, 2, 3, 4) void dep_file_identity_finish(
    const shell_dep_doc_t *doc, const dep_file_identity_layout_t *layout,
    char *destination, shell_dep_file_identity_t *identity) {
  if (!layout->path_absolute) {
    memcpy(destination, layout->cwd, layout->cwd_len);
    destination[layout->cwd_len] = '/';
  }
  destination[layout->combined_len] = '\0';
  /* Normalization drops a trailing separator and a terminal `.` component,
   * so record that the lookup required a directory before they disappear.
   * The payload is nonempty, so the combined path has a last byte. */
  unsigned char last = (unsigned char)destination[layout->combined_len - 1];
  unsigned char previous =
      layout->combined_len > 1
          ? (unsigned char)destination[layout->combined_len - 2]
          : 0;
  identity->requires_directory =
      last == '/' || (last == '.' && previous == '/');
  identity->length =
      dep_normalize_path(destination, (uint32_t)layout->combined_len, false);
  identity->absolute = layout->path_absolute || doc->cwd_absolute;
}

bool shell_dep_doc_file_identity_from_decoded(
    const shell_dep_graph_t *graph, const shell_dep_doc_t *doc,
    const char *decoded, size_t length, char *destination, size_t capacity,
    shell_dep_file_identity_t *identity) {
  *identity = (shell_dep_file_identity_t){0};
  dep_file_identity_layout_t layout;
  if (!dep_file_identity_plan(graph, doc, (unsigned char)decoded[0], length,
                              capacity, &layout))
    return false;
  /* Copy the payload first: it may already occupy destination, before the
   * recorded CWD prefix is inserted. */
  memmove(destination + layout.prefix_len, decoded, length);
  dep_file_identity_finish(doc, &layout, destination, identity);
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
                                       size_t destination_size,
                                       shell_dep_file_identity_t *identity) {
  *identity = (shell_dep_file_identity_t){0};
  if ((doc->kind != SHELL_DOC_FILE) || (!doc->path))
    return false;
  if (doc->flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)
    return false;
  if (doc->flags & SHELL_DEP_DOC_FLAG_IMPLICIT)
    return shell_dep_doc_file_identity_from_decoded(graph, doc, doc->path,
                                                    doc->path_len, destination,
                                                    destination_size, identity);
  if (doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH) {
    return shell_dep_doc_file_identity_from_decoded(graph, doc, doc->value,
                                                    doc->value_len, destination,
                                                    destination_size, identity);
  }
  if (doc->flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME)
    return false;
  dep_file_identity_measure_t measure = {0};
  size_t path_len = 0;
  if (shell_process_visit_word_value(doc->path, doc->path_len,
                                     dep_file_identity_byte, &measure,
                                     &path_len) != SHELL_PROCESS_OK ||
      path_len == 0)
    return false;
  dep_file_identity_layout_t layout;
  if (!dep_file_identity_plan(graph, doc, measure.first, path_len,
                              destination_size, &layout))
    return false;
  /* The measure pass validated the immutable word. Write it without another
   * measure pass, preserving destination atomicity on every failure above. */
  size_t decoded_len = 0;
  (void)shell_process_visit_word_value(
      doc->path, doc->path_len, dep_file_identity_write_byte,
      destination + layout.prefix_len, &decoded_len);
  dep_file_identity_finish(doc, &layout, destination, identity);
  return true;
}

/* current_offset references an installed pool entry. rel is a decoded nonempty
 * static path; relative targets require a known incoming directory.
 * effective_size is the validated pool bound. */
static SHELL_NONNULL(1, 3, 5) uint32_t
    cwd_resolve_dedup(shell_dep_graph_t *g, uint32_t current_offset,
                      const char *rel, uint32_t effective_size,
                      uint32_t *status) {
  char temp_path[SHELL_DEP_CWD_BUF_SIZE];
  size_t rel_len = strlen(rel);

  if (rel[0] == '/') {
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
  /* `2>(cmd)` is one word holding a process substitution (`echo 2>(:)` prints
   * `2/dev/fd/63`), not a descriptor redirect whose operand is `(cmd)`. */
  if (shell_source_process_substitution_open(cmd, end, cursor, NULL))
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
    size_t pid_after = 0;
    if (shell_source_skip_pid_parameter(cmd, end, pos, &pid_after)) {
      pos = (uint32_t)pid_after;
      continue;
    }
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
      pos += 2;
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
    if (shell_source_space((unsigned char)c) || c == '|' || c == ';' ||
        c == '&' || c == '<' || c == '>')
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
  /* Until a command word appears, a `NAME[...]` word keeps its subscript: the
   * blanks and operators inside it do not split the word. */
  bool command_word_seen = false;
  /* Bash stops reading it whole once a redirect follows an assignment word. */
  bool assignment_seen = false, subscript_blocked = false;
  /* The previous token was a `>&` or `<&` operator waiting for its operand. */
  bool duplication_operand_pending = false;

  while (pos < end && out->count < SHELL_DEP_MAX_TOKENS) {
    bool plain_word = false;
    while (pos < end) {
      size_t continued = shell_source_skip_escaped_line_endings(cmd, end, pos);
      if (continued != pos) {
        pos = (uint32_t)continued;
        continue;
      }
      if (!shell_source_space((unsigned char)cmd[pos]))
        break;
      pos++;
    }
    if (pos >= end)
      break;

    if (out->count == 0 && cmd[pos] == '(') {
      size_t content, expression_end, after;
      if (shell_source_arithmetic_command(cmd, end, pos, &content,
                                          &expression_end, &after) ==
          SHELL_ARITHMETIC_FRAME_COMPLETE) {
        pos = (uint32_t)after;
        continue;
      }
    }
    if (out->count == 0 && cmd[pos] == '[') {
      shell_conditional_t condition = shell_conditional_parse(cmd, end, pos);
      if (condition.frame == SHELL_CONDITIONAL_COMPLETE) {
        pos = (uint32_t)condition.after;
        continue;
      }
    }
    uint32_t tok_start = pos;
    /* The word after `>&` is its NUMBER operand even when a redirect operator
     * touches it: `2>&1>f` is `2>&1` and `>f`, so `1` is not the descriptor
     * prefix of a `1>` redirect. */
    bool duplication_operand = false;
    if (duplication_operand_pending) {
      size_t digits_after = 0;
      uint32_t digits_fd = 0;
      shell_source_io_number_t digits = shell_source_parse_io_number(
          cmd, pos, end, &digits_after, &digits_fd);
      duplication_operand = digits != SHELL_SOURCE_IO_NUMBER_NONE &&
                            digits != SHELL_SOURCE_IO_NUMBER_OVERFLOW;
      duplication_operand_pending = false;
    }
    uint32_t redirect_end =
        duplication_operand ? pos : scan_redirect_token(cmd, pos, end);
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
    if (!duplication_operand &&
        numeric_prefix != SHELL_SOURCE_IO_NUMBER_OVERFLOW &&
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
      subscript_blocked |= assignment_seen;
      pos = redirect_end;
      /* `>&-` closes and takes no operand, so only a final `&` waits. */
      size_t operator_end = shell_source_skip_escaped_line_endings_backward(
          cmd + tok_start, pos - tok_start, pos - tok_start);
      if (operator_end > 1 && cmd[tok_start + operator_end - 1] == '&') {
        size_t before = shell_source_skip_escaped_line_endings_backward(
            cmd + tok_start, pos - tok_start, operator_end - 1);
        duplication_operand_pending =
            before > 0 && (cmd[tok_start + before - 1] == '>' ||
                           cmd[tok_start + before - 1] == '<');
      }
      uint32_t target = pos;
      while (target < end) {
        size_t target_continued =
            shell_source_skip_escaped_line_endings(cmd, end, target);
        if (target_continued != target) {
          target = (uint32_t)target_continued;
          continue;
        }
        if (!shell_source_space((unsigned char)cmd[target]))
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
      plain_word = true;
      size_t subscript_open = 0, subscript_after = 0;
      if (!command_word_seen && !subscript_blocked &&
          shell_source_word_subscript(cmd, end, pos, &subscript_open,
                                      &subscript_after))
        pos = (uint32_t)subscript_after;
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
      shell_source_assignment_word_t assignment;
      if (plain_word) {
        if (shell_source_parse_scalar_assignment_word(
                cmd + tok_start, end - tok_start, &assignment))
          assignment_seen = true;
        else
          command_word_seen = true;
      }
    }
  }
  while (pos < end && shell_source_space((unsigned char)cmd[pos]))
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

/* Redirects and wholly elided words are not builtin arguments. tokens is a
 * prepared command and index names one of its tokens. */
static SHELL_NONNULL(1, 2) bool dep_skip_nonargument(
    const dep_token_list_t *tokens, uint32_t *index) {
  const dep_token_t *word = &tokens->tokens[*index];
  if (shell_source_word_is_elided(word->start, word->len))
    return true;
  if (classify_redirect(word) == DEP_REDIRECT_NONE)
    return false;
  if (shell_source_redirection_consumes_word(word->start, word->len) &&
      *index + 1 < tokens->count)
    (*index)++;
  return true;
}

/* A decoded static word: its length, first bytes and last bytes. Words of
 * interest (option bundles, long options, interpreter names) need no more. */
enum { DEP_WORD_HEAD = 32, DEP_WORD_TAIL = 8 };
typedef struct {
  char head[DEP_WORD_HEAD];
  char tail[DEP_WORD_TAIL];
  size_t length;
} dep_static_word_t;

static SHELL_NONNULL(3) bool dep_static_word_byte(unsigned char byte,
                                                  size_t position,
                                                  void *context) {
  dep_static_word_t *word = context;
  if (position < DEP_WORD_HEAD)
    word->head[position] = (char)byte;
  memmove(word->tail, word->tail + 1, DEP_WORD_TAIL - 1);
  word->tail[DEP_WORD_TAIL - 1] = (char)byte;
  word->length = position + 1;
  return true;
}

/* Decode tok when it is static; false for a dynamic word. */
static SHELL_NONNULL(1, 2) bool dep_static_word(const dep_token_t *tok,
                                                dep_static_word_t *word) {
  *word = (dep_static_word_t){0};
  size_t length = 0;
  return shell_visit_static_word(tok->start, tok->len, dep_static_word_byte,
                                 word, &length);
}

/* Whether word is exactly text, decoded. */
static SHELL_NONNULL(1,
                     2) bool dep_static_word_is(const dep_static_word_t *word,
                                                const char *text) {
  size_t length = strlen(text);
  return word->length == length && length <= DEP_WORD_HEAD &&
         !memcmp(word->head, text, length);
}

/* Whether word's last path component is name. */
static SHELL_NONNULL(1, 2) bool dep_static_word_names(
    const dep_static_word_t *word, const char *name) {
  size_t length = strlen(name);
  if (word->length < length || length >= DEP_WORD_TAIL)
    return false;
  const char *end = word->tail + DEP_WORD_TAIL;
  return !memcmp(end - length, name, length) &&
         (word->length == length || end[-(ptrdiff_t)length - 1] == '/');
}

/* The reference Bash's invocation grammar for the executed command at index
 * command of tokens (see shell_dep_stdin_code_t). Long options precede any
 * short option; in a short bundle `o` and `O` take the next word, `c` selects
 * a command string; `-` or `--` end options. Option errors make Bash exit
 * before reading. */
static SHELL_NONNULL(1) shell_dep_stdin_code_t
    dep_bash_stdin_code(const dep_token_list_t *tokens, uint32_t command) {
  bool longs = true, command_string = false, stdin_flag = false,
       parse_only = false;
  uint32_t i = command + 1;
  for (; i < tokens->count; i++) {
    if (dep_skip_nonargument(tokens, &i))
      continue;
    dep_static_word_t word;
    if (!dep_static_word(&tokens->tokens[i], &word))
      return command_string ? SHELL_DEP_STDIN_CODE_NONE
                            : SHELL_DEP_STDIN_CODE_UNKNOWN;
    if (dep_static_word_is(&word, "-") || dep_static_word_is(&word, "--")) {
      i++;
      break;
    }
    if (word.length < 2 || (word.head[0] != '-' && word.head[0] != '+'))
      break;
    if (word.length > DEP_WORD_HEAD)
      return SHELL_DEP_STDIN_CODE_UNKNOWN;
    if (word.head[0] == '-' && word.head[1] == '-') {
      static const char *const plain[] = {
          "--debug", "--debugger", "--login",      "--noediting", "--noprofile",
          "--norc",  "--posix",    "--restricted", "--verbose"};
      static const char *const quiet[] = {"--dump-po-strings", "--dump-strings",
                                          "--pretty-print"};
      bool known = false;
      for (size_t k = 0; longs && k < sizeof(plain) / sizeof(plain[0]); k++)
        known |= dep_static_word_is(&word, plain[k]);
      for (size_t k = 0; longs && k < sizeof(quiet) / sizeof(quiet[0]); k++)
        if (dep_static_word_is(&word, quiet[k]))
          known = parse_only = true;
      if (longs && (dep_static_word_is(&word, "--rcfile") ||
                    dep_static_word_is(&word, "--init-file"))) {
        uint32_t operand = i + 1;
        while (operand < tokens->count &&
               dep_skip_nonargument(tokens, &operand))
          operand++;
        if (operand >= tokens->count)
          return SHELL_DEP_STDIN_CODE_NONE;
        i = operand;
        continue;
      }
      /* --help and --version exit; any other is an invalid option. */
      if (!known)
        return SHELL_DEP_STDIN_CODE_NONE;
      continue;
    }
    longs = false;
    bool minus = word.head[0] == '-';
    for (size_t k = 1; k < word.length; k++) {
      char letter = word.head[k];
      if (letter == 'c')
        command_string = true;
      else if (letter == 's')
        stdin_flag |= minus;
      else if (letter == 'n' || letter == 'D')
        parse_only |= minus;
      else if (letter == 'o' || letter == 'O') {
        /* The next word is the option name; without one, Bash lists. */
        uint32_t operand = i + 1;
        while (operand < tokens->count &&
               dep_skip_nonargument(tokens, &operand))
          operand++;
        if (operand < tokens->count)
          i = operand;
      } else if (!memchr("ilrabefhkmptuvxBCEHPT", letter, 21))
        return SHELL_DEP_STDIN_CODE_NONE;
    }
  }
  if (command_string)
    return SHELL_DEP_STDIN_CODE_NONE;
  bool operand = false;
  for (; !stdin_flag && i < tokens->count; i++) {
    if (dep_skip_nonargument(tokens, &i))
      continue;
    dep_static_word_t word;
    /* A dynamic operand may expand to no word at all. */
    if (!dep_static_word(&tokens->tokens[i], &word))
      return SHELL_DEP_STDIN_CODE_UNKNOWN;
    operand = true;
    break;
  }
  if (operand)
    return SHELL_DEP_STDIN_CODE_NONE;
  return parse_only ? SHELL_DEP_STDIN_CODE_PARSES
                    : SHELL_DEP_STDIN_CODE_EXECUTES;
}

/* The stdin-code fact for a simple command whose executed target is
 * tokens[command] (UINT32_MAX for none), or dynamic. */
static SHELL_NONNULL(1) shell_dep_stdin_code_t
    dep_stdin_code(const dep_token_list_t *tokens, uint32_t command,
                   bool dynamic) {
  if (dynamic)
    return SHELL_DEP_STDIN_CODE_UNKNOWN;
  if (command == UINT32_MAX)
    return SHELL_DEP_STDIN_CODE_NONE;
  dep_static_word_t name;
  if (!dep_static_word(&tokens->tokens[command], &name))
    return SHELL_DEP_STDIN_CODE_UNKNOWN;
  if (dep_static_word_names(&name, "bash") ||
      dep_static_word_names(&name, "rbash"))
    return dep_bash_stdin_code(tokens, command);
  /* Other shell interpreters are not modeled. */
  static const char *const shells[] = {"sh",   "dash", "ash",  "ksh",
                                       "mksh", "zsh",  "yash", "posh",
                                       "fish", "csh",  "tcsh", "busybox"};
  for (size_t i = 0; i < sizeof(shells) / sizeof(shells[0]); i++)
    if (dep_static_word_names(&name, shells[i]))
      return SHELL_DEP_STDIN_CODE_UNKNOWN;
  return SHELL_DEP_STDIN_CODE_NONE;
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
    if (dep_skip_nonargument(tokens, &i))
      continue;

    const dep_token_t *token = &tokens->tokens[i];
    /* `cd -` takes no further argument. A following word only proves the
     * failure if it must survive expansion; an unquoted expansion or a
     * quoted list selector can disappear and leave a valid `cd -`. */
    if (dynamic)
      return ambiguous || !shell_builtin_word_guarantees_argument(token->start,
                                                                  token->len)
                 ? DEP_CD_DYNAMIC
                 : DEP_CD_INVALID;
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
 * Keep the first readonly rejection independent of argv presence: all later
 * argument words participate in the proof that the prefix is temporary.
 */
_Static_assert(SHELL_DEP_MAX_TOKENS <= 64,
               "prefix rejection bits cover every prepared token");

enum { DEP_ARGV_EMPTY = 1u, DEP_ARGV_PRESENT = 2u };

static SHELL_NONNULL(1, 2, 3, 4, 5) uint32_t
    dep_first_command_index(const dep_token_list_t *tokens,
                            uint32_t *assignment_stop, bool *isolated_setup,
                            uint64_t *rejected_assignments,
                            uint8_t *argv_presence) {
  *assignment_stop = UINT32_MAX;
  *isolated_setup = false;
  *rejected_assignments = 0;
  *argv_presence = DEP_ARGV_EMPTY;
  uint32_t command = UINT32_MAX;
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
    if (command != UINT32_MAX) {
      if (*argv_presence != DEP_ARGV_PRESENT) {
        if (shell_builtin_word_guarantees_argument(tokens->tokens[i].start,
                                                   tokens->tokens[i].len))
          *argv_presence = DEP_ARGV_PRESENT;
        else if (!shell_source_word_is_elided(tokens->tokens[i].start,
                                              tokens->tokens[i].len))
          *argv_presence |= DEP_ARGV_PRESENT;
      }
      continue;
    }
    shell_source_assignment_word_t assignment;
    const dep_token_t *word = &tokens->tokens[i];
    if (!shell_source_parse_scalar_assignment_word(word->start, word->len,
                                                   &assignment)) {
      command = i;
      *argv_presence =
          shell_builtin_word_guarantees_argument(word->start, word->len)
              ? DEP_ARGV_PRESENT
          : shell_source_word_is_elided(word->start, word->len)
              ? DEP_ARGV_EMPTY
              : DEP_ARGV_EMPTY | DEP_ARGV_PRESENT;
      continue;
    }
    if (shell_builtin_name_properties(word->start, assignment.name_end) &
        SHELL_VARIABLE_READONLY) {
      if (*assignment_stop == UINT32_MAX)
        *assignment_stop = i;
      *rejected_assignments |= UINT64_C(1) << i;
    }
  }
  return command;
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
  return shell_process_visit_word_value(tok->start, tok->len,
                                        decoded_path_indicator, &found,
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

/* Decode an effective static cd operand into the bounded CWD representation.
 * ANSI-C fragments have already applied their NUL truncation. Empty values and
 * output overflow make the destination unknowable.
 * tok is a parser-owned word; destination has destination_size writable bytes.
 * The immutable source and destination do not alias.
 * Runtime-dependent tilde expansion is not materialized as a symbolic HOME
 * string. truncated is an optional output for a static destination overflow. */
static SHELL_NONNULL(1,
                     2) bool decode_static_cwd_operand(const dep_token_t *tok,
                                                       char *destination,
                                                       size_t destination_size,
                                                       bool *truncated) {
  if (truncated)
    *truncated = false;
  shell_source_word_expansion_t expansion = shell_source_word_expansion(
      tok->start, tok->len, SHELL_SOURCE_WORD_ARGUMENT);
  if (destination_size == 0 || expansion.dynamic || expansion.leading_tilde)
    return false;

  size_t decoded_length = 0;
  if (shell_process_measure_word_value(tok->start, tok->len, &decoded_length) !=
          SHELL_PROCESS_OK ||
      decoded_length == 0)
    return false;
  if (decoded_length >= destination_size) {
    if (truncated)
      *truncated = true;
    return false;
  }

  size_t written = 0;
  /* The preceding measure established the value and capacity. */
  (void)shell_process_write_word_value(tok->start, tok->len, destination,
                                       destination_size - 1, &written);
  destination[written] = '\0';

  return true;
}

/* CDPATH can redirect a relative operand unless its first component is exactly
 * "." or "..". A dot-prefixed name such as .hidden still uses CDPATH.
 * destination is a nonempty decoded static path;
 * runtime tilde expansion was excluded before decoding. */
static SHELL_NONNULL(1) bool cwd_operand_uses_cdpath(const char *destination) {
  if (destination[0] == '/')
    return false;
  if (destination[0] != '.')
    return true;
  size_t dots = destination[1] == '.' ? 2 : 1;
  return destination[dots] != '/' && destination[dots] != '\0';
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
  /* A stage of a multi-stage pipeline, whose failed setup is the child's exit
   * status and is therefore inverted by the pipeline's `!`. */
  bool pipeline_member;
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
    groups[i].pipeline_member = context.pipeline_member;
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

/* Whether one range runs asynchronously: its own execution stage is followed
 * by a lone `&`, or an enclosing group is. Background syntax inside a
 * substitution belongs to the commands there, not to this one. */
static bool dep_range_is_backgrounded(const shell_pipeline_index_t *index,
                                      const dep_group_exec_t *groups,
                                      uint32_t range_index) {
  if (index->local_background[range_index])
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

    shell_source_heredoc_frame_t frame =
        shell_source_frame_heredoc(cmd, cmd_len, body_start, &hd->pending);
    if (frame.complete) {
      hd->content_start_pos = body_start;
      hd->content_end_pos = (uint32_t)frame.body_end;
      hd->body_after_pos = (uint32_t)frame.after;
      hd->has_source_span = true;
      for (uint32_t i = hd->marker_idx + 1; i < result->count; i++) {
        if (result->cmds[i].start >= body_start &&
            result->cmds[i].start < hd->body_after_pos)
          skip[i] = true;
      }
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
 * applies each owner's operations in source order and publishes the routes of
 * the descriptors each owner uses. */
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
  DEP_ROUTE_DYNAMIC,
  /* A stream installed by this recursive substitution, not an external
   * descriptor with the same number. Its depth tag names the owning graph. */
  DEP_ROUTE_CAPTURE,
  /* Source-aware pipeline resources used before the parent has completed
   * construction. value names the pipeline's input/output execution owner. */
  DEP_ROUTE_PIPE_INPUT,
  DEP_ROUTE_PIPE_OUTPUT,
  /* A variable contains a descriptor number, not a snapshot of its bytes.
   * The target is numeric or a private allocation slot above FD_MAX. Slot
   * facts never contain aliases, so resolution is exactly one indexed hop. */
  DEP_ROUTE_ALIAS,
  /* Read-only Bash asynchronous stdin; published once at the root. */
  DEP_ROUTE_NULL_INPUT,
} dep_route_kind_t;

/* Resource routes (DOC, DYNAMIC with an edge, CAPTURE, PIPE, PIPE_INPUT and
 * PIPE_OUTPUT) name a resource of the graph at their parse depth: the value
 * holds that depth above a 24-bit local index. Only one graph per depth is
 * alive at a time, so a value is unambiguous wherever it is read: in its own
 * graph, or in a nested parse that inherited it. */
enum { DEP_RESOURCE_DEPTH_SHIFT = 24 };
_Static_assert(SHELL_SOURCE_MAX_EXECUTABLE_NESTING + 1u <
                   (1u << (32 - DEP_RESOURCE_DEPTH_SHIFT)) - 1u,
               "resource depths leave the unknown sentinel unambiguous");

static uint32_t dep_resource_depth(uint32_t value) {
  return value >> DEP_RESOURCE_DEPTH_SHIFT;
}

static uint32_t dep_resource_index(uint32_t value) {
  return value & ((UINT32_C(1) << DEP_RESOURCE_DEPTH_SHIFT) - 1);
}

/* index is a local resource index below 2^24; UINT32_MAX (no resource) is
 * kept as is. */
static uint32_t dep_resource_value(uint32_t depth, uint32_t index) {
  return index == UINT32_MAX ? index
                             : index | depth << DEP_RESOURCE_DEPTH_SHIFT;
}

typedef struct {
  /* A named Bash descriptor is identified by its logical variable spelling,
   * not by the shared SHELL_DEP_FD_NAMED sentinel. */
  const char *name;
  uint32_t value, name_len;
} dep_fd_ref_t;

static dep_fd_ref_t dep_fd_numeric(uint32_t value) {
  return (dep_fd_ref_t){.value = value};
}

/* Named redirection spellings erase backslash-LF just like their source
 * parser. Compare logical identifier bytes so `{f\\\nd}` is never confused
 * with another name solely because the source happens to be wrapped.
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

static bool dep_resource_route(dep_fd_route_t route) {
  return route.kind == DEP_ROUTE_DOC || route.kind == DEP_ROUTE_CAPTURE ||
         route.kind == DEP_ROUTE_PIPE_INPUT ||
         route.kind == DEP_ROUTE_PIPE_OUTPUT ||
         (route.kind == DEP_ROUTE_DYNAMIC && route.value != UINT32_MAX);
}

/* A resource of an enclosing graph, inherited by the graph at depth. Its
 * uses are joined into that graph (dep_record_fd_import_use). */
static bool dep_route_foreign(dep_fd_route_t route, uint32_t depth) {
  return dep_resource_route(route) && dep_resource_depth(route.value) != depth;
}

static int dep_fd_ref_compare(dep_fd_ref_t a, dep_fd_ref_t b);

typedef struct dep_fd_imports dep_fd_imports_t;
enum { DEP_IMPORT_SCRATCH = 1u, DEP_IMPORT_MAYBE_SCRATCH = 2u };
typedef struct dep_route_journal dep_route_journal_t;
typedef struct dep_snapshot_source dep_snapshot_source_t;

/* Presence conditions a child returns to its parent. */
#define DEP_OBSERVATION_CONDITION_CAPACITY ((SHELL_DEP_MAX_EDGES + 8) * 3)

typedef struct {
  /* One-based tree roots in dep_route_journal_t; zero is an empty map. A
   * zero-initialized value represents one empty state. Distinct roots preserve
   * descriptor correlation across control and allocation alternatives until
   * graph routes are materialized. */
  uint32_t root;
  /* One-based immutable list in dep_route_journal_t. */
  uint32_t alternative_head;
  uint32_t membership_root;
  uint8_t alternative_count;
  /* Transforms preserve both flags even when filtering leaves one root.
   * Recursive imports use correlated to select distinct scalar/FD versions. */
  bool truncated;
  bool correlated;
} dep_route_state_t;

/* What a nested parse inherits at its entry: its parent's execution
 * versions, per path, in the shared arena (dep_route_arena_t), plus the
 * per-path entry transforms its parent prepared. The child reads those
 * versions in place (dep_import_route_alternatives). */
struct dep_fd_imports {
  /* IFS expansion facts inherited by a nested execution scope. */
  uint32_t ifs;
  uint32_t path_count;
  uint32_t path_ifs[SHELL_DEP_MAX_NODES];
  /* Each imported path's occupancy, when an allocation on it needed one. */
  shell_fd_partition_t path_process_domain[SHELL_DEP_MAX_NODES];
  bool path_process_domain_present[SHELL_DEP_MAX_NODES];
  /* Standard streams the child's capture pipe replaces (bit per fd). */
  uint8_t process_capture_mask;
  /* The parent's construction journal, and its versions on each path. They
   * outlive this recursive parse, including its final replay. NULL for a
   * root parse. */
  const dep_route_journal_t *scalar_journal;
  dep_route_state_t path_state[SHELL_DEP_MAX_NODES];
  /* Synchronous command substitutions return inherited observations. */
  bool observe_return;
};

typedef struct {
  uint32_t owner;
  uint32_t fd;
  uint8_t access;
  /* The inherited resource: a resource route of the graph at its depth
   * (dep_resource_value), so uses of one resource through distinct aliases
   * share it. */
  dep_fd_route_t route;
  const char *fd_name;
  uint32_t fd_name_len;
} dep_fd_import_use_t;

typedef struct dep_route_workspace dep_route_workspace_t;
typedef struct dep_snapshot_frame dep_snapshot_frame_t;

typedef struct dep_process_guard {
  const char *source;
  const struct dep_process_guard *parent;
  uint32_t depth;
  bool observed;
} dep_process_guard_t;

/* Construction-time identity for a process substitution's temporary pipe end
 * or its redirected installation. Several operands may have the same
 * owner and descriptor, so route resolution must use source identity rather
 * than claiming the first compatible graph edge.  This journal is private to
 * one recursive parse; copied child graphs have already resolved their own
 * routes before they are joined. */
typedef struct {
  uint32_t position;
  uint32_t edge;
  dep_fd_ref_t fd;
  const char *source;
  const dep_process_guard_t *guard;
  uint32_t next;
  uint8_t access;
  bool temporary, command_word, body_word, byte_use, standalone;
} dep_process_route_t;

typedef struct {
  dep_process_route_t entries[SHELL_DEP_MAX_EDGES * 2];
  dep_process_guard_t guards[SHELL_DEP_MAX_EDGES * 2];
  shell_avl_node_t guard_index[SHELL_DEP_MAX_EDGES * 2];
  uint32_t guard_root, guard_count;
  /* One-based owner-local chains. Appending a route never requires a search;
   * snapshot cursors consume only the newly installed operations. */
  uint32_t first[SHELL_DEP_MAX_NODES];
  uint32_t last[SHELL_DEP_MAX_NODES];
  /* Prepared once from observations within each temporary-end lifetime. */
  bool track[SHELL_DEP_MAX_NODES];
  bool tracking_ready[SHELL_DEP_MAX_NODES];
  uint16_t observed_low[SHELL_DEP_MAX_NODES];
  uint32_t count;
  bool private_edges;
} dep_process_route_map_t;

typedef struct {
  uint32_t owner;
  uint32_t fd;
  uint32_t anchor;
  uint8_t access;
  /* Capture GROUP records normally describe exposure, not a byte producer.
   * Shell-owned diagnostics and imported child flows are actual group uses. */
  bool actual_group;
  const char *fd_name;
  uint32_t fd_name_len;
} dep_stream_use_t;

static SHELL_NONNULL(1) dep_fd_ref_t
    dep_stream_fd(const dep_stream_use_t *use) {
  return (dep_fd_ref_t){
      .name = use->fd_name, .value = use->fd, .name_len = use->fd_name_len};
}

typedef enum {
  /* Command arguments expand before the simple command's redirections. */
  DEP_SNAPSHOT_COMMAND_WORD,
  /* RHS imports select null-path commits or temporary-prefix visibility,
   * never this assignment's own commit. */
  DEP_SNAPSHOT_ASSIGNMENT_VALUE,
  /* A redirect operand expands while its redirect list is applied
   * left-to-right, after preceding redirects but before its own operation. */
  DEP_SNAPSHOT_REDIRECT_OPERAND,
  /* Compound operands expand after their complete redirect setup. */
  DEP_SNAPSHOT_BODY_WORD,
  /* Internal completion consumes the full setup without exporting imports.
   * This value also counts the exportable expansion phases. */
  DEP_SNAPSHOT_SETUP,
} dep_snapshot_phase_t;

/* Phase-local substitution transfers. The incoming bit denotes a path with no
 * status-replacing substitution; empty bodies and skipped operands preserve
 * the current command's preceding value. The low bits are returning outcomes.
 */
typedef struct {
  uint8_t phase[DEP_SNAPSHOT_SETUP];
  /* Unconditional expansion errors are separate from the assignment-only
   * alternative of a command whose entire argv can disappear. */
  uint8_t errors;
  uint8_t null_assignment_errors;
  /* Prepared once from the effective command/wrapper, not from its status.
   * The scope mask admits both dispatches for runtime-unknown commands. */
  uint8_t redirect_scopes;
  /* Bash executes an argv-less stdin/named-FD redirect list in a child.
   * Assignment commits still belong to the parent. This is syntax-local,
   * independent of whether setup reaches every operation or changes an FD. */
  bool isolated_setup;
  bool setup_expansion_failure;
} dep_expansion_status_t;

enum {
  DEP_REDIRECT_CURRENT = 1u << 0,
  DEP_REDIRECT_CHILD = 1u << 1,
  DEP_REDIRECT_BAD_BUILTIN = 1u << 2,
};

/* Uses of a substitution's own capture stream and deferred parent pipelines
 * retain descriptor and execution-context provenance until their join. */
#define DEP_EXTERNAL_USE_CAPACITY                                              \
  (3 * SHELL_DEP_MAX_NODES + 2 * SHELL_DEP_MAX_EDGES)
typedef struct {
  /* Inherited boundary uses stay symbolic until the root graph is complete.
   * Child joins remap owners, never duplicate full-command FD resources. */
  dep_stream_use_t external_uses[DEP_EXTERNAL_USE_CAPACITY];
  shell_avl_node_t external_index[DEP_EXTERNAL_USE_CAPACITY];
  uint32_t external_root;
  uint32_t external_use_count;
  dep_stream_use_t capture_uses[SHELL_DEP_MAX_EDGES];
  shell_avl_node_t capture_index[SHELL_DEP_MAX_EDGES];
  uint32_t capture_root;
  uint32_t capture_use_count;
  dep_stream_use_t pipe_uses[SHELL_DEP_MAX_EDGES];
  shell_avl_node_t pipe_index[SHELL_DEP_MAX_EDGES];
  uint32_t pipe_root;
  uint32_t pipe_use_count;
  /* Semantic expansion facts, independent of effective descriptor edges.
   * Child joins and endpoint compaction use the same node mapping as streams.
   * Recursive results live in the existing caller-owned workspace. */
  uint8_t unresolved_paths[SHELL_DEP_MAX_NODES];
  /* Completed child-shell status, consumed before its stream slot is reused. */
  uint8_t status;
  /* Derived during existing parsing, never from graph node count. Blank
   * substitutions preserve status; comment-only $() does too, but comment-only
   * backticks execute an empty child and return success in reference Bash. */
  uint8_t empty_kind;
  /* Private join metadata: public graph edges remain the sole externally
   * visible representation of inherited descriptor byte flow. */
  dep_fd_imports_t fd_imports;
  dep_fd_import_use_t fd_import_uses[SHELL_DEP_MAX_EDGES];
  shell_avl_node_t fd_import_use_index[SHELL_DEP_MAX_EDGES];
  uint32_t fd_import_use_count;
  uint32_t fd_import_use_root;
  /* Shared scratch is used only between a completed child parse and its join.
   * Recursive parsing therefore never needs to retain another join plan. */
  struct dep_import_join *join;
  /* Parse depth of the graph these streams belong to. */
  uint32_t depth;
} dep_subgraph_streams_t;

/* Recursive parses need their graph and deferred-stream result concurrently
 * while the parent joins them. Keep one bounded slot per nesting level in the
 * caller-owned evaluation workspace rather than multiplying large automatic
 * objects (and sanitizer redzones) on the C call stack. */
typedef struct {
  shell_dep_graph_t graph;
  dep_subgraph_streams_t streams;
} dep_recursive_parse_t;

/* Portable predicates over scalar presence, never journal-local roots: value
 * is the presence a child observed for the named variable fd. Clauses are
 * alternatives and conditions within a clause are conjunctive. */
typedef struct {
  dep_fd_ref_t fd;
  uint32_t next, value;
} dep_observation_condition_t;
typedef struct {
  uint32_t conditions, next;
  uint8_t status;
} dep_observation_clause_t;
typedef struct {
  dep_observation_condition_t conditions[DEP_OBSERVATION_CONDITION_CAPACITY];
  dep_observation_clause_t clauses[SHELL_DEP_MAX_NODES * 5];
  uint32_t condition_count, clause_count;
} dep_observation_transfer_t;
typedef struct {
  shell_avl_node_t condition_index[DEP_OBSERVATION_CONDITION_CAPACITY];
  shell_avl_node_t clause_index[SHELL_DEP_MAX_NODES * 5];
  uint32_t condition_root, clause_root;
} dep_observation_index_t;
typedef struct {
  uint32_t clauses, next, position, key;
  const dep_process_guard_t *guard, *previous_guard;
  /* Borrowed guards belong to the enclosing parse's scanner inventory.
   * previous_guard permits prompt retirement of completed status-only scopes.
   * A clause-free event only closes scopes; it cannot replace phase status. */
  /* Phase status before this event, when an unrecorded earlier substitution
   * or the incoming shell status supplies the conditional skipped outcome. */
  uint8_t incoming_status;
  bool conditional;
} dep_observation_event_t;
typedef struct {
  dep_observation_transfer_t transfer;
  dep_observation_event_t events[SHELL_DEP_MAX_EDGES];
  uint32_t event_count;
} dep_observation_program_t;

typedef struct dep_import_join {
  dep_observation_transfer_t observations;
  /* Export-local indexes; never borrowed by a recursive child's summary or
   * checkpointed with the parent's append-only observation program. */
  dep_observation_index_t observation_index;
  dep_stream_use_t endpoints[SHELL_DEP_MAX_EDGES];
  shell_avl_node_t endpoint_index[SHELL_DEP_MAX_EDGES];
  dep_stream_use_t pipe_targets[SHELL_DEP_MAX_EDGES];
  shell_avl_node_t pipe_target_index[SHELL_DEP_MAX_EDGES];
  uint32_t group_parent[SHELL_DEP_MAX_NODES];
  uint32_t capture_first_child[SHELL_DEP_MAX_NODES];
  uint32_t capture_next_child[SHELL_DEP_MAX_NODES];
  uint32_t capture_first_use[SHELL_DEP_MAX_NODES];
  uint32_t capture_next_use[SHELL_DEP_MAX_EDGES];
  uint32_t capture_resource[SHELL_DEP_MAX_EDGES];
  uint32_t capture_endpoint[SHELL_DEP_MAX_EDGES];
  shell_avl_node_t capture_resource_index[SHELL_DEP_MAX_EDGES];
  uint32_t capture_outermost[SHELL_DEP_MAX_EDGES];
} dep_import_join_t;

#define DEP_EXECUTION_EVENT_CAPACITY (SHELL_MAX_GROUPS + SHELL_MAX_SUBCOMMANDS)
#define DEP_OBSERVATION_ROOT_EVENT DEP_EXECUTION_EVENT_CAPACITY
#define DEP_SCALAR_IMPORT_EVENT (DEP_OBSERVATION_ROOT_EVENT + 2)
#define DEP_VARIABLE_STATE_EVENT (DEP_OBSERVATION_ROOT_EVENT + 3)
/* The root traversal prepares canonical test programs, including nested
 * bodies. Values/nodes borrow source-operation scratch. After argv resolution
 * grammar refreshes in place before body snapshots borrow the program. */
typedef struct {
  const char *commands[SHELL_DEP_MAX_NODES];
  shell_test_program_t programs[SHELL_DEP_MAX_NODES];
  shell_avl_node_t index[SHELL_DEP_MAX_NODES];
  uint32_t root, count;
} dep_test_programs_t;

static SHELL_NONNULL(1, 3) int dep_test_program_compare(const void *context,
                                                        uint32_t index,
                                                        const void *key) {
  const dep_test_programs_t *tests = context;
  uintptr_t left = (uintptr_t)tests->commands[index], right = (uintptr_t)key;
  return left < right ? -1 : left != right;
}

/* command is the effective builtin source start reported during the root
 * semantic traversal. Successful inventory preparation guarantees its entry. */
static SHELL_NONNULL(1, 2) shell_test_program_t *dep_test_program(
    dep_test_programs_t *tests, const char *command) {
  uint32_t cursor = tests->root;
  for (;;) {
    int order = dep_test_program_compare(tests, cursor - 1, command);
    if (!order)
      return &tests->programs[cursor - 1];
    cursor = order > 0 ? tests->index[cursor - 1].left
                       : tests->index[cursor - 1].right;
  }
}

typedef struct {
  /* Zero means synchronous. Otherwise names the first event, biased by one.
   * Only direct stages participate; compound descendants use their own scope.
   */
  uint32_t unit[DEP_EXECUTION_EVENT_CAPACITY];
  uint32_t last[DEP_EXECUTION_EVENT_CAPACITY];
  bool early[DEP_EXECUTION_EVENT_CAPACITY];
  bool wrapper[DEP_EXECUTION_EVENT_CAPACITY];
} dep_async_plan_t;

/* Structural parsing discovers a recursive shell before the enclosing graph
 * has completed route resolution.  Keep the source metadata required to
 * replay only the descriptor state visible at that exact expansion point. */
typedef struct {
  const char *cmd;
  uint32_t cmd_len;
  const shell_parse_result_t *fast;
  const shell_execution_map_t *execution;
  const dep_async_plan_t *async;
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
  const bool *range_cd_failure_writes;
  /* First setup operation which cannot succeed. Earlier expansions/setup
   * remain observable; the command body and later operands do not run. */
  uint32_t *owner_setup_stop;
  const uint32_t *owner_assignment_stop;
  bool effects_active;
  /* Earliest source position beyond an unresolved arithmetic interpretation.
   * Later owners retain syntax but cannot publish execution-state proofs. */
  uint32_t *semantic_barrier;
  bool input_unit_recovery;
  dep_process_route_map_t *process_routes;
  dep_route_workspace_t *workspace;
  dep_snapshot_frame_t *snapshot;
  const shell_dep_word_resolver_t *resolver;
  uint8_t *unresolved_paths;
} dep_parse_context_t;

#include "shell_depgraph_coverage_impl.h"

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
  DEP_FD_OP_MOVE,
  DEP_FD_OP_CLOSE,
  DEP_FD_OP_FAILED,
  /* A resolved physical self-copy, never an independently parsed operation. */
  DEP_FD_OP_IDENTITY,
  /* A process substitution creates its parent pipe end during expansion,
   * independently of opening a redirect onto that pipe's pathname. */
  DEP_FD_OP_PROCESS,
} dep_fd_op_kind_t;

static bool dep_fd_op_copies(dep_fd_op_kind_t kind) {
  return kind == DEP_FD_OP_DUP || kind == DEP_FD_OP_MOVE;
}

/* Journal access kinds are unsigned single-bit masks, including bit 33.
 * Do not depend on a compiler's choice of enum signedness for ordering them. */
typedef uint64_t dep_fd_access_t;
enum {
  DEP_FD_ACCESS_READ = 1 << 0,
  DEP_FD_ACCESS_WRITE = 1 << 1,
  DEP_FD_ACCESS_BOTH = DEP_FD_ACCESS_READ | DEP_FD_ACCESS_WRITE,
  /* Private journal fact: live allocation, failed-setup absence, or unknown
   * variable value. Not a capability and never exported to the public graph. */
  DEP_FD_ACCESS_BINDING = 1 << 2,
  /* Private allocator candidates left by reached closes. */
  DEP_FD_ACCESS_AVAILABLE = 1 << 3,
  /* Event-keyed immutable parent version of a private execution alternative.
   * This is outcome provenance, not a child descriptor mutation to publish. */
  DEP_FD_ACCESS_PRIVATE_ENTRY = 1 << 4,
  /* Innermost private-entry event plus one; UINT32_MAX identifies a root
   * imported-entry observation anchor. Neither value is a map reference. */
  DEP_FD_ACCESS_PRIVATE_SCOPE = 1 << 8,
  /* Numeric sentinel keys retain transient read effects and the predefined
   * variable capability mask. Named keys retain descriptor-orphan state. */
  DEP_FD_ACCESS_EFFECT_STATE = 1 << 9,
  DEP_FD_ACCESS_SUBSTITUTION_STATUS = 1 << 10,
  /* Operation-keyed command-local Bash redirection undo descriptors. */
  DEP_FD_ACCESS_SAVED = 1 << 5,
  DEP_FD_ACCESS_ENTRY = 1 << 7,
  /* Per-physical-FD setup provenance. A failed copy from a source modified
   * in this frame proves nothing about its restored parent route. */
  DEP_FD_ACCESS_SETUP_FRAME = 1 << 16,
  /* Operation-keyed physical allocation and pre-redirect undo version. */
  DEP_FD_ACCESS_ALLOCATION_SLOTS = 1 << 17,
  DEP_FD_ACCESS_UNDO_ENTRY = 1 << 18,
  /* Physical destination of a path-local undo and whether exec must restore
   * an overwritten shell-owned scratch descriptor before disposing its save. */
  DEP_FD_ACCESS_UNDO_TARGET = 1 << 19,
  DEP_FD_ACCESS_UNDO_EXEC = 1 << 20,
  DEP_FD_ACCESS_SCRATCH = 1 << 21,
  /* Interpreter-local Bash stdin_redir, correlated with descriptor versions. */
  DEP_FD_ACCESS_STDIN_REDIR = 1 << 22,
  /* Selected setup dispatch for this owner, retained across prefix snapshots.
   */
  DEP_FD_ACCESS_SETUP_MODE = 1 << 23,
  /* A read -u argument's physical identity at command-word expansion. Keys
   * are owner-local token ordinals, disjoint from ordinary FD facts. */
  DEP_FD_ACCESS_READ_ARGUMENT = 1 << 25,
  DEP_FD_ACCESS_PROCESS_SLOT = 1 << 26,
  /* Symbolic occupancy of Bash's fixed low/high allocation domain. An
   * empty fact means no domain; value zero in a nonempty fact is impossible.
   * Clearing a domain must not turn it into the impossible terminal. */
  DEP_FD_ACCESS_PROCESS_DOMAIN = 1 << 27,
  DEP_FD_ACCESS_PROCESS_BEFORE = 1 << 28,
  DEP_FD_ACCESS_SELECTOR = 1 << 29,
  /* Root of the interpreter's persistent set of original process-pipe FDs.
   * Forking a compound closes these in the parent, not in its child. */
  DEP_FD_ACCESS_PROCESS_OWNED = 1 << 30,
  /* Expansion context, not a descriptor capability. Stored under numeric key
   * zero in the same immutable execution journal; never materialized as I/O. */
  DEP_FD_ACCESS_IFS = 1 << 12,
};

/* A version owns one resettable named-scalar map. Its holder stores the root
 * and INHERITED (executor contract) or DYNAMIC (unknown) fallback. Physical
 * descriptor facts and allocation occupancy stay in the outer map. */
#define DEP_FD_ACCESS_NAMED_BINDINGS ((dep_fd_access_t)UINT32_C(0x80000000))
/* Scalar presence is independent of value/descriptor facts. Numeric key zero
 * holds a bulk-invalidation generation; named facts carry that generation.
 * Existing packed journal keys have room for this private access kind. */
#define DEP_FD_ACCESS_VARIABLE_PRESENCE (UINT64_C(1) << 32)
/* An immutable presence-only submap makes scalar-import equivalence a root
 * comparison, independent of physical descriptor changes. Its numeric-zero
 * entry is the invalidation epoch; named entries retain presence and writer. */
#define DEP_FD_ACCESS_PRESENCE_MAP (UINT64_C(1) << 33)

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
  /* Identity transfer for a phase with no status-replacing substitution. */
  DEP_EXPANSION_INCOMING = 1u << 7,
};

enum {
  DEP_UNDO_CHILD = 1u << 0,
  DEP_UNDO_COMMAND = 1u << 1,
  DEP_UNDO_COMPOUND = 1u << 2,
  DEP_UNDO_BOTH = DEP_UNDO_CHILD | DEP_UNDO_COMMAND,
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
  /* The write half of one <> open is not another Bash redirect/save. */
  bool paired_open;
  /* This owner's active redirect frame can expose a scratch descriptor. */
  bool undo_observable;
  /* External setup has no undo list. Command/group setup owns its saves. */
  uint8_t undo_mode;
  /* NULL for unconditional setup. Borrowed from this parse's guard pool. */
  const dep_process_guard_t *guard;
  /* Process allocation observes low auxiliary identities only within its
   * owner lifetime. Prior closes still constrain occupancy, not identity. */
  uint16_t process_observed_low;
  /* One-based predefined-variable identity for a named destination. */
  uint8_t variable;
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
  return dep_fd_op_copies(op->kind) && op->fd <= SHELL_DEP_FD_MAX &&
         op->fd == op->target_fd;
}

static SHELL_NONNULL(1) bool dep_fd_op_saves_numeric(const dep_fd_op_t *op) {
  return !op->paired_open && op->kind != DEP_FD_OP_IDENTITY &&
         op->fd <= SHELL_DEP_FD_MAX && !dep_fd_op_numeric_self_dup(op);
}

/* Numeric compound redirects save descriptor slots for restoration at group
 * exit. Named allocations are persistent and self-duplication is a Bash no-op,
 * so neither creates a saved slot. The existing effective group table holds
 * the in-frame state; publication across a frame must leave saved slots alone.
 */
typedef struct {
  /* At most two slots per bounded redirect token (combined output). */
  uint32_t fds[SHELL_DEP_MAX_TOKENS * 2];
  /* Ordered undo keys retain path-local physical targets and scratch slots.
   * The numeric membership index is only for scope-crossing queries. */
  uint32_t scratch_keys[SHELL_DEP_MAX_TOKENS * 2];
  shell_avl_node_t scratch_index[SHELL_DEP_MAX_TOKENS * 2];
  uint32_t scratch_root;
  uint32_t scratch_count;
  shell_avl_node_t index[SHELL_DEP_MAX_TOKENS * 2];
  uint32_t root;
  uint32_t count;
} dep_redirect_frame_t;

/* A set of numeric descriptors, one per redirect operation of an owner. */
typedef struct {
  uint32_t fds[SHELL_DEP_MAX_TOKENS * 3];
  shell_avl_node_t index[SHELL_DEP_MAX_TOKENS * 3];
  uint32_t root, count;
} dep_fd_set_t;

typedef struct {
  const shell_parse_result_t *fast;
  const dep_redirect_frame_t *frames;
  int32_t source_group;
  int32_t destination_group;
} dep_route_publication_t;

typedef struct {
  uint32_t owner;
  dep_fd_op_t op;
} dep_fd_transition_t;

typedef enum {
  DEP_NAMED_EFFECT_TOKEN,
  DEP_NAMED_EFFECT_STATIC_ASSIGNMENT,
  DEP_NAMED_EFFECT_PRINTF_ATTACHED,
  DEP_NAMED_EFFECT_UNSET,
  DEP_NAMED_EFFECT_OPAQUE_WRITE,
  DEP_NAMED_EFFECT_OPAQUE_UNSET,
} dep_named_effect_kind_t;

typedef struct {
  dep_token_t token;
  /* One-based read-observation key, resolved once in this parse frame. */
  uint32_t observation;
  uint8_t kind;
  /* One-based predefined-variable registry identity, or zero. */
  uint8_t variable;
  /* Fresh-shell properties which require ordinary-scalar state. */
  uint8_t prohibited_properties;
  /* Zero derives SET/UNSET from kind. Some implicit writes can also remove
   * the value; cd's OLDPWD copies the entry presence of PWD. */
  uint8_t presence;
  bool presence_from_pwd;
  bool presence_may_skip;
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
  const char *start;
  uint32_t len;
  uint8_t variable;
  bool append;
} dep_variable_token_t;

/* names are each name's first assignment, in source order, so the names
 * assigned before a position are a prefix. special lists the indexes of
 * predefined variables; names are distinct, so it is bounded by the
 * predefined variable registry, not by the command. */
typedef struct {
  dep_variable_token_t names[SHELL_DEP_MAX_TOKENS];
  shell_avl_node_t index[SHELL_DEP_MAX_TOKENS];
  uint32_t special[SHELL_DEP_MAX_TOKENS];
  uint32_t root, count, special_count;
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
  const char *operation; /* Borrowed command identity for idempotent writes. */
  bool before_redirect;
  /* Pre-change cd failures do not write. Reporting/physical failures can
   * instead follow a successful chdir, joining changed and unchanged states. */
  bool success_only;
  bool failure_alternative;
  /* Zero is the root list; otherwise this is the one-based lexical group. */
  uint8_t scope;
  /* NULL means arbitrary writes can affect every visible binding. A retained
   * index excludes command-prefix bindings restored after this builtin. */
  const dep_prefix_assignment_set_t *restored_prefixes;
  const dep_prefix_assignment_set_t *presence_prefixes;
  bool ifs_write, ifs_append;
  bool ifs_maybe_unset;
  uint32_t ifs;
} dep_named_mutations_t;

/* cd changes variable contents, not the open descriptors they used to name. */
static const dep_named_mutations_t dep_cd_mutations = {
    .effects = {{.token = {"PWD", 3}, .kind = DEP_NAMED_EFFECT_TOKEN},
                {.token = {"OLDPWD", 6},
                 .kind = DEP_NAMED_EFFECT_TOKEN,
                 .presence_from_pwd = true}},
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
static bool dep_route_set_add(dep_route_set_t *snapshot, dep_fd_route_t route);

/* Word facts store up to four 32-bit words. Route sets hold distinct
 * entries, and two words can be equal, so each position carries its own kind
 * as a tag; the kinds have no route meaning here. */
static dep_route_set_t dep_word_fact(const uint32_t *words, uint32_t count) {
  static const dep_route_kind_t tags[] = {DEP_ROUTE_INHERITED,
                                          DEP_ROUTE_UNAVAILABLE,
                                          DEP_ROUTE_ABSENT, DEP_ROUTE_UNSEEN};
  dep_route_set_t fact = {.count = count, .ready = true};
  for (uint32_t i = 0; i < count; i++)
    fact.routes[i] = (dep_fd_route_t){tags[i], words[i]};
  return fact;
}

/* A process-domain fact is one occupancy value for fds 0..63: the may-free
 * and may-occupied words, each as its low and high half. An empty fact means
 * no allocation has needed one yet; the binding facts then give occupancy. */
static dep_route_set_t dep_domain_fact(shell_fd_occupancy_t occupancy) {
  const uint32_t words[] = {(uint32_t)occupancy.may_free,
                            (uint32_t)(occupancy.may_free >> 32),
                            (uint32_t)occupancy.may_occupied,
                            (uint32_t)(occupancy.may_occupied >> 32)};
  return dep_word_fact(words, 4);
}

/* A private slot's identity fact: its evaluation-wide identity token, then
 * its places, the descriptors below 64 it can occupy and whether it can lie
 * in the tail above 63. The token keeps one child-local slot per allocation
 * across recursive imports. One exact place makes updates of the slot strong
 * updates of that descriptor. */
static dep_route_set_t dep_slot_places_fact(uint32_t selector,
                                            shell_fd_allocation_t places) {
  const uint32_t words[] = {selector, (uint32_t)places.candidates,
                            (uint32_t)(places.candidates >> 32), places.tail};
  return dep_word_fact(words, 4);
}

/* fact is a nonempty identity fact. */
static SHELL_NONNULL(1) shell_fd_allocation_t
    dep_slot_places(const dep_route_set_t *fact) {
  return (shell_fd_allocation_t){fact->routes[1].value |
                                     (uint64_t)fact->routes[2].value << 32,
                                 fact->routes[3].value != 0};
}

/* fact is a nonempty process-domain fact. */
static SHELL_NONNULL(1) shell_fd_occupancy_t
    dep_domain_value(const dep_route_set_t *fact) {
  return (shell_fd_occupancy_t){
      fact->routes[0].value | (uint64_t)fact->routes[1].value << 32,
      fact->routes[2].value | (uint64_t)fact->routes[3].value << 32};
}

/* Immutable alternative lists carry route roots. */
typedef struct {
  uint32_t value;
  uint32_t next;
} dep_route_link_t;

/* Immutable membership index; list order remains independent of root order. */
typedef struct {
  uint32_t value, left, right;
  uint8_t height;
} dep_route_member_t;

typedef struct {
  uint32_t left, right, result;
} dep_route_join_t;

/* Route alternatives and path-dependent descriptor identities are separate
 * dimensions.  The public report can expose at most 16 alternative sinks,
 * while a shell may conditionally alter many more unrelated descriptors
 * before one is copied into fd 2. Use immutable workspace tries so state
 * copies share unchanged subtrees without allocating or copying a full
 * descriptor table per compound group. The journal budgets bounded trie paths
 * per state update; it retains live descriptor identities, never chains of
 * shadowed changes. Current, target-undo, and move-source histories can each
 * retain one version per bounded redirect entry for a source operation.
 * Exhausting either pool fails closed as graph truncation rather than changing
 * a report route silently. */
#define DEP_ROUTE_OPERATION_CAPACITY                                           \
  (SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS)
#define DEP_ROUTE_ALLOCATION_CAPACITY (DEP_ROUTE_OPERATION_CAPACITY * 3)
#define DEP_ROUTE_CHANGE_CAPACITY                                              \
  (DEP_ROUTE_OPERATION_CAPACITY * SHELL_DEP_MAX_TOKENS * 3)
#define DEP_ROUTE_SNAPSHOT_CAPACITY (DEP_ROUTE_OPERATION_CAPACITY * 4)
/* Trie intern table: a power of two at least twice the node capacity. */
#define DEP_ROUTE_MAP_TABLE (1u << 17)
_Static_assert(DEP_ROUTE_MAP_TABLE >= 2u * DEP_ROUTE_CHANGE_CAPACITY,
               "trie intern probes stay short");
/* Distinct descriptor names: one per retained token, plus imported names. */
#define DEP_ROUTE_NAME_CAPACITY                                                \
  (DEP_ROUTE_OPERATION_CAPACITY + SHELL_DEP_MAX_NODES * SHELL_DEP_MAX_TOKENS)
_Static_assert(DEP_ROUTE_NAME_CAPACITY <= UINT16_MAX,
               "name indexes fit private AVL links");

/* Route records' private byte budget: trie nodes, their intern table and
 * collection marks. */
#define DEP_ROUTE_STORAGE_BYTES                                                \
  ((sizeof(shell_pmap_node_t) + 1u) * DEP_ROUTE_CHANGE_CAPACITY +              \
   sizeof(uint16_t) * DEP_ROUTE_MAP_TABLE)
_Static_assert(DEP_ROUTE_CHANGE_CAPACITY <= UINT16_MAX,
               "private indexes fit 16 bits");
_Static_assert(DEP_ROUTE_SNAPSHOT_CAPACITY <= DEP_ROUTE_CHANGE_CAPACITY,
               "collection marks cover snapshots");

/* Presence queries need no graph edge. Budget one name per retained token,
 * plus PWD when OLDPWD is queried, independently of descriptor observations. */
#define DEP_READ_OBSERVATION_CAPACITY                                          \
  (DEP_ROUTE_OPERATION_CAPACITY + SHELL_DEP_MAX_NODES * SHELL_DEP_MAX_TOKENS + \
   1)
_Static_assert(DEP_READ_OBSERVATION_CAPACITY <= UINT16_MAX,
               "observation indexes fit private AVL links");
enum {
  DEP_READ_OBSERVE_VALUE = 1u,
  DEP_READ_OBSERVE_IDENTITY = 2u,
  DEP_READ_OBSERVE_ACCESS = 4u,
  DEP_READ_OBSERVE_PRESENCE = 8u,
};
typedef struct {
  dep_fd_ref_t fd;
  unsigned role;
  uint8_t variable;
} dep_read_observation_t;
/* Source names and static selectors are indexed once for role lookup, never
 * enumerated at child entry. Private slots retain
 * their allocation's borrowed name, so observation needs no mutable alias
 * inventory and cannot outlive a recursive journal rewind. */
typedef struct {
  dep_read_observation_t entries[DEP_READ_OBSERVATION_CAPACITY];
  shell_avl_node_t index[DEP_READ_OBSERVATION_CAPACITY];
  uint32_t root, count;
  /* Key-only named allocations support prepared mutation lookup; they do
   * not request observation capture or retain read-version correlations. */
  bool active, identity, presence;
} dep_read_observations_t;

/* Prepared entries are immutable. Copy their live prefix once per journal,
 * keeping unused node/token capacity out of the ordinary parse's work. */
static SHELL_NONNULL(1, 2) void dep_read_observations_copy(
    dep_read_observations_t *destination,
    const dep_read_observations_t *source) {
  destination->root = source->root;
  destination->count = source->count;
  destination->active = source->active;
  destination->identity = source->identity;
  destination->presence = source->presence;
  memcpy(destination->entries, source->entries,
         source->count * sizeof(source->entries[0]));
  memcpy(destination->index, source->index,
         source->count * sizeof(source->index[0]));
}

typedef enum {
  DEP_ALLOCATION_BINDING,
  DEP_ALLOCATION_TARGET_UNDO,
  DEP_ALLOCATION_MOVE_UNDO,
  DEP_ALLOCATION_PROCESS,
  DEP_ALLOCATION_PROCESS_GUARD,
  DEP_ALLOCATION_IMPORT,
} dep_allocation_role_t;

typedef struct {
  const char *name;
  /* Original allocation spelling, retained when this is an imported alias. */
  const char *allocation;
  uint32_t name_length;
  uint32_t position;
  uint32_t fd;
  dep_allocation_role_t role;
  /* A union for frame membership, not path-dependent restoration facts. */
  uint32_t closed_slots;
  uint32_t selector;
  unsigned observations;
  /* The epoch of the journal reset after which this record was last
   * interned. A record from an earlier evaluation has not reached the
   * operation: its first interning installs its initial fields, as a fresh
   * journal would have. */
  uint32_t epoch;
} dep_allocation_t;

/* Setup diagnostics are uses of prefix stderr, not uses of the command's
 * final descriptor table. Intern sink references across failure points; a
 * long redirect list must not collapse into the 16-entry route-set bound. */
typedef struct {
  uint32_t owner;
  dep_fd_route_t route;
} dep_diagnostic_use_t;

typedef struct {
  dep_diagnostic_use_t uses[DEP_EXTERNAL_USE_CAPACITY];
  shell_avl_node_t index[DEP_EXTERNAL_USE_CAPACITY];
  uint32_t root, count;
} dep_diagnostics_t;

typedef struct {
  const char *operation;
  dep_fd_ref_t name;
} dep_presence_writer_t;
#define DEP_PRESENCE_WRITER_CAPACITY                                           \
  (DEP_ROUTE_OPERATION_CAPACITY * SHELL_DEP_MAX_TOKENS)
_Static_assert(DEP_PRESENCE_WRITER_CAPACITY <= UINT16_MAX,
               "presence writer indexes fit private AVL links");

enum { DEP_OPEN_CAUSE_CAPACITY = 2 * SHELL_DEP_MAX_EDGES };
/* Immutable analysis values shared by every pass and recursion level of one
 * evaluation: descriptor maps, interned value snapshots, alternative lists and
 * descriptor names. A root published at any level stays valid until a
 * checkpoint taken before it is restored (dep_route_journal_checkpoint), so a
 * nested parse can read its parent's versions. Collection runs only while no
 * checkpoint is open. */
typedef struct dep_route_arena {
  /* Descriptor maps are hash-consed Patricia tries (shell_pmap_internal.h)
   * over keys made by dep_route_key(); leaf values are snapshot ids, except
   * in set-valued maps. The pool borrows the three arrays below. */
  shell_pmap_pool_t maps;
  shell_pmap_node_t map_nodes[DEP_ROUTE_CHANGE_CAPACITY];
  uint16_t map_table[DEP_ROUTE_MAP_TABLE];
  uint8_t map_marks[DEP_ROUTE_CHANGE_CAPACITY];
  /* Interned descriptor names, so map keys are integers. Names compare by
   * decoded spelling (dep_fd_ref_compare); ids are one-based. */
  dep_fd_ref_t names[DEP_ROUTE_NAME_CAPACITY];
  shell_avl_node_t name_index[DEP_ROUTE_NAME_CAPACITY];
  uint32_t name_root, name_count;
  dep_route_link_t links[DEP_ROUTE_CHANGE_CAPACITY];
  dep_route_member_t members[DEP_ROUTE_CHANGE_CAPACITY];
  dep_route_set_t snapshots[DEP_ROUTE_SNAPSHOT_CAPACITY];
  shell_avl_node_t snapshot_index[DEP_ROUTE_SNAPSHOT_CAPACITY];
  uint32_t snapshot_root;
  uint32_t snapshot_allocations;
  uint16_t snapshot_free, snapshot_free_count;
  bool snapshot_reuse;
  uint32_t link_count;
  uint32_t member_count;
  uint32_t snapshot_count;
  /* Snapshot collection marks (16), indexed by one-based id minus one. */
  uint8_t marks[DEP_ROUTE_SNAPSHOT_CAPACITY];
  /* Immutable map joins recur at outcome and scope boundaries. Reuse them
   * rather than traversing an unchanged descriptor map at every boundary. */
  dep_route_join_t joins[DEP_ROUTE_OPERATION_CAPACITY];
  /* Allocation identity is independent of the variable's current spelling.
   * Intern source operations once; paired opens and prefix versions reuse it.
   * Private slot numbers occupy the domain excluded from public io_numbers.
   * Both passes and nested parses share these identities. */
  dep_allocation_t allocations[DEP_ROUTE_ALLOCATION_CAPACITY];
  shell_avl_node_t allocation_index[DEP_ROUTE_ALLOCATION_CAPACITY];
  uint32_t allocation_root, allocation_count;
  /* Presence writer identities (operation, name), shared like allocation
   * records so inherited presence facts compare across passes and levels. */
  dep_presence_writer_t presence_writers[DEP_PRESENCE_WRITER_CAPACITY];
  shell_avl_node_t presence_writer_index[DEP_PRESENCE_WRITER_CAPACITY];
  uint32_t presence_writer_root, presence_writer_count;
  /* Open checkpoints: nested parses that will return their suffixes. */
  uint32_t checkpoints;
  /* Journal resets so far (dep_route_journal_t.epoch). */
  uint32_t epochs;
} dep_route_arena_t;

struct dep_route_journal {
  /* Values this pass reads and publishes; shared with the other pass and
   * with nested parses (dep_route_arena_t). */
  dep_route_arena_t *arena;
  /* Numeric descriptor spellings whose identity can be observed by this
   * parse. Named allocations need exact aliases only at these points; gaps are
   * represented by the operation's private allocation identity. Prepared once
   * from source-indexed operations before final route replay. */
  uint32_t observable_fds[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t observable_fd_count;
  /* Shared by construction and replay; recursive imports can retain symbols
   * after the corresponding journal-local allocation keys retire. */
  uint32_t *next_selector;
  dep_read_observations_t read_observations;
  bool scratch_observable;
  /* Some save with several possible places has marked them; until then no
   * descriptor read needs to look for such a mark. */
  bool save_marks;
  bool named_closes;
  bool ifs_seen;
  /* NULL in construction snapshots: only the final execution walk publishes
   * shell-owned diagnostics. owner names the setup/cleanup being executed. */
  dep_diagnostics_t *diagnostics;
  uint32_t diagnostic_owner;
  bool diagnostic_cleanup;
  /* Distinguishes this reset from every earlier one over the arena. */
  uint32_t epoch;
  /* Parse depth of the graph whose resources this pass creates. */
  uint32_t depth;
  /* The input has no safe dependency model (SHELL_DEP_EUNMODELED). Sticky
   * across journal resets and recursive parses: cleared when a root parse
   * begins, read when it ends. */
  bool unmodeled;
  /* Fallible redirection opens recorded as the cause of a missing descriptor
   * (a CLOSED route's value indexes this table), by their source spelling,
   * which also identifies their document node at every parse depth. A use
   * which relies on a cause marks it required; each parse level flags its
   * documents' open edges SHELL_DEP_EDGE_FLAG_REQUIRED. Root-parse scoped
   * with unmodeled. */
  const char *open_causes[DEP_OPEN_CAUSE_CAPACITY];
  uint32_t open_cause_count;
  bool open_cause_required[DEP_OPEN_CAUSE_CAPACITY];
};
_Static_assert(DEP_ROUTE_SNAPSHOT_CAPACITY + 1u <= UINT16_MAX,
               "route snapshot IDs fit packed journal nodes");
_Static_assert(DEP_ROUTE_STORAGE_BYTES <= 48u * DEP_ROUTE_CHANGE_CAPACITY,
               "canonical route storage must not grow the journal budget");

/* Descriptor-map callers supply one access bit. */
static uint8_t dep_fd_access_key(dep_fd_access_t access) {
  return (uint8_t)__builtin_ctzll(access);
}

/* Scope bookkeeping, as opposed to facts a forked child inherits: execution
 * entries, undo and setup records, process-substitution slots, owner-local
 * read-argument ordinals and transient read effects. */
static bool dep_route_bookkeeping(bool numeric, uint32_t value,
                                  dep_fd_access_t access) {
  switch (access) {
  case DEP_FD_ACCESS_PRIVATE_ENTRY:
    /* Except the temporary-assignment shadow set, which nested parses
     * inherit (dep_read_scalar_shadowed). */
    return !(numeric && value == DEP_SCALAR_IMPORT_EVENT);
  case DEP_FD_ACCESS_PRIVATE_SCOPE:
  case DEP_FD_ACCESS_SUBSTITUTION_STATUS:
  case DEP_FD_ACCESS_SAVED:
  case DEP_FD_ACCESS_ENTRY:
  case DEP_FD_ACCESS_SETUP_FRAME:
  case DEP_FD_ACCESS_ALLOCATION_SLOTS:
  case DEP_FD_ACCESS_UNDO_ENTRY:
  case DEP_FD_ACCESS_UNDO_TARGET:
  case DEP_FD_ACCESS_UNDO_EXEC:
  case DEP_FD_ACCESS_SETUP_MODE:
  case DEP_FD_ACCESS_PROCESS_SLOT:
  case DEP_FD_ACCESS_PROCESS_BEFORE:
    return true;
  case DEP_FD_ACCESS_READ_ARGUMENT:
    return numeric;
  case DEP_FD_ACCESS_EFFECT_STATE:
    return numeric && value != DEP_VARIABLE_STATE_EVENT;
  default:
    return false;
  }
}

/* Map keys: a class bit (DEP_ROUTE_KEY_BOOKKEEPING), then a descriptor id
 * above six access bits. Numeric references use their value as id; named
 * references use 2^32 plus their name id, so they order after every numeric
 * reference, as dep_fd_ref_compare() does. All fact keys of a map therefore
 * form one subtrie (shell_pmap_restrict). */
#define DEP_ROUTE_KEY_BOOKKEEPING (UINT64_C(1) << 63)
static uint64_t dep_route_key_of(uint64_t id, dep_fd_access_t access) {
  bool numeric = id < (UINT64_C(1) << 32);
  return (dep_route_bookkeeping(numeric, (uint32_t)id, access)
              ? DEP_ROUTE_KEY_BOOKKEEPING
              : 0) |
         id << 6 | dep_fd_access_key(access);
}

static dep_fd_access_t dep_route_key_access(uint64_t key) {
  return (dep_fd_access_t)(UINT64_C(1) << (key & 63u));
}

static SHELL_NONNULL(1) dep_fd_ref_t
    dep_route_key_fd(const dep_route_journal_t *journal, uint64_t key) {
  uint64_t id = (key & ~DEP_ROUTE_KEY_BOOKKEEPING) >> 6;
  return id >> 32 ? journal->arena->names[(uint32_t)id - 1]
                  : dep_fd_numeric((uint32_t)id);
}

static SHELL_NONNULL(1, 3) int dep_allocation_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key);
static SHELL_NONNULL(1, 2) uint32_t
    dep_allocation_slot(dep_route_journal_t *journal, const dep_fd_op_t *op);
static SHELL_NONNULL(1, 2) uint32_t
    dep_undo_slot(dep_route_journal_t *journal, const dep_fd_op_t *op,
                  dep_allocation_role_t role, bool create);
static SHELL_NONNULL(1) dep_fd_op_t dep_fd_move_close(const dep_fd_op_t *op);

/* Only descriptors whose route changed need an entry. Keeping
 * this sparse avoids multiplying the full descriptor table by every group
 * while still letting later duplications carry alternatives into fd 2. */
/* At most one independently selected route version per retained graph owner.
 * This is an internal control/allocation product, not the public fd-report
 * alternative bound. */
enum { DEP_ROUTE_STATE_CAPACITY = SHELL_DEP_MAX_NODES };
/* Versions a merge keeps apart for correlation; see dep_fd_widen(). */
enum { DEP_ROUTE_VERSION_LIMIT = 8 };

/* Per-command records of the setup-failure analysis
 * (dep_fd_correlated_setup_failures). Level b holds the versions before
 * prepared batch b; level L those after the last batch. pending holds, for
 * two adjacent levels, each version's joined unwind state per undo-list
 * class. Reused by every command: nothing here outlives one analysis. */
enum {
  DEP_FAILURE_LEVELS = SHELL_DEP_MAX_TOKENS * 3 + 1,
  DEP_FAILURE_WORDS = DEP_ROUTE_STATE_CAPACITY / 64,
  DEP_FAILURE_CLASSES = 3,
};
typedef struct {
  dep_route_state_t level[DEP_FAILURE_LEVELS];
  uint32_t count[DEP_FAILURE_LEVELS];
  uint32_t root[DEP_FAILURE_LEVELS][DEP_ROUTE_STATE_CAPACITY];
  uint8_t parent[DEP_FAILURE_LEVELS][DEP_ROUTE_STATE_CAPACITY];
  uint32_t begin[DEP_FAILURE_LEVELS], end[DEP_FAILURE_LEVELS];
  /* Versions that may fail at the level's batch, and those whose failure
   * proves the batch's duplication source closed. */
  uint64_t raises[DEP_FAILURE_LEVELS][DEP_FAILURE_WORDS];
  uint64_t closes_source[DEP_FAILURE_LEVELS][DEP_FAILURE_WORDS];
  dep_route_state_t pending[2][DEP_FAILURE_CLASSES][DEP_ROUTE_STATE_CAPACITY];
  uint64_t present[2][DEP_FAILURE_CLASSES][DEP_FAILURE_WORDS];
  /* For a running-class state: the level and version of the last failure
   * point it absorbed (level DEP_FAILURE_LEVELS when it joins several
   * lineages), and that failure point's proven-closed source, or
   * SHELL_DEP_FD_NONE. */
  uint32_t anchor_level[2][DEP_ROUTE_STATE_CAPACITY];
  uint32_t anchor_version[2][DEP_ROUTE_STATE_CAPACITY];
  uint32_t anchor_closed[2][DEP_ROUTE_STATE_CAPACITY];
} dep_failure_scan_t;

static SHELL_NONNULL(1, 3) int dep_presence_writer_compare(const void *context,
                                                           uint32_t index,
                                                           const void *key);
static SHELL_NONNULL(2) unsigned dep_presence_root(
    uint32_t root, const dep_route_journal_t *journal, dep_fd_ref_t name);
static SHELL_NONNULL(1, 2, 5) bool dep_presence_store(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t name,
    unsigned presence, const char *operation);
static SHELL_NONNULL(1, 2) bool dep_presence_put(dep_route_state_t *state,
                                                 dep_route_journal_t *journal,
                                                 dep_fd_ref_t name,
                                                 unsigned presence,
                                                 const char *operation);
static SHELL_NONNULL(1, 2, 3, 4) bool dep_prior_assignments(
    dep_route_state_t *state, dep_route_journal_t *journal,
    dep_snapshot_source_t *source, const char *position, bool assignment_only);
static SHELL_NONNULL(1, 2, 5) bool dep_presence_assume(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t name,
    unsigned presence, bool *possible);
static SHELL_NONNULL(1, 2, 4) bool dep_presence_clear(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_prefix_assignment_set_t *restored, const char *operation,
    uint32_t entry);

static SHELL_NONNULL(1) uint32_t
    dep_route_state_count(const dep_route_state_t *state) {
  return (uint32_t)state->alternative_count + 1;
}

typedef struct {
  uint32_t primary, next;
  bool first;
} dep_route_iterator_t;

static SHELL_NONNULL(1) dep_route_iterator_t
    dep_route_iterator(const dep_route_state_t *state) {
  return (dep_route_iterator_t){state->root, state->alternative_head, true};
}

/* Counted callers guarantee an available version (first or nonzero next).
 * No completion check or fallback is needed at this leaf. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_route_take(dep_route_iterator_t *iterator,
                   const dep_route_journal_t *journal) {
  if (iterator->first) {
    iterator->first = false;
    return iterator->primary;
  }
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_ALTERNATIVES);
  const dep_route_link_t *item = &journal->arena->links[iterator->next - 1];
  iterator->next = item->next;
  return item->value;
}

/* Open-ended traversal checks completion once before taking its value. */
static SHELL_NONNULL(1, 2,
                     3) bool dep_route_next(dep_route_iterator_t *iterator,
                                            const dep_route_journal_t *journal,
                                            uint32_t *root) {
  if (!iterator->first && !iterator->next)
    return false;
  *root = dep_route_take(iterator, journal);
  return true;
}

static SHELL_NONNULL(1) unsigned dep_member_height(
    const dep_route_journal_t *journal, uint32_t root) {
  return root ? journal->arena->members[root - 1].height : 0;
}

static SHELL_NONNULL(1) uint32_t
    dep_member_clone(dep_route_journal_t *journal, uint32_t root) {
  journal->arena->members[journal->arena->member_count] =
      journal->arena->members[root - 1];
  return ++journal->arena->member_count;
}

static SHELL_NONNULL(1) int dep_member_balance(dep_route_journal_t *journal,
                                               uint32_t root) {
  dep_route_member_t *member = &journal->arena->members[root - 1];
  unsigned left = dep_member_height(journal, member->left);
  unsigned right = dep_member_height(journal, member->right);
  member->height = (uint8_t)(1 + (left > right ? left : right));
  return (int)left - (int)right;
}

static SHELL_NONNULL(1) int dep_member_skew(const dep_route_journal_t *journal,
                                            uint32_t root) {
  const dep_route_member_t *member = &journal->arena->members[root - 1];
  return (int)dep_member_height(journal, member->left) -
         (int)dep_member_height(journal, member->right);
}

static SHELL_NONNULL(1) uint32_t
    dep_member_rotate(dep_route_journal_t *journal, uint32_t root, bool left) {
  dep_route_member_t *member = &journal->arena->members[root - 1];
  uint32_t next =
      dep_member_clone(journal, left ? member->right : member->left);
  dep_route_member_t *pivot = &journal->arena->members[next - 1];
  if (left) {
    member->right = pivot->left;
    pivot->left = root;
  } else {
    member->left = pivot->right;
    pivot->right = root;
  }
  dep_member_balance(journal, root);
  dep_member_balance(journal, next);
  return next;
}

/* The caller has established absence and reserved the path/rotation budget. */
static SHELL_NONNULL(1) uint32_t
    dep_member_insert(dep_route_journal_t *journal, uint32_t root,
                      uint32_t value) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_MEMBERSHIP);
  if (!root) {
    journal->arena->members[journal->arena->member_count] =
        (dep_route_member_t){.value = value, .height = 1};
    return ++journal->arena->member_count;
  }
  root = dep_member_clone(journal, root);
  dep_route_member_t *member = &journal->arena->members[root - 1];
  if (value < member->value)
    member->left = dep_member_insert(journal, member->left, value);
  else
    member->right = dep_member_insert(journal, member->right, value);
  int balance = dep_member_balance(journal, root);
  if (balance > 1) {
    if (dep_member_skew(journal, member->left) < 0) {
      member->left = dep_member_clone(journal, member->left);
      member->left = dep_member_rotate(journal, member->left, true);
    }
    return dep_member_rotate(journal, root, false);
  }
  if (balance < -1) {
    if (dep_member_skew(journal, member->right) > 0) {
      member->right = dep_member_clone(journal, member->right);
      member->right = dep_member_rotate(journal, member->right, false);
    }
    return dep_member_rotate(journal, root, true);
  }
  return root;
}

static SHELL_NONNULL(1, 2) bool dep_route_state_add_root(
    dep_route_state_t *state, dep_route_journal_t *journal, uint32_t root) {
  uint32_t count = dep_route_state_count(state);
  if (state->root == root)
    return true;
  uint32_t cursor = state->membership_root;
  while (cursor) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_MEMBERSHIP);
    const dep_route_member_t *member = &journal->arena->members[cursor - 1];
    if (member->value == root)
      return true;
    cursor = root < member->value ? member->left : member->right;
  }
  if (count == DEP_ROUTE_STATE_CAPACITY ||
      journal->arena->link_count == DEP_ROUTE_CHANGE_CAPACITY ||
      dep_member_height(journal, state->membership_root) + 5 >
          DEP_ROUTE_CHANGE_CAPACITY - journal->arena->member_count) {
    state->truncated = true;
    return false;
  }
  journal->arena->links[journal->arena->link_count] =
      (dep_route_link_t){root, state->alternative_head};
  state->alternative_head = ++journal->arena->link_count;
  state->alternative_count++;
  state->membership_root =
      dep_member_insert(journal, state->membership_root, root);
  return true;
}

static dep_route_state_t dep_route_state_single(uint32_t root) {
  return (dep_route_state_t){.root = root};
}

/* Rebuilding/filtering versions cannot clear prior loss or correlation. Apply
 * before a merge as well as when publishing a rebuilt state. */
static SHELL_NONNULL(1, 2) void dep_route_state_inherit(
    dep_route_state_t *result, const dep_route_state_t *input) {
  result->correlated |= input->correlated;
  result->truncated |= input->truncated;
}

enum { DEP_PARSE_DEPTH_LIMIT = SHELL_SOURCE_MAX_EXECUTABLE_NESTING };
#define DEP_SNAPSHOT_TABLE_CAPACITY                                            \
  (2 * SHELL_DEP_MAX_NODES + 3 * (DEP_PARSE_DEPTH_LIMIT + 1))

/* A numeric descriptor one owner uses, ascending by fd. It is a standard
 * descriptor with a fact in the owner's state, or one the owner's own
 * redirections touched; touched records which halves (dep_fd_access_t) its
 * last redirection assigned. This is emission provenance, not state. */
typedef struct {
  uint32_t fd;
  uint8_t touched;
} dep_owner_use_t;
/* An owner prepares at most SHELL_DEP_MAX_TOKENS * 3 operations
 * (dep_snapshot_source_t.ops), plus the three standard descriptors. */
enum { DEP_OWNER_USE_CAPACITY = SHELL_DEP_MAX_TOKENS * 3 + 3 };

/* Live construction state is separate from final-resolution scratch, but is
 * part of the same evaluation workspace. Tables retain scope/owner entries and
 * changed redirect-operand boundaries, not individual word substitutions.
 * Alternatives share immutable tree roots. A child parse checkpoints these
 * pools and releases only its own suffix. */
typedef struct {
  dep_route_state_t alternatives;
} dep_snapshot_table_t;

typedef struct {
  dep_named_effect_t effect;
  dep_named_effect_t empty_effect;
  dep_fd_ref_t parameter;
  uint32_t number, payload;
  unsigned number_value, timeout_value, payload_value, operand_kind;
  unsigned empty_number_value, empty_timeout_value, empty_payload_value;
  shell_builtin_variable_t variable;
  uint32_t parameter_prefix, position;
  bool option, valid, end, attached_static, attached_dynamic, dynamic;
  bool parameter_unquoted, can_disappear, may_fd, capture, restored;
  bool parameter_suffix, invalid_target, invalid_empty_target;
  bool unsupported_option;
  bool empty_known, empty_ifs, empty_restored;
  uint8_t number_scalar, timeout_scalar, payload_scalar;
  uint8_t parameter_variable;
} dep_read_word_t;

typedef struct {
  dep_read_word_t words[SHELL_DEP_MAX_TOKENS];
  dep_named_effect_t default_effect;
  const char *operation;
  uint32_t count;
  /* Only dynamic/captured argv needs per-version entry interpretation. */
  bool active, ifs_restored, entry_dependent;
} dep_read_plan_t;

enum {
  DEP_READ_OPTIONS,
  DEP_READ_DATA,
  DEP_READ_NUMBER,
  DEP_READ_TIMEOUT,
  DEP_READ_FD,
  DEP_READ_POSITIONAL,
  DEP_READ_TARGETS,
  DEP_READ_STOPPED_TARGETS,
  DEP_READ_PHASES
};

typedef struct {
  dep_route_state_t states[4][DEP_READ_PHASES][SHELL_DEP_MAX_TOKENS + 1];
  uint64_t ready[4][DEP_READ_PHASES];
} dep_read_frontier_t;

/* A parent version with its command's first count assignment names applied
 * for a nested expansion (dep_prior_assignments_apply). */
typedef struct {
  uint32_t parent, result, count, version;
  bool assignment_only, valid;
} dep_prior_memo_t;
enum { DEP_PRIOR_MEMO_CAPACITY = 4 };

struct dep_snapshot_source {
  dep_token_list_t tokens;
  dep_named_mutations_t mutations;
  /* Prefix commits before the first readonly rejection on the null path. */
  dep_named_mutations_t null_mutations;
  dep_prefix_assignment_set_t prefix_assignments;
  /* The command's assignment values expand in source order, each from the
   * same parent versions with one more earlier assignment applied. Resuming
   * from the previous expansion's result keeps a command's nested entries
   * O(assignments) map updates in all. Roots are collection roots. */
  dep_prior_memo_t prior_memo[DEP_PRIOR_MEMO_CAPACITY];
  uint32_t prior_memo_next;
  dep_exec_analysis_t exec;
  dep_read_plan_t read;
  /* NULL means this owner has no test expression. Otherwise borrow its
   * canonical program through the source operation, including refreshes. */
  shell_test_program_t *test;
  uint32_t observation_first[DEP_SNAPSHOT_SETUP],
      observation_last[DEP_SNAPSHOT_SETUP];
  dep_assignment_ifs_t assignment_ifs[SHELL_DEP_MAX_TOKENS];
  uint32_t assignment_ifs_count, assignment_ifs_cursor;
  uint32_t redirect_entry_table;
  dep_fd_op_t ops[SHELL_DEP_MAX_TOKENS * 3];
  shell_avl_node_t op_index[SHELL_DEP_MAX_TOKENS * 3];
  uint32_t op_root;
  /* Operand checkpoints and deferred heredoc boundaries share the owner's
   * incoming table. Append-only operations are consumed only over the delta
   * between checkpoints, never by replaying an entire redirect prefix. */
  uint32_t checkpoint_position[SHELL_DEP_MAX_TOKENS * 3];
  uint32_t checkpoint_table[SHELL_DEP_MAX_TOKENS * 3];
  bool checkpoint_diagnostic[SHELL_DEP_MAX_TOKENS * 3];
  shell_avl_node_t checkpoint_index[SHELL_DEP_MAX_TOKENS * 3];
  uint32_t checkpoint_root, checkpoint_count;
  uint32_t redirect_diagnostic_count;
  uint32_t op_count;
  uint32_t edge_cursor;
  uint32_t process_route_cursor;
  uint32_t process_word_cursor, body_process_cursor;
  /* One-based position of an empty process redirect's ambiguous pathname. */
  uint32_t empty_process_failure;
  bool deferred_document;
  bool undo_observable;
  /* Accumulated by the ordered setup walk, including cached prefixes. */
  bool setup_may_fail;
  bool setup_needs_walk;
  bool stdin_redirect;
  bool has_redirects;
  /* Argument/RHS expansion and readonly-assignment diagnostics use entry
   * stderr, before this owner's redirects. A diagnostic need not run a body. */
  bool entry_diagnostic;
  uint8_t argv_presence;
  /* Assignment RHS analysis selects EMPTY, PRESENT, or their union. This is
   * private phase state; child parsing checkpoints its own source records. */
  uint8_t assignment_dispatch;
  uint32_t readonly_stop;
  bool prepared;
};

typedef struct {
  uint32_t owner;
  uint32_t start;
} dep_ordered_owner_t;

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
  dep_fd_flow_t async_entry[DEP_EXECUTION_EVENT_CAPACITY];
} dep_fd_stream_t;

/* Private status cursor over the existing execution events. Group completion
 * replaces its provisional status with its body's final AND-OR result. Empty
 * stages stay unknown; no source or graph rescanning is needed. */
typedef struct {
  uint8_t status[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t execution[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t scoped_execution[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t entry_status[DEP_EXECUTION_EVENT_CAPACITY];
  uint8_t async_entry_status[DEP_EXECUTION_EVENT_CAPACITY];
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
  /* Setup diagnostics of this parse's owners, recorded as construction
   * interprets them (dep_record_diagnostic). capture is each owner's entry
   * after its read capture: where an assignment-phase diagnostic, which a
   * later expansion may reveal (dep_record_phase_diagnostic), is reported.
   * capture states are collection roots. */
  dep_diagnostics_t diagnostics;
  dep_route_state_t capture[SHELL_DEP_MAX_NODES];
  /* Construction's interpretation of each event, for publication: its entry
   * after read capture and assignment-phase stdin, its executed state, its
   * timer report state, and its enclosing scope's flow after it finished. And
   * of each group at its completion: its scope and setup-failure flows before
   * completion, and its parent scope's flow after. Collection roots. */
  dep_route_state_t event_entry[DEP_EXECUTION_EVENT_CAPACITY];
  dep_route_state_t event_executed[DEP_EXECUTION_EVENT_CAPACITY];
  dep_route_state_t event_report[DEP_EXECUTION_EVENT_CAPACITY];
  dep_fd_flow_t event_scope[DEP_EXECUTION_EVENT_CAPACITY];
  dep_fd_flow_t group_scope[SHELL_MAX_GROUPS];
  dep_fd_flow_t group_failure[SHELL_MAX_GROUPS];
  dep_fd_flow_t group_parent[SHELL_MAX_GROUPS];
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
  dep_cwd_flow_t async_cwd_entry[DEP_EXECUTION_EVENT_CAPACITY];
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
  /* Retain lexical facts across application resolver callbacks without
   * occupying the allocation-free parser's independent TLS backing. */
  shell_source_index_t source_index;
  /* Read evaluation completes before publication or recursive construction;
   * every owner reuses these two bounded, mode/phase/selector frontiers. */
  dep_read_frontier_t read_frontiers[2];
  /* Allocation identity tokens, shared by both replay streams. */
  uint32_t next_selector;
  dep_import_join_t import_join;
  dep_observation_program_t observations;
  dep_test_programs_t tests;
  /* Construction's version tables, per owner phase (dep_snapshot_table_t). */
  dep_snapshot_table_t snapshot_tables[DEP_SNAPSHOT_TABLE_CAPACITY];
  uint32_t snapshot_table_count;
  /* Values of every recursion level of an evaluation. */
  dep_route_arena_t route_arena;
  /* The evaluation's one interpretation: construction, which the final walk
   * publishes. Reset by the root parse; recursive parses checkpoint it. */
  dep_route_journal_t journal;
  dep_snapshot_frame_t snapshot_frames[DEP_PARSE_DEPTH_LIMIT + 1];
  /* One additional slot receives the rejected parse that exceeds the public
   * nesting limit. Index zero is unused because the root graph is caller
   * storage. */
  dep_recursive_parse_t recursive[DEP_PARSE_DEPTH_LIMIT + 2];
  dep_snapshot_source_t snapshot_sources[SHELL_DEP_MAX_NODES];
  uint32_t snapshot_source_count;
  /* Publication visits each owner's uses (dep_owner_use_t), never the
   * descriptor state it inherits. route_standard_mask marks the standard
   * descriptors among them. */
  dep_owner_use_t owner_uses[SHELL_DEP_MAX_NODES][DEP_OWNER_USE_CAPACITY];
  uint16_t owner_use_count[SHELL_DEP_MAX_NODES];
  uint8_t route_standard_mask[SHELL_DEP_MAX_NODES];
  /* Recognized read bodies publish their selected input separately. A group
   * only needs generic input exposure for an opaque descendant body. */
  bool generic_read[SHELL_DEP_MAX_NODES];
  bool test_body[SHELL_DEP_MAX_NODES];
  bool scoped_state_active[SHELL_MAX_GROUPS];
  /* Recursive expansion and final resolution use these at different times
   * for each containing group's evolving descriptor table. Keep the bounded
   * scratch in the caller-owned workspace, not on a parser stack. */
  bool group_state_ready[SHELL_MAX_GROUPS];
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
  /* The final walk's entry versions, as imported (a collection root). */
  dep_route_state_t entry_route_state;
  dep_route_state_t scoped_route_state[SHELL_MAX_GROUPS];
  dep_route_state_t group_route_state[SHELL_MAX_GROUPS];
  dep_route_state_t group_shell_route_state[SHELL_MAX_GROUPS];
  dep_failure_scan_t failure_scan;
  /* The root parse's observation inventory as it is collected, before
   * construction's journal is reset and receives it. */
  dep_read_observations_t read_inventory;
  /* Effective read/write alternatives at each owner, including command-local
   * redirects. This reuses the descriptor journal so ordinary byte-flow and
   * shell-owned timing reports cannot disagree at conditional joins. */
  /* Deferred I/O publication: ordinary commands retain resolved byte-route
   * unions; read/group owners retain correlated execution versions. Never
   * use this cache as a baseline for another owner's semantic evaluation. */
  dep_route_state_t owner_route_state[SHELL_DEP_MAX_NODES];
  /* Each owner's final local state, after its redirections (a collection
   * root): publication reads its descriptors' routes from it. */
  dep_route_state_t owner_local_state[SHELL_DEP_MAX_NODES];
  dep_route_set_t group_shell_time_routes[SHELL_MAX_GROUPS];
  bool group_shell_time_routes_ready[SHELL_MAX_GROUPS];
  uint32_t original_edge_count;
  uint32_t pipe_count;
  /* Phase-local boundary reconciliation scratch. Only actual-flow resource
   * keys enter the index; redundant group exposures are never stored. */
  dep_stream_use_t external_keys[DEP_EXTERNAL_USE_CAPACITY];
  dep_stream_use_t external_pending[DEP_EXTERNAL_USE_CAPACITY];
  uint32_t external_key_count;
  uint32_t external_key_root;
  uint32_t external_resource[DEP_EXTERNAL_USE_CAPACITY];
  shell_avl_node_t external_resource_index[DEP_EXTERNAL_USE_CAPACITY];
  uint32_t external_outermost[DEP_EXTERNAL_USE_CAPACITY];
  uint32_t external_active_start[SHELL_DEP_MAX_NODES];
  uint32_t external_active_count;
  uint32_t external_next_use[DEP_EXTERNAL_USE_CAPACITY];
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

/* Validate optional scratch once at the graph boundary. Syntax-only and empty
 * inputs may still be classified without it; construction requires a prepared
 * non-NULL workspace. Internal parsers inherit these size/alignment guarantees.
 */
static shell_dep_limits_t dep_prepare_limits(const shell_dep_limits_t *limits) {
  shell_dep_limits_t prepared = limits ? *limits : SHELL_DEP_LIMITS_DEFAULT;
  if (!prepared.workspace ||
      prepared.workspace_size < sizeof(dep_route_workspace_t) ||
      (uintptr_t)prepared.workspace % _Alignof(dep_route_workspace_t) != 0) {
    prepared.workspace = NULL;
    prepared.workspace_size = 0;
  }
  return prepared;
}

/* Graph state occupies the fixed prefix. Additional bytes in that same
 * evaluation buffer are available to lexical preparation throughout parsing,
 * including while a recursive child borrows the parent's route journals. */
static SHELL_NONNULL(1, 3) shell_source_workspace_scope_t
    dep_source_workspace(const char *source, size_t length,
                         const shell_dep_limits_t *limits) {
  if (limits->workspace) {
    dep_route_workspace_t *workspace = limits->workspace;
    shell_source_operation_index(&workspace->source_index);
    return shell_source_workspace_begin_retained(
        source, length,
        (unsigned char *)limits->workspace + sizeof(dep_route_workspace_t),
        limits->workspace_size - sizeof(dep_route_workspace_t));
  }
  return shell_source_workspace_begin(source, length, NULL, 0);
}

bool shell_dep_resolved_workspace_size(size_t command_length,
                                       const shell_dep_limits_t *limits,
                                       size_t *workspace_size) {
  size_t cache_size, graph_size, source_scratch_size;
  *workspace_size = 0;
  size_t alignment = shell_dep_workspace_alignment();
  if (!shell_expand_cache_size(command_length, &cache_size) ||
      !shell_dep_workspace_size(limits, &graph_size) ||
      !shell_source_workspace_size(command_length, &source_scratch_size) ||
      cache_size > SIZE_MAX - graph_size - alignment ||
      source_scratch_size > SIZE_MAX - cache_size - graph_size - alignment)
    return false;
  *workspace_size = cache_size + graph_size + alignment + source_scratch_size;
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
  int descriptor_order = dep_fd_ref_compare(
      (dep_fd_ref_t){
          .name = a->fd_name, .value = a->fd, .name_len = a->fd_name_len},
      (dep_fd_ref_t){
          .name = b->fd_name, .value = b->fd, .name_len = b->fd_name_len});
  if (descriptor_order)
    return descriptor_order;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  if (a->route.kind != b->route.kind)
    return a->route.kind < b->route.kind ? -1 : 1;
  return a->route.value < b->route.value ? -1
                                         : a->route.value != b->route.value;
}

/* The recorder establishes uniqueness once. Capacity preflight and join
 * materialization subsequently iterate this same unique plan, with no second
 * deduplication. Keys use resource provenance rather than an import slot:
 * distinct aliases can refer to the same route. */
static SHELL_NONNULL(1) bool dep_record_fd_import_use(
    dep_subgraph_streams_t *streams, uint32_t owner, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_fd_route_t route) {
  dep_fd_import_use_t key = {.owner = owner,
                             .fd = fd.value,
                             .access = access,
                             .route = route,
                             .fd_name = fd.name,
                             .fd_name_len = fd.name_len};
  uint32_t candidate = streams->fd_import_use_count + 1, match = 0;
  streams->fd_import_use_root = shell_avl_insert(
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

static SHELL_NONNULL(1, 3) int dep_read_observation_compare(const void *context,
                                                            uint32_t index,
                                                            const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
  const dep_read_observations_t *observations = context;
  return dep_fd_ref_compare(observations->entries[index].fd,
                            *(const dep_fd_ref_t *)key);
}

static SHELL_NONNULL(1) bool dep_read_observe(
    dep_read_observations_t *observations, dep_fd_ref_t fd, unsigned role) {
  uint32_t candidate = observations->count + 1, match = 0;
  observations->root =
      shell_avl_insert(observations->index, observations->root, candidate,
                       DEP_READ_OBSERVATION_CAPACITY,
                       dep_read_observation_compare, observations, &fd, &match);
  if (!match)
    return false;
  if (match == candidate)
    observations->entries[observations->count++] = (dep_read_observation_t){
        .fd = fd,
        .role = role,
        .variable = fd.value == SHELL_DEP_FD_NAMED
                        ? shell_builtin_name_index(fd.name, fd.name_len)
                        : 0};
  else
    observations->entries[match - 1].role |= role;
  observations->active |= role != 0;
  observations->presence |= (role & DEP_READ_OBSERVE_PRESENCE) != 0;
  observations->identity |=
      fd.value == SHELL_DEP_FD_NAMED && (role & DEP_READ_OBSERVE_IDENTITY);
  return true;
}

static SHELL_NONNULL(1) const dep_read_observation_t *dep_read_observation_find(
    const dep_read_observations_t *observations, dep_fd_ref_t fd) {
  uint32_t cursor = observations->root;
  while (cursor) {
    int order = dep_read_observation_compare(observations, cursor - 1, &fd);
    if (!order)
      return &observations->entries[cursor - 1];
    cursor = order > 0 ? observations->index[cursor - 1].left
                       : observations->index[cursor - 1].right;
  }
  return NULL;
}

static SHELL_NONNULL(1) unsigned dep_read_observation(
    const dep_read_observations_t *observations, dep_fd_ref_t fd) {
  const dep_read_observation_t *use =
      dep_read_observation_find(observations, fd);
  return use ? use->role : 0;
}

/* Recursive substitution plumbing owns one standard stream. Do not import a
 * parent redirect for that stream: `$(...)` and `<(...)` capture child stdout,
 * while `>(...)` supplies child stdin. Other persistent descriptors, including
 * stderr and auxiliary numeric FDs, remain available to the child. imports is
 * an initialized substitution snapshot; fd is its captured standard stream and
 * access is READ or WRITE. Capacity exhaustion remains an operational failure.
 */
/* The child's capture pipe replaces standard stream fd: 0 for `>(...)`, whose
 * stdin it supplies, or 1 for `$(...)` and `<(...)`, whose stdout it takes
 * (dep_child_install_capture). */
static SHELL_NONNULL(1) void dep_fd_import_install_capture(
    dep_fd_imports_t *imports, uint32_t fd) {
  imports->process_capture_mask |= (uint8_t)(1u << fd);
}

static SHELL_NONNULL(1, 2) int dep_stream_order(const dep_stream_use_t *a,
                                                const dep_stream_use_t *b) {
  if (a->anchor != b->anchor)
    return a->anchor < b->anchor ? -1 : 1;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  if (a->owner != b->owner)
    return a->owner < b->owner ? -1 : 1;
  return dep_fd_ref_compare(dep_stream_fd(a), dep_stream_fd(b));
}

static SHELL_NONNULL(1, 3) int dep_stream_compare(const void *context,
                                                  uint32_t index,
                                                  const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  const dep_stream_use_t *uses = context;
  return dep_stream_order(&uses[index], key);
}

static SHELL_NONNULL(1, 3) int dep_external_stream_compare(const void *context,
                                                           uint32_t index,
                                                           const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
  const dep_stream_use_t *uses = context;
  return dep_stream_order(&uses[index], key);
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_record_stream_use(
    dep_stream_use_t *uses, uint32_t *count, shell_avl_node_t *index,
    uint32_t *root, uint32_t owner, dep_fd_ref_t fd, dep_fd_access_t access,
    uint32_t anchor) {
  dep_stream_use_t key = {owner, fd.value, anchor,     access,
                          false, fd.name,  fd.name_len};
  uint32_t candidate = *count + 1, match = 0;
  *root = shell_avl_insert(index, *root, candidate, SHELL_DEP_MAX_EDGES,
                           dep_stream_compare, uses, &key, &match);
  if (!match)
    return false;
  if (match == candidate)
    uses[(*count)++] = key;
  return true;
}

static SHELL_NONNULL(1) bool dep_record_actual_capture(
    dep_subgraph_streams_t *streams, uint32_t owner, dep_fd_ref_t fd,
    dep_fd_access_t access, uint32_t anchor) {
  dep_stream_use_t key = {owner, fd.value, anchor,     access,
                          true,  fd.name,  fd.name_len};
  uint32_t candidate = streams->capture_use_count + 1, match = 0;
  streams->capture_root =
      shell_avl_insert(streams->capture_index, streams->capture_root, candidate,
                       SHELL_DEP_MAX_EDGES, dep_stream_compare,
                       streams->capture_uses, &key, &match);
  if (!match)
    return false;
  if (match == candidate)
    streams->capture_uses[streams->capture_use_count++] = key;
  else
    streams->capture_uses[match - 1].actual_group = true;
  return true;
}

static SHELL_NONNULL(1) bool dep_record_external_use(
    dep_subgraph_streams_t *streams, uint32_t owner, dep_fd_ref_t fd,
    dep_fd_access_t access, uint32_t inherited) {
  dep_stream_use_t key = {owner, fd.value, inherited,  access,
                          false, fd.name,  fd.name_len};
  uint32_t candidate = streams->external_use_count + 1, match = 0;
  streams->external_root = shell_avl_insert(
      streams->external_index, streams->external_root, candidate,
      DEP_EXTERNAL_USE_CAPACITY, dep_external_stream_compare,
      streams->external_uses, &key, &match);
  if (!match)
    return false;
  if (match == candidate)
    streams->external_uses[streams->external_use_count++] = key;
  return true;
}

/* Visit only uses of this parent pipe side. The stream index is ordered by
 * anchor/access first, making this O(log U + matching uses), not a scan of all
 * other pipelines' deferred uses for each pipe. */
static SHELL_NONNULL(1, 6, 7, 8, 9) bool dep_collect_pipe_uses(
    const dep_subgraph_streams_t *streams, uint32_t root, uint32_t anchor,
    dep_fd_access_t access, uint32_t pipe, dep_stream_use_t *uses,
    uint32_t *count, shell_avl_node_t *index, uint32_t *output_root) {
  if (!root)
    return true;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
  const dep_stream_use_t *item = &streams->pipe_uses[root - 1];
  const shell_avl_node_t *node = &streams->pipe_index[root - 1];
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
                               dep_stream_fd(item), access, pipe) &&
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

static SHELL_NONNULL(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11) bool dep_parse_dup_redirect(const dep_token_t *token, uint32_t *fd,
                                    uint32_t *target_fd, const char **fd_name,
                                    uint32_t *fd_name_len,
                                    const char **target_fd_name,
                                    uint32_t *target_fd_name_len, bool *close,
                                    dep_fd_access_t *access,
                                    bool *target_unquoted, bool *move) {
  if (token->len < 2)
    return false;
  size_t after = 0;
  uint32_t value = 0;
  *fd_name = NULL;
  *fd_name_len = 0;
  *target_fd_name = NULL;
  *target_fd_name_len = 0;
  *target_unquoted = false;
  *move = false;
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
  size_t move_prefix = 0;
  bool move_suffix = shell_source_fd_move_prefix(
      token->start + pos, token->len - pos, &move_prefix);
  if (dep_parse_fd_parameter(token->start, pos,
                             move_suffix ? pos + (uint32_t)move_prefix
                                         : token->len,
                             target_fd_name, target_fd_name_len)) {
    *target_unquoted = token->start[pos] != '"';
    *target_fd = SHELL_DEP_FD_NAMED;
    *close = false;
    *move = move_suffix;
    return true;
  }
  shell_process_fd_target_t target = shell_process_classify_static_fd_target(
      token->start + pos, token->len - pos, &value);
  if (target == SHELL_PROCESS_FD_TARGET_FD ||
      target == SHELL_PROCESS_FD_TARGET_MOVE) {
    *target_fd = value;
    *close = false;
    *move = target == SHELL_PROCESS_FD_TARGET_MOVE;
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
    bool move = false;
    bool failed = false;
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
                                &target_unquoted, &move)) {
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
      size_t move_prefix = 0;
      move =
          shell_source_fd_move_prefix(target->start, target->len, &move_prefix);
      if (dep_parse_fd_parameter(target->start, 0,
                                 move ? (uint32_t)move_prefix : target->len,
                                 &target_fd_name, &target_fd_name_len)) {
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
        } else if (target_kind == SHELL_PROCESS_FD_TARGET_FD ||
                   target_kind == SHELL_PROCESS_FD_TARGET_MOVE) {
          close = false;
          move = target_kind == SHELL_PROCESS_FD_TARGET_MOVE;
        } else if ((target_kind == SHELL_PROCESS_FD_TARGET_PATH ||
                    target_kind == SHELL_PROCESS_FD_TARGET_MOVE_INVALID) &&
                   !shell_source_argument_has_dynamic_syntax(target->start,
                                                             target->len)) {
          failed = true;
          close = false;
          move = false;
          target_fd = SHELL_DEP_FD_NONE;
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
        failed  ? DEP_FD_OP_FAILED
        : close ? DEP_FD_OP_CLOSE
        : move  ? DEP_FD_OP_MOVE
                : DEP_FD_OP_DUP,
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
        false,
        false,
        false,
        NULL,
        0,
        0,
    };
  }
  return true;
}

/* Process substitutions are descriptor routes just like file redirects. They
 * have already contributed their graph edges before effective routing runs;
 * retain the source position here so a later redirect, close, or duplicate
 * can replace or copy that route without leaving a stale PIPE edge behind. */
/* NULL cursor replays the complete list. NULL dynamic_edges omits the final
 * resolver's edge-replacement bookkeeping when preparing snapshot operations.
 */
/* Process routes whose edge publication replaces by its dynamic byte use:
 * a standalone temporary route without a byte use; a persistent route not
 * named by a descriptor variable (both only when operations carries owner's
 * process operations); and an opened standalone word of a read, a test or
 * no byte use, or of a body before any setup stop. */
static SHELL_NONNULL(1, 3, 6) void dep_mark_dynamic_process_edges(
    const dep_process_route_map_t *process_routes, uint32_t owner,
    const dep_snapshot_source_t *source, uint32_t setup_stop, bool operations,
    bool *dynamic_edges) {
  for (uint32_t route = process_routes->first[owner]; route;
       route = process_routes->entries[route - 1].next) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
    const dep_process_route_t *item = &process_routes->entries[route - 1];
    if (operations)
      dynamic_edges[item->edge] |= item->temporary
                                       ? item->standalone && !item->byte_use
                                       : item->fd.value != SHELL_DEP_FD_NAMED;
    if (!item->temporary || !process_routes->track[owner] || !item->standalone)
      continue;
    if (item->command_word &&
        (source->read.active || source->test || !item->byte_use))
      dynamic_edges[item->edge] = true;
    if (setup_stop == UINT32_MAX && item->body_word && !item->byte_use)
      dynamic_edges[item->edge] = true;
  }
}

static SHELL_NONNULL(2, 4, 5) bool dep_add_prepared_process_operations(
    uint32_t owner, const dep_process_route_map_t *process_routes,
    uint32_t *cursor, dep_fd_op_t *ops, uint32_t *op_count,
    uint32_t op_capacity) {
  uint32_t route = cursor && *cursor != 0
                       ? process_routes->entries[*cursor - 1].next
                       : process_routes->first[owner];
  for (; route != 0; route = process_routes->entries[route - 1].next) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
    const dep_process_route_t *binding = &process_routes->entries[route - 1];
    if (cursor)
      *cursor = route;
    if (binding->temporary && !process_routes->track[owner])
      continue;
    if (*op_count == op_capacity)
      return false;
    ops[(*op_count)++] = (dep_fd_op_t){
        binding->position,
        binding->temporary ? DEP_FD_OP_PROCESS : DEP_FD_OP_DYNAMIC,
        binding->fd.value,
        SHELL_DEP_FD_NONE,
        binding->temporary ? binding->source : binding->fd.name,
        binding->fd.name_len,
        NULL,
        0,
        binding->edge,
        binding->access,
        false,
        false,
        false,
        NULL,
        false,
        false,
        false,
        binding->guard,
        process_routes->observed_low[owner],
        0};
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
  if ((ops[index].kind == DEP_FD_OP_PROCESS) !=
      (key->kind == DEP_FD_OP_PROCESS))
    return ops[index].kind == DEP_FD_OP_PROCESS ? -1 : 1;
  return dep_fd_ref_compare((dep_fd_ref_t){.name = ops[index].fd_name,
                                           .value = ops[index].fd,
                                           .name_len = ops[index].fd_name_len},
                            (dep_fd_ref_t){.name = key->fd_name,
                                           .value = key->fd,
                                           .name_len = key->fd_name_len});
}

/* A newly discovered resource contributes all halves of its open together.
 * Existing prepared operations belong to earlier resources or static dup/close
 * syntax, so incremental snapshot preparation indexes only the new suffix.
 * The caller supplies at most SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS
 * operations. Every replay subsequently reads the prepared reset decision. */
static SHELL_NONNULL(1) void dep_prepare_fd_operation_resets(
    dep_fd_op_t *ops, uint32_t count, bool undo_observable, uint8_t undo_mode) {
  shell_avl_node_t seen[SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS];
  uint32_t root = 0;
  uint32_t first_high_open = UINT32_MAX;
  /* An open or copy onto a descriptor at or above 10 can land on a save of
   * an earlier redirection, so those saves are observable. */
  for (uint32_t i = 0; i < count; i++)
    if (ops[i].fd >= DEP_BASH_VARREDIR_MIN_FD &&
        ops[i].fd <= SHELL_DEP_FD_MAX &&
        (ops[i].kind == DEP_FD_OP_DOCUMENT ||
         ops[i].kind == DEP_FD_OP_DYNAMIC || dep_fd_op_copies(ops[i].kind)) &&
        ops[i].pos < first_high_open)
      first_high_open = ops[i].pos;
  for (uint32_t i = 0; i < count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    ops[i].variable =
        ops[i].fd == SHELL_DEP_FD_NAMED
            ? shell_builtin_name_index(ops[i].fd_name, ops[i].fd_name_len)
            : 0;
    ops[i].undo_observable =
        undo_observable ||
        (first_high_open != UINT32_MAX &&
         ops[i].fd < DEP_BASH_VARREDIR_MIN_FD && ops[i].pos < first_high_open);
    ops[i].undo_mode = undo_mode;
    uint32_t match = 0;
    root = shell_avl_insert(seen, root, i + 1, count, dep_fd_operation_compare,
                            ops, &ops[i], &match);
    ops[i].resets_descriptor =
        match == i + 1 && ops[i].kind != DEP_FD_OP_CLOSE &&
        ops[i].kind != DEP_FD_OP_PROCESS &&
        (ops[i].fd == SHELL_DEP_FD_NAMED || !dep_fd_op_copies(ops[i].kind));
    ops[i].paired_open =
        i != 0 && ops[i].pos == ops[i - 1].pos &&
        ops[i].kind == ops[i - 1].kind &&
        (ops[i].kind == DEP_FD_OP_DOCUMENT ||
         ops[i].kind == DEP_FD_OP_DYNAMIC) &&
        dep_fd_ref_equal((dep_fd_ref_t){.name = ops[i].fd_name,
                                        .value = ops[i].fd,
                                        .name_len = ops[i].fd_name_len},
                         (dep_fd_ref_t){.name = ops[i - 1].fd_name,
                                        .value = ops[i - 1].fd,
                                        .name_len = ops[i - 1].fd_name_len});
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
  const dep_fd_op_t *op = &ops[index];
  return dep_fd_ref_compare(
      op->kind == DEP_FD_OP_MOVE
          ? (dep_fd_ref_t){.name = op->target_fd_name,
                           .value = op->target_fd,
                           .name_len = op->target_fd_name_len}
          : (dep_fd_ref_t){.name = op->fd_name,
                           .value = op->fd,
                           .name_len = op->fd_name_len},
      *(const dep_fd_ref_t *)key);
}

/* Static dup/close records are in source order. Index the first close of each
 * descriptor once; resource discovery cannot change this syntax-local fact. */
static SHELL_NONNULL(1) void dep_prepare_fd_close_history(dep_fd_op_t *ops,
                                                          uint32_t count) {
  shell_avl_node_t closed[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t root = 0;
  for (uint32_t i = 0; i < count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    dep_fd_op_t *op = &ops[i];
    if (dep_fd_op_copies(op->kind)) {
      dep_fd_ref_t fd = {.name = op->target_fd_name,
                         .value = op->target_fd,
                         .name_len = op->target_fd_name_len};
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
    if (op->kind == DEP_FD_OP_CLOSE ||
        (op->kind == DEP_FD_OP_MOVE && !dep_fd_op_numeric_self_dup(op))) {
      dep_fd_ref_t fd = op->kind == DEP_FD_OP_MOVE
                            ? (dep_fd_ref_t){.name = op->target_fd_name,
                                             .value = op->target_fd,
                                             .name_len = op->target_fd_name_len}
                            : (dep_fd_ref_t){.name = op->fd_name,
                                             .value = op->fd,
                                             .name_len = op->fd_name_len};
      uint32_t match = 0;
      root = shell_avl_insert(closed, root, i + 1, count, dep_closed_fd_compare,
                              ops, &fd, &match);
    }
  }
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

static SHELL_NONNULL(4) void dep_exec_option_dynamic(const char *word,
                                                     size_t length, bool quoted,
                                                     void *context) {
  (void)word;
  (void)length;
  (void)quoted;
  dep_exec_option_t *option = context;
  option->dynamic = true;
  if (option->tail_is_argv0)
    option->attached_dynamic = true;
  else
    option->unresolved = true;
}

/* tokens is a scanned list and command indexes its command word. The required
 * outputs are writable; optional exec_persistent/wrapper_kind/current_redirects
 * may be NULL. current_redirects preserves a reached builtin wrapper's setup
 * scope independently of the effective target's lookup mode. */
static SHELL_NONNULL(1, 3, 4) const dep_token_t *dep_effective_static_builtin(
    const dep_token_list_t *tokens, uint32_t command,
    uint32_t *effective_command, bool *dynamic_target, bool *exec_persistent,
    shell_dep_command_wrapper_t *wrapper_kind, bool *current_redirects);

/* Under Bash's default varredir_close behavior, current-shell builtins and
 * brace groups retain their named allocations. External commands allocate in
 * their child; redirect-only commands have no retaining command lifetime.
 * Pipeline/background and subshell scopes remain private to their shell. */
static SHELL_NONNULL(1, 2) bool dep_owner_persists_named_binding(
    const shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t owner) {
  return graph->nodes[owner].type == SHELL_NODE_GROUP ||
         (graph->nodes[owner].type == SHELL_NODE_CMD &&
          (graph->nodes[owner].cmd.token_count != 0 ||
           graph->nodes[owner].cmd.kind != SHELL_COMMAND_SIMPLE) &&
          (context
               ->expansion_status[SHELL_MAX_GROUPS + context->node_range[owner]]
               .redirect_scopes &
           DEP_REDIRECT_CURRENT) != 0);
}

static SHELL_NONNULL(1, 2) bool dep_fd_bound(const dep_route_state_t *state,
                                             const dep_route_journal_t *journal,
                                             dep_fd_ref_t fd);
static SHELL_NONNULL(1, 2) bool dep_route_state_stores(
    const dep_route_state_t *state, const dep_route_journal_t *changes,
    dep_fd_ref_t fd, dep_fd_access_t access);

/* Whether the owner's final state has a descriptor at numeric fd: a bound
 * descriptor with a stored READ, WRITE or BINDING fact. An untouched
 * standard descriptor without one takes the boundary defaults. */
static SHELL_NONNULL(1, 2) bool dep_owner_use_present(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    dep_fd_ref_t fd) {
  return dep_fd_bound(state, journal, fd) &&
         (dep_route_state_stores(state, journal, fd, DEP_FD_ACCESS_READ) ||
          dep_route_state_stores(state, journal, fd, DEP_FD_ACCESS_WRITE) ||
          dep_route_state_stores(state, journal, fd, DEP_FD_ACCESS_BINDING));
}

/* Record that owner uses fd, with the halves its latest redirection
 * assigned (access), or with none when touched is false. state is the owner's
 * final local state. */
static SHELL_NONNULL(1, 3, 4) void dep_owner_use(
    dep_route_workspace_t *workspace, uint32_t owner,
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    uint32_t fd, dep_fd_access_t access, bool touched) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_STREAMS);
  if (fd > SHELL_DEP_FD_MAX ||
      !dep_owner_use_present(state, journal, dep_fd_numeric(fd)))
    return;
  dep_owner_use_t *uses = workspace->owner_uses[owner];
  uint32_t count = workspace->owner_use_count[owner], low = 0, high = count;
  while (low < high) {
    uint32_t middle = low + (high - low) / 2;
    if (uses[middle].fd < fd)
      low = middle + 1;
    else
      high = middle;
  }
  if (low == count || uses[low].fd != fd) {
    memmove(uses + low + 1, uses + low, (count - low) * sizeof(uses[0]));
    uses[low] = (dep_owner_use_t){fd, 0};
    workspace->owner_use_count[owner]++;
    if (fd <= 2)
      workspace->route_standard_mask[owner] |= (uint8_t)(1u << fd);
  }
  if (touched)
    uses[low].touched = (uint8_t)access;
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
    if (dep_skip_nonargument(tokens, &i))
      continue;
    const dep_token_t *word = &tokens->tokens[i];
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

/* A reached execution body can use its descriptor bindings. Setup-only
 * stages still retain their explicit effects and independently collected
 * diagnostics, but never become default capture/import/boundary producers. */
static SHELL_NONNULL(1, 2) bool dep_owner_has_body_io(
    const shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t owner, bool reached) {
  if (!reached || context->owner_setup_stop[owner] != UINT32_MAX)
    return false;
  const shell_dep_node_t *node = &graph->nodes[owner];
  return node->type == SHELL_NODE_GROUP ||
         (node->cmd.token_count != 0 &&
          dep_owner_exec(context, owner)->kind != DEP_EXEC_DESCRIPTORS);
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

typedef struct {
  shell_builtin_variable_scan_t variable;
  unsigned skip;
} dep_variable_scan_t;

static SHELL_NONNULL(2) bool dep_variable_assignment_byte(unsigned char byte,
                                                          void *context) {
  dep_variable_scan_t *scan = context;
  return shell_builtin_variable_byte(byte, &scan->variable);
}

static SHELL_NONNULL(3) bool dep_variable_word_byte(unsigned char byte,
                                                    size_t position,
                                                    void *context) {
  (void)position;
  dep_variable_scan_t *scan = context;
  if (scan->skip) {
    scan->skip--;
    return true;
  }
  return shell_builtin_variable_byte(byte, &scan->variable);
}

/* Prepared effects retain the registry identity needed by path-sensitive
 * validation. Decode the already-isolated target once, while preparing the
 * command, rather than rescanning source words during every route replay. */
static SHELL_NONNULL(1) uint8_t
    dep_named_effect_variable(const dep_named_effect_t *effect) {
  dep_variable_scan_t scan = {
      .variable = {.valid = true, .names = SHELL_BUILTIN_VARIABLE_MASK},
      .skip = effect->kind == DEP_NAMED_EFFECT_PRINTF_ATTACHED ? 2 : 0};
  if (effect->kind == DEP_NAMED_EFFECT_STATIC_ASSIGNMENT) {
    shell_source_decoded_assignment_t assignment;
    if (!shell_source_scan_decoded_assignment(
            effect->token.start, effect->token.len,
            dep_variable_assignment_byte, &scan, &assignment))
      return 0;
  } else {
    size_t decoded;
    if (shell_process_visit_word_value(effect->token.start, effect->token.len,
                                       dep_variable_word_byte, &scan,
                                       &decoded) != SHELL_PROCESS_OK)
      return 0;
  }
  return shell_builtin_variable_index(&scan.variable);
}

/* Command-prefix assignments are temporary unless the effective declaration
 * builtin promotes the same name into the current shell. Index their logical
 * identifier spellings once while locating the command word, then resolve
 * declaration operands in O(log n) without copying names or rescanning every
 * prefix for every operand. */
static SHELL_NONNULL(1, 3) int dep_prefix_assignment_compare_word(
    const dep_prefix_assignment_set_t *assignments, uint32_t index,
    const dep_token_t *word, bool assignment) {
  const dep_variable_token_t *expected = &assignments->names[index];
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
    (void)shell_process_visit_word_value(
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
    dep_prefix_assignment_set_t *assignments, const dep_token_t *name,
    bool append) {
  uint32_t candidate = assignments->count + 1;
  uint32_t match = 0;
  assignments->root = shell_avl_insert(
      assignments->index, assignments->root, candidate, SHELL_DEP_MAX_TOKENS,
      dep_prefix_assignment_compare, assignments, name, &match);
  if (match == candidate) {
    dep_variable_token_t *inserted = &assignments->names[assignments->count++];
    inserted->start = name->start;
    inserted->len = name->len;
    inserted->variable = shell_builtin_name_index(name->start, name->len);
    inserted->append = append;
    if (inserted->variable)
      assignments->special[assignments->special_count++] =
          assignments->count - 1;
  }
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

/* Resolve only explicit mutation targets, once during owner preparation.
 * The indexed inventory lends its already-isolated identifier; later journal
 * versions need neither decoded strings nor another source lookup. */
static SHELL_NONNULL(1, 2) void dep_prepare_observed_effect(
    dep_named_effect_t *effect, const dep_read_observations_t *observations) {
  if (effect->kind == DEP_NAMED_EFFECT_OPAQUE_WRITE ||
      effect->kind == DEP_NAMED_EFFECT_OPAQUE_UNSET)
    return;
  effect->variable = dep_named_effect_variable(effect);
  uint32_t root = observations->root;
  while (root) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    dep_fd_ref_t ref = observations->entries[root - 1].fd;
    int order = -1;
    if (ref.value == SHELL_DEP_FD_NAMED) {
      dep_named_route_target_t target = {
          .name = ref.name,
          .name_len = ref.name_len,
          .skip = effect->kind == DEP_NAMED_EFFECT_PRINTF_ATTACHED ? 2 : 0};
      if (effect->kind == DEP_NAMED_EFFECT_STATIC_ASSIGNMENT) {
        shell_source_decoded_assignment_t ignored;
        (void)shell_source_scan_decoded_assignment(
            effect->token.start, effect->token.len,
            dep_named_assignment_target_byte, &target, &ignored);
      } else {
        size_t ignored;
        (void)shell_process_visit_word_value(
            effect->token.start, effect->token.len, dep_named_route_target_byte,
            &target, &ignored);
      }
      order = target.order;
      unsigned char trailing;
      if (!order && dep_fd_name_next_byte(ref.name, ref.name_len,
                                          &target.name_position, &trailing))
        order = 1;
    }
    if (!order) {
      effect->observation = root;
      break;
    }
    root = order > 0 ? observations->index[root - 1].left
                     : observations->index[root - 1].right;
  }
}

static void dep_read_projection_parameter(const char *word, size_t length,
                                          bool quoted, void *context) {
  (void)word;
  (void)length;
  (void)quoted;
  (void)context;
}

static SHELL_NONNULL(2) bool dep_read_projection_byte(unsigned char byte,
                                                      void *context) {
  dep_named_route_target_t *target = context;
  /* The fragment visitor deliberately consumes the complete word, even after
   * a literal callback returns false. Preserve the first differing byte. */
  return target->order || dep_named_assignment_target_byte(byte, context);
}

/* Resolve a literal projection against borrowed identifier keys once, during
 * word preparation. A missing key is an ordinary unobserved target, not a
 * reason to clear the whole binding map. The sole scalar fragment has already
 * been classified; this indexed comparison does not evaluate it. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_read_projection_key(const dep_token_t *word,
                            const dep_read_observations_t *observations) {
  uint32_t root = observations->root;
  while (root) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    dep_fd_ref_t ref = observations->entries[root - 1].fd;
    int order = -1;
    if (ref.value == SHELL_DEP_FD_NAMED) {
      dep_named_route_target_t target = {.name = ref.name,
                                         .name_len = ref.name_len};
      (void)shell_builtin_visit_word_impl(
          word->start, word->len, dep_read_projection_byte,
          dep_read_projection_parameter, &target, true, NULL);
      order = target.order;
      unsigned char trailing;
      if (!order && dep_fd_name_next_byte(ref.name, ref.name_len,
                                          &target.name_position, &trailing))
        order = 1;
    }
    if (!order)
      return root;
    root = order > 0 ? observations->index[root - 1].left
                     : observations->index[root - 1].right;
  }
  return 0;
}

/* Resolve targets through Shellsplit's shared wrapper state machine. Target
 * lookup and redirect setup have separate lifetimes: a reached builtin wrapper
 * fixes current-shell setup even when an inner command executes an external.
 * The shared exec_persistent fact already retains whether the chain contains
 * builtin, so no additional source pass or duplicate wrapper state is needed.
 */
static SHELL_NONNULL(1, 3, 4) const dep_token_t *dep_effective_static_builtin(
    const dep_token_list_t *tokens, uint32_t command,
    uint32_t *effective_command, bool *dynamic_target, bool *exec_persistent,
    shell_dep_command_wrapper_t *wrapper_kind, bool *current_redirects) {
  *dynamic_target = false;
  *effective_command = command;
  if (exec_persistent)
    *exec_persistent = false;
  if (wrapper_kind)
    *wrapper_kind = SHELL_DEP_COMMAND_DIRECT;
  if (current_redirects)
    *current_redirects = false;

  while (command < tokens->count && dep_skip_nonargument(tokens, &command))
    command++;
  if (command == tokens->count)
    return NULL;
  const dep_token_t *candidate = &tokens->tokens[command];
  shell_source_wrapper_state_t wrapper = {0};
  shell_source_wrapper_step_t step =
      shell_source_wrapper_start(&wrapper, candidate->start, candidate->len);
  if (current_redirects)
    *current_redirects = !wrapper.exec_persistent;
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
    if (shell_source_word_is_elided(word->start, word->len))
      continue;
    dep_redirect_t redirect = classify_redirect(word);
    if (redirect != DEP_REDIRECT_NONE) {
      if (shell_source_redirection_consumes_word(word->start, word->len) &&
          i + 1 < tokens->count)
        i++;
      continue;
    }
    shell_source_wrapper_kind_t final_wrapper = wrapper.kind;
    step = shell_source_wrapper_consume(&wrapper, word->start, word->len);
    if (current_redirects)
      *current_redirects = !wrapper.exec_persistent;
    if (step == SHELL_SOURCE_WRAPPER_DYNAMIC_TARGET) {
      *dynamic_target = true;
      if (wrapper_kind)
        *wrapper_kind = final_wrapper == SHELL_SOURCE_WRAPPER_BUILTIN
                            ? SHELL_DEP_COMMAND_BUILTIN
                            : SHELL_DEP_COMMAND_SEARCH;
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

/* Wrapper resolution has already supplied the static target or explained
 * why there is none. A builtin-only lookup never executes an external path;
 * inspection/option-only wrappers likewise keep their setup in this shell. */
static uint8_t dep_command_redirect_scopes(uint32_t command,
                                           const dep_token_t *target,
                                           bool dynamic,
                                           shell_dep_command_wrapper_t wrapper,
                                           bool current_redirects) {
  if (dynamic)
    return DEP_REDIRECT_CURRENT | (current_redirects ? 0 : DEP_REDIRECT_CHILD);
  if (command == UINT32_MAX || !target)
    return DEP_REDIRECT_CURRENT;
  bool builtin = shell_source_word_is_builtin(target->start, target->len);
  if (wrapper == SHELL_DEP_COMMAND_BUILTIN)
    return DEP_REDIRECT_CURRENT | (builtin ? 0 : DEP_REDIRECT_BAD_BUILTIN);
  return builtin || current_redirects ? DEP_REDIRECT_CURRENT
                                      : DEP_REDIRECT_CHILD;
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
    (void)shell_process_visit_word_value(
        text, length, dep_named_route_target_byte, &target, &ignored);
  }
  return !target.order && target.name_position == 3;
}

static SHELL_NONNULL(1, 2) bool dep_ifs_note_assignment(
    dep_named_mutations_t *mutations, const dep_token_t *word) {
  dep_named_effect_t effect = {.token = *word,
                               .kind = DEP_NAMED_EFFECT_STATIC_ASSIGNMENT};
  if (!dep_effect_is_ifs(effect.token.start, effect.token.len, effect.kind))
    return false;
  shell_source_decoded_assignment_t assignment;
  (void)shell_source_scan_decoded_assignment(word->start, word->len, NULL, NULL,
                                             &assignment);
  dep_ifs_value_scan_t scan = {0};
  size_t ignored;
  bool known =
      !shell_source_argument_has_dynamic_syntax(word->start, word->len) &&
      shell_process_visit_word_value(word->start, word->len, dep_ifs_value_byte,
                                     &scan, &ignored) == SHELL_PROCESS_OK;
  dep_ifs_note(mutations, known ? dep_ifs_known(scan.digits) : DEP_IFS_DIGITS,
               assignment.append);
  return true;
}

/* Compile complete builtin words once. The shared read recognizer supplies
 * option roles; execution versions retain numeric values and borrowed names,
 * never a second decoded argv. */
static SHELL_NONNULL(1, 2, 3, 4) void dep_read_prepare(
    dep_read_plan_t *plan, const dep_token_list_t *tokens,
    const dep_prefix_assignment_set_t *prefixes,
    const dep_read_observations_t *observations) {
  *plan = (dep_read_plan_t){0};
  uint32_t stop;
  uint64_t rejected;
  uint8_t presence;
  bool isolated;
  uint32_t command =
      dep_first_command_index(tokens, &stop, &isolated, &rejected, &presence);
  if (command == UINT32_MAX)
    return;
  bool dynamic = false;
  uint32_t effective = command;
  const dep_token_t *builtin = dep_effective_static_builtin(
      tokens, command, &effective, &dynamic, NULL, NULL, NULL);
  if (!builtin || dynamic ||
      shell_source_static_builtin_kind(builtin->start, builtin->len) !=
          SHELL_SOURCE_BUILTIN_READ)
    return;
  plan->active = true;
  plan->operation = builtin->start;
  plan->default_effect = (dep_named_effect_t){.token = {"REPLY", 5},
                                              .kind = DEP_NAMED_EFFECT_TOKEN};
  dep_prepare_observed_effect(&plan->default_effect, observations);
  shell_builtin_read_t roles = {.writing = SHELL_READ_OPTIONS};
  bool dynamic_target = false;
  for (uint32_t i = effective + 1; i < tokens->count; i++) {
    if (dep_skip_nonargument(tokens, &i))
      continue;
    const dep_token_t *token = &tokens->tokens[i];
    shell_builtin_read_option_t scan = {.valid = true,
                                        .timeout = {.timeout = true}};
    bool projected = shell_builtin_visit_word_impl(
        token->start, token->len, shell_builtin_read_option_byte,
        shell_builtin_read_dynamic, &scan, true, shell_builtin_read_process);
    bool single_argument = projected && !scan.parameter_unquoted;
    bool invalid_target =
        single_argument && !(scan.target_shapes & SHELL_READ_TARGET_ACCEPT);
    unsigned phases = roles.writing | roles.polling;
    dep_read_word_t *word = &plan->words[plan->count++];
    *word = (dep_read_word_t){
        .effect = {.token = *token, .kind = DEP_NAMED_EFFECT_TOKEN},
        .number = (uint32_t)scan.number.whole,
        .payload = (uint32_t)scan.payload.whole,
        .number_value = shell_builtin_read_number_value(
            &scan.number, scan.unresolved || scan.attached_dynamic,
            single_argument),
        .timeout_value = shell_builtin_read_number_value(
            &scan.timeout, scan.unresolved || scan.attached_dynamic,
            single_argument),
        .payload_value = shell_builtin_read_number_value(
            &scan.payload, scan.attached_dynamic, single_argument),
        .empty_number_value =
            shell_builtin_read_number_value(&scan.number, false, true),
        .empty_timeout_value =
            shell_builtin_read_number_value(&scan.timeout, false, true),
        .empty_payload_value =
            shell_builtin_read_number_value(&scan.payload, false, true),
        .operand_kind = scan.operand_kind,
        .variable = invalid_target
                        ? SHELL_BUILTIN_VARIABLE_INVALID
                        : shell_builtin_variable(token->start, token->len),
        .position = (uint32_t)scan.position,
        .parameter_prefix = (uint32_t)scan.parameter_prefix,
        .parameter_suffix = scan.literal_count != scan.parameter_prefix,
        .invalid_target = invalid_target,
        .invalid_empty_target = projected && scan.target_invalid,
        .unsupported_option = scan.array || scan.readline,
        .number_scalar = scan.number_scalar,
        .timeout_scalar = scan.timeout_scalar,
        .payload_scalar = scan.payload_scalar,
        .parameter_unquoted = scan.parameter_unquoted,
        .can_disappear =
            scan.parameter_unquoted && !scan.literal_count &&
            !shell_builtin_word_guarantees_argument(token->start, token->len),
        .option = scan.option,
        .valid = scan.valid,
        .end = scan.end,
        .attached_static = scan.attached_static,
        .attached_dynamic = scan.attached_dynamic,
        .dynamic = scan.unresolved || scan.attached_dynamic,
        .capture = (phases & (SHELL_READ_OPTIONS | SHELL_READ_NUMBER |
                              SHELL_READ_TIMEOUT | SHELL_READ_FD)) != 0 ||
                   (roles.writing &
                    (SHELL_READ_POSITIONAL | SHELL_READ_TARGETS)) != 0};
    word->may_fd =
        ((phases & SHELL_READ_FD) &&
         word->number_value != SHELL_READ_VALUE_INVALID) ||
        ((phases & SHELL_READ_OPTIONS) && scan.operand_kind == SHELL_READ_FD &&
         word->payload_value != SHELL_READ_VALUE_INVALID);
    if (word->variable == SHELL_BUILTIN_VARIABLE_STATIC)
      dep_prepare_observed_effect(&word->effect, observations);
    if (projected && scan.parameter && !scan.multiple_parameters &&
        (!word->may_fd || !word->parameter_suffix || scan.number_scalar ||
         scan.payload_scalar)) {
      size_t begin, end;
      if (shell_source_parse_named_fd_parameter(
              scan.parameter, 0, scan.parameter_length, &begin, &end)) {
        word->parameter = (dep_fd_ref_t){.name = scan.parameter + begin,
                                         .value = SHELL_DEP_FD_NAMED,
                                         .name_len = (uint32_t)(end - begin)};
        word->parameter_variable = shell_builtin_name_index(
            word->parameter.name, word->parameter.name_len);
        word->empty_known = true;
        word->empty_ifs = scan.literal_count == 3 && scan.literal_ifs;
        word->empty_effect.kind = DEP_NAMED_EFFECT_TOKEN;
        word->empty_effect.variable =
            shell_builtin_variable_index(&scan.literal_target);
        if (scan.literal_count && !scan.target_invalid) {
          uint32_t key = dep_read_projection_key(token, observations);
          word->empty_effect.observation = key;
          if (key) {
            dep_fd_ref_t name = observations->entries[key - 1].fd;
            word->empty_effect.token = (dep_token_t){name.name, name.name_len};
          } else if (word->empty_effect.variable) {
            uint8_t variable = word->empty_effect.variable;
            word->empty_effect.token = (dep_token_t){
                shell_builtin_variable_index_name(variable),
                (uint32_t)shell_builtin_variable_index_length(variable)};
          } else if (word->empty_ifs) {
            word->empty_effect.token = (dep_token_t){"IFS", 3};
          }
          if (word->empty_effect.token.len)
            word->empty_restored = dep_prefix_assignment_contains(
                prefixes, &word->empty_effect.token);
        }
      }
    }
    plan->entry_dependent |= word->dynamic ||
                             word->parameter.value == SHELL_DEP_FD_NAMED ||
                             word->effect.variable != 0;
    unsigned role = shell_builtin_read_word(&roles, token->start, token->len);
    if ((role & SHELL_BUILTIN_ROLE_WRITE) &&
        !(role & SHELL_BUILTIN_ROLE_DYNAMIC))
      word->restored = dep_prefix_assignment_contains(prefixes, token);
    dynamic_target |= (role & SHELL_BUILTIN_ROLE_DYNAMIC) != 0;
  }
  if (dynamic_target)
    plan->ifs_restored =
        dep_prefix_assignment_contains(prefixes, &(dep_token_t){"IFS", 3});
}

/* Prepared tokens are source-ordered, preclassified command words (at most
 * SHELL_DEP_MAX_TOKENS). The required checkpoint destination has that many
 * entries; its borrowed commit boundaries share the tokens' source lifetime. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) void dep_prepare_named_mutations(
    dep_named_mutations_t *mutations, const dep_token_list_t *prepared,
    dep_prefix_assignment_set_t *prefix_assignments,
    dep_assignment_ifs_t *assignment_ifs, uint32_t *assignment_ifs_count,
    dep_named_mutations_t *null_mutations, uint32_t readonly_stop,
    bool cd_writes, bool cd_failure_writes, uint8_t argv_presence) {
  *mutations = (dep_named_mutations_t){0};
  *null_mutations = (dep_named_mutations_t){.before_redirect = true};
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
    dep_prefix_assignment_insert(prefix_assignments, &name, assignment.append);
    if (token < readonly_stop) {
      null_mutations->effects[null_mutations->count++] =
          (dep_named_effect_t){.token = name,
                               .kind = DEP_NAMED_EFFECT_TOKEN,
                               .prohibited_properties = SHELL_VARIABLE_INTEGER};
      (void)dep_ifs_note_assignment(null_mutations, word);
    }
    if (dep_ifs_note_assignment(&prefix_ifs, word)) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ASSIGNMENT_IFS);
      assignment_ifs[(*assignment_ifs_count)++] = (dep_assignment_ifs_t){
          word->start + word->len, prefix_ifs.ifs, prefix_ifs.ifs_append};
    }
  }

  /* A leading assignment is temporary when expanded argv is present. In
   * particular, Bash expands that command's redirect list against the
   * pre-existing descriptor-variable binding. An assignment-only command,
   * however, changes the current shell variable and invalidates just that
   * logical named-FD route, including when empty process words disappear.
   * Defer mutation until the command shape is known
   * so the two cases cannot be confused. */
  if (command == UINT32_MAX || argv_presence == DEP_ARGV_EMPTY) {
    *mutations = *null_mutations;
    return;
  }
  bool dynamic_builtin = false;
  uint32_t effective_command = command;
  const dep_token_t *builtin = dep_effective_static_builtin(
      &tokens, command, &effective_command, &dynamic_builtin, NULL, NULL, NULL);
  if (dynamic_builtin) {
    mutations->effects[mutations->count++] = (dep_named_effect_t){
        .token = tokens.tokens[command], .kind = DEP_NAMED_EFFECT_OPAQUE_UNSET};
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
    mutations->presence_prefixes = prefix_assignments;
    mutations->failure_alternative = cd_failure_writes;
    return;
  }
  shell_source_builtin_kind_t builtin_kind =
      shell_source_static_builtin_kind(builtin->start, builtin->len);
  if (builtin_kind == SHELL_SOURCE_BUILTIN_UNSET) {
    mutations->restored_prefixes = prefix_assignments;
    shell_builtin_unset_t state = {.options = true};
    bool conditional_unsets = false;
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_nonargument(&tokens, &i))
        continue;
      const dep_token_t *target = &tokens.tokens[i];
      bool option_position = state.options;
      unsigned roles =
          shell_builtin_unset_word(&state, target->start, target->len);
      if (!(roles & SHELL_BUILTIN_ROLE_WRITE))
        continue;
      if (roles & SHELL_BUILTIN_ROLE_DYNAMIC) {
        /* An unresolved leading option can select -f/-n or fail parsing.
         * Retain later variable unsets as possible until argv is fixed. */
        conditional_unsets |= option_position;
        /* Only unresolved runtime expansion can name an unrelated binding.
         * Static invalid targets fail individually; unset continues with its
         * remaining operands. */
        mutations->effects[mutations->count++] = (dep_named_effect_t){
            .token = *target, .kind = DEP_NAMED_EFFECT_OPAQUE_UNSET};
        mutations->ifs_maybe_unset = !prefix_ifs.ifs_write;
        continue;
      }
      {
        unsigned properties =
            shell_builtin_name_properties(target->start, target->len);
        dep_named_effect_t effect = {
            .token = *target,
            .presence_may_skip = conditional_unsets,
            .kind =
                (properties & SHELL_VARIABLE_UNSTABLE) &&
                        !(properties & SHELL_VARIABLE_DESPECIALIZES_ON_UNSET)
                    ? DEP_NAMED_EFFECT_TOKEN
                    : DEP_NAMED_EFFECT_UNSET};
        mutations->effects[mutations->count++] = effect;
        if (dep_effect_is_ifs(effect.token.start, effect.token.len,
                              effect.kind) &&
            !dep_prefix_assignment_contains(prefix_assignments, target)) {
          if (conditional_unsets)
            mutations->ifs_maybe_unset = true;
          else {
            dep_ifs_note(mutations, 0, false);
            mutations->ifs_maybe_unset = false;
          }
        }
      }
    }
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_READ) {
    mutations->restored_prefixes = prefix_assignments;
    shell_builtin_read_t state = {.writing = SHELL_READ_OPTIONS};
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_nonargument(&tokens, &i))
        continue;
      const dep_token_t *target = &tokens.tokens[i];
      unsigned roles =
          shell_builtin_read_word(&state, target->start, target->len);
      if (!(roles & SHELL_BUILTIN_ROLE_WRITE))
        continue;
      if (roles & SHELL_BUILTIN_ROLE_DYNAMIC) {
        mutations->effects[mutations->count++] = (dep_named_effect_t){
            .token = *target, .kind = DEP_NAMED_EFFECT_OPAQUE_WRITE};
        if (!prefix_ifs.ifs_write)
          dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
        continue;
      }
      {
        dep_named_effect_t effect = {.token = *target,
                                     .kind = DEP_NAMED_EFFECT_TOKEN};
        mutations->effects[mutations->count++] = effect;
        if (dep_effect_is_ifs(effect.token.start, effect.token.len,
                              effect.kind) &&
            !dep_prefix_assignment_contains(prefix_assignments, target))
          dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
      }
    }
    /* Only a surviving writing path with no target can assign REPLY. Missing
     * operands, proven errors and timeout-zero polling cannot. */
    if (shell_builtin_read_default_write(&state))
      mutations->effects[mutations->count++] =
          (dep_named_effect_t){.token = {.start = "REPLY", .len = 5},
                               .kind = DEP_NAMED_EFFECT_TOKEN};
    return;
  }

  if (builtin_kind == SHELL_SOURCE_BUILTIN_PRINTF) {
    shell_builtin_printf_t state = {0};
    dep_named_effect_t pending = {0};
    bool commit_target = false, target_ifs_write = false;
    uint32_t target_ifs = 0;
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_nonargument(&tokens, &i))
        continue;
      const dep_token_t *word = &tokens.tokens[i];
      unsigned roles =
          shell_builtin_printf_word(&state, word->start, word->len);
      if (roles & SHELL_BUILTIN_ROLE_DYNAMIC) {
        mutations->effects[mutations->count++] = (dep_named_effect_t){
            .token = *word, .kind = DEP_NAMED_EFFECT_OPAQUE_WRITE};
        if (commit_target) {
          pending.presence_may_skip = true;
          mutations->effects[mutations->count++] = pending;
        }
        dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
        return;
      }
      if ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
          state.phase == SHELL_PRINTF_OPTIONS)
        pending = (dep_named_effect_t){
            .token = *word,
            .kind = roles & SHELL_BUILTIN_ROLE_ATTACHED
                        ? DEP_NAMED_EFFECT_PRINTF_ATTACHED
                        : DEP_NAMED_EFFECT_TOKEN,
            .prohibited_properties = SHELL_VARIABLE_INTEGER};
      if (roles & SHELL_BUILTIN_ROLE_WRITE) {
        dep_named_effect_t effect =
            roles & SHELL_BUILTIN_ROLE_FORMAT
                ? pending
                : (dep_named_effect_t){.token = *word,
                                       .kind = DEP_NAMED_EFFECT_TOKEN};
        if (roles & SHELL_BUILTIN_ROLE_FORMAT)
          commit_target = true;
        else
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
                       shell_process_visit_word_value(
                           word->start, word->len, dep_ifs_value_byte, &scan,
                           &ignored) == SHELL_PROCESS_OK &&
                       !scan.format;
          uint32_t value = known ? dep_ifs_known(scan.digits) : DEP_IFS_DIGITS;
          if (roles & SHELL_BUILTIN_ROLE_FORMAT) {
            target_ifs_write = true;
            target_ifs = value;
          } else
            dep_ifs_note(mutations, value, false);
        }
      }
    }
    /* %n writes happen while formatting; -v commits the completed output. */
    if (commit_target)
      mutations->effects[mutations->count++] = pending;
    if (target_ifs_write)
      dep_ifs_note(mutations, target_ifs, false);
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
      if (dep_skip_nonargument(&tokens, &i))
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
              .token = *argument,
              .kind = DEP_NAMED_EFFECT_STATIC_ASSIGNMENT,
              .prohibited_properties =
                  state.no_integer ? 0 : SHELL_VARIABLE_INTEGER};
          dep_ifs_note_assignment(mutations, argument);
        }
      } else if ((roles & SHELL_BUILTIN_ROLE_PROMOTES_PREFIX) &&
                 dep_prefix_assignment_contains(prefix_assignments, argument)) {
        mutations->effects[mutations->count++] = (dep_named_effect_t){
            .token = *argument, .kind = DEP_NAMED_EFFECT_TOKEN};
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
    bool definite_optarg_destination = false;
    for (uint32_t i = effective_command + 1; i < tokens.count; i++) {
      if (dep_skip_nonargument(&tokens, &i))
        continue;
      const dep_token_t *target = &tokens.tokens[i];
      bool definite =
          state.phases == SHELL_GETOPTS_TARGET && !state.may_fail_before_data;
      unsigned roles =
          shell_builtin_getopts_word(&state, target->start, target->len);
      if (roles & SHELL_BUILTIN_ROLE_WRITE) {
        /* Normalize writes to OPTARG into its single final presence effect.
         * Bash's destination/OPTARG order depends on the option outcome. */
        if (dep_token_static_equals(target, "OPTARG")) {
          definite_optarg_destination |= definite;
          continue;
        }
        mutations->effects[mutations->count++] = (dep_named_effect_t){
            .token = *target,
            .kind = DEP_NAMED_EFFECT_TOKEN,
            .presence_may_skip = !definite,
            .prohibited_properties = SHELL_VARIABLE_INTEGER};
        if (dep_effect_is_ifs(target->start, target->len,
                              DEP_NAMED_EFFECT_TOKEN))
          dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
      }
    }
    /* These are final effects, not a universal runtime write order. Normal
     * options and end-of-options assign the destination after OPTARG; option
     * errors assign it first, then set or clear OPTARG. A definite OPTARG
     * destination stays set only when every possible optstring is silent.
     * These writes persist through temporary command prefixes, including
     * implicit updates when the destination is invalid or readonly.
     * A completed invocation has at least a command, optstring and target,
     * leaving two effect slots beyond its possible destination words. */
    if (state.phases & SHELL_GETOPTS_DATA) {
      bool maybe =
          state.may_fail_before_data || state.phases != SHELL_GETOPTS_DATA;
      memmove(mutations->effects + 2, mutations->effects,
              mutations->count * sizeof(mutations->effects[0]));
      mutations->effects[0] =
          (dep_named_effect_t){.token = {"OPTIND", 6},
                               .kind = DEP_NAMED_EFFECT_TOKEN,
                               .presence_may_skip = maybe};
      mutations->effects[1] = (dep_named_effect_t){
          .token = {"OPTARG", 6},
          .kind = DEP_NAMED_EFFECT_TOKEN,
          .presence = definite_optarg_destination &&
                              !state.may_clear_optarg_after_target
                          ? SHELL_TEST_TRUE
                          : SHELL_TEST_FALSE | SHELL_TEST_TRUE,
          .presence_may_skip = maybe};
      mutations->count += 2;
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

static SHELL_NONNULL(1, 2, 3) bool dep_observation_apply(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_observation_program_t *program, uint32_t event);

static SHELL_NONNULL(1) uint32_t
    dep_owner_event(const dep_parse_context_t *context, uint32_t owner);

/* Expansion errors belong to their executing shell. Null-command assignments
 * expand before the setup child exists; only redirect-phase errors return to
 * the parent as setup failure. The caller has established phase reachability.
 */
static SHELL_NONNULL(1) void dep_record_expansion_error(
    const dep_parse_context_t *context, uint32_t owner,
    dep_snapshot_phase_t phase, uint8_t errors) {
  uint32_t event = dep_owner_event(context, owner);
  dep_expansion_status_t *expansion = &context->expansion_status[event];
  if (phase == DEP_SNAPSHOT_ASSIGNMENT_VALUE) {
    const dep_snapshot_source_t *source =
        &context->workspace
             ->snapshot_sources[context->snapshot->prepared_source[owner]];
    if (source->argv_presence == (DEP_ARGV_EMPTY | DEP_ARGV_PRESENT) &&
        source->assignment_dispatch == DEP_ARGV_EMPTY) {
      expansion->null_assignment_errors |= errors;
      return;
    }
  }
  if (phase == DEP_SNAPSHOT_REDIRECT_OPERAND && expansion->isolated_setup)
    expansion->setup_expansion_failure |= errors != 0;
  else {
    expansion->errors |= errors;
    context->event_static_status[event] |= errors;
  }
}

/* All phases have been expanded for this event. Bash's assignment-only
 * commands expand their assignments before redirects, irrespective of where
 * the assignments occur in the source. A phase with no substitution preserves
 * the preceding status, including conditional expansion alternatives. */
static SHELL_NONNULL(1) uint8_t
    dep_expansion_status(const dep_parse_context_t *context, uint32_t event,
                         uint8_t incoming) {
  const dep_expansion_status_t *expansion = &context->expansion_status[event];
  for (unsigned phase = 0; phase <= DEP_SNAPSHOT_BODY_WORD; phase++) {
    uint8_t status = expansion->phase[phase];
    incoming = (status & DEP_STATUS_EITHER) |
               ((status & DEP_EXPANSION_INCOMING) ? incoming : 0);
  }
  return incoming;
}

/* Resettable assignment restrictions need the execution version to decide
 * success. Static status must retain failure even when the RHS succeeds;
 * unlike readonly rejection, this is an ordinary returning outcome. */
static SHELL_NONNULL(1) bool dep_assignments_may_reject(
    const dep_named_mutations_t *mutations) {
  for (uint32_t i = 0; i < mutations->count; ++i)
    if (shell_builtin_variable_index_properties(
            mutations->effects[i].variable) &
        SHELL_VARIABLE_NOASSIGN)
      return true;
  return false;
}

/* All assignment/redirect phases have been analyzed. A null-command child
 * returns the result of setup, not the status of its last substitution.
 * File/descriptor failures are composed separately by the setup machinery. */
static SHELL_NONNULL(1, 3) uint8_t
    dep_null_command_status(const dep_parse_context_t *context, uint32_t event,
                            const dep_named_mutations_t *mutations) {
  const dep_expansion_status_t *expansion = &context->expansion_status[event];
  uint8_t rejection =
      dep_assignments_may_reject(mutations) ? DEP_STATUS_MAY_FAIL : 0;
  if (expansion->isolated_setup)
    return DEP_STATUS_MAY_SUCCEED | rejection |
           (expansion->setup_expansion_failure ? DEP_STATUS_MAY_FAIL : 0);
  return dep_expansion_status(context, event, DEP_STATUS_MAY_SUCCEED) |
         rejection;
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

static SHELL_NONNULL(2, 3) unsigned dep_variable_properties(
    uint8_t variable, const dep_route_state_t *state,
    const dep_route_journal_t *journal);

/* Complete setup after its resources and operand expansions are constructed.
 * This is semantic execution analysis, not validation of the supplied parse.
 * Later snapshots reuse these ordered checkpoints. Optional may_fail receives
 * uncertainty from reached setup outcomes (resource opens and unresolved
 * descriptor states); definite failures are recorded in owner_setup_stop. */
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_complete_owner_setup(shell_dep_graph_t *graph,
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
  if ((source->ops[index].kind == DEP_FD_OP_PROCESS) !=
      (source->ops[pending].kind == DEP_FD_OP_PROCESS))
    return source->ops[index].kind == DEP_FD_OP_PROCESS ? -1 : 1;
  /* A known failure of a redirect's open follows that open: Bash attempts
   * it and reports its failure. */
  if ((source->ops[index].kind == DEP_FD_OP_FAILED) !=
      (source->ops[pending].kind == DEP_FD_OP_FAILED))
    return source->ops[index].kind == DEP_FD_OP_FAILED ? 1 : -1;
  return index < pending ? -1 : index != pending;
}

/* The operation tree retains stable identities as construction adds resources.
 * Only the requested source interval is visited, including its search paths.
 * indices is optional; when supplied, it receives each stable source slot so
 * semantic preparation can replace that record after journaling its original
 * move behavior. */
static SHELL_NONNULL(1, 5, 7) void dep_snapshot_operation_range(
    const dep_snapshot_source_t *source, uint32_t root, uint32_t begin,
    uint32_t end, dep_fd_op_t *ops, uint32_t *indices, uint32_t *count) {
  if (!root)
    return;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
  const dep_fd_op_t *op = &source->ops[root - 1];
  const shell_avl_node_t *node = &source->op_index[root - 1];
  if (op->pos >= begin)
    dep_snapshot_operation_range(source, node->left, begin, end, ops, indices,
                                 count);
  if (op->pos >= begin && op->pos < end) {
    if (indices)
      indices[*count] = root - 1;
    ops[(*count)++] = *op;
  }
  if (op->pos < end)
    dep_snapshot_operation_range(source, node->right, begin, end, ops, indices,
                                 count);
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
    const dep_token_list_t *tokens, uint32_t readonly_stop,
    uint8_t argv_presence) {
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
  workspace->snapshot_sources[slot].entry_diagnostic =
      readonly_stop != UINT32_MAX;
  workspace->snapshot_sources[slot].readonly_stop = readonly_stop;
  workspace->snapshot_sources[slot].argv_presence = argv_presence;
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

/* Observe only a live frame: a numeric use in a later independent command
 * cannot access this owner's disposed saves. Compound bodies, executable
 * expansion snapshots, moves and allocations can observe them during setup.
 * Static operation metadata and the existing parser features supply this
 * decision once; no source prefix is revisited during replay. */
static SHELL_NONNULL(1, 2, 4) bool dep_owner_observes_undo(
    const shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t owner, const dep_token_list_t *tokens, const dep_fd_op_t *ops,
    uint32_t count) {
  if (graph->nodes[owner].type == SHELL_NODE_GROUP)
    return true;
  if (context->workspace
          ->snapshot_sources[context->snapshot->prepared_source[owner]]
          .read.active)
    return true;
  uint32_t features = context->fast->cmds[context->node_range[owner]].features;
  if (features &
      (SHELL_FEAT_SUBSHELL | SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_HEREDOC))
    return true;
  for (uint32_t i = 0; i < count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    if (ops[i].fd == SHELL_DEP_FD_NAMED || ops[i].kind == DEP_FD_OP_MOVE ||
        (dep_fd_op_copies(ops[i].kind) &&
         ops[i].target_fd >= DEP_BASH_VARREDIR_MIN_FD &&
         ops[i].target_fd <= SHELL_DEP_FD_MAX))
      return true;
  }
  for (uint32_t i = 0; i < tokens->count; i++) {
    const dep_token_t *token = tokens->tokens + i;
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    dep_redirect_t redirect = classify_redirect(token);
    if (token->len && token->start[0] == '{' && redirect != DEP_REDIRECT_NONE)
      return true;
  }
  return false;
}

/* Preserve every possible setup scope. Isolated argv-less setup overrides
 * dispatch before snapshots prepare any operations, not just at publication. */
static SHELL_NONNULL(1) uint8_t
    dep_owner_undo_mode(const dep_parse_context_t *context, uint32_t owner) {
  if (context->node_group[owner] != UINT32_MAX)
    return DEP_UNDO_COMPOUND;
  const dep_expansion_status_t *status =
      &context->expansion_status[SHELL_MAX_GROUPS + context->node_range[owner]];
  if (status->isolated_setup)
    return DEP_UNDO_CHILD;
  return (status->redirect_scopes & DEP_REDIRECT_CURRENT ? DEP_UNDO_COMMAND
                                                         : 0) |
         (status->redirect_scopes & DEP_REDIRECT_CHILD ? DEP_UNDO_CHILD : 0);
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
          &source->null_mutations,
          source->argv_presence & DEP_ARGV_EMPTY ? source->readonly_stop : 0,
          context->range_cd_writes[context->node_range[owner]],
          context->range_cd_failure_writes[context->node_range[owner]],
          source->argv_presence);
      source->mutations.operation = source->null_mutations.operation =
          source->tokens.count ? source->tokens.tokens[0].start : NULL;
      uint32_t event = context->node_group[owner] != UINT32_MAX
                           ? context->node_group[owner]
                           : SHELL_MAX_GROUPS + context->node_range[owner];
      int32_t enclosing;
      if (event >= SHELL_MAX_GROUPS)
        enclosing = dep_range_group(&context->execution->pipeline,
                                    event - SHELL_MAX_GROUPS);
      else {
        uint16_t parent = context->fast->groups[event].parent;
        enclosing = parent == UINT16_MAX ? -1 : (int32_t)parent;
      }
      source->mutations.scope = source->null_mutations.scope =
          (uint8_t)(enclosing + 1);
      for (uint32_t i = 0; i < source->mutations.count; i++)
        dep_prepare_observed_effect(
            &source->mutations.effects[i],
            &context->workspace->journal.read_observations);
      for (uint32_t i = 0; i < source->null_mutations.count; i++)
        dep_prepare_observed_effect(
            &source->null_mutations.effects[i],
            &context->workspace->journal.read_observations);
      dep_read_prepare(&source->read, &source->tokens,
                       &source->prefix_assignments,
                       &context->workspace->journal.read_observations);
      if (graph->nodes[owner].cmd.kind == SHELL_COMMAND_CONDITIONAL) {
        shell_conditional_t condition = shell_conditional_parse(
            context->cmd, context->cmd_len,
            context->fast->cmds[context->node_range[owner]].start);
        source->test = shell_source_scratch_take_array(
            1, sizeof(*source->test), _Alignof(shell_test_program_t));
        if (!source->test)
          return false;
        if (!shell_test_compile_conditional(context->cmd, &condition,
                                            source->test))
          return false;
      }
    }
    source->undo_observable = dep_owner_observes_undo(
        graph, context, owner, &source->tokens, source->ops, source->op_count);
    /* Bash counts input instructions, not every operation targeting fd 0.
     * Named allocations and descriptor moves do not count. Reuse this owner's
     * prepared token/operation inventory; no source-prefix replay. */
    for (uint32_t token = 0; token < source->tokens.count; token++) {
      dep_redirect_t kind = classify_redirect(&source->tokens.tokens[token]);
      source->has_redirects |= kind != DEP_REDIRECT_NONE;
      if (redirect_fd(&source->tokens.tokens[token], kind) !=
          SHELL_DEP_FD_NAMED)
        source->stdin_redirect |= kind == DEP_REDIRECT_IN ||
                                  kind == DEP_REDIRECT_READ_WRITE ||
                                  kind == DEP_REDIRECT_HEREDOC;
    }
    for (uint32_t op = 0; op < source->op_count; op++)
      source->stdin_redirect |=
          source->ops[op].fd == 0 &&
          (source->ops[op].kind == DEP_FD_OP_CLOSE ||
           (source->ops[op].kind == DEP_FD_OP_DUP &&
            source->ops[op].access == DEP_FD_ACCESS_READ));
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
    source->has_redirects = true;
    source->stdin_redirect |= input && item->target_fd != SHELL_DEP_FD_NAMED;
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
        NULL,
        false,
        false,
        false,
        NULL,
        0,
        0};
    operation->document_flags = &graph->nodes[document].doc.flags;
    source->edge_cursor = cursor;
  }
  if (!dep_add_prepared_process_operations(
          owner, context->process_routes, &source->process_route_cursor,
          source->ops, &source->op_count,
          sizeof(source->ops) / sizeof(source->ops[0])))
    return false;
  if (source->op_count != prepared_count) {
    dep_prepare_fd_operation_resets(
        source->ops + prepared_count, source->op_count - prepared_count,
        source->undo_observable, dep_owner_undo_mode(context, owner));
    for (uint32_t i = prepared_count; i < source->op_count; i++) {
      const dep_fd_op_t *op = &source->ops[i];
      source->setup_needs_walk |=
          dep_fd_op_copies(op->kind) || op->kind == DEP_FD_OP_FAILED ||
          (op->kind == DEP_FD_OP_CLOSE && op->fd == SHELL_DEP_FD_NAMED);
      source->setup_may_fail |=
          op->kind == DEP_FD_OP_DYNAMIC ||
          (op->kind == DEP_FD_OP_DOCUMENT &&
           (graph->nodes[owner].type == SHELL_NODE_GROUP ||
            graph->nodes[dep_edge_document_index(graph,
                                                 &graph->edges[op->edge_index])]
                    .doc.kind == SHELL_DOC_FILE));
      uint32_t match = 0;
      source->op_root =
          shell_avl_insert(source->op_index, source->op_root, i + 1,
                           sizeof(source->ops) / sizeof(source->ops[0]),
                           dep_snapshot_operation_compare, source, &i, &match);
    }
  }
  *prepared = source;
  return true;
}
static SHELL_NONNULL(1, 2) bool dep_import_route_alternatives(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_fd_imports_t *imports);

static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_route_state_get_access(const dep_route_state_t *state,
                               const dep_route_journal_t *changes,
                               dep_fd_ref_t fd, dep_fd_access_t access);
/* Collection is enabled only at explicit completed-operation boundaries.
 * Root spans are borrowed from the active replay; NULL frame selects final
 * resolution. A recursive construction frame disables collection because its
 * caller can still hold in-flight imports. */
typedef struct dep_domain_collection {
  dep_route_workspace_t *workspace;
  const dep_snapshot_frame_t *frame;
  const dep_route_state_t *roots[8];
  /* Optional contiguous outcome roots retained during read publication. */
  const dep_route_state_t *states;
  uint32_t state_count;
  /* Borrowed cursor whose already-consumed prefix has been superseded. The
   * immutable link chain keeps the remaining roots available without copying
   * or rescanning the complete alternative set. */
  const dep_route_iterator_t *remaining;
  const dep_fd_flow_t *flow;
  const struct dep_domain_collection *parent;
} dep_domain_collection_t;

/* Required prepared route tables and journal. ops addresses op_count prepared
 * operations; NULL is permitted only for an empty operation span.
 * collection is NULL for a replay with unenumerated transient roots.
 */
static SHELL_NONNULL(1, 2) bool dep_route_state_apply(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_fd_op_t *ops, uint32_t op_count, bool begin_frame,
    const dep_domain_collection_t *collection);
static SHELL_NONNULL(1, 2,
                     3) bool dep_process_open(dep_route_state_t *state,
                                              dep_route_journal_t *journal,
                                              const dep_fd_op_t *op);

static SHELL_NONNULL(1, 2, 3) bool dep_process_close_owner(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_parse_context_t *context, uint32_t owner);
static SHELL_NONNULL(1, 2, 3) bool dep_process_guard_prepare(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_process_guard_t *guard);
static SHELL_NONNULL(1, 2) uint32_t
    dep_process_guard_key(dep_route_journal_t *journal,
                          const dep_process_guard_t *guard, bool create);
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_process_guard_select(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_process_guard_t *guard, dep_route_state_t *selected,
    bool *possible);
static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge_versions(
    dep_route_state_t *destination, const dep_route_state_t *source,
    dep_route_journal_t *journal);
static SHELL_NONNULL(1, 2, 3) bool dep_fd_join(dep_route_state_t *destination,
                                               const dep_route_state_t *source,
                                               dep_route_journal_t *journal);

static SHELL_NONNULL(1, 2, 3) bool dep_fd_factor_choices(
    dep_route_state_t *chosen, bool *have_choice, dep_route_journal_t *journal);

/* Join one outcome into the single version that continues them all, the first
 * one initializing it. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_route_state_join_choice(
    dep_route_state_t *chosen, bool *have_choice,
    const dep_route_state_t *branch, dep_route_journal_t *journal) {
  if (!*have_choice) {
    *chosen = *branch;
    *have_choice = true;
    return true;
  }
  return dep_fd_join(chosen, branch, journal);
}
static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_fd_fact(const dep_route_state_t *state,
                const dep_route_journal_t *journal, dep_fd_ref_t fd,
                dep_fd_access_t access);
static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_fd_raw_fact(const dep_route_state_t *state,
                    const dep_route_journal_t *journal, dep_fd_ref_t fd,
                    dep_fd_access_t access);
static SHELL_NONNULL(2) dep_route_set_t
    dep_fd_raw_root_fact(uint32_t root, const dep_route_journal_t *journal,
                         dep_fd_ref_t fd, dep_fd_access_t access);
/* Map iteration (shell_depgraph_factmap_impl.h). A snapshot of 0 means the
 * map does not bind the key; a visitor returns false to stop the walk. */
typedef bool (*dep_route_each_visit_t)(void *context, dep_fd_ref_t fd,
                                       dep_fd_access_t access,
                                       uint32_t snapshot);
typedef bool (*dep_route_diff_visit_t)(void *context, dep_fd_ref_t fd,
                                       dep_fd_access_t access, uint32_t left,
                                       uint32_t right);
static SHELL_NONNULL(1, 3) bool dep_route_map_each(
    const dep_route_journal_t *journal, uint32_t root,
    dep_route_each_visit_t visit, void *context);
static SHELL_NONNULL(1, 4) bool dep_route_map_diff(
    const dep_route_journal_t *journal, uint32_t left, uint32_t right,
    dep_route_diff_visit_t visit, void *context);
static SHELL_NONNULL(1, 2) uint32_t
    dep_route_state_snapshot(const dep_route_state_t *state,
                             const dep_route_journal_t *changes,
                             dep_fd_ref_t fd, dep_fd_access_t access);
static SHELL_NONNULL(1, 2) bool dep_observation_require(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t fd,
    unsigned roles);

static dep_fd_ref_t dep_variable_ref(uint8_t variable) {
  return (dep_fd_ref_t){
      .name = shell_builtin_variable_index_name(variable),
      .value = SHELL_DEP_FD_NAMED,
      .name_len = (uint32_t)shell_builtin_variable_index_length(variable)};
}

enum {
  /* `unset name` removed a live named-FD binding without closing its physical
   * descriptor. This state, including its original allocation scope, survives
   * repeated unsets until a successful named-FD allocation replaces it. Until
   * allocator correlation includes that orphaned slot, a later `{name}>...`
   * must remain outside the supported graph boundary. */
  DEP_EFFECT_STATE_ORPHANED_ALLOCATION = 1u << 1,
  DEP_EFFECT_STATE_SCOPE_SHIFT = 2,
};

static SHELL_NONNULL(1) bool dep_effect_state_has(const dep_route_set_t *state,
                                                  uint32_t flag) {
  for (uint32_t i = 0; i < state->count; i++)
    if (state->routes[i].value & flag)
      return true;
  return false;
}

static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_variable_state(const dep_route_state_t *state,
                       const dep_route_journal_t *journal);

#include "shell_depgraph_variable_impl.h"

/* This is the stateful builtin validation boundary. Syntax preparation has
 * already proved static target spellings; only the route journal can decide
 * whether a resettable predefined name is still special on every live path. */
static SHELL_NONNULL(1) bool dep_scope_is_descendant(
    const shell_parse_result_t *fast, uint8_t scope, uint8_t ancestor) {
  if (!scope || scope == ancestor)
    return false;
  if (!ancestor)
    return true;
  uint16_t group = (uint16_t)(scope - 1);
  while (fast->groups[group].parent != UINT16_MAX) {
    group = fast->groups[group].parent;
    if ((uint8_t)(group + 1) == ancestor)
      return true;
  }
  return false;
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_source_variables_supported(
    const dep_snapshot_source_t *source, const dep_route_state_t *state,
    const dep_route_journal_t *journal, const shell_parse_result_t *fast) {
  if (!dep_effects_supported(&source->mutations, state, journal) ||
      ((source->argv_presence & DEP_ARGV_EMPTY) &&
       !dep_effects_supported(&source->null_mutations, state, journal)))
    return false;
  /* Bash restores a plain NAME=value temporary environment, including
   * arithmetic side effects of predefined integer variables. NAME+=value is
   * evaluated against the existing integer and its nested arithmetic writes
   * survive, so that spelling still needs ordinary-scalar state. */
  for (uint32_t i = 0; i < source->prefix_assignments.count; i++) {
    const dep_variable_token_t *prefix = &source->prefix_assignments.names[i];
    if (prefix->append && prefix->variable &&
        (dep_variable_properties(prefix->variable, state, journal) &
         SHELL_VARIABLE_INTEGER))
      return false;
  }
  for (uint32_t i = 0; i < source->op_count; i++) {
    const dep_fd_op_t *op = &source->ops[i];
    uint8_t variable = op->variable;
    if (variable && (dep_variable_properties(variable, state, journal) &
                     (SHELL_VARIABLE_UNSTABLE | SHELL_VARIABLE_READONLY |
                      SHELL_VARIABLE_ARRAY | SHELL_VARIABLE_FROZEN)))
      return false;
    if (op->fd == SHELL_DEP_FD_NAMED && op->resets_descriptor) {
      dep_fd_ref_t fd = {
          .name = op->fd_name, .value = op->fd, .name_len = op->fd_name_len};
      dep_route_set_t effect_state =
          dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_EFFECT_STATE);
      for (uint32_t route = 0; route < effect_state.count; route++) {
        uint32_t value = effect_state.routes[route].value;
        if ((value & DEP_EFFECT_STATE_ORPHANED_ALLOCATION) &&
            dep_scope_is_descendant(
                fast, source->mutations.scope,
                (uint8_t)(value >> DEP_EFFECT_STATE_SCOPE_SHIFT)))
          return false;
      }
    }
  }
  return true;
}
static SHELL_NONNULL(1) uint8_t
    dep_read_binding_outcomes(const dep_route_set_t *facts);
static SHELL_NONNULL(1) dep_route_set_t
    dep_required_feasible(const dep_route_set_t *facts);
static SHELL_NONNULL(1) unsigned dep_read_value_class(
    const dep_route_set_t *facts);

static SHELL_NONNULL(1, 3) int dep_diagnostic_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
  const dep_diagnostics_t *diagnostics = context;
  const dep_diagnostic_use_t *a = &diagnostics->uses[index], *b = key;
  if (a->owner != b->owner)
    return a->owner < b->owner ? -1 : 1;
  if (a->route.kind != b->route.kind)
    return a->route.kind < b->route.kind ? -1 : 1;
  return a->route.value < b->route.value ? -1
                                         : a->route.value != b->route.value;
}

/* Called only for an executing shell failure. A disabled snapshot journal
 * has no publication destination. Each correlated version contributes its
 * actual write capability, before undo or later redirects can replace it. */
static SHELL_NONNULL(1, 2) bool dep_record_diagnostic(
    const dep_route_state_t *state, dep_route_journal_t *journal) {
  dep_diagnostics_t *diagnostics = journal->diagnostics;
  if (!diagnostics)
    return true;
  dep_route_iterator_t paths = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&paths, journal, &root)) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t stderr_routes =
        dep_fd_fact(&one, journal, dep_fd_numeric(2), DEP_FD_ACCESS_WRITE);
    if (stderr_routes.truncated)
      return false;
    for (uint32_t i = 0; i < stderr_routes.count; i++) {
      dep_fd_route_t route = stderr_routes.routes[i];
      if (route.kind == DEP_ROUTE_CLOSED || route.kind == DEP_ROUTE_ABSENT ||
          route.kind == DEP_ROUTE_UNAVAILABLE)
        continue;
      dep_diagnostic_use_t use = {journal->diagnostic_owner, route};
      uint32_t candidate = diagnostics->count + 1, match = 0;
      diagnostics->root =
          shell_avl_insert(diagnostics->index, diagnostics->root, candidate,
                           DEP_EXTERNAL_USE_CAPACITY, dep_diagnostic_compare,
                           diagnostics, &use, &match);
      if (!match)
        return false;
      if (match == candidate)
        diagnostics->uses[diagnostics->count++] = use;
    }
  }
  return true;
}
static SHELL_NONNULL(1, 2) bool dep_setup_begin(dep_route_state_t *state,
                                                dep_route_journal_t *journal,
                                                uint8_t modes);
static SHELL_NONNULL(1, 2) uint8_t
    dep_setup_mode(const dep_route_state_t *state,
                   const dep_route_journal_t *journal, uint8_t modes);
static SHELL_NONNULL(1, 2) bool dep_fd_bound(const dep_route_state_t *state,
                                             const dep_route_journal_t *journal,
                                             dep_fd_ref_t fd);
static SHELL_NONNULL(1, 2, 5) bool dep_fd_bindings(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_fd_op_t *ops, uint32_t op_count,
    const dep_named_mutations_t *mutations);
/* Concrete tables are derived journal views. Update only changed slots;
 * they do not independently interpret setup operations or validate operands. */

static SHELL_NONNULL(1, 2, 3) bool dep_fd_copy_source_exists(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal, dep_route_journal_t *requirements);
static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_missing_excused(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal, dep_route_journal_t *requirements);
static SHELL_NONNULL(1) bool dep_fd_binding_exists(
    const dep_route_set_t *binding, dep_route_journal_t *requirements);
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_fd_exec_contract_holds(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_state_t *entry, const dep_route_state_t *shell,
    const dep_route_journal_t *journal);
static SHELL_NONNULL(1, 2, 3) uint8_t
    dep_fd_operation_outcomes(const dep_fd_op_t *op,
                              const dep_route_state_t *state,
                              const dep_route_journal_t *journal);
/* Required prepared tables and journal. ops may be NULL only when op_count is
 * zero. Conditional joins and redirect-frame restoration belong to the
 * outcome stream, not to publication of one completed setup. */
static SHELL_NONNULL(1, 2, 3) bool dep_route_state_publish(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_route_state_t *executed_state, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec,
    const dep_domain_collection_t *collection);
static bool dep_restore_continuation_route_state(
    dep_route_state_t *continuation, dep_route_journal_t *changes,
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

static SHELL_NONNULL(1, 2) uint32_t
    dep_ifs_get(const dep_route_state_t *state,
                const dep_route_journal_t *journal) {
  if (!journal->ifs_seen)
    return 0;
  /* Preserve allocation/control correlation until this actual expansion
   * boundary. The digit fact itself needs only a bounded lattice, not a list
   * of IFS strings or descriptor alternatives. */
  uint32_t value = 0;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root, path = 0;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t fact =
        dep_fd_raw_fact(&one, journal, dep_fd_numeric(0), DEP_FD_ACCESS_IFS);
    uint32_t next = fact.routes[0].value;
    value = path++ ? dep_ifs_join(value, next) : next;
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

static SHELL_NONNULL(1, 2) bool dep_stdin_marker_store(
    dep_route_state_t *state, dep_route_journal_t *journal, bool value) {
  dep_route_set_t fact = {0};
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, value});
  return dep_route_state_store_access(state, journal, dep_fd_numeric(0),
                                      DEP_FD_ACCESS_STDIN_REDIR, fact);
}

/* async_redirect_stdin is best effort: an open failure leaves the incoming
 * descriptor and still executes the body. Preserve that path alongside the
 * successful read-only binding, with its interpreter marker correlation. */
static SHELL_NONNULL(1, 2) bool dep_async_stdin(dep_route_state_t *state,
                                                dep_route_journal_t *journal,
                                                bool diagnose) {
  dep_route_state_t result = {0};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  bool first = true;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t marker = dep_fd_raw_fact(&one, journal, dep_fd_numeric(0),
                                             DEP_FD_ACCESS_STDIN_REDIR);
    if (first) {
      result = one;
      first = false;
    } else if (!dep_route_state_add_root(&result, journal, root))
      return false;
    if (marker.routes[0].value)
      continue;
    if (diagnose && !dep_record_diagnostic(&one, journal))
      return false;
    const dep_fd_access_t access[] = {DEP_FD_ACCESS_READ, DEP_FD_ACCESS_WRITE,
                                      DEP_FD_ACCESS_BINDING};
    const dep_fd_route_t route[] = {{DEP_ROUTE_NULL_INPUT, UINT32_MAX},
                                    {DEP_ROUTE_UNAVAILABLE, UINT32_MAX},
                                    {DEP_ROUTE_INHERITED, UINT32_MAX}};
    for (uint32_t i = 0; i < 3; i++) {
      dep_route_set_t fact = {0};
      dep_route_set_set(&fact, route[i]);
      if (!dep_route_state_store_access(&one, journal, dep_fd_numeric(0),
                                        access[i], fact))
        return false;
    }
    if (!dep_route_state_add_root(&result, journal, one.root))
      return false;
  }
  result.correlated = true;
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

static SHELL_NONNULL(1,
                     2) bool dep_fd_private_begin(dep_route_state_t *state,
                                                  dep_route_journal_t *journal,
                                                  uint32_t event);

/* The owner's inventory is prepared once. Early wrappers have already
 * installed stdin at their execution-unit entry; simple commands do so only
 * at redirect setup, after their argv and assignment-value expansions. */
static SHELL_NONNULL(1, 2, 4, 5) bool dep_owner_stdin(
    const dep_parse_context_t *context, const dep_snapshot_source_t *source,
    uint32_t owner, dep_route_state_t *state, dep_route_journal_t *journal,
    bool entry) {
  uint32_t group = context->node_group[owner];
  uint32_t event = group == UINT32_MAX
                       ? SHELL_MAX_GROUPS + context->node_range[owner]
                       : group;
  uint32_t unit = context->async->unit[event];
  bool incoming =
      group == UINT32_MAX
          ? context->fast->cmds[context->node_range[owner]].pipe_input_mode !=
                SHELL_PIPE_MODE_NONE
          : context->execution->pipeline.group_connector[group] ==
                SHELL_TYPE_PIPELINE;
  bool compound = group != UINT32_MAX;
  if (unit && unit - 1 == event && !context->async->wrapper[event] &&
      entry == compound && !incoming && !source->stdin_redirect &&
      !dep_async_stdin(state, journal, true))
    return false;
  if (entry && compound) {
    bool subshell = context->fast->groups[group].kind == SHELL_GROUP_SUBSHELL;
    if (subshell || source->has_redirects || incoming)
      return dep_stdin_marker_store(state, journal,
                                    source->stdin_redirect || incoming);
  }
  return true;
}

typedef struct {
  uint64_t input, targets;
  uint8_t status;
  bool default_target, unsupported, assigned_failure, unassigned_failure,
      exhausted;
  /* A -u descriptor may not exist on some path of this version: no
   * dependency graph models the read (SHELL_DEP_EUNMODELED). Failed opens
   * which may leave it missing instead become requirements of a safe run
   * (dep_fd_binding_exists). */
  bool descriptor_missing;
  /* Some path of this version reaches a read failure which Bash reports as a
   * shell-level error: an invalid, missing or unresolved option operand, an
   * invalid or readonly target, or a read error on a descriptor without read
   * access. No dependency graph models it (SHELL_DEP_EUNMODELED). End of
   * input, a timeout and a zero-count read on any descriptor fail silently
   * and are ordinary outcomes. */
  bool shell_error;
} dep_read_result_t;

enum {
  DEP_READ_SUCCESS,
  DEP_READ_ASSIGNED_FAILURE,
  DEP_READ_UNASSIGNED_FAILURE,
  DEP_READ_OUTCOMES
};

typedef struct {
  dep_route_state_t outcomes[DEP_READ_OUTCOMES];
  dep_route_state_t inputs[SHELL_DEP_MAX_TOKENS + 1];
  uint64_t input_mask;
  uint8_t mask;
} dep_read_versions_t;

static SHELL_NONNULL(1, 2, 3) dep_read_result_t
    dep_read_evaluate(const dep_read_plan_t *plan,
                      const dep_route_state_t *state,
                      dep_route_journal_t *journal,
                      dep_read_versions_t *observations,
                      dep_read_frontier_t *frontier);

static SHELL_NONNULL(2) bool dep_read_scalar_shadowed(
    uint32_t root, const dep_route_journal_t *journal, dep_fd_ref_t fd);

/* Capture argument values before redirects can reassign their variables.
 * These private facts travel with execution versions, keeping entry identity
 * correlated with the physical descriptor after setup. */
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_read_capture(const dep_read_plan_t *plan, dep_route_state_t *state,
                     dep_route_journal_t *journal) {
  if (!plan->active)
    return SHELL_DEP_OK;
  /* Static argv needs no entry snapshots. Semantic validation belongs to the
   * reached post-setup frontier, where earlier descriptor failures are known.
   */
  if (!plan->entry_dependent)
    return SHELL_DEP_OK;
  dep_route_state_t result = {0};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  bool first = true;
  while (dep_route_next(&iterator, journal, &root)) {
    /* A joined binding names every place its descriptor may occupy. Capture
     * one version per place, so each read sees one physical descriptor; the
     * versions together cover every execution of the joined entry. */
    dep_route_state_t captures[SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
    uint32_t capture_count = 1;
    captures[0] = dep_route_state_single(root);
    for (uint32_t i = 0; i < plan->count; i++) {
      const dep_read_word_t *word = &plan->words[i];
      if (!word->capture || word->parameter.value != SHELL_DEP_FD_NAMED)
        continue;
      for (uint32_t c = 0, count = capture_count; c < count; c++) {
        dep_route_state_t one = captures[c];
        if (!dep_observation_require(
                &one, journal, word->parameter,
                DEP_READ_OBSERVE_VALUE |
                    (word->may_fd
                         ? DEP_READ_OBSERVE_IDENTITY | DEP_READ_OBSERVE_ACCESS
                         : 0)))
          return SHELL_DEP_ETRUNC;
        dep_route_set_t binding = dep_fd_raw_fact(
            &one, journal, word->parameter, DEP_FD_ACCESS_BINDING);
        if (dep_read_scalar_shadowed(one.root, journal, word->parameter))
          dep_route_set_set(&binding,
                            (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
        /* Bash can update these values without any explicit scalar writer.
         * Their spelling/target validity is static, their captured value is
         * not.
         */
        if (word->parameter_variable &&
            (dep_variable_properties(word->parameter_variable, &one, journal) &
             SHELL_VARIABLE_UNSTABLE))
          dep_route_set_set(&binding,
                            (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
        /* Misses left by a failed required open lie on paths the
         * requirements exclude (dep_required_feasible); they stay beside the
         * live descriptor so the read can drop them. */
        dep_route_set_t live = dep_required_feasible(&binding);
        if (word->may_fd && live.count == 1 &&
            live.routes[0].kind == DEP_ROUTE_INHERITED) {
          /* A live descriptor without a tracked place: adopt a private
           * identity once, so an argument keeps that FD if a redirect later
           * rebinds its name. */
          dep_fd_op_t imported = {.pos = UINT32_MAX,
                                  .fd_name = word->parameter.name,
                                  .fd_name_len = word->parameter.name_len};
          uint32_t slot = dep_allocation_slot(journal, &imported);
          if (slot == SHELL_DEP_FD_NONE)
            return SHELL_DEP_ETRUNC;
          dep_route_set_t alias = {0};
          dep_route_set_set(&alias, (dep_fd_route_t){DEP_ROUTE_ALIAS, slot});
          dep_route_set_t bound = alias;
          for (uint32_t r = 0; r < binding.count; r++)
            if (binding.routes[r].kind != DEP_ROUTE_INHERITED &&
                !dep_route_set_add(&bound, binding.routes[r]))
              return SHELL_DEP_ETRUNC;
          for (uint32_t access = DEP_FD_ACCESS_READ;
               access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
            dep_route_set_t entry =
                access == DEP_FD_ACCESS_BINDING
                    ? live
                    : dep_fd_raw_fact(&one, journal, word->parameter,
                                      (dep_fd_access_t)access);
            if (!dep_route_state_store_access(&one, journal,
                                              dep_fd_numeric(slot),
                                              (dep_fd_access_t)access, entry) ||
                !dep_route_state_store_access(
                    &one, journal, word->parameter, (dep_fd_access_t)access,
                    access == DEP_FD_ACCESS_BINDING ? bound : alias))
              return SHELL_DEP_ETRUNC;
          }
          binding = bound;
        }
        if (word->parameter_unquoted &&
            (dep_ifs_get(&one, journal) & DEP_IFS_DIGITS) &&
            !(binding.count == 1 &&
              (binding.routes[0].kind == DEP_ROUTE_ABSENT ||
               binding.routes[0].kind == DEP_ROUTE_UNAVAILABLE)))
          dep_route_set_set(&binding,
                            (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
        if (!word->may_fd) {
          unsigned value = dep_read_value_class(&binding);
          dep_route_set_set(&binding,
                            (dep_fd_route_t){value == 1   ? DEP_ROUTE_ABSENT
                                             : value == 2 ? DEP_ROUTE_INHERITED
                                                          : DEP_ROUTE_DYNAMIC,
                                             0});
        }
        bool places = word->may_fd && binding.count > 1;
        for (uint32_t r = 0; places && r < binding.count; r++)
          places = binding.routes[r].kind == DEP_ROUTE_ALIAS ||
                   binding.routes[r].kind == DEP_ROUTE_ABSENT ||
                   binding.routes[r].kind == DEP_ROUTE_UNAVAILABLE;
        for (uint32_t r = places ? 1 : binding.count; r < binding.count; r++) {
          if (capture_count == SHELL_DEP_TIME_MAX_EXTERNAL_FDS)
            return SHELL_DEP_ETRUNC;
          dep_route_state_t place = one;
          dep_route_set_t value = {0};
          dep_route_set_set(&value, binding.routes[r]);
          if (!dep_route_state_store_access(&place, journal, dep_fd_numeric(i),
                                            DEP_FD_ACCESS_READ_ARGUMENT, value))
            return SHELL_DEP_ETRUNC;
          captures[capture_count++] = place;
        }
        if (places) {
          dep_route_set_t value = {0};
          dep_route_set_set(&value, binding.routes[0]);
          binding = value;
        }
        if (!dep_route_state_store_access(&one, journal, dep_fd_numeric(i),
                                          DEP_FD_ACCESS_READ_ARGUMENT, binding))
          return SHELL_DEP_ETRUNC;
        captures[c] = one;
      }
    }
    for (uint32_t c = 0; c < capture_count; c++) {
      if (first) {
        result = captures[c];
        first = false;
      } else if (!dep_route_state_add_root(&result, journal, captures[c].root))
        return SHELL_DEP_ETRUNC;
    }
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return SHELL_DEP_OK;
}

/* selection is zero for default stdin, or one plus an operand ordinal selected
 * by dep_read_evaluate. Its entry capture and completed setup are in state.
 * Optional display receives the logical name only when its captured allocation
 * supplies the descriptor number. An empty fragment instead leaves a static
 * numeric operand, not a use of that variable's descriptor. */
static SHELL_NONNULL(1, 2, 4) dep_fd_ref_t
    dep_read_descriptor(const dep_read_plan_t *plan,
                        const dep_route_state_t *state, uint32_t selection,
                        const dep_route_journal_t *journal,
                        dep_fd_ref_t *display) {
  dep_fd_ref_t physical = dep_fd_numeric(0), logical = physical;
  if (selection) {
    const dep_read_word_t *word = &plan->words[selection - 1];
    physical = dep_fd_numeric(
        word->operand_kind == SHELL_READ_FD ? word->payload : word->number);
    logical = physical;
    if (word->parameter.value == SHELL_DEP_FD_NAMED) {
      dep_route_set_t captured =
          dep_fd_raw_fact(state, journal, dep_fd_numeric(selection - 1),
                          DEP_FD_ACCESS_READ_ARGUMENT);
      if (captured.routes[0].kind == DEP_ROUTE_ALIAS) {
        physical = dep_fd_numeric(captured.routes[0].value);
        logical = word->parameter;
      }
    }
  }
  if (display)
    *display = logical;
  return physical;
}

static unsigned dep_read_operand_phase(unsigned kind) {
  return kind == SHELL_READ_DATA      ? DEP_READ_DATA
         : kind == SHELL_READ_TIMEOUT ? DEP_READ_TIMEOUT
         : kind == SHELL_READ_FD      ? DEP_READ_FD
                                      : DEP_READ_NUMBER;
}

/* Descriptor presence is getopt validation, not read permission. External
 * streams have unknown runtime capabilities, except the executor's stdin
 * (fd 0), which the contract provides readable (SHELL_DEP_EUNMODELED);
 * explicit opens/closures establish definite access. Nonmutating queries
 * cache the selector masks; refining queries resolve only each live frontier
 * cell's selected descriptor. */
static SHELL_NONNULL(1) unsigned dep_read_access_outcomes(
    const dep_route_set_t *input) {
  unsigned result = 0;
  for (uint32_t i = 0; i < input->count; i++) {
    dep_route_kind_t kind = input->routes[i].kind;
    if (kind == DEP_ROUTE_CLOSED || kind == DEP_ROUTE_ABSENT ||
        kind == DEP_ROUTE_UNAVAILABLE)
      result |= DEP_STATUS_MAY_FAIL;
    else {
      result |= DEP_STATUS_MAY_SUCCEED;
      if ((kind == DEP_ROUTE_INHERITED && input->routes[i].value != 0) ||
          kind == DEP_ROUTE_UNSEEN ||
          (kind == DEP_ROUTE_DYNAMIC && input->routes[i].value == UINT32_MAX))
        result |= DEP_STATUS_MAY_FAIL;
    }
  }
  return result;
}

/* The read-access facts of a descriptor with binding which remain possible
 * under the graph's requirements. Access facts carry no failed-open cause;
 * the binding does. When every missing binding route records one, the
 * descriptor is missing only where a required open failed, so its closed
 * access routes lie only on paths the requirements exclude. An unavailable
 * access route is an open descriptor without that access: it stays. */
static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_read_feasible_access(const dep_route_set_t *binding,
                             const dep_route_set_t *input) {
  for (uint32_t i = 0; i < binding->count; i++)
    if ((binding->routes[i].kind == DEP_ROUTE_CLOSED ||
         binding->routes[i].kind == DEP_ROUTE_ABSENT ||
         binding->routes[i].kind == DEP_ROUTE_UNAVAILABLE) &&
        binding->routes[i].value == UINT32_MAX)
      return *input;
  dep_route_set_t feasible = {.ready = input->ready,
                              .truncated = input->truncated};
  for (uint32_t i = 0; i < input->count; i++)
    if (input->routes[i].kind != DEP_ROUTE_CLOSED)
      feasible.routes[feasible.count++] = input->routes[i];
  return feasible;
}

static SHELL_NONNULL(1, 2, 3, 4, 5, 6) void dep_read_input_masks(
    const dep_read_plan_t *plan, const dep_route_state_t *state,
    const dep_route_journal_t *journal, uint64_t *present, uint64_t *readable,
    uint64_t *errors) {
  *present = *readable = *errors = 0;
  for (uint32_t selection = 0; selection <= plan->count; selection++) {
    if (selection) {
      const dep_read_word_t *word = &plan->words[selection - 1];
      if (!word->may_fd)
        continue;
      if (word->parameter.value == SHELL_DEP_FD_NAMED) {
        dep_route_set_t argument =
            dep_fd_raw_fact(state, journal, dep_fd_numeric(selection - 1),
                            DEP_FD_ACCESS_READ_ARGUMENT);
        if (argument.count != 1 ||
            (argument.routes[0].kind != DEP_ROUTE_ALIAS &&
             argument.routes[0].kind != DEP_ROUTE_ABSENT &&
             argument.routes[0].kind != DEP_ROUTE_UNAVAILABLE))
          continue;
      }
    }
    uint64_t bit = UINT64_C(1) << selection;
    dep_fd_ref_t fd =
        dep_read_descriptor(plan, state, selection, journal, NULL);
    dep_route_set_t binding =
        dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_BINDING);
    if (dep_read_binding_outcomes(&binding) & DEP_STATUS_MAY_SUCCEED)
      *present |= bit;
    dep_route_set_t input = dep_fd_fact(state, journal, fd, DEP_FD_ACCESS_READ);
    input = dep_read_feasible_access(&binding, &input);
    unsigned access = dep_read_access_outcomes(&input);
    if (access & DEP_STATUS_MAY_SUCCEED)
      *readable |= bit;
    if (access & DEP_STATUS_MAY_FAIL)
      *errors |= bit;
  }
}

static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge(dep_route_state_t *destination,
                                                const dep_route_state_t *source,
                                                dep_route_journal_t *journal);

/* One completed setup version, refined by an actual descriptor observation.
 * possible=false discards an infeasible alternative. */
static SHELL_NONNULL(1, 3,
                     4) bool dep_read_state_add(dep_route_state_t *destination,
                                                bool ready,
                                                const dep_route_state_t *state,
                                                dep_route_journal_t *journal) {
  if (ready)
    return dep_fd_merge(destination, state, journal);
  *destination = *state;
  return true;
}

/* state is one imported entry or its root observation anchor. The sparse map
 * contains only predicate operands, not executable bindings or map IDs. Its
 * one PRIVATE_ENTRY holder is the only additional journal-root reference. */
static SHELL_NONNULL(1, 2) bool dep_observation_remember(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t fact) {
  dep_route_set_t recorded = dep_fd_raw_fact(
      state, journal, dep_fd_numeric(DEP_OBSERVATION_ROOT_EVENT + 1),
      DEP_FD_ACCESS_PRIVATE_ENTRY);
  dep_route_state_t observations =
      dep_route_state_single(recorded.count ? recorded.routes[0].value : 0);
  if (!dep_route_state_store_access(&observations, journal, fd, access, fact))
    return false;
  dep_route_set_set(&recorded,
                    (dep_fd_route_t){DEP_ROUTE_INHERITED, observations.root});
  return dep_route_state_store_access(
      state, journal, dep_fd_numeric(DEP_OBSERVATION_ROOT_EVENT + 1),
      DEP_FD_ACCESS_PRIVATE_ENTRY, recorded);
}

/* Require one named dependency of a selected immutable execution version.
 * Private-entry links lead back to the imported entry, before local writes or
 * pipes. Its sparse map memoizes each requested role, including unknown facts
 * as explicit empty entries. No child scans the root's read-name inventory.
 * Argument capture calls this before option validation, so early failures
 * retain their entry dependencies as well as successful descriptor queries. */
static SHELL_NONNULL(1, 2) bool dep_observation_require(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t fd,
    unsigned roles) {
  dep_route_set_t scope =
      dep_fd_raw_fact(state, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_PRIVATE_SCOPE);
  if (!scope.count)
    return true;
  if (scope.routes[0].value != UINT32_MAX) {
    dep_fd_ref_t event = dep_fd_numeric(scope.routes[0].value - 1);
    dep_route_set_t origin =
        dep_fd_raw_fact(state, journal, event, DEP_FD_ACCESS_PRIVATE_ENTRY);
    dep_route_state_t parent = dep_route_state_single(origin.routes[0].value);
    if (!dep_observation_require(&parent, journal, fd, roles))
      return false;
    if (parent.root == origin.routes[0].value)
      return true;
    origin.routes[0].value = parent.root;
    return dep_route_state_store_access(state, journal, event,
                                        DEP_FD_ACCESS_PRIVATE_ENTRY, origin);
  }
  const dep_fd_access_t accesses[] = {
      DEP_FD_ACCESS_READ_ARGUMENT, DEP_FD_ACCESS_SELECTOR, DEP_FD_ACCESS_READ,
      DEP_FD_ACCESS_VARIABLE_PRESENCE};
  const unsigned requests[] = {
      DEP_READ_OBSERVE_VALUE, DEP_READ_OBSERVE_IDENTITY,
      DEP_READ_OBSERVE_ACCESS, DEP_READ_OBSERVE_PRESENCE};
  for (unsigned i = 0; i < 4; i++) {
    if (!(roles & requests[i]))
      continue;
    dep_route_set_t recorded = dep_fd_raw_fact(
        state, journal, dep_fd_numeric(DEP_OBSERVATION_ROOT_EVENT + 1),
        DEP_FD_ACCESS_PRIVATE_ENTRY);
    dep_route_state_t memo =
        dep_route_state_single(recorded.count ? recorded.routes[0].value : 0);
    if (dep_route_state_snapshot(&memo, journal, fd, accesses[i]))
      continue;
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_READ_OBSERVATIONS);
    dep_route_set_t binding =
        dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_BINDING);
    dep_route_set_t fact = {.ready = true};
    if (requests[i] == DEP_READ_OBSERVE_PRESENCE) {
      unsigned presence = dep_presence_root(state->root, journal, fd);
      if (presence != 3u)
        dep_route_set_set(&fact,
                          (dep_fd_route_t){DEP_ROUTE_INHERITED, presence});
    } else if (requests[i] == DEP_READ_OBSERVE_VALUE) {
      const dep_read_observation_t *use =
          dep_read_observation_find(&journal->read_observations, fd);
      unsigned value = dep_read_value_class(&binding);
      if (use && use->variable &&
          (dep_variable_properties(use->variable, state, journal) &
           SHELL_VARIABLE_UNSTABLE))
        value = 3;
      if (value != 3)
        dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, value});
    } else if (requests[i] == DEP_READ_OBSERVE_IDENTITY && binding.count == 1 &&
               binding.routes[0].kind == DEP_ROUTE_ALIAS) {
      uint32_t slot = binding.routes[0].value;
      if (slot <= SHELL_DEP_FD_MAX ||
          journal->arena->allocations[slot - SHELL_DEP_FD_MAX - 1].allocation)
        dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_ALIAS, slot});
    } else if (requests[i] == DEP_READ_OBSERVE_ACCESS) {
      dep_route_set_t input =
          dep_fd_fact(state, journal, fd, DEP_FD_ACCESS_READ);
      unsigned access = dep_read_access_outcomes(&input);
      if (access != DEP_STATUS_EITHER)
        dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, access});
    }
    if (!dep_observation_remember(state, journal, fd, accesses[i], fact))
      return false;
  }
  return true;
}

/* Forget completed operands before preparing another decision. Only guards
 * needed by tracked process descriptors keep the owner's pipe lifetime. Walking
 * the two ancestry paths visits exited scopes, never a source prefix or all
 * guards. */
static SHELL_NONNULL(1, 2) bool dep_observation_leave(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_process_guard_t *previous, const dep_process_guard_t *next) {
  const dep_process_guard_t *common = previous, *other = next;
  while (common != other) {
    if (common && (!other || common->depth >= other->depth))
      common = common->parent;
    else
      other = other->parent;
  }
  if (previous == common)
    return true;
  dep_route_state_t result = {0};
  bool ready = false;
  dep_route_iterator_t versions = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_state_inherit(&one, state);
    for (const dep_process_guard_t *guard = previous; guard != common;
         guard = guard->parent) {
      if (guard->observed)
        continue;
      uint32_t key = dep_process_guard_key(journal, guard, false);
      if (key != SHELL_DEP_FD_NONE &&
          !dep_route_state_store_access(&one, journal, dep_fd_numeric(key),
                                        DEP_FD_ACCESS_PROCESS_SLOT,
                                        (dep_route_set_t){.ready = true}))
        return false;
    }
    if (!ready)
      result = one;
    else if (!dep_fd_merge_versions(&result, &one, journal))
      return false;
    ready = true;
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

/* Predicates describe input identity, not a child-local descriptor mutation.
 * Apply them while that expansion's parent version is still current. */
static SHELL_NONNULL(1, 2, 3) bool dep_observation_apply(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_observation_program_t *program, uint32_t event) {
  const dep_observation_event_t *operation = &program->events[event - 1];
  if (!dep_observation_leave(state, journal, operation->previous_guard,
                             operation->guard))
    return false;
  if (!operation->clauses)
    return true;
  if (operation->guard &&
      !dep_process_guard_prepare(state, journal, operation->guard))
    return false;
  dep_route_state_t result = {0};
  bool ready = false;
  dep_route_iterator_t versions = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t entry = dep_route_state_single(root);
    dep_route_state_inherit(&entry, state);
    bool executes = !operation->guard ||
                    dep_fd_raw_fact(&entry, journal,
                                    dep_fd_numeric(dep_process_guard_key(
                                        journal, operation->guard, false)),
                                    DEP_FD_ACCESS_PROCESS_SLOT)
                        .routes[0]
                        .value;
    if (operation->conditional || !executes) {
      dep_route_state_t skipped = entry;
      dep_route_set_t status =
          dep_fd_raw_fact(&skipped, journal, dep_fd_numeric(operation->key),
                          DEP_FD_ACCESS_SUBSTITUTION_STATUS);
      if (!status.count) {
        dep_route_set_set(
            &status,
            (dep_fd_route_t){DEP_ROUTE_INHERITED, operation->incoming_status});
        if (!dep_route_state_store_access(
                &skipped, journal, dep_fd_numeric(operation->key),
                DEP_FD_ACCESS_SUBSTITUTION_STATUS, status))
          return false;
      }
      if (!dep_read_state_add(&result, ready, &skipped, journal))
        return false;
      ready = true;
    }
    if (!executes)
      continue;
    for (uint32_t c = operation->clauses; c;
         c = program->transfer.clauses[c - 1].next) {
      const dep_observation_clause_t *clause =
          &program->transfer.clauses[c - 1];
      dep_route_state_t one = entry;
      bool possible = true;
      for (uint32_t condition = clause->conditions; condition && possible;
           condition = program->transfer.conditions[condition - 1].next) {
        const dep_observation_condition_t *test =
            &program->transfer.conditions[condition - 1];
        /* Children return presence conditions only. */
        if (!dep_observation_require(&one, journal, test->fd,
                                     DEP_READ_OBSERVE_PRESENCE) ||
            !dep_presence_assume(&one, journal, test->fd, test->value,
                                 &possible))
          return false;
      }
      if (!possible)
        continue;
      dep_route_set_t status = {0};
      dep_route_set_set(&status,
                        (dep_fd_route_t){DEP_ROUTE_INHERITED, clause->status});
      if (!dep_route_state_store_access(
              &one, journal, dep_fd_numeric(operation->key),
              DEP_FD_ACCESS_SUBSTITUTION_STATUS, status) ||
          !dep_read_state_add(&result, ready, &one, journal))
        return false;
      ready = true;
    }
  }
  if (!ready)
    return false;
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

/* Exact immutable conjunction/list interning. Keys include every semantic
 * field, including allocation provenance; status alone is never equivalence.
 * AVL indexes bound lookup independently of imported path/record count. */
static int dep_observation_condition_compare(const void *context,
                                             uint32_t index, const void *key) {
  const dep_observation_transfer_t *transfer = context;
  const dep_observation_condition_t *a = &transfer->conditions[index];
  const dep_observation_condition_t *b = key;
  int fd = dep_fd_ref_compare(a->fd, b->fd);
  if (fd)
    return fd;
  if (a->value != b->value)
    return a->value < b->value ? -1 : 1;
  return a->next < b->next ? -1 : a->next != b->next;
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_observation_condition_intern(dep_observation_transfer_t *transfer,
                                     dep_observation_index_t *index,
                                     dep_observation_condition_t condition) {
  uint32_t candidate = transfer->condition_count + 1, match = 0;
  index->condition_root = shell_avl_insert(
      index->condition_index, index->condition_root, candidate,
      DEP_OBSERVATION_CONDITION_CAPACITY, dep_observation_condition_compare,
      transfer, &condition, &match);
  if (match == candidate)
    transfer->conditions[transfer->condition_count++] = condition;
  return match;
}

static int dep_observation_clause_compare(const void *context, uint32_t index,
                                          const void *key) {
  const dep_observation_transfer_t *transfer = context;
  const dep_observation_clause_t *a = &transfer->clauses[index];
  const dep_observation_clause_t *b = key;
  if (a->conditions != b->conditions)
    return a->conditions < b->conditions ? -1 : 1;
  if (a->status != b->status)
    return a->status < b->status ? -1 : 1;
  return a->next < b->next ? -1 : a->next != b->next;
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_observation_clause_intern(dep_observation_transfer_t *transfer,
                                  dep_observation_index_t *index,
                                  dep_observation_clause_t clause) {
  uint32_t candidate = transfer->clause_count + 1, match = 0;
  index->clause_root =
      shell_avl_insert(index->clause_index, index->clause_root, candidate,
                       SHELL_DEP_MAX_NODES * 5, dep_observation_clause_compare,
                       transfer, &clause, &match);
  if (match == candidate)
    transfer->clauses[transfer->clause_count++] = clause;
  return match;
}

typedef struct {
  dep_observation_transfer_t *transfer;
  dep_observation_clause_t *clause;
  const dep_route_journal_t *journal;
  uint8_t capture_mask;
  dep_observation_index_t *index;
} dep_observation_export_walk_t;

static bool dep_observation_export_entry(void *context, dep_fd_ref_t fd,
                                         dep_fd_access_t access,
                                         uint32_t snapshot) {
  dep_observation_export_walk_t *walk = context;
  const dep_route_journal_t *journal = walk->journal;
  if (fd.value < 3 && (walk->capture_mask & (1u << fd.value)))
    return true;
  const dep_route_set_t *fact = &journal->arena->snapshots[snapshot - 1];
  if (!fact->count)
    return true;
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS ||
      access == DEP_FD_ACCESS_PRESENCE_MAP)
    return dep_route_map_each(journal, fact->routes[0].value,
                              dep_observation_export_entry, walk);
  /* Only presence is returned to the parent. A child's read outcome does
   * not refine the parent's descriptor or argument facts. */
  if (access != DEP_FD_ACCESS_VARIABLE_PRESENCE)
    return true;
  dep_observation_condition_t condition = {.fd = fd,
                                           .next = walk->clause->conditions,
                                           .value = fact->routes[0].value};
  uint32_t condition_id =
      dep_observation_condition_intern(walk->transfer, walk->index, condition);
  if (!condition_id)
    return false;
  walk->clause->conditions = condition_id;
  return true;
}

/* Only requested predicates are exported. Empty entries memoize unknown facts
 * without constraining an outcome. Child-local IDs are converted before the
 * child journal dies; no inherited table or global name inventory is walked. */
static SHELL_NONNULL(1, 2, 3, 6) bool dep_observation_export_conditions(
    dep_observation_transfer_t *transfer, dep_observation_clause_t *clause,
    const dep_route_journal_t *journal, uint32_t root, uint8_t capture_mask,
    dep_observation_index_t *index) {
  dep_observation_export_walk_t walk = {transfer, clause, journal, capture_mask,
                                        index};
  return dep_route_map_each(journal, root, dep_observation_export_entry, &walk);
}

/* final is this parse's completed outcome flow (construction's). */
static SHELL_NONNULL(1, 2) bool dep_observation_export(
    dep_route_workspace_t *workspace, const dep_fd_flow_t *final,
    uint8_t capture_mask) {
  dep_observation_transfer_t *transfer = &workspace->import_join.observations;
  transfer->condition_count = transfer->clause_count = 0;
  dep_observation_index_t *index = &workspace->import_join.observation_index;
  index->condition_root = index->clause_root = 0;
  dep_route_journal_t *journal = &workspace->journal;
  const dep_fd_flow_t *flow = final;
  if (!journal->read_observations.active) {
    for (unsigned outcome = 0; outcome < 5; outcome++)
      if (flow->mask & (1u << outcome))
        transfer->clauses[transfer->clause_count++] =
            (dep_observation_clause_t){
                .status = dep_substitution_status((uint8_t)(1u << outcome))};
    return true;
  }
  for (unsigned outcome = 0; outcome < 5; outcome++) {
    if (!(flow->mask & (1u << outcome)))
      continue;
    dep_route_iterator_t versions = dep_route_iterator(&flow->state[outcome]);
    uint32_t root;
    while (dep_route_next(&versions, journal, &root)) {
      dep_route_state_t one = dep_route_state_single(root);
      dep_route_set_t origin = dep_fd_raw_fact(
          &one, journal, dep_fd_numeric(DEP_OBSERVATION_ROOT_EVENT),
          DEP_FD_ACCESS_PRIVATE_ENTRY);
      one = dep_route_state_single(origin.routes[0].value);
      dep_route_set_t observed = dep_fd_raw_fact(
          &one, journal, dep_fd_numeric(DEP_OBSERVATION_ROOT_EVENT + 1),
          DEP_FD_ACCESS_PRIVATE_ENTRY);
      dep_observation_clause_t clause = {
          .status = dep_substitution_status((uint8_t)(1u << outcome))};
      if (observed.count && !dep_observation_export_conditions(
                                transfer, &clause, journal,
                                observed.routes[0].value, capture_mask, index))
        return false;
      if (!dep_observation_clause_intern(transfer, index, clause))
        return false;
    }
  }
  return true;
}

/* Keep the write signature on each immutable version: two paths with the
 * same status/selector can still assign different targets (polling writes
 * none, rejected targets keep only their earlier prefix). Unequal effect
 * facts prevent premature factoring. The two existing 32-bit route values
 * hold low/high target bits; the high word's top bit records REPLY. These
 * are positional words: retrieve the single-root snapshot directly, since
 * route unions deduplicate equal values and would discard the high word. */
#define DEP_READ_EFFECT_REPLY (UINT32_C(1) << 31)
_Static_assert(SHELL_DEP_MAX_TOKENS < 64,
               "read target bits leave bit 63 for the REPLY marker");
static SHELL_NONNULL(1,
                     2) bool dep_read_note_write(dep_route_state_t *state,
                                                 dep_route_journal_t *journal,
                                                 uint64_t targets, bool reply) {
  dep_route_state_t result = {0};
  dep_route_iterator_t paths = dep_route_iterator(state);
  uint32_t root;
  bool ready = false;
  while (dep_route_next(&paths, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_state_inherit(&one, state);
    dep_route_set_t effects =
        dep_fd_raw_root_fact(root, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                             DEP_FD_ACCESS_EFFECT_STATE);
    if (!effects.count) {
      effects.count = 2;
      effects.routes[0] = effects.routes[1] =
          (dep_fd_route_t){DEP_ROUTE_INHERITED, 0};
    }
    effects.routes[0].value |= (uint32_t)targets;
    effects.routes[1].value |=
        (uint32_t)(targets >> 32) | (reply ? DEP_READ_EFFECT_REPLY : 0);
    if (!dep_route_state_store_access(&one, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_EFFECT_STATE, effects) ||
        !dep_read_state_add(&result, ready, &one, journal))
      return false;
    ready = true;
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

static SHELL_NONNULL(1, 5, 6) bool dep_read_frontier_add(
    dep_read_frontier_t *frontier, unsigned mode, unsigned phase, uint64_t bits,
    const dep_route_state_t *state, dep_route_journal_t *journal) {
  for (; bits; bits &= bits - 1) {
    unsigned selection = (unsigned)__builtin_ctzll(bits);
    uint64_t bit = UINT64_C(1) << selection;
    if (!dep_read_state_add(&frontier->states[mode][phase][selection],
                            (frontier->ready[mode][phase] & bit) != 0, state,
                            journal))
      return false;
    frontier->ready[mode][phase] |= bit;
  }
  return true;
}

static SHELL_NONNULL(1, 3, 4) bool dep_read_outcome_add(
    dep_read_versions_t *observations, unsigned outcome,
    const dep_route_state_t *state, dep_route_journal_t *journal) {
  if (!dep_read_state_add(&observations->outcomes[outcome],
                          (observations->mask & (1u << outcome)) != 0, state,
                          journal))
    return false;
  observations->mask |= (uint8_t)(1u << outcome);
  return true;
}

/* Only the selected descriptor is queried at each live frontier cell; the
 * prepared word stream and the entire descriptor table are never rescanned. */
static SHELL_NONNULL(1, 2, 3, 5, 6, 7) void dep_read_selection_masks(
    const dep_read_plan_t *plan, const dep_route_state_t *state,
    const dep_route_journal_t *journal, uint32_t selection, uint64_t *present,
    uint64_t *readable, uint64_t *errors) {
  uint64_t bit = UINT64_C(1) << selection;
  dep_fd_ref_t fd = dep_read_descriptor(plan, state, selection, journal, NULL);
  dep_route_set_t binding =
      dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_BINDING);
  dep_route_set_t input = dep_fd_fact(state, journal, fd, DEP_FD_ACCESS_READ);
  input = dep_read_feasible_access(&binding, &input);
  unsigned access = dep_read_access_outcomes(&input);
  *present =
      (dep_read_binding_outcomes(&binding) & DEP_STATUS_MAY_SUCCEED) ? bit : 0;
  *readable = (access & DEP_STATUS_MAY_SUCCEED) ? bit : 0;
  *errors = (access & DEP_STATUS_MAY_FAIL) ? bit : 0;
}

static SHELL_NONNULL(1, 3, 4) bool dep_read_fail(
    dep_read_result_t *result, bool assigned, const dep_route_state_t *state,
    dep_route_journal_t *journal, dep_read_versions_t *observations) {
  if (assigned)
    result->assigned_failure = true;
  else
    result->unassigned_failure = true;
  result->status |= DEP_STATUS_MAY_FAIL;
  return !observations ||
         dep_read_outcome_add(observations,
                              assigned ? DEP_READ_ASSIGNED_FAILURE
                                       : DEP_READ_UNASSIGNED_FAILURE,
                              state, journal);
}

/* Complete a target/option path once, with its own assignment prefix. A target
 * rejection is terminal: carrying all earlier stopping points through every
 * remaining word would repeatedly query and merge an ever-growing path set.
 * observations is optional for the nonmutating role/status query. */
static SHELL_NONNULL(1, 2, 3) bool dep_read_complete(
    dep_read_result_t *result, dep_route_state_t *state,
    dep_route_journal_t *journal, unsigned mode, unsigned phase, uint64_t bit,
    uint64_t present, uint64_t readable, uint64_t errors,
    dep_read_versions_t *observations) {
  bool finished = phase == DEP_READ_OPTIONS || phase == DEP_READ_POSITIONAL ||
                  phase == DEP_READ_TARGETS ||
                  phase == DEP_READ_STOPPED_TARGETS;
  if (!finished) {
    result->shell_error = true;
    return dep_read_fail(result, false, state, journal, observations);
  }
  bool good = phase != DEP_READ_STOPPED_TARGETS;
  result->shell_error |= !mode && (bit & errors);
  bool success =
      (mode & 2u) ? (bit & present) != 0 : good && (bit & readable) != 0;
  bool default_target =
      !(mode & 2u) &&
      (phase == DEP_READ_OPTIONS || phase == DEP_READ_POSITIONAL) &&
      ((mode & 1u) || (bit & readable));
  if (observations && default_target &&
      !dep_read_note_write(state, journal, 0, true))
    return false;
  if (success) {
    result->status |= DEP_STATUS_MAY_SUCCEED;
    if (observations &&
        !dep_read_outcome_add(observations, DEP_READ_SUCCESS, state, journal))
      return false;
  }
  if (mode & 2u) {
    if (!dep_read_fail(result, false, state, journal, observations))
      return false;
  } else {
    if ((((mode & 1u) ? (bit & errors) != 0 : (bit & readable) != 0) ||
         (!good && ((mode & 1u) || (bit & readable)))) &&
        !dep_read_fail(result, true, state, journal, observations))
      return false;
    if (!(mode & 1u) && (bit & errors) &&
        !dep_read_fail(result, false, state, journal, observations))
      return false;
  }
  result->default_target |= default_target;
  if (!mode && (bit & readable)) {
    result->input |= bit;
    if (observations) {
      unsigned selection = (unsigned)__builtin_ctzll(bit);
      if (!dep_read_state_add(&observations->inputs[selection],
                              (observations->input_mask & bit) != 0, state,
                              journal))
        return false;
      observations->input_mask |= bit;
    }
  }
  return true;
}

/* Argument facts are captured at expansion, before redirect setup. Both role
 * evaluation and mutation publication use these same per-version facts. */
static SHELL_NONNULL(1, 3, 4, 5, 6) dep_route_set_t
    dep_read_argument(const dep_read_word_t *word, uint32_t index,
                      const dep_route_state_t *state,
                      const dep_route_journal_t *journal, bool *empty,
                      bool *positive) {
  dep_route_set_t argument = {0};
  *empty = *positive = false;
  if (word->capture && word->parameter.value == SHELL_DEP_FD_NAMED) {
    argument = dep_fd_raw_fact(state, journal, dep_fd_numeric(index),
                               DEP_FD_ACCESS_READ_ARGUMENT);
    *empty = *positive = argument.count != 0;
    for (uint32_t a = 0; a < argument.count; a++) {
      dep_route_kind_t kind = argument.routes[a].kind;
      *empty &= kind == DEP_ROUTE_ABSENT || kind == DEP_ROUTE_UNAVAILABLE;
      *positive &= kind == DEP_ROUTE_ALIAS || kind == DEP_ROUTE_INHERITED ||
                   kind == DEP_ROUTE_CLOSED;
    }
  }
  return argument;
}

static SHELL_NONNULL(1, 2, 3) shell_builtin_variable_t
    dep_read_target(const dep_read_word_t *word, const dep_route_state_t *state,
                    const dep_route_journal_t *journal, bool empty,
                    bool positive) {
  if (empty && word->empty_known) {
    if (word->invalid_empty_target ||
        (!word->parameter_prefix && !word->parameter_suffix))
      return SHELL_BUILTIN_VARIABLE_INVALID;
    return word->empty_effect.variable
               ? dep_variable_classification(word->empty_effect.variable, state,
                                             journal)
               : SHELL_BUILTIN_VARIABLE_STATIC;
  }
  if (word->invalid_target || (positive && !word->parameter_prefix))
    return SHELL_BUILTIN_VARIABLE_INVALID;
  return word->effect.variable ? dep_variable_classification(
                                     word->effect.variable, state, journal)
                               : word->variable;
}

/* The bounded option frontier tracks the selected descriptor together with
 * zero-character and polling modes. Words are preclassified once; no source
 * or descriptor table is rescanned for each alternative. observations and
 * frontier are NULL for a nonmutating role/status query. Otherwise frontier
 * provides two reusable workspace frontiers and observations receives the
 * refined terminal/input versions. The caller pins those versions across any
 * subsequent collection; only the frontier scratch can be reused immediately.
 */
static SHELL_NONNULL(1, 2, 3) dep_read_result_t
    dep_read_evaluate_version(const dep_read_plan_t *plan,
                              const dep_route_state_t *state,
                              dep_route_journal_t *journal,
                              dep_read_versions_t *observations,
                              dep_read_frontier_t *frontier) {
  uint64_t phases[4][DEP_READ_PHASES] = {{1}};
  dep_read_result_t result = {0};
  if (observations) {
    memset(frontier, 0, 2 * sizeof(*frontier));
    *observations = (dep_read_versions_t){0};
    frontier[0].states[0][DEP_READ_OPTIONS][0] = *state;
    if (!dep_route_state_store_access(
            &frontier[0].states[0][DEP_READ_OPTIONS][0], journal,
            dep_fd_numeric(SHELL_DEP_FD_NONE), DEP_FD_ACCESS_EFFECT_STATE,
            (dep_route_set_t){.ready = true}))
      goto exhausted;
  }
#define READ_NEXT(m, p, bits)                                                  \
  do {                                                                         \
    next[(m)][(p)] |= (bits);                                                  \
    if (observations && !dep_read_frontier_add(&frontier[(i + 1) & 1u], (m),   \
                                               (p), (bits), &one, journal))    \
      goto exhausted;                                                          \
  } while (0)
#define READ_FAIL(assigned)                                                    \
  do {                                                                         \
    result.shell_error = true;                                                 \
    if (!dep_read_fail(&result, (assigned), &one, journal, observations))      \
      goto exhausted;                                                          \
  } while (0)
#define READ_STOP()                                                            \
  do {                                                                         \
    if (!dep_read_complete(&result, &one, journal, mode,                       \
                           DEP_READ_STOPPED_TARGETS, choices, present,         \
                           readable, errors, observations))                    \
      goto exhausted;                                                          \
  } while (0)

  uint64_t present = UINT64_MAX, readable = UINT64_MAX, errors = 0;
  if (!observations)
    dep_read_input_masks(plan, state, journal, &present, &readable, &errors);
  for (uint32_t i = 0; i < plan->count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_READ_INPUT);
    const dep_read_word_t *word = &plan->words[i];
    bool named = word->parameter.value == SHELL_DEP_FD_NAMED;
    bool empty = false, positive = false;
    dep_route_set_t argument =
        dep_read_argument(word, i, state, journal, &empty, &positive);
    /* A descriptor word captures its name's binding routes verbatim, before
     * the command's own redirects can rebind the name, so a missing route
     * there still records the open whose failure left it (every such route
     * names its cause). Those no-value alternatives lie on paths the
     * requirements exclude: record the requirements and drop them, leaving
     * the version without outcomes when nothing else remains. Other words
     * capture a value class whose routes carry no cause. */
    if (word->capture && named && word->may_fd && !positive && argument.count) {
      dep_route_set_t feasible = dep_required_feasible(&argument);
      bool caused = argument.count != feasible.count && !argument.truncated;
      for (uint32_t a = 0; caused && a < feasible.count; a++)
        caused = feasible.routes[a].kind != DEP_ROUTE_CLOSED &&
                 feasible.routes[a].kind != DEP_ROUTE_ABSENT &&
                 feasible.routes[a].kind != DEP_ROUTE_UNAVAILABLE;
      if (caused) {
        (void)dep_fd_binding_exists(&argument,
                                    journal->diagnostics ? journal : NULL);
        if (!feasible.count)
          return result;
        argument = feasible;
        empty = false;
        positive = true;
        for (uint32_t a = 0; a < argument.count; a++)
          positive &= argument.routes[a].kind == DEP_ROUTE_ALIAS ||
                      argument.routes[a].kind == DEP_ROUTE_INHERITED;
      }
    }
    uint64_t next[4][DEP_READ_PHASES] = {{0}};
    if (observations)
      memset(&frontier[(i + 1) & 1u], 0, sizeof(frontier[0]));
    for (unsigned mode = 0; mode < 4; mode++) {
      for (unsigned phase = 0; phase < DEP_READ_PHASES; phase++) {
        uint64_t pending = phases[mode][phase];
        while (pending) {
          DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_READ_INPUT);
          unsigned selection = (unsigned)__builtin_ctzll(pending);
          uint64_t choices = UINT64_C(1) << selection;
          pending &= pending - 1;
          dep_route_state_t one =
              observations ? frontier[i & 1u].states[mode][phase][selection]
                           : *state;
          shell_builtin_variable_t variable =
              dep_read_target(word, &one, journal, empty, positive);
          bool writable = variable == SHELL_BUILTIN_VARIABLE_STATIC ||
                          variable == SHELL_BUILTIN_VARIABLE_DYNAMIC;
          if (observations)
            dep_read_selection_masks(plan, &one, journal, selection, &present,
                                     &readable, &errors);
          if (phase == DEP_READ_TARGETS) {
            bool elided = empty && word->can_disappear;
            if (!elided && !(mode & 2u) &&
                (choices & (mode & 1u ? UINT64_MAX : readable)) &&
                variable == SHELL_BUILTIN_VARIABLE_ARITHMETIC) {
              result.unsupported = true;
              continue;
            }
            /* An unresolved later target can reject assignment after earlier
             * writes. Fork before recording this target: the stopped version
             * must retain exactly that earlier prefix, not an arbitrary-name
             * write which would invalidate every visible descriptor binding.
             * Polling never reaches target validation or assignment. */
            if (!elided && !(mode & 2u) &&
                variable == SHELL_BUILTIN_VARIABLE_DYNAMIC) {
              result.shell_error = true;
              READ_STOP();
            }
            if (writable && !elided && !(mode & 2u) &&
                (choices & (mode & 1u ? UINT64_MAX : readable))) {
              result.targets |= UINT64_C(1) << i;
              if (observations &&
                  !dep_read_note_write(&one, journal, UINT64_C(1) << i, false))
                goto exhausted;
            }
            if (writable || elided)
              READ_NEXT(mode, DEP_READ_TARGETS, choices);
            else {
              /* An invalid, readonly or frozen target is reported; Bash
               * silently skips a non-assignable one, and polling assigns
               * nothing. */
              result.shell_error |=
                  !(mode & 2u) && variable != SHELL_BUILTIN_VARIABLE_NOASSIGN;
              READ_STOP();
            }
            continue;
          }
          if (empty && word->can_disappear) {
            READ_NEXT(mode, phase, choices);
            continue;
          }
          bool option = phase == DEP_READ_OPTIONS;
          /* Selector bytes are capabilities only on an actual option path.
           * Pending prompt/numeric operands use this same prepared word as
           * data. Earlier -u errors have already terminated their paths. */
          if (option && word->unsupported_option) {
            result.unsupported = true;
            continue;
          }
          if (option && word->dynamic && !word->option &&
              !word->parameter_prefix &&
              !(empty && word->empty_known && !word->invalid_empty_target &&
                (word->parameter_prefix || word->parameter_suffix))) {
            /* Source inspection deliberately deferred this competing option /
             * FD interpretation. Known allocation digits are an invalid first
             * target; unknown values could instead enable unsupported options.
             */
            if (!empty && !positive)
              result.unsupported = true;
            else if (mode & 2u) {
              /* Option parsing, and so its errors, precede polling. */
              result.shell_error = true;
              READ_STOP();
            } else
              READ_FAIL(false);
            continue;
          }
          if (phase == DEP_READ_POSITIONAL ||
              (option && (!word->option || word->position < 2))) {
            /* Attribute-dependent arithmetic is unsupported only when this
             * execution reaches an actual assignment. Earlier argument/FD
             * failures and polling never evaluate the target's contents. */
            if (!(mode & 2u) &&
                (choices & (mode & 1u ? UINT64_MAX : readable)) &&
                variable == SHELL_BUILTIN_VARIABLE_ARITHMETIC) {
              result.unsupported = true;
              continue;
            }
            /* Bash's timeout-zero availability probe precedes target checks. */
            if ((mode & 2u) || variable != SHELL_BUILTIN_VARIABLE_INVALID) {
              if (!(mode & 2u) && variable == SHELL_BUILTIN_VARIABLE_DYNAMIC) {
                /* An invalid first identifier fails before input; a readonly
                 * one can fail after input. Neither alternative writes this
                 * target. Keep both separate from the writable version. */
                READ_FAIL(false);
                READ_STOP();
              }
              if (writable && !(mode & 2u) &&
                  (choices & (mode & 1u ? UINT64_MAX : readable))) {
                result.targets |= UINT64_C(1) << i;
                if (observations && !dep_read_note_write(
                                        &one, journal, UINT64_C(1) << i, false))
                  goto exhausted;
              }
              if (writable)
                READ_NEXT(mode, DEP_READ_TARGETS, choices);
              else {
                result.shell_error |=
                    !(mode & 2u) && variable != SHELL_BUILTIN_VARIABLE_NOASSIGN;
                READ_STOP();
              }
            } else
              READ_FAIL(false);
            continue;
          }
          if (option && !word->valid) {
            if (word->end && word->position == 2)
              READ_NEXT(mode, DEP_READ_POSITIONAL, choices);
            else
              READ_FAIL(false);
            continue;
          }
          if (option && !word->operand_kind) {
            READ_NEXT(mode, DEP_READ_OPTIONS, choices);
            continue;
          }
          unsigned operand =
              option ? dep_read_operand_phase(word->operand_kind) : phase;
          bool nonempty = word->attached_static || positive;
          if (option && !nonempty)
            READ_NEXT(mode, operand, choices);
          if (option && !word->attached_static && !word->attached_dynamic)
            continue;
          unsigned value =
              option ? (empty ? word->empty_payload_value : word->payload_value)
              : operand == DEP_READ_TIMEOUT
                  ? (empty ? word->empty_timeout_value : word->timeout_value)
                  : (empty ? word->empty_number_value : word->number_value);
          /* Preparation distinguishes whole-word and attached numeric
           * templates. Captured allocation digits refine a signed scalar,
           * including integer leading zeroes, not arbitrary concatenation
           * (which can wrap or round). */
          uint8_t scalar = option                        ? word->payload_scalar
                           : operand == DEP_READ_TIMEOUT ? word->timeout_scalar
                                                         : word->number_scalar;
          if (value == SHELL_READ_VALUE_UNKNOWN && named && scalar && positive)
            value = scalar == 2 ? SHELL_READ_VALUE_INVALID
                                : SHELL_READ_VALUE_NONZERO;
          if (option && empty && !word->attached_static)
            continue;
          if (operand == DEP_READ_DATA) {
            READ_NEXT(mode, DEP_READ_OPTIONS, choices);
          } else if (value == SHELL_READ_VALUE_INVALID) {
            /* A whole option-looking word can be a pending numeric operand.
             * Its invalid prefix fails before any dynamic FD lookup, even
             * when its attached payload is a tracked parameter. */
            READ_FAIL(false);
          } else if (operand == DEP_READ_FD) {
            bool exact_fd = named && scalar == 1;
            if (word->dynamic && !empty &&
                (!exact_fd || argument.count != 1 ||
                 argument.routes[0].kind == DEP_ROUTE_DYNAMIC ||
                 argument.routes[0].kind == DEP_ROUTE_UNSEEN)) {
              result.unsupported = true;
              continue;
            }
            if (named && !empty) {
              if (!dep_fd_binding_exists(&argument,
                                         journal->diagnostics ? journal : NULL))
                result.descriptor_missing = true;
              if (argument.routes[0].kind != DEP_ROUTE_ALIAS) {
                READ_FAIL(false);
                continue;
              }
            }
            dep_fd_ref_t fd =
                dep_read_descriptor(plan, &one, i + 1, journal, NULL);
            {
              dep_route_set_t binding =
                  dep_fd_raw_fact(&one, journal, fd, DEP_FD_ACCESS_BINDING);
              /* Only the final execution walk records requirements. A
               * descriptor missing only where a required open failed fails
               * the read only on paths the requirements exclude, so that
               * failure has no outcome. Any other missing route is a read
               * error: its failure is an outcome which the script may
               * handle (dep_read_status_consumed). */
              if (!dep_fd_binding_exists(&binding,
                                         journal->diagnostics ? journal : NULL))
                result.descriptor_missing = true;
              dep_route_set_t required = dep_required_feasible(&binding);
              uint8_t outcomes = dep_read_binding_outcomes(&required);
              if (outcomes & DEP_STATUS_MAY_FAIL)
                READ_FAIL(false);
              if (!(outcomes & DEP_STATUS_MAY_SUCCEED))
                continue;
            }
            READ_NEXT(mode, DEP_READ_OPTIONS, UINT64_C(1) << (i + 1));
          } else {
            unsigned bit = operand == DEP_READ_TIMEOUT ? 2u : 1u;
            if (value == SHELL_READ_VALUE_UNKNOWN) {
              /* Unknown data can also be an invalid number. This failure
               * precedes later options, FD validation and target writes. */
              READ_FAIL(false);
              READ_NEXT(mode | bit, DEP_READ_OPTIONS, choices);
              READ_NEXT(mode & ~bit, DEP_READ_OPTIONS, choices);
            } else
              READ_NEXT(value == SHELL_READ_VALUE_ZERO ? mode | bit
                                                       : mode & ~bit,
                        DEP_READ_OPTIONS, choices);
          }
        }
      }
    }
    memcpy(phases, next, sizeof(phases));
  }
  for (unsigned mode = 0; mode < 4; mode++)
    for (unsigned phase = 0; phase < DEP_READ_PHASES; phase++)
      for (uint64_t pending = phases[mode][phase]; pending;
           pending &= pending - 1) {
        unsigned selection = (unsigned)__builtin_ctzll(pending);
        uint64_t bit = UINT64_C(1) << selection;
        dep_route_state_t one =
            observations
                ? frontier[plan->count & 1u].states[mode][phase][selection]
                : *state;
        if (observations)
          dep_read_selection_masks(plan, &one, journal, selection, &present,
                                   &readable, &errors);
        if (!dep_read_complete(&result, &one, journal, mode, phase, bit,
                               present, readable, errors, observations))
          goto exhausted;
      }
#undef READ_NEXT
#undef READ_FAIL
#undef READ_STOP
  return result;
exhausted:
  result.exhausted = true;
  return result;
}

/* Capability alternatives must be interpreted independently, including status
 * queries which do not request observation storage. Each result retains its
 * completed-write signature and input provenance through subsequent merging. */
static SHELL_NONNULL(1, 2, 3) dep_read_result_t
    dep_read_evaluate(const dep_read_plan_t *plan,
                      const dep_route_state_t *state,
                      dep_route_journal_t *journal,
                      dep_read_versions_t *observations,
                      dep_read_frontier_t *frontier) {
  dep_route_state_t entries = *state;
  if (plan->entry_dependent)
    for (uint32_t i = 0; i < plan->count; ++i)
      if (!dep_variable_resolve(&entries, journal,
                                plan->words[i].effect.variable) ||
          !dep_variable_resolve(&entries, journal,
                                plan->words[i].empty_effect.variable))
        return (dep_read_result_t){.exhausted = true};
  if (dep_route_state_count(&entries) == 1)
    return dep_read_evaluate_version(plan, &entries, journal, observations,
                                     frontier);
  dep_read_result_t result = {0};
  if (observations)
    *observations = (dep_read_versions_t){0};
  dep_route_iterator_t versions = dep_route_iterator(&entries);
  uint32_t root;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_state_inherit(&one, &entries);
    dep_read_versions_t local;
    dep_read_result_t read = dep_read_evaluate_version(
        plan, &one, journal, observations ? &local : NULL, frontier);
    result.input |= read.input;
    result.targets |= read.targets;
    result.status |= read.status;
    result.default_target |= read.default_target;
    result.unsupported |= read.unsupported;
    result.assigned_failure |= read.assigned_failure;
    result.unassigned_failure |= read.unassigned_failure;
    result.exhausted |= read.exhausted;
    if (result.exhausted)
      return result;
    if (!observations)
      continue;
    for (unsigned i = 0; i < DEP_READ_OUTCOMES; ++i)
      if ((local.mask & (1u << i)) &&
          !dep_read_outcome_add(observations, i, &local.outcomes[i], journal))
        goto exhausted;
    for (uint32_t i = 0; i <= plan->count; ++i) {
      uint64_t bit = UINT64_C(1) << i;
      if (!(local.input_mask & bit))
        continue;
      if (!dep_read_state_add(&observations->inputs[i],
                              (observations->input_mask & bit) != 0,
                              &local.inputs[i], journal))
        goto exhausted;
      observations->input_mask |= bit;
    }
  }
  return result;
exhausted:
  result.exhausted = true;
  return result;
}

static SHELL_NONNULL(1, 2, 3) bool dep_ifs_copy(dep_route_state_t *destination,
                                                const dep_route_state_t *source,
                                                dep_route_journal_t *journal) {
  uint32_t value = dep_ifs_get(source, journal);
  return value == dep_ifs_get(destination, journal) ||
         dep_ifs_store(destination, journal, value);
}

static SHELL_NONNULL(1, 2, 3) bool dep_ifs_apply(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_named_mutations_t *mutations) {
  if (!mutations->ifs_write && !mutations->ifs_maybe_unset)
    return true;
  uint32_t value =
      mutations->ifs_write ? mutations->ifs : dep_ifs_get(state, journal);
  if (mutations->ifs_write && mutations->ifs_append)
    value |= dep_ifs_get(state, journal);
  if (mutations->ifs_maybe_unset)
    value = dep_ifs_join(value, 0);
  return dep_ifs_store(state, journal, value);
}

/* Zero: expansion is unchanged. One: it necessarily produces no usable
 * descriptor. Two: decimal splitting could change the selected descriptor;
 * without an exact runtime number this source is outside route analysis. */
static SHELL_NONNULL(1, 2, 3) unsigned dep_fd_ifs_expansion(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal) {
  if (!op->target_unquoted)
    return 0;
  uint32_t value = dep_ifs_get(state, journal);
  if (!(value & DEP_IFS_DIGITS))
    return 0;
  if (((value >> DEP_IFS_CERTAIN_SHIFT) & DEP_IFS_DIGITS) == DEP_IFS_DIGITS ||
      ((value & DEP_IFS_SELF) &&
       dep_fd_name_equal(op->target_fd_name, op->target_fd_name_len, "IFS", 3)))
    return 1;
  return 2;
}

/* A numeric destination can equal a named source's physical slot. A newly
 * allocated named destination never does, even when it rebinds the same name.
 * Every retained allocation path must agree before collapsing the operation;
 * otherwise each path resolves its identity during journal application. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_physical_self(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal) {
  if (!dep_fd_op_copies(op->kind) || op->fd == SHELL_DEP_FD_NAMED)
    return false;
  if (dep_fd_op_numeric_self_dup(op))
    return true;
  if (op->target_fd != SHELL_DEP_FD_NAMED)
    return false;
  dep_fd_ref_t source = {.name = op->target_fd_name,
                         .value = op->target_fd,
                         .name_len = op->target_fd_name_len};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    /* Slot identity needs the variable proof, not its last byte route. An
     * unset/reassignment invalidates that proof without closing the old FD. */
    dep_route_set_t slots =
        dep_fd_raw_fact(&one, journal, source, DEP_FD_ACCESS_BINDING);
    if (slots.count != 1 || slots.routes[0].kind != DEP_ROUTE_ALIAS ||
        slots.routes[0].value != op->fd)
      return false;
  }
  return true;
}

static SHELL_NONNULL(1, 2, 3) dep_fd_op_t
    dep_fd_effective_operation(const dep_fd_op_t *op,
                               const dep_route_state_t *state,
                               const dep_route_journal_t *journal) {
  dep_fd_op_t result = *op;
  result.undo_mode = dep_setup_mode(state, journal, op->undo_mode);
  unsigned expansion = dep_fd_ifs_expansion(op, state, journal);
  /* Field splitting applies to the parameter value, not the literal suffix.
   * Removing every digit leaves `-`, which closes the destination. */
  if (expansion == 1) {
    result.kind =
        op->kind == DEP_FD_OP_MOVE ? DEP_FD_OP_CLOSE : DEP_FD_OP_FAILED;
    result.resets_descriptor = false;
    result.target_closed_locally = false;
    result.target_unquoted = false;
    result.document_flags = NULL;
    result.paired_open = false;
    if (result.kind == DEP_FD_OP_CLOSE) {
      result.target_fd = SHELL_DEP_FD_NONE;
      result.target_fd_name = NULL;
      result.target_fd_name_len = 0;
      result.access = DEP_FD_ACCESS_BOTH;
    }
  } else if (expansion == 0 && dep_fd_physical_self(op, state, journal)) {
    result.kind = DEP_FD_OP_IDENTITY;
    result.resets_descriptor = false;
    result.target_closed_locally = false;
  }
  return result;
}

/* Names and numeric aliases designate the same physical slot. A failure is
 * local only when every selected execution version modified that slot in this
 * setup frame. Untracked/invalidated variables still fail the input boundary.
 */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_source_closed_locally(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal) {
  if (op->target_closed_locally)
    return true;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_fd_ref_t source = {.name = op->target_fd_name,
                           .value = op->target_fd,
                           .name_len = op->target_fd_name_len};
    if (source.value == SHELL_DEP_FD_NAMED) {
      dep_route_set_t slots =
          dep_fd_raw_fact(&one, journal, source, DEP_FD_ACCESS_BINDING);
      if (slots.count != 1 || slots.routes[0].kind != DEP_ROUTE_ALIAS)
        return false;
      source = dep_fd_numeric(slots.routes[0].value);
    }
    dep_route_set_t modified =
        dep_fd_raw_fact(&one, journal, source, DEP_FD_ACCESS_SETUP_FRAME);
    dep_route_set_t frame = dep_fd_raw_fact(
        &one, journal, dep_fd_numeric(SHELL_DEP_FD_NONE), DEP_FD_ACCESS_ENTRY);
    if (!modified.count || !frame.count ||
        modified.routes[0].value != frame.routes[0].value)
      return false;
  }
  return true;
}

/* Pipes are installed before expansion/redirection. Their stable source
 * owners are available even when the corresponding control edge is emitted
 * only after this owner's nested substitutions have been joined. */
static bool dep_snapshot_install_pipeline(dep_route_state_t *alternatives,
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
        route = (dep_fd_route_t){DEP_ROUTE_PIPE_INPUT,
                                 dep_resource_value(changes->depth, owner)};
      if (fd == 1 && access == DEP_FD_ACCESS_WRITE)
        route = (dep_fd_route_t){DEP_ROUTE_PIPE_OUTPUT,
                                 dep_resource_value(changes->depth, owner)};
      dep_route_set_t set = {0};
      dep_route_set_set(&set, route);
      if (!dep_route_state_store_access(alternatives, changes,
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

static SHELL_NONNULL(1, 2) bool dep_process_owned(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    dep_fd_ref_t fd);

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
        shell_avl_insert(frame->index, frame->root, candidate,
                         sizeof(frame->fds) / sizeof(frame->fds[0]),
                         dep_numeric_fd_compare, frame->fds, &fd, &match);
    if (!match)
      return false;
    if (match == candidate) {
      frame->fds[frame->count++] = fd;
    }
  }
  return true;
}

static SHELL_NONNULL(1) bool dep_redirect_frame_scratch(
    dep_redirect_frame_t *frame, uint32_t key) {
  if (key == SHELL_DEP_FD_NONE)
    return true;
  uint32_t candidate = frame->scratch_count + 1, match = 0;
  frame->scratch_root = shell_avl_insert(
      frame->scratch_index, frame->scratch_root, candidate,
      sizeof(frame->scratch_keys) / sizeof(frame->scratch_keys[0]),
      dep_numeric_fd_compare, frame->scratch_keys, &key, &match);
  if (!match)
    return false;
  if (match == candidate)
    frame->scratch_keys[frame->scratch_count++] = key;
  return true;
}

/* Numeric aliases of a named close are real temporary slots too. Slot
 * identities come from the reached operation, never from a later variable
 * spelling or another traversal of the redirect list. frame already records
 * numeric destinations from these same prepared ops; journal holds their
 * reached setup versions. ops may be NULL only when op_count is zero. */
static SHELL_NONNULL(1, 2) bool dep_redirect_frame_aliases(
    dep_redirect_frame_t *frame, dep_route_journal_t *journal,
    const dep_fd_op_t *ops, uint32_t op_count) {
  for (uint32_t op = 0; op < op_count; op++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES);
    if ((journal->observable_fd_count || journal->named_closes) &&
        ops[op].fd == SHELL_DEP_FD_NAMED && ops[op].resets_descriptor &&
        !dep_redirect_frame_scratch(frame,
                                    dep_allocation_slot(journal, ops + op)))
      return false;
    bool move =
        ops[op].kind == DEP_FD_OP_MOVE && !dep_fd_op_numeric_self_dup(ops + op);
    if (ops[op].fd == SHELL_DEP_FD_NAMED && ops[op].kind == DEP_FD_OP_CLOSE &&
        !dep_redirect_frame_scratch(
            frame, dep_undo_slot(journal, ops + op, DEP_ALLOCATION_TARGET_UNDO,
                                 false)))
      return false;
    if (dep_fd_op_saves_numeric(ops + op)) {
      uint32_t key =
          dep_undo_slot(journal, ops + op, DEP_ALLOCATION_TARGET_UNDO, false);
      if (!dep_redirect_frame_scratch(frame, key))
        return false;
    }
    if (move) {
      dep_fd_op_t close = dep_fd_move_close(ops + op);
      if (!dep_redirect_frame_scratch(
              frame,
              dep_undo_slot(journal, &close, DEP_ALLOCATION_MOVE_UNDO, false)))
        return false;
    }
    if (!move &&
        (ops[op].fd != SHELL_DEP_FD_NAMED || ops[op].kind != DEP_FD_OP_CLOSE))
      continue;
    dep_allocation_t key = {.name = ops[op].fd_name, .position = ops[op].pos};
    uint32_t cursor = journal->arena->allocation_root;
    while (cursor) {
      int order = dep_allocation_compare(journal, cursor - 1, &key);
      if (!order)
        break;
      cursor = order > 0 ? journal->arena->allocation_index[cursor - 1].left
                         : journal->arena->allocation_index[cursor - 1].right;
    }
    if (!cursor || !journal->arena->allocations[cursor - 1].closed_slots)
      continue;
    const dep_route_set_t *slots =
        &journal->arena
             ->snapshots[journal->arena->allocations[cursor - 1].closed_slots -
                         1];
    for (uint32_t slot = 0; slot < slots->count; slot++) {
      uint32_t fd = slots->routes[slot].value, candidate = frame->count + 1;
      uint32_t match = 0;
      frame->root =
          shell_avl_insert(frame->index, frame->root, candidate,
                           sizeof(frame->fds) / sizeof(frame->fds[0]),
                           dep_numeric_fd_compare, frame->fds, &fd, &match);
      if (!match)
        return false;
      if (match == candidate) {
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

/* Adds fd to set; false when the set is full. */
static SHELL_NONNULL(1) bool dep_fd_set_add(dep_fd_set_t *set, uint32_t fd) {
  uint32_t candidate = set->count + 1, match = 0;
  set->root = shell_avl_insert(set->index, set->root, candidate,
                               SHELL_DEP_MAX_TOKENS * 3, dep_numeric_fd_compare,
                               set->fds, &fd, &match);
  if (match == candidate)
    set->fds[set->count++] = fd;
  return match != 0;
}

static SHELL_NONNULL(1) bool dep_fd_set_has(const dep_fd_set_t *set,
                                            uint32_t fd) {
  uint32_t root = set->root;
  while (root) {
    int order = dep_numeric_fd_compare(set->fds, root - 1, &fd);
    if (!order)
      return true;
    root = order < 0 ? set->index[root - 1].right : set->index[root - 1].left;
  }
  return false;
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

/* Whether a command's own redirect setup failure is inverted by its `!`. A
 * simple command's returning failure is negated with its other outcomes, and
 * so is any command that runs as a pipeline or asynchronous child, whose
 * failed setup is that child's exit status. In the current shell, Bash
 * returns a compound command's setup failure before applying the inversion. */
static bool dep_setup_failure_negated(shell_command_kind_t kind,
                                      uint32_t negation_count, bool child) {
  return (kind == SHELL_COMMAND_SIMPLE || child) &&
         (negation_count & UINT32_C(1));
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

static SHELL_NONNULL(4) void dep_exit_operand_dynamic(const char *word,
                                                      size_t length,
                                                      bool quoted,
                                                      void *context) {
  (void)word;
  (void)length;
  (void)quoted;
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
    if (dep_skip_nonargument(tokens, &i))
      continue;
    const dep_token_t *word = &tokens->tokens[i];
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

/* A private interpreter's termination is a return to its parent, not a reason
 * to discard the child's known status. Launch success is handled separately
 * by the asynchronous-list cursor. */
static uint8_t dep_status_child_return(uint8_t status) {
  return (status & (DEP_STATUS_EITHER | DEP_STATUS_EXIT_INCOMING)) |
         ((status & DEP_STATUS_TERMINAL_SUCCESS) ? DEP_STATUS_MAY_SUCCEED : 0) |
         ((status & (DEP_STATUS_TERMINAL_FAILURE | DEP_STATUS_ABORT_FAILURE))
              ? DEP_STATUS_MAY_FAIL
              : 0);
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
  const shell_group_t *descriptor = &context->fast->groups[group];
  uint8_t added = context->event_static_status[group] & DEP_STATUS_STOP;
  if (context->group_exec[group].setup_can_fail)
    added |= DEP_STATUS_MAY_FAIL;
  dep_group_completion_t result = {0};
  for (unsigned i = 0; i < 5; i++) {
    uint8_t outcome = (uint8_t)(1u << i);
    if (context->group_exec[group].isolated) {
      if (outcome == DEP_STATUS_TERMINAL_SUCCESS)
        outcome = DEP_STATUS_MAY_SUCCEED;
      else if (outcome &
               (DEP_STATUS_TERMINAL_FAILURE | DEP_STATUS_ABORT_FAILURE))
        outcome = DEP_STATUS_MAY_FAIL;
    }
    /* In the current shell, setup runs outside this compound's negation and
     * negation only inverts body returns. A pipeline stage runs in a child
     * whose failed setup is its exit status, so the pipeline's `!` inverts
     * it. An enclosing compound may still negate a returned setup failure. */
    bool negated = group_is_pipeline_negated(descriptor);
    uint8_t returned = negated ? dep_status_negate(outcome) : outcome;
    if (added & (1u << i))
      result.added |=
          context->group_exec[group].pipeline_member ? returned : outcome;
    result.outcome[i] = returned;
  }
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
  uint32_t candidate = source->checkpoint_count + 1, match = 0;
  source->checkpoint_root = shell_avl_insert(
      source->checkpoint_index, source->checkpoint_root, candidate, capacity,
      dep_snapshot_checkpoint_compare, source, &position, &match);
  if (!match)
    return false;
  if (match == candidate) {
    source->checkpoint_position[source->checkpoint_count] = position;
    source->checkpoint_diagnostic[source->checkpoint_count] = false;
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
static SHELL_NONNULL(1, 2, 3) void dep_route_domains_collect(
    dep_route_journal_t *journal, const dep_domain_collection_t *collection,
    const dep_route_state_t *live, const dep_route_state_t *pending);

/* The table after all redirections receives the owner's body process words
 * (dep_snapshot_phase_table). *table is replaced by a fresh copy, so those
 * never reach an entry or an earlier checkpoint that shares it. */
static SHELL_NONNULL(1, 2) bool dep_snapshot_table_private(
    dep_route_workspace_t *workspace, uint32_t *table) {
  uint32_t copy = dep_snapshot_table_allocate(workspace);
  if (copy == UINT32_MAX)
    return false;
  workspace->snapshot_tables[copy] = workspace->snapshot_tables[*table];
  *table = copy;
  return true;
}

static SHELL_NONNULL(1, 2, 3, 6, 7) shell_dep_error_t
    dep_snapshot_operand_table(
        shell_dep_graph_t *graph, dep_route_workspace_t *workspace,
        dep_snapshot_source_t *source, uint32_t entry_table, uint32_t position,
        uint32_t *result, const dep_parse_context_t *context, uint32_t owner) {
  /* All successful assignment-only commits precede redirect expansion. Cache
   * this one phase entry separately from the immutable command/RHS entry. */
  uint32_t event = context->node_group[owner] == UINT32_MAX
                       ? SHELL_MAX_GROUPS + context->node_range[owner]
                       : context->node_group[owner];
  bool async_setup =
      context->async->unit[event] == event + 1 && !context->async->early[event];
  if (async_setup ||
      (source->mutations.before_redirect && source->mutations.count)) {
    if (source->redirect_entry_table == UINT32_MAX) {
      uint32_t table = dep_snapshot_table_allocate(workspace);
      if (table == UINT32_MAX)
        return SHELL_DEP_ETRUNC;
      dep_route_state_t alternatives =
          dep_snapshot_alternatives(&workspace->snapshot_tables[entry_table]);
      if (async_setup && !dep_owner_stdin(context, source, owner, &alternatives,
                                          &workspace->journal, false))
        return SHELL_DEP_ETRUNC;
      /* Only assignment-only commits precede redirect expansion; a command's
       * own effects (cd's PWD) happen after it, in a background command's
       * subshell as well. */
      if (source->mutations.before_redirect &&
          (!dep_fd_bindings(&alternatives, &workspace->journal, NULL, 0,
                            &source->mutations) ||
           !dep_ifs_apply(&alternatives, &workspace->journal,
                          &source->mutations)))
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
  uint32_t operation_indices[DEP_ROUTE_OPERATION_CAPACITY];
  dep_snapshot_operation_range(source, source->op_root, begin, position, ops,
                               operation_indices, &count);
  if (!count) {
    if ((position == UINT32_MAX &&
         !dep_snapshot_table_private(workspace, &incoming)) ||
        !dep_snapshot_checkpoint_record(source, position, incoming))
      return SHELL_DEP_ETRUNC;
    *result = incoming;
    return SHELL_DEP_OK;
  }
  uint32_t first = source->op_root;
  while (source->op_index[first - 1].left)
    first = source->op_index[first - 1].left;
  first--;
  /* A descriptor-only exec keeps the exec contract against the state its
   * redirections started from (dep_fd_exec_contract_holds). */
  bool persistent =
      event >= SHELL_MAX_GROUPS && source->exec.persistent_redirects;
  dep_route_state_t setup_entry = {0}, shell_entry = {0};
  if (persistent) {
    setup_entry = dep_snapshot_alternatives(&tables[entry_table]);
    shell_entry =
        dep_snapshot_alternatives(&tables[context->snapshot->persistent[0]]);
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
      if ((boundary == UINT32_MAX &&
           !dep_snapshot_table_private(workspace, &incoming)) ||
          !dep_snapshot_checkpoint_record(source, boundary, incoming))
        return SHELL_DEP_ETRUNC;
      continue;
    }
    uint32_t table = dep_snapshot_table_allocate(workspace);
    if (table == UINT32_MAX)
      return SHELL_DEP_ETRUNC;
    dep_route_state_t alternatives =
        dep_snapshot_alternatives(&tables[incoming]);
    dep_domain_collection_t collection = {.workspace = workspace,
                                          .frame = context->snapshot};
    for (uint32_t op = batch; op < end; op++) {
      if (ops[op].pos >= context->owner_setup_stop[owner])
        break;
      dep_route_domains_collect(&workspace->journal, &collection, &alternatives,
                                NULL);
      unsigned expansion =
          dep_fd_ifs_expansion(ops + op, &alternatives, &workspace->journal);
      if (expansion == 2)
        return SHELL_DEP_EPARSE;
      dep_fd_op_t effective = dep_fd_effective_operation(
          ops + op, &alternatives, &workspace->journal);
      /* Only tracked variable-to-descriptor associations are supported.
       * Check this semantic boundary against the ordered journal, including
       * saves created earlier in this setup, never a concrete representative.
       * Numeric closed sources instead fail setup at runtime below. */
      dep_fd_ref_t operand =
          effective.kind == DEP_FD_OP_CLOSE
              ? (dep_fd_ref_t){.name = effective.fd_name,
                               .value = effective.fd,
                               .name_len = effective.fd_name_len}
              : (dep_fd_ref_t){.name = effective.target_fd_name,
                               .value = effective.target_fd,
                               .name_len = effective.target_fd_name_len};
      if ((effective.kind == DEP_FD_OP_CLOSE ||
           dep_fd_op_copies(effective.kind)) &&
          !dep_fd_bound(&alternatives, &workspace->journal, operand))
        return SHELL_DEP_EPARSE;
      uint8_t outcomes = dep_fd_operation_outcomes(ops + op, &alternatives,
                                                   &workspace->journal);
      /* A copy or move whose source may not exist on some path reaching it
       * can fail at runtime: unmodeled, unless a failed open of the source is
       * the only cause, which then becomes a requirement of a safe run. */
      if (dep_fd_op_copies(ops[op].kind) &&
          !dep_fd_copy_source_exists(ops + op, &alternatives,
                                     &workspace->journal,
                                     &workspace->journal)) {
        workspace->journal.unmodeled = true;
        return SHELL_DEP_EUNMODELED;
      }
      if ((outcomes & DEP_STATUS_MAY_FAIL) &&
          (ops[op].kind != DEP_FD_OP_DOCUMENT ||
           graph->nodes[owner].type == SHELL_NODE_GROUP ||
           graph->nodes[dep_edge_document_index(
                            graph, &graph->edges[ops[op].edge_index])]
                   .doc.kind == SHELL_DOC_FILE))
        source->setup_may_fail = true;
      if (!(outcomes & DEP_STATUS_MAY_SUCCEED)) {
        /* A previously unavailable symbolic operand remains outside the
         * supported binding contract. A known numeric close, a close within
         * this setup, and the implicit pipe duplication are supported runtime
         * failures. */
        bool excused =
            dep_fd_missing_excused(&effective, &alternatives,
                                   &workspace->journal, &workspace->journal);
        if (!excused && !expansion &&
            !dep_fd_source_closed_locally(ops + op, &alternatives,
                                          &workspace->journal) &&
            ops[op].target_fd == SHELL_DEP_FD_NAMED)
          return SHELL_DEP_EPARSE;
        /* A reached setup operation which cannot succeed is a certain
         * shell-level error, which no dependency graph represents, unless
         * every missing route already records a failed open whose success
         * the graph requires: the operation then fails only where those
         * requirements fail. */
        if (!excused) {
          workspace->journal.unmodeled = true;
          return SHELL_DEP_EUNMODELED;
        }
        /* Every path reaching it fails here, as Bash does: the owner's setup
         * stops at this operation and its body never runs. */
        if (ops[op].pos < context->owner_setup_stop[owner])
          context->owner_setup_stop[owner] = ops[op].pos;
        break;
      }
      if (persistent &&
          !dep_fd_exec_contract_holds(&effective, &alternatives, &setup_entry,
                                      &shell_entry, &workspace->journal)) {
        workspace->journal.unmodeled = true;
        return SHELL_DEP_EUNMODELED;
      }
      dep_route_state_t previous_state = alternatives;
      /* Keep the entry state live: the application can sweep the journal. */
      collection.roots[0] = &previous_state;
      collection.roots[1] = &setup_entry;
      collection.roots[2] = &shell_entry;
      /* The owner's setup frame begins at its first operation, whichever
       * checkpoint this range resumes from. */
      if (!dep_route_state_apply(&alternatives, &workspace->journal, ops + op,
                                 1, operation_indices[op] == first,
                                 &collection))
        return SHELL_DEP_ETRUNC;
      /* The journal application above consumed the original MOVE identity.
       * All later publication and frame restoration must consume its effective
       * CLOSE/IDENTITY semantics rather than reinterpret the raw operand. */
      source->ops[operation_indices[op]] = effective;
      ops[op] = effective;
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

/* Required retained owner with its inverse source map installed. */
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
 * product. */
static SHELL_NONNULL(1, 2, 4, 5) bool dep_fd_begin(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, dep_route_state_t *selected);

static SHELL_NONNULL(1, 2, 4, 5, 10, 12) shell_dep_error_t dep_fd_finish_owner(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_route_state_t *executed_state,
    const dep_fd_op_t *ops, uint32_t op_count, bool descriptor_exec,
    bool named_binding, const dep_named_mutations_t *mutations,
    dep_route_state_t *report_state, const dep_route_state_t *setup_entry);

static SHELL_NONNULL(1, 2, 4, 5) bool dep_fd_complete_group(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t group,
    dep_route_journal_t *journal, const dep_redirect_frame_t *frames);
/* Captures and aggregate substitution status belong to one command's
 * evaluation, not its continuation. Deferred input publication retains its
 * own immutable pre-cleanup root. Retire only prepared owner-local keys;
 * imported predicates in PRIVATE_ENTRY observation trees remain intact. */
static SHELL_NONNULL(1, 3, 4) bool dep_fd_retire_owner_facts(
    const dep_parse_context_t *context, uint32_t event,
    dep_route_state_t *state, dep_route_journal_t *journal) {
  if (event < SHELL_MAX_GROUPS)
    return true;
  uint32_t slot =
      context->snapshot
          ->prepared_source[context->range_node[event - SHELL_MAX_GROUPS]];
  const dep_snapshot_source_t *source =
      &context->workspace->snapshot_sources[slot];
  if (!source->read.active && !source->observation_first[0] &&
      !source->observation_first[1] && !source->observation_first[2] &&
      !source->observation_first[3])
    return true;
  dep_route_state_t result = {0};
  dep_route_iterator_t versions = dep_route_iterator(state);
  uint32_t root;
  bool ready = false;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_state_inherit(&one, state);
    for (uint32_t i = 0; i < source->read.count; i++) {
      const dep_read_word_t *word = &source->read.words[i];
      if (word->capture && word->parameter.value == SHELL_DEP_FD_NAMED &&
          !dep_route_state_store_access(&one, journal, dep_fd_numeric(i),
                                        DEP_FD_ACCESS_READ_ARGUMENT,
                                        (dep_route_set_t){.ready = true}))
        return false;
    }
    if (source->read.active &&
        !dep_route_state_store_access(
            &one, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
            DEP_FD_ACCESS_EFFECT_STATE, (dep_route_set_t){.ready = true}))
      return false;
    for (uint32_t phase = 0; phase <= DEP_SNAPSHOT_BODY_WORD; phase++)
      if (source->observation_first[phase] &&
          !dep_route_state_store_access(
              &one, journal, dep_fd_numeric(slot * DEP_SNAPSHOT_SETUP + phase),
              DEP_FD_ACCESS_SUBSTITUTION_STATUS,
              (dep_route_set_t){.ready = true}))
        return false;
    if (!ready)
      result = one;
    else if (!dep_fd_merge_versions(&result, &one, journal))
      return false;
    ready = true;
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

static SHELL_NONNULL(1, 2, 4, 5) bool dep_fd_finish(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    const dep_fd_flow_t *executed, dep_route_journal_t *journal);

static SHELL_NONNULL(1) int32_t
    dep_snapshot_event_group(const dep_parse_context_t *context,
                             uint32_t event) {
  if (event >= SHELL_MAX_GROUPS)
    return dep_range_group(&context->execution->pipeline,
                           event - SHELL_MAX_GROUPS);
  uint16_t parent = context->fast->groups[event].parent;
  return parent == UINT16_MAX ? -1 : (int32_t)parent;
}

/* A compound is an execution stage in its parent's list independently of its
 * retained body commands. Share this stage stream with snapshot
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

/* Build asynchronous execution units once from the source-ordered stage
 * stream. Each scope's list is consumed once; closing `&` marks its AND/OR
 * and pipeline members without visiting nested compound bodies. */
static SHELL_NONNULL(1) void dep_construction_control_initialize(
    const dep_parse_context_t *context);

static SHELL_NONNULL(1, 2) void dep_async_plan_build(
    const dep_parse_context_t *context, dep_async_plan_t *plan) {
  dep_construction_control_initialize(context);
  const dep_ordered_owner_t *events = context->snapshot->owners;
  const uint32_t *previous = context->snapshot->previous_same_scope;
  uint32_t count = context->snapshot->owner_count;
  uint32_t first[SHELL_MAX_GROUPS + 1], prior[DEP_EXECUTION_EVENT_CAPACITY];
  bool and_or[SHELL_MAX_GROUPS + 1] = {0};
  for (uint32_t scope = 0; scope <= SHELL_MAX_GROUPS; scope++)
    first[scope] = UINT32_MAX;
  for (uint32_t i = 0; i < count; i++) {
    uint32_t event = events[i].owner;
    uint32_t scope = dep_snapshot_event_group(context, event) + 1;
    const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
    uint16_t connector =
        event < SHELL_MAX_GROUPS
            ? pipeline->group_connector[event]
            : pipeline->range_connector[event - SHELL_MAX_GROUPS];
    uint16_t successor =
        event < SHELL_MAX_GROUPS
            ? pipeline->group_successor[event]
            : pipeline->range_successor[event - SHELL_MAX_GROUPS];
    bool continuation = connector == SHELL_TYPE_AND ||
                        connector == SHELL_TYPE_OR ||
                        connector == SHELL_TYPE_PIPELINE;
    if (!continuation || first[scope] == UINT32_MAX) {
      first[scope] = event;
      and_or[scope] = false;
      prior[event] = UINT32_MAX;
    } else {
      prior[event] = events[previous[i]].owner;
      and_or[scope] |=
          connector == SHELL_TYPE_AND || connector == SHELL_TYPE_OR;
    }
    if (successor != SHELL_TYPE_BACKGROUND)
      continue;
    uint32_t start = first[scope];
    bool timed = start < SHELL_MAX_GROUPS
                     ? context->fast->groups[start].pipeline_time_direct
                     : context->fast->cmds[start - SHELL_MAX_GROUPS]
                           .pipeline_time_direct;
    plan->last[start] = event;
    plan->wrapper[start] = and_or[scope] || timed;
    plan->early[start] = plan->wrapper[start] || start < SHELL_MAX_GROUPS;
    for (uint32_t member = event; member != UINT32_MAX;
         member = prior[member]) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
      plan->unit[member] = start + 1;
    }
  }
}

static SHELL_NONNULL(1) void dep_control_stream_initialize(
    dep_control_stream_t *stream) {
  memset(stream, 0, sizeof(*stream));
  for (uint32_t scope = 0; scope <= SHELL_MAX_GROUPS; scope++)
    stream->last[scope] = UINT32_MAX;
}

/* A consumer outside a completed asynchronous unit observes launch success,
 * not the child's outcome. Keep the raw event status for child-local AND/OR
 * and pipeline composition; project only the unit's final completed event.
 * This also applies when that event is the last member of a closing compound.
 * A stopped parent entry cannot launch a child and remains stopped. */
static SHELL_NONNULL(1, 2) uint8_t
    dep_control_completed_status(const dep_parse_context_t *context,
                                 const dep_control_stream_t *stream,
                                 uint32_t event, uint32_t index) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
  uint32_t unit = context->async->unit[event];
  if (unit && context->async->last[unit - 1] == event) {
    uint8_t entry = stream->async_entry_status[unit - 1];
    return (entry & DEP_STATUS_STOP) |
           (entry & DEP_STATUS_EITHER ? DEP_STATUS_MAY_SUCCEED : 0);
  }
  return stream->status[index];
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
      uint8_t body = last == UINT32_MAX
                         ? DEP_STATUS_EITHER
                         : dep_control_completed_status(
                               context, stream, events[last].owner, last);
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
      incoming = dep_control_completed_status(
          context, stream, events[previous[index]].owner, previous[index]);
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
    /* Input-unit recovery applies to the returning parent status, after any
     * asynchronous unit restores its entry, even when no child was launched. */
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
    if (context->async->unit[event] == event + 1)
      stream->async_entry_status[event] = incoming;
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
  const dep_ordered_owner_t *owners = context->snapshot->owners;
  const uint32_t *previous = context->snapshot->previous_same_scope;
  uint32_t count = context->snapshot->owner_count;
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
  uint32_t start = event < SHELL_MAX_GROUPS
                       ? context->fast->groups[event].start
                       : context->fast->cmds[event - SHELL_MAX_GROUPS].start;
  if (dep_coverage_effects_blocked(context, start))
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
  /* Save the returning parent after input-unit recovery, before child-local
   * changes. Restoring a pre-recovery abort would stop the parent again. */
  if (context->async->unit[event] == event + 1)
    frame->async_cwd_entry[event] = *flow;
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
  uint32_t unit = context->async->unit[event];
  if (unit && context->async->last[unit - 1] == event) {
    result = frame->async_cwd_entry[unit - 1];
    if (result.mask & DEP_STATUS_EITHER) {
      dep_cwd_state_t incoming =
          dep_cwd_selected(&result, DEP_STATUS_EITHER, result.state[0]);
      result.mask &= (uint8_t)~DEP_STATUS_EITHER;
      dep_cwd_add(&result, 0, incoming);
    }
    frame->cwd_scope[dep_snapshot_event_group(context, event) + 1] = result;
  }
}

/* event is a begun simple-command source event, not a group event. */
static SHELL_NONNULL(1) void dep_cwd_finish_command(
    const dep_parse_context_t *context, uint32_t event,
    dep_cwd_state_t candidate, bool changes_directory, bool setup_may_fail,
    bool may_change_on_failure) {
  dep_cwd_flow_t executed = {.mask = context->event_static_status[event]};
  dep_cwd_state_t stopped =
      dep_cwd_selected(&context->snapshot->cwd_entry[event],
                       dep_cwd_run_mask(context, event), candidate);
  uint32_t owner = context->range_node[event - SHELL_MAX_GROUPS];
  if (context->owner_setup_stop[owner] != UINT32_MAX ||
      context->execution->pipeline
          .local_process[context->execution->owner[event - SHELL_MAX_GROUPS]])
    candidate = stopped;
  const shell_range_t *cmd = &context->fast->cmds[event - SHELL_MAX_GROUPS];
  bool negated = cmd->pipeline_negation_count & 1u;
  bool setup_negated = dep_setup_failure_negated(
      cmd->kind, cmd->pipeline_negation_count,
      context->execution->pipeline
          .local_process[context->execution->owner[event - SHELL_MAX_GROUPS]]);
  for (unsigned i = 0; i < 5; i++)
    executed.state[i] = i < 2 && (!changes_directory || i == (unsigned)negated)
                            ? candidate
                            : stopped;
  /* Shell return status is not the chdir phase's status: reporting a selected
   * directory, or physical resolution, can fail after changing directory. */
  if (changes_directory && may_change_on_failure) {
    unsigned failure = negated ? 0 : 1;
    executed.state[failure] = dep_cwd_join(stopped, candidate);
  }
  if (!changes_directory && setup_may_fail) {
    unsigned failure = setup_negated ? 0 : 1;
    executed.state[failure] = dep_cwd_join(executed.state[failure], stopped);
  }
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
  memset(frame->event_entry, 0, sizeof(frame->event_entry));
  memset(frame->event_executed, 0, sizeof(frame->event_executed));
  memset(frame->event_report, 0, sizeof(frame->event_report));
  memset(frame->event_scope, 0, sizeof(frame->event_scope));
  memset(frame->group_scope, 0, sizeof(frame->group_scope));
  memset(frame->group_failure, 0, sizeof(frame->group_failure));
  memset(frame->group_parent, 0, sizeof(frame->group_parent));

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
  /* A borrowed entry state's facts are all in its versions; a missing fact
   * is the executor contract. */
  if (!dep_import_route_alternatives(&alternatives, &workspace->journal,
                                     inherited) ||
      !dep_snapshot_table_publish(root, &alternatives))
    return false;
  frame->fd_stream.scope[0].mask = DEP_STATUS_EITHER;
  frame->fd_stream.scope[0].state[0] = frame->fd_stream.scope[0].state[1] =
      alternatives;
  frame->diagnostics.count = frame->diagnostics.root = 0;
  memset(frame->capture, 0, sizeof(frame->capture));
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
/* Consume the new word-expansion suffix once. Redirect operands use the same
 * process operations in the ordered setup index instead. */
static SHELL_NONNULL(1, 2, 3) bool dep_snapshot_process_words(
    const dep_parse_context_t *context, dep_snapshot_source_t *source,
    dep_snapshot_table_t *entry, uint32_t owner, bool body) {
  uint32_t cursor =
      body ? source->body_process_cursor : source->process_word_cursor;
  uint32_t route = cursor ? context->process_routes->entries[cursor - 1].next
                          : context->process_routes->first[owner];
  dep_route_state_t state = dep_snapshot_alternatives(entry), previous = state;
  dep_domain_collection_t collection = {.workspace = context->workspace,
                                        .frame = context->snapshot};
  bool changed = false;
  for (; route; route = context->process_routes->entries[route - 1].next) {
    const dep_process_route_t *item =
        &context->process_routes->entries[route - 1];
    if (body)
      source->body_process_cursor = route;
    else
      source->process_word_cursor = route;
    if (!item->temporary || !(body ? item->body_word : item->command_word) ||
        !context->process_routes->track[owner])
      continue;
    dep_fd_op_t op = {.pos = item->position,
                      .kind = DEP_FD_OP_PROCESS,
                      .fd_name = item->source,
                      .edge_index = item->edge,
                      .access = item->access,
                      .guard = item->guard,
                      .process_observed_low =
                          context->process_routes->observed_low[owner]};
    dep_route_domains_collect(&context->workspace->journal, &collection, &state,
                              &previous);
    if (!dep_process_open(&state, &context->workspace->journal, &op))
      return false;
    changed = true;
  }
  return !changed || dep_snapshot_table_publish(entry, &state);
}

static SHELL_NONNULL(1, 2) bool dep_record_diagnostic(
    const dep_route_state_t *state, dep_route_journal_t *journal);

/* The diagnostics owner's expansions marked (dep_record_phase_diagnostic),
 * now that all of them are known: the assignment-phase one at its entry
 * after read capture, each redirect-operand one at its checkpoint up to the
 * setup stop, and an unknown arithmetic command's on its executed state. */
static SHELL_NONNULL(1, 2, 3, 5) bool dep_snapshot_owner_diagnostics(
    const shell_dep_graph_t *graph, const dep_parse_context_t *context,
    const dep_snapshot_source_t *source, uint32_t owner,
    const dep_route_state_t *executed) {
  dep_route_workspace_t *workspace = context->workspace;
  dep_route_journal_t *journal = &workspace->journal;
  if (source->entry_diagnostic &&
      !dep_record_diagnostic(&context->snapshot->capture[owner], journal))
    return false;
  for (uint32_t i = 0;
       source->redirect_diagnostic_count && i < source->checkpoint_count; i++) {
    if (!source->checkpoint_diagnostic[i] ||
        source->checkpoint_position[i] > context->owner_setup_stop[owner])
      continue;
    dep_route_state_t at = dep_snapshot_alternatives(
        &workspace->snapshot_tables[source->checkpoint_table[i]]);
    if (!dep_record_diagnostic(&at, journal))
      return false;
  }
  return graph->nodes[owner].type != SHELL_NODE_CMD ||
         graph->nodes[owner].cmd.kind != SHELL_COMMAND_ARITHMETIC ||
         graph->nodes[owner].cmd.arithmetic_truth != SHELL_ARITHMETIC_UNKNOWN ||
         context->owner_setup_stop[owner] != UINT32_MAX ||
         dep_record_diagnostic(executed, journal);
}

/* Completes the frame's current owner: its setup, its flow outcomes and, for
 * an owner whose here-document is deferred, a fresh table for its successor
 * (*entry). */
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_snapshot_complete_owner(shell_dep_graph_t *graph,
                                const dep_parse_context_t *context,
                                dep_snapshot_table_t **entry_slot) {
  dep_snapshot_table_t *entry = *entry_slot;
  dep_route_workspace_t *workspace = context->workspace;
  dep_route_journal_t *changes = &workspace->journal;
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_snapshot_table_t *tables = workspace->snapshot_tables;
  uint32_t owner = frame->current_owner;
  uint32_t event = dep_owner_event(context, owner);
  changes->diagnostic_owner = owner;
  if (frame->execution[owner] != DEP_EXECUTION_NEVER) {
    dep_snapshot_source_t *prepared;
    uint32_t op_count = 0, completed;
    if (!dep_snapshot_fd_operations(graph, context, owner, &prepared))
      return SHELL_DEP_EPARSE;
    if (!dep_snapshot_process_words(context, prepared, entry, owner, false))
      return SHELL_DEP_ETRUNC;
    shell_dep_error_t error = dep_snapshot_operand_table(
        graph, workspace, prepared, (uint32_t)(entry - tables), UINT32_MAX,
        &completed, context, owner);
    if (error != SHELL_DEP_OK)
      return error;
    dep_snapshot_operation_range(prepared, prepared->op_root, 0, UINT32_MAX,
                                 workspace->ops, NULL, &op_count);
    dep_route_state_t alternatives =
        dep_snapshot_alternatives(&tables[completed]);
    /* Setup starts from the state before the first redirection: the
     * owner's entry with its assignment-phase effects. */
    uint32_t setup_table;
    error = dep_snapshot_operand_table(graph, workspace, prepared,
                                       (uint32_t)(entry - tables), 0,
                                       &setup_table, context, owner);
    if (error != SHELL_DEP_OK)
      return error;
    dep_route_state_t setup_entry =
        dep_snapshot_alternatives(&tables[setup_table]);
    bool descriptor_exec =
        event >= SHELL_MAX_GROUPS && prepared->exec.persistent_redirects;
    if (event < SHELL_MAX_GROUPS) {
      if (!dep_redirect_frame_record(&frame->redirect_frames[event],
                                     workspace->ops, op_count) ||
          !dep_redirect_frame_aliases(&frame->redirect_frames[event], changes,
                                      workspace->ops, op_count))
        return SHELL_DEP_ETRUNC;
      frame->active_groups[frame->active_group_count++] = event;
    }
    frame->event_executed[event] = alternatives;
    /* A report finish leaves untouched is the entry with this owner's
     * reached setup published onto it. */
    frame->event_report[event] = frame->event_entry[event];
    uint32_t reached = 0;
    while (reached < op_count &&
           workspace->ops[reached].pos < context->owner_setup_stop[owner])
      reached++;
    if (!dep_route_state_publish(&frame->event_report[event], changes,
                                 &alternatives, workspace->ops, reached,
                                 descriptor_exec, NULL))
      return SHELL_DEP_ETRUNC;
    error = dep_fd_finish_owner(
        context, &frame->fd_stream, event, changes, &alternatives,
        workspace->ops, op_count, descriptor_exec,
        dep_owner_persists_named_binding(graph, context, owner),
        &prepared->mutations, &frame->event_report[event], &setup_entry);
    if (error != SHELL_DEP_OK ||
        !dep_snapshot_owner_diagnostics(graph, context, prepared, owner,
                                        &alternatives))
      return error != SHELL_DEP_OK ? error : SHELL_DEP_ETRUNC;
    frame->event_scope[event] =
        frame->fd_stream
            .scope[dep_owner_enclosing_group(
                       graph, context->fast, &context->execution->pipeline,
                       context->node_range, context->node_group, owner) +
                   1];
  } else {
    dep_fd_flow_t none = {0};
    if (!dep_fd_finish(context, &frame->fd_stream, event, &none, changes))
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
    *entry_slot = &tables[frame->current_table];
  }
  return SHELL_DEP_OK;
}

/* Completes the frame's current owner, if any, and begins the next owner of
 * the ordered event stream in *entry. */
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_snapshot_advance(shell_dep_graph_t *graph,
                         const dep_parse_context_t *context,
                         dep_snapshot_table_t **entry) {
  dep_route_workspace_t *workspace = context->workspace;
  dep_route_journal_t *changes = &workspace->journal;
  dep_snapshot_frame_t *frame = context->snapshot;
  if (frame->current_owner != UINT32_MAX) {
    shell_dep_error_t error =
        dep_snapshot_complete_owner(graph, context, entry);
    if (error != SHELL_DEP_OK)
      return error;
  }

  /* The requested retained owner is in the remaining ordered event stream.
   * Every preceding stage has an endpoint now that cd is never hidden. */
  uint32_t owner;
  {
    uint32_t index = frame->cursor++;
    uint32_t event = frame->owners[index].owner;
    SHELL_PIPELINE_WORK();
    if (!dep_snapshot_complete_groups(context, frame->owners[index].start))
      return SHELL_DEP_ETRUNC;
    owner = dep_snapshot_event_owner(context, event);
    changes->diagnostic_owner = owner;
    dep_route_state_t selected;
    if (!dep_fd_begin(context, &frame->fd_stream, event, changes, &selected))
      return SHELL_DEP_ETRUNC;
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
    /* No effect past the coverage barrier executes. */
    if (dep_coverage_effects_blocked(context, frame->owners[index].start))
      frame->execution[owner] = DEP_EXECUTION_NEVER;
    dep_snapshot_source_t *prepared;
    if (frame->execution[owner] != DEP_EXECUTION_NEVER &&
        !dep_snapshot_fd_operations(graph, context, owner, &prepared))
      return SHELL_DEP_EPARSE;
    if (frame->execution[owner] != DEP_EXECUTION_NEVER) {
      if (!dep_source_variables_supported(prepared, &selected, changes,
                                          context->fast))
        return SHELL_DEP_EPARSE;
      shell_dep_error_t capture =
          dep_read_capture(&prepared->read, &selected, changes);
      if (capture != SHELL_DEP_OK)
        return capture;
      frame->capture[owner] = selected;
      if (!dep_owner_stdin(context, prepared, owner, &selected, changes, true))
        return SHELL_DEP_ETRUNC;
      frame->event_entry[event] = selected;
      if (event < SHELL_MAX_GROUPS && !context->group_exec[event].isolated)
        frame->fd_stream.selected[event] = selected;
      /* The owner's pipe ends replace its standard streams after the
       * assignment phase: expansions see the entry without them. */
      bool pipe_both = false;
      if (!dep_snapshot_install_pipeline(&selected, changes, context, owner,
                                         &pipe_both))
        return SHELL_DEP_ETRUNC;
    }
    if (!dep_snapshot_table_publish(*entry, &selected))
      return SHELL_DEP_ETRUNC;
  }
  frame->current_owner = owner;
  return SHELL_DEP_OK;
}

static SHELL_NONNULL(1, 3, 7) shell_dep_error_t
    dep_snapshot_phase_table(shell_dep_graph_t *graph,
                             const dep_subgraph_streams_t *streams,
                             const dep_parse_context_t *context,
                             uint32_t current_owner, uint32_t position,
                             dep_snapshot_phase_t phase, uint32_t *table) {
  const dep_fd_imports_t *inherited = streams ? &streams->fd_imports : NULL;
  dep_route_workspace_t *workspace = context->workspace;
  dep_snapshot_frame_t *frame = context->snapshot;
  if (!frame->initialized && !dep_snapshot_frame_initialize(context, inherited))
    return SHELL_DEP_ETRUNC;
  workspace->journal.diagnostics = &frame->diagnostics;
  dep_snapshot_table_t *tables = workspace->snapshot_tables;
  bool historical = frame->cached_entry[current_owner] != UINT32_MAX;
  dep_snapshot_table_t *entry =
      &tables[historical ? frame->cached_entry[current_owner]
                         : frame->current_table];

  while (!historical && frame->current_owner != current_owner) {
    shell_dep_error_t error = dep_snapshot_advance(graph, context, &entry);
    if (error != SHELL_DEP_OK)
      return error;
  }

  workspace->journal.diagnostic_owner = current_owner;
  dep_snapshot_source_t *prepared;
  if (!dep_snapshot_fd_operations(graph, context, current_owner, &prepared))
    return SHELL_DEP_EPARSE;
  if (!dep_snapshot_process_words(context, prepared, entry, current_owner,
                                  false))
    return SHELL_DEP_ETRUNC;
  if (phase == DEP_SNAPSHOT_REDIRECT_OPERAND || phase == DEP_SNAPSHOT_SETUP ||
      phase == DEP_SNAPSHOT_BODY_WORD) {
    shell_dep_error_t error = dep_snapshot_operand_table(
        graph, workspace, prepared, (uint32_t)(entry - tables),
        phase == DEP_SNAPSHOT_BODY_WORD ? UINT32_MAX : position, table, context,
        current_owner);
    if (error != SHELL_DEP_OK || phase != DEP_SNAPSHOT_BODY_WORD)
      return error;
    dep_snapshot_table_t *body = &tables[*table];
    if (!dep_snapshot_process_words(context, prepared, body, current_owner,
                                    true))
      return SHELL_DEP_ETRUNC;
    /* dep_complete_substitution applies each returned observation once to
     * this cached body table. Imports consume that established state; replay
     * here would apply the newly appended observation a second time. */
    return SHELL_DEP_OK;
  }
  *table = (uint32_t)(entry - tables);
  return SHELL_DEP_OK;
}

/* Runs construction to the end of the owner stream: every owner and every
 * group completes, not only those an expansion has queried. The final walk
 * then has construction's interpretation of every owner. */
static SHELL_NONNULL(1, 3) shell_dep_error_t
    dep_snapshot_finish(shell_dep_graph_t *graph,
                        const dep_subgraph_streams_t *streams,
                        const dep_parse_context_t *context) {
  dep_snapshot_frame_t *frame = context->snapshot;
  if (!frame->initialized &&
      !dep_snapshot_frame_initialize(context,
                                     streams ? &streams->fd_imports : NULL))
    return SHELL_DEP_ETRUNC;
  context->workspace->journal.diagnostics = &frame->diagnostics;
  dep_snapshot_table_t *entry =
      &context->workspace->snapshot_tables[frame->current_table];
  while (frame->cursor < frame->owner_count) {
    shell_dep_error_t error = dep_snapshot_advance(graph, context, &entry);
    if (error != SHELL_DEP_OK)
      return error;
  }
  if (frame->current_owner != UINT32_MAX) {
    shell_dep_error_t error =
        dep_snapshot_complete_owner(graph, context, &entry);
    if (error != SHELL_DEP_OK)
      return error;
    frame->current_owner = UINT32_MAX;
  }
  return dep_snapshot_complete_groups(context, UINT32_MAX) ? SHELL_DEP_OK
                                                           : SHELL_DEP_ETRUNC;
}

/* The caller has established phase reachability and a possible shell
 * diagnostic. Recording its route is independent of control outcomes: a
 * file-substitution read can fail without aborting its enclosing shell.
 * Final resolution consumes markers before cleanup and later redirects. */
static SHELL_NONNULL(1, 3) shell_dep_error_t
    dep_record_phase_diagnostic(shell_dep_graph_t *graph,
                                const dep_subgraph_streams_t *streams,
                                const dep_parse_context_t *context,
                                uint32_t owner, uint32_t position,
                                dep_snapshot_phase_t phase) {
  dep_snapshot_source_t *source =
      &context->workspace
           ->snapshot_sources[context->snapshot->prepared_source[owner]];
  if (phase == DEP_SNAPSHOT_REDIRECT_OPERAND ||
      phase == DEP_SNAPSHOT_BODY_WORD) {
    uint32_t table;
    shell_dep_error_t error = dep_snapshot_phase_table(
        graph, streams, context, owner, position, phase, &table);
    if (error != SHELL_DEP_OK)
      return error;
    /* A deferred heredoc can reuse a checkpoint at its document boundary.
     * Retain this exact expansion position too, without replaying its prefix.
     */
    if (!dep_snapshot_checkpoint_record(source, position, table))
      return SHELL_DEP_ETRUNC;
    uint32_t checkpoint =
        dep_snapshot_checkpoint_find(source, position, true) - 1;
    if (!source->checkpoint_diagnostic[checkpoint]) {
      source->checkpoint_diagnostic[checkpoint] = true;
      source->redirect_diagnostic_count++;
    }
  } else
    source->entry_diagnostic = true;
  return SHELL_DEP_OK;
}

/* Scoped syntax failures carry both a diagnostic and their shell outcome.
 * An expansion callback's API failure instead fails the analysis boundary. */
static SHELL_NONNULL(1, 3) shell_dep_error_t
    dep_record_expansion_result(shell_dep_graph_t *graph,
                                const dep_subgraph_streams_t *streams,
                                const dep_parse_context_t *context,
                                uint32_t owner, uint32_t position,
                                dep_snapshot_phase_t phase, uint8_t errors) {
  if (!errors)
    return SHELL_DEP_OK;
  shell_dep_error_t error = dep_record_phase_diagnostic(graph, streams, context,
                                                        owner, position, phase);
  if (error == SHELL_DEP_OK)
    dep_record_expansion_error(context, owner, phase, errors);
  return error;
}

/* Recursive expansions request an import from one of the expansion
 * phases, not SETUP. Reuse the established checkpoint; exporting descriptors
 * is separate from resolving the operand's reachability. */
enum { DEP_DOMAIN_UNION = SHELL_FD_PARTS };
static SHELL_NONNULL(1, 2, 3) bool dep_fd_domain_stored(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    shell_fd_partition_t *partition);
static SHELL_NONNULL(1, 2, 3) bool dep_fd_domain_store(
    dep_route_state_t *state, dep_route_journal_t *journal,
    shell_fd_partition_t *partition);

static SHELL_NONNULL(1, 3, 7, 9) shell_dep_error_t dep_snapshot_fd_imports(
    shell_dep_graph_t *graph, const dep_subgraph_streams_t *streams,
    const dep_parse_context_t *context, uint32_t current_owner,
    uint32_t position, dep_snapshot_phase_t phase, dep_fd_imports_t *imports,
    const dep_process_guard_t *guard, bool *active) {
  *imports = (dep_fd_imports_t){0};
  uint32_t table;
  shell_dep_error_t error = dep_snapshot_phase_table(
      graph, streams, context, current_owner, position, phase, &table);
  if (error != SHELL_DEP_OK)
    return error;
  dep_route_workspace_t *workspace = context->workspace;
  dep_route_journal_t *changes = &workspace->journal;
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_snapshot_table_t *entry = &workspace->snapshot_tables[table];
  dep_route_state_t alternatives = dep_snapshot_alternatives(entry);
  if (guard) {
    dep_route_state_t executing;
    bool possible;
    if (!dep_process_guard_select(&alternatives, changes, guard, &executing,
                                  &possible))
      return SHELL_DEP_ETRUNC;
    if (!possible) {
      *active = false;
      return SHELL_DEP_OK;
    }
    alternatives = executing;
  }
  imports->ifs = dep_ifs_get(&alternatives, changes);
  dep_snapshot_source_t *assignment_source = NULL;
  bool null_path = false, command_path = true;
  const dep_assignment_ifs_t *assignment_ifs = NULL;
  if (phase == DEP_SNAPSHOT_ASSIGNMENT_VALUE) {
    dep_snapshot_source_t *source =
        &workspace->snapshot_sources[frame->prepared_source[current_owner]];
    assignment_source = source;
    null_path = (source->assignment_dispatch & DEP_ARGV_EMPTY) != 0;
    command_path = (source->assignment_dispatch & DEP_ARGV_PRESENT) != 0;
    if (null_path) {
      while (source->assignment_ifs_cursor < source->assignment_ifs_count &&
             source->assignment_ifs[source->assignment_ifs_cursor].after <=
                 context->cmd + position) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ASSIGNMENT_IFS);
        source->assignment_ifs_cursor++;
      }
      if (source->assignment_ifs_cursor) {
        assignment_ifs =
            &source->assignment_ifs[source->assignment_ifs_cursor - 1];
        uint32_t assigned =
            assignment_ifs->value | (assignment_ifs->append ? imports->ifs : 0);
        imports->ifs =
            command_path ? dep_ifs_join(imports->ifs, assigned) : assigned;
      }
    }
  }
  if (assignment_source &&
      !dep_prefixes_resolve(&alternatives,
                            &assignment_source->prefix_assignments, changes))
    return SHELL_DEP_ETRUNC;
  uint32_t base_paths =
      alternatives.correlated ? dep_route_state_count(&alternatives) : 1;
  uint32_t variants = null_path && command_path ? 2 : 1;
  uint32_t paths = base_paths * variants;
  if (paths > SHELL_DEP_MAX_NODES)
    return SHELL_DEP_ETRUNC;
  imports->path_count = paths;
  imports->scalar_journal = changes;
  dep_route_iterator_t iterator = dep_route_iterator(&alternatives);
  uint32_t root = 0;
  for (uint32_t path = 0; path < paths; path++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_EXPORTS);
    if (path % variants == 0)
      root = dep_route_take(&iterator, changes);
    dep_route_state_t selected =
        base_paths == 1 ? alternatives : dep_route_state_single(root);
    bool assignment_only = null_path && (variants == 1 || path % variants == 0);
    if (assignment_source &&
        !dep_prior_assignments(&selected, changes, assignment_source,
                               context->cmd + position, assignment_only))
      return SHELL_DEP_ETRUNC;
    imports->path_state[path] = selected;
    uint32_t ifs = dep_ifs_get(&selected, changes);
    imports->path_ifs[path] =
        assignment_only && assignment_ifs
            ? assignment_ifs->value | (assignment_ifs->append ? ifs : 0)
            : ifs;
    imports->path_process_domain_present[path] = dep_fd_domain_stored(
        &selected, changes, &imports->path_process_domain[path]);
  }
  return SHELL_DEP_OK;
}
#include "shell_depgraph_test_impl.h"

static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_complete_owner_setup(shell_dep_graph_t *graph,
                             const dep_subgraph_streams_t *streams,
                             const dep_parse_context_t *context, uint32_t owner,
                             bool *may_fail) {
  if (may_fail)
    *may_fail = false;
  if (graph->status & SHELL_DEP_STATUS_TRUNCATED)
    return SHELL_DEP_OK;
  if (!dep_owner_phase_active(context, owner, DEP_SNAPSHOT_SETUP, UINT32_MAX)) {
    if (may_fail)
      *may_fail =
          context->owner_setup_stop[owner] != UINT32_MAX &&
          !(context->event_static_status[dep_owner_event(context, owner)] &
            DEP_STATUS_STOP);
    return SHELL_DEP_OK;
  }
  dep_snapshot_source_t *prepared;
  if (!dep_snapshot_fd_operations(graph, context, owner, &prepared))
    return SHELL_DEP_EPARSE;
  if (prepared->setup_needs_walk || prepared->read.active) {
    uint32_t table;
    shell_dep_error_t error = dep_snapshot_phase_table(
        graph, streams, context, owner, UINT32_MAX, DEP_SNAPSHOT_SETUP, &table);
    if (error != SHELL_DEP_OK)
      return error;
    if (prepared->read.active) {
      dep_snapshot_table_t *snapshot =
          &context->workspace->snapshot_tables[table];
      dep_route_state_t alternatives = dep_snapshot_alternatives(snapshot);
      uint8_t status = 0;
      dep_route_iterator_t iterator = dep_route_iterator(&alternatives);
      uint32_t root;
      while (dep_route_next(&iterator, &context->workspace->journal, &root)) {
        dep_route_state_t one = dep_route_state_single(root);
        dep_read_result_t read = dep_read_evaluate(
            &prepared->read, &one, &context->workspace->journal, NULL, NULL);
        if (read.unsupported)
          return SHELL_DEP_EPARSE;
        status |= read.status;
      }
      uint32_t event = dep_owner_event(context, owner);
      context->event_body_status[event] = status;
      if (context->fast->cmds[context->node_range[owner]]
              .pipeline_negation_count &
          1u)
        status = dep_status_negate(status);
      context->event_static_status[event] =
          status | (context->event_static_status[event] & DEP_STATUS_STOP);
    }
  }
  if (may_fail)
    *may_fail = prepared->setup_may_fail;
  return SHELL_DEP_OK;
}

/* Record a reached FILE operand's known failure, whether its spelling was
 * statically empty or the resolver produced an unusable pathname. A file
 * command substitution fails in its child, not the enclosing command setup.
 * Either is a certain shell-level error, which no dependency graph represents
 * (SHELL_DEP_EUNMODELED). word/document/owner are the installed operand and
 * its execution owner. */
static SHELL_NONNULL(1, 2, 3) void dep_record_file_failure(
    shell_dep_graph_t *graph, const dep_parse_context_t *context,
    const dep_token_t *word, uint32_t owner,
    shell_expand_word_purpose_t purpose, uint32_t document) {
  context->workspace->journal.unmodeled = true;
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
/* Whether a word has an unquoted brace expansion. Bash expands braces in a
 * redirection operand before any other expansion, and more than one
 * resulting word is an "ambiguous redirect"; a degenerate one-element
 * sequence such as {1..1} is counted as well. Expansions are skipped whole:
 * a brace inside them is not a brace expansion of this word. */
static SHELL_NONNULL(1) bool dep_word_brace_expands(const char *word,
                                                    size_t length) {
  char quote = 0;
  for (size_t position = 0; position < length;) {
    char byte = word[position];
    size_t after = 0, open = 0;
    if (quote != '\'' && byte == '`' &&
        shell_source_skip_complete_backtick(word, length, position, &after)) {
      position = after;
      continue;
    }
    if (quote != '\'' && byte == '$') {
      if ((shell_source_dollar_arithmetic_open(word, length, position, &open) &&
           shell_source_skip_arithmetic_expansion(word, length, position,
                                                  &after)) ||
          (shell_source_dollar_parentheses_open(word, length, position,
                                                &open) &&
           shell_source_find_balanced_parentheses(word, length, open,
                                                  &after)) ||
          shell_source_skip_variable_expansion(word, length, position,
                                               &after)) {
        position = after;
        continue;
      }
    }
    if (quote) {
      if (byte == quote)
        quote = 0;
      else if (quote == '"' && byte == '\\')
        position++;
      position++;
      continue;
    }
    if (byte == '\\') {
      position += 2;
      continue;
    }
    if (byte == '\'' || byte == '"') {
      quote = byte;
      position++;
      continue;
    }
    if (byte == '{') {
      shell_source_brace_fragment_t fragment =
          shell_source_scan_brace_fragment(word, length, position);
      if (fragment.expands)
        return true;
      position = fragment.after > position ? fragment.after : position + 1;
      continue;
    }
    position++;
  }
  return false;
}

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
  if (eligible && purpose == SHELL_EXPAND_WORD_REDIRECT_PATH &&
      dep_word_brace_expands(word->start, word->len)) {
    dep_record_file_failure(graph, context, word, owner, purpose, document);
    return SHELL_DEP_OK;
  }
  if (eligible && shell_expand_purpose_is_path(purpose) &&
      !(graph->nodes[document].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME)) {
    size_t decoded_length;
    if (shell_process_measure_word_value(word->start, word->len,
                                         &decoded_length) == SHELL_PROCESS_OK &&
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
  if (eligible && shell_expand_purpose_is_path(purpose) && value->dynamic &&
      !value->resolved)
    context->unresolved_paths[owner] = true;
  if (!eligible || !shell_expand_purpose_is_path(purpose) || !value->resolved)
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

/* Visit one version's named identities; no joined cache or historical setup
 * representative can decide liveness for a different branch. Only names whose
 * descriptor facts differ from the parse's entry version are visited: an
 * entry fact is inherited, so it cannot reach a document of this graph
 * (dep_route_foreign). This keeps a nested parse's work proportional to its
 * own changes rather than to the state it borrows. */
typedef struct {
  const shell_dep_graph_t *graph;
  const shell_dep_edge_t *original_edges;
  const dep_route_state_t *state;
  const dep_route_journal_t *journal;
  const bool *named_setup_documents;
  uint32_t original_edge_count;
  bool *live_named_documents;
} dep_live_named_walk_t;

static SHELL_NONNULL(1) void dep_mark_live_named(dep_live_named_walk_t *walk,
                                                 dep_fd_ref_t fd) {
  const dep_route_journal_t *journal = walk->journal;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
  dep_route_set_t bindings =
      dep_fd_fact(walk->state, journal, fd, DEP_FD_ACCESS_BINDING);
  bool live = false;
  for (uint32_t i = 0; i < bindings.count; i++)
    live |= bindings.routes[i].kind == DEP_ROUTE_INHERITED;
  if (!live)
    return;
  for (uint32_t facet = DEP_FD_ACCESS_READ; facet <= DEP_FD_ACCESS_WRITE;
       facet <<= 1) {
    dep_route_set_t routes =
        dep_fd_fact(walk->state, journal, fd, (dep_fd_access_t)facet);
    for (uint32_t i = 0; i < routes.count; i++) {
      dep_fd_route_t route = routes.routes[i];
      if (route.kind != DEP_ROUTE_DOC ||
          dep_route_foreign(route, journal->depth) ||
          dep_resource_index(route.value) >= walk->original_edge_count)
        continue;
      uint32_t document = dep_edge_document_index(
          walk->graph, &walk->original_edges[dep_resource_index(route.value)]);
      if (document != UINT32_MAX && walk->named_setup_documents[document])
        walk->live_named_documents[document] = true;
    }
  }
}

/* current and entry are the snapshots of (fd, access) in the final and entry
 * roots; the named-binding holder recurses into the submaps' difference. */
static bool dep_mark_live_named_change(void *context, dep_fd_ref_t fd,
                                       dep_fd_access_t access, uint32_t current,
                                       uint32_t entry) {
  dep_live_named_walk_t *walk = context;
  const dep_route_journal_t *journal = walk->journal;
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS)
    return dep_route_map_diff(
        journal,
        current ? journal->arena->snapshots[current - 1].routes[0].value : 0,
        entry ? journal->arena->snapshots[entry - 1].routes[0].value : 0,
        dep_mark_live_named_change, walk);
  if (current && fd.value == SHELL_DEP_FD_NAMED &&
      (access == DEP_FD_ACCESS_BINDING || access == DEP_FD_ACCESS_READ ||
       access == DEP_FD_ACCESS_WRITE))
    dep_mark_live_named(walk, fd);
  return true;
}

/* A named FD_OPEN remains meaningful only if the final persistent descriptor
 * table still reaches its original document. Historical setup edges alone are
 * not enough: `exec {fd}>out; exec {fd}>&-` has opened `out`, but has retired
 * that binding before any ordinary byte flow can use it. */
static SHELL_NONNULL(1, 2, 4, 5, 6, 7) void dep_mark_transient_documents(
    shell_dep_graph_t *graph, const shell_dep_edge_t *original_edges,
    uint32_t original_edge_count, const dep_fd_flow_t *final,
    const dep_route_journal_t *journal, bool *named_setup_documents,
    bool *live_named_documents, uint32_t entry_root) {
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

  /* Every version of every outcome: a binding can be live in one version
   * only. */
  for (unsigned outcome = 0; outcome < 5; outcome++) {
    if (!(final->mask & (1u << outcome)))
      continue;
    dep_route_iterator_t versions = dep_route_iterator(&final->state[outcome]);
    uint32_t root;
    while (dep_route_next(&versions, journal, &root)) {
      dep_route_state_t version = dep_route_state_single(root);
      dep_live_named_walk_t walk = {graph,
                                    original_edges,
                                    &version,
                                    journal,
                                    named_setup_documents,
                                    original_edge_count,
                                    live_named_documents};
      (void)dep_route_map_diff(journal, root, entry_root,
                               dep_mark_live_named_change, &walk);
    }
  }

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
    for (uint32_t use = 0; use < streams->external_use_count; use++)
      streams->external_uses[use].owner =
          remap[streams->external_uses[use].owner];
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
  /* Owner IDs changed, so rebuild the bounded external-use index once. */
  if (streams) {
    streams->external_root = 0;
    for (uint32_t use = 0; use < streams->external_use_count; use++) {
      uint32_t match = 0;
      streams->external_root = shell_avl_insert(
          streams->external_index, streams->external_root, use + 1,
          DEP_EXTERNAL_USE_CAPACITY, dep_external_stream_compare,
          streams->external_uses, &streams->external_uses[use], &match);
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

#include "shell_depgraph_factmap_impl.h"

#include "shell_depgraph_fdflow_impl.h"

/* Project the same refined target roles used for input selection into scalar
 * mutation effects. The syntactic recognizer's union can include an identifier
 * which this execution consumes as option data instead. Words and variable
 * classes are already prepared; no tokenization or decoded argv is needed. */
static SHELL_NONNULL(1, 2, 3, 4, 5, 6) void dep_read_mutations(
    const dep_read_plan_t *plan, const dep_read_result_t *read,
    const dep_prefix_assignment_set_t *prefixes, const dep_route_state_t *state,
    const dep_route_journal_t *journal, dep_named_mutations_t *mutations) {
  *mutations = (dep_named_mutations_t){.restored_prefixes = prefixes,
                                       .operation = plan->operation};
  for (uint32_t i = 0; i < plan->count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_READ_INPUT);
    if (!(read->targets & (UINT64_C(1) << i)))
      continue;
    const dep_read_word_t *word = &plan->words[i];
    bool empty, positive;
    (void)dep_read_argument(word, i, state, journal, &empty, &positive);
    shell_builtin_variable_t variable =
        dep_read_target(word, state, journal, empty, positive);
    if (variable == SHELL_BUILTIN_VARIABLE_DYNAMIC) {
      mutations->effects[mutations->count++] = (dep_named_effect_t){
          .token = word->effect.token, .kind = DEP_NAMED_EFFECT_OPAQUE_WRITE};
      if (!plan->ifs_restored)
        dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
      continue;
    }
    bool projected = empty && word->empty_known;
    dep_named_effect_t effect = projected ? word->empty_effect : word->effect;
    if (effect.token.len) {
      mutations->effects[mutations->count++] = effect;
      if (!(projected ? word->empty_restored : word->restored) &&
          (projected ? word->empty_ifs
                     : dep_effect_is_ifs(effect.token.start, effect.token.len,
                                         effect.kind)))
        dep_ifs_note(mutations, DEP_IFS_DIGITS, false);
    }
  }
  if (read->default_target)
    mutations->effects[mutations->count++] = plan->default_effect;
}

/* report_state is optional. It receives the timing shell's returning outcomes,
 * including move-source effects but excluding skipped predecessors and child
 * publication. A directly timed exec retains its local descriptor setup.
 * read_result is NULL for ordinary owners, or a prepared read outcome.
 * parent_pins optionally retains sibling outcome versions during publication.
 * A supplied report_state is initialized storage: collection tracks its
 * evolving version as well as the sibling reports retained by parent_pins.
 */
static SHELL_NONNULL(1, 2, 4, 5, 10, 12, 17) bool dep_fd_finish_owner_scope(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_route_state_t *executed_state,
    const dep_fd_op_t *ops, uint32_t op_count, bool descriptor_exec,
    bool named_binding, const dep_named_mutations_t *mutations,
    dep_route_state_t *report_state, const dep_route_state_t *setup_entry,
    uint8_t mode, bool setup_survived, const dep_read_result_t *read_result,
    const dep_domain_collection_t *parent_pins, dep_fd_flow_t *finished) {
  dep_route_state_t selected = stream->selected[event];
  dep_domain_collection_t collection = {
      .workspace = context->workspace,
      .frame =
          journal == &context->workspace->journal ? context->snapshot : NULL,
      .roots = {&selected, executed_state, setup_entry, report_state, NULL}};
  collection.parent = parent_pins;
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
    if (!dep_fd_bindings(&local, journal, ops, op_count, mutations))
      return false;
    body->state[0] = body->state[1] = local;
    dep_fd_flow_t *failure = &stream->setup_failure[event];
    dep_route_state_t persistent = selected;
    if (!dep_route_state_publish(&persistent, journal, &local, ops, op_count,
                                 false, &collection) ||
        !dep_fd_bindings(&persistent, journal, ops, op_count, mutations) ||
        !dep_fd_setup_failures(&selected, journal, &persistent, ops,
                               all_op_count, false, true, mutations, failure,
                               setup_entry, context, &collection))
      return false;
    return true;
  }
  uint32_t range = event - SHELL_MAX_GROUPS;
  const dep_snapshot_source_t *source =
      &context->workspace->snapshot_sources
           [context->snapshot->prepared_source[context->range_node[range]]];
  dep_read_result_t read = {0};
  dep_named_mutations_t read_mutations;
  if (source->read.active) {
    read = read_result ? *read_result
                       : dep_read_evaluate(&source->read, executed_state,
                                           journal, NULL, NULL);
    dep_read_mutations(&source->read, &read, &source->prefix_assignments,
                       executed_state, journal, &read_mutations);
    mutations = &read_mutations;
  }
  bool nullable_readonly =
      source->argv_presence == (DEP_ARGV_EMPTY | DEP_ARGV_PRESENT) &&
      source->readonly_stop != UINT32_MAX;
  bool private = context->execution->pipeline.local_process[range];
  /* An argv-less command with an input/named redirect performs its setup in a
   * child. Assignments preceding that setup still belong to the parent, but
   * neither successful nor failed redirects publish descriptor changes. */
  bool current_setup = mode == DEP_UNDO_COMMAND;
  bool child_setup = mode == DEP_UNDO_CHILD;
  dep_route_state_t continued = selected;
  dep_route_state_t failed_setup = selected;
  dep_route_state_t child_continued = selected;
  /* Every call below that takes the collection can sweep the route journal.
   * Each of these states is rewritten in place and read after such a call, but
   * a callee only roots the one it is handed. */
  collection.roots[4] = &continued;
  collection.roots[5] = &failed_setup;
  collection.roots[6] = &child_continued;
  if (child_setup) {
    dep_named_mutations_t unchanged = {0};
    const dep_named_mutations_t *parent_mutations =
        mutations->before_redirect ? mutations : &unchanged;
    if (!dep_ifs_copy(&child_continued, setup_entry, journal) ||
        !dep_fd_bindings(&child_continued, journal, ops, 0, parent_mutations))
      return false;
  }
  if (setup_survived && current_setup && (!private || report_state)) {
    journal->diagnostic_cleanup = true;
    bool restored =
        dep_route_state_publish(&continued, journal, executed_state, ops,
                                op_count, descriptor_exec, &collection);
    journal->diagnostic_cleanup = false;
    failed_setup = continued;
    if (!restored ||
        !dep_fd_bindings(&continued, journal, ops, op_count, mutations))
      return false;
  }
  /* A failed setup stops before the command runs, so its continuation keeps
   * the published descriptor state but none of the command's own variable
   * effects. Assignment-only commands instead commit their values before any
   * redirect operand is expanded, so those survive the failure. */
  if (child_setup) {
    continued = child_continued;
    failed_setup = continued;
  } else if (current_setup && mutations->before_redirect &&
             (!private || report_state)) {
    if (!dep_fd_bindings(&failed_setup, journal, ops, 0, mutations))
      return false;
  }
  /* Only setup the model treats as failing (see setup_may_fail) diverges from
   * the completed command. Here-documents and here-strings do not. */
  bool failure_modeled = source->setup_may_fail || stop != UINT32_MAX;
  dep_fd_flow_t failures;
  if (!dep_fd_setup_failures(
          &selected, journal, failure_modeled ? &failed_setup : &continued, ops,
          all_op_count, descriptor_exec, named_binding, mutations, &failures,
          setup_entry, context, &collection))
    return false;
  if (child_setup && failures.mask)
    failures.state[1] = child_continued;
  /* The failure outcomes are built before the failed-body publication below,
   * which can sweep the route journal. Keep them reachable. */
  collection.flow = &failures;
  uint8_t body_status = context->event_body_status[event];
  if (source->argv_presence == DEP_ARGV_EMPTY &&
      !context->expansion_status[event].isolated_setup &&
      (source->observation_first[0] || source->observation_first[1] ||
       (source->observation_first[2] || source->observation_first[3]))) {
    body_status = DEP_STATUS_MAY_SUCCEED;
    uint32_t slot =
        context->snapshot->prepared_source[context->range_node[range]];
    for (unsigned phase = 0; phase <= DEP_SNAPSHOT_BODY_WORD; phase++) {
      uint8_t status = context->expansion_status[event].phase[phase];
      if (source->observation_first[phase]) {
        dep_route_set_t observed =
            dep_fd_raw_fact(executed_state, journal,
                            dep_fd_numeric(slot * DEP_SNAPSHOT_SETUP + phase),
                            DEP_FD_ACCESS_SUBSTITUTION_STATUS);
        if (observed.count)
          status = (uint8_t)observed.routes[0].value;
      }
      body_status = (status & DEP_STATUS_EITHER) |
                    ((status & DEP_EXPANSION_INCOMING) ? body_status : 0);
    }
  }
  if (source->read.active)
    body_status = read.status;
  if (source->argv_presence == DEP_ARGV_EMPTY &&
      dep_assignments_may_reject(&source->null_mutations))
    body_status |= DEP_STATUS_MAY_FAIL;
  if (source->test) {
    dep_route_state_t body = *executed_state;
    dep_test_context_t test = {.state = &body,
                               .journal = journal,
                               .prefixes = &source->prefix_assignments};
    unsigned result = shell_test_evaluate(source->test, dep_test_lookup, &test);
    body_status = (result & SHELL_TEST_TRUE ? DEP_STATUS_MAY_SUCCEED : 0) |
                  (result & (SHELL_TEST_FALSE | SHELL_TEST_ERROR_RESULT)
                       ? DEP_STATUS_MAY_FAIL
                       : 0);
  }
  /* A nonmutating executable consumes its substitution values, not their
   * completion status. With no setup or persistent effects, all of those
   * private observation paths reconverge to the selected entry. Retaining
   * their input predicates would enumerate discarded results in every later
   * command. Assignment-only commands, reads, and descriptor/variable effects
   * still retain the predicates selecting their actual outcomes. Deferred
   * I/O uses executed_state, not this continuation projection. */
  if (source->argv_presence == DEP_ARGV_PRESENT && !source->read.active &&
      !all_op_count && !descriptor_exec && !mutations->count &&
      !mutations->ifs_write &&
      !context->process_routes->first[context->range_node[range]] &&
      (source->observation_first[0] || source->observation_first[1] ||
       (source->observation_first[2] || source->observation_first[3])))
    continued = selected;
  if (private)
    body_status = dep_status_child_return(body_status);
  if (!setup_survived)
    body_status = 0;
  dep_route_state_t failed_body = continued;
  bool runtime_exec =
      descriptor_exec &&
      dep_owner_exec(context, context->range_node[range])->kind ==
          DEP_EXEC_RUNTIME;
  if (setup_survived && current_setup && (!private || report_state) &&
      (runtime_exec || mutations->success_only ||
       (source->read.active && read.unassigned_failure))) {
    /* Runtime exec option errors do not retain numeric redirects. Likewise,
     * pre-change cd failure preserves PWD/OLDPWD while keeping any descriptor
     * variables allocated during its successful redirect setup. A read failure
     * before assignment publishes no target writes; partial assignment failures
     * instead use their terminal version's exact earlier-write signature. */
    dep_named_mutations_t no_mutations = {0};
    const dep_named_mutations_t *failed_mutations =
        mutations->success_only ||
                (source->read.active && read.unassigned_failure)
            ? &no_mutations
            : mutations;
    failed_body = selected;
    if (!dep_route_state_publish(&failed_body, journal, executed_state, ops,
                                 op_count, descriptor_exec && !runtime_exec,
                                 &collection) ||
        !dep_fd_bindings(&failed_body, journal, ops, op_count,
                         failed_mutations))
      return false;
    if (source->read.active && read.unassigned_failure &&
        read.assigned_failure &&
        !dep_fd_merge(&failed_body, &continued, journal))
      return false;
    if (mutations->failure_alternative &&
        !dep_fd_merge(&failed_body, &continued, journal))
      return false;
  }
  bool negated = context->fast->cmds[range].pipeline_negation_count & 1u;
  dep_fd_flow_t outcomes = {.mask = negated ? dep_status_negate(body_status)
                                            : body_status};
  uint8_t stops =
      (nullable_readonly && !private ? context->expansion_status[event].errors
                                     : context->event_static_status[event]) &
      DEP_STATUS_STOP;
  outcomes.mask |= stops;
  if (context->owner_setup_stop[context->range_node[range]] != UINT32_MAX)
    outcomes.mask = stops;
  for (unsigned i = 0; i < 5; i++)
    outcomes.state[i] = private ? *executed_state
                        : i < 2 ? continued
                                : selected;
  outcomes.state[negated ? 0 : 1] = private ? *executed_state : failed_body;
  if (source->test && setup_survived) {
    for (unsigned i = 0; i < 2; ++i) {
      if (!(outcomes.mask & (1u << i)))
        continue;
      dep_route_state_t refined;
      bool ready, failed = false;
      unsigned desired =
          (i == 0) != negated ? SHELL_TEST_TRUE : SHELL_TEST_FALSE;
      if (!dep_test_select(source, &outcomes.state[i], journal, &refined,
                           &ready, desired, &failed))
        return false;
      if (ready)
        outcomes.state[i] = refined;
      else
        outcomes.mask &= (uint8_t)~(1u << i);
    }
  }
  if (failures.mask &&
      !dep_fd_add(&outcomes,
                  dep_setup_failure_negated(
                      context->fast->cmds[range].kind,
                      context->fast->cmds[range].pipeline_negation_count,
                      private)
                      ? 0
                      : 1,
                  failures.state[1], journal))
    return false;
  if (nullable_readonly && !private) {
    /* Only the empty-argv alternative commits these prefixes. Its readonly
     * failure precedes redirects and must not borrow the executable body's
     * descriptor mutations. Keep it separate through input-unit recovery. */
    dep_route_state_t stopped = selected;
    if (!dep_fd_mutation_bindings(&stopped, journal, &source->null_mutations) ||
        !dep_ifs_apply(&stopped, journal, &source->null_mutations))
      return false;
    uint8_t null_status =
        DEP_STATUS_ABORT_FAILURE |
        context->expansion_status[event].null_assignment_errors;
    for (unsigned outcome = 2; outcome < 5; outcome++)
      if ((null_status & (1u << outcome)) &&
          !dep_fd_add(&outcomes, outcome, stopped, journal))
        return false;
  }
  if (report_state) {
    /* A timer inside a child sees that child's exec redirects, even though
     * they are not published into its parent's continuation. */
    if (!setup_survived && failures.mask)
      *report_state = failures.state[1];
    else {
      *report_state = descriptor_exec ? *executed_state : continued;
      if ((body_status & DEP_STATUS_MAY_FAIL) &&
          !dep_fd_merge(report_state, &failed_body, journal))
        return false;
      if (failures.mask &&
          !dep_fd_merge(report_state, &failures.state[1], journal))
        return false;
    }
  }
  if (!private)
    for (unsigned i = 0; i < 5; i++)
      if ((outcomes.mask & (1u << i)) &&
          !dep_process_close_owner(&outcomes.state[i], journal, context,
                                   context->range_node[range]))
        return false;
  if (report_state && !dep_process_close_owner(report_state, journal, context,
                                               context->range_node[range]))
    return false;
  *finished = outcomes;
  return true;
}

/* Select successful versions by their one setup dispatch. A missing tag is
 * meaningful for a command with no redirects, or one stopped before setup. */
static SHELL_NONNULL(1, 2, 4, 5) bool dep_setup_select(
    const dep_route_state_t *state, dep_route_journal_t *journal, uint8_t mode,
    dep_route_state_t *selected, bool *found) {
  *selected = (dep_route_state_t){0};
  *found = false;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t fact =
        dep_fd_raw_fact(&one, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                        DEP_FD_ACCESS_SETUP_MODE);
    if (fact.count && fact.routes[0].value != mode)
      continue;
    if (!*found) {
      *selected = one;
      *found = true;
    } else if (!dep_route_state_add_root(selected, journal, root))
      return false;
  }
  dep_route_state_inherit(selected, state);
  return true;
}

/* Setup and publication share the same scope choices. Finish the outcome
 * stream only once after completing each selected dispatch independently. */
static SHELL_NONNULL(1, 2, 4, 5, 10, 12) shell_dep_error_t dep_fd_finish_owner(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, const dep_route_state_t *executed_state,
    const dep_fd_op_t *ops, uint32_t op_count, bool descriptor_exec,
    bool named_binding, const dep_named_mutations_t *mutations,
    dep_route_state_t *report_state, const dep_route_state_t *setup_entry) {
  uint32_t owner = dep_snapshot_event_owner(context, event);
  uint8_t modes = dep_owner_undo_mode(context, owner);
  bool survived = context->owner_setup_stop[owner] == UINT32_MAX;
  dep_fd_flow_t outcomes = {0};
  const dep_snapshot_source_t *prepared =
      &context->workspace
           ->snapshot_sources[context->snapshot->prepared_source[owner]];
  if (event >= SHELL_MAX_GROUPS && survived &&
      (prepared->read.active || prepared->observation_first[0] ||
       prepared->observation_first[1] ||
       (prepared->observation_first[2] || prepared->observation_first[3]))) {
    dep_route_iterator_t iterator = dep_route_iterator(executed_state);
    uint32_t root;
    bool report_ready = false;
    while (dep_route_next(&iterator, journal, &root)) {
      dep_route_state_t one = dep_route_state_single(root);
      dep_route_state_inherit(&one, executed_state);
      const dep_read_plan_t *plan = &prepared->read;
      dep_read_versions_t observations = {.outcomes = {one}, .mask = 1};
      dep_read_result_t read = {0};
      if (plan->active)
        read = dep_read_evaluate(plan, &one, journal, &observations,
                                 context->workspace->read_frontiers);
      if (read.exhausted)
        return SHELL_DEP_ETRUNC;
      if (read.unsupported)
        return SHELL_DEP_EPARSE;
      dep_domain_collection_t read_pins = {
          .remaining = &iterator,
          .states = observations.outcomes,
          .state_count = DEP_READ_OUTCOMES,
          .flow = &outcomes,
          .roots = {report_ready ? report_state : NULL, &one}};
      for (unsigned kind = 0; kind < DEP_READ_OUTCOMES; kind++) {
        if (!(observations.mask & (1u << kind)))
          continue;
        dep_route_iterator_t versions =
            dep_route_iterator(&observations.outcomes[kind]);
        uint32_t version;
        while (dep_route_next(&versions, journal, &version)) {
          dep_route_state_t terminal = dep_route_state_single(version);
          dep_route_state_inherit(&terminal, &observations.outcomes[kind]);
          dep_read_result_t local_read = read;
          dep_route_set_t effects = dep_fd_raw_root_fact(
              version, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
              DEP_FD_ACCESS_EFFECT_STATE);
          local_read.targets = effects.count
                                   ? (uint64_t)effects.routes[0].value |
                                         ((uint64_t)(effects.routes[1].value &
                                                     ~DEP_READ_EFFECT_REPLY)
                                          << 32)
                                   : 0;
          local_read.default_target =
              effects.count &&
              (effects.routes[1].value & DEP_READ_EFFECT_REPLY) != 0;
          local_read.status = kind == DEP_READ_SUCCESS ? DEP_STATUS_MAY_SUCCEED
                                                       : DEP_STATUS_MAY_FAIL;
          local_read.assigned_failure = kind == DEP_READ_ASSIGNED_FAILURE;
          local_read.unassigned_failure = kind == DEP_READ_UNASSIGNED_FAILURE;
          read_pins.roots[0] = report_ready ? report_state : NULL;
          dep_route_state_t report = {0};
          dep_fd_flow_t path;
          uint8_t mode = dep_setup_mode(&terminal, journal, modes);
          if (!dep_fd_finish_owner_scope(
                  context, stream, event, journal, &terminal, ops, op_count,
                  descriptor_exec,
                  named_binding &&
                      (modes != DEP_UNDO_BOTH || mode == DEP_UNDO_COMMAND),
                  mutations, report_state ? &report : NULL, setup_entry, mode,
                  true, plan->active ? &local_read : NULL, &read_pins, &path))
            return SHELL_DEP_ETRUNC;
          for (unsigned outcome = 0; outcome < 5; outcome++)
            if ((path.mask & (1u << outcome)) &&
                (!dep_fd_retire_owner_facts(context, event,
                                            &path.state[outcome], journal) ||
                 !dep_fd_add(&outcomes, outcome, path.state[outcome], journal)))
              return SHELL_DEP_ETRUNC;
          if (report_state) {
            if (!report_ready) {
              *report_state = report;
              report_ready = true;
            } else if (!dep_fd_merge(report_state, &report, journal))
              return SHELL_DEP_ETRUNC;
          }
        }
      }
    }
    return dep_fd_finish(context, stream, event, &outcomes, journal)
               ? SHELL_DEP_OK
               : SHELL_DEP_ETRUNC;
  }
  if (modes != DEP_UNDO_BOTH) {
    if (!dep_fd_finish_owner_scope(
            context, stream, event, journal, executed_state, ops, op_count,
            descriptor_exec, named_binding, mutations, report_state,
            setup_entry, modes, survived, NULL, NULL, &outcomes))
      return SHELL_DEP_ETRUNC;
    return event < SHELL_MAX_GROUPS ||
                   dep_fd_finish(context, stream, event, &outcomes, journal)
               ? SHELL_DEP_OK
               : SHELL_DEP_ETRUNC;
  }
  bool report_ready = false;
  for (uint8_t mode = DEP_UNDO_CHILD; mode <= DEP_UNDO_COMMAND; mode <<= 1) {
    dep_route_state_t selected;
    bool found;
    if (!op_count) {
      selected = *executed_state;
      found = true;
    } else if (!dep_setup_select(executed_state, journal, mode, &selected,
                                 &found))
      return SHELL_DEP_ETRUNC;
    if (!found)
      selected = *setup_entry;
    /* This scratch span's lifetime ends before another owner or recursive
     * parse. The caller's prepared operations remain unchanged. */
    dep_fd_op_t *scoped_ops = context->workspace->op_scratch;
    for (uint32_t op = 0; op < op_count; op++) {
      scoped_ops[op] = ops[op];
      scoped_ops[op].undo_mode = mode;
    }
    dep_fd_flow_t scoped;
    dep_route_state_t report = {0};
    /* The next mode selects from executed_state again, after this one's scope
     * may have swept the journal. */
    dep_domain_collection_t pins = {
        .flow = &outcomes,
        .roots = {report_ready ? report_state : NULL, executed_state}};
    if (!dep_fd_finish_owner_scope(
            context, stream, event, journal, &selected, scoped_ops, op_count,
            descriptor_exec, mode == DEP_UNDO_COMMAND && named_binding,
            mutations, report_state ? &report : NULL, setup_entry, mode,
            survived && found, NULL, &pins, &scoped))
      return SHELL_DEP_ETRUNC;
    for (unsigned outcome = 0; outcome < 5; outcome++)
      if ((scoped.mask & (1u << outcome)) &&
          !dep_fd_add(&outcomes, outcome, scoped.state[outcome], journal))
        return SHELL_DEP_ETRUNC;
    if (report_state) {
      if (!report_ready) {
        *report_state = report;
        report_ready = true;
      } else if (!dep_fd_merge(report_state, &report, journal))
        return SHELL_DEP_ETRUNC;
    }
  }
  return dep_fd_finish(context, stream, event, &outcomes, journal)
             ? SHELL_DEP_OK
             : SHELL_DEP_ETRUNC;
}

/* An allocation skipped only because this compound's setup failed is known
 * absent, not an arbitrary variable value. Joining absence with the successful
 * allocation retains its possible routes, but invents no route on absence.
 * Explicit scalar writes invalidate allocation associations; stable unsets
 * retain emptiness, never a proof that the old physical descriptor closed. */
typedef struct {
  dep_route_state_t *failed;
  const dep_route_state_t *body;
  dep_route_journal_t *journal;
} dep_fd_absence_walk_t;

static bool dep_fd_absence_entry(void *context, dep_fd_ref_t fd,
                                 dep_fd_access_t access, uint32_t body,
                                 uint32_t entry) {
  dep_fd_absence_walk_t *walk = context;
  dep_route_journal_t *journal = walk->journal;
  if (!body)
    return true;
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS &&
      !dep_route_map_diff(
          journal, journal->arena->snapshots[body - 1].routes[0].value,
          entry ? journal->arena->snapshots[entry - 1].routes[0].value : 0,
          dep_fd_absence_entry, walk))
    return false;
  if (access == DEP_FD_ACCESS_BINDING &&
      dep_fd_fact(walk->body, journal, fd, DEP_FD_ACCESS_BINDING)
              .routes[0]
              .kind == DEP_ROUTE_INHERITED &&
      dep_fd_fact(walk->failed, journal, fd, DEP_FD_ACCESS_BINDING)
              .routes[0]
              .kind == DEP_ROUTE_UNSEEN)
    return dep_fd_mark_absent(walk->failed, journal, fd);
  return true;
}

/* Visits the keys the body version root changed relative to entry_root. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_setup_absences(
    dep_route_state_t *failed, const dep_route_state_t *body,
    dep_route_journal_t *journal, uint32_t root, uint32_t entry_root) {
  dep_fd_absence_walk_t walk = {failed, body, journal};
  return dep_route_map_diff(journal, root, entry_root, dep_fd_absence_entry,
                            &walk);
}

static SHELL_NONNULL(1, 2, 4, 5) bool dep_fd_complete_group(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t group,
    dep_route_journal_t *journal, const dep_redirect_frame_t *frames) {
  dep_fd_flow_t body = stream->scope[group + 1], completed = {0};
  dep_group_completion_t completion = dep_group_completion(context, group);
  dep_route_state_t entry = stream->selected[group];
  dep_route_state_t failed = stream->setup_failure[group].state[1];
  dep_route_state_t body_names;
  if (completion.added &&
      (!dep_fd_select(&body, DEP_STATUS_EITHER | DEP_STATUS_STOP, journal,
                      &body_names) ||
       !dep_fd_setup_absences(&failed, &body_names, journal, body_names.root,
                              entry.root)))
    return false;
  if (context->group_exec[group].isolated)
    failed = entry;
  else if (completion.added &&
           !dep_process_close_owner(&failed, journal, context,
                                    context->group_node[group]))
    return false;
  for (unsigned i = 0; i < 5; i++) {
    if ((completion.added & (1u << i)) &&
        !dep_fd_add(&completed, i, failed, journal))
      return false;
    if (!(body.mask & (1u << i)))
      continue;
    dep_route_state_t state = body.state[i];
    if (!context->group_exec[group].isolated) {
      journal->diagnostic_cleanup = true;
      bool restored =
          dep_fd_restore_slots(&state, journal, frames[group].scratch_keys,
                               frames[group].scratch_count);
      journal->diagnostic_cleanup = false;
      if (!restored)
        return false;
      if (!dep_process_close_owner(&state, journal, context,
                                   context->group_node[group]))
        return false;
    }
    for (unsigned target = 0; target < 5; target++)
      if ((completion.outcome[i] & (1u << target)) &&
          !dep_fd_add(&completed, target, state, journal))
        return false;
  }
  if (!dep_fd_finish(context, stream, group, &completed, journal))
    return false;
  /* Group setup failure, body, and selected-entry versions have no consumer
   * after completion has published them into the parent flow. */
  stream->scope[group + 1] = (dep_fd_flow_t){0};
  stream->setup_failure[group] = (dep_fd_flow_t){0};
  return true;
}

/* Restore the completed body's temporary numeric frame and dispose its
 * process pipes before the shell-owned timing report. Continuations are
 * transferred separately by dep_fd_stream. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_publish_completed_scope(
    dep_route_state_t *destination_state,
    const dep_route_state_t *completed_state, dep_route_journal_t *journal,
    const dep_route_publication_t *publication,
    const dep_parse_context_t *context) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
  dep_route_state_t alternatives = *completed_state;
  if (!dep_restore_continuation_route_state(&alternatives, journal,
                                            publication) ||
      !dep_process_close_owner(&alternatives, journal, context,
                               context->group_node[publication->source_group]))
    return false;
  *destination_state = alternatives;
  return true;
}

static SHELL_NONNULL(1, 2) bool dep_complete_route_group(
    dep_route_workspace_t *workspace, const dep_parse_context_t *context,
    uint32_t group) {
  workspace->journal.diagnostic_owner = context->group_node[group];
  uint16_t raw_parent = context->fast->groups[group].parent;
  int32_t parent = raw_parent == UINT16_MAX ? -1 : (int32_t)raw_parent;
  dep_route_publication_t publication = {
      context->fast, workspace->group_redirect_frames, (int32_t)group, parent};
  dep_route_state_t *completed_state = &workspace->group_route_state[group];
  /* Construction completed this group (dep_snapshot_complete_groups). */
  const dep_snapshot_frame_t *frame = context->snapshot;
  if (context->fast->groups[group].pipeline_time_mode != SHELL_PIPE_TIME_NONE) {
    if (!dep_fd_select(&frame->group_scope[group],
                       DEP_STATUS_EITHER | DEP_STATUS_STOP, &workspace->journal,
                       completed_state))
      return false;
  } else {
    *completed_state =
        dep_fd_point_version(&frame->group_scope[group], completed_state);
  }
  workspace->group_time_routes[group] =
      dep_time_report_for_fd2(completed_state, &workspace->journal);
  if (workspace->group_shell_time_routes_ready[group]) {
    if (frame->group_scope[group].mask) {
      if (!dep_publish_completed_scope(
              &workspace->group_shell_route_state[group], completed_state,
              &workspace->journal, &publication, context))
        return false;
      workspace->group_shell_time_routes[group] = dep_time_report_for_fd2(
          &workspace->group_shell_route_state[group], &workspace->journal);
    } else
      /* No body version reached completion. An entry fallback is not a
       * successful cleanup path and must not invent a report destination. */
      workspace->group_shell_time_routes[group] =
          (dep_route_set_t){.ready = true};
    if (dep_group_completion(context, group).added & DEP_STATUS_MAY_FAIL) {
      /* This foreground timer still reports when its compound setup fails.
       * That path retains the setup prefix, not any body descriptor effects. */
      dep_route_set_t failed = dep_fd_fact(
          &frame->group_failure[group].state[1], &workspace->journal,
          dep_fd_numeric(2), DEP_FD_ACCESS_WRITE);
      for (uint32_t route = 0; route < failed.count; route++)
        if (!dep_route_set_add(&workspace->group_shell_time_routes[group],
                               failed.routes[route]))
          return false;
    }
  }

  dep_route_state_t *destination_state =
      parent >= 0 ? &workspace->group_route_state[parent]
                  : &workspace->persistent_route_state;
  *destination_state =
      dep_fd_point_version(&frame->group_parent[group], destination_state);
  if (parent >= 0) {
    workspace->group_time_routes[parent] =
        dep_time_report_for_fd2(destination_state, &workspace->journal);
  } else {
    workspace->persistent_time_routes =
        dep_time_report_for_fd2(destination_state, &workspace->journal);
  }
  return true;
}

static SHELL_NONNULL(1) bool dep_snapshot_complete_groups(
    const dep_parse_context_t *context, uint32_t before_position) {
  dep_snapshot_frame_t *frame = context->snapshot;
  dep_route_workspace_t *workspace = context->workspace;
  while (frame->active_group_count) {
    uint32_t group = frame->active_groups[frame->active_group_count - 1];
    if (context->execution->pipeline.group_tail[group].redirect_end >
        before_position)
      break;
    frame->active_group_count--;
    workspace->journal.diagnostics = &frame->diagnostics;
    workspace->journal.diagnostic_owner = context->group_node[group];
    frame->group_scope[group] = frame->fd_stream.scope[group + 1];
    frame->group_failure[group] = frame->fd_stream.setup_failure[group];
    if (!dep_fd_complete_group(context, &frame->fd_stream, group,
                               &workspace->journal, frame->redirect_frames))
      return false;
    uint16_t parent = context->fast->groups[group].parent;
    frame->group_parent[group] =
        frame->fd_stream.scope[parent == UINT16_MAX ? 0 : parent + 1];
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
  uint32_t position, fd;
} dep_low_observation_t;

typedef struct {
  uint32_t fds[DEP_ROUTE_OPERATION_CAPACITY];
  bool required[DEP_ROUTE_OPERATION_CAPACITY];
  shell_avl_node_t index[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t root, count;
  /* Root-only collection borrows the final-route journal's inventory until
   * construction copies it into the snapshot journal. Recursive inspections
   * reuse that prepared inventory and leave this pointer NULL. This keeps the
   * node/token-sized table out of every recursive parser stack frame. */
  dep_read_observations_t *read_observations;
  dep_test_programs_t *tests;
  /* Source positions of descriptor-sensitive operations, including nested
   * bodies. Sort once, then query command/group lifetimes by lower bound. */
  uint32_t positions[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t position_count;
  dep_low_observation_t low[DEP_ROUTE_OPERATION_CAPACITY];
  uint32_t low_count;
  bool overflow;
  bool named_fds;
  bool has_process;
  bool named_closes;
  bool scratch_observable;
  const char *pending_operand;
  uint32_t pending_destination;
  const char *source;
  size_t source_length;
} dep_observable_inventory_t;

static SHELL_NONNULL(1, 2) void dep_inventory_position(
    dep_observable_inventory_t *inventory, const char *source) {
  if (inventory->position_count == DEP_ROUTE_OPERATION_CAPACITY) {
    inventory->overflow = true;
    return;
  }
  inventory->positions[inventory->position_count++] =
      (uint32_t)(source - inventory->source);
}

/* Collect low numeric references at the semantic validation boundary. High
 * descriptors retain the shared named-allocation/scratch identity model. */
static SHELL_NONNULL(1, 2) void dep_inventory_low(
    dep_observable_inventory_t *inventory, const char *source, uint32_t fd) {
  if (fd < 3 || fd >= DEP_BASH_VARREDIR_MIN_FD)
    return;
  if (inventory->low_count == DEP_ROUTE_OPERATION_CAPACITY) {
    inventory->overflow = true;
    return;
  }
  inventory->low[inventory->low_count++] =
      (dep_low_observation_t){(uint32_t)(source - inventory->source), fd};
}

static SHELL_NONNULL(1, 2) int dep_low_observation_compare(const void *left,
                                                           const void *right) {
  const dep_low_observation_t *a = left, *b = right;
  if (a->fd != b->fd)
    return a->fd < b->fd ? -1 : 1;
  return a->position < b->position ? -1 : a->position != b->position;
}

/* The fixed low-auxiliary range is below Bash's named-allocation minimum.
 * Query its indexed references, never an owner's source. Standard streams
 * are always potential observable pipe ends. */
static SHELL_NONNULL(1, 4) bool dep_process_lifetime_observed(
    const dep_observable_inventory_t *inventory, uint32_t begin, uint32_t end,
    uint16_t *observed_low) {
  *observed_low = 7u;
  uint32_t low = 0, high = inventory->position_count;
  while (low < high) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
    uint32_t middle = low + (high - low) / 2;
    if (inventory->positions[middle] < begin)
      low = middle + 1;
    else
      high = middle;
  }
  if (low == inventory->position_count || inventory->positions[low] >= end)
    return false;
  for (uint32_t fd = 3; fd < DEP_BASH_VARREDIR_MIN_FD; fd++) {
    low = 0;
    high = inventory->low_count;
    dep_low_observation_t key = {begin, fd};
    while (low < high) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
      uint32_t middle = low + (high - low) / 2;
      if (dep_low_observation_compare(&inventory->low[middle], &key) < 0)
        low = middle + 1;
      else
        high = middle;
    }
    if (low < inventory->low_count && inventory->low[low].fd == fd &&
        inventory->low[low].position < end)
      *observed_low |= (uint16_t)(1u << fd);
  }
  return true;
}

/* Finalize before recording any temporary end or guard for this owner. The
 * existing phase checkpoint advances earlier owners once and applies scope
 * restoration/pipeline setup. Only the three standard bindings are queried;
 * a past close in another lifetime must not enable Cartesian enumeration. */
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t
    dep_prepare_process_tracking(shell_dep_graph_t *graph,
                                 const dep_subgraph_streams_t *streams,
                                 const dep_parse_context_t *context,
                                 uint32_t owner, uint32_t position,
                                 dep_snapshot_phase_t phase) {
  dep_process_route_map_t *process = context->process_routes;
  if (process->tracking_ready[owner])
    return SHELL_DEP_OK;
  if (!process->track[owner]) {
    uint32_t table;
    shell_dep_error_t error = dep_snapshot_phase_table(
        graph, streams, context, owner, position, phase, &table);
    if (error != SHELL_DEP_OK)
      return error;
    const dep_snapshot_table_t *entry =
        &context->workspace->snapshot_tables[table];
    dep_route_state_t state = dep_snapshot_alternatives(entry);
    for (uint32_t fd = 0; fd < 3; fd++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
      if (dep_fd_occupancy(&state, &context->workspace->journal, fd)
              .may_be_free) {
        process->track[owner] = true;
        break;
      }
    }
  }
  process->tracking_ready[owner] = true;
  return SHELL_DEP_OK;
}

static SHELL_NONNULL(1, 3) int dep_observable_compare(const void *context,
                                                      uint32_t index,
                                                      const void *key) {
  const dep_observable_inventory_t *inventory = context;
  uint32_t value = inventory->fds[index], other = *(const uint32_t *)key;
  return value < other ? -1 : value != other;
}

static SHELL_NONNULL(1) void dep_inventory_add(
    dep_observable_inventory_t *inventory, uint32_t fd, bool required) {
  if (fd > SHELL_DEP_FD_MAX)
    return;
  uint32_t candidate = inventory->count + 1, match = 0;
  inventory->root =
      shell_avl_insert(inventory->index, inventory->root, candidate,
                       DEP_ROUTE_OPERATION_CAPACITY, dep_observable_compare,
                       inventory, &fd, &match);
  if (!match)
    inventory->overflow = true;
  else {
    if (match == candidate) {
      inventory->fds[inventory->count++] = fd;
    }
    inventory->required[match - 1] |= required;
  }
}

static SHELL_NONNULL(1, 7) void dep_observe_read_fd(
    const char *word, uint32_t fd, unsigned kind, const char *parameter,
    size_t parameter_length, bool identity, void *context) {
  dep_observable_inventory_t *inventory = context;
  /* Ordinary standard streams cannot observe private high ends. Explicit
   * auxiliary selectors and named identities can, including in nested shells.
   * Possible standard-slot reuse is retained by the owner's entry snapshot. */
  if (kind == 2 || (kind == 1 && fd >= 3) || identity)
    dep_inventory_position(inventory, word);
  if (kind == 1)
    dep_inventory_low(inventory, word, fd);
  if (parameter && inventory->read_observations &&
      !dep_read_observe(inventory->read_observations,
                        (dep_fd_ref_t){.name = parameter,
                                       .value = SHELL_DEP_FD_NAMED,
                                       .name_len = (uint32_t)parameter_length},
                        identity ? DEP_READ_OBSERVE_IDENTITY |
                                       DEP_READ_OBSERVE_ACCESS
                                 : DEP_READ_OBSERVE_VALUE))
    inventory->overflow = true;
  if (kind == 2) {
    inventory->named_fds = true;
    inventory->scratch_observable = true;
  } else if (kind == 1 || kind == 3) {
    if (inventory->read_observations &&
        !dep_read_observe(inventory->read_observations, dep_fd_numeric(fd),
                          kind == 3 ? DEP_READ_OBSERVE_ACCESS
                                    : DEP_READ_OBSERVE_IDENTITY |
                                          DEP_READ_OBSERVE_ACCESS))
      inventory->overflow = true;
    if (kind == 1)
      dep_inventory_add(inventory, fd, true);
    inventory->scratch_observable |= fd >= DEP_BASH_VARREDIR_MIN_FD;
  }
}

static SHELL_NONNULL(1, 3) void dep_observe_process(const char *word,
                                                    size_t length,
                                                    void *context) {
  dep_observable_inventory_t *inventory = context;
  inventory->has_process |= !shell_source_empty_process_word(word, length);
}

/* Names borrow decoded program values. Only grammar-selected queries enter
 * this inventory, including the PWD dependency of an OLDPWD presence write. */
static SHELL_NONNULL(1, 3) void dep_observe_presence(const char *word,
                                                     size_t length,
                                                     void *context) {
  dep_observable_inventory_t *inventory = context;
  if (length == 6 && !memcmp(word, "OLDPWD", 6) &&
      !dep_read_observe(inventory->read_observations,
                        (dep_fd_ref_t){.name = "PWD",
                                       .name_len = 3,
                                       .value = SHELL_DEP_FD_NAMED},
                        DEP_READ_OBSERVE_PRESENCE))
    inventory->overflow = true;
  if (!dep_read_observe(inventory->read_observations,
                        (dep_fd_ref_t){.name = word,
                                       .name_len = (uint32_t)length,
                                       .value = SHELL_DEP_FD_NAMED},
                        DEP_READ_OBSERVE_PRESENCE))
    inventory->overflow = true;
}

static SHELL_NONNULL(1, 2, 3) void dep_observe_test(
    const char *command, const shell_test_program_t *program, void *context) {
  dep_observable_inventory_t *inventory = context;
  dep_test_programs_t *tests = inventory->tests;
  uint32_t candidate = tests->count + 1, match = 0;
  tests->root = shell_avl_insert(tests->index, tests->root, candidate,
                                 SHELL_DEP_MAX_NODES, dep_test_program_compare,
                                 tests, command, &match);
  if (!match)
    inventory->overflow = true;
  else if (match == candidate) {
    tests->commands[tests->count] = command;
    tests->programs[tests->count++] = *program;
  }
}

static SHELL_NONNULL(1, 2) void dep_observe_descriptor_token(
    const shell_token_t *token, void *context) {
  dep_observable_inventory_t *inventory = context;
  bool current_shell = token->start - token->position == inventory->source;
  if (inventory->pending_operand &&
      token->start >= inventory->pending_operand) {
    uint32_t fd = 0;
    shell_process_fd_target_t kind = shell_process_classify_static_fd_target(
        token->start, token->length, &fd);
    if (kind == SHELL_PROCESS_FD_TARGET_FD ||
        kind == SHELL_PROCESS_FD_TARGET_MOVE) {
      if (fd >= 3 || inventory->pending_destination >= 3)
        dep_inventory_position(inventory, token->start);
      dep_inventory_low(inventory, token->start, fd);
      dep_inventory_add(inventory, fd, true);
      inventory->scratch_observable |= fd >= DEP_BASH_VARREDIR_MIN_FD;
    }
    inventory->named_closes |= kind == SHELL_PROCESS_FD_TARGET_MOVE;
    if (current_shell && ((kind == SHELL_PROCESS_FD_TARGET_CLOSE &&
                           inventory->pending_destination < 3) ||
                          (kind == SHELL_PROCESS_FD_TARGET_MOVE && fd < 3)))
      dep_inventory_position(inventory, token->start);
    inventory->scratch_observable |=
        (kind == SHELL_PROCESS_FD_TARGET_MOVE ||
         (kind == SHELL_PROCESS_FD_TARGET_CLOSE && token->group_depth != 0)) &&
        inventory->pending_destination >= DEP_BASH_VARREDIR_MIN_FD &&
        inventory->pending_destination <= SHELL_DEP_FD_MAX;
    if (shell_source_argument_has_dynamic_syntax(token->start, token->length)) {
      dep_inventory_position(inventory, token->start);
      size_t start = (size_t)(token->start - inventory->source);
      size_t end = shell_source_skip_redirect_word(inventory->source, start,
                                                   inventory->source_length);
      size_t prefix;
      bool move =
          shell_source_fd_move_prefix(token->start, end - start, &prefix);
      inventory->named_closes |= move;
      inventory->scratch_observable |=
          move && inventory->pending_destination >= DEP_BASH_VARREDIR_MIN_FD &&
          inventory->pending_destination <= SHELL_DEP_FD_MAX;
    }
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
    return;
  }
  size_t after = 0;
  uint32_t fd = 0;
  bool sensitive = false;
  if (shell_source_parse_io_number(token->start, 0, token->length, &after,
                                   &fd) == SHELL_SOURCE_IO_NUMBER_VALID) {
    sensitive = fd >= 3;
    dep_inventory_add(inventory, fd, false);
  } else if (shell_source_parse_named_fd_redirect(token->start, 0,
                                                  token->length, &after)) {
    size_t name_after;
    (void)shell_source_parse_named_fd_at_word_start(token->start, 0,
                                                    token->length, &name_after);
    if (inventory->read_observations &&
        !dep_read_observe(inventory->read_observations,
                          (dep_fd_ref_t){.name = token->start + 1,
                                         .value = SHELL_DEP_FD_NAMED,
                                         .name_len = (uint32_t)name_after - 2},
                          0))
      inventory->overflow = true;
    sensitive = true;
    inventory->named_fds = true;
    inventory->scratch_observable = true;
    dep_token_t raw = {.start = token->start, .len = (uint32_t)token->length};
    inventory->named_closes |= classify_redirect(&raw) == DEP_REDIRECT_DUP;
  }
  dep_token_t raw = {.start = token->start, .len = (uint32_t)token->length};
  uint32_t source, target, source_len, target_len;
  const char *source_name, *target_name;
  bool close, target_unquoted, move;
  dep_fd_access_t access;
  if (dep_parse_dup_redirect(&raw, &source, &target, &source_name, &source_len,
                             &target_name, &target_len, &close, &access,
                             &target_unquoted, &move)) {
    sensitive |= source >= 3 || (!close && target >= 3);
    dep_inventory_low(inventory, token->start, source);
    if (!close && target != source)
      dep_inventory_low(inventory, token->start, target);
    sensitive |= current_shell &&
                 ((close && source < 3) ||
                  (move && (target < 3 || (target_unquoted && source < 3))));
    inventory->named_closes |= (source == SHELL_DEP_FD_NAMED && close) || move;
    inventory->scratch_observable |=
        ((move || (close && token->group_depth != 0)) &&
         source >= DEP_BASH_VARREDIR_MIN_FD && source <= SHELL_DEP_FD_MAX) ||
        (!close && target >= DEP_BASH_VARREDIR_MIN_FD &&
         target <= SHELL_DEP_FD_MAX) ||
        target == SHELL_DEP_FD_NAMED;
    dep_inventory_add(inventory, source, true);
    dep_inventory_add(inventory, target, true);
  } else if (classify_redirect(&raw) == DEP_REDIRECT_DUP) {
    /* A separated duplication operand is the next lexical word. Whitespace
     * is outside the redirect token, so retain both its destination and its
     * source frontier. The destination remains observable even when the next
     * word is `-` and contributes no numeric source of its own. */
    uint32_t destination = redirect_fd(&raw, DEP_REDIRECT_DUP);
    sensitive |= destination >= 3;
    dep_inventory_low(inventory, token->start, destination);
    dep_inventory_add(inventory, destination, true);
    inventory->pending_operand = token->start + token->length;
    inventory->pending_destination = destination;
  } else
    dep_inventory_low(inventory, token->start, fd);
  if (sensitive)
    dep_inventory_position(inventory, token->start);
}

/* Source/context and inverse maps belong to this construction. Workspace was
 * validated at entry; streams and process_routes are prepared destinations. */
static SHELL_NONNULL(1, 2, 3, 4) void dep_collect_external_routes(
    shell_dep_graph_t *graph, dep_subgraph_streams_t *streams,
    dep_route_workspace_t *workspace, const bool *eligible);

/* Project shell setup/undo output through the same resources as body output.
 * The owner remains CMD/GROUP and fd 2 identifies shell-origin stderr. */
static SHELL_NONNULL(1) uint32_t
    dep_route_pipe(const dep_route_workspace_t *workspace,
                   dep_fd_route_t route);

/* diagnostics are construction's (dep_snapshot_frame_t.diagnostics). */
static SHELL_NONNULL(1, 3, 4, 5) bool dep_publish_diagnostics(
    shell_dep_graph_t *graph, uint32_t max_edges,
    dep_route_workspace_t *workspace, dep_subgraph_streams_t *streams,
    const dep_diagnostics_t *diagnostics) {
  if (!diagnostics->count)
    return true;
  /* Reuse join scratch after body publication and before pipe joining. A
   * body and a setup failure can write the same owner/fd/resource; keep one
   * public relation, with indexed rather than per-diagnostic edge rescans. */
  dep_stream_use_t *sinks = workspace->import_join.endpoints;
  shell_avl_node_t *index = workspace->import_join.endpoint_index;
  uint32_t count = 0, root = 0;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    const shell_dep_edge_t *edge = &graph->edges[i];
    if ((edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND) &&
        edge->source_fd == 2 &&
        !dep_record_stream_use(sinks, &count, index, &root, edge->from,
                               dep_fd_numeric(2), DEP_FD_ACCESS_WRITE,
                               edge->to))
      return false;
  }
  for (uint32_t i = 0; i < diagnostics->count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    const dep_diagnostic_use_t *use = &diagnostics->uses[i];
    dep_fd_route_t route = use->route;
    bool retained;
    if (dep_route_foreign(route, streams->depth)) {
      retained = dep_record_fd_import_use(
          streams, use->owner, dep_fd_numeric(2), DEP_FD_ACCESS_WRITE, route);
    } else if (route.kind == DEP_ROUTE_INHERITED) {
      retained = dep_record_external_use(streams, use->owner, dep_fd_numeric(2),
                                         DEP_FD_ACCESS_WRITE, route.value);
    } else if (route.kind == DEP_ROUTE_CAPTURE) {
      retained = dep_record_actual_capture(
          streams, use->owner, dep_fd_numeric(2), DEP_FD_ACCESS_WRITE,
          dep_resource_index(route.value));
    } else if (dep_route_pipe(workspace, route) != UINT32_MAX) {
      retained = dep_record_stream_use(
          streams->pipe_uses, &streams->pipe_use_count, streams->pipe_index,
          &streams->pipe_root, use->owner, dep_fd_numeric(2),
          DEP_FD_ACCESS_WRITE,
          workspace->pipes[dep_route_pipe(workspace, route)].from);
    } else {
      /* Runtime-unknown routes are not concrete resource references. Do not
       * return a complete graph after losing their diagnostic destination. */
      if ((route.kind != DEP_ROUTE_DOC && route.kind != DEP_ROUTE_DYNAMIC) ||
          dep_resource_index(route.value) >= workspace->original_edge_count)
        return false;
      const shell_dep_edge_t *original =
          &workspace->original_edges[dep_resource_index(route.value)];
      shell_dep_edge_type_t type = original->type;
      if (type == SHELL_EDGE_FD_OPEN)
        type = original->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND
                   ? SHELL_EDGE_APPEND
                   : SHELL_EDGE_WRITE;
      uint32_t before = count;
      if (!dep_record_stream_use(sinks, &count, index, &root, use->owner,
                                 dep_fd_numeric(2), DEP_FD_ACCESS_WRITE,
                                 original->to))
        return false;
      if (count == before)
        continue;
      retained = dep_add_resolved_edge_refs(
          graph, max_edges, use->owner, original->to, type, dep_fd_numeric(2),
          dep_fd_numeric(SHELL_DEP_FD_NONE), SHELL_DEP_EDGE_FLAG_NONE);
    }
    if (!retained)
      return false;
  }
  return true;
}

/* Ordinary deferred body I/O needs the union of byte routes, not the setup's
 * private undo/allocator history. Resolve aliases against their own versions
 * now, while those versions are live. This is one sparse publication cache per
 * owner, never a descriptor-table copy per execution alternative. Read and
 * compound owners still need their full correlated semantic versions. */
/* The pipe edge a local pipe-end route names (dep_snapshot_install_pipeline
 * keys it by the owner whose stdin or stdout it is), or UINT32_MAX for any
 * other route. A pipeline stage has at most one pipe on each side. */
static SHELL_NONNULL(1) uint32_t
    dep_route_pipe(const dep_route_workspace_t *workspace,
                   dep_fd_route_t route) {
  if ((route.kind != DEP_ROUTE_PIPE_INPUT &&
       route.kind != DEP_ROUTE_PIPE_OUTPUT) ||
      dep_route_foreign(route, workspace->journal.depth))
    return UINT32_MAX;
  uint32_t owner = dep_resource_index(route.value);
  return route.kind == DEP_ROUTE_PIPE_INPUT
             ? workspace->owner_edges.pipe_in[owner]
             : workspace->owner_edges.pipe_out[owner];
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_retain_owner_io(
    dep_route_workspace_t *workspace, const dep_parse_context_t *context,
    const shell_dep_graph_t *graph, const dep_route_state_t *state,
    uint32_t owner) {
  dep_route_state_t *retained = &workspace->owner_route_state[owner];
  if (graph->nodes[owner].type == SHELL_NODE_GROUP ||
      workspace->snapshot_sources[context->snapshot->prepared_source[owner]]
          .read.active) {
    *retained = *state;
    return true;
  }
  if (dep_owner_exec(context, owner)->kind == DEP_EXEC_DESCRIPTORS)
    return true;
  uint32_t count = workspace->owner_use_count[owner];
  for (uint32_t use = 0; use < count + 3; use++) {
    uint32_t fd =
        use < count ? workspace->owner_uses[owner][use].fd : use - count;
    if (use >= count && (workspace->route_standard_mask[owner] & (1u << fd)))
      continue;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
         access <<= 1) {
      dep_route_set_t routes =
          dep_fd_fact(state, &workspace->journal, dep_fd_numeric(fd),
                      (dep_fd_access_t)access);
      if (routes.truncated ||
          !dep_route_state_store_access(retained, &workspace->journal,
                                        dep_fd_numeric(fd),
                                        (dep_fd_access_t)access, routes))
        return false;
    }
  }
  return true;
}

/* Whether the script consumes this read's exit status: it is negated, or the
 * left operand of `&&` or `||`, or it ends a brace group or subshell whose
 * status the script consumes that way (the compound's status is the read's).
 * Loop and conditional bodies are not groups, so their status consumption
 * is not followed; function definitions are rejected before analysis.
 * A read error the script handles, such as `read -n "$n" x || true`, is an
 * ordinary failure outcome with unknown assigned values; Bash's message is
 * part of its stderr output. An unhandled one has no dependency model
 * (SHELL_DEP_EUNMODELED). A read error never stops execution, so handling
 * applies even to a certain one. */
static SHELL_NONNULL(1) bool dep_read_status_consumed(
    const dep_parse_context_t *context, uint32_t owner) {
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  uint32_t range = context->node_range[owner];
  uint16_t successor = pipeline->range_successor[range];
  if (successor == SHELL_TYPE_AND || successor == SHELL_TYPE_OR ||
      context->fast->cmds[range].pipeline_negation_count != 0)
    return true;
  if (successor != SHELL_TYPE_SIMPLE)
    return false;
  /* Ranges are lexical, and the read's own auxiliary ranges (such as a
   * here-string body) lie within its span. The read ends a group when the
   * group's last range does; an enclosing group's last range is then that
   * same range or another within the read. */
  const shell_range_t *read = &context->fast->cmds[range];
  for (uint16_t group = pipeline->containing_group[range]; group != UINT16_MAX;
       group = context->fast->groups[group].parent) {
    const shell_group_t *compound = &context->fast->groups[group];
    uint32_t last =
        (uint32_t)compound->first_command + compound->command_count - 1u;
    if (context->fast->cmds[last].start >= read->start + read->len)
      return false;
    successor = pipeline->group_successor[group];
    if (successor == SHELL_TYPE_AND || successor == SHELL_TYPE_OR ||
        compound->pipeline_negation_count != 0)
      return true;
    if (successor != SHELL_TYPE_SIMPLE)
      return false;
  }
  return false;
}

/* Emit read's selected input through the same deferred resources as ordinary
 * body I/O. A captured allocation keeps its argument's name even when redirects
 * subsequently reassign that variable. An empty scalar leaves a literal FD,
 * published numerically. A selected auxiliary FD is a real use, unlike an
 * unreferenced allocation or undo save. */
static SHELL_NONNULL(1, 3, 4, 5, 6, 7) bool dep_publish_read_inputs(
    shell_dep_graph_t *graph, uint32_t max_edges,
    dep_route_workspace_t *workspace, dep_subgraph_streams_t *streams,
    const dep_parse_context_t *context, const bool *eligible,
    bool *used_documents) {
  dep_stream_use_t *keys = workspace->import_join.endpoints;
  shell_avl_node_t *index = workspace->import_join.endpoint_index;
  uint32_t count = 0, key_root = 0;
  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!eligible[owner] || graph->nodes[owner].type != SHELL_NODE_CMD)
      continue;
    const dep_read_plan_t *plan =
        &workspace->snapshot_sources[context->snapshot->prepared_source[owner]]
             .read;
    if (!plan->active)
      continue;
    dep_route_iterator_t iterator =
        dep_route_iterator(&workspace->owner_route_state[owner]);
    uint32_t root;
    while (dep_route_next(&iterator, &workspace->journal, &root)) {
      dep_route_state_t state = dep_route_state_single(root);
      dep_read_versions_t observations;
      dep_read_result_t result =
          dep_read_evaluate(plan, &state, &workspace->journal, &observations,
                            workspace->read_frontiers);
      if (result.exhausted)
        return false;
      if ((result.descriptor_missing || result.shell_error) &&
          !dep_read_status_consumed(context, owner))
        workspace->journal.unmodeled = true;
      for (uint32_t selection = 0; selection <= plan->count; selection++) {
        if (!(result.input & (UINT64_C(1) << selection)))
          continue;
        state = observations.inputs[selection];
        dep_fd_ref_t display;
        dep_fd_ref_t physical = dep_read_descriptor(
            plan, &state, selection, &workspace->journal, &display);
        dep_route_set_t routes = dep_fd_fact(&state, &workspace->journal,
                                             physical, DEP_FD_ACCESS_READ);
        if (routes.truncated)
          return false;
        for (uint32_t choice = 0; choice < routes.count; choice++) {
          dep_fd_route_t route = routes.routes[choice];
          bool retained = true;
          if (route.kind == DEP_ROUTE_CLOSED ||
              route.kind == DEP_ROUTE_ABSENT ||
              route.kind == DEP_ROUTE_UNAVAILABLE)
            continue;
          if (dep_route_foreign(route, streams->depth))
            retained = dep_record_fd_import_use(streams, owner, display,
                                                DEP_FD_ACCESS_READ, route);
          else if (route.kind == DEP_ROUTE_INHERITED ||
                   route.kind == DEP_ROUTE_NULL_INPUT)
            retained = dep_record_external_use(streams, owner, display,
                                               DEP_FD_ACCESS_READ, route.value);
          else if (route.kind == DEP_ROUTE_CAPTURE)
            retained = dep_record_actual_capture(
                streams, owner, display, DEP_FD_ACCESS_READ,
                dep_resource_index(route.value));
          else if (dep_route_pipe(workspace, route) != UINT32_MAX) {
            const shell_dep_edge_t *pipe =
                &workspace->pipes[dep_route_pipe(workspace, route)];
            /* An enclosing group may already expose this same pipe side for
             * ordinary members. Keep a selected auxiliary use distinct, but
             * do not duplicate its aggregate fd-0 relation on a read member. */
            if (graph->nodes[pipe->to].type == SHELL_NODE_GROUP &&
                workspace->generic_read[pipe->to] &&
                display.value == pipe->target_fd)
              continue;
            retained = dep_record_stream_use(
                streams->pipe_uses, &streams->pipe_use_count,
                streams->pipe_index, &streams->pipe_root, owner, display,
                DEP_FD_ACCESS_READ, pipe->to);
          } else {
            if ((route.kind != DEP_ROUTE_DOC &&
                 route.kind != DEP_ROUTE_DYNAMIC) ||
                dep_resource_index(route.value) >=
                    workspace->original_edge_count)
              return false;
            const shell_dep_edge_t *original =
                &workspace->original_edges[dep_resource_index(route.value)];
            if (graph->nodes[original->to].type == SHELL_NODE_GROUP &&
                workspace->generic_read[original->to] &&
                display.value != SHELL_DEP_FD_NAMED &&
                display.value == original->target_fd &&
                dep_route_owned_by_enclosing_group(
                    graph, context->fast, &context->execution->pipeline,
                    context->node_range, context->node_group, owner, original))
              continue;
            uint32_t from = original->from;
            shell_dep_edge_type_t type = route.kind == DEP_ROUTE_DOC
                                             ? SHELL_EDGE_READ
                                             : SHELL_EDGE_SUBST;
            if (type == SHELL_EDGE_READ &&
                graph->nodes[from].type != SHELL_NODE_DOC)
              from = original->to;
            uint32_t before = count;
            if (!dep_record_stream_use(keys, &count, index, &key_root, owner,
                                       display, DEP_FD_ACCESS_READ, from))
              return false;
            used_documents[dep_resource_index(route.value)] |=
                original->to == owner && original->target_fd == display.value &&
                (display.value != SHELL_DEP_FD_NAMED ||
                 dep_fd_ref_equal(
                     (dep_fd_ref_t){.name = original->target_fd_name,
                                    .value = original->target_fd,
                                    .name_len = original->target_fd_name_len},
                     display));
            if (count == before)
              continue;
            retained = dep_add_resolved_edge_refs(
                graph, max_edges, from, owner, type,
                dep_fd_numeric(type == SHELL_EDGE_READ ? SHELL_DEP_FD_NONE
                                                       : original->source_fd),
                display, SHELL_DEP_EDGE_FLAG_NONE);
          }
          if (!retained)
            return false;
        }
      }
    }
  }
  return true;
}

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
  memset(workspace->scoped_state_active, 0,
         sizeof(workspace->scoped_state_active));
  memset(workspace->group_state_ready, 0, sizeof(workspace->group_state_ready));
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
  memset(workspace->owner_route_state, 0, sizeof(workspace->owner_route_state));
  memset(workspace->owner_local_state, 0, sizeof(workspace->owner_local_state));
  /* Construction imported this parse's entry (dep_snapshot_frame_initialize).
   */
  workspace->persistent_route_state = dep_snapshot_alternatives(
      &workspace->snapshot_tables[context->snapshot->persistent[0]]);
  workspace->entry_route_state = workspace->persistent_route_state;
  workspace->persistent_time_routes = dep_time_report_for_fd2(
      &workspace->persistent_route_state, &workspace->journal);
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
  bool setup_only_edges[SHELL_DEP_MAX_EDGES] = {false};
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
  const dep_ordered_owner_t *control_events = context->snapshot->owners;
  const uint32_t *control_previous = context->snapshot->previous_same_scope;
  uint32_t control_count = context->snapshot->owner_count;
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
        if (!dep_complete_route_group(workspace, context, completed))
          return SHELL_DEP_ETRUNC;
      }
      (void)source_event;
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
    if (dep_coverage_effects_blocked(context, owner_order[owner_index].start))
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
    workspace->owner_use_count[owner] = 0;
    workspace->route_standard_mask[owner] = 0;
    if (owner_execution == DEP_EXECUTION_NEVER) {
      /* Syntax owners stay in the graph, but no descriptor setup, expansion
       * resource, publication, or timer report executes at this entry. */
      workspace->time_reports[owner] =
          (dep_route_set_t){.routes = {{DEP_ROUTE_UNAVAILABLE, UINT32_MAX}},
                            .count = 1,
                            .ready = true};
      continue;
    }
    workspace->journal.diagnostic_owner = owner;
    bool one_shot_scope = false;
    int32_t named_scope =
        dep_owner_named_scope(graph, fast, pipeline, group_exec, node_range,
                              node_group, owner, &one_shot_scope);
    int32_t enclosing_group = dep_owner_enclosing_group(
        graph, fast, pipeline, node_range, node_group, owner);
    if (named_scope >= 0) {
      if (!workspace->scoped_state_active[named_scope]) {
        workspace->scoped_state_active[named_scope] = true;
        bool effective_parent = enclosing_group >= 0 &&
                                workspace->group_state_ready[enclosing_group];
        int32_t report_parent =
            dep_named_scope_parent(fast, group_exec, (uint32_t)named_scope);
        workspace->scoped_route_state[named_scope] =
            effective_parent ? workspace->group_route_state[enclosing_group]
            : report_parent >= 0 &&
                    workspace->scoped_time_routes_ready[report_parent]
                ? workspace->scoped_route_state[report_parent]
                : workspace->persistent_route_state;
        workspace->scoped_time_routes[named_scope] = dep_time_report_for_fd2(
            &workspace->scoped_route_state[named_scope], &workspace->journal);
        workspace->scoped_time_routes_ready[named_scope] = true;
      }
    }
    bool publishes_to_group = enclosing_group >= 0 &&
                              !(graph->nodes[owner].type == SHELL_NODE_GROUP &&
                                group_exec[node_group[owner]].isolated);
    /* Construction interpreted this owner (dep_snapshot_complete_owner).
     * Publication reads its records: the entry after the assignment phase,
     * the state its redirections start from, its executed state, and its
     * prepared operations in their effective form. */
    const dep_snapshot_frame_t *frame = context->snapshot;
    uint32_t source_event = dep_owner_event(context, owner);
    dep_route_state_t selected_state = frame->event_entry[source_event];
    dep_snapshot_source_t *stdin_source;
    if (!dep_snapshot_fd_operations(graph, context, owner, &stdin_source))
      return SHELL_DEP_EPARSE;
    /* `exec` changes its current shell's descriptor table whenever it runs.
     * In a conditional list that table is only available to a proven `&&`
     * success continuation; it must not be promoted into `persistent`. */
    bool descriptor_exec = graph->nodes[owner].type == SHELL_NODE_CMD &&
                           dep_owner_exec(context, owner)->persistent_redirects;
    dep_snapshot_operation_range(stdin_source, stdin_source->op_root, 0,
                                 UINT32_MAX, ops, NULL, &op_count);
    uint32_t reached_op_count = 0;
    while (reached_op_count < op_count &&
           ops[reached_op_count].pos < context->owner_setup_stop[owner])
      reached_op_count++;
    dep_route_state_t local_route_state = frame->event_executed[source_event];
    dep_mark_dynamic_process_edges(
        process_routes, owner, stdin_source, context->owner_setup_stop[owner],
        (graph->nodes[owner].type == SHELL_NODE_CMD &&
         node_range[owner] != UINT32_MAX && node_range[owner] < fast->count) ||
            (graph->nodes[owner].type == SHELL_NODE_GROUP &&
             node_group[owner] != UINT32_MAX),
        dynamic_route_edges);
    dep_prepare_fd_close_history(ops, op_count);
    if (graph->nodes[owner].type == SHELL_NODE_GROUP &&
        node_group[owner] != UINT32_MAX &&
        !dep_redirect_frame_record(
            &workspace->group_redirect_frames[node_group[owner]], ops,
            op_count))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    /* Setup has already run in the journal. This pass records only observable
     * transition metadata; replaying physical descriptor state here would
     * lose scratch saves and correlated allocation alternatives. */
    for (uint32_t op = 0; op < reached_op_count; op++) {
      dep_fd_op_t *item = &ops[op];
      if (item->kind == DEP_FD_OP_DOCUMENT && item->fd == SHELL_DEP_FD_NAMED)
        reached_named_opens[item->edge_index] = true;
      if (item->kind == DEP_FD_OP_IDENTITY || dep_fd_op_numeric_self_dup(item))
        continue;
      /* An explicit close affects this command even when it is not a
       * persistent `exec` transition. Preserve that real I/O state in the
       * graph; ordinary nonpersistent duplications still need no setup edge
       * beyond their routing effect. */
      if (item->kind == DEP_FD_OP_CLOSE ||
          (dep_fd_op_copies(item->kind) &&
           (item->kind == DEP_FD_OP_MOVE || item->fd == SHELL_DEP_FD_NAMED ||
            descriptor_exec))) {
        if (fd_transition_count >= SHELL_DEP_MAX_EDGES)
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        else
          fd_transitions[fd_transition_count++] =
              (dep_fd_transition_t){owner, *item};
      }
      if (item->kind == DEP_FD_OP_MOVE) {
        if (fd_transition_count == SHELL_DEP_MAX_EDGES)
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        else
          fd_transitions[fd_transition_count++] =
              (dep_fd_transition_t){owner, dep_fd_move_close(item)};
      }
    }
    bool precise_input =
        graph->nodes[owner].type == SHELL_NODE_CMD && stdin_source->read.active;
    if (descriptor_exec || precise_input ||
        (graph->nodes[owner].type == SHELL_NODE_CMD &&
         graph->nodes[owner].cmd.token_count == 0)) {
      for (uint32_t op = 0; op < reached_op_count; op++)
        if ((ops[op].kind == DEP_FD_OP_DOCUMENT ||
             ops[op].kind == DEP_FD_OP_DYNAMIC) &&
            ops[op].fd != SHELL_DEP_FD_NAMED &&
            ops[op].edge_index < original_edge_count) {
          const shell_dep_edge_t *original =
              &original_edges[ops[op].edge_index];
          /* A null command installs process descriptors without transferring
           * body bytes. FILE/document redirects keep their setup effects. */
          if (descriptor_exec || original->type == SHELL_EDGE_SUBST ||
              (!precise_input &&
               graph->nodes[original->to].type == SHELL_NODE_ENDPOINT))
            setup_only_edges[ops[op].edge_index] = true;
        }
    }
    dep_route_state_t *scope_route_state =
        publishes_to_group ? &workspace->group_route_state[enclosing_group]
        : named_scope >= 0 ? &workspace->scoped_route_state[named_scope]
                           : &workspace->persistent_route_state;
    dep_route_state_t owner_time_state = selected_state;
    dep_route_state_t incoming_time_context = selected_state;
    /* Byte-use selection is distinct from setup replacement. A numeric close
     * removes a previous explicit use; a named allocation never adds one just
     * because its backing slot happens to have that numeric identity. Uses
     * are recorded against the owner's final local state. */
    const dep_route_journal_t *use_journal = &workspace->journal;
    for (uint32_t op = 0; op < reached_op_count; op++) {
      const dep_fd_op_t *item = ops + op;
      if (item->fd <= SHELL_DEP_FD_MAX)
        dep_owner_use(
            workspace, owner, &local_route_state, use_journal, item->fd,
            item->kind == DEP_FD_OP_CLOSE ? 0 : DEP_FD_ACCESS_BOTH, true);
      else if (item->kind == DEP_FD_OP_CLOSE) {
        uint32_t allocation = dep_allocation_slot(&workspace->journal, item);
        if (allocation == SHELL_DEP_FD_NONE)
          return SHELL_DEP_ETRUNC;
        const dep_allocation_t *saved =
            &workspace->journal.arena
                 ->allocations[allocation - SHELL_DEP_FD_MAX - 1];
        const dep_route_set_t *slots =
            &workspace->journal.arena->snapshots[saved->closed_slots - 1];
        /* A close of one of several places removes none of their uses: each
         * keeps it on the paths where the descriptor was elsewhere. */
        if (slots->count == 1 && slots->routes[0].kind == DEP_ROUTE_ALIAS)
          dep_owner_use(workspace, owner, &local_route_state, use_journal,
                        slots->routes[0].value, 0, true);
      }
      if (item->kind == DEP_FD_OP_MOVE && !dep_fd_op_numeric_self_dup(item) &&
          item->target_fd <= SHELL_DEP_FD_MAX)
        dep_owner_use(workspace, owner, &local_route_state, use_journal,
                      item->target_fd, 0, true);
    }
    for (uint32_t fd = 0; fd < 3; fd++)
      dep_owner_use(workspace, owner, &local_route_state, use_journal, fd, 0,
                    false);
    workspace->owner_local_state[owner] = local_route_state;
    if (graph->nodes[owner].type == SHELL_NODE_GROUP &&
        !dep_redirect_frame_aliases(
            &workspace->group_redirect_frames[node_group[owner]],
            &workspace->journal, ops, reached_op_count))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    /* Success continuations retain exec mutations and named allocations,
     * but never numeric command-local redirects. Replay locally first so a
     * persistent allocation may copy a temporary descriptor in this list. */
    /* Deferred byte/report publication still needs this completed setup after
     * continuation cleanup. Register its lifetime before cleanup can collect
     * the journal, not after it has returned a different continuation. */
    if (!dep_retain_owner_io(workspace, context, graph, &local_route_state,
                             owner))
      return SHELL_DEP_ETRUNC;
    if (!dep_route_state_publish(&owner_time_state, &workspace->journal,
                                 &local_route_state, ops, reached_op_count,
                                 descriptor_exec, NULL))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    uint32_t report_boundary = target_time_boundary[owner];
    bool report_owns_scope =
        report_boundary != 0 &&
        (!one_shot_scope || time_boundaries[report_boundary - 1].target_scope);
    if (report_owns_scope)
      owner_time_state = frame->event_report[source_event];
    if (source_event >= SHELL_MAX_GROUPS) {
      /* This selected version, not an eager union of success, failure and
       * stopped paths: the next owner selects its own connector outcomes. */
      *scope_route_state = dep_fd_point_version(
          &frame->event_scope[source_event], &selected_state);
    }
    if (graph->nodes[owner].type == SHELL_NODE_GROUP) {
      uint32_t group = node_group[owner];
      /* Preserve the full effective table. The group-tail routes may be
       * copied by a later in-body exec even though their byte-flow edge
       * belongs to the group endpoint, not every child. */
      workspace->group_state_ready[group] = true;
      workspace->group_route_state[group] = local_route_state;
      workspace->group_time_routes[group] = dep_time_report_for_fd2(
          &workspace->group_route_state[group], &workspace->journal);
      workspace->group_time_routes_ready[group] = true;
      active_groups[active_group_count++] = group;
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
      uint32_t boundary = target_time_boundary[owner];
      bool needs_shell_report_state =
          boundary != 0 && time_boundaries[boundary - 1].target_shell_state;
      if (needs_shell_report_state) {
        workspace->group_shell_route_state[group] = owner_time_state;
        workspace->group_shell_time_routes[group] = dep_time_report_for_fd2(
            &workspace->group_shell_route_state[group], &workspace->journal);
        workspace->group_shell_time_routes_ready[group] = true;
      }
    }
    if (!descriptor_exec && graph->nodes[owner].type == SHELL_NODE_CMD) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
      if (target_time_boundary[owner] != 0 &&
          !workspace->time_reports[owner].ready)
        workspace->time_reports[owner] = dep_time_report_for_fd2(
            report_owns_scope ? &owner_time_state : &incoming_time_context,
            &workspace->journal);
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
        dep_route_set_t reports =
            dep_time_report_for_fd2(&owner_time_state, &workspace->journal);
        workspace->time_reports[owner] = reports;
      }
    }

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
      dep_fd_route_t route = dep_owner_state_route(
          &local_route_state, &workspace->journal, fd,
          input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE);
      if (route.kind == DEP_ROUTE_DOC &&
          !dep_route_foreign(route, workspace->journal.depth) &&
          dep_resource_index(route.value) == edge)
        owner_edges->effective_document[edge] = true;
    }

    if (!one_shot_scope) {
      dep_route_set_t *scope_reports =
          publishes_to_group ? &workspace->group_time_routes[enclosing_group]
          : named_scope >= 0 ? &workspace->scoped_time_routes[named_scope]
                             : &workspace->persistent_time_routes;
      *scope_reports =
          dep_time_report_for_fd2(scope_route_state, &workspace->journal);
    }
  }
  while (active_group_count) {
    uint32_t completed = active_groups[--active_group_count];
    if (!dep_complete_route_group(workspace, context, completed))
      return SHELL_DEP_ETRUNC;
  }

  dep_capture_due_time_reports(workspace, time_boundaries, time_boundary_count,
                               &time_boundary_cursor, UINT32_MAX);

  bool external_eligible[SHELL_DEP_MAX_NODES] = {false};
  memset(workspace->generic_read, 0, sizeof(workspace->generic_read));
  memset(workspace->test_body, 0, sizeof(workspace->test_body));
  for (uint32_t owner = 0; owner < graph->node_count; owner++)
    if (resolved_owner[owner]) {
      external_eligible[owner] = dep_owner_has_body_io(
          graph, context, owner,
          control_execution[owner] != DEP_EXECUTION_NEVER);
      if (graph->nodes[owner].type == SHELL_NODE_CMD)
        workspace->test_body[owner] =
            workspace
                ->snapshot_sources[context->snapshot->prepared_source[owner]]
                .test != NULL;
      if (graph->nodes[owner].type == SHELL_NODE_CMD &&
          !workspace->test_body[owner] &&
          !workspace
               ->snapshot_sources[context->snapshot->prepared_source[owner]]
               .read.active) {
        workspace->generic_read[owner] = external_eligible[owner];
        int32_t group = dep_range_group(pipeline, node_range[owner]);
        if (group >= 0)
          workspace->generic_read[group_node[group]] |=
              workspace->generic_read[owner];
      }
    }
  for (uint32_t group = fast->group_count; group-- > 0;) {
    uint32_t parent = fast->groups[group].parent;
    if (group_node[group] != UINT32_MAX && parent != UINT16_MAX &&
        group_node[parent] != UINT32_MAX)
      workspace->generic_read[group_node[parent]] |=
          workspace->generic_read[group_node[group]];
  }
  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!local_owner[owner] || graph->nodes[owner].type != SHELL_NODE_CMD)
      continue;
    shell_dep_cmd_t *command = &graph->nodes[owner].cmd;
    command->pipe_stdin_source = UINT32_MAX;
    command->pipe_stdin_target = UINT32_MAX;
    command->pipe_stdout_source = UINT32_MAX;
    command->pipe_stdout_target = UINT32_MAX;
    const dep_route_state_t *state = &workspace->owner_local_state[owner];
    dep_fd_route_t input = dep_owner_state_route(
        state, &workspace->journal, dep_fd_numeric(0), DEP_FD_ACCESS_READ);
    dep_fd_route_t output = dep_owner_state_route(
        state, &workspace->journal, dep_fd_numeric(1), DEP_FD_ACCESS_WRITE);
    uint32_t input_pipe = dep_route_pipe(workspace, input);
    uint32_t output_pipe = dep_route_pipe(workspace, output);
    if (input_pipe != UINT32_MAX) {
      command->pipe_stdin_source = pipes[input_pipe].from;
      command->pipe_stdin_target = pipes[input_pipe].to;
    }
    if (output_pipe != UINT32_MAX) {
      command->pipe_stdout_source = pipes[output_pipe].from;
      command->pipe_stdout_target = pipes[output_pipe].to;
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
  bool read_documents[SHELL_DEP_MAX_EDGES] = {false};
  if (!dep_publish_read_inputs(graph, max_edges, workspace, streams, context,
                               external_eligible, read_documents))
    return SHELL_DEP_ETRUNC;

  /* Descriptor duplication and close are shell setup operations. A symbolic
   * descriptor has no fixed numeric byte route until a later use, while a
   * persistent numeric `exec` operation changes the shell's later FD state.
   * Both remain visible without pretending that setup transfers bytes. */
  for (uint32_t transition = 0; transition < fd_transition_count;
       transition++) {
    const dep_fd_transition_t *item = &fd_transitions[transition];
    dep_fd_ref_t source = {.name = item->op.fd_name,
                           .value = item->op.fd,
                           .name_len = item->op.fd_name_len};
    if (item->op.kind == DEP_FD_OP_CLOSE) {
      dep_add_resolved_edge_refs(
          graph, max_edges, item->owner, item->owner, SHELL_EDGE_FD_CLOSE,
          source, dep_fd_numeric(SHELL_DEP_FD_NONE), SHELL_DEP_EDGE_FLAG_NONE);
    } else {
      dep_add_resolved_edge_refs(
          graph, max_edges, item->owner, item->owner, SHELL_EDGE_FD_OPEN,
          (dep_fd_ref_t){.name = item->op.target_fd_name,
                         .value = item->op.target_fd,
                         .name_len = item->op.target_fd_name_len},
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
        graph->nodes[document].type != SHELL_NODE_DOC)
      continue;

    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_EDGES);
    const char *spelling = dep_document_source(&graph->nodes[document]);
    if (spelling &&
        (uint32_t)(spelling - cmd) >= context->owner_setup_stop[owner])
      continue;
    if (context->owner_setup_stop[owner] == UINT32_MAX &&
        owner_edges->effective_document[edge] && !setup_only_edges[edge] &&
        (original->type != SHELL_EDGE_READ || workspace->generic_read[owner] ||
         !external_eligible[owner]) &&
        !(graph->nodes[owner].type == SHELL_NODE_CMD &&
          graph->nodes[owner].cmd.kind != SHELL_COMMAND_SIMPLE)) {
      /* An argv-less stage has no body. Its explicit document binding still
       * represents reached redirect setup, unlike an inherited default use. */
      if (!external_eligible[owner])
        dep_add_resolved_edge_refs(
            graph, max_edges, original->from, original->to, original->type,
            (dep_fd_ref_t){.name = original->source_fd_name,
                           .value = original->source_fd,
                           .name_len = original->source_fd_name_len},
            (dep_fd_ref_t){.name = original->target_fd_name,
                           .value = original->target_fd,
                           .name_len = original->target_fd_name_len},
            original->flags);
      continue;
    }
    if (read_documents[edge])
      continue;
    uint8_t flags = original->type == SHELL_EDGE_APPEND
                        ? SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND
                        : SHELL_DEP_EDGE_FLAG_NONE;
    if (original->type == SHELL_EDGE_READ) {
      dep_add_resolved_edge_refs(
          graph, max_edges, document, owner, SHELL_EDGE_FD_OPEN,
          dep_fd_numeric(SHELL_DEP_FD_NONE),
          (dep_fd_ref_t){.name = original->target_fd_name,
                         .value = original->target_fd,
                         .name_len = original->target_fd_name_len},
          flags);
    } else {
      dep_add_resolved_edge_refs(
          graph, max_edges, owner, document, SHELL_EDGE_FD_OPEN,
          (dep_fd_ref_t){.name = original->source_fd_name,
                         .value = original->source_fd,
                         .name_len = original->source_fd_name_len},
          dep_fd_numeric(SHELL_DEP_FD_NONE), flags);
    }
  }

  /* Persistent exec and null-command process descriptors are setup. Keep
   * their endpoint relation without claiming that a body transferred bytes. */
  for (uint32_t edge = 0; edge < original_edge_count; edge++) {
    const shell_dep_edge_t *original = &original_edges[edge];
    bool precise_group_input =
        original->type == SHELL_EDGE_SUBST &&
        original->target_fd != SHELL_DEP_FD_NONE &&
        graph->nodes[original->to].type == SHELL_NODE_GROUP &&
        resolved_owner[original->to] &&
        !workspace->generic_read[original->to] &&
        control_execution[original->to] != DEP_EXECUTION_NEVER;
    if ((!setup_only_edges[edge] && !precise_group_input) ||
        read_documents[edge])
      continue;
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
          (dep_fd_ref_t){.name = original->source_fd_name,
                         .value = original->source_fd,
                         .name_len = original->source_fd_name_len},
          (dep_fd_ref_t){.name = original->target_fd_name,
                         .value = original->target_fd,
                         .name_len = original->target_fd_name_len},
          SHELL_DEP_EDGE_FLAG_NONE);
    }
  }

  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!external_eligible[owner])
      continue;
    for (uint32_t use = 0; use < workspace->owner_use_count[owner]; use++) {
      dep_fd_ref_t fd = dep_fd_numeric(workspace->owner_uses[owner][use].fd);
      dep_fd_access_t touched =
          (dep_fd_access_t)workspace->owner_uses[owner][use].touched;
      for (uint32_t access = 0; access < 2; access++) {
        if ((access == 0 && !workspace->generic_read[owner]) ||
            (workspace->test_body[owner] && fd.value != 2))
          continue;
        dep_route_state_t owner_state = workspace->owner_route_state[owner];
        dep_fd_access_t direction =
            access == 0 ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE;
        dep_route_set_t alternatives = dep_route_state_get_access(
            &owner_state, &workspace->journal, fd, direction);
        if (alternatives.truncated)
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        for (uint32_t alternative = 0; alternative < alternatives.count;
             alternative++) {
          dep_fd_route_t route = alternatives.routes[alternative];
          if (dep_route_foreign(route, streams->depth)) {
            /* Standard streams are implicit uses. Auxiliary descriptors only
             * transfer bytes when this owner explicitly redirects them. Do
             * this after replay so replaced or closed aliases emit no flow. */
            if ((fd.value <= 2 || (touched & direction) != 0) &&
                !dep_record_fd_import_use(streams, owner, fd, direction, route))
              graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            continue;
          }
          if (route.kind == DEP_ROUTE_CAPTURE) {
            if ((fd.value <= 2 || (touched & direction) != 0) &&
                !dep_record_stream_use(
                    streams->capture_uses, &streams->capture_use_count,
                    streams->capture_index, &streams->capture_root, owner, fd,
                    direction, dep_resource_index(route.value)))
              graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            continue;
          }
          if (route.kind != DEP_ROUTE_DOC && route.kind != DEP_ROUTE_DYNAMIC)
            continue;
          /* Allocation backing slots are descriptor state, not implicit byte
           * uses. As with imported/capture routes, only standard streams or
           * explicitly redirected auxiliary descriptors transfer bytes. */
          if (fd.value > 2 && (touched & direction) == 0)
            continue;
          uint32_t original_edge = dep_resource_index(route.value);
          if (original_edge >= original_edge_count) {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            continue;
          }
          const shell_dep_edge_t *original = &original_edges[original_edge];
          if ((touched & direction) == 0 &&
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
          if (setup_only_edges[original_edge] &&
              ((original->from == owner || original->to == owner) ||
               fd.value > 2))
            continue;
          if (route.kind == DEP_ROUTE_DOC &&
              (original->type == SHELL_EDGE_READ ||
               (original->type == SHELL_EDGE_FD_OPEN &&
                original->target_fd == SHELL_DEP_FD_NAMED))) {
            dep_add_resolved_edge_refs(
                graph, max_edges, original->from, owner, SHELL_EDGE_READ,
                dep_fd_numeric(SHELL_DEP_FD_NONE), fd, resolved_flags);
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
                graph, max_edges, owner, original->to, type, fd,
                dep_fd_numeric(SHELL_DEP_FD_NONE), resolved_flags);
          } else if (original->type == SHELL_EDGE_SUBST ||
                     (original->type == SHELL_EDGE_FD_OPEN &&
                      original->target_fd == SHELL_DEP_FD_NAMED)) {
            dep_add_resolved_edge_refs(
                graph, max_edges, original->from, owner, SHELL_EDGE_SUBST,
                dep_fd_numeric(original->source_fd), fd, resolved_flags);
          } else {
            shell_dep_edge_type_t type = original->type == SHELL_EDGE_FD_OPEN
                                             ? SHELL_EDGE_WRITE
                                             : original->type;
            dep_add_resolved_edge_refs(
                graph, max_edges, owner, original->to, type, fd,
                dep_fd_numeric(SHELL_DEP_FD_NONE), resolved_flags);
          }
        }
      }
    }
  }

  if (!dep_publish_diagnostics(graph, max_edges, workspace, streams,
                               &context->snapshot->diagnostics))
    return SHELL_DEP_ETRUNC;

  workspace->time_pipe_target_count = 0;
  for (uint32_t pipe = 0; pipe < pipe_count; pipe++) {
    const shell_dep_edge_t *original = &pipes[pipe];
    dep_stream_use_t *sources = workspace->import_join.endpoints;
    dep_stream_use_t *targets = workspace->import_join.pipe_targets;
    shell_avl_node_t *source_index = workspace->import_join.endpoint_index;
    shell_avl_node_t *target_index = workspace->import_join.pipe_target_index;
    uint32_t source_root = 0, target_root = 0;
    uint32_t source_count = 0, target_count = 0;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
         access <<= 1) {
      uint32_t owner =
          access == DEP_FD_ACCESS_READ ? original->to : original->from;
      dep_stream_use_t *uses = access == DEP_FD_ACCESS_READ ? targets : sources;
      uint32_t *count =
          access == DEP_FD_ACCESS_READ ? &target_count : &source_count;
      shell_avl_node_t *index =
          access == DEP_FD_ACCESS_READ ? target_index : source_index;
      uint32_t *root =
          access == DEP_FD_ACCESS_READ ? &target_root : &source_root;
      dep_route_state_t alternatives = workspace->owner_route_state[owner];
      /* A pipeline installs a real descriptor connection even for a null
       * stage. Retain that setup topology, but no default body stream. */
      bool pipe_binding =
          external_eligible[owner] ||
          (resolved_owner[owner] &&
           control_execution[owner] != DEP_EXECUTION_NEVER &&
           graph->nodes[owner].type == SHELL_NODE_CMD &&
           graph->nodes[owner].cmd.token_count == 0 &&
           graph->nodes[owner].cmd.kind == SHELL_COMMAND_SIMPLE);
      if (access == DEP_FD_ACCESS_READ && !workspace->generic_read[owner] &&
          graph->nodes[owner].type != SHELL_NODE_CMD)
        pipe_binding = false;
      if (access == DEP_FD_ACCESS_READ &&
          graph->nodes[owner].type == SHELL_NODE_CMD &&
          graph->nodes[owner].cmd.token_count &&
          !workspace->generic_read[owner])
        pipe_binding = false;
      for (uint32_t use = 0;
           pipe_binding && context->owner_setup_stop[owner] == UINT32_MAX &&
           use < workspace->owner_use_count[owner];
           use++) {
        const dep_owner_use_t *item = &workspace->owner_uses[owner][use];
        if (empty_timing_owner[owner] ||
            (workspace->test_body[owner] && item->fd != 2) ||
            (item->fd > 2 && (item->touched & access) == 0))
          continue;
        dep_route_set_t choices = dep_route_state_get_access(
            &alternatives, &workspace->journal, dep_fd_numeric(item->fd),
            (dep_fd_access_t)access);
        for (uint32_t choice = 0; choice < choices.count; choice++)
          if (dep_route_pipe(workspace, choices.routes[choice]) == pipe &&
              !dep_record_stream_use(uses, count, index, root, owner,
                                     dep_fd_numeric(item->fd),
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
          /* A terminal is retained only with its first producer. Reserve
           * both graph entries before publishing either one or its timing
           * target; later producers can fail without orphaning the node. */
          if (graph->node_count >= max_nodes ||
              graph->edge_count >= max_edges) {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
            if (graph->nodes[sources[out].owner].type == SHELL_NODE_TIME)
              graph->nodes[sources[out].owner].time.report_route_flags |=
                  SHELL_TIME_REPORT_ROUTE_UNKNOWN;
            continue;
          }
          terminal = graph->node_count++;
          graph->nodes[terminal].type = SHELL_NODE_ENDPOINT;
          graph->nodes[terminal].endpoint.reserved = DEP_ENDPOINT_TERMINAL_PIPE;
          dep_add_resolved_edge_refs(
              graph, max_edges, sources[out].owner, terminal, SHELL_EDGE_PIPE,
              dep_stream_fd(&sources[out]), dep_fd_numeric(0),
              SHELL_DEP_EDGE_FLAG_NONE);
          if (workspace->time_pipe_target_count < SHELL_DEP_MAX_EDGES) {
            workspace->time_pipe_targets[workspace->time_pipe_target_count++] =
                (dep_stream_use_t){terminal, 0,    pipe, DEP_FD_ACCESS_READ,
                                   false,    NULL, 0};
            workspace->time_pipe_count[pipe]++;
          } else {
            graph->status |= SHELL_DEP_STATUS_TRUNCATED;
          }
        } else
          complete = dep_add_resolved_edge_refs(
              graph, max_edges, sources[out].owner, terminal, SHELL_EDGE_PIPE,
              dep_stream_fd(&sources[out]), dep_fd_numeric(0),
              SHELL_DEP_EDGE_FLAG_NONE);
      } else {
        for (uint32_t in = 0; in < target_count; in++)
          complete =
              dep_add_resolved_edge_refs(
                  graph, max_edges, sources[out].owner, targets[in].owner,
                  SHELL_EDGE_PIPE, dep_stream_fd(&sources[out]),
                  dep_stream_fd(&targets[in]), SHELL_DEP_EDGE_FLAG_NONE) &&
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

  /* Resolved owner tables are still live here. Reconcile group exposures
   * before charging storage for executable uses, not at root publication. */
  dep_collect_external_routes(graph, streams, workspace, external_eligible);

  dep_mark_transient_documents(
      graph, original_edges, original_edge_count,
      &context->snapshot->fd_stream.scope[0], &workspace->journal,
      workspace->named_setup_documents, workspace->live_named_documents,
      workspace->entry_route_state.root);
  streams->status = context->snapshot->fd_stream.scope[0].mask;
  if (imports && imports->observe_return &&
      !dep_observation_export(workspace, &context->snapshot->fd_stream.scope[0],
                              imports->process_capture_mask))
    return SHELL_DEP_ETRUNC;
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
  dep_fd_ref_t fds[SHELL_DEP_MAX_EDGES];
  uint32_t count;
} dep_endpoint_list_t;

static SHELL_NONNULL(1, 6, 9, 10) shell_dep_error_t shell_dep_graph_parse_impl(
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
  return dep_fd_ref_compare(dep_stream_fd(use), dep_stream_fd(key));
}

static SHELL_NONNULL(1,
                     3) int dep_external_resource_compare(const void *context,
                                                          uint32_t index,
                                                          const void *pending) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
  const dep_stream_use_t *uses = context, *a = &uses[index], *b = pending;
  if (a->anchor != b->anchor)
    return a->anchor < b->anchor ? -1 : 1;
  if (a->access != b->access)
    return a->access < b->access ? -1 : 1;
  return dep_fd_ref_compare(dep_stream_fd(a), dep_stream_fd(b));
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
    resource_root = shell_avl_insert(
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
        (graph->nodes[use->owner].type == SHELL_NODE_GROUP &&
         !use->actual_group))
      continue;
    dep_record_stream_use(scratch->endpoints, &count, scratch->endpoint_index,
                          &root, scratch->capture_endpoint[i],
                          dep_stream_fd(use), access, use->anchor);
  }
  for (uint32_t i = 0; i < count; i++) {
    endpoints->nodes[i] = scratch->endpoints[i].owner;
    endpoints->fds[i] = dep_stream_fd(&scratch->endpoints[i]);
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
                                                dep_fd_ref_t source_fd,
                                                dep_fd_ref_t target_fd,
                                                dep_subst_kind_t kind) {
  dep_add_edge(graph, from, to, SHELL_EDGE_SUBST, source_fd.value,
               target_fd.value);
  shell_dep_edge_t *edge = &graph->edges[graph->edge_count - 1];
  if (source_fd.value == SHELL_DEP_FD_NAMED)
    dep_set_named_fd(edge, true, source_fd.name, source_fd.name_len);
  if (target_fd.value == SHELL_DEP_FD_NAMED)
    dep_set_named_fd(edge, false, target_fd.name, target_fd.name_len);
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
  for (uint32_t i = 0; i < subgraph_streams->external_use_count; i++) {
    const dep_stream_use_t *use = &subgraph_streams->external_uses[i];
    dep_record_external_use(out_streams, node_offset + use->owner,
                            dep_stream_fd(use), (dep_fd_access_t)use->access,
                            use->anchor);
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
  if (streams->external_use_count >
      DEP_EXTERNAL_USE_CAPACITY - out_streams->external_use_count)
    return false;
  if (streams->fd_import_use_count > SHELL_DEP_MAX_EDGES ||
      out_streams->fd_import_use_count > SHELL_DEP_MAX_EDGES ||
      out_streams->capture_use_count > SHELL_DEP_MAX_EDGES ||
      out_streams->pipe_use_count > SHELL_DEP_MAX_EDGES)
    return false;
  /* A copied child has fresh owner indices. Each distinct use therefore
   * consumes a new metadata slot, even when it needs no public edge yet.
   * Stage imported identities as well, so a failed join never leaves copied
   * TIME nodes promising a capture or pipe route that was not retained. */
  uint32_t captures = 0, pipes = 0, foreign = 0;
  for (uint32_t i = 0; i < streams->fd_import_use_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
    const dep_fd_import_use_t *use = &streams->fd_import_uses[i];
    if (use->owner >= subgraph->node_count)
      return false;
    if (dep_resource_depth(use->route.value) != out_streams->depth) {
      foreign++;
      continue;
    }
    if (use->route.kind == DEP_ROUTE_CAPTURE) {
      captures++;
      continue;
    }
    if (use->route.kind == DEP_ROUTE_PIPE_INPUT ||
        use->route.kind == DEP_ROUTE_PIPE_OUTPUT) {
      if (dep_resource_index(use->route.value) >= out->node_count ||
          !dep_is_execution_node(out, dep_resource_index(use->route.value)))
        return false;
      pipes++;
      continue;
    }
    if ((use->route.kind != DEP_ROUTE_DOC &&
         use->route.kind != DEP_ROUTE_DYNAMIC) ||
        dep_resource_index(use->route.value) >= out->edge_count)
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
  for (uint32_t i = 0; i < subgraph_streams->fd_import_use_count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_IMPORT_USES);
    const dep_fd_import_use_t *use = &subgraph_streams->fd_import_uses[i];
    dep_fd_route_t route = use->route;
    if (node_offset > UINT32_MAX - use->owner)
      return false;
    /* A resource of an enclosing graph passes on to that graph's join. */
    if (dep_resource_depth(route.value) != out_streams->depth) {
      if (!dep_record_fd_import_use(
              out_streams, node_offset + use->owner,
              (dep_fd_ref_t){.name = use->fd_name,
                             .value = use->fd,
                             .name_len = use->fd_name_len},
              (dep_fd_access_t)use->access, route))
        return false;
      continue;
    }
    uint32_t child = node_offset + use->owner;
    if (child >= out->node_count)
      return false;
    if (route.kind == DEP_ROUTE_CAPTURE) {
      if (!dep_record_actual_capture(
              out_streams, child,
              (dep_fd_ref_t){.name = use->fd_name,
                             .value = use->fd,
                             .name_len = use->fd_name_len},
              (dep_fd_access_t)use->access, dep_resource_index(route.value)))
        return false;
      continue;
    }
    if (route.kind == DEP_ROUTE_PIPE_INPUT ||
        route.kind == DEP_ROUTE_PIPE_OUTPUT) {
      if (!dep_record_stream_use(
              out_streams->pipe_uses, &out_streams->pipe_use_count,
              out_streams->pipe_index, &out_streams->pipe_root, child,
              (dep_fd_ref_t){.name = use->fd_name,
                             .value = use->fd,
                             .name_len = use->fd_name_len},
              (dep_fd_access_t)use->access, dep_resource_index(route.value)))
        return false;
      continue;
    }
    if ((route.kind != DEP_ROUTE_DOC && route.kind != DEP_ROUTE_DYNAMIC) ||
        dep_resource_index(route.value) >= out->edge_count)
      return false;
    const shell_dep_edge_t *original =
        &out->edges[dep_resource_index(route.value)];
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
      dep_add_resolved_edge_refs(out, max_edges, original->from, child, type,
                                 dep_fd_numeric(original->source_fd),
                                 (dep_fd_ref_t){.name = use->fd_name,
                                                .value = use->fd,
                                                .name_len = use->fd_name_len},
                                 type == SHELL_EDGE_SUBST
                                     ? original->flags
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
      dep_add_resolved_edge_refs(out, max_edges, child, original->to, type,
                                 (dep_fd_ref_t){.name = use->fd_name,
                                                .value = use->fd,
                                                .name_len = use->fd_name_len},
                                 dep_fd_numeric(original->target_fd),
                                 SHELL_DEP_EDGE_FLAG_NONE);
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
    dep_subst_kind_t kind, dep_fd_ref_t producer_fd, uint32_t *route_edge) {
  bool named_setup = producer_fd.value == SHELL_DEP_FD_NAMED;
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
      (kind == DEP_SUBST_PROCESS_INPUT || kind == DEP_SUBST_PROCESS_OUTPUT ||
       kind == DEP_SUBST_PROCESS_WORD);
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
    if (route_edge)
      *route_edge = out->edge_count;
    if (kind == DEP_SUBST_PROCESS_INPUT || kind == DEP_SUBST_PROCESS_WORD) {
      return dep_add_resolved_edge_refs(
          out, max_edges, endpoint, consumer_node,
          named_setup ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_SUBST,
          dep_fd_numeric(SHELL_DEP_FD_NONE),
          kind == DEP_SUBST_PROCESS_INPUT ? producer_fd
                                          : dep_fd_numeric(SHELL_DEP_FD_NONE),
          SHELL_DEP_EDGE_FLAG_NONE);
    }
    return dep_add_resolved_edge_refs(
        out, max_edges, consumer_node, endpoint,
        named_setup ? SHELL_EDGE_FD_OPEN : SHELL_EDGE_WRITE, producer_fd,
        dep_fd_numeric(SHELL_DEP_FD_NONE), SHELL_DEP_EDGE_FLAG_NONE);
  }

  if (!needs_collector) {
    uint32_t producer = node_offset + endpoints.nodes[0];
    dep_fd_ref_t source_fd = endpoints.fds[0];
    if (route_edge)
      *route_edge = out->edge_count;
    dep_add_subst_edge(out, producer, consumer_node, source_fd,
                       kind == DEP_SUBST_PROCESS_INPUT
                           ? producer_fd
                           : dep_fd_numeric(SHELL_DEP_FD_NONE),
                       kind);
    return true;
  }

  uint32_t collector = out->node_count++;
  out->nodes[collector].type = SHELL_NODE_ENDPOINT;
  out->nodes[collector].endpoint.reserved = 0;
  if (kind == DEP_SUBST_PROCESS_OUTPUT) {
    if (route_edge)
      *route_edge = out->edge_count;
    dep_add_resolved_edge_refs(
        out, max_edges, consumer_node, collector, SHELL_EDGE_WRITE, producer_fd,
        dep_fd_numeric(SHELL_DEP_FD_NONE), SHELL_DEP_EDGE_FLAG_NONE);
    for (uint32_t i = 0; i < endpoints.count; i++)
      dep_add_subst_edge(out, collector, node_offset + endpoints.nodes[i],
                         dep_fd_numeric(SHELL_DEP_FD_NONE), endpoints.fds[i],
                         DEP_SUBST_PROCESS_OUTPUT);
  } else {
    for (uint32_t i = 0; i < endpoints.count; i++) {
      uint32_t producer = node_offset + endpoints.nodes[i];
      dep_fd_ref_t source_fd = endpoints.fds[i];
      dep_add_edge(out, producer, collector, SHELL_EDGE_WRITE, source_fd.value,
                   SHELL_DEP_FD_NONE);
      if (source_fd.value == SHELL_DEP_FD_NAMED)
        dep_set_named_fd(&out->edges[out->edge_count - 1], true, source_fd.name,
                         source_fd.name_len);
    }
    if (route_edge)
      *route_edge = out->edge_count;
    dep_add_subst_edge(
        out, collector, consumer_node, dep_fd_numeric(SHELL_DEP_FD_NONE),
        kind == DEP_SUBST_PROCESS_INPUT ? producer_fd
                                        : dep_fd_numeric(SHELL_DEP_FD_NONE),
        kind);
  }
  return true;
}

static SHELL_NONNULL(1) void dep_record_process_substitution_route(
    dep_process_route_map_t *routes, uint32_t edge, uint32_t owner,
    uint32_t position, bool input, dep_fd_ref_t fd) {
  /* Each parent-facing edge has at most one temporary creation and one
   * redirect installation, bounded by twice the graph edge capacity. */
  uint32_t slot = ++routes->count;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
  routes->entries[slot - 1] = (dep_process_route_t){
      .position = position,
      .edge = edge,
      .fd = fd,
      .access = input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE};
  if (routes->last[owner] != 0)
    routes->entries[routes->last[owner] - 1].next = slot;
  else
    routes->first[owner] = slot;
  routes->last[owner] = slot;
}

static SHELL_NONNULL(1, 5) void dep_record_process_temporary(
    dep_process_route_map_t *routes, uint32_t edge, uint32_t owner,
    uint32_t position, const char *source, bool input, bool command_word,
    bool byte_use, bool standalone, const dep_process_guard_t *guard,
    bool body_word) {
  dep_record_process_substitution_route(routes, edge, owner, position, input,
                                        dep_fd_numeric(SHELL_DEP_FD_NONE));
  dep_process_route_t *route = &routes->entries[routes->last[owner] - 1];
  route->temporary = true;
  route->source = source;
  route->guard = guard;
  route->command_word = command_word && !body_word;
  route->body_word = body_word;
  /* Body process allocations have their own post-setup phase. MAX excludes
   * them from source-position redirect checkpoints; the body cursor opens
   * them in expansion order after setup, retaining source as their identity. */
  if (body_word)
    route->position = UINT32_MAX;
  route->byte_use = byte_use;
  route->standalone = standalone;
  routes->private_edges |= standalone && !byte_use;
  for (const dep_process_guard_t *current = routes->track[owner] ? guard : NULL;
       current && !current->observed; current = current->parent)
    routes->guards[current - routes->guards].observed = true;
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
      dep_add_resolved_edge_refs(out, max_edges, offset + endpoints.nodes[i],
                                 pipe, SHELL_EDGE_WRITE, endpoints.fds[i],
                                 dep_fd_numeric(SHELL_DEP_FD_NONE),
                                 SHELL_DEP_EDGE_FLAG_NONE);
    else
      dep_add_subst_edge(out, pipe, offset + endpoints.nodes[i],
                         dep_fd_numeric(SHELL_DEP_FD_NONE), endpoints.fds[i],
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
 * input validation remains responsible for public EINPUT handling. Once graph
 * capacity has omitted setup metadata, context-dependent semantic rejection
 * cannot establish unsupported syntax or a descriptor contract violation from
 * that incomplete state. This applies during expansion/snapshot construction
 * as well as final route resolution. */
static SHELL_NONNULL(1) shell_dep_error_t
    dep_stop_graph_construction(shell_dep_graph_t *out,
                                shell_dep_error_t error) {
  if (error == SHELL_DEP_EINPUT)
    error = SHELL_DEP_EPARSE;
  if ((error == SHELL_DEP_EPARSE || error == SHELL_DEP_EUNMODELED) &&
      (out->status & SHELL_DEP_STATUS_TRUNCATED))
    error = SHELL_DEP_ETRUNC;
  out->node_count = 0;
  out->edge_count = 0;
  out->cwd_buf.len = 0;
  out->status = error == SHELL_DEP_ETRUNC ? SHELL_DEP_STATUS_TRUNCATED
                                          : SHELL_DEP_STATUS_ERROR;
  return error;
}

/* Flag the open edges of this level's documents whose fallible open a
 * descriptor use requires (dep_route_journal_t.open_causes). Causes and
 * documents are both bounded by graph capacity. */
static SHELL_NONNULL(1, 2) void dep_flag_required_opens(
    shell_dep_graph_t *graph, const dep_route_journal_t *journal) {
  bool required[SHELL_DEP_MAX_NODES] = {false}, any = false;
  for (uint32_t cause = 0; cause < journal->open_cause_count; cause++)
    any |= journal->open_cause_required[cause];
  if (!any)
    return;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    const char *source = dep_document_source(&graph->nodes[node]);
    for (uint32_t cause = 0; source && cause < journal->open_cause_count;
         cause++)
      required[node] |= journal->open_cause_required[cause] &&
                        journal->open_causes[cause] == source;
  }
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    shell_dep_edge_t *item = &graph->edges[edge];
    if ((required[item->from] || required[item->to]) &&
        (item->type == SHELL_EDGE_FD_OPEN || item->type == SHELL_EDGE_READ ||
         item->type == SHELL_EDGE_WRITE || item->type == SHELL_EDGE_APPEND))
      item->flags |= SHELL_DEP_EDGE_FLAG_REQUIRED;
  }
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
  if (shell_source_empty_process_word(target->start, target->len)) {
    /* No pathname is produced: redirect expansion is ambiguous, not an open
     * of a fictional /dev/fd/N. Earlier argv expansions still ran. */
    uint32_t position = (uint32_t)(redirect_token->start - context->cmd);
    if (!dep_owner_phase_active(context, consumer_node,
                                DEP_SNAPSHOT_REDIRECT_OPERAND, position))
      return SHELL_DEP_OK;
    uint32_t table;
    shell_dep_error_t error = dep_snapshot_phase_table(
        out, out_streams, context, consumer_node, position,
        DEP_SNAPSHOT_REDIRECT_OPERAND, &table);
    if (error != SHELL_DEP_OK)
      return error;
    if (!dep_owner_phase_active(context, consumer_node,
                                DEP_SNAPSHOT_REDIRECT_OPERAND, position))
      return SHELL_DEP_OK;
    dep_snapshot_source_t *source =
        &context->workspace->snapshot_sources
             [context->snapshot->prepared_source[consumer_node]];
    uint32_t slot = source->op_count;
    if (slot == sizeof(source->ops) / sizeof(source->ops[0]))
      return SHELL_DEP_ETRUNC;
    source->ops[source->op_count++] =
        (dep_fd_op_t){.pos = position,
                      .kind = DEP_FD_OP_FAILED,
                      .fd = SHELL_DEP_FD_NONE,
                      .target_fd = SHELL_DEP_FD_NONE,
                      .edge_index = UINT32_MAX};
    uint32_t match = 0;
    source->op_root =
        shell_avl_insert(source->op_index, source->op_root, slot + 1,
                         sizeof(source->ops) / sizeof(source->ops[0]),
                         dep_snapshot_operation_compare, source, &slot, &match);
    source->setup_may_fail = source->setup_needs_walk = true;
    source->empty_process_failure = position + 1;
    return SHELL_DEP_OK;
  }
  uint32_t position = (uint32_t)(redirect_token->start - context->cmd);
  bool active = dep_owner_phase_active(context, consumer_node,
                                       DEP_SNAPSHOT_REDIRECT_OPERAND, position);
  if (active) {
    shell_dep_error_t error =
        dep_prepare_process_tracking(out, out_streams, context, consumer_node,
                                     position, DEP_SNAPSHOT_REDIRECT_OPERAND);
    if (error != SHELL_DEP_OK)
      return error;
  }
  dep_recursive_parse_t *child = dep_recursive_parse_prepare(limits, depth + 1);
  shell_dep_graph_t *subgraph = &child->graph;
  dep_subgraph_streams_t *subgraph_streams = &child->streams;
  dep_fd_imports_t *fd_imports = &child->streams.fd_imports;
  shell_dep_error_t snapshot_error =
      !active
          ? SHELL_DEP_OK
          : dep_snapshot_fd_imports(out, out_streams, context, consumer_node,
                                    position, DEP_SNAPSHOT_REDIRECT_OPERAND,
                                    fd_imports, NULL, &active);
  if (snapshot_error != SHELL_DEP_OK)
    return snapshot_error;
  active =
      active && dep_owner_phase_active(context, consumer_node,
                                       DEP_SNAPSHOT_REDIRECT_OPERAND, position);
  if (active)
    dep_fd_import_install_capture(fd_imports, target->start[0] == '>' ? 0 : 1);
  shell_dep_error_t error = shell_dep_graph_parse_impl(
      sub_content, sub_len, cwd,
      dep_expansion_cwd_known(out, context, consumer_node),
      dep_expansion_cwd_absolute(out, context, consumer_node), limits,
      depth + 1, NULL, subgraph, subgraph_streams, fd_imports, active,
      context->resolver);
  if (error != SHELL_DEP_OK)
    return error;
  dep_import_child_coverage(out, subgraph, context, target->start, active);
  if (subgraph->node_count == 0 && !active)
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
    named_setup_fd = (dep_fd_ref_t){.name = named_fd_name,
                                    .value = SHELL_DEP_FD_NAMED,
                                    .name_len = named_fd_name_len};
    named_setup = &named_setup_fd;
  }
  uint32_t route_edge = UINT32_MAX, second_route_edge = UINT32_MAX;
  bool combined =
      redirect == DEP_REDIRECT_BOTH || redirect == DEP_REDIRECT_BOTH_APPEND;
  if ((!input && !output) || redirect == DEP_REDIRECT_READ_WRITE ||
      subgraph->node_count == 0) {
    dep_fd_access_t access =
        redirect == DEP_REDIRECT_READ_WRITE ? DEP_FD_ACCESS_BOTH
        : redirect == DEP_REDIRECT_IN       ? DEP_FD_ACCESS_READ
                                            : DEP_FD_ACCESS_WRITE;
    dep_fd_ref_t fd = named_setup
                          ? *named_setup
                          : dep_fd_numeric(combined ? 1 : redirected_fd);
    uint32_t parent_edges[3] = {UINT32_MAX, UINT32_MAX, UINT32_MAX};
    bool child_writes = target->start[0] == '<';
    bool native_marker =
        !(access & (child_writes ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE));
    if (native_marker && out->edge_count == max_edges)
      return SHELL_DEP_ETRUNC;
    if (!dep_install_process_pipe(
            out, max_nodes, max_edges - (native_marker ? 1u : 0u),
            effective_cwd_buf_size, out_streams, subgraph, subgraph_streams,
            consumer_node, child_writes, &fd, parent_edges, access, combined))
      return SHELL_DEP_ETRUNC;
    uint32_t temporary_edge = parent_edges[child_writes ? 0 : 1];
    if (native_marker) {
      const shell_dep_edge_t *opposite =
          &out->edges[parent_edges[child_writes ? 1 : 0]];
      uint32_t pipe = child_writes ? opposite->to : opposite->from;
      temporary_edge = out->edge_count;
      dep_add_edge(out, child_writes ? pipe : consumer_node,
                   child_writes ? consumer_node : pipe,
                   child_writes ? SHELL_EDGE_SUBST : SHELL_EDGE_WRITE,
                   SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
    }
    uint32_t position = (uint32_t)(target->start - context->cmd);
    dep_record_process_temporary(
        context->process_routes, temporary_edge, consumer_node, position,
        target->start, child_writes, false, false, native_marker, NULL, false);
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
        named_setup ? *named_setup : dep_fd_numeric(redirected_fd),
        &route_edge);
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
          DEP_SUBST_PROCESS_OUTPUT,
          named_setup ? *named_setup
                      : dep_fd_numeric(combined ? 1 : redirected_fd),
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
    dep_record_process_temporary(context->process_routes, route_edge,
                                 consumer_node, position, target->start,
                                 target->start[0] == '<', false, false, false,
                                 NULL, false);
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

/* Keep the existing producer/collector resource identity for the temporary
 * parent pipe end. Word expansion creates it even when its generated pathname
 * is only option data or a rejected read target, not a byte-use argument. */
static SHELL_NONNULL(1, 5, 6, 7, 8, 9) bool dep_connect_process_word(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t cwd_size, dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *child, const dep_subgraph_streams_t *streams,
    const dep_parse_context_t *context, const dep_token_t *fragment,
    uint32_t owner, dep_snapshot_phase_t phase, bool byte_use,
    const dep_process_guard_t *guard) {
  uint32_t edge = UINT32_MAX;
  bool input = fragment->start[0] == '<';
  if (child->node_count == 0) {
    dep_fd_ref_t fd = dep_fd_numeric(SHELL_DEP_FD_NONE);
    uint32_t edges[3] = {UINT32_MAX, UINT32_MAX, UINT32_MAX};
    if (!dep_install_process_pipe(
            out, max_nodes, max_edges, cwd_size, out_streams, child, streams,
            owner, input, &fd, edges,
            input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE, false))
      return false;
    edge = edges[input ? 0 : 1];
  } else if (!dep_connect_substitution(
                 out, max_nodes, max_edges, cwd_size, out_streams, child,
                 streams, owner,
                 input ? DEP_SUBST_PROCESS_WORD : DEP_SUBST_PROCESS_OUTPUT,
                 dep_fd_numeric(input ? 1 : SHELL_DEP_FD_NONE), &edge))
    return false;
  /* A successful process connection always retains its parent-facing pipe
   * edge, including a child with no exposed stream. */
  const shell_dep_node_t *producer = &out->nodes[out->edges[edge].from];
  bool exposed_input =
      input && !(producer->type == SHELL_NODE_ENDPOINT &&
                 producer->endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE);
  dep_record_process_temporary(
      context->process_routes, edge, owner,
      (uint32_t)(fragment->start - context->cmd), fragment->start, input,
      phase != DEP_SNAPSHOT_REDIRECT_OPERAND, byte_use && exposed_input, true,
      guard, phase == DEP_SNAPSHOT_BODY_WORD);
  return true;
}

static SHELL_NONNULL(1, 3) int dep_process_guard_compare(const void *context,
                                                         uint32_t index,
                                                         const void *key) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
  const dep_process_route_map_t *map = context;
  uintptr_t left = (uintptr_t)map->guards[index].source;
  uintptr_t right = (uintptr_t)key;
  return left < right ? -1 : left != right;
}

static SHELL_NONNULL(1, 2) const dep_process_guard_t *dep_process_guard_find(
    const dep_process_route_map_t *map, const char *source) {
  uint32_t cursor = map->guard_root;
  while (cursor) {
    int order = dep_process_guard_compare(map, cursor - 1, source);
    if (!order)
      return &map->guards[cursor - 1];
    cursor = order > 0 ? map->guard_index[cursor - 1].left
                       : map->guard_index[cursor - 1].right;
  }
  return NULL;
}

/* Intern only guards owning an executable substitution. Existing guards stop
 * the ancestor walk immediately; each newly needed scope is visited once,
 * using the forward iterator's stack rather than rescanning source text. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_process_word_guard(
    dep_process_route_map_t *map, const dep_token_t *word,
    const shell_source_substitution_scan_t *scan,
    const dep_process_guard_t **guard, bool process,
    const dep_process_guard_t *inherited) {
  *guard = inherited;
  const shell_source_expansion_scope_t *scope = &scan->scope;
  const shell_source_expansion_scope_t *pending[SHELL_MAX_SUBCOMMANDS + 1];
  uint32_t count = 0, cursor = scan->scope_count;
  while (scope->guard_start) {
    *guard = dep_process_guard_find(map, word->start + scope->guard_start - 1);
    if (*guard)
      break;
    pending[count++] = scope;
    size_t parent = scope->guard_parent;
    if (!parent) {
      *guard = inherited;
      break;
    }
    *guard = dep_process_guard_find(map, word->start + parent - 1);
    if (*guard)
      break;
    while (scan->scopes[--cursor].guard_start != parent) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
    }
    scope = &scan->scopes[cursor];
  }
  while (count) {
    scope = pending[--count];
    const char *source = word->start + scope->guard_start - 1;
    uint32_t candidate = map->guard_count + 1, match = 0;
    map->guard_root =
        shell_avl_insert(map->guard_index, map->guard_root, candidate,
                         sizeof(map->guards) / sizeof(map->guards[0]),
                         dep_process_guard_compare, map, source, &match);
    if (!match)
      return false;
    map->guards[map->guard_count++] = (dep_process_guard_t){
        .source = source,
        .parent = *guard,
        .depth = *guard ? (*guard)->depth + 1 : 1,
    };
    *guard = &map->guards[match - 1];
  }
  for (const dep_process_guard_t *current = process ? *guard : NULL;
       current && !current->observed; current = current->parent)
    map->guards[current - map->guards].observed = true;
  return true;
}

static SHELL_NONNULL(1, 5, 6, 7, 8, 10) shell_dep_error_t
    dep_connect_expansions_kind(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const dep_token_t *word, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
        uint32_t consumer_node, dep_subst_kind_t kind, bool heredoc,
        bool syntax_only, const dep_process_guard_t *inherited_guard);

/* Bash's $(<word) has no external command at its outer level: it reads the
 * resolved word as a file. A static word is one DOC→SUBST flow; a dynamic
 * word first receives an explicitly tagged filename-selection flow. status
 * is written only when handled; the caller publishes its completion through
 * the same aggregate/correlated transfer as an ordinary child. */
static SHELL_NONNULL(1, 5, 6, 8, 9, 11, 18, 19) shell_dep_error_t
    dep_connect_file_command_substitution(
        shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
        uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
        const char *content, uint32_t content_len, const char *cwd,
        const shell_dep_limits_t *limits, uint32_t depth,
        const dep_parse_context_t *context, uint32_t expansion_owner,
        uint32_t snapshot_position, dep_snapshot_phase_t snapshot_phase,
        uint32_t consumer_node, dep_subst_kind_t consumer_kind,
        bool syntax_only, bool *handled, uint8_t *status,
        const dep_process_guard_t *guard) {
  *handled = false;
  const char *file_path = NULL;
  uint32_t file_path_len = 0;
  if (!dep_file_command_substitution(content, content_len, &file_path,
                                     &file_path_len))
    return SHELL_DEP_OK;
  *handled = true;
  *status = DEP_STATUS_EITHER;

  dep_token_t operand = {file_path, file_path_len};
  bool active =
      !syntax_only && dep_owner_phase_active(context, expansion_owner,
                                             snapshot_phase, snapshot_position);
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
  /* Pathname resolution does not prove that opening/reading succeeds. The
   * shell reader can report through phase-local stderr even when it has no
   * stdout content, including an invalid resolved filename and process-backed
   * paths. Retain that flow before either fast path can return. */
  if (active) {
    shell_dep_error_t error =
        dep_record_phase_diagnostic(out, out_streams, context, expansion_owner,
                                    snapshot_position, snapshot_phase);
    if (error != SHELL_DEP_OK)
      return error;
  }
  if (dep_redirect_target_is_process_substitution(&operand)) {
    if (shell_source_empty_process_word(operand.start, operand.len)) {
      /* Valid syntax, but no pathname: Bash reports an ambiguous input
       * redirect. This is substitution failure, not an empty child parse. */
      *status = DEP_STATUS_MAY_FAIL;
      return SHELL_DEP_OK;
    }
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
                                          snapshot_phase, fd_imports, guard,
                                          &active);
    if (snapshot_error != SHELL_DEP_OK)
      return snapshot_error;
    active =
        active && dep_owner_phase_active(context, expansion_owner,
                                         snapshot_phase, snapshot_position);
    if (active)
      dep_fd_import_install_capture(fd_imports,
                                    operand.start[0] == '>' ? 0 : 1);
    shell_dep_error_t error = shell_dep_graph_parse_impl(
        sub_content, sub_len, cwd,
        dep_expansion_cwd_known(out, context, expansion_owner),
        dep_expansion_cwd_absolute(out, context, expansion_owner), limits,
        depth + 1, NULL, subgraph, subgraph_streams, fd_imports, active,
        context->resolver);
    if (error != SHELL_DEP_OK)
      return error;
    dep_import_child_coverage(out, subgraph, context, operand.start, active);
    if (subgraph->node_count == 0)
      return SHELL_DEP_OK;

    bool connected;
    if (active && operand.start[0] == '<') {
      uint32_t edge = UINT32_MAX;
      connected = dep_connect_substitution(
          out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
          subgraph, subgraph_streams, consumer_node, DEP_SUBST_PROCESS_WORD,
          dep_fd_numeric(1), &edge);
      if (connected) {
        const shell_dep_node_t *producer = &out->nodes[out->edges[edge].from];
        bool exposed =
            !(producer->type == SHELL_NODE_ENDPOINT &&
              producer->endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE);
        if (exposed)
          out->edges[edge].flags = consumer_kind == DEP_SUBST_SHELL_WORD
                                       ? SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD
                                       : SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME;
        dep_record_process_temporary(
            context->process_routes, edge, expansion_owner,
            (uint32_t)(operand.start - context->cmd), operand.start, true,
            snapshot_phase != DEP_SNAPSHOT_REDIRECT_OPERAND, exposed, !exposed,
            guard, snapshot_phase == DEP_SNAPSHOT_BODY_WORD);
      }
    } else if (active)
      connected = dep_connect_process_word(
          out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
          subgraph, subgraph_streams, context, &operand, expansion_owner,
          snapshot_phase, false, guard);
    else
      connected = dep_append_disconnected_substitution(
          out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
          subgraph, subgraph_streams);
    return connected ? SHELL_DEP_OK : SHELL_DEP_ETRUNC;
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
    /* A failed file substitution has no stdout content. Its stderr marker
     * above and executed pathname substitutions remain independent flows. */
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
   * the parent shell. Bash optimizes the filename expansion in the enclosing
   * execution context: its process descriptors remain visible to later words
   * until that command finishes. Preserve those descriptor effects while
   * isolating the substitution's status. */
  uint32_t event = dep_owner_event(context, expansion_owner);
  dep_expansion_status_t saved = context->expansion_status[event];
  uint8_t saved_static = context->event_static_status[event];
  shell_dep_error_t error = dep_connect_expansions_kind(
      out, max_nodes, max_edges, effective_cwd_buf_size, out_streams, &operand,
      cwd, limits, depth, context, expansion_owner, snapshot_position,
      snapshot_phase, document_node, DEP_SUBST_DYNAMIC_NAME, false, syntax_only,
      guard);
  context->expansion_status[event] = saved;
  context->event_static_status[event] = saved_static;
  return error;
}

/* Publish aggregate and correlated completion together, before stream joining
 * reuses a child's optional portable summary. NULL means status-only (including
 * file shortcuts), not a child summary left in scratch. Identity transfers do
 * not replace this command's preceding substitution status. Other completions
 * supersede status without erasing earlier descriptor observations. A scoped
 * identity also closes completed guards without replacing completion status.
 * All synchronous children in one scanner-declared operand reuse its guard.
 * Callers append nondecreasing positions per owner and phase, placing scoped
 * identity transfers at the completed subtree's boundary before later words. */
static SHELL_NONNULL(1, 2, 3) shell_dep_error_t dep_complete_substitution(
    shell_dep_graph_t *graph, const dep_subgraph_streams_t *streams,
    const dep_parse_context_t *context, uint32_t owner, uint32_t position,
    uint32_t word_position, dep_snapshot_phase_t phase, bool conditional,
    uint8_t status, const dep_observation_transfer_t *returned,
    const dep_process_guard_t *guard) {
  dep_route_workspace_t *workspace = context->workspace;
  uint32_t slot = context->snapshot->prepared_source[owner];
  dep_snapshot_source_t *source = &workspace->snapshot_sources[slot];
  dep_observation_program_t *program = &workspace->observations;
  const dep_process_guard_t *previous_guard =
      source->observation_last[phase]
          ? program->events[source->observation_last[phase] - 1].guard
          : NULL;
  bool identity = status == DEP_EXPANSION_INCOMING;
  if (identity && (!previous_guard || previous_guard == guard))
    return SHELL_DEP_OK;
  uint8_t *prior =
      &context->expansion_status[dep_owner_event(context, owner)].phase[phase];
  uint8_t incoming = *prior;
  conditional = (conditional && !guard) ||
                (phase == DEP_SNAPSHOT_ASSIGNMENT_VALUE &&
                 source->argv_presence == (DEP_ARGV_EMPTY | DEP_ARGV_PRESENT) &&
                 source->assignment_dispatch == DEP_ARGV_EMPTY);
  uint32_t conditions = returned ? returned->condition_count : 0;
  uint32_t count = identity ? 0 : returned ? returned->clause_count : 1;
  if (!guard && !conditions && !source->observation_first[phase]) {
    if (identity)
      return SHELL_DEP_OK;
    *prior = status | (conditional ? incoming : 0);
    return SHELL_DEP_OK;
  }
  uint32_t condition_base = program->transfer.condition_count;
  uint32_t clause_base = program->transfer.clause_count;
  if (program->event_count == SHELL_DEP_MAX_EDGES ||
      conditions > DEP_OBSERVATION_CONDITION_CAPACITY - condition_base ||
      count > SHELL_DEP_MAX_NODES * 5 - clause_base)
    return SHELL_DEP_ETRUNC;
  for (uint32_t i = 0; i < conditions; i++) {
    dep_observation_condition_t condition = returned->conditions[i];
    if (condition.next)
      condition.next += condition_base;
    program->transfer.conditions[condition_base + i] = condition;
  }
  uint32_t clauses = 0;
  for (uint32_t i = 0; i < count; i++) {
    dep_observation_clause_t clause =
        returned ? returned->clauses[i]
                 : (dep_observation_clause_t){.status = status};
    if (clause.conditions)
      clause.conditions += condition_base;
    clause.next = clauses;
    program->transfer.clauses[clause_base + i] = clause;
    clauses = clause_base + i + 1;
  }
  program->transfer.condition_count += conditions;
  program->transfer.clause_count += count;
  uint32_t event = ++program->event_count;
  program->events[event - 1] = (dep_observation_event_t){
      .clauses = clauses,
      .position =
          phase == DEP_SNAPSHOT_REDIRECT_OPERAND ? position : word_position,
      .key = slot * DEP_SNAPSHOT_SETUP + phase,
      .incoming_status = incoming,
      .guard = guard,
      .previous_guard = previous_guard,
      .conditional = conditional};
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  if (phase == DEP_SNAPSHOT_BODY_WORD && source->observation_last[phase])
    shellsplit_test_observation_order_record(
        program->events[source->observation_last[phase] - 1].position,
        program->events[event - 1].position);
#endif
  if (source->observation_last[phase])
    program->events[source->observation_last[phase] - 1].next = event;
  else
    source->observation_first[phase] = event;
  source->observation_last[phase] = event;
  uint32_t table;
  shell_dep_error_t error = dep_snapshot_phase_table(
      graph, streams, context, owner, position, phase, &table);
  if (error != SHELL_DEP_OK)
    return error;
  dep_snapshot_table_t *entry = &workspace->snapshot_tables[table];
  dep_route_state_t state = dep_snapshot_alternatives(entry);
  if (!dep_observation_apply(&state, &workspace->journal, program, event) ||
      !dep_snapshot_table_publish(entry, &state))
    return SHELL_DEP_ETRUNC;
  dep_route_set_t completed =
      dep_fd_raw_fact(&state, &workspace->journal,
                      dep_fd_numeric(slot * DEP_SNAPSHOT_SETUP + phase),
                      DEP_FD_ACCESS_SUBSTITUTION_STATUS);
  if (completed.count) {
    *prior = 0;
    for (uint32_t i = 0; i < completed.count; i++)
      *prior |= (uint8_t)completed.routes[i].value;
  } else if (!identity)
    *prior = status | (conditional ? incoming : 0);
  return SHELL_DEP_OK;
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
        bool syntax_only, const dep_process_guard_t *inherited_guard) {
  bool active =
      !syntax_only && dep_owner_phase_active(context, expansion_owner,
                                             snapshot_phase, snapshot_position);
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc, .suppress_process = heredoc}};
  bool guarded = false;
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
    bool executing = active;
    if (active) {
      shell_dep_error_t error = dep_prepare_process_tracking(
          out, out_streams, context, expansion_owner, snapshot_position,
          snapshot_phase);
      if (error != SHELL_DEP_OK)
        return error;
    }
    const dep_process_guard_t *guard = NULL;
    if (!dep_process_word_guard(
            context->process_routes, word, &scan, &guard,
            context->process_routes->track[expansion_owner] &&
                (subshell.start[0] == '<' || subshell.start[0] == '>') &&
                !shell_source_empty_process_word(subshell.start, subshell.len),
            inherited_guard))
      return SHELL_DEP_ETRUNC;
    guarded |= guard != inherited_guard;
    uint8_t substitution_status = DEP_EXPANSION_INCOMING;
    dep_recursive_parse_t *child = NULL;
    const dep_observation_transfer_t *returned = NULL;
    uint32_t sub_len = 0;
    const char *sub_content = extract_subshell_content(&subshell, &sub_len);
    if (!sub_content)
      return SHELL_DEP_EPARSE;
    bool process_fragment =
        subshell.start[0] == '<' || subshell.start[0] == '>';
    if (sub_len > 0 &&
        !(process_fragment &&
          shell_source_empty_process_word(subshell.start, subshell.len))) {
      bool file_handled = false;
      shell_dep_error_t file_error = SHELL_DEP_OK;
      if (subshell.start[0] == '$')
        file_error = dep_connect_file_command_substitution(
            out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
            sub_content, sub_len, cwd, limits, depth, context, expansion_owner,
            snapshot_position, snapshot_phase, consumer_node, kind, syntax_only,
            &file_handled, &substitution_status, guard);
      if (file_error != SHELL_DEP_OK)
        return file_error;
      if (file_handled)
        executing = executing &&
                    dep_owner_phase_active(context, expansion_owner,
                                           snapshot_phase, snapshot_position);
      if (!file_handled) {
        child = dep_recursive_parse_prepare(limits, depth + 1);
        shell_dep_graph_t *subgraph = &child->graph;
        dep_subgraph_streams_t *subgraph_streams = &child->streams;
        dep_fd_imports_t *fd_imports = &child->streams.fd_imports;
        shell_dep_error_t snapshot_error =
            !executing
                ? SHELL_DEP_OK
                : dep_snapshot_fd_imports(out, out_streams, context,
                                          expansion_owner, snapshot_position,
                                          snapshot_phase, fd_imports, guard,
                                          &executing);
        if (snapshot_error != SHELL_DEP_OK)
          return snapshot_error;
        executing = executing &&
                    dep_owner_phase_active(context, expansion_owner,
                                           snapshot_phase, snapshot_position);
        if (executing)
          dep_fd_import_install_capture(fd_imports,
                                        subshell.start[0] == '>' ? 0 : 1);
        fd_imports->observe_return = executing && !process_fragment;
        shell_dep_error_t error = shell_dep_graph_parse_impl(
            sub_content, sub_len, cwd,
            dep_expansion_cwd_known(out, context, expansion_owner),
            dep_expansion_cwd_absolute(out, context, expansion_owner), limits,
            depth + 1, NULL, subgraph, subgraph_streams, fd_imports, executing,
            context->resolver);
        if (error != SHELL_DEP_OK)
          return error;
        dep_import_child_coverage(out, subgraph, context, subshell.start,
                                  executing);
        bool preserves_status =
            subgraph_streams->empty_kind == SHELL_SOURCE_BLANK ||
            (subgraph_streams->empty_kind == SHELL_SOURCE_COMMENT &&
             subshell.start[0] == '$');
        if (!preserves_status)
          substitution_status =
              dep_substitution_status(subgraph_streams->status);
        if (subgraph_streams->empty_kind == SHELL_SOURCE_NONEMPTY)
          returned = &context->workspace->import_join.observations;
      }
    }
    if (executing && !process_fragment) {
      shell_dep_error_t error = dep_complete_substitution(
          out, out_streams, context, expansion_owner, snapshot_position,
          (uint32_t)(subshell.start - context->cmd), snapshot_phase,
          scan.scope.conditional, substitution_status, returned, guard);
      if (error != SHELL_DEP_OK)
        return error;
    }
    if (child) {
      shell_dep_graph_t *subgraph = &child->graph;
      dep_subgraph_streams_t *subgraph_streams = &child->streams;
      if (subgraph->node_count > 0 || process_fragment) {
        /* A process substitution in a filename or document operand
         * contributes a descriptor pathname, not its stream bytes. Retain
         * its commands without inventing stdout-to-document byte flow. */
        bool disconnected = !executing;
        bool connected = !disconnected ||
                         dep_append_disconnected_substitution(
                             out, max_nodes, max_edges, effective_cwd_buf_size,
                             out_streams, subgraph, subgraph_streams);
        if (!disconnected && process_fragment)
          connected = dep_connect_process_word(
              out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
              subgraph, subgraph_streams, context, &subshell, expansion_owner,
              snapshot_phase,
              kind != DEP_SUBST_DYNAMIC_NAME &&
                  out->nodes[consumer_node].type != SHELL_NODE_DOC,
              guard);
        else if (!disconnected)
          connected = dep_connect_substitution(
              out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
              subgraph, subgraph_streams, consumer_node, kind,
              dep_fd_numeric(1), NULL);
        if (!connected)
          return SHELL_DEP_ETRUNC;
      }
    }
    active =
        active && dep_owner_phase_active(context, expansion_owner,
                                         snapshot_phase, snapshot_position);
    scan_status = dep_next_word_substitution(word, &scan, &subshell);
  }
  if (active) {
    if (guarded) {
      shell_dep_error_t completion = dep_complete_substitution(
          out, out_streams, context, expansion_owner, snapshot_position,
          (uint32_t)(word->start + word->len - context->cmd), snapshot_phase,
          false, DEP_EXPANSION_INCOMING, NULL, inherited_guard);
      if (completion != SHELL_DEP_OK)
        return completion;
    }
    shell_dep_error_t error = dep_record_expansion_result(
        out, out_streams, context, expansion_owner, snapshot_position,
        snapshot_phase,
        (scan.has_expansion_termination ? DEP_STATUS_TERMINAL_FAILURE : 0) |
            (scan.has_expansion_abort ? DEP_STATUS_ABORT_FAILURE : 0));
    if (error != SHELL_DEP_OK)
      return error;
  }
  return scan_status != SHELL_SOURCE_SCAN_DONE ? SHELL_DEP_EPARSE
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
      snapshot_phase, consumer_node, kind, false, false, NULL);
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
      DEP_SNAPSHOT_REDIRECT_OPERAND, owner, DEP_SUBST_SHELL_WORD, false, true,
      NULL);
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
      false, NULL);
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

#include "shell_depgraph_conditional_impl.h"

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

/* Mark ordinary data and admitted test arguments. Test values can select a
 * different grammar, refreshed before body snapshots. Other shell-state
 * operands stay unresolved. Redirects/prefixes have their own phases.
 * Wholly elided words never advance argv roles, just as in semantic
 * validation and mutation analysis. Unknown dispatch remains unresolved.
 * printf data is ordinary argv except state-controlling %b operands in %n
 * formats; those, its options, destination and format retain their semantic
 * roles. */
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
  } else if (kind == SHELL_SOURCE_BUILTIN_NONE ||
             kind == SHELL_SOURCE_BUILTIN_TEST ||
             kind == SHELL_SOURCE_BUILTIN_BRACKET) {
    ordinary_after = effective_command;
  }

  if (ordinary_after != UINT32_MAX) {
    for (uint32_t i = ordinary_after + 1; i < tokens->count; i++) {
      if (dep_skip_nonargument(tokens, &i))
        continue;
      eligible[i] = true;
    }
    return;
  }

  if (kind != SHELL_SOURCE_BUILTIN_PRINTF)
    return;
  shell_builtin_printf_t state = {0};
  for (uint32_t i = effective_command + 1; i < tokens->count; i++) {
    if (dep_skip_nonargument(tokens, &i))
      continue;
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
  if (dep_route_foreign(route, streams->depth)) {
    if (!dep_record_fd_import_use(streams, timer,
                                  dep_fd_numeric(time->report_fd),
                                  DEP_FD_ACCESS_WRITE, route))
      return false;
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_GRAPH;
    return true;
  }
  if (route.kind == DEP_ROUTE_CAPTURE) {
    if (!dep_record_stream_use(
            streams->capture_uses, &streams->capture_use_count,
            streams->capture_index, &streams->capture_root, timer,
            dep_fd_numeric(time->report_fd), DEP_FD_ACCESS_WRITE,
            dep_resource_index(route.value)))
      return false;
    time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_GRAPH;
    return true;
  }
  if (route.kind == DEP_ROUTE_INHERITED) {
    if (!dep_time_record_external_fd(time, route.value) ||
        !dep_record_external_use(streams, timer,
                                 dep_fd_numeric(time->report_fd),
                                 DEP_FD_ACCESS_WRITE, route.value))
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
  uint32_t pipe = dep_route_pipe(workspace, route);
  if (pipe != UINT32_MAX) {
    uint32_t start = workspace->time_pipe_start[pipe];
    uint32_t count = workspace->time_pipe_count[pipe];
    for (uint32_t i = 0; i < count; i++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_PIPE_TARGETS);
      const dep_stream_use_t *target = &workspace->time_pipe_targets[start + i];
      if (!dep_add_resolved_edge_refs(
              graph, max_edges, timer, target->owner, SHELL_EDGE_PIPE,
              dep_fd_numeric(time->report_fd), dep_stream_fd(target),
              SHELL_DEP_EDGE_FLAG_NONE))
        return false;
      time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_GRAPH;
    }
    return count != 0;
  }
  if (route.kind != DEP_ROUTE_DOC && route.kind != DEP_ROUTE_DYNAMIC)
    return false;
  if (dep_resource_index(route.value) >= workspace->original_edge_count)
    return false;
  const shell_dep_edge_t *original =
      &workspace->original_edges[dep_resource_index(route.value)];
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

static SHELL_NONNULL(1, 6, 9, 10) shell_dep_error_t shell_dep_graph_parse_raw(
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
  /* Syntax-analysis exhaustion supplies no qualified structural prefix.
   * A supplied truncated fast result also carries no byte-admission proof;
   * validate that domain before returning. Ordinary parsing reuses its cached
   * admission. Semantic inventory cannot establish support for the suffix. */
  if (fast_err == SHELL_ETRUNC && fast_result.count == 0) {
    shell_source_status_t bytes = shell_source_bytes_status(cmd, cmd_len);
    if (bytes != SHELL_SOURCE_COMPLETE && bytes != SHELL_SOURCE_TRUNCATED) {
      out->status = SHELL_DEP_STATUS_ERROR;
      return SHELL_DEP_EPARSE;
    }
    out->status = SHELL_DEP_STATUS_TRUNCATED;
    return SHELL_DEP_ETRUNC;
  }
  shell_source_empty_kind_t empty = fast_result.count
                                        ? SHELL_SOURCE_NONEMPTY
                                        : shell_source_empty_kind(cmd, cmd_len);
  if (empty == SHELL_SOURCE_BLANK) {
    streams->empty_kind = SHELL_SOURCE_BLANK;
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
  dep_observable_inventory_t observable = {.source = cmd,
                                           .source_length = cmd_len};
  if (depth == 0 && limits->workspace) {
    dep_route_workspace_t *workspace = limits->workspace;
    workspace->tests.root = workspace->tests.count = 0;
    observable.tests = &workspace->tests;
    observable.read_observations = &workspace->read_inventory;
    observable.read_observations->root = observable.read_observations->count =
        0;
    observable.read_observations->active = false;
    observable.read_observations->identity = false;
    observable.read_observations->presence = false;
  }
  /* Inspect the complete immutable source, not only ranges retained by the
   * supplied fast result. A truncated structural prefix cannot hide a later
   * expansion whose semantics require unrepresentable translated source. */
  shell_semantic_result_t inspected = shell_tokenizer_inspect_semantics(
      cmd, cmd_len, dep_observe_descriptor_token, dep_observe_read_fd,
      dep_observe_process, observable.tests ? dep_observe_presence : NULL,
      observable.tests ? dep_observe_test : NULL, &observable);
  if (inspected == SHELL_SEMANTIC_UNSUPPORTED) {
    out->status = SHELL_DEP_STATUS_ERROR;
    return SHELL_DEP_EPARSE;
  }
  if (inspected == SHELL_SEMANTIC_EWORKSPACE) {
    out->status = SHELL_DEP_STATUS_ERROR;
    return SHELL_DEP_EWORKSPACE;
  }
  if (inspected == SHELL_SEMANTIC_TRUNCATED || observable.overflow) {
    out->status = SHELL_DEP_STATUS_TRUNCATED;
    return SHELL_DEP_ETRUNC;
  }
  qsort(observable.positions, observable.position_count,
        sizeof(observable.positions[0]), dep_numeric_value_compare);
  qsort(observable.low, observable.low_count, sizeof(observable.low[0]),
        dep_low_observation_compare);
  out->status = fast_result.status;

  if (fast_result.count == 0) {
    /* The shared lexical classifier includes erased physical continuations. */
    streams->empty_kind = (uint8_t)empty;
    return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                      : SHELL_DEP_OK;
  }

  /* The public boundary prepared size/alignment; only construction needs the
   * resource. Syntax and empty-source classification above need no workspace.
   */
  if (depth == 0 && !limits->workspace) {
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
  dep_process_route_map_t process_routes = {0};
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
    uint32_t end = (uint32_t)execution.pipeline.group_tail[i].redirect_end;
    if (end < group->end)
      end = group->end;
    process_routes.track[node_index] =
        dep_process_lifetime_observed(&observable, group->start, end,
                                      &process_routes.observed_low[node_index]);
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
  bool range_cd_failure_writes[SHELL_MAX_SUBCOMMANDS] = {false};
  uint32_t owner_assignment_stop[SHELL_DEP_MAX_NODES];
  uint32_t owner_setup_stop[SHELL_DEP_MAX_NODES];
  for (uint32_t node = 0; node < SHELL_DEP_MAX_NODES; node++)
    owner_assignment_stop[node] = owner_setup_stop[node] = UINT32_MAX;
  dep_route_workspace_t *route_workspace = limits->workspace;
  streams->join = &route_workspace->import_join;
  streams->depth = depth;
  if (depth == 0) {
    route_workspace->next_selector = 0;
    route_workspace->observations.event_count = 0;
    route_workspace->observations.transfer.clause_count = 0;
    route_workspace->observations.transfer.condition_count = 0;
    route_workspace->snapshot_table_count = 0;
    dep_route_arena_reset(&route_workspace->route_arena);
    dep_route_journal_reset(&route_workspace->journal,
                            &route_workspace->route_arena);
    route_workspace->journal.next_selector = &route_workspace->next_selector;
    {
      uint32_t retained = 0;
      for (uint32_t i = 0; i < observable.count; i++)
        if ((observable.required[i] ||
             (observable.named_fds &&
              observable.fds[i] >= DEP_BASH_VARREDIR_MIN_FD)) &&
            (observable.has_process ||
             observable.fds[i] >= DEP_BASH_VARREDIR_MIN_FD))
          observable.fds[retained++] = observable.fds[i];
      observable.count = retained;
    }
    qsort(observable.fds, observable.count, sizeof(observable.fds[0]),
          dep_numeric_value_compare);
    route_workspace->journal.observable_fd_count = observable.count;
    route_workspace->journal.scratch_observable = observable.scratch_observable;
    route_workspace->journal.named_closes = observable.named_closes;
    dep_read_observations_copy(&route_workspace->journal.read_observations,
                               observable.read_observations);
    memcpy(route_workspace->journal.observable_fds, observable.fds,
           observable.count * sizeof(observable.fds[0]));
    route_workspace->snapshot_source_count = 0;
  }
  route_workspace->journal.depth = depth;
  memset(&route_workspace->snapshot_frames[depth], 0,
         sizeof(route_workspace->snapshot_frames[depth]));
  for (uint32_t owner = 0; owner < SHELL_DEP_MAX_NODES; owner++) {
    route_workspace->snapshot_frames[depth].cached_entry[owner] = UINT32_MAX;
    route_workspace->snapshot_frames[depth].prepared_source[owner] = UINT32_MAX;
  }
  dep_async_plan_t async = {0};
  uint32_t semantic_barrier = UINT32_MAX;
  const dep_parse_context_t parse_context = {
      .cmd = cmd,
      .cmd_len = (uint32_t)cmd_len,
      .fast = &fast_result,
      .execution = &execution,
      .async = &async,
      .node_range = node_range,
      .range_node = range_node,
      .group_node = group_node,
      .node_group = node_group,
      .group_exec = group_exec,
      .event_static_status = event_static_status,
      .event_body_status = event_body_status,
      .expansion_status = expansion_status,
      .range_cd_writes = range_cd_writes,
      .range_cd_failure_writes = range_cd_failure_writes,
      .owner_assignment_stop = owner_assignment_stop,
      .owner_setup_stop = owner_setup_stop,
      .effects_active = effects_active,
      .semantic_barrier = &semantic_barrier,
      .input_unit_recovery = depth == 0,
      .process_routes = &process_routes,
      .workspace = route_workspace,
      .snapshot = &route_workspace->snapshot_frames[depth],
      .resolver = resolver,
      .unresolved_paths = streams->unresolved_paths,
  };
  dep_async_plan_build(&parse_context, &async);

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
        bool self = false;
        if (consumes_word && token + 1 < tokens.count &&
            source_fd != SHELL_DEP_FD_NAMED) {
          shell_process_fd_target_t kind =
              shell_process_classify_static_fd_target(
                  tokens.tokens[token + 1].start, tokens.tokens[token + 1].len,
                  &target_fd);
          self = (kind == SHELL_PROCESS_FD_TARGET_FD ||
                  kind == SHELL_PROCESS_FD_TARGET_MOVE) &&
                 source_fd == target_fd;
        }
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
      if (dep_coverage_position_blocked(semantic_barrier,
                                        fast_result.groups[group].start)) {
        *event_cwd_known = false;
        *event_cwd_absolute = false;
      }
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
          out, streams, &parse_context, group_node[group],
          &group_exec[group].setup_can_fail);
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
    bool range_backgrounded =
        dep_range_is_backgrounded(&execution.pipeline, group_exec, si);

    /* The fast parser may end this range at the backslash of an escaped
     * physical line ending, with the following redirect range beginning after
     * LF. That backslash is grammar, not a trailing argv word. */
    uint32_t token_length = rlen;
    uint32_t range_end = rstart + rlen;
    bool empty_timed_pipeline =
        shell_pipeline_range_is_empty_timing(cmd, range);
    if (token_length != 0 && range_end < cmd_len &&
        cmd[range_end - 1] == '\\' && cmd[range_end] == '\n')
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
    bool arithmetic_command = range->kind == SHELL_COMMAND_ARITHMETIC;
    bool conditional_command = range->kind == SHELL_COMMAND_CONDITIONAL;
    bool compound_command = arithmetic_command || conditional_command;
    shell_conditional_t condition;
    if (conditional_command)
      condition = shell_conditional_parse(cmd, cmd_len, range->start);
    size_t arithmetic_content = 0, arithmetic_end = 0, arithmetic_after = 0;
    shell_arithmetic_result_t arithmetic = {0};
    if (arithmetic_command) {
      (void)shell_source_arithmetic_command(cmd, cmd_len, range->start,
                                            &arithmetic_content,
                                            &arithmetic_end, &arithmetic_after);
      arithmetic = shell_arithmetic_analyze(
          cmd + arithmetic_content, arithmetic_end - arithmetic_content);
    }
    if (tokens.count == 0 && !empty_timed_pipeline && !compound_command &&
        !shell_execution_document(&lexical_documents[si]))
      continue;

    uint32_t readonly_stop;
    uint64_t rejected_assignments;
    uint8_t argv_presence;
    bool isolated_setup;
    uint32_t command =
        dep_first_command_index(&tokens, &readonly_stop, &isolated_setup,
                                &rejected_assignments, &argv_presence);
    if (compound_command) {
      argv_presence = DEP_ARGV_PRESENT;
      isolated_setup = false;
    }
    uint32_t assignment_stop =
        argv_presence == DEP_ARGV_EMPTY ? readonly_stop : UINT32_MAX;
    uint32_t effective_command = command;
    bool dynamic_command = false;
    bool exec_persistent = false;
    bool current_redirects = false;
    shell_dep_command_wrapper_t effective_wrapper = SHELL_DEP_COMMAND_DIRECT;
    const dep_token_t *effective_builtin =
        command == UINT32_MAX
            ? NULL
            : dep_effective_static_builtin(
                  &tokens, command, &effective_command, &dynamic_command,
                  &exec_persistent, &effective_wrapper, &current_redirects);
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
        argv_presence == DEP_ARGV_EMPTY && isolated_setup;
    expansion_status[source_event].redirect_scopes =
        dep_command_redirect_scopes(command, effective_builtin, dynamic_command,
                                    effective_wrapper, current_redirects);
    dep_execution_certainty_t source_execution =
        dep_event_execution(&parse_context, source_event);
    bool active = source_execution != DEP_EXECUTION_NEVER;
    dep_cwd_begin(&parse_context, source_event, range_cwd_offset,
                  range_cwd_known, range_cwd_absolute);
    if (dep_coverage_position_blocked(semantic_barrier, rstart)) {
      *range_cwd_known = false;
      *range_cwd_absolute = false;
    }

    uint32_t cd_next_cwd_offset = *range_cwd_offset;
    bool cd_next_cwd_known = *range_cwd_known;
    bool cd_next_cwd_absolute = *range_cwd_absolute;
    if (is_cd && active) {
      /* cd's arguments and redirects expand before it changes directory.
       * Compute the next state now, but build any graph-visible effects with
       * the incoming state below. */
      if (cd_physical && cd_target_kind != DEP_CD_INVALID)
        cd_target_kind = DEP_CD_DYNAMIC;
      /* A relative runtime HOME can also select CDPATH and print the chosen
       * directory. Reporting may fail after chdir, just as with cd - or a
       * dynamic operand. Share this phase fact with PWD/OLDPWD effects. */
      range_cd_failure_writes[si] =
          cd_target_kind == DEP_CD_DYNAMIC || cd_target_kind == DEP_CD_HOME;
      if (cd_target_kind == DEP_CD_OPERAND && !cwd_isolated) {
        char arg_buf[256];
        bool truncated = false;
        if (!decode_static_cwd_operand(cd_operand, arg_buf, sizeof(arg_buf),
                                       &truncated)) {
          cd_next_cwd_known = false;
          range_cd_failure_writes[si] = true;
          if (truncated)
            out->status |= SHELL_DEP_STATUS_TRUNCATED;
        } else if (cwd_operand_uses_cdpath(arg_buf)) {
          cd_next_cwd_known = false;
          range_cd_failure_writes[si] = true;
        } else if (arg_buf[0] == '/' || cd_next_cwd_known) {
          if (arg_buf[0] == '/')
            cd_next_cwd_known = true;
          if (arg_buf[0] == '/')
            cd_next_cwd_absolute = true;
          uint32_t status_before = out->status;
          cd_next_cwd_offset =
              cwd_resolve_dedup(out, cd_next_cwd_offset, arg_buf,
                                effective_cwd_buf_size, &out->status);
          if ((out->status & ~status_before) != 0)
            cd_next_cwd_known = false;
        }
      } else if (cd_target_kind == DEP_CD_HOME && !cwd_isolated) {
        cd_next_cwd_known = false;
        cd_next_cwd_absolute = false;
      } else if (cd_target_kind == DEP_CD_DYNAMIC && !cwd_isolated &&
                 cd_next_cwd_known) {
        cd_next_cwd_known = false;
      }
    }

    /* A runtime command may resolve to `cd`, but its words and redirects
     * still expand in the incoming directory. Commit uncertainty only after
     * constructing this stage, just like a statically known cd transition. */
    bool dynamic_cwd_transition =
        dynamic_command && (!cwd_isolated || next_conditional);

    bool is_export = effective_builtin &&
                     dep_token_static_equals(effective_builtin, "export");

    if (out->node_count >= max_nodes) {
      /* Earlier substitutions may still have private route markers awaiting
       * final resolution. An incomplete construction cannot expose them. */
      if (process_routes.private_edges)
        return dep_stop_graph_construction(out, SHELL_DEP_ETRUNC);
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
      return SHELL_DEP_ETRUNC;
    }

    uint32_t cmd_node_idx = out->node_count;
    shell_dep_node_t *node = &out->nodes[out->node_count++];
    node_range[cmd_node_idx] = si;
    range_node[si] = cmd_node_idx;
    process_routes.track[cmd_node_idx] = dep_process_lifetime_observed(
        &observable, range->start, execution.end[si],
        &process_routes.observed_low[cmd_node_idx]);
    node->type = SHELL_NODE_CMD;
    node->cmd.kind = range->kind;
    node->cmd.arithmetic_expression = NULL;
    node->cmd.arithmetic_expression_length = 0;
    node->cmd.arithmetic_truth = SHELL_ARITHMETIC_UNKNOWN;
    node->cmd.has_redirections =
        lexical_documents[si].type == SHELL_TYPE_HEREDOC ||
        lexical_documents[si].type == SHELL_TYPE_HERESTRING;
    for (uint32_t t = 0; t < tokens.count; ++t)
      node->cmd.has_redirections |=
          classify_redirect(&tokens.tokens[t]) != DEP_REDIRECT_NONE;
    node->cmd.conditional_expression = NULL;
    node->cmd.conditional_expression_length = 0;
    node->cmd.conditional_operand_count = 0;
    node->cmd.conditional_predicate = SHELL_CONDITIONAL_PREDICATE_NONE;
    node->cmd.conditional_negated = false;
    node->cmd.conditional_unresolved = false;
    node->cmd.conditional_arithmetic_unresolved = false;
    for (unsigned operand = 0; operand < 2; ++operand) {
      node->cmd.conditional_operands[operand] = NULL;
      node->cmd.conditional_operand_lengths[operand] = 0;
    }
    node->cmd.conditional_truth = SHELL_CONDITIONAL_UNKNOWN;
    if (conditional_command) {
      node->cmd.conditional_expression = cmd + condition.content;
      node->cmd.conditional_expression_length =
          (uint32_t)(condition.end - condition.content);
      node->cmd.conditional_operand_count = condition.operand_count;
      node->cmd.conditional_predicate = condition.predicate;
      node->cmd.conditional_negated = condition.negated;
      for (unsigned operand = 0; operand < condition.operand_count; ++operand) {
        node->cmd.conditional_operands[operand] =
            cmd + condition.operands[operand];
        node->cmd.conditional_operand_lengths[operand] =
            (uint32_t)condition.operand_lengths[operand];
      }
    }
    if (arithmetic_command) {
      node->cmd.arithmetic_expression = cmd + arithmetic_content;
      node->cmd.arithmetic_expression_length =
          (uint32_t)(arithmetic_end - arithmetic_content);
      node->cmd.arithmetic_truth = !arithmetic.known  ? SHELL_ARITHMETIC_UNKNOWN
                                   : arithmetic.value ? SHELL_ARITHMETIC_NONZERO
                                                      : SHELL_ARITHMETIC_ZERO;
    }
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
        if (hd->literal)
          flags |= SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL;
        if (hd->pending.strip_tabs)
          flags |= SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS;
      }
      uint32_t prefix_start = execution.pipeline.document_start[fragment];
      uint32_t fd = inline_document_target_fd(cmd, prefix_start, marker);
      /* Inline documents are absent from the owner's ordinary token list.
       * Complete the classification here, before expanding any operands. */
      if (argv_presence == DEP_ARGV_EMPTY &&
          (fd == 0 || fd == SHELL_DEP_FD_NAMED))
        expansion_status[source_event].isolated_setup = true;
      node->cmd.has_redirections = true;
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
    if (!dep_snapshot_record_owner_tokens(&parse_context, cmd_node_idx, &tokens,
                                          readonly_stop, argv_presence)) {
      return dep_stop_graph_construction(out, SHELL_DEP_ETRUNC);
    }
    dep_snapshot_source_t *assignment_source =
        &route_workspace->snapshot_sources[parse_context.snapshot
                                               ->prepared_source[cmd_node_idx]];
    assignment_source->exec = exec_analysis;
    /* Attach the inventoried test before any snapshot or status query. A
     * literal expression need not request a descriptor snapshot at all.
     * Dispatch is already established here; reuse it without rescanning argv.
     */
    if (effective_builtin && !dynamic_command) {
      shell_source_builtin_kind_t kind = shell_source_static_builtin_kind(
          effective_builtin->start, effective_builtin->len);
      if (kind == SHELL_SOURCE_BUILTIN_TEST ||
          kind == SHELL_SOURCE_BUILTIN_BRACKET) {
        assignment_source->test =
            dep_test_program(&route_workspace->tests, effective_builtin->start);
        size_t count = 0;
        for (uint32_t i = effective_command + 1; i < tokens.count; ++i) {
          if (dep_skip_nonargument(&tokens, &i))
            continue;
          assignment_source->test->words[count++].token = i;
        }
      }
    }
    bool command_word_active = dep_owner_phase_active(
        &parse_context, cmd_node_idx, DEP_SNAPSHOT_COMMAND_WORD, range->start);
    if (tokens.count > max_tokens)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;

    /* A reached command whose name is statically empty fails its lookup
     * ("command not found", or exec's "not found"): a certain shell-level
     * error, which no dependency graph represents (SHELL_DEP_EUNMODELED).
     * The flag is sticky, so a recursive parse cannot absorb it. */
    if (command_word_active && effective_builtin) {
      const dep_token_t *name = exec_analysis.kind == DEP_EXEC_REPLACE
                                    ? &exec_analysis.target
                                    : effective_builtin;
      size_t decoded_length;
      if (shell_process_measure_word_value(
              name->start, name->len, &decoded_length) == SHELL_PROCESS_OK &&
          decoded_length == 0)
        parse_context.workspace->journal.unmodeled = true;
    }

    bool expandable_arguments[SHELL_DEP_MAX_TOKENS];
    bool argument_substitutions[SHELL_DEP_MAX_TOKENS] = {false};
    bool prefix_expanded[SHELL_DEP_MAX_TOKENS] = {false};
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
        /* test/[ read their argument parameters before redirect setup,
         * even when that setup later prevents the builtin body from running.
         * Predicate effects below retain their separate body-phase guard. */
        if (assignment_source->test && !conditional_command &&
            word > effective_command &&
            dep_owner_phase_active(&parse_context, cmd_node_idx,
                                   DEP_SNAPSHOT_COMMAND_WORD, range->start)) {
          dep_condition_context_t references = {.graph = out,
                                                .max_nodes = max_nodes,
                                                .max_edges = max_edges,
                                                .owner = cmd_node_idx};
          if (!shell_conditional_visit_parameters(
                  argument->start, argument->len, dep_condition_reference,
                  &references))
            return dep_stop_graph_construction(out, SHELL_DEP_ETRUNC);
        }
        shell_source_substitution_scan_t scan = {0};
        dep_token_t fragment;
        argument_substitutions[word] =
            dep_next_word_substitution(argument, &scan, &fragment) ==
            SHELL_SOURCE_SCAN_FOUND;
        /* Bash expands the complete argv before its redirect list. In
         * particular a later word's process FD is already visible to an
         * earlier redirect operand. Prefix assignment RHSs stay in their
         * distinct, later assignment phase below. */
        shell_dep_error_t expansion_error = dep_connect_word_substitutions(
            out, max_nodes, max_edges, effective_cwd_buf_size, streams,
            argument, out->cwd_buf.data + *range_cwd_offset, limits, depth,
            &parse_context, cmd_node_idx, range->start,
            DEP_SNAPSHOT_COMMAND_WORD, cmd_node_idx);
        if (expansion_error != SHELL_DEP_OK)
          return dep_stop_graph_construction(out, expansion_error);
      }
    }

    /* All argv queries are complete. Refine the canonical program before
     * any redirect/body snapshot can evaluate its grammar or return status. */
    if (assignment_source->test && !conditional_command) {
      bool changed = false;
      for (uint32_t i = 0; i < assignment_source->test->word_count; ++i) {
        shell_test_value_t *word = &assignment_source->test->words[i];
        const shell_dep_word_value_t *value = argument_values[word->token];
        if (!word->known && value && value->resolved && value->count == 1) {
          shell_test_set_value(word, value->first, value->first_length);
          changed = true;
        }
      }
      if (changed && !shell_test_refresh(assignment_source->test))
        return dep_stop_graph_construction(out, SHELL_DEP_ETRUNC);
    }

    /* For a statically present command, temporary assignment RHSs follow
     * argv expansion but precede its redirects, including redirects written
     * before the assignments. Null/nullable dispatch keeps its existing
     * ordered assignment checkpoints below. */
    for (uint32_t word = 0; command != UINT32_MAX &&
                            argv_presence == DEP_ARGV_PRESENT && word < command;
         word++) {
      const dep_token_t *token = &tokens.tokens[word];
      dep_redirect_t redirect = classify_redirect(token);
      if (redirect != DEP_REDIRECT_NONE) {
        if (shell_source_redirection_consumes_word(token->start, token->len))
          word++;
        continue;
      }
      prefix_expanded[word] = true;
      if (rejected_assignments & (UINT64_C(1) << word))
        continue;
      shell_source_assignment_word_t assignment;
      (void)shell_source_parse_scalar_assignment_word(token->start, token->len,
                                                      &assignment);
      assignment_source->assignment_dispatch = DEP_ARGV_PRESENT;
      dep_token_t value = {token->start + assignment.equals + 1,
                           token->len - assignment.equals - 1};
      shell_dep_error_t error = dep_connect_word_substitutions(
          out, max_nodes, max_edges, effective_cwd_buf_size, streams, &value,
          out->cwd_buf.data + *range_cwd_offset, limits, depth, &parse_context,
          cmd_node_idx, (uint32_t)(token->start - cmd),
          DEP_SNAPSHOT_ASSIGNMENT_VALUE, cmd_node_idx);
      if (error != SHELL_DEP_OK)
        return dep_stop_graph_construction(out, error);
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
    shell_builtin_declaration_t export_state = {.kind =
                                                    SHELL_SOURCE_BUILTIN_EXPORT,
                                                .options = true,
                                                .promotes_prefix = true};

    bool saw_argv_word = false;
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
                       active && ti < assignment_stop &&
                           !(rejected_assignments & (UINT64_C(1) << ti)),
                       cmd_node_idx, &out->status);
        /* Temporary readonly prefixes are rejected before expanding their
         * RHS. Assignment-only rejection instead follows RHS expansion and
         * aborts later assignments; declaration operands expand as argv. */
        uint8_t dispatch = argv_presence;
        if (ti > readonly_stop)
          dispatch &= (uint8_t)~DEP_ARGV_EMPTY;
        if (rejected_assignments & (UINT64_C(1) << ti))
          dispatch &= (uint8_t)~DEP_ARGV_PRESENT;
        if (!dispatch || prefix_expanded[ti]) {
          ti++;
          continue;
        }
        assignment_source->assignment_dispatch = dispatch;
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

      if (shell_source_word_is_elided(tok->start, tok->len)) {
        ti++;
        continue;
      }

      /* Assign argv roles after removing prefixes, redirects and elided words.
       * An unresolved word may supply argv[0]; later words can therefore be
       * arguments. Track this independently of the bounded public token array.
       */
      bool is_argument = saw_argv_word;
      saw_argv_word = true;

      /* Export assignments remain ENVVAR documents, but their surrounding
       * redirect list and other words use the ordinary command graph. */
      shell_source_decoded_assignment_t export_assignment;
      unsigned export_roles = is_export && ti > effective_command
                                  ? shell_builtin_declaration_word(
                                        &export_state, tok->start, tok->len)
                                  : 0;
      if (is_export && ti > effective_command &&
          shell_source_scan_decoded_assignment(tok->start, tok->len, NULL, NULL,
                                               &export_assignment) &&
          export_assignment.source_delimiter) {
        add_doc_envvar(
            out, max_nodes, max_edges, tok->start, export_assignment.name_end,
            tok->start + export_assignment.equals + 1,
            tok->len - export_assignment.equals - 1, export_assignment.append,
            active && (export_roles & SHELL_BUILTIN_ROLE_WRITE), cmd_node_idx,
            &out->status);
        if (node->cmd.token_count < max_tokens) {
          uint32_t idx = node->cmd.token_count++;
          node->cmd.tokens[idx] = tok->start;
          node->cmd.token_lens[idx] = tok->len;
        }
        ti++;
        continue;
      }

      bool had_subshell = argument_substitutions[ti];

      if (node->cmd.token_count < max_tokens) {
        uint32_t idx = node->cmd.token_count++;
        node->cmd.tokens[idx] = tok->start;
        node->cmd.token_lens[idx] = tok->len;
      }

      /* Only argument words supply FILE/ARG relations. Wrapper targets remain
       * arguments of their outer command; effective executable identity is
       * recorded separately below. Unresolved substitution spellings are not
       * guessed to be pathname arguments. */
      if (is_argument) {
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

    if (conditional_command) {
      uint32_t body_table;
      shell_dep_error_t prepared = dep_snapshot_phase_table(
          out, streams, &parse_context, cmd_node_idx, UINT32_MAX,
          DEP_SNAPSHOT_BODY_WORD, &body_table);
      if (prepared != SHELL_DEP_OK)
        return dep_stop_graph_construction(out, prepared);
      dep_snapshot_source_t *source =
          &route_workspace->snapshot_sources
               [parse_context.snapshot->prepared_source[cmd_node_idx]];
      dep_condition_context_t evaluation = {
          out,          max_nodes,
          max_edges,    effective_cwd_buf_size,
          streams,      out->cwd_buf.data + *range_cwd_offset,
          limits,       depth,
          cmd_node_idx, &parse_context,
          &condition,   source->test};
      dep_condition_result_t result;
      shell_dep_error_t error = dep_evaluate_condition(
          &evaluation, condition.root, active, NULL, &result);
      if (error != SHELL_DEP_OK)
        return dep_stop_graph_construction(out, error);
    }

    dep_snapshot_source_t *test_source =
        &route_workspace->snapshot_sources[parse_context.snapshot
                                               ->prepared_source[cmd_node_idx]];
    uint8_t test_status = DEP_STATUS_EITHER;
    if (test_source->test && active) {
      shell_dep_error_t error =
          dep_test_body_status_at(out, streams, &parse_context, cmd_node_idx,
                                  test_source->test->root, false, &test_status);
      if (error != SHELL_DEP_OK)
        return dep_stop_graph_construction(out, error);
      if (!conditional_command &&
          dep_owner_phase_active(&parse_context, cmd_node_idx,
                                 DEP_SNAPSHOT_BODY_WORD, UINT32_MAX)) {
        dep_test_file_context_t context = {
            out,          max_nodes,       max_edges,
            cmd_node_idx, argument_values, parse_context.unresolved_paths};
        shell_test_observe_files(test_source->test, dep_observe_test_file,
                                 &context);
        shell_test_observe_comparisons(test_source->test,
                                       dep_observe_test_comparison, &context);
      }
      if (conditional_command)
        node->cmd.conditional_truth =
            test_status == DEP_STATUS_MAY_SUCCEED ? SHELL_CONDITIONAL_TRUE
            : test_status == DEP_STATUS_MAY_FAIL  ? SHELL_CONDITIONAL_FALSE
                                                  : SHELL_CONDITIONAL_UNKNOWN;
    }

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
    {
      uint32_t target = UINT32_MAX;
      for (uint32_t token = 0; execution_target && token < tokens.count;
           token++)
        if (tokens.tokens[token].start == execution_target->start) {
          target = token;
          break;
        }
      node->cmd.stdin_code = dep_stdin_code(
          &tokens, target,
          dynamic_command || exec_analysis.kind == DEP_EXEC_RUNTIME);
    }

    /* Status proof is construction metadata, not a reason to rescan graph
     * edges later. Keep ordinary return outcomes distinct from expansion,
     * exit, and command-replacement outcomes that terminate this shell. */
    {
      uint8_t expansion_outcomes =
          event_static_status[source_event] & DEP_STATUS_STOP;
      uint8_t outcomes =
          argv_presence == DEP_ARGV_EMPTY
              ? dep_null_command_status(&parse_context, source_event,
                                        &test_source->null_mutations)
              : DEP_STATUS_EITHER;
      if (effective_builtin)
        outcomes = dep_static_command_status(effective_builtin);
      if (arithmetic_command)
        outcomes = !arithmetic.known  ? DEP_STATUS_EITHER
                   : arithmetic.value ? DEP_STATUS_MAY_SUCCEED
                                      : DEP_STATUS_MAY_FAIL;
      if (conditional_command)
        outcomes = node->cmd.conditional_truth == SHELL_CONDITIONAL_UNKNOWN
                       ? DEP_STATUS_EITHER
                   : node->cmd.conditional_truth == SHELL_CONDITIONAL_TRUE
                       ? DEP_STATUS_MAY_SUCCEED
                       : DEP_STATUS_MAY_FAIL;
      if (test_source->test)
        outcomes = test_status;
      if (expansion_status[source_event].redirect_scopes &
          DEP_REDIRECT_BAD_BUILTIN)
        outcomes = DEP_STATUS_MAY_FAIL;
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
      if (argv_presence == DEP_ARGV_EMPTY && readonly_assignment)
        outcomes = DEP_STATUS_ABORT_FAILURE;
      event_body_status[source_event] = outcomes;
      if (cwd_isolated) {
        outcomes = dep_status_child_return(dep_status_resolve(
            outcomes, parse_context.snapshot->cwd_entry[source_event].mask &
                          dep_cwd_run_mask(&parse_context, source_event)));
        expansion_outcomes = dep_status_child_return(expansion_outcomes);
      }
      /* Apply local pipeline negation after every command phase has contributed
       * its outcomes. Only returning paths are inverted; exit, replacement and
       * expansion/assignment termination retain their shell exit status. */
      if (node->cmd.pipeline_negated)
        outcomes = dep_status_negate(outcomes);
      event_static_status[source_event] = outcomes | expansion_outcomes;
      if (argv_presence == (DEP_ARGV_EMPTY | DEP_ARGV_PRESENT) &&
          readonly_stop != UINT32_MAX)
        event_static_status[source_event] |=
            DEP_STATUS_ABORT_FAILURE |
            expansion_status[source_event].null_assignment_errors;
    }

    bool setup_may_fail;
    shell_dep_error_t setup_error = dep_complete_owner_setup(
        out, streams, &parse_context, cmd_node_idx, &setup_may_fail);
    if (setup_error != SHELL_DEP_OK)
      return dep_stop_graph_construction(out, setup_error);
    uint8_t setup_failure =
        dep_setup_failure_negated(
            node->cmd.kind, node->cmd.pipeline_negation_count, cwd_isolated)
            ? DEP_STATUS_MAY_SUCCEED
            : DEP_STATUS_MAY_FAIL;
    if (setup_may_fail)
      event_static_status[source_event] |= setup_failure;
    if (owner_setup_stop[cmd_node_idx] != UINT32_MAX) {
      event_static_status[source_event] =
          setup_failure | (event_static_status[source_event] & DEP_STATUS_STOP);
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
                                             *range_cwd_absolute},
                           is_cd && cd_target_kind != DEP_CD_INVALID,
                           setup_may_fail, range_cd_failure_writes[si]);
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

  shell_dep_error_t finish_error =
      dep_snapshot_finish(out, streams, &parse_context);
  if (finish_error != SHELL_DEP_OK)
    return dep_stop_graph_construction(out, finish_error);
  shell_dep_error_t route_error = dep_resolve_effective_routes(
      out, cmd, (uint32_t)cmd_len, &fast_result, &execution.pipeline,
      node_range, range_node, node_group, group_node, group_exec, max_nodes,
      max_edges, streams, &streams->fd_imports, &process_routes,
      route_workspace, &parse_context);
  /* The final walk stops at a descriptor contract violation. */
  if (route_error != SHELL_DEP_OK && route_workspace->journal.unmodeled)
    route_error = SHELL_DEP_EUNMODELED;
  if (route_error == SHELL_DEP_OK)
    dep_flag_required_opens(out, &route_workspace->journal);
  if (route_error != SHELL_DEP_OK)
    return dep_stop_graph_construction(out, route_error);
  return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                    : SHELL_DEP_OK;
}

/* Resource keys omit owners. Each distinct key requires at least one public
 * edge even after structural coalescing, so exhausting this bounded index is
 * a genuine capacity stop, not a redundant-group bookkeeping limit. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_external_key(dep_route_workspace_t *workspace,
                     const dep_stream_use_t *key) {
  uint32_t match = 0, candidate = workspace->external_key_count + 1;
  workspace->external_key_root = shell_avl_insert(
      workspace->external_resource_index, workspace->external_key_root,
      candidate, DEP_EXTERNAL_USE_CAPACITY, dep_external_resource_compare,
      workspace->external_keys, key, &match);
  if (match == candidate) {
    workspace->external_keys[workspace->external_key_count++] = *key;
    workspace->external_outermost[match - 1] = UINT32_MAX;
  }
  return match;
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_external_key_find(const dep_route_workspace_t *workspace,
                          const dep_stream_use_t *key) {
  uint32_t root = workspace->external_key_root;
  while (root) {
    int order =
        dep_external_resource_compare(workspace->external_keys, root - 1, key);
    if (!order)
      return root;
    const shell_avl_node_t *node =
        &workspace->external_resource_index[root - 1];
    root = order < 0 ? node->right : node->left;
  }
  return 0;
}

enum {
  DEP_EXTERNAL_KEYS,
  DEP_EXTERNAL_GROUP,
  DEP_EXTERNAL_FLOW,
};

static SHELL_NONNULL(1, 2, 3, 4) void dep_external_owner_routes(
    shell_dep_graph_t *graph, dep_subgraph_streams_t *streams,
    dep_route_workspace_t *workspace, const dep_stream_use_t *key,
    unsigned phase) {
  uint32_t resource = phase == DEP_EXTERNAL_KEYS
                          ? dep_external_key(workspace, key)
                          : dep_external_key_find(workspace, key);
  if (!resource) {
    /* A group exposure not used by any executable is deliberately absent. */
    if (phase != DEP_EXTERNAL_GROUP)
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    return;
  }
  resource--;
  if (phase == DEP_EXTERNAL_GROUP) {
    if (workspace->external_outermost[resource] == UINT32_MAX) {
      workspace->external_outermost[resource] = key->owner;
      workspace->external_resource[workspace->external_active_count++] =
          resource;
    }
  } else if (phase == DEP_EXTERNAL_FLOW) {
    uint32_t owner = workspace->external_outermost[resource];
    if (!dep_record_external_use(
            streams, owner == UINT32_MAX ? key->owner : owner,
            dep_stream_fd(key), (dep_fd_access_t)key->access, key->anchor))
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
  }
}

/* Enumerate descriptor facts, not source text or redirect operations. The
 * key census and emission are two indexed projections of the same immutable
 * resolved table. Missing standard entries supply ordinary defaults; sparse
 * standard entries expose both available directions, like document/pipe
 * routing. Auxiliary streams require an owner-local use, not a backing save. */
static SHELL_NONNULL(1, 2, 3) void dep_external_owner_collect(
    shell_dep_graph_t *graph, dep_subgraph_streams_t *streams,
    dep_route_workspace_t *workspace, uint32_t owner, unsigned phase) {
  uint32_t count = workspace->owner_use_count[owner];
  for (uint32_t use = 0; use < count + 3; use++) {
    bool sparse = use < count;
    uint32_t fd = sparse ? workspace->owner_uses[owner][use].fd : use - count;
    if (!sparse) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_OWNER_STREAMS);
      if (workspace->route_standard_mask[owner] & (1u << fd))
        continue;
    }
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
         access <<= 1) {
      if ((access == DEP_FD_ACCESS_READ && !workspace->generic_read[owner]) ||
          (workspace->test_body[owner] && fd != 2))
        continue;
      bool used =
          sparse ? fd <= 2 ||
                       (workspace->owner_uses[owner][use].touched & access) != 0
                 : (fd == 0 ? access == DEP_FD_ACCESS_READ
                            : access == DEP_FD_ACCESS_WRITE);
      if (!used)
        continue;
      dep_route_set_t choices = dep_route_state_get_access(
          &workspace->owner_route_state[owner], &workspace->journal,
          dep_fd_numeric(fd), (dep_fd_access_t)access);
      if (choices.truncated)
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      for (uint32_t choice = 0; choice < choices.count; choice++) {
        if (choices.routes[choice].kind != DEP_ROUTE_INHERITED &&
            choices.routes[choice].kind != DEP_ROUTE_NULL_INPUT)
          continue;
        dep_stream_use_t key = {
            owner, fd, choices.routes[choice].value, access, false, NULL, 0};
        dep_external_owner_routes(graph, streams, workspace, &key, phase);
      }
    }
  }
}

/* eligible marks only local executable owners and local group exposures with
 * resolved route tables; copied child owners use their pending flow records.
 * One forest traversal maintains outermost matching group exposures. The
 * active stack contains each resource at most once, however deeply groups
 * nest. Child flows already coalesced onto a GROUP remain actual flows. */
static SHELL_NONNULL(1, 2, 3, 4) void dep_collect_external_routes(
    shell_dep_graph_t *graph, dep_subgraph_streams_t *streams,
    dep_route_workspace_t *workspace, const bool *eligible) {
  dep_import_join_t *scratch = &workspace->import_join;
  workspace->external_key_root = workspace->external_key_count = 0;
  workspace->external_active_count = 0;
  uint32_t pending = streams->external_use_count;
  memcpy(workspace->external_pending, streams->external_uses,
         pending * sizeof(streams->external_uses[0]));
  streams->external_use_count = streams->external_root = 0;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
    scratch->group_parent[node] = UINT32_MAX;
    scratch->capture_first_child[node] = UINT32_MAX;
    scratch->capture_next_child[node] = UINT32_MAX;
    scratch->capture_first_use[node] = UINT32_MAX;
    if (eligible[node] && graph->nodes[node].type == SHELL_NODE_CMD)
      dep_external_owner_collect(graph, streams, workspace, node,
                                 DEP_EXTERNAL_KEYS);
  }
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type != SHELL_EDGE_GROUP)
      continue;
    scratch->group_parent[item->to] = item->from;
    scratch->capture_next_child[item->to] =
        scratch->capture_first_child[item->from];
    scratch->capture_first_child[item->from] = item->to;
  }
  for (uint32_t use = 0; use < pending; use++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
    const dep_stream_use_t *item = &workspace->external_pending[use];
    dep_external_owner_routes(graph, streams, workspace, item,
                              DEP_EXTERNAL_KEYS);
    workspace->external_next_use[use] = scratch->capture_first_use[item->owner];
    scratch->capture_first_use[item->owner] = use;
  }
  for (uint32_t root = 0; root < graph->node_count; root++) {
    if (scratch->group_parent[root] != UINT32_MAX)
      continue;
    uint32_t node = root;
    for (;;) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
      bool group = graph->nodes[node].type == SHELL_NODE_GROUP;
      workspace->external_active_start[node] = workspace->external_active_count;
      if (eligible[node])
        dep_external_owner_collect(graph, streams, workspace, node,
                                   group ? DEP_EXTERNAL_GROUP
                                         : DEP_EXTERNAL_FLOW);
      for (uint32_t use = scratch->capture_first_use[node]; use != UINT32_MAX;
           use = workspace->external_next_use[use]) {
        dep_external_owner_routes(graph, streams, workspace,
                                  &workspace->external_pending[use],
                                  DEP_EXTERNAL_FLOW);
      }
      if (scratch->capture_first_child[node] != UINT32_MAX) {
        node = scratch->capture_first_child[node];
        continue;
      }
      for (;;) {
        while (workspace->external_active_count >
               workspace->external_active_start[node]) {
          uint32_t resource =
              workspace->external_resource[--workspace->external_active_count];
          workspace->external_outermost[resource] = UINT32_MAX;
        }
        if (node == root)
          break;
        if (scratch->capture_next_child[node] != UINT32_MAX) {
          node = scratch->capture_next_child[node];
          break;
        }
        node = scratch->group_parent[node];
      }
      if (node == root)
        break;
    }
  }
}

static int dep_external_use_compare(const void *left, const void *right) {
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
  const dep_stream_use_t *a = left, *b = right;
  if (a->anchor != b->anchor)
    return a->anchor < b->anchor ? -1 : 1;
  if (a->owner != b->owner)
    return a->owner < b->owner ? -1 : 1;
  int fd_order = dep_fd_ref_compare(dep_stream_fd(a), dep_stream_fd(b));
  if (fd_order)
    return fd_order;
  return a->access < b->access ? -1 : a->access != b->access;
}

/* Materialize only at the root, after child remapping and endpoint pruning.
 * Node and edge reservations are paired: a failed reservation never leaves
 * an unused boundary node or an out-of-bounds public relation. */
static SHELL_NONNULL(1, 2, 3) void dep_publish_external_routes(
    shell_dep_graph_t *graph, dep_subgraph_streams_t *streams,
    const shell_dep_limits_t *limits) {
  qsort(streams->external_uses, streams->external_use_count,
        sizeof(streams->external_uses[0]), dep_external_use_compare);
  uint32_t max_nodes = limits->max_nodes < SHELL_DEP_MAX_NODES
                           ? limits->max_nodes
                           : SHELL_DEP_MAX_NODES;
  uint32_t max_edges = limits->max_edges < SHELL_DEP_MAX_EDGES
                           ? limits->max_edges
                           : SHELL_DEP_MAX_EDGES;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_TIME) {
      graph->nodes[node].time.report_external_fd_count = 0;
      graph->nodes[node].time.report_route_flags &=
          ~SHELL_TIME_REPORT_ROUTE_EXTERNAL;
    }
  uint32_t inherited = SHELL_DEP_FD_NONE, endpoint = UINT32_MAX;
  for (uint32_t use = 0; use < streams->external_use_count; use++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BOUNDARY);
    const dep_stream_use_t *item = &streams->external_uses[use];
    bool timer = graph->nodes[item->owner].type == SHELL_NODE_TIME;
    if (item->anchor != inherited) {
      inherited = item->anchor;
      endpoint = UINT32_MAX;
    }
    if (graph->edge_count == max_edges ||
        (endpoint == UINT32_MAX && graph->node_count == max_nodes)) {
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (timer)
        graph->nodes[item->owner].time.report_route_flags |=
            SHELL_TIME_REPORT_ROUTE_UNKNOWN;
      continue;
    }
    if (timer && !dep_time_record_external_fd(&graph->nodes[item->owner].time,
                                              inherited)) {
      graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      graph->nodes[item->owner].time.report_route_flags |=
          SHELL_TIME_REPORT_ROUTE_UNKNOWN;
      continue;
    }
    if (endpoint == UINT32_MAX) {
      endpoint = graph->node_count++;
      graph->nodes[endpoint] =
          inherited == UINT32_MAX
              ? (shell_dep_node_t){.type = SHELL_NODE_DOC,
                                   .doc = {.kind = SHELL_DOC_FILE,
                                           .path = "/dev/null",
                                           .path_len = 9,
                                           .flags =
                                               SHELL_DEP_DOC_FLAG_IMPLICIT}}
              : (shell_dep_node_t){.type = SHELL_NODE_FD,
                                   .fd = {.number = inherited}};
      streams->unresolved_paths[endpoint] = 0;
    }
    bool input = item->access == DEP_FD_ACCESS_READ;
    dep_init_edge(&graph->edges[graph->edge_count++],
                  input ? endpoint : item->owner,
                  input ? item->owner : endpoint,
                  input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE, SHELL_DIR_FORWARD,
                  input ? SHELL_DEP_FD_NONE : item->fd,
                  input ? item->fd : SHELL_DEP_FD_NONE);
    if (timer)
      graph->nodes[item->owner].time.report_route_flags |=
          SHELL_TIME_REPORT_ROUTE_EXTERNAL;
    if (item->fd == SHELL_DEP_FD_NAMED)
      dep_set_named_fd(&graph->edges[graph->edge_count - 1], !input,
                       item->fd_name, item->fd_name_len);
  }
}

/* A capacity stop can occur before the parent resolves a copied child's
 * deferred report stream. Public partial graphs must describe retained edges,
 * not a child-local promise awaiting that join. Keep the missing route explicit
 * as UNKNOWN, rather than misclassifying it as external or closed. */
static SHELL_NONNULL(1, 3) shell_dep_error_t
    dep_finish_public_graph(shell_dep_graph_t *graph, shell_dep_error_t status,
                            dep_subgraph_streams_t *streams,
                            const shell_dep_limits_t *limits) {
  if (status != SHELL_DEP_OK && status != SHELL_DEP_ETRUNC)
    return status;
  /* A failed recursive join can discard the complete partial graph. Its
   * deferred uses belong to that discarded construction, not a new graph. */
  if (graph->node_count == 0)
    return status;
  if (streams->external_use_count)
    dep_publish_external_routes(graph, streams, limits);
  if (graph->status & SHELL_DEP_STATUS_TRUNCATED)
    status = SHELL_DEP_ETRUNC;
  uint32_t retained_reports[SHELL_DEP_MAX_NODES] = {0};
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_TIME_BOUNDARIES);
    if (graph->edges[edge].type != SHELL_EDGE_TIME &&
        graph->nodes[graph->edges[edge].to].type != SHELL_NODE_FD)
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
static SHELL_NONNULL(1, 6, 9, 10) shell_dep_error_t shell_dep_graph_parse_impl(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    bool initial_cwd_known, bool initial_cwd_absolute,
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams, const dep_fd_imports_t *imports,
    bool effects_active, const shell_dep_word_resolver_t *resolver) {
  if (depth == 0) {
    dep_route_workspace_t *root = limits->workspace;
    if (root) {
      root->journal.unmodeled = false;
      root->journal.open_cause_count = 0;
    }
    shell_dep_error_t status = shell_dep_graph_parse_raw(
        cmd, cmd_len, initial_cwd, initial_cwd_known, initial_cwd_absolute,
        limits, depth, provided_fast, out, streams, imports, effects_active,
        resolver);
    /* A violation anywhere, including in a recursive parse whose failure its
     * parent absorbed, disqualifies the whole input. */
    if (root && root->journal.unmodeled)
      return dep_stop_graph_construction(out, SHELL_DEP_EUNMODELED);
    return status;
  }
  dep_route_workspace_t *workspace = limits->workspace;
  uint32_t tables = workspace->snapshot_table_count;
  dep_route_checkpoint_t journal =
      dep_route_journal_checkpoint(&workspace->journal);
  uint32_t sources = workspace->snapshot_source_count;
  uint32_t observation_events = workspace->observations.event_count;
  uint32_t observation_clauses = workspace->observations.transfer.clause_count;
  uint32_t observation_conditions =
      workspace->observations.transfer.condition_count;
  shell_dep_error_t status = shell_dep_graph_parse_raw(
      cmd, cmd_len, initial_cwd, initial_cwd_known, initial_cwd_absolute,
      limits, depth, provided_fast, out, streams, imports, effects_active,
      resolver);
  workspace->snapshot_table_count = tables;
  dep_route_journal_restore(&workspace->journal, &journal);
  workspace->snapshot_source_count = sources;
  workspace->observations.event_count = observation_events;
  workspace->observations.transfer.clause_count = observation_clauses;
  workspace->observations.transfer.condition_count = observation_conditions;
  return status;
}

shell_dep_error_t shell_dep_graph_parse(const char *cmd, size_t cmd_len,
                                        const char *initial_cwd,
                                        const shell_dep_limits_t *limits,
                                        shell_dep_graph_t *out) {
  shell_dep_limits_t prepared = dep_prepare_limits(limits);
  limits = &prepared;
  shell_source_operation_begin(cmd, cmd_len);
  shell_source_workspace_scope_t previous =
      dep_source_workspace(cmd, cmd_len, limits);
  dep_subgraph_streams_t streams = {0};
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      limits, 0, NULL, out, &streams, NULL, true, NULL);
  if (shell_source_scratch_exhausted())
    status = dep_stop_graph_construction(out, SHELL_DEP_EWORKSPACE);
  shell_source_workspace_end(previous);
  shell_source_operation_end();
  return dep_finish_public_graph(out, status, &streams, limits);
}

shell_dep_error_t shell_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) {
  if (!fast)
    return shell_dep_graph_parse(cmd, cmd_len, initial_cwd, limits, out);
  shell_dep_limits_t prepared = dep_prepare_limits(limits);
  limits = &prepared;
  shell_source_operation_begin(cmd, cmd_len);
  if (fast->status == SHELL_STATUS_OK)
    shell_source_operation_prechecked();
  shell_source_workspace_scope_t previous =
      dep_source_workspace(cmd, cmd_len, limits);
  dep_subgraph_streams_t streams = {0};
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      limits, 0, fast, out, &streams, NULL, true, NULL);
  if (shell_source_scratch_exhausted())
    status = dep_stop_graph_construction(out, SHELL_DEP_EWORKSPACE);
  shell_source_workspace_end(previous);
  shell_source_operation_end();
  return dep_finish_public_graph(out, status, &streams, limits);
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
  shell_source_workspace_scope_t previous =
      dep_source_workspace(cmd, cmd_len, &graph_limits);
  dep_subgraph_streams_t streams = {0};
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      &graph_limits, 0, NULL, out, &streams, NULL, true, &resolver);
  if (shell_source_scratch_exhausted())
    status = dep_stop_graph_construction(out, SHELL_DEP_EWORKSPACE);
  shell_source_workspace_end(previous);
  shell_source_operation_end();
  if (cache.error != SHELL_DEP_OK)
    return dep_stop_graph_construction(out, cache.error);
  status = dep_finish_public_graph(out, status, &streams, &graph_limits);
  if (unresolved_paths &&
      (status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC))
    memcpy(unresolved_paths, streams.unresolved_paths, out->node_count);
  return status;
}

shell_dep_error_t shell_dep_graph_parse_with_fast_resolver(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out, const shell_dep_word_resolver_t *resolver,
    uint8_t *unresolved_paths) {
  shell_dep_limits_t prepared = dep_prepare_limits(limits);
  limits = &prepared;
  shell_source_operation_begin(cmd, cmd_len);
  if (fast->status == SHELL_STATUS_OK)
    shell_source_operation_prechecked();
  shell_source_workspace_scope_t previous =
      dep_source_workspace(cmd, cmd_len, limits);
  dep_subgraph_streams_t streams = {0};
  shell_dep_error_t status = shell_dep_graph_parse_impl(
      cmd, cmd_len, initial_cwd, true, initial_cwd && initial_cwd[0] == '/',
      limits, 0, fast, out, &streams, NULL, true, resolver);
  if (shell_source_scratch_exhausted())
    status = dep_stop_graph_construction(out, SHELL_DEP_EWORKSPACE);
  status = dep_finish_public_graph(out, status, &streams, limits);
  memset(unresolved_paths, 0, SHELL_DEP_MAX_NODES * sizeof(*unresolved_paths));
  if (status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC)
    memcpy(unresolved_paths, streams.unresolved_paths,
           out->node_count * sizeof(*unresolved_paths));
  shell_source_workspace_end(previous);
  shell_source_operation_end();
  return status;
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
    else if (shell_ascii_print(byte))
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
      /* The CWD is caller-supplied filesystem context and may contain line
       * ends or quotes, so it is escaped like every other dumped string. */
      const char *cwd = n->cmd.cwd_offset < g->cwd_buf.len
                            ? g->cwd_buf.data + n->cmd.cwd_offset
                            : "?";
      fprintf(fp, "  [%u] CMD cwd=\"", i);
      dep_dump_escaped_span(fp, cwd, (uint32_t)strlen(cwd));
      fputc('"', fp);
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
      if (n->cmd.kind == SHELL_COMMAND_ARITHMETIC) {
        fputs(" arithmetic=\"", fp);
        dep_dump_escaped_span(fp, n->cmd.arithmetic_expression,
                              n->cmd.arithmetic_expression_length);
        fprintf(fp, "\" truth=%s redirects=%s",
                n->cmd.arithmetic_truth == SHELL_ARITHMETIC_ZERO ? "zero"
                : n->cmd.arithmetic_truth == SHELL_ARITHMETIC_NONZERO
                    ? "nonzero"
                    : "unknown",
                n->cmd.has_redirections ? "yes" : "no");
      }
      if (n->cmd.kind == SHELL_COMMAND_CONDITIONAL) {
        fputs(" conditional=\"", fp);
        dep_dump_escaped_span(fp, n->cmd.conditional_expression,
                              n->cmd.conditional_expression_length);
        fprintf(fp, "\" truth=%s redirects=%s",
                n->cmd.conditional_truth == SHELL_CONDITIONAL_TRUE ? "true"
                : n->cmd.conditional_truth == SHELL_CONDITIONAL_FALSE
                    ? "false"
                    : "unknown",
                n->cmd.has_redirections ? "yes" : "no");
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
    } else if (n->type == SHELL_NODE_FD) {
      fprintf(fp, "  [%u] FD inherited=%u\n", i, n->fd.number);
    } else if (n->type == SHELL_NODE_FILE_COMPARISON) {
      fprintf(fp, "  [%u] FILE_COMPARISON predicates=%#x empty=%#x\n", i,
              n->file_comparison.predicates, n->file_comparison.empty_operands);
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
        if (n->doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)
          fputs(" implicit", fp);
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
        fputc('"', fp);
        if (n->doc.value) {
          fputs(" value=\"", fp);
          dep_dump_escaped_span(fp, n->doc.value, n->doc.value_len);
          fputc('"', fp);
        } else
          fputs(" reference", fp);
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
  /* A required open is a document open, never a duplication. */
  uint32_t flags = edge->flags & ~(uint32_t)SHELL_DEP_EDGE_FLAG_REQUIRED;
  if (duplicate)
    return edge->flags == SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP && from_execution &&
           to_execution && edge->from == edge->to &&
           edge->source_fd != SHELL_DEP_FD_NONE &&
           edge->target_fd != SHELL_DEP_FD_NONE;

  bool document_output = from_execution && to == SHELL_NODE_DOC &&
                         edge->source_fd != SHELL_DEP_FD_NONE &&
                         edge->target_fd == SHELL_DEP_FD_NONE;
  if (append)
    return flags == SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND && document_output;
  if (flags != SHELL_DEP_EDGE_FLAG_NONE)
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

/* ARG is the command-to-path association. Other document kinds have distinct
 * shell semantics and must not acquire pathname meaning merely because ARG is
 * undirected. Endpoint bounds are established before this helper is called. */
static SHELL_NONNULL(1) bool dep_arg_edge_endpoints_valid(
    const shell_dep_graph_t *graph, const shell_dep_edge_t *edge,
    shell_dep_node_type_t from, shell_dep_node_type_t to) {
  if (from == SHELL_NODE_CMD && to == SHELL_NODE_DOC)
    return graph->nodes[edge->to].doc.kind == SHELL_DOC_FILE;
  if (from == SHELL_NODE_DOC && to == SHELL_NODE_CMD)
    return graph->nodes[edge->from].doc.kind == SHELL_DOC_FILE;
  return false;
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
  uint32_t time_external_flow_count[SHELL_DEP_MAX_NODES];
  uint32_t time_external_coverage[SHELL_DEP_MAX_NODES];
  bool time_external_match[SHELL_DEP_MAX_NODES];
  bool fd_duplicate[SHELL_DEP_MAX_NODES];
  bool fd_used[SHELL_DEP_MAX_NODES];
  bool implicit_used[SHELL_DEP_MAX_NODES];
  bool implicit_invalid[SHELL_DEP_MAX_NODES];
  bool time_topology_valid[SHELL_DEP_MAX_NODES];
  bool endpoint_input_direction[SHELL_DEP_MAX_NODES];
  bool endpoint_output_direction[SHELL_DEP_MAX_NODES];
  bool endpoint_has_producer[SHELL_DEP_MAX_NODES];
  bool endpoint_has_setup[SHELL_DEP_MAX_NODES];
  bool endpoint_has_consumer[SHELL_DEP_MAX_NODES];
  bool endpoint_topology_valid[SHELL_DEP_MAX_NODES];
  uint32_t control_head[SHELL_DEP_MAX_NODES];
  uint32_t control_next[SHELL_DEP_MAX_EDGES];
  uint16_t comparison_owner[SHELL_DEP_MAX_NODES];
  uint16_t comparison_left[SHELL_DEP_MAX_NODES];
  uint16_t comparison_right[SHELL_DEP_MAX_NODES];
  uint32_t control_indegree[SHELL_DEP_MAX_NODES];
} dep_validation_index_t;

static SHELL_NONNULL(1, 3) int dep_boundary_number_compare(const void *context,
                                                           uint32_t node,
                                                           const void *key) {
  const shell_dep_graph_t *graph = context;
  uint32_t number = graph->nodes[node].fd.number,
           other = *(const uint32_t *)key;
  return number < other ? -1 : number != other;
}

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
  shell_avl_node_t descriptors[SHELL_DEP_MAX_NODES];
  uint32_t descriptor_root = 0;
  uint32_t implicit = UINT32_MAX;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    index->time_target[node] = UINT32_MAX;
    index->time_topology_valid[node] = true;
    index->time_external_match[node] = true;
    index->endpoint_topology_valid[node] = true;
    index->control_head[node] = UINT32_MAX;
    if (graph->nodes[node].type == SHELL_NODE_DOC &&
        (graph->nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) {
      index->implicit_invalid[node] = implicit != UINT32_MAX;
      implicit = node;
    }
    if (graph->nodes[node].type == SHELL_NODE_FD) {
      uint32_t match = 0;
      descriptor_root =
          shell_avl_insert(descriptors, descriptor_root, node + 1,
                           SHELL_DEP_MAX_NODES, dep_boundary_number_compare,
                           graph, &graph->nodes[node].fd.number, &match);
      index->fd_duplicate[node] = match != node + 1;
    }
  }

  for (uint32_t edge_index = 0; edge_index < graph->edge_count; edge_index++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
    const shell_dep_edge_t *edge = &graph->edges[edge_index];
    if (edge->from >= graph->node_count || edge->to >= graph->node_count)
      continue;
    index->edge_in_bounds[edge_index] = true;
    if (edge->type == SHELL_EDGE_FILE_COMPARE)
      index->comparison_owner[edge->to]++;
    if (edge->type == SHELL_EDGE_FILE_LEFT)
      index->comparison_left[edge->from]++;
    if (edge->type == SHELL_EDGE_FILE_RIGHT)
      index->comparison_right[edge->from]++;

    const shell_dep_node_t *from = &graph->nodes[edge->from];
    const shell_dep_node_t *to = &graph->nodes[edge->to];
    if (from->type == SHELL_NODE_FD && edge->type == SHELL_EDGE_READ)
      index->fd_used[edge->from] = true;
    if (to->type == SHELL_NODE_FD && edge->type == SHELL_EDGE_WRITE)
      index->fd_used[edge->to] = true;
    if (from->type == SHELL_NODE_DOC &&
        (from->doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) {
      index->implicit_used[edge->from] = true;
      index->implicit_invalid[edge->from] |= edge->type != SHELL_EDGE_READ;
    }
    if (to->type == SHELL_NODE_DOC &&
        (to->doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT))
      index->implicit_invalid[edge->to] = true;
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
        if (report_flow && to->type == SHELL_NODE_FD) {
          index->time_external_flow_count[edge->from]++;
          bool declared = false;
          uint32_t count = from->time.report_external_fd_count;
          if (count <= SHELL_DEP_TIME_MAX_EXTERNAL_FDS)
            for (uint32_t i = 0; i < count; i++)
              if (from->time.report_external_fds[i] == to->fd.number) {
                uint32_t bit = 1u << i;
                declared =
                    (index->time_external_coverage[edge->from] & bit) == 0;
                index->time_external_coverage[edge->from] |= bit;
                break;
              }
          index->time_external_match[edge->from] &= declared;
        } else
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

/* Every validation failure goes through these helpers, so the result keeps
 * three invariants without per-site discipline: a recorded error always makes
 * the result invalid; each stored diagnostic adds exactly one to error_count;
 * and nothing is stored once SHELL_DEP_MAX_VALIDATE_ERRORS entries exist.
 * Later errors still mark the result invalid but are not described. Node
 * diagnostics keep edge_idx zero; edge diagnostics record the edge. */
#if defined(__GNUC__) || defined(__clang__)
#define DEP_VALIDATION_PRINTF(string_index, first_argument)                    \
  __attribute__((format(printf, string_index, first_argument)))
#else
#define DEP_VALIDATION_PRINTF(string_index, first_argument)
#endif

static SHELL_NONNULL(1, 3)
    DEP_VALIDATION_PRINTF(3, 0) void dep_validation_record(
        shell_dep_graph_validation_t *r, uint32_t edge_idx, const char *format,
        va_list arguments) {
  r->valid = false;
  if (r->error_count == SHELL_DEP_MAX_VALIDATE_ERRORS)
    return;
  r->errors[r->error_count].edge_idx = edge_idx;
  vsnprintf(r->errors[r->error_count].msg, sizeof(r->errors[0].msg), format,
            arguments);
  r->error_count++;
}

static SHELL_NONNULL(1, 2)
    DEP_VALIDATION_PRINTF(2, 3) void dep_validation_error(
        shell_dep_graph_validation_t *r, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  dep_validation_record(r, 0, format, arguments);
  va_end(arguments);
}

static SHELL_NONNULL(1, 3)
    DEP_VALIDATION_PRINTF(3, 4) void dep_validation_edge_error(
        shell_dep_graph_validation_t *r, uint32_t edge_idx, const char *format,
        ...) {
  va_list arguments;
  va_start(arguments, format);
  dep_validation_record(r, edge_idx, format, arguments);
  va_end(arguments);
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
    if (g->node_count > SHELL_DEP_MAX_NODES)
      dep_validation_error(&r, "node_count %u exceeds capacity %u",
                           g->node_count, SHELL_DEP_MAX_NODES);
    if (g->edge_count > SHELL_DEP_MAX_EDGES)
      dep_validation_error(&r, "edge_count %u exceeds capacity %u",
                           g->edge_count, SHELL_DEP_MAX_EDGES);
    if (g->cwd_buf.len > SHELL_DEP_CWD_BUF_SIZE)
      dep_validation_error(&r, "cwd_buf.len %zu exceeds capacity %u",
                           g->cwd_buf.len, SHELL_DEP_CWD_BUF_SIZE);
    return r;
  }

  dep_validation_index_t index;
  dep_validation_index_build(g, &index);

  for (uint32_t i = 0;
       i < g->node_count && r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS;
       i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
    const shell_dep_node_t *n = &g->nodes[i];
    if (n->type > SHELL_NODE_FILE_COMPARISON) {
      dep_validation_error(&r, "node %u: invalid node type %u", i, n->type);
      continue;
    }
    if (n->type == SHELL_NODE_CMD) {
      if ((n->cmd.kind != SHELL_COMMAND_SIMPLE &&
           n->cmd.kind != SHELL_COMMAND_ARITHMETIC &&
           n->cmd.kind != SHELL_COMMAND_CONDITIONAL) ||
          (n->cmd.kind == SHELL_COMMAND_ARITHMETIC &&
           (n->cmd.token_count != 0 || n->cmd.effective_command_known ||
            !n->cmd.arithmetic_expression ||
            n->cmd.arithmetic_truth > SHELL_ARITHMETIC_NONZERO))) {
        dep_validation_error(
            &r, "CMD node %u: invalid arithmetic command metadata", i);
        continue;
      }
      if (n->cmd.kind == SHELL_COMMAND_CONDITIONAL &&
          (n->cmd.token_count || n->cmd.effective_command_known ||
           !n->cmd.conditional_expression ||
           (n->cmd.conditional_operand_count == 0 &&
            n->cmd.conditional_predicate != SHELL_CONDITIONAL_PREDICATE_NONE) ||
           n->cmd.conditional_operand_count > 2 ||
           (n->cmd.conditional_operand_count &&
            !n->cmd.conditional_operands[0]) ||
           (n->cmd.conditional_operand_count == 2 &&
            !n->cmd.conditional_operands[1]) ||
           n->cmd.conditional_operand_count !=
               shell_conditional_arity(n->cmd.conditional_predicate) ||
           n->cmd.conditional_truth > SHELL_CONDITIONAL_TRUE)) {
        dep_validation_error(&r, "CMD node %u: invalid conditional metadata",
                             i);
        continue;
      }
      if (n->cmd.token_count > SHELL_DEP_MAX_TOKENS) {
        dep_validation_error(&r,
                             "CMD node %u: token_count %u exceeds capacity %u",
                             i, n->cmd.token_count, SHELL_DEP_MAX_TOKENS);
        continue;
      }
      if (n->cmd.pipeline_negated !=
          ((n->cmd.pipeline_negation_count & 1u) != 0)) {
        dep_validation_error(&r, "CMD node %u: inconsistent pipeline negation",
                             i);
        if (r.error_count == SHELL_DEP_MAX_VALIDATE_ERRORS)
          continue;
      }
      if (n->cmd.cwd_offset >= g->cwd_buf.len) {
        dep_validation_error(&r,
                             "CMD node %u: cwd_offset %u >= cwd_buf.len %zu", i,
                             n->cmd.cwd_offset, g->cwd_buf.len);
      } else if (memchr(g->cwd_buf.data + n->cmd.cwd_offset, '\0',
                        g->cwd_buf.len - n->cmd.cwd_offset) == NULL) {
        dep_validation_error(
            &r, "CMD node %u: cwd at offset %u is not NUL-terminated", i,
            n->cmd.cwd_offset);
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          ((n->cmd.effective_command_known &&
            n->cmd.effective_command_token >= n->cmd.token_count) ||
           n->cmd.effective_command_wrapper > SHELL_DEP_COMMAND_EXEC)) {
        dep_validation_error(&r, "CMD node %u: invalid effective command", i);
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          n->cmd.cwd_absolute && !n->cmd.cwd_known) {
        dep_validation_error(&r, "CMD node %u: absolute CWD is not known", i);
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          n->cmd.pipeline_time_mode > SHELL_PIPE_TIME_POSIX) {
        dep_validation_error(&r, "CMD node %u: invalid pipeline time mode %u",
                             i, (unsigned)n->cmd.pipeline_time_mode);
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          n->cmd.pipeline_time_mode <= SHELL_PIPE_TIME_POSIX &&
          !dep_time_owner_valid(g, n->cmd.pipeline_time_mode,
                                n->cmd.pipeline_time_id)) {
        dep_validation_error(&r, "CMD node %u: invalid pipeline time owner %u",
                             i, n->cmd.pipeline_time_id);
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
        dep_validation_error(&r, "CMD node %u: invalid effective pipe owner",
                             i);
      }
    } else if (n->type == SHELL_NODE_DOC) {
      const shell_dep_doc_t *doc = &n->doc;
      const uint8_t known_flags =
          SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
          SHELL_DEP_DOC_FLAG_DYNAMIC_NAME | SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL |
          SHELL_DEP_DOC_FLAG_TRANSIENT | SHELL_DEP_DOC_FLAG_ENVVAR_APPEND |
          SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
          SHELL_DEP_DOC_FLAG_EXPANSION_FAILED | SHELL_DEP_DOC_FLAG_IMPLICIT;
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
                              SHELL_DEP_DOC_FLAG_EXPANSION_FAILED |
                              SHELL_DEP_DOC_FLAG_IMPLICIT)) == 0 &&
              !((doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH) &&
                (doc->flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) &&
              (!(doc->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)
                   ? doc->value == NULL && doc->value_len == 0
                   : doc->value != NULL && doc->value_len > 0 &&
                         !(doc->flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) &&
                         memchr(doc->value, 0, doc->value_len) == NULL);
          if (doc->flags & SHELL_DEP_DOC_FLAG_IMPLICIT)
            shape_valid =
                shape_valid && doc->flags == SHELL_DEP_DOC_FLAG_IMPLICIT &&
                doc->path_len == 9 && memcmp(doc->path, "/dev/null", 9) == 0 &&
                !doc->cwd_known && !doc->cwd_absolute && doc->cwd_offset == 0 &&
                index.implicit_used[i] && !index.implicit_invalid[i];
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
        dep_validation_error(
            &r, "DOC node %u: invalid kind, flags, or payload shape", i);
      }
      if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
          doc->kind == SHELL_DOC_FILE &&
          ((doc->cwd_absolute && !doc->cwd_known) ||
           (doc->cwd_known && (doc->cwd_offset >= g->cwd_buf.len ||
                               !memchr(g->cwd_buf.data + doc->cwd_offset, 0,
                                       g->cwd_buf.len - doc->cwd_offset))))) {
        dep_validation_error(&r, "DOC node %u: invalid file CWD", i);
      }
    } else if (n->type == SHELL_NODE_GROUP) {
      if (n->group.pipeline_negated !=
          ((n->group.pipeline_negation_count & 1u) != 0)) {
        dep_validation_error(
            &r, "GROUP node %u: inconsistent pipeline negation", i);
        continue;
      }
      if (n->group.pipeline_time_mode > SHELL_PIPE_TIME_POSIX) {
        dep_validation_error(&r, "GROUP node %u: invalid pipeline time mode %u",
                             i, (unsigned)n->group.pipeline_time_mode);
        continue;
      }
      if (!dep_time_owner_valid(g, n->group.pipeline_time_mode,
                                n->group.pipeline_time_id)) {
        dep_validation_error(&r,
                             "GROUP node %u: invalid pipeline time owner %u", i,
                             n->group.pipeline_time_id);
        continue;
      }
      if (n->group.kind != SHELL_GROUP_BRACE &&
          n->group.kind != SHELL_GROUP_SUBSHELL) {
        dep_validation_error(&r, "GROUP node %u: invalid kind %u", i,
                             n->group.kind);
        continue;
      }
      if (!n->group.start || n->group.length == 0) {
        dep_validation_error(&r, "GROUP node %u: empty source span", i);
        continue;
      }
      if (n->group.parent != UINT32_MAX) {
        bool has_parent_edge =
            n->group.parent < g->node_count && n->group.parent != i &&
            g->nodes[n->group.parent].type == SHELL_NODE_GROUP &&
            index.group_parent_edge[i];
        if (!has_parent_edge) {
          dep_validation_error(
              &r, "GROUP node %u: invalid parent %u or containment edge", i,
              n->group.parent);
        }
      }
    } else if (n->type == SHELL_NODE_FILE_COMPARISON) {
      if (!n->file_comparison.predicates ||
          (n->file_comparison.predicates & ~DEP_FILE_COMPARE_KINDS) ||
          (n->file_comparison.empty_operands & ~3u) ||
          index.comparison_owner[i] != 1 || index.comparison_left[i] != 1 ||
          index.comparison_right[i] != 1) {
        dep_validation_error(
            &r, "FILE_COMPARISON node %u: invalid kind, operands or owner", i);
      }
    } else if (n->type == SHELL_NODE_FD) {
      if (n->fd.number > SHELL_DEP_FD_MAX || index.fd_duplicate[i] ||
          !index.fd_used[i]) {
        dep_validation_error(
            &r,
            "FD node %u: invalid, duplicate, or unused inherited descriptor",
            i);
      }
    } else if (n->type == SHELL_NODE_TIME) {
      uint32_t target = index.time_target[i];
      uint32_t target_count = index.time_target_count[i];
      uint32_t report_flow_count = index.time_report_flow_count[i];
      bool topology_valid =
          index.time_topology_valid[i] && index.time_external_match[i] &&
          index.time_external_flow_count[i] == n->time.report_external_fd_count;
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
        dep_validation_error(
            &r, "TIME node %u: too many external report descriptors", i);
        continue;
      }
      topology_valid &= index.time_external_coverage[i] ==
                        (1u << n->time.report_external_fd_count) - 1u;
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
        dep_validation_error(
            &r, "TIME node %u: invalid mode, span, report fd, or target", i);
      }
    } else if (n->type == SHELL_NODE_ENDPOINT) {
      if (n->endpoint.reserved != 0 &&
          n->endpoint.reserved != DEP_ENDPOINT_TERMINAL_PIPE &&
          n->endpoint.reserved != DEP_ENDPOINT_PROCESS_PIPE) {
        dep_validation_error(&r, "ENDPOINT node %u: unknown endpoint flags %u",
                             i, n->endpoint.reserved);
        continue;
      }
      if (n->endpoint.reserved == DEP_ENDPOINT_PROCESS_PIPE) {
        bool input_direction = index.endpoint_input_direction[i];
        bool output_direction = index.endpoint_output_direction[i];
        bool topology_valid = index.endpoint_topology_valid[i];
        if (!topology_valid || (!input_direction && !output_direction)) {
          dep_validation_error(&r,
                               "ENDPOINT node %u: invalid process-pipe "
                               "topology",
                               i);
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
        dep_validation_error(
            &r, "ENDPOINT node %u: valid=%d producers=%d consumers=%d", i,
            topology_valid, has_producer, has_consumer);
      }
    }
  }

  for (uint32_t i = 0;
       i < g->edge_count && r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS;
       i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_GRAPH_VALIDATION);
    const shell_dep_edge_t *e = &g->edges[i];

    if (!index.edge_in_bounds[i]) {
      dep_validation_edge_error(&r, i, "OOB: from=%u to=%u nodes=%u", e->from,
                                e->to, g->node_count);
      continue;
    }

    if (e->type > SHELL_EDGE_FILE_RIGHT || e->dir > SHELL_DIR_UNDIR) {
      dep_validation_edge_error(&r, i, "invalid edge type %u or direction %u",
                                e->type, e->dir);
      continue;
    }

    if ((e->source_fd != SHELL_DEP_FD_NONE &&
         e->source_fd != SHELL_DEP_FD_NAMED &&
         e->source_fd > SHELL_DEP_FD_MAX) ||
        (e->target_fd != SHELL_DEP_FD_NONE &&
         e->target_fd != SHELL_DEP_FD_NAMED &&
         e->target_fd > SHELL_DEP_FD_MAX)) {
      dep_validation_edge_error(
          &r, i, "descriptor outside supported range: source=%u target=%u",
          e->source_fd, e->target_fd);
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
      dep_validation_edge_error(
          &r, i, "named descriptor is missing or has stray name metadata");
      continue;
    }

    if (e->type == SHELL_EDGE_FILE_TEST
            ? (e->flags == 0 || (e->flags & ~DEP_FILE_TEST_FLAGS) != 0)
            : ((e->flags & ~(SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                             SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME |
                             SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND |
                             SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP |
                             SHELL_DEP_EDGE_FLAG_ENV_READ |
                             SHELL_DEP_EDGE_FLAG_REQUIRED)) != 0 ||
               ((e->flags & SHELL_DEP_EDGE_FLAG_REQUIRED) != 0 &&
                ((e->type != SHELL_EDGE_READ && e->type != SHELL_EDGE_WRITE &&
                  e->type != SHELL_EDGE_APPEND &&
                  e->type != SHELL_EDGE_FD_OPEN) ||
                 (g->nodes[e->from].type != SHELL_NODE_DOC &&
                  g->nodes[e->to].type != SHELL_NODE_DOC))) ||
               ((e->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
                (e->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) ||
               ((e->flags & (SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                             SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME)) != 0 &&
                e->type != SHELL_EDGE_SUBST) ||
               ((e->flags & SHELL_DEP_EDGE_FLAG_ENV_READ) != 0 &&
                e->type != SHELL_EDGE_ENV) ||
               ((e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0 &&
                e->type != SHELL_EDGE_FD_OPEN) ||
               ((e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0 &&
                e->type != SHELL_EDGE_FD_OPEN) ||
               ((e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND) != 0 &&
                (e->flags & SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP) != 0))) {
      dep_validation_edge_error(&r, i, "invalid flags %#x for %s edge",
                                e->flags, shell_dep_edge_type_name(e->type));
      continue;
    }

    bool edge_form = e->type == SHELL_EDGE_ARG
                         ? e->dir == SHELL_DIR_UNDIR &&
                               e->source_fd == SHELL_DEP_FD_NONE &&
                               e->target_fd == SHELL_DEP_FD_NONE
                         : e->dir == SHELL_DIR_FORWARD;
    if (!edge_form) {
      dep_validation_edge_error(&r, i,
                                "invalid direction or descriptors for %s edge",
                                shell_dep_edge_type_name(e->type));
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
      ok = (ft == SHELL_NODE_DOC || ft == SHELL_NODE_FD) &&
           (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP) &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd != SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_WRITE:
    case SHELL_EDGE_APPEND:
      ok = (ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP ||
            ft == SHELL_NODE_TIME) &&
           (tt == SHELL_NODE_DOC || tt == SHELL_NODE_ENDPOINT ||
            (tt == SHELL_NODE_FD && e->type == SHELL_EDGE_WRITE)) &&
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
      ok = ft == SHELL_NODE_DOC && tt == SHELL_NODE_CMD &&
           g->nodes[e->from].doc.kind == SHELL_DOC_ENVVAR &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE &&
           (e->flags == SHELL_DEP_EDGE_FLAG_ENV_READ
                ? g->nodes[e->from].doc.value == NULL
                : e->flags == 0 && g->nodes[e->from].doc.value != NULL);
      break;
    case SHELL_EDGE_ARG:
      ok = dep_arg_edge_endpoints_valid(g, e, ft, tt);
      break;
    case SHELL_EDGE_FILE_TEST:
      ok = ft == SHELL_NODE_CMD && tt == SHELL_NODE_DOC &&
           g->nodes[e->to].doc.kind == SHELL_DOC_FILE &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_FILE_COMPARE:
      ok = ft == SHELL_NODE_CMD && tt == SHELL_NODE_FILE_COMPARISON &&
           e->flags == 0 && e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE;
      break;
    case SHELL_EDGE_FILE_LEFT:
    case SHELL_EDGE_FILE_RIGHT:
      ok = ft == SHELL_NODE_FILE_COMPARISON && tt == SHELL_NODE_DOC &&
           g->nodes[e->to].doc.kind == SHELL_DOC_FILE && e->flags == 0 &&
           e->source_fd == SHELL_DEP_FD_NONE &&
           e->target_fd == SHELL_DEP_FD_NONE;
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
      dep_validation_edge_error(
          &r, i, "type mismatch: %s(%s)->%s(%s) for %s edge",
          shell_dep_node_type_name(ft),
          ft == SHELL_NODE_DOC
              ? shell_dep_doc_kind_name(g->nodes[e->from].doc.kind)
              : "",
          shell_dep_node_type_name(tt),
          tt == SHELL_NODE_DOC
              ? shell_dep_doc_kind_name(g->nodes[e->to].doc.kind)
              : "",
          shell_dep_edge_type_name(e->type));
    }
  }

  if (r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS &&
      !dep_validation_control_acyclic(g, &index)) {
    dep_validation_error(&r, "control topology contains a cycle");
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
    return "Dependency workspace unavailable";
  case SHELL_DEP_EEXPAND:
    return "Word resolution failed";
  case SHELL_DEP_EUNMODELED:
    return "No safe dependency model";
  default:
    return "Unknown error";
  }
}
