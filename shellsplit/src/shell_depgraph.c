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
#include "shell_source_internal.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- NAME HELPERS --- */

static const char *dep_edge_names[] = {
    "READ", "WRITE", "APPEND", "PIPE", "ARG",        "ENV",   "SUBST",
    "SEQ",  "AND",   "OR",     "CWD",  "BACKGROUND", "GROUP", "FD_OPEN",
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
         (doc->flags & ~(SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
                         SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
                         SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL |
                         SHELL_DEP_DOC_FLAG_TRANSIENT)) == 0;
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

/* --- CWD RESOLUTION --- */

static void cwd_normalize(char *path, uint32_t len) {
  if (len == 0)
    return;

  uint32_t w = 0;
  uint32_t r = 0;

  while (r < len) {
    if (path[r] == '/') {
      if (w == 0 || path[w - 1] != '/')
        path[w++] = '/';
      while (r < len && path[r] == '/')
        r++;
      continue;
    }

    uint32_t comp_start = r;
    while (r < len && path[r] != '/')
      r++;
    uint32_t comp_len = r - comp_start;

    if (comp_len == 1 && path[comp_start] == '.') {
      continue;
    }

    if (comp_len == 2 && path[comp_start] == '.' &&
        path[comp_start + 1] == '.') {
      if (w > 1) {
        w--;
        while (w > 0 && path[w - 1] != '/')
          w--;
      }
      continue;
    }

    memmove(path + w, path + comp_start, comp_len);
    w += comp_len;
  }

  if (w == 0) {
    path[0] = '/';
    w = 1;
  }
  if (w > 1 && path[w - 1] == '/')
    w--;
  path[w] = '\0';
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

  cwd_normalize(temp_path, (uint32_t)strlen(temp_path));
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

/* A delimiter is escaped only when preceded by an odd-length run of
 * backslashes. The scanner and extractor must agree on this rule or an even
 * run can make a real closing delimiter look like ordinary data. */
static bool dep_char_escaped(const char *text, uint32_t pos) {
  uint32_t backslashes = 0;
  while (pos > 0 && text[pos - 1] == '\\') {
    backslashes++;
    pos--;
  }
  return (backslashes & 1u) != 0;
}

static uint32_t scan_redirect_token(const char *cmd, uint32_t pos,
                                    uint32_t end) {
  /* Bash combined stdout/stderr redirections have no numeric io_number.
   * Keep the complete operator as one token so its following operand is not
   * misread as an executable command. */
  if (pos + 1 < end && cmd[pos] == '&' && cmd[pos + 1] == '>')
    return pos + ((pos + 2 < end && cmd[pos + 2] == '>') ? 3u : 2u);
  size_t named_after = 0;
  size_t name_start = 0;
  size_t name_length = 0;
  if (shell_source_parse_named_fd(cmd, pos, end, &named_after, &name_start,
                                  &name_length) &&
      named_after < end &&
      (cmd[named_after] == '<' || cmd[named_after] == '>')) {
    uint32_t cursor = (uint32_t)named_after + 1;
    char operator_char = cmd[named_after];
    if (cursor < end && cmd[cursor] == operator_char)
      cursor++;
    else if (cursor < end && ((operator_char == '<' && cmd[cursor] == '>') ||
                              (operator_char == '>' && cmd[cursor] == '|')))
      cursor++;
    if (cursor < end && cmd[cursor] == '&') {
      cursor++;
      if (cursor < end && cmd[cursor] == '-')
        cursor++;
      else
        while (cursor < end && isdigit((unsigned char)cmd[cursor]))
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
  uint32_t cursor = (uint32_t)parsed_after;
  if (cursor >= end || (cmd[cursor] != '<' && cmd[cursor] != '>'))
    return pos;

  char operator_char = cmd[cursor++];
  if (cursor < end && cmd[cursor] == operator_char)
    cursor++;
  else if (cursor < end && ((operator_char == '<' && cmd[cursor] == '>') ||
                            (operator_char == '>' && cmd[cursor] == '|')))
    cursor++;
  if (cursor < end && cmd[cursor] == '&') {
    cursor++;
    if (cursor < end && cmd[cursor] == '-')
      cursor++;
    else
      while (cursor < end && isdigit((unsigned char)cmd[cursor]))
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
    if (c == '\\' && pos + 1 < end) {
      /* The escaped byte is literal, so an escaped `$(` must not require a
       * matching close parenthesis. Parentheses are ordinary word bytes here.
       */
      pos += 2;
      continue;
    }
    if (c == '$' && pos + 1 < end && cmd[pos + 1] == '\'') {
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
    if (c == '$' && pos + 1 < end && cmd[pos + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, end, pos + 1, &after))
        return false;
      pos = (uint32_t)after;
      continue;
    }
    if ((c == '<' || c == '>') && pos + 1 < end && cmd[pos + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, end, pos + 1, &after))
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
    while (pos < end && isspace((unsigned char)cmd[pos]))
      pos++;
    if (pos >= end)
      break;

    uint32_t tok_start = pos;
    uint32_t redirect_end = scan_redirect_token(cmd, pos, end);

    if ((cmd[pos] == '<' || cmd[pos] == '>') && pos + 1 < end &&
        cmd[pos + 1] == '(') {
      /* Keep a process-substitution word as one token. This covers both a
       * whitespace-separated redirect target (`> >(cmd)`) and an ordinary
       * argument (`cmd <(producer)`), which must not become a synthetic
       * fd-0 redirect. */
      process_sub_target = false;
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, end, pos + 1, &after)) {
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
      while (target < end && isspace((unsigned char)cmd[target]))
        target++;
      process_sub_target =
          target < end &&
          (cmd[target] == '(' || ((cmd[target] == '<' || cmd[target] == '>') &&
                                  target + 1 < end && cmd[target + 1] == '('));
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
        if (pos + 1 < end) {
          char c1 = cmd[pos], c2 = cmd[pos + 1];
          if ((c1 == '>' && c2 == '>') || (c1 == '|' && c2 == '|') ||
              (c1 == '&' && c2 == '&') || (c1 == '<' && c2 == '<')) {
            pos += 2;
          } else {
            pos++;
          }
        } else {
          pos++;
        }
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

static bool is_env_assign(const dep_token_t *tok) {
  if (tok->len < 3)
    return false;
  char c = tok->start[0];
  if (!isalpha((unsigned char)c) && c != '_')
    return false;
  for (uint32_t i = 1; i < tok->len; i++) {
    if (tok->start[i] == '=')
      return true;
    if (!isalnum((unsigned char)tok->start[i]) && tok->start[i] != '_')
      return false;
  }
  return false;
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
  return tok->len >= 3 && (tok->start[0] == '<' || tok->start[0] == '>') &&
         tok->start[1] == '(';
}

static dep_redirect_t classify_redirect(const dep_token_t *tok) {
  if (tok->len == 2 && tok->start[0] == '&' && tok->start[1] == '>')
    return DEP_REDIRECT_BOTH;
  if (tok->len == 3 && tok->start[0] == '&' && tok->start[1] == '>' &&
      tok->start[2] == '>')
    return DEP_REDIRECT_BOTH_APPEND;
  size_t after = 0;
  uint32_t descriptor = 0;
  size_t name_start = 0;
  size_t name_length = 0;
  if (shell_source_parse_named_fd(tok->start, 0, tok->len, &after, &name_start,
                                  &name_length)) {
    if (after >= tok->len)
      return DEP_REDIRECT_NONE;
    uint32_t operator_len = tok->len - (uint32_t)after;
    if (operator_len == 1 && tok->start[after] == '<')
      return DEP_REDIRECT_IN;
    if (operator_len == 1 && tok->start[after] == '>')
      return DEP_REDIRECT_OUT;
    if (operator_len == 2 && tok->start[after] == '>' &&
        tok->start[after + 1] == '>')
      return DEP_REDIRECT_APPEND;
    if (operator_len == 2 && tok->start[after] == '<' &&
        tok->start[after + 1] == '>')
      return DEP_REDIRECT_READ_WRITE;
    if (operator_len >= 2 &&
        ((tok->start[after] == '<' && tok->start[after + 1] == '&') ||
         (tok->start[after] == '>' && tok->start[after + 1] == '&') ||
         (operator_len >= 3 && tok->start[after] == '>' &&
          tok->start[after + 1] == '>' && tok->start[after + 2] == '&')))
      return DEP_REDIRECT_DUP;
    return DEP_REDIRECT_NONE;
  }
  shell_source_io_number_t io_number = shell_source_parse_io_number(
      tok->start, 0, tok->len, &after, &descriptor);
  if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return DEP_REDIRECT_NONE;
  uint32_t pos = (uint32_t)after;
  if (pos == 0 && dep_token_is_process_substitution_word(tok))
    return DEP_REDIRECT_NONE;
  uint32_t operator_len = tok->len - pos;
  if (operator_len == 1 && tok->start[pos] == '<')
    return DEP_REDIRECT_IN;
  if (operator_len == 1 && tok->start[pos] == '>')
    return DEP_REDIRECT_OUT;
  if (operator_len == 2 && tok->start[pos] == '>' && tok->start[pos + 1] == '>')
    return DEP_REDIRECT_APPEND;
  if (operator_len == 2 && tok->start[pos] == '<' && tok->start[pos + 1] == '>')
    return DEP_REDIRECT_READ_WRITE;
  if (operator_len == 2 && tok->start[pos] == '>' && tok->start[pos + 1] == '|')
    return DEP_REDIRECT_OUT;
  if (operator_len == 2 && tok->start[pos] == '<' && tok->start[pos + 1] == '<')
    return DEP_REDIRECT_HEREDOC;
  if (operator_len >= 2 &&
      ((tok->start[pos] == '<' && tok->start[pos + 1] == '&') ||
       (tok->start[pos] == '>' && tok->start[pos + 1] == '&') ||
       (operator_len >= 3 && tok->start[pos] == '>' &&
        tok->start[pos + 1] == '>' && tok->start[pos + 2] == '&')))
    return DEP_REDIRECT_DUP;
  return DEP_REDIRECT_NONE;
}

static bool dep_token_is_named_fd_redirect(const dep_token_t *tok) {
  size_t after = 0, name_start = 0, name_length = 0;
  return tok &&
         shell_source_parse_named_fd(tok->start, 0, tok->len, &after,
                                     &name_start, &name_length) &&
         after < tok->len &&
         (tok->start[after] == '<' || tok->start[after] == '>');
}

static uint32_t redirect_fd(const dep_token_t *tok, dep_redirect_t redirect) {
  size_t after = 0;
  uint32_t descriptor = 0;
  size_t name_start = 0;
  size_t name_length = 0;
  if (shell_source_parse_named_fd(tok->start, 0, tok->len, &after, &name_start,
                                  &name_length))
    return SHELL_DEP_FD_NAMED;
  if (shell_source_parse_io_number(tok->start, 0, tok->len, &after,
                                   &descriptor) == SHELL_SOURCE_IO_NUMBER_VALID)
    return descriptor;
  return (redirect == DEP_REDIRECT_IN || redirect == DEP_REDIRECT_READ_WRITE)
             ? 0
             : 1;
}

static bool
dep_redirect_target_is_process_substitution(const dep_token_t *target) {
  return target->len >= 3 &&
         (target->start[0] == '<' || target->start[0] == '>') &&
         target->start[1] == '(' && target->start[target->len - 1] == ')';
}

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
  bool in_single_quote = false;
  bool in_double_quote = false;
  for (uint32_t i = 0; i < tok->len; i++) {
    uint32_t backslashes = 0;
    for (uint32_t j = i; j > 0 && tok->start[j - 1] == '\\'; j--)
      backslashes++;
    bool escaped = (backslashes % 2) != 0;
    if (tok->start[i] == '\'' && !in_double_quote && !escaped) {
      in_single_quote = !in_single_quote;
      continue;
    }
    if (tok->start[i] == '"' && !in_single_quote && !escaped) {
      in_double_quote = !in_double_quote;
      continue;
    }
    /* Command substitutions remain active in double quotes, but Bash process
     * substitutions do not. Treat `<(producer)` and `>(consumer)` there as
     * ordinary literal bytes so they cannot create phantom command nodes or
     * dynamic descriptor routes. */
    if (in_single_quote || escaped ||
        (in_double_quote && (tok->start[i] == '<' || tok->start[i] == '>')))
      continue;
    if ((tok->start[i] == '`') ||
        ((tok->start[i] == '$' || tok->start[i] == '<' ||
          tok->start[i] == '>') &&
         i + 1 < tok->len && tok->start[i + 1] == '(' &&
         !(tok->start[i] == '$' && i + 2 < tok->len &&
           tok->start[i + 2] == '('))) {
      dep_token_t candidate = {tok->start + i, tok->len - i};
      uint32_t content_len = 0;
      const char *content = extract_subshell_content(&candidate, &content_len);
      uint32_t candidate_span = 1;
      if (content) {
        candidate_span = (uint32_t)(content - candidate.start) + content_len;
        if (candidate.start[0] != '`')
          candidate_span++; /* closing ')' */
        else
          candidate_span++; /* closing '`' */
      }
      if (i >= min_offset) {
        subshell->start = candidate.start;
        subshell->len = candidate_span;
        *span_len = candidate_span;
        return true;
      }
      /* Skip the whole outer construct so nested substitutions are not
       * reported as siblings.  Malformed constructs still make progress. */
      if (candidate_span > 1 && candidate_span <= tok->len - i)
        i += candidate_span - 1;
    }
  }
  *span_len = 0;
  return false;
}

static const char *extract_subshell_content(const dep_token_t *tok,
                                            uint32_t *out_len) {
  if (tok->len >= 2 &&
      (tok->start[0] == '$' || tok->start[0] == '<' || tok->start[0] == '>') &&
      tok->start[1] == '(') {
    size_t after = 0;
    if (shell_source_find_balanced_parentheses(tok->start, tok->len, 1,
                                               &after) &&
        after >= 3 && after <= tok->len) {
      *out_len = (uint32_t)(after - 3);
      return tok->start + 2;
    }
  } else if (tok->len >= 1 && tok->start[0] == '`') {
    uint32_t i = 1;
    bool in_quote = false;
    char quote_char = 0;
    while (i < tok->len) {
      if (!in_quote) {
        if ((tok->start[i] == '"' || tok->start[i] == '\'') &&
            !dep_char_escaped(tok->start, i)) {
          in_quote = true;
          quote_char = tok->start[i];
        } else if (tok->start[i] == '`' && !dep_char_escaped(tok->start, i)) {
          *out_len = i - 1;
          return tok->start + 1;
        }
      } else {
        if (tok->start[i] == quote_char && !dep_char_escaped(tok->start, i)) {
          in_quote = false;
        }
      }
      i++;
    }
  }
  *out_len = 0;
  return NULL;
}

static bool token_streq(const dep_token_t *tok, const char *str,
                        uint32_t slen) {
  return tok->len == slen && memcmp(tok->start, str, slen) == 0;
}

typedef enum {
  DEP_CD_HOME,
  DEP_CD_OPERAND,
  DEP_CD_DYNAMIC,
  DEP_CD_INVALID,
} dep_cd_target_t;

/* Return the one pathname argument that can change CWD. Redirections do not
 * count as arguments; `-L`, `-P`, and `--` are the portable option forms.
 * Invalid option or multiple-pathname forms leave the shell CWD unchanged. */
static dep_cd_target_t cd_target(const dep_token_list_t *tokens,
                                 const dep_token_t **operand) {
  bool end_options = false;
  bool dynamic = false;
  const dep_token_t *found = NULL;

  if (operand)
    *operand = NULL;
  for (uint32_t i = 1; i < tokens->count; i++) {
    dep_redirect_t redirect = classify_redirect(&tokens->tokens[i]);
    if (redirect != DEP_REDIRECT_NONE) {
      if (redirect != DEP_REDIRECT_DUP)
        i++;
      continue;
    }

    const dep_token_t *token = &tokens->tokens[i];
    if (dynamic)
      return DEP_CD_INVALID;
    if (!end_options && token_streq(token, "--", 2)) {
      end_options = true;
      continue;
    }
    if (!end_options &&
        (token_streq(token, "-L", 2) || token_streq(token, "-P", 2)))
      continue;
    if (!end_options && token_streq(token, "-", 1)) {
      if (found)
        return DEP_CD_INVALID;
      dynamic = true; /* `cd -` resolves through the runtime OLDPWD. */
      continue;
    }
    if (!end_options && token->len > 1 && token->start[0] == '-')
      return DEP_CD_INVALID;
    if (found)
      return DEP_CD_INVALID;
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

/* CWD tracking is intentionally structural: it only follows a `cd` operand
 * whose destination is fully known from shell syntax. This is stricter than
 * decoded-word rendering, which deliberately preserves executable expansion
 * fragments for later inspection. */
static bool token_has_dynamic_cwd_syntax(const dep_token_t *tok) {
  bool in_single_quote = false;
  bool in_double_quote = false;

  for (uint32_t i = 0; i < tok->len; i++) {
    char c = tok->start[i];
    if (in_single_quote) {
      if (c == '\'')
        in_single_quote = false;
      continue;
    }
    if (c == '\\' && i + 1 < tok->len) {
      i++;
      continue;
    }
    if (!in_double_quote && c == '\'') {
      in_single_quote = true;
      continue;
    }
    if (c == '"') {
      in_double_quote = !in_double_quote;
      continue;
    }
    if (!in_double_quote && c == '$' && i + 1 < tok->len &&
        tok->start[i + 1] == '\'') {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(tok->start, tok->len, i,
                                                   &after))
        return true;
      i = (uint32_t)after - 1;
      continue;
    }
    if (c == '$' || c == '`')
      return true;
    if (!in_double_quote && ((c == '<' || c == '>') && i + 1 < tok->len &&
                             tok->start[i + 1] == '('))
      return true;
    if (!in_double_quote &&
        (c == '*' || c == '?' || c == '[' || c == '{' || c == '}'))
      return true;
  }
  return false;
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
      token_has_dynamic_cwd_syntax(tok))
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
static bool group_is_pipeline_negated(const shell_group_t *group) {
  return group && (group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0;
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
} dep_group_exec_t;

static void dep_prepare_group_execution(const char *command,
                                        uint32_t command_length,
                                        const shell_parse_result_t *result,
                                        dep_group_exec_t *groups) {
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    groups[i].isolated = group->kind == SHELL_GROUP_SUBSHELL;

    size_t position = group->end;
    while (position < command_length &&
           isspace((unsigned char)command[position]))
      position++;
    for (;;) {
      size_t after =
          shell_source_skip_redirect(command, position, command_length);
      if (after == position)
        break;
      position = after;
      while (position < command_length &&
             isspace((unsigned char)command[position]))
        position++;
    }
    if (position >= command_length)
      continue;
    if (command[position] == '|' &&
        !(position + 1 < command_length && command[position + 1] == '|')) {
      groups[i].isolated = true;
    } else if (command[position] == '&' && !(position + 1 < command_length &&
                                             command[position + 1] == '&')) {
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
                                     uint32_t global_offset,
                                     bool global_known) {
  dep_group_exec_t *context = &groups[group];
  if (context->cwd_initialized)
    return;

  uint32_t offset = global_offset;
  bool known = global_known;
  uint16_t parent = result->groups[group].parent;
  while (parent != UINT16_MAX) {
    if (groups[parent].isolated) {
      dep_initialize_group_cwd(result, groups, parent, global_offset,
                               global_known);
      offset = groups[parent].cwd_offset;
      known = groups[parent].cwd_known;
      break;
    }
    parent = result->groups[parent].parent;
  }
  context->cwd_offset = offset;
  context->cwd_known = known;
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
    bool adjacent = true;
    for (uint32_t p = group->end; p < position; p++) {
      if (!isspace((unsigned char)command[p])) {
        adjacent = false;
        break;
      }
    }
    if (adjacent) {
      found = (int32_t)i;
      latest_end = group->end;
    }
  }
  return found;
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
    dep_token_list_t tokens = {0};
    if (scan_tokens(command, group->end, position - group->end, &tokens) ||
        tokens.count == 0)
      continue;
    bool redirects_only = true;
    for (uint32_t token = 0; token < tokens.count;) {
      dep_redirect_t redirect = classify_redirect(&tokens.tokens[token++]);
      if (redirect == DEP_REDIRECT_NONE) {
        redirects_only = false;
        break;
      }
      if (redirect != DEP_REDIRECT_DUP) {
        if (token >= tokens.count) {
          redirects_only = false;
          break;
        }
        token++;
      }
    }
    if (redirects_only) {
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
    bool adjacent = true;
    for (uint32_t p = position; p < group->start; p++) {
      if (!isspace((unsigned char)command[p])) {
        adjacent = false;
        break;
      }
    }
    if (adjacent) {
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
  uint32_t digit_start = marker_start;
  while (digit_start > 0 && isdigit((unsigned char)cmd[digit_start - 1]))
    digit_start--;
  if (digit_start == marker_start)
    return marker_start;
  if (digit_start > 0) {
    unsigned char preceding = (unsigned char)cmd[digit_start - 1];
    if (!isspace(preceding) && preceding != ';' && preceding != '|' &&
        preceding != '&' && preceding != '(' && preceding != ')' &&
        preceding != '{' && preceding != '}' && preceding != '<' &&
        preceding != '>')
      return marker_start;
  }
  size_t after = 0;
  uint32_t descriptor = 0;
  return shell_source_parse_io_number(cmd, digit_start, marker_start, &after,
                                      &descriptor) ==
                     SHELL_SOURCE_IO_NUMBER_VALID &&
                 after == marker_start
             ? digit_start
             : marker_start;
}

static uint32_t inline_document_target_fd(const char *cmd,
                                          uint32_t marker_start) {
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
    skip[i] = true;

    size_t delimiter = result->cmds[i].start + 2;
    size_t marker_end = result->cmds[i].start + result->cmds[i].len;
    if (!shell_source_parse_heredoc_delimiter(cmd, marker_end, &delimiter,
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
  fn->doc.name = NULL;
  fn->doc.name_len = 0;
  fn->doc.value = NULL;
  fn->doc.value_len = 0;
  fn->doc.flags = SHELL_DEP_DOC_FLAG_NONE;
  dep_token_t operand = {path, path_len};
  dep_token_t nested;
  uint32_t span = 0;
  if (find_subshell_at_or_after(&operand, 0, &nested, &span))
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
  node->doc.name = NULL;
  node->doc.name_len = 0;
  node->doc.value = NULL;
  node->doc.value_len = 0;
  node->doc.flags = SHELL_DEP_DOC_FLAG_NONE;
  dep_token_t operand = {path, path_len};
  dep_token_t nested;
  uint32_t span = 0;
  if (find_subshell_at_or_after(&operand, 0, &nested, &span))
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
                                       dep_redirect_t redir, uint32_t *status,
                                       uint32_t *document_index) {
  if (redir != DEP_REDIRECT_READ_WRITE)
    return add_doc_file(g, max_nodes, max_edges, path, path_len, cmd_idx,
                        SHELL_EDGE_FD_OPEN, SHELL_DIR_FORWARD, redir,
                        SHELL_DEP_FD_NAMED, status, document_index);

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
  node->doc.name = NULL;
  node->doc.name_len = 0;
  node->doc.value = NULL;
  node->doc.value_len = 0;
  node->doc.flags = SHELL_DEP_DOC_FLAG_NONE;
  dep_token_t operand = {path, path_len};
  dep_token_t nested;
  uint32_t span = 0;
  if (find_subshell_at_or_after(&operand, 0, &nested, &span))
    node->doc.flags |= SHELL_DEP_DOC_FLAG_DYNAMIC_NAME;

  dep_init_edge(&g->edges[g->edge_count++], document, cmd_idx,
                SHELL_EDGE_FD_OPEN, SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE,
                SHELL_DEP_FD_NAMED);
  dep_init_edge(&g->edges[g->edge_count++], cmd_idx, document,
                SHELL_EDGE_FD_OPEN, SHELL_DIR_FORWARD, SHELL_DEP_FD_NAMED,
                SHELL_DEP_FD_NONE);
  if (document_index)
    *document_index = document;
  return true;
}

static bool add_doc_envvar(shell_dep_graph_t *g, uint32_t max_nodes,
                           uint32_t max_edges, const char *name,
                           uint32_t name_len, const char *value,
                           uint32_t value_len, uint32_t cmd_idx,
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
  en->doc.flags = SHELL_DEP_DOC_FLAG_NONE;
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
  dep_init_edge(edge, document_idx, owner_idx, SHELL_EDGE_READ,
                SHELL_DIR_FORWARD, SHELL_DEP_FD_NONE, target_fd);
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
  /* Closing a descriptor is distinct from never mentioning it. It has no
   * graph edge, but must suppress inferred substitution topology. */
  DEP_ROUTE_CLOSED,
  DEP_ROUTE_DOC,
  DEP_ROUTE_PIPE,
  DEP_ROUTE_DYNAMIC,
} dep_route_kind_t;

typedef struct {
  dep_route_kind_t kind;
  /* The inherited descriptor for DEP_ROUTE_INHERITED, otherwise an edge or
   * pipe index for materialized routes. */
  uint32_t value;
} dep_fd_route_t;

typedef struct {
  uint32_t fd;
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

/* Recursive graphs need one small piece of information that is deliberately
 * not public graph topology: whether each execution endpoint still exposes
 * the external streams inherited by the containing substitution. The parser
 * uses it only while joining recursive graphs; callers continue to consume
 * the graph's concrete READ/WRITE/PIPE/SUBST edges. */
typedef struct {
  bool stdin_inherited[SHELL_DEP_MAX_NODES];
  bool stdout_inherited[SHELL_DEP_MAX_NODES];
} dep_subgraph_streams_t;

enum {
  DEP_ENDPOINT_TERMINAL_PIPE = 1,
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
  uint32_t edge_index;
  dep_fd_access_t access;
} dep_fd_op_t;

static bool dep_is_execution_node(const shell_dep_graph_t *graph,
                                  uint32_t node) {
  return node < graph->node_count &&
         (graph->nodes[node].type == SHELL_NODE_CMD ||
          graph->nodes[node].type == SHELL_NODE_GROUP);
}

static dep_fd_route_entry_t *dep_route_slot(dep_fd_route_entry_t *entries,
                                            uint32_t *count, uint32_t fd,
                                            bool create) {
  for (uint32_t i = 0; i < *count; i++)
    if (entries[i].fd == fd)
      return &entries[i];
  if (!create || *count >= DEP_MAX_FD_ROUTES)
    return NULL;
  entries[*count].fd = fd;
  entries[*count].read_route = (dep_fd_route_t){DEP_ROUTE_INHERITED, fd};
  entries[*count].write_route = (dep_fd_route_t){DEP_ROUTE_INHERITED, fd};
  return &entries[(*count)++];
}

static bool dep_route_assign(dep_fd_route_entry_t *entries, uint32_t *count,
                             uint32_t fd, dep_fd_access_t access,
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

static dep_fd_route_t dep_route_get(const dep_fd_route_entry_t *entries,
                                    uint32_t count, uint32_t fd,
                                    dep_fd_access_t access) {
  for (uint32_t i = 0; i < count; i++)
    if (entries[i].fd == fd)
      return access == DEP_FD_ACCESS_READ ? entries[i].read_route
                                          : entries[i].write_route;
  return (dep_fd_route_t){DEP_ROUTE_INHERITED, fd};
}

static bool dep_route_inherits(const dep_owner_routes_t *routes, uint32_t fd,
                               dep_fd_access_t access) {
  dep_fd_route_t route =
      dep_route_get(routes->fd, routes->fd_count, fd, access);
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

static bool dep_parse_dup_redirect(const dep_token_t *token, uint32_t *fd,
                                   uint32_t *target_fd, bool *close,
                                   dep_fd_access_t *access) {
  if (!token || !fd || !target_fd || !close || !access || token->len < 3)
    return false;
  size_t after = 0;
  uint32_t value = 0;
  shell_source_io_number_t source_number =
      shell_source_parse_io_number(token->start, 0, token->len, &after, &value);
  if (source_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return false;
  uint32_t pos = (uint32_t)after;
  if (pos >= token->len ||
      (token->start[pos] != '<' && token->start[pos] != '>'))
    return false;
  bool input = token->start[pos] == '<';
  *fd = source_number == SHELL_SOURCE_IO_NUMBER_NONE ? (input ? 0 : 1) : value;
  *access = input ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE;
  pos++;
  if (!input && pos < token->len && token->start[pos] == '>')
    pos++;
  if (pos >= token->len || token->start[pos++] != '&')
    return false;
  if (pos == token->len - 1 && token->start[pos] == '-') {
    *close = true;
    *target_fd = SHELL_DEP_FD_NONE;
    return true;
  }
  size_t target_after = 0;
  shell_source_io_number_t target_number = shell_source_parse_io_number(
      token->start, pos, token->len, &target_after, &value);
  if (target_number != SHELL_SOURCE_IO_NUMBER_VALID ||
      target_after != token->len)
    return false;
  *close = false;
  *target_fd = value;
  return true;
}

static bool dep_add_dup_operations(const char *cmd, uint32_t start,
                                   uint32_t length, dep_fd_op_t *ops,
                                   uint32_t *op_count, uint32_t op_capacity) {
  dep_token_list_t tokens = {0};
  if (scan_tokens(cmd, start, length, &tokens))
    return false;
  for (uint32_t i = 0; i < tokens.count; i++) {
    bool close;
    uint32_t fd;
    uint32_t target_fd;
    dep_fd_access_t access;
    if (!dep_parse_dup_redirect(&tokens.tokens[i], &fd, &target_fd, &close,
                                &access))
      continue;
    if (*op_count >= op_capacity)
      return false;
    ops[(*op_count)++] = (dep_fd_op_t){
        (uint32_t)(tokens.tokens[i].start - cmd),
        close ? DEP_FD_OP_CLOSE : DEP_FD_OP_DUP,
        fd,
        target_fd,
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
    if (kind == DEP_REDIRECT_DUP || kind == DEP_REDIRECT_NONE)
      continue;
    if (++token >= tokens.count)
      break;
    const dep_token_t *target = &tokens.tokens[token];
    if ((kind != DEP_REDIRECT_IN && kind != DEP_REDIRECT_OUT &&
         kind != DEP_REDIRECT_APPEND && kind != DEP_REDIRECT_READ_WRITE) ||
        !dep_redirect_target_is_process_substitution(target))
      continue;

    bool input = dep_process_substitution_is_input(kind, target);
    bool output = dep_process_substitution_is_output(kind, target);
    if (!input && !output)
      continue;
    uint32_t fd = redirect_fd(redirect, kind);
    uint32_t edge_index = UINT32_MAX;
    for (uint32_t edge = 0; edge < original_edge_count; edge++) {
      if (used_edges[edge])
        continue;
      const shell_dep_edge_t *item = &original_edges[edge];
      bool matches =
          output ? item->type == SHELL_EDGE_WRITE && item->from == owner &&
                       item->source_fd == fd && item->to < graph->node_count &&
                       graph->nodes[item->to].type == SHELL_NODE_ENDPOINT
                 : item->type == SHELL_EDGE_SUBST && item->to == owner &&
                       item->target_fd == fd;
      if (matches) {
        edge_index = edge;
        break;
      }
    }
    /* A syntactically valid substitution with no executable endpoint does not
     * create a graph route. Keep the parser's empty-subgraph behavior rather
     * than manufacturing a relation for it here. */
    if (edge_index == UINT32_MAX)
      continue;
    if (*op_count >= op_capacity)
      return false;
    used_edges[edge_index] = true;
    dynamic_edges[edge_index] = true;
    ops[(*op_count)++] =
        (dep_fd_op_t){(uint32_t)(target->start - cmd),
                      DEP_FD_OP_DYNAMIC,
                      fd,
                      SHELL_DEP_FD_NONE,
                      edge_index,
                      output ? DEP_FD_ACCESS_WRITE : DEP_FD_ACCESS_READ};
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

static uint32_t dep_group_trailing_end(const char *cmd, uint32_t cmd_len,
                                       uint32_t start) {
  bool single = false;
  bool dbl = false;
  for (uint32_t pos = start; pos < cmd_len; pos++) {
    char c = cmd[pos];
    if (c == '\\' && !single && pos + 1 < cmd_len) {
      pos++;
      continue;
    }
    if (c == '\'' && !dbl) {
      single = !single;
      continue;
    }
    if (c == '"' && !single) {
      dbl = !dbl;
      continue;
    }
    if (!single && !dbl && (c == '<' || c == '>' || c == '$')) {
      dep_token_t candidate = {cmd + pos, cmd_len - pos};
      uint32_t content_len = 0;
      const char *content = extract_subshell_content(&candidate, &content_len);
      if (content) {
        uint32_t span = (uint32_t)(content - candidate.start) + content_len + 1;
        if (span <= candidate.len) {
          pos += span - 1;
          continue;
        }
      }
    }
    if (!single && !dbl && c == '&' && pos > start &&
        (cmd[pos - 1] == '<' || cmd[pos - 1] == '>'))
      continue;
    if (!single && !dbl &&
        (c == ';' || c == '|' || c == '&' || c == '\n' || c == '\r'))
      return pos;
  }
  return cmd_len;
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

static bool dep_add_resolved_edge(shell_dep_graph_t *graph, uint32_t max_edges,
                                  uint32_t from, uint32_t to,
                                  shell_dep_edge_type_t type,
                                  uint32_t source_fd, uint32_t target_fd,
                                  uint8_t flags) {
  if (graph->edge_count >= max_edges) {
    graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    return false;
  }
  dep_add_edge(graph, from, to, type, source_fd, target_fd);
  graph->edges[graph->edge_count - 1].flags = flags;
  return true;
}

/* An output process substitution creates its collector before source-order
 * descriptor routing is resolved. If a later redirect or close replaces that
 * descriptor, the nested command still executes but receives no payload from
 * the outer command. Remove the now-unfed collector and its SUBST edge rather
 * than reporting an imaginary dynamic-content flow. */
static void dep_prune_unfed_endpoints(shell_dep_graph_t *graph,
                                      dep_subgraph_streams_t *streams) {
  bool discard[SHELL_DEP_MAX_NODES] = {false};
  bool any_discarded = false;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (graph->nodes[node].type != SHELL_NODE_ENDPOINT ||
        graph->nodes[node].endpoint.reserved != 0)
      continue;
    bool has_write = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      has_write = has_write || (graph->edges[edge].type == SHELL_EDGE_WRITE &&
                                graph->edges[edge].to == node);
    }
    discard[node] = !has_write;
    any_discarded = any_discarded || discard[node];
  }
  if (!any_discarded)
    return;

  uint32_t remap[SHELL_DEP_MAX_NODES];
  uint32_t kept_nodes = 0;
  for (uint32_t node = 0; node < graph->node_count; node++)
    remap[node] = discard[node] ? UINT32_MAX : kept_nodes++;

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
    memcpy(streams->stdin_inherited, stdin_inherited,
           sizeof(streams->stdin_inherited));
    memcpy(streams->stdout_inherited, stdout_inherited,
           sizeof(streams->stdout_inherited));
  }
  graph->node_count = kept_nodes;
}

static void dep_resolve_effective_routes(shell_dep_graph_t *graph,
                                         const char *cmd, uint32_t cmd_len,
                                         const shell_parse_result_t *fast,
                                         const uint32_t *node_range,
                                         const uint32_t *group_node,
                                         uint32_t max_nodes, uint32_t max_edges,
                                         dep_subgraph_streams_t *streams) {
  dep_owner_routes_t routes[SHELL_DEP_MAX_NODES] = {0};
  bool resolved_owner[SHELL_DEP_MAX_NODES] = {false};
  bool local_owner[SHELL_DEP_MAX_NODES] = {false};
  for (uint32_t node = 0; node < graph->node_count; node++)
    local_owner[node] = graph->nodes[node].type == SHELL_NODE_CMD &&
                        node_range[node] != UINT32_MAX &&
                        node_range[node] < fast->count;
  for (uint32_t group = 0; group < fast->group_count; group++)
    if (group_node[group] != UINT32_MAX &&
        group_node[group] < graph->node_count)
      local_owner[group_node[group]] = true;
  shell_dep_edge_t original_edges[SHELL_DEP_MAX_EDGES];
  uint32_t original_edge_count = graph->edge_count;
  memcpy(original_edges, graph->edges,
         original_edge_count * sizeof(original_edges[0]));
  bool used_dynamic_edges[SHELL_DEP_MAX_EDGES] = {false};
  bool dynamic_route_edges[SHELL_DEP_MAX_EDGES] = {false};
  shell_dep_edge_t pipes[SHELL_DEP_MAX_EDGES];
  uint32_t pipe_count = 0;

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

  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!dep_is_execution_node(graph, owner) || !local_owner[owner])
      continue;
    resolved_owner[owner] = true;
    dep_fd_op_t ops[SHELL_DEP_MAX_EDGES + SHELL_DEP_MAX_TOKENS];
    uint32_t op_count = 0;
    dep_owner_routes_t *state = &routes[owner];

    for (uint32_t pipe = 0; pipe < pipe_count; pipe++) {
      if (pipes[pipe].from == owner &&
          !dep_route_assign(state->fd, &state->fd_count, pipes[pipe].source_fd,
                            DEP_FD_ACCESS_WRITE,
                            (dep_fd_route_t){DEP_ROUTE_PIPE, pipe}))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (pipes[pipe].to == owner &&
          !dep_route_assign(state->fd, &state->fd_count, pipes[pipe].target_fd,
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
      if (!source || op_count >= sizeof(ops) / sizeof(ops[0])) {
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        continue;
      }
      ops[op_count++] = (dep_fd_op_t){
          (uint32_t)(source - cmd),
          DEP_FD_OP_DOCUMENT,
          item->type == SHELL_EDGE_READ ? item->target_fd : item->source_fd,
          SHELL_DEP_FD_NONE,
          edge,
          item->type == SHELL_EDGE_READ ? DEP_FD_ACCESS_READ
                                        : DEP_FD_ACCESS_WRITE,
      };
    }

    if (graph->nodes[owner].type == SHELL_NODE_CMD &&
        node_range[owner] != UINT32_MAX && node_range[owner] < fast->count) {
      const shell_range_t *range = &fast->cmds[node_range[owner]];
      if (!dep_add_process_substitution_operations(
              cmd, range->start, range->len, owner, graph, original_edges,
              original_edge_count, used_dynamic_edges, dynamic_route_edges, ops,
              &op_count, sizeof(ops) / sizeof(ops[0])))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      if (!dep_add_dup_operations(cmd, range->start, range->len, ops, &op_count,
                                  sizeof(ops) / sizeof(ops[0])))
        graph->status |= SHELL_DEP_STATUS_TRUNCATED;
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
                dynamic_route_edges, ops, &op_count,
                sizeof(ops) / sizeof(ops[0])) ||
            !dep_add_dup_operations(cmd, descriptor->end, trailing_len, ops,
                                    &op_count, sizeof(ops) / sizeof(ops[0])))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
        break;
      }
    }

    dep_sort_fd_operations(ops, op_count);
    for (uint32_t op = 0; op < op_count; op++) {
      dep_fd_op_t *item = &ops[op];
      if (item->kind == DEP_FD_OP_DOCUMENT) {
        if (!dep_route_assign(
                state->fd, &state->fd_count, item->fd, item->access,
                (dep_fd_route_t){DEP_ROUTE_DOC, item->edge_index}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else if (item->kind == DEP_FD_OP_DYNAMIC) {
        if (!dep_route_assign(
                state->fd, &state->fd_count, item->fd, item->access,
                (dep_fd_route_t){DEP_ROUTE_DYNAMIC, item->edge_index}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else if (item->kind == DEP_FD_OP_CLOSE) {
        if (!dep_route_assign(state->fd, &state->fd_count, item->fd,
                              DEP_FD_ACCESS_BOTH,
                              (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX}))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else {
        dep_fd_route_t copied_read = dep_route_get(
            state->fd, state->fd_count, item->target_fd, DEP_FD_ACCESS_READ);
        dep_fd_route_t copied_write = dep_route_get(
            state->fd, state->fd_count, item->target_fd, DEP_FD_ACCESS_WRITE);
        if (!dep_route_assign(state->fd, &state->fd_count, item->fd,
                              DEP_FD_ACCESS_READ, copied_read) ||
            !dep_route_assign(state->fd, &state->fd_count, item->fd,
                              DEP_FD_ACCESS_WRITE, copied_write))
          graph->status |= SHELL_DEP_STATUS_TRUNCATED;
      }
    }
    streams->stdin_inherited[owner] =
        dep_route_inherits(state, 0, DEP_FD_ACCESS_READ);
    streams->stdout_inherited[owner] =
        dep_route_inherits(state, 1, DEP_FD_ACCESS_WRITE);
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

  for (uint32_t owner = 0; owner < graph->node_count; owner++) {
    if (!resolved_owner[owner])
      continue;
    const dep_owner_routes_t *state = &routes[owner];
    for (uint32_t i = 0; i < state->fd_count; i++) {
      const dep_fd_route_t route[2] = {state->fd[i].read_route,
                                       state->fd[i].write_route};
      for (uint32_t access = 0; access < 2; access++) {
        if (route[access].kind != DEP_ROUTE_DOC &&
            route[access].kind != DEP_ROUTE_DYNAMIC)
          continue;
        const shell_dep_edge_t *original = &original_edges[route[access].value];
        if (route[access].kind == DEP_ROUTE_DOC &&
            original->type == SHELL_EDGE_READ) {
          dep_add_resolved_edge(graph, max_edges, original->from, owner,
                                SHELL_EDGE_READ, SHELL_DEP_FD_NONE,
                                state->fd[i].fd, original->flags);
        } else if (route[access].kind == DEP_ROUTE_DOC) {
          dep_add_resolved_edge(graph, max_edges, owner, original->to,
                                original->type, state->fd[i].fd,
                                SHELL_DEP_FD_NONE, original->flags);
        } else if (original->type == SHELL_EDGE_SUBST) {
          dep_add_resolved_edge(graph, max_edges, original->from, owner,
                                SHELL_EDGE_SUBST, original->source_fd,
                                state->fd[i].fd, original->flags);
        } else {
          dep_add_resolved_edge(graph, max_edges, owner, original->to,
                                original->type, state->fd[i].fd,
                                SHELL_DEP_FD_NONE, original->flags);
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
        dep_add_resolved_edge(graph, max_edges, original->from, terminal,
                              SHELL_EDGE_PIPE, source->fd[out].fd, 0,
                              original->flags);
        continue;
      }
      for (uint32_t in = 0; in < target->fd_count; in++) {
        if (target->fd[in].read_route.kind != DEP_ROUTE_PIPE ||
            target->fd[in].read_route.value != pipe)
          continue;
        dep_add_resolved_edge(graph, max_edges, original->from, original->to,
                              SHELL_EDGE_PIPE, source->fd[out].fd,
                              target->fd[in].fd, original->flags);
      }
    }
  }

  dep_prune_unfed_endpoints(graph, streams);
}

static void dep_mark_transient_inline_documents(shell_dep_graph_t *graph) {
  for (uint32_t node = 0; node < graph->node_count; node++) {
    shell_dep_node_t *document = &graph->nodes[node];
    if (document->type != SHELL_NODE_DOC ||
        (document->doc.kind != SHELL_DOC_HEREDOC &&
         document->doc.kind != SHELL_DOC_HERESTRING))
      continue;
    bool consumed = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      consumed = consumed || (graph->edges[edge].type == SHELL_EDGE_READ &&
                              graph->edges[edge].from == node);
    }
    if (!consumed)
      document->doc.flags |= SHELL_DEP_DOC_FLAG_TRANSIENT;
  }
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
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams);

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
    if (out->nodes[out->node_count].type == SHELL_NODE_CMD)
      out->nodes[out->node_count].cmd.cwd_offset += cwd_offset_shift;
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
  return true;
}

/* Copy one parsed substitution and wire its actual stream topology into the
 * parent graph. Word and input-process substitutions carry nested output to
 * the parent; output-process substitutions carry the parent's redirected fd
 * to nested stdin. A collector is only needed when one direct SUBST edge
 * would conceal several producers or descriptor routing. */
static bool dep_connect_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const shell_dep_graph_t *subgraph,
    const dep_subgraph_streams_t *subgraph_streams, uint32_t consumer_node,
    dep_subst_kind_t kind, uint32_t producer_fd) {
  dep_endpoint_list_t endpoints;
  if (kind == DEP_SUBST_PROCESS_OUTPUT)
    dep_collect_substitution_inputs(subgraph, subgraph_streams, &endpoints);
  else
    dep_collect_substitution_outputs(subgraph, subgraph_streams, &endpoints);

  bool needs_collector =
      kind == DEP_SUBST_PROCESS_OUTPUT || endpoints.count > 1;
  uint32_t extra_nodes = endpoints.count > 0 && needs_collector ? 1 : 0;
  uint32_t extra_edges = 0;
  if (endpoints.count == 1 && !needs_collector) {
    extra_edges = 1;
  } else if (endpoints.count > 0 && kind == DEP_SUBST_PROCESS_OUTPUT) {
    extra_edges = 1 + endpoints.count; /* producer WRITE plus collector SUBST */
  } else if (endpoints.count > 1) {
    extra_edges = endpoints.count + 1; /* producer WRITEs plus one SUBST */
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
  if (endpoints.count == 0)
    return true;

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
 * redirect attached to an ordinary command. */
static shell_dep_error_t dep_connect_redirect_process_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const dep_token_t *redirect_token, dep_redirect_t redirect,
    const dep_token_t *target, const char *cwd,
    const shell_dep_limits_t *limits, uint32_t depth, uint32_t consumer_node,
    bool *handled) {
  *handled = false;
  if (redirect != DEP_REDIRECT_IN && redirect != DEP_REDIRECT_OUT &&
      redirect != DEP_REDIRECT_APPEND && redirect != DEP_REDIRECT_READ_WRITE &&
      redirect != DEP_REDIRECT_BOTH && redirect != DEP_REDIRECT_BOTH_APPEND)
    return SHELL_DEP_OK;

  if (!dep_redirect_target_is_process_substitution(target))
    return SHELL_DEP_OK;

  /* A named descriptor is a handle allocation, not an established byte route.
   * Its process-substitution form needs descriptor-flow modeling and remains
   * explicitly unsupported. */
  if (redirect_fd(redirect_token, redirect) == SHELL_DEP_FD_NAMED) {
    *handled = true;
    return SHELL_DEP_EPARSE;
  }

  *handled = true;
  const char *sub_content = target->start + 2;
  uint32_t sub_len = target->len - 3;
  shell_dep_graph_t subgraph = {0};
  dep_subgraph_streams_t subgraph_streams = {0};
  shell_dep_error_t error =
      shell_dep_graph_parse_impl(sub_content, sub_len, cwd, limits, depth + 1,
                                 NULL, &subgraph, &subgraph_streams);
  if (error == SHELL_DEP_EPARSE || error == SHELL_DEP_EINPUT)
    return SHELL_DEP_EPARSE;
  if (error == SHELL_DEP_ETRUNC)
    out->status |= SHELL_DEP_STATUS_TRUNCATED;
  if (error != SHELL_DEP_OK || subgraph.node_count == 0)
    return SHELL_DEP_OK;

  bool input = dep_process_substitution_is_input(redirect, target);
  bool output = dep_process_substitution_is_output(redirect, target);
  bool connected = false;
  if (input) {
    connected = dep_connect_substitution(
        out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
        &subgraph, &subgraph_streams, consumer_node, DEP_SUBST_PROCESS_INPUT,
        redirect_fd(redirect_token, redirect));
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
          DEP_SUBST_PROCESS_OUTPUT,
          combined ? 1 : redirect_fd(redirect_token, redirect));
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
  return SHELL_DEP_OK;
}

static shell_dep_error_t dep_connect_word_substitutions_kind(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const dep_token_t *word, const char *cwd, const shell_dep_limits_t *limits,
    uint32_t depth, uint32_t consumer_node, dep_subst_kind_t kind);

/* Bash's $(<word) has no external command at its outer level: it reads the
 * resolved word as a file. A static word is one DOC→SUBST flow; a dynamic
 * word first receives an explicitly tagged filename-selection flow. */
static shell_dep_error_t dep_connect_file_command_substitution(
    shell_dep_graph_t *out, uint32_t max_nodes, uint32_t max_edges,
    uint32_t effective_cwd_buf_size, dep_subgraph_streams_t *out_streams,
    const char *content, uint32_t content_len, const char *cwd,
    const shell_dep_limits_t *limits, uint32_t depth, uint32_t consumer_node,
    dep_subst_kind_t consumer_kind, bool *handled) {
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
    shell_dep_error_t error =
        shell_dep_graph_parse_impl(sub_content, sub_len, cwd, limits, depth + 1,
                                   NULL, &subgraph, &subgraph_streams);
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
                                       consumer_node, consumer_kind, 1)
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
      cwd, limits, depth, document_node, DEP_SUBST_DYNAMIC_NAME);
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
    if ((text[pos] != '$' || pos + 1 >= length || text[pos + 1] != '(') &&
        text[pos] != '`')
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
    const shell_dep_limits_t *limits, uint32_t depth, uint32_t document_node) {
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
            sub_content, sub_len, cwd, limits, depth, document_node,
            DEP_SUBST_SHELL_WORD, &file_handled);
      if (file_error != SHELL_DEP_OK)
        return file_error;
      if (!file_handled) {
        shell_dep_graph_t subgraph = {0};
        dep_subgraph_streams_t subgraph_streams = {0};
        shell_dep_error_t error = shell_dep_graph_parse_impl(
            sub_content, sub_len, cwd, limits, depth + 1, NULL, &subgraph,
            &subgraph_streams);
        if (error == SHELL_DEP_EPARSE || error == SHELL_DEP_EINPUT)
          return SHELL_DEP_EPARSE;
        if (error == SHELL_DEP_ETRUNC)
          out->status |= SHELL_DEP_STATUS_TRUNCATED;
        if (error == SHELL_DEP_OK && subgraph.node_count > 0 &&
            !dep_connect_substitution(out, max_nodes, max_edges,
                                      effective_cwd_buf_size, out_streams,
                                      &subgraph, &subgraph_streams,
                                      document_node, DEP_SUBST_SHELL_WORD, 1))
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
    uint32_t depth, uint32_t consumer_node, dep_subst_kind_t kind) {
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
            sub_content, sub_len, cwd, limits, depth, consumer_node, kind,
            &file_handled);
      if (file_error != SHELL_DEP_OK)
        return file_error;
      if (!file_handled) {
        shell_dep_graph_t subgraph = {0};
        dep_subgraph_streams_t subgraph_streams = {0};
        shell_dep_error_t error = shell_dep_graph_parse_impl(
            sub_content, sub_len, cwd, limits, depth + 1, NULL, &subgraph,
            &subgraph_streams);
        if (error == SHELL_DEP_EPARSE || error == SHELL_DEP_EINPUT)
          return SHELL_DEP_EPARSE;
        if (error == SHELL_DEP_ETRUNC)
          out->status |= SHELL_DEP_STATUS_TRUNCATED;
        if (error == SHELL_DEP_OK && subgraph.node_count > 0) {
          bool connected =
              subshell.start[0] != '>' ||
              dep_append_disconnected_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size,
                  out_streams, &subgraph, &subgraph_streams);
          if (subshell.start[0] != '>')
            connected = dep_connect_substitution(
                out, max_nodes, max_edges, effective_cwd_buf_size, out_streams,
                &subgraph, &subgraph_streams, consumer_node,
                subshell.start[0] == '<' ? DEP_SUBST_PROCESS_WORD : kind, 1);
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
    uint32_t depth, uint32_t consumer_node) {
  return dep_connect_word_substitutions_kind(
      out, max_nodes, max_edges, effective_cwd_buf_size, out_streams, word, cwd,
      limits, depth, consumer_node, DEP_SUBST_SHELL_WORD);
}

typedef struct {
  const char *value;
  uint32_t value_len;
  uint32_t target_fd;
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
    while (position < end && isspace((unsigned char)cmd[position]))
      position++;
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
    if (operator_pos + 3 <= end && cmd[operator_pos] == '<' &&
        cmd[operator_pos + 1] == '<' && cmd[operator_pos + 2] == '<') {
      uint32_t operand = operator_pos + 3;
      while (operand < end && isspace((unsigned char)cmd[operand]))
        operand++;
      size_t after = operand;
      if (!shell_source_skip_shell_word(cmd, end, operand, &after) ||
          after == operand || after > UINT32_MAX || count == capacity) {
        *complete = false;
        return count;
      }
      items[count++] = (dep_group_herestring_t){
          cmd + operand, (uint32_t)(after - operand), explicit_fd ? fd : 0};
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

/* The fast parser separates an io_number directly adjacent to a here-string
 * (for example `3<<<data`) into a synthetic SIMPLE range. The descriptor is
 * part of the redirection, never an executable command. */
static bool range_is_herestring_fd_prefix(const char *cmd,
                                          const shell_range_t *range,
                                          const shell_range_t *next) {
  if (!cmd || !range || !next || range->type != SHELL_TYPE_SIMPLE ||
      !(next->type & SHELL_TYPE_HERESTRING) || range->len == 0 ||
      range->start + range->len != next->start)
    return false;
  for (uint32_t pos = 0; pos < range->len; pos++)
    if (!isdigit((unsigned char)cmd[range->start + pos]))
      return false;
  return true;
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
static bool dep_prepare_fast_result(shell_parse_result_t *fast,
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
    const shell_range_t *range = &fast->cmds[i];
    if (range->len == 0 || range->start > command_length ||
        range->len > command_length - range->start ||
        range->start < previous_end ||
        !dep_fast_command_type_valid(range->type) ||
        (range->features & ~valid_features) != 0 ||
        (range->modifiers & ~SHELL_CMD_MOD_PIPE_NEGATED) != 0 ||
        (range->group_kinds & ~(SHELL_GROUP_BRACE | SHELL_GROUP_SUBSHELL)) != 0)
      return false;
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
        (group->parent != UINT16_MAX && group->parent >= i))
      return false;
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
  return true;
}

static shell_dep_error_t shell_dep_graph_parse_impl(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, uint32_t depth,
    const shell_parse_result_t *provided_fast, shell_dep_graph_t *out,
    dep_subgraph_streams_t *streams) {
  dep_subgraph_streams_t ignored_streams = {0};
  if (!streams)
    streams = &ignored_streams;
  else
    memset(streams, 0, sizeof(*streams));
  if (!cmd || !out || cmd_len == 0) {
    if (out) {
      out->node_count = 0;
      out->edge_count = 0;
      out->status = SHELL_DEP_STATUS_ERROR;
      out->cwd_buf.len = 0;
    }
    return SHELL_DEP_EINPUT;
  }

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

  shell_dep_limits_t local_limits;
  if (!limits) {
    local_limits = SHELL_DEP_LIMITS_DEFAULT;
    limits = &local_limits;
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

  shell_parse_result_t fast_result;
  shell_error_t fast_err;
  if (provided_fast) {
    fast_result = *provided_fast;
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
  if (!dep_prepare_fast_result(&fast_result, (uint32_t)cmd_len)) {
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
  const char *init_cwd = initial_cwd ? initial_cwd : ".";
  size_t init_len = strlen(init_cwd);
  if (init_len >= effective_cwd_buf_size) {
    init_len = effective_cwd_buf_size - 1;
    out->status |= SHELL_DEP_STATUS_TRUNCATED;
  }
  memcpy(out->cwd_buf.data, init_cwd, init_len);
  out->cwd_buf.data[init_len] = '\0';
  if (strcmp(init_cwd, ".") != 0) {
    cwd_normalize(out->cwd_buf.data, init_len);
  }
  init_len = strlen(out->cwd_buf.data);
  out->cwd_buf.len = init_len + 1;
  uint32_t cwd_offset = 0;
  bool cwd_known = true;

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
    node->group.pipeline_negated = group_is_pipeline_negated(group);
    node->group.parent =
        group->parent == UINT16_MAX || group_node[group->parent] == UINT32_MAX
            ? UINT32_MAX
            : group_node[group->parent];
    if (node->group.parent != UINT32_MAX) {
      if (out->edge_count >= max_edges) {
        out->status |= SHELL_DEP_STATUS_TRUNCATED;
      } else {
        dep_init_edge(&out->edges[out->edge_count++], node->group.parent,
                      node_index, SHELL_EDGE_GROUP, SHELL_DIR_FORWARD,
                      SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
      }
    }
  }

  dep_group_exec_t group_exec[SHELL_MAX_GROUPS] = {0};
  dep_prepare_group_execution(cmd, (uint32_t)cmd_len, &fast_result, group_exec);

  for (uint32_t si = 0; si < fast_result.count; si++) {
    if (skip_buf[si]) {
      if (fast_result.cmds[si].type & SHELL_TYPE_HEREDOC) {
        for (uint32_t h = 0; h < hcount; h++) {
          if (heredocs[h].marker_idx == si) {
            heredocs[h].cmd_node_idx = last_cmd_idx;
            heredocs[h].group_idx = find_preceding_group(
                &fast_result, cmd, fast_result.cmds[si].start);
            if (heredocs[h].group_idx < 0) {
              uint32_t redirect_start = fast_result.cmds[si].start;
              while (redirect_start > 0 &&
                     isdigit((unsigned char)cmd[redirect_start - 1]))
                redirect_start--;
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
          }
        }
      }
      continue;
    }

    const shell_range_t *range = &fast_result.cmds[si];
    uint32_t rstart = range->start;
    uint32_t rlen = range->len;
    int32_t isolated_group =
        dep_range_isolated_group(&fast_result, group_exec, si);
    uint32_t *range_cwd_offset = &cwd_offset;
    bool *range_cwd_known = &cwd_known;
    if (isolated_group >= 0) {
      dep_initialize_group_cwd(&fast_result, group_exec,
                               (uint32_t)isolated_group, cwd_offset, cwd_known);
      range_cwd_offset = &group_exec[isolated_group].cwd_offset;
      range_cwd_known = &group_exec[isolated_group].cwd_known;
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
      uint32_t pos = 3;
      while (pos < mlen && isspace((unsigned char)marker[pos]))
        pos++;

      const char *word = marker + pos;
      uint32_t word_len = mlen - pos;

      uint32_t document = UINT32_MAX;
      if (last_cmd_idx >= 0 &&
          add_document_read(out, max_nodes, max_edges, (uint32_t)last_cmd_idx,
                            SHELL_DOC_HERESTRING, NULL, 0, word, word_len,
                            inline_document_target_fd(cmd, rstart),
                            SHELL_DEP_DOC_FLAG_NONE, &out->status, &document)) {
        dep_token_t here_word = {word, word_len};
        shell_dep_error_t expansion_error = dep_connect_word_substitutions(
            out, max_nodes, max_edges, effective_cwd_buf_size, streams,
            &here_word, out->cwd_buf.data + *range_cwd_offset, limits, depth,
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

    dep_token_list_t tokens;
    if (scan_tokens(cmd, rstart, rlen, &tokens))
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
    if (tokens.malformed) {
      out->node_count = 0;
      out->edge_count = 0;
      out->status = SHELL_DEP_STATUS_ERROR;
      out->cwd_buf.len = 0;
      return SHELL_DEP_EPARSE;
    }

    for (uint32_t ti = 0; ti < tokens.count; ti++) {
      if (dep_token_is_named_fd_redirect(&tokens.tokens[ti]) &&
          classify_redirect(&tokens.tokens[ti]) == DEP_REDIRECT_DUP) {
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
    }

    if (tokens.count == 0)
      continue;

    bool is_cd = false;
    if (tokens.count >= 1) {
      const dep_token_t *t = &tokens.tokens[0];
      if (token_streq(t, "cd", 2))
        is_cd = true;
    }

    if (is_cd) {
      if (limits->cd_as_cmd && out->node_count < max_nodes) {
        uint32_t cmd_node_idx = out->node_count;
        shell_dep_node_t *node = &out->nodes[out->node_count++];
        node_range[cmd_node_idx] = si;
        node->type = SHELL_NODE_CMD;
        node->cmd.cwd_offset = *range_cwd_offset;
        node->cmd.group_depth = range->group_depth;
        node->cmd.group_kinds = range->group_kinds;
        node->cmd.backgrounded = range_backgrounded;
        node->cmd.pipeline_negated =
            (range->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0;
        node->cmd.cwd_known = *range_cwd_known;
        node->cmd.token_count = 0;
        if (tokens.count > max_tokens)
          out->status |= SHELL_DEP_STATUS_TRUNCATED;

        for (uint32_t ti = 0;
             ti < tokens.count && node->cmd.token_count < max_tokens; ti++) {
          node->cmd.tokens[ti] = tokens.tokens[ti].start;
          node->cmd.token_lens[ti] = tokens.tokens[ti].len;
          node->cmd.token_count++;
        }

        if (out->edge_count < max_edges) {
          dep_init_edge(&out->edges[out->edge_count++], cmd_node_idx,
                        cmd_node_idx, SHELL_EDGE_CWD, SHELL_DIR_FORWARD,
                        SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
        } else
          out->status |= SHELL_DEP_STATUS_TRUNCATED;

        for (uint32_t ti = 1; ti < tokens.count; ti++) {
          const dep_token_t *tok = &tokens.tokens[ti];
          bool looks_like_path = token_looks_like_path(tok);
          if (looks_like_path && out->node_count < max_nodes &&
              out->edge_count < max_edges) {
            shell_dep_node_t *an = &out->nodes[out->node_count++];
            an->type = SHELL_NODE_DOC;
            an->doc.kind = SHELL_DOC_FILE;
            an->doc.path = tok->start;
            an->doc.path_len = tok->len;
            an->doc.name = NULL;
            an->doc.name_len = 0;
            an->doc.value = NULL;
            an->doc.value_len = 0;
            an->doc.flags = SHELL_DEP_DOC_FLAG_NONE;

            dep_init_edge(&out->edges[out->edge_count++], cmd_node_idx,
                          out->node_count - 1, SHELL_EDGE_ARG, SHELL_DIR_UNDIR,
                          SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
          } else if (looks_like_path)
            out->status |= SHELL_DEP_STATUS_TRUNCATED;
        }
        last_cmd_idx = (int32_t)cmd_node_idx;
      } else if (limits->cd_as_cmd)
        out->status |= SHELL_DEP_STATUS_TRUNCATED;

      /* An enclosing isolated group owns its own mutable CWD state. Only a
       * simple command that itself runs asynchronously or as a pipeline
       * element suppresses the update below. */
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

      const dep_token_t *cd_operand = NULL;
      dep_cd_target_t cd_target_kind = cd_target(&tokens, &cd_operand);
      if (cd_target_kind == DEP_CD_OPERAND && !cwd_isolated &&
          *range_cwd_known) {
        char arg_buf[256];
        bool tilde_expanded = false;
        bool truncated = false;
        if (!decode_static_cwd_operand(cd_operand, arg_buf, sizeof(arg_buf),
                                       &tilde_expanded, &truncated)) {
          *range_cwd_known = false;
          if (truncated)
            out->status |= SHELL_DEP_STATUS_TRUNCATED;
        } else if (cwd_operand_uses_cdpath(arg_buf, tilde_expanded)) {
          *range_cwd_known = false;
        } else {
          uint32_t status_before = out->status;
          *range_cwd_offset =
              cwd_resolve_dedup(out, *range_cwd_offset, arg_buf, tilde_expanded,
                                effective_cwd_buf_size, &out->status);
          if ((out->status & ~status_before) != 0)
            *range_cwd_known = false;
        }
      } else if (cd_target_kind == DEP_CD_HOME && !cwd_isolated &&
                 *range_cwd_known) {
        *range_cwd_offset =
            cwd_resolve_dedup(out, *range_cwd_offset, "$HOME", true,
                              effective_cwd_buf_size, &out->status);
      } else if (cd_target_kind == DEP_CD_DYNAMIC && !cwd_isolated &&
                 *range_cwd_known) {
        *range_cwd_known = false;
      }
      if (next_conditional)
        *range_cwd_known = false;
      continue;
    }

    bool is_redirect_only = true;
    {
      uint32_t t = 0;
      while (t < tokens.count) {
        dep_redirect_t r = classify_redirect(&tokens.tokens[t]);
        if (r != DEP_REDIRECT_NONE) {
          t += r == DEP_REDIRECT_DUP ? 1 : 2;
        } else {
          is_redirect_only = false;
          break;
        }
      }
    }

    if (is_redirect_only && tokens.count > 0 && last_cmd_idx >= 0) {
      uint32_t prev_cmd = (uint32_t)last_cmd_idx;
      uint32_t t = 0;
      while (t < tokens.count) {
        dep_redirect_t redir = classify_redirect(&tokens.tokens[t]);
        t++;
        if (redir == DEP_REDIRECT_DUP)
          continue;
        if (t < tokens.count && redir != DEP_REDIRECT_NONE) {
          const dep_token_t *target = &tokens.tokens[t];
          uint32_t owner = prev_cmd;
          /* A redirect immediately following a completed group belongs to
           * that group execution endpoint. Do not project it onto members. */
          int32_t group = find_preceding_group(&fast_result, cmd, rstart);
          if (group < 0)
            group = find_trailing_redirect_group(&fast_result, cmd, rstart);
          if (group >= 0 && group_node[group] != UINT32_MAX)
            owner = group_node[group];

          bool handled_process = false;
          shell_dep_error_t process_error =
              dep_connect_redirect_process_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                  &tokens.tokens[t - 1], redir, target,
                  out->cwd_buf.data + *range_cwd_offset, limits, depth, owner,
                  &handled_process);
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
            document_added = add_doc_file_named_fd_open(
                out, max_nodes, max_edges, target->start, target->len, owner,
                redir, &out->status, &document);
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
          if (document_added &&
              dep_connect_word_substitutions_kind(
                  out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                  target, out->cwd_buf.data + *range_cwd_offset, limits, depth,
                  document, DEP_SUBST_DYNAMIC_NAME) == SHELL_DEP_EPARSE) {
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

    bool is_export = false;
    if (tokens.count >= 1 && token_streq(&tokens.tokens[0], "export", 6))
      is_export = true;

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
    node->cmd.pipeline_negated =
        (range->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0;
    node->cmd.cwd_known = *range_cwd_known && range->type != SHELL_TYPE_AND &&
                          range->type != SHELL_TYPE_OR;
    node->cmd.token_count = 0;
    if (tokens.count > max_tokens)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;

    uint32_t ti = 0;

    if (is_export) {
      if (node->cmd.token_count < max_tokens) {
        uint32_t idx = node->cmd.token_count++;
        node->cmd.tokens[idx] = tokens.tokens[0].start;
        node->cmd.token_lens[idx] = tokens.tokens[0].len;
      }
      ti = 1;

      while (ti < tokens.count) {
        const dep_token_t *etok = &tokens.tokens[ti];

        if (is_env_assign(etok)) {
          uint32_t eq_pos = 0;
          for (uint32_t i = 0; i < etok->len; i++) {
            if (etok->start[i] == '=') {
              eq_pos = i;
              break;
            }
          }

          add_doc_envvar(out, max_nodes, max_edges, etok->start, eq_pos,
                         etok->start + eq_pos + 1, etok->len - eq_pos - 1,
                         cmd_node_idx, &out->status);
          dep_token_t value = {etok->start + eq_pos + 1,
                               etok->len - eq_pos - 1};
          if (dep_connect_word_substitutions(
                  out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                  &value, out->cwd_buf.data + *range_cwd_offset, limits, depth,
                  cmd_node_idx) == SHELL_DEP_EPARSE) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = SHELL_DEP_STATUS_ERROR;
            out->cwd_buf.len = 0;
            return SHELL_DEP_EPARSE;
          }

          if (node->cmd.token_count < max_tokens) {
            uint32_t idx = node->cmd.token_count++;
            node->cmd.tokens[idx] = etok->start;
            node->cmd.token_lens[idx] = etok->len;
          }
        } else {
          if (node->cmd.token_count < max_tokens) {
            uint32_t idx = node->cmd.token_count++;
            node->cmd.tokens[idx] = etok->start;
            node->cmd.token_lens[idx] = etok->len;
          }
        }
        ti++;
      }
      goto add_control_edge;
    }

    while (ti < tokens.count && is_env_assign(&tokens.tokens[ti])) {
      const dep_token_t *etok = &tokens.tokens[ti];
      uint32_t eq_pos = 0;
      for (uint32_t i = 0; i < etok->len; i++) {
        if (etok->start[i] == '=') {
          eq_pos = i;
          break;
        }
      }

      add_doc_envvar(out, max_nodes, max_edges, etok->start, eq_pos,
                     etok->start + eq_pos + 1, etok->len - eq_pos - 1,
                     cmd_node_idx, &out->status);
      dep_token_t value = {etok->start + eq_pos + 1, etok->len - eq_pos - 1};
      if (dep_connect_word_substitutions(
              out, max_nodes, max_edges, effective_cwd_buf_size, streams,
              &value, out->cwd_buf.data + *range_cwd_offset, limits, depth,
              cmd_node_idx) == SHELL_DEP_EPARSE) {
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
        ti++;
        if (redir == DEP_REDIRECT_DUP)
          continue;
        if (ti < tokens.count) {
          const dep_token_t *target = &tokens.tokens[ti];
          bool handled_process = false;
          shell_dep_error_t process_error =
              dep_connect_redirect_process_substitution(
                  out, max_nodes, max_edges, effective_cwd_buf_size, streams,
                  tok, redir, target, out->cwd_buf.data + *range_cwd_offset,
                  limits, depth, cmd_node_idx, &handled_process);
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
            document_added = add_doc_file_named_fd_open(
                out, max_nodes, max_edges, target->start, target->len,
                cmd_node_idx, redir, &out->status, &document);
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
          shell_dep_error_t expansion_error =
              document_added
                  ? dep_connect_word_substitutions_kind(
                        out, max_nodes, max_edges, effective_cwd_buf_size,
                        streams, target, out->cwd_buf.data + *range_cwd_offset,
                        limits, depth, document, DEP_SUBST_DYNAMIC_NAME)
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
                sub_content, sub_len, sub_cwd_str, limits, depth, cmd_node_idx,
                DEP_SUBST_SHELL_WORD, &file_handled);
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
            shell_dep_error_t sub_err = shell_dep_graph_parse_impl(
                sub_content, sub_len, sub_cwd_str, limits, depth + 1, NULL,
                &sub_graph, &subgraph_streams);
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
                    1);
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

  add_control_edge:;
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
      }

    } else if (last_cmd_idx >= 0)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;

    if (si + 1 < fast_result.count &&
        (fast_result.cmds[si + 1].type == SHELL_TYPE_AND ||
         fast_result.cmds[si + 1].type == SHELL_TYPE_OR))
      *range_cwd_known = false;
    last_cmd_idx = (int32_t)cmd_node_idx;
  }

  for (uint32_t i = 0; i < fast_result.group_count; i++) {
    const shell_group_t *group = &fast_result.groups[i];
    if (group_node[i] == UINT32_MAX)
      continue;
    dep_group_herestring_t here_strings[SHELL_DEP_MAX_EDGES];
    bool complete = true;
    uint32_t here_count = scan_group_herestrings(
        cmd, (uint32_t)cmd_len, group, here_strings,
        sizeof(here_strings) / sizeof(here_strings[0]), &complete);
    if (!complete)
      out->status |= SHELL_DEP_STATUS_TRUNCATED;
    for (uint32_t h = 0; h < here_count; h++) {
      const dep_group_herestring_t *here = &here_strings[h];
      uint32_t document = UINT32_MAX;
      if (!add_document_read(out, max_nodes, max_edges, group_node[i],
                             SHELL_DOC_HERESTRING, NULL, 0, here->value,
                             here->value_len, here->target_fd,
                             SHELL_DEP_DOC_FLAG_NONE, &out->status, &document))
        continue;
      dep_token_t here_word = {here->value, here->value_len};
      shell_dep_error_t expansion_error = dep_connect_word_substitutions(
          out, max_nodes, max_edges, effective_cwd_buf_size, streams,
          &here_word, out->cwd_buf.data + cwd_offset, limits, depth, document);
      if (expansion_error == SHELL_DEP_EPARSE) {
        out->node_count = 0;
        out->edge_count = 0;
        out->status = SHELL_DEP_STATUS_ERROR;
        out->cwd_buf.len = 0;
        return SHELL_DEP_EPARSE;
      }
    }
  }

  for (uint32_t h = 0; h < hcount; h++) {
    heredoc_info_t *hd = &heredocs[h];
    if (!hd->has_source_span)
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
    if (!add_document_read(out, max_nodes, max_edges, owner, SHELL_DOC_HEREDOC,
                           hd->delimiter, hd->delimiter_len, content_ptr,
                           content_len,
                           inline_document_target_fd(
                               cmd, fast_result.cmds[hd->marker_idx].start),
                           flags, &out->status, &document) ||
        hd->literal || content_len == 0)
      continue;
    shell_dep_error_t expansion_error = dep_connect_heredoc_substitutions(
        out, max_nodes, max_edges, effective_cwd_buf_size, streams, content_ptr,
        content_len, out->cwd_buf.data + cwd_offset, limits, depth, document);
    if (expansion_error == SHELL_DEP_EPARSE) {
      out->node_count = 0;
      out->edge_count = 0;
      out->status = SHELL_DEP_STATUS_ERROR;
      out->cwd_buf.len = 0;
      return SHELL_DEP_EPARSE;
    }
  }

  dep_resolve_effective_routes(out, cmd, (uint32_t)cmd_len, &fast_result,
                               node_range, group_node, max_nodes, max_edges,
                               streams);
  dep_mark_transient_inline_documents(out);
  return (out->status & SHELL_DEP_STATUS_TRUNCATED) ? SHELL_DEP_ETRUNC
                                                    : SHELL_DEP_OK;
}

shell_dep_error_t shell_dep_graph_parse(const char *cmd, size_t cmd_len,
                                        const char *initial_cwd,
                                        const shell_dep_limits_t *limits,
                                        shell_dep_graph_t *out) {
  return shell_dep_graph_parse_impl(cmd, cmd_len, initial_cwd, limits, 0, NULL,
                                    out, NULL);
}

shell_dep_error_t shell_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) {
  if (!fast)
    return shell_dep_graph_parse(cmd, cmd_len, initial_cwd, limits, out);
  return shell_dep_graph_parse_impl(cmd, cmd_len, initial_cwd, limits, 0, fast,
                                    out, NULL);
}

/* --- GRAPH UTILITIES --- */

void shell_dep_graph_dump(const shell_dep_graph_t *g, FILE *fp) {
  fprintf(fp, "Graph: %u nodes, %u edges, status=0x%x\n", g->node_count,
          g->edge_count, g->status);

  fprintf(fp, "Nodes:\n");
  for (uint32_t i = 0; i < g->node_count; i++) {
    const shell_dep_node_t *n = &g->nodes[i];
    if (n->type == SHELL_NODE_CMD) {
      fprintf(fp, "  [%u] CMD cwd=\"%s\"%s tokens=[", i,
              n->cmd.cwd_offset < g->cwd_buf.len
                  ? g->cwd_buf.data + n->cmd.cwd_offset
                  : "?",
              n->cmd.pipeline_negated ? " negated" : "");
      for (uint32_t j = 0; j < n->cmd.token_count; j++) {
        if (j > 0)
          fprintf(fp, ", ");
        fprintf(fp, "\"%.*s\"", n->cmd.token_lens[j], n->cmd.tokens[j]);
      }
      fprintf(fp, "]\n");
    } else if (n->type == SHELL_NODE_GROUP) {
      fprintf(fp, "  [%u] GROUP span=\"%.*s\" parent=%u%s\n", i,
              n->group.length, n->group.start ? n->group.start : "",
              n->group.parent, n->group.pipeline_negated ? " negated" : "");
    } else if (n->type == SHELL_NODE_ENDPOINT) {
      fprintf(fp, "  [%u] ENDPOINT%s\n", i,
              n->endpoint.reserved == DEP_ENDPOINT_TERMINAL_PIPE
                  ? " terminal-pipe"
                  : "");
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
    if (e->flags != SHELL_DEP_EDGE_FLAG_NONE)
      fprintf(fp, " flags=0x%x", e->flags);
    fputc('\n', fp);
  }
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
    } else if (n->type == SHELL_NODE_DOC) {
      const shell_dep_doc_t *doc = &n->doc;
      const uint8_t known_flags = SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS |
                                  SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
                                  SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL |
                                  SHELL_DEP_DOC_FLAG_TRANSIENT;
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
                        (doc->flags & ~(SHELL_DEP_DOC_FLAG_DYNAMIC_NAME)) == 0;
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
                        doc->flags == SHELL_DEP_DOC_FLAG_NONE;
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
          n->endpoint.reserved != DEP_ENDPOINT_TERMINAL_PIPE) {
        r.valid = false;
        snprintf(r.errors[r.error_count].msg, 96,
                 "ENDPOINT node %u: unknown endpoint flags %u", i,
                 n->endpoint.reserved);
        r.error_count++;
        continue;
      }
      bool has_producer = false;
      bool has_consumer = false;
      bool topology_valid = true;
      for (uint32_t edge = 0; edge < g->edge_count; edge++) {
        const shell_dep_edge_t *current = &g->edges[edge];
        if (current->to == i) {
          bool producer = n->endpoint.reserved == DEP_ENDPOINT_TERMINAL_PIPE
                              ? current->type == SHELL_EDGE_PIPE
                              : current->type == SHELL_EDGE_WRITE;
          topology_valid = topology_valid && producer;
          has_producer = has_producer || producer;
        }
        if (current->from == i) {
          bool consumer =
              n->endpoint.reserved == 0 && current->type == SHELL_EDGE_SUBST;
          topology_valid = topology_valid && consumer;
          has_consumer = has_consumer || consumer;
        }
      }
      if (!topology_valid || !has_producer ||
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

    if (e->type > SHELL_EDGE_FD_OPEN || e->dir > SHELL_DIR_UNDIR) {
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

    if ((e->flags & ~(SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                      SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME)) != 0 ||
        ((e->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
         (e->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0) ||
        (e->type != SHELL_EDGE_SUBST && e->flags != SHELL_DEP_EDGE_FLAG_NONE)) {
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
      ok = (((ft == SHELL_NODE_CMD || ft == SHELL_NODE_GROUP) &&
             tt == SHELL_NODE_DOC && e->source_fd == SHELL_DEP_FD_NAMED &&
             e->target_fd == SHELL_DEP_FD_NONE) ||
            (ft == SHELL_NODE_DOC &&
             (tt == SHELL_NODE_CMD || tt == SHELL_NODE_GROUP) &&
             e->source_fd == SHELL_DEP_FD_NONE &&
             e->target_fd == SHELL_DEP_FD_NAMED)) &&
           e->dir == SHELL_DIR_FORWARD;
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
  default:
    return "Unknown error";
  }
}
