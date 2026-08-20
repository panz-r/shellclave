#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * trie.c - Normalised Command Trie (NCT) with typed wildcards.
 *
 * Each node stores a token type (literal or wildcard). Suggestions use
 * the join of all observed types at each position for precise generalisation.
 */

#include "shelltype.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc.h"
#include "io.h"
#include "metadata.h"
#include "read_line.h"

/* Check if a type supports parametrized wildcards.
 * Mirrors type_supports_param() in policy.c. */
static bool trie_type_supports_param(st_token_type_t t) {
  return st_type_supports_metadata(t);
}

static const st_metadata_entry_t *sample_metadata(st_token_type_t type,
                                                  const char *text) {
  if (!text)
    return NULL;
  if (type == ST_TYPE_SIZE)
    return st_metadata_lookup(type, st_size_suffix(text));
  if (type == ST_TYPE_DURATION) {
    const char *suffix = text;
    if (*suffix == '-')
      suffix++;
    while (*suffix && (isdigit((unsigned char)*suffix) || *suffix == '.'))
      suffix++;
    return st_metadata_lookup(type, suffix);
  }
  if (type == ST_TYPE_UUID && strlen(text) == 36)
    return st_metadata_lookup(type, text[14] == '4'   ? "v4"
                                    : text[14] == '5' ? "v5"
                                                      : NULL);
  if (type == ST_TYPE_TIMESTAMP) {
    size_t len = strlen(text);
    if (len == 10)
      return st_metadata_lookup(type, "date");
    if (len == 8)
      return st_metadata_lookup(type, "time");
    if (len >= 19)
      return st_metadata_lookup(type, "datetime");
  }
  if (type == ST_TYPE_SHA) {
    size_t len = strlen(text);
    return st_metadata_lookup(type, len == 7    ? "short"
                                    : len == 40 ? "40"
                                    : len == 64 ? "64"
                                                : NULL);
  }
  if (type == ST_TYPE_FINGERPRINT)
    return st_metadata_lookup(type, strncmp(text, "SHA256:", 7) == 0 ? "sha256"
                                                                     : "md5");
  if (type == ST_TYPE_RANGE)
    return st_metadata_lookup(type, "step");
  if (type == ST_TYPE_PERM_OCTAL)
    return st_metadata_lookup(type, "bits");
  return NULL;
}

/* --- NODE HELPERS --- */

static st_node_t *node_new(const char *token, st_token_type_t type) {
  st_node_t *node = calloc(1, sizeof(st_node_t));
  if (!node)
    return NULL;

  node->token = strdup(token);
  if (!node->token) {
    free(node);
    return NULL;
  }

  node->type = type;
  node->count = 0;
  node->observed_types = 0;
  node->children = NULL;
  node->num_children = 0;
  node->children_capacity = 0;
  node->sample_values = NULL;
  node->num_samples = 0;
  node->metadata_observations = 0;
  node->common_metadata = ST_META_NONE;
  node->metadata_mixed = false;

  return node;
}

static void node_free(st_node_t *node) {
  if (!node)
    return;
  for (size_t i = 0; i < node->num_children; i++) {
    node_free(node->children[i]);
  }
  free(node->children);
  for (size_t i = 0; i < node->num_samples; i++) {
    free(node->sample_values[i]);
  }
  free(node->sample_values);
  free(node->token);
  free(node);
}

static bool node_ensure_capacity(st_node_t *node, size_t needed) {
  if (node->children_capacity >= needed)
    return true;
  size_t new_cap = node->children_capacity == 0 ? ST_INITIAL_CHILDREN_CAP
                                                : node->children_capacity * 2;
  while (new_cap < needed)
    new_cap *= 2;
  st_node_t **new_children =
      realloc(node->children, new_cap * sizeof(st_node_t *));
  if (!new_children)
    return false;
  node->children = new_children;
  node->children_capacity = new_cap;
  return true;
}

/* Find child by token text (for literals) or by type (for wildcards) */
static st_node_t *node_find_child(st_node_t *node, const char *token,
                                  st_token_type_t type) {
  for (size_t i = 0; i < node->num_children; i++) {
    st_node_t *child = node->children[i];
    if (child->type == ST_TYPE_LITERAL && type == ST_TYPE_LITERAL) {
      if (strcmp(child->token, token) == 0)
        return child;
    } else if (child->type == type) {
      return child;
    }
  }
  return NULL;
}

/* --- TRIE INSERTION --- */

static st_error_t trie_insert_with_count(st_node_t *root, st_token_t *tokens,
                                         size_t count, uint32_t increment) {
  if (increment > UINT32_MAX - root->count)
    return ST_ERR_LIMIT;
  st_node_t *current = root;
  for (size_t i = 0; i < count; i++) {
    st_node_t *child = node_find_child(current, tokens[i].text, tokens[i].type);
    if (!child)
      break;
    if (increment > UINT32_MAX - child->count)
      return ST_ERR_LIMIT;
    current = child;
  }

  st_node_t *path[ST_MAX_CMD_TOKENS + 1] = {root};
  uint64_t old_observed[ST_MAX_CMD_TOKENS] = {0};
  uint32_t old_metadata_observations[ST_MAX_CMD_TOKENS] = {0};
  uint16_t old_common_metadata[ST_MAX_CMD_TOKENS] = {0};
  bool old_metadata_mixed[ST_MAX_CMD_TOKENS] = {false};
  bool sample_added[ST_MAX_CMD_TOKENS] = {false};
  size_t path_count = 1;
  size_t created_index = SIZE_MAX;
  current = root;
  current->count += increment;

  for (size_t i = 0; i < count; i++) {
    st_node_t *child = node_find_child(current, tokens[i].text, tokens[i].type);
    if (!child) {
      if (!node_ensure_capacity(current, current->num_children + 1))
        goto memory_failure;
      const char *tok_str = (tokens[i].type == ST_TYPE_LITERAL)
                                ? tokens[i].text
                                : st_type_symbol[tokens[i].type];
      child = node_new(tok_str, tokens[i].type);
      if (!child)
        goto memory_failure;
      current->children[current->num_children++] = child;
      if (created_index == SIZE_MAX)
        created_index = i;
    }

    path[path_count++] = child;
    child->count += increment;
    old_observed[i] = child->observed_types;
    old_metadata_observations[i] = child->metadata_observations;
    old_common_metadata[i] = child->common_metadata;
    old_metadata_mixed[i] = child->metadata_mixed;
    /* Track observed types at this position */
    if (tokens[i].type != ST_TYPE_LITERAL) {
      child->observed_types |= (1ULL << tokens[i].type);
      const st_metadata_entry_t *observed =
          sample_metadata(tokens[i].type, tokens[i].text);
      if (increment > UINT32_MAX - child->metadata_observations)
        goto limit_failure;
      if (child->metadata_observations == 0 && observed) {
        child->common_metadata = (uint16_t)observed->id;
      } else if (!observed ||
                 child->common_metadata != (uint16_t)observed->id) {
        child->metadata_mixed = true;
      }
      child->metadata_observations += increment;
      /* Store original value as sample (for parametrized suggestions) */
      if (child->num_samples < ST_MAX_SAMPLE_VALUES) {
        char **new_vals = realloc(child->sample_values,
                                  (child->num_samples + 1) * sizeof(char *));
        if (!new_vals)
          goto memory_failure;
        child->sample_values = new_vals;
        child->sample_values[child->num_samples] = strdup(tokens[i].text);
        if (!child->sample_values[child->num_samples])
          goto memory_failure;
        child->num_samples++;
        sample_added[i] = true;
      }
    }
    current = child;
  }
  return ST_OK;

limit_failure:
  for (size_t i = 0; i < path_count; i++)
    path[i]->count -= increment;
  {
    size_t existing_tokens =
        created_index == SIZE_MAX ? path_count - 1 : created_index;
    for (size_t i = 0; i < existing_tokens; i++) {
      st_node_t *node = path[i + 1];
      node->observed_types = old_observed[i];
      node->metadata_observations = old_metadata_observations[i];
      node->common_metadata = old_common_metadata[i];
      node->metadata_mixed = old_metadata_mixed[i];
      if (sample_added[i]) {
        free(node->sample_values[node->num_samples - 1]);
        node->num_samples--;
      }
    }
  }
  if (created_index != SIZE_MAX) {
    st_node_t *parent = path[created_index];
    parent->num_children--;
    node_free(path[created_index + 1]);
  }
  return ST_ERR_LIMIT;

memory_failure:
  for (size_t i = 0; i < path_count; i++)
    path[i]->count -= increment;
  size_t existing_tokens =
      created_index == SIZE_MAX ? path_count - 1 : created_index;
  for (size_t i = 0; i < existing_tokens; i++) {
    st_node_t *node = path[i + 1];
    node->observed_types = old_observed[i];
    node->metadata_observations = old_metadata_observations[i];
    node->common_metadata = old_common_metadata[i];
    node->metadata_mixed = old_metadata_mixed[i];
    if (sample_added[i]) {
      free(node->sample_values[node->num_samples - 1]);
      node->num_samples--;
    }
  }
  if (created_index != SIZE_MAX) {
    st_node_t *parent = path[created_index];
    st_node_t *created = path[created_index + 1];
    assert(parent->num_children > 0 &&
           parent->children[parent->num_children - 1] == created);
    parent->num_children--;
    node_free(created);
  }
  return ST_ERR_MEMORY;
}

static st_error_t learner_insert_atomic(st_learner_t *learner,
                                        st_token_t *tokens, size_t count) {
  if (learner->trie.total_commands == UINT32_MAX)
    return ST_ERR_LIMIT;
  st_error_t err = trie_insert_with_count(learner->trie.root, tokens, count, 1);
  if (err == ST_OK)
    learner->trie.total_commands++;
  return err;
}

static bool learner_tokens_valid(const st_token_t *tokens, size_t count) {
  if (!tokens || count == 0 || count > ST_MAX_CMD_TOKENS)
    return false;
  for (size_t i = 0; i < count; i++) {
    if (!tokens[i].text || tokens[i].text[0] == '\0' ||
        tokens[i].type < ST_TYPE_LITERAL || tokens[i].type >= ST_TYPE_COUNT ||
        strlen(tokens[i].text) >= ST_MAX_TOKEN_LEN)
      return false;
    if (tokens[i].type == ST_TYPE_LITERAL)
      for (const unsigned char *p = (const unsigned char *)tokens[i].text; *p;
           p++)
        if ((*p < 0x20 && *p != ' ') || *p == 0x7f)
          return false;
  }
  return true;
}

/* --- PUBLIC API – LIFECYCLE --- */

st_learner_t *st_learner_new(uint32_t min_support, double min_confidence) {
  st_learner_t *learner = calloc(1, sizeof(st_learner_t));
  if (!learner)
    return NULL;

  learner->trie.root = node_new("", ST_TYPE_LITERAL);
  if (!learner->trie.root) {
    free(learner);
    return NULL;
  }

  learner->trie.total_commands = 0;
  learner->min_support = min_support > 0 ? min_support : ST_DEFAULT_MIN_SUPPORT;
  learner->min_confidence = min_confidence;
  learner->max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS;
  learner->blacklist = NULL;
  learner->blacklist_count = 0;
  learner->blacklist_capacity = 0;

  return learner;
}

void st_learner_free(st_learner_t *learner) {
  if (!learner)
    return;
  node_free(learner->trie.root);
  for (size_t i = 0; i < learner->blacklist_count; i++) {
    free(learner->blacklist[i]);
  }
  free(learner->blacklist);
  free(learner);
}

/* --- PUBLIC API – FEED --- */

st_error_t st_feed(st_learner_t *learner, const char *raw_cmd) {
  if (!learner || !raw_cmd || !raw_cmd[0])
    return ST_ERR_INVALID;

  st_token_array_t typed;
  typed.tokens = NULL;
  typed.count = 0;
  st_error_t err = st_normalize_typed(raw_cmd, &typed);
  if (err != ST_OK)
    return err;
  if (!learner_tokens_valid(typed.tokens, typed.count)) {
    st_free_token_array(&typed);
    return ST_ERR_INVALID;
  }

  err = learner_insert_atomic(learner, typed.tokens, typed.count);
  st_free_token_array(&typed);
  return err;
}

st_error_t st_feed_parsed(st_learner_t *learner, const char *raw_cmd,
                          const void *parse) {
  if (!learner || !raw_cmd || !raw_cmd[0] || !parse)
    return ST_ERR_INVALID;

  const st_token_array_t *typed = (const st_token_array_t *)parse;
  if (!learner_tokens_valid(typed->tokens, typed->count))
    return ST_ERR_INVALID;
  return learner_insert_atomic(learner, typed->tokens, typed->count);
}

/* --- PUBLIC API – SUGGESTIONS --- */

typedef struct {
  char *pattern;
  uint32_t count;
  double confidence;
} st_candidate_t;

typedef struct {
  st_candidate_t *candidates;
  size_t count;
  size_t capacity;
  uint32_t min_support;
  double min_confidence;
  const st_learner_t *learner;
  bool failed;
} dfs_ctx_t;

static bool dfs_ctx_ensure(dfs_ctx_t *ctx) {
  if (ctx->capacity >= ctx->count + 1)
    return true;
  size_t new_cap = ctx->capacity == 0 ? 64 : ctx->capacity * 2;
  st_candidate_t *new_arr =
      realloc(ctx->candidates, new_cap * sizeof(st_candidate_t));
  if (!new_arr)
    return false;
  ctx->candidates = new_arr;
  ctx->capacity = new_cap;
  return true;
}

static const char *node_suggestion_token(const st_node_t *node,
                                         st_token_type_t type,
                                         char buffer[32]) {
  snprintf(buffer, 32, "%s", st_type_symbol[type]);
  if (node && node->metadata_observations >= 2 && !node->metadata_mixed &&
      node->common_metadata != ST_META_NONE && trie_type_supports_param(type) &&
      type != ST_TYPE_SEMVER) {
    const st_metadata_entry_t *common = NULL;
    for (size_t i = 0;
         i < sizeof(st_metadata_entries) / sizeof(st_metadata_entries[0]); i++)
      if (st_metadata_entries[i].id ==
          (st_metadata_id_t)node->common_metadata) {
        common = &st_metadata_entries[i];
        break;
      }
    if (common && common->type == type)
      snprintf(buffer, 32, "%s.%s", st_type_symbol[type], common->name);
  }
  return buffer;
}

typedef struct {
  st_candidate_t *items;
  size_t count;
  size_t capacity;
} candidate_list_t;

typedef struct {
  st_candidate_t suffix;
  const st_node_t *child;
} branch_candidate_t;

static void candidate_list_free(candidate_list_t *list) {
  for (size_t i = 0; i < list->count; i++)
    free(list->items[i].pattern);
  free(list->items);
  memset(list, 0, sizeof(*list));
}

static bool candidate_list_append(candidate_list_t *list,
                                  st_candidate_t candidate) {
  if (list->count == list->capacity) {
    size_t capacity = list->capacity == 0 ? 4 : list->capacity * 2;
    if (capacity < list->capacity || capacity > SIZE_MAX / sizeof(*list->items))
      return false;
    st_candidate_t *grown =
        realloc(list->items, capacity * sizeof(*list->items));
    if (!grown)
      return false;
    list->items = grown;
    list->capacity = capacity;
  }
  list->items[list->count++] = candidate;
  return true;
}

static uint32_t node_terminal_count(const st_node_t *node) {
  uint64_t continued = 0;
  for (size_t i = 0; i < node->num_children; i++)
    continued += node->children[i]->count;
  assert(continued <= node->count);
  return node->count - (uint32_t)continued;
}

static bool literal_is_unrepresentable(const char *token) {
  if (!token || token[0] == '\0' || strpbrk(token, " \t\r\n\v\f"))
    return true;
  if (strcmp(token, "*") == 0)
    return true;
  for (int type = ST_TYPE_LITERAL + 1; type < ST_TYPE_COUNT; type++) {
    const char *symbol = st_type_symbol[type];
    size_t length = strlen(symbol);
    if (strcmp(token, symbol) == 0 ||
        (symbol[0] == '#' && strncmp(token, symbol, length) == 0 &&
         token[length] == '.'))
      return true;
  }
  return false;
}

static int compare_branch_candidates(const void *left, const void *right) {
  const branch_candidate_t *a = left;
  const branch_candidate_t *b = right;
  int suffix = strcmp(a->suffix.pattern, b->suffix.pattern);
  if (suffix != 0)
    return suffix;
  if (a->child->type != b->child->type)
    return a->child->type < b->child->type ? -1 : 1;
  return strcmp(a->child->token, b->child->token);
}

static bool append_prefixed(candidate_list_t *output,
                            const branch_candidate_t *branch, const char *token,
                            double confidence) {
  size_t token_length = strlen(token);
  size_t suffix_length = strlen(branch->suffix.pattern);
  if (token_length >= ST_MAX_PATTERN_LEN ||
      suffix_length >= ST_MAX_PATTERN_LEN - token_length - (suffix_length != 0))
    return true;
  size_t length = token_length + (suffix_length != 0) + suffix_length;
  char *pattern = malloc(length + 1);
  if (!pattern)
    return false;
  memcpy(pattern, token, token_length);
  size_t used = token_length;
  if (suffix_length != 0)
    pattern[used++] = ' ';
  memcpy(pattern + used, branch->suffix.pattern, suffix_length + 1);
  st_candidate_t candidate = {.pattern = pattern,
                              .count = branch->suffix.count,
                              .confidence = confidence};
  if (!candidate_list_append(output, candidate)) {
    free(pattern);
    return false;
  }
  return true;
}

/* Return complete terminal continuations following node.  Each returned
 * pattern is empty only when a command terminates at node itself. */
static bool collect_complete_continuations(const st_node_t *node,
                                           candidate_list_t *output) {
  uint32_t terminal = node_terminal_count(node);
  if (terminal != 0) {
    char *empty = strdup("");
    if (!empty || !candidate_list_append(
                      output, (st_candidate_t){empty, terminal, 1.0})) {
      free(empty);
      return false;
    }
  }

  branch_candidate_t *branches = NULL;
  size_t branch_count = 0;
  size_t branch_capacity = 0;
  for (size_t child_index = 0; child_index < node->num_children;
       child_index++) {
    const st_node_t *child = node->children[child_index];
    candidate_list_t suffixes = {0};
    if (!collect_complete_continuations(child, &suffixes)) {
      candidate_list_free(&suffixes);
      goto failure;
    }
    if (suffixes.count > SIZE_MAX - branch_count)
      goto suffix_failure;
    size_t needed = branch_count + suffixes.count;
    if (needed > branch_capacity) {
      size_t capacity = branch_capacity == 0 ? 8 : branch_capacity;
      while (capacity < needed) {
        if (capacity > SIZE_MAX / 2)
          goto suffix_failure;
        capacity *= 2;
      }
      if (capacity > SIZE_MAX / sizeof(*branches))
        goto suffix_failure;
      branch_candidate_t *grown =
          realloc(branches, capacity * sizeof(*branches));
      if (!grown)
        goto suffix_failure;
      branches = grown;
      branch_capacity = capacity;
    }
    for (size_t i = 0; i < suffixes.count; i++)
      branches[branch_count++] = (branch_candidate_t){suffixes.items[i], child};
    free(suffixes.items);
    continue;

  suffix_failure:
    candidate_list_free(&suffixes);
    goto failure;
  }

  if (branch_count > 1)
    qsort(branches, branch_count, sizeof(*branches), compare_branch_candidates);
  for (size_t begin = 0; begin < branch_count;) {
    size_t end = begin + 1;
    while (end < branch_count && strcmp(branches[begin].suffix.pattern,
                                        branches[end].suffix.pattern) == 0)
      end++;

    size_t literal_count = 0;
    size_t typed_count = 0;
    uint64_t group_total = 0;
    uint64_t typed_total = 0;
    st_token_type_t joined = ST_TYPE_COUNT;
    const branch_candidate_t *dominant = NULL;
    for (size_t i = begin; i < end; i++) {
      const st_node_t *child = branches[i].child;
      group_total += branches[i].suffix.count;
      if (child->type == ST_TYPE_LITERAL) {
        literal_count++;
        continue;
      }
      typed_count++;
      typed_total += branches[i].suffix.count;
      joined =
          joined == ST_TYPE_COUNT ? child->type : st_join(joined, child->type);
      if (!dominant || branches[i].suffix.count > dominant->suffix.count ||
          (branches[i].suffix.count == dominant->suffix.count &&
           child->type < dominant->child->type))
        dominant = &branches[i];
    }

    bool command_position = node->token[0] == '\0';
    if (literal_count >= 2 && !command_position && group_total <= UINT32_MAX) {
      branch_candidate_t aggregate = {
          .suffix = {.pattern = branches[begin].suffix.pattern,
                     .count = (uint32_t)group_total,
                     .confidence = (double)group_total / (double)node->count},
          .child = branches[begin].child,
      };
      if (!append_prefixed(output, &aggregate, "*",
                           aggregate.suffix.confidence))
        goto failure;
    } else {
      for (size_t i = begin; i < end; i++) {
        const st_node_t *child = branches[i].child;
        if (child->type != ST_TYPE_LITERAL ||
            literal_is_unrepresentable(child->token))
          continue;
        double confidence =
            branches[i].suffix.pattern[0] == '\0'
                ? (double)branches[i].suffix.count / (double)node->count
                : branches[i].suffix.confidence;
        if (!append_prefixed(output, &branches[i], child->token, confidence))
          goto failure;
      }
    }

    if (literal_count >= 2 && !command_position) {
      begin = end;
      continue;
    }
    if (typed_count == 1 && dominant) {
      char token[32];
      node_suggestion_token(dominant->child, dominant->child->type, token);
      double confidence =
          dominant->suffix.pattern[0] == '\0'
              ? (double)dominant->suffix.count / (double)node->count
              : dominant->suffix.confidence;
      if (!append_prefixed(output, dominant, token, confidence))
        goto failure;
    } else if (typed_count >= 2 && dominant && typed_total <= UINT32_MAX) {
      st_token_type_t selected;
      const st_node_t *metadata_node = NULL;
      uint32_t support;
      if ((uint64_t)dominant->suffix.count * 10 >= typed_total * 7) {
        selected = dominant->child->type;
        support = dominant->suffix.count;
        metadata_node = dominant->child;
      } else {
        selected = joined;
        support = (uint32_t)typed_total;
      }
      char token[32];
      node_suggestion_token(metadata_node, selected, token);
      branch_candidate_t aggregate = {
          .suffix = {.pattern = branches[begin].suffix.pattern,
                     .count = support,
                     .confidence = (double)support / (double)node->count},
          .child = dominant->child,
      };
      if (!append_prefixed(output, &aggregate, token,
                           aggregate.suffix.confidence))
        goto failure;
    }
    begin = end;
  }

  for (size_t i = 0; i < branch_count; i++)
    free(branches[i].suffix.pattern);
  free(branches);
  return true;

failure:
  for (size_t i = 0; i < branch_count; i++)
    free(branches[i].suffix.pattern);
  free(branches);
  candidate_list_free(output);
  return false;
}

static void collect_suggestions(st_learner_t *learner, dfs_ctx_t *ctx) {
  candidate_list_t complete = {0};
  if (!collect_complete_continuations(learner->trie.root, &complete)) {
    ctx->failed = true;
    return;
  }
  for (size_t i = 0; i < complete.count; i++) {
    st_candidate_t candidate = complete.items[i];
    if (candidate.pattern[0] == '\0' ||
        (candidate.pattern[0] == '*' &&
         (candidate.pattern[1] == '\0' || candidate.pattern[1] == ' ')) ||
        candidate.count < ctx->min_support ||
        candidate.confidence < ctx->min_confidence ||
        st_validate_pattern(candidate.pattern, NULL) != ST_OK ||
        st_is_blacklisted(ctx->learner, candidate.pattern)) {
      free(candidate.pattern);
      complete.items[i].pattern = NULL;
      continue;
    }
    if (!dfs_ctx_ensure(ctx)) {
      free(candidate.pattern);
      complete.items[i].pattern = NULL;
      ctx->failed = true;
      break;
    }
    ctx->candidates[ctx->count++] = candidate;
    complete.items[i].pattern = NULL;
  }
  if (ctx->failed)
    for (size_t i = 0; i < complete.count; i++)
      free(complete.items[i].pattern);
  free(complete.items);
}

static int compare_candidates(const void *a, const void *b) {
  const st_candidate_t *ca = (const st_candidate_t *)a;
  const st_candidate_t *cb = (const st_candidate_t *)b;
  if (ca->confidence > cb->confidence)
    return -1;
  if (ca->confidence < cb->confidence)
    return 1;
  if (ca->count > cb->count)
    return -1;
  if (ca->count < cb->count)
    return 1;
  return strcmp(ca->pattern, cb->pattern);
}

static int compare_candidate_patterns(const void *a, const void *b) {
  const st_candidate_t *ca = (const st_candidate_t *)a;
  const st_candidate_t *cb = (const st_candidate_t *)b;
  int pattern_order = strcmp(ca->pattern, cb->pattern);
  return pattern_order != 0 ? pattern_order : compare_candidates(a, b);
}

static size_t deduplicate(st_candidate_t *candidates, size_t count) {
  if (count <= 1)
    return count;
  size_t write = 1;
  for (size_t read = 1; read < count; read++) {
    if (strcmp(candidates[read].pattern, candidates[write - 1].pattern) != 0) {
      if (write != read) {
        free(candidates[write].pattern);
        candidates[write] = candidates[read];
      }
      write++;
    } else {
      free(candidates[read].pattern);
    }
  }
  return write;
}

st_suggestion_t *st_suggest(st_learner_t *learner, size_t *out_count) {
  if (out_count)
    *out_count = 0;
  if (!learner || !out_count)
    return NULL;

  dfs_ctx_t ctx = {
      .candidates = NULL,
      .count = 0,
      .capacity = 0,
      .min_support = learner->min_support,
      .min_confidence = learner->min_confidence,
      .learner = learner,
  };

  collect_suggestions(learner, &ctx);

  if (ctx.failed) {
    for (size_t i = 0; i < ctx.count; i++)
      free(ctx.candidates[i].pattern);
    free(ctx.candidates);
    return NULL;
  }

  if (ctx.count == 0) {
    return NULL;
  }

  qsort(ctx.candidates, ctx.count, sizeof(st_candidate_t),
        compare_candidate_patterns);
  ctx.count = deduplicate(ctx.candidates, ctx.count);
  qsort(ctx.candidates, ctx.count, sizeof(st_candidate_t), compare_candidates);

  size_t result_count = ctx.count;
  if (result_count > learner->max_suggestions) {
    result_count = learner->max_suggestions;
  }
  if (result_count == 0) {
    for (size_t i = 0; i < ctx.count; i++)
      free(ctx.candidates[i].pattern);
    free(ctx.candidates);
    return NULL;
  }

  st_suggestion_t *result = calloc(result_count, sizeof(st_suggestion_t));
  if (!result) {
    for (size_t i = 0; i < ctx.count; i++)
      free(ctx.candidates[i].pattern);
    free(ctx.candidates);
    return NULL;
  }

  for (size_t i = 0; i < result_count; i++) {
    result[i].pattern = ctx.candidates[i].pattern;
    result[i].count = ctx.candidates[i].count;
    result[i].confidence = ctx.candidates[i].confidence;
  }

  for (size_t i = result_count; i < ctx.count; i++) {
    free(ctx.candidates[i].pattern);
  }
  free(ctx.candidates);

  *out_count = result_count;
  return result;
}

void st_free_suggestions(st_suggestion_t *suggestions, size_t count) {
  if (!suggestions)
    return;
  for (size_t i = 0; i < count; i++)
    free(suggestions[i].pattern);
  free(suggestions);
}

/* --- PUBLIC API – BLACKLIST --- */

static bool blacklist_ensure(st_learner_t *learner) {
  if (learner->blacklist_capacity > learner->blacklist_count)
    return true;
  size_t new_cap =
      learner->blacklist_capacity == 0 ? 16 : learner->blacklist_capacity * 2;
  char **new_arr = realloc(learner->blacklist, new_cap * sizeof(char *));
  if (!new_arr)
    return false;
  learner->blacklist = new_arr;
  learner->blacklist_capacity = new_cap;
  return true;
}

st_error_t st_blacklist_add(st_learner_t *learner, const char *pattern) {
  if (!learner || !pattern || pattern[0] == '\0')
    return ST_ERR_INVALID;
  if (st_is_blacklisted(learner, pattern))
    return ST_OK;
  if (!blacklist_ensure(learner))
    return ST_ERR_MEMORY;
  char *copy = strdup(pattern);
  if (!copy)
    return ST_ERR_MEMORY;
  learner->blacklist[learner->blacklist_count++] = copy;
  return ST_OK;
}

bool st_is_blacklisted(const st_learner_t *learner, const char *pattern) {
  if (!learner || !pattern || pattern[0] == '\0')
    return false;
  for (size_t i = 0; i < learner->blacklist_count; i++) {
    if (strcmp(learner->blacklist[i], pattern) == 0)
      return true;
  }
  return false;
}

/* --- PUBLIC API – SERIALISATION --- */

static bool parse_u32_field(const char *text, char **end, uint32_t *value) {
  if (!text || !end || !value || !isdigit((unsigned char)text[0]))
    return false;
  errno = 0;
  unsigned long parsed = strtoul(text, end, 10);
  if (errno == ERANGE || parsed > UINT32_MAX)
    return false;
  *value = (uint32_t)parsed;
  return true;
}

static bool line_ends_here(const char *text) {
  return text[0] == '\0' || (text[0] == '\n' && text[1] == '\0') ||
         (text[0] == '\r' && text[1] == '\n' && text[2] == '\0');
}

static const st_metadata_entry_t *metadata_by_id(uint16_t id) {
  for (size_t i = 0;
       i < sizeof(st_metadata_entries) / sizeof(st_metadata_entries[0]); i++)
    if (st_metadata_entries[i].id == (st_metadata_id_t)id)
      return &st_metadata_entries[i];
  return NULL;
}

static bool line_equals(const char *line, const char *expected) {
  size_t length = strcspn(line, "\r\n");
  return strlen(expected) == length && strncmp(line, expected, length) == 0 &&
         line_ends_here(line + length);
}

static bool parse_u32_exact(const char *text, uint32_t *value) {
  char *end = NULL;
  return parse_u32_field(text, &end, value) && *end == '\0';
}

static char *hex_encode(const char *text) {
  static const char digits[] = "0123456789abcdef";
  size_t length = strlen(text);
  if (length > (SIZE_MAX - 1) / 2)
    return NULL;
  char *encoded = malloc(length * 2 + 1);
  if (!encoded)
    return NULL;
  for (size_t i = 0; i < length; i++) {
    unsigned char byte = (unsigned char)text[i];
    encoded[i * 2] = digits[byte >> 4];
    encoded[i * 2 + 1] = digits[byte & 0x0f];
  }
  encoded[length * 2] = '\0';
  return encoded;
}

static int hex_value(unsigned char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static bool hex_encoding_valid(const char *encoded) {
  size_t length = strlen(encoded);
  if (length == 0 || (length & 1) != 0 || length / 2 >= ST_MAX_TOKEN_LEN)
    return false;
  for (size_t i = 0; i < length; i += 2) {
    int high = hex_value((unsigned char)encoded[i]);
    int low = hex_value((unsigned char)encoded[i + 1]);
    if (high < 0 || low < 0 || (high == 0 && low == 0))
      return false;
    unsigned char byte = (unsigned char)((high << 4) | low);
    if (byte < 0x20 || byte == 0x7f)
      return false;
  }
  return true;
}

static char *hex_decode(const char *encoded) {
  size_t length = strlen(encoded);
  char *decoded = malloc(length / 2 + 1);
  if (!decoded)
    return NULL;
  for (size_t i = 0; i < length; i += 2) {
    int high = hex_value((unsigned char)encoded[i]);
    int low = hex_value((unsigned char)encoded[i + 1]);
    decoded[i / 2] = (char)((high << 4) | low);
  }
  decoded[length / 2] = '\0';
  return decoded;
}

typedef struct {
  FILE *fp;
  st_error_t error;
  uint32_t next_id;
} learner_save_ctx_t;

static void dfs_save_v3(st_node_t *node, uint32_t parent_id, size_t depth,
                        learner_save_ctx_t *ctx) {
  if (!node || ctx->error != ST_OK)
    return;
  if (depth > ST_MAX_CMD_TOKENS || ctx->next_id == UINT32_MAX) {
    ctx->error = ST_ERR_LIMIT;
    return;
  }

  uint32_t id = ctx->next_id++;
  const char *metadata = "-";
  if (node->metadata_mixed)
    metadata = "!";
  else if (node->common_metadata != ST_META_NONE) {
    const st_metadata_entry_t *entry = metadata_by_id(node->common_metadata);
    if (!entry || entry->type != node->type) {
      ctx->error = ST_ERR_FORMAT;
      return;
    }
    metadata = entry->name;
  }

  char *payload = NULL;
  const char *encoded = "-";
  char kind = 'T';
  if (node->type == ST_TYPE_LITERAL) {
    kind = 'L';
    payload = hex_encode(node->token);
    if (!payload) {
      ctx->error = ST_ERR_MEMORY;
      return;
    }
    encoded = payload;
  }
  if (fprintf(ctx->fp, "%u\t%u\t%c\t%u\t%u\t%s\t%u\t%s\n", id, parent_id, kind,
              (unsigned)node->type, node->count, metadata,
              node->metadata_observations, encoded) < 0)
    ctx->error = ST_ERR_IO;
  free(payload);

  for (size_t i = 0; i < node->num_children; i++)
    dfs_save_v3(node->children[i], id, depth + 1, ctx);
}

static bool node_counts_valid(const st_node_t *node) {
  uint64_t child_total = 0;
  for (size_t i = 0; i < node->num_children; i++) {
    const st_node_t *child = node->children[i];
    if (child->count == 0 || child->count > node->count ||
        !node_counts_valid(child))
      return false;
    child_total += child->count;
  }
  return child_total <= node->count;
}

st_error_t st_save(const st_learner_t *learner, const char *path) {
  if (!learner || !path)
    return ST_ERR_INVALID;

  st_atomic_output_t output;
  st_atomic_output_result_t begin = st_atomic_output_begin(path, &output);
  if (begin != ST_ATOMIC_OUTPUT_OK)
    return begin == ST_ATOMIC_OUTPUT_MEMORY ? ST_ERR_MEMORY : ST_ERR_IO;
  if (fprintf(output.stream, "# ST trie dump v3\n# total_commands=%u\n",
              learner->trie.total_commands) < 0) {
    st_atomic_output_discard(&output);
    return ST_ERR_IO;
  }
  learner_save_ctx_t ctx = {.fp = output.stream, .error = ST_OK, .next_id = 1};
  for (size_t i = 0; i < learner->trie.root->num_children; i++)
    dfs_save_v3(learner->trie.root->children[i], 0, 1, &ctx);
  if (ctx.error == ST_OK) {
    if (st_atomic_output_commit(&output) != 0)
      ctx.error = ST_ERR_IO;
  } else {
    st_atomic_output_discard(&output);
  }
  return ctx.error;
}

st_error_t st_load(st_learner_t *learner, const char *path) {
  if (!learner || !path)
    return ST_ERR_INVALID;
  FILE *fp = fopen(path, "r");
  if (!fp)
    return ST_ERR_IO;

  st_node_t *new_root = node_new("", ST_TYPE_LITERAL);
  if (!new_root) {
    fclose(fp);
    return ST_ERR_MEMORY;
  }

  char line[4096];
  uint32_t saved_total = 0;
  st_line_status_t line_status = st_read_line(fp, line, sizeof(line));
  if (line_status != ST_LINE_OK || !line_equals(line, "# ST trie dump v3"))
    goto format_or_io_failure;
  line_status = st_read_line(fp, line, sizeof(line));
  if (line_status != ST_LINE_OK || strncmp(line, "# total_commands=", 17) != 0)
    goto format_or_io_failure;
  char *end = NULL;
  if (!parse_u32_field(line + 17, &end, &saved_total) || !line_ends_here(end))
    goto format_failure;

  size_t capacity = 16;
  st_node_t **nodes = calloc(capacity, sizeof(*nodes));
  uint16_t *depths = calloc(capacity, sizeof(*depths));
  if (!nodes || !depths) {
    free(nodes);
    free(depths);
    goto memory_failure;
  }
  nodes[0] = new_root;
  uint32_t expected_id = 1;
  while ((line_status = st_read_line(fp, line, sizeof(line))) == ST_LINE_OK) {
    size_t length = strcspn(line, "\r\n");
    if (!line_ends_here(line + length))
      goto records_format_failure;
    line[length] = '\0';
    char *fields[8] = {line};
    for (size_t i = 1; i < 8; i++) {
      char *tab = strchr(fields[i - 1], '\t');
      if (!tab)
        goto records_format_failure;
      *tab = '\0';
      fields[i] = tab + 1;
    }
    if (strchr(fields[7], '\t'))
      goto records_format_failure;

    uint32_t id, parent_id, type_value, count, observations;
    if (!parse_u32_exact(fields[0], &id) || id != expected_id ||
        !parse_u32_exact(fields[1], &parent_id) || parent_id >= id ||
        strlen(fields[2]) != 1 ||
        (fields[2][0] != 'L' && fields[2][0] != 'T') ||
        !parse_u32_exact(fields[3], &type_value) ||
        type_value >= ST_TYPE_COUNT || !parse_u32_exact(fields[4], &count) ||
        count == 0 || !parse_u32_exact(fields[6], &observations))
      goto records_format_failure;
    if (id >= capacity) {
      size_t grown = capacity * 2;
      while (grown <= id)
        grown *= 2;
      st_node_t **new_nodes = realloc(nodes, grown * sizeof(*nodes));
      if (!new_nodes)
        goto records_memory_failure;
      nodes = new_nodes;
      uint16_t *new_depths = realloc(depths, grown * sizeof(*depths));
      if (!new_depths)
        goto records_memory_failure;
      depths = new_depths;
      memset(nodes + capacity, 0, (grown - capacity) * sizeof(*nodes));
      memset(depths + capacity, 0, (grown - capacity) * sizeof(*depths));
      capacity = grown;
    }
    if (!nodes[parent_id] || depths[parent_id] >= ST_MAX_CMD_TOKENS)
      goto records_format_failure;

    st_token_type_t type = (st_token_type_t)type_value;
    bool literal = fields[2][0] == 'L';
    if (literal != (type == ST_TYPE_LITERAL) ||
        (literal ? fields[7][0] == '\0' : strcmp(fields[7], "-") != 0))
      goto records_format_failure;
    if (literal && !hex_encoding_valid(fields[7]))
      goto records_format_failure;
    char *token =
        literal ? hex_decode(fields[7]) : strdup(st_type_symbol[type]);
    if (!token)
      goto records_memory_failure;
    if (node_find_child(nodes[parent_id], token, type)) {
      free(token);
      goto records_format_failure;
    }

    bool mixed = strcmp(fields[5], "!") == 0;
    const st_metadata_entry_t *common = NULL;
    if (strcmp(fields[5], "-") != 0 && !mixed) {
      common = st_metadata_lookup(type, fields[5]);
      if (!common || strcmp(common->name, fields[5]) != 0)
        goto token_format_failure;
    }
    if ((literal && (observations != 0 || mixed || common)) ||
        (!literal && (observations != count || (mixed == (common != NULL)))) ||
        (common && (common->type != type || type == ST_TYPE_SEMVER)))
      goto token_format_failure;

    st_node_t *child = node_new(token, type);
    free(token);
    if (!child)
      goto records_memory_failure;
    child->count = count;
    child->observed_types = literal ? 0 : (1ULL << type);
    child->metadata_observations = observations;
    child->common_metadata = common ? (uint16_t)common->id : ST_META_NONE;
    child->metadata_mixed = mixed;
    if (!node_ensure_capacity(nodes[parent_id],
                              nodes[parent_id]->num_children + 1)) {
      node_free(child);
      goto records_memory_failure;
    }
    nodes[parent_id]->children[nodes[parent_id]->num_children++] = child;
    nodes[id] = child;
    depths[id] = depths[parent_id] + 1;
    expected_id++;
    continue;

  token_format_failure:
    free(token);
    goto records_format_failure;
  }
  if (line_status != ST_LINE_EOF)
    goto records_status_failure;
  if (fclose(fp) != 0) {
    fp = NULL;
    free(nodes);
    free(depths);
    node_free(new_root);
    return ST_ERR_IO;
  }
  fp = NULL;
  free(nodes);
  free(depths);
  new_root->count = saved_total;
  if (!node_counts_valid(new_root)) {
    node_free(new_root);
    return ST_ERR_FORMAT;
  }

  /* The serialized total must agree with the reconstructed first-level
   * counts.  Otherwise the metadata could claim commands that are absent from
   * the trie (or silently discard commands during a round trip). */
  uint64_t reconstructed_total = 0;
  for (size_t i = 0; i < new_root->num_children; i++) {
    if (UINT64_MAX - reconstructed_total < new_root->children[i]->count) {
      node_free(new_root);
      return ST_ERR_FORMAT;
    }
    reconstructed_total += new_root->children[i]->count;
  }
  if (reconstructed_total != saved_total) {
    node_free(new_root);
    return ST_ERR_FORMAT;
  }

  /* Commit only after the complete replacement has loaded successfully. */
  st_node_t *old_root = learner->trie.root;
  learner->trie.root = new_root;
  learner->trie.total_commands = saved_total;
  node_free(old_root);
  return ST_OK;

records_status_failure:
  if (line_status == ST_LINE_IO) {
    free(nodes);
    free(depths);
    node_free(new_root);
    fclose(fp);
    return ST_ERR_IO;
  }
records_format_failure:
  free(nodes);
  free(depths);
  goto format_failure;
records_memory_failure:
  free(nodes);
  free(depths);
memory_failure:
  node_free(new_root);
  fclose(fp);
  return ST_ERR_MEMORY;
format_or_io_failure:
  if (line_status == ST_LINE_IO) {
    node_free(new_root);
    fclose(fp);
    return ST_ERR_IO;
  }
format_failure:
  node_free(new_root);
  fclose(fp);
  return ST_ERR_FORMAT;
}
