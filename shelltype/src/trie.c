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
#include "crc32.h"
#include "io.h"
#include "metadata.h"
#include "netpattern.h"
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
    if (!tokens[i].text || tokens[i].type < ST_TYPE_LITERAL ||
        tokens[i].type >= ST_TYPE_COUNT ||
        strlen(tokens[i].text) >= ST_MAX_TOKEN_LEN)
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

st_error_t st_feed(st_learner_t *learner, const char *netargv) {
  if (!learner || !netargv || !netargv[0])
    return ST_ERR_INVALID;

  st_token_array_t typed;
  typed.tokens = NULL;
  typed.count = 0;
  st_error_t err = st_classify(netargv, &typed);
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

st_error_t st_feed_parsed(st_learner_t *learner,
                          const st_token_array_t *typed) {
  if (!learner || !typed)
    return ST_ERR_INVALID;
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

static int compare_branch_candidates(const void *left, const void *right) {
  const branch_candidate_t *a = left;
  const branch_candidate_t *b = right;
  int suffix = st_netpattern_compare(a->suffix.pattern, b->suffix.pattern);
  if (suffix != 0)
    return suffix;
  if (a->child->type != b->child->type)
    return a->child->type < b->child->type ? -1 : 1;
  return strcmp(a->child->token, b->child->token);
}

static bool append_prefixed(candidate_list_t *output,
                            const branch_candidate_t *branch, const char *token,
                            st_token_type_t type, double confidence) {
  st_token_t typed = {.text = (char *)token, .type = type};
  char *prefix = NULL;
  if (st_netpattern_encode(&typed, 1, &prefix) != ST_OK)
    return false;
  size_t token_length = strlen(prefix);
  size_t suffix_length = strlen(branch->suffix.pattern);
  if (token_length >= ST_MAX_NETPATTERN_LEN ||
      suffix_length >= ST_MAX_NETPATTERN_LEN - token_length) {
    free(prefix);
    return true;
  }
  size_t length = token_length + suffix_length;
  char *pattern = malloc(length + 1);
  if (!pattern) {
    free(prefix);
    return false;
  }
  memcpy(pattern, prefix, token_length);
  free(prefix);
  size_t used = token_length;
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
    while (end < branch_count &&
           st_netpattern_compare(branches[begin].suffix.pattern,
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
      if (!append_prefixed(output, &aggregate, "*", ST_TYPE_ANY,
                           aggregate.suffix.confidence))
        goto failure;
    } else {
      for (size_t i = begin; i < end; i++) {
        const st_node_t *child = branches[i].child;
        if (child->type != ST_TYPE_LITERAL)
          continue;
        double confidence =
            branches[i].suffix.pattern[0] == '\0'
                ? (double)branches[i].suffix.count / (double)node->count
                : branches[i].suffix.confidence;
        if (!append_prefixed(output, &branches[i], child->token,
                             ST_TYPE_LITERAL, confidence))
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
      if (!append_prefixed(output, dominant, token, dominant->child->type,
                           confidence))
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
      if (!append_prefixed(output, &aggregate, token, selected,
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
    st_token_array_t decoded = {0};
    st_error_t decode_error =
        candidate.pattern[0] ? st_netpattern_decode(candidate.pattern, &decoded)
                             : ST_ERR_FORMAT;
    bool leading_any = decode_error == ST_OK && decoded.count != 0 &&
                       decoded.tokens[0].type == ST_TYPE_ANY;
    st_free_token_array(&decoded);
    if (decode_error != ST_OK || leading_any ||
        candidate.count < ctx->min_support ||
        candidate.confidence < ctx->min_confidence ||
        st_validate_netpattern(candidate.pattern, NULL) != ST_OK ||
        st_is_netpattern_blacklisted(ctx->learner, candidate.pattern)) {
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
  return st_netpattern_compare(ca->pattern, cb->pattern);
}

static int compare_candidate_patterns(const void *a, const void *b) {
  const st_candidate_t *ca = (const st_candidate_t *)a;
  const st_candidate_t *cb = (const st_candidate_t *)b;
  int pattern_order = st_netpattern_compare(ca->pattern, cb->pattern);
  return pattern_order != 0 ? pattern_order : compare_candidates(a, b);
}

static size_t deduplicate(st_candidate_t *candidates, size_t count) {
  if (count <= 1)
    return count;
  size_t write = 1;
  for (size_t read = 1; read < count; read++) {
    if (st_netpattern_compare(candidates[read].pattern,
                              candidates[write - 1].pattern) != 0) {
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

st_error_t st_blacklist_add_netpattern(st_learner_t *learner,
                                       const char *pattern) {
  if (!learner || !pattern || pattern[0] == '\0')
    return ST_ERR_INVALID;
  st_token_array_t decoded = {0};
  st_error_t decode_error = st_netpattern_decode(pattern, &decoded);
  st_free_token_array(&decoded);
  if (decode_error != ST_OK)
    return decode_error;
  if (st_is_netpattern_blacklisted(learner, pattern))
    return ST_OK;
  if (!blacklist_ensure(learner))
    return ST_ERR_MEMORY;
  char *copy = strdup(pattern);
  if (!copy)
    return ST_ERR_MEMORY;
  learner->blacklist[learner->blacklist_count++] = copy;
  return ST_OK;
}

bool st_is_netpattern_blacklisted(const st_learner_t *learner,
                                  const char *pattern) {
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

typedef struct {
  FILE *fp;
  st_error_t error;
  uint32_t next_id;
  uint32_t crc;
} learner_save_ctx_t;

static bool append_netstring_field(char *record, size_t capacity, size_t *used,
                                   const char *value) {
  size_t length = strlen(value);
  int prefix = snprintf(record + *used, capacity - *used, "%zu:", length);
  if (prefix < 0 || (size_t)prefix >= capacity - *used ||
      length + 1 >= capacity - *used - (size_t)prefix)
    return false;
  *used += (size_t)prefix;
  memcpy(record + *used, value, length);
  *used += length;
  record[(*used)++] = ',';
  record[*used] = '\0';
  return true;
}

static uint32_t count_saved_nodes(const st_node_t *node, bool *overflow) {
  if (!node || *overflow)
    return 0;
  uint64_t total = 1;
  for (size_t i = 0; i < node->num_children; i++)
    total += count_saved_nodes(node->children[i], overflow);
  if (total > UINT32_MAX) {
    *overflow = true;
    return 0;
  }
  return (uint32_t)total;
}

static void dfs_save_v4(st_node_t *node, uint32_t parent_id, size_t depth,
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

  char kind = 'T';
  const char *token = "";
  if (node->type == ST_TYPE_LITERAL) {
    kind = 'L';
    token = node->token;
  }
  char id_text[16], parent_text[16], type_text[16], count_text[16];
  char observations_text[16], kind_text[2] = {kind, '\0'};
  snprintf(id_text, sizeof(id_text), "%u", id);
  snprintf(parent_text, sizeof(parent_text), "%u", parent_id);
  snprintf(type_text, sizeof(type_text), "%u", (unsigned)node->type);
  snprintf(count_text, sizeof(count_text), "%u", node->count);
  snprintf(observations_text, sizeof(observations_text), "%u",
           node->metadata_observations);
  char record[ST_MAX_TOKEN_LEN + 256] = {0};
  size_t used = 0;
  if (!append_netstring_field(record, sizeof(record), &used, id_text) ||
      !append_netstring_field(record, sizeof(record), &used, parent_text) ||
      !append_netstring_field(record, sizeof(record), &used, kind_text) ||
      !append_netstring_field(record, sizeof(record), &used, type_text) ||
      !append_netstring_field(record, sizeof(record), &used, count_text) ||
      !append_netstring_field(record, sizeof(record), &used, metadata) ||
      !append_netstring_field(record, sizeof(record), &used,
                              observations_text) ||
      !append_netstring_field(record, sizeof(record), &used, token)) {
    ctx->error = ST_ERR_LIMIT;
    return;
  }
  char prefix[32];
  int prefix_length = snprintf(prefix, sizeof(prefix), "%zu:", used);
  if (prefix_length < 0 || (size_t)prefix_length >= sizeof(prefix) ||
      fprintf(ctx->fp, "%s%s,\n", prefix, record) < 0) {
    ctx->error = ST_ERR_IO;
    return;
  }
  ctx->crc = st_crc32_update(prefix, (size_t)prefix_length, ctx->crc);
  ctx->crc = st_crc32_update(record, used, ctx->crc);
  ctx->crc = st_crc32_update(",\n", 2, ctx->crc);

  for (size_t i = 0; i < node->num_children; i++)
    dfs_save_v4(node->children[i], id, depth + 1, ctx);
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
  bool overflow = false;
  uint64_t node_total = 0;
  for (size_t i = 0; i < learner->trie.root->num_children; i++)
    node_total += count_saved_nodes(learner->trie.root->children[i], &overflow);
  if (overflow || node_total > UINT32_MAX) {
    st_atomic_output_discard(&output);
    return ST_ERR_LIMIT;
  }
  if (fprintf(output.stream,
              "# shelltype-learner v4\n# total-commands: %u\n# nodes: %u\n",
              learner->trie.total_commands, (unsigned)node_total) < 0) {
    st_atomic_output_discard(&output);
    return ST_ERR_IO;
  }
  learner_save_ctx_t ctx = {
      .fp = output.stream, .error = ST_OK, .next_id = 1, .crc = 0};
  for (size_t i = 0; i < learner->trie.root->num_children; i++)
    dfs_save_v4(learner->trie.root->children[i], 0, 1, &ctx);
  if (ctx.error == ST_OK && ctx.next_id - 1 != node_total)
    ctx.error = ST_ERR_FORMAT;
  if (ctx.error == ST_OK &&
      fprintf(output.stream, "# CRC32: %08x\n", ctx.crc) < 0)
    ctx.error = ST_ERR_IO;
  if (ctx.error == ST_OK) {
    if (st_atomic_output_commit(&output) != 0)
      ctx.error = ST_ERR_IO;
  } else {
    st_atomic_output_discard(&output);
  }
  return ctx.error;
}

static st_error_t read_outer_record(FILE *fp, char **payload, uint32_t *crc) {
  *payload = NULL;
  char prefix[32];
  size_t prefix_length = 0, length = 0;
  int ch = fgetc(fp);
  if (ch == EOF)
    return ferror(fp) ? ST_ERR_IO : ST_ERR_FORMAT;
  bool leading_zero = ch == '0';
  do {
    if (!isdigit((unsigned char)ch) || prefix_length + 1 >= sizeof(prefix))
      return ST_ERR_FORMAT;
    prefix[prefix_length++] = (char)ch;
    unsigned digit = (unsigned)(ch - '0');
    if (length > (SIZE_MAX - digit) / 10)
      return ST_ERR_LIMIT;
    length = length * 10 + digit;
    ch = fgetc(fp);
  } while (ch != ':' && ch != EOF);
  if (ch != ':' || (leading_zero && prefix_length != 1) || length == 0 ||
      length >= ST_MAX_TOKEN_LEN + 256)
    return ST_ERR_FORMAT;
  prefix[prefix_length++] = ':';
  char *record = malloc(length + 1);
  if (!record)
    return ST_ERR_MEMORY;
  if (fread(record, 1, length, fp) != length) {
    free(record);
    return ferror(fp) ? ST_ERR_IO : ST_ERR_FORMAT;
  }
  record[length] = '\0';
  if (memchr(record, '\0', length) || fgetc(fp) != ',' || fgetc(fp) != '\n') {
    free(record);
    return ferror(fp) ? ST_ERR_IO : ST_ERR_FORMAT;
  }
  *crc = st_crc32_update(prefix, prefix_length, *crc);
  *crc = st_crc32_update(record, length, *crc);
  *crc = st_crc32_update(",\n", 2, *crc);
  *payload = record;
  return ST_OK;
}

static bool take_netstring_field(char *record, size_t length, size_t *offset,
                                 char **field) {
  if (*offset >= length || !isdigit((unsigned char)record[*offset]))
    return false;
  size_t field_length = 0;
  bool leading_zero = record[*offset] == '0';
  size_t digits_count = 0;
  do {
    unsigned digit = (unsigned)(record[*offset] - '0');
    if (field_length > (SIZE_MAX - digit) / 10)
      return false;
    field_length = field_length * 10 + digit;
    (*offset)++;
    digits_count++;
  } while (*offset < length && isdigit((unsigned char)record[*offset]));
  if (*offset >= length || record[(*offset)++] != ':' ||
      (leading_zero && digits_count != 1) || field_length >= length - *offset ||
      record[*offset + field_length] != ',')
    return false;
  *field = record + *offset;
  *offset += field_length;
  record[(*offset)++] = '\0';
  return true;
}

static bool parse_crc_footer(const char *line, uint32_t *crc) {
  size_t length = strcspn(line, "\r\n");
  if (length != 17 || strncmp(line, "# CRC32: ", 9) != 0 ||
      !line_ends_here(line + length))
    return false;
  uint32_t value = 0;
  for (size_t i = 9; i < 17; i++) {
    unsigned char c = (unsigned char)line[i];
    unsigned digit = c >= '0' && c <= '9'   ? c - '0'
                     : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                            : 16;
    if (digit == 16)
      return false;
    value = value * 16 + digit;
  }
  *crc = value;
  return true;
}

st_error_t st_load(st_learner_t *learner, const char *path) {
  if (!learner || !path)
    return ST_ERR_INVALID;
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return ST_ERR_IO;
  st_error_t error = ST_ERR_FORMAT;
  st_node_t *new_root = node_new("", ST_TYPE_LITERAL);
  st_node_t **nodes = NULL;
  uint16_t *depths = NULL;
  if (!new_root) {
    fclose(fp);
    return ST_ERR_MEMORY;
  }

  char line[128];
  uint32_t saved_total = 0, node_count = 0;
  st_line_status_t status = st_read_line(fp, line, sizeof(line));
  if (status != ST_LINE_OK || !line_equals(line, "# shelltype-learner v4"))
    goto done;
  status = st_read_line(fp, line, sizeof(line));
  if (status != ST_LINE_OK || strncmp(line, "# total-commands: ", 18) != 0)
    goto done;
  char *end = NULL;
  if (!parse_u32_field(line + 18, &end, &saved_total) || !line_ends_here(end))
    goto done;
  status = st_read_line(fp, line, sizeof(line));
  if (status != ST_LINE_OK || strncmp(line, "# nodes: ", 9) != 0 ||
      !parse_u32_field(line + 9, &end, &node_count) || !line_ends_here(end) ||
      node_count == UINT32_MAX)
    goto done;

  nodes = calloc((size_t)node_count + 1, sizeof(*nodes));
  depths = calloc((size_t)node_count + 1, sizeof(*depths));
  if (!nodes || !depths) {
    error = ST_ERR_MEMORY;
    goto done;
  }
  nodes[0] = new_root;
  uint32_t computed_crc = 0;
  for (uint32_t expected_id = 1; expected_id <= node_count; expected_id++) {
    char *record = NULL;
    error = read_outer_record(fp, &record, &computed_crc);
    if (error != ST_OK)
      goto done;
    char *fields[8];
    size_t record_length = strlen(record), offset = 0;
    bool valid = true;
    for (size_t field = 0; field < 8; field++)
      valid = valid && take_netstring_field(record, record_length, &offset,
                                            &fields[field]);
    if (!valid || offset != record_length) {
      free(record);
      error = ST_ERR_FORMAT;
      goto done;
    }
    uint32_t id, parent_id, type_value, count, observations;
    if (!parse_u32_exact(fields[0], &id) || id != expected_id ||
        !parse_u32_exact(fields[1], &parent_id) || parent_id >= id ||
        strlen(fields[2]) != 1 ||
        (fields[2][0] != 'L' && fields[2][0] != 'T') ||
        !parse_u32_exact(fields[3], &type_value) ||
        type_value >= ST_TYPE_COUNT || !parse_u32_exact(fields[4], &count) ||
        count == 0 || !parse_u32_exact(fields[6], &observations) ||
        !nodes[parent_id] || depths[parent_id] >= ST_MAX_CMD_TOKENS) {
      free(record);
      error = ST_ERR_FORMAT;
      goto done;
    }
    st_token_type_t type = (st_token_type_t)type_value;
    bool literal = fields[2][0] == 'L';
    if (literal != (type == ST_TYPE_LITERAL) ||
        (literal ? strlen(fields[7]) >= ST_MAX_TOKEN_LEN
                 : fields[7][0] != '\0')) {
      free(record);
      error = ST_ERR_FORMAT;
      goto done;
    }
    const char *token = literal ? fields[7] : st_type_symbol[type];
    if (node_find_child(nodes[parent_id], token, type)) {
      free(record);
      error = ST_ERR_FORMAT;
      goto done;
    }
    bool mixed = strcmp(fields[5], "!") == 0;
    const st_metadata_entry_t *common = NULL;
    if (strcmp(fields[5], "-") != 0 && !mixed)
      common = st_metadata_lookup(type, fields[5]);
    if ((strcmp(fields[5], "-") != 0 && !mixed &&
         (!common || strcmp(common->name, fields[5]) != 0)) ||
        (literal && (observations != 0 || mixed || common)) ||
        (!literal && (observations != count || (mixed == (common != NULL)))) ||
        (common && (common->type != type || type == ST_TYPE_SEMVER))) {
      free(record);
      error = ST_ERR_FORMAT;
      goto done;
    }
    st_node_t *child = node_new(token, type);
    if (!child) {
      free(record);
      error = ST_ERR_MEMORY;
      goto done;
    }
    child->count = count;
    child->observed_types = literal ? 0 : (UINT64_C(1) << type);
    child->metadata_observations = observations;
    child->common_metadata = common ? (uint16_t)common->id : ST_META_NONE;
    child->metadata_mixed = mixed;
    if (!node_ensure_capacity(nodes[parent_id],
                              nodes[parent_id]->num_children + 1)) {
      node_free(child);
      free(record);
      error = ST_ERR_MEMORY;
      goto done;
    }
    nodes[parent_id]->children[nodes[parent_id]->num_children++] = child;
    nodes[id] = child;
    depths[id] = depths[parent_id] + 1;
    free(record);
  }

  /* From here onward every validation failure is a format error. The record
   * reader leaves error as ST_OK after the final successful node. */
  error = ST_ERR_FORMAT;
  status = st_read_line(fp, line, sizeof(line));
  uint32_t expected_crc = 0;
  if (status != ST_LINE_OK || !parse_crc_footer(line, &expected_crc) ||
      expected_crc != computed_crc)
    goto done;
  status = st_read_line(fp, line, sizeof(line));
  if (status != ST_LINE_EOF)
    goto done;
  new_root->count = saved_total;
  if (!node_counts_valid(new_root))
    goto done;
  uint64_t reconstructed_total = 0;
  for (size_t i = 0; i < new_root->num_children; i++)
    reconstructed_total += new_root->children[i]->count;
  if (reconstructed_total != saved_total)
    goto done;
  if (fclose(fp) != 0) {
    fp = NULL;
    error = ST_ERR_IO;
    goto done;
  }
  fp = NULL;
  free(nodes);
  free(depths);
  st_node_t *old_root = learner->trie.root;
  learner->trie.root = new_root;
  learner->trie.total_commands = saved_total;
  node_free(old_root);
  return ST_OK;

done:
  if (status == ST_LINE_IO)
    error = ST_ERR_IO;
  free(nodes);
  free(depths);
  node_free(new_root);
  if (fp && fclose(fp) != 0 && error == ST_ERR_FORMAT)
    error = ST_ERR_IO;
  return error;
}
