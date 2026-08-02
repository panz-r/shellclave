/*
 * trie_variants.c - Token type variant suggestion for edit UI.
 * Walks the trie based on a pattern and returns observed type variants
 * for a specific token position, allowing the UI to present generalization
 * options (more specific to more general).
 */

#include "shelltype.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Collect observed types at target position in trie. */
static void collect_variants_at(st_node_t *node, const char **pattern_tokens,
                                size_t pattern_count, size_t target_pos,
                                size_t depth, st_token_type_t *collected_types,
                                size_t *type_count) {
  if (!node || depth >= pattern_count)
    return;

  /* The prefix selects one trie node. At the edited position, every child is
   * an observed alternative; choosing the child matching the current token
   * would hide precisely the sibling variants this API is meant to expose. */
  if (depth == target_pos) {
    for (size_t i = 0; i < node->num_children; i++) {
      uint64_t observed = node->children[i]->observed_types;
      for (int t = 1; t < ST_TYPE_COUNT; t++) {
        if (!(observed & (1ULL << t)) || t == ST_TYPE_ANY)
          continue;
        bool found = false;
        for (size_t j = 0; j < *type_count; j++)
          if (collected_types[j] == (st_token_type_t)t) {
            found = true;
            break;
          }
        if (!found && *type_count < ST_MAX_TOKEN_VARIANTS - 1)
          collected_types[(*type_count)++] = (st_token_type_t)t;
      }
    }
    return;
  }

  const char *current_token = pattern_tokens[depth];
  st_token_type_t current_type = st_type_from_pattern_token(current_token);

  if (current_type == ST_TYPE_LITERAL) {
    for (size_t i = 0; i < node->num_children; i++) {
      st_node_t *child = node->children[i];
      if (child->type == ST_TYPE_LITERAL &&
          strcmp(child->token, current_token) == 0) {
        collect_variants_at(child, pattern_tokens, pattern_count, target_pos,
                            depth + 1, collected_types, type_count);
        return;
      }
    }
    return;
  }

  /* A generalized prefix may cover several typed trie branches. Traverse all
   * lattice-compatible children so downstream variants are independent of
   * insertion order. */
  for (size_t i = 0; i < node->num_children; i++) {
    st_node_t *child = node->children[i];
    if (child->type != ST_TYPE_LITERAL &&
        st_is_compatible(child->type, current_type))
      collect_variants_at(child, pattern_tokens, pattern_count, target_pos,
                          depth + 1, collected_types, type_count);
  }
}

/* Suggest type variants for editing a pattern token. */
size_t st_policy_suggest_token_variants(st_learner_t *learner,
                                        const char **pattern_tokens,
                                        size_t token_count, size_t edit_pos,
                                        st_token_variant_t *out_variants) {
  if (!learner || !pattern_tokens || !out_variants || edit_pos >= token_count)
    return 0;
  for (size_t i = 0; i < token_count; i++) {
    if (!pattern_tokens[i])
      return 0;
  }

  st_token_type_t collected[ST_MAX_TOKEN_VARIANTS];
  size_t type_count = 0;

  /* Walk trie to collect observed types */
  collect_variants_at(learner->trie.root, pattern_tokens, token_count, edit_pos,
                      0, collected, &type_count);

  /* If no observed types, use current type */
  if (type_count == 0) {
    st_token_type_t current_type =
        st_type_from_pattern_token(pattern_tokens[edit_pos]);
    if (current_type != ST_TYPE_LITERAL && current_type != ST_TYPE_ANY) {
      collected[type_count++] = current_type;
    } else {
      /* Literal -> suggest turning into a type */
      if (current_type == ST_TYPE_LITERAL)
        collected[type_count++] = ST_TYPE_VALUE;
    }
  }

  /* Build variant list */
  size_t out_count = 0;
  st_token_type_t current_type =
      st_type_from_pattern_token(pattern_tokens[edit_pos]);

  /* Add current type first */
  for (size_t i = 0; current_type != ST_TYPE_ANY && i < type_count; i++) {
    if (collected[i] == current_type) {
      out_variants[out_count].type = current_type;
      out_variants[out_count].type_symbol = st_type_symbol[current_type];
      out_variants[out_count].sample_value = NULL;
      out_count++;
      break;
    }
  }

  /* Add remaining types */
  for (size_t i = 0; i < type_count && out_count < ST_MAX_TOKEN_VARIANTS - 1;
       i++) {
    if (collected[i] != current_type && collected[i] != ST_TYPE_ANY) {
      out_variants[out_count].type = collected[i];
      out_variants[out_count].type_symbol = st_type_symbol[collected[i]];
      out_variants[out_count].sample_value = NULL;
      out_count++;
    }
  }

  /* Add general categories for common types */
  if (out_count < ST_MAX_TOKEN_VARIANTS - 1) {
    if (current_type == ST_TYPE_ABS_PATH || current_type == ST_TYPE_REL_PATH) {
      bool has_path = false;
      for (size_t i = 0; i < out_count; i++) {
        if (out_variants[i].type == ST_TYPE_PATH) {
          has_path = true;
          break;
        }
      }
      if (!has_path) {
        out_variants[out_count].type = ST_TYPE_PATH;
        out_variants[out_count].type_symbol = st_type_symbol[ST_TYPE_PATH];
        out_variants[out_count].sample_value = NULL;
        out_count++;
      }
    }
    if (current_type == ST_TYPE_HEXHASH || current_type == ST_TYPE_SHA) {
      bool has_val = false;
      for (size_t i = 0; i < out_count; i++) {
        if (out_variants[i].type == ST_TYPE_VALUE) {
          has_val = true;
          break;
        }
      }
      if (!has_val) {
        out_variants[out_count].type = ST_TYPE_VALUE;
        out_variants[out_count].type_symbol = st_type_symbol[ST_TYPE_VALUE];
        out_variants[out_count].sample_value = NULL;
        out_count++;
      }
    }
  }

  /* Reserve the final slot for exactly one wildcard, the most general type. */
  if (out_count < ST_MAX_TOKEN_VARIANTS) {
    out_variants[out_count].type = ST_TYPE_ANY;
    out_variants[out_count].type_symbol = "*";
    out_variants[out_count].sample_value = NULL;
    out_count++;
  }

  return out_count;
}

/* Apply a type change to a pattern at a given position. Caller must free
 * result. */
char *st_policy_apply_type_at(st_learner_t *learner,
                              const char **pattern_tokens, size_t token_count,
                              size_t edit_pos, st_token_type_t new_type) {
  (void)learner;
  if (!pattern_tokens || token_count == 0 || edit_pos >= token_count ||
      new_type <= ST_TYPE_LITERAL || new_type >= ST_TYPE_COUNT)
    return NULL;
  for (size_t i = 0; i < token_count; i++) {
    if (!pattern_tokens[i])
      return NULL;
  }

  size_t buf_size = ST_MAX_PATTERN_LEN;
  char *result = malloc(buf_size);
  if (!result)
    return NULL;
  result[0] = '\0';

  char *ptr = result;
  size_t remain = buf_size;

  for (size_t i = 0; i < token_count; i++) {
    if (i > 0) {
      int written = snprintf(ptr, remain, " ");
      if (written < 0 || (size_t)written >= remain) {
        free(result);
        return NULL;
      }
      ptr += written;
      remain -= (size_t)written;
    }
    const char *tok =
        (i == edit_pos) ? st_type_symbol[new_type] : pattern_tokens[i];
    if (!tok)
      tok = "";
    int written = snprintf(ptr, remain, "%s", tok);
    if (written < 0 || (size_t)written >= remain) {
      free(result);
      return NULL;
    }
    ptr += written;
    remain -= (size_t)written;
  }
  return result;
}
