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

#include "alloc.h"

_Static_assert(ST_TYPE_COUNT <= 64,
               "token variant collection requires a 64-bit type mask");

/* Collect observed types at target position in trie. */
static void collect_variants_at(st_node_t *node, const char **pattern_tokens,
                                size_t pattern_count, size_t target_pos,
                                size_t depth, uint64_t *observed_types) {
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
        *observed_types |= 1ULL << t;
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
                            depth + 1, observed_types);
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
                          depth + 1, observed_types);
  }
}

/* Pick the lowest-enum minimal element of the remaining lattice subset.  A
 * strict subtype must be emitted before its supertypes; enum order provides a
 * deterministic total order only where the lattice leaves types incomparable.
 */
static st_token_type_t most_specific_remaining(uint64_t remaining) {
  for (int candidate = ST_TYPE_LITERAL + 1; candidate < ST_TYPE_ANY;
       candidate++) {
    if (!(remaining & (1ULL << candidate)))
      continue;
    bool has_stricter = false;
    for (int other = ST_TYPE_LITERAL + 1; other < ST_TYPE_ANY; other++) {
      if (other == candidate || !(remaining & (1ULL << other)))
        continue;
      if (st_is_compatible((st_token_type_t)other,
                           (st_token_type_t)candidate) &&
          !st_is_compatible((st_token_type_t)candidate,
                            (st_token_type_t)other)) {
        has_stricter = true;
        break;
      }
    }
    if (!has_stricter)
      return (st_token_type_t)candidate;
  }
  return ST_TYPE_COUNT;
}

static bool pattern_tokens_are_representable(const char **pattern_tokens,
                                             size_t token_count) {
  char pattern[ST_MAX_PATTERN_LEN];
  size_t used = 0;

  for (size_t i = 0; i < token_count; i++) {
    const char *token = pattern_tokens[i];
    if (!token || !token[0] || strchr(token, ' '))
      return false;
    size_t length = strlen(token);
    size_t separator = i != 0 ? 1 : 0;
    if (used + separator + length >= sizeof(pattern))
      return false;
    if (separator)
      pattern[used++] = ' ';
    memcpy(pattern + used, token, length);
    used += length;
  }
  pattern[used] = '\0';

  st_pattern_info_t info = {0};
  return st_validate_pattern(pattern, &info) == ST_OK &&
         info.token_count == token_count;
}

/* Suggest type variants for editing a pattern token. */
size_t st_policy_suggest_token_variants(st_learner_t *learner,
                                        const char **pattern_tokens,
                                        size_t token_count, size_t edit_pos,
                                        st_token_variant_t *out_variants) {
  if (out_variants)
    memset(out_variants, 0, ST_MAX_TOKEN_VARIANTS * sizeof(*out_variants));
  if (!learner || !pattern_tokens || !out_variants || token_count == 0 ||
      token_count > ST_MAX_CMD_TOKENS || edit_pos >= token_count)
    return 0;
  if (!pattern_tokens_are_representable(pattern_tokens, token_count))
    return 0;

  uint64_t observed_types = 0;

  /* Walk trie to collect observed types */
  collect_variants_at(learner->trie.root, pattern_tokens, token_count, edit_pos,
                      0, &observed_types);

  /* If no observed types, use current type */
  if (observed_types == 0) {
    st_token_type_t current_type =
        st_type_from_pattern_token(pattern_tokens[edit_pos]);
    if (current_type != ST_TYPE_LITERAL && current_type != ST_TYPE_ANY) {
      observed_types |= 1ULL << current_type;
    } else {
      /* Literal -> suggest turning into a type */
      if (current_type == ST_TYPE_LITERAL)
        observed_types |= 1ULL << ST_TYPE_VALUE;
    }
  }

  /* Build variant list */
  size_t out_count = 0;
  st_token_type_t current_type =
      st_type_from_pattern_token(pattern_tokens[edit_pos]);

  /* Add current type first */
  if (current_type != ST_TYPE_ANY && current_type < ST_TYPE_COUNT &&
      (observed_types & (1ULL << current_type))) {
    out_variants[out_count].type = current_type;
    out_variants[out_count].type_symbol = st_type_symbol[current_type];
    out_variants[out_count].sample_value = NULL;
    out_count++;
    observed_types &= ~(1ULL << current_type);
  }

  /* Add remaining observed types in a deterministic linear extension of the
   * lattice.  Truncation therefore cannot depend on feed order. */
  while (observed_types && out_count < ST_MAX_TOKEN_VARIANTS - 1) {
    st_token_type_t selected = most_specific_remaining(observed_types);
    if (selected == ST_TYPE_COUNT)
      break;
    out_variants[out_count].type = selected;
    out_variants[out_count].type_symbol = st_type_symbol[selected];
    out_variants[out_count].sample_value = NULL;
    out_count++;
    observed_types &= ~(1ULL << selected);
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

  /* Reserve the final slot for exactly one wildcard, the most general type.
   * A leading wildcard is not valid policy grammar, so never suggest it for
   * the command position. */
  if (edit_pos != 0 && out_count < ST_MAX_TOKEN_VARIANTS) {
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
      token_count > ST_MAX_CMD_TOKENS || new_type <= ST_TYPE_LITERAL ||
      new_type >= ST_TYPE_COUNT)
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
