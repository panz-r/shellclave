/*
 * trie_variants.c - Token type variant suggestion for edit UI.
 * Walks the trie based on a pattern and returns observed type variants
 * for a specific token position, allowing the UI to present generalization
 * options (more specific to more general).
 */

#include "normalize_internal.h"
#include "shelltype.h"
#include "trie_internal.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"

_Static_assert(ST_TYPE_COUNT <= 64,
               "token variant collection requires a 64-bit type mask");

static size_t token_text_length(const st_token_t *token) {
  if (!token || !token->text)
    return 0;
  return (token->text_length || token->text[0] == '\0') ? token->text_length
                                                        : strlen(token->text);
}

size_t st_token_variants_at(const st_token_array_t *pattern, size_t edit_pos,
                            st_token_variant_t *out_variants,
                            size_t max_variants) {
  if (!pattern || !pattern->tokens || !out_variants || max_variants == 0 ||
      edit_pos >= pattern->count)
    return 0;

  const st_token_t *token = &pattern->tokens[edit_pos];
  st_token_type_t start_type = token->type;
  if (start_type < ST_TYPE_LITERAL || start_type >= ST_TYPE_COUNT ||
      !token->text)
    return 0;
  if (start_type == ST_TYPE_LITERAL &&
      memchr(token->text, '\0', token_text_length(token)) == NULL)
    start_type = st_token_classify_bytes(token->text, token_text_length(token));

  size_t out = 0;
  out_variants[out++] = (st_token_variant_t){
      .type = ST_TYPE_LITERAL,
      .type_symbol = st_type_symbol[ST_TYPE_LITERAL],
  };
  if (out < max_variants && start_type != ST_TYPE_LITERAL)
    out_variants[out++] = (st_token_variant_t){
        .type = start_type,
        .type_symbol = st_type_symbol[start_type],
    };

  bool seen[ST_TYPE_COUNT] = {false};
  if (start_type != ST_TYPE_LITERAL)
    seen[start_type] = true;
  st_token_type_t current = start_type;
  while (current != ST_TYPE_ANY && out < max_variants) {
    st_token_type_t next_wide = ST_TYPE_ANY;
    for (st_token_type_t type = ST_TYPE_LITERAL + 1; type < ST_TYPE_COUNT;
         type++) {
      if (type == current || seen[type])
        continue;
      st_token_type_t joined = st_type_join[current][type];
      if (joined != current && !seen[joined] &&
          (next_wide == ST_TYPE_ANY || st_is_compatible(joined, next_wide)))
        next_wide = joined;
    }
    if (next_wide == ST_TYPE_ANY || next_wide == current)
      break;
    seen[next_wide] = true;
    out_variants[out++] = (st_token_variant_t){
        .type = next_wide,
        .type_symbol = st_type_symbol[next_wide],
    };
    current = next_wide;
  }
  if (out < max_variants && !seen[ST_TYPE_ANY])
    out_variants[out++] = (st_token_variant_t){
        .type = ST_TYPE_ANY,
        .type_symbol = st_type_symbol[ST_TYPE_ANY],
    };
  return out;
}

/* Collect observed types at target position in trie. */
static void collect_variants_at(const st_node_t *node,
                                const st_token_t *pattern_tokens,
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

  const char *current_token = pattern_tokens[depth].text;
  size_t current_token_length = token_text_length(&pattern_tokens[depth]);
  st_token_type_t current_type = pattern_tokens[depth].type;

  if (current_type == ST_TYPE_LITERAL) {
    for (size_t i = 0; i < node->num_children; i++) {
      const st_node_t *child = node->children[i];
      if (child->type == ST_TYPE_LITERAL &&
          child->token_length == current_token_length &&
          memcmp(child->token, current_token, current_token_length) == 0) {
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
    const st_node_t *child = node->children[i];
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

static bool pattern_tokens_are_representable(const st_token_array_t *pattern) {
  st_netpattern_t encoded = {0};
  st_error_t error =
      st_netpattern_encode_owned(pattern->tokens, pattern->count, &encoded);
  st_netpattern_free(&encoded);
  return error == ST_OK;
}

/* Suggest type variants for editing a pattern token. */
size_t st_learner_suggest_token_variants(const st_learner_t *learner,
                                         const st_token_array_t *pattern,
                                         size_t edit_pos,
                                         st_token_variant_t *out_variants) {
  if (out_variants)
    memset(out_variants, 0, ST_MAX_TOKEN_VARIANTS * sizeof(*out_variants));
  if (!learner || !pattern || !pattern->tokens || !out_variants ||
      pattern->count == 0 || pattern->count > ST_MAX_CMD_TOKENS ||
      edit_pos >= pattern->count)
    return 0;
  if (!pattern_tokens_are_representable(pattern))
    return 0;

  uint64_t observed_types = 0;

  /* Walk trie to collect observed types */
  collect_variants_at(learner->trie.root, pattern->tokens, pattern->count,
                      edit_pos, 0, &observed_types);

  /* If no observed types, use current type */
  if (observed_types == 0) {
    st_token_type_t current_type = pattern->tokens[edit_pos].type;
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
  st_token_type_t current_type = pattern->tokens[edit_pos].type;

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
st_error_t st_netpattern_apply_type_at_owned(st_netpattern_view_t netpattern,
                                             size_t edit_pos,
                                             st_token_type_t new_type,
                                             st_netpattern_t *out_netpattern) {
  if (!netpattern.data || netpattern.length == 0 || !out_netpattern ||
      out_netpattern->data || out_netpattern->length != 0 ||
      new_type <= ST_TYPE_LITERAL || new_type >= ST_TYPE_COUNT)
    return ST_ERR_INVALID;
  st_token_array_t decoded = {0};
  st_error_t error = st_netpattern_decode_view(netpattern, &decoded);
  if (error != ST_OK)
    return error;
  if (edit_pos >= decoded.count) {
    st_token_array_free(&decoded);
    return ST_ERR_INVALID;
  }
  if (decoded.tokens[edit_pos].compound) {
    const char *old_capture = decoded.tokens[edit_pos].capture;
    size_t old_capture_length = decoded.tokens[edit_pos].capture_length;
    st_token_type_t old_capture_type = decoded.tokens[edit_pos].capture_type;
    decoded.tokens[edit_pos].capture = (char *)st_type_symbol[new_type];
    decoded.tokens[edit_pos].capture_type = new_type;
    decoded.tokens[edit_pos].capture_length = strlen(st_type_symbol[new_type]);
    error = st_netpattern_encode_owned(decoded.tokens, decoded.count,
                                       out_netpattern);
    decoded.tokens[edit_pos].capture = old_capture;
    decoded.tokens[edit_pos].capture_type = old_capture_type;
    decoded.tokens[edit_pos].capture_length = old_capture_length;
    st_token_array_free(&decoded);
    return error;
  }
  const char *old_text = decoded.tokens[edit_pos].text;
  size_t old_text_length = decoded.tokens[edit_pos].text_length;
  decoded.tokens[edit_pos].text = (char *)st_type_symbol[new_type];
  decoded.tokens[edit_pos].text_length = strlen(st_type_symbol[new_type]);
  decoded.tokens[edit_pos].type = new_type;
  error =
      st_netpattern_encode_owned(decoded.tokens, decoded.count, out_netpattern);
  decoded.tokens[edit_pos].text = old_text;
  decoded.tokens[edit_pos].text_length = old_text_length;
  st_token_array_free(&decoded);
  return error;
}

st_error_t st_netpattern_apply_type_at(const char *netpattern, size_t edit_pos,
                                       st_token_type_t new_type,
                                       char **out_netpattern) {
  if (out_netpattern)
    *out_netpattern = NULL;
  if (!netpattern || !out_netpattern)
    return ST_ERR_INVALID;
  st_netpattern_t owned = {0};
  st_error_t error = st_netpattern_apply_type_at_owned(
      (st_netpattern_view_t){.data = netpattern, .length = strlen(netpattern)},
      edit_pos, new_type, &owned);
  if (error != ST_OK)
    return error;
  if (memchr(owned.data, '\0', owned.length)) {
    st_netpattern_free(&owned);
    return ST_ERR_LIMIT;
  }
  *out_netpattern = owned.data;
  return ST_OK;
}
