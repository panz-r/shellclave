/*
 * trie_variants.c - Token type variant suggestion for edit UI.
 * Walks the trie based on a pattern and returns observed type variants
 * for a specific token position, allowing the UI to present generalization
 * options (more specific to more general).
 */

#include "shelltype.h"
#include "policy_variants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Collect observed types at target position in trie. */
static void collect_variants_at(
    st_node_t *node,
    const char **pattern_tokens,
    size_t pattern_count,
    size_t target_pos,
    size_t depth,
    st_token_type_t *collected_types,
    size_t *type_count,
    char **sample_values,
    size_t max_samples,
    size_t *out_sample_count)
{
    if (!node || depth >= pattern_count) return;

    const char *current_token = pattern_tokens[depth];
    st_token_type_t current_type = st_type_from_pattern_token(current_token);

    /* Find matching child */
    st_node_t *child = NULL;
    for (size_t i = 0; i < node->num_children; i++) {
        st_node_t *c = node->children[i];
        if (current_type == ST_TYPE_LITERAL) {
            if (c->type == ST_TYPE_LITERAL && strcmp(c->token, current_token) == 0) {
                child = c;
                break;
            }
        } else {
            if (c->type == current_type) {
                child = c;
                break;
            }
        }
    }

    /* If not found, try generic match */
    if (!child) {
        for (size_t i = 0; i < node->num_children; i++) {
            if (node->children[i]->type != ST_TYPE_LITERAL) {
                child = node->children[i];
                break;
            }
        }
    }

    /* Record types at target position */
    if (depth == target_pos && child) {
        for (int t = 1; t < ST_TYPE_COUNT; t++) {
            if (child->observed_types & (1u << t)) {
                bool found = false;
                for (size_t j = 0; j < *type_count; j++) {
                    if (collected_types[j] == (st_token_type_t)t) { found = true; break; }
                }
                if (!found && *type_count < ST_MAX_TOKEN_VARIANTS) {
                    collected_types[(*type_count)++] = (st_token_type_t)t;
                }
            }
        }
        if (sample_values && child->num_samples > 0) {
            size_t add = (child->num_samples < max_samples) ? child->num_samples : max_samples;
            for (size_t s = 0; s < add && *out_sample_count < max_samples; s++) {
                sample_values[(*out_sample_count)++] = child->sample_values[s];
            }
        }
    }

    /* Recurse */
    if (child) {
        collect_variants_at(child, pattern_tokens, pattern_count, target_pos,
                           depth + 1, collected_types, type_count,
                           sample_values, max_samples, out_sample_count);
    }
}

/* Suggest type variants for editing a pattern token. */
size_t st_policy_suggest_token_variants(
    st_learner_t *learner,
    const char **pattern_tokens,
    size_t token_count,
    size_t edit_pos,
    st_token_variant_t *out_variants)
{
    if (!learner || !pattern_tokens || !out_variants || edit_pos >= token_count) return 0;

    st_token_type_t collected[ST_MAX_TOKEN_VARIANTS];
    size_t type_count = 0;

    /* Walk trie to collect observed types */
    collect_variants_at(learner->trie.root, pattern_tokens, token_count, edit_pos, 0,
                       collected, &type_count, NULL, 0, NULL);

    /* If no observed types, use current type */
    if (type_count == 0) {
        st_token_type_t current_type = st_type_from_pattern_token(pattern_tokens[edit_pos]);
        if (current_type != ST_TYPE_LITERAL) {
            collected[type_count++] = current_type;
        } else {
            /* Literal -> suggest turning into a type */
            out_variants[0].type = ST_TYPE_VALUE;
            out_variants[0].type_symbol = st_type_symbol[ST_TYPE_VALUE];
            out_variants[0].sample_value = NULL;
            return 1;
        }
    }

    /* Build variant list */
    size_t out_count = 0;
    st_token_type_t current_type = st_type_from_pattern_token(pattern_tokens[edit_pos]);

    /* Add current type first */
    for (size_t i = 0; i < type_count; i++) {
        if (collected[i] == current_type) {
            out_variants[out_count].type = current_type;
            out_variants[out_count].type_symbol = st_type_symbol[current_type];
            out_variants[out_count].sample_value = NULL;
            out_count++;
            break;
        }
    }

    /* Add remaining types */
    for (size_t i = 0; i < type_count && out_count < ST_MAX_TOKEN_VARIANTS; i++) {
        if (collected[i] != current_type) {
            out_variants[out_count].type = collected[i];
            out_variants[out_count].type_symbol = st_type_symbol[collected[i]];
            out_variants[out_count].sample_value = NULL;
            out_count++;
        }
    }

    /* Add general categories for common types */
    if (out_count < ST_MAX_TOKEN_VARIANTS) {
        if (current_type == ST_TYPE_ABS_PATH || current_type == ST_TYPE_REL_PATH) {
            bool has_path = false;
            for (size_t i = 0; i < out_count; i++) {
                if (out_variants[i].type == ST_TYPE_PATH) { has_path = true; break; }
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
                if (out_variants[i].type == ST_TYPE_VALUE) { has_val = true; break; }
            }
            if (!has_val) {
                out_variants[out_count].type = ST_TYPE_VALUE;
                out_variants[out_count].type_symbol = st_type_symbol[ST_TYPE_VALUE];
                out_variants[out_count].sample_value = NULL;
                out_count++;
            }
        }
    }

    /* Always add wildcard as most general */
    if (out_count < ST_MAX_TOKEN_VARIANTS) {
        out_variants[out_count].type = ST_TYPE_ANY;
        out_variants[out_count].type_symbol = "*";
        out_variants[out_count].sample_value = NULL;
        out_count++;
    }

    return out_count;
}

/* Apply a type change to a pattern at a given position. Caller must free result. */
char *st_policy_apply_type_at(
    st_learner_t *learner,
    const char **pattern_tokens,
    size_t token_count,
    size_t edit_pos,
    st_token_type_t new_type)
{
    (void)learner;
    size_t buf_size = ST_MAX_PATTERN_LEN;
    char *result = malloc(buf_size);
    if (!result) return NULL;
    result[0] = '\0';

    char *ptr = result;
    size_t remain = buf_size;

    for (size_t i = 0; i < token_count; i++) {
        if (i > 0) {
            int written = snprintf(ptr, remain, " ");
            if (written < 0 || (size_t)written >= remain) {
                result[buf_size - 1] = '\0';
                return result;
            }
            ptr += written;
            remain -= (size_t)written;
        }
        const char *tok = (i == edit_pos) ? st_type_symbol[new_type] : pattern_tokens[i];
        if (!tok) tok = "";
        int written = snprintf(ptr, remain, "%s", tok);
        if (written < 0 || (size_t)written >= remain) {
            result[buf_size - 1] = '\0';
            return result;
        }
        ptr += written;
        remain -= (size_t)written;
    }
    return result;
}