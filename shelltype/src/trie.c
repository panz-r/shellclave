#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * trie.c - Normalised Command Trie (NCT) with typed wildcards.
 *
 * Each node stores a token type (literal or wildcard). Suggestions use
 * the join of all observed types at each position for precise generalisation.
 */

#include "shelltype.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ============================================================
 * STRING BUFFER — reusable scratch for suggestion building
 * ============================================================ */

typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
} st_strbuf_t;

static bool st_strbuf_init(st_strbuf_t *sb, size_t init_cap)
{
    sb->buf = malloc(init_cap);
    if (!sb->buf) return false;
    sb->buf[0] = '\0';
    sb->len = 0;
    sb->cap = init_cap;
    return true;
}

static void st_strbuf_clear(st_strbuf_t *sb)
{
    sb->buf[0] = '\0';
    sb->len = 0;
}

static void st_strbuf_append(st_strbuf_t *sb, const char *str, size_t len)
{
    if (sb->len + len + 1 > sb->cap) {
        size_t new_cap = sb->cap * 2;
        while (new_cap < sb->len + len + 1) new_cap *= 2;
        char *new_buf = realloc(sb->buf, new_cap);
        if (!new_buf) return;
        sb->buf = new_buf;
        sb->cap = new_cap;
    }
    memcpy(sb->buf + sb->len, str, len);
    sb->len += len;
    sb->buf[sb->len] = '\0';
}

static void st_strbuf_free(st_strbuf_t *sb)
{
    free(sb->buf);
    sb->buf = NULL;
    sb->len = sb->cap = 0;
}

/* ============================================================
 * NODE HELPERS
 * ============================================================ */

static st_node_t *node_new(const char *token, st_token_type_t type)
{
    st_node_t *node = calloc(1, sizeof(st_node_t));
    if (!node) return NULL;

    node->token = strdup(token);
    if (!node->token) { free(node); return NULL; }

    node->type = type;
    node->count = 0;
    node->observed_types = 0;
    node->children = NULL;
    node->num_children = 0;
    node->children_capacity = 0;
    node->sample_values = NULL;
    node->num_samples = 0;

    return node;
}

static void node_free(st_node_t *node)
{
    if (!node) return;
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

static bool node_ensure_capacity(st_node_t *node, size_t needed)
{
    if (node->children_capacity >= needed) return true;
    size_t new_cap = node->children_capacity == 0
                         ? ST_INITIAL_CHILDREN_CAP
                         : node->children_capacity * 2;
    while (new_cap < needed) new_cap *= 2;
    st_node_t **new_children = realloc(node->children,
                                        new_cap * sizeof(st_node_t *));
    if (!new_children) return false;
    node->children = new_children;
    node->children_capacity = new_cap;
    return true;
}

/* Find child by token text (for literals) or by type (for wildcards) */
static st_node_t *node_find_child(st_node_t *node,
                                   const char *token,
                                   st_token_type_t type)
{
    for (size_t i = 0; i < node->num_children; i++) {
        st_node_t *child = node->children[i];
        if (child->type == ST_TYPE_LITERAL && type == ST_TYPE_LITERAL) {
            if (strcmp(child->token, token) == 0) return child;
        } else if (child->type == type) {
            return child;
        }
    }
    return NULL;
}

/* ============================================================
 * TRIE INSERTION
 * ============================================================ */

static bool trie_insert_with_count(st_node_t *root,
                                   st_token_t *tokens, size_t count,
                                   uint32_t increment)
{
    st_node_t *current = root;
    current->count += increment;

    for (size_t i = 0; i < count; i++) {
        st_node_t *child = node_find_child(current, tokens[i].text, tokens[i].type);
        if (!child) {
            if (!node_ensure_capacity(current, current->num_children + 1))
                return false;
            const char *tok_str = (tokens[i].type == ST_TYPE_LITERAL)
                                      ? tokens[i].text
                                      : st_type_symbol[tokens[i].type];
            child = node_new(tok_str, tokens[i].type);
            if (!child) return false;
            current->children[current->num_children++] = child;
        }

        child->count += increment;
        /* Track observed types at this position */
        if (tokens[i].type != ST_TYPE_LITERAL) {
            child->observed_types |= (1u << tokens[i].type);
        }
        current = child;
    }
    return true;
}

static bool trie_insert(st_node_t *root, st_token_t *tokens, size_t count)
{
    return trie_insert_with_count(root, tokens, count, 1);
}

/* ============================================================
 * PUBLIC API – LIFECYCLE
 * ============================================================ */

st_learner_t *st_learner_new(uint32_t min_support, double min_confidence)
{
    st_learner_t *learner = calloc(1, sizeof(st_learner_t));
    if (!learner) return NULL;

    learner->trie.root = node_new("", ST_TYPE_LITERAL);
    if (!learner->trie.root) { free(learner); return NULL; }

    learner->trie.total_commands = 0;
    learner->min_support = min_support > 0 ? min_support : ST_DEFAULT_MIN_SUPPORT;
    learner->min_confidence = min_confidence;
    learner->max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS;
    learner->blacklist = NULL;
    learner->blacklist_count = 0;
    learner->blacklist_capacity = 0;

    return learner;
}

void st_learner_free(st_learner_t *learner)
{
    if (!learner) return;
    node_free(learner->trie.root);
    for (size_t i = 0; i < learner->blacklist_count; i++) {
        free(learner->blacklist[i]);
    }
    free(learner->blacklist);
    free(learner);
}

/* ============================================================
 * PUBLIC API – FEED
 * ============================================================ */

st_error_t st_feed(st_learner_t *learner, const char *raw_cmd)
{
    if (!learner || !raw_cmd || !raw_cmd[0]) return ST_ERR_INVALID;

    st_token_array_t typed;
    typed.tokens = NULL;
    typed.count = 0;
    st_error_t err = st_normalize_typed(raw_cmd, &typed);
    if (err != ST_OK) return err;

    if (!trie_insert(learner->trie.root, typed.tokens, typed.count)) {
        st_free_token_array(&typed);
        return ST_ERR_MEMORY;
    }

    learner->trie.total_commands++;
    st_free_token_array(&typed);
    return ST_OK;
}

st_error_t st_feed_parsed(st_learner_t *learner, const char *raw_cmd,
                            const void *parse)
{
    if (!learner || !raw_cmd || !raw_cmd[0] || !parse) return ST_ERR_INVALID;

    const st_token_array_t *typed = (const st_token_array_t *)parse;
    if (!typed->tokens || typed->count == 0) return ST_ERR_INVALID;

    if (!trie_insert(learner->trie.root, typed->tokens, typed->count))
        return ST_ERR_MEMORY;

    learner->trie.total_commands++;
    return ST_OK;
}

/* ============================================================
 * PUBLIC API – SUGGESTIONS
 * ============================================================ */

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
} dfs_ctx_t;

static bool dfs_ctx_ensure(dfs_ctx_t *ctx)
{
    if (ctx->capacity >= ctx->count + 1) return true;
    size_t new_cap = ctx->capacity == 0 ? 64 : ctx->capacity * 2;
    st_candidate_t *new_arr = realloc(ctx->candidates,
                                       new_cap * sizeof(st_candidate_t));
    if (!new_arr) return false;
    ctx->candidates = new_arr;
    ctx->capacity = new_cap;
    return true;
}

static char *join_tokens(const char **path, size_t depth)
{
    if (depth == 0) return strdup("");

    size_t total = 0;
    size_t first = 0;
    for (size_t i = 0; i < depth; i++) {
        if (path[i][0] == '\0') { first = i + 1; continue; }
        total += strlen(path[i]);
    }
    if (total == 0) return strdup("");

    size_t non_empty = 0;
    for (size_t i = first; i < depth; i++) non_empty++;
    if (non_empty > 1) total += non_empty - 1;

    char *result = malloc(total + 1);
    if (!result) return NULL;

    char *p = result;
    bool need_space = false;
    for (size_t i = first; i < depth; i++) {
        if (path[i][0] == '\0') continue;
        if (need_space) *p++ = ' ';
        size_t len = strlen(path[i]);
        memcpy(p, path[i], len);
        p += len;
        need_space = true;
    }
    *p = '\0';
    return result;
}

static void dfs_collect(st_node_t *node, const char **path, size_t depth,
                        uint32_t parent_count, dfs_ctx_t *ctx, st_strbuf_t *sb)
{
    if (!node) return;
    if (depth >= 1024) return;

    path[depth] = node->token;
    depth++;

    if (node->token[0] != '\0' && node->count >= ctx->min_support) {
        double confidence = (parent_count > 0)
                                ? (double)node->count / (double)parent_count
                                : 1.0;

        if (confidence >= ctx->min_confidence) {
            /* Build pattern: use observed_types join for wildcard nodes */
            const char *pattern_tokens[1024];
            for (size_t i = 0; i < depth; i++) {
                pattern_tokens[i] = path[i];
            }

            /* For the current node, if it's a wildcard with observed types,
             * use the join of all observed types */
            char effective_token[32];
            if (node->type != ST_TYPE_LITERAL && node->observed_types != 0) {
                st_token_type_t joined = ST_TYPE_ANY;
                for (int t = 0; t < ST_TYPE_COUNT; t++) {
                    if (node->observed_types & (1u << t)) {
                        if (joined == ST_TYPE_ANY) {
                            joined = (st_token_type_t)t;
                        } else {
                            joined = st_join(joined, (st_token_type_t)t);
                        }
                    }
                }
                if (joined != ST_TYPE_ANY) {
                    snprintf(effective_token, sizeof(effective_token), "%s",
                             st_type_symbol[joined]);
                    pattern_tokens[depth - 1] = effective_token;
                }
            }

            st_strbuf_clear(sb);
            for (size_t j = 0; j < depth; j++) {
                if (j > 0) st_strbuf_append(sb, " ", 1);
                st_strbuf_append(sb, pattern_tokens[j], strlen(pattern_tokens[j]));
            }
            char *pattern = strdup(sb->buf);
            if (pattern) {
                if (!st_is_blacklisted(ctx->learner, pattern)) {
                    if (dfs_ctx_ensure(ctx)) {
                        ctx->candidates[ctx->count].pattern = pattern;
                        ctx->candidates[ctx->count].count = node->count;
                        ctx->candidates[ctx->count].confidence = confidence;
                        ctx->count++;
                    } else {
                        free(pattern);
                    }
                } else {
                    free(pattern);
                }
            }
        }
    }

    for (size_t i = 0; i < node->num_children; i++) {
        dfs_collect(node->children[i], path, depth, node->count, ctx, sb);
    }
}

static int compare_candidates(const void *a, const void *b)
{
    const st_candidate_t *ca = (const st_candidate_t *)a;
    const st_candidate_t *cb = (const st_candidate_t *)b;
    if (ca->confidence > cb->confidence) return -1;
    if (ca->confidence < cb->confidence) return 1;
    if (ca->count > cb->count) return -1;
    if (ca->count < cb->count) return 1;
    return 0;
}

static size_t deduplicate(st_candidate_t *candidates, size_t count)
{
    if (count <= 1) return count;
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

st_suggestion_t *st_suggest(st_learner_t *learner, size_t *out_count)
{
    if (!learner || !out_count) return NULL;

    dfs_ctx_t ctx = {
        .candidates = NULL,
        .count = 0,
        .capacity = 0,
        .min_support = learner->min_support,
        .min_confidence = learner->min_confidence,
        .learner = learner,
    };

    const char *path[1024];
    st_strbuf_t sb;
    if (!st_strbuf_init(&sb, 256)) {
        *out_count = 0;
        return NULL;
    }
    dfs_collect(learner->trie.root, path, 0, 0, &ctx, &sb);
    st_strbuf_free(&sb);

    if (ctx.count == 0) {
        *out_count = 0;
        return NULL;
    }

    qsort(ctx.candidates, ctx.count, sizeof(st_candidate_t), compare_candidates);
    ctx.count = deduplicate(ctx.candidates, ctx.count);

    size_t result_count = ctx.count;
    if (result_count > learner->max_suggestions) {
        result_count = learner->max_suggestions;
    }

    st_suggestion_t *result = calloc(result_count, sizeof(st_suggestion_t));
    if (!result) {
        for (size_t i = 0; i < ctx.count; i++) free(ctx.candidates[i].pattern);
        free(ctx.candidates);
        *out_count = 0;
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

void st_free_suggestions(st_suggestion_t *suggestions, size_t count)
{
    if (!suggestions) return;
    for (size_t i = 0; i < count; i++) free(suggestions[i].pattern);
    free(suggestions);
}

/* ============================================================
 * PUBLIC API – BLACKLIST
 * ============================================================ */

static bool blacklist_ensure(st_learner_t *learner)
{
    if (learner->blacklist_capacity > learner->blacklist_count) return true;
    size_t new_cap = learner->blacklist_capacity == 0 ? 16 : learner->blacklist_capacity * 2;
    char **new_arr = realloc(learner->blacklist, new_cap * sizeof(char *));
    if (!new_arr) return false;
    learner->blacklist = new_arr;
    learner->blacklist_capacity = new_cap;
    return true;
}

st_error_t st_blacklist_add(st_learner_t *learner, const char *pattern)
{
    if (!learner || !pattern) return ST_ERR_INVALID;
    if (st_is_blacklisted(learner, pattern)) return ST_OK;
    if (!blacklist_ensure(learner)) return ST_ERR_MEMORY;
    char *copy = strdup(pattern);
    if (!copy) return ST_ERR_MEMORY;
    learner->blacklist[learner->blacklist_count++] = copy;
    return ST_OK;
}

bool st_is_blacklisted(const st_learner_t *learner, const char *pattern)
{
    if (!learner || !pattern) return false;
    for (size_t i = 0; i < learner->blacklist_count; i++) {
        if (strcmp(learner->blacklist[i], pattern) == 0) return true;
    }
    return false;
}

/* ============================================================
 * PUBLIC API – SERIALISATION
 * ============================================================ */

typedef struct {
    FILE *fp;
    st_error_t error;
} save_ctx_t;

static void dfs_save(st_node_t *node, const char **path, size_t depth,
                     save_ctx_t *ctx)
{
    if (!node || ctx->error != ST_OK) return;
    if (node->token[0] != '\0') {
        if (depth >= 1024) return;
        path[depth] = node->token;
        depth++;
    }

    /* Save every node that has a count, not just leaves.
     * This preserves the full trie structure including nodes
     * that are both complete commands AND have children
     * (e.g., "git" and "git commit" both fed separately). */
    if (node->token[0] != '\0' && node->count > 0) {
        char *pattern = join_tokens(path, depth);
        if (pattern) {
            if (fprintf(ctx->fp, "%u\t%s\n", node->count, pattern) < 0) {
                ctx->error = ST_ERR_IO;
            }
            free(pattern);
        }
    }

    for (size_t i = 0; i < node->num_children; i++) {
        dfs_save(node->children[i], path, depth, ctx);
    }
}

st_error_t st_save(const st_learner_t *learner, const char *path)
{
    if (!learner || !path) return ST_ERR_INVALID;
    FILE *fp = fopen(path, "w");
    if (!fp) return ST_ERR_IO;
    if (fprintf(fp, "# ST trie dump\n# total_commands=%u\n",
                learner->trie.total_commands) < 0) {
        fclose(fp);
        return ST_ERR_IO;
    }
    save_ctx_t ctx = { .fp = fp, .error = ST_OK };
    const char *save_path[1024];
    dfs_save(learner->trie.root, save_path, 0, &ctx);
    fclose(fp);
    return ctx.error;
}

st_error_t st_load(st_learner_t *learner, const char *path)
{
    if (!learner || !path) return ST_ERR_INVALID;
    FILE *fp = fopen(path, "r");
    if (!fp) return ST_ERR_IO;

    /* Read total_commands from header if present */
    char line[4096];
    uint32_t saved_total = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] != '#') {
            /* First non-comment line, rewind and process it below */
            fseek(fp, -((long)strlen(line)), SEEK_CUR);
            break;
        }
        if (strncmp(line, "# total_commands=", 17) == 0) {
            saved_total = (uint32_t)strtoul(line + 17, NULL, 10);
        }
    }

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#') continue;
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        uint32_t count = (uint32_t)strtoul(line, NULL, 10);
        char *pattern = tab + 1;
        size_t plen = strlen(pattern);
        while (plen > 0 && (pattern[plen - 1] == '\n' || pattern[plen - 1] == '\r')) {
            pattern[--plen] = '\0';
        }
        if (plen == 0 || count == 0) continue;

        /* Parse typed tokens from pattern */
        char *pattern_copy = strdup(pattern);
        if (!pattern_copy) { fclose(fp); return ST_ERR_MEMORY; }

        /* Count tokens */
        size_t token_count = 1;
        for (const char *p = pattern_copy; *p; p++) {
            if (*p == ' ') token_count++;
        }

        st_token_t *tokens = calloc(token_count, sizeof(st_token_t));
        if (!tokens) { free(pattern_copy); fclose(fp); return ST_ERR_MEMORY; }

        size_t ti = 0;
        char *saveptr = NULL;
        char *tok = strtok_r(pattern_copy, " ", &saveptr);
        while (tok && ti < token_count) {
            /* Check if it's a type symbol */
            st_token_type_t type = ST_TYPE_LITERAL;
            for (int t = 1; t < ST_TYPE_COUNT; t++) {
                if (strcmp(tok, st_type_symbol[t]) == 0) {
                    type = (st_token_type_t)t;
                    break;
                }
            }
            /* If not a recognised type symbol, classify the token
             * the same way the command normaliser does. */
            if (type == ST_TYPE_LITERAL) {
                type = st_classify_token(tok);
            }
            tokens[ti].text = strdup(tok);
            tokens[ti].type = type;
            ti++;
            tok = strtok_r(NULL, " ", &saveptr);
        }
        token_count = ti;

        /* Walk/create the trie path and increment count on every node.
         * dfs_collect computes confidence as node_count / parent_count, so every
         * node on the path must be updated for correct ranking. */
        st_node_t *current = learner->trie.root;
        current->count += count;
        for (size_t i = 0; i < token_count; i++) {
            st_node_t *child = node_find_child(current, tokens[i].text, tokens[i].type);
            if (!child) {
                if (!node_ensure_capacity(current, current->num_children + 1)) {
                    for (size_t j = 0; j < token_count; j++) free(tokens[j].text);
                    free(tokens);
                    free(pattern_copy);
                    fclose(fp);
                    return ST_ERR_MEMORY;
                }
                const char *tok_str = (tokens[i].type == ST_TYPE_LITERAL)
                                          ? tokens[i].text
                                          : st_type_symbol[tokens[i].type];
                child = node_new(tok_str, tokens[i].type);
                if (!child) {
                    for (size_t j = 0; j < token_count; j++) free(tokens[j].text);
                    free(tokens);
                    free(pattern_copy);
                    fclose(fp);
                    return ST_ERR_MEMORY;
                }
                current->children[current->num_children++] = child;
            }
            current = child;
            child->count += count;
        }

        for (size_t i = 0; i < token_count; i++) free(tokens[i].text);
        free(tokens);
        free(pattern_copy);
    }

    /* Restore total_commands and root count from the saved header value.
     * The root count is needed for confidence calculation in suggestions. */
    learner->trie.total_commands = saved_total;
    learner->trie.root->count = saved_total;

    fclose(fp);
    return ST_OK;
}
