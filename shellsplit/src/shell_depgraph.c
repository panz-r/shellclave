/*
 * shell_depgraph.c - Abstract Command Dependency Graph (ACDG)
 *
 * Zero-copy bounded-memory parser that builds a coarse-grained
 * command dependency graph from shell command strings.
 *
 * Consumes the output of the fast tokenizer (shell_parse_fast).
 */

#include "shell_depgraph.h"
#include "shell_tokenizer.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

static const char *dep_edge_names[] = {
    "READ", "WRITE", "APPEND", "PIPE", "ARG",
    "ENV", "SUBST", "SEQ", "AND", "OR",
};

static const char *dep_node_names[] = {
    "CMD", "DOC",
};

static const char *dep_doc_names[] = {
    "FILE", "HEREDOC", "HERESTRING", "ENVVAR",
};

const char *shell_dep_edge_type_name(shell_dep_edge_type_t type)
{
    if ((int)type < 0 || (int)type >= (int)(sizeof(dep_edge_names) / sizeof(dep_edge_names[0])))
        return "UNKNOWN";
    return dep_edge_names[type];
}

const char *shell_dep_node_type_name(shell_dep_node_type_t type)
{
    if ((int)type < 0 || (int)type >= (int)(sizeof(dep_node_names) / sizeof(dep_node_names[0])))
        return "UNKNOWN";
    return dep_node_names[type];
}

const char *shell_dep_doc_kind_name(shell_dep_doc_kind_t kind)
{
    if ((int)kind < 0 || (int)kind >= (int)(sizeof(dep_doc_names) / sizeof(dep_doc_names[0])))
        return "UNKNOWN";
    return dep_doc_names[kind];
}

/* ============================================================
 * CWD RESOLUTION
 * ============================================================ */

#define SHELL_DEP_MAX_CWD_LEN     256
#define SHELL_DEP_MAX_CWD_ENTRIES 128

typedef struct {
    char (*buf)[SHELL_DEP_MAX_CWD_LEN];
    uint32_t count;
    uint32_t capacity;
} shell_dep_cwd_buf_t;

static bool cwd_buf_init(shell_dep_cwd_buf_t *b)
{
    b->capacity = SHELL_DEP_MAX_CWD_ENTRIES;
    b->buf = calloc(b->capacity, SHELL_DEP_MAX_CWD_LEN);
    if (!b->buf) return false;
    b->count = 0;
    return true;
}

static void cwd_buf_free(shell_dep_cwd_buf_t *b)
{
    free(b->buf);
    b->buf = NULL;
}

static void cwd_normalize(char *path, uint32_t len)
{
    if (len == 0) return;

    uint32_t w = 0;
    uint32_t r = 0;

    while (r < len) {
        if (path[r] == '/') {
            path[w++] = '/';
            while (r < len && path[r] == '/') r++;
            continue;
        }

        uint32_t comp_start = r;
        while (r < len && path[r] != '/') r++;
        uint32_t comp_len = r - comp_start;

        if (comp_len == 1 && path[comp_start] == '.') {
            continue;
        }

        if (comp_len == 2 && path[comp_start] == '.' && path[comp_start + 1] == '.') {
            if (w > 1) {
                w--;
                while (w > 0 && path[w - 1] != '/') w--;
            }
            continue;
        }

        memcpy(path + w, path + comp_start, comp_len);
        w += comp_len;
    }

    if (w == 0) { path[0] = '/'; w = 1; }
    if (w > 1 && path[w - 1] == '/') w--;
    path[w] = '\0';
}

static const char *cwd_resolve(shell_dep_cwd_buf_t *cwd_buf,
                                const char *current, const char *rel)
{
    if (!rel || rel[0] == '\0') return current;
    if (rel[0] == '/') return rel;
    if (strcmp(rel, "$HOME") == 0) return rel;

    if (cwd_buf->count >= cwd_buf->capacity) {
        uint32_t new_cap = cwd_buf->capacity * 2;
        char (*new_buf)[SHELL_DEP_MAX_CWD_LEN] = realloc(cwd_buf->buf, new_cap * SHELL_DEP_MAX_CWD_LEN);
        if (!new_buf) return rel;
        cwd_buf->buf = new_buf;
        cwd_buf->capacity = new_cap;
    }

    char *out = cwd_buf->buf[cwd_buf->count];

    size_t cur_len = strlen(current);
    size_t rel_len = 0;
    while (rel[rel_len] != '\0' && rel[rel_len] != ' ' && rel[rel_len] != '\t')
        rel_len++;

    if (cur_len + 1 + rel_len + 1 >= SHELL_DEP_MAX_CWD_LEN)
        return rel;

    memcpy(out, current, cur_len);
    out[cur_len] = '/';
    memcpy(out + cur_len + 1, rel, rel_len);
    out[cur_len + 1 + rel_len] = '\0';

    cwd_normalize(out, (uint32_t)(cur_len + 1 + rel_len));
    cwd_buf->count++;
    return out;
}

/* ============================================================
 * LIGHTWEIGHT TOKENIZER
 * ============================================================ */

typedef struct {
    const char *start;
    uint32_t len;
} dep_token_t;

typedef struct {
    dep_token_t tokens[SHELL_DEP_MAX_TOKENS];
    uint32_t count;
} dep_token_list_t;

static void scan_tokens(const char *cmd, uint32_t range_start, uint32_t range_len,
                         dep_token_list_t *out)
{
    out->count = 0;
    uint32_t pos = range_start;
    uint32_t end = range_start + range_len;

    while (pos < end && out->count < SHELL_DEP_MAX_TOKENS) {
        while (pos < end && isspace((unsigned char)cmd[pos])) pos++;
        if (pos >= end) break;

        uint32_t tok_start = pos;

        if (cmd[pos] == '\'') {
            pos++;
            while (pos < end && cmd[pos] != '\'') pos++;
            if (pos < end) pos++;
        } else if (cmd[pos] == '"') {
            pos++;
            while (pos < end && cmd[pos] != '"') {
                if (cmd[pos] == '\\' && pos + 1 < end) pos++;
                pos++;
            }
            if (pos < end) pos++;
        } else if (cmd[pos] == '\\' && pos + 1 < end) {
            pos += 2;
        } else {
            while (pos < end) {
                char c = cmd[pos];
                if (isspace((unsigned char)c)) break;
                if (c == '$' && pos + 1 < end && cmd[pos + 1] == '(') {
                    pos += 2;
                    int depth = 1;
                    while (pos < end && depth > 0) {
                        if (cmd[pos] == '(') depth++;
                        else if (cmd[pos] == ')') { depth--; if (depth == 0) break; }
                        pos++;
                    }
                    if (pos < end && depth == 0) pos++;
                    continue;
                }
                if (c == '`') {
                    pos++;
                    while (pos < end && cmd[pos] != '`') pos++;
                    if (pos < end) pos++;
                    continue;
                }
                if (c == '|' || c == ';' || c == '&' || c == '<' || c == '>') {
                    break;
                }
                pos++;
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
}

/* ============================================================
 * TOKEN CLASSIFICATION HELPERS
 * ============================================================ */

static bool is_env_assign(const dep_token_t *tok)
{
    if (tok->len < 3) return false;
    char c = tok->start[0];
    if (!isalpha((unsigned char)c) && c != '_') return false;
    for (uint32_t i = 1; i < tok->len; i++) {
        if (tok->start[i] == '=') return true;
        if (!isalnum((unsigned char)tok->start[i]) && tok->start[i] != '_') return false;
    }
    return false;
}

typedef enum {
    DEP_REDIRECT_NONE,
    DEP_REDIRECT_IN,
    DEP_REDIRECT_OUT,
    DEP_REDIRECT_APPEND,
    DEP_REDIRECT_ERR_OUT,
    DEP_REDIRECT_ERR_APP,
} dep_redirect_t;

static dep_redirect_t classify_redirect(const dep_token_t *tok)
{
    if (tok->len == 1) {
        if (tok->start[0] == '<') return DEP_REDIRECT_IN;
        if (tok->start[0] == '>') return DEP_REDIRECT_OUT;
    } else if (tok->len == 2) {
        if (tok->start[0] == '>' && tok->start[1] == '>') return DEP_REDIRECT_APPEND;
        if (tok->start[0] == '2' && tok->start[1] == '>') return DEP_REDIRECT_ERR_OUT;
    } else if (tok->len == 3) {
        if (tok->start[0] == '2' && tok->start[1] == '>' && tok->start[2] == '>')
            return DEP_REDIRECT_ERR_APP;
    }
    return DEP_REDIRECT_NONE;
}

static bool is_subshell_start(const dep_token_t *tok)
{
    if (tok->len >= 2 && tok->start[0] == '$' && tok->start[1] == '(') return true;
    if (tok->len >= 1 && tok->start[0] == '`') return true;
    return false;
}

static const char *extract_subshell_content(const dep_token_t *tok, uint32_t *out_len)
{
    if (tok->len >= 2 && tok->start[0] == '$' && tok->start[1] == '(') {
        int depth = 1;
        uint32_t i = 2;
        while (i < tok->len && depth > 0) {
            if (tok->start[i] == '(') depth++;
            if (tok->start[i] == ')') depth--;
            if (depth > 0) i++;
        }
        if (depth == 0) {
            *out_len = i - 2;
            return tok->start + 2;
        }
    } else if (tok->len >= 1 && tok->start[0] == '`') {
        uint32_t i = 1;
        while (i < tok->len && tok->start[i] != '`') i++;
        if (i < tok->len) {
            *out_len = i - 1;
            return tok->start + 1;
        }
    }
    *out_len = 0;
    return NULL;
}

static bool token_streq(const dep_token_t *tok, const char *str, uint32_t slen)
{
    return tok->len == slen && memcmp(tok->start, str, slen) == 0;
}

static bool token_looks_like_path(const dep_token_t *tok)
{
    for (uint32_t i = 0; i < tok->len; i++) {
        if (tok->start[i] == '/' || tok->start[i] == '.') return true;
    }
    return false;
}

/* ============================================================
 * HEREDOC PRE-SCAN
 * ============================================================ */

typedef struct {
    uint32_t marker_idx;
    const char *delimiter;
    uint32_t delimiter_len;
    bool strip_tabs;
    uint32_t line_end;
    uint32_t content_start_pos;
    uint32_t terminator_idx;
    int32_t cmd_node_idx;
} heredoc_info_t;

static uint32_t prescan_heredocs(const char *cmd, size_t cmd_len,
                                  const shell_parse_result_t *result,
                                  heredoc_info_t *heredocs, uint32_t max_heredocs,
                                  bool *skip)
{
    uint32_t hcount = 0;
    for (uint32_t i = 0; i < result->count; i++) skip[i] = false;

    for (uint32_t i = 0; i < result->count && hcount < max_heredocs; i++) {
        if (!(result->cmds[i].type & SHELL_TYPE_HEREDOC)) continue;

        heredoc_info_t *hd = &heredocs[hcount++];
        hd->marker_idx = i;
        hd->cmd_node_idx = -1;
        skip[i] = true;

        const char *marker = cmd + result->cmds[i].start;
        uint32_t mlen = result->cmds[i].len;
        uint32_t pos = 2;

        hd->strip_tabs = false;
        if (pos < mlen && marker[pos] == '-') { hd->strip_tabs = true; pos++; }

        bool quoted = false;
        if (pos < mlen && (marker[pos] == '\'' || marker[pos] == '"')) {
            quoted = true;
            pos++;
        }

        hd->delimiter = marker + pos;
        hd->delimiter_len = mlen - pos;
        if (quoted && hd->delimiter_len > 0) hd->delimiter_len--;

        uint32_t mend = result->cmds[i].start + result->cmds[i].len;
        hd->line_end = mend;
        while (hd->line_end < cmd_len && cmd[hd->line_end] != '\n') hd->line_end++;
        hd->content_start_pos = 0;
        hd->terminator_idx = UINT32_MAX;
    }

    for (uint32_t h = 0; h < hcount; h++) {
        heredoc_info_t *hd = &heredocs[h];

        for (int32_t j = (int32_t)result->count - 1; j >= 0; j--) {
            if (j <= (int32_t)hd->marker_idx) break;
            if (skip[(uint32_t)j]) continue;
            if (result->cmds[j].start <= hd->line_end) continue;

            const char *text = cmd + result->cmds[j].start;
            uint32_t tlen = result->cmds[j].len;

            if (hd->strip_tabs) {
                while (tlen > 0 && *text == '\t') { text++; tlen--; }
            }

            if (tlen == hd->delimiter_len &&
                memcmp(text, hd->delimiter, hd->delimiter_len) == 0) {
                hd->terminator_idx = (uint32_t)j;
                skip[(uint32_t)j] = true;

                for (uint32_t k = hd->marker_idx + 1; k < (uint32_t)j; k++) {
                    if (result->cmds[k].start > hd->line_end) {
                        skip[k] = true;
                        if (hd->content_start_pos == 0)
                            hd->content_start_pos = result->cmds[k].start;
                    }
                }

                if (hd->content_start_pos == 0)
                    hd->content_start_pos = result->cmds[j].start;

                break;
            }
        }
    }

    return hcount;
}

/* ============================================================
 * NODE/EDGE BUILDER HELPERS
 * ============================================================ */

static bool add_doc_file(shell_dep_graph_t *g, uint32_t max_nodes, uint32_t max_edges,
                          const char *path, uint32_t path_len,
                          uint32_t cmd_idx, shell_dep_edge_type_t etype,
                          shell_dep_edge_dir_t edir,
                          dep_redirect_t redir, uint32_t *status)
{
    if (g->node_count >= max_nodes) { *status |= SHELL_DEP_STATUS_TRUNCATED; return false; }
    shell_dep_node_t *fn = &g->nodes[g->node_count++];
    fn->type = SHELL_NODE_DOC;
    fn->doc.kind = SHELL_DOC_FILE;
    fn->doc.path = path;
    fn->doc.path_len = path_len;
    fn->doc.name = NULL;
    fn->doc.name_len = 0;
    fn->doc.value = NULL;
    fn->doc.value_len = 0;

    if (g->edge_count >= max_edges) { *status |= SHELL_DEP_STATUS_TRUNCATED; return false; }
    shell_dep_edge_t *e = &g->edges[g->edge_count++];
    e->type = etype;
    e->dir = edir;

    if (redir == DEP_REDIRECT_IN) {
        e->from = g->node_count - 1;
        e->to = cmd_idx;
    } else {
        e->from = cmd_idx;
        e->to = g->node_count - 1;
    }

    return true;
}

static bool add_doc_envvar(shell_dep_graph_t *g, uint32_t max_nodes, uint32_t max_edges,
                            const char *name, uint32_t name_len,
                            const char *value, uint32_t value_len,
                            uint32_t cmd_idx, uint32_t *status)
{
    if (g->node_count >= max_nodes) { *status |= SHELL_DEP_STATUS_TRUNCATED; return false; }
    shell_dep_node_t *en = &g->nodes[g->node_count++];
    en->type = SHELL_NODE_DOC;
    en->doc.kind = SHELL_DOC_ENVVAR;
    en->doc.name = name;
    en->doc.name_len = name_len;
    en->doc.value = value;
    en->doc.value_len = value_len;
    en->doc.path = NULL;
    en->doc.path_len = 0;

    if (g->edge_count >= max_edges) { *status |= SHELL_DEP_STATUS_TRUNCATED; return false; }
    shell_dep_edge_t *e = &g->edges[g->edge_count++];
    e->from = g->node_count - 1;
    e->to = cmd_idx;
    e->type = SHELL_EDGE_ENV;
    e->dir = SHELL_DIR_FORWARD;

    return true;
}

/* ============================================================
 * MAIN PARSER
 * ============================================================ */

shell_dep_error_t shell_parse_depgraph(
    const char *cmd,
    size_t cmd_len,
    const char *initial_cwd,
    const shell_dep_limits_t *limits,
    shell_dep_graph_t *out
)
{
    if (!cmd || !out || cmd_len == 0) {
        if (out) {
            out->node_count = 0;
            out->edge_count = 0;
            out->status = 2;
        }
        return SHELL_DEP_EINPUT;
    }

    shell_dep_limits_t local_limits;
    if (!limits) {
        local_limits = SHELL_DEP_LIMITS_DEFAULT;
        limits = &local_limits;
    }

    uint32_t max_nodes = limits->max_nodes;
    if (max_nodes > SHELL_DEP_MAX_NODES) max_nodes = SHELL_DEP_MAX_NODES;
    uint32_t max_edges = limits->max_edges;
    if (max_edges > SHELL_DEP_MAX_EDGES) max_edges = SHELL_DEP_MAX_EDGES;
    uint32_t max_tokens = limits->max_tokens_per_cmd;
    if (max_tokens > SHELL_DEP_MAX_TOKENS) max_tokens = SHELL_DEP_MAX_TOKENS;

    memset(out, 0, sizeof(shell_dep_graph_t));

    shell_parse_result_t fast_result;
    shell_error_t fast_err = shell_parse_fast(cmd, cmd_len, NULL, &fast_result);
    if (fast_err == SHELL_EPARSE && fast_result.count == 0) {
        out->status = 0;
        return SHELL_DEP_OK;
    }
    if (fast_err == SHELL_EPARSE) {
        out->status = 2;
        return SHELL_DEP_EPARSE;
    }
    out->status = fast_result.status;

    if (fast_result.count == 0) return SHELL_DEP_OK;

    bool skip_buf[SHELL_MAX_SUBCOMMANDS];
    heredoc_info_t heredocs[SHELL_DEP_MAX_HEREDOCS];
    uint32_t hcount = prescan_heredocs(cmd, cmd_len, &fast_result,
                                        heredocs, SHELL_DEP_MAX_HEREDOCS, skip_buf);

    shell_dep_cwd_buf_t cwd_buf;
    if (!cwd_buf_init(&cwd_buf)) return SHELL_DEP_EPARSE;
    const char *cwd = initial_cwd ? initial_cwd : ".";

    int32_t last_cmd_idx = -1;

    for (uint32_t si = 0; si < fast_result.count; si++) {
        if (skip_buf[si]) {
            if (fast_result.cmds[si].type & SHELL_TYPE_HEREDOC) {
                for (uint32_t h = 0; h < hcount; h++) {
                    if (heredocs[h].marker_idx == si)
                        heredocs[h].cmd_node_idx = last_cmd_idx;
                }
            }
            continue;
        }

        const shell_range_t *range = &fast_result.cmds[si];
        uint32_t rstart = range->start;
        uint32_t rlen = range->len;

        if (range->type & SHELL_TYPE_HERESTRING) {
            const char *marker = cmd + rstart;
            uint32_t mlen = rlen;
            uint32_t pos = 3;
            while (pos < mlen && isspace((unsigned char)marker[pos])) pos++;

            const char *word = marker + pos;
            uint32_t word_len = mlen - pos;

            if (last_cmd_idx >= 0 && out->node_count < max_nodes) {
                shell_dep_node_t *doc = &out->nodes[out->node_count++];
                doc->type = SHELL_NODE_DOC;
                doc->doc.kind = SHELL_DOC_HERESTRING;
                doc->doc.value = word;
                doc->doc.value_len = word_len;
                doc->doc.path = NULL;
                doc->doc.path_len = 0;
                doc->doc.name = NULL;
                doc->doc.name_len = 0;

                if (out->edge_count < max_edges) {
                    shell_dep_edge_t *e = &out->edges[out->edge_count++];
                    e->from = out->node_count - 1;
                    e->to = (uint32_t)last_cmd_idx;
                    e->type = SHELL_EDGE_READ;
                    e->dir = SHELL_DIR_FORWARD;
                }
            }
            continue;
        }

        dep_token_list_t tokens;
        scan_tokens(cmd, rstart, rlen, &tokens);

        if (tokens.count == 0) continue;

        bool is_cd = false;
        if (tokens.count >= 1) {
            const dep_token_t *t = &tokens.tokens[0];
            if (token_streq(t, "cd", 2)) is_cd = true;
        }

        if (is_cd) {
            if (tokens.count >= 2) {
                dep_token_t arg = tokens.tokens[1];
                char arg_buf[256];
                uint32_t alen = arg.len < 255 ? arg.len : 255;
                memcpy(arg_buf, arg.start, alen);
                arg_buf[alen] = '\0';
                cwd = cwd_resolve(&cwd_buf, cwd, arg_buf);
            } else {
                cwd = "$HOME";
            }
            continue;
        }

        bool is_redirect_only = true;
        {
            uint32_t t = 0;
            while (t < tokens.count) {
                dep_redirect_t r = classify_redirect(&tokens.tokens[t]);
                if (r != DEP_REDIRECT_NONE) {
                    t += 2;
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
                if (t < tokens.count && redir != DEP_REDIRECT_NONE) {
                    const dep_token_t *target = &tokens.tokens[t];
                    shell_dep_edge_type_t etype = SHELL_EDGE_WRITE;
                    switch (redir) {
                        case DEP_REDIRECT_IN: etype = SHELL_EDGE_READ; break;
                        case DEP_REDIRECT_OUT:
                        case DEP_REDIRECT_ERR_OUT: etype = SHELL_EDGE_WRITE; break;
                        case DEP_REDIRECT_APPEND:
                        case DEP_REDIRECT_ERR_APP: etype = SHELL_EDGE_APPEND; break;
                        default: break;
                    }
                    add_doc_file(out, max_nodes, max_edges,
                                 target->start, target->len,
                                 prev_cmd, etype, SHELL_DIR_FORWARD, redir, &out->status);
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
            cwd_buf_free(&cwd_buf);
            return SHELL_DEP_ETRUNC;
        }

        uint32_t cmd_node_idx = out->node_count;
        shell_dep_node_t *node = &out->nodes[out->node_count++];
        node->type = SHELL_NODE_CMD;
        node->cmd.cwd = cwd;
        node->cmd.token_count = 0;

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
                        if (etok->start[i] == '=') { eq_pos = i; break; }
                    }

                    add_doc_envvar(out, max_nodes, max_edges,
                                   etok->start, eq_pos,
                                   etok->start + eq_pos + 1, etok->len - eq_pos - 1,
                                   cmd_node_idx, &out->status);

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
                if (etok->start[i] == '=') { eq_pos = i; break; }
            }

            add_doc_envvar(out, max_nodes, max_edges,
                           etok->start, eq_pos,
                           etok->start + eq_pos + 1, etok->len - eq_pos - 1,
                           cmd_node_idx, &out->status);
            ti++;
        }

        bool found_command = false;
        while (ti < tokens.count) {
            const dep_token_t *tok = &tokens.tokens[ti];
            dep_redirect_t redir = classify_redirect(tok);

            if (redir != DEP_REDIRECT_NONE) {
                ti++;
                if (ti < tokens.count) {
                    const dep_token_t *target = &tokens.tokens[ti];

                    shell_dep_edge_type_t etype;
                    shell_dep_edge_dir_t edir = SHELL_DIR_FORWARD;

                    switch (redir) {
                        case DEP_REDIRECT_IN:
                            etype = SHELL_EDGE_READ; break;
                        case DEP_REDIRECT_OUT:
                        case DEP_REDIRECT_ERR_OUT:
                            etype = SHELL_EDGE_WRITE; break;
                        case DEP_REDIRECT_APPEND:
                        case DEP_REDIRECT_ERR_APP:
                            etype = SHELL_EDGE_APPEND; break;
                        default:
                            etype = SHELL_EDGE_WRITE; break;
                    }

                    add_doc_file(out, max_nodes, max_edges,
                                 target->start, target->len,
                                 cmd_node_idx, etype, edir, redir, &out->status);
                }
                ti++;
                continue;
            }

            if (is_subshell_start(tok)) {
                uint32_t sub_len = 0;
                const char *sub_content = extract_subshell_content(tok, &sub_len);
                if (sub_content && sub_len > 0) {
                    shell_dep_graph_t sub_graph;
                    shell_dep_error_t sub_err = shell_parse_depgraph(
                        sub_content, sub_len, cwd, limits, &sub_graph
                    );
                    if (sub_err == SHELL_DEP_OK && sub_graph.node_count > 0) {
                        int32_t sub_cmd_idx = -1;
                        for (int32_t i = (int32_t)sub_graph.node_count - 1; i >= 0; i--) {
                            if (sub_graph.nodes[i].type == SHELL_NODE_CMD) {
                                sub_cmd_idx = i;
                                break;
                            }
                        }

                        uint32_t node_offset = out->node_count;
                        for (uint32_t i = 0; i < sub_graph.node_count && out->node_count < max_nodes; i++) {
                            out->nodes[out->node_count++] = sub_graph.nodes[i];
                        }

                        for (uint32_t i = 0; i < sub_graph.edge_count && out->edge_count < max_edges; i++) {
                            shell_dep_edge_t *e = &out->edges[out->edge_count++];
                            e->from = sub_graph.edges[i].from + node_offset;
                            e->to = sub_graph.edges[i].to + node_offset;
                            e->type = sub_graph.edges[i].type;
                            e->dir = sub_graph.edges[i].dir;
                        }

                        if (sub_cmd_idx >= 0 && out->edge_count < max_edges) {
                            shell_dep_edge_t *se = &out->edges[out->edge_count++];
                            se->from = node_offset + (uint32_t)sub_cmd_idx;
                            se->to = cmd_node_idx;
                            se->type = SHELL_EDGE_SUBST;
                            se->dir = SHELL_DIR_FORWARD;
                        }
                    }
                }

                if (node->cmd.token_count < max_tokens) {
                    uint32_t idx = node->cmd.token_count++;
                    node->cmd.tokens[idx] = tok->start;
                    node->cmd.token_lens[idx] = tok->len;
                }
                ti++;
                continue;
            }

            if (!found_command) found_command = true;

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

                    shell_dep_edge_t *ae = &out->edges[out->edge_count++];
                    ae->from = cmd_node_idx;
                    ae->to = out->node_count - 1;
                    ae->type = SHELL_EDGE_ARG;
                    ae->dir = SHELL_DIR_UNDIR;
                }
            }

            ti++;
        }

    add_control_edge:
        if (last_cmd_idx >= 0 && out->edge_count < max_edges) {
            shell_dep_edge_t *edge = &out->edges[out->edge_count++];
            edge->from = (uint32_t)last_cmd_idx;
            edge->to = cmd_node_idx;
            edge->dir = SHELL_DIR_FORWARD;

            uint16_t stype = range->type;
            if (stype == (1u << 8))
                edge->type = SHELL_EDGE_PIPE;
            else if (stype == (1u << 9))
                edge->type = SHELL_EDGE_AND;
            else if (stype == (1u << 10))
                edge->type = SHELL_EDGE_OR;
            else
                edge->type = SHELL_EDGE_SEQ;
        }

        last_cmd_idx = (int32_t)cmd_node_idx;
    }

    for (uint32_t h = 0; h < hcount; h++) {
        heredoc_info_t *hd = &heredocs[h];
        if (hd->terminator_idx == UINT32_MAX) continue;
        if (hd->cmd_node_idx < 0) continue;

        uint32_t content_start = hd->content_start_pos;
        uint32_t content_end = fast_result.cmds[hd->terminator_idx].start;
        if (content_end > 0 && content_end > content_start) content_end--;

        uint32_t content_len = 0;
        const char *content_ptr = NULL;
        if (content_end > content_start) {
            content_ptr = cmd + content_start;
            content_len = content_end - content_start;
            if (content_len > 0 && content_ptr[content_len - 1] == '\n') content_len--;
        }

        if (out->node_count >= max_nodes) break;
        shell_dep_node_t *dn = &out->nodes[out->node_count++];
        dn->type = SHELL_NODE_DOC;
        dn->doc.kind = SHELL_DOC_HEREDOC;
        dn->doc.value = content_ptr;
        dn->doc.value_len = content_len;
        dn->doc.name = hd->delimiter;
        dn->doc.name_len = hd->delimiter_len;
        dn->doc.path = NULL;
        dn->doc.path_len = 0;

        if (out->edge_count < max_edges) {
            shell_dep_edge_t *e = &out->edges[out->edge_count++];
            e->from = out->node_count - 1;
            e->to = (uint32_t)hd->cmd_node_idx;
            e->type = SHELL_EDGE_READ;
            e->dir = SHELL_DIR_FORWARD;
        }
    }

    cwd_buf_free(&cwd_buf);
    return SHELL_DEP_OK;
}

/* ============================================================
 * GRAPH UTILITIES
 * ============================================================ */

void shell_dep_graph_dump(const shell_dep_graph_t *g, FILE *fp)
{
    fprintf(fp, "Graph: %u nodes, %u edges, status=0x%x\n",
            g->node_count, g->edge_count, g->status);

    fprintf(fp, "Nodes:\n");
    for (uint32_t i = 0; i < g->node_count; i++) {
        const shell_dep_node_t *n = &g->nodes[i];
        if (n->type == SHELL_NODE_CMD) {
            fprintf(fp, "  [%u] CMD cwd=\"%s\" tokens=[", i, n->cmd.cwd ? n->cmd.cwd : ".");
            for (uint32_t j = 0; j < n->cmd.token_count; j++) {
                if (j > 0) fprintf(fp, ", ");
                fprintf(fp, "\"%.*s\"", n->cmd.token_lens[j], n->cmd.tokens[j]);
            }
            fprintf(fp, "]\n");
        } else {
            fprintf(fp, "  [%u] DOC %s", i, shell_dep_doc_kind_name(n->doc.kind));
            if (n->doc.kind == SHELL_DOC_FILE && n->doc.path) {
                fprintf(fp, " path=\"%.*s\"", n->doc.path_len, n->doc.path);
            } else if (n->doc.kind == SHELL_DOC_ENVVAR) {
                fprintf(fp, " name=\"%.*s\" value=\"%.*s\"",
                        n->doc.name_len, n->doc.name ? n->doc.name : "",
                        n->doc.value_len, n->doc.value ? n->doc.value : "");
            } else if (n->doc.kind == SHELL_DOC_HEREDOC) {
                fprintf(fp, " delim=\"%.*s\" content=\"%.*s\"",
                        n->doc.name_len, n->doc.name ? n->doc.name : "",
                        n->doc.value_len, n->doc.value ? n->doc.value : "");
            } else if (n->doc.kind == SHELL_DOC_HERESTRING && n->doc.value) {
                fprintf(fp, " content=\"%.*s\"", n->doc.value_len, n->doc.value);
            }
            fprintf(fp, "\n");
        }
    }

    fprintf(fp, "Edges:\n");
    for (uint32_t i = 0; i < g->edge_count; i++) {
        const shell_dep_edge_t *e = &g->edges[i];
        const char *arrow = e->dir == SHELL_DIR_FORWARD ? "->" :
                            e->dir == SHELL_DIR_UNDIR   ? "<>" : "<->";
        fprintf(fp, "  [%u] %s %s %u %s %u\n", i,
                shell_dep_edge_type_name(e->type), arrow,
                e->from, arrow, e->to);
    }
}

shell_dep_validate_result_t shell_dep_validate(const shell_dep_graph_t *g)
{
    shell_dep_validate_result_t r;
    r.valid = true;
    r.error_count = 0;

    for (uint32_t i = 0; i < g->edge_count && r.error_count < SHELL_DEP_MAX_VALIDATE_ERRORS; i++) {
        const shell_dep_edge_t *e = &g->edges[i];

        if (e->from >= g->node_count || e->to >= g->node_count) {
            r.valid = false;
            r.errors[r.error_count].edge_idx = i;
            snprintf(r.errors[r.error_count].msg, 96,
                     "OOB: from=%u to=%u nodes=%u", e->from, e->to, g->node_count);
            r.error_count++;
            continue;
        }

        shell_dep_node_type_t ft = g->nodes[e->from].type;
        shell_dep_node_type_t tt = g->nodes[e->to].type;

        bool ok = true;
        switch (e->type) {
            case SHELL_EDGE_PIPE:
            case SHELL_EDGE_SEQ:
            case SHELL_EDGE_AND:
            case SHELL_EDGE_OR:
            case SHELL_EDGE_SUBST:
                ok = (ft == SHELL_NODE_CMD && tt == SHELL_NODE_CMD);
                break;
            case SHELL_EDGE_READ:
                ok = (ft == SHELL_NODE_DOC && tt == SHELL_NODE_CMD);
                break;
            case SHELL_EDGE_WRITE:
            case SHELL_EDGE_APPEND:
                ok = (ft == SHELL_NODE_CMD && tt == SHELL_NODE_DOC);
                break;
            case SHELL_EDGE_ENV:
                ok = (ft == SHELL_NODE_DOC && tt == SHELL_NODE_CMD);
                break;
            case SHELL_EDGE_ARG:
                ok = ((ft == SHELL_NODE_CMD && tt == SHELL_NODE_DOC) ||
                      (ft == SHELL_NODE_DOC && tt == SHELL_NODE_CMD));
                break;
        }

        if (!ok) {
            r.valid = false;
            r.errors[r.error_count].edge_idx = i;
            snprintf(r.errors[r.error_count].msg, 96,
                     "type mismatch: %s(%s)->%s(%s) for %s edge",
                     shell_dep_node_type_name(ft),
                     ft == SHELL_NODE_DOC ? shell_dep_doc_kind_name(g->nodes[e->from].doc.kind) : "",
                     shell_dep_node_type_name(tt),
                     tt == SHELL_NODE_DOC ? shell_dep_doc_kind_name(g->nodes[e->to].doc.kind) : "",
                     shell_dep_edge_type_name(e->type));
            r.error_count++;
        }
    }

    return r;
}
