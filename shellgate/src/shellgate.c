/*
 * shellgate.c - Shell command policy gate
 *
 * Connects shellsplit (parsing + depgraph) with shelltype (policy eval).
 */

#include "shellgate.h"
#include "shell_tokenizer.h"
#include "shell_depgraph.h"
#include "shelltype.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/* ============================================================
 * PORTABLE strlcpy
 * ============================================================ */

static size_t sg_strlcpy(char *dst, const char *src, size_t size)
{
    size_t slen = strlen(src);
    if (size > 0) {
        size_t copy = slen < size - 1 ? slen : size - 1;
        memcpy(dst, src, copy);
        dst[copy] = '\0';
    }
    return slen;
}

/* ============================================================
 * OUTPUT BUFFER WRITER
 * ============================================================ */

typedef struct {
    char    *base;
    size_t   size;
    size_t   used;
    bool     overflow;
} buf_writer_t;

static void bw_init(buf_writer_t *w, char *buf, size_t buf_size)
{
    w->base     = buf;
    w->size     = buf_size;
    w->used     = 0;
    w->overflow = false;
}

static const char *bw_copy(buf_writer_t *w, const char *src, size_t src_len)
{
    if (w->used >= w->size) {
        w->overflow = true;
        return NULL;
    }
    size_t avail = w->size - w->used;
    size_t copy  = src_len < avail ? src_len : avail - 1;
    if (copy == 0 && avail <= 1) {
        w->overflow = true;
        return NULL;
    }
    char *dst = w->base + w->used;
    memcpy(dst, src, copy);
    dst[copy] = '\0';
    const char *result = dst;
    w->used += copy + 1;
    if (src_len > copy) w->overflow = true;
    return result;
}

static const char *bw_printf(buf_writer_t *w, const char *fmt, ...)
{
    if (w->used >= w->size) {
        w->overflow = true;
        return NULL;
    }
    va_list ap;
    va_start(ap, fmt);
    size_t avail = w->size - w->used;
    int n = vsnprintf(w->base + w->used, avail, fmt, ap);
    va_end(ap);
    if (n < 0) {
        w->overflow = true;
        return NULL;
    }
    const char *result = w->base + w->used;
    if ((size_t)n >= avail) {
        w->used = w->size;
        w->overflow = true;
    } else {
        w->used += (size_t)n + 1;
    }
    return result;
}

/* ============================================================
 * GATE STATE
 * ============================================================ */

struct sg_gate {
    st_policy_ctx_t *pctx;
    st_policy_t     *policy;

    char     cwd[512];
    uint32_t reject_mask;
    sg_stop_mode_t stop_mode;
    bool     suggestions;

    sg_expand_var_fn  expand_var_fn;
    void             *expand_var_ctx;
    sg_expand_glob_fn expand_glob_fn;
    void             *expand_glob_ctx;
};

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

sg_gate_t *sg_gate_new(void)
{
    sg_gate_t *g = calloc(1, sizeof(*g));
    if (!g) return NULL;

    g->pctx = st_policy_ctx_new();
    if (!g->pctx) { free(g); return NULL; }

    g->policy = st_policy_new(g->pctx);
    if (!g->policy) { st_policy_ctx_free(g->pctx); free(g); return NULL; }

    sg_strlcpy(g->cwd, ".", sizeof(g->cwd));
    g->reject_mask = SG_REJECT_MASK_DEFAULT;
    g->stop_mode = SG_STOP_FIRST_FAIL;
    g->suggestions = true;

    return g;
}

void sg_gate_free(sg_gate_t *gate)
{
    if (!gate) return;
    if (gate->policy) st_policy_free(gate->policy);
    if (gate->pctx)   st_policy_ctx_free(gate->pctx);
    free(gate);
}

/* ============================================================
 * CONFIGURATION
 * ============================================================ */

sg_error_t sg_gate_set_cwd(sg_gate_t *gate, const char *cwd)
{
    if (!gate || !cwd) return SG_ERR_INVALID;
    sg_strlcpy(gate->cwd, cwd, sizeof(gate->cwd));
    return SG_OK;
}

sg_error_t sg_gate_set_reject_mask(sg_gate_t *gate, uint32_t mask)
{
    if (!gate) return SG_ERR_INVALID;
    gate->reject_mask = mask;
    return SG_OK;
}

sg_error_t sg_gate_set_stop_mode(sg_gate_t *gate, sg_stop_mode_t mode)
{
    if (!gate) return SG_ERR_INVALID;
    gate->stop_mode = mode;
    return SG_OK;
}

sg_error_t sg_gate_set_suggestions(sg_gate_t *gate, bool enabled)
{
    if (!gate) return SG_ERR_INVALID;
    gate->suggestions = enabled;
    return SG_OK;
}

sg_error_t sg_gate_set_expand_var(sg_gate_t *gate,
                                   sg_expand_var_fn fn, void *user_ctx)
{
    if (!gate) return SG_ERR_INVALID;
    gate->expand_var_fn  = fn;
    gate->expand_var_ctx = user_ctx;
    return SG_OK;
}

sg_error_t sg_gate_set_expand_glob(sg_gate_t *gate,
                                    sg_expand_glob_fn fn, void *user_ctx)
{
    if (!gate) return SG_ERR_INVALID;
    gate->expand_glob_fn  = fn;
    gate->expand_glob_ctx = user_ctx;
    return SG_OK;
}

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path)
{
    if (!gate || !path) return SG_ERR_INVALID;
    st_error_t err = st_policy_load(gate->policy, path);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_save_policy(const sg_gate_t *gate, const char *path)
{
    if (!gate || !path) return SG_ERR_INVALID;
    st_error_t err = st_policy_save(gate->policy, path);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_add_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_add(gate->policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_remove_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_remove(gate->policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

uint32_t sg_gate_rule_count(const sg_gate_t *gate)
{
    if (!gate) return 0;
    return (uint32_t)st_policy_count(gate->policy);
}

/* ============================================================
 * INTERNAL: TOKEN EXPANSION HELPERS
 * ============================================================ */

static bool extract_var_name(const char *tok, size_t len,
                              char *name_out, size_t name_max)
{
    if (len < 2 || tok[0] != '$') return false;

    size_t start = 1;
    size_t end   = len;

    if (len > 3 && tok[1] == '{' && tok[len - 1] == '}') {
        start = 2;
        end   = len - 1;
    }

    size_t nlen = end - start;
    if (nlen == 0 || nlen >= name_max) return false;

    for (size_t i = start; i < end; i++) {
        char c = tok[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return false;
    }

    memcpy(name_out, tok + start, nlen);
    name_out[nlen] = '\0';
    return true;
}

static bool has_glob_chars(const char *tok, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (tok[i] == '*' || tok[i] == '?' || tok[i] == '[') return true;
    }
    return false;
}

/* ============================================================
 * INTERNAL: BUILD COMMAND STRING WITH OPTIONAL EXPANSION
 * ============================================================ */

#define SG_EXPAND_BUF 1024

static const char *build_cmd_string(const shell_dep_cmd_t *cmd,
                                     buf_writer_t *bw,
                                     const sg_gate_t *gate)
{
    if (bw->used >= bw->size) { bw->overflow = true; return NULL; }

    size_t start = bw->used;
    size_t avail = bw->size - start;
    size_t pos   = 0;

    for (uint32_t i = 0; i < cmd->token_count; i++) {
        if (i > 0 && pos < avail) bw->base[start + pos++] = ' ';

        const char *text = cmd->tokens[i];
        size_t text_len  = cmd->token_lens[i];
        bool expanded    = false;

        /* Try variable expansion */
        if (gate->expand_var_fn) {
            char var_name[128];
            if (extract_var_name(text, text_len, var_name, sizeof(var_name))) {
                char exp[SG_EXPAND_BUF];
                size_t elen = gate->expand_var_fn(var_name, exp, sizeof(exp),
                                                   gate->expand_var_ctx);
                if (elen > 0) {
                    text = exp;
                    text_len = elen;
                    expanded = true;
                }
            }
        }

        /* Try glob expansion (only if variable expansion didn't fire) */
        if (!expanded && gate->expand_glob_fn) {
            if (has_glob_chars(text, text_len)) {
                char pattern[256];
                size_t plen = text_len < sizeof(pattern) - 1
                              ? text_len : sizeof(pattern) - 1;
                memcpy(pattern, text, plen);
                pattern[plen] = '\0';

                char exp[SG_EXPAND_BUF];
                size_t elen = gate->expand_glob_fn(pattern, exp, sizeof(exp),
                                                    gate->expand_glob_ctx);
                if (elen > 0) {
                    text = exp;
                    text_len = elen;
                }
            }
        }

        if (pos + text_len >= avail) {
            size_t writable = avail > pos + 1 ? avail - pos - 1 : 0;
            if (writable > 0) memcpy(bw->base + start + pos, text, writable);
            pos = avail > 0 ? avail - 1 : 0;
            bw->overflow = true;
            break;
        }
        memcpy(bw->base + start + pos, text, text_len);
        pos += text_len;
    }
    bw->base[start + pos] = '\0';
    bw->used = start + pos + 1;
    return bw->base + start;
}

/* ============================================================
 * INTERNAL: CHECK FEATURES FROM FAST PARSER AGAINST REJECT MASK
 * ============================================================ */

static const char *check_features(const shell_parse_result_t *fast,
                                   uint32_t reject_mask,
                                   uint32_t *bad_idx)
{
    static const struct { uint32_t bit; const char *name; } feats[] = {
        { SHELL_FEAT_SUBSHELL,     "command substitution" },
        { SHELL_FEAT_ARITH,        "arithmetic expansion" },
        { SHELL_FEAT_HEREDOC,      "heredoc" },
        { SHELL_FEAT_HERESTRING,   "herestring" },
        { SHELL_FEAT_PROCESS_SUB,  "process substitution" },
        { SHELL_FEAT_LOOPS,        "loop" },
        { SHELL_FEAT_CONDITIONALS, "conditional" },
        { SHELL_FEAT_CASE,         "case statement" },
    };

    for (uint32_t si = 0; si < fast->count; si++) {
        uint16_t fbits = fast->cmds[si].features;
        for (int k = 0; k < (int)(sizeof(feats)/sizeof(feats[0])); k++) {
            if ((fbits & feats[k].bit) && (reject_mask & feats[k].bit)) {
                if (bad_idx) *bad_idx = si;
                return feats[k].name;
            }
        }
    }
    return NULL;
}

/* ============================================================
 * EVALUATION
 * ============================================================ */

sg_error_t sg_eval(sg_gate_t *gate, const char *cmd,
                   char *buf, size_t buf_size,
                   sg_result_t *out)
{
    if (!gate || !cmd || !buf || !out) return SG_ERR_INVALID;
    if (buf_size == 0) return SG_ERR_INVALID;

    memset(out, 0, sizeof(*out));
    out->verdict = SG_VERDICT_ALLOW;

    size_t cmd_len = strlen(cmd);
    if (cmd_len == 0) return SG_ERR_INVALID;

    buf_writer_t bw;
    bw_init(&bw, buf, buf_size);

    /* Step 1: Fast parse to check features */
    shell_parse_result_t fast;
    shell_error_t ferr = shell_parse_fast(cmd, cmd_len, NULL, &fast);
    if (ferr == SHELL_EPARSE && fast.count == 0) {
        out->verdict = SG_VERDICT_ALLOW;
        return SG_OK;
    }
    if (ferr == SHELL_EPARSE) {
        out->verdict = SG_VERDICT_REJECT;
        out->deny_reason = bw_copy(&bw, "parse error", 11);
        out->subcmd_count = 1;
        out->subcmds[0].verdict = SG_VERDICT_REJECT;
        out->subcmds[0].reject_reason = out->deny_reason;
        return SG_OK;
    }

    /* Step 2: Feature rejection */
    uint32_t bad_idx = 0;
    const char *feat = check_features(&fast, gate->reject_mask, &bad_idx);
    if (feat) {
        out->verdict = SG_VERDICT_REJECT;
        out->deny_reason = bw_printf(&bw, "%s not allowed", feat);
        out->subcmd_count = 1;
        out->subcmds[0].verdict = SG_VERDICT_REJECT;
        out->subcmds[0].reject_reason = out->deny_reason;
        return SG_OK;
    }

    /* Step 3: Build depgraph */
    shell_dep_graph_t graph;
    shell_dep_error_t derr = shell_parse_depgraph(cmd, cmd_len, gate->cwd, NULL, &graph);
    if (derr != SHELL_DEP_OK) {
        out->verdict = SG_VERDICT_REJECT;
        out->deny_reason = bw_copy(&bw, "depgraph error", 14);
        out->subcmd_count = 1;
        out->subcmds[0].verdict = SG_VERDICT_REJECT;
        out->subcmds[0].reject_reason = out->deny_reason;
        return SG_OK;
    }

    /* Step 4: Walk CMD nodes, evaluate each against policy */
    for (uint32_t ni = 0; ni < graph.node_count && out->subcmd_count < SG_MAX_SUBCMD_RESULTS; ni++) {
        const shell_dep_node_t *node = &graph.nodes[ni];
        if (node->type != SHELL_NODE_CMD) continue;
        if (node->cmd.token_count == 0) continue;

        sg_subcmd_result_t *sr = &out->subcmds[out->subcmd_count++];

        sr->command = build_cmd_string(&node->cmd, &bw, gate);

        st_eval_result_t eval;
        st_error_t eval_err = st_policy_eval(gate->policy, sr->command ? sr->command : "",
                                              gate->suggestions ? &eval : NULL);
        if (eval_err != ST_OK) {
            sr->matches = false;
            sr->verdict = SG_VERDICT_DENY;
            sr->reject_reason = bw_copy(&bw, "policy eval error", 17);
        } else if (eval.matches) {
            sr->matches = true;
            sr->verdict = SG_VERDICT_ALLOW;
        } else {
            sr->matches = false;
            sr->verdict = SG_VERDICT_DENY;

            if (eval.suggestion_count > 0 && out->suggestion_count == 0) {
                out->suggestions[0] = bw_copy(&bw,
                    eval.suggestions[0].pattern,
                    strlen(eval.suggestions[0].pattern));
                if (out->suggestions[0]) out->suggestion_count++;
            }
            if (eval.suggestion_count > 1 && out->suggestion_count == 1) {
                out->suggestions[1] = bw_copy(&bw,
                    eval.suggestions[1].pattern,
                    strlen(eval.suggestions[1].pattern));
                if (out->suggestions[1]) out->suggestion_count++;
            }
        }

        if (!sr->matches && out->deny_reason == NULL) {
            out->deny_reason = sr->reject_reason ? sr->reject_reason : sr->command;
            out->attention_index = out->subcmd_count - 1;
        }

        if (!sr->matches && gate->stop_mode == SG_STOP_FIRST_FAIL) break;
        if (sr->matches && gate->stop_mode == SG_STOP_FIRST_PASS) break;
    }

    if (out->subcmd_count == 0) {
        out->verdict = SG_VERDICT_ALLOW;
        return bw.overflow ? SG_ERR_TRUNC : SG_OK;
    }

    bool all_match = true;
    for (uint32_t i = 0; i < out->subcmd_count; i++) {
        if (!out->subcmds[i].matches) { all_match = false; break; }
    }

    out->verdict = all_match ? SG_VERDICT_ALLOW : SG_VERDICT_DENY;
    out->truncated = bw.overflow;
    return bw.overflow ? SG_ERR_TRUNC : SG_OK;
}

/* ============================================================
 * HELPERS
 * ============================================================ */

const char *sg_verdict_name(sg_verdict_t v)
{
    switch (v) {
        case SG_VERDICT_ALLOW:  return "ALLOW";
        case SG_VERDICT_DENY:   return "DENY";
        case SG_VERDICT_REJECT: return "REJECT";
    }
    return "UNKNOWN";
}
