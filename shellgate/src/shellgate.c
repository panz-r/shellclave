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

    strncpy(g->cwd, ".", sizeof(g->cwd) - 1);
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
    strncpy(gate->cwd, cwd, sizeof(gate->cwd) - 1);
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
 * INTERNAL: BUILD COMMAND STRING FROM DEPGRAPH CMD NODE
 * ============================================================ */

static void build_cmd_string(const shell_dep_cmd_t *cmd, char *buf, size_t buf_len)
{
    size_t pos = 0;
    for (uint32_t i = 0; i < cmd->token_count && pos < buf_len - 1; i++) {
        if (i > 0 && pos < buf_len - 1) buf[pos++] = ' ';
        uint32_t tlen = cmd->token_lens[i];
        if (tlen > buf_len - pos - 1) tlen = (uint32_t)(buf_len - pos - 1);
        memcpy(buf + pos, cmd->tokens[i], tlen);
        pos += tlen;
    }
    buf[pos] = '\0';
}

/* ============================================================
 * INTERNAL: CHECK FEATURES FROM FAST PARSER AGAINST REJECT MASK
 * ============================================================ */

static const char *check_features(const shell_parse_result_t *fast,
                                   uint32_t reject_mask,
                                   uint32_t *bad_idx)
{
    static const struct { uint32_t bit; const char *name; } feats[] = {
        { 1u << 2, "command substitution" },
        { 1u << 3, "arithmetic expansion" },
        { 1u << 4, "heredoc" },
        { 1u << 5, "herestring" },
        { 1u << 6, "process substitution" },
        { 1u << 7, "loop" },
        { 1u << 8, "conditional" },
        { 1u << 9, "case statement" },
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

sg_error_t sg_eval(sg_gate_t *gate, const char *cmd, sg_result_t *out)
{
    if (!gate || !cmd || !out) return SG_ERR_INVALID;

    memset(out, 0, sizeof(*out));
    out->verdict = SG_VERDICT_ALLOW;

    size_t cmd_len = strlen(cmd);
    if (cmd_len == 0) return SG_ERR_INVALID;

    /* Step 1: Fast parse to check features */
    shell_parse_result_t fast;
    shell_error_t ferr = shell_parse_fast(cmd, cmd_len, NULL, &fast);
    if (ferr == SHELL_EPARSE && fast.count == 0) {
        out->verdict = SG_VERDICT_ALLOW;
        return SG_OK;
    }
    if (ferr == SHELL_EPARSE) {
        out->verdict = SG_VERDICT_REJECT;
        snprintf(out->subcmds[0].reject_reason, sizeof(out->subcmds[0].reject_reason),
                 "parse error");
        out->subcmd_count = 1;
        out->deny_reason = out->subcmds[0].reject_reason;
        return SG_OK;
    }

    /* Step 2: Feature rejection */
    uint32_t bad_idx = 0;
    const char *feat = check_features(&fast, gate->reject_mask, &bad_idx);
    if (feat) {
        out->verdict = SG_VERDICT_REJECT;
        snprintf(out->subcmds[0].reject_reason, sizeof(out->subcmds[0].reject_reason),
                 "%s not allowed", feat);
        out->subcmd_count = 1;
        out->deny_reason = out->subcmds[0].reject_reason;
        return SG_OK;
    }

    /* Step 3: Build depgraph */
    shell_dep_graph_t graph;
    shell_dep_error_t derr = shell_parse_depgraph(cmd, cmd_len, gate->cwd, NULL, &graph);
    if (derr != SHELL_DEP_OK) {
        out->verdict = SG_VERDICT_REJECT;
        snprintf(out->subcmds[0].reject_reason, sizeof(out->subcmds[0].reject_reason),
                 "depgraph error");
        out->subcmd_count = 1;
        out->deny_reason = out->subcmds[0].reject_reason;
        return SG_OK;
    }

    /* Step 4: Walk CMD nodes, evaluate each against policy */
    for (uint32_t ni = 0; ni < graph.node_count && out->subcmd_count < SG_MAX_SUBCMD_RESULTS; ni++) {
        const shell_dep_node_t *node = &graph.nodes[ni];
        if (node->type != SHELL_NODE_CMD) continue;
        if (node->cmd.token_count == 0) continue;

        sg_subcmd_result_t *sr = &out->subcmds[out->subcmd_count++];

        build_cmd_string(&node->cmd, sr->command, sizeof(sr->command));

        st_eval_result_t eval;
        st_error_t eval_err = st_policy_eval(gate->policy, sr->command,
                                              gate->suggestions ? &eval : NULL);
        if (eval_err != ST_OK) {
            sr->matches = false;
            sr->verdict = SG_VERDICT_DENY;
            snprintf(sr->reject_reason, sizeof(sr->reject_reason), "policy eval error");
        } else if (eval.matches) {
            sr->matches = true;
            sr->verdict = SG_VERDICT_ALLOW;
        } else {
            sr->matches = false;
            sr->verdict = SG_VERDICT_DENY;

            if (eval.suggestion_count > 0 && out->suggestion_count == 0) {
                strncpy(out->suggestion_a, eval.suggestions[0].pattern,
                        sizeof(out->suggestion_a) - 1);
                out->suggestion_count++;
            }
            if (eval.suggestion_count > 1 && out->suggestion_count == 1) {
                strncpy(out->suggestion_b, eval.suggestions[1].pattern,
                        sizeof(out->suggestion_b) - 1);
                out->suggestion_count++;
            }
        }

        if (!sr->matches && out->deny_reason == NULL) {
            out->deny_reason = sr->reject_reason[0] ? sr->reject_reason : sr->command;
            out->attention_index = out->subcmd_count - 1;
        }

        /* Step 5: Apply stop mode */
        if (!sr->matches && gate->stop_mode == SG_STOP_FIRST_FAIL) break;
        if (sr->matches && gate->stop_mode == SG_STOP_FIRST_PASS) break;
    }

    if (out->subcmd_count == 0) {
        out->verdict = SG_VERDICT_ALLOW;
        return SG_OK;
    }

    bool all_match = true;
    for (uint32_t i = 0; i < out->subcmd_count; i++) {
        if (!out->subcmds[i].matches) { all_match = false; break; }
    }

    out->verdict = all_match ? SG_VERDICT_ALLOW : SG_VERDICT_DENY;
    return SG_OK;
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
