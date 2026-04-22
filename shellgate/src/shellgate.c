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
    st_policy_t     *deny_policy;

    char     cwd[512];
    uint32_t reject_mask;
    sg_stop_mode_t stop_mode;
    bool     suggestions;

    sg_expand_var_fn  expand_var_fn;
    void             *expand_var_ctx;
    sg_expand_glob_fn expand_glob_fn;
    void             *expand_glob_ctx;

    bool                  viol_enabled;
    sg_violation_config_t viol_config;
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

    g->deny_policy = st_policy_new(g->pctx);
    if (!g->deny_policy) { st_policy_free(g->policy); st_policy_ctx_free(g->pctx); free(g); return NULL; }

    sg_strlcpy(g->cwd, ".", sizeof(g->cwd));
    g->reject_mask = SG_REJECT_MASK_DEFAULT;
    g->stop_mode = SG_STOP_FIRST_FAIL;
    g->suggestions = true;

    return g;
}

void sg_gate_free(sg_gate_t *gate)
{
    if (!gate) return;
    if (gate->policy)       st_policy_free(gate->policy);
    if (gate->deny_policy)  st_policy_free(gate->deny_policy);
    if (gate->pctx)         st_policy_ctx_free(gate->pctx);
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

sg_error_t sg_gate_set_violation_config(sg_gate_t *gate,
                                          const sg_violation_config_t *config)
{
    if (!gate || !config) return SG_ERR_INVALID;
    gate->viol_enabled = true;
    gate->viol_config = *config;
    return SG_OK;
}

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

sg_error_t sg_gate_load_policy(sg_gate_t *gate, const char *path)
{
    if (!gate || !path) return SG_ERR_INVALID;
    st_error_t err = st_policy_load(gate->policy, path, /*clear_first=*/false);
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

sg_error_t sg_gate_add_deny_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_add(gate->deny_policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

sg_error_t sg_gate_remove_deny_rule(sg_gate_t *gate, const char *pattern)
{
    if (!gate || !pattern) return SG_ERR_INVALID;
    st_error_t err = st_policy_remove(gate->deny_policy, pattern);
    if (err != ST_OK) return SG_ERR_INVALID;
    return SG_OK;
}

uint32_t sg_gate_deny_rule_count(const sg_gate_t *gate)
{
    if (!gate) return 0;
    return (uint32_t)st_policy_count(gate->deny_policy);
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
 * VIOLATION DEFAULT CONFIG
 * ============================================================ */

void sg_violation_config_default(sg_violation_config_t *cfg)
{
    static const char *def_write_paths[] = {
        "/etc/", "/boot/", "/root/", "/lib/", "/usr/lib/",
        "/sbin/", "/bin/", "/var/lib/", "/proc/", "/sys/",
    };
    static const char *def_dirs[] = {
        "/etc", "/boot", "/root", "/lib", "/usr/lib",
        "/sbin", "/bin", "/var/lib", "/proc", "/sys",
        "/usr", "/var", "/opt",
    };
    static const char *def_env[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "IFS",
        "LD_DEBUG", "ENV", "BASH_ENV",
    };
    static const char *def_cmds[] = {
        "sudo", "su", "ssh", "scp", "crontab", "passwd",
    };
    static const char *def_reads[] = {
        "/etc/shadow", "/etc/ssh/", "/etc/gshadow",
        "/root/.ssh/", "/etc/ca-certificates",
    };

    memset(cfg, 0, sizeof(*cfg));

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_write_paths)/sizeof(def_write_paths[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_write_paths[cfg->sensitive_write_path_count++] = def_write_paths[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_dirs)/sizeof(def_dirs[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_dirs[cfg->sensitive_dir_count++] = def_dirs[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_env)/sizeof(def_env[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->sensitive_env_names[cfg->sensitive_env_name_count++] = def_env[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_cmds)/sizeof(def_cmds[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->sensitive_cmd_names[cfg->sensitive_cmd_name_count++] = def_cmds[i];

    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_reads)/sizeof(def_reads[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_read_paths[cfg->sensitive_read_path_count++] = def_reads[i];

    cfg->redirect_fanout_threshold = 3;

    static const char *def_downloads[] = { "curl", "wget" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_downloads)/sizeof(def_downloads[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->download_cmds[cfg->download_cmd_count++] = def_downloads[i];

    static const char *def_spawns[] = { "sh", "bash", "env", "perl", "python", "ruby", "node" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_spawns)/sizeof(def_spawns[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->shell_spawn_cmds[cfg->shell_spawn_cmd_count++] = def_spawns[i];

    static const char *def_perms[] = { "chmod", "chown", "chgrp" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_perms)/sizeof(def_perms[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->perm_mod_cmds[cfg->perm_mod_cmd_count++] = def_perms[i];

    static const char *def_secrets[] = {
        "/.ssh/", ".env", "/.aws/", "/.kube/",
        "/.npmrc", "/.netrc", "/.pgpass",
        "/.gitconfig", "/.git-credentials",
        "/.docker/", "/.vault-token", "/.gnupg/",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_secrets)/sizeof(def_secrets[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->sensitive_secret_paths[cfg->sensitive_secret_path_count++] = def_secrets[i];

    static const char *def_readcmds[] = {
        "cat", "head", "tail", "less", "more",
        "base64", "xxd", "od", "strings", "hexdump",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_readcmds)/sizeof(def_readcmds[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->file_reading_cmds[cfg->file_reading_cmd_count++] = def_readcmds[i];

    static const char *def_uploads[] = { "curl", "wget", "scp", "rsync" };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_uploads)/sizeof(def_uploads[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->upload_cmds[cfg->upload_cmd_count++] = def_uploads[i];

    static const char *def_listeners[] = {
        "nc", "ncat", "netcat", "socat",
        "ngrok", "cloudflared",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_listeners)/sizeof(def_listeners[0]))
                        && i < SG_VIOL_MAX_NAMES; i++)
        cfg->listener_cmds[cfg->listener_cmd_count++] = def_listeners[i];

    static const char *def_profiles[] = {
        "/.bashrc", "/.profile", "/.zshrc",
        "/.bash_profile", "/.ssh/authorized_keys", "/.ssh/config",
    };
    for (uint32_t i = 0; i < (uint32_t)(sizeof(def_profiles)/sizeof(def_profiles[0]))
                        && i < SG_VIOL_MAX_PATHS; i++)
        cfg->shell_profile_paths[cfg->shell_profile_path_count++] = def_profiles[i];
}

/* ============================================================
 * VIOLATION SCANNING HELPERS
 * ============================================================ */

static bool path_has_prefix(const char *path, uint32_t path_len,
                              const char *prefix)
{
    size_t plen = strlen(prefix);
    if (path_len < plen) return false;
    return memcmp(path, prefix, plen) == 0;
}

static bool path_contains(const char *path, uint32_t path_len,
                            const char *needle)
{
    size_t nlen = strlen(needle);
    if (path_len < nlen) return false;
    for (uint32_t i = 0; i <= path_len - nlen; i++) {
        if (memcmp(path + i, needle, nlen) == 0)
            return true;
    }
    return false;
}

static bool tok_equals(const char *tok, uint32_t tok_len, const char *str)
{
    size_t slen = strlen(str);
    return tok_len == slen && memcmp(tok, str, slen) == 0;
}

static bool emit_violation(sg_violation_t *viol, uint32_t *count,
                            uint32_t max, uint32_t type, uint32_t severity,
                            uint32_t cmd_idx, const char *desc, const char *detail)
{
    if (*count >= max) return false;
    sg_violation_t *v = &viol[(*count)++];
    v->type           = type;
    v->severity       = severity;
    v->cmd_node_index = cmd_idx;
    v->description    = desc;
    v->detail         = detail;
    return true;
}

static bool has_control_flow_path(const shell_dep_graph_t *g,
                                    uint32_t from, uint32_t to)
{
    bool visited[SHELL_DEP_MAX_NODES];
    memset(visited, 0, sizeof(visited));
    uint32_t stack[SHELL_DEP_MAX_NODES];
    uint32_t sp = 0;
    stack[sp++] = from;
    visited[from] = true;

    while (sp > 0) {
        uint32_t cur = stack[--sp];
        if (cur == to) return true;
        for (uint32_t i = 0; i < g->edge_count; i++) {
            const shell_dep_edge_t *e = &g->edges[i];
            if (e->from != cur) continue;
            if (e->type != SHELL_EDGE_SEQ && e->type != SHELL_EDGE_AND &&
                e->type != SHELL_EDGE_OR  && e->type != SHELL_EDGE_PIPE)
                continue;
            if (!visited[e->to]) {
                visited[e->to] = true;
                stack[sp++] = e->to;
            }
        }
    }
    return false;
}

/* ============================================================
 * VIOLATION SCANNING ENGINE
 * ============================================================ */

static void sg_violation_scan(const shell_dep_graph_t *graph,
                               const sg_violation_config_t *cfg,
                               buf_writer_t *bw,
                               sg_violation_t *violations, uint32_t max_violations,
                               uint32_t *violation_count, uint32_t *violation_flags,
                               uint32_t *node_viols,
                               uint32_t *cmd_write_count, uint32_t *cmd_read_count,
                               uint32_t *cmd_env_count)
{
    *violation_count = 0;
    *violation_flags = 0;

    for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
        const shell_dep_edge_t *e = &graph->edges[ei];
        const shell_dep_node_t *from_node = &graph->nodes[e->from];
        const shell_dep_node_t *to_node   = &graph->nodes[e->to];

        /* --- Per-node edge counters --- */
        if (from_node->type == SHELL_NODE_CMD) {
            if (e->type == SHELL_EDGE_WRITE || e->type == SHELL_EDGE_APPEND)
                cmd_write_count[e->from]++;
        }
        if (to_node->type == SHELL_NODE_CMD) {
            if (e->type == SHELL_EDGE_READ)
                cmd_read_count[e->to]++;
            if (e->type == SHELL_EDGE_ENV)
                cmd_env_count[e->to]++;
        }

        /* --- SG_VIOL_WRITE_SENSITIVE --- */
        if ((e->type == SHELL_EDGE_WRITE || e->type == SHELL_EDGE_APPEND)
            && to_node->type == SHELL_NODE_DOC && to_node->doc.kind == SHELL_DOC_FILE) {
            for (uint32_t p = 0; p < cfg->sensitive_write_path_count; p++) {
                if (path_has_prefix(to_node->doc.path, to_node->doc.path_len,
                                     cfg->sensitive_write_paths[p])) {
                    const char *desc = bw_printf(bw, "writes to sensitive path");
                    const char *det  = bw_copy(bw, to_node->doc.path, to_node->doc.path_len);
                    emit_violation(violations, violation_count, max_violations,
                                   SG_VIOL_WRITE_SENSITIVE, 80, e->from, desc, det);
                    node_viols[e->from] |= SG_VIOL_WRITE_SENSITIVE;
                    *violation_flags |= SG_VIOL_WRITE_SENSITIVE;
                    break;
                }
            }
        }

        /* --- SG_VIOL_ENV_PRIVILEGED --- */
        if (e->type == SHELL_EDGE_ENV
            && from_node->type == SHELL_NODE_DOC && from_node->doc.kind == SHELL_DOC_ENVVAR
            && to_node->type == SHELL_NODE_CMD && to_node->cmd.token_count > 0) {

            bool sensitive_env = false;
            for (uint32_t n = 0; n < cfg->sensitive_env_name_count; n++) {
                if (tok_equals(from_node->doc.name, from_node->doc.name_len,
                               cfg->sensitive_env_names[n])) {
                    sensitive_env = true;
                    break;
                }
            }
            if (sensitive_env) {
                const char *cmd0 = to_node->cmd.tokens[0];
                uint32_t cmd0_len = to_node->cmd.token_lens[0];
                for (uint32_t c = 0; c < cfg->sensitive_cmd_name_count; c++) {
                    if (tok_equals(cmd0, cmd0_len, cfg->sensitive_cmd_names[c])) {
                        const char *desc = bw_printf(bw, "sensitive env before privileged cmd");
                        const char *det  = bw_printf(bw, "%.*s before %.*s",
                                                      (int)from_node->doc.name_len, from_node->doc.name,
                                                      (int)cmd0_len, cmd0);
                        emit_violation(violations, violation_count, max_violations,
                                       SG_VIOL_ENV_PRIVILEGED, 90, e->to, desc, det);
                        node_viols[e->to] |= SG_VIOL_ENV_PRIVILEGED;
                        *violation_flags |= SG_VIOL_ENV_PRIVILEGED;
                        break;
                    }
                }
            }
        }

        /* --- SG_VIOL_SUBST_SENSITIVE --- */
        if (e->type == SHELL_EDGE_SUBST) {
            uint32_t sub_cmd = e->from;
            for (uint32_t ej = 0; ej < graph->edge_count; ej++) {
                const shell_dep_edge_t *re = &graph->edges[ej];
                if (re->to != sub_cmd) continue;
                if (re->type != SHELL_EDGE_READ && re->type != SHELL_EDGE_ARG) continue;
                const shell_dep_node_t *doc = &graph->nodes[re->from];
                if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
                for (uint32_t p = 0; p < cfg->sensitive_read_path_count; p++) {
                    if (path_has_prefix(doc->doc.path, doc->doc.path_len,
                                         cfg->sensitive_read_paths[p])) {
                        const char *desc = bw_printf(bw, "subshell reads sensitive file");
                        const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                        emit_violation(violations, violation_count, max_violations,
                                       SG_VIOL_SUBST_SENSITIVE, 85, e->to, desc, det);
                        node_viols[e->to] |= SG_VIOL_SUBST_SENSITIVE;
                        *violation_flags |= SG_VIOL_SUBST_SENSITIVE;
                        break;
                    }
                }
            }
        }
    }

    /* --- SG_VIOL_REMOVE_SYSTEM --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;
        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];
        if (!tok_equals(cmd0, cmd0_len, "rm") && !tok_equals(cmd0, cmd0_len, "rmdir"))
            continue;
        for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni || e->type != SHELL_EDGE_ARG) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            for (uint32_t d = 0; d < cfg->sensitive_dir_count; d++) {
                if (path_has_prefix(doc->doc.path, doc->doc.path_len,
                                     cfg->sensitive_dirs[d])) {
                    const char *desc = bw_printf(bw, "removal of system directory");
                    const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                    emit_violation(violations, violation_count, max_violations,
                                   SG_VIOL_REMOVE_SYSTEM, 95, ni, desc, det);
                    node_viols[ni] |= SG_VIOL_REMOVE_SYSTEM;
                    *violation_flags |= SG_VIOL_REMOVE_SYSTEM;
                    break;
                }
            }
        }
    }

    /* --- SG_VIOL_WRITE_THEN_READ --- */
    for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
        const shell_dep_edge_t *e1 = &graph->edges[ei];
        if (e1->type != SHELL_EDGE_WRITE && e1->type != SHELL_EDGE_APPEND) continue;
        const shell_dep_node_t *f1 = &graph->nodes[e1->to];
        if (f1->type != SHELL_NODE_DOC || f1->doc.kind != SHELL_DOC_FILE) continue;

        for (uint32_t ej = 0; ej < graph->edge_count; ej++) {
            const shell_dep_edge_t *e2 = &graph->edges[ej];
            if (e2->type != SHELL_EDGE_READ) continue;
            const shell_dep_node_t *f2 = &graph->nodes[e2->from];
            if (f2->type != SHELL_NODE_DOC || f2->doc.kind != SHELL_DOC_FILE) continue;
            if (f1->doc.path_len != f2->doc.path_len) continue;
            if (memcmp(f1->doc.path, f2->doc.path, f1->doc.path_len) != 0) continue;

            if (has_control_flow_path(graph, e1->from, e2->to)) {
                const char *desc = bw_printf(bw, "write then read of same file");
                const char *det  = bw_copy(bw, f1->doc.path, f1->doc.path_len);
                emit_violation(violations, violation_count, max_violations,
                               SG_VIOL_WRITE_THEN_READ, 60, e2->to, desc, det);
                node_viols[e2->to] |= SG_VIOL_WRITE_THEN_READ;
                *violation_flags |= SG_VIOL_WRITE_THEN_READ;
                break;
            }
        }
    }

    /* --- SG_VIOL_REDIRECT_FANOUT --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        if (graph->nodes[ni].type != SHELL_NODE_CMD) continue;
        if (cmd_write_count[ni] > cfg->redirect_fanout_threshold) {
            const char *desc = bw_printf(bw, "excessive redirect fan-out (%u targets)",
                                          cmd_write_count[ni]);
            emit_violation(violations, violation_count, max_violations,
                           SG_VIOL_REDIRECT_FANOUT, 40, ni, desc, NULL);
            node_viols[ni] |= SG_VIOL_REDIRECT_FANOUT;
            *violation_flags |= SG_VIOL_REDIRECT_FANOUT;
        }
    }

    /* --- SG_VIOL_NET_DOWNLOAD_EXEC --- */
    for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
        const shell_dep_edge_t *e = &graph->edges[ei];
        if (e->type != SHELL_EDGE_PIPE) continue;
        const shell_dep_node_t *src = &graph->nodes[e->from];
        const shell_dep_node_t *dst = &graph->nodes[e->to];
        if (src->type != SHELL_NODE_CMD || dst->type != SHELL_NODE_CMD) continue;
        if (src->cmd.token_count == 0 || dst->cmd.token_count == 0) continue;

        bool is_download = false;
        for (uint32_t c = 0; c < cfg->download_cmd_count; c++) {
            if (tok_equals(src->cmd.tokens[0], src->cmd.token_lens[0],
                           cfg->download_cmds[c])) {
                is_download = true;
                break;
            }
        }
        if (!is_download) continue;

        bool is_spawn = false;
        for (uint32_t c = 0; c < cfg->shell_spawn_cmd_count; c++) {
            if (tok_equals(dst->cmd.tokens[0], dst->cmd.token_lens[0],
                           cfg->shell_spawn_cmds[c])) {
                is_spawn = true;
                break;
            }
        }
        if (!is_spawn) continue;

        const char *desc = bw_printf(bw, "download piped into shell executor");
        const char *det  = bw_printf(bw, "%.*s | %.*s",
                                      (int)src->cmd.token_lens[0], src->cmd.tokens[0],
                                      (int)dst->cmd.token_lens[0], dst->cmd.tokens[0]);
        emit_violation(violations, violation_count, max_violations,
                       SG_VIOL_NET_DOWNLOAD_EXEC, 95, e->to, desc, det);
        node_viols[e->to] |= SG_VIOL_NET_DOWNLOAD_EXEC;
        *violation_flags |= SG_VIOL_NET_DOWNLOAD_EXEC;
    }

    /* --- SG_VIOL_PERM_SYSTEM --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

        bool is_perm = false;
        for (uint32_t c = 0; c < cfg->perm_mod_cmd_count; c++) {
            if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                           cfg->perm_mod_cmds[c])) {
                is_perm = true;
                break;
            }
        }
        if (!is_perm) continue;

        bool has_recursive = false;
        for (uint32_t t = 1; t < node->cmd.token_count; t++) {
            if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-R")) {
                has_recursive = true;
                break;
            }
        }
        if (!has_recursive) continue;

        for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni || e->type != SHELL_EDGE_ARG) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            for (uint32_t d = 0; d < cfg->sensitive_dir_count; d++) {
                if (path_has_prefix(doc->doc.path, doc->doc.path_len,
                                    cfg->sensitive_dirs[d])) {
                    const char *desc = bw_printf(bw, "recursive permission change on system dir");
                    const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                    emit_violation(violations, violation_count, max_violations,
                                   SG_VIOL_PERM_SYSTEM, 85, ni, desc, det);
                    node_viols[ni] |= SG_VIOL_PERM_SYSTEM;
                    *violation_flags |= SG_VIOL_PERM_SYSTEM;
                    break;
                }
            }
        }
    }

    /* --- SG_VIOL_SHELL_ESCALATION --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;

        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];
        if (!tok_equals(cmd0, cmd0_len, "sudo") && !tok_equals(cmd0, cmd0_len, "su"))
            continue;

        bool is_spawn = false;
        for (uint32_t c = 0; c < cfg->shell_spawn_cmd_count; c++) {
            if (tok_equals(node->cmd.tokens[1], node->cmd.token_lens[1],
                           cfg->shell_spawn_cmds[c])) {
                is_spawn = true;
                break;
            }
        }
        if (!is_spawn) continue;

        const char *desc = bw_printf(bw, "privileged shell spawn");
        const char *det  = bw_printf(bw, "%.*s %.*s",
                                      (int)cmd0_len, cmd0,
                                      (int)node->cmd.token_lens[1], node->cmd.tokens[1]);
        emit_violation(violations, violation_count, max_violations,
                       SG_VIOL_SHELL_ESCALATION, 90, ni, desc, det);
        node_viols[ni] |= SG_VIOL_SHELL_ESCALATION;
        *violation_flags |= SG_VIOL_SHELL_ESCALATION;
    }

    /* --- SG_VIOL_SUDO_REDIRECT --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];
        if (!tok_equals(cmd0, cmd0_len, "sudo") && !tok_equals(cmd0, cmd0_len, "su"))
            continue;

        bool has_redirect = false;
        const char *target_path = NULL;
        uint32_t target_path_len = 0;
        for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni) continue;
            if (e->type != SHELL_EDGE_WRITE && e->type != SHELL_EDGE_APPEND) continue;
            has_redirect = true;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type == SHELL_NODE_DOC && doc->doc.kind == SHELL_DOC_FILE) {
                target_path = doc->doc.path;
                target_path_len = doc->doc.path_len;
            }
            break;
        }
        if (!has_redirect) continue;

        const char *desc = bw_printf(bw, "sudo with redirect");
        const char *det  = target_path
            ? bw_copy(bw, target_path, target_path_len)
            : bw_printf(bw, "%.*s", (int)cmd0_len, cmd0);
        emit_violation(violations, violation_count, max_violations,
                       SG_VIOL_SUDO_REDIRECT, 80, ni, desc, det);
        node_viols[ni] |= SG_VIOL_SUDO_REDIRECT;
        *violation_flags |= SG_VIOL_SUDO_REDIRECT;
    }

    /* --- SG_VIOL_READ_SECRETS --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

        bool is_reader = false;
        for (uint32_t c = 0; c < cfg->file_reading_cmd_count; c++) {
            if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                           cfg->file_reading_cmds[c])) {
                is_reader = true;
                break;
            }
        }
        if (!is_reader) continue;

        for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni || e->type != SHELL_EDGE_ARG) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            for (uint32_t p = 0; p < cfg->sensitive_secret_path_count; p++) {
                if (path_contains(doc->doc.path, doc->doc.path_len,
                                  cfg->sensitive_secret_paths[p])) {
                    const char *desc = bw_printf(bw, "reading secret file");
                    const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                    emit_violation(violations, violation_count, max_violations,
                                   SG_VIOL_READ_SECRETS, 75, ni, desc, det);
                    node_viols[ni] |= SG_VIOL_READ_SECRETS;
                    *violation_flags |= SG_VIOL_READ_SECRETS;
                    break;
                }
            }
        }
    }

    /* --- SG_VIOL_NET_UPLOAD --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;

        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];

        bool is_upload = false;
        for (uint32_t c = 0; c < cfg->upload_cmd_count; c++) {
            if (tok_equals(cmd0, cmd0_len, cfg->upload_cmds[c])) {
                is_upload = true;
                break;
            }
        }
        if (!is_upload) continue;

        bool has_upload_flag = false;
        bool is_scp_upload = false;
        bool is_rsync_upload = false;

        if (tok_equals(cmd0, cmd0_len, "curl")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                const char *tok = node->cmd.tokens[t];
                uint32_t tlen = node->cmd.token_lens[t];
                if (tok_equals(tok, tlen, "-d") ||
                    tok_equals(tok, tlen, "--data") ||
                    tok_equals(tok, tlen, "--data-binary") ||
                    tok_equals(tok, tlen, "--data-raw") ||
                    tok_equals(tok, tlen, "--data-urlencode") ||
                    tok_equals(tok, tlen, "-F") ||
                    tok_equals(tok, tlen, "--form") ||
                    tok_equals(tok, tlen, "-T") ||
                    tok_equals(tok, tlen, "--upload-file")) {
                    has_upload_flag = true;
                    break;
                }
                if ((tlen >= 3 && tok[0] == '-' && tok[1] == 'd' && tok[2] == '@') ||
                    (tlen >= 3 && tok[0] == '-' && tok[1] == 'F' && tok[2] == '=') ||
                    (tlen >= 3 && tok[0] == '-' && tok[1] == 'T' && tok[2] != '\0')) {
                    has_upload_flag = true;
                    break;
                }
            }
        } else if (tok_equals(cmd0, cmd0_len, "wget")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t],
                               "--post-file") ||
                    tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t],
                               "--post-data")) {
                    has_upload_flag = true;
                    break;
                }
            }
        } else if (tok_equals(cmd0, cmd0_len, "scp")) {
            const char *last = node->cmd.tokens[node->cmd.token_count - 1];
            uint32_t last_len = node->cmd.token_lens[node->cmd.token_count - 1];
            for (uint32_t c = 0; c < last_len; c++) {
                if (last[c] == ':') {
                    is_scp_upload = true;
                    break;
                }
            }
        } else if (tok_equals(cmd0, cmd0_len, "rsync")) {
            const char *last = node->cmd.tokens[node->cmd.token_count - 1];
            uint32_t last_len = node->cmd.token_lens[node->cmd.token_count - 1];
            for (uint32_t c = 0; c < last_len; c++) {
                if (last[c] == ':') {
                    is_rsync_upload = true;
                    break;
                }
            }
        }

        if (!has_upload_flag && !is_scp_upload && !is_rsync_upload) continue;

        const char *desc = bw_printf(bw, "network file upload");
        const char *det  = bw_printf(bw, "%.*s", (int)cmd0_len, cmd0);
        emit_violation(violations, violation_count, max_violations,
                       SG_VIOL_NET_UPLOAD, 85, ni, desc, det);
        node_viols[ni] |= SG_VIOL_NET_UPLOAD;
        *violation_flags |= SG_VIOL_NET_UPLOAD;
    }

    /* --- SG_VIOL_NET_LISTENER --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;

        bool is_listener_cmd = false;
        for (uint32_t c = 0; c < cfg->listener_cmd_count; c++) {
            if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0],
                           cfg->listener_cmds[c])) {
                is_listener_cmd = true;
                break;
            }
        }
        if (!is_listener_cmd) continue;

        bool has_listen = false;
        if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "nc") ||
            tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "ncat") ||
            tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "netcat")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-l") ||
                    tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "--listen")) {
                    has_listen = true;
                    break;
                }
            }
        } else if (tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "socat")) {
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                for (uint32_t c = 0; c < node->cmd.token_lens[t]; c++) {
                    if (node->cmd.tokens[t][c] == 'L' ||
                        node->cmd.tokens[t][c] == 'l') {
                        uint32_t remaining = node->cmd.token_lens[t] - c;
                        if (remaining >= 6 &&
                            (memcmp(node->cmd.tokens[t] + c, "LISTEN", 6) == 0 ||
                             memcmp(node->cmd.tokens[t] + c, "listen", 6) == 0)) {
                            has_listen = true;
                            break;
                        }
                    }
                }
                if (has_listen) break;
            }
        } else {
            has_listen = true;
        }

        if (!has_listen) continue;

        const char *desc = bw_printf(bw, "starting network listener");
        const char *det  = bw_printf(bw, "%.*s", (int)node->cmd.token_lens[0],
                                      node->cmd.tokens[0]);
        emit_violation(violations, violation_count, max_violations,
                       SG_VIOL_NET_LISTENER, 80, ni, desc, det);
        node_viols[ni] |= SG_VIOL_NET_LISTENER;
        *violation_flags |= SG_VIOL_NET_LISTENER;
    }

    /* --- SG_VIOL_SHELL_OBFUSCATION --- */
    for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
        const shell_dep_edge_t *e = &graph->edges[ei];
        if (e->type != SHELL_EDGE_PIPE) continue;
        const shell_dep_node_t *src = &graph->nodes[e->from];
        const shell_dep_node_t *dst = &graph->nodes[e->to];
        if (src->type != SHELL_NODE_CMD || dst->type != SHELL_NODE_CMD) continue;
        if (src->cmd.token_count == 0 || dst->cmd.token_count == 0) continue;

        bool is_decoder = false;
        if (tok_equals(src->cmd.tokens[0], src->cmd.token_lens[0], "base64")) {
            for (uint32_t t = 1; t < src->cmd.token_count; t++) {
                if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "-d") ||
                    tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "--decode")) {
                    is_decoder = true;
                    break;
                }
            }
        }
        if (!is_decoder && tok_equals(src->cmd.tokens[0], src->cmd.token_lens[0], "openssl")) {
            bool has_enc = false, has_d = false;
            for (uint32_t t = 1; t < src->cmd.token_count; t++) {
                if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "enc"))
                    has_enc = true;
                if (tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "-d") ||
                    tok_equals(src->cmd.tokens[t], src->cmd.token_lens[t], "--decode"))
                    has_d = true;
            }
            if (has_enc && has_d) is_decoder = true;
        }
        if (!is_decoder) continue;

        bool is_spawn = false;
        for (uint32_t c = 0; c < cfg->shell_spawn_cmd_count; c++) {
            if (tok_equals(dst->cmd.tokens[0], dst->cmd.token_lens[0],
                           cfg->shell_spawn_cmds[c])) {
                is_spawn = true;
                break;
            }
        }
        if (!is_spawn) continue;

        const char *desc = bw_printf(bw, "decoded payload piped to shell");
        const char *det  = bw_printf(bw, "%.*s | %.*s",
                                      (int)src->cmd.token_lens[0], src->cmd.tokens[0],
                                      (int)dst->cmd.token_lens[0], dst->cmd.tokens[0]);
        emit_violation(violations, violation_count, max_violations,
                       SG_VIOL_SHELL_OBFUSCATION, 90, e->to, desc, det);
        node_viols[e->to] |= SG_VIOL_SHELL_OBFUSCATION;
        *violation_flags |= SG_VIOL_SHELL_OBFUSCATION;
    }

    /* --- SG_VIOL_GIT_DESTRUCTIVE --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count < 2) continue;
        if (!tok_equals(node->cmd.tokens[0], node->cmd.token_lens[0], "git"))
            continue;

        const char *subcmd = node->cmd.tokens[1];
        uint32_t subcmd_len = node->cmd.token_lens[1];

        bool destructive = false;
        if (tok_equals(subcmd, subcmd_len, "push")) {
            for (uint32_t t = 2; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "--force") ||
                    tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-f")) {
                    destructive = true;
                    break;
                }
            }
        } else if (tok_equals(subcmd, subcmd_len, "clean")) {
            for (uint32_t t = 2; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-x") ||
                    tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-fdx") ||
                    tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-fx")) {
                    destructive = true;
                    break;
                }
            }
        } else if (tok_equals(subcmd, subcmd_len, "filter-branch")) {
            destructive = true;
        }

        if (!destructive) continue;

        const char *desc = bw_printf(bw, "destructive git operation");
        const char *det  = bw_printf(bw, "git %.*s", (int)subcmd_len, subcmd);
        emit_violation(violations, violation_count, max_violations,
                       SG_VIOL_GIT_DESTRUCTIVE, 70, ni, desc, det);
        node_viols[ni] |= SG_VIOL_GIT_DESTRUCTIVE;
        *violation_flags |= SG_VIOL_GIT_DESTRUCTIVE;
    }

    /* --- SG_VIOL_PERSISTENCE --- */
    for (uint32_t ni = 0; ni < graph->node_count; ni++) {
        const shell_dep_node_t *node = &graph->nodes[ni];
        if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0) continue;

        const char *cmd0 = node->cmd.tokens[0];
        uint32_t cmd0_len = node->cmd.token_lens[0];

        if (tok_equals(cmd0, cmd0_len, "crontab")) {
            bool is_list = false;
            for (uint32_t t = 1; t < node->cmd.token_count; t++) {
                if (tok_equals(node->cmd.tokens[t], node->cmd.token_lens[t], "-l")) {
                    is_list = true;
                    break;
                }
            }
            if (!is_list) {
                const char *desc = bw_printf(bw, "crontab modification");
                const char *det  = bw_printf(bw, "crontab");
                emit_violation(violations, violation_count, max_violations,
                               SG_VIOL_PERSISTENCE, 75, ni, desc, det);
                node_viols[ni] |= SG_VIOL_PERSISTENCE;
                *violation_flags |= SG_VIOL_PERSISTENCE;
            }
            continue;
        }

        for (uint32_t ei = 0; ei < graph->edge_count; ei++) {
            const shell_dep_edge_t *e = &graph->edges[ei];
            if (e->from != ni) continue;
            if (e->type != SHELL_EDGE_WRITE && e->type != SHELL_EDGE_APPEND) continue;
            const shell_dep_node_t *doc = &graph->nodes[e->to];
            if (doc->type != SHELL_NODE_DOC || doc->doc.kind != SHELL_DOC_FILE) continue;
            for (uint32_t p = 0; p < cfg->shell_profile_path_count; p++) {
                if (path_contains(doc->doc.path, doc->doc.path_len,
                                  cfg->shell_profile_paths[p])) {
                    const char *desc = bw_printf(bw, "writing to shell profile/ssh config");
                    const char *det  = bw_copy(bw, doc->doc.path, doc->doc.path_len);
                    emit_violation(violations, violation_count, max_violations,
                                   SG_VIOL_PERSISTENCE, 80, ni, desc, det);
                    node_viols[ni] |= SG_VIOL_PERSISTENCE;
                    *violation_flags |= SG_VIOL_PERSISTENCE;
                    break;
                }
            }
        }
    }
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
    memset(&graph, 0, sizeof(graph));
    graph.buf.data = buf;
    graph.buf.capacity = buf_size;
    shell_dep_error_t derr = shell_parse_depgraph(cmd, cmd_len, gate->cwd, NULL, &graph);
    if (derr != SHELL_DEP_OK) {
        out->verdict = SG_VERDICT_REJECT;
        out->deny_reason = bw_copy(&bw, "depgraph error", 14);
        out->subcmd_count = 1;
        out->subcmds[0].verdict = SG_VERDICT_REJECT;
        out->subcmds[0].reject_reason = out->deny_reason;
        return SG_OK;
    }

    /* Step 3.5: Violation scan on the depgraph */
    uint32_t node_viols[SHELL_DEP_MAX_NODES];
    uint32_t cmd_write_count[SHELL_DEP_MAX_NODES];
    uint32_t cmd_read_count[SHELL_DEP_MAX_NODES];
    uint32_t cmd_env_count[SHELL_DEP_MAX_NODES];
    memset(node_viols, 0, sizeof(node_viols));
    memset(cmd_write_count, 0, sizeof(cmd_write_count));
    memset(cmd_read_count, 0, sizeof(cmd_read_count));
    memset(cmd_env_count, 0, sizeof(cmd_env_count));

    if (gate->viol_enabled) {
        sg_violation_scan(&graph, &gate->viol_config, &bw,
                          out->violations, SG_MAX_VIOLATIONS,
                          &out->violation_count, &out->violation_flags,
                          node_viols, cmd_write_count, cmd_read_count, cmd_env_count);
        out->has_violations = (out->violation_count > 0);
    }

    /* Step 4: Walk CMD nodes, evaluate each against policy */
    for (uint32_t ni = 0; ni < graph.node_count && out->subcmd_count < SG_MAX_SUBCMD_RESULTS; ni++) {
        const shell_dep_node_t *node = &graph.nodes[ni];
        if (node->type != SHELL_NODE_CMD) continue;
        if (node->cmd.token_count == 0) continue;

        sg_subcmd_result_t *sr = &out->subcmds[out->subcmd_count++];

        sr->command = build_cmd_string(&node->cmd, &bw, gate);

        sr->write_count    = cmd_write_count[ni];
        sr->read_count     = cmd_read_count[ni];
        sr->env_count      = cmd_env_count[ni];
        sr->violation_flags = node_viols[ni];

        const char *cmd_str = sr->command ? sr->command : "";

        /* Check deny policy first */
        st_eval_result_t deny_eval;
        st_error_t deny_err = st_policy_eval(gate->deny_policy, cmd_str,
                                              gate->suggestions ? &deny_eval : NULL);
        if (deny_err == ST_OK && deny_eval.matches) {
            sr->matches = true;
            sr->verdict = SG_VERDICT_DENY;
            sr->reject_reason = bw_copy(&bw, "deny policy match", 17);
        } else {
            /* Check allow policy */
            st_eval_result_t eval;
            st_error_t eval_err = st_policy_eval(gate->policy, cmd_str,
                                                  gate->suggestions ? &eval : NULL);
            if (eval_err != ST_OK) {
                sr->matches = false;
                sr->verdict = SG_VERDICT_UNDETERMINED;
            } else if (eval.matches) {
                sr->matches = true;
                sr->verdict = SG_VERDICT_ALLOW;
            } else {
                sr->matches = false;
                sr->verdict = SG_VERDICT_UNDETERMINED;

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

            /* Generate deny suggestions from deny policy */
            if (deny_err == ST_OK && out->deny_suggestion_count == 0) {
                if (deny_eval.suggestion_count > 0) {
                    out->deny_suggestions[0] = bw_copy(&bw,
                        deny_eval.suggestions[0].pattern,
                        strlen(deny_eval.suggestions[0].pattern));
                    if (out->deny_suggestions[0]) out->deny_suggestion_count++;
                }
                if (deny_eval.suggestion_count > 1 && out->deny_suggestion_count == 1) {
                    out->deny_suggestions[1] = bw_copy(&bw,
                        deny_eval.suggestions[1].pattern,
                        strlen(deny_eval.suggestions[1].pattern));
                    if (out->deny_suggestions[1]) out->deny_suggestion_count++;
                }
            }
        }

    if (sr->verdict == SG_VERDICT_REJECT || sr->verdict == SG_VERDICT_DENY) {
            if (out->deny_reason == NULL) {
                out->deny_reason = sr->reject_reason ? sr->reject_reason : sr->command;
                out->attention_index = out->subcmd_count - 1;
            }
        }

        if (!sr->matches && gate->stop_mode == SG_STOP_FIRST_FAIL) break;
        if (sr->matches && gate->stop_mode == SG_STOP_FIRST_PASS) break;
    }

    if (out->subcmd_count == 0) {
        out->verdict = SG_VERDICT_ALLOW;
        return bw.overflow ? SG_ERR_TRUNC : SG_OK;
    }

    bool all_allow = true;
    bool any_reject = false;
    bool any_deny = false;
    for (uint32_t i = 0; i < out->subcmd_count; i++) {
        if (out->subcmds[i].verdict != SG_VERDICT_ALLOW) all_allow = false;
        if (out->subcmds[i].verdict == SG_VERDICT_REJECT) any_reject = true;
        if (out->subcmds[i].verdict == SG_VERDICT_DENY) any_deny = true;
    }

    if (any_reject)
        out->verdict = SG_VERDICT_REJECT;
    else if (any_deny)
        out->verdict = SG_VERDICT_DENY;
    else if (all_allow)
        out->verdict = SG_VERDICT_ALLOW;
    else
        out->verdict = SG_VERDICT_UNDETERMINED;
    out->truncated = bw.overflow;
    return bw.overflow ? SG_ERR_TRUNC : SG_OK;
}

/* ============================================================
 * HELPERS
 * ============================================================ */

const char *sg_verdict_name(sg_verdict_t v)
{
    switch (v) {
        case SG_VERDICT_ALLOW:        return "ALLOW";
        case SG_VERDICT_DENY:         return "DENY";
        case SG_VERDICT_REJECT:       return "REJECT";
        case SG_VERDICT_UNDETERMINED: return "UNDETERMINED";
    }
    return "UNKNOWN";
}
