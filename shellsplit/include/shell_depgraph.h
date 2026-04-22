/*
 * shell_depgraph.h - Abstract Command Dependency Graph (ACDG)
 *
 * Zero-copy bounded-memory parser that builds a coarse-grained
 * command dependency graph from shell command strings.
 *
 * Consumes the output of the fast tokenizer (shell_parse_fast).
 * Produces a linearized, topologically-sorted graph of CMD and DOC
 * nodes with directed/undirected edges.
 *
 * Design principles:
 * - Zero-copy: tokens point into original input string
 * - Bounded memory: caller provides output buffer with limits
 * - No dynamic allocation
 */

#ifndef SHELL_DEPGRAPH_H
#define SHELL_DEPGRAPH_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ============================================================
 * CONSTANTS & LIMITS
 * ============================================================ */

#define SHELL_DEP_MAX_NODES   128
#define SHELL_DEP_MAX_EDGES   256
#define SHELL_DEP_MAX_TOKENS  32
#define SHELL_DEP_MAX_HEREDOCS 8

/* ============================================================
 * TYPE DEFINITIONS
 * ============================================================ */

typedef enum {
    SHELL_DEP_OK      =  0,
    SHELL_DEP_EINPUT  = -1,
    SHELL_DEP_ETRUNC  = -2,
    SHELL_DEP_EPARSE  = -3,
} shell_dep_error_t;

typedef enum {
    SHELL_DEP_STATUS_OK         = 0,
    SHELL_DEP_STATUS_TRUNCATED = 1 << 0,
} shell_dep_status_t;

typedef enum {
    SHELL_NODE_CMD = 0,
    SHELL_NODE_DOC,
} shell_dep_node_type_t;

typedef enum {
    SHELL_DOC_FILE        = 0,
    SHELL_DOC_HEREDOC     = 1,
    SHELL_DOC_HERESTRING  = 2,
    SHELL_DOC_ENVVAR      = 3,
} shell_dep_doc_kind_t;

typedef enum {
    SHELL_EDGE_READ   = 0,
    SHELL_EDGE_WRITE  = 1,
    SHELL_EDGE_APPEND = 2,
    SHELL_EDGE_PIPE   = 3,
    SHELL_EDGE_ARG    = 4,
    SHELL_EDGE_ENV    = 5,
    SHELL_EDGE_SUBST  = 6,
    SHELL_EDGE_SEQ    = 7,
    SHELL_EDGE_AND    = 8,
    SHELL_EDGE_OR     = 9,
} shell_dep_edge_type_t;

typedef enum {
    SHELL_DIR_FORWARD = 0,
    SHELL_DIR_BIDIR   = 1,
    SHELL_DIR_UNDIR   = 2,
} shell_dep_edge_dir_t;

typedef struct {
    uint32_t max_nodes;
    uint32_t max_edges;
    uint32_t max_tokens_per_cmd;
} shell_dep_limits_t;

static const shell_dep_limits_t SHELL_DEP_LIMITS_DEFAULT = {
    .max_nodes = SHELL_DEP_MAX_NODES,
    .max_edges = SHELL_DEP_MAX_EDGES,
    .max_tokens_per_cmd = SHELL_DEP_MAX_TOKENS,
};

/**
 * CMD node - an isolated shell command
 *
 * Tokens are zero-copy pointers into the original input string.
 * cwd is the resolved working directory when this command runs (owned copy).
 */
typedef struct {
    const char *tokens[SHELL_DEP_MAX_TOKENS];
    uint32_t    token_lens[SHELL_DEP_MAX_TOKENS];
    uint32_t    token_count;
    const char *cwd;
} shell_dep_cmd_t;

/**
 * DOC node - a data artifact
 *
 * Fields are used according to kind:
 *   FILE:      path/path_len
 *   HEREDOC:   name/name_len (delimiter), value/value_len (content)
 *   HERESTRING: value/value_len (content)
 *   ENVVAR:    name/name_len, value/value_len
 */
typedef struct {
    shell_dep_doc_kind_t kind;
    const char *path;
    uint32_t    path_len;
    const char *name;
    uint32_t    name_len;
    const char *value;
    uint32_t    value_len;
} shell_dep_doc_t;

typedef struct {
    shell_dep_node_type_t type;
    union {
        shell_dep_cmd_t  cmd;
        shell_dep_doc_t  doc;
    };
} shell_dep_node_t;

typedef struct {
    uint32_t from;
    uint32_t to;
    shell_dep_edge_type_t type;
    shell_dep_edge_dir_t  dir;
} shell_dep_edge_t;

typedef struct {
    shell_dep_node_t nodes[SHELL_DEP_MAX_NODES];
    uint32_t node_count;
    shell_dep_edge_t edges[SHELL_DEP_MAX_EDGES];
    uint32_t edge_count;
    uint32_t status;
} shell_dep_graph_t;

/**
 * Validation result - checked by shell_dep_validate
 */
#define SHELL_DEP_MAX_VALIDATE_ERRORS 16

typedef struct {
    bool valid;
    uint32_t error_count;
    struct {
        uint32_t edge_idx;
        char msg[96];
    } errors[SHELL_DEP_MAX_VALIDATE_ERRORS];
} shell_dep_validate_result_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * API
 * ============================================================ */

/**
 * Parse a shell command into a dependency graph.
 */
shell_dep_error_t shell_parse_depgraph(
    const char *cmd,
    size_t cmd_len,
    const char *initial_cwd,
    const shell_dep_limits_t *limits,
    shell_dep_graph_t *out
);

const char *shell_dep_edge_type_name(shell_dep_edge_type_t type);
const char *shell_dep_node_type_name(shell_dep_node_type_t type);
const char *shell_dep_doc_kind_name(shell_dep_doc_kind_t kind);

/**
 * Dump graph to FILE* for debugging.
 */
void shell_dep_graph_dump(const shell_dep_graph_t *g, FILE *fp);

/**
 * Validate graph integrity:
 * - All edge from/to within node_count bounds
 * - Edge types consistent with node types
 *   (PIPE/SEQ/AND/OR/SUBST require CMD→CMD,
 *    READ requires DOC→CMD, WRITE/APPEND require CMD→DOC,
 *    ENV requires DOC→CMD, ARG requires CMD↔DOC)
 */
shell_dep_validate_result_t shell_dep_validate(const shell_dep_graph_t *g);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_DEPGRAPH_H */
