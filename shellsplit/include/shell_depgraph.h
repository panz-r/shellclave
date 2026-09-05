/*
 * shell_depgraph.h - Abstract Command Dependency Graph (ACDG)
 *
 * Zero-copy bounded-memory parser that builds a coarse-grained
 * command dependency graph from shell command strings.
 *
 * Consumes the output of the fast tokenizer (shell_parse_fast).
 * Produces a linearized, topologically-sorted graph of CMD and DOC
 * nodes with directed/undirected edges. Compound groups are first-class
 * execution endpoints: their redirects and external pipes connect to the
 * GROUP node, while GROUP edges express containment rather than I/O.
 *
 * Design principles:
 * - Zero-copy: tokens point into original input string
 * - Bounded memory: caller provides output buffer with limits
 * - No dynamic allocation
 */

#ifndef SHELL_DEPGRAPH_H
#define SHELL_DEPGRAPH_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- CONSTANTS AND LIMITS --- */

#define SHELL_DEP_MAX_NODES 128
#define SHELL_DEP_MAX_EDGES 256
#define SHELL_DEP_MAX_TOKENS 32
#define SHELL_DEP_MAX_HEREDOCS 8
#define SHELL_DEP_CWD_BUF_SIZE 16384 /* 16KB buffer for unique CWD strings */
/* An edge endpoint has no applicable file descriptor. */
#define SHELL_DEP_FD_NONE UINT32_MAX
/* A Bash `{name}OPword` redirect uses a shell-managed descriptor whose numeric
 * value is only known at execution time. The graph preserves its setup edge
 * but must not mislabel it as stdout or stderr I/O. */
#define SHELL_DEP_FD_NAMED (UINT32_MAX - 1u)
/* Shell io_number values are bounded by the implementation's signed fd
 * domain. Keeping this below SHELL_DEP_FD_NONE makes the sentinel unambiguous.
 */
#define SHELL_DEP_FD_MAX ((uint32_t)INT_MAX)

/* CWD buffer must accommodate at least one PATH_MAX-sized path */
#if defined(PATH_MAX) && PATH_MAX > SHELL_DEP_CWD_BUF_SIZE
#error "SHELL_DEP_CWD_BUF_SIZE must be >= PATH_MAX"
#endif

/* --- TYPE DEFINITIONS --- */

typedef enum {
  SHELL_DEP_OK = 0,
  SHELL_DEP_EINPUT = -1,
  SHELL_DEP_ETRUNC = -2,
  SHELL_DEP_EPARSE = -3,
} shell_dep_error_t;

typedef enum {
  SHELL_DEP_STATUS_OK = 0,
  SHELL_DEP_STATUS_TRUNCATED = 1 << 0,
  SHELL_DEP_STATUS_ERROR = 1 << 1,
} shell_dep_status_t;

typedef enum {
  SHELL_NODE_CMD = 0,
  SHELL_NODE_DOC,
  SHELL_NODE_GROUP, /* Compound-command execution endpoint and container. */
  /* Non-executable collector for a dynamically produced substitution stream.
   * Its incoming WRITE edges identify producer descriptors; its outgoing
   * SUBST edge identifies the shell execution context that consumes it. */
  SHELL_NODE_ENDPOINT,
} shell_dep_node_type_t;

typedef enum {
  SHELL_DOC_FILE = 0,
  SHELL_DOC_HEREDOC = 1,
  SHELL_DOC_HERESTRING = 2,
  SHELL_DOC_ENVVAR = 3,
} shell_dep_doc_kind_t;

typedef enum {
  SHELL_DEP_DOC_FLAG_NONE = 0,
  /* `value` is a physical `<<-` source span. Use the content helpers to
   * obtain the tab-stripped logical bytes. */
  SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS = 1 << 0,
  /* The file-path operand contains a command substitution, so `path` is
   * source spelling rather than a resolved filesystem path. This covers both
   * ordinary redirections and Bash `$(<word)` file-command substitutions. */
  SHELL_DEP_DOC_FLAG_DYNAMIC_NAME = 1 << 1,
  /* The heredoc delimiter was quoted and its body is literal. */
  SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL = 1 << 2,
  /* An inline input document is evaluated during redirection setup but a later
   * redirect replaces the target descriptor, so it has no effective READ edge.
   */
  SHELL_DEP_DOC_FLAG_TRANSIENT = 1 << 3,
} shell_dep_doc_flags_t;

typedef enum {
  SHELL_EDGE_READ = 0,
  SHELL_EDGE_WRITE = 1,
  SHELL_EDGE_APPEND = 2,
  SHELL_EDGE_PIPE = 3,
  SHELL_EDGE_ARG = 4,
  SHELL_EDGE_ENV = 5,
  SHELL_EDGE_SUBST = 6,
  SHELL_EDGE_SEQ = 7,
  SHELL_EDGE_AND = 8,
  SHELL_EDGE_OR = 9,
  SHELL_EDGE_CWD = 10,
  SHELL_EDGE_BACKGROUND = 11,
  SHELL_EDGE_GROUP = 12,
  /* A named-FD redirect opens a descriptor but does not itself route command
   * bytes to the file. This setup edge preserves the file-to-descriptor
   * orientation (`<`), descriptor-to-file orientation (`>`/`>>`), or both
   * (`<>`) without falsely claiming stdout/stderr I/O. */
  SHELL_EDGE_FD_OPEN = 13,
} shell_dep_edge_type_t;

typedef enum {
  SHELL_DIR_FORWARD = 0,
  SHELL_DIR_BIDIR = 1,
  SHELL_DIR_UNDIR = 2,
} shell_dep_edge_dir_t;

typedef enum {
  SHELL_DEP_EDGE_FLAG_NONE = 0,
  /* This SUBST edge supplies bytes that the shell incorporates into a word
   * before invoking its command. A caller can submit that later content to a
   * separate Shellgate inspection. Other SUBST edges model dynamic descriptor
   * routing, such as process substitution, and must not be treated as shell
   * word evaluation. */
  SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD = 1 << 0,
  /* This SUBST edge supplies a FILE document's runtime pathname. The value
   * affects I/O topology but is not itself command-word content for a later
   * Shellgate inspection. The receiving FILE DOC has DYNAMIC_NAME set. */
  SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME = 1 << 1,
} shell_dep_edge_flags_t;

/**
 * Limits for depgraph parsing.
 * Set cwd_buf_size to 0 to use the default SHELL_DEP_CWD_BUF_SIZE (16384).
 * The actual buffer in shell_dep_graph_t is always SHELL_DEP_CWD_BUF_SIZE
 * bytes; cwd_buf_size in limits is the effective bound checked during parsing.
 * Values from 2 through the buffer maximum are valid. A value of 1 is
 * rejected because even the NUL-terminated root path cannot fit; 0 selects
 * the default.
 */
typedef struct {
  uint32_t max_nodes;
  uint32_t max_edges;
  uint32_t max_tokens_per_cmd;
  uint32_t cwd_buf_size; /* 0 = use default SHELL_DEP_CWD_BUF_SIZE */
  /* cd_as_cmd: when true, 'cd' commands produce CMD nodes (with CWD edge);
   *            when false (default), cd is processed for CWD side-effects
   *            but does not produce a node in the graph. */
  bool cd_as_cmd;
} shell_dep_limits_t;

static const shell_dep_limits_t SHELL_DEP_LIMITS_DEFAULT = {
    SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
    0, /* cwd_buf_size: use default 16384 */
    false};

/**
 * Get human-readable error string for depgraph error code.
 * @param err  Error code from shell_dep_error_t enum
 * @return     Static string, never NULL
 */
const char *shell_dep_error_string(shell_dep_error_t err);

/**
 * Fixed-size buffer for unique CWD strings.
 * CWDs are deduplicated and referenced by offset.
 * Bounded by SHELL_DEP_CWD_BUF_SIZE (16384 bytes).
 */
typedef struct {
  char data[SHELL_DEP_CWD_BUF_SIZE];
  size_t len;
} shell_dep_cwd_buf_t;

/**
 * CMD node - an isolated shell command
 *
 * Tokens are zero-copy pointers into the original input string.
 * cwd_offset is the offset into graph->cwd_buf.data for the resolved working
 * directory.
 */
typedef struct {
  const char *tokens[SHELL_DEP_MAX_TOKENS];
  uint32_t token_lens[SHELL_DEP_MAX_TOKENS];
  uint32_t token_count;
  uint32_t cwd_offset;  /* Offset into graph->cwd_buf.data */
  uint16_t group_depth; /* Enclosing command-group nesting depth */
  uint8_t group_kinds;  /* shell_group_kind_t bitset of enclosing groups */
  bool backgrounded;    /* Command runs asynchronously */
  /* This command is a member of a POSIX `! pipeline`; the pipeline's final
   * status is inverted after all members have run. */
  bool pipeline_negated;
  bool cwd_known; /* False when branch composition makes CWD ambiguous */
} shell_dep_cmd_t;

typedef struct {
  const char *start; /* Opening group delimiter in the original input */
  uint32_t length;   /* Complete group span, including delimiters */
  uint32_t parent;   /* Parent group node, or UINT32_MAX */
  uint8_t kind;      /* shell_group_kind_t */
  /* This compound command is a member of a POSIX `! pipeline`. */
  bool pipeline_negated;
} shell_dep_group_t;

/**
 * Dynamic substitution-stream collector.
 *
 * An ENDPOINT normally has incoming WRITE edges and outgoing SUBST edges.
 * The parser may also use an internal terminal endpoint for a pipe whose
 * reader was replaced by a later redirect; that endpoint has only incoming
 * PIPE edges, preserving the producer's real output relation without
 * inventing a consumer. Descriptor ownership is carried by those edges,
 * avoiding a second, ambiguous descriptor field on the endpoint itself.
 */
typedef struct {
  uint8_t reserved;
} shell_dep_endpoint_t;

/**
 * DOC node - a data artifact
 *
 * Fields are used according to kind:
 *   FILE:      path/path_len
 *   HEREDOC:   name/name_len (borrowed delimiter display span),
 *              value/value_len (source content)
 *   HERESTRING: value/value_len (content; an expandable word can receive
 *               incoming SUBST edges before its READ edge supplies owner)
 *   ENVVAR:    name/name_len, value/value_len
 *
 * All fields borrow source spans. Heredoc delimiter matching applies shell
 * quote removal, but `name` is not a decoded value: one enclosing homogeneous
 * `'...'` or `"..."` pair is elided for display, while mixed-quote,
 * backslash, and ANSI-C spellings retain their source span.
 * `value` always preserves physical source bytes; for `<<-`, use
 * shell_dep_doc_content_length() and
 * shell_dep_doc_write_content() to obtain logical tab-stripped content. CRLF
 * heredoc framing is recognized, but carriage returns remain content bytes.
 */
typedef struct {
  shell_dep_doc_kind_t kind;
  const char *path;
  uint32_t path_len;
  const char *name;
  uint32_t name_len;
  const char *value;
  uint32_t value_len;
  uint8_t flags; /* shell_dep_doc_flags_t */
} shell_dep_doc_t;

typedef struct {
  shell_dep_node_type_t type;
  union {
    shell_dep_cmd_t cmd;
    shell_dep_doc_t doc;
    shell_dep_group_t group;
    shell_dep_endpoint_t endpoint;
  };
} shell_dep_node_t;

typedef struct {
  uint32_t from;
  uint32_t to;
  shell_dep_edge_type_t type;
  shell_dep_edge_dir_t dir;
  uint8_t flags; /* shell_dep_edge_flags_t */
  /* Descriptor pair for the directed byte relation. Use SHELL_DEP_FD_NONE on
   * the non-descriptor side: DOC→owner READ is none→fd, owner→DOC WRITE is
   * fd→none, and PIPE is fd→fd. Shell-word and dynamic-FILE-name SUBST edges
   * terminate at none; an unflagged process-substitution route can instead
   * carry the redirected outer descriptor as its target fd. */
  uint32_t source_fd;
  uint32_t target_fd;
} shell_dep_edge_t;

typedef struct {
  shell_dep_node_t nodes[SHELL_DEP_MAX_NODES];
  uint32_t node_count;
  shell_dep_edge_t edges[SHELL_DEP_MAX_EDGES];
  uint32_t edge_count;
  uint32_t status;
  shell_dep_cwd_buf_t cwd_buf; /* Fixed 16KB buffer for unique CWD strings */
} shell_dep_graph_t;

/**
 * Validation result - checked by shell_dep_graph_validate
 */
#define SHELL_DEP_MAX_VALIDATE_ERRORS 16

typedef struct {
  bool valid;
  uint32_t error_count;
  struct {
    uint32_t edge_idx;
    char msg[96];
  } errors[SHELL_DEP_MAX_VALIDATE_ERRORS];
} shell_dep_graph_validation_t;

/* --- API --- */

/**
 * Parse a shell command into a dependency graph.
 *
 * All pointers in the output graph (tokens, paths, names, values) reference
 * the original `cmd` string. The caller must ensure `cmd` remains valid and
 * unmodified for the lifetime of the graph.
 *
 * Subshell parsing is internally limited to 16 levels (defense-in-depth).
 * Returns SHELL_DEP_EPARSE when that limit is exceeded.
 * Returns SHELL_DEP_ETRUNC and sets SHELL_DEP_STATUS_TRUNCATED when a caller
 * limit or fixed parser limit prevents the complete graph from being stored.
 * On input or parse errors, writable output counts are cleared and
 * SHELL_DEP_STATUS_ERROR is set.
 *
 * Command, backtick, process, and Bash file-command substitutions are
 * represented as dynamic I/O: direct SHELL_EDGE_SUBST edges when one
 * execution endpoint or FILE document supplies the stream, or
 * WRITE→ENDPOINT→SUBST paths when several producers or descriptor routing
 * must be retained. Unquoted heredoc bodies receive the same command and
 * backtick-substitution analysis; quoted delimiters keep their body literal.
 * SUBST marks runtime-generated topology;
 * `SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD` identifies the subset where bytes
 * become shell-word content and callers may submit it to a later Shellgate
 * pass. `SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME` instead supplies a FILE
 * document pathname and must not request that inspection. Unflagged SUBST
 * edges are dynamic descriptor routes. Neither kind by itself means that a
 * receiving program executes those bytes: process
 * substitution is ordinary I/O, while an interpreter such as `sh` reading that
 * descriptor as source is application-level semantics. A process substitution
 * used as an ordinary word is not itself a redirect:
 * `<(producer)` retains a producer-to-command SUBST relation with no target
 * descriptor, while `>(consumer)` retains the nested command graph without
 * claiming that the outer program writes a particular descriptor to it.
 * In a redirect operand, a matching pair establishes the descriptor route:
 * `< <(producer)` supplies the redirect fd and `> >(consumer)` receives it.
 * A cross-direction pair such as `< >(consumer)` or `> <(producer)` still
 * evaluates and retains the nested graph, but the shell syntax establishes no
 * byte route between that nested command and the redirect. `<>` is modeled as
 * read/write: `<> <(producer)` supplies its input side, while `<> >(consumer)`
 * establishes its known write side through an ENDPOINT to the consumer's
 * stdin. Its default descriptor is fd 0; neither form fabricates the opposite
 * descriptor direction.
 *
 * READ, WRITE, APPEND, and PIPE edges model the effective descriptor bindings
 * after redirections, descriptor duplication, and descriptor closes have
 * been applied in source order. A recursive substitution contributes an
 * inherited-stream relation only while its relevant descriptor still refers
 * to the original inherited fd; a close or duplication from another fd does
 * not fabricate a SUBST edge. A replaced document remains as a DOC syntax
 * artifact without a stale I/O edge and carries
 * SHELL_DEP_DOC_FLAG_TRANSIENT; an expandable one retains its setup-time
 * SUBST flow as well.
 *
 * Subshell extraction tracks simple single/double quotes and odd/even
 * backslash escapes while finding delimiters. It is not a complete shell
 * grammar; malformed structures are rejected instead of being represented as
 * a partial graph.
 */
shell_dep_error_t shell_dep_graph_parse(const char *cmd, size_t cmd_len,
                                        const char *initial_cwd,
                                        const shell_dep_limits_t *limits,
                                        shell_dep_graph_t *out);

const char *shell_dep_edge_type_name(shell_dep_edge_type_t type);
const char *shell_dep_node_type_name(shell_dep_node_type_t type);
const char *shell_dep_doc_kind_name(shell_dep_doc_kind_t kind);

/** Measure the logical value bytes of a document without allocating. For a
 * `<<-` heredoc this removes all leading tabs from each physical body line. */
bool shell_dep_doc_content_length(const shell_dep_doc_t *doc,
                                  size_t *content_length);

/** Write the logical value bytes of a document into caller storage. Measure
 * first; on failure `written` is zero and no partial content is exposed. A
 * NULL destination is accepted only for empty logical content. */
bool shell_dep_doc_write_content(const shell_dep_doc_t *doc, char *destination,
                                 size_t destination_size, size_t *written);

/**
 * Dump graph to FILE* for debugging.
 */
void shell_dep_graph_dump(const shell_dep_graph_t *g, FILE *fp);

/**
 * Validate graph integrity:
 * - All edge from/to within node_count bounds
 * - Node and edge types, containment parentage, directions, and descriptor
 *   fields consistent with their documented graph roles
 *   (PIPE/SEQ/AND/OR require CMD/GROUP endpoints; SUBST additionally permits
 *    ENDPOINT and DOC(FILE) sources and DOC(HEREDOC/HERESTRING) targets; READ
 * requires DOC→CMD/GROUP, WRITE/APPEND require an execution endpoint→DOC or
 * ENDPOINT, ENV requires DOC→CMD, ARG requires CMD↔DOC)
 */
shell_dep_graph_validation_t
shell_dep_graph_validate(const shell_dep_graph_t *g);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_DEPGRAPH_H */
