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
 * value is only known at execution time. The graph records its logical name
 * alongside this sentinel; callers must not treat the sentinel as a unique
 * descriptor identity. */
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
  /* Caller-owned dependency-analysis workspace was absent, misaligned, or
   * too small. It is required for compound-group descriptor snapshots and
   * descriptor-route resolution. */
  SHELL_DEP_EWORKSPACE = -4,
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
  /* A document is evaluated during redirection setup but every ordinary
   * descriptor route to it is later replaced or closed. A transient FILE
   * document retains its FD_OPEN setup edge without claiming byte flow.
   * Transient heredoc and here-string documents have no FD_OPEN edge. A named
   * setup is non-transient only while the final persistent descriptor table
   * still routes that name to the document; a later persistent close or rebind
   * leaves the historical FD_OPEN edge as setup evidence and marks its document
   * transient. */
  SHELL_DEP_DOC_FLAG_TRANSIENT = 1 << 3,
  /* An ENVVAR document records `name+=value`, not `name=value`. Its value
   * span is the appended source fragment, not the resulting variable value. */
  SHELL_DEP_DOC_FLAG_ENVVAR_APPEND = 1 << 4,
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
  /* A setup-time redirection binds a descriptor without claiming command-byte
   * flow. It represents named descriptors and ordinary numeric descriptors
   * whose route is later replaced or closed. Direction preserves file-to-FD
   * (`<`), FD-to-file (`>`/`>>`), both (`<>`), or a named descriptor's
   * process-substitution endpoint until a later `$name` use materializes the
   * actual I/O edge. */
  SHELL_EDGE_FD_OPEN = 13,
  /* An explicit `>&-` or `<&-` close, including Bash `{name}` descriptors
   * and persistent numeric `exec` descriptors. The edge records that
   * source-order setup transition without inventing a byte route. */
  SHELL_EDGE_FD_CLOSE = 14,
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
  /* A setup-only FD_OPEN output binding used Bash/POSIX append mode (`>>` or
   * `&>>`). An unflagged output FD_OPEN is ordinary truncating output. */
  SHELL_DEP_EDGE_FLAG_FD_OPEN_APPEND = 1 << 2,
  /* A setup-only FD_OPEN binding duplicates another descriptor rather than
   * opening a document. Its source and target can be numeric or Bash named
   * descriptors. */
  SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP = 1 << 3,
} shell_dep_edge_flags_t;

/**
 * Limits for depgraph parsing.
 * Set cwd_buf_size to 0 to use the default SHELL_DEP_CWD_BUF_SIZE (16384).
 * The actual buffer in shell_dep_graph_t is always SHELL_DEP_CWD_BUF_SIZE
 * bytes; cwd_buf_size in limits is the effective bound checked during parsing.
 * Values from 2 through the buffer maximum are valid. A value of 1 is
 * rejected because even the NUL-terminated root path cannot fit; 0 selects
 * the default. `workspace` is caller-owned scratch storage used only while
 * parsing and resolving descriptor routes; it is never retained by the graph.
 * This includes temporary state for reconstructing inherited descriptor
 * routes at compound-group expansion points. Obtain the required maximum
 * size and alignment with shell_dep_workspace_size() and
 * shell_dep_workspace_alignment(). Command and initial-CWD inputs may overlap
 * each other because both are read-only, but neither may overlap the writable
 * workspace or shell_dep_graph_t output. A NULL, misaligned, or undersized
 * workspace causes
 * SHELL_DEP_EWORKSPACE rather than a hidden allocation; invalid overlap is
 * rejected with SHELL_DEP_EINPUT.
 */
typedef struct {
  uint32_t max_nodes;
  uint32_t max_edges;
  uint32_t max_tokens_per_cmd;
  uint32_t cwd_buf_size; /* 0 = use default SHELL_DEP_CWD_BUF_SIZE */
  /* cd_as_cmd: when true, a statically recognized current-shell `cd` (direct
   *            or through `command`/`builtin`) produces a CMD node with a CWD
   *            edge. When false (default), a plain `cd` only changes tracked
   *            CWD; redirects or executable substitutions still require a
   *            CMD endpoint so their effects remain visible. */
  bool cd_as_cmd;
  void *workspace;
  size_t workspace_size;
} shell_dep_limits_t;

static const shell_dep_limits_t SHELL_DEP_LIMITS_DEFAULT = {
    SHELL_DEP_MAX_NODES,
    SHELL_DEP_MAX_EDGES,
    SHELL_DEP_MAX_TOKENS,
    0, /* cwd_buf_size: use default 16384 */
    false,
    NULL,
    0};

/**
 * Get human-readable error string for depgraph error code.
 * @param err  Error code from shell_dep_error_t enum
 * @return     Static string, never NULL
 */
const char *shell_dep_error_string(shell_dep_error_t err);

/** Return the alignment required by caller-owned depgraph workspace storage. */
size_t shell_dep_workspace_alignment(void);

/**
 * Return the temporary workspace required for one dependency-graph parse and
 * descriptor-route resolution.
 * `limits` may be NULL; the current fixed-capacity implementation returns the
 * same maximum size for every valid limits configuration. The size is
 * independent of command text, so callers can reuse one buffer across
 * evaluations. Returns false only for invalid output arguments.
 */
bool shell_dep_workspace_size(const shell_dep_limits_t *limits,
                              size_t *workspace_size);

/**
 * Fixed-size buffer for unique CWD strings.
 * CWDs are deduplicated and referenced by offset.
 * Bounded by SHELL_DEP_CWD_BUF_SIZE (16384 bytes).
 */
typedef struct {
  char data[SHELL_DEP_CWD_BUF_SIZE];
  size_t len;
} shell_dep_cwd_buf_t;

typedef enum {
  SHELL_DEP_COMMAND_DIRECT = 0,
  SHELL_DEP_COMMAND_SEARCH = 1,  /* `command` executes the target. */
  SHELL_DEP_COMMAND_BUILTIN = 2, /* `builtin` requires a shell builtin. */
  SHELL_DEP_COMMAND_EXEC = 3, /* `exec` replaces the shell with its target. */
} shell_dep_command_wrapper_t;

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
  /* Index in tokens of the statically known command executed by this simple
   * command, after `command`/`builtin` wrappers and any static `exec` target.
   * `effective_command_known` is false for dynamic, absent, or inspection-only
   * `command -v/-V` targets, and for an unresolved `exec` target.
   * The wrapper kind describes only the final wrapper before that target. */
  uint32_t effective_command_token;
  bool effective_command_known;
  shell_dep_command_wrapper_t effective_command_wrapper;
  uint32_t cwd_offset;  /* Offset into graph->cwd_buf.data */
  uint16_t group_depth; /* Enclosing command-group nesting depth */
  uint8_t group_kinds;  /* shell_group_kind_t bitset of enclosing groups */
  bool backgrounded;    /* Command runs asynchronously */
  /* Every leading `!` belongs to this pipeline. The boolean is the effective
   * odd-count status inversion after all members have run. */
  uint32_t pipeline_negation_count;
  bool pipeline_negated;
  bool cwd_known;    /* False when branch composition makes CWD ambiguous */
  bool cwd_absolute; /* False when CWD is rooted at a relative initial path */
  /* Effective fd-0 and fd-1 pipeline endpoint pairs after redirects and
   * descriptor copies. Both fields in a pair are UINT32_MAX when that stream
   * does not carry a pipe. Group endpoints remain intact rather than
   * inventing additional PIPE edges. A replaced peer can leave a route to a
   * terminal endpoint; join these pairs to a final PIPE edge before claiming
   * command-to-command byte flow. */
  uint32_t pipe_stdin_source;
  uint32_t pipe_stdin_target;
  uint32_t pipe_stdout_source;
  uint32_t pipe_stdout_target;
} shell_dep_cmd_t;

typedef struct {
  const char *start; /* Opening group delimiter in the original input */
  uint32_t length;   /* Complete group span, including delimiters */
  uint32_t parent;   /* Parent group node, or UINT32_MAX */
  uint8_t kind;      /* shell_group_kind_t */
  uint32_t pipeline_negation_count;
  /* Effective odd-count inversion for this compound pipeline member. */
  bool pipeline_negated;
} shell_dep_group_t;

/**
 * Dynamic substitution-stream collector.
 *
 * An ENDPOINT normally has incoming WRITE edges and outgoing SUBST edges.
 * The parser may also use internal endpoint forms: a terminal pipe whose
 * reader was replaced by a later redirect has only incoming PIPE edges, and
 * an unconnected named-FD process substitution retains one FD_OPEN setup edge
 * until a later symbolic descriptor use materializes byte flow. Descriptor
 * ownership is carried by those edges, avoiding a second, ambiguous
 * descriptor field on the endpoint itself. `reserved` is internal parser
 * state; callers must treat it as opaque.
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
 *   ENVVAR:    name/name_len, value/value_len (borrowed assignment spelling;
 *              ENVVAR_APPEND distinguishes `+=` from `=`)
 *
 * All fields borrow source spans. Heredoc delimiter matching applies shell
 * quote removal, but `name` is not a decoded value: one enclosing homogeneous
 * `'...'` or `"..."` pair is elided for display, while mixed-quote,
 * backslash, and ANSI-C spellings retain their source span.
 * `value` always preserves physical source bytes; for `<<-`, use
 * shell_dep_doc_content_length() and
 * shell_dep_doc_write_content() to obtain logical tab-stripped content. CRLF
 * heredoc framing is recognized, but carriage returns remain content bytes.
 * An ENVVAR assignment's name and value spans belong to one contiguous source
 * word; its `=` or `+=` delimiter lies between them and can contain escaped
 * line continuations. Quoting can cross that delimiter, so use
 * shell_dep_doc_env_name_length/write for the logical identifier rather than
 * comparing `name` directly.
 */
typedef struct {
  shell_dep_doc_kind_t kind;
  const char *path;
  uint32_t path_len;
  /* FILE path interpretation uses the execution CWD at the operand's
   * expansion point. cwd_absolute distinguishes a real absolute CWD from a
   * relative initial base whose modeled path may look absolute. Unknown CWD
   * or dynamic names cannot establish a static file identity. Other document
   * kinds leave these fields unused. */
  uint32_t cwd_offset;
  bool cwd_known;
  bool cwd_absolute;
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
  /* Non-NULL only when the matching descriptor is SHELL_DEP_FD_NAMED. The
   * span is its source spelling without `{}`, `$`, or quote bytes; its
   * logical identity removes escaped physical line endings under Shellsplit's
   * normal source rules. It borrows `cmd`, just like node tokens and document
   * paths. */
  const char *source_fd_name;
  uint32_t source_fd_name_len;
  const char *target_fd_name;
  uint32_t target_fd_name_len;
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
 * The graph models simple-command lists, pipelines, and brace/subshell groups.
 * Control compounds (including function declarations, `select`, and `coproc`),
 * shell-semantic array forms (including array element targets), and unmodeled
 * current-shell forms (`mapfile`/`readarray`, `wait -p`, and mutating
 * arithmetic expansions) return SHELL_DEP_EPARSE, as do unmodeled Bash `[[ …
 * ]]`,
 * `(( … ))`, `time`, `$"…"`, and `;&` / `;;&` forms.
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
 * This direct route requires the whole operand to be one process substitution.
 * If a named-FD process substitution's nested command redirects away that
 * inherited stream, its internal ENDPOINT retains the FD_OPEN setup without
 * inventing byte flow; a later exact `$name` descriptor use materializes the
 * actual SUBST or WRITE edge.
 * Composite operands such as `prefix<(producer)` retain a dynamic FILE document
 * and the nested commands, without inventing a stream route or treating their
 * stdout as pathname bytes. Command substitutions within that filename still
 * supply pathname bytes through SUBST_DYNAMIC_NAME edges.
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
 * artifact without a stale byte-flow edge. A replaced FILE document retains
 * its FD_OPEN setup-time descriptor binding and carries
 * SHELL_DEP_DOC_FLAG_TRANSIENT when no effective route remains. Replaced
 * heredoc and here-string documents have no FD_OPEN edge. An expandable
 * document retains its setup-time SUBST flow as well.
 *
 * Bash named descriptors (`{name}>file`) retain the bare descriptor name on
 * their FD_OPEN, FD_CLOSE, and affected routing edges. A whole redirection
 * operand `$name` or `${name}` may reuse that descriptor. Their names use the
 * same escaped-physical-line-ending normalization as source parsing; general
 * parameter expansion is intentionally not interpreted as a descriptor
 * reference. An unknown, closed, reassigned, or
 * syntactically composite named reference is an error rather than a guessed
 * route. With Bash's default `varredir_close` behavior, an ordinary simple
 * command with a command word and a non-isolated brace-group redirect tail
 * retain an open named binding in the current shell; redirect-only and
 * assignment-only commands do not. Subshell groups and groups executing as a
 * pipeline member or background job retain bindings only in their private
 * execution scope. Leading assignments on a command are temporary: they do
 * not replace a visible descriptor-variable binding while that command's
 * redirects or nested substitutions expand. Assignment-only scalar names
 * follow shell lexical spelling, so `f\\\nd=value` and `fd+=value` still
 * identify `fd`. A non-`exec` close is
 * local, whereas `exec` persists a close. Commands that mutate `shopt`
 * `varredir_close`, `lastpipe`, or `expand_aliases`, POSIX mode, or statically
 * recognized current-shell metaprogramming builtins (`eval`, `.`, `source`,
 * `trap`, `alias`, `unalias`, `fc`, and `enable`), are rejected as unsupported,
 * so this lifetime and pipeline-scope invariant is never silently changed.
 * The executor must start Bash in the documented clean noninteractive state.
 * Start it with `POSIXLY_CORRECT` absent (not merely empty), then make that
 * variable readonly before evaluating submitted source. `bash -p -c ...` is
 * the supported basis: privileged mode ignores `BASH_ENV`, `BASHOPTS`, and
 * `SHELLOPTS`, and declines imported shell functions that could shadow a
 * modelled builtin such as `exec`. An equivalent launcher must establish the
 * same option and command-lookup state before source validation, including no
 * startup aliases or traps, no disabled or shadowed modelled builtins, and a
 * readonly unset `POSIXLY_CORRECT`. A runtime-expanded command word is
 * intentionally not promoted to one of these builtin roles.
 *
 * Shell builtin roles use a static quote-removed spelling: `e'x'ec` and
 * `com'mand' -p e'x'ec` have the same descriptor semantics as their plain
 * forms. A word with runtime expansion is never promoted into a builtin or
 * descriptor-variable role. An `exec` invocation without a command operand,
 * including one with scalar assignment or standard `exec` option prefixes,
 * carries named and numeric bindings through brace groups and into each
 * inheriting child execution scope. Numeric setup such
 * as `exec 3>file`, `exec 4>&3`, and `exec 3>&-` is represented by setup
 * edges; it is not byte flow until a later command uses it as an active
 * standard stream or duplicates it onto one. Child scopes inherit a snapshot
 * but never export
 * their changes. A descriptor setup can cross a direct, unambiguous `&&`
 * success continuation, because that right-hand command runs only after the
 * setup succeeded; it never promotes into the ordinary persistent table or
 * across `||`/mixed conditional joins. A nested expansion in an ordinary
 * command word sees the descriptor state before that simple command's redirect
 * list. An expansion in a redirect operand, process substitution, or
 * here-string operand, or expandable heredoc instead sees only the preceding
 * redirects in that list. Builtins that may rewrite descriptor variables
 * do so after their own redirects have expanded and taken effect; their
 * mutations invalidate affected bindings for later commands, or every named
 * binding when the target is dynamic. An assignment-only command can instead
 * change a descriptor variable before expanding its redirect operand.
 *
 * Subshell extraction tracks simple single/double quotes and odd/even
 * backslash escapes while finding delimiters. It is not a complete shell
 * grammar; malformed structures are rejected instead of being represented as
 * a partial graph. For valid input that reaches descriptor-route resolution,
 * `limits` must provide the caller-owned workspace described by
 * shell_dep_limits_t; otherwise this returns SHELL_DEP_EWORKSPACE with `out`
 * cleared. `initial_cwd` is a borrowed NUL-terminated path; NULL selects
 * `"."`. `cmd` and `initial_cwd` may overlap because both are read-only, but
 * neither may overlap `out` or the workspace. Invalid overlap is rejected
 * with SHELL_DEP_EINPUT before any writable span is changed.
 * Parsing errors that are detected before route resolution do not require
 * workspace.
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
 * NULL destination is accepted only for empty logical content. The complete
 * destination buffer must not overlap the document's borrowed value span;
 * overlap is rejected before either span is modified. */
bool shell_dep_doc_write_content(const shell_dep_doc_t *doc, char *destination,
                                 size_t destination_size, size_t *written);

/** Measure or write an ENVVAR document's quote-removed identifier. The write
 * API is failure-atomic and does not add a NUL terminator. Other document
 * kinds and malformed assignment spans are rejected. The complete destination
 * buffer must not overlap the borrowed assignment word, including its value;
 * overlap is rejected before either span is modified. */
bool shell_dep_doc_env_name_length(const shell_dep_doc_t *doc,
                                   size_t *name_length);
bool shell_dep_doc_write_env_name(const shell_dep_doc_t *doc, char *destination,
                                  size_t destination_size, size_t *written);
/** Compare an ENVVAR document's logical identifier without materializing it. */
bool shell_dep_doc_env_name_equals(const shell_dep_doc_t *doc, const char *name,
                                   size_t name_length);

/** Write a static FILE document's lexical path identity into caller storage.
 * The result combines the document's recorded execution CWD with its decoded
 * path, then removes redundant separators and single-dot components. Parent
 * components remain lexical: collapsing `link/..` would be unsound when
 * `link` is a symlink. It does not resolve symlinks or inspect the filesystem.
 * Dynamic paths and relative
 * paths with an unknown CWD return false. `absolute` distinguishes an actual
 * absolute identity from one rooted at a relative initial CWD; compare it
 * along with the output bytes. `written` excludes the trailing NUL. On
 * failure outputs are cleared and the destination is unchanged. */
bool shell_dep_doc_file_identity_write(const shell_dep_graph_t *graph,
                                       const shell_dep_doc_t *doc,
                                       char *destination,
                                       size_t destination_size, size_t *written,
                                       bool *absolute);

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
 * ENDPOINT, ENV requires DOC→CMD, ARG requires CMD↔DOC; FD_OPEN is a
 * forward setup binding: execution→DOC for output, DOC→execution for input,
 * execution→ENDPOINT for process-substitution output, or
 * execution/ENDPOINT→execution for descriptor routing. An internal retained
 * process-substitution endpoint may have only its named FD_OPEN setup until a
 * later descriptor use adds byte flow. It also permits a
 * same-owner execution descriptor duplication. FD_CLOSE is a same-owner
 * CMD/GROUP setup transition with a source descriptor and no target)
 */
shell_dep_graph_validation_t
shell_dep_graph_validate(const shell_dep_graph_t *g);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_DEPGRAPH_H */
