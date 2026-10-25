/*
 * shell_depgraph.h - Abstract Command Dependency Graph (ACDG)
 *
 * Zero-copy bounded-memory parser that builds a coarse-grained
 * command dependency graph from shell command strings.
 *
 * Consumes the output of the fast tokenizer (shell_parse_fast).
 * Produces a linearized graph of execution and data-resource nodes with
 * directed/undirected edges. Control relations form a DAG; byte relations
 * need not. Compound groups are first-class
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

#include "shell_contract.h"
#include "shell_expand.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "shell_tokenizer.h"

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
  /* Coarse syntax or unsupported/unclassified semantic failure. This alone
   * does not establish a Bash syntax error. shell_parse_draft() supplies the
   * source-level classification; COMPLETE still permits semantic rejection. */
  SHELL_DEP_EPARSE = -3,
  /* Caller-owned dependency-analysis workspace was absent, misaligned, or
   * too small. It is required for compound-group descriptor snapshots and
   * descriptor-route resolution. */
  SHELL_DEP_EWORKSPACE = -4,
  /* The expansion callback failed or returned malformed canonical bytes. */
  SHELL_DEP_EEXPAND = -5,
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
  /* Shell-owned Bash `time` operation for one pipeline. */
  SHELL_NODE_TIME,
  /* A descriptor inherited when the complete submitted command starts. */
  SHELL_NODE_FD,
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
  /* A document is evaluated during redirection setup but retains no effective
   * byte-use or persistent named-descriptor route. A transient FILE
   * document retains its FD_OPEN setup edge without claiming byte flow.
   * Heredoc and here-string documents likewise retain reached FD_OPEN setup
   * when no effective byte use remains, including a zero-count read. A named
   * setup is non-transient only while the final persistent descriptor table
   * still routes that name to the document; a later persistent close or rebind
   * leaves the historical FD_OPEN edge as setup evidence and marks its document
   * transient. */
  SHELL_DEP_DOC_FLAG_TRANSIENT = 1 << 3,
  /* An ENVVAR document records `name+=value`, not `name=value`. Its value
   * span is the appended source fragment, not the resulting variable value. */
  SHELL_DEP_DOC_FLAG_ENVVAR_APPEND = 1 << 4,
  /* Internal expansion-aware construction retains original FILE path spelling
   * and borrows a decoded, nonempty NUL-free pathname in value/value_len. It
   * is data, never source to quote-remove. Ordinary public source-only parsers
   * do not set this flag. */
  SHELL_DEP_DOC_FLAG_RESOLVED_PATH = 1 << 5,
  /* A reached FILE operand was statically empty after quote removal, or its
   * resolved expansion yielded zero/multiple words or an empty pathname.
   * Setup fails without opening the file. Source-only parsers also emit this
   * flag. Unreached operands retain their source spelling without this flag. */
  SHELL_DEP_DOC_FLAG_EXPANSION_FAILED = 1 << 6,
  /* Bash-supplied resource, not an explicit source redirection. For FILE,
   * path/path_len borrow a library-owned immutable canonical pathname for
   * the graph lifetime; do not expand or quote-remove it. Other spans and
   * CWD fields are empty. Currently used for asynchronous stdin /dev/null. */
  SHELL_DEP_DOC_FLAG_IMPLICIT = 1 << 7,
} shell_dep_doc_flags_t;

typedef enum {
  SHELL_EDGE_READ = 0,
  SHELL_EDGE_WRITE = 1,
  SHELL_EDGE_APPEND = 2,
  SHELL_EDGE_PIPE = 3,
  /* Possible pathname argument of a simple command, represented only by a
   * FILE document and excluding its first surviving argv word. Prefix
   * assignments, redirects and elided words do not advance that position;
   * quoted empty words do. Wrapper targets remain arguments of their outer
   * command. ARG is an undirected association, not a byte-use edge or
   * executable-identity declaration. */
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
   * whose route is later replaced or closed, as well as setup-only process
   * redirects on null commands or descriptor-only exec. Direction preserves
   * file-to-FD (`<`), FD-to-file (`>`/`>>`), both (`<>`), or a process endpoint
   * for numeric and named descriptors. `< <(producer)` and `> >(consumer)`
   * install descriptors without body-byte transfer. A later actual use can
   * materialize the corresponding byte-flow edge. */
  SHELL_EDGE_FD_OPEN = 13,
  /* An explicit `>&-` / `<&-` close or a successful move's source close,
   * including Bash `{name}` and persistent numeric `exec` descriptors. The
   * edge records that source-order setup transition without a byte route. */
  SHELL_EDGE_FD_CLOSE = 14,
  /* TIME node to the command/group endpoint that roots the measured
   * pipeline. This is structural, not a byte-flow edge. */
  SHELL_EDGE_TIME = 15,
} shell_dep_edge_type_t;

typedef enum {
  SHELL_DIR_FORWARD = 0,
  SHELL_DIR_BIDIR = 1,
  SHELL_DIR_UNDIR = 2,
} shell_dep_edge_dir_t;

typedef enum {
  SHELL_DEP_EDGE_FLAG_NONE = 0,
  /* This SUBST edge supplies bytes that the shell incorporates into a word
   * for a command argument or conditional string operand. A caller can submit
   * that later content to a separate Shellgate inspection. Other SUBST edges
   * model dynamic descriptor routing, such as process substitution, and must
   * not be treated as shell word evaluation. */
  SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD = 1 << 0,
  /* This SUBST edge supplies a FILE document's runtime pathname. The value
   * affects I/O topology but is not itself command-word content for a later
   * Shellgate inspection. The dependency remains when expansion changes the
   * receiving FILE DOC from DYNAMIC_NAME to RESOLVED_PATH or EXPANSION_FAILED.
   */
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
 * parsing and resolving descriptor routes; it is never retained by the graph
 * and need not be initialized or cleared by the caller between parses.
 * Bytes beyond shell_dep_workspace_size()'s fixed prefix serve as source
 * scratch for delimiter preparation and non-evicting subscript boundaries.
 * shell_source_workspace_size(command_length, &bytes) gives a sufficient
 * extra capacity; larger inputs can require EWORKSPACE and a retry.
 * The fixed prefix includes the operation's lexical index, independent of
 * parsing performed by application expansion callbacks, and temporary state
 * for reconstructing inherited descriptor routes at compound-group expansion
 * points. Obtain the fixed graph-state
 * size and alignment with shell_dep_workspace_size() and
 * shell_dep_workspace_alignment(). The limits object, command and initial-CWD
 * inputs, writable workspace, and shell_dep_graph_t output must have storage
 * and lifetimes appropriate to their roles; no writable span may overlap a
 * borrowed input or another writable object. A NULL, misaligned, or undersized
 * workspace causes (for nonempty executable source, including cd)
 * SHELL_DEP_EWORKSPACE rather than a hidden allocation. Storage aliasing is
 * invalid API use and is not checked at runtime.
 */
typedef struct {
  uint32_t max_nodes;
  uint32_t max_edges;
  uint32_t max_tokens_per_cmd;
  uint32_t cwd_buf_size; /* 0 = use default SHELL_DEP_CWD_BUF_SIZE */
  void *workspace;
  size_t workspace_size;
} shell_dep_limits_t;

static const shell_dep_limits_t SHELL_DEP_LIMITS_DEFAULT = {
    SHELL_DEP_MAX_NODES,
    SHELL_DEP_MAX_EDGES,
    SHELL_DEP_MAX_TOKENS,
    0, /* cwd_buf_size: use default 16384 */
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
 * Return the fixed temporary workspace for lexical indexing, graph state and
 * descriptor-route resolution. Additional source-sized lexical scratch can
 * share its tail, as described by shell_dep_limits_t. `limits` may be NULL; the
 * current fixed-capacity implementation returns the same maximum size for every
 * valid limits configuration. The size is independent of command text, so
 * callers can reuse one buffer across evaluations. `workspace_size` is required
 * and receives the size; the current fixed-capacity sizing operation always
 * succeeds.
 */
bool shell_dep_workspace_size(const shell_dep_limits_t *limits,
                              size_t *workspace_size) SHELL_NONNULL(2);

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

/* Expression truth before redirection/setup failures. UNKNOWN retains both
 * return outcomes; ZERO means failure and NONZERO means success. */
typedef enum {
  SHELL_ARITHMETIC_UNKNOWN = 0,
  SHELL_ARITHMETIC_ZERO,
  SHELL_ARITHMETIC_NONZERO,
} shell_arithmetic_truth_t;

/* Predicate truth before redirect/setup or expansion failure. */
typedef enum {
  SHELL_CONDITIONAL_UNKNOWN = 0,
  SHELL_CONDITIONAL_FALSE,
  SHELL_CONDITIONAL_TRUE,
} shell_conditional_truth_t;

/**
 * CMD node - an isolated shell command
 *
 * Tokens are zero-copy pointers into the original input string. Wholly elided
 * empty process-substitution words are omitted; surviving concatenated words
 * retain their source spelling (for example a<()b, whose static value is ab).
 * Quoted empty arguments survive. This expansion does not reopen the lexical
 * assignment-prefix or reserved-word positions.
 * cwd_offset is the offset into graph->cwd_buf.data for the resolved working
 * directory. Arithmetic and conditional commands have no argv tokens; their
 * spans borrow the original immutable input just as simple-command tokens do.
 */
typedef struct {
  shell_command_kind_t kind;
  /* Borrowed CONDITIONAL spans in source/expansion order; never argv or
   * pathname operands. Predicate truth includes lexical negation. EQUAL and
   * NOT_EQUAL require a fully quoted RHS and nocasematch disabled. */
  const char *conditional_expression;
  uint32_t conditional_expression_length;
  const char *conditional_operands[2];
  uint32_t conditional_operand_lengths[2];
  uint8_t conditional_operand_count; /* One for unary, two for comparison. */
  shell_conditional_predicate_t conditional_predicate;
  bool conditional_negated; /* Parity of lexical ! operators. */
  shell_conditional_truth_t conditional_truth;
  const char *arithmetic_expression; /* Borrowed content for ARITHMETIC. */
  uint32_t arithmetic_expression_length;
  shell_arithmetic_truth_t arithmetic_truth;
  bool
      has_redirections; /* Explicit setup for any kind, including unused copies.
                         */
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
  /* Bash `time` mode for this command's local syntactic pipeline, or
   * SHELL_PIPE_TIME_NONE. Timing applied to an enclosing compound is retained
   * on that GROUP node instead. */
  shell_pipeline_time_mode_t pipeline_time_mode;
  /* Stable ownership of the effective timing operation. Zero means none;
   * otherwise this is the owning TIME node index plus one. The biased form
   * keeps zero-initialized public graph values valid. */
  uint32_t pipeline_time_id;
  /* Static lexical CWD shared by all modeled paths reaching this expansion.
   * cd success installs its destination; pre-change failure preserves entry.
   * Reporting/physical failures may follow a directory change and join those
   * possibilities rather than claiming that nonzero status means no change.
   * Thus cd /path && command can be known, while cd /path; command joins both
   * outcomes. Argumentless cd can also report after CDPATH lookup of a relative
   * HOME; its failure does not prove entry CWD or PWD/OLDPWD unchanged.
   * Dynamic HOME/CDPATH/physical resolution remains unknown. The
   * offset is not an authoritative path unless cwd_known is true. */
  bool cwd_known;
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
  /* Effective timing mode for this compound's local syntactic pipeline. A
   * later compound member inherits the mode without becoming a direct timing
   * target; only an incoming TIME edge identifies the CMD/GROUP carrying the
   * reserved prefix. Enclosed CMD nodes keep their own local timing metadata.
   */
  shell_pipeline_time_mode_t pipeline_time_mode;
  /* Effective TIME owner, encoded as its node index plus one; zero means no
   * timing operation. Unlike the incoming TIME edge, this also associates
   * later syntactic pipeline members whose byte route may be redirected. */
  uint32_t pipeline_time_id;
} shell_dep_group_t;

/**
 * Dynamic substitution-stream collector.
 *
 * An ENDPOINT normally has incoming WRITE edges and outgoing SUBST edges.
 * The parser may also use internal endpoint forms: a terminal pipe whose
 * reader was replaced by a later redirect has only incoming PIPE edges, and
 * a process-substitution pipe can retain only readers or only writers.
 * Numeric reads use SUBST and writes use WRITE, including both for `<>`;
 * persistent/named descriptors retain FD_OPEN setup until a later use adds
 * byte flow. No edge invents a producer/consumer in the disconnected child.
 * Descriptor ownership is carried by those edges, avoiding a second, ambiguous
 * descriptor field on the endpoint itself. `reserved` is internal parser
 * state; callers must treat it as opaque.
 */
typedef struct {
  uint8_t reserved;
} shell_dep_endpoint_t;

/** Full-command I/O boundary resource. `number` is the original inherited
 * descriptor, not a mutable shell-local slot or an OS file identity. One node
 * is shared by all retained uses of that number, including recursive scopes.
 * READ/WRITE edges carry the local execution descriptor on their execution
 * side and SHELL_DEP_FD_NONE on this resource side. These are available routes,
 * not predictions that an executable actually reads or writes bytes. The
 * boundary is not an internal pipe, control relation, or substitution bridge.
 * Different inherited numbers are not presumed to name distinct OS objects.
 */
typedef struct {
  uint32_t number;
} shell_dep_fd_t;

/** Effective destination class for Bash's shell-owned timing report. */
typedef enum {
  /* The report leaves the command through a WRITE edge to an inherited FD
   * node. report_target_fd is that node's inherited descriptor number. */
  SHELL_TIME_REPORT_EXTERNAL = 0,
  /* One outgoing WRITE, APPEND, PIPE, or SUBST edge identifies an internal
   * destination (not an inherited FD boundary). */
  SHELL_TIME_REPORT_GRAPH,
  /* The effective report descriptor is closed. */
  SHELL_TIME_REPORT_CLOSED,
  /* The descriptor exists, but has no write-capable route (for example,
   * after `exec 2<input`), or the timing operation is provably unreachable
   * and produces no report. This is distinct from an explicit close. */
  SHELL_TIME_REPORT_UNAVAILABLE,
  /* The route could not be retained. Valid only on a truncated graph. */
  SHELL_TIME_REPORT_UNKNOWN,
  /* Two or more destinations or descriptor aliases are retained, including
   * runtime-dependent alternatives. Inspect
   * report_route_flags, report_external_fds, and every outgoing WRITE,
   * APPEND, PIPE, or SUBST report edge. */
  SHELL_TIME_REPORT_MULTIPLE,
} shell_dep_time_report_route_t;

typedef enum {
  SHELL_TIME_REPORT_ROUTE_NONE = 0,
  SHELL_TIME_REPORT_ROUTE_EXTERNAL = 1 << 0,
  SHELL_TIME_REPORT_ROUTE_GRAPH = 1 << 1,
  SHELL_TIME_REPORT_ROUTE_CLOSED = 1 << 2,
  SHELL_TIME_REPORT_ROUTE_UNAVAILABLE = 1 << 3,
  SHELL_TIME_REPORT_ROUTE_UNKNOWN = 1 << 4,
} shell_dep_time_report_route_flags_t;

/* Conditional descriptor lists can leave a timing report routed through more
 * than one inherited descriptor. This bounded public list is exact unless the
 * graph is marked truncated. */
#define SHELL_DEP_TIME_MAX_EXTERNAL_FDS 16

/** Bash `time` pipeline metadata. The source span covers the measured
 * pipeline (without requiring callers to reconstruct the reserved prefix).
 * Exactly one TIME edge targets the directly measured CMD or GROUP, whose
 * pipeline_time_mode equals mode. Every retained member of that syntactic
 * pipeline identifies this node through pipeline_time_id even when descriptor
 * redirection means there is no corresponding command-to-command PIPE edge.
 * A directly timed compound is owned by its GROUP node; flattened inner CMD
 * nodes retain only their own local timing and never inherit that direct TIME
 * edge.
 * Construction assigns that relation from the parser's pipeline ranges;
 * callers can validate its retained graph topology, but cannot reconstruct
 * source pipeline membership from routed edges alone.
 * The timing report is produced by the shell on report_fd. Its effective
 * destination is explicit. A deterministic destination retains the compact
 * report_route/report_target_fd summary. MULTIPLE uses report_route_flags,
 * every outgoing WRITE/APPEND/PIPE/SUBST edge, and report_external_fds to
 * retain all statically possible destinations. External list entries are
 * derived from retained WRITE-to-FD edges, not an alternative routing model.
 * CLOSED contributes a flag but
 * no edge.
 * CLOSED means an explicit close; UNAVAILABLE means the effective descriptor
 * lacks a write-capable route. UNKNOWN remains reserved for capacity
 * truncation. */
typedef struct {
  const char *start;
  uint32_t length;
  shell_pipeline_time_mode_t mode;
  uint32_t report_fd;
  uint32_t report_target_fd;
  shell_dep_time_report_route_t report_route;
  uint32_t report_route_flags;
  uint32_t report_external_fd_count;
  uint32_t report_external_fds[SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
} shell_dep_time_t;

/**
 * DOC node - a data artifact
 *
 * Fields are used according to kind:
 *   FILE:      path/path_len (source); RESOLVED_PATH uses value/value_len
 *              for the separately borrowed decoded pathname; IMPLICIT uses
 *              a library-owned immutable canonical path, not shell source
 *   HEREDOC:   name/name_len (borrowed delimiter display span),
 *              value/value_len (source content)
 *   HERESTRING: value/value_len (content; an expandable word can receive
 *               incoming SUBST edges before its READ edge supplies owner)
 *   ENVVAR:    name/name_len, value/value_len (borrowed assignment spelling;
 *              ENVVAR_APPEND distinguishes `+=` from `=`)
 *
 * Fields ordinarily borrow source spans. An internal expansion-aware graph's
 * RESOLVED_PATH value instead borrows its resolver's decoded payload for the
 * lifetime of that graph. IMPLICIT paths are library-owned and valid for the
 * graph lifetime; no resolver callback or quote removal applies to them.
 * Heredoc delimiter matching applies shell quote
 * removal, but `name` is not a decoded value: one enclosing homogeneous
 * `'...'` or `"..."` pair is elided for display, while mixed-quote,
 * backslash, and ANSI-C spellings retain their source span. Other `value`
 * fields preserve physical source bytes; for `<<-`, use
 * shell_dep_doc_content_length() and
 * shell_dep_doc_write_content() to obtain logical tab-stripped content. Source
 * line boundaries use LF; carriage returns remain significant in both
 * delimiter words and content bytes.
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
   * kinds and IMPLICIT absolute FILE documents leave these fields unused. */
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
    shell_dep_time_t time;
    shell_dep_fd_t fd;
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
 * A capacity stop may retain a consistent partial graph. If construction or
 * descriptor resolution cannot complete safely, counts and CWD storage length
 * are cleared instead; the status remains TRUNCATED, never ERROR.
 * On input or parse errors, writable output counts are cleared and
 * SHELL_DEP_STATUS_ERROR is set.
 *
 * The graph models simple-command lists, pipelines, and brace/subshell groups.
 * Bash's reserved `time` prefix produces one TIME node and structural TIME
 * edge to the measured pipeline root. `report_fd` identifies the shell-owned
 * timing report descriptor; a distinct WRITE, APPEND, PIPE, or substitution
 * edge records a concrete report route. Path-dependent routes use
 * SHELL_TIME_REPORT_MULTIPLE without discarding alternatives. The TIME edge
 * itself does not claim byte flow.
 * Proven unreachable stages retain syntax and structural relationships, but
 * have no effective assignment, descriptor setup, byte-flow, or substitution
 * effects. Runtime-unknown branches retain possible effects; this is not
 * runtime execution or general builtin evaluation. Unreachable timing nodes
 * retain their TIME topology with an unavailable report route. Malformed and
 * unsupported syntax is rejected even in unreachable stages.
 * Runtime-dependent redirect setup adds possible failure to a proved command
 * or compound outcome, never success before negation. A statically known
 * descriptor failure (including a statically empty filename) preserves
 * argument and assignment-value expansions,
 * which precede a simple command's redirects even when their words appear
 * later in the source. It also preserves earlier redirect operand expansions
 * and setup, but suppresses later redirect operands and the command or
 * compound body. A
 * compound's setup failure bypasses its negation and retains its entry
 * directory rather than a directory reached by its body; a simple command's
 * returning setup failure is negated normally.
 * An argv-less command normally returns its last executed substitution status
 * (success when none ran). Bash instead runs its redirect setup in a child
 * when any redirect targets fd 0 or a named FD, including self-duplication and
 * later redirects. Successful child setup returns success independently of
 * substitution status. Redirect expansion errors fail that child, while
 * assignment-value errors still affect the parent. Parent assignments remain
 * visible, but the child's descriptor allocations and changes do not persist.
 * Unquoted named-FD duplication operands follow the current shell's IFS.
 * A proved all-decimal separator set produces a known setup failure. Partial
 * or unresolved decimal splitting returns SHELL_DEP_EPARSE rather than
 * guessing a numeric descriptor. Double-quoted `$name` / `${name}` operands
 * bypass splitting and retain their ordinary binding contract. IFS changes
 * follow the same outcome and scope lifetime as descriptor bindings.
 * Bash descriptor moves (`n>&m-` / `n<&m-`) copy the binding as a whole and
 * close m only after successful duplication. Self-moves are no-ops, including
 * on a closed numeric descriptor. A trailing source dash outside a completed
 * quoted fragment selects move syntax (`3-`, `"3"-`, `3\\-`); a quoted
 * whole `"3-"` is instead an ordinary word, which is a legacy pathname for
 * bare `>&word` and a setup failure with an explicit destination descriptor.
 * Exact allocated-descriptor references such as `${fd}-` and `"$fd"-` are
 * supported; general runtime descriptor evaluation remains unsupported.
 * If known IFS splitting removes every digit from an unquoted reference,
 * its literal suffix yields `-` and closes the destination instead. Partial
 * or unresolved decimal splitting remains unsupported; quoted references
 * bypass splitting.
 * Numeric moves save their source close for restoration only if the
 * destination was already open. A newly allocated named destination also
 * saves it. Otherwise the source close survives an ordinary command or a
 * compound, and even a later redirect failure, unless an earlier temporary
 * redirect had already saved that source. Saved source closes are restored
 * even when a later redirect fails by copying that locally closed source.
 * Successful descriptor-only exec
 * keeps both effects. Named variables keep their value; their physical slot
 * is closed and may be reused. Setup uses existing FD_OPEN duplication and
 * FD_CLOSE edges, while byte-flow edges use the resulting effective routes.
 * Temporary undo runs in reverse registration order, restoring from each
 * live physical save and disposing it after successful restoration. Later
 * allocations, closes, or moves can reuse or overwrite those slots.
 * Descriptor-only exec discards ordinary undo but restores overwritten
 * shell-owned scratch descriptors. A failed restoration stops that undo list:
 * its target remains unchanged, and older saves remain live. This does not
 * change the command body's status or prevent independent enclosing scopes from
 * performing their own cleanup. Conditional named bindings retain their
 * associated physical/private slot and resource together; byte-flow
 * alternatives are united only after resolving each association in its own
 * execution version. A later redirect or redirect-operand substitution may
 * use a save created earlier in that setup; ordinary argument substitutions
 * run before setup and cannot see it. Direct external-command setup creates
 * no undo saves, but can use saves inherited from an active enclosing group.
 * Runtime dispatch retains separate builtin and external setup versions,
 * including each version's scratch allocations and setup failures. Argv-less
 * fd 0/named-FD setup likewise creates no undo saves in its child. Returning
 * outcomes and timing reports preserve these versions through publication;
 * ordinary argv expansions still precede both setup variants.
 * Failed setup uses ordinary numeric undo in current-shell setup, including on
 * descriptor-only exec. It reads the live saves from that reached prefix, so
 * a closed save can stop restoration and leave an earlier temporary route
 * installed. Timing reports exclude successful cleanup when setup never
 * reached the body. Byte-flow edges also include shell-owned setup/undo
 * diagnostics, including parameter/arithmetic expansion and known
 * readonly-assignment errors: their CMD/GROUP
 * owner and source fd 2 identify the stderr capability at the failure point,
 * before cleanup or later redirects. Such an edge does not imply that the
 * command body executed. Diagnostics can feed a substitution, pipe, file, or
 * inherited descriptor; closed/read-only stderr emits no bytes.
 * Argument/RHS expansion diagnostics use entry stderr; redirect operands and
 * expandable here-documents use stderr after preceding redirects, before the
 * current redirect and before cleanup. Expansion failure syntax retains a
 * possible diagnostic route without evaluating variable or arithmetic values.
 * Optimized `$(<word)` readers also retain possible open/read diagnostics,
 * even when pathname resolution removes their stdout content flow. Those
 * diagnostics use the enclosing expansion phase's stderr; the read failure
 * remains local to the substitution. Resolving a pathname does not prove I/O
 * success or remove these possible routes.
 * Assignment errors use pre-redirection stderr. A failing argv-less readonly
 * assignment prevents its redirects, while a readonly executable prefix may
 * still execute the command. Rejected temporary prefixes skip their RHS;
 * assignment-only and export forms expand it before rejection. Failed
 * assignments retain syntax but do not contribute effective ENV edges.
 * Dispatch depends on argv after expansion, not syntactic command words.
 * When every command word can disappear, both assignment-only and executable
 * alternatives remain possible: rejected RHS substitutions are retained only
 * on the former, without terminating the latter's continuation. A quoted empty
 * scalar word is an argv entry; an unquoted expansion or quoted "$@" can
 * instead produce no entries. Empty process fragments produce no pathname;
 * wholly unquoted empty-process words disappear before command/wrapper and
 * builtin-argument selection. Quoted name enumeration with * and defaulted
 * positional lists (-/:-) retain at least one entry. Quoted positional-list
 * error operators (?/:?) either retain an entry or abort expansion; an abort is
 * not an assignment-only dispatch. These presence proofs do not imply exactly
 * one argument or resolve command identity. Successful argv-less stages have no
 * default body streams; their explicit setup and pipeline connections remain
 * represented. Possible filesystem and implicit asynchronous-stdin open
 * failures retain diagnostic alternatives without asserting that the open
 * actually failed. Completed named allocations can survive a later setup
 * failure. Descriptor existence is tracked separately from read/write
 * capability: duplicating a live read-only FD succeeds even though subsequent
 * writes, including timing reports, are unavailable. CWD tracking follows
 * execution outcomes. A statically recognized current-shell cd is an ordinary
 * CMD node with a CWD edge, including through command/builtin wrappers;
 * callers need not reconstruct directory changes from its argv. Its words
 * and redirects use the incoming CWD, before its transition is committed:
 * unreachable transitions leave it unchanged. A conditional brace body tracks
 * its own executing-path directory; its continuation keeps a known CWD only
 * when paths reaching that continuation agree. Terminated paths do not
 * contribute; input-unit abort paths retain their directory when recovery
 * reaches a later complete input unit. A supported static absolute `cd` can
 * restore a known directory after an ambiguous or dynamic transition. No
 * filesystem success is inferred beyond the existing lexical cd model.
 * Subshells, background stages, pipelines and substitutions never export CWD
 * changes. Skipped descriptor-duplication operands retain nested substitution
 * syntax without inventing a FILE resource or an effective
 * descriptor/substitution edge. Active runtime-expanded duplication targets
 * remain unsupported. Control compounds (including function declarations,
 * `select`, and `coproc`), shell-semantic array forms (including array element
 * targets), and unmodeled current-shell forms (`mapfile`/`readarray`, `wait
 * -p`, Readline-enabled `read -e`/`-E`, and mutating arithmetic expansions)
 * return SHELL_DEP_EPARSE, as do
 * active parameter-assignment operators (=/:=), prompt transformations
 * (`${value@P}`), and actual indirect dereferences (`${!ref}`). These can
 * mutate bindings or evaluate value data as shell syntax without a modeled
 * runtime source. Ordinary expansion and prefix-name enumeration do not
 * perform that re-evaluation and remain supported. The same rejection applies
 * to `test`/`[` -v array-variable lookups and unresolved lookup operands or
 * expression roles. Quoting such a target does not disable its subscript
 * evaluation. Static scalar queries and non-evaluating string/file predicates
 * remain supported; expression argument cardinality must be known.
 * Declaration operands recognize assignments after quote removal and empty
 * process-fragment elision. Scalar writes invalidate the same named bindings
 * as plain spellings; integer/protected/readonly restrictions still apply.
 * ENVVAR names retain their raw spans and decode through the name accessors.
 * This does not change lexical command-prefix assignment recognition.
 * A successful whole-variable unset of a resettable predefined Bash getter,
 * integer, or array is retained in the path-local execution journal. Later
 * writes in that shell and its descendants are ordinary scalar writes.
 * Command, backtick, and process substitutions inherit the path's capability
 * mask, separately from physical descriptor imports. Child-local changes do
 * not publish into their parent. A
 * conditional unset, a child-shell unset observed from its parent, or a join
 * which can retain the original predefined binding does not establish that
 * proof. Automatically recreated, unset-rejected, readonly, and executor-
 * frozen variables never acquire it. This is shell-state semantics, not a
 * source-only tokenizer decision.
 * `getopts` likewise rejects integer/protected or runtime-expanded destinations
 * and unknown operand cardinality before its target. Quoted runtime optstrings
 * must leave every possible target position safe (including an expanded --).
 * Ordinary scalar destinations and static invalid-target error paths remain
 * supported. These checks belong to the shared source-semantics boundary, not
 * descriptor-route validation.
 * Unmodeled Bash `[[ …
 * ]]`,
 * dynamic or mutating arithmetic commands, `$"…"`, and `;&` / `;;&` forms
 * are also rejected. Surviving
 * non-ASCII ANSI-C Unicode escapes are also rejected because their bytes
 * depend on an unmodeled execution locale. Escapes discarded after a decoded
 * NUL do not contribute a locale requirement. ASCII Unicode escapes and byte
 * escapes remain supported.
 * Active legacy backtick bodies requiring Bash's escape-layer removal return
 * SHELL_DEP_EPARSE: raw borrowed spans cannot model their decoded nested
 * source. This covers escapes before $, backticks, backslashes, and newlines,
 * plus double quotes under enclosing double quoting. Ordinary backticks and
 * escapes whose slash survives into the nested shell remain supported; quoted
 * literal backticks are data. Use $(...) for nested substitutions without this
 * layer.
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
 * installs a pipe descriptor and retains the nested graph. It establishes no
 * byte transfer between those peers: they share a resource with two readers
 * or two writers. `<>` installs both read and write capabilities on the same
 * ENDPOINT, independently of which side the nested command exposes. Its
 * default descriptor is fd 0. Every installation replaces the previous
 * descriptor, including cross-direction pairs and disconnected child streams.
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
 * heredoc and here-string documents likewise retain their FD_OPEN setup,
 * including input installed but not consumed by a modelled builtin. An
 * expandable document retains its setup-time SUBST flow as well.
 *
 * Bash named descriptors (`{name}>file`) retain the bare descriptor name on
 * their FD_OPEN, FD_CLOSE, and affected routing edges. A whole redirection
 * operand `$name` or `${name}` may reuse that descriptor. Their names use the
 * same source normalization as parsing: only backslash-LF is erased. CR stays
 * significant, including before LF, so it cannot join an identifier across a
 * physical line. General parameter expansion is intentionally not interpreted
 * as a descriptor reference. An unknown, closed, reassigned, or syntactically
 * composite named reference is an error rather than a guessed route, except
 * that a proven physical self-duplication/move is a no-op even on a closed
 * slot. Its variable binding must still be established and unchanged. With
 * Bash's default `varredir_close` behavior, a current-shell builtin and a
 * non-isolated brace-group redirect tail retain an open named binding in that
 * shell. External-command redirects run in a child: neither named allocations
 * nor unsaved move-source closes change its parent. Static dispatch uses the
 * default Bash builtin set and the effective command/builtin wrapper;
 * unresolved dispatch retains both compatible execution scopes. A reached
 * builtin wrapper fixes current-shell redirect setup even when an inner command
 * wrapper selects an external executable. Rebinding a descriptor variable does
 * not close its earlier allocations; their physical slots remain available to
 * numeric uses. Temporary redirects restore the state at their first
 * modification, including allocations made earlier in the same setup list.
 * Redirect-only and assignment-only commands do not retain named allocations.
 * Subshell groups and groups executing as a pipeline member or background job
 * retain bindings only in their private execution scope. A local
 * pipeline/background command never publishes its mutations into an enclosing
 * private group. A conditional unset or reassignment invalidates the binding
 * proof for later unconditional uses; an explicit reallocation in the same
 * lexical group or after returning to an enclosing group establishes a new
 * binding. Reallocation of an orphaned descriptor variable only after entering
 * a deeper compound is rejected until its physical-slot alternatives can remain
 * correlated across that boundary. Repeated unsets do not close the orphaned
 * physical descriptor or change the scope where it was orphaned; only a
 * successful supported reallocation clears that state. Leading assignments on a
 * command are temporary: they do not replace a visible descriptor-variable
 * binding while that command's redirects or nested substitutions expand.
 * Opening a named file/document route first consumes Bash's lowest free
 * descriptor for the resource, then allocates the retained named descriptor
 * at or above fd 10. Consequently, a temporarily closed fd 10 is reused by
 * the named descriptor only when some lower descriptor can hold the resource;
 * runtime-dependent inherited low-descriptor occupancy is retained as route
 * alternatives. Named duplication needs no temporary resource descriptor.
 * Assignment-only scalar names follow shell lexical spelling, so `f\\\nd=value`
 * and `fd+=value` still identify `fd`. A non-`exec` close is local, whereas
 * `exec` persists a close. Commands that mutate shell option state through
 * `set` or `shopt`, or statically recognized
 * current-shell metaprogramming builtins (`eval`, `.`, `source`, `trap`,
 * `alias`, `unalias`, `fc`, `let`, `enable`, `compgen`, `complete`, `compopt`,
 * and `bind`), are rejected as unsupported,
 * so this lifetime and pipeline-scope invariant is never silently changed. The
 * executor is the pinned Bash 5.3.20 reference, not an arbitrary Bash version,
 * and must start in the documented clean noninteractive state. Start
 * it with `POSIXLY_CORRECT` absent (not merely empty), clear `BASH_COMPAT` and
 * `BASH_XTRACEFD`, then make all three variables readonly before evaluating
 * submitted source. Set LC_ALL to C/POSIX or an installed UTF-8 locale before
 * launching Bash and make it readonly in trusted startup. The parser uses
 * byte-oriented syntax under this fixed contract, independently of the
 * embedding application's locale. Analysis does not change that locale.
 * `bash -p -c ...` is the
 * supported basis: privileged mode ignores `BASH_ENV`, `BASHOPTS`, and
 * `SHELLOPTS`, and declines imported shell functions that could shadow a
 * modelled builtin such as `exec`. An equivalent launcher must establish the
 * same option and command-lookup state before source validation, including
 * nocasematch disabled, no
 * startup aliases or traps, no disabled or shadowed modelled builtins, and a
 * frozen `POSIXLY_CORRECT`, `BASH_COMPAT`, `BASH_XTRACEFD`, and `LC_ALL`. A
 * runtime-expanded command word is
 * intentionally not promoted to one of these builtin roles.
 * Completion and Readline can expand input data as shell source or execute
 * registered callbacks even in a fresh noninteractive shell with terminal
 * input. Ordinary `read` remains supported; e/E bytes used as option operands
 * or variable names are not Readline selectors. Their effective roles are
 * validated against captured entry values after redirect setup, not a union
 * of all syntactically possible roles. Earlier option/descriptor failures
 * terminate that path before later selectors can activate.
 * Recursive analysis inherits known-empty scalar facts independently of
 * descriptor routing, including variables which have never named an FD.
 * Builtin `read` uses only its selected readable input: fd 0 by default, or
 * the last valid `-u` operand, validated in option order after redirect setup.
 * Static decimal operands and exact tracked `$fd`/`${fd}` references are
 * supported (including attached and quoted forms). Named argument values are
 * captured before redirects can reallocate their variables. Assignment RHS
 * substitutions see preceding prefix assignments, including temporary ones;
 * ordinary argv expands before those temporary assignments. Bash redirection
 * expansion and IFS splitting retain the separate shell binding table.
 * Unquoted names
 * require incoming IFS not to split digits. Other runtime descriptor values
 * are unsupported, not ordinary-data resolver requests. Timeout-zero polling,
 * zero character counts, and pre-input validation failures have no byte READ.
 * Unknown numeric count/timeout operands also retain early invalid-number
 * failures; later options cannot repair them or add descriptor proofs to them.
 * Invalid literal identifier prefixes survive dynamic target expansions;
 * captured-empty values also refine invalid suffixes. An invalid first target
 * fails before input, later errors retain only earlier assignments, and
 * timeout-zero polling bypasses target validation.
 * Whole-word and attached signed scalar operands retain separate numeric
 * facts; known allocation digits with a minus sign fail before input. Integer
 * leading zeroes preserve that sign and exact descriptor identity; a captured
 * empty fragment leaves the literal numeric operand, published with its
 * numeric FD rather than the empty variable's name. Negative
 * nonzero integer prefixes also prove failure across unknown suffixes. Invalid
 * integer literal suffixes prove failure for a single argument too; timeouts
 * and unresolved splitting do not share that deletion-closed rule. A
 * completed timeout conversion (six fractional digits plus the seventh
 * character's rounding decision) retains its result across later fragments;
 * incomplete/general concatenations retain unknown wrapping/rounding behavior.
 * An expansion ends leading-tilde recognition. Single-argument target proofs
 * recognize scalar identifiers and a conservative NAME[...] envelope; invalid
 * literal suffixes cannot be repaired by an opaque fragment. A process path
 * can occur inside a dynamically formed subscript, so '/' alone does not prove
 * failure. Explicit array targets remain unsupported. Unquoted splitting and
 * list expansion do not establish a single-target proof.
 * Their child effects remain visible even when read fails. Pathnames used as
 * prompt/delimiter data are not target errors. Known-empty scalar
 * fragments select their prepared literal target identity, not an arbitrary
 * variable write. Arithmetic targets are unsupported only if assignment is
 * reachable after option and descriptor validation.
 * Every reached -u validates existence and refines its continuation; failure
 * from EOF, polling, targets or later options is not a proof of absence.
 * Temporary redirects are restored before returning those facts. Private
 * scopes may return observations of unchanged inherited descriptors, never
 * evidence derived from child-installed pipes or descriptors.
 * This includes synchronous command/backtick substitutions: their predicates
 * retain imported argument value classes and allocation identity, paired with
 * their returning status even on failures before FD validation. Child capture
 * pipes cannot prove parent descriptor availability. Named dependencies are
 * captured lazily from immutable imported-entry anchors and memoized per
 * version/role, including unknowns; child entry does not scan sibling names.
 * Conditional substitutions keep a skipped path with its prior status. All
 * substitutions within one conditional operand share its decision; nested
 * operands cannot execute on a skipped parent. Descriptor proofs use immutable
 * imported facts and branch-local changes, never a representative routing
 * table. Ordinary and file-optimized substitutions supersede status without
 * erasing earlier observations. Empty or blank substitutions (space, tab, LF
 * and erased backslash-LF continuations), and comment-only $(), preserve the
 * current command's preceding substitution status; comment-only backticks
 * return success. A new assignment-only command starts with success, not the
 * previous command's status. Success of an ordinary enclosing executable does
 * not imply that a substitution succeeded. Comments end at LF; CR, VT and FF
 * outside comments are not blank. Nonblank bodies which cannot produce retained
 * commands are rejected, never modeled as empty success. Numeric argument
 * captures and phase status are command-local; deferred I/O retains its
 * pre-cleanup immutable snapshot. Exported predicates are interned by complete
 * meaning, not by status alone. Nonmutating executables without descriptor
 * setup discard private substitution outcome distinctions at their continuation
 * boundary. Read target/REPLY/IFS writes remain paired with the paths that
 * assign them; a successful poll does not inherit writes from a failing
 * nonpolling path. Unused input redirects retain setup, not consumption;
 * process-input SUBST is ordinary I/O without SUBST_SHELL_WORD. Temporary high
 * descriptor saves remain observable when explicitly selected with `-u`.
 * Conditional parameter operands retain creation and no-creation alternatives
 * for their process-substitution descriptors. Substitutions in one operand
 * share its execution decision, and nested operands respect their parent.
 * Unobserved temporary descriptors retain graph effects without enumerating
 * independent guard combinations. Descriptor observation is scoped to the
 * command/compound lifetime, including nested uses and escaping aliases. Timing
 * alone does not require physical identities. Incoming standard-FD occupancy
 * uses the actual phase snapshot, including scope restoration and reopening;
 * historical closes outside this lifetime do not enable tracking. Symbolic
 * occupancy preserves the first-two-free and high-slot-search conditions for
 * moved and retained pipe ends, without enumerating inherited descriptor tables
 * or increasing pressure for unrelated source lifetimes. Named allocations and
 * temporary descriptor saves retain the same joint constraints, including
 * low-slot availability. Existence observations restrict a version;
 * opens/closes change it. Private allocation selectors preserve named/save/pipe
 * identities in fd 0..63 through closes, reuse, undo, and recursive imports,
 * without a separate version per hidden numeric choice. Named variables retain
 * their selected numeric value after close. The existing conservative
 * observed/private tail model applies above that range. Imported aliases of one
 * selected descriptor share one child-local slot; closing either alias affects
 * both in that child, not its parent bindings. Child reads can still advance
 * shared open-file descriptions. The graph models possible provenance, not byte
 * availability or predicted EOF. Cleanup releases the selected descriptor;
 * explicit descriptor changes remain. Descriptor-sensitive builtin outcomes
 * keep their selected versions through connectors, even when the builtin has no
 * redirects. Private pipeline/group outcomes select their own parent-entry
 * alternatives without publishing child mutations. Forking a compound closes
 * the invoking shell's original process-substitution ends; the child inherits
 * those FDs, and explicit duplicates survive the parent's cleanup. Later
 * pipeline stages inherit that post-cleanup parent table, not the preceding
 * child's mutations. Process expansions inside parameter words likewise
 * preserve original-pipe fallback onto a closed standard stream.
 * Empty/comment-only process substitutions create no pathname: inside
 * $(<word) they produce execution failure, not a parse error or a pipe.
 * Captured values can resolve competing option/FD roles which source-only
 * consumers conservatively reject, and identify invalid numeric/empty targets
 * even after `--`. Invalid first targets fail before input; invalid later
 * targets retain possible input and preceding writes, then fail. Timeout-zero
 * classification includes Bash's whole-part wrapping and validated conversion
 * to unsigned seconds.
 * Stable scalar unsets can establish empty captured values. Automatically
 * updated variables such as $_ retain unknown captures, even after unset:
 * `unset _; : 1; read -n"$_" value <<<payload` must retain possible input.
 * Bulk scalar writes invalidate named bindings in each immutable execution
 * version, not physical descriptors. Prepared temporary-prefix exclusions and
 * setup-failure restoration preserve their own incoming bindings; no global
 * observation-inventory or mutation-history scan is required per write.
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
 * redirects in that list. Known setup failure suppresses later redirect
 * expansion effects, including parameter/arithmetic failures without a nested
 * command substitution; it does not suppress earlier argv/RHS expansions.
 * Conditional read/write route alternatives retain
 * their original resources across these recursive snapshots, including the
 * path-local close-on-exec property of active saved descriptors. Child-shell
 * exec overwrite/close operations use that inherited lifetime, not merely
 * the saved bytes' provenance. Byte-flow uses
 * are emitted only from the final effective descriptor state, not from
 * aliases subsequently replaced or closed; earlier input redirects can still
 * feed a substitution evaluated in a later operand. Recursive joins reserve
 * those imported edges before copying child topology, and return truncation
 * when the bounded capacity is exhausted. Builtins that may rewrite descriptor
 * variables do so after their own redirects have expanded and taken effect;
 * their mutations invalidate affected bindings for later commands, or every
 * named binding when the target is dynamic. An assignment-only command can
 * instead change a descriptor variable before expanding its redirect operand.
 *
 * Subshell extraction tracks simple single/double quotes and odd/even
 * backslash escapes while finding delimiters. It is not a complete shell
 * grammar; malformed structures are rejected instead of being represented as
 * a partial graph. For valid input that reaches descriptor-route resolution,
 * `limits` must provide the caller-owned workspace described by
 * shell_dep_limits_t; otherwise this returns SHELL_DEP_EWORKSPACE with `out`
 * cleared. `initial_cwd` is a borrowed NUL-terminated path; NULL selects
 * `"."`. Borrowed inputs and limits must remain alive and unchanged throughout
 * the call. They must not overlap `out` or the workspace, and those two
 * writable objects must not overlap each other. Violating these storage
 * preconditions is invalid API use and is not checked at runtime.
 * Parsing errors that are detected before route resolution do not require
 * workspace.
 */
shell_dep_error_t
shell_dep_graph_parse(const char *cmd, size_t cmd_len, const char *initial_cwd,
                      const shell_dep_limits_t *limits, shell_dep_graph_t *out)
    SHELL_NONNULL(1, 5);

/* Build from the unchanged strict result of shell_parse_fast(), or the
 * qualified prefix result of shell_parse_draft(). cmd and cmd_len must be
 * exactly the immutable source span described by fast. Supplying different
 * source bytes or edited metadata is invalid API use; no correspondence
 * check or second fast parse is performed. Successful supplied results also
 * establish byte admission, which graph construction does not repeat. Error
 * and truncated results retain their ordinary handling; truncation alone
 * does not establish byte admission. Graph construction still checks
 * supported semantics and its resource limits. Borrowed source must outlive
 * the graph, and fast and out must be distinct. NULL fast requests ordinary
 * shell_dep_graph_parse() behavior. Other source/workspace contracts above
 * apply, including error and truncation handling. */
shell_dep_error_t shell_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out) SHELL_NONNULL(1, 6);

/* Size the caller workspace for graph construction with word resolution.
 * Uses shell_dep_workspace_alignment(). NULL limits selects defaults. Returns
 * false and clears size on arithmetic overflow; no source bytes are inspected.
 * The extra reservation includes bounded metadata, a source-offset index and
 * shell_source_workspace_size() bytes for delimiter preparation in that buffer.
 * Source and expansion payloads otherwise remain borrowed. */
bool shell_dep_resolved_workspace_size(size_t command_length,
                                       const shell_dep_limits_t *limits,
                                       size_t *workspace_size) SHELL_NONNULL(3);

/* Construct a graph using application-supplied canonical whole-word values.
 * The ordinary graph source/CWD/limits/output contracts apply. Workspace must
 * meet shell_dep_resolved_workspace_size(), including with a NULL callback
 * (which leaves dynamic words unresolved). context is optional application
 * state. Each eligible dynamic source word is queried at most once, in analysis
 * order, not runtime scheduling order. Source syntax is validated before any
 * callback; callback effects themselves cannot be rolled back.
 *
 * Callback payloads are borrowed by resolved FILE documents: keep them alive
 * and immutable for the graph lifetime, not just until this function returns.
 * No expansion is executed or reparsed as shell source. SUBST inspection
 * obligations are retained. Malformed/failed values return SHELL_DEP_EEXPAND
 * with an empty error graph. Truncation retains normal partial-graph handling.
 *
 * Optional unresolved_paths references SHELL_DEP_MAX_NODES writable bytes,
 * distinct from inputs, output and workspace. It receives one flag per retained
 * node for unresolved active pathname expansion, including removed byte-flow
 * edges. Unused bytes and all flags on errors are zero. */
shell_dep_error_t shell_dep_graph_parse_resolved(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, shell_dep_graph_t *out,
    shell_expand_word_netargv_fn expand, void *context,
    uint8_t *unresolved_paths) SHELL_NONNULL(1, 5);

const char *shell_dep_edge_type_name(shell_dep_edge_type_t type);
const char *shell_dep_node_type_name(shell_dep_node_type_t type);
const char *shell_dep_doc_kind_name(shell_dep_doc_kind_t kind);

/** Measure document content without allocating. Heredoc spans include every
 * body byte before the closing delimiter line, including the final LF when
 * present. For a literal heredoc this is its exact payload; `<<-` removes
 * leading tabs from each body line. Expandable bodies remain unevaluated
 * source templates, not claims about expanded runtime bytes. Empty bodies
 * have zero length; carriage returns are never normalized. */
bool shell_dep_doc_content_length(const shell_dep_doc_t *doc,
                                  size_t *content_length) SHELL_NONNULL(1, 2);

/** Write the logical value bytes of a document into caller storage. Measure
 * first; on failure `written` is zero and no partial content is exposed. A
 * NULL destination is accepted only for empty logical content. The destination
 * must not overlap the document's borrowed value span; this caller precondition
 * is not checked at runtime. */
bool shell_dep_doc_write_content(const shell_dep_doc_t *doc, char *destination,
                                 size_t destination_size, size_t *written)
    SHELL_NONNULL(1, 4);

/** Measure or write an ENVVAR document's quote-removed identifier. The write
 * API is failure-atomic and does not add a NUL terminator. Other document
 * kinds and malformed assignment spans are rejected. The destination must not
 * overlap the borrowed assignment word, including its value; this caller
 * precondition is not checked at runtime. */
bool shell_dep_doc_env_name_length(const shell_dep_doc_t *doc,
                                   size_t *name_length) SHELL_NONNULL(1, 2);
bool shell_dep_doc_write_env_name(const shell_dep_doc_t *doc, char *destination,
                                  size_t destination_size, size_t *written)
    SHELL_NONNULL(1, 2, 4);
/** Compare an ENVVAR document's logical identifier without materializing it. */
bool shell_dep_doc_env_name_equals(const shell_dep_doc_t *doc, const char *name,
                                   size_t name_length) SHELL_NONNULL(1, 2);

/** Write a static FILE document's lexical path identity into caller storage.
 * The result combines the document's recorded execution CWD with its decoded
 * path, then removes redundant separators and single-dot components. Parent
 * components remain lexical: collapsing `link/..` would be unsound when
 * `link` is a symlink. It does not resolve symlinks or inspect the filesystem.
 * The document's dynamic-path classification is authoritative. Unresolved or
 * failed expansions and relative paths with an unknown CWD return false;
 * callback-resolved paths use their decoded value without reinterpreting it as
 * shell syntax. `absolute` distinguishes an actual
 * absolute identity from one rooted at a relative initial CWD; compare it
 * along with the output bytes. `written` excludes the trailing NUL. On
 * failure outputs are cleared and the destination is unchanged.
 * The caller supplies consistent graph/document metadata: when cwd_known is
 * true, cwd_offset references an installed, complete NUL-terminated entry in
 * the graph's CWD pool. Metadata and source spans remain immutable during
 * the call; destination and outputs must not overlap their storage. This
 * function tests path availability and output capacity, not graph integrity.
 * Use shell_dep_graph_validate() if validating an externally supplied graph. */
bool shell_dep_doc_file_identity_write(const shell_dep_graph_t *graph,
                                       const shell_dep_doc_t *doc,
                                       char *destination,
                                       size_t destination_size, size_t *written,
                                       bool *absolute)
    SHELL_NONNULL(1, 2, 3, 5, 6);

/**
 * Dump graph to FILE* for debugging.
 */
void shell_dep_graph_dump(const shell_dep_graph_t *g, FILE *fp)
    SHELL_NONNULL(1, 2);

/**
 * Validate graph integrity:
 * - Node, edge, command-token, and CWD-pool counts fit their fixed storage
 * - All edge from/to within node_count bounds
 * - Node and edge types, containment parentage, directions, and descriptor
 *   fields consistent with their documented graph roles
 *   (PIPE/SEQ/AND/OR require CMD/GROUP endpoints; SUBST additionally permits
 *    ENDPOINT and DOC(FILE) sources and DOC(HEREDOC/HERESTRING) targets; READ
 * requires DOC→CMD/GROUP, WRITE/APPEND require an execution endpoint→DOC or
 * ENDPOINT, ENV requires DOC→CMD, ARG requires CMD↔DOC(FILE); FD_OPEN is a
 * forward setup binding: execution→DOC for output, DOC→execution for input,
 * execution→ENDPOINT for process-substitution output, or
 * execution/ENDPOINT→execution for descriptor routing. An internal retained
 * process-substitution endpoint may have only FD_OPEN setup, or one-sided
 * numeric SUBST/WRITE uses, without a connected child stream. It also permits a
 * same-owner execution descriptor duplication. FD_CLOSE is a same-owner
 * CMD/GROUP setup transition with a source descriptor and no target; TIME is
 * a descriptor-free structural edge from one TIME node to the directly timed
 * CMD/GROUP endpoint. A TIME node may additionally originate WRITE/APPEND to a
 * DOC/ENDPOINT, PIPE to a CMD/GROUP/ENDPOINT, or SUBST to a substitution
 * consumer for its shell-owned report.
 * Effective timing owners must identify that TIME node; only a graph marked
 * truncated may retain timed metadata without its owner or report route.
 * CMD/GROUP pipeline_negated must equal the parity of pipeline_negation_count,
 * including in a truncated graph. SEQ, AND, OR, PIPE, BACKGROUND, and GROUP
 * edges together form an acyclic control/containment topology.
 * This is the validation boundary for malformed numeric graph metadata; the
 * graph itself must address valid shell_dep_graph_t storage. It does not prove
 * that retained source pointers address readable spans: source-storage sizes
 * and lifetimes remain caller preconditions for graph consumers.
 * This public validator checks graph topology. Exact membership of every
 * later pipeline stage is source grammar, not recoverable from PIPE edges
 * after descriptor routing. Construction derives that membership from the
 * parser-produced ranges; an unchanged parse and its matching immutable
 * source are caller preconditions, not independently revalidated input.
 */
shell_dep_graph_validation_t
shell_dep_graph_validate(const shell_dep_graph_t *g) SHELL_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_DEPGRAPH_H */
