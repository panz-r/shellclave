#ifndef SHELL_TOKENIZER_H
#define SHELL_TOKENIZER_H

#include "shell_contract.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fast shell parser: zero-copy ranges in a fixed-size result. It performs no
 * dynamic allocation. See shell_tokenizer_full.h for allocating tokenization.
 */

/* --- CONSTANTS AND LIMITS --- */

#define SHELL_MAX_SUBCOMMANDS 64 // Default max subcommands
#define SHELL_MAX_GROUPS SHELL_MAX_SUBCOMMANDS

/* --- TYPE DEFINITIONS --- */

/**
 * Return codes
 */
typedef enum {
  SHELL_OK = 0,      // Success
  SHELL_EINPUT = -1, // Invalid input
  SHELL_ETRUNC = -2, // Truncated - caller should use fallback
  SHELL_EPARSE = -3, // Parse error
} shell_error_t;

/**
 * Status flags (returned in shell_parse_result_t.status)
 */
typedef enum {
  SHELL_STATUS_OK = 0,
  SHELL_STATUS_TRUNCATED = 1 << 0, // Limits exceeded, use fallback
  SHELL_STATUS_ERROR = 1 << 1,     // Parse error
} shell_status_t;

/* Command form is independent of the preceding connector. GROUP describes
 * container headers; flattened records use SIMPLE, ARITHMETIC or CONDITIONAL.
 */
typedef enum {
  SHELL_COMMAND_SIMPLE = 0,
  SHELL_COMMAND_GROUP,
  SHELL_COMMAND_ARITHMETIC,
  SHELL_COMMAND_CONDITIONAL,
} shell_command_kind_t;

/* Normalized conditional predicate. Bare words use STRING_NONEMPTY; = and ==
 * share STRING_EQUAL for literal RHSs. Active static stars use PATTERN_MATCH
 * or PATTERN_NOT_MATCH. VARIABLE_SET queries a statically named scalar; an
 * empty assigned value is set. Lexical ! parity is represented separately. */
typedef enum {
  SHELL_CONDITIONAL_PREDICATE_NONE = 0,
  SHELL_CONDITIONAL_STRING_NONEMPTY,
  SHELL_CONDITIONAL_STRING_EMPTY,
  SHELL_CONDITIONAL_STRING_EQUAL,
  SHELL_CONDITIONAL_STRING_NOT_EQUAL,
  SHELL_CONDITIONAL_PATTERN_MATCH,
  SHELL_CONDITIONAL_PATTERN_NOT_MATCH,
  SHELL_CONDITIONAL_VARIABLE_SET, /* Static scalar-name presence lookup. */
  /* Filesystem predicates depend on runtime filesystem state. Symlink is the
   * common normalized predicate for Bash's -L and -h spellings; -e and
   * -a both use FILE_EXISTS. NONEMPTY tests size greater than zero. Access
   * predicates use effective identity; EXECUTABLE includes directory search.
   * OWNED_BY_USER/GROUP compare effective UID/GID. MODIFIED_SINCE_READ tests
   * modification time greater than access time, including subsecond fields.
   * All predicates except SYMLINK follow symbolic links. Nonempty paths have
   * unknown truth; the library does not query the host filesystem. */
  SHELL_CONDITIONAL_FILE_EXISTS,
  SHELL_CONDITIONAL_FILE_REGULAR,
  SHELL_CONDITIONAL_FILE_DIRECTORY,
  SHELL_CONDITIONAL_FILE_SYMLINK,
  SHELL_CONDITIONAL_FILE_NONEMPTY,
  SHELL_CONDITIONAL_FILE_BLOCK,
  SHELL_CONDITIONAL_FILE_CHARACTER,
  SHELL_CONDITIONAL_FILE_FIFO,
  SHELL_CONDITIONAL_FILE_SOCKET,
  SHELL_CONDITIONAL_FILE_READABLE,
  SHELL_CONDITIONAL_FILE_WRITABLE,
  SHELL_CONDITIONAL_FILE_EXECUTABLE,
  SHELL_CONDITIONAL_FILE_SETUID,
  SHELL_CONDITIONAL_FILE_SETGID,
  SHELL_CONDITIONAL_FILE_STICKY,
  SHELL_CONDITIONAL_FILE_OWNED_BY_USER,
  SHELL_CONDITIONAL_FILE_OWNED_BY_GROUP,
  SHELL_CONDITIONAL_FILE_MODIFIED_SINCE_READ,
} shell_conditional_predicate_t;

/**
 * Subcommand type - the operator or structural marker associated with this
 * subcommand. These are a mutually exclusive token-type field; callers that
 * need auxiliary properties must use the separate shell_cmd_features_t field
 * rather than OR-ing feature bits into a type value.
 */
typedef enum {
  SHELL_TYPE_SIMPLE = 0,             // Single command, no separator
  SHELL_TYPE_PIPELINE = 1 << 8,      // Preceded by literal | or |&
  SHELL_TYPE_AND = 1 << 9,           // Preceded by &&
  SHELL_TYPE_OR = 1 << 10,           // Preceded by ||
  SHELL_TYPE_SEMICOLON = 1 << 11,    // Preceded by ;
  SHELL_TYPE_HEREDOC = 1 << 12,      // Starts with << (heredoc)
  SHELL_TYPE_HERESTRING = 1 << 13,   // Starts with <<< (here-string)
  SHELL_TYPE_SUBSTITUTION = 1 << 14, // Command/process substitution operator
  SHELL_TYPE_BACKGROUND = 1 << 15,   // Preceded by a background '&'
} shell_cmd_type_t;

/* The byte streams connected by a pipeline operator. A range not preceded by
 * a pipeline uses NONE; a range following `|` or `|&` records that connector's
 * mode, including a document-only heredoc or here-string range. */
typedef enum {
  SHELL_PIPE_MODE_NONE = 0,
  SHELL_PIPE_MODE_STDOUT,
  SHELL_PIPE_MODE_STDOUT_AND_STDERR,
} shell_pipe_mode_t;

/* Effective formatting selected by Bash's reserved `time` pipeline prefix. */
typedef enum {
  SHELL_PIPE_TIME_NONE = 0,
  SHELL_PIPE_TIME_DEFAULT,
  SHELL_PIPE_TIME_POSIX,
} shell_pipeline_time_mode_t;

/* Orthogonal syntactic modifiers. Unlike shell_cmd_type_t these describe the
 * complete command/pipeline rather than the separator before one range. */
typedef enum {
  SHELL_CMD_MOD_NONE = 0,
  SHELL_CMD_MOD_PIPE_NEGATED = 1 << 0, /* POSIX `! pipeline` */
  SHELL_CMD_MOD_PIPE_TIMED = 1 << 1,   /* Bash `time pipeline` */
} shell_cmd_modifier_t;

/* Kinds of enclosing command groups. Values are a bitset so mixed nesting is
 * represented without losing an outer subshell boundary. */
typedef enum {
  SHELL_GROUP_NONE = 0,
  SHELL_GROUP_BRACE = 1 << 0,
  SHELL_GROUP_SUBSHELL = 1 << 1,
} shell_group_kind_t;

/**
 * Subcommand features - what's inside the subcommand.
 * Control flags recognize complete unquoted lexical words, including words
 * inside executable substitutions. Quotes, escapes and adjacent fragments
 * prevent a match; physical backslash-LF continuations are removed. Comments,
 * redirect operands and literal expansion/document data do not contribute
 * control words. These flags do not establish a complete control-flow grammar
 * or semantic support; standalone keyword spellings remain lexical markers
 * even in ordinary argument positions.
 * Arithmetic commands and expansions use arithmetic syntax for their bodies.
 * Conditional operands suppress pathname expansion and control-word roles.
 * Ordinary operand glob detection is suppressed; supported active RHS stars
 * set SHELL_FEAT_GLOBS for conditional pattern matching. Executable children
 * establish their own shell-command feature context.
 * Extglob alternatives are pattern data; active expansions within them still
 * contribute their feature bits, including nested executable-child features.
 */
typedef enum {
  SHELL_FEAT_NONE = 0,
  SHELL_FEAT_VARS = 1 << 0,             // $VAR, ${VAR}, $1, etc.
  SHELL_FEAT_GLOBS = 1 << 1,            // *, ?, [abc]; conditional RHS *
  SHELL_FEAT_SUBSHELL = 1 << 2,         // $(...), `...`
  SHELL_FEAT_ARITH = 1 << 3,            // $((...)) and ((...))
  SHELL_FEAT_HEREDOC = 1 << 4,          // << delimiter (in subcommand)
  SHELL_FEAT_HERESTRING = 1 << 5,       // <<< here-string (in subcommand)
  SHELL_FEAT_PROCESS_SUB = 1 << 6,      // <(cmd), >(cmd)
  SHELL_FEAT_LOOPS = 1 << 7,            // while, for, until loops
  SHELL_FEAT_CONDITIONALS = 1 << 8,     // if/then/elif/else/fi and [[...]]
  SHELL_FEAT_CASE = 1 << 9,             // case/esac statements
  SHELL_FEAT_SUBSHELL_FILE = 1 << 10,   // $(<file) - read from file
  SHELL_FEAT_PIPELINE = 1 << 11,        // literal | or |& pipeline construct
  SHELL_FEAT_GROUP = UINT32_C(1) << 12, // Command group
  SHELL_FEAT_BACKGROUND = UINT32_C(1) << 13,   // Background execution
  SHELL_FEAT_EXTGLOB = UINT32_C(1) << 14,      // Bash extglob pattern
  SHELL_FEAT_ANSI_C_QUOTE = UINT32_C(1) << 15, // Bash $'...' quote
  SHELL_FEAT_ARRAY = UINT32_C(1) << 16,    // Bash array assignment/reference
  SHELL_FEAT_NAMED_FD = UINT32_C(1) << 17, // Bash {name} redirect
  SHELL_FEAT_COMBINED_REDIRECT = UINT32_C(1) << 18, // Bash &>/&>>
} shell_cmd_features_t;

/**
 * Per-call limits for fast parser
 */
typedef struct {
  uint32_t max_subcommands; // Max subcommands to return
  bool strict_mode;         // Reject incomplete or malformed syntax
  /* Optional borrowed source scratch. NULL/zero selects bounded private
   * storage; a larger supplied buffer extends that capacity. A buffer of
   * shell_source_workspace_size() supplies a sufficient capacity bound.
   * Exhaustion returns ETRUNC with zero retained ranges, not a
   * malformed-source result.
   * It is used only during parsing and must not overlap inputs or outputs. */
  void *workspace;
  size_t workspace_size;
} shell_limits_t;

/* Sufficient capacity for operation-local source-analysis scratch: delimiter
 * normalization (including literal command-fragment printing), non-evicting
 * subscript boundary facts, conditional-pattern evaluation, and compiled
 * builtin-test arguments, expression nodes and bounded ambiguous-grammar
 * projection. Pattern evaluation reserves projected units, a prefix table
 * and decoded subject bytes as needed.
 * Builtin-test programs remain live through graph construction and recursive
 * analysis. Public iterators retain subscript facts in the buffer
 * between next() calls.
 * No source is read and no storage is allocated.
 * Required output is cleared on arithmetic overflow (false). The buffer may
 * have any alignment and must not alias source or result storage. Existing
 * syntax/depth/output limits still apply independently of this byte bound.
 * Smaller buffers remain valid; reservations check capacity and arithmetic
 * independently and report exhaustion through the consuming API. */
bool shell_source_workspace_size(size_t source_length, size_t *workspace_size)
    SHELL_NONNULL(2);

/**
 * Strict mode rejects unterminated quotes, substitutions, parentheses,
 * top-level heredocs, and invalid parameter expansions. A single trailing
 * semicolon is accepted as a command-list terminator; trailing pipes and
 * logical operators are not.
 */

/**
 * Default limits
 */
#ifdef __cplusplus
static const shell_limits_t SHELL_LIMITS_DEFAULT = {SHELL_MAX_SUBCOMMANDS,
                                                    false, NULL, 0};
#else
static const shell_limits_t SHELL_LIMITS_DEFAULT = {
    .max_subcommands = SHELL_MAX_SUBCOMMANDS, .strict_mode = false};
#endif

/**
 * Feature flag set - alternative to bitmask shell_cmd_features_t.
 * Provides named boolean fields for each feature.
 * Use shell_feature_flags_from_bits() to populate this struct.
 */
typedef struct {
  bool has_vars;
  bool has_globs;
  bool has_subshell;
  bool has_arith;
  bool has_heredoc;
  bool has_herestring;
  bool has_process_sub;
  bool has_loops;
  bool has_conditionals;
  bool has_case;
  bool has_subshell_file;
  bool has_pipeline;
  bool has_group;
  bool has_background;
  bool has_extglob;
  bool has_ansi_c_quote;
  bool has_array;
  bool has_named_fd;
  bool has_combined_redirect;
} shell_feature_flags_t;

/**
 * Extract feature flags from a subcommand's features bitmask.
 * @param features  Raw features bitmask from shell_range_t.features
 * @param flags     Output struct; NULL is ignored
 */
void shell_feature_flags_from_bits(uint32_t features,
                                   shell_feature_flags_t *flags);

/**
 * Get human-readable error string for fast parser error code.
 * @param err  Error code from shell_error_t enum
 * @return     Static string, never NULL
 */
const char *shell_error_string(shell_error_t err);

/**
 * Zero-copy subcommand - just indices into original command
 */
typedef struct {
  uint32_t start; // Index in command string
  uint32_t len;   // Length
  uint16_t type;  // shell_cmd_type_t
  shell_command_kind_t kind;
  uint16_t modifiers; // shell_cmd_modifier_t
  /* Number of leading `!` pipeline modifiers. `modifiers` retains the
   * compatible nonzero indication; callers derive the effective inversion
   * from this count's parity. */
  uint32_t pipeline_negation_count;
  uint8_t pipeline_time_mode; // shell_pipeline_time_mode_t
  /* True only on the pipeline root that carried reserved `time` syntax. */
  bool pipeline_time_direct;
  uint8_t pipe_input_mode; // shell_pipe_mode_t for a preceding pipeline
  uint32_t features;       // shell_cmd_features_t
  uint16_t group_depth;    // Enclosing command-group nesting depth
  uint8_t group_kinds;     // shell_group_kind_t bitset of enclosing groups
} shell_range_t;

/** A complete compound-command half-open span [start, end), including the
 * delimiters. The command interval indexes the command collection returned
 * beside this descriptor: shell_parse_result_t.cmds for a fast parse and
 * shell_processed_commands_t.commands for a processed parse. Processed
 * results remap the interval after structural ranges are omitted. An empty
 * interval starts at the number of collection entries preceding that group's
 * source interval, including the one-past-end position for a trailing group.
 * parent is
 * UINT16_MAX for a top-level group. */
typedef struct {
  uint32_t start;
  uint32_t end;
  uint16_t first_command;
  uint16_t command_count;
  uint16_t parent;
  uint8_t kind;       // Exactly one shell_group_kind_t value
  uint16_t modifiers; // shell_cmd_modifier_t on this compound pipeline member
  uint32_t pipeline_negation_count;
  uint8_t pipeline_time_mode; // shell_pipeline_time_mode_t
  /* True when this group itself follows a reserved `time` prefix. False for
   * timing inherited because the group is a later member of that pipeline. */
  bool pipeline_time_direct;
} shell_group_t;

/**
 * Parse result - caller allocates this. Its fixed command and group capacities
 * are SHELL_MAX_SUBCOMMANDS and SHELL_MAX_GROUPS; do not depend on a concrete
 * byte size, which is ABI and compiler-layout dependent. All offsets and
 * semantic metadata belong to the exact input span passed to shell_parse_fast.
 * A consumer supplied both this result and source bytes must receive that
 * unchanged span and length. Pairing it with another source or editing its
 * metadata is invalid API use, not an alternate command representation.
 */
typedef struct {
  shell_range_t cmds[SHELL_MAX_SUBCOMMANDS]; // Subcommand ranges
  shell_group_t groups[SHELL_MAX_GROUPS];    // Complete compound-group spans
  uint32_t count;                            // Number of subcommands found
  uint32_t group_count;                      // Number of complete groups found
  uint32_t status;                           // shell_status_t flags
} shell_parse_result_t;

/* --- FAST PARSER API --- */

/**
 * Fast shell command parser - zero-copy, no malloc
 *
 * Parses command string and extracts subcommand ranges.
 * Uses caller-provided result buffer - no dynamic allocation.
 *
 * @param cmd       Input command string
 * @param cmd_len   Length of command string
 * @param limits    Per-call limits (can be NULL for defaults)
 * @param result    Caller-allocated result buffer
 * @return          SHELL_OK on success, error code otherwise
 *
 * On success, result contains ranges into cmd. Complete heredoc bodies are
 * data, not executable ranges; their declaration remains a single
 * SHELL_TYPE_HEREDOC range. Nonempty trivia-only spans (space, tab, LF, erased
 * backslash-LF continuations, comments ending at LF) succeed with no range.
 * CR, VT and FF are ordinary word bytes, including CR before LF; no line-ending
 * normalization is performed. Only backslash-LF is a continuation.
 * Zero-length input remains SHELL_EINPUT. On truncation, completed ranges
 * remain available and result->status includes
 * SHELL_STATUS_TRUNCATED.
 * In strict_mode, complete-source syntax validation precedes range/group
 * capacity checks: a malformed suffix is SHELL_EPARSE, not SHELL_ETRUNC.
 * Non-strict parsing retains diagnostic tolerance for unfinished source; its
 * ranges are not a guarantee that the source can be modeled semantically.
 * SHELL_EPARSE is a coarse failure code, including unsupported byte domains;
 * it does not prove a Bash syntax error. Use shell_parse_draft() from
 * shell_source.h for typed syntax/unsupported/input/resource classification.
 */
shell_error_t shell_parse_fast(const char *cmd, size_t cmd_len,
                               const shell_limits_t *limits,
                               shell_parse_result_t *result)
    SHELL_NONNULL(1, 4);

/**
 * Copy subcommand to buffer (null-terminated)
 *
 * @param cmd     Original command string
 * @param range   Subcommand range
 * @param buf     Output buffer
 * @param buf_len Buffer size
 * @return        Bytes written (excluding null), or 0 on error
 */
size_t shell_subcommand_copy(const char *cmd, const shell_range_t *range,
                             char *buf, size_t buf_len) SHELL_NONNULL(1, 2, 3);

/**
 * Get subcommand pointer (not null-terminated)
 *
 * @param cmd     Original command string
 * @param range   Subcommand range
 * @param out_len Output parameter for length
 * @return        Pointer into original command (not null-terminated)
 */
const char *shell_subcommand_view(const char *cmd, const shell_range_t *range,
                                  size_t *out_len) SHELL_NONNULL(1, 2);

/* Full parser section is in shell_tokenizer_full.h */

#ifdef __cplusplus
}
#endif

#endif // SHELL_TOKENIZER_H
