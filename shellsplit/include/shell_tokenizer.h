#ifndef SHELL_TOKENIZER_H
#define SHELL_TOKENIZER_H

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

/**
 * Subcommand type - the operator associated with this subcommand
 * (shifted to upper bits to avoid conflict with features)
 */
typedef enum {
  SHELL_TYPE_SIMPLE = 0,             // Single command, no separator
  SHELL_TYPE_PIPELINE = 1 << 8,      // Preceded by literal |
  SHELL_TYPE_AND = 1 << 9,           // Preceded by &&
  SHELL_TYPE_OR = 1 << 10,           // Preceded by ||
  SHELL_TYPE_SEMICOLON = 1 << 11,    // Preceded by ;
  SHELL_TYPE_HEREDOC = 1 << 12,      // Starts with << (heredoc)
  SHELL_TYPE_HERESTRING = 1 << 13,   // Starts with <<< (here-string)
  SHELL_TYPE_SUBSTITUTION = 1 << 14, // Command/process substitution operator
  SHELL_TYPE_BACKGROUND = 1 << 15,   // Preceded by a background '&'
} shell_cmd_type_t;

/* Kinds of enclosing command groups. Values are a bitset so mixed nesting is
 * represented without losing an outer subshell boundary. */
typedef enum {
  SHELL_GROUP_NONE = 0,
  SHELL_GROUP_BRACE = 1 << 0,
  SHELL_GROUP_SUBSHELL = 1 << 1,
} shell_group_kind_t;

/**
 * Subcommand features - what's inside the subcommand
 */
typedef enum {
  SHELL_FEAT_NONE = 0,
  SHELL_FEAT_VARS = 1 << 0,                  // $VAR, ${VAR}, $1, etc.
  SHELL_FEAT_GLOBS = 1 << 1,                 // *, ?, [abc]
  SHELL_FEAT_SUBSHELL = 1 << 2,              // $(...), `...`
  SHELL_FEAT_ARITH = 1 << 3,                 // $((...))
  SHELL_FEAT_HEREDOC = 1 << 4,               // << delimiter (in subcommand)
  SHELL_FEAT_HERESTRING = 1 << 5,            // <<< here-string (in subcommand)
  SHELL_FEAT_PROCESS_SUB = 1 << 6,           // <(cmd), >(cmd)
  SHELL_FEAT_LOOPS = 1 << 7,                 // while, for, until loops
  SHELL_FEAT_CONDITIONALS = 1 << 8,          // if/then/elif/else/fi
  SHELL_FEAT_CASE = 1 << 9,                  // case/esac statements
  SHELL_FEAT_SUBSHELL_FILE = 1 << 10,        // $(<file) - read from file
  SHELL_FEAT_PIPELINE = 1 << 11,             // literal | pipeline construct
  SHELL_FEAT_GROUP = UINT32_C(1) << 12,      // Command group
  SHELL_FEAT_BACKGROUND = UINT32_C(1) << 13, // Background execution
} shell_cmd_features_t;

/**
 * Per-call limits for fast parser
 */
typedef struct {
  uint32_t max_subcommands; // Max subcommands to return
  bool strict_mode;         // Reject incomplete or malformed syntax
} shell_limits_t;

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
                                                    false};
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
  uint32_t start;       // Index in command string
  uint32_t len;         // Length
  uint16_t type;        // shell_cmd_type_t
  uint32_t features;    // shell_cmd_features_t
  uint16_t group_depth; // Enclosing command-group nesting depth
  uint8_t group_kinds;  // shell_group_kind_t bitset of enclosing groups
} shell_range_t;

/** A complete compound-command half-open span [start, end), including the
 * delimiters. The command interval indexes the command collection returned
 * beside this descriptor: shell_parse_result_t.cmds for a fast parse and
 * shell_processed_commands_t.commands for a processed parse. Processed
 * results remap the interval after structural ranges are omitted. parent is
 * UINT16_MAX for a top-level group. */
typedef struct {
  uint32_t start;
  uint32_t end;
  uint16_t first_command;
  uint16_t command_count;
  uint16_t parent;
  uint8_t kind; // Exactly one shell_group_kind_t value
} shell_group_t;

/**
 * Parse result - caller allocates this. Its fixed command and group capacities
 * are SHELL_MAX_SUBCOMMANDS and SHELL_MAX_GROUPS; do not depend on a concrete
 * byte size, which is ABI and compiler-layout dependent.
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
 * SHELL_TYPE_HEREDOC range. Comment-only source spans yield no range. On
 * truncation, completed ranges remain available and result->status includes
 * SHELL_STATUS_TRUNCATED.
 */
shell_error_t shell_parse_fast(const char *cmd, size_t cmd_len,
                               const shell_limits_t *limits,
                               shell_parse_result_t *result);

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
                             char *buf, size_t buf_len);

/**
 * Get subcommand pointer (not null-terminated)
 *
 * @param cmd     Original command string
 * @param range   Subcommand range
 * @param out_len Output parameter for length
 * @return        Pointer into original command (not null-terminated)
 */
const char *shell_subcommand_view(const char *cmd, const shell_range_t *range,
                                  size_t *out_len);

/* Full parser section is in shell_tokenizer_full.h */

#ifdef __cplusplus
}
#endif

#endif // SHELL_TOKENIZER_H
