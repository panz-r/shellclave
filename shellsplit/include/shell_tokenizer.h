#ifndef SHELL_TOKENIZER_H
#define SHELL_TOKENIZER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Shell Command Parser - Fast Zero-Copy Variant
 * 
 * Two modes:
 * 1. Fast parser (this API): Single-pass, zero-copy, bounded output
 * 2. Full parser: Deep tokenization, recursive (see shell_tokenizer_full.h)
 * 
 * Fast parser design:
 * - No dynamic memory allocation
 * - Caller provides result buffer with max subcommands
 * - Returns subcommand ranges (indices into original command)
 * - Truncation reported via return code if input exceeds limits
 */

/* ============================================================
 * CONSTANTS & LIMITS
 * ============================================================ */

#define SHELL_MAX_SUBCOMMANDS 64   // Default max subcommands
#define SHELL_MAX_DEPTH 8           // Default max nesting depth

/* ============================================================
 * TYPE DEFINITIONS
 * ============================================================ */

/**
 * Return codes
 */
typedef enum {
    SHELL_OK = 0,          // Success
    SHELL_EINPUT = -1,     // Invalid input
    SHELL_ETRUNC = -2,     // Truncated - caller should use fallback
    SHELL_EPARSE = -3,     // Parse error
} shell_error_t;

/**
 * Status flags (returned in shell_parse_result_t.status)
 */
typedef enum {
    SHELL_STATUS_OK = 0,
    SHELL_STATUS_TRUNCATED = 1 << 0,  // Limits exceeded, use fallback
    SHELL_STATUS_ERROR = 1 << 1,     // Parse error
} shell_status_t;

/**
 * Subcommand type - what separator started this subcommand
 * (shifted to upper bits to avoid conflict with features)
 */
typedef enum {
    SHELL_TYPE_SIMPLE     = 0,         // Single command, no separator
    SHELL_TYPE_PIPELINE   = 1 << 8,   // Followed by |
    SHELL_TYPE_AND        = 1 << 9,   // Followed by &&
    SHELL_TYPE_OR         = 1 << 10,  // Followed by ||
    SHELL_TYPE_SEMICOLON  = 1 << 11,  // Followed by ;
    SHELL_TYPE_HEREDOC    = 1 << 12,  // Starts with << (heredoc)
    SHELL_TYPE_HERESTRING = 1 << 13,  // Starts with <<< (here-string)
} shell_cmd_type_t;

/**
 * Subcommand features - what's inside the subcommand
 */
typedef enum {
    SHELL_FEAT_NONE       = 0,
    SHELL_FEAT_VARS       = 1 << 0,   // $VAR, ${VAR}, $1, etc.
    SHELL_FEAT_GLOBS      = 1 << 1,   // *, ?, [abc]
    SHELL_FEAT_SUBSHELL   = 1 << 2,   // $(...), `...`
    SHELL_FEAT_ARITH      = 1 << 3,   // $((...))
    SHELL_FEAT_HEREDOC    = 1 << 4,   // << delimiter (in subcommand)
    SHELL_FEAT_HERESTRING = 1 << 5,   // <<< here-string (in subcommand)
    SHELL_FEAT_PROCESS_SUB = 1 << 6,  // <(cmd), >(cmd)
} shell_cmd_features_t;

/**
 * Per-call limits for fast parser
 */
typedef struct {
    uint32_t max_subcommands;   // Max subcommands to return
    uint32_t max_depth;        // Max nesting depth
} shell_limits_t;

/**
 * Default limits
 */
static const shell_limits_t SHELL_LIMITS_DEFAULT = {
    .max_subcommands = SHELL_MAX_SUBCOMMANDS,
    .max_depth = SHELL_MAX_DEPTH
};

/**
 * Zero-copy subcommand - just indices into original command
 */
typedef struct {
    uint32_t start;     // Index in command string
    uint32_t len;      // Length
    uint16_t type;     // shell_cmd_type_t
    uint16_t features; // shell_cmd_features_t
} shell_range_t;

/**
 * Parse result - caller allocates this
 * Size: 64 * 8 + 8 = 520 bytes (for 64 max subcommands)
 */
typedef struct {
    shell_range_t cmds[SHELL_MAX_SUBCOMMANDS];  // Subcommand ranges
    uint32_t count;         // Number of subcommands found
    uint32_t status;      // shell_status_t flags
} shell_parse_result_t;

/* C++ compatibility */
#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * FAST PARSER API - Zero-Copy, Bounded
 * ============================================================ */

/**
 * Fast shell command parser - single pass, no malloc
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
 * On SHELL_OK: result->count contains valid subcommands
 * On SHELL_ETRUNC: result->status has TRUNCATED, caller should use fallback
 * On SHELL_EINPUT: result->status has ERROR, invalid input
 */
shell_error_t shell_parse_fast(
    const char* cmd,
    size_t cmd_len,
    const shell_limits_t* limits,
    shell_parse_result_t* result
);

/**
 * Copy subcommand to buffer (null-terminated)
 * 
 * @param cmd     Original command string
 * @param range   Subcommand range
 * @param buf     Output buffer
 * @param buf_len Buffer size
 * @return        Bytes written (excluding null), or 0 on error
 */
size_t shell_copy_subcommand(
    const char* cmd,
    const shell_range_t* range,
    char* buf,
    size_t buf_len
);

/**
 * Get subcommand pointer (not null-terminated)
 * 
 * @param cmd     Original command string
 * @param range   Subcommand range
 * @param out_len Output parameter for length
 * @return        Pointer into original command (not null-terminated)
 */
const char* shell_get_subcommand(
    const char* cmd,
    const shell_range_t* range,
    uint32_t* out_len
);

/* Full parser section is in shell_tokenizer_full.h */

#ifdef __cplusplus
}
#endif

#endif // SHELL_TOKENIZER_H
