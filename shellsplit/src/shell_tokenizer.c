#include "shell_tokenizer.h"
#include <ctype.h>
#include <string.h>

/* ============================================================
 * FAST PARSER IMPLEMENTATION
 * ============================================================ */

/**
 * Check if character is a shell separator
 */
static inline bool is_separator(char c) {
    return c == '|' || c == ';' || c == '&' || c == '<' || c == '>' || c == '\n' || c == '\r';
}

/**
 * Check if at position we have a specific operator
 */
static inline bool match_operator(const char* s, size_t len, const char* op) {
    size_t op_len = strlen(op);
    if (len < op_len) return false;
    return strncmp(s, op, op_len) == 0;
}

/**
 * Detect features in a subcommand range
 */
static void detect_features(const char* cmd, uint32_t start, uint32_t len, uint16_t* features) {
    const char* p = cmd + start;
    uint32_t i = 0;
    bool in_single_quotes = false;
    bool in_double_quotes = false;
    int arith_depth = 0;
    
    while (i < len) {
        char c = p[i];
        
        // Handle single quotes - no expansion inside
        if (c == '\'') {
            in_single_quotes = !in_single_quotes;
            i++;
            continue;
        }
        
        if (in_single_quotes) {
            i++;
            continue;
        }
        
        // Handle double quotes - variables expand, globs don't
        if (c == '"') {
            in_double_quotes = !in_double_quotes;
            i++;
            continue;
        }
        
        // Skip escapes
        if (c == '\\' && i + 1 < len) {
            i += 2;
            continue;
        }
        
        // Track arithmetic depth and detect variables inside
        if (c == '$' && i + 1 < len && p[i + 1] == '(' && i + 2 < len && p[i + 2] == '(') {
            arith_depth++;
            *features |= SHELL_FEAT_ARITH;
            // Check if first variable after $((
            if (i + 3 < len) {
                char next = p[i + 3];
                if (isalpha(next) || next == '_') {
                    *features |= SHELL_FEAT_VARS;
                }
            }
            // Don't skip ahead - let next iteration process the content
            i++;
            continue;
        }
        if (arith_depth > 0) {
            // Inside $((...)) - detect variables and subshells
            if (c == ')') {
                arith_depth--;
                i++;
                continue;
            }
            // Check for $VAR and $(...) patterns inside arithmetic
            if (c == '$' && i + 1 < len) {
                char next = p[i + 1];
                if (next == '(') {
                    // $(...) subshell inside arithmetic
                    *features |= SHELL_FEAT_SUBSHELL;
                } else if (next == '{') {
                    *features |= SHELL_FEAT_VARS;
                } else if (isdigit(next) || next == '#' || next == '?' || next == '$' ||
                           next == '!' || next == '@' || next == '*') {
                    *features |= SHELL_FEAT_VARS;
                } else if (isalpha(next) || next == '_') {
                    *features |= SHELL_FEAT_VARS;
                }
            }
            i++;
            continue;
        }
        
        // Check for features
        switch (c) {
            case '$':
                // Variables expand in double quotes
                if (i + 1 < len) {
                    char next = p[i + 1];
                    if (next == '(') {
                        if (i + 2 < len && p[i + 2] == '(') {
                            // This is handled in arith_depth section above
                            i += 3;
                            continue;
                        }
                        *features |= SHELL_FEAT_SUBSHELL;
                    } else if (next == '`') {
                        *features |= SHELL_FEAT_SUBSHELL;
                    } else if (next == '{') {
                        *features |= SHELL_FEAT_VARS;
                    } else if (isdigit(next) || next == '#' || next == '?' || next == '$' || 
                               next == '!' || next == '@' || next == '*') {
                        *features |= SHELL_FEAT_VARS;
                    } else if (isalpha(next) || next == '_') {
                        *features |= SHELL_FEAT_VARS;
                    }
                }
                break;
            case '`':
                *features |= SHELL_FEAT_SUBSHELL;
                break;
            case '*':
            case '?':
                // Globs do NOT expand in double quotes
                if (!in_double_quotes) {
                    *features |= SHELL_FEAT_GLOBS;
                }
                break;
            case '[':
                // Globs do NOT expand in double quotes, and not in heredoc context
                if (!in_double_quotes && !(i > 0 && p[i - 1] == '<')) {
                    *features |= SHELL_FEAT_GLOBS;
                }
                break;
            default:
                break;
        }
        
        i++;
    }
}

/**
 * Fast shell command parser - single pass, zero-copy, bounded
 */
shell_error_t shell_parse_fast(
    const char* cmd,
    size_t cmd_len,
    const shell_limits_t* limits,
    shell_parse_result_t* result
) {
    // Validate inputs
    if (!cmd || !result) {
        return SHELL_EINPUT;
    }
    
    if (cmd_len == 0) {
        result->count = 0;
        result->status = SHELL_STATUS_OK;
        return SHELL_OK;
    }
    
    // Use default limits if not provided
    shell_limits_t local_limits;
    if (!limits) {
        local_limits = SHELL_LIMITS_DEFAULT;
        limits = &local_limits;
    }
    
    // Initialize result
    memset(result, 0, sizeof(shell_parse_result_t));
    
    uint32_t max_cmds = limits->max_subcommands;
    if (max_cmds > SHELL_MAX_SUBCOMMANDS) {
        max_cmds = SHELL_MAX_SUBCOMMANDS;
    }
    
    uint32_t max_depth = limits->max_depth;
    (void)max_depth; // Reserved for future subshell depth tracking
    
    // Helper to trim whitespace and record subcommand
    #define RECORD_SUBCMD(s, e, type_val) do { \
        uint32_t _s = (s); \
        uint32_t _e = (e); \
        while (_s < _e && isspace((unsigned char)cmd[_s])) _s++; \
        while (_e > _s && isspace((unsigned char)cmd[_e-1])) _e--; \
        if (_s < _e && subcmd_idx < max_cmds) { \
            result->cmds[subcmd_idx].start = _s; \
            result->cmds[subcmd_idx].len = _e - _s; \
            result->cmds[subcmd_idx].type = (type_val); \
            result->cmds[subcmd_idx].features = 0; \
            detect_features(cmd, _s, _e - _s, &result->cmds[subcmd_idx].features); \
            subcmd_idx++; \
        } else if (subcmd_idx >= max_cmds) { \
            result->status = SHELL_STATUS_TRUNCATED; \
            result->count = subcmd_idx; \
            return SHELL_ETRUNC; \
        } \
    } while(0)
    
    uint32_t pos = 0;
    uint32_t subcmd_start = 0;
    uint32_t subcmd_idx = 0;
    uint16_t current_type = SHELL_TYPE_SIMPLE;
    bool in_quotes = false;
    char quote_char = 0;
    int brace_depth = 0;
    int arith_depth = 0;  // Track when inside $((...))
    
    while (pos < cmd_len) {
        char c = cmd[pos];
        
        // Handle quotes
        if (!in_quotes && (c == '"' || c == '\'')) {
            in_quotes = true;
            quote_char = c;
            pos++;
            continue;
        }
        if (in_quotes && c == quote_char) {
            in_quotes = false;
            quote_char = 0;
            pos++;
            continue;
        }
        
        // Skip content inside quotes
        if (in_quotes) {
            // Handle escape in quotes
            if (c == '\\' && pos + 1 < cmd_len) {
                pos += 2;
            } else {
                pos++;
            }
            continue;
        }
        
        // Track brace depth for ${var...}
        if (c == '{') {
            brace_depth++;
        } else if (c == '}' && brace_depth > 0) {
            brace_depth--;
        }
        
        // Track paren depth for $(...), $((...)), <(...), >(...)
        // Note: $(( opens TWO parens - handle specially to avoid double counting
        if (c == '$' && pos + 2 < cmd_len && cmd[pos + 1] == '(' && cmd[pos + 2] == '(') {
            // This is $(( - arithmetic expansion, opens TWO parentheses
            brace_depth += 2;
            arith_depth += 2;  // Track that we're inside arithmetic
            pos += 3;  // Skip $(( entirely (3 chars)
            continue;
        }
        if (c == '(') {
            brace_depth++;
        } else if (c == ')' && brace_depth > 0) {
            brace_depth--;
            if (arith_depth > 0) {
                arith_depth--;  // Decrement arithmetic depth
            }
        }
        
        // Handle bare $ - must be followed by valid characters
        // $$ (PID), $? (exit status), $# (arg count), $! (last bg pid), 
        // $*/$@ (positional params) at end ARE valid
        if (c == '$') {
            if (pos + 1 >= cmd_len) {
                // $ at end - check if this is the second $ of $$
                if (pos > 0 && cmd[pos - 1] == '$') {
                    // This is $$ - valid!
                } else {
                    // Bare $ at end - malformed
                    brace_depth++;
                }
            } else {
                char next = cmd[pos + 1];
                // $ must be followed by: alphanumeric, _, {, (, `, digit, or special var chars (*, @, #, ?, !, $)
                if (!isalpha(next) && next != '_' && next != '{' && next != '(' && 
                    next != '`' && !isdigit(next) && next != '*' && next != '@' && 
                    next != '#' && next != '?' && next != '!' && next != '$') {
                    // Malformed $ - increment brace_depth so it will fail the final check
                    brace_depth++;
                }
            }
        }
        
        // Handle escapes outside quotes
        if (c == '\\' && pos + 1 < cmd_len) {
            pos += 2;
            continue;
        }
        
        // Check for HERESTRING <<< (here-string) - must check before << and NOT inside arithmetic
        if (arith_depth == 0 && c == '<' && pos + 2 < cmd_len && cmd[pos + 1] == '<' && cmd[pos + 2] == '<') {
            // End current subcommand if it has content (trim whitespace)
            if (subcmd_idx < max_cmds && subcmd_start < pos) {
                uint32_t s = subcmd_start;
                uint32_t e = pos;
                while (s < e && isspace((unsigned char)cmd[s])) s++;
                while (e > s && isspace((unsigned char)cmd[e-1])) e--;
                if (s < e) {
                    result->cmds[subcmd_idx].start = s;
                    result->cmds[subcmd_idx].len = e - s;
                    result->cmds[subcmd_idx].type = current_type;
                    result->cmds[subcmd_idx].features = 0;
                    detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features);
                    subcmd_idx++;
                }
            }
            
            // Start herestring as new subcommand
            if (subcmd_idx >= max_cmds) {
                result->status = SHELL_STATUS_TRUNCATED;
                result->count = subcmd_idx;
                return SHELL_ETRUNC;
            }
            
            // Record herestring subcommand: include <<< and the string
            uint32_t herestring_start = pos;
            pos += 3; // Skip <<<
            
            // Skip whitespace
            while (pos < cmd_len && isspace(cmd[pos])) pos++;
            
            // Find end of the string (next whitespace or separator)
            uint32_t string_start = pos;
            while (pos < cmd_len && !isspace(cmd[pos]) && !is_separator(cmd[pos])) pos++;
            uint32_t string_len = pos - string_start;
            
            if (string_len == 0) {
                // No string found - treat as less-than
                pos = herestring_start + 1;
            } else {
                // Record herestring subcommand: <<< + string
                result->cmds[subcmd_idx].start = herestring_start;
                result->cmds[subcmd_idx].len = (pos - herestring_start);
                result->cmds[subcmd_idx].type = SHELL_TYPE_HERESTRING;
                result->cmds[subcmd_idx].features = SHELL_FEAT_HERESTRING;
                subcmd_idx++;
                
                // Start next subcommand
                subcmd_start = pos;
                current_type = SHELL_TYPE_SIMPLE;
                
                // Skip whitespace to next token
                while (pos < cmd_len && isspace(cmd[pos])) pos++;
                continue;
            }
        }
        
        // Check for HEREDOC << (heredoc) - only if not <<< and NOT inside arithmetic
        if (arith_depth == 0 && c == '<' && pos + 1 < cmd_len && cmd[pos + 1] == '<') {
            // End current subcommand if it has content (trim whitespace)
            if (subcmd_idx < max_cmds && subcmd_start < pos) {
                uint32_t s = subcmd_start;
                uint32_t e = pos;
                while (s < e && isspace((unsigned char)cmd[s])) s++;
                while (e > s && isspace((unsigned char)cmd[e-1])) e--;
                if (s < e) {
                    result->cmds[subcmd_idx].start = s;
                    result->cmds[subcmd_idx].len = e - s;
                    result->cmds[subcmd_idx].type = current_type;
                    result->cmds[subcmd_idx].features = 0;
                    detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features);
                    subcmd_idx++;
                }
            }
            
            // Start heredoc as new subcommand
            if (subcmd_idx >= max_cmds) {
                result->status = SHELL_STATUS_TRUNCATED;
                result->count = subcmd_idx;
                return SHELL_ETRUNC;
            }
            
            // Find heredoc delimiter (word after <<)
            uint32_t heredoc_start = pos;
            pos += 2; // Skip <<
            
            // Skip whitespace
            while (pos < cmd_len && isspace(cmd[pos])) pos++;
            
            // Find end of delimiter (whitespace or end)
            uint32_t delim_start = pos;
            while (pos < cmd_len && !isspace(cmd[pos]) && cmd[pos] != ';') pos++;
            uint32_t delim_len = pos - delim_start;
            
            if (delim_len == 0) {
                // No delimiter found - treat as less-than
                pos = heredoc_start + 1;
            } else {
                // Record heredoc subcommand: include << and delimiter
                result->cmds[subcmd_idx].start = heredoc_start;
                result->cmds[subcmd_idx].len = (pos - heredoc_start); // << + delimiter
                result->cmds[subcmd_idx].type = SHELL_TYPE_HEREDOC;
                result->cmds[subcmd_idx].features = SHELL_FEAT_HEREDOC;
                subcmd_idx++;
                
                // Start next subcommand after delimiter
                subcmd_start = pos;
                current_type = SHELL_TYPE_SIMPLE;
                
                // Skip whitespace to next token
                while (pos < cmd_len && isspace(cmd[pos])) pos++;
                continue;
            }
        }
        
        
        // Check for separators (but not if inside arithmetic - there < > are operators)
        if (arith_depth == 0 && is_separator(c)) {
            // Handle &&
            if (c == '&' && pos + 1 < cmd_len && cmd[pos + 1] == '&') {
                // End current subcommand (trim whitespace)
                if (subcmd_start < pos) {
                    if (subcmd_idx >= max_cmds) {
                        result->status = SHELL_STATUS_TRUNCATED;
                        result->count = subcmd_idx;
                        return SHELL_ETRUNC;
                    }
                    uint32_t s = subcmd_start;
                    uint32_t e = pos;
                    while (s < e && isspace((unsigned char)cmd[s])) s++;
                    while (e > s && isspace((unsigned char)cmd[e-1])) e--;
                    if (s < e) {
                        result->cmds[subcmd_idx].start = s;
                        result->cmds[subcmd_idx].len = e - s;
                        result->cmds[subcmd_idx].type = current_type;
                        result->cmds[subcmd_idx].features = 0;
                        detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features);
                        subcmd_idx++;
                    }
                }
                
                // Start new subcommand with AND type
                pos += 2;
                subcmd_start = pos;
                current_type = SHELL_TYPE_AND;
                continue;
            }
            
            // Handle ||
            if (c == '|' && pos + 1 < cmd_len && cmd[pos + 1] == '|') {
                // End current subcommand (trim whitespace)
                if (subcmd_start < pos) {
                    if (subcmd_idx >= max_cmds) {
                        result->status = SHELL_STATUS_TRUNCATED;
                        result->count = subcmd_idx;
                        return SHELL_ETRUNC;
                    }
                    uint32_t s = subcmd_start;
                    uint32_t e = pos;
                    while (s < e && isspace((unsigned char)cmd[s])) s++;
                    while (e > s && isspace((unsigned char)cmd[e-1])) e--;
                    if (s < e) {
                        result->cmds[subcmd_idx].start = s;
                        result->cmds[subcmd_idx].len = e - s;
                        result->cmds[subcmd_idx].type = current_type;
                        result->cmds[subcmd_idx].features = 0;
                        detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features);
                        subcmd_idx++;
                    }
                }
                
                // Start new subcommand with OR type
                pos += 2;
                subcmd_start = pos;
                current_type = SHELL_TYPE_OR;
                continue;
            }
            
            // Handle |
            if (c == '|' && !(pos > 0 && cmd[pos-1] == '>')) {
                // End current subcommand (trim whitespace)
                if (subcmd_start < pos) {
                    if (subcmd_idx >= max_cmds) {
                        result->status = SHELL_STATUS_TRUNCATED;
                        result->count = subcmd_idx;
                        return SHELL_ETRUNC;
                    }
                    uint32_t s = subcmd_start;
                    uint32_t e = pos;
                    while (s < e && isspace((unsigned char)cmd[s])) s++;
                    while (e > s && isspace((unsigned char)cmd[e-1])) e--;
                    if (s < e) {
                        result->cmds[subcmd_idx].start = s;
                        result->cmds[subcmd_idx].len = e - s;
                        result->cmds[subcmd_idx].type = current_type;
                        result->cmds[subcmd_idx].features = 0;
                        detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features);
                        subcmd_idx++;
                    }
                }
                
                // Start new subcommand with PIPELINE type
                pos++;
                subcmd_start = pos;
                current_type = SHELL_TYPE_PIPELINE;
                continue;
            }
            
            // Handle ; and newlines as command separators
            if (c == ';' || c == '\n' || c == '\r') {
                // End current subcommand (trim whitespace)
                if (subcmd_start < pos) {
                    if (subcmd_idx >= max_cmds) {
                        result->status = SHELL_STATUS_TRUNCATED;
                        result->count = subcmd_idx;
                        return SHELL_ETRUNC;
                    }
                    uint32_t s = subcmd_start;
                    uint32_t e = pos;
                    while (s < e && isspace((unsigned char)cmd[s])) s++;
                    while (e > s && isspace((unsigned char)cmd[e-1])) e--;
                    if (s < e) {
                        result->cmds[subcmd_idx].start = s;
                        result->cmds[subcmd_idx].len = e - s;
                        result->cmds[subcmd_idx].type = current_type;
                        result->cmds[subcmd_idx].features = 0;
                        detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features);
                        subcmd_idx++;
                    }
                }
                
                // Start new subcommand with SEMICOLON type
                pos++;
                subcmd_start = pos;
                current_type = SHELL_TYPE_SEMICOLON;
                continue;
            }
            
            // Handle < and > (redirects) - skip but don't break subcommand
            // But NOT if inside arithmetic - there they're operators, not redirects
            if ((c == '<' || c == '>') && arith_depth == 0) {
                // Check for process substitution: >(cmd) or <(cmd)
                if (pos + 1 < cmd_len && cmd[pos + 1] == '(') {
                    // Process substitution - skip the (cmd) part
                    pos += 2; // skip > or < and (
                    int depth = 1;
                    while (pos < cmd_len && depth > 0) {
                        if (cmd[pos] == '(') depth++;
                        if (cmd[pos] == ')') depth--;
                        if (depth > 0) pos++;
                    }
                    // Mark that we have process substitution
                    result->cmds[subcmd_idx].features |= SHELL_FEAT_PROCESS_SUB;
                    if (current_type == SHELL_TYPE_SIMPLE) {
                        current_type = SHELL_TYPE_PIPELINE;
                    }
                    continue;
                }
                pos++;
                // Skip file descriptor number if present
                while (pos < cmd_len && isdigit(cmd[pos])) pos++;
                // Skip whitespace
                while (pos < cmd_len && isspace(cmd[pos])) pos++;
                continue;
            }
        }
        
        pos++;
    }
    
    // End final subcommand
    if (subcmd_start < pos && subcmd_idx < max_cmds) {
        // Trim trailing whitespace
        uint32_t end_pos = pos;
        while (end_pos > subcmd_start && isspace((unsigned char)cmd[end_pos - 1])) {
            end_pos--;
        }
        
        // Trim leading whitespace  
        uint32_t start_pos = subcmd_start;
        while (start_pos < end_pos && isspace((unsigned char)cmd[start_pos])) {
            start_pos++;
        }
        
        if (start_pos < end_pos) {
            result->cmds[subcmd_idx].start = start_pos;
            result->cmds[subcmd_idx].len = end_pos - start_pos;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].features = 0;
            detect_features(cmd, start_pos, end_pos - start_pos,
                           &result->cmds[subcmd_idx].features);
            subcmd_idx++;
        }
    } else if (subcmd_idx >= max_cmds) {
        result->status = SHELL_STATUS_TRUNCATED;
        result->count = subcmd_idx;
        return SHELL_ETRUNC;
    }
    
    // Check for unclosed quotes or braces - this indicates malformed input
    if (in_quotes || brace_depth > 0) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
    }
    
    result->count = subcmd_idx;
    result->status = SHELL_STATUS_OK;
    return SHELL_OK;
}

/**
 * Copy subcommand to buffer (null-terminated)
 */
size_t shell_copy_subcommand(
    const char* cmd,
    const shell_range_t* range,
    char* buf,
    size_t buf_len
) {
    if (!cmd || !range || !buf || buf_len == 0) {
        return 0;
    }
    
    if (range->len == 0) {
        buf[0] = '\0';
        return 0;
    }
    
    size_t copy_len = range->len;
    if (copy_len >= buf_len) {
        copy_len = buf_len - 1;
    }
    
    memcpy(buf, cmd + range->start, copy_len);
    buf[copy_len] = '\0';
    return copy_len;
}

/**
 * Get subcommand pointer (not null-terminated)
 */
const char* shell_get_subcommand(
    const char* cmd,
    const shell_range_t* range,
    uint32_t* out_len
) {
    if (!cmd || !range) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    
    if (out_len) *out_len = range->len;
    return cmd + range->start;
}
