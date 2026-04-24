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
        result->status = SHELL_STATUS_ERROR;
        return SHELL_EINPUT;
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
    int brace_start_pos = -1;
    int paren_depth = 0;  // Track regular parentheses ()
    int arith_depth = 0;  // Track when inside $((...))
    
    while (pos < cmd_len) {
        // Additional bounds check for safety
        if (pos >= cmd_len) break;
        char c = cmd[pos];
        
        // Check for invalid characters at start of command:
        // - Control characters (0x01-0x1F, 0x7F)
        // - High bytes (0x80-0xFF) - binary data, not valid shell
        if (pos == 0 && !in_quotes && arith_depth == 0) {
            unsigned char uc = (unsigned char)c;
            if ((uc >= 0x01 && uc <= 0x1F) || uc == 0x7F || uc >= 0x80) {
                result->status = SHELL_STATUS_ERROR;
                result->count = 0;
                return SHELL_EPARSE;
            }
        }
        
        // Handle quotes
        if (!in_quotes && (c == '"' || c == '\'')) {
            in_quotes = true;
            quote_char = c;
            pos++;
            continue;
        }

        // Skip content inside quotes
        if (in_quotes) {
            if (quote_char == '\'') {
                // Single quotes: no escapes, everything is literal until closing '
                if (c == '\'') {
                    in_quotes = false;
                    quote_char = 0;
                }
                pos++;
            } else {
                // Double quotes: handle escapes for ", \, $, `
                if (c == '\\' && pos + 1 < cmd_len) {
                    pos += 2;  // Skip escaped char
                } else if (c == '"') {
                    in_quotes = false;
                    quote_char = 0;
                    pos++;
                } else {
                    pos++;
                }
            }
            continue;
        }
        
        // Track brace depth for ${var...}
        // Also track if we have a variable name after ${
        if (c == '{') {
            if (brace_depth == 0 && pos > 0 && cmd[pos-1] == '$') {
                // This is ${ - start of variable expansion, remember position
                // Content starts AFTER this brace
                brace_start_pos = pos + 1;
            }
            brace_depth++;
        } else if (c == '}' && brace_depth > 0) {
            // Check for empty ${} - no variable name between braces
            if (brace_start_pos > 0 && brace_depth == 1) {
                // We're closing the ${...} - check if there's any content
                // Content starts at brace_start_pos (after ${) and ends at pos (before })
                bool has_content = false;
                for (uint32_t i = (uint32_t)brace_start_pos; i < pos; i++) {
                    if (!isspace((unsigned char)cmd[i])) {
                        has_content = true;
                        break;
                    }
                }
                if (!has_content) {
                    // Empty ${} - malformed
                    result->status = SHELL_STATUS_ERROR;
                    result->count = subcmd_idx;
                    return SHELL_EPARSE;
                }
                brace_start_pos = -1;  // Reset
            }
            brace_depth--;
        }

        // Track arithmetic expansion $(( ... )) and (( ... ))
        // Note: $(( opens TWO parens - handle specially to avoid double counting
        if (c == '$' && pos + 2 < cmd_len && cmd[pos + 1] == '(' && cmd[pos + 2] == '(') {
            // This is $(( - arithmetic expansion, opens TWO parentheses
            arith_depth += 2;  // Track that we're inside arithmetic
            pos += 3;  // Skip $(( entirely (3 chars)
            continue;
        }
        // Also handle plain (( )) - arithmetic in bash
        if (c == '(' && pos + 1 < cmd_len && cmd[pos + 1] == '(') {
            // This is (( - arithmetic
            arith_depth += 2;
            pos += 2;  // Skip ((
            continue;
        }
        if (c == ')') {
            // Check if closing arithmetic
            if (arith_depth > 0 && pos > 0 && cmd[pos-1] == ')') {
                // This might be closing (( or $(( - arithmetic
                arith_depth--;
            }
        }

        // Track regular parentheses () for subshell detection
        // But not inside arithmetic $(( )) or process substitution <( )
        // Only track when NOT inside arithmetic expansion
        if (arith_depth == 0) {
            if (c == '(') {
                paren_depth++;
            } else if (c == ')' && paren_depth > 0) {
                paren_depth--;
            }
        }
        
        // Handle bare $ - must be followed by valid characters
        // $$ (PID), $? (exit status), $# (arg count), $! (last bg pid), 
        // $*/$@ (positional params) at end ARE valid
        // Skip $ handling inside quotes - $ is literal in single quotes
        if (c == '$' && !in_quotes) {
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
                    bool in_proc_quote = false;
                    char proc_quote_char = 0;
                    while (pos < cmd_len && depth > 0) {
                        char pc = cmd[pos];
                        if (!in_proc_quote) {
                            if (pc == '"' || pc == '\'') {
                                in_proc_quote = true;
                                proc_quote_char = pc;
                            } else if (pc == '(') {
                                depth++;
                            } else if (pc == ')') {
                                depth--;
                            }
                        } else {
                            if (pc == proc_quote_char) {
                                in_proc_quote = false;
                            } else if (pc == '\\' && pos + 1 < cmd_len) {
                                pos++; // skip escaped char
                            }
                        }
                        pos++;
                    }
                    // Check if we exited due to unmatched parens (invalid)
                    if (depth > 0) {
                        // Unclosed parenthesis - invalid
                        result->status = SHELL_STATUS_ERROR;
                        result->count = subcmd_idx;
                        return SHELL_EPARSE;
                    }
                    // Mark that we have process substitution (if we have at least one subcommand)
                    if (subcmd_idx > 0 && subcmd_idx < max_cmds) {
                        result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_PROCESS_SUB;
                    }
                    if (current_type == SHELL_TYPE_SIMPLE) {
                        current_type = SHELL_TYPE_PIPELINE;
                    }
                    continue;
                }
                // Check for multi-char redirects: >>, <<, >&, &>, <&, &<, etc.
                bool is_double_redirect = false;
                bool is_fd_redirect = false;  // >& or <& (file descriptor redirect)
                if (pos + 1 < cmd_len) {
                    if (cmd[pos + 1] == '>' || cmd[pos + 1] == '<') {
                        // >>, <<
                        is_double_redirect = true;
                        pos++; // skip second char
                    } else if (cmd[pos + 1] == '&') {
                        // >& or <& (fd redirect)
                        is_fd_redirect = true;
                        pos++; // skip the &
                    }
                }
                pos++;
                // Skip file descriptor number if present (but not after >>, and not for fd redirects)
                // For 2>file, skip the 2. For 2>&1, don't skip the 1 (it's the target).
                if (!is_double_redirect && !is_fd_redirect) {
                    while (pos < cmd_len && isdigit(cmd[pos])) pos++;
                }
                // Skip whitespace
                while (pos < cmd_len && isspace(cmd[pos])) pos++;
                // Validate: redirect must be followed by a valid target
                // Check for end of input or invalid next character
                if (pos >= cmd_len) {
                    // No target after redirect - invalid
                    result->status = SHELL_STATUS_ERROR;
                    result->count = subcmd_idx;
                    return SHELL_EPARSE;
                }
                
                // Check for valid redirect operators: &>, &>>, <&, &<, etc.
                // These are valid bash redirects (e.g., >&1, 2>&1, &>file)
                char next_ch = cmd[pos];
                // Redirect target can't be an operator
                if (next_ch == '<' || next_ch == '>' || next_ch == '|' || 
                    next_ch == ';' || next_ch == '&' || next_ch == '\n') {
                    result->status = SHELL_STATUS_ERROR;
                    result->count = subcmd_idx;
                    return SHELL_EPARSE;
                }
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

    if (limits && limits->strict_mode) {
        bool in_single = false, in_double = false;
        for (size_t i = 0; i < cmd_len; i++) {
            char c = cmd[i];
            if (c == '\\' && i + 1 < cmd_len) {
                i++;
                continue;
            }
            if (c == '\'' && !in_double) {
                in_single = !in_single;
            } else if (c == '"' && !in_single) {
                in_double = !in_double;
            }
        }
        if (in_single || in_double) {
            result->status |= SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
        }
    }

    // Check for unclosed quotes or braces - this indicates malformed input
    // Only in strict mode; permissive mode allows unterminated quotes
    if ((limits && limits->strict_mode) && (in_quotes || brace_depth > 0)) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
    }
    
    // Check for unclosed parentheses - indicates invalid input like "( git"
    // But allow subshell syntax - only reject if paren_depth > 0 AND the content 
    // doesn't look like a valid subshell (e.g., "( ls )" has matching parens)
    if ((limits && limits->strict_mode) && paren_depth > 0) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
    }
    
    // Check for incomplete case statement: "case ... in" without "esac"
    // Scan for "case" keyword and validate structure
    {
        // Look for case...in pattern without esac
        bool has_case = false;
        bool has_in = false;
        bool has_esac = false;
        
        for (size_t i = 0; i + 3 < cmd_len; i++) {
            // Skip quoted sections
            if (cmd[i] == '\'' || cmd[i] == '"') {
                char quote = cmd[i];
                i++;
                while (i < cmd_len && cmd[i] != quote) {
                    if (cmd[i] == '\\' && i + 1 < cmd_len) i++;
                    i++;
                }
                continue;
            }
            
            // Check for "case" as complete word
            if (i + 3 < cmd_len && strncmp(cmd + i, "case", 4) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 4 >= cmd_len || !isalnum((unsigned char)cmd[i+4]));
                if (ok_before && ok_after) {
                    has_case = true;
                }
            }
            
            // Check for "in" as complete word (case's in)
            if (i + 1 < cmd_len && strncmp(cmd + i, "in", 2) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 2 >= cmd_len || !isalnum((unsigned char)cmd[i+2]));
                if (ok_before && ok_after && has_case && !has_in) {
                    has_in = true;
                }
            }
            
            // Check for "esac" as complete word
            if (i + 3 < cmd_len && strncmp(cmd + i, "esac", 4) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 4 >= cmd_len || !isalnum((unsigned char)cmd[i+4]));
                if (ok_before && ok_after) {
                    has_esac = true;
                }
            }
        }
        
        // If we have "case ... in" but no "esac", it's invalid
        if (has_case && has_in && !has_esac) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
        }
    }
    
    // Check for incomplete loop: while/until/for without "done"
    {
        bool has_while_until_for = false;
        bool has_do = false;
        bool has_done = false;
        bool has_for_in = false;  // for VAR in LIST
        
        for (size_t i = 0; i + 2 < cmd_len; i++) {
            // Skip quoted sections
            if (cmd[i] == '\'' || cmd[i] == '"') {
                char quote = cmd[i];
                i++;
                while (i < cmd_len && cmd[i] != quote) {
                    if (cmd[i] == '\\' && i + 1 < cmd_len) i++;
                    i++;
                }
                continue;
            }
            
            // Check for "while" as complete word
            if (i + 4 < cmd_len && strncmp(cmd + i, "while", 5) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 5 >= cmd_len || !isalnum((unsigned char)cmd[i+5]));
                if (ok_before && ok_after) {
                    has_while_until_for = true;
                }
            }
            
            // Check for "until" as complete word
            if (i + 4 < cmd_len && strncmp(cmd + i, "until", 5) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 5 >= cmd_len || !isalnum((unsigned char)cmd[i+5]));
                if (ok_before && ok_after) {
                    has_while_until_for = true;
                }
            }
            
            // Check for "for" as complete word
            if (i + 2 < cmd_len && strncmp(cmd + i, "for", 3) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 3 >= cmd_len || !isalnum((unsigned char)cmd[i+3]));
                if (ok_before && ok_after) {
                    has_while_until_for = true;
                    // Check for "for ... in" pattern
                    if (i + 6 < cmd_len && strncmp(cmd + i + 3, " in", 3) == 0) {
                        has_for_in = true;
                    }
                }
            }
            
            // Check for "do" as complete word (loop's do)
            if (i + 1 < cmd_len && strncmp(cmd + i, "do", 2) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 2 >= cmd_len || !isalnum((unsigned char)cmd[i+2]));
                if (ok_before && ok_after && (has_while_until_for || has_for_in)) {
                    has_do = true;
                }
            }
            
            // Check for "done" as complete word
            if (i + 3 < cmd_len && strncmp(cmd + i, "done", 4) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 4 >= cmd_len || !isalnum((unsigned char)cmd[i+4]));
                if (ok_before && ok_after) {
                    has_done = true;
                }
            }
        }
        
        // If we have while/until/for with "do" but no "done", it's invalid
        // BUT allow C-style for loops: for ((expr; expr; expr))
        // These have (( without needing do/done
        bool is_c_style_for = false;
        for (size_t i = 0; i + 5 < cmd_len; i++) {
            // Look for "for ((" pattern - C-style for loop
            if (strncmp(cmd + i, "for ((", 6) == 0) {
                is_c_style_for = true;
                break;
            }
        }
        
        if ((has_while_until_for || has_for_in) && has_do && !has_done && !is_c_style_for) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
        }
    }
    
    // Check for incomplete if statement: "if ... then" without "fi"
    {
        bool has_if = false;
        bool has_then = false;
        bool has_fi = false;
        
        for (size_t i = 0; i + 1 < cmd_len; i++) {
            // Skip quoted sections
            if (cmd[i] == '\'' || cmd[i] == '"') {
                char quote = cmd[i];
                i++;
                while (i < cmd_len && cmd[i] != quote) {
                    if (cmd[i] == '\\' && i + 1 < cmd_len) i++;
                    i++;
                }
                continue;
            }
            
            // Check for "if" as complete word
            // Must not be alphanumeric before or after
            if (i + 1 < cmd_len && strncmp(cmd + i, "if", 2) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 2 >= cmd_len || !isalnum((unsigned char)cmd[i+2]));
                if (ok_before && ok_after) {
                    has_if = true;
                }
            }
            
            // Check for "then" as complete word
            if (i + 3 < cmd_len && strncmp(cmd + i, "then", 4) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 4 >= cmd_len || !isalnum((unsigned char)cmd[i+4]));
                if (ok_before && ok_after && has_if) {
                    has_then = true;
                }
            }
            
            // Check for "fi" as complete word
            if (i + 1 < cmd_len && strncmp(cmd + i, "fi", 2) == 0) {
                bool ok_before = (i == 0 || !isalnum((unsigned char)cmd[i-1]));
                bool ok_after = (i + 2 >= cmd_len || !isalnum((unsigned char)cmd[i+2]));
                if (ok_before && ok_after) {
                    has_fi = true;
                }
            }
        }
        
        // If we have "if ... then" but no "fi", it's invalid
        if (has_if && has_then && !has_fi) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
        }
    }
    
    // Check for invalid shell: bare redirects (>, >>, <, <<, <<<) or bare separators (; | &)
    // If there's no actual command content, it's invalid shell
    if (subcmd_idx == 0) {
        bool has_valid_content = false;
        for (size_t i = 0; i < cmd_len; i++) {
            char ch = cmd[i];
            if (isspace((unsigned char)ch)) continue;
            
            // Skip redirect operators
            if (ch == '<' || ch == '>') {
                // Check for multi-char redirects: <<, >>, <<<, &>, &>>
                if (i + 1 < cmd_len && (cmd[i+1] == '<' || cmd[i+1] == '>')) {
                    i++; // skip second char
                    // Check for <<< or &>>/&<<
                    if (i + 1 < cmd_len && (cmd[i+1] == '<' || cmd[i+1] == '>')) {
                        i++;
                    }
                    continue;
                }
                // Check for &> or &< 
                if (ch == '&' && i + 1 < cmd_len) {
                    i++;
                    continue;
                }
                continue;
            }
            
            // Skip separators
            if (ch == ';' || ch == '|' || ch == '&') {
                // Skip && or ||
                if (i + 1 < cmd_len && cmd[i+1] == ch) {
                    i++;
                }
                continue;
            }
            
            // Found actual content - this is valid
            has_valid_content = true;
            break;
        }
        
        if (!has_valid_content) {
            result->status = SHELL_STATUS_ERROR;
            result->count = 0;
            return SHELL_EPARSE;
        }
    }
    
    // Check for invalid shell: bare redirects (>, >>, <, <<, <<<) or bare separators
    // If there's no actual command content, it's invalid shell
    // A valid shell command must have at least one alphanumeric character or special var
    bool has_command_content = false;
    for (uint32_t i = 0; i < subcmd_idx; i++) {
        uint32_t start = result->cmds[i].start;
        uint32_t len = result->cmds[i].len;
        
        // Check if this subcommand has actual content (not just redirect chars)
        for (uint32_t j = 0; j < len; j++) {
            char ch = cmd[start + j];
            // Skip redirect operators and separators
            if (ch == '<' || ch == '>' || ch == ';' || ch == '|' || ch == '&') {
                continue;
            }
            // Skip whitespace
            if (isspace((unsigned char)ch)) {
                continue;
            }
            // This subcommand has actual command content
            has_command_content = true;
            break;
        }
        if (has_command_content) break;
    }
    
    if (!has_command_content) {
        result->status = SHELL_STATUS_ERROR;
        result->count = 0;
        return SHELL_EPARSE;
    }
    
    // Check for trailing separator: "cmd |" or "cmd ;" or "cmd &" is invalid shell
    // (unless it's && or || which would connect to another command)
    if (subcmd_idx > 0) {
        // Get the last subcommand
        uint32_t last_start = result->cmds[subcmd_idx - 1].start;
        uint32_t last_len = result->cmds[subcmd_idx - 1].len;
        
        if (last_len > 0) {
            // Check if the last subcommand ends with |, ;, or &
            char last_char = cmd[last_start + last_len - 1];
            if (last_char == '|' || last_char == ';' || last_char == '&') {
                // Check it's not && or ||
                if (!(last_len >= 2 && cmd[last_start + last_len - 2] == last_char)) {
                    // Trailing separator without valid continuation
                    result->status = SHELL_STATUS_ERROR;
                    result->count = subcmd_idx;
                    return SHELL_EPARSE;
                }
            }
        }
    }
    
    // Also check for the case where we have a trailing separator but no subcommand after it
    // This happens with "cmd |" where the | sets subcmd_start past the end
    if (subcmd_start >= cmd_len && subcmd_idx > 0) {
        // The last thing we saw was a separator - check what type
        // If current_type is PIPELINE/SEMICOLON/AND/OR, we have a trailing separator
        if (current_type == SHELL_TYPE_PIPELINE || 
            current_type == SHELL_TYPE_SEMICOLON ||
            current_type == SHELL_TYPE_AND ||
            current_type == SHELL_TYPE_OR) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
        }
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

const char* shell_error_string(shell_error_t err) {
    switch (err) {
        case SHELL_OK:      return "OK";
        case SHELL_EINPUT:  return "Invalid input";
        case SHELL_ETRUNC:  return "Truncated (limits exceeded)";
        case SHELL_EPARSE:  return "Parse error";
        default:            return "Unknown error";
    }
}
