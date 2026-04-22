#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * normalize.c - Command normalisation with typed wildcard lattice.
 *
 * Classifies each token into the most specific type in the lattice.
 * Provides join and compatibility tables for policy generation and verification.
 */

#include "shelltype.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

/* ============================================================
 * TYPE SYMBOLS
 * ============================================================ */

const char *st_type_symbol[ST_TYPE_COUNT] = {
    [ST_TYPE_LITERAL]       = "",
    [ST_TYPE_HEXHASH]       = "#h",
    [ST_TYPE_NUMBER]        = "#n",
    [ST_TYPE_IPV4]          = "#i",
    [ST_TYPE_WORD]          = "#w",
    [ST_TYPE_QUOTED]        = "#q",
    [ST_TYPE_QUOTED_SPACE]  = "#qs",
    [ST_TYPE_FILENAME]      = "#f",
    [ST_TYPE_REL_PATH]      = "#r",
    [ST_TYPE_ABS_PATH]      = "#p",
    [ST_TYPE_PATH]          = "#path",
    [ST_TYPE_URL]           = "#u",
    [ST_TYPE_VALUE]         = "#val",
    [ST_TYPE_ANY]           = "*",
};

/* ============================================================
 * JOIN TABLE
 *
 * st_type_join[a][b] = narrowest type covering both a and b.
 *
 * Lattice:
 *   #h ⊂ #n ⊂ #val ⊂ *
 *   #i ⊂ #val ⊂ *
 *   #w ⊂ #val ⊂ *
 *   #q ⊂ #qs ⊂ #val ⊂ *
 *   #f ⊂ #r ⊂ #path ⊂ *
 *   #p ⊂ #path ⊂ *
 *   #u ⊂ *
 * ============================================================ */

const st_token_type_t st_type_join[ST_TYPE_COUNT][ST_TYPE_COUNT] = {
    /* LITERAL */
    { ST_TYPE_LITERAL, ST_TYPE_HEXHASH, ST_TYPE_NUMBER, ST_TYPE_IPV4,
      ST_TYPE_WORD, ST_TYPE_QUOTED, ST_TYPE_QUOTED_SPACE, ST_TYPE_FILENAME,
      ST_TYPE_REL_PATH, ST_TYPE_ABS_PATH, ST_TYPE_PATH, ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* HEXHASH */
    { ST_TYPE_HEXHASH, ST_TYPE_HEXHASH, ST_TYPE_NUMBER, ST_TYPE_VALUE,
      ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_ANY,   ST_TYPE_ANY,   ST_TYPE_ANY,  ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* NUMBER */
    { ST_TYPE_NUMBER, ST_TYPE_NUMBER, ST_TYPE_NUMBER, ST_TYPE_VALUE,
      ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_ANY,   ST_TYPE_ANY,   ST_TYPE_ANY,  ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* IPV4 */
    { ST_TYPE_IPV4, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_IPV4,
      ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* WORD */
    { ST_TYPE_WORD, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_WORD, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* QUOTED */
    { ST_TYPE_QUOTED, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_VALUE, ST_TYPE_QUOTED, ST_TYPE_QUOTED_SPACE, ST_TYPE_VALUE,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* QUOTED_SPACE */
    { ST_TYPE_QUOTED_SPACE, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_VALUE, ST_TYPE_QUOTED_SPACE, ST_TYPE_QUOTED_SPACE, ST_TYPE_VALUE,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* FILENAME */
    { ST_TYPE_FILENAME, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_FILENAME,
      ST_TYPE_REL_PATH, ST_TYPE_PATH, ST_TYPE_PATH, ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* REL_PATH */
    { ST_TYPE_REL_PATH, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_REL_PATH,
      ST_TYPE_REL_PATH, ST_TYPE_PATH, ST_TYPE_PATH, ST_TYPE_ANY,
      ST_TYPE_ANY, ST_TYPE_ANY },
    /* ABS_PATH */
    { ST_TYPE_ABS_PATH, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_PATH,
      ST_TYPE_PATH, ST_TYPE_ABS_PATH, ST_TYPE_PATH, ST_TYPE_ANY,
      ST_TYPE_ANY, ST_TYPE_ANY },
    /* PATH */
    { ST_TYPE_PATH, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_PATH,
      ST_TYPE_PATH, ST_TYPE_PATH, ST_TYPE_PATH, ST_TYPE_ANY,
      ST_TYPE_ANY, ST_TYPE_ANY },
    /* URL */
    { ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_URL,
      ST_TYPE_ANY, ST_TYPE_ANY },
    /* VALUE */
    { ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE, ST_TYPE_VALUE,
      ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,  ST_TYPE_ANY,
      ST_TYPE_VALUE, ST_TYPE_ANY },
    /* ANY */
    { ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY, ST_TYPE_ANY,
      ST_TYPE_ANY, ST_TYPE_ANY },
};

/* ============================================================
 * COMPATIBILITY TABLE
 *
 * st_type_compatible[cmd_type][policy_type] = true iff cmd_type ≤ policy_type.
 * A command token of cmd_type matches a policy node of policy_type.
 * ============================================================ */

#define C(a, b) ((a) <= (b)) ? false : false,  /* placeholder, filled below */

/* We define it explicitly for clarity: */
const bool st_type_compatible[ST_TYPE_COUNT][ST_TYPE_COUNT] = {
    /* LITERAL matches only LITERAL and ANY */
    { true,  false, false, false, false, false, false, false, false, false, false, false, false, true  },
    /* #h matches #h, #n, #val, * */
    { false, true,  true,  false, false, false, false, false, false, false, false, false, true,  true  },
    /* #n matches #n, #val, * */
    { false, false, true,  false, false, false, false, false, false, false, false, false, true,  true  },
    /* #i matches #i, #val, * */
    { false, false, false, true,  false, false, false, false, false, false, false, false, true,  true  },
    /* #w matches #w, #val, * */
    { false, false, false, false, true,  false, false, false, false, false, false, false, true,  true  },
    /* #q matches #q, #qs, #val, * */
    { false, false, false, false, false, true,  true,  false, false, false, false, false, true,  true  },
    /* #qs matches #qs, #val, * */
    { false, false, false, false, false, false, true,  false, false, false, false, false, true,  true  },
    /* #f matches #f, #r, #path, * */
    { false, false, false, false, false, false, false, true,  true,  false, true,  false, false, true  },
    /* #r matches #r, #path, * */
    { false, false, false, false, false, false, false, false, true,  false, true,  false, false, true  },
    /* #p matches #p, #path, * */
    { false, false, false, false, false, false, false, false, false, true,  true,  false, false, true  },
    /* #path matches #path, * */
    { false, false, false, false, false, false, false, false, false, false, true,  false, false, true  },
    /* #u matches #u, * */
    { false, false, false, false, false, false, false, false, false, false, false, true,  false, true  },
    /* #val matches #val, * */
    { false, false, false, false, false, false, false, false, false, false, false, false, true,  true  },
    /* * matches * */
    { false, false, false, false, false, false, false, false, false, false, false, false, false, true  },
};

/* ============================================================
 * CLASSIFICATION HELPERS
 * ============================================================ */

static bool is_decimal_number(const char *token)
{
    if (!token[0]) return false;
    const char *p = token;
    if (*p == '-') p++;
    if (!*p) return false;
    while (*p) {
        if (!isdigit((unsigned char)*p)) return false;
        p++;
    }
    return true;
}

static bool is_hex_number(const char *token)
{
    if (token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
        if (!token[2]) return false;
        for (const char *p = token + 2; *p; p++) {
            if (!isxdigit((unsigned char)*p)) return false;
        }
        return true;
    }
    return false;
}

static bool is_hex_hash(const char *token)
{
    size_t len = strlen(token);
    if (len < 8) return false;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)token[i])) return false;
    }
    return true;
}

static bool is_ipv4(const char *token)
{
    int dots = 0;
    const char *p = token;
    while (*p) {
        if (*p == '.') dots++;
        else if (!isdigit((unsigned char)*p)) return false;
        p++;
    }
    return dots == 3;
}

static bool is_absolute_path(const char *token)
{
    return token[0] == '/' && token[1] != '\0';
}

static bool is_relative_path(const char *token)
{
    /* Contains ".." or "/" but does not start with "/" */
    if (token[0] == '/') return false;
    if (strstr(token, "..") != NULL) return true;
    if (strchr(token, '/') != NULL) return true;
    return false;
}

static bool is_filename(const char *token)
{
    /* No "/", has "." (extension), not a number/word/etc. */
    if (strchr(token, '/') != NULL) return false;
    if (strchr(token, '.') == NULL) return false;
    return true;
}

static bool is_url(const char *token)
{
    /* protocol://... */
    const char *colon = strchr(token, ':');
    if (!colon) return false;
    if (colon[1] != '/' || colon[2] != '/') return false;
    /* Check protocol part is alphabetic */
    for (const char *p = token; p < colon; p++) {
        if (!isalpha((unsigned char)*p)) return false;
    }
    return true;
}

static bool has_whitespace(const char *token)
{
    for (const char *p = token; *p; p++) {
        if (isspace((unsigned char)*p)) return true;
    }
    return false;
}

/* ============================================================
 * PUBLIC: CLASSIFY
 * ============================================================ */

st_token_type_t st_classify_token(const char *token)
{
    if (!token || !token[0]) return ST_TYPE_LITERAL;

    /* Absolute path */
    if (is_absolute_path(token)) return ST_TYPE_ABS_PATH;

    /* URL */
    if (is_url(token)) return ST_TYPE_URL;

    /* IPv4 */
    if (is_ipv4(token)) return ST_TYPE_IPV4;

    /* Hex hash (8+ hex chars, no 0x prefix for git-style hashes) */
    if (is_hex_hash(token)) return ST_TYPE_HEXHASH;

    /* Hex number (0x...) */
    if (is_hex_number(token)) return ST_TYPE_NUMBER;

    /* Decimal number */
    if (is_decimal_number(token)) return ST_TYPE_NUMBER;

    /* Relative path (has / or ..) */
    if (is_relative_path(token)) return ST_TYPE_REL_PATH;

    /* Filename (has ., no /) */
    if (is_filename(token)) return ST_TYPE_FILENAME;

    /* Words are LITERAL by default - they could be command names,
     * subcommands, or fixed arguments. Only classify as #w when
     * the context indicates a variable position (after long flags,
     * redirections, etc.) - handled by the caller. */

    /* Quoted string with whitespace */
    if (has_whitespace(token)) return ST_TYPE_QUOTED_SPACE;

    /* Default: literal */
    return ST_TYPE_LITERAL;
}

/* ============================================================
 * TOKENISATION
 * ============================================================ */

static char **tokenize_command(const char *raw_cmd, size_t *out_count)
{
    size_t len = strlen(raw_cmd);
    size_t max_tokens = len / 2 + 2;
    char **tokens = calloc(max_tokens, sizeof(char *));
    if (!tokens) return NULL;

    size_t count = 0;
    const char *p = raw_cmd;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        /* Check for pipe */
        if (*p == '|') {
            tokens[count] = strdup("|");
            if (!tokens[count]) goto fail;
            count++;
            p++;
            continue;
        }

        /* Check for redirection operators */
        bool found_redir = false;
        const char *redir_start = p;
        if (*p == '&' && (p[1] == '>' || (p[1] == '>' && p[2] == '>'))) {
            size_t rlen = (p[2] == '>') ? 3 : 2;
            tokens[count] = strndup(redir_start, rlen);
            if (!tokens[count]) goto fail;
            count++;
            p += rlen;
            found_redir = true;
        } else if (*p == '2' && (p[1] == '>' || (p[1] == '>' && p[2] == '>'))) {
            size_t rlen = (p[2] == '>') ? 3 : 2;
            tokens[count] = strndup(redir_start, rlen);
            if (!tokens[count]) goto fail;
            count++;
            p += rlen;
            found_redir = true;
        } else if (*p == '>' && p[1] == '>') {
            tokens[count] = strdup(">>");
            if (!tokens[count]) goto fail;
            count++;
            p += 2;
            found_redir = true;
        } else if (*p == '>' || *p == '<') {
            char buf[3] = { *p, '\0', '\0' };
            tokens[count] = strdup(buf);
            if (!tokens[count]) goto fail;
            count++;
            p++;
            found_redir = true;
        }
        if (found_redir) continue;

        /* Quoted string */
        char quote = 0;
        if (*p == '"' || *p == '\'') {
            quote = *p;
            p++;
            const char *start = p;
            while (*p && *p != quote) {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            tokens[count] = strndup(start, (size_t)(p - start));
            if (!tokens[count]) goto fail;
            count++;
            if (*p == quote) p++;
            continue;
        }

        /* Regular token */
        const char *start = p;
        while (*p && !isspace((unsigned char)*p) &&
               *p != '|' && *p != '>' && *p != '<' && *p != '&') {
            p++;
        }
        tokens[count] = strndup(start, (size_t)(p - start));
        if (!tokens[count]) goto fail;
        count++;
    }

    *out_count = count;
    return tokens;

fail:
    for (size_t i = 0; i < count; i++) free(tokens[i]);
    free(tokens);
    return NULL;
}

/* ============================================================
 * PUBLIC API: TYPED NORMALISATION
 * ============================================================ */

st_error_t st_normalize_typed(const char *raw_cmd, st_token_array_t *out)
{
    if (!raw_cmd || !out) return ST_ERR_INVALID;

    size_t raw_count = 0;
    char **raw_tokens = tokenize_command(raw_cmd, &raw_count);
    if (!raw_tokens) return ST_ERR_MEMORY;

    /* Worst case: every token splits into 2 (e.g., --flag=value → 2 tokens) */
    out->tokens = calloc(raw_count * 2, sizeof(st_token_t));
    if (!out->tokens) {
        for (size_t i = 0; i < raw_count; i++) free(raw_tokens[i]);
        free(raw_tokens);
        return ST_ERR_MEMORY;
    }
    out->count = 0;

    const char *prev = NULL;
    for (size_t i = 0; i < raw_count; i++) {
        const char *tok = raw_tokens[i];

        /* Handle --flag=value: split into --flag and value */
        if (tok[0] == '-' && tok[1] == '-') {
            const char *eq = strchr(tok + 2, '=');
            if (eq) {
                size_t flag_len = (size_t)(eq - tok);
                out->tokens[out->count].text = strndup(tok, flag_len);
                if (!out->tokens[out->count].text) goto fail;
                out->tokens[out->count].type = ST_TYPE_LITERAL;
                out->count++;

                out->tokens[out->count].text = strdup(eq + 1);
                if (!out->tokens[out->count].text) goto fail;
                out->tokens[out->count].type = st_classify_token(eq + 1);
                out->count++;

                prev = tok;
                continue;
            }
        }

        /* Handle env assignment: VAR=value → VAR= + value */
        bool is_env = false;
        const char *eq = strchr(tok, '=');
        if (eq && eq != tok) {
            is_env = true;
            for (const char *c = tok; c < eq; c++) {
                if (!isalnum((unsigned char)*c) && *c != '_') { is_env = false; break; }
            }
        }
        if (is_env) {
            size_t var_len = (size_t)(eq - tok);
            out->tokens[out->count].text = malloc(var_len + 2);
            if (!out->tokens[out->count].text) goto fail;
            memcpy(out->tokens[out->count].text, tok, var_len);
            out->tokens[out->count].text[var_len] = '=';
            out->tokens[out->count].text[var_len + 1] = '\0';
            out->tokens[out->count].type = ST_TYPE_LITERAL;
            out->count++;

            out->tokens[out->count].text = strdup(eq + 1);
            if (!out->tokens[out->count].text) goto fail;
            out->tokens[out->count].type = st_classify_token(eq + 1);
            out->count++;

            prev = tok;
            continue;
        }

        /* Pipes and redirections are structural literals */
        if (strcmp(tok, "|") == 0 ||
            strcmp(tok, ">") == 0 || strcmp(tok, ">>") == 0 ||
            strcmp(tok, "<") == 0 || strcmp(tok, "2>") == 0 ||
            strcmp(tok, "2>>") == 0 || strcmp(tok, "&>") == 0 ||
            strcmp(tok, "&>>") == 0 || strcmp(tok, ">&") == 0) {
            out->tokens[out->count].text = strdup(tok);
            if (!out->tokens[out->count].text) goto fail;
            out->tokens[out->count].type = ST_TYPE_LITERAL;
            out->count++;
            prev = tok;
            continue;
        }

        /* Long flag (--something) followed by a separate token → next token is a value.
         * Short flags (-X, -la) are kept as literals; we don't generalise their values. */
        if (prev && prev[0] == '-' && prev[1] == '-' && strchr(prev + 2, '=') == NULL) {
            /* This token is a value after a long flag */
            out->tokens[out->count].text = strdup(tok);
            if (!out->tokens[out->count].text) goto fail;
            out->tokens[out->count].type = st_classify_token(tok);
            out->count++;
            prev = tok;
            continue;
        }

        /* Token after a redirection operator → value */
        if (prev && (strcmp(prev, ">") == 0 || strcmp(prev, ">>") == 0 ||
                     strcmp(prev, "<") == 0 || strcmp(prev, "2>") == 0 ||
                     strcmp(prev, "2>>") == 0 || strcmp(prev, "&>") == 0 ||
                     strcmp(prev, "&>>") == 0 || strcmp(prev, ">&") == 0)) {
            out->tokens[out->count].text = strdup(tok);
            if (!out->tokens[out->count].text) goto fail;
            out->tokens[out->count].type = st_classify_token(tok);
            out->count++;
            prev = tok;
            continue;
        }

        /* Default: classify the token */
        out->tokens[out->count].text = strdup(tok);
        if (!out->tokens[out->count].text) goto fail;
        out->tokens[out->count].type = st_classify_token(tok);
        out->count++;
        prev = tok;
    }

    for (size_t i = 0; i < raw_count; i++) free(raw_tokens[i]);
    free(raw_tokens);
    return ST_OK;

fail:
    for (size_t i = 0; i < out->count; i++) free(out->tokens[i].text);
    free(out->tokens);
    out->tokens = NULL;
    out->count = 0;
    for (size_t i = 0; i < raw_count; i++) free(raw_tokens[i]);
    free(raw_tokens);
    return ST_ERR_MEMORY;
}

void st_free_token_array(st_token_array_t *arr)
{
    if (!arr) return;
    for (size_t i = 0; i < arr->count; i++) free(arr->tokens[i].text);
    free(arr->tokens);
    arr->tokens = NULL;
    arr->count = 0;
}

/* ============================================================
 * PUBLIC API: LEGACY STRING NORMALISATION
 * ============================================================ */

st_error_t st_normalize(const char *raw_cmd, char ***out_tokens, size_t *out_token_count)
{
    if (!raw_cmd || !out_tokens || !out_token_count) return ST_ERR_INVALID;

    st_token_array_t typed;
    typed.tokens = NULL;
    typed.count = 0;
    st_error_t err = st_normalize_typed(raw_cmd, &typed);
    if (err != ST_OK) return err;

    char **tokens = calloc(typed.count, sizeof(char *));
    if (!tokens) {
        st_free_token_array(&typed);
        return ST_ERR_MEMORY;
    }

    for (size_t i = 0; i < typed.count; i++) {
        if (typed.tokens[i].type == ST_TYPE_LITERAL) {
            tokens[i] = strdup(typed.tokens[i].text);
        } else {
            tokens[i] = strdup(st_type_symbol[typed.tokens[i].type]);
        }
        if (!tokens[i]) {
            for (size_t j = 0; j < i; j++) free(tokens[j]);
            free(tokens);
            st_free_token_array(&typed);
            return ST_ERR_MEMORY;
        }
    }

    *out_tokens = tokens;
    *out_token_count = typed.count;
    st_free_token_array(&typed);
    return ST_OK;
}

void st_free_tokens(char **tokens, size_t count)
{
    if (!tokens) return;
    for (size_t i = 0; i < count; i++) free(tokens[i]);
    free(tokens);
}
