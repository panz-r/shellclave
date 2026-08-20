/*
 * shelltype.h - Shell command type classifier and policy engine
 *
 * Observes allowed commands and incrementally suggests generalised policy
 * rules. Uses a Normalised Command Trie (NCT) with typed wildcards to
 * generalise variable parts of commands while maintaining precise control over
 * policy scope.
 */

#ifndef SHELLTYPE_H
#define SHELLTYPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- ERROR CODES --- */

typedef enum {
  ST_OK = 0,
  ST_ERR_INVALID = -1,
  ST_ERR_MEMORY = -2,
  ST_ERR_IO = -3,
  ST_ERR_FAILED = -4,
  ST_ERR_FORMAT = -5,
  ST_ERR_LIMIT = -6,
} st_error_t;

/**
 * Return a human-readable string for an st_error_t code.
 */
const char *st_error_string(st_error_t err);

/* --- CONSTANTS --- */

#define ST_DEFAULT_MIN_SUPPORT 5       /* Minimum count to suggest a rule */
#define ST_DEFAULT_MIN_CONFIDENCE 0.05 /* Minimum confidence threshold */
#define ST_DEFAULT_MAX_SUGGESTIONS 20  /* Max suggestions per query */
#define ST_MAX_PATTERN_LEN 1024        /* Max length of a pattern string */
#define ST_MAX_TOKEN_LEN 256           /* Max length of a single token */
#define ST_MAX_CMD_TOKENS 128          /* Max tokens in a command/pattern */
#define ST_MAX_SAMPLE_VALUES                                                   \
  32 /* Max original values stored per variable node */
#define ST_INITIAL_CHILDREN_CAP 4 /* Initial capacity for children array */
#define ST_MAX_TOKEN_VARIANTS 8   /* Max type variants for edit UI */

/* --- TOKEN TYPE LATTICE --- */

/*
 * Ordering (⊂ = strict subset):
 *   #sha ⊂ #h ⊂ #val ⊂ *
 *   #n ⊂ #val ⊂ *
 *   #i, #ipv6 ⊂ #ipaddr ⊂ #val ⊂ *
 *   #w ⊂ #val ⊂ *
 *   #q ⊂ #qs ⊂ #val ⊂ *
 *   #f ⊂ #r ⊂ #path ⊂ *
 *   #p ⊂ #path ⊂ *
 *   #u ⊂ *
 *   #method ⊂ #w ⊂ #val ⊂ *
 *   #mac, #cron, #duration, #regex, #glob, #range, #signal,
 *   #user_group, #perm ⊂ #val ⊂ *
 *
 * #f and #w are incomparable (a filename is not a word, a word is not a
 * filename). #hash, #hyp ⊂ #w ⊂ #val ⊂ *
 * Ambiguous tokens (e.g., "Makefile") could be #w or #f and require user
 * disambiguation.
 */

typedef enum {
  ST_TYPE_LITERAL = 0,  /* Exact string match (bottom element) */
  ST_TYPE_HEXHASH,      /* #h: 8+ hex chars (e.g., deadbeef) */
  ST_TYPE_NUMBER,       /* #n: decimal, hex, octal integers */
  ST_TYPE_IPV4,         /* #i: dotted decimal (192.168.1.1) */
  ST_TYPE_IPV6,         /* #ipv6: IPv6 address (2001:db8::1, ::1) */
  ST_TYPE_IPADDR,       /* #ipaddr: any IP address (#i ∨ #ipv6) */
  ST_TYPE_WORD,         /* #w: [a-zA-Z_][a-zA-Z0-9_]* */
  ST_TYPE_QUOTED,       /* #q: quoted string, no whitespace */
  ST_TYPE_QUOTED_SPACE, /* #qs: quoted string with whitespace */
  ST_TYPE_FILENAME,     /* #f: no /, has . extension */
  ST_TYPE_REL_PATH,     /* #r: has .. or / but not ^/ */
  ST_TYPE_ABS_PATH,     /* #p: starts with / */
  ST_TYPE_PATH,         /* #path: any path type (#p ∨ #r ∨ #f) */
  ST_TYPE_URL,          /* #u: protocol://... */
  ST_TYPE_VALUE,        /* #val: any scalar (#n ∨ #i ∨ #w ∨ #q ∨ #qs) */
  ST_TYPE_SHORTOPT,     /* #sopt: short option (-v, -la, -rf) */
  ST_TYPE_LONGOPT,      /* #lopt: long option (--help, --verbose) */
  ST_TYPE_OPT,          /* #opt: any option (#sopt ∨ #lopt) */
  ST_TYPE_UUID,         /* #uuid: UUID format (8-4-4-4-12 hex) */
  ST_TYPE_EMAIL,        /* #email: user@domain format */
  ST_TYPE_HOSTNAME,     /* #host: hostname or domain name */
  ST_TYPE_PORT,         /* #port: port number (1-65535) */
  ST_TYPE_SIZE,         /* #size: size with suffix (10M, 2GiB) */
  ST_TYPE_SEMVER,       /* #semver: semantic version (1.2.3-alpha) */
  ST_TYPE_TIMESTAMP,    /* #ts: ISO 8601 date/time */
  ST_TYPE_HASH_ALGO,    /* #hash: crypto hash algorithm name */
  ST_TYPE_ENV_VAR,      /* #env: $VAR or ${VAR} */
  ST_TYPE_HYPHENATED,   /* #hyp: hyphenated identifier (a-b where a,b are 1+
                           alnum/_ chars) */
  ST_TYPE_BRANCH, /* #branch: git branch/ref name (main, feature/x, release/v2)
                   */
  ST_TYPE_SHA,    /* #sha: SHA/hash digest (7-64 hex chars) */
  ST_TYPE_IMAGE,  /* #image: container image ref (nginx:latest, ghcr.io/org/app)
                   */
  ST_TYPE_PKG,    /* #pkg: package specifier (express, @babel/core@^7) */
  ST_TYPE_USER,   /* #user: unix username (root, www-data, deploy-user) */
  ST_TYPE_FINGERPRINT, /* #fp: SSH key fingerprint (SHA256:xxx or MD5 hex
                          colons) */
  ST_TYPE_MAC,         /* #mac: MAC address (aa:bb:cc:dd:ee:ff) */
  ST_TYPE_METHOD,      /* #method: HTTP method (GET, POST, PUT, etc.) */
  ST_TYPE_CRON,        /* #cron: cron schedule field */
  ST_TYPE_DURATION,    /* #duration: time duration (30s, 1.5h, 100ms) */
  ST_TYPE_REGEX,       /* #regex: regular expression pattern */
  ST_TYPE_GLOB,        /* #glob: glob pattern (*.txt, file?.log) */
  ST_TYPE_RANGE,       /* #range: numeric range (1-5, 0,30) */
  ST_TYPE_SIGNAL,      /* #signal: signal name/number (HUP, SIGTERM, 9) */
  ST_TYPE_USER_GROUP,  /* #user_group: user:group spec (root:docker) */
  ST_TYPE_PERM_OCTAL,  /* #perm: octal permission (755, 0644) */
  ST_TYPE_ANY,         /* *: everything (top element) */
  ST_TYPE_COUNT        /* number of types */
} st_token_type_t;

/**
 * String representation of each token type (for display and serialization).
 * Indexed by st_token_type_t.
 */
extern const char *st_type_symbol[ST_TYPE_COUNT];

/**
 * Join table: st_type_join[a][b] = narrowest type covering both a and b.
 * Indexed by st_token_type_t.
 */
extern const st_token_type_t st_type_join[ST_TYPE_COUNT][ST_TYPE_COUNT];

/**
 * Compatibility table: st_type_compatible[cmd_type][policy_type] is true
 * if a command token of cmd_type matches a policy node of policy_type.
 * Equivalent to: cmd_type ≤ policy_type in the lattice.
 */
extern const bool st_type_compatible[ST_TYPE_COUNT][ST_TYPE_COUNT];

/**
 * Return the join of two token types (narrowest type covering both).
 */
static inline st_token_type_t st_join(st_token_type_t a, st_token_type_t b) {
  return st_type_join[a][b];
}

/**
 * Check if a command token type is compatible with a policy node type.
 * Returns true if cmd_type ≤ policy_type in the lattice.
 */
static inline bool st_is_compatible(st_token_type_t cmd_type,
                                    st_token_type_t policy_type) {
  return st_type_compatible[cmd_type][policy_type];
}

/* --- TYPED TOKEN --- */

/**
 * A token with its classified type.
 */
typedef struct st_token {
  char *text; /* Token text (for literals) or type symbol (for wildcards) */
  st_token_type_t type; /* Classified type */
} st_token_t;

/**
 * Array of typed tokens returned by st_normalize_typed().
 */
typedef struct st_token_array {
  st_token_t *tokens;
  size_t count;
} st_token_array_t;

/* --- DATA STRUCTURES (Learner Trie) --- */

/**
 * A node in the Normalised Command Trie.
 * Each node represents one token in a normalised command sequence.
 */
typedef struct st_node {
  char *token;             /* Normalised token text or type symbol */
  st_token_type_t type;    /* Token type (ST_TYPE_LITERAL for exact match) */
  uint32_t count;          /* Number of commands reaching this node */
  uint64_t observed_types; /* Bitmask of types observed at this position */
  char **sample_values;    /* Original token values seen (for debugging) */
  size_t num_samples;      /* Number of samples stored */
  uint32_t metadata_observations; /* Typed values considered for metadata */
  uint16_t common_metadata;       /* Internal closed-vocabulary metadata id */
  bool metadata_mixed;            /* Metadata differed or was unavailable */
  struct st_node **children;      /* Array of child pointers */
  size_t num_children;
  size_t children_capacity;
} st_node_t;

/**
 * The trie itself – a root node and a total command counter.
 */
typedef struct st_trie {
  st_node_t *root;
  uint32_t total_commands; /* Total number of commands fed */
} st_trie_t;

/**
 * A suggestion candidate generated from the trie.
 */
typedef struct st_suggestion {
  char *pattern;     /* Complete policy rule, e.g. "git commit -m #n" */
  uint32_t count;    /* Number of learned commands fully matched by the rule */
  double confidence; /* Support relative to commands at its divergence */
} st_suggestion_t;

/**
 * Main learner handle.
 */
typedef struct st_learner {
  st_trie_t trie;
  uint32_t min_support;   /* Minimum count to suggest (default 5) */
  double min_confidence;  /* Minimum confidence (default 0.05) */
  size_t max_suggestions; /* Max suggestions per query (default 20) */
  char **blacklist;       /* Patterns the user rejected */
  size_t blacklist_count;
  size_t blacklist_capacity;
} st_learner_t;

/* --- LIFECYCLE --- */

st_learner_t *st_learner_new(uint32_t min_support, double min_confidence);
void st_learner_free(st_learner_t *learner);

/* --- FEEDING COMMANDS --- */

/* Feed operations are atomic: on error the learner is unchanged. raw_cmd is
 * one already-isolated, execute-program-style subcommand, not a compound shell
 * program. Tokens at or above ST_MAX_TOKEN_LEN are rejected. Use
 * st_feed_parsed when exact token boundaries are already available. */
st_error_t st_feed(st_learner_t *learner, const char *raw_cmd);
st_error_t st_feed_parsed(st_learner_t *learner, const char *raw_cmd,
                          const void *parse);

/* --- SUGGESTIONS --- */

/* Returns complete policy rules, never command prefixes. Returns NULL and
 * clears out_count when no suggestions can be produced or the learner is
 * invalid. */
st_suggestion_t *st_suggest(st_learner_t *learner, size_t *out_count);
void st_free_suggestions(st_suggestion_t *suggestions, size_t count);

/* --- BLACKLIST --- */

st_error_t st_blacklist_add(st_learner_t *learner, const char *pattern);
bool st_is_blacklisted(const st_learner_t *learner, const char *pattern);

/* --- SERIALISATION --- */

/* Learner state uses the strict v3 node format; older formats are rejected.
 * Successful saves use synchronized same-directory atomic replacement.
 * Concurrent saves to the same destination require external synchronization.
 */
st_error_t st_save(const st_learner_t *learner, const char *path);
st_error_t st_load(st_learner_t *learner, const char *path);

/* --- NORMALISATION (public for testing) --- */

/**
 * Normalise a raw command string into an array of typed tokens.
 * Each token is classified into the most specific type in the lattice.
 * Token text remains the complete concrete input token; it is never replaced
 * with a synthesized wildcard or metadata-bearing symbol.
 * The input is one already-isolated, execute-program-style subcommand. Shell
 * control flow and compound command isolation belong to an upstream parser.
 * Commands with more than ST_MAX_CMD_TOKENS tokens return ST_ERR_INVALID.
 *
 * The caller must free the returned array with st_free_token_array().
 */
st_error_t st_normalize_typed(const char *raw_cmd, st_token_array_t *out);

/**
 * Free a typed token array.
 */
void st_free_token_array(st_token_array_t *arr);

/**
 * Legacy: normalise into string tokens (backward compatible).
 * Wildcard tokens use their type symbol (e.g., "#n", "#p", "*").
 */
st_error_t st_normalize(const char *raw_cmd, char ***out_tokens,
                        size_t *out_token_count);

/**
 * Free a string token array.
 */
void st_free_tokens(char **tokens, size_t count);

/**
 * Classify a single token string into its most specific type.
 * Returns ST_TYPE_LITERAL if no wildcard type matches.
 */
st_token_type_t st_classify_token(const char *token);

/**
 * Classify a pattern token string (e.g., "#val", "*") into its st_token_type_t.
 * Returns ST_TYPE_LITERAL if token is NULL, empty, or doesn't start with '#'.
 * Used by the type-lattice walker and trie-based variant collection.
 */
st_token_type_t st_type_from_pattern_token(const char *token);

/**
 * Extract the file extension from a path (including dot).
 * Returns NULL if no extension found.
 */
const char *st_path_extension(const char *text);

/**
 * Extract the size suffix from a size token.
 * Returns pointer after last digit/dot, or NULL if no suffix.
 */
const char *st_size_suffix(const char *text);

/* --- POLICY STATISTICS --- */

/**
 * Policy statistics for monitoring and tuning.
 */
typedef struct {
  uint64_t eval_count;           /* Total evaluations */
  uint64_t filter_reject_count;  /* Pre-filter rejected count */
  uint64_t trie_walk_count;      /* Evaluations that reached trie walk */
  uint64_t suggestion_count;     /* Suggestion pairs generated */
  uint64_t filter_rebuild_count; /* Number of filter rebuilds triggered */
  uint64_t
      filter_rebuild_us; /* Cumulative filter rebuild time (microseconds) */
  size_t pattern_count;  /* Current number of active patterns */
  size_t state_count;    /* Number of trie states */
  size_t memory_bytes;   /* Total memory usage */
} st_policy_stats_t;

/* --- POLICY MODULE (arena-allocated, NFA-renderable) --- */

/**
 * Shared policy context: stable chunk allocator, string pool, and shared state.
 * Multiple policies can share a context to deduplicate token strings
 * across policy sets.
 *
 * Reference counting and string interning are thread-safe, including when
 * several policies share a context. Use st_policy_ctx_retain() when creating a
 * policy and st_policy_ctx_release() when freeing it. Reset is only allowed
 * when refcount == 1 (only the context itself holds a reference).
 */
typedef struct st_policy_ctx st_policy_ctx_t;

/**
 * Opaque policy trie stored in a shared policy context.
 *
 * Concurrent logical readers of a stable policy are supported, including
 * evaluation, verification, diagnostics, save, and graph export. Although
 * evaluation may warm internal caches, it remains a logical read operation.
 * Pattern mutation, load, merge, compaction, clear, and destruction require
 * external serialization against every other operation on that policy.
 */
typedef struct st_policy st_policy_t;

/* The policy trie stores active pattern identifiers in 16 bits. */
#define ST_MAX_POLICY_PATTERNS UINT16_MAX

/**
 * NFA render options.
 */
typedef struct {
  uint8_t category_mask;    /* Accepting category (0x01=safe, etc.) */
  uint32_t pattern_id_base; /* Starting pattern_id for this policy */
  bool include_tags;        /* Emit Tags: lines in NFA output */
  const char *identifier;   /* NFA header identifier string (NULL = default) */
} st_nfa_render_opts_t;

/* --- Context lifecycle --- */

st_policy_ctx_t *st_policy_ctx_new(void);
st_policy_ctx_t *st_policy_ctx_new_with_arena(size_t arena_size);
void st_policy_ctx_free(st_policy_ctx_t *ctx);
void st_policy_ctx_retain(st_policy_ctx_t *ctx);
void st_policy_ctx_release(st_policy_ctx_t *ctx);
st_error_t st_policy_ctx_reset(st_policy_ctx_t *ctx);
const char *st_policy_ctx_intern(st_policy_ctx_t *ctx, const char *str);

/* --- Context introspection (internal use) --- */

/**
 * Check if exactly one policy uses the context (refcount == 2: the caller's
 * context reference plus one policy reference). Used by st_policy_compact to
 * verify that rebuilding cannot invalidate another policy.
 */
bool st_policy_ctx_is_exclusive(const st_policy_ctx_t *ctx);

/**
 * Reset the context's arena and string pool to reclaim memory.
 * Discards all interned strings and arena data. Only safe when no policies
 * reference this context (refcount == 1). Equivalent to destroying and
 * recreating the context, but preserves the handle.
 */
st_error_t st_policy_ctx_compact(st_policy_ctx_t *ctx);

/* --- Policy lifecycle --- */

st_policy_t *st_policy_new(st_policy_ctx_t *ctx);
void st_policy_free(st_policy_t *policy);

/* --- Pattern management --- */

st_error_t st_policy_add(st_policy_t *policy, const char *pattern);
/* Adds all patterns atomically; on failure the policy is unchanged. */
st_error_t st_policy_batch_add(st_policy_t *policy, const char **patterns,
                               size_t count);
st_error_t st_policy_remove(st_policy_t *policy, const char *pattern);
size_t st_policy_count(const st_policy_t *policy);

/* --- Verification --- */

/**
 * A suggestion for expanding a policy to cover a new command.
 * Fixed-size buffer — no allocation, no cleanup needed.
 */
typedef struct {
  char pattern[ST_MAX_PATTERN_LEN];
  /* Borrowed from policy storage. Valid only while the owning policy remains
   * stable; mutation, load, clear, compaction, or destruction invalidates it.
   */
  const char *based_on; /* Existing pattern this extends, or NULL */
  double confidence;    /* matched_prefix_tokens / total_cmd_tokens */
} st_expand_suggestion_t;

/**
 * Result of st_policy_eval. Caller passes a pointer to this struct.
 */
typedef struct {
  bool matches;
  /* Borrowed from policy storage. Valid only while the owning policy remains
   * stable; mutation, load, clear, compaction, or destruction invalidates it.
   */
  const char *matching_pattern; /* NULL if no match */
  size_t suggestion_count;      /* 0-2, only filled if !matches */
  st_expand_suggestion_t suggestions[2];
  st_error_t error; /* ST_ERR_FAILED if build fails */
} st_eval_result_t;

/**
 * Unified evaluate + suggest.
 *
 * Walks the policy trie with one already-isolated, execute-program-style
 * subcommand. Compound shell syntax must be split by an upstream parser. If it
 * matches, sets
 * result->matches=true and result->matching_pattern.
 * When several patterns match, matching_pattern is the narrowest pattern;
 * equivalent or incomparable matches are ordered lexicographically.
 *
 * If it doesn't match and result is non-NULL, generates up to 2
 * expansion suggestions in result->suggestions[].
 *
 * Passing NULL for result disables suggestions (verify-only fast path).
 *
 * NOTE: This function has side effects — it may rebuild internal
 * position filters if the policy epoch has changed (cache warming).
 */
st_error_t st_policy_eval(st_policy_t *policy, const char *raw_cmd,
                          st_eval_result_t *result);

/* On failure, each writable output is cleared even when another argument is
 * invalid. */
st_error_t st_policy_verify_all(const st_policy_t *policy, const char *raw_cmd,
                                const char ***matching_patterns,
                                size_t *match_count);

void st_policy_free_matches(const char **matches, size_t count);

/* --- NFA rendering --- */

/* Provisional Shellclave-to-c-dfa graph export. Each typed transition contains
 * one predefined lattice symbol plus an optional canonical metadata
 * annotation. Metadata is not a new lattice element and is never copied from
 * concrete token text. The interchange format is not yet stable. Successful
 * renders use synchronized same-directory atomic replacement. */
st_error_t st_policy_render_nfa(const st_policy_t *policy, const char *path,
                                const st_nfa_render_opts_t *opts);

/* --- Serialization --- */

/* A successful save synchronizes the complete temporary file, atomically
 * replaces path, and synchronizes its parent directory. ST_ERR_IO after the
 * atomic replacement can leave either the previous or new complete file
 * durable across a crash. Concurrent saves to the same path require external
 * synchronization. */
st_error_t st_policy_save(const st_policy_t *policy, const char *path);
st_error_t st_policy_load(st_policy_t *policy, const char *path,
                          bool clear_first);
st_error_t st_policy_compact(st_policy_t *policy);
st_error_t st_policy_clear(st_policy_t *policy);

/* --- Merge --- */

/**
 * Merge all patterns from src into dst. Duplicates are skipped.
 * Takes write lock on dst, read lock on src.
 * The merge is atomic: on failure, dst is unchanged. Returns ST_OK on success
 * or the error that prevented the merge.
 */
st_error_t st_policy_merge(st_policy_t *dst, const st_policy_t *src);

/* --- Diff --- */

/**
 * Compare two policies and return lists of added/removed patterns.
 * Patterns in b but not a are "added"; patterns in a but not b are "removed".
 * Caller must free the returned arrays with st_free_diff_result().
 * Takes read lock on both policies.
 */
typedef struct {
  char **added;
  size_t added_count;
  char **removed;
  size_t removed_count;
} st_policy_diff_t;

st_error_t st_policy_diff(const st_policy_t *a, const st_policy_t *b,
                          st_policy_diff_t *result);
void st_free_diff_result(st_policy_diff_t *result);

/* --- Diagnostics --- */

size_t st_policy_memory_usage(const st_policy_t *policy);
size_t st_policy_working_set(const st_policy_t *policy);
size_t st_policy_state_count(const st_policy_t *policy);

/* --- Statistics --- */

/**
 * Get policy statistics for monitoring and tuning.
 */
void st_policy_get_stats(const st_policy_t *policy, st_policy_stats_t *stats);

/* --- DOT graph export --- */

/**
 * Dump the policy trie as a GraphViz DOT file for debugging.
 * Shows states (nodes) and transitions (edges), highlighting accepting states.
 */
st_error_t st_policy_dump_dot(const st_policy_t *policy, const char *path);

/* --- Dry-run mode --- */

/**
 * Simulate adding a pattern without modifying the policy.
 * Reports whether an existing pattern subsumes the proposed pattern. When it
 * does, conflicting_pattern receives the canonical existing pattern that
 * makes the proposal redundant. A broader proposal that would replace an
 * existing narrower pattern is not reported as redundant.
 */
st_error_t st_policy_simulate_add(st_policy_t *policy, const char *pattern,
                                  bool *would_match,
                                  const char **conflicting_pattern);

/* --- Pattern validation --- */

/**
 * Parsed token details from pattern validation.
 * Fixed-size buffers — no allocation, no cleanup needed.
 */
typedef struct {
  size_t token_count;                                    /* number of tokens */
  char token_texts[ST_MAX_CMD_TOKENS][ST_MAX_TOKEN_LEN]; /* token text */
  st_token_type_t token_types[ST_MAX_CMD_TOKENS];        /* token type */
} st_pattern_info_t;

/**
 * Validate pattern syntax and parameter validity without modifying any policy.
 * If info is non-NULL, fills in parsed token details on success.
 * Returns ST_OK if valid, ST_ERR_INVALID on bad syntax or unknown parameter.
 */
st_error_t st_validate_pattern(const char *pattern, st_pattern_info_t *info);

/* --- POLICY EXPANSION SUGGESTIONS (Miner) --- */

/**
 * Step 2: Given a chosen pattern (as typed tokens), suggest up to 3
 * generalizations by widening one non-literal token at a time.
 * Also includes the exact-match-as-literal variant.
 *
 * Caller allocates out[3]. No cleanup needed.
 */
/* Single token variant for edit UI (one option in the list) */
typedef struct st_token_variant {
  st_token_type_t type;    /* The type to suggest */
  const char *type_symbol; /* Static type symbol, e.g. "#path" or "*" */
  /* Borrowed from learner storage. Valid only while the learner remains
   * stable; feeding, loading, or destruction may invalidate it. */
  const char *sample_value; /* Optional sample from history (can be NULL) */
} st_token_variant_t;

/* Returns zero and clears all three outputs if an allocation fails, any
 * candidate exceeds ST_MAX_PATTERN_LEN, or an input token cannot be represented
 * faithfully by the space-delimited policy grammar. */
size_t st_policy_suggest_variants(const st_policy_t *policy,
                                  const st_token_t *tokens, size_t token_count,
                                  st_expand_suggestion_t out[3]);
/* --- TOKEN VARIANT EDITING (for TUI edit mode) --- */

/**
 * Suggest type variants for editing a specific token position in a pattern.
 *
 * Given a pattern with tokens and an edit position, walks the learner trie
 * to find observed type variants at that position. The current type is kept
 * first when it was observed. Remaining alternatives are deterministic and
 * ordered from more specific to more general; incomparable alternatives use
 * st_token_type_t order as a stable tie-break. If the result is truncated,
 * that same order decides which alternatives are retained. Except at command
 * position zero, where policy grammar forbids it, the wildcard (*) is always
 * the final, most-general option.
 *
 * @param learner    The learner/trie context
 * @param pattern_tokens  Array of pattern token strings (e.g., ["git", "#p"])
 * @param token_count    Number of tokens in pattern
 * @param edit_pos       Position to edit (0-indexed)
 * @param out_variants   Output array (caller allocates ST_MAX_TOKEN_VARIANTS
 * entries)
 * @return Number of variants written to out_variants, or zero if the input
 *         token array cannot be represented by policy grammar
 */
size_t st_policy_suggest_token_variants(st_learner_t *learner,
                                        const char **pattern_tokens,
                                        size_t token_count, size_t edit_pos,
                                        st_token_variant_t *out_variants);

/**
 * Apply a type change to a pattern at a given position.
 *
 * @param learner      The learner context (unused, kept for future expansion)
 * @param pattern_tokens  Original pattern tokens
 * @param token_count     Number of tokens
 * @param edit_pos        Position to change
 * @param new_type        New type to set at that position
 * @return Newly allocated string with the type applied (caller must free), or
 *         NULL for invalid input, an overlong result, or allocation failure
 */
char *st_policy_apply_type_at(st_learner_t *learner,
                              const char **pattern_tokens, size_t token_count,
                              size_t edit_pos, st_token_type_t new_type);

#ifdef __cplusplus
}
#endif

#endif /* SHELLTYPE_H */
