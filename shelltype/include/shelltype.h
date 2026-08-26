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
#define ST_MAX_NETPATTERN_LEN 4096     /* Max canonical encoded pattern */
#define ST_MAX_TOKEN_LEN 256           /* Max length of a single token */
#define ST_MAX_CMD_TOKENS 128          /* Max tokens in a command/pattern */
#define ST_MAX_CPL_LEN                                                         \
  (ST_MAX_NETPATTERN_LEN * 6 + ST_MAX_CMD_TOKENS * 3) /* Max rendered CPL */
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
 * A token with its classified type. Input APIs borrow every string. Tokens
 * returned through st_token_array_t own their strings as one array result and
 * must be released with st_token_array_free().
 */
typedef struct st_token {
  const char *text;     /* Borrowed input or read-only array-owned value */
  st_token_type_t type; /* Classified type */
  /* A compound token still occupies exactly one argv position. Its concrete
   * or policy value is prefix + capture + suffix. The first implementation is
   * deliberately bounded to one classified/typed capture. */
  bool compound;
  const char *prefix;
  const char *capture;
  const char *suffix;
  st_token_type_t capture_type;
} st_token_t;

/**
 * Array of typed tokens returned by st_netargv_classify().
 */
typedef struct st_token_array {
  /* Owns the allocation backing the strings returned by classify/decode. */
  st_token_t *tokens;
  size_t count;
} st_token_array_t;

/* Borrowed classified netargv payload. `text` is not NUL-terminated and is
 * valid only for the duration of an st_netargv_visit() callback. */
typedef struct {
  const char *text;
  size_t text_length;
  st_token_type_t type;
} st_token_view_t;

/* A borrowed canonical netargv span. `data` may be NULL only when `length`
 * is zero. Netargv remains Shellclave's NUL-free transport: embedded NUL
 * bytes are invalid even though generic netstring payloads may contain them.
 */
typedef struct {
  const char *data;
  size_t length;
} st_netargv_view_t;

/* --- DATA STRUCTURES (Learner Trie) --- */

/**
 * A node in the Normalised Command Trie.
 * Each node represents one token in a normalised command sequence.
 */
typedef struct st_learner st_learner_t;

/**
 * A suggestion candidate generated from the trie.
 */
typedef struct st_suggestion {
  char *pattern;     /* Complete canonical netpattern policy rule */
  uint32_t count;    /* Number of learned commands fully matched by the rule */
  double confidence; /* Support relative to commands at its divergence */
} st_suggestion_t;

/**
 * Main learner handle.
 */
typedef struct {
  uint32_t min_support;
  double min_confidence;
  size_t max_suggestions;
} st_learner_config_t;

typedef struct {
  uint32_t command_count;
  size_t blacklist_count;
} st_learner_stats_t;

/* --- LIFECYCLE --- */

/* Initializes every field to its documented default. NULL is a no-op. */
void st_learner_config_default(st_learner_config_t *config);

/* NULL selects the documented defaults for every option. A non-NULL config is
 * copied exactly: min_support = 0 permits zero support and
 * max_suggestions = 0 disables suggestions. */
st_learner_t *st_learner_new(const st_learner_config_t *config);
void st_learner_free(st_learner_t *learner);
st_error_t st_learner_get_config(const st_learner_t *learner,
                                 st_learner_config_t *config);
st_error_t st_learner_set_config(st_learner_t *learner,
                                 const st_learner_config_t *config);
void st_learner_get_stats(const st_learner_t *learner,
                          st_learner_stats_t *stats);

/* --- FEEDING COMMANDS --- */

/* Feed operations are atomic: on error the learner is unchanged. netargv is a
 * canonical concatenation of netstrings, one per already-preprocessed argv
 * element: <decimal byte length>:<bytes>,. Payloads cannot contain NUL. For
 * example, argv {"printf", "two words"} is "6:printf,9:two words,". It is not
 * shell source. Shellsplit is one valid producer, but callers may provide an
 * equivalent trusted argv. Empty arguments and embedded whitespace are
 * preserved. Arguments at or above ST_MAX_TOKEN_LEN are rejected. */
st_error_t st_learner_feed_netargv(st_learner_t *learner, const char *netargv);
/* Length-aware form of st_learner_feed_netargv(). It uses the supplied length
 * directly instead of scanning for a NUL terminator. */
st_error_t st_learner_feed_netargv_view(st_learner_t *learner,
                                        st_netargv_view_t netargv);
st_error_t st_learner_feed_tokens(st_learner_t *learner,
                                  const st_token_array_t *typed);

/* --- SUGGESTIONS --- */

/* Returns complete policy rules, never command prefixes. Returns NULL and
 * clears out_count when no suggestions can be produced or the learner is
 * invalid. */
st_suggestion_t *st_learner_suggest(st_learner_t *learner, size_t *out_count);
void st_suggestion_list_free(st_suggestion_t *suggestions, size_t count);

/* --- BLACKLIST --- */

st_error_t st_learner_blacklist_add_netpattern(st_learner_t *learner,
                                               const char *netpattern);
bool st_learner_is_netpattern_blacklisted(const st_learner_t *learner,
                                          const char *netpattern);

/* --- SERIALISATION --- */

/* Learner state uses the strict framed v5 format. Each node is an outer
 * netstring containing canonical netstring fields, and the record stream is
 * protected by a declared count and CRC32. Older formats are rejected.
 * Successful saves use synchronized same-directory atomic replacement.
 * Concurrent saves to the same destination require external synchronization.
 */
st_error_t st_learner_save(const st_learner_t *learner, const char *path);
st_error_t st_learner_load(st_learner_t *learner, const char *path);

/* --- CLASSIFICATION --- */

/**
 * Classify canonical netstring-encoded argv into typed tokens.
 * Each token is classified into the most specific type in the lattice.
 * Token text remains the complete concrete input token; it is never replaced
 * with a synthesized wildcard or metadata-bearing symbol.
 * `netargv` uses the canonical concatenated-netstring format documented for
 * st_learner_feed_netargv. Its elements must already be the argv of one
 * isolated subcommand. Shell tokenization, control-flow isolation, redirection
 * removal, quote-fragment assembly, and escape processing belong upstream. This
 * function decodes argument boundaries and assigns types; it does not tokenize
 * shell text. Non-canonical or malformed encodings return ST_ERR_FORMAT.
 *
 * The caller must free the returned array with st_token_array_free(). The
 * `*_view` form below uses its supplied length directly instead of scanning for
 * a NUL terminator.
 */
st_error_t st_netargv_classify(const char *netargv, st_token_array_t *out);
st_error_t st_netargv_classify_view(st_netargv_view_t netargv,
                                    st_token_array_t *out);

typedef bool (*st_netargv_token_visitor_t)(const st_token_view_t *token,
                                           void *user_ctx);

/* Classify canonical netargv without allocating or copying token payloads.
 * The callback sees each concrete payload as a borrowed span; returning false
 * stops successfully. If non-NULL, visited_count receives callback
 * invocations. Classification has the same contextual rules as
 * st_netargv_classify(). The `*_view` form uses its supplied length directly
 * instead of scanning for a NUL terminator. */
st_error_t st_netargv_visit(const char *netargv,
                            st_netargv_token_visitor_t visitor, void *user_ctx,
                            size_t *visited_count);
st_error_t st_netargv_visit_view(st_netargv_view_t netargv,
                                 st_netargv_token_visitor_t visitor,
                                 void *user_ctx, size_t *visited_count);

/**
 * Free a typed token array.
 */
void st_token_array_free(st_token_array_t *arr);

/**
 * Classify a single token string into its most specific type.
 * Returns ST_TYPE_LITERAL if no wildcard type matches.
 */
st_token_type_t st_token_classify(const char *token);

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
 * several policies share a context. A new policy retains its context; release
 * the caller reference when it is no longer needed. Reset is only allowed
 * when refcount == 1 (only the caller reference remains).
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
/* A new context carries one caller reference. Release it when no longer
 * needed; the final release destroys the context. */
void st_policy_ctx_retain(st_policy_ctx_t *ctx);
void st_policy_ctx_release(st_policy_ctx_t *ctx);
st_error_t st_policy_ctx_reset(st_policy_ctx_t *ctx);

/* --- Policy lifecycle --- */

st_policy_t *st_policy_new(st_policy_ctx_t *ctx);
void st_policy_free(st_policy_t *policy);

/* --- Pattern management --- */

/* Convert between human CPL and canonical nested tagged netpatterns. The
 * caller owns the successful output and frees it with free(). */
st_error_t st_netpattern_from_cpl(const char *cpl, char **out_netpattern);
st_error_t st_netpattern_to_cpl(const char *netpattern, char **out_cpl);
st_error_t st_netpattern_encode(const st_token_t *tokens, size_t count,
                                char **out_netpattern);
st_error_t st_netpattern_decode(const char *netpattern,
                                st_token_array_t *out_tokens);
/* Policy mutation accepts canonical nested tagged netpatterns only. Human CPL
 * must be converted explicitly with st_netpattern_from_cpl(). */
st_error_t st_policy_add_netpattern(st_policy_t *policy, const char *pattern);
/* Adds all patterns atomically; on failure the policy is unchanged. */
st_error_t st_policy_batch_add_netpatterns(st_policy_t *policy,
                                           const char *const *patterns,
                                           size_t count);
st_error_t st_policy_remove_netpattern(st_policy_t *policy,
                                       const char *pattern);
size_t st_policy_rule_count(const st_policy_t *policy);

/* --- Verification --- */

/**
 * A suggestion for expanding a policy to cover a new command.
 * Fixed-size buffer — no allocation, no cleanup needed.
 */
typedef struct {
  char pattern[ST_MAX_NETPATTERN_LEN];
  /* Borrowed from policy storage. Valid only while the owning policy remains
   * stable; mutation, load, clear, compaction, or destruction invalidates it.
   */
  const char *based_on; /* Existing canonical netpattern, or NULL */
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
  const char *matching_pattern; /* Canonical netpattern, or NULL */
  size_t suggestion_count;      /* 0-2, only filled if !matches */
  st_expand_suggestion_t suggestions[2];
  st_error_t suggestion_error; /* Suggestion-rendering error, or ST_OK */
} st_eval_result_t;

/**
 * Unified evaluate + suggest.
 *
 * Walks the policy trie with one canonical netstring-encoded, already
 * preprocessed argv. Shellsplit is one valid producer, but is not required.
 * If it matches, sets
 * result->matches=true and result->matching_pattern.
 * When several patterns match, matching_pattern is the narrowest pattern;
 * equivalent or incomparable matches are ordered lexicographically.
 *
 * If it doesn't match, generates up to 2 expansion suggestions in
 * result->suggestions[].
 *
 * `result` is required. Use st_policy_match() for a Boolean-only check.
 * A non-OK suggestion_error does not change the completed match decision.
 *
 * NOTE: This function has side effects — it may rebuild internal position
 * filters if the policy epoch has changed (cache warming). The `*_view` form
 * uses its supplied length directly instead of scanning for a NUL terminator.
 */
st_error_t st_policy_eval(st_policy_t *policy, const char *netargv,
                          st_eval_result_t *result);
st_error_t st_policy_eval_view(st_policy_t *policy, st_netargv_view_t netargv,
                               st_eval_result_t *result);

/* Match one canonical, already-preprocessed netargv without generating
 * suggestions or allocating result patterns. On success, writes whether any
 * policy rule matches. The `*_view` form uses its supplied length directly
 * instead of scanning for a NUL terminator. */
st_error_t st_policy_match(st_policy_t *policy, const char *netargv,
                           bool *matches);
st_error_t st_policy_match_view(st_policy_t *policy, st_netargv_view_t netargv,
                                bool *matches);

/* netargv has the same encoding and preprocessing contract as st_policy_eval.
 * On success, matching_patterns is a caller-owned outer array released with
 * st_policy_matches_free(); its individual entries are borrowed from stable
 * policy storage and are invalidated by policy mutation, load, clear,
 * compaction, or destruction. On failure, each writable output is cleared even
 * when another argument is invalid. The `*_view` form uses its supplied length
 * directly instead of scanning for a NUL terminator. */
st_error_t st_policy_verify_all(const st_policy_t *policy, const char *netargv,
                                const char ***matching_patterns,
                                size_t *match_count);
st_error_t st_policy_verify_all_view(const st_policy_t *policy,
                                     st_netargv_view_t netargv,
                                     const char ***matching_patterns,
                                     size_t *match_count);

void st_policy_matches_free(const char **matches);

typedef bool (*st_policy_match_visitor_t)(const char *netpattern,
                                          void *user_ctx);

/* Visit matching canonical patterns without allocating a result array. The
 * callback runs while the policy read lock is held and must not re-enter that
 * policy. Returning false stops successfully; visited_count reports callbacks
 * that were invoked. The `*_view` form uses its supplied length directly
 * instead of scanning for a NUL terminator. */
st_error_t st_policy_visit_matches(const st_policy_t *policy,
                                   const char *netargv,
                                   st_policy_match_visitor_t visitor,
                                   void *user_ctx, size_t *visited_count);
st_error_t st_policy_visit_matches_view(const st_policy_t *policy,
                                        st_netargv_view_t netargv,
                                        st_policy_match_visitor_t visitor,
                                        void *user_ctx, size_t *visited_count);

/* --- NFA rendering --- */

/* Provisional Shellclave-to-c-dfa graph export. Each typed transition contains
 * one predefined lattice symbol plus an optional canonical metadata
 * annotation. Metadata is not a new lattice element and is never copied from
 * concrete token text. The interchange format is not yet stable. Successful
 * renders use synchronized same-directory atomic replacement. */
st_error_t st_policy_render_nfa(const st_policy_t *policy, const char *path,
                                const st_nfa_render_opts_t *opts);

/* --- Serialization --- */

/* Save and load use the canonical length-framed v3 policy format exclusively.
 * A successful save synchronizes the complete temporary file, atomically
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
 * Caller must free the returned arrays with st_policy_diff_free().
 * Takes read lock on both policies.
 */
typedef struct {
  char **added;
  size_t added_count;
  char **removed;
  size_t removed_count;
} st_policy_diff_t;

typedef enum {
  ST_POLICY_DIFF_ADDED,
  ST_POLICY_DIFF_REMOVED,
} st_policy_diff_kind_t;

typedef bool (*st_policy_diff_visitor_t)(st_policy_diff_kind_t kind,
                                         const char *netpattern,
                                         void *user_ctx);

/* Visit the difference between policies without allocating a snapshot. Added
 * patterns are active in b but not a; removed patterns are active in a but not
 * b. Results are emitted in that order, preserving each policy's active-rule
 * order. Pattern text is borrowed and both policy read locks remain held while
 * the callback runs, so it must not re-enter or mutate either policy. Returning
 * false stops successfully; visited_count includes the callback that stopped
 * traversal. */
st_error_t st_policy_visit_diff(const st_policy_t *a, const st_policy_t *b,
                                st_policy_diff_visitor_t visitor,
                                void *user_ctx, size_t *visited_count);

st_error_t st_policy_diff(const st_policy_t *a, const st_policy_t *b,
                          st_policy_diff_t *result);
void st_policy_diff_free(st_policy_diff_t *result);

/* --- Diagnostics --- */

size_t st_policy_memory_usage(const st_policy_t *policy);
size_t st_policy_working_set(const st_policy_t *policy);
size_t st_policy_state_count(const st_policy_t *policy);

/* --- Statistics --- */

/**
 * Get policy statistics for monitoring and tuning. If stats is non-NULL, it
 * is cleared before use; a NULL policy therefore produces zero statistics.
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
st_error_t
st_policy_simulate_add_netpattern(const st_policy_t *policy,
                                  const char *netpattern, bool *would_match,
                                  const char **conflicting_netpattern);

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
st_error_t st_netpattern_validate(const char *pattern, st_pattern_info_t *info);

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
  /* Optional sample from learner history. It is NULL for static variants and
   * otherwise borrowed until the learner is mutated, loaded, or destroyed. */
  const char *sample_value;
} st_token_variant_t;

/* Write deterministic lattice widening choices for one decoded pattern token
 * into caller-provided output storage. Static variants never allocate and
 * always have sample_value == NULL. */
size_t st_token_variants_at(const st_token_array_t *pattern, size_t edit_pos,
                            st_token_variant_t *out_variants,
                            size_t max_variants);

/* Returns canonical netpattern suggestions. Returns zero and clears all three
 * outputs if allocation or encoding fails. */
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
 * @param pattern     Decoded canonical pattern tokens
 * @param edit_pos       Position to edit (0-indexed)
 * @param out_variants   Output array (caller allocates ST_MAX_TOKEN_VARIANTS
 * entries)
 * @return Number of variants written, or zero for invalid input
 */
size_t st_learner_suggest_token_variants(const st_learner_t *learner,
                                         const st_token_array_t *pattern,
                                         size_t edit_pos,
                                         st_token_variant_t *out_variants);

/**
 * Apply a type change to a pattern at a given position.
 *
 * @param netpattern      Original canonical netpattern
 * @param edit_pos        Position to change
 * @param new_type        New type to set at that position
 * @param out_netpattern  Receives an allocated canonical netpattern
 */
st_error_t st_netpattern_apply_type_at(const char *netpattern, size_t edit_pos,
                                       st_token_type_t new_type,
                                       char **out_netpattern);

#ifdef __cplusplus
}
#endif

#endif /* SHELLTYPE_H */
