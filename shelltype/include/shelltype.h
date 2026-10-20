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

#include "shell_contract.h"

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
#define ST_MAX_TOKEN_LEN 256  /* Learner/pattern literal storage capacity */
#define ST_MAX_CMD_TOKENS 128 /* Max tokens in a command/pattern */
#define ST_MAX_CPL_LEN                                                         \
  (ST_MAX_NETPATTERN_LEN * 6 + ST_MAX_CMD_TOKENS * 3) /* Max rendered CPL */
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
 * Lattice ordering table: st_type_compatible[a][b] is true iff a ≤ b.
 * This is a generalization relation, not a runtime policy-match predicate.
 * In particular, LITERAL is the lattice bottom but unclassified runtime
 * values do not match typed wildcards. Use the policy evaluation APIs for
 * runtime acceptance, including argv context and parameter metadata.
 */
extern const bool st_type_compatible[ST_TYPE_COUNT][ST_TYPE_COUNT];

/**
 * Return the join of two token types (narrowest type covering both).
 */
static inline st_token_type_t st_join(st_token_type_t a, st_token_type_t b) {
  return st_type_join[a][b];
}

/**
 * Return cmd_type ≤ policy_type in the lattice, for joins/generalizations.
 * This does not determine whether a runtime value satisfies a policy token;
 * see st_type_compatible above. Both arguments must be valid type enums.
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
  /* Appended so existing positional initializers retain their field order.
   * Zero selects strlen() for legacy C-string tokens; byte-oriented callers
   * provide all applicable lengths explicitly. */
  size_t text_length;
  size_t prefix_length;
  size_t capture_length;
  size_t suffix_length;
} st_token_t;

/**
 * Owned token array returned by classification, decoding, or validation.
 */
typedef struct st_token_array {
  /* Owns the allocation backing the strings returned by classify/decode. */
  st_token_t *tokens;
  size_t count;
} st_token_array_t;

/* Borrowed classified netargv payload. `text` is not NUL-terminated and is
 * valid only for the duration of an st_netargv_visit_view() callback. */
typedef struct {
  const char *text;
  size_t text_length;
  st_token_type_t type;
} st_token_view_t;

/* A borrowed canonical netargv span. `data` may be NULL only when `length`
 * is zero. It is byte-oriented canonical transport: payloads may contain NUL
 * bytes and callers must always retain the explicit enclosing length. */
typedef struct {
  const char *data;
  size_t length;
} st_netargv_view_t;

/* Canonical netpatterns use the same byte-oriented transport discipline as
 * netargv. The encoded bytes may contain NUL because literal payloads are
 * nested netstrings. */
typedef struct {
  const char *data;
  size_t length;
} st_netpattern_view_t;

typedef struct {
  char *data;
  size_t length;
} st_netpattern_t;

/* Release an owned netpattern and reset it. Initialize an owned netpattern to
 * {0}. APIs that produce an st_netpattern_t require an empty output object;
 * release a successful result before reusing it as an output argument. */
void st_netpattern_free(st_netpattern_t *pattern);

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
  /* Complete owned canonical netpattern policy rule. It may contain NUL;
   * use pattern_length rather than C-string operations. */
  char *pattern;
  size_t pattern_length;
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
                                 st_learner_config_t *config)
    SHELL_NONNULL(1, 2);
st_error_t st_learner_set_config(st_learner_t *learner,
                                 const st_learner_config_t *config)
    SHELL_NONNULL(1, 2);
void st_learner_get_stats(const st_learner_t *learner,
                          st_learner_stats_t *stats) SHELL_NONNULL(1, 2);

/* --- FEEDING COMMANDS --- */

/* Feed operations are atomic: on error the learner is unchanged. netargv is a
 * canonical concatenation of netstrings, one per already-preprocessed argv
 * element: <decimal byte length>:<bytes>,. The view preserves embedded NUL
 * payloads and need not be terminated. For example, argv {"printf", "two
 * words"} is "6:printf,9:two words,". It is not shell source. Shellsplit is one
 * valid producer, but callers may provide an equivalent trusted argv. Empty
 * arguments and embedded whitespace are preserved. Arguments at or above
 * ST_MAX_TOKEN_LEN are rejected. */

st_error_t st_learner_feed_netargv_view(st_learner_t *learner,
                                        st_netargv_view_t netargv)
    SHELL_NONNULL(1);
/* Feed caller-classified tokens atomically. Explicit-length token spans need
 * not be NUL-terminated and may contain NUL bytes. Parameter metadata
 * refinements are textual and are therefore omitted for a non-literal token
 * with embedded NUL. */
st_error_t st_learner_feed_tokens(st_learner_t *learner,
                                  const st_token_array_t *typed)
    SHELL_NONNULL(1, 2);

/* --- SUGGESTIONS --- */

/* Returns complete policy rules, never command prefixes. The returned rules
 * may contain NUL; use st_suggestion_t::pattern_length. Support counts use the
 * complete runtime matching predicate, including overlapping token types and
 * continuation constraints. Confidence divides that support by the learned
 * commands matching the prefix before the proposal's divergence. Thresholds
 * are applied after this accounting.
 *
 * The compact trie retains typed buckets, not concrete typed-token history.
 * If a parameter would match an indeterminate part of a mixed bucket, the
 * learner tries the same rule without value-discriminating parameters. A rule
 * whose literal or compound constraints still lack exact support evidence is
 * not published. Returns NULL and clears out_count when no suggestions can be
 * produced from the supplied learner. */
st_suggestion_t *st_learner_suggest(st_learner_t *learner, size_t *out_count)
    SHELL_NONNULL(1, 2);
void st_suggestion_list_free(st_suggestion_t *suggestions, size_t count);

/* --- BLACKLIST --- */

st_error_t st_learner_blacklist_add_netpattern(st_learner_t *learner,
                                               st_netpattern_view_t netpattern)
    SHELL_NONNULL(1);
bool st_learner_is_netpattern_blacklisted(const st_learner_t *learner,
                                          st_netpattern_view_t netpattern)
    SHELL_NONNULL(1);

/* --- SERIALISATION --- */

/* Learner state uses the strict framed v5 format. Each node is an outer
 * netstring containing canonical netstring fields, and the record stream is
 * protected by a declared count and CRC32. Older formats are rejected.
 * Successful saves use synchronized same-directory atomic replacement.
 * Existing regular files retain their permission and special mode bits
 * (subject to OS permission rules); ownership is not copied. The final mode is
 * applied after serialization, while temporary files remain private until
 * then. Symlinks are replaced without following them. Other existing
 * destination types are rejected with ST_ERR_IO.
 * Filesystem-valid basenames require no extra room for a temporary suffix.
 * The complete save pathname, including NUL, must fit PATH_MAX; longer
 * spellings return ST_ERR_IO with errno ENAMETOOLONG before creating a file.
 * A failure before replacement leaves the destination unchanged; a directory
 * synchronization failure after replacement leaves the complete new file
 * installed, but its durability across a crash is not guaranteed.
 * Concurrent saves to the same destination require external synchronization.
 */
st_error_t st_learner_save(const st_learner_t *learner, const char *path)
    SHELL_NONNULL(1, 2);
st_error_t st_learner_load(st_learner_t *learner, const char *path)
    SHELL_NONNULL(1, 2);

/* --- CLASSIFICATION --- */

/**
 * Classify canonical netstring-encoded argv into typed tokens.
 * Each token is classified into the most specific type in the lattice.
 * Token text remains the complete concrete input token; it is never replaced
 * with a synthesized wildcard or metadata-bearing symbol.
 * `netargv` uses the canonical concatenated-netstring format documented for
 * st_learner_feed_netargv_view. Its elements must already be the argv of one
 * isolated subcommand. Shell tokenization, control-flow isolation, redirection
 * removal, quote-fragment assembly, and escape processing belong upstream. This
 * function decodes argument boundaries and assigns types; it does not tokenize
 * shell text. Non-canonical or malformed encodings return ST_ERR_FORMAT.
 * The returned tokens retain each payload's explicit text_length, including
 * embedded NUL bytes. Input uses its explicit byte length, without requiring
 * a terminating NUL.
 *
 * The caller must free the returned array with st_token_array_free().
 */

st_error_t st_netargv_classify_view(st_netargv_view_t netargv,
                                    st_token_array_t *out) SHELL_NONNULL(2);

typedef bool (*st_netargv_token_visitor_t)(const st_token_view_t *token,
                                           void *user_ctx);

/* Classify canonical netargv without allocating or copying token payloads.
 * The callback sees each concrete payload as a borrowed span; returning false
 * stops successfully. If non-NULL, visited_count receives callback
 * invocations. Classification has the same contextual rules as
 * st_netargv_classify_view(). Input uses its explicit byte length and may
 * contain NUL payloads. */

st_error_t st_netargv_visit_view(st_netargv_view_t netargv,
                                 st_netargv_token_visitor_t visitor,
                                 void *user_ctx, size_t *visited_count)
    SHELL_NONNULL(2);

/**
 * Free a typed token array.
 */
void st_token_array_free(st_token_array_t *arr);

/**
 * Classify one borrowed, immutable token byte span without command context.
 * The caller supplies length readable bytes; no terminator is required and
 * embedded NUL bytes are preserved. text may be NULL only when length is zero.
 * Empty spans and tokens matching no wildcard type return ST_TYPE_LITERAL.
 * Classification uses fixed ASCII character sets, independent of the host
 * locale. High bytes remain literal data rather than identifier characters;
 * path and other byte-shaped types retain their documented rules.
 * This is not shell tokenization or a span-storage validation boundary.
 */
st_token_type_t st_token_classify(const char *text, size_t length);

/**
 * Extract the file extension from a path (including dot).
 * Returns NULL if no extension found.
 */
const char *st_path_extension(const char *text) SHELL_NONNULL(1);

/**
 * Extract the size suffix from a size token.
 * Returns pointer after last digit/dot, or NULL if no suffix.
 */
const char *st_size_suffix(const char *text) SHELL_NONNULL(1);

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
void st_policy_ctx_retain(st_policy_ctx_t *ctx) SHELL_NONNULL(1);
void st_policy_ctx_release(st_policy_ctx_t *ctx);
st_error_t st_policy_ctx_reset(st_policy_ctx_t *ctx) SHELL_NONNULL(1);

/* --- Policy lifecycle --- */

st_policy_t *st_policy_new(st_policy_ctx_t *ctx) SHELL_NONNULL(1);
void st_policy_free(st_policy_t *policy);

/* --- Pattern management --- */

/* Convert between human CPL and canonical nested tagged netpatterns. CPL
 * quoted literals use C-style escapes plus \xHH for every arbitrary byte;
 * unquoted words remain deliberately restricted to ordinary visible syntax.
 * A compound uses one unquoted capture marker, for example
 * `prefix{#path}suffix`; quoted literal fragments may be adjacent to that
 * marker, for example `"a\\x00{"{#n}"}\\x00z"`. An ordinary literal and each
 * compound component (prefix, capture, suffix) must independently have fewer
 * than ST_MAX_TOKEN_LEN decoded bytes. Structural braces do not count toward
 * those limits; a complete compound spelling may exceed one literal's limit.
 * Canonical inputs and outputs carry explicit lengths and preserve every byte.
 * CPL itself is printable text; arbitrary literal bytes use escaped notation.
 */

/* Owned-output forms require `out_netpattern` to be empty (initialized to {0}
 * or released with st_netpattern_free()). Empty initialized output storage is
 * a caller precondition; it remains empty on failure. */
st_error_t st_netpattern_from_cpl_owned(const char *cpl,
                                        st_netpattern_t *out_netpattern)
    SHELL_NONNULL(1, 2);
st_error_t st_netpattern_to_cpl_view(st_netpattern_view_t netpattern,
                                     char **out_cpl) SHELL_NONNULL(2);
/* Encoding validates payload limits and compound capture metadata. NULL
 * tokens, zero count or count above ST_MAX_CMD_TOKENS return
 * ST_ERR_INVALID. Otherwise tokens supplies count readable entries whose
 * payload storage remains valid and unchanged throughout the call. */
st_error_t st_netpattern_encode_owned(const st_token_t *tokens, size_t count,
                                      st_netpattern_t *out_netpattern)
    SHELL_NONNULL(3);
st_error_t st_netpattern_decode_view(st_netpattern_view_t netpattern,
                                     st_token_array_t *out_tokens)
    SHELL_NONNULL(2);
/* Policy mutation accepts canonical nested tagged netpatterns only. Human CPL
 * must be converted explicitly with st_netpattern_from_cpl_owned(). */

st_error_t st_policy_add_netpattern_view(st_policy_t *policy,
                                         st_netpattern_view_t pattern)
    SHELL_NONNULL(1);
/* Adds all patterns atomically; on failure the policy is unchanged. NULL
 * patterns or zero count return ST_ERR_INVALID. Otherwise patterns supplies
 * count readable views, whose storage remains valid throughout the call. */
st_error_t
st_policy_batch_add_netpattern_views(st_policy_t *policy,
                                     const st_netpattern_view_t *patterns,
                                     size_t count) SHELL_NONNULL(1);

st_error_t st_policy_remove_netpattern_view(st_policy_t *policy,
                                            st_netpattern_view_t pattern)
    SHELL_NONNULL(1);
size_t st_policy_rule_count(const st_policy_t *policy) SHELL_NONNULL(1);

/* --- Verification --- */

/**
 * A suggestion for expanding a policy to cover a new command.
 * Fixed-size buffer — no allocation, no cleanup needed.
 */
typedef struct {
  char pattern[ST_MAX_NETPATTERN_LEN];
  /* Explicit canonical byte length; the payload may contain NUL. The byte at
   * pattern[pattern_length] is a compatibility terminator only and is not
   * part of the netpattern. Binary consumers must use this length. */
  size_t pattern_length;
  /* Borrowed from policy storage. Valid only while the owning policy remains
   * stable; mutation, load, clear, compaction, or destruction invalidates it.
   */
  /* Existing canonical netpattern, or NULL; may contain NUL. Consume it with
   * based_on_length rather than as a C string. */
  const char *based_on;
  size_t based_on_length;
  double confidence; /* matched_prefix_tokens / total_cmd_tokens */
} st_expand_suggestion_t;

/**
 * Result of st_policy_eval_view. The evaluator initializes the whole object, so
 * only the first suggestion_count entries are meaningful on return.
 */
typedef struct {
  bool matches;
  /* Borrowed from policy storage. Valid only while the owning policy remains
   * stable; mutation, load, clear, compaction, or destruction invalidates it.
   */
  /* Canonical netpattern, or NULL; may contain NUL. Consume it with
   * matching_pattern_length rather than as a C string. */
  const char *matching_pattern;
  size_t matching_pattern_length;
  size_t suggestion_count; /* 0-2, only filled if !matches */
  st_expand_suggestion_t suggestions[2];
  st_error_t suggestion_error; /* First representation error, or ST_OK;
                                * ST_ERR_MEMORY clears all suggestions. */
} st_eval_result_t;

/**
 * Unified evaluate + suggest.
 *
 * Walks the policy trie with one canonical netstring-encoded, already
 * preprocessed argv. Shellsplit is one valid producer, but is not required.
 * Explicit lengths preserve embedded NUL bytes. Runtime arguments and
 * compound captures are not limited by ST_MAX_TOKEN_LEN; that capacity applies
 * to learner/pattern literal storage and fixed-size diagnostic fields.
 * If it matches, sets
 * result->matches=true and result->matching_pattern.
 * When several patterns match, matching_pattern is the narrowest pattern;
 * equivalent or incomparable matches are ordered lexicographically.
 *
 * If it doesn't match, generates up to 2 expansion suggestions in
 * result->suggestions[].
 *
 * `result` is required. Use st_policy_match_view() for a Boolean-only check.
 * A non-OK suggestion_error does not change the completed match decision.
 * Each published suggestion covers the complete input argv. Unrepresentable
 * candidates are skipped without discarding other candidates; suggestion_error
 * records the first such error even when valid suggestions are available.
 * Allocation failure instead clears the suggestion batch and reports
 * ST_ERR_MEMORY, taking precedence over representation errors.
 *
 * NOTE: This function has side effects — it may rebuild internal position
 * filters if the policy epoch has changed (cache warming).
 */

st_error_t st_policy_eval_view(const st_policy_t *policy,
                               st_netargv_view_t netargv,
                               st_eval_result_t *result) SHELL_NONNULL(1, 3);

/* Match one canonical, already-preprocessed netargv without generating
 * suggestions or allocating result patterns. On success, writes whether any
 * policy rule matches. */

st_error_t st_policy_match_view(const st_policy_t *policy,
                                st_netargv_view_t netargv, bool *matches)
    SHELL_NONNULL(1, 3);

/* netargv has the same encoding and preprocessing contract as
 * st_policy_eval_view. On success, matching_patterns is a caller-owned outer
 * array released with st_policy_matches_free(); its individual entries are
 * borrowed from stable policy storage and are invalidated by policy mutation,
 * load, clear, compaction, or destruction. On failure, each writable output is
 * cleared on malformed input. */

st_error_t st_policy_verify_all_view(const st_policy_t *policy,
                                     st_netargv_view_t netargv,
                                     st_netpattern_view_t **matching_patterns,
                                     size_t *match_count)
    SHELL_NONNULL(1, 3, 4);

void st_policy_matches_free(st_netpattern_view_t *matches);

typedef bool (*st_policy_match_visitor_t)(st_netpattern_view_t netpattern,
                                          void *user_ctx);

/* Visit matching canonical patterns without allocating a result array. The
 * callback runs while the policy read lock is held and must not re-enter that
 * policy. Returning false stops successfully; visited_count reports callbacks
 * that were invoked. The supplied byte length is used directly; encoded values
 * need not be NUL-terminated. */

st_error_t st_policy_visit_matches_view(const st_policy_t *policy,
                                        st_netargv_view_t netargv,
                                        st_policy_match_visitor_t visitor,
                                        void *user_ctx, size_t *visited_count)
    SHELL_NONNULL(1, 3, 5);

/* --- NFA rendering --- */

/* Provisional Shellclave-to-c-dfa graph export. Each typed transition contains
 * one predefined lattice symbol plus an optional canonical metadata
 * annotation. Metadata is not a new lattice element and is never copied from
 * concrete token text. The interchange format is not yet stable. Successful
 * renders use synchronized same-directory atomic replacement with the same
 * pathname-length, destination-type, mode and failure semantics as
 * st_policy_save. NULL opts
 * selects the default render options. */
st_error_t st_policy_render_nfa(const st_policy_t *policy, const char *path,
                                const st_nfa_render_opts_t *opts)
    SHELL_NONNULL(1, 2);

/* --- Serialization --- */

/* Save and load use the canonical length-framed v3 policy format exclusively.
 * A successful save synchronizes the complete temporary file, atomically
 * replaces path, and synchronizes its parent directory. ST_ERR_IO after the
 * atomic replacement can leave either the previous or new complete file
 * durable across a crash. Concurrent saves to the same path require external
 * synchronization. Existing regular files retain their mode; symlinks are
 * replaced without following them. Other existing destination types are
 * rejected with ST_ERR_IO. Filesystem-valid basenames require no extra room
 * for a temporary suffix. Permission and special mode bits are applied after
 * serialization, subject to OS permission rules; ownership is not copied.
 * Temporary files remain private until then. Before replacement, any failure
 * leaves path unchanged; after replacement a parent-sync failure leaves the
 * complete new file installed, with crash durability uncertain. The complete
 * save pathname, including NUL, must fit PATH_MAX; longer spellings return
 * ST_ERR_IO with errno ENAMETOOLONG before creating a file. */
st_error_t st_policy_save(const st_policy_t *policy, const char *path)
    SHELL_NONNULL(1, 2);
st_error_t st_policy_load(st_policy_t *policy, const char *path,
                          bool clear_first) SHELL_NONNULL(1, 2);
/* Rebuild active patterns to reclaim storage. A nonempty policy sharing its
 * context with another policy returns ST_ERR_INVALID without mutation. */
st_error_t st_policy_compact(st_policy_t *policy) SHELL_NONNULL(1);
st_error_t st_policy_clear(st_policy_t *policy) SHELL_NONNULL(1);

/* --- Merge --- */

/**
 * Merge all patterns from src into dst. Duplicates are skipped.
 * Takes write lock on dst, read lock on src.
 * The merge is atomic: on failure, dst is unchanged. Returns ST_OK on success
 * or the error that prevented the merge.
 */
st_error_t st_policy_merge(st_policy_t *dst, const st_policy_t *src)
    SHELL_NONNULL(1, 2);

/* --- Diff --- */

/**
 * Compare two policies and return lists of added/removed patterns.
 * Patterns in b but not a are "added"; patterns in a but not b are "removed".
 * `result` must be initialized to {0}, or released with st_policy_diff_free(),
 * before this call. This initialization is a caller precondition. A successful
 * result owns its arrays; release it before reuse.
 * A valid empty result remains empty on failure. Caller must free returned
 * arrays with st_policy_diff_free().
 * Takes read lock on both policies.
 */
typedef struct {
  st_netpattern_t *added;
  size_t added_count;
  st_netpattern_t *removed;
  size_t removed_count;
} st_policy_diff_t;

typedef enum {
  ST_POLICY_DIFF_ADDED,
  ST_POLICY_DIFF_REMOVED,
} st_policy_diff_kind_t;

typedef bool (*st_policy_diff_visitor_t)(st_policy_diff_kind_t kind,
                                         st_netpattern_view_t netpattern,
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
                                void *user_ctx, size_t *visited_count)
    SHELL_NONNULL(1, 2, 3, 5);

st_error_t st_policy_diff(const st_policy_t *a, const st_policy_t *b,
                          st_policy_diff_t *result) SHELL_NONNULL(1, 2, 3);
void st_policy_diff_free(st_policy_diff_t *result);

/* --- Diagnostics --- */

size_t st_policy_memory_usage(const st_policy_t *policy) SHELL_NONNULL(1);
size_t st_policy_working_set(const st_policy_t *policy) SHELL_NONNULL(1);
size_t st_policy_state_count(const st_policy_t *policy) SHELL_NONNULL(1);

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
st_error_t st_policy_dump_dot(const st_policy_t *policy, const char *path)
    SHELL_NONNULL(1, 2);

/* --- Dry-run mode --- */

/**
 * Simulate adding a pattern without modifying the policy.
 * Reports whether an existing pattern subsumes the proposed pattern. When it
 * does, conflicting_pattern receives the canonical existing pattern that
 * makes the proposal redundant. A broader proposal that would replace an
 * existing narrower pattern is not reported as redundant.
 * Proposals follow the same command-position grammar as validation and
 * insertion: a leading compound or whole-token ANY returns ST_ERR_INVALID,
 * with would_match set to false and any supplied conflict output cleared.
 * NULL conflicting_netpattern omits the optional conflict output.
 */

st_error_t st_policy_simulate_add_netpattern_view(
    const st_policy_t *policy, st_netpattern_view_t netpattern,
    bool *would_match, st_netpattern_view_t *conflicting_netpattern)
    SHELL_NONNULL(1, 3);

/* --- Pattern validation --- */

/**
 * Validate canonical framing, token/component limits, parameter vocabulary,
 * and policy command-position grammar without modifying any policy.
 * NULL out_tokens requests validation only; it does not change which patterns
 * are valid. Otherwise out_tokens must point to an empty array (initialized to
 * {0} or released with st_token_array_free()), distinct from the input span.
 * On success it owns the decoded tokens, including exact byte lengths and
 * compound prefix/capture/suffix metadata; release it with
 * st_token_array_free(). On failure it remains empty.
 * Accepts embedded NUL and exact-size, unterminated input.
 * Returns ST_OK if valid, or a framing, grammar/parameter, limit, or allocation
 * error. Details reuse the decoding allocations without copying token text.
 */

st_error_t st_netpattern_validate_view(st_netpattern_view_t pattern,
                                       st_token_array_t *out_tokens);

/* --- POLICY EXPANSION SUGGESTIONS (Miner) --- */

/* Single token variant for edit UI (one option in the list) */
typedef struct st_token_variant {
  st_token_type_t type;    /* The type to suggest */
  const char *type_symbol; /* Static type symbol, e.g. "#path" or "*" */
} st_token_variant_t;

/* Write deterministic lattice widening choices for one decoded pattern token
 * into caller-provided output storage. Results never allocate. For compounds,
 * choices target the capture type, beginning with its current type; applying a
 * choice preserves the literal affixes. No whole-word LITERAL choice is
 * returned for compounds. Ordinary tokens retain their initial LITERAL choice;
 * additional choices cover their runtime classifications in argv context. A
 * generalized predecessor may require a wider choice to cover every possible
 * context. Unclassified literals offer only LITERAL and, outside command
 * position, ANY. A leading whole-token ANY is never offered. Compound command
 * words are not supported policy grammar; unsupported policy heads produce no
 * choices. pattern supplies valid decoded canonical tokens (or an empty array).
 * Token metadata and borrowed storage are caller preconditions, not
 * revalidated. An out-of-range edit position or zero capacity returns zero. */
size_t st_token_variants_at(const st_token_array_t *pattern, size_t edit_pos,
                            st_token_variant_t *out_variants,
                            size_t max_variants) SHELL_NONNULL(1, 3);

/* Suggest up to three canonical netpatterns from decoded policy-pattern tokens,
 * as returned by st_netpattern_decode_view, or an equivalent producer. These
 * are NOT concrete command tokens from st_netargv_classify_view: typed tokens
 * must retain their canonical wildcard spelling and metadata, and compounds
 * must retain their capture spelling, type, and literal affixes. Valid token
 * metadata and readable, unchanged token/component spans are caller
 * preconditions; the function does not revalidate them.
 *
 * Variant zero treats each pattern token's text bytes as a whole-word literal.
 * It matches those spellings, not necessarily a command accepted by the chosen
 * pattern. Remaining variants widen one non-literal token or compound capture
 * at a time, preserving all other tokens and literal affixes.
 *
 * Caller provides non-aliasing out[3] storage; it is overwritten and needs no
 * cleanup. policy and tokens remain borrowed for the duration of the call.
 * Zero/excessive token counts, unsupported policy heads, and allocation or
 * encoding failures return zero and clear all three outputs. */
size_t st_policy_suggest_variants(const st_policy_t *policy,
                                  const st_token_t *tokens, size_t token_count,
                                  st_expand_suggestion_t out[3])
    SHELL_NONNULL(1, 2, 4);
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
 * Compounds edit the capture type, not the whole word. Capture observations
 * come only from exact retained literal words with matching affixes; type-only
 * buckets do not retain the bytes needed to prove a capture or affix match.
 * Ordinary literal prefixes select exact literal branches and project onto
 * their argv-context type buckets. Such typed buckets aggregate values, so
 * downstream observations are category-level, not exact-value correlations.
 * Wildcard prefixes use runtime type acceptance (ANY includes literals).
 * Type-wide parameters (semver components, range step, permission bits) need
 * only the accepted classified type. Parameters which discriminate values
 * require retained common metadata proving the entire bucket satisfies them;
 * mixed/absent metadata cannot establish that value-specific evidence.
 * If no observations are available, the current token/capture type supplies
 * fallback choices; an ordinary literal uses the generic VALUE fallback.
 * The alternatives are observed edit choices, not a promise that every choice
 * widens the entire original pattern. No sample strings are retained or copied.
 *
 * @param learner    The learner/trie context
 * @param pattern     Decoded canonical pattern tokens
 * @param edit_pos       Position to edit (0-indexed)
 * @param out_variants   Output array (caller allocates ST_MAX_TOKEN_VARIANTS
 * entries)
 * The token array and its immutable storage must satisfy the canonical decoded
 * token contract. This query does not encode or allocate; an empty pattern or
 * out-of-range edit position or unsupported policy head returns zero.
 * @return Number of variants written
 */
size_t st_learner_suggest_token_variants(const st_learner_t *learner,
                                         const st_token_array_t *pattern,
                                         size_t edit_pos,
                                         st_token_variant_t *out_variants)
    SHELL_NONNULL(1, 2, 4);

/**
 * Apply a type change to a pattern at a given position.
 *
 * @param netpattern      Original canonical netpattern
 * @param edit_pos        Position to change
 * @param new_type        New type to set at that position
 * @param out_netpattern  Receives an owned canonical netpattern
 * The resulting head must be valid policy grammar: neither a whole-token ANY
 * nor a compound token. An argument edit cannot repair an unsupported head;
 * changing a whole-token ANY head to a supported type can. ANY inside an
 * argument's compound capture remains valid.
 *
 * out_netpattern must be empty (initialized to {0} or released with
 * st_netpattern_free()). On success it owns the canonical bytes; release it
 * with st_netpattern_free(). On failure it remains empty.
 */

st_error_t st_netpattern_apply_type_at_owned(st_netpattern_view_t netpattern,
                                             size_t edit_pos,
                                             st_token_type_t new_type,
                                             st_netpattern_t *out_netpattern)
    SHELL_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SHELLTYPE_H */
