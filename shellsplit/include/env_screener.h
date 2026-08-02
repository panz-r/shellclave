#ifndef SHELL_ENV_SCREENER_H
#define SHELL_ENV_SCREENER_H

#include <stdbool.h>
#include <stddef.h>

#include "relative_permutation_entropy.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Scores environment-variable names and values with built-in patterns and
 * entropy metrics. It does not modify the environment or allocate memory.
 */

/* ============================================================
 * CONFIGURATION (can be overridden)
 * ============================================================ */

#ifndef ENV_SCREENER_POSTERIOR_THRESHOLD
#define ENV_SCREENER_POSTERIOR_THRESHOLD 0.5
#endif

#ifndef ENV_SCREENER_MIN_LENGTH
#define ENV_SCREENER_MIN_LENGTH 24
#endif

/* ============================================================
 * RETURN CODES
 * ============================================================ */

typedef enum {
  ENV_SCREENER_OK = 0,
  ENV_SCREENER_BUFFER_TOO_SMALL = 1,
  ENV_SCREENER_ERROR = -1
} env_screener_status_t;

/* ============================================================
 * API FUNCTIONS
 * ============================================================ */

/**
 * Calculate Shannon entropy of a string
 * @param str   Input string
 * @return     Entropy in bits (0-8 per character)
 */
double env_screener_calculate_entropy(const char *str);

/**
 * Check if variable name matches known secret patterns
 * @param name  Variable name
 * @return      true when name matches a built-in secret pattern
 */
bool env_screener_is_secret_pattern(const char *name);

/**
 * Check if variable name is in whitelist (known safe)
 * @param name  Variable name
 * @return      true when name is in the built-in whitelist
 */
bool env_screener_is_whitelisted(const char *name);

/**
 * Screen all environment variables
 *
 * Caller provides pre-allocated array for results. Module fills it with
 * indices into 'environ' that point to flagged variables.
 *
 * @param out_indices           write: caller-allocated array of flagged indices
 * @param capacity                read: size of out_indices array
 * @param out_count             write: number of flagged variables (or minimum
 * capacity needed)
 * @param posterior_threshold     read: minimum posterior probability to flag;
 * must be finite and in [0, 1]
 * @param min_length             read: minimum value length to consider
 * @return                       ENV_SCREENER_OK on success,
 * ENV_SCREENER_BUFFER_TOO_SMALL if capacity too small (out_count has minimum
 * needed), ENV_SCREENER_ERROR on error
 */
env_screener_status_t env_screener_scan(int *out_indices, int capacity,
                                        int *out_count,
                                        double posterior_threshold,
                                        int min_length);

/**
 * Get recommended initial capacity
 * @return  Recommended capacity for typical use
 */
int env_screener_recommended_capacity(void);

/**
 * Get the whitelist (for documentation)
 * @return  Comma-separated list of whitelisted variable names
 */
const char *env_screener_get_whitelist_doc(void);

/**
 * Calculate combined entropy score for a value
 * Combines Shannon entropy with relative permutation entropy
 * @param value  The value to score
 * @return      Combined heuristic score
 */
double env_screener_combined_score(const char *value);

/**
 * Calculate combined secret score for a name-value pair
 * Includes boosts for known secret prefixes and variable name patterns
 * @param name   Variable name (e.g., "API_KEY", "MY_SECRET") or NULL
 * @param value  Variable value
 * @return      Combined score in [0, 1]
 */
double env_screener_combined_score_name(const char *name, const char *value);

/**
 * Check whether value resembles a file path.
 * @param value  The value to check
 * @return      true if value looks like a path
 */
bool looks_like_path(const char *value);

/**
 * Check whether value resembles Base64 text.
 * @param value  The value to check
 * @return      true if value appears to be base64 encoded
 */
bool looks_like_base64(const char *value);

/**
 * Check if value has a known secret prefix
 * @param value            The value to check
 * @param out_suffix_entropy  If not NULL, receives entropy of suffix (after
 * prefix)
 * @return                 true if known prefix detected
 */
bool check_secret_prefix(const char *value, double *out_suffix_entropy);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_ENV_SCREENER_H */
