#ifndef SHELL_ENV_SCREENER_H
#define SHELL_ENV_SCREENER_H

#include <stdbool.h>
#include <stddef.h>

#include "relative_permutation_entropy.h"

/**
 * env_screener - Environment Variable Screening Module
 * 
 * Provides functionality to analyze environment variables for potential secrets
 * by detecting high-entropy values and known secret patterns.
 * 
 * This module ONLY performs analysis. It returns indices of variables that should be
 * reviewed. The caller decides what action to take (block, prompt user, etc.).
 * 
 * Caller-allocates pattern: caller provides array for results, module fills it.
 * No dynamic allocation in this module.
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
 * @return      true if name suggests a secret
 */
bool env_screener_is_secret_pattern(const char *name);

/**
 * Check if variable name is in whitelist (known safe)
 * @param name  Variable name  
 * @return      true if whitelisted
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
 * @param out_count             write: number of flagged variables (or minimum capacity needed)
 * @param entropy_threshold       read: minimum entropy to flag as suspicious
 * @param min_length             read: minimum value length to consider
 * @return                       ENV_SCREENER_OK on success, ENV_SCREENER_BUFFER_TOO_SMALL if capacity too small (out_count has minimum needed), ENV_SCREENER_ERROR on error
 */
env_screener_status_t env_screener_scan(
    int *out_indices,
    int capacity,
    int *out_count,
    double posterior_threshold,
    int min_length
);

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
 * @return      Combined score (higher = more likely to be secret)
 * 
 * The relative entropy ratio helps distinguish:
 * - Secrets: high ratio (>1.0) - original is more random than permutations
 * - Paths: low ratio (<1.0) - original has structure that gets destroyed by permutation
 */
double env_screener_combined_score(const char *value);

/**
 * Calculate combined secret score for a name-value pair
 * Includes boosts for known secret prefixes and variable name patterns
 * @param name   Variable name (e.g., "API_KEY", "MY_SECRET") or NULL
 * @param value  Variable value
 * @return      Score 0.0-1.0 (higher = more likely to be a secret)
 */
double env_screener_combined_score_name(const char *name, const char *value);

/**
 * Check if value looks like a file path (negative indicator for secrets)
 * @param value  The value to check
 * @return      true if value looks like a path
 */
bool looks_like_path(const char *value);

/**
 * Check if value looks like base64 encoded (positive indicator for secrets)
 * @param value  The value to check
 * @return      true if value appears to be base64 encoded
 */
bool looks_like_base64(const char *value);

/**
 * Check if value has a known secret prefix
 * @param value            The value to check
 * @param out_suffix_entropy  If not NULL, receives entropy of suffix (after prefix)
 * @return                 true if known prefix detected
 */
bool check_secret_prefix(const char *value, double *out_suffix_entropy);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_ENV_SCREENER_H */
