#ifndef RELATIVE_PERMUTATION_ENTROPY_H
#define RELATIVE_PERMUTATION_ENTROPY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Relative Permutation Entropy
 *
 * Compares a string's entropy with entropy measured over permutations of the
 * same bytes.
 */

/**
 * Calculate n-gram entropy
 * @param s  Input string
 * @param n  N-gram size (1 for char, 2 for 2-gram)
 * @return   Entropy in bits, or NAN for invalid input
 */
double ngram_entropy(const char *s, int n);

/**
 * Calculate median permutation entropy
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @param n       N-gram size
 * @return        Median entropy of permutations, or NAN for invalid input or
 *                allocation failure
 */
double permutation_entropy(const char *s, int n_perms, int n);

/**
 * Calculate relative entropy ratio
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @param n       N-gram size
 * @return        Ratio: H(original) / H(permuted), or NAN for invalid input or
 *                allocation failure
 */
double relative_entropy_ratio(const char *s, int n_perms, int n);

/**
 * Calculate conditional entropy H(Char_i | Char_{i-1})
 * @param s  Input string
 * @return   Conditional entropy in bits, or NAN for invalid input
 */
double conditional_entropy(const char *s);

/**
 * Calculate median conditional entropy over permutations
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @return        Median conditional entropy of permutations, or NAN for
 *                invalid input or allocation failure
 */
double permutation_conditional_entropy(const char *s, int n_perms);

/**
 * Calculate relative conditional entropy ratio
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @return        Ratio: H_cond(original) / H_cond(permuted), or NAN for
 *                invalid input or allocation failure
 */
double relative_conditional_entropy(const char *s, int n_perms);

#ifdef __cplusplus
}
#endif

#endif /* RELATIVE_PERMUTATION_ENTROPY_H */
