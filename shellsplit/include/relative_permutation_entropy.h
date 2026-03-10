#ifndef RELATIVE_PERMUTATION_ENTROPY_H
#define RELATIVE_PERMUTATION_ENTROPY_H

#include <stddef.h>

/**
 * Relative Permutation Entropy
 * 
 * Measures how "random" a string is by comparing its entropy to the
 * entropy of permuted versions of itself.
 * 
 * High ratio = original is more random than permutations = likely secret
 * Low ratio = original has structure like natural language or paths
 */

/**
 * Calculate n-gram entropy
 * @param s  Input string
 * @param n  N-gram size (1 for char, 2 for 2-gram)
 * @return   Entropy in bits
 */
double ngram_entropy(const char *s, int n);

/**
 * Calculate median permutation entropy
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @param n       N-gram size
 * @return        Median entropy of permutations
 */
double permutation_entropy(const char *s, int n_perms, int n);

/**
 * Calculate relative entropy ratio
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @param n       N-gram size
 * @return        Ratio: H(original) / H(permuted)
 *                >1.0 means original is more random than permutations (suspicious)
 *                <1.0 means original has structure (like paths, natural language)
 */
double relative_entropy_ratio(const char *s, int n_perms, int n);

/**
 * Calculate conditional entropy H(Char_i | Char_{i-1})
 * @param s  Input string
 * @return   Conditional entropy in bits
 */
double conditional_entropy(const char *s);

/**
 * Calculate median conditional entropy over permutations
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @return        Median conditional entropy of permutations
 */
double permutation_conditional_entropy(const char *s, int n_perms);

/**
 * Calculate relative conditional entropy ratio
 * @param s        Input string
 * @param n_perms Number of permutations to sample
 * @return        Ratio: H_cond(original) / H_cond(permuted)
 *                >1.0 means original has more predictable structure than random
 *                <1.0 means original is more random than permutations
 */
double relative_conditional_entropy(const char *s, int n_perms);

#endif /* RELATIVE_PERMUTATION_ENTROPY_H */
