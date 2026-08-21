#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"
#include "relative_permutation_entropy.h"

// Function to compute Shannon entropy for n-grams
double ngram_entropy(const char *s, int n) {
  if (!s || (n != 1 && n != 2))
    return NAN;
  int freq[256 * 256] = {0}; // Supports up to 2-grams
  size_t total_ngrams = 0;
  size_t len = strlen(s);

  if (len < (size_t)n)
    return 0.0;

  for (size_t i = 0; i <= len - (size_t)n; i++) {
    int index = 0;
    for (int j = 0; j < n; j++) {
      index = (index << 8) | (unsigned char)s[i + j];
    }
    freq[index]++;
    total_ngrams++;
  }

  if (total_ngrams == 0)
    return 0.0;

  double entropy = 0.0;
  for (int i = 0; i < 256 * 256; i++) {
    if (freq[i] == 0)
      continue;
    double p = (double)freq[i] / total_ngrams;
    entropy -= p * log2(p);
  }

  return entropy;
}

// Forward declaration
void fixed_permute_string(char *s, int perm_index);

// Conditional entropy H(Char_i | Char_{i-1}) - entropy of char given previous
// char
double conditional_entropy(const char *s) {
  if (!s)
    return NAN;
  int bigram_freq[256][256] = {0};
  int char_freq[256] = {0};
  int total_bigrams = 0;

  int len = strlen(s);
  if (len < 2)
    return 0.0;

  for (int i = 1; i < len; i++) {
    unsigned char prev = (unsigned char)s[i - 1];
    unsigned char curr = (unsigned char)s[i];
    bigram_freq[prev][curr]++;
    char_freq[prev]++;
    total_bigrams++;
  }

  if (total_bigrams == 0)
    return 0.0;

  double entropy = 0.0;
  for (int x = 0; x < 256; x++) {
    if (char_freq[x] == 0)
      continue;

    for (int y = 0; y < 256; y++) {
      if (bigram_freq[x][y] == 0)
        continue;

      double p_xy = (double)bigram_freq[x][y] / total_bigrams;
      double p_y_given_x = (double)bigram_freq[x][y] / char_freq[x];
      entropy -= p_xy * log2(p_y_given_x);
    }
  }

  return entropy;
}

// Median conditional entropy over permutations
double permutation_conditional_entropy(const char *s, int n_perms) {
  if (!s || n_perms <= 0)
    return NAN;
  if (strlen(s) < 12) {
    return conditional_entropy(s);
  }

  size_t length = strlen(s);
  if ((size_t)n_perms > SIZE_MAX / sizeof(double))
    return NAN;
  double *entropies = malloc((size_t)n_perms * sizeof(*entropies));
  char *perm = malloc(length + 1);
  if (!entropies || !perm) {
    free(entropies);
    free(perm);
    return NAN;
  }

  for (int i = 0; i < n_perms; i++) {
    memcpy(perm, s, length + 1);
    fixed_permute_string(perm, i);
    entropies[i] = conditional_entropy(perm);
  }

  // Sort to find median
  for (int i = 0; i < n_perms - 1; i++) {
    for (int j = i + 1; j < n_perms; j++) {
      if (entropies[i] > entropies[j]) {
        double temp = entropies[i];
        entropies[i] = entropies[j];
        entropies[j] = temp;
      }
    }
  }

  double median = entropies[n_perms / 2];
  free(entropies);
  free(perm);
  return median;
}

// Relative conditional entropy ratio
double relative_conditional_entropy(const char *s, int n_perms) {
  if (!s || n_perms <= 0)
    return NAN;
  double H_original = conditional_entropy(s);
  double H_permuted = permutation_conditional_entropy(s, n_perms);
  if (H_permuted == 0.0) {
    return 2.0; /* permutation collapsed entropy: original was structured */
  }
  return H_original / H_permuted;
}

// Forward declaration
void fixed_permute_string(char *s, int perm_index);

// Simple deterministic pseudo-random based on seed
static unsigned int deterministic_rand(unsigned int seed) {
  return (seed * 1103515245 + 12345) & 0x7fffffff;
}

// Function to generate a permutation of a string (in-place) using Fisher-Yates
void fixed_permute_string(char *s, int perm_index) {
  size_t len = strlen(s);
  if (len <= 1)
    return;

  // Use perm_index as the initial seed
  unsigned int seed = perm_index;
  for (size_t i = len - 1; i > 0; i--) {
    seed = deterministic_rand(seed);
    size_t j = seed % (i + 1);

    // Swap positions i and j
    char temp = s[i];
    s[i] = s[j];
    s[j] = temp;
  }
}

// Function to compute median permutation entropy
double permutation_entropy(const char *s, int n_perms, int n) {
  if (!s || n_perms <= 0 || (n != 1 && n != 2))
    return NAN;
  if (strlen(s) < 12) {
    return ngram_entropy(s, n);
  }

  size_t length = strlen(s);
  if ((size_t)n_perms > SIZE_MAX / sizeof(double))
    return NAN;
  double *entropies = malloc((size_t)n_perms * sizeof(*entropies));
  char *perm = malloc(length + 1);
  if (!entropies || !perm) {
    free(entropies);
    free(perm);
    return NAN;
  }

  for (int i = 0; i < n_perms; i++) {
    memcpy(perm, s, length + 1);
    fixed_permute_string(perm, i);
    entropies[i] = ngram_entropy(perm, n);
  }

  // Sort entropies to find median
  for (int i = 0; i < n_perms - 1; i++) {
    for (int j = i + 1; j < n_perms; j++) {
      if (entropies[i] > entropies[j]) {
        double temp = entropies[i];
        entropies[i] = entropies[j];
        entropies[j] = temp;
      }
    }
  }

  double median = entropies[n_perms / 2];
  free(entropies);
  free(perm);
  return median;
}

// Function to compute relative entropy ratio
double relative_entropy_ratio(const char *s, int n_perms, int n) {
  if (!s || n_perms <= 0 || (n != 1 && n != 2))
    return NAN;
  double H_original = ngram_entropy(s, n);
  double H_permuted = permutation_entropy(s, n_perms, n);
  if (H_permuted == 0.0) {
    return 2.0; /* permutation collapsed entropy: original was structured */
  }
  return H_original / H_permuted;
}
