#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Function to compute Shannon entropy for n-grams
double ngram_entropy(const char *s, int n) {
    int freq[256 * 256] = {0}; // Supports up to 2-grams
    int total_ngrams = 0;
    int len = strlen(s);

    if (len < n) return 0.0;

    for (int i = 0; i <= len - n; i++) {
        int index = 0;
        for (int j = 0; j < n; j++) {
            index = (index << 8) | (unsigned char)s[i + j];
        }
        freq[index]++;
        total_ngrams++;
    }

    if (total_ngrams == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256 * 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / total_ngrams;
        entropy -= p * log2(p);
    }

    return entropy;
}

// Forward declaration
void fixed_permute_string(char *s, int perm_index);

// Conditional entropy H(Char_i | Char_{i-1}) - entropy of char given previous char
double conditional_entropy(const char *s) {
    int bigram_freq[256][256] = {0};
    int char_freq[256] = {0};
    int total_bigrams = 0;
    
    int len = strlen(s);
    if (len < 2) return 0.0;
    
    for (int i = 1; i < len; i++) {
        unsigned char prev = (unsigned char)s[i-1];
        unsigned char curr = (unsigned char)s[i];
        bigram_freq[prev][curr]++;
        char_freq[prev]++;
        total_bigrams++;
    }
    
    if (total_bigrams == 0) return 0.0;
    
    double entropy = 0.0;
    for (int x = 0; x < 256; x++) {
        if (char_freq[x] == 0) continue;
        
        for (int y = 0; y < 256; y++) {
            if (bigram_freq[x][y] == 0) continue;
            
            double p_xy = (double)bigram_freq[x][y] / total_bigrams;
            double p_y_given_x = (double)bigram_freq[x][y] / char_freq[x];
            entropy -= p_xy * log2(p_y_given_x);
        }
    }
    
    return entropy;
}

// Median conditional entropy over permutations
double permutation_conditional_entropy(const char *s, int n_perms) {
    if (strlen(s) < 12) {
        return conditional_entropy(s);
    }
    
    double entropies[10];
    char perm[256];
    
    for (int i = 0; i < n_perms; i++) {
        strcpy(perm, s);
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
    
    return entropies[n_perms / 2];
}

// Relative conditional entropy ratio
double relative_conditional_entropy(const char *s, int n_perms) {
    double H_original = conditional_entropy(s);
    double H_permuted = permutation_conditional_entropy(s, n_perms);
    if (H_permuted == 0.0) {
        return 2.0;  /* permutation collapsed entropy: original was structured */
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
    int len = strlen(s);
    if (len <= 1) return;
    
    // Use perm_index as the initial seed
    unsigned int seed = perm_index;
    for (int i = len - 1; i > 0; i--) {
        seed = deterministic_rand(seed);
        int j = seed % (i + 1);
        
        // Swap positions i and j
        char temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}

// Function to compute median permutation entropy
double permutation_entropy(const char *s, int n_perms, int n) {
    if (strlen(s) < 12) {
        return ngram_entropy(s, n);
    }

    double entropies[10]; // Fixed to 10 permutations
    char perm[256]; // Assume max string length of 255

    for (int i = 0; i < n_perms; i++) {
        strcpy(perm, s);
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

    return entropies[n_perms / 2]; // Median
}

// Function to compute relative entropy ratio
double relative_entropy_ratio(const char *s, int n_perms, int n) {
    double H_original = ngram_entropy(s, n);
    double H_permuted = permutation_entropy(s, n_perms, n);
    if (H_permuted == 0.0) {
        return 2.0;  /* permutation collapsed entropy: original was structured */
    }
    return H_original / H_permuted;
}

#ifndef RELATIVE_ENTROPY_NO_MAIN
int main() {
    const char *test_strings[] = {
        "sk_live_abc123XYZ789",  // Secret
        "this_is_a_file_path.txt", // File path
        "hello world",            // Natural language
        "a1b2c3d4e5f6"           // Structured secret
    };

    for (int i = 0; i < 4; i++) {
        const char *s = test_strings[i];
        double ratio_char = relative_entropy_ratio(s, 10, 1);
        double ratio_2gram = relative_entropy_ratio(s, 10, 2);

        printf("String: %s\n", s);
        printf("  Character ratio: %.2f\n", ratio_char);
        printf("  2-gram ratio: %.2f\n", ratio_2gram);
        printf("  Combined score: %.2f\n\n", 0.3 * ratio_char + 0.7 * ratio_2gram);
    }

    return 0;
}
#endif

