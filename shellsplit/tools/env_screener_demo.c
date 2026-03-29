#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>
#include <getopt.h>

#include "env_screener.h"
#include "relative_permutation_entropy.h"

#define INDENT "  "
#define CENSORED "[VALUE REDACTED]"

const char* safe_value_str(const char* value) {
    (void)value;
    return CENSORED;
}

void print_separator(void) {
    printf("----------------------------------------\n");
}

void print_banner(const char* title) {
    printf("\n");
    print_separator();
    printf("[STEP] %s\n", title);
    print_separator();
}

bool is_empty_value(const char* value) {
    return value == NULL || value[0] == '\0';
}

void print_value_analysis(const char* name, const char* value) {
    print_banner("1. PARSE INPUT");
    
    printf("%sVAR=%s\n", INDENT, name);
    printf("%sVALUE=%s\n", INDENT, safe_value_str(value));
    printf("%sValue length: %zu\n", INDENT, strlen(value));
    printf("%sIs empty: %s\n", INDENT, is_empty_value(value) ? "YES (skip)" : "NO");
}

void print_whitelist_check(const char* name) {
    print_banner("2. WHITELIST CHECK");
    
    printf("%sVariable name: %s\n", INDENT, name);
    bool is_whitelisted = env_screener_is_whitelisted(name);
    printf("%sIs whitelisted: %s\n", INDENT, is_whitelisted ? "YES (skip)" : "NO");
    
    if (!is_whitelisted) {
        printf("%sKnown safe vars (partial): DISPLAY, PATH, HOME, SSH_AUTH_SOCK, etc.\n", INDENT);
    }
}

void print_min_length_check(const char* value, int min_length) {
    print_banner("3. MINIMUM LENGTH CHECK");
    
    printf("%sMin length threshold: %d\n", INDENT, min_length);
    printf("%sValue length: %zu\n", INDENT, strlen(value));
    printf("%sExceeds min length: %s\n", INDENT, 
           (int)strlen(value) >= min_length ? "YES (continue)" : "NO (skip)");
}

void print_entropy_analysis(const char* value, bool has_prefix, double suffix_entropy) {
    print_banner("4. ENTROPY ANALYSIS");
    
    double shannon;
    if (has_prefix && suffix_entropy > 0) {
        printf("%sHas secret prefix: YES\n", INDENT);
        printf("%sUsing suffix entropy (after prefix): %.4f bits\n", INDENT, suffix_entropy);
        shannon = suffix_entropy;
    } else {
        printf("%sHas secret prefix: NO\n", INDENT);
        printf("%sShannon entropy (full value): %.4f bits/char\n", INDENT, 
               env_screener_calculate_entropy(value));
        shannon = env_screener_calculate_entropy(value);
    }
    
    printf("%sMaximum possible entropy: 8.0 bits/char\n", INDENT);
    printf("%sNormalized (0-1): %.4f\n", INDENT, shannon / 8.0);
    
    printf("\n%sRelative Permutation Entropy (5 permutations):\n", INDENT);
    
    double rel_conditional = relative_conditional_entropy(value, 5);
    double rel_ratio_2gram = relative_entropy_ratio(value, 5, 2);
    
    printf("%s  - Conditional entropy ratio: %.4f\n", INDENT, rel_conditional);
    if (rel_conditional > 1.0) {
        printf("%s    >1.0 means original is MORE random than permutations (suspicious)\n", INDENT);
    } else {
        printf("%s    <1.0 means original has structure that permutations destroy\n", INDENT);
    }
    
    printf("%s  - 2-gram entropy ratio: %.4f\n", INDENT, rel_ratio_2gram);
    if (rel_ratio_2gram > 1.0) {
        printf("%s    >1.0 means original is MORE random than permutations (suspicious)\n", INDENT);
    } else {
        printf("%s    <1.0 means original has structure that permutations destroy\n", INDENT);
    }
}

void print_pattern_checks(const char* name, const char* value) {
    print_banner("5. PATTERN CHECKS");
    
    bool has_name_pattern = env_screener_is_secret_pattern(name);
    printf("%sName matches secret pattern (KEY, SECRET, TOKEN, etc.): %s\n", 
           INDENT, has_name_pattern ? "YES" : "NO");
    
    double suffix_entropy;
    bool has_prefix = check_secret_prefix(value, &suffix_entropy);
    printf("%sValue has known secret prefix: %s\n", INDENT, has_prefix ? "YES" : "NO");
    if (has_prefix) {
        printf("%s  Suffix entropy: %.4f bits\n", INDENT, suffix_entropy);
        printf("%s  Known prefixes: sk-, AKIA, ghp_, xoxb-, github_pat_, etc.\n", INDENT);
    }
    
    bool is_path = looks_like_path(value);
    printf("%sValue looks like a path: %s\n", INDENT, is_path ? "YES (negative indicator)" : "NO");
    
    bool is_base64 = looks_like_base64(value);
    printf("%sValue looks like base64: %s\n", INDENT, is_base64 ? "YES" : "NO");
}

void print_bayesian_scoring(double shannon, double rel_conditional, double rel_2gram,
                            bool has_prefix, bool has_name_pattern, bool is_path) {
    print_banner("6. BAYESIAN SCORING");
    
    printf("%sP(secret) prior: 0.10\n\n", INDENT);
    
    printf("%sEvidence factors:\n", INDENT);
    
    double posterior = 0.10;
    
    printf("%s  [A] Entropy evidence:\n", INDENT);
    double deviation = rel_conditional - 1.0;
    double gaussian = exp(-0.5 * pow(deviation / 0.15, 2));
    double lh_s_cond = 0.1 + 0.85 * gaussian;
    double lh_ns_cond = (fabs(deviation) < 0.3) ? 0.1 : (0.5 + 0.45 * exp(-0.5 * pow((fabs(deviation) - 0.3) / 0.2, 2)));
    printf("%s    Conditional ratio: %.4f -> P(E|secret)=%.4f, P(E|~secret)=%.4f\n", 
           INDENT, rel_conditional, lh_s_cond, lh_ns_cond);
    
    deviation = rel_2gram - 1.0;
    gaussian = exp(-0.5 * pow(deviation / 0.15, 2));
    double lh_s_2gram = 0.1 + 0.85 * gaussian;
    lh_ns_cond = (fabs(deviation) < 0.3) ? 0.1 : (0.5 + 0.45 * exp(-0.5 * pow((fabs(deviation) - 0.3) / 0.2, 2)));
    printf("%s    2-gram ratio: %.4f -> P(E|secret)=%.4f, P(E|~secret)=%.4f\n", 
           INDENT, rel_2gram, lh_s_2gram, lh_ns_cond);
    
    double shannon_norm = shannon / 8.0;
    double lh_shannon = 1.0 / (1.0 + exp(-10.0 * (shannon_norm - 0.6)));
    double lh_ns_shannon = 1.0 / (1.0 + exp(-10.0 * (0.6 - shannon_norm)));
    printf("%s    Shannon normalized: %.4f -> P(E|secret)=%.4f, P(E|~secret)=%.4f\n", 
           INDENT, shannon_norm, lh_shannon, lh_ns_shannon);
    
    posterior = posterior * lh_s_cond / (posterior * lh_s_cond + (1.0 - posterior) * lh_ns_cond);
    printf("%s    Posterior after [A]: %.4f\n", INDENT, posterior);
    
    posterior = posterior * lh_s_2gram / (posterior * lh_s_2gram + (1.0 - posterior) * lh_ns_cond);
    printf("%s    Posterior after [B]: %.4f\n", INDENT, posterior);
    
    posterior = posterior * lh_shannon / (posterior * lh_shannon + (1.0 - posterior) * lh_ns_shannon);
    printf("%s    Posterior after [C]: %.4f\n", INDENT, posterior);
    
    printf("\n%s  [B] Prefix evidence: %s\n", INDENT, has_prefix ? "PRESENT" : "ABSENT");
    double lh_p_secret = has_prefix ? 0.98 : 0.12;
    double lh_p_not = has_prefix ? 0.02 : 0.88;
    posterior = posterior * lh_p_secret / (posterior * lh_p_secret + (1.0 - posterior) * lh_p_not);
    printf("%s    Posterior after [D]: %.4f\n", INDENT, posterior);
    
    printf("\n%s  [C] Name pattern evidence: %s\n", INDENT, has_name_pattern ? "PRESENT" : "ABSENT");
    double lh_n_secret = has_name_pattern ? 0.90 : 0.15;
    double lh_n_not = has_name_pattern ? 0.10 : 0.85;
    posterior = posterior * lh_n_secret / (posterior * lh_n_secret + (1.0 - posterior) * lh_n_not);
    printf("%s    Posterior after [E]: %.4f\n", INDENT, posterior);
    
    printf("\n%s  [D] Path evidence: %s\n", INDENT, is_path ? "PRESENT (negative)" : "ABSENT");
    double lh_path_secret = is_path ? 0.01 : 0.95;
    double lh_path_not = is_path ? 0.99 : 0.05;
    posterior = posterior * lh_path_secret / (posterior * lh_path_secret + (1.0 - posterior) * lh_path_not);
    printf("%s    Posterior after [F]: %.4f\n", INDENT, posterior);
    
    printf("\n%sFINAL SCORE: %.4f\n", INDENT, posterior);
}

void print_threshold_decision(double score, double threshold) {
    print_banner("7. THRESHOLD DECISION");
    
    printf("%sThreshold: %.4f\n", INDENT, threshold);
    printf("%sScore: %.4f\n", INDENT, score);
    printf("%sDecision: %s\n", INDENT, score > threshold ? "FLAGGED (would block/prompt)" : "CLEAR");
}

void print_summary(const char* name, const char* value, double score, 
                   bool is_whitelisted, bool passes_min_length, double threshold) {
    print_separator();
    printf("SUMMARY: %s=%s (len=%zu)\n", name, safe_value_str(value), strlen(value));
    print_separator();
    
    if (is_whitelisted) {
        printf("  Result: WHITELISTED (skipped)\n");
        return;
    }
    
    if (!passes_min_length) {
        printf("  Result: TOO SHORT (skipped)\n");
        return;
    }
    
    printf("  Score: %.4f / Threshold: %.4f\n", score, threshold);
    printf("  Verdict: %s\n", score > threshold ? "FLAGGED" : "CLEAR");
}

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [OPTIONS] VAR=VALUE\n", prog);
    fprintf(stderr, "\nAnalyze an environment variable and show the screening process.\n");
    fprintf(stderr, "The VALUE is redacted in output to avoid exposing secrets.\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -t <threshold>  Set posterior threshold (default: 0.5)\n");
    fprintf(stderr, "  -m <length>     Set minimum value length (default: 24)\n");
    fprintf(stderr, "  -h              Show this help\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s GITHUB_TOKEN=ghp_xxx...\n", prog);
    fprintf(stderr, "  %s API_KEY=sk_live_xxx...\n", prog);
    fprintf(stderr, "  %s PATH=/usr/local/bin:/usr/bin\n", prog);
    fprintf(stderr, "  %s MY_SECRET=randomHighEntropyString\n", prog);
}

int main(int argc, char** argv) {
    const char* var_eq_value = NULL;
    double threshold = ENV_SCREENER_POSTERIOR_THRESHOLD;
    int min_length = ENV_SCREENER_MIN_LENGTH;
    
    int opt;
    while ((opt = getopt(argc, argv, "t:m:h")) != -1) {
        switch (opt) {
            case 't':
                threshold = atof(optarg);
                break;
            case 'm':
                min_length = atoi(optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: VAR=VALUE argument required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    var_eq_value = argv[optind];
    
    char* eq = strchr(var_eq_value, '=');
    if (!eq) {
        fprintf(stderr, "Error: Invalid format. Expected VAR=VALUE\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    size_t name_len = eq - var_eq_value;
    if (name_len == 0) {
        fprintf(stderr, "Error: Empty variable name\n");
        return 1;
    }
    
    char* name = strndup(var_eq_value, name_len);
    char* value = strdup(eq + 1);
    
    printf("\n");
    printf("################################################################################\n");
    printf("#                  ENVIRONMENT VARIABLE SCREENING DEMO                           #\n");
    printf("################################################################################\n");
    printf("\nInput: %s=%s (len=%zu)\n", name, safe_value_str(value), strlen(value));
    printf("Threshold: %.2f | Min Length: %d\n", threshold, min_length);
    
    print_value_analysis(name, value);
    
    bool whitelisted = env_screener_is_whitelisted(name);
    print_whitelist_check(name);
    
    if (whitelisted) {
        print_summary(name, value, 0.0, true, false, threshold);
        free(name);
        free(value);
        return 0;
    }
    
    if (is_empty_value(value)) {
        printf("\n[STEP] Value is empty - skipping analysis\n");
        print_summary(name, value, 0.0, false, false, threshold);
        free(name);
        free(value);
        return 0;
    }
    
    bool passes_min_length = (int)strlen(value) >= min_length;
    print_min_length_check(value, min_length);
    
    if (!passes_min_length) {
        print_summary(name, value, 0.0, false, false, threshold);
        free(name);
        free(value);
        return 0;
    }
    
    double suffix_entropy = 0;
    bool has_prefix = check_secret_prefix(value, &suffix_entropy);
    
    double shannon;
    if (has_prefix && suffix_entropy > 0) {
        shannon = suffix_entropy;
    } else {
        shannon = env_screener_calculate_entropy(value);
    }
    
    double rel_conditional = relative_conditional_entropy(value, 5);
    double rel_ratio_2gram = relative_entropy_ratio(value, 5, 2);
    
    print_entropy_analysis(value, has_prefix, suffix_entropy);
    
    bool has_name_pattern = env_screener_is_secret_pattern(name);
    bool is_path = looks_like_path(value);
    
    print_pattern_checks(name, value);
    print_bayesian_scoring(shannon, rel_conditional, rel_ratio_2gram, has_prefix, has_name_pattern, is_path);
    
    double score = env_screener_combined_score_name(name, value);
    print_threshold_decision(score, threshold);
    print_summary(name, value, score, false, true, threshold);
    
    printf("\n");
    
    free(name);
    free(value);
    
    return 0;
}
