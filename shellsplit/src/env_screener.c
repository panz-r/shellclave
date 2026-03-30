#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#include "env_screener.h"

/**
 * Known secret prefixes - common prefixes in API keys/secrets
 */
static const char *secret_prefixes[] = {
    "sk-",       /* OpenAI, Stripe */
    "sk_live_",  /* Stripe live */
    "sk_test_",  /* Stripe test */
    "pk_live_",  /* Stripe public live */
    "pk_test_",  /* Stripe public test */
    "AKIA",      /* AWS access key */
    "api_",      /* Generic API key prefix */
    "apikey",    /* Generic API key */
    "ghp_",      /* GitHub personal token */
    "glpat-",    /* GitLab personal access token */
    "xoxb-",    /* Slack bot token */
    "xoxa-",    /* Slack user token */
    "EAACEdE",   /* Facebook access token */
    "AIza",      /* Google API key */
    "AIzaSy",    /* Google API key variant */
    "sq0csp-",   /* Google OAuth secret */
    "sq0a-",     /* Google OAuth */
    "ya29.",     /* Google OAuth token */
    "github_pat_", /* GitHub fine-grained token */
    NULL
};
static const char *whitelisted_vars[] = {
    /* X11/Wayland */
    "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
    "XDG_RUNTIME_DIR", "XDG_SESSION_ID", "XDG_CURRENT_DESKTOP", 
    "XDG_SESSION_TYPE", "XDG_VTNR", "XDG_SEAT",
    /* GNOME/KDE */
    "GNOME_DESKTOP_SESSION_ID", "GNOME_TERMINAL_SCREEN", 
    "GNOME_TERMINAL_SERVICE", "GNOME_TERMINAL_VERSION",
    "KDE_FULL_SESSION", "KDE_SESSION_VERSION", "KDE_MULTIHEAD",
    "QT_QPA_PLATFORM", "QT_STYLE_OVERRIDE",
    /* Terminal */
    "TMUX", "TMUX_PANE", "TERM", "TERM_PROGRAM", "COLORTERM",
    "LS_COLORS", "LESSCLOSE", "LESSOPEN",
    /* Shell/Env */
    "SHELL", "PWD", "HOME", "USER", "LOGNAME", "PATH",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "HOSTNAME", "HOST", "MACHTYPE", "ARCH",
    /* SSH/Auth */
    "SSH_AUTH_SOCK", "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY",
    /* Other common */
    "PS1", "PS2", "PS3", "PS4", "PROMPT_COMMAND",
    "HISTCONTROL", "HISTFILESIZE", "HISTSIZE", "HISTTIMEFORMAT",
    "GLOBIGNORE", "BASHOPTS", "BASH_VERSION", "BASH_VERSINFO",
    "GROUPS", "UID", "EUID", "GID", "EGID",
    "MEMORY_PRESSURE_WATCH", "INVOCATION_ID", "JOURNAL_STREAM",
    "WAYLAND_DISLOCK",
    NULL
};

/**
 * Secret patterns in variable names
 */
static const char *secret_patterns[] = {
    "KEY", "SECRET", "TOKEN", "PASSWORD", 
    "CREDENTIAL", "API", "AUTH", "PRIVATE",
    NULL
};

double env_screener_calculate_entropy(const char *str) {
    if (!str || !str[0]) return 0;
    
    int freq[256] = {0};
    int len = 0;
    
    while (str[len]) {
        freq[(unsigned char)str[len]]++;
        len++;
    }
    
    double entropy = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

bool env_screener_is_secret_pattern(const char *name) {
    if (!name) return false;
    
    for (int i = 0; secret_patterns[i]; i++) {
        if (strstr(name, secret_patterns[i])) {
            return true;
        }
    }
    return false;
}

bool env_screener_is_whitelisted(const char *name) {
    if (!name) return false;
    
    for (int i = 0; whitelisted_vars[i]; i++) {
        if (strcmp(name, whitelisted_vars[i]) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Check if value has a known secret prefix and return combined score
 * @param value  The value to check
 * @param out_suffix_entropy  If not NULL, receives entropy of suffix (after prefix)
 * @return       true if known prefix detected
 */
bool check_secret_prefix(const char *value, double *out_suffix_entropy) {
    if (!value || !value[0]) return false;
    
    size_t value_len = strlen(value);
    
    for (int i = 0; secret_prefixes[i]; i++) {
        size_t prefix_len = strlen(secret_prefixes[i]);
        if (value_len > prefix_len && strncmp(value, secret_prefixes[i], prefix_len) == 0) {
            /* Found prefix - calculate entropy of suffix */
            if (out_suffix_entropy) {
                *out_suffix_entropy = env_screener_calculate_entropy(value + prefix_len);
            }
            return true;
        }
    }
    
    return false;
}

/**
 * Check if value looks like a path (negative indicator for secrets)
 * @param value  The value to check
 * @return      true if value looks like a path
 */
bool looks_like_path(const char *value) {
    if (!value || strlen(value) < 2) return false;
    
    /* Starts with / or ~ (absolute or home-relative path) */
    if (value[0] == '/') return true;
    if (value[0] == '~') return true;
    
    /* Contains path separators in the middle */
    if (strstr(value, "/tmp/") ||
        strstr(value, "/var/") ||
        strstr(value, "/home/") ||
        strstr(value, "/usr/") ||
        strstr(value, "/etc/") ||
        strstr(value, "/run/") ||
        strstr(value, "/.local/") ||
        strstr(value, "/.cache/")) {
        return true;
    }
    
    return false;
}

/**
 * Check if value looks like base64 encoded (positive indicator for secrets)
 * @param value  The value to check
 * @return      true if value appears to be base64 encoded
 */
bool looks_like_base64(const char *value) {
    if (!value || strlen(value) < 4) return false;
    
    size_t len = strlen(value);
    
    /* Base64 uses only these characters: A-Z, a-z, 0-9, +, /, = (padding) */
    for (size_t i = 0; i < len; i++) {
        char c = value[i];
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '+' || c == '/' || c == '=')) {
            return false;
        }
    }
    
    /* Valid base64: length should be divisible by 4 (with optional padding) */
    /* And should have some padding or at least be long enough */
    if (len % 4 != 0) return false;
    
    /* Check for proper padding at end */
    if (len >= 1 && value[len-1] == '=') return true;
    if (len >= 2 && value[len-2] == '=') return true;
    
    /* Or at least 16+ chars without padding (still likely base64) */
    return len >= 16;
}

int env_screener_recommended_capacity(void) {
    return 32;
}

env_screener_status_t env_screener_scan(
    int *out_indices,
    int capacity,
    int *out_count,
    double posterior_threshold,
    int min_length
) {
    extern char **environ;
    
    if (!out_indices || !out_count) {
        return ENV_SCREENER_ERROR;
    }
    
    *out_count = 0;
    
    if (!environ) {
        return ENV_SCREENER_OK;
    }
    
    int flagged = 0;
    
    /* First pass: count how many would be flagged */
    for (int i = 0; environ[i]; i++) {
        char *eq = strchr(environ[i], '=');
        if (!eq) continue;
        
        /* Extract variable name */
        size_t name_len = eq - environ[i];
        if (name_len == 0) continue;
        
        char name[256];
        if (name_len >= sizeof(name)) continue;
        strncpy(name, environ[i], name_len);
        name[name_len] = '\0';
        
        char *value = eq + 1;
        
        /* Skip empty values */
        if (!value[0]) continue;
        
        /* Skip whitelisted */
        if (env_screener_is_whitelisted(name)) continue;
        
        /* Skip values too short */
        if ((int)strlen(value) < min_length) continue;
        
        /* Calculate Bayesian secret score */
        double score = env_screener_combined_score_name(name, value);
        
        /* Flag if score exceeds threshold */
        if (score > posterior_threshold) {
            flagged++;
        }
    }
    
    /* Check capacity */
    if (flagged > capacity) {
        *out_count = flagged;
        return ENV_SCREENER_BUFFER_TOO_SMALL;
    }
    
    /* Second pass: fill output array */
    int out_idx = 0;
    for (int i = 0; environ[i] && out_idx < capacity; i++) {
        char *eq = strchr(environ[i], '=');
        if (!eq) continue;
        
        size_t name_len = eq - environ[i];
        if (name_len == 0) continue;
        
        char name[256];
        if (name_len >= sizeof(name)) continue;
        strncpy(name, environ[i], name_len);
        name[name_len] = '\0';
        
        char *value = eq + 1;
        
        if (!value[0]) continue;
        if ((int)strlen(value) < min_length) continue;
        if (env_screener_is_whitelisted(name)) continue;
        
        /* Use Bayesian score */
        double score = env_screener_combined_score_name(name, value);
        
        if (score > posterior_threshold) {
            out_indices[out_idx++] = i;
        }
    }
    
    *out_count = out_idx;
    return ENV_SCREENER_OK;
}

/**
 * Bayesian secret detection
 * 
 * P(secret | evidence) = P(evidence | secret) * P(secret) / P(evidence)
 * 
 * We combine evidence conditionally independently:
 * P(E|secret) = P(entropy|secret) * P(prefix|secret) * P(name|secret)
 */

#define PRIOR_SECRET 0.10

/**
 * Bayesian likelihood functions for relative entropy ratios
 * 
 * For secrets: ratios cluster around 1.0 (Gaussian-like)
 * For non-secrets: ratios deviate from 1.0 (bimodal)
 */

#include <math.h>

/* Gaussian-like centered at 1.0 with std dev 0.15, scaled to 0-1 */
static double lh_ratio_secret(double ratio) {
    double deviation = ratio - 1.0;
    double gaussian = exp(-0.5 * pow(deviation / 0.15, 2));
    /* Scale to reasonable likelihood range */
    return 0.1 + 0.85 * gaussian;
}

/* Bimodal: high likelihood for ratios far from 1.0 */
static double lh_ratio_nonsecret(double ratio) {
    double deviation = fabs(ratio - 1.0);
    if (deviation < 0.3) {
        return 0.1;
    } else {
        double distance_from_peak = fmax(0.0, deviation - 0.3);
        double gaussian = exp(-0.5 * pow(distance_from_peak / 0.2, 2));
        return 0.5 + 0.45 * gaussian;
    }
}

/* Sigmoid for Shannon - high entropy favors secret */
static double lh_shannon_secret(double shannon_normalized) {
    return 1.0 / (1.0 + exp(-10.0 * (shannon_normalized - 0.6)));
}

/* Sigmoid for Shannon - low entropy favors non-secret */
static double lh_shannon_nonsecret(double shannon_normalized) {
    return 1.0 / (1.0 + exp(-10.0 * (0.6 - shannon_normalized)));
}

/* Update posterior with one piece of evidence using Bayes rule */
static double bayes_update(double posterior, double lh_h, double lh_not_h) {
    double unnormalized_h = posterior * lh_h;
    double unnormalized_not_h = (1.0 - posterior) * lh_not_h;
    double total = unnormalized_h + unnormalized_not_h;
    if (total <= 0.0) return posterior;
    return unnormalized_h / total;
}

static double likelihood_from_entropy(double shannon, double rel_conditional, double rel_2gram) {
    double posterior = PRIOR_SECRET;
    
    /* Process each ratio with Bayesian update */
    double lh_s_cond = lh_ratio_secret(rel_conditional);
    double lh_ns_cond = lh_ratio_nonsecret(rel_conditional);
    posterior = bayes_update(posterior, lh_s_cond, lh_ns_cond);
    
    double lh_s_2gram = lh_ratio_secret(rel_2gram);
    double lh_ns_2gram = lh_ratio_nonsecret(rel_2gram);
    posterior = bayes_update(posterior, lh_s_2gram, lh_ns_2gram);
    
    /* Update with smooth Shannon entropy likelihoods */
    double shannon_normalized = shannon / 8.0;
    double lh_s_shannon = lh_shannon_secret(shannon_normalized);
    double lh_ns_shannon = lh_shannon_nonsecret(shannon_normalized);
    posterior = bayes_update(posterior, lh_s_shannon, lh_ns_shannon);
    
    return posterior;
}

static double combine_evidence(double posterior, bool has_prefix,
                                bool has_name_pattern, bool is_path) {
    /* Update with prefix evidence */
    double lh_p_secret = has_prefix ? 0.98 : 0.12;
    double lh_p_not = has_prefix ? 0.02 : 0.88;
    posterior = bayes_update(posterior, lh_p_secret, lh_p_not);
    
    /* Update with name pattern evidence */
    double lh_n_secret = has_name_pattern ? 0.90 : 0.15;
    double lh_n_not = has_name_pattern ? 0.10 : 0.85;
    posterior = bayes_update(posterior, lh_n_secret, lh_n_not);
    
    /* Update with path evidence */
    double lh_path_secret = is_path ? 0.01 : 0.95;
    double lh_path_not = is_path ? 0.99 : 0.05;
    posterior = bayes_update(posterior, lh_path_secret, lh_path_not);
    
    return posterior;
}

/**
 * Calculate combined secret score using Bayesian inference
 * @param name   Variable name (e.g., "API_KEY", "MY_SECRET") or NULL
 * @param value  Variable value
 * @return      Probability 0.0-1.0 (higher = more likely to be a secret)
 */
double env_screener_combined_score_name(const char *name, const char *value) {
    if (!value || strlen(value) < 8) return 0.0;
    
    /* Get entropy evidence - use suffix entropy if has prefix */
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
    
    /* Get other evidence */
    bool has_name_pattern = (name && env_screener_is_secret_pattern(name));
    bool is_path = looks_like_path(value);
    
    /* Calculate entropy-based posterior */
    double lh_entropy = likelihood_from_entropy(shannon, rel_conditional, rel_ratio_2gram);
    
    /* Combine all evidence using Bayesian updates */
    double posterior = lh_entropy;
    posterior = combine_evidence(posterior, has_prefix, has_name_pattern, is_path);
    
    return posterior;
}

/* Legacy function for backward compatibility */
double env_screener_combined_score(const char *value) {
    return env_screener_combined_score_name(NULL, value);
}

const char *env_screener_get_whitelist_doc(void) {
    static char doc[2048] = {0};
    if (doc[0]) return doc;
    
    size_t pos = 0;
    for (int i = 0; whitelisted_vars[i] && pos < sizeof(doc) - 20; i++) {
        if (i > 0) {
            pos += snprintf(doc + pos, sizeof(doc) - pos, ", ");
        }
        pos += snprintf(doc + pos, sizeof(doc) - pos, "%s", whitelisted_vars[i]);
    }
    return doc;
}
