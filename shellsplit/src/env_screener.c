#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#include "env_screener.h"

/**
 * Whitelisted variables - known safe to pass through
 */
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

int env_screener_recommended_capacity(void) {
    return 32;
}

env_screener_status_t env_screener_scan(
    int *out_indices,
    int capacity,
    int *out_count,
    double entropy_threshold,
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
        
        /* Skip values too short */
        if ((int)strlen(value) < min_length) continue;
        
        /* Skip whitelisted */
        if (env_screener_is_whitelisted(name)) continue;
        
        /* Check secret patterns */
        if (env_screener_is_secret_pattern(name)) {
            flagged++;
            continue;
        }
        
        /* Check entropy */
        double entropy = env_screener_calculate_entropy(value);
        if (entropy > entropy_threshold) {
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
        
        if (env_screener_is_secret_pattern(name) ||
            env_screener_calculate_entropy(value) > entropy_threshold) {
            out_indices[out_idx++] = i;
        }
    }
    
    *out_count = out_idx;
    return ENV_SCREENER_OK;
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
