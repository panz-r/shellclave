/*
 * anomaly_demo - Interactive anomaly detection demo tool
 *
 * Reads commands from stdin, prints anomaly scores, optionally updates model.
 * Usage:
 *   anomaly_demo [options]
 *
 * Options:
 *   -m <file>   Load model from file (or create new if not exists)
 *   -s <file>   Save model to file
 *   -t <num>    Set anomaly threshold (default: 5.0)
 *   -u          Update model with commands (learning mode)
 *   -d <scale>  Apply decay to model (e.g., 0.99)
 *   -p <count>  Prune entries with count < count
 *   -c          Compact model (recover memory)
 *   -h          Show this help
 *
 * Examples:
 *   # Score commands interactively
 *   anomaly_demo -m model.bin
 *
 *   # Train on commands from file
 *   cat commands.txt | anomaly_demo -u -s model.bin
 *
 *   # Apply decay and compact
 *   anomaly_demo -m model.bin -d 0.99 -c -s model.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "sg_anomaly.h"

#define MAX_LINE 4096

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -m <file>   Load model from file (or create new if not exists)\n");
    printf("  -s <file>   Save model to file\n");
    printf("  -t <num>    Set anomaly threshold (default: 5.0)\n");
    printf("  -u          Update model with commands (learning mode)\n");
    printf("  -d <scale>  Apply decay to model (e.g., 0.99)\n");
    printf("  -p <count>  Prune entries with count < count\n");
    printf("  -c          Compact model (recover memory)\n");
    printf("  -h          Show this help\n");
}

static void print_result(const char *cmd, double score,
                        bool detected, bool updated)
{
    printf("[%s] score=%.2f", cmd, score);
    if (detected) {
        printf(" ANOMALOUS");
    }
    if (updated) {
        printf(" (learned)");
    }
    printf("\n");
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;

    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

/* Simple tokenizer: split command into tokens for anomaly update */
static size_t tokenize(const char *line, const char **tokens, size_t max_tokens)
{
    size_t count = 0;
    static char buf[MAX_LINE];

    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr;
    char *token = strtok_r(buf, " \t\r\n", &saveptr);
    while (token && count < max_tokens) {
        tokens[count++] = token;
        token = strtok_r(NULL, " \t\r\n", &saveptr);
    }
    return count;
}

int main(int argc, char **argv)
{
    const char *model_path = NULL;
    const char *save_path = NULL;
    double threshold = 5.0;
    bool learning = false;
    double decay_scale = 0.0;
    bool do_decay = false;
    size_t prune_min = 0;
    bool do_prune = false;
    bool do_compact = false;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            model_path = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            save_path = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            threshold = atof(argv[++i]);
        } else if (strcmp(argv[i], "-u") == 0) {
            learning = true;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            decay_scale = atof(argv[++i]);
            do_decay = true;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            prune_min = (size_t)atoi(argv[++i]);
            do_prune = true;
        } else if (strcmp(argv[i], "-c") == 0) {
            do_compact = true;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Create or load model */
    sg_anomaly_model_t *model = sg_anomaly_model_new_ex(0.1, -10.0);
    if (!model) {
        fprintf(stderr, "Failed to create model\n");
        return 1;
    }

    if (model_path) {
        if (sg_anomaly_load(model, model_path) != 0) {
            fprintf(stderr, "Warning: Could not load model from %s, starting fresh\n",
                    model_path);
        } else {
            printf("Loaded model from %s (vocab=%zu)\n",
                   model_path, sg_anomaly_vocab_size(model));
        }
    }

    /* Handle maintenance operations */
    if (do_decay) {
        printf("Applying decay (scale=%.2f)...\n", decay_scale);
        sg_anomaly_model_decay(model, decay_scale);
        printf("After decay: vocab=%zu, total_uni=%zu\n",
               sg_anomaly_vocab_size(model), sg_anomaly_total_uni(model));
    }

    if (do_prune) {
        printf("Pruning entries with count < %zu...\n", prune_min);
        size_t removed = sg_anomaly_model_prune(model, prune_min);
        printf("Removed %zu entries\n", removed);
    }

    if (do_compact) {
        printf("Compacting model...\n");
        bool did_compact = sg_anomaly_model_compact(model);
        printf("Compaction %s\n", did_compact ? "completed" : "not needed");
    }

    /* Save if requested */
    if (save_path && (do_decay || do_prune || do_compact)) {
        if (sg_anomaly_save(model, save_path) == 0) {
            printf("Model saved to %s\n", save_path);
        } else {
            fprintf(stderr, "Failed to save model to %s\n", save_path);
        }
    }

    /* Interactive mode */
    if (!do_decay && !do_prune && !do_compact && !save_path) {
        printf("Anomaly detection (threshold=%.2f, learning=%s)\n",
               threshold, learning ? "on" : "off");
        printf("Enter commands (Ctrl+D to exit):\n");

        char line[MAX_LINE];
        const char *tokens[256];

        while (fgets(line, sizeof(line), stdin)) {
            char *cmd = trim(line);
            if (!*cmd) continue;

            size_t count = tokenize(cmd, tokens, 256);

            /* Score the command sequence */
            double score = sg_anomaly_score(model, tokens, count);

            /* Adjust for short sequences */
            if (count < 3) {
                score = 0.0;
            }

            bool detected = (count >= 3) && (score > threshold);
            bool updated = false;

            /* Update model if in learning mode */
            if (learning && count > 0) {
                if (!detected) {
                    sg_anomaly_update(model, tokens, count);
                    updated = true;
                }
            }

            print_result(cmd, score, detected, updated);
        }
    }

    /* Save on exit if requested */
    if (save_path && !do_decay && !do_prune && !do_compact) {
        if (sg_anomaly_save(model, save_path) == 0) {
            printf("Model saved to %s\n", save_path);
        } else {
            fprintf(stderr, "Failed to save model to %s\n", save_path);
        }
    }

    if (sg_anomaly_model_had_error(model)) {
        fprintf(stderr, "Warning: Model had an allocation error\n");
    }

    sg_anomaly_model_free(model);
    return 0;
}
