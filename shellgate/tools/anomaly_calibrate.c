/*
 * anomaly_calibrate - Threshold calibration and ROC curve generator
 *
 * Trains the anomaly model on a corpus of normal commands, generates
 * synthetic anomalies via perturbation, evaluates at multiple thresholds,
 * and outputs ROC curve data (TPR, FPR, precision, F1, AUC).
 *
 * Usage:
 *   anomaly_calibrate -n normal.txt [options]
 *
 * Options:
 *   -n <file>   Normal commands corpus (one command per line, required)
 *   -o <file>   Output file (default: stdout)
 *   -t <s,e,i>  Threshold range: start,end,step (default: 0.0,15.0,0.5)
 *   -p <type>   Perturbation: swap|insert|substitute|shuffle|all (default: all)
 *   -N <num>    Synthetics per normal command (default: 3)
 *   -f <fmt>    Output: csv|json|text (default: csv)
 *   -s <file>   Save trained model to file
 *   -h          Show help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

#include "shellgate.h"
#include "sg_anomaly.h"

#define MAX_LINE 4096
#define MAX_TOKENS 256
#define MAX_CMDS  65536
#define MAX_SYNTHTETIC (MAX_CMDS * 4)

/* Uncommon commands for substitution/insertion perturbations */
static const char *rare_cmds[] = {
    "mkfs", "fdisk", "dd", "iptables", "reboot",
    "shutdown", "nc", "strace", "objdump", "gdb",
    "hexdump", "base64", "strings", "nm", "strip"
};
#define NUM_RARE (sizeof(rare_cmds) / sizeof(rare_cmds[0]))

typedef enum {
    PERTURB_SWAP = 0,
    PERTURB_INSERT,
    PERTURB_SUBSTITUTE,
    PERTURB_SHUFFLE,
    PERTURB_ALL
} perturb_type_t;

typedef struct {
    double threshold;
    int tp, fp, tn, fn;
    double tpr, fpr, precision, f1;
} roc_point_t;

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

static size_t tokenize_cmd(const char *line, char **tokens, size_t max_tokens, char *buf, size_t buf_size)
{
    size_t count = 0;
    strncpy(buf, line, buf_size - 1);
    buf[buf_size - 1] = '\0';
    char *saveptr;
    char *token = strtok_r(buf, " \t\r\n", &saveptr);
    while (token && count < max_tokens) {
        tokens[count++] = token;
        token = strtok_r(NULL, " \t\r\n", &saveptr);
    }
    return count;
}

/* Build a semicolon-separated command string from token array */
static size_t build_cmd_str(const char **tokens, size_t count, char *out, size_t out_size)
{
    size_t pos = 0;
    for (size_t i = 0; i < count && pos < out_size - 1; i++) {
        size_t tlen = strlen(tokens[i]);
        if (pos + tlen + 2 >= out_size) break;
        if (i > 0) {
            out[pos++] = ' ';
            out[pos++] = ';';
            out[pos++] = ' ';
        }
        memcpy(out + pos, tokens[i], tlen);
        pos += tlen;
    }
    out[pos] = '\0';
    return pos;
}

static unsigned int rand_uint(unsigned int *state)
{
    *state = *state * 1103515245u + 12345u;
    return (*state >> 16) & 0x7fff;
}

/* Perturbation: swap two adjacent commands */
static bool perturb_swap(const char **tokens, size_t count,
                          char *out, size_t out_size, unsigned int *rng)
{
    if (count < 2) return false;
    /* Pick two random positions to swap */
    size_t a = rand_uint(rng) % count;
    size_t b = rand_uint(rng) % count;
    if (a == b) b = (b + 1) % count;

    const char *copy[MAX_TOKENS];
    for (size_t i = 0; i < count; i++) copy[i] = tokens[i];
    const char *tmp = copy[a];
    copy[a] = copy[b];
    copy[b] = tmp;
    build_cmd_str(copy, count, out, out_size);
    return true;
}

/* Perturbation: insert a random rare command */
static bool perturb_insert(const char **tokens, size_t count,
                             char *out, size_t out_size, unsigned int *rng)
{
    if (count < 2) return false;
    const char *copy[MAX_TOKENS + 2];
    size_t insert_pos = rand_uint(rng) % (count + 1);
    size_t j = 0;
    for (size_t i = 0; i < count && j < MAX_TOKENS; i++) {
        if (i == insert_pos) {
            copy[j++] = rare_cmds[rand_uint(rng) % NUM_RARE];
        }
        copy[j++] = tokens[i];
    }
    if (insert_pos == count && j < MAX_TOKENS)
        copy[j++] = rare_cmds[rand_uint(rng) % NUM_RARE];
    build_cmd_str(copy, j, out, out_size);
    return true;
}

/* Perturbation: substitute one command with a rare one */
static bool perturb_substitute(const char **tokens, size_t count,
                                 char *out, size_t out_size, unsigned int *rng)
{
    if (count == 0) return false;
    const char *copy[MAX_TOKENS];
    size_t pos = rand_uint(rng) % count;
    for (size_t i = 0; i < count; i++) {
        copy[i] = (i == pos) ? rare_cmds[rand_uint(rng) % NUM_RARE] : tokens[i];
    }
    build_cmd_str(copy, count, out, out_size);
    return true;
}

/* Perturbation: shuffle all tokens */
static bool perturb_shuffle(const char **tokens, size_t count,
                              char *out, size_t out_size, unsigned int *rng)
{
    if (count < 2) return false;
    const char *copy[MAX_TOKENS];
    for (size_t i = 0; i < count; i++) copy[i] = tokens[i];
    /* Fisher-Yates */
    for (size_t i = count - 1; i > 0; i--) {
        size_t j = rand_uint(rng) % (i + 1);
        const char *tmp = copy[i];
        copy[i] = copy[j];
        copy[j] = tmp;
    }
    /* Check that shuffle actually changed something */
    bool changed = false;
    for (size_t i = 0; i < count; i++) {
        if (copy[i] != tokens[i]) { changed = true; break; }
    }
    if (!changed) return false;
    build_cmd_str(copy, count, out, out_size);
    return true;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s -n <corpus> [options]\n", prog);
    printf("Options:\n");
    printf("  -n <file>   Normal commands corpus (one per line, required)\n");
    printf("  -o <file>   Output file (default: stdout)\n");
    printf("  -t <s,e,i>  Threshold range: start,end,step (default: 0.0,15.0,0.5)\n");
    printf("  -p <type>   Perturbation: swap|insert|substitute|shuffle|all (default: all)\n");
    printf("  -N <num>    Synthetics per normal command (default: 3)\n");
    printf("  -f <fmt>    Output: csv|json|text (default: csv)\n");
    printf("  -s <file>   Save trained model to file\n");
    printf("  -h          Show help\n");
}

int main(int argc, char **argv)
{
    const char *normal_path = NULL;
    const char *output_path = NULL;
    const char *save_model_path = NULL;
    double t_start = 0.0, t_end = 15.0, t_step = 0.5;
    perturb_type_t ptype = PERTURB_ALL;
    int num_synth_per_cmd = 3;
    const char *fmt = "csv";
    unsigned int rng = (unsigned int)time(NULL);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            normal_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (sscanf(argv[++i], "%lf,%lf,%lf", &t_start, &t_end, &t_step) != 3) {
                fprintf(stderr, "Invalid threshold range: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "swap") == 0) ptype = PERTURB_SWAP;
            else if (strcmp(argv[i], "insert") == 0) ptype = PERTURB_INSERT;
            else if (strcmp(argv[i], "substitute") == 0) ptype = PERTURB_SUBSTITUTE;
            else if (strcmp(argv[i], "shuffle") == 0) ptype = PERTURB_SHUFFLE;
            else if (strcmp(argv[i], "all") == 0) ptype = PERTURB_ALL;
            else { fprintf(stderr, "Unknown perturbation: %s\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "-N") == 0 && i + 1 < argc) {
            num_synth_per_cmd = atoi(argv[++i]);
            if (num_synth_per_cmd < 1) num_synth_per_cmd = 1;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            fmt = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            save_model_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!normal_path) {
        fprintf(stderr, "Error: -n <corpus> is required\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Load normal corpus */
    FILE *fp = fopen(normal_path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open %s: ", normal_path);
        perror(NULL);
        return 1;
    }

    char **normal_cmds = calloc(MAX_CMDS, sizeof(char *));
    size_t normal_count = 0;
    char line[MAX_LINE];

    while (fgets(line, sizeof(line), fp) && normal_count < MAX_CMDS) {
        char *cmd = trim(line);
        if (!*cmd) continue;
        normal_cmds[normal_count++] = strdup(cmd);
    }
    fclose(fp);

    if (normal_count == 0) {
        fprintf(stderr, "No commands in corpus\n");
        return 1;
    }
    fprintf(stderr, "Loaded %zu normal commands\n", normal_count);

    /* Create gate and train model */
    sg_gate_t *gate = sg_gate_new();
    sg_gate_enable_anomaly(gate, 5.0, 0.1, -10.0);

    /* Allow all commands for training */
    for (size_t i = 0; i < normal_count; i++) {
        char buf[8192];
        sg_result_t r;
        sg_eval(gate, normal_cmds[i], strlen(normal_cmds[i]),
                buf, sizeof(buf), &r);
    }
    fprintf(stderr, "Model trained (vocab=%zu)\n",
            sg_gate_anomaly_vocab_size(gate));

    if (save_model_path) {
        sg_gate_save_anomaly_model(gate, save_model_path);
        fprintf(stderr, "Model saved to %s\n", save_model_path);
    }

    /* Score normal commands */
    double *normal_scores = calloc(normal_count, sizeof(double));
    for (size_t i = 0; i < normal_count; i++) {
        char buf[8192];
        sg_result_t r;
        sg_eval(gate, normal_cmds[i], strlen(normal_cmds[i]),
                buf, sizeof(buf), &r);
        normal_scores[i] = r.anomaly_score;
    }

    /* Generate and score synthetic anomalies */
    char **synth_cmds = calloc(MAX_SYNTHTETIC, sizeof(char *));
    double *synth_scores = calloc(MAX_SYNTHTETIC, sizeof(double));
    size_t synth_count = 0;

    char tok_buf[MAX_LINE];
    char *tok_ptrs[MAX_TOKENS];
    char synth_buf[MAX_LINE];

    for (size_t i = 0; i < normal_count && synth_count < MAX_SYNTHTETIC; i++) {
        strncpy(tok_buf, normal_cmds[i], sizeof(tok_buf) - 1);
        tok_buf[sizeof(tok_buf) - 1] = '\0';
        size_t tcount = tokenize_cmd(normal_cmds[i], (char**)tok_ptrs,
                                      MAX_TOKENS, tok_buf, sizeof(tok_buf));
        if (tcount < 2) continue;

        /* We need the original tokens as strings for perturbation */
        char *orig_dup = strdup(normal_cmds[i]);
        char *saveptr;
        const char *tokens[MAX_TOKENS];
        char *tok = strtok_r(orig_dup, " \t\r\n;", &saveptr);
        size_t ntok = 0;
        while (tok && ntok < MAX_TOKENS) {
            tokens[ntok++] = tok;
            tok = strtok_r(NULL, " \t\r\n;", &saveptr);
        }

        for (int n = 0; n < num_synth_per_cmd && synth_count < MAX_SYNTHTETIC; n++) {
            bool ok = false;

            if (ptype == PERTURB_SWAP || ptype == PERTURB_ALL) {
                ok = perturb_swap(tokens, ntok, synth_buf, sizeof(synth_buf), &rng);
            }
            if (!ok && (ptype == PERTURB_INSERT || ptype == PERTURB_ALL)) {
                ok = perturb_insert(tokens, ntok, synth_buf, sizeof(synth_buf), &rng);
            }
            if (!ok && (ptype == PERTURB_SUBSTITUTE || ptype == PERTURB_ALL)) {
                ok = perturb_substitute(tokens, ntok, synth_buf, sizeof(synth_buf), &rng);
            }
            if (!ok && (ptype == PERTURB_SHUFFLE || ptype == PERTURB_ALL)) {
                ok = perturb_shuffle(tokens, ntok, synth_buf, sizeof(synth_buf), &rng);
            }
            if (!ok) { free(orig_dup); continue; }

            synth_cmds[synth_count] = strdup(synth_buf);

            /* Score the synthetic anomaly */
            char buf[8192];
            sg_result_t r;
            sg_eval(gate, synth_buf, strlen(synth_buf),
                    buf, sizeof(buf), &r);
            synth_scores[synth_count] = r.anomaly_score;
            synth_count++;
        }
        free(orig_dup);
    }

    fprintf(stderr, "Generated %zu synthetic anomalies\n", synth_count);

    /* Compute ROC curve */
    size_t num_thresholds = (size_t)((t_end - t_start) / t_step) + 1;
    if (num_thresholds > 1000) num_thresholds = 1000;
    roc_point_t *roc = calloc(num_thresholds, sizeof(roc_point_t));

    for (size_t t = 0; t < num_thresholds; t++) {
        double threshold = t_start + t * t_step;
        if (threshold > t_end) break;

        int tp = 0, fp = 0, tn = 0, fn = 0;

        for (size_t i = 0; i < normal_count; i++) {
            if (normal_scores[i] > threshold) fp++;
            else tn++;
        }
        for (size_t i = 0; i < synth_count; i++) {
            if (synth_scores[i] > threshold) tp++;
            else fn++;
        }

        roc[t].threshold = threshold;
        roc[t].tp = tp; roc[t].fp = fp;
        roc[t].tn = tn; roc[t].fn = fn;
        roc[t].tpr = (tp + fn > 0) ? (double)tp / (double)(tp + fn) : 0.0;
        roc[t].fpr = (fp + tn > 0) ? (double)fp / (double)(fp + tn) : 0.0;
        roc[t].precision = (tp + fp > 0) ? (double)tp / (double)(tp + fp) : 0.0;
        roc[t].f1 = (roc[t].precision + roc[t].tpr > 0)
                     ? 2.0 * roc[t].precision * roc[t].tpr / (roc[t].precision + roc[t].tpr)
                     : 0.0;
    }

    /* Compute AUC using trapezoidal rule (FPR decreases as threshold increases) */
    double auc = 0.0;
    for (size_t t = 1; t < num_thresholds; t++) {
        double dfpr = fabs(roc[t].fpr - roc[t - 1].fpr);
        auc += dfpr * (roc[t].tpr + roc[t - 1].tpr) / 2.0;
    }

    /* Find best F1 threshold */
    double best_f1 = -1.0;
    double best_threshold = t_start;
    for (size_t t = 0; t < num_thresholds; t++) {
        if (roc[t].f1 > best_f1) {
            best_f1 = roc[t].f1;
            best_threshold = roc[t].threshold;
        }
    }

    /* Open output */
    FILE *out = stdout;
    if (output_path) {
        out = fopen(output_path, "w");
        if (!out) {
            fprintf(stderr, "Cannot open output: %s\n", output_path);
            return 1;
        }
    }

    /* Output results */
    if (strcmp(fmt, "json") == 0) {
        fprintf(out, "{\n");
        fprintf(out, "  \"normal_count\": %zu,\n", normal_count);
        fprintf(out, "  \"anomaly_count\": %zu,\n", synth_count);
        fprintf(out, "  \"auc\": %.4f,\n", auc);
        fprintf(out, "  \"best_threshold\": %.2f,\n", best_threshold);
        fprintf(out, "  \"best_f1\": %.4f,\n", best_f1);
        fprintf(out, "  \"points\": [\n");
        for (size_t t = 0; t < num_thresholds; t++) {
            fprintf(out, "    {\"threshold\": %.2f, \"tp\": %d, \"fp\": %d, "
                         "\"tn\": %d, \"fn\": %d, \"tpr\": %.4f, \"fpr\": %.4f, "
                         "\"precision\": %.4f, \"f1\": %.4f}%s\n",
                    roc[t].threshold, roc[t].tp, roc[t].fp, roc[t].tn, roc[t].fn,
                    roc[t].tpr, roc[t].fpr, roc[t].precision, roc[t].f1,
                    (t < num_thresholds - 1) ? "," : "");
        }
        fprintf(out, "  ]\n}\n");
    } else if (strcmp(fmt, "text") == 0) {
        fprintf(out, "Threshold calibration results\n");
        fprintf(out, "Normal: %zu  Anomalies: %zu  AUC: %.4f\n",
                normal_count, synth_count, auc);
        fprintf(out, "Best threshold: %.2f (F1=%.4f)\n\n",
                best_threshold, best_f1);
        fprintf(out, "%-10s %6s %6s %6s %6s %8s %8s %10s %8s\n",
                "Thresh", "TP", "FP", "TN", "FN", "TPR", "FPR", "Prec", "F1");
        fprintf(out, "%-10s %6s %6s %6s %6s %8s %8s %10s %8s\n",
                "------", "--", "--", "--", "--", "---", "---", "----", "--");
        for (size_t t = 0; t < num_thresholds; t++) {
            fprintf(out, "%-10.2f %6d %6d %6d %6d %8.4f %8.4f %10.4f %8.4f\n",
                    roc[t].threshold, roc[t].tp, roc[t].fp,
                    roc[t].tn, roc[t].fn,
                    roc[t].tpr, roc[t].fpr, roc[t].precision, roc[t].f1);
        }
    } else {
        /* CSV (default) */
        fprintf(out, "threshold,tp,fp,tn,fn,tpr,fpr,precision,f1\n");
        for (size_t t = 0; t < num_thresholds; t++) {
            fprintf(out, "%.2f,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.4f\n",
                    roc[t].threshold, roc[t].tp, roc[t].fp,
                    roc[t].tn, roc[t].fn,
                    roc[t].tpr, roc[t].fpr, roc[t].precision, roc[t].f1);
        }
        fprintf(out, "# normal=%zu anomaly=%zu auc=%.4f best_threshold=%.2f best_f1=%.4f\n",
                normal_count, synth_count, auc, best_threshold, best_f1);
    }

    if (output_path) fclose(out);

    /* Cleanup */
    for (size_t i = 0; i < normal_count; i++) free(normal_cmds[i]);
    free(normal_cmds);
    free(normal_scores);
    for (size_t i = 0; i < synth_count; i++) free(synth_cmds[i]);
    free(synth_cmds);
    free(synth_scores);
    free(roc);
    sg_gate_free(gate);

    return 0;
}
