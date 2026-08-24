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

#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sg_anomaly.h"
#include "shell_abstract.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shellgate.h"

#define MAX_LINE 4096
#define MAX_TOKENS 256
#define MAX_CMDS 65536
#define MAX_SYNTHTETIC (MAX_CMDS * 4)

/* Uncommon commands for substitution/insertion perturbations */
static const char *rare_cmds[] = {"mkfs",    "fdisk",    "dd",      "iptables",
                                  "reboot",  "shutdown", "nc",      "strace",
                                  "objdump", "gdb",      "hexdump", "base64",
                                  "strings", "nm",       "strip"};
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

typedef struct {
  char *raw_netseq;
  char *type_netseq;
  size_t count;
} corpus_record_t;

typedef shell_netstring_view_t netseq_span_t;

static void free_corpus(corpus_record_t *records, size_t count) {
  if (!records)
    return;
  for (size_t i = 0; i < count; i++) {
    free(records[i].raw_netseq);
    free(records[i].type_netseq);
  }
  free(records);
}

static char *trim(char *s) {
  while (isspace((unsigned char)*s))
    s++;
  if (*s == 0)
    return s;
  char *end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end))
    end--;
  end[1] = '\0';
  return s;
}

static bool collect_netseq_views(const char *netseq, size_t length,
                                 netseq_span_t *out, size_t capacity,
                                 size_t *count) {
  *count = 0;
  shell_netstring_iter_t iter;
  if (shell_netstring_iter_init(&iter, netseq, length) != SHELL_NETSTRING_OK)
    return false;
  shell_netstring_status_t status;
  shell_netstring_view_t view;
  for (;;) {
    status = shell_netstring_iter_next(&iter, &view);
    if (status != SHELL_NETSTRING_OK)
      break;
    if (*count == capacity)
      return false;
    out[(*count)++] = view;
  }
  return status == SHELL_NETSTRING_DONE;
}

static bool rare_spans(const char *command, netseq_span_t *raw,
                       netseq_span_t *type, char raw_buf[64],
                       char type_buf[80]) {
  size_t length = strlen(command);
  size_t raw_written = 0;
  if (shell_netstring_write(raw_buf, 64, command, length, &raw_written) !=
      SHELL_NETSTRING_OK)
    return false;
  size_t type_written = 0;
  if (shell_netstring_write(type_buf, 80, raw_buf, raw_written,
                            &type_written) != SHELL_NETSTRING_OK)
    return false;
  *raw = (netseq_span_t){(const unsigned char *)raw_buf, raw_written, NULL, 0};
  *type =
      (netseq_span_t){(const unsigned char *)type_buf, type_written, NULL, 0};
  return true;
}

static char *render_selection(const netseq_span_t *spans, size_t count,
                              const size_t *order, const char *rare_command,
                              bool type_sequence) {
  char raw_buf[64], type_buf[80];
  netseq_span_t rare_raw, rare_type;
  if (rare_command &&
      !rare_spans(rare_command, &rare_raw, &rare_type, raw_buf, type_buf))
    return NULL;
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    netseq_span_t span = order[i] == SIZE_MAX
                             ? (type_sequence ? rare_type : rare_raw)
                             : spans[order[i]];
    if (span.record_length > SIZE_MAX - total)
      return NULL;
    total += span.record_length;
  }
  char *out = malloc(total + 1);
  if (!out)
    return NULL;
  size_t used = 0;
  for (size_t i = 0; i < count; i++) {
    netseq_span_t span = order[i] == SIZE_MAX
                             ? (type_sequence ? rare_type : rare_raw)
                             : spans[order[i]];
    memcpy(out + used, span.record, span.record_length);
    used += span.record_length;
  }
  out[used] = '\0';
  return out;
}

static unsigned int rand_uint(unsigned int *state) {
  *state = *state * 1103515245u + 12345u;
  return (*state >> 16) & 0x7fff;
}

/* Perturbation: swap two adjacent commands */
static bool perturb_swap(size_t *order, size_t count, unsigned int *rng) {
  if (count < 2)
    return false;
  /* Pick two random positions to swap */
  size_t a = rand_uint(rng) % count;
  size_t b = rand_uint(rng) % count;
  if (a == b)
    b = (b + 1) % count;

  for (size_t i = 0; i < count; i++)
    order[i] = i;
  size_t tmp = order[a];
  order[a] = order[b];
  order[b] = tmp;
  return true;
}

/* Perturbation: insert a random rare command */
static bool perturb_insert(size_t *order, size_t *out_count, size_t count,
                           unsigned int *rng) {
  if (count < 2)
    return false;
  if (count >= MAX_TOKENS)
    return false;
  size_t insert_pos = rand_uint(rng) % (count + 1);
  size_t j = 0;
  for (size_t i = 0; i < count; i++) {
    if (i == insert_pos) {
      order[j++] = SIZE_MAX;
    }
    order[j++] = i;
  }
  if (insert_pos == count)
    order[j++] = SIZE_MAX;
  *out_count = j;
  return true;
}

/* Perturbation: substitute one command with a rare one */
static bool perturb_substitute(size_t *order, size_t count, unsigned int *rng) {
  if (count == 0)
    return false;
  size_t pos = rand_uint(rng) % count;
  for (size_t i = 0; i < count; i++) {
    order[i] = i == pos ? SIZE_MAX : i;
  }
  return true;
}

/* Perturbation: shuffle all tokens */
static bool perturb_shuffle(size_t *order, size_t count, unsigned int *rng) {
  if (count < 2)
    return false;
  for (size_t i = 0; i < count; i++)
    order[i] = i;
  /* Shuffle token copies in-place using Fisher-Yates. */
  for (size_t i = count - 1; i > 0; i--) {
    size_t j = rand_uint(rng) % (i + 1);
    size_t tmp = order[i];
    order[i] = order[j];
    order[j] = tmp;
  }
  /* Check that shuffle actually changed something */
  bool changed = false;
  for (size_t i = 0; i < count; i++) {
    if (order[i] != i) {
      changed = true;
      break;
    }
  }
  if (!changed)
    return false;
  return true;
}

static void print_usage(const char *prog) {
  printf("Usage: %s -n <corpus> [options]\n", prog);
  printf("Options:\n");
  printf("  -n <file>   Normal commands corpus (one per line, required)\n");
  printf("  -o <file>   Output file (default: stdout)\n");
  printf("  -t <s,e,i>  Threshold range: start,end,step (default: "
         "0.0,15.0,0.5)\n");
  printf("  -p <type>   Perturbation: swap|insert|substitute|shuffle|all "
         "(default: all)\n");
  printf("  -N <num>    Synthetics per normal command (default: 3)\n");
  printf("  -f <fmt>    Output: csv|json|text (default: csv)\n");
  printf("  -s <file>   Save trained model to file\n");
  printf("  -h          Show help\n");
}

int main(int argc, char **argv) {
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
      if (strcmp(argv[i], "swap") == 0)
        ptype = PERTURB_SWAP;
      else if (strcmp(argv[i], "insert") == 0)
        ptype = PERTURB_INSERT;
      else if (strcmp(argv[i], "substitute") == 0)
        ptype = PERTURB_SUBSTITUTE;
      else if (strcmp(argv[i], "shuffle") == 0)
        ptype = PERTURB_SHUFFLE;
      else if (strcmp(argv[i], "all") == 0)
        ptype = PERTURB_ALL;
      else {
        fprintf(stderr, "Unknown perturbation: %s\n", argv[i]);
        return 1;
      }
    } else if (strcmp(argv[i], "-N") == 0 && i + 1 < argc) {
      num_synth_per_cmd = atoi(argv[++i]);
      if (num_synth_per_cmd < 1)
        num_synth_per_cmd = 1;
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

  sg_gate_t *gate = sg_gate_new();
  if (!gate || sg_gate_enable_anomaly(gate, 5.0, 0.1, -10.0) != SG_OK) {
    sg_gate_free(gate);
    fprintf(stderr, "Cannot create anomaly gate\n");
    return 1;
  }

  /* Load and train from the normal shell-source corpus. */
  FILE *fp = fopen(normal_path, "r");
  if (!fp) {
    fprintf(stderr, "Cannot open %s: ", normal_path);
    perror(NULL);
    sg_gate_free(gate);
    return 1;
  }

  corpus_record_t *normal = calloc(MAX_CMDS, sizeof(*normal));
  if (!normal) {
    fclose(fp);
    sg_gate_free(gate);
    fprintf(stderr, "Cannot allocate corpus storage\n");
    return 1;
  }
  size_t normal_count = 0;
  char line[MAX_LINE];

  while (fgets(line, sizeof(line), fp) && normal_count < MAX_CMDS) {
    char *cmd = trim(line);
    if (!*cmd)
      continue;
    char *raw = NULL, *type = NULL;
    size_t raw_count = 0, type_count = 0;
    if (shell_build_command_netseq(cmd, NULL, &raw, &raw_count) !=
            SHELL_PROCESS_OK ||
        shell_build_type_netseq(cmd, NULL, &type, &type_count) !=
            SHELL_PROCESS_OK ||
        raw_count == 0 || raw_count != type_count) {
      free(raw);
      free(type);
      continue;
    }
    char buf[8192];
    sg_result_t result;
    if (sg_eval(gate, cmd, strlen(cmd), buf, sizeof(buf), &result) != SG_OK) {
      free(raw);
      free(type);
      continue;
    }
    normal[normal_count++] = (corpus_record_t){raw, type, raw_count};
  }
  fclose(fp);

  if (normal_count == 0) {
    fprintf(stderr, "No commands in corpus\n");
    free_corpus(normal, normal_count);
    sg_gate_free(gate);
    return 1;
  }
  fprintf(stderr, "Loaded %zu normal commands\n", normal_count);

  fprintf(stderr, "Model trained (vocab=%zu)\n",
          sg_gate_anomaly_vocab_size(gate));

  if (save_model_path) {
    sg_gate_save_anomaly_model(gate, save_model_path);
    fprintf(stderr, "Model saved to %s\n", save_model_path);
  }

  /* Score normal commands */
  double *normal_scores = calloc(normal_count, sizeof(double));
  if (!normal_scores) {
    fprintf(stderr, "Cannot allocate normal scores\n");
    free_corpus(normal, normal_count);
    sg_gate_free(gate);
    return 1;
  }
  for (size_t i = 0; i < normal_count; i++) {
    sg_anomaly_sequence_score_t score = {0};
    if (sg_gate_score_anomaly_netseq(
            gate, normal[i].raw_netseq, strlen(normal[i].raw_netseq),
            normal[i].type_netseq, strlen(normal[i].type_netseq),
            &score) != SG_OK) {
      fprintf(stderr, "Cannot score canonical corpus record\n");
      free(normal_scores);
      free_corpus(normal, normal_count);
      sg_gate_free(gate);
      return 1;
    }
    normal_scores[i] = score.combined_score;
  }

  /* Generate and score synthetic anomalies */
  double *synth_scores = calloc(MAX_SYNTHTETIC, sizeof(double));
  if (!synth_scores) {
    fprintf(stderr, "Cannot allocate synthetic scores\n");
    free(normal_scores);
    free_corpus(normal, normal_count);
    sg_gate_free(gate);
    return 1;
  }
  size_t synth_count = 0;

  for (size_t i = 0; i < normal_count && synth_count < MAX_SYNTHTETIC; i++) {
    if (normal[i].count < 2 || normal[i].count > MAX_TOKENS)
      continue;
    netseq_span_t raw_spans[MAX_TOKENS], type_spans[MAX_TOKENS];
    size_t raw_count = 0, type_count = 0;
    if (!collect_netseq_views(normal[i].raw_netseq,
                              strlen(normal[i].raw_netseq), raw_spans,
                              MAX_TOKENS, &raw_count) ||
        !collect_netseq_views(normal[i].type_netseq,
                              strlen(normal[i].type_netseq), type_spans,
                              MAX_TOKENS, &type_count) ||
        raw_count != normal[i].count || type_count != raw_count)
      continue;

    for (int n = 0; n < num_synth_per_cmd && synth_count < MAX_SYNTHTETIC;
         n++) {
      size_t order[MAX_TOKENS + 1];
      size_t selected_count = raw_count;
      const char *rare = rare_cmds[rand_uint(&rng) % NUM_RARE];
      bool ok = false;

      if (ptype == PERTURB_SWAP || ptype == PERTURB_ALL) {
        ok = perturb_swap(order, raw_count, &rng);
      }
      if (!ok && (ptype == PERTURB_INSERT || ptype == PERTURB_ALL)) {
        ok = perturb_insert(order, &selected_count, raw_count, &rng);
      }
      if (!ok && (ptype == PERTURB_SUBSTITUTE || ptype == PERTURB_ALL)) {
        ok = perturb_substitute(order, raw_count, &rng);
      }
      if (!ok && (ptype == PERTURB_SHUFFLE || ptype == PERTURB_ALL)) {
        ok = perturb_shuffle(order, raw_count, &rng);
      }
      if (!ok)
        continue;
      char *raw =
          render_selection(raw_spans, selected_count, order, rare, false);
      char *type =
          render_selection(type_spans, selected_count, order, rare, true);
      if (!raw || !type) {
        free(raw);
        free(type);
        continue;
      }
      sg_anomaly_sequence_score_t score = {0};
      if (sg_gate_score_anomaly_netseq(gate, raw, strlen(raw), type,
                                       strlen(type), &score) == SG_OK)
        synth_scores[synth_count++] = score.combined_score;
      free(raw);
      free(type);
    }
  }

  fprintf(stderr, "Generated %zu synthetic anomalies\n", synth_count);

  /* Compute ROC curve */
  size_t num_thresholds = (size_t)((t_end - t_start) / t_step) + 1;
  if (num_thresholds > 1000)
    num_thresholds = 1000;
  roc_point_t *roc = calloc(num_thresholds, sizeof(roc_point_t));
  if (!roc) {
    fprintf(stderr, "Cannot allocate ROC output\n");
    free(synth_scores);
    free(normal_scores);
    free_corpus(normal, normal_count);
    sg_gate_free(gate);
    return 1;
  }

  for (size_t t = 0; t < num_thresholds; t++) {
    double threshold = t_start + t * t_step;
    if (threshold > t_end)
      break;

    int tp = 0, fp = 0, tn = 0, fn = 0;

    for (size_t i = 0; i < normal_count; i++) {
      if (normal_scores[i] > threshold)
        fp++;
      else
        tn++;
    }
    for (size_t i = 0; i < synth_count; i++) {
      if (synth_scores[i] > threshold)
        tp++;
      else
        fn++;
    }

    roc[t].threshold = threshold;
    roc[t].tp = tp;
    roc[t].fp = fp;
    roc[t].tn = tn;
    roc[t].fn = fn;
    roc[t].tpr = (tp + fn > 0) ? (double)tp / (double)(tp + fn) : 0.0;
    roc[t].fpr = (fp + tn > 0) ? (double)fp / (double)(fp + tn) : 0.0;
    roc[t].precision = (tp + fp > 0) ? (double)tp / (double)(tp + fp) : 0.0;
    roc[t].f1 = (roc[t].precision + roc[t].tpr > 0)
                    ? 2.0 * roc[t].precision * roc[t].tpr /
                          (roc[t].precision + roc[t].tpr)
                    : 0.0;
  }

  /* Compute AUC using trapezoidal rule (FPR decreases as threshold increases)
   */
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

  /* Open requested output target (stdout by default). */
  FILE *out = stdout;
  if (output_path) {
    out = fopen(output_path, "w");
    if (!out) {
      fprintf(stderr, "Cannot open output: %s\n", output_path);
      free(roc);
      free(synth_scores);
      free(normal_scores);
      free_corpus(normal, normal_count);
      sg_gate_free(gate);
      return 1;
    }
  }

  /* Write calibration output in the requested format. */
  if (strcmp(fmt, "json") == 0) {
    fprintf(out, "{\n");
    fprintf(out, "  \"normal_count\": %zu,\n", normal_count);
    fprintf(out, "  \"anomaly_count\": %zu,\n", synth_count);
    fprintf(out, "  \"auc\": %.4f,\n", auc);
    fprintf(out, "  \"best_threshold\": %.2f,\n", best_threshold);
    fprintf(out, "  \"best_f1\": %.4f,\n", best_f1);
    fprintf(out, "  \"points\": [\n");
    for (size_t t = 0; t < num_thresholds; t++) {
      fprintf(out,
              "    {\"threshold\": %.2f, \"tp\": %d, \"fp\": %d, "
              "\"tn\": %d, \"fn\": %d, \"tpr\": %.4f, \"fpr\": %.4f, "
              "\"precision\": %.4f, \"f1\": %.4f}%s\n",
              roc[t].threshold, roc[t].tp, roc[t].fp, roc[t].tn, roc[t].fn,
              roc[t].tpr, roc[t].fpr, roc[t].precision, roc[t].f1,
              (t < num_thresholds - 1) ? "," : "");
    }
    fprintf(out, "  ]\n}\n");
  } else if (strcmp(fmt, "text") == 0) {
    fprintf(out, "Threshold calibration results\n");
    fprintf(out, "Normal: %zu  Anomalies: %zu  AUC: %.4f\n", normal_count,
            synth_count, auc);
    fprintf(out, "Best threshold: %.2f (F1=%.4f)\n\n", best_threshold, best_f1);
    fprintf(out, "%-10s %6s %6s %6s %6s %8s %8s %10s %8s\n", "Thresh", "TP",
            "FP", "TN", "FN", "TPR", "FPR", "Prec", "F1");
    fprintf(out, "%-10s %6s %6s %6s %6s %8s %8s %10s %8s\n", "------", "--",
            "--", "--", "--", "---", "---", "----", "--");
    for (size_t t = 0; t < num_thresholds; t++) {
      fprintf(out, "%-10.2f %6d %6d %6d %6d %8.4f %8.4f %10.4f %8.4f\n",
              roc[t].threshold, roc[t].tp, roc[t].fp, roc[t].tn, roc[t].fn,
              roc[t].tpr, roc[t].fpr, roc[t].precision, roc[t].f1);
    }
  } else {
    /* CSV (default) */
    fprintf(out, "threshold,tp,fp,tn,fn,tpr,fpr,precision,f1\n");
    for (size_t t = 0; t < num_thresholds; t++) {
      fprintf(out, "%.2f,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.4f\n", roc[t].threshold,
              roc[t].tp, roc[t].fp, roc[t].tn, roc[t].fn, roc[t].tpr,
              roc[t].fpr, roc[t].precision, roc[t].f1);
    }
    fprintf(
        out,
        "# normal=%zu anomaly=%zu auc=%.4f best_threshold=%.2f best_f1=%.4f\n",
        normal_count, synth_count, auc, best_threshold, best_f1);
  }

  if (output_path)
    fclose(out);

  /* Release temporary buffers before returning. */
  free_corpus(normal, normal_count);
  free(normal_scores);
  free(synth_scores);
  free(roc);
  sg_gate_free(gate);

  return 0;
}
