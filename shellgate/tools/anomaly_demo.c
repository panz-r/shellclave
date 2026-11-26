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

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sg_anomaly.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"

#define MAX_LINE 4096

static void print_usage(const char *prog) {
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

static void print_result(const char *cmd, double score, bool detected,
                         bool updated) {
  printf("[%s] score=%.2f", cmd, score);
  if (detected) {
    printf(" ANOMALOUS");
  }
  if (updated) {
    printf(" (learned)");
  }
  printf("\n");
}

/* A finite number that fills text. */
static SHELL_NONNULL(1, 2) bool parse_finite(const char *text, double *out) {
  char *end = NULL;
  errno = 0;
  double value = strtod(text, &end);
  if (end == text || *end != '\0' || errno != 0 || !isfinite(value))
    return false;
  *out = value;
  return true;
}

/* A non-negative decimal integer that fills text. */
static SHELL_NONNULL(1, 2) bool parse_count(const char *text, size_t *out) {
  if (*text < '0' || *text > '9')
    return false;
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 10);
  if (*end != '\0' || errno != 0 || value > SIZE_MAX)
    return false;
  *out = (size_t)value;
  return true;
}

typedef enum { LINE_OK, LINE_EOF, LINE_NUL, LINE_LONG } line_status_t;

/* Read one physical line into line (size bytes) without its newline. A line
 * with a NUL byte or longer than the buffer is consumed and reported, so it
 * is neither truncated nor split into several commands. */
static SHELL_NONNULL(1) line_status_t read_line(char *line, size_t size) {
  size_t used = 0;
  line_status_t status = LINE_OK;
  for (;;) {
    int current = fgetc(stdin);
    if (current == EOF) {
      if (used == 0 && status == LINE_OK)
        return LINE_EOF;
      break;
    }
    if (current == '\n')
      break;
    if (current == '\0')
      status = LINE_NUL;
    else if (used + 1 < size)
      line[used++] = (char)current;
    else if (status == LINE_OK)
      status = LINE_LONG;
  }
  line[used] = '\0';
  return status;
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

int main(int argc, char **argv) {
  const char *model_path = NULL;
  const char *save_path = NULL;
  double threshold = 5.0;
  bool learning = false;
  double decay_scale = 0.0;
  bool do_decay = false;
  size_t prune_min = 0;
  bool do_prune = false;
  bool do_compact = false;
  bool save_failed = false;

  /* Parse CLI options into runtime settings. */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
      model_path = argv[++i];
    } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      save_path = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      if (!parse_finite(argv[++i], &threshold)) {
        fprintf(stderr, "Invalid threshold: %s\n", argv[i]);
        return 1;
      }
    } else if (strcmp(argv[i], "-u") == 0) {
      learning = true;
    } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      if (!parse_finite(argv[++i], &decay_scale)) {
        fprintf(stderr, "Invalid decay scale: %s\n", argv[i]);
        return 1;
      }
      do_decay = true;
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      if (!parse_count(argv[++i], &prune_min)) {
        fprintf(stderr, "Invalid prune count: %s\n", argv[i]);
        return 1;
      }
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
  sg_anomaly_config_t config;
  sg_anomaly_config_default(&config);
  sg_anomaly_model_t *model = sg_anomaly_model_new_with_config(&config);
  if (!model) {
    fprintf(stderr, "Failed to create model\n");
    return 1;
  }

  if (model_path) {
    if (sg_anomaly_model_load(model, model_path) != SG_ANOMALY_OK) {
      fprintf(stderr, "Warning: Could not load model from %s, starting fresh\n",
              model_path);
    } else {
      printf("Loaded model from %s (vocab=%zu)\n", model_path,
             sg_anomaly_model_vocab_size(model));
    }
  }

  /* Handle maintenance operations */
  if (do_decay) {
    printf("Applying decay (scale=%.2f)...\n", decay_scale);
    if (sg_anomaly_model_decay(model, decay_scale) != SG_ANOMALY_OK) {
      fprintf(stderr, "anomaly decay failed\n");
      sg_anomaly_model_free(model);
      return 1;
    }
    printf("After decay: vocab=%zu, total_uni=%zu\n",
           sg_anomaly_model_vocab_size(model),
           sg_anomaly_model_total_unigrams(model));
  }

  if (do_prune) {
    printf("Pruning entries with count < %zu...\n", prune_min);
    size_t removed = 0;
    if (sg_anomaly_model_prune(model, prune_min, &removed) != SG_ANOMALY_OK) {
      fprintf(stderr, "anomaly prune failed\n");
      sg_anomaly_model_free(model);
      return 1;
    }
    printf("Removed %zu entries\n", removed);
  }

  if (do_compact) {
    printf("Compacting model...\n");
    if (sg_anomaly_model_compact(model) != SG_ANOMALY_OK) {
      fprintf(stderr, "anomaly compaction failed\n");
      sg_anomaly_model_free(model);
      return 1;
    }
    printf("Compaction completed\n");
  }

  /* Save if requested */
  if (save_path && (do_decay || do_prune || do_compact)) {
    if (sg_anomaly_model_save(model, save_path) == SG_ANOMALY_OK) {
      printf("Model saved to %s\n", save_path);
    } else {
      fprintf(stderr, "Failed to save model to %s\n", save_path);
      save_failed = true;
    }
  }

  /* Interactive mode: the maintenance options replace it; -s only saves what
   * it learned. */
  if (!do_decay && !do_prune && !do_compact) {
    printf("Anomaly detection (threshold=%.2f, learning=%s)\n", threshold,
           learning ? "on" : "off");
    printf("Enter commands (Ctrl+D to exit):\n");

    char line[MAX_LINE] = {0};
    line_status_t line_status;
    while ((line_status = read_line(line, sizeof(line))) != LINE_EOF) {
      if (line_status != LINE_OK) {
        fprintf(stderr, "Skipped a line %s\n",
                line_status == LINE_NUL ? "with a NUL byte"
                                        : "longer than the line buffer");
        continue;
      }
      char *cmd = trim(line);
      if (!*cmd)
        continue;

      size_t count = 0;
      shell_netstring_buffer_t netseq = {0};
      shell_process_status_t sequence_status =
          shell_build_command_netseq_buffer(cmd, strlen(cmd), NULL, &netseq,
                                            &count);
      /* A comment-only line holds no command. */
      if (sequence_status == SHELL_PROCESS_BLANK)
        continue;
      if (sequence_status != SHELL_PROCESS_OK || !netseq.data) {
        fprintf(stderr, "Could not parse command sequence\n");
        continue;
      }

      /* Score the command sequence */
      double score = INFINITY;
      sg_anomaly_status_t score_status = sg_anomaly_model_score_netseq(
          model, (const char *)netseq.data, netseq.length, &score);
      if (score_status != SG_ANOMALY_OK) {
        shell_netstring_buffer_free(&netseq);
        fprintf(stderr, "Could not score command sequence\n");
        continue;
      }

      /* Adjust for short sequences */
      if (count < 3) {
        score = 0.0;
      }

      /* An empty model scores INFINITY: nothing is known, so nothing is
       * anomalous yet and the command can be learned. */
      bool detected = (count >= 3) && isfinite(score) && (score > threshold);
      bool updated = false;

      /* Update model if in learning mode */
      if (learning && count > 0) {
        if (!detected) {
          updated =
              sg_anomaly_model_update_netseq(model, (const char *)netseq.data,
                                             netseq.length) == SG_ANOMALY_OK;
        }
      }

      print_result(cmd, score, detected, updated);
      shell_netstring_buffer_free(&netseq);
    }
  }

  /* Save on exit if requested */
  if (save_path && !do_decay && !do_prune && !do_compact) {
    if (sg_anomaly_model_save(model, save_path) == SG_ANOMALY_OK) {
      printf("Model saved to %s\n", save_path);
    } else {
      fprintf(stderr, "Failed to save model to %s\n", save_path);
      save_failed = true;
    }
  }

  if (sg_anomaly_model_had_error(model)) {
    fprintf(stderr, "Warning: Model had an allocation error\n");
  }

  sg_anomaly_model_free(model);
  return save_failed ? 1 : 0;
}
