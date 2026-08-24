/*
 * shelltype-tool.c - Shelltype policy CLI tool.
 *
 * Reads length-framed canonical netargv records, builds a trie,
 * and outputs suggested policy rules.
 *
 * Usage:
 *   shelltype-tool --input <file> --suggest [--min-support N] [--output <file>]
 *   shelltype-tool --policy <file> --verify "command"
 *   shelltype-tool --policy <file> --verify-file <file>
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shell_netstring.h"
#include "shelltype.h"

/* Read one outer netstring whose payload is a complete canonical netargv. */
static int read_netargv_record(FILE *stream, char **out) {
  unsigned char *record = NULL;
  size_t record_length = 0;
  shell_netstring_status_t status =
      shell_netstring_read_stream(stream, 0, &record, &record_length);
  if (status == SHELL_NETSTRING_DONE)
    return 0;
  if (status != SHELL_NETSTRING_OK)
    return -1;
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  if (shell_netstring_iter_init(&iter, record, record_length) !=
          SHELL_NETSTRING_OK ||
      shell_netstring_iter_next(&iter, &view) != SHELL_NETSTRING_OK ||
      view.record_length != record_length ||
      memchr(view.payload, '\0', view.payload_length) != NULL) {
    free(record);
    return -1;
  }
  memmove(record, view.payload, view.payload_length);
  record[view.payload_length] = '\0';
  *out = (char *)record;
  return 1;
}

static void free_policy(st_policy_t *policy, st_policy_ctx_t *context) {
  st_policy_free(policy);
  st_policy_ctx_release(context);
}

static int print_match(const char *prefix, const char *netpattern) {
  char *cpl = NULL;
  if (!netpattern || st_netpattern_to_cpl(netpattern, &cpl) != ST_OK) {
    free(cpl);
    return -1;
  }
  int result = printf("%s%s)\n", prefix, cpl);
  free(cpl);
  return result < 0 ? -1 : 0;
}

static void print_usage(const char *prog) {
  fprintf(stderr, "Usage: %s [options]\n", prog);
  fprintf(stderr, "\n");
  fprintf(stderr,
          "Command Policy Learner - suggests generalised policy rules\n");
  fprintf(stderr, "from observed allowed commands.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Learning mode:\n");
  fprintf(stderr,
          "  --input <file>       Outer-netstring-framed netargv file\n");
  fprintf(stderr, "  --suggest            Generate and print suggestions\n");
  fprintf(stderr,
          "  --min-support <N>    Minimum occurrence count (default: %d)\n",
          ST_DEFAULT_MIN_SUPPORT);
  fprintf(stderr,
          "  --min-confidence <F> Minimum confidence 0.0-1.0 (default: %.2f)\n",
          ST_DEFAULT_MIN_CONFIDENCE);
  fprintf(stderr,
          "  --max-suggestions <N> Max suggestions to show (default: %d)\n",
          ST_DEFAULT_MAX_SUGGESTIONS);
  fprintf(
      stderr,
      "  --output <file>      Write suggestions to file instead of stdout\n");
  fprintf(stderr, "  --save <file>        Save learner state to file\n");
  fprintf(stderr, "  --load <file>        Load learner state from file\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Policy mode:\n");
  fprintf(stderr, "  --policy <file>      Load a canonical v3 policy file\n");
  fprintf(stderr, "  --verify <netargv>   Verify canonical netstring argv "
                  "against policy\n");
  fprintf(stderr,
          "  --verify-file <file> Verify outer-netstring-framed netargv\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Other:\n");
  fprintf(stderr, "  --classify <netargv> Classify canonical netstring argv\n");
  fprintf(
      stderr,
      "  --validate <pat>     Validate pattern syntax, show parsed tokens\n");
  fprintf(stderr, "  --stats <file>       Show policy statistics\n");
  fprintf(stderr, "  -h, --help           Show this help\n");
}

int main(int argc, char *argv[]) {
  const char *input_file = NULL;
  const char *output_file = NULL;
  const char *save_file = NULL;
  const char *load_file = NULL;
  const char *policy_file = NULL;
  const char *verify_cmd = NULL;
  const char *verify_file = NULL;
  const char *validate_pat = NULL;
  const char *stats_file = NULL;
  const char *classify_cmd = NULL;
  bool do_suggest = false;
  uint32_t min_support = ST_DEFAULT_MIN_SUPPORT;
  double min_confidence = ST_DEFAULT_MIN_CONFIDENCE;
  size_t max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS;

  static struct option long_options[] = {
      {"input", required_argument, 0, 'i'},
      {"suggest", no_argument, 0, 's'},
      {"min-support", required_argument, 0, 'm'},
      {"min-confidence", required_argument, 0, 'c'},
      {"max-suggestions", required_argument, 0, 'x'},
      {"output", required_argument, 0, 'o'},
      {"save", required_argument, 0, 'S'},
      {"load", required_argument, 0, 'L'},
      {"policy", required_argument, 0, 'P'},
      {"verify", required_argument, 0, 'v'},
      {"verify-file", required_argument, 0, 'V'},
      {"validate", required_argument, 0, 't'},
      {"stats", required_argument, 0, 'T'},
      {"classify", required_argument, 0, 'N'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "hi:s", long_options, NULL)) != -1) {
    switch (opt) {
    case 'i':
      input_file = optarg;
      break;
    case 's':
      do_suggest = true;
      break;
    case 'm':
      min_support = (uint32_t)atoi(optarg);
      break;
    case 'c':
      min_confidence = atof(optarg);
      break;
    case 'x':
      max_suggestions = (size_t)atoi(optarg);
      break;
    case 'o':
      output_file = optarg;
      break;
    case 'S':
      save_file = optarg;
      break;
    case 'L':
      load_file = optarg;
      break;
    case 'P':
      policy_file = optarg;
      break;
    case 'v':
      verify_cmd = optarg;
      break;
    case 'V':
      verify_file = optarg;
      break;
    case 't':
      validate_pat = optarg;
      break;
    case 'T':
      stats_file = optarg;
      break;
    case 'N':
      classify_cmd = optarg;
      break;
    case 'h':
      print_usage(argv[0]);
      return 0;
    default:
      print_usage(argv[0]);
      return 1;
    }
  }

  /* Classify mode */
  if (classify_cmd) {
    st_token_array_t arr = {NULL, 0};
    st_error_t err = st_classify(classify_cmd, &arr);
    if (err != ST_OK) {
      fprintf(stderr, "Error: normalisation failed (%d)\n", err);
      return 1;
    }
    for (size_t i = 0; i < arr.count; i++) {
      const char *sym = st_type_symbol[arr.tokens[i].type];
      printf("  [%zu] %-30s type=%-4d (%s)\n", i, arr.tokens[i].text,
             arr.tokens[i].type, sym[0] ? sym : "LITERAL");
    }
    st_free_token_array(&arr);
    return 0;
  }

  /* Validate pattern mode */
  if (validate_pat) {
    st_pattern_info_t info;
    char *netpattern = NULL;
    st_error_t err = st_netpattern_from_cpl(validate_pat, &netpattern);
    if (err == ST_OK)
      err = st_validate_netpattern(netpattern, &info);
    free(netpattern);
    if (err != ST_OK) {
      fprintf(stderr, "INVALID: %s\n", validate_pat);
      return 1;
    }
    printf("VALID: %s (%zu tokens)\n", validate_pat, info.token_count);
    for (size_t i = 0; i < info.token_count; i++) {
      const char *sym = st_type_symbol[info.token_types[i]];
      printf("  [%zu] %-30s type=%-4d (%s)\n", i, info.token_texts[i],
             info.token_types[i], sym[0] ? sym : "LITERAL");
    }
    return 0;
  }

  /* Stats mode */
  if (stats_file) {
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : NULL;
    if (!policy) {
      st_policy_ctx_release(context);
      fprintf(stderr, "Error: failed to create policy\n");
      return 1;
    }
    st_error_t err = st_policy_load(policy, stats_file, false);
    if (err != ST_OK) {
      fprintf(stderr, "Error: failed to load policy from '%s' (%d)\n",
              stats_file, err);
      free_policy(policy, context);
      return 1;
    }
    st_policy_stats_t stats;
    st_policy_get_stats(policy, &stats);
    printf("Policy statistics:\n");
    printf("  Patterns:        %zu\n", stats.pattern_count);
    printf("  States:          %zu\n", stats.state_count);
    printf("  Memory usage:    %zu bytes\n", stats.memory_bytes);
    printf("  Evaluations:     %lu\n", (unsigned long)stats.eval_count);
    printf("  Filter rejects:  %lu\n",
           (unsigned long)stats.filter_reject_count);
    printf("  Trie walks:      %lu\n", (unsigned long)stats.trie_walk_count);
    printf("  Filter rebuilds: %lu\n",
           (unsigned long)stats.filter_rebuild_count);
    printf("  Rebuild time:    %lu us\n",
           (unsigned long)stats.filter_rebuild_us);
    free_policy(policy, context);
    return 0;
  }

  /* Policy verify mode */
  if (policy_file) {
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : NULL;
    if (!policy) {
      st_policy_ctx_release(context);
      fprintf(stderr, "Error: failed to create policy\n");
      return 1;
    }

    st_error_t err = st_policy_load(policy, policy_file, false);
    if (err != ST_OK) {
      fprintf(stderr, "Error: failed to load policy from '%s' (%d)\n",
              policy_file, err);
      free_policy(policy, context);
      return 1;
    }

    fprintf(stderr, "Loaded policy with %zu patterns\n",
            st_policy_count(policy));

    /* Single command verify */
    if (verify_cmd) {
      st_eval_result_t r = {0};
      err = st_policy_eval(policy, verify_cmd, &r);
      if (err != ST_OK) {
        fprintf(stderr, "Error: invalid netargv (%d)\n", err);
        free_policy(policy, context);
        return 1;
      }
      if (r.matches) {
        if (print_match("ALLOW (matched: ", r.matching_pattern) != 0) {
          fprintf(stderr, "Error: failed to render matching netpattern\n");
          free_policy(policy, context);
          return 1;
        }
      } else {
        printf("DENY\n");
      }
      free_policy(policy, context);
      return 0;
    }

    /* File verify */
    if (verify_file) {
      FILE *fp = fopen(verify_file, "rb");
      if (!fp) {
        fprintf(stderr, "Error: cannot open '%s'\n", verify_file);
        free_policy(policy, context);
        return 1;
      }

      int record_count = 0;
      int allow_count = 0;
      int deny_count = 0;
      char *record = NULL;
      int read_status;
      while ((read_status = read_netargv_record(fp, &record)) == 1) {
        st_eval_result_t r = {0};
        err = st_policy_eval(policy, record, &r);
        if (err != ST_OK) {
          fprintf(stderr, "Error: invalid netargv record %d (%d)\n",
                  record_count + 1, err);
          free(record);
          fclose(fp);
          free_policy(policy, context);
          return 1;
        } else if (r.matches) {
          char prefix[64];
          snprintf(prefix, sizeof(prefix),
                   "ALLOW: record %-6d (matched: ", record_count + 1);
          if (print_match(prefix, r.matching_pattern) != 0) {
            fprintf(stderr, "Error: failed to render matching netpattern\n");
            free(record);
            fclose(fp);
            free_policy(policy, context);
            return 1;
          }
          allow_count++;
        } else {
          printf("DENY:  record %d\n", record_count + 1);
          deny_count++;
        }
        free(record);
        record = NULL;
        record_count++;
      }
      free(record);
      fclose(fp);
      if (read_status < 0) {
        fprintf(stderr, "Error: malformed framed input '%s'\n", verify_file);
        free_policy(policy, context);
        return 1;
      }

      fprintf(stderr, "\nSummary: %d commands, %d ALLOW, %d DENY\n",
              record_count, allow_count, deny_count);
      free_policy(policy, context);
      return 0;
    }

    fprintf(stderr,
            "Error: --verify or --verify-file required with --policy\n");
    free_policy(policy, context);
    return 1;
  }

  /* Learning mode */
  if (!input_file && !load_file) {
    fprintf(stderr, "Error: --input or --load is required\n");
    print_usage(argv[0]);
    return 1;
  }

  /* Create learner */
  st_learner_t *learner = st_learner_new(min_support, min_confidence);
  if (!learner) {
    fprintf(stderr, "Error: failed to create learner\n");
    return 1;
  }
  learner->max_suggestions = max_suggestions;

  /* Optionally load state */
  if (load_file) {
    st_error_t err = st_load(learner, load_file);
    if (err != ST_OK) {
      fprintf(stderr, "Error: failed to load state from '%s' (%d)\n", load_file,
              err);
      st_learner_free(learner);
      return 1;
    }
  }

  /* Feed commands from input file */
  if (input_file) {
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
      fprintf(stderr, "Error: cannot open '%s'\n", input_file);
      st_learner_free(learner);
      return 1;
    }

    int record_count = 0;
    int error_count = 0;
    char *record = NULL;
    int read_status;
    while ((read_status = read_netargv_record(fp, &record)) == 1) {
      st_error_t err = st_feed(learner, record);
      if (err != ST_OK) {
        error_count++;
        if (error_count <= 3)
          fprintf(stderr, "Warning: failed to feed record %d (%d)\n",
                  record_count + 1, err);
      }
      free(record);
      record = NULL;
      record_count++;
    }
    free(record);
    fclose(fp);
    if (read_status < 0) {
      fprintf(stderr, "Error: malformed framed input '%s'\n", input_file);
      st_learner_free(learner);
      return 1;
    }

    fprintf(stderr, "Fed %d commands (%d errors)\n", record_count, error_count);
    fprintf(stderr, "Total commands in trie: %u\n",
            learner->trie.total_commands);
  }

  /* Generate suggestions */
  if (do_suggest) {
    size_t sug_count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &sug_count);

    FILE *out = stdout;
    if (output_file) {
      out = fopen(output_file, "w");
      if (!out) {
        fprintf(stderr, "Error: cannot open '%s' for writing\n", output_file);
        st_learner_free(learner);
        return 1;
      }
    }

    if (sug_count == 0) {
      fprintf(out, "No suggestions (min_support=%u, min_confidence=%.2f)\n",
              min_support, min_confidence);
    } else {
      fprintf(out,
              "Top %zu suggestions (min_support=%u, min_confidence=%.2f):\n",
              sug_count, min_support, min_confidence);
      for (size_t i = 0; i < sug_count; i++) {
        char *cpl = NULL;
        if (st_netpattern_to_cpl(suggestions[i].pattern, &cpl) != ST_OK)
          cpl = strdup("<invalid netpattern>");
        fprintf(out, "%3zu. %-50s (count=%u, confidence=%.2f)\n", i + 1,
                cpl ? cpl : "<allocation failure>", suggestions[i].count,
                suggestions[i].confidence);
        free(cpl);
      }
    }

    if (out != stdout)
      fclose(out);
    st_free_suggestions(suggestions, sug_count);
  }

  /* Save state */
  if (save_file) {
    st_error_t err = st_save(learner, save_file);
    if (err != ST_OK) {
      fprintf(stderr, "Error: failed to save state to '%s' (%d)\n", save_file,
              err);
      st_learner_free(learner);
      return 1;
    }
    fprintf(stderr, "State saved to '%s'\n", save_file);
  }

  st_learner_free(learner);
  return 0;
}
