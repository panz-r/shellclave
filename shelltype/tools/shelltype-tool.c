/*
 * shelltype-tool.c - Shelltype policy CLI tool.
 *
 * Reads allowed commands from a file (one per line), builds a trie,
 * and outputs suggested policy rules.
 *
 * Usage:
 *   shelltype-tool --input <file> --suggest [--min-support N] [--output <file>]
 *   shelltype-tool --policy <file> --verify "command"
 *   shelltype-tool --policy <file> --verify-file <file>
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>

#include "shelltype.h"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Command Policy Learner - suggests generalised policy rules\n");
    fprintf(stderr, "from observed allowed commands.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Learning mode:\n");
    fprintf(stderr, "  --input <file>       Input file with one command per line\n");
    fprintf(stderr, "  --suggest            Generate and print suggestions\n");
    fprintf(stderr, "  --min-support <N>    Minimum occurrence count (default: %d)\n",
            ST_DEFAULT_MIN_SUPPORT);
    fprintf(stderr, "  --min-confidence <F> Minimum confidence 0.0-1.0 (default: %.2f)\n",
            ST_DEFAULT_MIN_CONFIDENCE);
    fprintf(stderr, "  --max-suggestions <N> Max suggestions to show (default: %d)\n",
            ST_DEFAULT_MAX_SUGGESTIONS);
    fprintf(stderr, "  --output <file>      Write suggestions to file instead of stdout\n");
    fprintf(stderr, "  --save <file>        Save learner state to file\n");
    fprintf(stderr, "  --load <file>        Load learner state from file\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Policy mode:\n");
    fprintf(stderr, "  --policy <file>      Load policy file (one pattern per line)\n");
    fprintf(stderr, "  --verify <cmd>       Verify a single command against the policy\n");
    fprintf(stderr, "  --verify-file <file> Verify commands from a file (one per line)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Other:\n");
    fprintf(stderr, "  --normalize <cmd>    Show normalised form of a command\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
}

int main(int argc, char *argv[])
{
    const char *input_file = NULL;
    const char *output_file = NULL;
    const char *save_file = NULL;
    const char *load_file = NULL;
    const char *normalize_cmd = NULL;
    const char *policy_file = NULL;
    const char *verify_cmd = NULL;
    const char *verify_file = NULL;
    bool do_suggest = false;
    uint32_t min_support = ST_DEFAULT_MIN_SUPPORT;
    double min_confidence = ST_DEFAULT_MIN_CONFIDENCE;
    size_t max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS;

    static struct option long_options[] = {
        { "input",          required_argument, 0, 'i' },
        { "suggest",        no_argument,       0, 's' },
        { "min-support",    required_argument, 0, 'm' },
        { "min-confidence", required_argument, 0, 'c' },
        { "max-suggestions",required_argument, 0, 'x' },
        { "output",         required_argument, 0, 'o' },
        { "save",           required_argument, 0, 'S' },
        { "load",           required_argument, 0, 'L' },
        { "normalize",      required_argument, 0, 'n' },
        { "policy",         required_argument, 0, 'P' },
        { "verify",         required_argument, 0, 'v' },
        { "verify-file",    required_argument, 0, 'V' },
        { "help",           no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hi:s", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': input_file = optarg; break;
            case 's': do_suggest = true; break;
            case 'm': min_support = (uint32_t)atoi(optarg); break;
            case 'c': min_confidence = atof(optarg); break;
            case 'x': max_suggestions = (size_t)atoi(optarg); break;
            case 'o': output_file = optarg; break;
            case 'S': save_file = optarg; break;
            case 'L': load_file = optarg; break;
            case 'n': normalize_cmd = optarg; break;
            case 'P': policy_file = optarg; break;
            case 'v': verify_cmd = optarg; break;
            case 'V': verify_file = optarg; break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Normalize-only mode */
    if (normalize_cmd) {
        char **tokens = NULL;
        size_t count = 0;
        st_error_t err = st_normalize(normalize_cmd, &tokens, &count);
        if (err != ST_OK) {
            fprintf(stderr, "Error: normalisation failed (%d)\n", err);
            return 1;
        }
        printf("Normalised: ");
        for (size_t i = 0; i < count; i++) {
            if (i > 0) printf(" ");
            printf("%s", tokens[i]);
        }
        printf("\n");
        st_free_tokens(tokens, count);
        return 0;
    }

    /* Policy verify mode */
    if (policy_file) {
        st_policy_t *policy = st_policy_new(st_policy_ctx_new());
        if (!policy) {
            fprintf(stderr, "Error: failed to create policy\n");
            return 1;
        }

        st_error_t err = st_policy_load(policy, policy_file);
        if (err != ST_OK) {
            fprintf(stderr, "Error: failed to load policy from '%s' (%d)\n",
                    policy_file, err);
            st_policy_free(policy);
            return 1;
        }

        fprintf(stderr, "Loaded policy with %zu patterns\n", st_policy_count(policy));

        /* Single command verify */
        if (verify_cmd) {
            st_eval_result_t r;
            err = st_policy_eval(policy, verify_cmd, &r);
            if (r.matches) {
                printf("ALLOW (matched: %s)\n", r.matching_pattern ? r.matching_pattern : "(unknown)");
            } else {
                printf("DENY\n");
            }
            st_policy_free(policy);
            return 0;
        }

        /* File verify */
        if (verify_file) {
            FILE *fp = fopen(verify_file, "r");
            if (!fp) {
                fprintf(stderr, "Error: cannot open '%s'\n", verify_file);
                st_policy_free(policy);
                return 1;
            }

            char line[4096];
            int line_count = 0;
            int allow_count = 0;
            int deny_count = 0;
            while (fgets(line, sizeof(line), fp)) {
                size_t len = strlen(line);
                while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
                if (len == 0) continue;
                if (line[0] == '#') continue;

                st_eval_result_t r;
                err = st_policy_eval(policy, line, &r);
                if (r.matches) {
                    printf("ALLOW: %-60s (matched: %s)\n", line, r.matching_pattern ? r.matching_pattern : "(unknown)");
                    allow_count++;
                } else {
                    printf("DENY:  %s\n", line);
                    deny_count++;
                }
                line_count++;
            }
            fclose(fp);

            fprintf(stderr, "\nSummary: %d commands, %d ALLOW, %d DENY\n",
                    line_count, allow_count, deny_count);
            st_policy_free(policy);
            return 0;
        }

        fprintf(stderr, "Error: --verify or --verify-file required with --policy\n");
        st_policy_free(policy);
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
            fprintf(stderr, "Error: failed to load state from '%s' (%d)\n",
                    load_file, err);
            st_learner_free(learner);
            return 1;
        }
    }

    /* Feed commands from input file */
    if (input_file) {
        FILE *fp = fopen(input_file, "r");
        if (!fp) {
            fprintf(stderr, "Error: cannot open '%s'\n", input_file);
            st_learner_free(learner);
            return 1;
        }

        char line[4096];
        int line_count = 0;
        int error_count = 0;
        while (fgets(line, sizeof(line), fp)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            if (len == 0) continue;
            if (line[0] == '#') continue;

            st_error_t err = st_feed(learner, line);
            if (err != ST_OK) {
                error_count++;
                if (error_count <= 3) {
                    fprintf(stderr, "Warning: failed to feed line %d: %s\n",
                            line_count + 1, line);
                }
            }
            line_count++;
        }
        fclose(fp);

        fprintf(stderr, "Fed %d commands (%d errors)\n", line_count, error_count);
        fprintf(stderr, "Total commands in trie: %u\n", learner->trie.total_commands);
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
            fprintf(out, "Top %zu suggestions (min_support=%u, min_confidence=%.2f):\n",
                    sug_count, min_support, min_confidence);
            for (size_t i = 0; i < sug_count; i++) {
                fprintf(out, "%3zu. %-50s (count=%u, confidence=%.2f)\n",
                        i + 1, suggestions[i].pattern,
                        suggestions[i].count, suggestions[i].confidence);
            }
        }

        if (out != stdout) fclose(out);
        st_free_suggestions(suggestions, sug_count);
    }

    /* Save state */
    if (save_file) {
        st_error_t err = st_save(learner, save_file);
        if (err != ST_OK) {
            fprintf(stderr, "Error: failed to save state to '%s' (%d)\n",
                    save_file, err);
            st_learner_free(learner);
            return 1;
        }
        fprintf(stderr, "State saved to '%s'\n", save_file);
    }

    st_learner_free(learner);
    return 0;
}
