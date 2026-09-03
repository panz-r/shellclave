#define _POSIX_C_SOURCE 200809L
#include "shell_ast_generator.h"
#include "shell_ast.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct shell_ast_generator_internal {
  uint64_t rng_state;
} shell_ast_generator_internal_t;

static uint64_t splitmix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

static uint64_t random_next(shell_ast_generator_t *gen) {
  shell_ast_generator_internal_t *g = (shell_ast_generator_internal_t *)gen;
  g->rng_state = splitmix64(g->rng_state);
  return g->rng_state;
}

static uint64_t random_range(shell_ast_generator_t *gen, uint64_t max) {
  if (max == 0)
    return 0;
  return random_next(gen) % max;
}

static const char *COMMANDS[] = {
    "ls",     "cat",       "echo",     "grep",  "sed",     "awk",   "find",
    "sort",   "uniq",      "head",     "tail",  "wc",      "tr",    "cut",
    "paste",  "diff",      "comm",     "vim",   "nano",    "less",  "more",
    "tar",    "gzip",      "gunzip",   "zip",   "unzip",   "curl",  "wget",
    "ssh",    "scp",       "rsync",    "make",  "gcc",     "g++",   "clang",
    "python", "perl",      "ruby",     "node",  "npm",     "git",   "svn",
    "hg",     "chmod",     "chown",    "chgrp", "mkdir",   "rmdir", "rm",
    "mv",     "cp",        "touch",    "ln",    "df",      "du",    "free",
    "top",    "ps",        "pidof",    "kill",  "killall", "pgrep", "pkill",
    "whoami", "id",        "hostname", "uname", "date",    "cal",   "uptime",
    "dmesg",  "journalctl"};

#define NUM_COMMANDS (sizeof(COMMANDS) / sizeof(COMMANDS[0]))

static const char *VARIABLES[] = {
    "HOME",  "USER",    "PATH",   "PWD",    "SHELL", "TERM", "HOSTNAME", "LANG",
    "SHLVL", "DISPLAY", "EDITOR", "VISUAL", "PAGER", "MAIL", "TZ"};

#define NUM_VARIABLES (sizeof(VARIABLES) / sizeof(VARIABLES[0]))

static const char *GLOB_PATTERNS[] = {
    "*.txt",       "*.log", "*.conf",     "*.sh",           "*.c",
    "*.h",         "*.o",   "file?.dat",  "test[0-9]*.txt", "data*.csv",
    "*.{txt,log}", "dir/*", "dir/**/*.c", "file??.*",       "*.tmp"};

#define NUM_GLOB_PATTERNS (sizeof(GLOB_PATTERNS) / sizeof(GLOB_PATTERNS[0]))

static const char *CASE_PATTERNS[] = {"*.txt", "*.log", "*",
                                      "foo",   "bar",   "[0-9]*"};

#define NUM_CASE_PATTERNS (sizeof(CASE_PATTERNS) / sizeof(CASE_PATTERNS[0]))

static const char *LOOP_TYPES[] = {"while", "until", "for"};

static const char *ARITHMETIC_EXPRS[] = {
    "1 + 2",       "x - y",         "a * b",  "p / q",  "n % m",
    "i++",         "j--",           "a += 3", "b -= 1", "x = y",
    "(a + b) * c", "a > b ? a : b", "a & b",  "a | b",  "a ^ b"};

#define NUM_ARITHMETIC (sizeof(ARITHMETIC_EXPRS) / sizeof(ARITHMETIC_EXPRS[0]))

shell_ast_generator_t *shell_ast_generator_create(uint64_t seed) {
  shell_ast_generator_internal_t *g = (shell_ast_generator_internal_t *)calloc(
      1, sizeof(shell_ast_generator_internal_t));
  if (!g)
    return NULL;
  g->rng_state = seed;
  return (shell_ast_generator_t *)g;
}

void shell_ast_generator_destroy(shell_ast_generator_t *gen) {
  if (gen) {
    free(gen);
  }
}

static const char *gen_random_command(shell_ast_generator_t *gen) {
  return COMMANDS[random_range(gen, NUM_COMMANDS)];
}

/* NOTE: Returns pointer to static buffer, only valid until next call to any
 * gen_random_* function. Use immediately - shell_ast_add_redirect strdup's
 * the target so this is safe for the current usage pattern. */
static const char *gen_random_file(shell_ast_generator_t *gen) {
  static char buf[64];
  snprintf(buf, sizeof(buf), "/tmp/test%u.txt",
           (unsigned)random_range(gen, 10));
  return buf;
}

static const char *gen_random_variable(shell_ast_generator_t *gen) {
  return VARIABLES[random_range(gen, NUM_VARIABLES)];
}

static const char *gen_random_glob(shell_ast_generator_t *gen) {
  return GLOB_PATTERNS[random_range(gen, NUM_GLOB_PATTERNS)];
}

static const char *gen_random_case_pattern(shell_ast_generator_t *gen) {
  return CASE_PATTERNS[random_range(gen, NUM_CASE_PATTERNS)];
}

static const char *gen_random_arithmetic(shell_ast_generator_t *gen) {
  return ARITHMETIC_EXPRS[random_range(gen, NUM_ARITHMETIC)];
}

/* --- PHASE 1: GENERATOR FUNCTIONS FOR EACH AST TYPE --- */

static ast_node_t *gen_command(shell_ast_generator_t *gen, shell_ast_t *ast) {
  return shell_ast_add_command(ast, gen_random_command(gen));
}

static ast_node_t *gen_command_with_redirects(shell_ast_generator_t *gen,
                                              shell_ast_t *ast) {
  ast_node_t *cmd = gen_command(gen, ast);
  if (random_range(gen, 4) == 0) {
    int type = random_range(gen, 5);
    const char *target = gen_random_file(gen);

    // Ensure target is never empty - always use a valid filename
    if (!target || strlen(target) == 0) {
      target = "/tmp/test.txt";
    }

    switch (type) {
    case 0:
      cmd = shell_ast_add_redirect(ast, cmd, target, -1, false, false, false);
      break;
    case 1:
      cmd = shell_ast_add_redirect(ast, cmd, target, -1, true, false, false);
      break;
    case 2:
      cmd = shell_ast_add_redirect(ast, cmd, target, -1, false, true, false);
      break;
    case 3:
      cmd = shell_ast_add_redirect(ast, cmd, target, 2, false, false, true);
      break;
    case 4:
      cmd = shell_ast_add_redirect(ast, cmd, target, 2, false, true, true);
      break;
    }
  }
  return cmd;
}

// Generate variable: $VAR or ${VAR}
static ast_node_t *gen_variable(shell_ast_generator_t *gen, shell_ast_t *ast) {
  bool is_braced = (random_range(gen, 2) == 0);
  const char *var_name = gen_random_variable(gen);
  // Ensure variable name is never empty - always use a valid name
  if (!var_name || strlen(var_name) == 0) {
    var_name = "HOME";
  }
  return shell_ast_add_variable(ast, var_name, is_braced);
}

// Generate quoted string: 'single' or "double"
static ast_node_t *gen_quote(shell_ast_generator_t *gen, shell_ast_t *ast) {
  char quote_char = (random_range(gen, 2) == 0) ? '"' : '\'';
  bool is_closed = (random_range(gen, 10) != 0); // 90% closed
  const char *content = "hello world test content";
  return shell_ast_add_quote(ast, content, quote_char, is_closed);
}

// Generate glob pattern: *.txt, file?.log, etc.
static ast_node_t *gen_glob(shell_ast_generator_t *gen, shell_ast_t *ast) {
  const char *pattern = gen_random_glob(gen);
  return shell_ast_add_glob(ast, pattern);
}

// Generate case statement: case VAR in pattern) cmd;; esac
static ast_node_t *gen_case(shell_ast_generator_t *gen, shell_ast_t *ast) {
  const char *var = gen_random_variable(gen);
  const char *pattern = gen_random_case_pattern(gen);
  ast_node_t *body = gen_command_with_redirects(gen, ast);
  return shell_ast_add_case(ast, var, pattern, body);
}

// Generate if statement: if cmd then cmd [else cmd] fi
static ast_node_t *gen_if(shell_ast_generator_t *gen, shell_ast_t *ast) {
  ast_node_t *condition = gen_command_with_redirects(gen, ast);
  ast_node_t *then_branch = gen_command_with_redirects(gen, ast);
  return shell_ast_add_if(ast, condition, then_branch);
}

// Generate loop: while/until/for
static ast_node_t *gen_loop(shell_ast_generator_t *gen, shell_ast_t *ast) {
  const char *loop_type = LOOP_TYPES[random_range(gen, 3)];
  ast_node_t *body = gen_command_with_redirects(gen, ast);
  /* `for name in words` takes shell words, not a command list. Keep its
   * generated list free of redirects while while/until retain a command
   * condition. */
  ast_node_t *list = strcmp(loop_type, "for") == 0
                         ? gen_glob(gen, ast)
                         : gen_command_with_redirects(gen, ast);
  return shell_ast_add_loop(ast, loop_type, "i", list, body);
}

// Generate arithmetic: $(( expr ))
static ast_node_t *gen_arithmetic(shell_ast_generator_t *gen,
                                  shell_ast_t *ast) {
  bool is_unclosed = (random_range(gen, 5) == 0);
  const char *expr = gen_random_arithmetic(gen);
  return shell_ast_add_arithmetic(ast, expr, is_unclosed);
}

// Generate subshell: ( cmd )
static ast_node_t *gen_subshell(shell_ast_generator_t *gen, shell_ast_t *ast) {
  ast_node_t *inner = gen_command_with_redirects(gen, ast);
  return shell_ast_add_subshell(ast, inner);
}

static ast_node_t *gen_sequence(shell_ast_generator_t *gen, shell_ast_t *ast);

// POSIX brace group: { cmd; }.  Keep the required separator in the serializer
// rather than overloading the variable-expansion is_braced flag.
static ast_node_t *gen_brace_group_depth(shell_ast_generator_t *gen,
                                         shell_ast_t *ast, unsigned depth) {
  ast_node_t *inner = NULL;
  if (depth < 3 && random_range(gen, 4) == 0)
    inner = gen_brace_group_depth(gen, ast, depth + 1);
  else if (random_range(gen, 3) == 0)
    inner = gen_sequence(gen, ast);
  else if (random_range(gen, 2) == 0)
    inner = gen_subshell(gen, ast);
  else
    inner = gen_command_with_redirects(gen, ast);
  return shell_ast_add_brace_group(ast, inner);
}

static ast_node_t *gen_brace_group(shell_ast_generator_t *gen,
                                   shell_ast_t *ast) {
  return gen_brace_group_depth(gen, ast, 0);
}

// Generate process substitution: <(cmd) or >(cmd)
static ast_node_t *gen_process_sub(shell_ast_generator_t *gen,
                                   shell_ast_t *ast) {
  ast_node_t *cmd = gen_command(gen, ast);
  bool is_input = (random_range(gen, 2) == 0);
  return shell_ast_add_process_sub(ast, cmd, is_input);
}

// Generate pipeline: cmd1 | cmd2
static ast_node_t *gen_pipeline(shell_ast_generator_t *gen, shell_ast_t *ast) {
  ast_node_t *cmd1 = random_range(gen, 5) == 0
                         ? gen_brace_group(gen, ast)
                         : gen_command_with_redirects(gen, ast);
  ast_node_t *cmd2 = random_range(gen, 5) == 0
                         ? gen_brace_group(gen, ast)
                         : gen_command_with_redirects(gen, ast);
  return shell_ast_add_pipeline(ast, cmd1, cmd2);
}

// Generate sequence: cmd1 ; cmd2 or cmd1 && cmd2 or cmd1 || cmd2
static ast_node_t *gen_sequence(shell_ast_generator_t *gen, shell_ast_t *ast) {
  ast_node_t *cmd1 = gen_command_with_redirects(gen, ast);
  ast_node_t *cmd2 = gen_command_with_redirects(gen, ast);
  const char *sep = ";";
  int sep_type = random_range(gen, 3);
  if (sep_type == 0)
    sep = "&&";
  else if (sep_type == 1)
    sep = "||";
  return shell_ast_add_sequence(ast, cmd1, cmd2, sep);
}

/* --- PHASE 2: COMPLEX COMBINATIONS --- */

// cmd $VAR *.txt > file - variable + glob + redirect
static void gen_complex_var_glob_redirect(shell_ast_generator_t *gen,
                                          shell_ast_t *ast) {
  ast_node_t *cmd = gen_command(gen, ast);
  ast_node_t *var_node = gen_variable(gen, ast);
  ast_node_t *glob_node = gen_glob(gen, ast);

  cmd->child = var_node;
  var_node->next = glob_node;

  const char *target = gen_random_file(gen);
  cmd = shell_ast_add_redirect(ast, cmd, target, -1, false, false, false);
  ast->root = cmd;
  ast->has_valid_structure = true;
  ast->has_redirect = true;
}

// echo $(cmd) | grep $PATTERN - subshell in pipeline
static void gen_subshell_in_pipeline(shell_ast_generator_t *gen,
                                     shell_ast_t *ast) {
  ast_node_t *cmd1 = shell_ast_add_command(ast, "echo");
  ast_node_t *subshell = gen_subshell(gen, ast);
  cmd1->child = subshell;

  ast_node_t *cmd2 = shell_ast_add_command(ast, "grep");
  ast_node_t *var = gen_variable(gen, ast);
  cmd2->child = var;

  ast->root = shell_ast_add_pipeline(ast, cmd1, cmd2);
  ast->has_valid_structure = true;
  ast->has_subshell = true;
}

static void gen_brace_group_in_pipeline(shell_ast_generator_t *gen,
                                        shell_ast_t *ast) {
  ast_node_t *source = gen_command_with_redirects(gen, ast);
  ast_node_t *group = gen_brace_group(gen, ast);
  ast_node_t *pipeline = shell_ast_add_pipeline(ast, source, group);
  if (pipeline && random_range(gen, 2) == 0)
    pipeline = shell_ast_add_redirect(ast, pipeline, gen_random_file(gen), -1,
                                      false, false, false);
  ast->root = pipeline;
  ast->has_valid_structure = pipeline != NULL;
}

/* Exercise group aggregate control edges without making the recursive AST
 * generator unbounded.  Nested groups remain produced by gen_brace_group(). */
static void gen_brace_group_control(shell_ast_generator_t *gen,
                                    shell_ast_t *ast) {
  static const char *const separators[] = {"&&", "||", "&"};
  ast_node_t *left = gen_brace_group(gen, ast);
  ast_node_t *right = random_range(gen, 2) == 0
                          ? gen_brace_group(gen, ast)
                          : gen_command_with_redirects(gen, ast);
  ast->root = shell_ast_add_sequence(
      ast, left, right,
      separators[random_range(gen,
                              sizeof(separators) / sizeof(separators[0]))]);
  ast->has_valid_structure = ast->root != NULL;
}

// cmd && $VAR || other - compound with variables
static void gen_compound_with_vars(shell_ast_generator_t *gen,
                                   shell_ast_t *ast) {
  ast_node_t *cmd1 = gen_command(gen, ast);
  ast_node_t *var1 = gen_variable(gen, ast);

  ast_node_t *seq1 = shell_ast_add_sequence(ast, cmd1, var1, "&&");

  ast_node_t *cmd2 = gen_command(gen, ast);

  ast->root = shell_ast_add_sequence(ast, seq1, cmd2, "||");
  ast->has_valid_structure = true;
}

// for f in *.txt; do cat $f; done - glob in loop
static void gen_glob_in_loop(shell_ast_generator_t *gen, shell_ast_t *ast) {
  ast_node_t *glob = gen_glob(gen, ast);
  ast_node_t *body = gen_command(gen, ast);
  ast_node_t *var = gen_variable(gen, ast);
  body->child = var;

  ast_node_t *list = glob;
  ast_node_t *loop = shell_ast_add_loop(ast, "for", "f", list, body);

  ast->root = loop;
  ast->has_valid_structure = true;
  ast->has_loops = true;
  ast->has_glob = true;
}

/* --- PHASE 3: INVALID CASES - MORE COMPREHENSIVE --- */

// Unclosed heredoc without closing delimiter
static void gen_unclosed_heredoc(shell_ast_generator_t *gen, shell_ast_t *ast) {
  (void)gen;
  ast_node_t *node =
      shell_ast_add_heredoc(ast, "EOF", NULL); // No content = unclosed
  if (node) {
    node->is_valid = false;
    ast->root = node;
    ast->has_heredoc = true;
    ast->has_valid_structure = false;
  }
}

// Mismatched quotes: "hello' - open double, close single
static void gen_mismatched_quotes(shell_ast_generator_t *gen,
                                  shell_ast_t *ast) {
  (void)gen;
  ast_node_t *node = shell_ast_add_quote(ast, "hello", '"', false);
  if (node) {
    // Mark as having quote mismatch by setting is_braced incorrectly
    node->is_braced = false; // Single quote marker but content from double
    ast->root = node;
    ast->has_unclosed_quote = true;
    ast->has_valid_structure = false;
  }
}

// Unclosed backtick: using command with invalid flag to represent unclosed
// backtick We create "``" (empty backticks) which is truly invalid in bash
static void gen_unclosed_backtick(shell_ast_generator_t *gen,
                                  shell_ast_t *ast) {
  (void)gen;
  ast_node_t *node = shell_ast_add_backtick(ast, "echo nested", false);
  if (node) {
    ast->root = node;
    ast->has_valid_structure = false;
  }
}

// Empty command with operators: | cmd (leading separator)
static void gen_leading_separator(shell_ast_generator_t *gen,
                                  shell_ast_t *ast) {
  (void)gen;
  ast_node_t *node = shell_ast_add_command(ast, "|");
  if (node) {
    node->is_valid = false;
    ast->root = node;
    ast->has_valid_structure = false;
  }
}

// Invalid arithmetic: $(( without closing
static void gen_invalid_arithmetic(shell_ast_generator_t *gen,
                                   shell_ast_t *ast) {
  (void)gen; // unused parameter
  ast_node_t *node = shell_ast_add_arithmetic(ast, "", true); // Empty unclosed
  if (node) {
    ast->root = node;
    ast->has_arithmetic = true;
    ast->has_unclosed_paren = true;
    ast->has_valid_structure = false;
  }
}

// Unclosed subshell: ( cmd without )
static void gen_unclosed_subshell(shell_ast_generator_t *gen,
                                  shell_ast_t *ast) {
  ast_node_t *node = shell_ast_add_subshell(ast, gen_command(gen, ast));
  if (node) {
    node->is_valid = false;
    ast->root = node;
    ast->has_subshell = true;
    ast->has_unclosed_paren = true;
    ast->has_valid_structure = false;
  }
}

static void gen_unclosed_brace_group(shell_ast_generator_t *gen,
                                     shell_ast_t *ast) {
  ast_node_t *node = shell_ast_add_brace_group(ast, gen_command(gen, ast));
  if (node) {
    node->is_valid = false;
    node->brace_form = AST_BRACE_UNCLOSED;
    ast->root = node;
    ast->has_unclosed_brace = true;
    ast->has_valid_structure = false;
  }
}

static void gen_brace_missing_separator(shell_ast_generator_t *gen,
                                        shell_ast_t *ast) {
  ast_node_t *node = shell_ast_add_brace_group(ast, gen_command(gen, ast));
  if (node) {
    node->is_valid = false;
    node->brace_form = AST_BRACE_MISSING_SEPARATOR;
    ast->root = node;
    ast->has_valid_structure = false;
  }
}

static void gen_brace_crossed_subshell(shell_ast_generator_t *gen,
                                       shell_ast_t *ast) {
  ast_node_t *node = shell_ast_add_brace_group(ast, gen_command(gen, ast));
  if (node) {
    node->is_valid = false;
    node->brace_form = AST_BRACE_CROSSED_SUBSHELL;
    ast->root = node;
    ast->has_unclosed_paren = true;
    ast->has_valid_structure = false;
  }
}

// Invalid redirect target: cmd > (no file)
static void gen_missing_redirect_target(shell_ast_generator_t *gen,
                                        shell_ast_t *ast) {
  ast_node_t *cmd = gen_command(gen, ast);
  ast_node_t *node =
      shell_ast_add_redirect(ast, cmd, "", -1, false, false, false);
  if (node) {
    node->is_valid = false;
    ast->root = node;
    ast->has_redirect = true;
    ast->has_valid_structure = false;
  }
}

// Multiple unclosed: unclosed quote + paren
static void gen_multiple_unclosed(shell_ast_generator_t *gen,
                                  shell_ast_t *ast) {
  (void)gen;
  // Create unclosed quote
  ast_node_t *quote = shell_ast_add_quote(ast, "text", '"', false);
  // Create unclosed paren
  ast_node_t *paren = shell_ast_add_subshell(ast, NULL);
  if (paren)
    paren->is_valid = false;

  // Chain them - both invalid
  if (quote) {
    quote->next = paren;
    ast->root = quote;
  } else {
    ast->root = paren;
  }

  ast->has_unclosed_quote = true;
  ast->has_unclosed_paren = true;
  ast->has_valid_structure = false;
}

// Invalid case without esac
static void gen_incomplete_case(shell_ast_generator_t *gen, shell_ast_t *ast) {
  (void)gen;
  ast_node_t *node =
      shell_ast_add_case(ast, "$VAR", "pattern", gen_command(gen, ast));
  if (node) {
    node->is_valid = false;
    ast->root = node;
    ast->has_case = true;
    ast->has_valid_structure = false;
  }
}

// Invalid if without fi
static void gen_incomplete_if(shell_ast_generator_t *gen, shell_ast_t *ast) {
  (void)gen;
  ast_node_t *node =
      shell_ast_add_if(ast, gen_command(gen, ast), gen_command(gen, ast));
  if (node) {
    node->is_valid = false;
    ast->root = node;
    ast->has_conditionals = true;
    ast->has_valid_structure = false;
  }
}

// Invalid loop without done
static void gen_incomplete_loop(shell_ast_generator_t *gen, shell_ast_t *ast) {
  (void)gen;
  ast_node_t *node = shell_ast_add_loop(
      ast, "while", "i", gen_command(gen, ast), gen_command(gen, ast));
  if (node) {
    node->is_valid = false;
    ast->root = node;
    ast->has_loops = true;
    ast->has_valid_structure = false;
  }
}

/* --- MAIN GENERATOR FUNCTIONS --- */

static void gen_valid_shell(shell_ast_generator_t *gen, shell_ast_t *ast) {
  int type = random_range(gen, 100);

  if (type < 20) {
    // Simple command with optional redirect
    ast->root = gen_command_with_redirects(gen, ast);
  } else if (type < 30) {
    ast_node_t *cmd = gen_command(gen, ast);
    ast_node_t *var = gen_variable(gen, ast);
    var->next = cmd->child;
    cmd->child = var;
    ast->root = cmd;
  } else if (type < 40) {
    ast_node_t *cmd = gen_command(gen, ast);
    ast_node_t *glob = gen_glob(gen, ast);
    glob->next = cmd->child;
    cmd->child = glob;
    ast->root = cmd;
  } else if (type < 50) {
    // Pipeline
    ast->root = gen_pipeline(gen, ast);
  } else if (type < 60) {
    // Sequence (; or && or ||)
    ast->root = gen_sequence(gen, ast);
  } else if (type < 66) {
    // Subshell
    ast->root = gen_subshell(gen, ast);
    ast->has_subshell = true;
  } else if (type < 73) {
    // POSIX brace group
    ast->root = gen_brace_group(gen, ast);
  } else if (type < 80) {
    // Arithmetic
    ast->root = gen_arithmetic(gen, ast);
    if (ast->root && !ast->root->is_valid) {
      ast->has_unclosed_paren = true;
      ast->has_valid_structure = false;
      return;
    }
    ast->has_arithmetic = true;
  } else if (type < 84) {
    // Process substitution
    ast->root = gen_process_sub(gen, ast);
    ast->has_process_sub = true;
  } else if (type < 87) {
    ast_node_t *cmd = gen_command(gen, ast);
    ast_node_t *quote = gen_quote(gen, ast);
    quote->is_valid = true;
    quote->next = cmd->child;
    cmd->child = quote;
    ast->root = cmd;
    // Clear flags that might have been set by unclosed quote
    ast->has_unclosed_quote = false;
    ast->has_valid_structure = true;
  } else if (type < 90) {
    // Loop (for/while/until)
    ast->root = gen_loop(gen, ast);
    ast->has_loops = true;
  } else if (type < 92) {
    // If statement
    ast->root = gen_if(gen, ast);
    ast->has_conditionals = true;
  } else if (type < 94) {
    // Case statement
    ast->root = gen_case(gen, ast);
    ast->has_case = true;
  } else if (type < 96) {
    // Complex: variable + glob + redirect
    gen_complex_var_glob_redirect(gen, ast);
  } else if (type < 98) {
    // Complex: subshell in pipeline
    gen_subshell_in_pipeline(gen, ast);
  } else if (type < 99) {
    // Complex: brace groups at pipeline and aggregate-control boundaries.
    if (random_range(gen, 3) == 0)
      gen_brace_group_in_pipeline(gen, ast);
    else if (random_range(gen, 2) == 0)
      gen_brace_group_control(gen, ast);
    else
      gen_compound_with_vars(gen, ast);
  } else {
    // Complex: glob in loop
    gen_glob_in_loop(gen, ast);
  }

  if (ast->root) {
    ast->has_valid_structure = true;
  }
}

static void gen_invalid_shell(shell_ast_generator_t *gen, shell_ast_t *ast) {
  typedef void (*invalid_generator_t)(shell_ast_generator_t *, shell_ast_t *);
  static const invalid_generator_t generators[] = {
      gen_unclosed_heredoc,        gen_mismatched_quotes,
      gen_unclosed_backtick,       gen_leading_separator,
      gen_invalid_arithmetic,      gen_unclosed_subshell,
      gen_missing_redirect_target, gen_multiple_unclosed,
      gen_incomplete_case,         gen_incomplete_if,
      gen_incomplete_loop,         gen_unclosed_brace_group,
      gen_brace_missing_separator, gen_brace_crossed_subshell,
  };
  size_t choice =
      (size_t)random_range(gen, 9 + sizeof(generators) / sizeof(generators[0]));
  if (choice < 9) {
    switch (choice) {
    case 0:
      shell_ast_add_binary(ast);
      break;
    case 1:
      shell_ast_add_control_char(ast);
      break;
    case 2:
      shell_ast_add_high_bytes(ast);
      break;
    case 3:
      shell_ast_add_unclosed_quote(ast, '"');
      break;
    case 4:
      shell_ast_add_unclosed_paren(ast);
      break;
    case 5:
      shell_ast_add_unclosed_brace(ast);
      break;
    case 6:
      shell_ast_add_bare_redirect(ast);
      break;
    case 7:
      shell_ast_add_separators_only(ast);
      break;
    default:
      shell_ast_add_incomplete_glob(ast);
      break;
    }
  } else {
    generators[choice - 9](gen, ast);
  }
}

shell_ast_t *shell_ast_generator_generate(shell_ast_generator_t *gen) {
  if (!gen)
    return NULL;
  shell_ast_t *ast = shell_ast_create();
  if (!ast)
    return NULL;

  // Increase invalid generation rate to test more edge cases
  bool generate_invalid = (random_range(gen, 100) < 30);

  if (generate_invalid) {
    gen_invalid_shell(gen, ast);
  } else {
    gen_valid_shell(gen, ast);
  }

  return ast;
}
