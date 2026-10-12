#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "shell_abstract.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void print_usage(const char *prog) {
  fprintf(stderr, "Usage: %s [OPTIONS] [command]\n", prog);
  fprintf(stderr, "   or: %s [OPTIONS] -f <file>\n", prog);
  fprintf(stderr, "\nOptions:\n");
  fprintf(stderr, "  -f <file>   Read command from file (one per line)\n");
  fprintf(stderr, "  -e <env>    Add environment variable (VAR=value)\n");
  fprintf(stderr, "  -c <cwd>    Set current working directory\n");
  fprintf(stderr, "  -x          Expand variables using environment\n");
  fprintf(stderr, "  -h          Show this help\n");
}

void print_element(shell_abstract_element_t *elem) {
  printf("    Type: %s\n", shell_abstract_type_name(elem->type));
  printf("    Original: %s\n", elem->original);
  printf("    Abstracted: %s\n", elem->abstraction);
  printf("    Position: %zu-%zu\n", elem->start, elem->end);

  switch (elem->type) {
  case SHELL_ABSTRACT_EV:
  case SHELL_ABSTRACT_PV:
  case SHELL_ABSTRACT_SV:
    printf("    Var name: %s\n",
           elem->data.var.name ? elem->data.var.name : "(null)");
    printf("    Braced: %s\n", elem->data.var.is_braced ? "yes" : "no");
    if (elem->expanded) {
      printf("    Expanded: %s\n", elem->expanded);
    }
    break;

  case SHELL_ABSTRACT_AP:
  case SHELL_ABSTRACT_RP:
  case SHELL_ABSTRACT_HP:
    printf("    Path: %s\n",
           elem->data.path.path ? elem->data.path.path : "(null)");
    printf("    Absolute: %s\n", elem->data.path.is_absolute ? "yes" : "no");
    printf("    Ends with /: %s\n",
           elem->data.path.ends_with_slash ? "yes" : "no");
    if (elem->expanded) {
      printf("    Expanded: %s\n", elem->expanded);
    }
    break;

  case SHELL_ABSTRACT_GB:
    printf("    Glob pattern: %s\n",
           elem->data.glob.pattern ? elem->data.glob.pattern : "(null)");
    printf("    Has slash: %s\n", elem->data.glob.has_slash ? "yes" : "no");
    break;

  case SHELL_ABSTRACT_CS:
    printf("    Command: %s\n", elem->data.cmd_subst.content
                                    ? elem->data.cmd_subst.content
                                    : "(null)");
    break;

  default:
    break;
  }
}

void process_command(const char *cmd, const shell_runtime_context_t *ctx,
                     bool expand) {
  printf("========================================\n");
  printf("Command: %s\n", cmd);
  printf("========================================\n");

  shell_abstract_command_t *result = NULL;
  if (shell_abstract_command_parse(cmd, strlen(cmd), &result) !=
      SHELL_ABSTRACT_OK) {
    printf("ERROR: Failed to abstract command\n\n");
    return;
  }

  printf("\n--- Results ---\n");
  printf("Original:    %s\n", result->original);
  printf("Abstracted:  %s\n", result->display_text);
  printf("Elements:    %zu\n", result->element_count);

  printf("\n--- Flags ---\n");
  printf("Has variables:     %d\n", result->has_variables);
  printf("Has pos_vars:      %d\n", result->has_pos_vars);
  printf("Has special_vars:  %d\n", result->has_special_vars);
  printf("Has globs:         %d\n", result->has_globs);
  printf("Has paths:         %d\n", result->has_paths);
  printf("Has abs_paths:     %d\n", result->has_abs_paths);
  printf("Has rel_paths:     %d\n", result->has_rel_paths);
  printf("Has home_paths:    %d\n", result->has_home_paths);
  printf("Has cmd_subst:     %d\n", result->has_cmd_subst);
  printf("Has arithmetic:    %d\n", result->has_arithmetic);
  printf("Has strings:       %d\n", result->has_strings);

  printf("\n--- Elements ---\n");
  for (size_t i = 0; i < result->element_count; i++) {
    printf("\n[%zu] %s\n", i, result->elements[i]->abstraction);
    print_element(result->elements[i]);
  }

  // Expand if requested
  if (expand && ctx) {
    printf("\n--- Expansion ---\n");
    if (shell_abstract_command_expand(result, ctx)) {
      for (size_t i = 0; i < result->element_count; i++) {
        if (result->elements[i]->expanded) {
          printf("%s -> %s\n", result->elements[i]->abstraction,
                 result->elements[i]->expanded);
        }
      }
    }
  }

  printf("\n");
  shell_abstract_command_free(result);
}

int main(int argc, char **argv) {
  int status = EXIT_FAILURE;
  const char *filename = NULL;
  bool expand = false;
  const char *cwd = NULL;
  /* Runtime context only borrows CWD storage. Both argv and this buffer live
   * through every command processed below; neither needs heap ownership. */
  char cwd_buffer[4096];
  shell_runtime_context_t ctx = {0};
  char **env_add = NULL;
  const char **env = NULL;
  char *command = NULL;
  FILE *input = NULL;
  int env_count = 0;
  int env_capacity = 10;

  env_add = calloc(env_capacity, sizeof(char *));
  if (!env_add) {
    fprintf(stderr, "Memory error\n");
    goto cleanup;
  }

  // Parse arguments
  int opt;
  while ((opt = getopt(argc, argv, "f:e:c:xh")) != -1) {
    switch (opt) {
    case 'f':
      filename = optarg;
      break;
    case 'e':
      if (env_count < env_capacity) {
        env_add[env_count++] = optarg;
      }
      break;
    case 'c':
      cwd = optarg;
      break;
    case 'x':
      expand = true;
      break;
    case 'h':
    default:
      print_usage(argv[0]);
      status = opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
      goto cleanup;
    }
  }

  // Build runtime context
  if (cwd) {
    ctx.cwd = cwd;
  } else {
    ctx.cwd = getcwd(cwd_buffer, sizeof(cwd_buffer));
  }

  // Build environment (additions first so they take precedence)
  extern char **environ;
  int env_size = 0;
  for (char **e = environ; *e; e++)
    env_size++;

  env = calloc(env_size + env_count + 1, sizeof(*env));
  if (!env) {
    fprintf(stderr, "Memory error\n");
    goto cleanup;
  }

  // Add user-specified env vars first (so they override system vars)
  int idx = 0;
  for (int i = 0; i < env_count; i++) {
    env[idx++] = env_add[i];
  }
  // Then add system environment, skipping any we've already added
  for (char **e = environ; *e; e++) {
    // Skip if this variable was already added
    bool skip = false;
    for (int i = 0; i < env_count; i++) {
      const char *eq = strchr(env_add[i], '=');
      if (eq) {
        size_t var_len = eq - env_add[i];
        if (strncmp(*e, env_add[i], var_len) == 0 && (*e)[var_len] == '=') {
          skip = true;
          break;
        }
      }
    }
    if (!skip) {
      env[idx++] = *e;
    }
  }
  env[idx] = NULL;
  ctx.env = env;

  if (filename) {
    // Read from file
    input = fopen(filename, "r");
    if (!input) {
      fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
      goto cleanup;
    }

    char line[8192];
    while (fgets(line, sizeof(line), input)) {
      // Remove trailing newline
      size_t len = strlen(line);
      if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
      }
      // Skip empty lines and comments
      if (line[0] == '\0' || line[0] == '#') {
        continue;
      }
      process_command(line, &ctx, expand);
    }

    if (ferror(input)) {
      fprintf(stderr, "Error: Cannot read file '%s'\n", filename);
      goto cleanup;
    }
  } else if (optind < argc) {
    // Command from arguments - join all remaining args
    size_t total_len = 0;
    for (int i = optind; i < argc; i++) {
      total_len += strlen(argv[i]) + 1;
    }

    command = malloc(total_len);
    if (!command) {
      fprintf(stderr, "Memory error\n");
      goto cleanup;
    }

    char *position = command;
    for (int i = optind; i < argc; i++) {
      if (i > optind)
        *position++ = ' ';
      size_t length = strlen(argv[i]);
      memcpy(position, argv[i], length);
      position += length;
    }
    *position = '\0';

    process_command(command, &ctx, expand);
  } else {
    // Read from stdin
    char line[8192];
    printf("Enter shell commands (Ctrl-D to end):\n");
    while (fgets(line, sizeof(line), stdin)) {
      // Remove trailing newline
      size_t len = strlen(line);
      if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
      }
      if (line[0] == '\0')
        continue;
      process_command(line, &ctx, expand);
    }
    if (ferror(stdin)) {
      fprintf(stderr, "Error: Cannot read stdin\n");
      goto cleanup;
    }
  }

  status = EXIT_SUCCESS;
cleanup:
  if (input && fclose(input) != 0) {
    fprintf(stderr, "Error: Cannot close input file\n");
    status = EXIT_FAILURE;
  }
  free(command);
  free(env_add);
  free(env);

  return status;
}
