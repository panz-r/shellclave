#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"
#include "shell_interop.h"
#include "shell_tokenizer.h"

struct shell_interop_handle {
  shell_parse_result_t result;
  char cmd_buffer[SHELL_INTEROP_BUFFER_SIZE];
};

shell_interop_handle_t *shell_interop_new(void) {
  shell_interop_handle_t *handle = calloc(1, sizeof(shell_interop_handle_t));
  return handle;
}

/* Release interop parser state allocated by shell_interop_new(). */
void shell_interop_free(shell_interop_handle_t *handle) {
  if (handle) {
    free(handle);
  }
}

/* Parse command text and run fast parsing into the interop handle result. */
shell_error_t shell_interop_parse(shell_interop_handle_t *handle,
                                  const char *cmd, size_t cmd_len,
                                  size_t *subcommand_count) {
  if (subcommand_count)
    *subcommand_count = 0;
  if (!handle)
    return SHELL_EINPUT;

  memset(&handle->result, 0, sizeof(handle->result));
  handle->cmd_buffer[0] = '\0';

  if (!cmd || !subcommand_count)
    return SHELL_EINPUT;

  if (cmd_len == 0)
    return SHELL_EINPUT;

  /* Reject commands that exceed buffer capacity */
  if (cmd_len >= sizeof(handle->cmd_buffer))
    return SHELL_ETRUNC;

  /* Shell commands cannot contain NUL bytes.  Reject them before copying so
   * the length-based parser and string-returning accessors share one view of
   * the input. */
  if (memchr(cmd, '\0', cmd_len) != NULL)
    return SHELL_EINPUT;

  /* Copy command to buffer (null-terminate) */
  memcpy(handle->cmd_buffer, cmd, cmd_len);
  handle->cmd_buffer[cmd_len] = '\0';

  /* Use default limits */
  shell_limits_t limits = SHELL_LIMITS_DEFAULT;

  /* Run parser over buffered command and populate handle->result. */
  shell_error_t err =
      shell_parse_fast(handle->cmd_buffer, cmd_len, &limits, &handle->result);

  if (err != SHELL_OK) {
    /* A failed parse must not expose the partially populated result produced
     * while the fast parser was examining the input. */
    memset(&handle->result, 0, sizeof(handle->result));
    handle->cmd_buffer[0] = '\0';
    return err;
  }

  *subcommand_count = handle->result.count;
  return SHELL_OK;
}

/* Get subcommand count */
size_t shell_interop_subcommand_count(const shell_interop_handle_t *handle) {
  return handle ? handle->result.count : 0;
}

bool shell_interop_subcommand_range(const shell_interop_handle_t *handle,
                                    size_t index, shell_range_t *range) {
  if (range)
    memset(range, 0, sizeof(*range));
  if (!handle || !range || index >= handle->result.count)
    return false;
  *range = handle->result.cmds[index];
  return true;
}

bool shell_interop_subcommand_view(const shell_interop_handle_t *handle,
                                   size_t index, const char **data,
                                   size_t *length) {
  if (data)
    *data = NULL;
  if (length)
    *length = 0;
  if (!handle || !data || !length || index >= handle->result.count)
    return false;
  *data = handle->cmd_buffer + handle->result.cmds[index].start;
  *length = handle->result.cmds[index].len;
  return true;
}

char *shell_interop_subcommand_dup(const shell_interop_handle_t *handle,
                                   size_t index) {
  const char *data = NULL;
  size_t length = 0;
  if (!shell_interop_subcommand_view(handle, index, &data, &length)) {
    return NULL;
  }

  char *buf = malloc(length + 1);
  if (buf == NULL) {
    return NULL;
  }

  memcpy(buf, data, length);
  buf[length] = '\0';
  return buf;
}

shell_error_t shell_interop_format_features(uint32_t features, char *output,
                                            size_t output_size,
                                            size_t *written) {
  static const struct {
    uint32_t flag;
    const char *name;
  } names[] = {{SHELL_FEAT_VARS, "VAR"},
               {SHELL_FEAT_GLOBS, "GLOB"},
               {SHELL_FEAT_SUBSHELL, "SUBSHELL"},
               {SHELL_FEAT_ARITH, "ARITH"},
               {SHELL_FEAT_HEREDOC, "HEREDOC"},
               {SHELL_FEAT_HERESTRING, "HERESTRING"},
               {SHELL_FEAT_PROCESS_SUB, "PROCSUB"},
               {SHELL_FEAT_LOOPS, "LOOPS"},
               {SHELL_FEAT_CONDITIONALS, "COND"},
               {SHELL_FEAT_CASE, "CASE"},
               {SHELL_FEAT_SUBSHELL_FILE, "SUBSHELL_FILE"},
               {SHELL_FEAT_PIPELINE, "PIPELINE"},
               {SHELL_FEAT_GROUP, "GROUP"},
               {SHELL_FEAT_BACKGROUND, "BACKGROUND"}};
  if (written)
    *written = 0;
  if (!output || output_size == 0 || !written)
    return SHELL_EINPUT;
  output[0] = '\0';
  size_t length = 0;
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    if (!(features & names[i].flag))
      continue;
    size_t name_length = strlen(names[i].name);
    size_t separator = length != 0;
    if (name_length > SIZE_MAX - length - separator ||
        length + separator + name_length >= output_size) {
      output[0] = '\0';
      return SHELL_ETRUNC;
    }
    if (separator)
      output[length++] = ' ';
    memcpy(output + length, names[i].name, name_length);
    length += name_length;
  }
  if (length == 0) {
    if (output_size < sizeof("none"))
      return SHELL_ETRUNC;
    memcpy(output, "none", sizeof("none"));
    *written = sizeof("none") - 1;
    return SHELL_OK;
  }
  output[length] = '\0';
  *written = length;
  return SHELL_OK;
}

const char *shell_interop_command_type_name(shell_cmd_type_t type) {
  if (type & SHELL_TYPE_PIPELINE) {
    return "PIPE";
  } else if (type & SHELL_TYPE_AND) {
    return "AND";
  } else if (type & SHELL_TYPE_OR) {
    return "OR";
  } else if (type & SHELL_TYPE_SEMICOLON) {
    return "SEMICOLON";
  } else if (type & SHELL_TYPE_HEREDOC) {
    return "HEREDOC";
  } else if (type & SHELL_TYPE_HERESTRING) {
    return "HERESTRING";
  } else if (type & SHELL_TYPE_SUBSTITUTION) {
    return "SUBSTITUTION";
  } else if (type & SHELL_TYPE_BACKGROUND) {
    return "BACKGROUND";
  }
  return "SIMPLE";
}
