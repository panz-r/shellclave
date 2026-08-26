#ifndef SHELL_DEPGRAPH_INTERNAL_H
#define SHELL_DEPGRAPH_INTERNAL_H

#include "shell_depgraph.h"
#include "shell_tokenizer.h"

shell_dep_error_t shell_dep_graph_parse_with_fast(
    const char *cmd, size_t cmd_len, const char *initial_cwd,
    const shell_dep_limits_t *limits, const shell_parse_result_t *fast,
    shell_dep_graph_t *out);

#endif
