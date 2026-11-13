/* Golden-graph serializer for engine redesign stages.
 *
 * Usage: shellsplit_golden_graphs CORPUS > OUTPUT
 *
 * CORPUS holds one source per line, hex-encoded. Each source is parsed with
 * the default limits and "/" as the initial CWD; the result is printed as
 * canonical text: the parse status, every node field that
 * depgraph_compare.h treats as semantic (plus stdin_code), and the edges
 * sorted, since the graph contract orders nodes but not edges. Pointer fields
 * print as source offsets when they borrow the source, otherwise as their
 * content. Two engines agree on a corpus exactly when their outputs are
 * byte-identical, so a stage is checked with diff(1).
 *
 * This is test machinery: it reads only public graph fields. */
#include "graph_fixture.h"
#include "shell_depgraph.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const char *source;
  size_t length;
  FILE *out;
} golden_t;

/* Print a borrowed span: its source offset when it lies within the source,
 * otherwise its bytes in hex. NULL prints as "-". */
static void span(const golden_t *g, const char *pointer, size_t length) {
  if (!pointer) {
    fputs("-", g->out);
    return;
  }
  if (pointer >= g->source && pointer + length <= g->source + g->length) {
    fprintf(g->out, "@%zu+%zu", (size_t)(pointer - g->source), length);
    return;
  }
  fputc('=', g->out);
  for (size_t i = 0; i < length; i++)
    fprintf(g->out, "%02x", (unsigned char)pointer[i]);
}

static void node(const golden_t *g, uint32_t index, const shell_dep_node_t *n) {
  FILE *out = g->out;
  fprintf(out, "N%u type=%d", index, (int)n->type);
  switch (n->type) {
  case SHELL_NODE_CMD: {
    const shell_dep_cmd_t *c = &n->cmd;
    fprintf(out, " kind=%d cond=", (int)c->kind);
    span(g, c->conditional_expression, c->conditional_expression_length);
    for (unsigned i = 0; i < 2; i++) {
      fputs(" operand=", out);
      span(g, c->conditional_operands[i], c->conditional_operand_lengths[i]);
    }
    fprintf(out,
            " operands=%u predicate=%d negated=%d truth=%d unresolved=%d "
            "arith_unresolved=%d arith=",
            c->conditional_operand_count, (int)c->conditional_predicate,
            (int)c->conditional_negated, (int)c->conditional_truth,
            (int)c->conditional_unresolved,
            (int)c->conditional_arithmetic_unresolved);
    span(g, c->arithmetic_expression, c->arithmetic_expression_length);
    fprintf(out, " arith_truth=%d redirections=%d tokens=[",
            (int)c->arithmetic_truth, (int)c->has_redirections);
    for (uint32_t i = 0; i < c->token_count; i++) {
      if (i)
        fputc(',', out);
      span(g, c->tokens[i], c->token_lens[i]);
    }
    fprintf(out, "] effective=");
    if (c->effective_command_known)
      fprintf(out, "%u", c->effective_command_token);
    else
      fputc('?', out);
    fprintf(out,
            " wrapper=%d cwd=%u depth=%u group_kinds=%u background=%d "
            "negations=%u negated=%d time=%d/%u cwd_known=%d cwd_absolute=%d "
            "pipe=%u,%u,%u,%u stdin_code=%d",
            (int)c->effective_command_wrapper, c->cwd_offset,
            (unsigned)c->group_depth, (unsigned)c->group_kinds,
            (int)c->backgrounded, c->pipeline_negation_count,
            (int)c->pipeline_negated, (int)c->pipeline_time_mode,
            c->pipeline_time_id, (int)c->cwd_known, (int)c->cwd_absolute,
            c->pipe_stdin_source, c->pipe_stdin_target, c->pipe_stdout_source,
            c->pipe_stdout_target, (int)c->stdin_code);
    break;
  }
  case SHELL_NODE_DOC: {
    const shell_dep_doc_t *d = &n->doc;
    fprintf(out, " kind=%d flags=%u", (int)d->kind, (unsigned)d->flags);
    if (d->kind == SHELL_DOC_FILE) {
      fputs(" path=", out);
      span(g, d->path, d->path_len);
      fprintf(out, " cwd=%u cwd_known=%d cwd_absolute=%d", d->cwd_offset,
              (int)d->cwd_known, (int)d->cwd_absolute);
    }
    if (d->kind == SHELL_DOC_HEREDOC || d->kind == SHELL_DOC_ENVVAR) {
      fputs(" name=", out);
      span(g, d->name, d->name_len);
    }
    if (d->kind != SHELL_DOC_FILE ||
        (d->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)) {
      fputs(" value=", out);
      span(g, d->value, d->value_len);
    }
    break;
  }
  case SHELL_NODE_GROUP:
    fputs(" span=", out);
    span(g, n->group.start, n->group.length);
    fprintf(out, " parent=%u kind=%d negations=%u negated=%d time=%d/%u",
            n->group.parent, (int)n->group.kind,
            n->group.pipeline_negation_count, (int)n->group.pipeline_negated,
            (int)n->group.pipeline_time_mode, n->group.pipeline_time_id);
    break;
  case SHELL_NODE_TIME:
    fputs(" span=", out);
    span(g, n->time.start, n->time.length);
    fprintf(out, " mode=%d report=%d/%d route=%d/%u external=[",
            (int)n->time.mode, (int)n->time.report_fd,
            (int)n->time.report_target_fd, (int)n->time.report_route,
            (unsigned)n->time.report_route_flags);
    for (uint32_t i = 0; i < n->time.report_external_fd_count; i++)
      fprintf(out, "%s%d", i ? "," : "", (int)n->time.report_external_fds[i]);
    fputc(']', out);
    break;
  case SHELL_NODE_ENDPOINT:
    break;
  case SHELL_NODE_FD:
    fprintf(out, " number=%d", (int)n->fd.number);
    break;
  case SHELL_NODE_FILE_COMPARISON:
    fprintf(out, " predicates=%u empty=%u",
            (unsigned)n->file_comparison.predicates,
            (unsigned)n->file_comparison.empty_operands);
    break;
  }
  fputc('\n', out);
}

static int compare_lines(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

static void edges(const golden_t *g, const shell_dep_graph_t *graph) {
  char *lines[SHELL_DEP_MAX_EDGES];
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *e = &graph->edges[i];
    char *line = NULL;
    size_t size = 0;
    golden_t text = *g;
    text.out = open_memstream(&line, &size);
    if (!text.out)
      abort();
    fprintf(text.out,
            "E %u>%u type=%d dir=%d flags=%u fds=%d/%d names=", e->from, e->to,
            (int)e->type, (int)e->dir, (unsigned)e->flags, (int)e->source_fd,
            (int)e->target_fd);
    span(&text, e->source_fd_name, e->source_fd_name_len);
    fputc('/', text.out);
    span(&text, e->target_fd_name, e->target_fd_name_len);
    fclose(text.out);
    lines[i] = line;
  }
  qsort(lines, graph->edge_count, sizeof(lines[0]), compare_lines);
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    fprintf(g->out, "%s\n", lines[i]);
    free(lines[i]);
  }
}

static int hex_value(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s CORPUS\n", argv[0]);
    return 2;
  }
  FILE *corpus = fopen(argv[1], "r");
  if (!corpus) {
    perror(argv[1]);
    return 2;
  }
  int exit_code = 2;
  char *line = NULL, *source = NULL;
  size_t capacity = 0, longest = 0;
  ssize_t read;
  while ((read = getline(&line, &capacity, corpus)) > 0)
    if ((size_t)read / 2 > longest)
      longest = (size_t)read / 2;
  rewind(corpus);
  shellsplit_graph_fixture_t fixture;
  if (!shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE,
                                     longest, 1, false, 0)) {
    fprintf(stderr, "fixture allocation failed\n");
    goto done;
  }
  source = malloc(longest + 1);
  if (!source)
    goto destroy;
  shell_dep_graph_t *graph = fixture.graph[0];
  for (uint32_t index = 0; (read = getline(&line, &capacity, corpus)) > 0;
       index++) {
    size_t digits = (size_t)read;
    while (digits && (line[digits - 1] == '\n' || line[digits - 1] == '\r'))
      digits--;
    size_t length = digits / 2;
    for (size_t i = 0; i < length; i++) {
      int high = hex_value(line[2 * i]), low = hex_value(line[2 * i + 1]);
      if (high < 0 || low < 0) {
        fprintf(stderr, "corpus line %u is not hex\n", index + 1);
        goto destroy;
      }
      source[i] = (char)(high << 4 | low);
    }
    golden_t g = {source, length, stdout};
    shell_dep_error_t status =
        shell_dep_graph_parse(source, length, "/", &fixture.limits, graph);
    printf("#%u status=%d graph=%u nodes=%u edges=%u cwd=", index, (int)status,
           (unsigned)graph->status, graph->node_count, graph->edge_count);
    span(&g, graph->cwd_buf.data, graph->cwd_buf.len);
    fputc('\n', stdout);
    for (uint32_t i = 0; i < graph->node_count; i++)
      node(&g, i, &graph->nodes[i]);
    edges(&g, graph);
  }
  exit_code = 0;
destroy:
  shellsplit_graph_fixture_destroy(&fixture);
done:
  free(source);
  free(line);
  fclose(corpus);
  return exit_code;
}
