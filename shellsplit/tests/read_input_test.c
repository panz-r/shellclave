#include "../src/shell_builtin_internal.h"
#include "../src/shell_depgraph_internal.h"
#include "../src/shell_semantics_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "depgraph_compare.h"
#include "depgraph_invariants.h"
#include "graph_fixture.h"
#include "shell_depgraph.h"
#include "shell_processor.h"
#include "word_expansion_cases.h"
#ifdef SHELLSPLIT_TEST_ALLOCATOR
#include "test_allocator.h"
#endif
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\nsource: %s\n", __FILE__, __LINE__,           \
              #condition, current_source);                                     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static const char *current_source;
#ifdef SHELLSPLIT_TEST_ALLOCATOR
/* The operand probe audits graph calls while processor checks in the same
 * cases legitimately allocate their own result storage. */
static bool audit_graph_allocations;
#endif
static shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
static shell_dep_graph_t *graph, *other;

static void parse(const char *source) {
  current_source = source;
  shell_dep_error_t status =
      shell_dep_graph_parse(source, strlen(source), "/", &limits, graph);
  if (status != SHELL_DEP_OK)
    fprintf(stderr,
            "parse status: %d, graph status: %u, nodes: %u, edges: %u\n",
            status, graph->status, graph->node_count, graph->edge_count);
  CHECK(status == SHELL_DEP_OK);
  /* The invariant helper validates successful graphs before inspecting them. */
  CHECK(shellsplit_test_depgraph_invariants(source, strlen(source), status,
                                            graph, &limits));
  shell_parse_result_t fast;
  CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
  CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", &limits,
                                        &fast, other) == SHELL_DEP_OK);
  CHECK(shellsplit_test_graph_equal(graph, other));
}

/* The input violates the descriptor contract (descriptors above 2 start
 * closed): a certain descriptor error disqualifies it. */
static void reject(const char *source) {
  current_source = source;
  shell_dep_error_t status =
      shell_dep_graph_parse(source, strlen(source), "/", &limits, graph);
  CHECK(status == SHELL_DEP_EUNMODELED);
  CHECK(shellsplit_test_depgraph_invariants(source, strlen(source), status,
                                            graph, &limits));
}

static uint32_t command(const char *word) {
  size_t length = strlen(word);
  for (uint32_t i = 0; i < graph->node_count; i++) {
    const shell_dep_node_t *node = &graph->nodes[i];
    if (node->type != SHELL_NODE_CMD)
      continue;
    for (uint32_t t = 0; t < node->cmd.token_count; t++)
      if (node->cmd.token_lens[t] == length &&
          !memcmp(node->cmd.tokens[t], word, length))
        return i;
  }
  CHECK(false);
  return UINT32_MAX;
}

static bool input_edge(const shell_dep_edge_t *edge, uint32_t owner) {
  return edge->to == owner &&
         (edge->type == SHELL_EDGE_READ || edge->type == SHELL_EDGE_PIPE ||
          edge->type == SHELL_EDGE_SUBST);
}

static unsigned inputs(uint32_t owner, uint32_t fd, const char *name) {
  unsigned count = 0;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (!input_edge(edge, owner))
      continue;
    CHECK(edge->target_fd == fd);
    if (name) {
      CHECK(edge->target_fd_name_len == strlen(name));
      CHECK(!memcmp(edge->target_fd_name, name, strlen(name)));
    }
    CHECK(!(edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD));
    count++;
  }
  return count;
}

static bool document_input(uint32_t owner, const char *text) {
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    const shell_dep_node_t *node = &graph->nodes[edge->from];
    if (!input_edge(edge, owner) || node->type != SHELL_NODE_DOC)
      continue;
    const char *value =
        node->doc.kind == SHELL_DOC_FILE ? node->doc.path : node->doc.value;
    size_t length = node->doc.kind == SHELL_DOC_FILE ? node->doc.path_len
                                                     : node->doc.value_len;
    if (length == strlen(text) && !memcmp(value, text, length))
      return true;
  }
  return false;
}

/* Check all input alternatives, not merely the existence of some READ from
 * this document. A correct resource on the wrong command-local FD is wrong.
 * Some reads genuinely require a may-fail open; those pass REQUIRED here
 * instead of weakening the default NONE expectation. */
static void expect_document_input_flags(uint32_t owner, const char *text,
                                        uint32_t fd, const char *name,
                                        bool expected, uint32_t flags) {
  (void)inputs(owner, fd, name);
  unsigned matches = 0;
  for (uint32_t e = 0; e < graph->edge_count; e++) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    const shell_dep_node_t *node = &graph->nodes[edge->from];
    if (!input_edge(edge, owner) || node->type != SHELL_NODE_DOC)
      continue;
    const char *value =
        node->doc.kind == SHELL_DOC_FILE ? node->doc.path : node->doc.value;
    size_t length = node->doc.kind == SHELL_DOC_FILE ? node->doc.path_len
                                                     : node->doc.value_len;
    if (length != strlen(text) || memcmp(value, text, length))
      continue;
    CHECK(edge->type == SHELL_EDGE_READ);
    CHECK(edge->source_fd == SHELL_DEP_FD_NONE);
    CHECK(edge->flags == flags);
    CHECK(name ||
          (edge->target_fd_name == NULL && edge->target_fd_name_len == 0));
    matches++;
  }
  if (matches != (unsigned)expected)
    fprintf(stderr,
            "document '%s' -> node %u fd %u name '%s': expected %u, got %u\n",
            text, owner, fd, name ? name : "", (unsigned)expected, matches);
  CHECK(matches == (unsigned)expected);
}
static void expect_document_input(uint32_t owner, const char *text, uint32_t fd,
                                  const char *name, bool expected) {
  expect_document_input_flags(owner, text, fd, name, expected,
                              SHELL_DEP_EDGE_FLAG_NONE);
}

static bool document_write(uint32_t owner, const char *path) {
  for (uint32_t e = 0; e < graph->edge_count; e++) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    const shell_dep_node_t *node = &graph->nodes[edge->to];
    if (edge->from == owner && edge->type == SHELL_EDGE_WRITE &&
        node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_FILE &&
        node->doc.path_len == strlen(path) &&
        !memcmp(node->doc.path, path, strlen(path)))
      return true;
  }
  return false;
}

/* Whether the graph requires the open of FILE document path. */
static bool document_required(const char *path) {
  for (uint32_t e = 0; e < graph->edge_count; e++) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    const shell_dep_node_t *node = &graph->nodes[edge->from];
    if ((edge->flags & SHELL_DEP_EDGE_FLAG_REQUIRED) &&
        node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_FILE &&
        node->doc.path_len == strlen(path) &&
        !memcmp(node->doc.path, path, strlen(path)))
      return true;
  }
  return false;
}

static void static_selection(void) {
  static const char *const words[] = {"read -u3 value",
                                      "read -u 3 value",
                                      "read -ru3 value",
                                      "read '-u' '3' value",
                                      "read -u\\3 value",
                                      "read -u+3 value",
                                      "read -u ' 3 ' value",
                                      "read -u03 value",
                                      "read -u0 -u3 value",
                                      "builtin read -u3 value",
                                      "command read -u3 value",
                                      "command builtin read -u3 value",
                                      "read -p -u -u3 value",
                                      "read -d '' -u3 value",
                                      "read -n2 -N1 -t1 -u3 -- value"};
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source), "%s 3<input <unused", words[i]);
    parse(source);
    uint32_t owner = command("read");
    CHECK(inputs(owner, 3, NULL) == 1);
    CHECK(document_input(owner, "input"));
    bool setup = false;
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      if (edge->type == SHELL_EDGE_FD_OPEN && edge->to == owner &&
          edge->target_fd == 0)
        setup = true;
    }
    CHECK(setup);
  }
  parse("read value");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  reject("read -u2147483647 value");
  parse("read -u3 -u4 value 3<<<first 4<<<last");
  CHECK(inputs(command("read"), 4, NULL) == 1);
  CHECK(document_input(command("read"), "last"));
  reject("read -u3 POSIXLY_CORRECT 3<<<payload");
  reject("read first bad-name 3<<<payload -u3");
}

static void no_byte_input(void) {
  static const char *const silent[] = {"read -t0 value",
                                       "read -t 0 value",
                                       "read -n0 value",
                                       "read -N 0 value",
                                       "read -n0 -u3 value 3<<<payload",
                                       "read -t0 -u3 value 3<<<payload",
                                       "read -n0 value <input",
                                       "read -t0 bad-name <input"};
  for (size_t i = 0; i < sizeof(silent) / sizeof(silent[0]); i++) {
    parse(silent[i]);
    CHECK(inputs(command("read"), 0, NULL) == 0);
  }
  /* Reference Bash reports each of these as a read error before reading
   * any byte. Unhandled, the error rejects the input; handled by `||`, the
   * failure is an ordinary outcome, still without input. */
  static const char *const errors[] = {"read -z value",
                                       "read -u",
                                       "read -u-1 value",
                                       "read -u2147483648 value",
                                       "read -u18446744073709551617 value",
                                       "read -n18446744073709551617 value",
                                       "read -N18446744073709551617 value",
                                       "read -u0x3 value",
                                       "read -u3- value",
                                       "read -u '' value",
                                       "read bad-name <input",
                                       "read -u3 value 3>out"};
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
    char source[128];
    reject(errors[i]);
    snprintf(source, sizeof(source), "%s || true", errors[i]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
  }
  parse("read -n0 -n1 value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  parse("read -t0 -t1 value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  /* A read whose descriptor is missing on every path has no modelable
   * source: reference Bash fails each with "invalid file descriptor"
   * (rc=1), including repeated -u where an earlier closed operand aborts
   * the read even when a later one names an open heredoc. */
  reject("read -u3 value 3<&-");
  reject("read -u3 -u4 value 3<&- 4<<<payload");
  reject("read -u4 -u3 value 4<&- 3<<<payload");
}

static void named_selection(void) {
  static const char *const selectors[] = {"-u \"$fd\"", "-u\"${fd}\"", "-u $fd",
                                          "-u${fd}"};
  for (size_t i = 0; i < sizeof(selectors) / sizeof(selectors[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source),
             "exec {fd}<<<old; read %s value {fd}<<<new", selectors[i]);
    parse(source);
    CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
    CHECK(document_input(command("read"), "old"));
    CHECK(!document_input(command("read"), "new"));
  }
  reject("exec {fd}<input; read -u \"$fd\" value {fd}<&-");
  parse("exec {fd}<<<payload; IFS=012 read -u $fd value");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  parse("IFS=012; exec {fd}<<<payload; read -u \"$fd\" value");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  parse("exec 10<&-; exec {fd}<<<old; exec {fd}<&-; "
        "read -u\"$fd\" value 10<<<new");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  CHECK(document_input(command("read"), "new"));
  /* The argument is expanded before the redirect rebinds fd, so the read
   * sees old. That open is required: if it fails, fd is unset and the read
   * reports an error. */
  parse("exec {fd}<<<old; "
        "echo \"$(read -u\"$fd\" value {fd}<<<new)\"");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  expect_document_input_flags(command("read"), "old", SHELL_DEP_FD_NAMED, "fd",
                              true, SHELL_DEP_EDGE_FLAG_REQUIRED);
  CHECK(!document_input(command("read"), "new"));
  /* Closing the name after capture closes the argument's descriptor: a
   * certain read error. */
  reject("exec {fd}<<<old; echo \"$(read -u\"$fd\" value {fd}<&-)\"");
  /* A failed allocation leaves no value. Attached emptiness leaves -u
   * pending, while a bare unquoted empty operand disappears altogether.
   * Either way -u takes 3 as its operand. Where the open succeeds, 3 is an
   * invalid variable name instead: a read error, rejected unless handled. */
  static const char *const empty_arguments[] = {"-u\"$fd\"", "-u $fd"};
  for (size_t i = 0; i < sizeof(empty_arguments) / sizeof(empty_arguments[0]);
       i++) {
    char source[256];
    snprintf(source, sizeof(source),
             "unset fd; exec {fd}<input; read %s 3 value 3<<<payload",
             empty_arguments[i]);
    reject(source);
    snprintf(source, sizeof(source),
             "unset fd; exec {fd}<input; read %s 3 value 3<<<payload || true",
             empty_arguments[i]);
    /* Precision gap: the analysis attributes the failed open's path to its
     * cause, so the open becomes a requirement and that path, the only one
     * reading fd 3, is not represented. Conservative, but the handled read
     * on that path raises no error and could be modeled. */
    parse(source);
    CHECK(inputs(command("read"), 3, NULL) == 0);
  }
  static const char *const unsupported[] = {
      "read -u \"$fd\" value",
      "read -u \"$(printf 3)\" value",
      "read -u \"${fd:-3}\" value",
      "read -u 1\"$fd\" value",
      "exec {fd}<<<payload && read -u1\"$fd\" value",
      "exec {fd}<<<payload && read -u 1\"$fd\" value",
      "exec {fd}<<<payload && read -u\"$fd\"1 value",
      "exec {fd}<<<payload && read -u\"$fd\"\"$fd\" value",
      "IFS=012; exec {fd}<<<payload; read -u $fd value"};
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    current_source = unsupported[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
}

static void recursive_and_pipe_inputs(void) {
  parse("printf payload | read value");
  uint32_t owner = command("read");
  CHECK(inputs(owner, 0, NULL) == 1);
  bool pipe = false;
  for (uint32_t e = 0; e < graph->edge_count; e++)
    pipe |=
        graph->edges[e].type == SHELL_EDGE_PIPE && graph->edges[e].to == owner;
  CHECK(pipe);
  parse("printf payload | { read value; }");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  parse("read value & wait");
  /* Bash's best-effort /dev/null open can fail and leave inherited stdin. */
  CHECK(inputs(command("read"), 0, NULL) == 2);
  CHECK(document_input(command("read"), "/dev/null"));
  parse("exec {fd}<<<payload; read -u\"$fd\" value & wait");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  static const char *const sources[] = {
      "printf ignored | read -u3 value 3<<<payload",
      "{ read -u3 value; } 3<<<payload", "(read -u3 value) 3<<<payload",
      "read -u3 value 3< <(printf payload)"};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    parse(sources[i]);
    CHECK(inputs(command("read"), 3, NULL) > 0);
  }
  /* Redirect-save parking: Bash parks the overwritten fd 3 heredoc at the
   * lowest free fd >= 10 while `read` runs, so -u10 reads "payload"
   * (verified: `exec 3<<<payload; read -u10 value 3>out` yields
   * value=[payload]; the save goes to 11/12 when 10/11 are occupied). The
   * analysis does not yet place Bash's saves exactly (as F_DUPFD(fd, 10)), so
   * it cannot prove fd 10 present and conservatively reports no model. */
  reject("exec 3<<<payload; read -u10 value 3>out");
  /* The outer redirect applies after the substitution expands, so the
   * capture's read never sees fd 3: reference Bash reports "invalid file
   * descriptor" (rc=1 for the read, empty echo). */
  reject("echo \"$(read -u3 value)\" 3<<<payload");
  parse("exec {fd}< <(printf payload); echo \"$(read -u \"$fd\" value)\"");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  parse("exec {fd}< <(printf payload); cat <(read -u \"$fd\" value)");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  parse("read -u3 value 3<<<payload 2> >(cat)");
  CHECK(inputs(command("read"), 3, NULL) == 1);
  bool stderr_pipe = false;
  for (uint32_t e = 0; e < graph->edge_count; e++) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    stderr_pipe |= edge->from == command("read") &&
                   edge->type == SHELL_EDGE_WRITE && edge->source_fd == 2 &&
                   graph->nodes[edge->to].type == SHELL_NODE_ENDPOINT;
  }
  CHECK(stderr_pipe);
  static const char *const setup_only[] = {
      "read -u3 value < <(printf ignored) 3<<<payload",
      "read -t0 value < <(printf ignored)",
      "{ read -u3 value; } < <(printf ignored) 3<<<payload"};
  for (size_t i = 0; i < sizeof(setup_only) / sizeof(setup_only[0]); i++) {
    parse(setup_only[i]);
    uint32_t producer = command("printf");
    bool setup = false;
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      CHECK(edge->from != producer || edge->type != SHELL_EDGE_SUBST);
      setup |= edge->from == producer && edge->type == SHELL_EDGE_FD_OPEN;
    }
    CHECK(setup);
  }
}

static void assignment_and_control(void) {
  /* A failed read preserves the fd variable (reference Bash leaves $fd
   * intact with rc=1). The read errors are handled by `|| true`; unhandled,
   * they would reject the input. */
  static const char *const safe[] = {"read -u3 fd 3>out", "read -u3 fd 3<&-",
                                     "read -t0 fd", "read bad-name fd"};
  for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source),
             "exec {fd}>out; %s || true; printf x >&\"$fd\"", safe[i]);
    parse(source);
    bool write = false;
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      write |= edge->from == command("printf") &&
               edge->type == SHELL_EDGE_WRITE &&
               graph->nodes[edge->to].type == SHELL_NODE_DOC;
    }
    CHECK(write);
  }
  current_source = "exec {fd}>out; read -n0 fd; printf x >&\"$fd\"";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  parse("read -t0 bad-name && echo maybe");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  CHECK(inputs(command("echo"), 0, NULL) == 1);
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&-; read -u3 value && echo skipped || printf reached");
}

/* A read whose descriptor exists on only some paths fails at the shell level
 * ("invalid file descriptor") on the others. Where `&&` consumes the read's
 * status, that error is an ordinary failure outcome: the read's input is
 * modeled on the open path, and the continuation runs only there. Unhandled,
 * one such path suffices to leave the input without a dependency model
 * (descriptor rule, SHELL_DEP_EUNMODELED), whichever context, capture or
 * read form contains it. */
static void conditional_descriptor_versions(void) {
  static const char *const connectors[] = {"&&", "||"};
  static const char *const contexts[] = {"%s", "{ %s; }", "(%s)",
                                         "time { %s; }"};
  for (size_t c = 0; c < sizeof(connectors) / sizeof(connectors[0]); c++)
    for (size_t k = 0; k < sizeof(contexts) / sizeof(contexts[0]); k++) {
      char body[512], source[640];
      /* Reference Bash reads payload where the conditional open placed fd 3
       * and fails the read elsewhere (verified: choice=yes reads payload
       * and writes reached; choice=no fails rc=1). */
      snprintf(body, sizeof(body),
               "exec 3<&-; test \"$choice\" = yes %s exec 3<<<payload; "
               "read -u3 value && echo reached >reached",
               connectors[c]);
      snprintf(source, sizeof(source), contexts[k], body);
      parse(source);
      CHECK(inputs(command("read"), 3, NULL) == 1);
      CHECK(document_input(command("read"), "payload"));
      CHECK(document_write(command("echo"), "reached"));
      snprintf(body, sizeof(body),
               "exec 3<&-; test \"$choice\" = yes %s exec 3<<<payload; "
               "read -u3 value; echo reached >reached",
               connectors[c]);
      snprintf(source, sizeof(source), contexts[k], body);
      reject(source);
      /* With a repeated -u the last one wins on the open path (fd 4 reads
       * "selected"), but the first, closed -u still aborts the read on the
       * other path (verified rc=1). */
      snprintf(body, sizeof(body),
               "exec 3<&-; test \"$choice\" = yes %s exec 3<<<payload; "
               "read -u3 -u4 value 4<<<selected && echo reached >reached",
               connectors[c]);
      snprintf(source, sizeof(source), contexts[k], body);
      parse(source);
      CHECK(inputs(command("read"), 4, NULL) == 1);
      CHECK(document_input(command("read"), "selected"));
      CHECK(!document_input(command("read"), "payload"));
      CHECK(document_write(command("echo"), "reached"));
      snprintf(body, sizeof(body),
               "exec 3<&-; test \"$choice\" = yes %s exec 3<<<payload; "
               "read -u3 -u4 value 4<<<selected; echo reached >reached",
               connectors[c]);
      snprintf(source, sizeof(source), contexts[k], body);
      reject(source);
    }
  for (size_t c = 0; c < sizeof(connectors) / sizeof(connectors[0]); c++) {
    char source[512];
    /* The conditional close is a no-op: fd 3 starts closed and nothing opens
     * it, so the read fails on every path (reference Bash: "invalid file
     * descriptor", rc=1 for both connector senses). */
    snprintf(source, sizeof(source),
             "test \"$choice\" = yes %s exec 3<&-; read -u3 value",
             connectors[c]);
    reject(source);
    /* A named fd closed on one path and kept on the other (verified Bash
     * reads payload when kept, fails rc=1 when closed). */
    snprintf(source, sizeof(source),
             "exec {fd}<<<payload && { test \"$choice\" = yes %s "
             "exec {fd}<&-; read -u\"$fd\" value && echo reached >reached; }",
             connectors[c]);
    parse(source);
    CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
    CHECK(document_input(command("read"), "payload"));
    CHECK(document_write(command("echo"), "reached"));
    snprintf(source, sizeof(source),
             "exec {fd}<<<payload && { test \"$choice\" = yes %s "
             "exec {fd}<&-; read -u\"$fd\" value; echo reached >reached; }",
             connectors[c]);
    reject(source);
    /* The same through a capture: on the open path the substitution's read
     * consumes payload; on the closed path it fails unhandled. */
    snprintf(source, sizeof(source),
             "exec 3<&-; test \"$choice\" = yes %s exec 3<<<payload; "
             "echo \"$(read -u3 value)\"",
             connectors[c]);
    reject(source);
    /* The same for a zero-byte read: on the open path `read -t0` succeeds
     * without consuming (verified fd stays empty); on the closed path it
     * fails unhandled. */
    snprintf(source, sizeof(source),
             "exec {fd}>out && { exec 3<&-; "
             "test \"$choice\" = yes %s exec 3<<<payload; "
             "read -u3 -t0 fd; printf x >&\"$fd\"; }",
             connectors[c]);
    reject(source);
  }
  /* Enough read operands exceed the path version bound, so the join that
   * folds them leaves named bindings known on one side only. That join reads
   * every name as unknown over an empty override map, which later named
   * queries descend into. */
  parse("{ read first $gap $gap $gap $gap $gap && [[ -v first ]] && x; } "
        "<<<payload");
}

static void captured_option_values(void) {
  static const char *const options[] = {"-p\"$fd\"",  "-d\"${fd}\"",
                                        "-i\"$fd\"",  "-n\"$fd\"",
                                        "-N \"$fd\"", "-t\"$fd\""};
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    char source[512];
    /* Successful setup proves the value nonempty; semicolon also allows
     * allocation failure, legitimately changing attached operand roles. */
    snprintf(source, sizeof(source),
             "exec {fd}<<<payload && read %s -u\"$fd\" value <unused",
             options[i]);
    parse(source);
    CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
    CHECK(document_input(command("read"), "payload"));
    CHECK(!document_input(command("read"), "unused"));
  }
  reject("exec {fd}>out && { read -p\"$fd\" -u3 fd 3<&-; "
         "printf x >&\"$fd\"; }");
  parse("exec {fd}<<<old && read -p\"$fd\" -u\"$fd\" value {fd}<<<new");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  CHECK(document_input(command("read"), "old"));
  CHECK(!document_input(command("read"), "new"));
  parse("exec {fd}<<<old && echo \"$(read -p\"$fd\" -u\"$fd\" value)\"");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  CHECK(document_input(command("read"), "old"));
  /* Where the open fails, the empty attached operands shift roles and the
   * read takes stdin (unused) without error. Precision gap: the analysis
   * attributes that path to the failed open, making the open a requirement,
   * so only payload is represented. Conservative, not exact. */
  parse("exec {fd}<<<payload; read -p\"$fd\" -u\"$fd\" value <unused");
  CHECK(document_input(command("read"), "payload"));
  CHECK(!document_input(command("read"), "unused"));
  parse("read -p\"$prompt\" -u3 value 3<<<payload");
  CHECK(document_input(command("read"), "payload"));
  /* Unknown prompt emptiness really may cause -u3 to become prompt data. */
  bool stdin_input = false;
  for (uint32_t e = 0; e < graph->edge_count; e++)
    stdin_input |= input_edge(&graph->edges[e], command("read")) &&
                   graph->edges[e].target_fd == 0;
  CHECK(stdin_input);
  parse("unset fd; exec {fd}<input; read -p\"$fd\" -u3 value 3<<<payload");
  CHECK(document_input(command("read"), "payload"));
  stdin_input = false;
  for (uint32_t e = 0; e < graph->edge_count; e++)
    stdin_input |= input_edge(&graph->edges[e], command("read")) &&
                   graph->edges[e].target_fd == 0;
  CHECK(stdin_input);
}

static void numeric_operand_classification(void) {
  static const struct {
    const char *word;
    unsigned whole, timeout, payload;
  } templates[] = {
      {"-n-\"$fd\"", 0, 0, 2},    {"-t+\"$fd\"", 0, 0, 1},
      {"-\"$fd\"", 2, 2, 1},      {"\" +${fd} \"", 1, 0, 1},
      {"-n1\"$fd\"", 0, 0, 0},    {"-t0.\"$fd\"", 0, 0, 0},
      {"-n-0\"$fd\"", 0, 0, 2},   {"-u00\"$fd\"", 0, 0, 1},
      {"\"-00${fd} \"", 2, 0, 1}, {"-t0\"$fd\"", 0, 0, 0},
      {"-u1\"$fd\"", 0, 0, 0},    {"\"0 ${fd}\"", 0, 0, 1},
      {"-n-\"$fd\"0", 0, 0, 0},   {"-n\"$fd\"\"$other\"", 0, 0, 0}};
  for (size_t i = 0; i < sizeof(templates) / sizeof(templates[0]); i++) {
    current_source = templates[i].word;
    shell_builtin_read_option_t scan;
    CHECK(shell_builtin_read_scan_word(current_source, strlen(current_source),
                                       &scan));
    CHECK(scan.number_scalar == templates[i].whole);
    CHECK(scan.timeout_scalar == templates[i].timeout);
    CHECK(scan.payload_scalar == templates[i].payload);
  }
  static const struct {
    const char *word;
    unsigned number, timeout, payload, empty_number, empty_timeout,
        empty_payload;
  } classes[] = {
      {"-p\"$fd\"", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID},
      {"-n\"${fd}\"", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID},
      {"-t\"$fd\"", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_ZERO},
      {"\"$fd\"", SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_UNKNOWN,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_ZERO, SHELL_READ_VALUE_INVALID},
      {"-n0\"$fd\"", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_ZERO},
      {"-nx\"$fd\"", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID},
      {"-t\"$fd\"x", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID},
      {"\"$fd\"+1", SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_UNKNOWN,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_NONZERO,
       SHELL_READ_VALUE_NONZERO, SHELL_READ_VALUE_INVALID},
      {"-t0.000000x\"$fd\"", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_ZERO, SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_ZERO}};
  for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
    current_source = classes[i].word;
    shell_builtin_read_option_t scan;
    CHECK(shell_builtin_read_scan_word(current_source, strlen(current_source),
                                       &scan));
    bool dynamic = scan.unresolved || scan.attached_dynamic;
    CHECK(shell_builtin_read_number_value(&scan.number, dynamic, true) ==
          classes[i].number);
    CHECK(shell_builtin_read_number_value(&scan.timeout, dynamic, true) ==
          classes[i].timeout);
    CHECK(shell_builtin_read_number_value(&scan.payload, scan.attached_dynamic,
                                          true) == classes[i].payload);
    CHECK(shell_builtin_read_number_value(&scan.number, false, true) ==
          classes[i].empty_number);
    CHECK(shell_builtin_read_number_value(&scan.timeout, false, true) ==
          classes[i].empty_timeout);
    CHECK(shell_builtin_read_number_value(&scan.payload, false, true) ==
          classes[i].empty_payload);
  }

  static const char first[] = "nNtu", second[] = "pdinNtu";
  static const char *const parameters[] = {"\"$fd\"", "\"${fd}\"",
                                           "\"$unknown\""};
  for (size_t f = 0; f < sizeof(first) - 1; f++)
    for (size_t s = 0; s < sizeof(second) - 1; s++)
      for (size_t p = 0; p < sizeof(parameters) / sizeof(parameters[0]); p++) {
        char source[384];
        snprintf(source, sizeof(source),
                 "unset fd; read -%c\"$fd\" -%c%s value <<<payload "
                 "&& printf accepted >accepted || printf failed >failed",
                 first[f], second[s], parameters[p]);
        parse(source);
        CHECK(inputs(command("read"), 0, NULL) == 0);
        CHECK(!document_write(command("accepted"), "accepted"));
        CHECK(document_write(command("failed"), "failed"));
      }

  /* An argument error has no target, REPLY, or IFS writes. Later uses expose
   * accidental invalidation instead of merely checking the absence of READ.
   * Each read reports its error ("invalid number"), which `|| true`
   * handles; unhandled, the error rejects the input. */
  reject("exec {out}>out && exec {input}<<<saved && { IFS=; unset fd; "
         "read -n\"$fd\" -p\"$fd\" out IFS <<<payload; "
         "printf kept >&\"$out\"; read -u $input later; }");
  parse("exec {out}>out && exec {input}<<<saved && { IFS=; unset fd; "
        "read -n\"$fd\" -p\"$fd\" out IFS <<<payload || true; "
        "printf kept >&\"$out\"; read -u $input later; }");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  CHECK(document_write(command("kept"), "out"));
  expect_document_input(command("later"), "saved", SHELL_DEP_FD_NAMED, "input",
                        true);
  reject("exec {REPLY}>out && { unset fd; "
         "read -u\"$fd\" -n\"$fd\" <<<payload; "
         "printf kept >&\"$REPLY\"; }");
  parse("exec {REPLY}>out && { unset fd; "
        "read -u\"$fd\" -n\"$fd\" <<<payload || true; "
        "printf kept >&\"$REPLY\"; }");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  CHECK(document_write(command("kept"), "out"));

  /* Captured emptiness refines literal payloads too, not just bare $fd. */
  static const struct {
    const char *option;
    bool input, success;
  } empty_payloads[] = {{"-n0", false, true},  {"-N0", false, true},
                        {"-t0", false, true},  {"-n1", true, true},
                        {"-nx", false, false}, {"-tbad", false, false}};
  for (size_t i = 0; i < sizeof(empty_payloads) / sizeof(empty_payloads[0]);
       i++) {
    char source[384];
    snprintf(source, sizeof(source),
             "unset fd; read %s\"$fd\" value <<<payload "
             "&& printf accepted >accepted || printf failed >failed",
             empty_payloads[i].option);
    parse(source);
    CHECK((inputs(command("read"), 0, NULL) != 0) == empty_payloads[i].input);
    CHECK(document_write(command("accepted"), "accepted") ==
          empty_payloads[i].success);
    if (!empty_payloads[i].success)
      CHECK(document_write(command("failed"), "failed"));
  }
  parse("exec {fd}<<<saved && "
        "read -n\"$fd\" -p\"$fd\" -u3 value 3<<<payload");
  expect_document_input(command("read"), "payload", 3, NULL, true);
  parse("unset fd; read -p\"$fd\" -n1 value <<<payload");
  expect_document_input(command("read"), "payload", 0, NULL, true);
  /* `-n -p…` reports an invalid number. Unhandled, that read error rejects
   * the input; handled, the prompt's substitution has still run. */
  reject("unset fd; read -n\"$fd\" -p\"$(printf expanded)\" value "
         "<<<payload");
  parse("unset fd; read -n\"$fd\" -p\"$(printf expanded)\" value "
        "<<<payload || true");
  CHECK(!document_input(command("read"), "payload"));
  bool expanded = false;
  for (uint32_t e = 0; e < graph->edge_count; e++) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    expanded |= edge->type == SHELL_EDGE_SUBST &&
                edge->from == command("expanded") &&
                edge->to == command("read");
  }
  CHECK(expanded);

  /* Empty observations belong to execution versions, not identifier names.
   * Later writes (including read/REPLY and arbitrary targets) must discard
   * them, failed setup must not apply them, and children cannot export them.
   * A count the analysis cannot prove valid may be an invalid number, a read
   * error which `|| true` handles. */
  static const char *const writes[] = {"fd=1",
                                       "printf -v fd %s 1",
                                       "export fd=1",
                                       "read -n0 fd",
                                       "read -n0 -- \"$target\" || true",
                                       "fd=1 true"};
  for (size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); i++) {
    char source[384];
    snprintf(source, sizeof(source),
             "unset fd; %s; read -n\"$fd\" value <<<payload || true",
             writes[i]);
    parse(source);
    CHECK(document_input(command("value"), "payload") ==
          (i + 1 != sizeof(writes) / sizeof(writes[0])));
  }
  reject("unset REPLY; read -n0; "
         "read -n\"$REPLY\" -p\"$REPLY\" value <<<payload");
  reject("exec {fd}>out && { "
         "result=$(unset fd; read -n\"$fd\" -p\"$fd\" value <<<payload); "
         "printf kept >&\"$fd\"; }");
  parse("exec {fd}<<<saved && { fd=temporary unset fd; "
        "read -n\"$fd\" -p\"$fd\" -u3 value 3<<<payload; }");
  expect_document_input(command("read"), "payload", 3, NULL, true);
  reject("exec {fd}<<<saved && { exec 3<&-; unset fd 0<&3; "
         "read -n\"$fd\" -p\"$fd\" -u4 value 4<<<payload; }");
  reject("exec {fd}<<<saved; test \"$choice\" = yes && unset 'f'd; "
         "read -n\"$fd\" -p\"$fd\" -u3 value 3<<<payload");

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous_source = 0, previous_read = 0, previous_routes = 0;
  for (unsigned count = 4; count <= 16; count *= 2) {
    char source[4096];
    size_t used = 0;
    for (unsigned i = 0; i < count; i++)
      used += (size_t)snprintf(source + used, sizeof(source) - used,
                               "unset fd%u; read -n\"$fd%u\" "
                               "-p\"$fd%u\" value <<<payload || true; ",
                               i, i, i);
    shellsplit_test_source_scan_reset();
    parse(source);
    size_t source_work = shellsplit_test_source_scan_work();
    size_t read_work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_READ_INPUT);
    size_t route_work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    CHECK(!previous_source || source_work <= 3 * previous_source);
    CHECK(!previous_read || read_work <= 3 * previous_read);
    CHECK(!previous_routes || route_work <= 3 * previous_routes);
    previous_source = source_work;
    previous_read = read_work;
    previous_routes = route_work;
  }
#endif
}

/* The counts below are dynamic or proven empty, so each read may report or
 * certainly reports an invalid number; `|| true` handles those read errors.
 * What remains under test is which reads may consume input once a write
 * invalidates, or an unset re-establishes, the proven emptiness. */
static void binding_invalidation(void) {
  static const char *const unstable[] = {
      "unset _; : 1; read -n\"$_\" value <<<payload || true",
      ("unset '_'; builtin : 1; builtin read -n\"${_}\" value <<<payload || "
       "true"),
      "unset _; : 1; { read -n\"$_\" value <<<payload || true; }",
      "(unset _; : 1; read -n\"$_\" value <<<payload || true)",
      "unset _; : 1; result=$(read -n\"$_\" value <<<payload || true)"};
  for (size_t i = 0; i < sizeof(unstable) / sizeof(unstable[0]); i++) {
    parse(unstable[i]);
    CHECK(document_input(command("value"), "payload"));
  }
  parse("unset _; : 1; read -n\"$_\" value <<<payload "
        "&& printf accepted >accepted");
  CHECK(document_input(command("value"), "payload"));
  CHECK(document_write(command("accepted"), "accepted"));
  parse("unset count; : 1; read -n\"$count\" value <<<payload "
        "&& printf accepted >accepted");
  CHECK(!document_input(command("value"), "payload"));
  CHECK(!document_write(command("accepted"), "accepted"));

  static const char *const writes[] = {"read -n0 -- \"$target\" || true",
                                       "read -N0 first \"$target\" || true"};
  for (size_t w = 0; w < sizeof(writes) / sizeof(writes[0]); w++) {
    char source[512];
    snprintf(source, sizeof(source),
             "unset count; %s; read -n\"$count\" value <<<payload || true",
             writes[w]);
    parse(source);
    CHECK(document_input(command("value"), "payload"));
    snprintf(source, sizeof(source),
             "unset count; %s; unset count; "
             "read -n\"$count\" value <<<payload || true",
             writes[w]);
    parse(source);
    CHECK(!document_input(command("value"), "payload"));
    snprintf(source, sizeof(source),
             "unset count; count=temporary %s; "
             "read -n\"$count\" value <<<payload || true",
             writes[w]);
    parse(source);
    CHECK(!document_input(command("value"), "payload"));
    /* Duplicating the closed fd 3 onto stdin certainly fails (reference
     * Bash: "Bad file descriptor"), so the whole setup has no model. */
    snprintf(source, sizeof(source),
             "unset count; exec 3<&-; %s 0<&3; "
             "read -n\"$count\" value <<<payload || true",
             writes[w]);
    reject(source);
    snprintf(source, sizeof(source),
             "unset count; (%s); read -n\"$count\" value <<<payload || true",
             writes[w]);
    parse(source);
    CHECK(!document_input(command("value"), "payload"));
    snprintf(source, sizeof(source),
             "unset count; result=$(%s); "
             "read -n\"$count\" value <<<payload || true",
             writes[w]);
    parse(source);
    CHECK(!document_input(command("value"), "payload"));
    snprintf(source, sizeof(source),
             "unset count; %s; exec {count}<<<saved && "
             "read -u\"$count\" value",
             writes[w]);
    parse(source);
    expect_document_input(command("value"), "saved", SHELL_DEP_FD_NAMED,
                          "count", true);
  }
  /* Duplicating the closed fd 9 certainly fails. */
  reject("exec 9<&-; exec {count}<&9; "
         "read -n0 -- \"$target\" || true; "
         "read -n\"$count\" value <<<payload || true");
  reject("unset count; "
         "read -n0 -- \"$target\"; read -n\"$count\" value <<<payload");
  parse("unset count; test \"$choice\" = yes && "
        "read -n0 -- \"$target\" || true; "
        "read -n\"$count\" value <<<payload || true");
  CHECK(document_input(command("value"), "payload"));
  parse("exec {count}>saved && { "
        "read -n0 -- \"$target\" || true; printf retained >&10; }");
  CHECK(document_write(command("retained"), "saved"));
  parse("exec {count}>saved && { result=$(unset count; "
        "read -n\"$count\" value <<<payload || true); "
        "printf retained >&$count; }");
  CHECK(!document_input(command("value"), "payload"));
  CHECK(document_write(command("retained"), "saved"));
  parse("exec {count}>saved && { result=$(read -n0 -- \"$target\" || true; "
        "unset count; read -n\"$count\" value <<<payload || true); "
        "printf retained >&$count; }");
  CHECK(!document_input(command("value"), "payload"));
  CHECK(document_write(command("retained"), "saved"));

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* No active empty facts: unrelated future-only names must not be visited
   * once per arbitrary writer. Also exercise established empty overrides and
   * temporary-prefix exclusions, charging actual map operations. `!`
   * consumes each read's status, handling its read error without adding a
   * command per unit. */
  for (unsigned established = 0; established < 2; established++) {
    size_t previous = 0;
    for (unsigned count = 4; count <= 16; count *= 2) {
      char source[8192];
      size_t used = 0;
      if (established)
        for (unsigned i = 0; i < count; i++)
          used += (size_t)snprintf(source + used, sizeof(source) - used,
                                   "unset count%u; ", i);
      for (unsigned i = 0; i < count; i++)
        used += (size_t)snprintf(source + used, sizeof(source) - used,
                                 "! count0=temp read -n0 -- \"$target\"; ");
      for (unsigned i = 0; i < count; i++)
        used += (size_t)snprintf(source + used, sizeof(source) - used,
                                 "! read -n\"$count%u\" value <<<payload; ", i);
      shellsplit_test_source_scan_reset();
      parse(source);
      size_t work = shellsplit_test_metadata_work(
          SHELLSPLIT_TEST_WORK_BINDING_INVALIDATION);
      CHECK(work > 0);
      CHECK(!previous || work <= 3 * previous);
      previous = work;
    }
  }
#endif
}

static void inherited_variable_capabilities(void) {
  static const char *const supported[] = {
      "unset RANDOM; result=$(read RANDOM <<<payload)",
      "unset RANDOM; result=`read RANDOM <<<payload`",
      "unset RANDOM; : <(read RANDOM <<<payload)",
      "unset RANDOM; : >(read RANDOM <<<payload)",
      "unset RANDOM; result=$(inner=$(read RANDOM <<<payload))",
      "unset RANDOM; result=$(read RANDOM <<<payload | cat)",
      "unset RANDOM; result=$({ read RANDOM <<<payload; })",
      "unset SECONDS; result=$(read SECONDS <<<payload)",
      "unset BASH_REMATCH; result=$(read BASH_REMATCH <<<payload)",
      "unset RANDOM; result=$(read -p\"$RANDOM\" -e value <<<payload)",
      "unset RANDOM; RANDOM=changed result=$(read RANDOM <<<payload) :",
      ("test \"$choice\" = yes && unset RANDOM || unset RANDOM; "
       "result=$(read RANDOM <<<payload)"),
  };
  for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
    parse(supported[i]);
    CHECK(document_input(command("read"), "payload"));
  }
  parse("unset RANDOM; result=$(printf -v RANDOM %s payload)");
  parse("unset OPTIND; result=$(getopts a OPTIND -a)");
  parse("unset RANDOM; exec {RANDOM}<<<payload && "
        "result=$(read -u\"$RANDOM\" value)");
  expect_document_input(command("read"), "payload", SHELL_DEP_FD_NAMED,
                        "RANDOM", true);
  parse("unset RANDOM; result=$(read -n0 RANDOM)");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  /* A child inherits the parent's capabilities, not its lifetime. Its write
   * cannot replace the parent's known-empty scalar value. */
  parse("unset RANDOM; result=$(read RANDOM <<<child); "
        "read -p\"$RANDOM\" -e value <<<payload");
  CHECK(document_input(command("value"), "payload"));
  /* Distinguish inherited capability paths even when ordinary scalar binding
   * facts coincide; neither a conditional nor an isolated unset is a proof. */
  static const char *const unsupported[] = {
      "test \"$choice\" = yes && unset RANDOM; "
      "result=$(read RANDOM <<<payload)",
      "test \"$choice\" = yes && unset RANDOM; "
      "result=$(inner=$(read RANDOM <<<payload))",
      "test \"$choice\" = yes && unset RANDOM; "
      "read -n0 -- \"$target\"; result=$(read RANDOM <<<payload)",
      "result=$(unset RANDOM); read RANDOM <<<payload",
      ": <(unset RANDOM); result=$(read RANDOM <<<payload)",
      "unset RANDOM | cat; result=$(read RANDOM <<<payload)",
  };
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    current_source = unsupported[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }
}

static void predefined_variable_lifecycle(void) {
  static const char *const initially_special[] = {
      "read RANDOM <<<payload",    "getopts a OPTIND -a",
      "declare SECONDS='other=2'", "printf -v RANDOM '%s' 'other=2'",
      "exec {DIRSTACK}>dirstack",
  };
  for (size_t i = 0;
       i < sizeof(initially_special) / sizeof(initially_special[0]); i++) {
    current_source = initially_special[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }

  parse("unset RANDOM; read RANDOM <<<payload");
  CHECK(document_input(command("read"), "payload"));
  parse("unset RANDOM; printf -v RANDOM '%s' 'other=2'");
  parse("unset OPTIND; getopts a OPTIND -a");
  parse("unset SECONDS; declare SECONDS='other=2'");
  parse("unset OPTIND; OPTIND='other=2'");
  /* Nonassignable predefined targets reject writes after consuming input.
   * Earlier targets remain assigned; polling and zero-character reads retain
   * their separate input contracts. Rejection is an ordinary builtin failure.
   */
  parse("read first FUNCNAME IFS last <<<payload && printf accepted >accepted; "
        "printf continued >continued");
  CHECK(document_input(command("read"), "payload"));
  CHECK(!document_write(command("accepted"), "accepted"));
  CHECK(document_write(command("continued"), "continued"));
  parse("read -n0 first FUNCNAME IFS last <<<payload && "
        "printf accepted >accepted");
  CHECK(!document_input(command("read"), "payload"));
  CHECK(!document_write(command("accepted"), "accepted"));
  parse("read -t0 first FUNCNAME IFS last <<<payload");
  CHECK(!document_input(command("read"), "payload"));
  parse("unset FUNCNAME; read FUNCNAME <<<payload");
  CHECK(document_input(command("read"), "payload"));
  parse("name=unused; unset -- \"$name\" FUNCNAME; "
        "read FUNCNAME <<<payload && printf accepted >accepted");
  CHECK(document_input(command("read"), "payload"));
  CHECK(document_write(command("accepted"), "accepted"));
  parse("FUNCNAME=value unset FUNCNAME; "
        "read FUNCNAME <<<payload && printf accepted >accepted");
  CHECK(document_input(command("read"), "payload"));
  CHECK(document_write(command("accepted"), "accepted"));
  parse("unset -- \"$name\"; read first FUNCNAME IFS last <<<payload");
  CHECK(document_input(command("read"), "payload"));
  parse("unset -- \"$name\"; read -t0 FUNCNAME <<<payload");
  CHECK(!document_input(command("read"), "payload"));
  parse("IFS=0123456789; unset -- \"$name\" IFS; "
        "exec {fd}<input && cat <&$fd");
  CHECK(document_input(command("cat"), "input"));
  parse("IFS=0123456789; unset -- IFS \"$name\"; "
        "exec {fd}<input && cat <&$fd");
  CHECK(document_input(command("cat"), "input"));
  parse("unset FUNCNAME; exec {FUNCNAME}>funcname; "
        "printf payload >&$FUNCNAME");
  CHECK(document_write(command("payload"), "funcname"));
  parse("unset GROUPS; exec {GROUPS}>groups; printf payload >&$GROUPS");
  CHECK(document_write(command("payload"), "groups"));
  parse("unset DIRSTACK; exec {DIRSTACK}>dirstack; "
        "printf payload >&$DIRSTACK");
  CHECK(document_write(command("payload"), "dirstack"));
  parse("unset DIRSTACK; unset DIRSTACK; exec {DIRSTACK}>fresh; "
        "printf payload >&$DIRSTACK");
  CHECK(document_write(command("payload"), "fresh"));
  parse("unset DIRSTACK; exec {DIRSTACK}>old; unset DIRSTACK; "
        "unset DIRSTACK; exec {DIRSTACK}>new && "
        "printf payload >&$DIRSTACK");
  CHECK(document_write(command("payload"), "new"));

  /* Empty option operands are preserved as path-local values. Bash rejects
   * these invocations before reading or assigning, so their && successors do
   * not run. */
  parse("unset RANDOM; : marker; "
        "read -n\"$RANDOM\" -p\"$RANDOM\" value <<<payload && "
        "printf accepted >accepted");
  CHECK(!document_input(command("read"), "payload"));
  CHECK(!document_write(command("accepted"), "accepted"));
  parse("unset fd; read -u\"$fd\" -n\"$fd\" value <<<payload && "
        "printf accepted >accepted");
  CHECK(!document_input(command("read"), "payload"));
  CHECK(!document_write(command("accepted"), "accepted"));

  parse("{ unset RANDOM; read RANDOM <<<payload; }");
  CHECK(document_input(command("read"), "payload"));
  parse("(unset RANDOM; read RANDOM <<<payload)");
  CHECK(document_input(command("read"), "payload"));
  static const char *const isolated_or_conditional[] = {
      "(unset RANDOM); read RANDOM <<<payload",
      "unset RANDOM | read RANDOM <<<payload",
      "test \"$choice\" = yes && unset RANDOM; read RANDOM <<<payload",
  };
  for (size_t i = 0;
       i < sizeof(isolated_or_conditional) / sizeof(isolated_or_conditional[0]);
       i++) {
    current_source = isolated_or_conditional[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }

  /* These variables do not become stable scalar named-FD destinations. */
  static const char *const protected_names[] = {
      "unset _; exec {_}>out",
      "unset PIPESTATUS; exec {PIPESTATUS}>out",
      "unset BASH_ARGC; exec {BASH_ARGC}>out",
  };
  for (size_t i = 0; i < sizeof(protected_names) / sizeof(protected_names[0]);
       i++) {
    current_source = protected_names[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }

  /* Duplicating the closed fd 3 onto stdin certainly fails (reference
   * Bash: "Bad file descriptor"), so the setup has no dependency model and
   * nothing for the independent materializer to rebuild. */
  reject("exec 10<&- && exec 10>ten || read -n0 value 0<&3; "
         "printf marker >&10");
}

static void named_timing_routes(void) {
  static const char *const sources[] = {
      "{ time printf payload; } 2>&1 | "
      "{ exec {fd}<&0; read -u\"$fd\" value; }",
      "{ { time printf payload; }; } 2>&1 | "
      "{ exec {fd}<&0; read -u\"$fd\" value; }",
      "{ time printf payload; } 2>&1 | "
      "{ exec {left}<&0 {right}<&0; "
      "read -u\"$left\" first; read -u\"$right\" second; }",
      "echo \"$({ time printf payload; } 2>&1 | "
      "{ exec {fd}<&0; read -u\"$fd\" value; })\""};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    parse(sources[i]);
    unsigned named_reports = 0;
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      if (graph->nodes[edge->from].type == SHELL_NODE_TIME &&
          edge->type == SHELL_EDGE_PIPE &&
          edge->target_fd == SHELL_DEP_FD_NAMED) {
        CHECK(edge->source_fd == 2 && edge->target_fd_name_len != 0);
        CHECK(graph->nodes[edge->to].type == SHELL_NODE_CMD);
        named_reports++;
      }
    }
    CHECK(named_reports == (i == 2 ? 2 : 1));
  }
}

static void contextual_option_roles(void) {
  static const char *const operands[] = {"-u \"$fd\"", "-u $fd", "-u \"${fd}\"",
                                         "-u${fd}"};
  static const char *const options[] = {"-p\"$fd\"", "-d\"$fd\"", "-i\"$fd\"",
                                        "-n\"$fd\"", "-N\"$fd\"", "-t\"$fd\""};
  for (size_t o = 0; o < sizeof(options) / sizeof(options[0]); o++)
    for (size_t u = 0; u < sizeof(operands) / sizeof(operands[0]); u++) {
      char source[512];
      snprintf(source, sizeof(source),
               "exec {fd}<<<payload && read %s %s value <unused", options[o],
               operands[u]);
      parse(source);
      CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
      CHECK(document_input(command("read"), "payload"));
      CHECK(!document_input(command("read"), "unused"));
    }
  parse("exec {fd}<<<old && read -p\"$fd\" -u \"$fd\" value {fd}<<<new");
  CHECK(document_input(command("read"), "old"));
  CHECK(!document_input(command("read"), "new"));
  parse("exec {fd}<<<payload && echo \"$(read -p\"$fd\" -u \"$fd\" value)\"");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "fd") == 1);
  reject("unset fd; "
         "read -p\"$fd\" -u \"$fd\" value 3<<<payload");
  reject("exec {fd}<<<payload && read -p\"$prompt\" -u \"$fd\" value");

  /* Without route context, the competing scalar may be an unsupported
   * option. These consumers stay conservative and failure-atomic. */
  current_source = "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value";
  CHECK(shell_tokenizer_has_unsupported_semantics(current_source,
                                                  strlen(current_source)));
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(current_source, strlen(current_source), NULL,
                               &processed) == SHELL_PROCESS_EPARSE);
  CHECK(!processed.commands && !processed.command_count && !processed.groups &&
        !processed.group_count && !processed.group_io_ops &&
        !processed.group_io_op_count);
  shell_processed_commands_free(&processed);
  static const char *const unknown[] = {
      "read -p\"$prompt\" -u \"$fd\" value", "read -p\"$prompt\" -u $fd value",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" -e value",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" -a values",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"${fd:-3}\" value"};
  for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++) {
    current_source = unknown[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
}

static void timeout_conversion(void) {
  static const char *const polls[] = {"4294967296",
                                      "8589934592",
                                      "4294967296.0000001",
                                      "+4294967296",
                                      "18446744073709551616",
                                      "-18446744073709551616",
                                      "36893488147419103232.0000001"};
  for (size_t i = 0; i < sizeof(polls) / sizeof(polls[0]); i++) {
    char source[384];
    snprintf(source, sizeof(source), "read -t%s value <<<payload", polls[i]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    snprintf(source, sizeof(source),
             "exec {fd}>out && { read -t%s fd <<<payload; "
             "printf x >&\"$fd\"; }",
             polls[i]);
    parse(source);
    CHECK(document_write(command("printf"), "out"));
    snprintf(source, sizeof(source),
             "exec {REPLY}>out && { read -t%s <<<payload; "
             "printf x >&\"$REPLY\"; }",
             polls[i]);
    parse(source);
    CHECK(document_write(command("printf"), "out"));
  }
  parse("read -t4294967296.5 value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  parse("read -t4294967296.0000009 value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  parse("read -t4294967296.000000x value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  parse("read -t4294967295 value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  reject("exec {fd}>out && { read -t-4294967296 fd <<<payload; "
         "printf x >&\"$fd\"; }");
  reject("read -t9223372036854775808 value <<<payload");
  static const struct {
    const char *operand;
    bool valid;
  } wrapping[] = {{"18446744073709551617", true},
                  {"+18446744073709551617", true},
                  {"-18446744073709551615", true},
                  {"-18446744073709551615.5", true},
                  {"36893488147419103233", true},
                  {"18446744073709551616.0000009", true},
                  {"9223372036854775807", true},
                  {"18446744073709551615", false},
                  {"-9223372036854775808", false},
                  {"-18446744073709551616.5", false},
                  {"-18446744073709551617.5", false},
                  {"18446744073709551617x", false},
                  {"18446744073709551617.0x", false}};
  for (size_t i = 0; i < sizeof(wrapping) / sizeof(wrapping[0]); i++) {
    char source[384];
    snprintf(source, sizeof(source),
             "read -t%s value <<<payload && echo reached >reached || "
             "printf failed >failed",
             wrapping[i].operand);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == wrapping[i].valid);
    CHECK(document_write(command("echo"), "reached") == wrapping[i].valid);
    CHECK(document_write(command("printf"), "failed"));
    if (!wrapping[i].valid) {
      /* An invalid timeout is a read error, handled here by `|| true`; it
       * leaves REPLY untouched. */
      snprintf(source, sizeof(source),
               "exec {REPLY}>out && { read -t%s <<<payload || true; "
               "printf x >&\"$REPLY\"; }",
               wrapping[i].operand);
      parse(source);
      CHECK(document_write(command("printf"), "out"));
    }
  }
}

static void captured_target_values(void) {
  static const char *const numeric[] = {
      "\"$input\"", "\"${input}\"", "$input",  "\"\"$input",
      "$input\"\"", "''$input",     "$input''"};
  for (size_t i = 0; i < sizeof(numeric) / sizeof(numeric[0]); i++)
    for (unsigned form = 0; form < 4; form++) {
      unsigned later = form & 1u;
      char source[512];
      snprintf(source, sizeof(source),
               "exec {input}<<<payload {out}>out && { "
               "read -u\"$input\" %s%s%s out && echo x >unreachable || "
               "printf x >&\"$out\"; }",
               form & 2u ? "-- " : "", later ? "first " : "", numeric[i]);
      parse(source);
      CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "input") == later);
      CHECK(!document_write(command("echo"), "unreachable"));
      CHECK(document_write(command("printf"), "out"));
    }
  /* Entry values, not the temporary assignment or a redirect's replacement,
   * determine whether the expanded first target is a valid identifier. Here
   * it is a descriptor number, so each read reports an error, which
   * `|| true` handles. */
  static const char *const captures[] = {
      "input=temporary read -u\"$input\" -- \"$input\"",
      "read -u\"$input\" -- \"$input\" {input}<<<replacement",
      "command read -u\"$input\" -- \"$input\"",
      "builtin read -u\"$input\" -- \"$input\""};
  for (size_t i = 0; i < sizeof(captures) / sizeof(captures[0]); i++) {
    char source[384];
    snprintf(source, sizeof(source),
             "exec {input}<<<payload {out}>out && { %s || true; "
             "printf x >&\"$out\"; }",
             captures[i]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(document_write(command("printf"), "out"));
  }
  static const char *const empty[] = {"$empty",     "\"$empty\"", "\"\"$empty",
                                      "$empty\"\"", "''$empty",   "$empty''"};
  for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); i++)
    for (unsigned later = 0; later < 2; later++) {
      char source[512];
      snprintf(source, sizeof(source),
               "exec {input}<<<payload {out}>out && { unset empty; "
               "unset empty; "
               "read -u\"$input\" -- %s%s value && echo x >reached; "
               "printf x >&\"$out\"; }",
               later ? "first " : "", empty[i]);
      parse(source);
      CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "input") ==
            (later || i == 0));
      CHECK(document_write(command("echo"), "reached") == (i == 0));
      CHECK(document_write(command("printf"), "out"));
    }
  /* Only the unquoted empty operand disappears, leaving -u 3; the others
   * pass an empty descriptor, a read error which `|| true` handles. */
  for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); i++) {
    char source[384];
    snprintf(source, sizeof(source),
             "unset empty; "
             "read -u %s 3 value 3<<<payload || true",
             empty[i]);
    parse(source);
    CHECK(inputs(command("read"), 3, NULL) == (i == 0));
  }
  static const char *const modes[] = {"-t0", "-n0", "-N0"};
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    char source[384];
    snprintf(source, sizeof(source),
             "exec {input}<<<payload {out}>out && { "
             "read %s -u\"$input\" -- \"$input\" out && echo x >reached; "
             "printf x >&\"$out\"; }",
             modes[i]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(document_write(command("echo"), "reached") == (i == 0));
    CHECK(document_write(command("printf"), "out"));
  }
  parse("exec {input}<<<payload && { "
        "! read -u\"$input\" -- first \"$input\" && echo x >reached; }");
  CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "input") == 1);
  CHECK(document_write(command("echo"), "reached"));
  reject("read -- \"$unknown\" value <<<payload");
  reject("read -- ${unknown:-value} other <<<payload");
  static const char *const contexts[] = {"%s", "{ %s; }", "(%s)",
                                         "time { %s; }", "echo \"$(%s)\""};
  /* The numeric target fails the read before input in every context. That
   * read error rejects the input unless `|| true` handles it. */
  for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); i++) {
    char body[256], source[384];
    snprintf(body, sizeof(body), contexts[i],
             "read -u\"$input\" -- \"$input\"");
    snprintf(source, sizeof(source), "exec {input}<<<payload && %s", body);
    reject(source);
    snprintf(body, sizeof(body), contexts[i],
             "read -u\"$input\" -- \"$input\" || true");
    snprintf(source, sizeof(source), "exec {input}<<<payload && %s", body);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
  }
  reject("exec {input}<<<payload {out}>out && { "
         "test \"$choice\" = yes && exec {input}<<<other; "
         "read -u\"$input\" -- \"$input\" out; printf x >&\"$out\"; }");
  reject("exec {out}>out && { unset target; "
         "test \"$choice\" = yes && exec {target}<<<other; "
         "read -u3 -- \"$target\" out 3<<<payload; printf x >&\"$out\"; }");
  reject("exec {REPLY}>out && { unset empty; "
         "read -- \"\"$empty <<<payload; printf x >&\"$REPLY\"; }");
  /* Duplicating the closed fd 9 onto a named allocation certainly fails
   * (reference Bash: "Bad file descriptor"), like the numeric dup-from-closed
   * setups elsewhere: no dependency model. */
  reject("exec {REPLY}>out && { unset empty; exec 9<&-; "
         "exec {empty}<&9; read -- $empty <<<payload; "
         "printf x >&\"$REPLY\"; }");
  /* The preceding target really is assigned, even though the later numeric
   * target makes read fail. Its old descriptor binding must not survive. */
  current_source = "exec {input}<<<payload {first}>out && { "
                   "read -u\"$input\" -- first \"$input\"; "
                   "printf x >&\"$first\"; }";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  CHECK(shell_dep_graph_validate(graph).valid);
}

/* Unknown fragments cannot repair an invalid literal identifier prefix.
 * Empty captures also expose invalid suffixes without another source walk. */
static void signed_operand_refinement(void) {
  static const char options[] = "nNtu";
  static const char *const operands[] = {"-\"$fd\"", "\"-${fd}\"",
                                         "'-'\"$fd\""};
  for (size_t o = 0; o < sizeof(options) - 1; o++)
    for (size_t p = 0; p < sizeof(operands) / sizeof(operands[0]); p++)
      for (unsigned separate = 0; separate < 2; separate++) {
        char source[512];
        snprintf(source, sizeof(source),
                 "exec {fd}<<<saved && read -%c%s%s value <<<payload "
                 "&& printf accepted >accepted || printf failed >failed",
                 options[o], separate ? " " : "", operands[p]);
        parse(source);
        CHECK(inputs(command("read"), 0, NULL) == 0);
        CHECK(!document_write(command("accepted"), "accepted"));
        CHECK(document_write(command("failed"), "failed"));
      }
  reject("exec {out}>out && exec {fd}<<<saved && { IFS=; "
         "read -n-\"$fd\" out IFS <<<payload; printf kept >&\"$out\"; "
         "read -u $fd later; }");
  /* Handled by `|| true`, the read error leaves a graph to inspect. */
  parse("exec {out}>out && exec {fd}<<<saved && { IFS=; "
        "read -n-\"$fd\" out IFS <<<payload || true; printf kept >&\"$out\"; "
        "read -u $fd later; }");
  expect_document_input(command("later"), "saved", SHELL_DEP_FD_NAMED, "fd",
                        true);
  parse("exec {fd}<<<saved && read -n+\"$fd\" value <<<payload");
  expect_document_input(command("read"), "payload", 0, NULL, true);
  reject("exec {fd}<<<saved && read -u '+\"$fd\"' value");
  parse("exec {fd}<<<saved && read -u+\"$fd\" value");
  expect_document_input(command("read"), "saved", SHELL_DEP_FD_NAMED, "fd",
                        true);
  parse("exec {fd}<<<saved && read -u \" +${fd} \" value");
  expect_document_input(command("read"), "saved", SHELL_DEP_FD_NAMED, "fd",
                        true);
  reject("unset fd; read -n-\"$fd\" value <<<payload");
}

/* Prefix facts survive opaque suffixes, but literal projection across an
 * unknown fragment must not manufacture a completed conversion. */
static void zero_prefixed_operand_refinement(void) {
  static const char options[] = "nNu";
  static const char *const negative[] = {"-0\"$fd\"", "\"-00${fd} \"",
                                         "'-000'\"$fd\"", "-0\\\n0\"${fd}\""};
  for (size_t o = 0; o < sizeof(options) - 1; o++) {
    for (size_t p = 0; p < sizeof(negative) / sizeof(negative[0]); p++)
      for (unsigned separate = 0; separate < 2; separate++) {
        char source[512];
        snprintf(source, sizeof(source),
                 "exec {fd}<<<saved && read -%c%s%s value IFS <<<payload "
                 "&& printf accepted >accepted || printf failed >failed",
                 options[o], separate ? " " : "", negative[p]);
        parse(source);
        CHECK(inputs(command("read"), 0, NULL) == 0);
        CHECK(!document_write(command("accepted"), "accepted"));
        CHECK(document_write(command("failed"), "failed"));
      }
    /* The negative operand is a read error, handled by `|| true`; the
     * failed read assigns nothing. */
    char source[512];
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved {out}>out {REPLY}>reply && { IFS=; "
             "read -%c-0\"$fd\" out IFS <<<payload || true; "
             "printf kept >&\"$out\"; printf reply >&\"$REPLY\"; "
             "read -u $fd later; }",
             options[o]);
    parse(source);
    CHECK(inputs(command("out"), 0, NULL) == 0);
    CHECK(document_write(command("kept"), "out"));
    CHECK(document_write(command("reply"), "reply"));
    expect_document_input(command("later"), "saved", SHELL_DEP_FD_NAMED, "fd",
                          true);
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved {REPLY}>reply && { "
             "read -%c-00\"$fd\" <<<payload || true; "
             "printf kept >&\"$REPLY\"; }",
             options[o]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(document_write(command("kept"), "reply"));
  }
  static const char *const positive[] = {"0\"$fd\"", "\"+00${fd} \"",
                                         "'000'\"$fd\""};
  for (size_t p = 0; p < sizeof(positive) / sizeof(positive[0]); p++)
    for (unsigned separate = 0; separate < 2; separate++) {
      char source[384];
      snprintf(source, sizeof(source),
               "exec {fd}<<<saved && read -u%s%s value <unused",
               separate ? " " : "", positive[p]);
      parse(source);
      expect_document_input(command("read"), "saved", SHELL_DEP_FD_NAMED, "fd",
                            true);
      CHECK(!document_input(command("read"), "unused"));
    }
  parse("exec {fd}<<<old && read -u00\"$fd\" value {fd}<<<new");
  expect_document_input(command("read"), "old", SHELL_DEP_FD_NAMED, "fd", true);
  CHECK(!document_input(command("read"), "new"));
  parse("exec {fd}<<<saved && result=$(read -u00\"$fd\" value)");
  expect_document_input(command("read"), "saved", SHELL_DEP_FD_NAMED, "fd",
                        true);
  static const char *const empty[] = {
      "unset fd; read -u0\"$fd\" value <<<payload",
      "unset fd; read -u-0\"$fd\" value <<<payload",
      "unset fd; read -u \"+00${fd} \" value <<<payload",
      "unset fd; read -u0\"$fd\" value {fd}<<<other <<<payload",
      "unset fd; result=$(read -u00\"$fd\" value <<<payload)"};
  for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); i++) {
    parse(empty[i]);
    expect_document_input(command("read"), "payload", 0, NULL, true);
    CHECK(!document_input(command("read"), "other"));
  }
  parse("unset fd; read -u3\"$fd\" value 3<<<payload");
  expect_document_input(command("read"), "payload", 3, NULL, true);
  /* The read error is handled: its status is consumed. */
  parse("unset fd; exec 0<&-; read -u0\"$fd\" value "
        "&& printf accepted >accepted || printf failed >failed");
  for (size_t o = 0; o < 2; o++) {
    char source[384];
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved && read -%c00\"$fd\" value <<<payload",
             options[o]);
    parse(source);
    expect_document_input(command("read"), "payload", 0, NULL, true);
    snprintf(source, sizeof(source),
             "unset fd; read -%c-00\"$fd\" value <<<payload "
             "&& printf accepted >accepted",
             options[o]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(document_write(command("accepted"), "accepted"));
  }
  static const char *const unsupported[] = {
      "read -u0\"$unknown\" value",
      "exec {fd}<<<saved && read -u1\"$fd\" value",
      "exec {fd}<<<saved && read -u\"0 ${fd}\" value",
      "exec {fd}<<<saved && read -u0\"$fd\"0 value",
  };
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    current_source = unsupported[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }
}

static void irreversible_operand_prefixes(void) {
  static const struct {
    const char *operand;
    unsigned number, timeout;
  } facts[] = {
      {"-1\"$unknown\"", SHELL_READ_VALUE_INVALID, SHELL_READ_VALUE_UNKNOWN},
      {"-0\"$unknown\"", SHELL_READ_VALUE_UNKNOWN, SHELL_READ_VALUE_UNKNOWN},
      {"0.000000\"$unknown\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_UNKNOWN},
      {"0.0000000\"$unknown\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_ZERO},
      {"0.0000005\"$unknown\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_NONZERO},
      {"0.000000x\"$unknown\"later\"$other\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_ZERO},
      {"-0.0000005\"$unknown\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID},
      {"4294967296.0000000\"$unknown\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_ZERO},
      {"-18446744073709551615.0000000\"$unknown\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_NONZERO},
      {"9223372036854775808.0000000\"$unknown\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_INVALID},
      {"0.000\"$unknown\"0000\"$other\"", SHELL_READ_VALUE_INVALID,
       SHELL_READ_VALUE_UNKNOWN}};
  for (size_t i = 0; i < sizeof(facts) / sizeof(facts[0]); i++) {
    current_source = facts[i].operand;
    shell_builtin_read_option_t scan;
    CHECK(shell_builtin_read_scan_word(current_source, strlen(current_source),
                                       &scan));
    CHECK(shell_builtin_read_number_value(&scan.number, true, true) ==
          facts[i].number);
    CHECK(shell_builtin_read_number_value(&scan.timeout, true, true) ==
          facts[i].timeout);
    char source[512];
    snprintf(source, sizeof(source), "-t%s", facts[i].operand);
    current_source = source;
    CHECK(shell_builtin_read_scan_word(source, strlen(source), &scan));
    CHECK(shell_builtin_read_number_value(&scan.payload, true, true) ==
          facts[i].timeout);
  }
  static const char options[] = "nNu";
  static const char *const wrappers[] = {"", "builtin ", "command builtin "};
  for (size_t o = 0; o < sizeof(options) - 1; o++)
    for (unsigned separate = 0; separate < 2; separate++)
      for (size_t w = 0; w < sizeof(wrappers) / sizeof(wrappers[0]); w++) {
        char source[768];
        snprintf(source, sizeof(source),
                 "exec {fd}<<<saved && exec {out}>out && { IFS=; "
                 "%sread -%c%s-1\"$fd\"\"$unknown\" out IFS <<<payload "
                 "&& printf accepted >accepted || printf failed >failed; "
                 "printf kept >&\"$out\"; read -u $fd later; }",
                 wrappers[w], options[o], separate ? " " : "");
        parse(source);
        CHECK(inputs(command("out"), 0, NULL) == 0);
        CHECK(!document_write(command("accepted"), "accepted"));
        CHECK(document_write(command("failed"), "failed"));
        CHECK(document_write(command("kept"), "out"));
        expect_document_input(command("later"), "saved", SHELL_DEP_FD_NAMED,
                              "fd", true);
      }
  for (size_t i = 3; i < sizeof(facts) / sizeof(facts[0]) - 1; i++) {
    for (unsigned separate = 0; separate < 2; separate++) {
      char source[768];
      bool reading = facts[i].timeout == SHELL_READ_VALUE_NONZERO;
      snprintf(source, sizeof(source),
               "exec {out}>out && { IFS=; read -t%s%s out IFS <<<payload "
               "&& printf accepted >accepted || printf failed >failed; "
               "%s }",
               separate ? " " : "", facts[i].operand,
               reading ? "" : "printf kept >&\"$out\";");
      parse(source);
      CHECK(inputs(command("read"), 0, NULL) == reading);
      CHECK(document_write(command("accepted"), "accepted") ==
            (facts[i].timeout != SHELL_READ_VALUE_INVALID));
      if (!reading)
        CHECK(document_write(command("kept"), "out"));
    }
  }
  parse("exec {REPLY}>out && { "
        "read -t0.0000000\"$unknown\" <<<payload; printf kept >&\"$REPLY\"; }");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  CHECK(document_write(command("kept"), "out"));
}

static void fragment_target_classification(void) {
  static const char *const tildes[] = {"$empty~", "${empty}~", "\"$empty\"~",
                                       "$empty\\\n~"};
  for (size_t i = 0; i < sizeof(tildes) / sizeof(tildes[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec {out}>out && { unset empty; IFS=; "
             "read -- %s out IFS <<<payload "
             "&& printf accepted >accepted || printf failed >failed; "
             "printf kept >&\"$out\"; }",
             tildes[i]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(!document_write(command("accepted"), "accepted"));
    CHECK(document_write(command("failed"), "failed"));
    CHECK(document_write(command("kept"), "out"));
  }
  current_source = "~$empty";
  shell_builtin_read_option_t scan;
  CHECK(!shell_builtin_read_scan_word(current_source, strlen(current_source),
                                      &scan));
  static const char *const paths[] = {
      "pre<(printf generated >child)",
      "<(printf generated >child)suffix",
      "pre>(printf generated >child)",
      ">(printf generated >child)suffix",
      "\"$unknown\"<(printf generated >child)",
      "pre<(printf generated >child)\"$unknown\"",
      "<(printf generated >child)\"$unknown\"suffix",
      "pre<(printf generated >child)>(printf generated >child)"};
  for (size_t p = 0; p < sizeof(paths) / sizeof(paths[0]); p++) {
    char source[768];
    snprintf(source, sizeof(source),
             "exec {out}>out && { IFS=; read -- %s out IFS <<<payload "
             "&& printf accepted >accepted || printf failed >failed; "
             "printf kept >&\"$out\"; }",
             paths[p]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(!document_write(command("accepted"), "accepted"));
    CHECK(document_write(command("failed"), "failed"));
    CHECK(document_write(command("generated"), "child"));
    CHECK(document_write(command("kept"), "out"));
    /* A pathname target or count is invalid: a read error, handled here by
     * `|| true`. */
    if (p < 4) {
      snprintf(source, sizeof(source), "read %s value <<<payload || true",
               paths[p]);
      parse(source);
      CHECK(inputs(command("read"), 0, NULL) == 0);
    }
    /* Prompt/delimiter roles consume pathname data, not target identifiers. */
    snprintf(source, sizeof(source), "read -p%s value <<<payload", paths[p]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 1);
    snprintf(source, sizeof(source), "read -n%s value <<<payload || true",
             paths[p]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
  }
  parse("read -t0.0000000<(printf generated >child) value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  CHECK(document_write(command("generated"), "child"));
  parse("read -t1.0000000<(printf generated >child) value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  reject("read -n \"$unknown\"<(printf generated >child) value <<<payload");
  reject("exec {fd}<<<saved && "
         "read -u \"$fd\"<(printf generated >child) value <<<payload");
  reject("unset empty; read -- $empty<(printf generated) value <<<payload");
  /* This unquoted scalar has unresolved splitting, not a one-target proof. */
  /* Handled by `|| true`, the read error leaves a graph to inspect. */
  parse("unset empty; read -- $empty<(printf generated) value <<<payload "
        "|| true");
  CHECK(!document_input(command("read"), "payload"));
  reject("read -- $unknown<(printf generated) value <<<payload");
  reject("read -- \"$@\"<(printf generated >child) value <<<payload");
  reject("read -- <(printf generated >child)\"$@\" value <<<payload");
  parse("read -p'pre<(printf generated)' value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  unsigned commands = 0;
  for (uint32_t n = 0; n < graph->node_count; n++)
    commands += graph->nodes[n].type == SHELL_NODE_CMD;
  CHECK(commands == 1);
  current_source = "pre<(:)";
  scan = (shell_builtin_read_option_t){.valid = true};
  CHECK(!shell_builtin_visit_single_word(current_source, strlen(current_source),
                                         shell_builtin_read_option_byte,
                                         shell_builtin_read_dynamic, &scan));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 4; count <= 16; count *= 2) {
    char source[2048];
    size_t used = (size_t)snprintf(source, sizeof(source), "read -- ");
    for (unsigned i = 0; i < count; i++)
      used += (size_t)snprintf(source + used, sizeof(source) - used,
                               "pre<(:)\"$unknown\" ");
    snprintf(source + used, sizeof(source) - used, "value <<<payload || true");
    shellsplit_test_source_scan_reset();
    parse(source);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work < 4096 * strlen(source));
    CHECK(!previous || work <= previous * 3);
    previous = work;
    CHECK(!document_input(command("read"), "payload"));
  }
#endif
}

static void literal_failure_proofs(void) {
  static const char options[] = "nNu";
  static const char *const suffixes[] = {"\"$unknown\"x",
                                         "\"$unknown\"2147483648",
                                         "\"$a\"x\"$b\"", "\"$unknown\".0"};
  for (size_t o = 0; o < sizeof(options) - 1; o++)
    for (size_t s = 0; s < sizeof(suffixes) / sizeof(suffixes[0]); s++)
      for (unsigned separate = 0; separate < 2; separate++) {
        char source[768];
        snprintf(source, sizeof(source),
                 "exec {out}>out && exec {input}<<<saved && { IFS=; "
                 "builtin read -%c%s%s out IFS <<<payload "
                 "&& printf accepted >accepted || printf failed >failed; "
                 "printf kept >&\"$out\"; read -u $input later; }",
                 options[o], separate ? " " : "", suffixes[s]);
        parse(source);
        CHECK(!document_input(command("out"), "payload"));
        CHECK(!document_write(command("accepted"), "accepted"));
        CHECK(document_write(command("failed"), "failed"));
        CHECK(document_write(command("kept"), "out"));
        expect_document_input(command("later"), "saved", SHELL_DEP_FD_NAMED,
                              "input", true);
      }
  reject("exec {REPLY}>out && { read -n\"$unknown\"x <<<payload; "
         "printf kept >&\"$REPLY\"; }");

  static const char *const targets[] = {"pre\"$unknown\"-", "\"$unknown\"~",
                                        "\"$unknown\"/tail", "\"$a\"-\"$b\"!",
                                        "\"$(printf generated >child)\"-"};
  static const char *const modes[] = {"", "-n0 ", "-N0 ", "-t0 "};
  for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++)
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
      char source[768];
      snprintf(source, sizeof(source),
               "exec {out}>out && { IFS=; read %s-- %s out IFS <<<payload "
               "&& printf accepted >accepted || printf failed >failed; "
               "printf kept >&\"$out\"; }",
               modes[m], targets[t]);
      parse(source);
      CHECK(!document_input(command("read"), "payload"));
      CHECK(document_write(command("accepted"), "accepted") == (m == 3));
      CHECK(document_write(command("kept"), "out"));
      if (t == 4)
        CHECK(document_write(command("generated"), "child"));
    }
  reject("exec {out}>out && { read first pre\"$unknown\"- out IFS "
         "<<<payload; printf kept >&\"$out\"; }");

  static const char *const possible[] = {
      "\"$unknown\"0", "${unknown}-", "\"$@\"-",
      "\"a${open}\"<(printf generated >child)\"]\"",
      "\"a${open}\"<(printf generated >child)\"$close\""};
  /* These targets may be valid, so the read may consume input; they may
   * also be invalid, a possible read error which `|| true` handles. */
  for (size_t p = 0; p < sizeof(possible) / sizeof(possible[0]); p++) {
    char source[512];
    snprintf(source, sizeof(source), "read -- %s value <<<payload || true",
             possible[p]);
    parse(source);
    CHECK(document_input(command("read"), "payload"));
  }
  current_source = "read -- 'a[1]' <<<payload";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  current_source = "\"$unknown\"x";
  shell_builtin_read_option_t scan;
  CHECK(shell_builtin_read_scan_word(current_source, strlen(current_source),
                                     &scan));
  CHECK(shell_builtin_read_number_value(&scan.number, true, true) ==
        SHELL_READ_VALUE_INVALID);
  CHECK(shell_builtin_read_number_value(&scan.number, true, false) ==
        SHELL_READ_VALUE_UNKNOWN);
  CHECK(shell_builtin_read_number_value(&scan.timeout, true, true) ==
        SHELL_READ_VALUE_UNKNOWN);
  reject("read -n\"$unknown\"0 value <<<payload");
  reject("read -t\"$unknown\"x value <<<payload");
  /* Array-shaped text and underscores are ordinary prompt bytes. Exercise
   * the complete target-shape projection without enabling array assignment. */
  parse("read -p '_a_b[1]' value <<<payload");
  CHECK(document_input(command("read"), "payload"));
  parse("read -n-0 value <<<payload");
  CHECK(!document_input(command("read"), "payload"));
}

static void contextual_capabilities(void) {
  static const char *const selectors[] = {"-e", "-E", "-a", "-re", "-ra"};
  static const char operands[] = "pdinNu";
  for (size_t s = 0; s < sizeof(selectors) / sizeof(selectors[0]); s++)
    for (size_t o = 0; o < sizeof(operands) - 1; o++) {
      char source[512];
      bool data = o < 3;
      snprintf(source, sizeof(source),
               "unset fd; command read -%c\"$fd\" %s value <<<payload "
               "&& printf accepted >accepted || printf failed >failed",
               operands[o], selectors[s]);
      parse(source);
      CHECK(document_input(command("read"), "payload") == data);
      CHECK(document_write(command("accepted"), "accepted") == data);
      CHECK(document_write(command("failed"), "failed"));
      /* The read descriptor is missing on every path (fd 3 starts closed
       * and `<<<payload` feeds fd 0), so the read fails before any
       * capability matters. `&&` consumes that read error: only the `||`
       * fallback runs. */
      snprintf(source, sizeof(source),
               "exec 3<&-; read -u3 %s value <<<payload "
               "&& printf accepted >accepted || printf failed >failed",
               selectors[s]);
      parse(source);
      CHECK(!document_input(command("read"), "payload"));
      CHECK(!document_write(command("accepted"), "accepted"));
      CHECK(document_write(command("failed"), "failed"));
    }
  static const char *const rejected[] = {
      "read -e value <<<payload",
      "read -E value <<<payload",
      "read -a values <<<payload",
      "read -p\"$unknown\" -e value <<<payload",
      "exec {fd}<<<saved && read -p\"$fd\" -e value <<<payload",
      "read -u3 -e value 3<<<payload",
      "echo \"$(read -e value <<<payload)\"",
      "unset fd; echo \"$(fd=changed; read -p\"$fd\" -e value <<<payload)\"",
      "unset fd; fd=changed result=$(read -p\"$fd\" -e value <<<payload)",
      "unset fd; fd=changed fd=$(read -p\"$fd\" -e value <<<payload)",
      ("unset fd; fd=changed result=$(nested=$(read -p\"$fd\" -e value "
       "<<<payload)) :"),
      "unset fd; fd=changed result=$(read -p\"$fd\" -e value <<<payload) :",
      "exec {fd}<<<saved; fd=changed result=$(read -u\"$fd\" value)",
      "exec {fd}<<<saved; fd=changed result=$(read -u\"$fd\" value) :",
      ("exec {fd}<<<old; fd=changed result=$(exec {fd}<<<saved; "
       "read -u\"$fd\" value) :"),
      "unset fd; echo \"$(inner=$(read -e value <<<payload))\"",
      ("unset fd; choice && exec {fd}<<<saved; "
       "echo \"$(read -p\"$fd\" -e value <<<payload)\""),
      "read -p\"$unknown\" -a values <<<payload"};
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    current_source = rejected[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const char *const inherited_empty[] = {
      "unset fd; echo \"$(read -p\"$fd\" -e value <<<payload)\"",
      "unset fd; result=$(inner=$(read -p\"$fd\" -e value <<<payload))",
      "unset fd; fd=$(read -p\"$fd\" -e value <<<payload)",
      "unset fd; fd=changed result=$(unset fd; read -p\"$fd\" -e value "
      "<<<payload) :",
      "unset fd; : <(read -p\"$fd\" -e value <<<payload)",
      "exec {fd}<<<saved; unset fd; "
      "result=$(read -p\"$fd\" -e value <<<payload)"};
  for (size_t i = 0; i < sizeof(inherited_empty) / sizeof(inherited_empty[0]);
       i++) {
    parse(inherited_empty[i]);
    CHECK(document_input(command("read"), "payload"));
  }
  parse("exec {fd}<<<saved; result=$(read -u\"$fd\" value) :");
  CHECK(document_input(command("read"), "saved"));
  parse("exec {fd}<<<saved; IFS=1 result=$(read -u $fd value) :");
  CHECK(document_input(command("read"), "saved"));
  parse("exec {fd}<<<saved; fd=$(read -u\"$fd\" value)");
  CHECK(document_input(command("read"), "saved"));
  /* Only a successful new allocation supersedes the temporary value. */
  parse("exec {fd}<<<old; fd=changed result=$(exec {fd}<<<saved && "
        "read -u\"$fd\" value) :");
  CHECK(document_input(command("read"), "saved"));
  CHECK(!document_input(command("read"), "old"));
  current_source = "unset fd; read -p\"$fd\" -e value <<<payload";
  CHECK(shell_tokenizer_has_unsupported_semantics(current_source,
                                                  strlen(current_source)));
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  if (audit_graph_allocations)
    CHECK(shellsplit_test_alloc_count() == 0);
#endif
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(current_source, strlen(current_source), NULL,
                               &processed) == SHELL_PROCESS_EPARSE);
  CHECK(!processed.commands && !processed.command_count);
  shell_processed_commands_free(&processed);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  if (audit_graph_allocations)
    shellsplit_test_alloc_fail_at(0);
#endif
}

static void reachable_target_attributes(void) {
  static const char *const reads[] = {
      "read -- -p\"$empty\" RANDOM <<<payload",
      "read -- first -p\"$empty\" RANDOM <<<payload",
      "read -u3 RANDOM 3>writeonly",
      "read -n-\"$fd\" RANDOM <<<payload",
      "read -u-\"$fd\" RANDOM <<<payload",
      "read -n\"$empty\" -p\"$empty\" RANDOM <<<payload"};
  for (size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved && { unset empty; %s "
             "&& printf accepted >accepted || printf failed >failed; }",
             reads[i]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == (i == 1));
    CHECK(!document_write(command("accepted"), "accepted"));
    CHECK(document_write(command("failed"), "failed"));
  }
  /* A missing read descriptor fails before any target handling: reference
   * Bash reports "invalid file descriptor" and takes the `||` branch, but
   * the failed setup has no dependency model. */
  /* The read error is handled: its status is consumed. */
  parse("exec {fd}<<<saved && { unset empty; read -u3 RANDOM 3<&- "
        "&& printf accepted >accepted || printf failed >failed; }");
  parse("unset empty; read -t0 -- RANDOM\"$empty\" <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  static const char *const unsupported[] = {
      "read RANDOM <<<payload",
      "read -n0 RANDOM",
      "unset empty; read -- RANDOM\"$empty\" <<<payload",
      "unset empty; read -- RAN\"$empty\"DOM <<<payload",
      "unset empty; read -- \"${empty}\"RANDOM <<<payload",
      "read -u3 RANDOM 3<<<payload"};
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    current_source = unsupported[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  parse("unset RANDOM empty");
  parse("unset RANDOM empty; read -n0 RANDOM");
  parse("unset RANDOM empty; read -n0 RANDOM\"$empty\"");
  CHECK(inputs(command("read"), 0, NULL) == 0);
}

static void literal_target_refinement(void) {
  static const char *const targets[] = {
      "other\"$empty\"",      "\"${empty}\"other", "oth\"$empty\"er",
      "'oth'\"$empty\"$'er'", "other$empty",       "o\"$empty\"",
      "in\"$empty\""};
  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec {out}>out && exec {input}<<<saved && { unset empty; IFS=; "
             "read -n0 %s; printf kept >&\"$out\"; read -u $input later; }",
             targets[i]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(document_write(command("kept"), "out"));
    expect_document_input(command("later"), "saved", SHELL_DEP_FD_NAMED,
                          "input", true);
  }
  parse("exec {out}>out && { unset empty; "
        "out=temporary read -n0 o\"$empty\"ut; printf kept >&\"$out\"; }");
  CHECK(document_write(command("kept"), "out"));
  current_source = "exec {out}>out && { unset empty; "
                   "read -n0 \"${empty}\"out; printf kept >&\"$out\"; }";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  parse("exec {input}<<<saved && { unset empty; IFS=; "
        "IFS= read -n0 I\"$empty\"FS; read -u $input later; }");
  expect_document_input(command("later"), "saved", SHELL_DEP_FD_NAMED, "input",
                        true);
  current_source = "exec {input}<<<saved && { unset empty; IFS=; "
                   "read -n0 I\"$empty\"FS; read -u $input later; }";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  parse("exec {out}>out && { unset empty; "
        ": \"$(read -n0 other\"$empty\")\"; printf kept >&\"$out\"; }");
  CHECK(document_write(command("kept"), "out"));
  parse("exec {out}>out && exec {input}<<<saved && { unset empty; "
        "read -u\"$input\" oth\"$empty\"er; printf kept >&\"$out\"; }");
  CHECK(document_write(command("kept"), "out"));
  expect_document_input(command("read"), "saved", SHELL_DEP_FD_NAMED, "input",
                        true);
  /* Graph acceptance supplies the capture proof. A source-only processor
   * must not silently guess the same literal target from an expansion. */
  CHECK(shell_tokenizer_has_unsupported_semantics(current_source,
                                                  strlen(current_source)));
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  if (audit_graph_allocations)
    CHECK(shellsplit_test_alloc_count() == 0);
#endif
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(current_source, strlen(current_source), NULL,
                               &processed) == SHELL_PROCESS_EPARSE);
  CHECK(!processed.commands && !processed.command_count && !processed.groups &&
        !processed.group_count && !processed.group_io_ops &&
        !processed.group_io_op_count);
  shell_processed_commands_free(&processed);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  if (audit_graph_allocations)
    shellsplit_test_alloc_fail_at(0);
#endif
}

static void exec_exit_elision(void) {
  static const char *const elided[] = {"<()", ">()", "<()>()", "<(# comment\n)",
                                       "<(\\\n)"};
  for (size_t i = 0; i < sizeof(elided) / sizeof(elided[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source), "exec %s 3>out; printf reached >&3",
             elided[i]);
    parse(source);
    CHECK(document_write(command("reached"), "out"));
    snprintf(source, sizeof(source), "(true; exit %s) && printf reached >out",
             elided[i]);
    parse(source);
    CHECK(document_write(command("reached"), "out"));
    snprintf(source, sizeof(source),
             "(false; builtin exit %s) || printf reached >out", elided[i]);
    parse(source);
    CHECK(document_write(command("reached"), "out"));
  }
  /* exec of the empty command name certainly fails (reference Bash:
   * "exec: : not found", the shell exits 127): no dependency model. */
  reject("exec <() '' 3>out; printf reached >&3");
  parse("(true; command exit <() \"\") && printf reached >out");
  CHECK(!document_write(command("reached"), "out"));
  parse("(false; exit <() 0 >()) && printf reached >out");
  CHECK(document_write(command("reached"), "out"));
  parse("exec -a <() name >() 3>out; printf reached >&3");
  CHECK(document_write(command("reached"), "out"));
  parse("(true; exit -- <()) && printf reached >out");
  CHECK(document_write(command("reached"), "out"));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_source_scan_reset();
  parse("exec {fd}>out; printf reached >&\"$fd\"");
  CHECK(document_write(command("reached"), "out"));
  CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_READ_OBSERVATIONS) ==
        0);
#endif
}

static void invalid_target_projection(void) {
  static const char *const targets[] = {"-p\"$empty\"", "bad-\"$empty\"",
                                        "9\"$empty\"",  "\"$empty\"-",
                                        "\"$empty\"0",  "\"$empty\"a-"};
  static const char *const modes[] = {"", "-n0 ", "-N0 ", "-t0 "};
  static const char *const wrappers[] = {"", "builtin ", "command "};
  for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++)
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
      for (unsigned later = 0; later < 2; later++) {
        char source[512];
        snprintf(source, sizeof(source),
                 "unset empty; %sread %s-- %s%s value IFS <<<payload "
                 "&& printf accepted >success || printf rejected >failure",
                 wrappers[t % 3], modes[m], later ? "first " : "", targets[t]);
        parse(source);
        CHECK(inputs(command("read"), 0, NULL) == (m == 0 && later));
        CHECK(document_write(command("accepted"), "success") == (m == 3));
        CHECK(document_write(command("rejected"), "failure"));
      }
  static const char *const prefixes[] = {"-p\"$unknown\"", "bad-\"$unknown\"",
                                         "9\"$unknown\""};
  for (size_t t = 0; t < sizeof(prefixes) / sizeof(prefixes[0]); t++) {
    char source[512];
    /* An unknown fragment may complete an invalid target: a possible read
     * error, which `|| true` handles. Assignment stops before out. */
    snprintf(source, sizeof(source),
             "exec {out}>out && { read -- %s out IFS <<<payload || true; "
             "printf kept >&\"$out\"; }",
             prefixes[t]);
    parse(source);
    CHECK(inputs(command("read"), 0, NULL) == 0);
    CHECK(document_write(command("kept"), "out"));
  }
  reject("exec {out}>out && { unset empty; "
         "read -- -p\"$empty\" out IFS <<<payload; printf kept >&\"$out\"; }");
  reject("exec {out}>out && { unset empty; "
         "read -- \"$empty\"- <<<payload; printf kept >&\"$out\"; }");
  reject("exec {fd}<<<saved && read -- \"$fd\"suffix value <<<payload");
  reject("exec {REPLY}>out && { unset empty; "
         "read -- \"$empty\"- <<<payload; printf kept >&\"$REPLY\"; }");
  /* Projection across an unknown fragment is not unconditional invalidity:
   * the expansion may contribute the valid leading letter of a target. */
  reject("read -- \"$unknown\"0 value <<<payload");
  parse("unset empty; read -- x\"$empty\" value <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  /* Later descriptor and IFS targets are untouched, even after an earlier
   * valid target was assigned. Unquoted -u checks both retained guarantees. */
  reject("exec {fd}<<<saved && { unset empty; "
         "read -- first -p\"$empty\" fd IFS <<<payload; "
         "read -u $fd result; }");
  /* Handled by `|| true`, the read error leaves a graph to inspect. */
  parse("exec {fd}<<<saved && { unset empty; "
        "read -- first -p\"$empty\" fd IFS <<<payload || true; "
        "read -u $fd result; }");
  expect_document_input(command("result"), "saved", SHELL_DEP_FD_NAMED, "fd",
                        true);
  current_source =
      "exec {fd}<<<saved && { unset empty; "
      "read -n0 -- fd -p\"$empty\" IFS <<<payload || read -u\"$fd\" result; }";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
}

static void unrelated_observations(void) {
  for (unsigned family = 0; family < 4; family++) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t previous_source = 0, previous_read = 0, previous_routes = 0;
#endif
    for (unsigned count = 4; count <= 16; count *= 2) {
      char source[4096] = "";
      size_t length =
          (size_t)snprintf(source, sizeof(source), "%s",
                           family == 3 ? "exec {observed}<<<known && { " : "");
      for (unsigned i = 0; i < count; i++)
        length += (size_t)snprintf(
            source + length, sizeof(source) - length,
            "test \"$choice%u\" = yes && exec {fd%u}<<<payload; ", i, i);
      snprintf(source + length, sizeof(source) - length,
               "read -p \"$%s\" -u3 value 3<<<selected",
               family == 0 ? "prompt" : "fd0");
      if (family == 2)
        snprintf(source + length, sizeof(source) - length,
                 "read -p fixed -u3 value 3<<<selected");
      else if (family == 3)
        /* The target is the descriptor number, an invalid name: a read
         * error which `|| true` handles. */
        snprintf(source + length, sizeof(source) - length,
                 "read -u3 -- \"$observed\" 3<<<selected || true; }");
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      parse(source);
      CHECK(inputs(command("read"), 3, NULL) == (family != 3));
      CHECK(document_input(command("read"), "selected") == (family != 3));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t source_work = shellsplit_test_source_scan_work();
      size_t read_work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_READ_INPUT);
      size_t route_work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
      CHECK(!previous_source || source_work <= 3 * previous_source);
      CHECK(!previous_read || read_work <= 3 * previous_read);
      if (previous_routes && route_work > 3 * previous_routes)
        fprintf(stderr, "read observation route work: %zu -> %zu\n",
                previous_routes, route_work);
      CHECK(!previous_routes || route_work <= 3 * previous_routes);
      previous_source = source_work;
      previous_read = read_work;
      previous_routes = route_work;
#endif
    }
  }
}

static void observed_classes_with_unrelated_allocations(void) {
  for (unsigned family = 0; family < 2; family++)
    for (unsigned count = 4; count <= 16; count *= 2) {
      char source[4096];
      size_t length = (size_t)snprintf(
          source, sizeof(source), "%s",
          family == 0 ? "" : "exec {selected}<<<selected && { ");
      for (unsigned i = 0; i < count; i++)
        length += (size_t)snprintf(
            source + length, sizeof(source) - length,
            "test \"$choice%u\" = yes && exec {fd%u}<<<payload; ", i, i);
      snprintf(source + length, sizeof(source) - length, "%s",
               family == 0 ? "read -p\"$fd0\" -u3 value 3<<<selected"
                           : "read -u \"$selected\" value; }");
      parse(source);
      if (family == 0)
        CHECK(document_input(command("read"), "selected"));
      else {
        CHECK(inputs(command("read"), SHELL_DEP_FD_NAMED, "selected") == 1);
        CHECK(document_input(command("read"), "selected"));
      }
    }
}

static void refined_target_mutations(void) {
  parse("exec {out}>out && { unset empty; "
        "read -p\"$empty\" out value <<<payload; printf x >&\"$out\"; }");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  CHECK(document_write(command("printf"), "out"));
  /* IFS is prompt data here, not a write target. Losing that distinction
   * would reject the subsequent safe unquoted descriptor argument. */
  parse("exec {fd}<<<payload && { unset empty; "
        "read -p\"$empty\" IFS value <<<data; read -u $fd other; }");
  bool selected = false;
  for (uint32_t e = 0; e < graph->edge_count; e++) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    selected |= edge->type == SHELL_EDGE_READ &&
                edge->target_fd == SHELL_DEP_FD_NAMED &&
                edge->target_fd_name_len == 2 &&
                !memcmp(edge->target_fd_name, "fd", 2);
  }
  CHECK(selected);
  static const char *const reads[] = {
      "read first bad-name fd <<<payload", "read POSIXLY_CORRECT fd <<<payload",
      "read first POSIXLY_CORRECT fd <<<payload", "fd=temporary read -n0 fd"};
  /* The invalid and frozen (executor-readonly) targets are read errors,
   * which `|| true` handles; a stopped read leaves fd untouched. */
  reject("exec {fd}>out && { read first bad-name fd <<<payload; "
         "printf x >&\"$fd\"; }");
  for (size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec {fd}>out && { %s || true; printf x >&\"$fd\"; }", reads[i]);
    parse(source);
    CHECK(document_write(command("printf"), "out"));
  }
  parse("exec {REPLY}>out && { read -t0; printf x >&\"$REPLY\"; }");
  CHECK(document_write(command("printf"), "out"));
  current_source = "exec {REPLY}>out && { read -n0; printf x >&\"$REPLY\"; }";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
}

static void dynamic_target_failures(void) {
  static const char *const counts[] = {"-n0", "-N0"};
  static const char *const contexts[] = {
      "%s || printf fallback >marker",
      "%s && printf accepted >marker",
      "! %s && printf fallback >marker",
      "(%s) || printf fallback >marker",
      ": | %s || printf fallback >marker",
      "printf '%%s' \"$(%s || printf fallback >marker)\""};
  /* Precision gap: an assignment-only command's status is its last
   * substitution's, so `||` consumes the read error, but the analysis does
   * not follow a status out of a substitution and rejects it. */
  reject("target=bad-name; value=$(read -n0 first \"$target\" last "
         "<<<payload) || printf fallback >marker");
  for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
    char body[256], source[768];
    snprintf(body, sizeof(body), "read %s first \"$target\" last <<<payload",
             counts[c]);
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); i++) {
      char context[512];
      snprintf(context, sizeof(context), contexts[i], body);
      snprintf(source, sizeof(source), "target=bad-name; %s", context);
      parse(source);
      CHECK(
          document_write(command(i == 1 ? "accepted" : "fallback"), "marker"));
      CHECK(inputs(command("read"), 0, NULL) == 0);
    }
    /* A failure before the unresolved target's write preserves the binding
     * used by its || continuation. The success path writes fd, so projecting
     * a union of all target writes onto both statuses would reject this read.
     */
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved && { read %s first \"$target\" fd <<<payload "
             "|| read -u\"$fd\" result; }",
             counts[c]);
    parse(source);
    expect_document_input(command("result"), "saved", SHELL_DEP_FD_NAMED, "fd",
                          true);
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved && { read %s -- \"$target\" fd <<<payload "
             "|| read -u\"$fd\" result; }",
             counts[c]);
    parse(source);
    expect_document_input(command("result"), "saved", SHELL_DEP_FD_NAMED, "fd",
                          true);
    /* Earlier committed writes must not be rolled back on the same failure.
     * A changed fd value no longer supplies a supported exact descriptor. */
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved && { read %s fd \"$target\" last <<<payload "
             "|| read -u\"$fd\" result; }",
             counts[c]);
    current_source = source;
    CHECK(shell_dep_graph_parse(source, strlen(source), "/", &limits, graph) ==
          SHELL_DEP_EPARSE);
  }

  /* Ordinary byte reads retain the input of readonly/late-invalid failures;
   * static invalid first identifiers still fail before input. */
  parse("read -- \"$target\" later <<<payload || printf fallback >marker");
  expect_document_input(command("read"), "payload", 0, NULL, true);
  CHECK(document_write(command("fallback"), "marker"));
  parse("read first \"$target\" last <<<payload || printf fallback >marker");
  expect_document_input(command("read"), "payload", 0, NULL, true);
  CHECK(document_write(command("fallback"), "marker"));
  parse("read bad-name later <<<payload || printf fallback >marker");
  CHECK(inputs(command("read"), 0, NULL) == 0);
  CHECK(document_write(command("fallback"), "marker"));
  parse("read POSIXLY_CORRECT later <<<payload || printf fallback >marker");
  expect_document_input(command("read"), "payload", 0, NULL, true);
  CHECK(document_write(command("fallback"), "marker"));

  /* Polling ignores even unresolved targets, including a would-be write to
   * IFS or fd. A later use must still see the entry descriptor identity. */
  parse("exec {fd}<<<saved && { read -t0 first \"$target\" IFS fd <<<payload "
        "; read -u $fd result; }");
  expect_document_input(command("result"), "saved", SHELL_DEP_FD_NAMED, "fd",
                        true);
  CHECK(inputs(command("first"), 0, NULL) == 0);
  parse("read -t0 first \"$target\" last <<<payload && printf polled >marker");
  CHECK(document_write(command("polled"), "marker"));

  /* Each possible stopping point has its own write prefix. An earlier
   * unresolved target may itself name fd before a later target rejects, so
   * that failure does not promise an unchanged descriptor identity. */
  parse("read -n0 first \"$a\" middle \"$b\" last <<<payload "
        "|| printf fallback >marker");
  CHECK(document_write(command("fallback"), "marker"));
  current_source =
      "exec {fd}<<<saved && { read -n0 first \"$a\" middle \"$b\" fd "
      "<<<payload || read -u\"$fd\" result; }";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  parse("read -n0 first last <<<payload || printf impossible >marker");
  CHECK(!document_write(command("impossible"), "marker"));
  parse("read -n0 first bad-name last <<<payload && printf impossible >marker");
  CHECK(!document_write(command("impossible"), "marker"));
  /* Rejection ends target assignment, not the expansion of later arguments:
   * those substitutions have already run before the builtin validates names. */
  parse("read -n0 first \"$target\" \"$(printf expanded >expanded)\" "
        "<<<payload || printf fallback >marker");
  CHECK(document_write(command("expanded"), "expanded"));
  CHECK(document_write(command("fallback"), "marker"));
  parse("read -n0 first bad-name \"$(printf expanded >expanded)\" "
        "<<<payload || printf fallback >marker");
  CHECK(document_write(command("expanded"), "expanded"));
  CHECK(document_write(command("fallback"), "marker"));
  /* Captured empty words elide only when unquoted. The following first
   * literal target therefore writes fd; quoting the empty argument stops
   * assignment instead and preserves fd for the fallback. */
  static const char *const empty_words[] = {"$empty", "\"\"$empty"};
  for (size_t i = 0; i < sizeof(empty_words) / sizeof(empty_words[0]); i++) {
    char source[512];
    /* The closed-9 duplication certainly fails and has no model; the
     * elision under test needs only the unset variable. */
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved && { unset empty; "
             "read -n0 -- %s fd <<<payload "
             "|| read -u\"$fd\" result; }",
             empty_words[i]);
    parse(source);
    expect_document_input(command("result"), "saved", SHELL_DEP_FD_NAMED, "fd",
                          i != 0);
  }
  current_source = "read -n0 first \"$a\" middle \"$b\" last <<<payload "
                   "|| printf fallback >marker";
  static const unsigned node_limits[] = {0, 4, SHELL_DEP_MAX_NODES};
  static const unsigned edge_limits[] = {0, 6, SHELL_DEP_MAX_EDGES};
  for (size_t n = 0; n < sizeof(node_limits) / sizeof(node_limits[0]); n++)
    for (size_t e = 0; e < sizeof(edge_limits) / sizeof(edge_limits[0]); e++) {
      limits.max_nodes = node_limits[n];
      limits.max_edges = edge_limits[e];
      shell_dep_error_t status = shell_dep_graph_parse(
          current_source, strlen(current_source), "/", &limits, graph);
      CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
      CHECK(graph->node_count <= limits.max_nodes);
      CHECK(graph->edge_count <= limits.max_edges);
      CHECK(shell_dep_graph_validate(graph).valid);
    }
  limits.max_nodes = SHELL_DEP_MAX_NODES;
  limits.max_edges = SHELL_DEP_MAX_EDGES;
}

static void workspace_and_allocation(void) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  /* Each source is modeled; `|| true` handles the read errors of the
   * invalid targets (a descriptor number, /dev/fd/63). */
  static const char *const sources[] = {
      "exec {fd}< <(printf payload); echo \"$(read -u \"$fd\" value)\"",
      "exec {fd}<<<payload && { read -u\"$fd\" -- \"$fd\" || true; }",
      "exec {fd}<<<saved; export NA<()ME+<()=value; read -u\"$fd\" value",
      "read -t18446744073709551617 value <<<payload",
      "exec 3<&- 4<&- 63<&-; read -u63 value <(printf payload) || true",
      "value=$(< <()) || printf fallback >fallback",
      "read -n0 first \"$target\" last <<<payload || printf fallback >marker",
      ("exec {fd}<<<saved && { read -n0 first \"$target\" fd "
       "<<<payload || read -u\"$fd\" result; }"),
      "(exec 0<&-); time cat ${a:+<(:)} ${b:+<(:)}",
      "exec 0<&-; exec 0<input && echo \"$(< <(:))\"",
      ("cat ${a:+<(:)} ${b:+<(:)} ${c:+<(:)} ${d:+<(:)} "
       "${e:+<(:)} ${f:+<(:)} ${g:+<(:)} ${h:+<(:)}")};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    current_source = sources[i];
    shellsplit_test_alloc_reset();
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_fail_at(1);
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
  }
#endif
}

static void input_error_phases(void) {
  static const char *const reads[] = {
      "read -u3 out 3>writeonly", "read out 0<&-",
      "read -u3 out bad-name 3>writeonly", "read -t0 out 0<&-"};
  /* Reading a write-only or closed descriptor is a read error, handled
   * here by `|| true`; the failed read assigns nothing. */
  reject("exec {out}>out && { read -u3 out 3>writeonly; "
         "printf x >&\"$out\"; }");
  for (size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec {out}>out && { %s || true; printf x >&\"$out\"; }",
             reads[i]);
    parse(source);
    CHECK(document_write(command("printf"), "out"));
    CHECK(inputs(command("read"), 0, NULL) == 0);
  }
  /* A missing read descriptor fails before any assignment: reference Bash
   * leaves $out intact and takes rc=1, but the failed setup has no
   * dependency model (the zero-byte write-only form is separately EPARSE
   * per the assigns cases below). */
  reject("exec {out}>out && { read -u3 -n0 out 3<&-; "
         "printf x >&\"$out\"; }");
  static const char *const no_success[] = {
      "read -u3 value 3>writeonly && printf reached >reached",
      "read value 0<&- && printf reached >reached",
      "read -n0 value 0<&- && printf reached >reached",
      "read -u3 -n0 value 3>writeonly && printf reached >reached"};
  for (size_t i = 0; i < sizeof(no_success) / sizeof(no_success[0]); i++) {
    parse(no_success[i]);
    CHECK(!document_write(command("printf"), "reached"));
  }
  static const char *const assigns[] = {
      "read -n0 out 0<&-", "read -N0 out 0<&-", "read -u3 -n0 out 3>writeonly"};
  for (size_t i = 0; i < sizeof(assigns) / sizeof(assigns[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec {out}>out && { %s; printf x >&\"$out\"; }", assigns[i]);
    current_source = source;
    CHECK(shell_dep_graph_parse(source, strlen(source), "/", &limits, graph) ==
          SHELL_DEP_EPARSE);
  }
  parse("read -u3 -t0 value 3>writeonly && printf reached >reached");
  CHECK(document_write(command("printf"), "reached"));
}

static void group_reader_propagation(void) {
  static const char *const sources[] = {
      "{ exec 3<<<selected; read -u3 value; } <input",
      "{ >out; read -u3 value; } <input 3<<<selected",
      "{ read -n0 value; read -u3 value; } <input 3<<<selected",
      "{ read -z && cat; read -u3 value; } <input 3<<<selected",
      "{ { >out; }; read -u3 value; } <input 3<<<selected",
      "printf ignored | { exec 3<<<selected; read -u3 value; }"};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    parse(sources[i]);
    CHECK(document_input(command("-u3"), "selected"));
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      CHECK(
          !((edge->type == SHELL_EDGE_READ || edge->type == SHELL_EDGE_PIPE) &&
            edge->target_fd == 0 &&
            graph->nodes[edge->to].type == SHELL_NODE_GROUP));
    }
  }
}

static void process_descriptor_input(void) {
  current_source = "Bash process-body blank classification";
  CHECK(shell_source_empty_process_word("<( )", 4));
  CHECK(shell_source_empty_process_word("<(\t\n)", 5));
  CHECK(!shell_source_empty_process_word("<(\r)", 4));
  CHECK(!shell_source_empty_process_word("<(\v)", 4));
  CHECK(!shell_source_empty_process_word("<(\f)", 4));
  /* A process word after the targets is itself a target, /dev/fd/63: an
   * invalid name, so the read reports an error, which `|| true` handles. */
  reject("exec 3<&- 4<&- 63<&-; read -u63 value <(printf payload)");
  static const char *const sources[] = {
      "exec 3<&- 4<&- 63<&-; read -u63 value <(printf payload) || true",
      "exec 3<&- 4<&- 63<&-; read -p <(printf payload) -u63 value",
      "exec 3<&- 4<&- 63<&-; read -u63 <(printf payload) || true",
      ("exec 3<&- 4<&- 63<&-; read -u63 value 0<unused <(printf payload) "
       "|| true"),
      "exec 3<&- 4<&- 63<&-; time read -u63 value <(printf payload) || true",
      "exec 3<&- 4<&- 63<&-; { read -u63 value; } < <(printf payload)"};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    parse(sources[i]);
    unsigned count = inputs(command("read"), 63, NULL);
    CHECK(count == (i != 2));
    if (i != 2) {
      bool producer = false;
      for (uint32_t e = 0; e < graph->edge_count; e++)
        producer |= graph->edges[e].from == command("printf") &&
                    input_edge(&graph->edges[e], command("read"));
      CHECK(producer);
    }
  }
  current_source = "exec {out}>out && { exec 63<&-; "
                   "read -u63 out <(printf payload); printf x >&\"$out\"; }";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&- 4<&- 63<&-; : <(printf payload); read -u63 value && printf "
        "x >reached");
  /* Reference Bash lets the group's process substitution take the highest
   * free fd (63 here; verified 63, else 62/60 top-down), `exec 3<&63` dups it
   * persistently (inner rc=0), and the later `read -u3` consumes payload
   * (rc=1 only for the missing trailing newline). The analysis does not place
   * Bash's process-substitution descriptors exactly, so it cannot prove fd 63
   * present for the dup and conservatively reports no model. */
  reject("exec 3<&- 4<&- 63<&-; { exec 3<&63; } < <(printf payload); read -u3 "
         "value");
  parse("exec 3<&- 4<&- 63<&-; read -u63 value >(:) && printf x >reached");
  CHECK(inputs(command("read"), 63, NULL) == 0);
  CHECK(!document_write(command("printf"), "reached"));
  reject("exec 3<&- 4<&- 62<&- 63<&-; "
         "read -u62 value <(:) <(printf second)");
  /* Handled by `|| true`, the read error leaves a graph to inspect. */
  parse("exec 3<&- 4<&- 62<&- 63<&-; "
        "read -u62 value <(:) <(printf second) || true");
  bool second = false;
  for (uint32_t e = 0; e < graph->edge_count; e++)
    second |= graph->edges[e].from == command("second") &&
              input_edge(&graph->edges[e], command("read"));
  CHECK(second);
  parse("exec 3<&- 4<&- 63<&-; "
        "echo <(printf payload) \"$(read -u63 nested)\"");
  CHECK(inputs(command("read"), 63, NULL) == 1);
  reject("exec 3<&- 4<&- 63<&-; read -u63 value <()");
  parse("read value <() <<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  parse("read -p >( ) -u3 value <<<payload 3<<<unused");
  CHECK(inputs(command("read"), 0, NULL) == 1);
  reject("exec 3<&- 4<&- 63<&-; read -u63 value <( )");
  reject("exec 3<&- 4<&- 63<&-; read -u63 value <(exec 1>&-)");
  /* An empty process substitution has no pathname: reference Bash reports
   * "ambiguous redirect" and runs neither the read nor the guarded printf.
   * The certainly-failing setup has no dependency model. */
  reject("read value < <() && printf x >reached");
  parse("exec 3<&- 4<&- 63<&-; read -u63 value > <(printf payload)");
  CHECK(inputs(command("read"), 63, NULL) == 1);
  for (uint32_t e = 0; e < graph->edge_count; e++)
    CHECK(!(input_edge(&graph->edges[e], command("read")) &&
            graph->edges[e].from == command("read")));
  reject("exec 3<&- 4<&- 63<&-; read -u63 value <> >(:)");
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&- 4<&- 63<&-; 63<&- path=<(printf payload) "
        "read -u63 value && printf reached >reached");
  parse("exec 3<&- 4<&- 63<&-; 3<input path=<(printf payload) read -u63 value");
  CHECK(inputs(command("read"), 63, NULL) == 1);
}

static void conditional_process_input(void) {
  /* Reference Bash resolves `${choice:+<(:)}` to fd 63 (top-down
   * allocation) when present and leaves 63 closed otherwise: the zero-byte
   * read succeeds on the substitution path and fails with a shell-level
   * error elsewhere, which `&&` consumes: the success path exists only with
   * the substitution, the fallback only without it. */
  static const char *const values[] = {"${choice:+<(:)}", "${choice:-<(:)}",
                                       "${choice+<(:)}", "${choice-<(:)}",
                                       "${outer:+${inner:+<(:)}}"};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec 3<&- 4<&- 63<&-; path=%s read -u63 -n0 value "
             "&& printf success >success || printf fallback >fallback",
             values[i]);
    parse(source);
    CHECK(document_write(command("success"), "success"));
    CHECK(document_write(command("fallback"), "fallback"));
    snprintf(source, sizeof(source),
             "exec 3<&- 4<&- 63<&-; path=%s read -u63 -n0 value; "
             "printf success >success",
             values[i]);
    reject(source);
  }
  parse("exec 3<&- 4<&- 63<&-; path=<(:) read -u63 -n0 value "
        "|| printf fallback >fallback");
  CHECK(!document_write(command("fallback"), "fallback"));
  /* Each source below reads through fd 63 (or a nested guarded read of it)
   * where a conditional substitution provides that descriptor on some paths
   * only: rejected by the same descriptor rule. */
  static const char *const shared[] = {
      "${choice:+<(printf first)<(printf second)}",
      "${outer:+<(printf first)${inner:+<(printf second)}}"};
  for (size_t i = 0; i < sizeof(shared) / sizeof(shared[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec 3<&- 4<&- 62<&- 63<&-; path=%s read -u63 value", shared[i]);
    reject(source);
  }
  reject("exec 3<&- 4<&- 62<&- 63<&-; "
         "one=${a:+<(printf first)} two=${b:+<(printf second)} "
         "read -u63 value");
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&- 4<&- 63<&-; "
        "path=${choice:+<(:)$(read -u63 -n0 inner || printf bad >bad)} "
        "read -u63 -n0 value || printf fallback >fallback");
  reject("exec 3<&- 4<&- 63<&-; path=${choice:+<(:)} read -u63 -n0 value; "
         "read -u63 -n0 later && printf leaked >leaked");
  /* When the conditional substitution is present it takes 63, `exec 3<&63`
   * persists it to fd 3 and the read consumes payload; otherwise the dup
   * fails. A missing descriptor on one path rejects the input. */
  reject("exec 3<&- 4<&- 63<&-; "
         "{ exec 3<&63; } 0<${choice:+<(printf payload)}; read -u3 value");
  parse("exec 3<&- 4<&- 63<&-; echo \"$(<prefix<(:))\" "
        "\"$(read -u63 -n0 value || printf fallback >fallback)\"");
  CHECK(!document_write(command("fallback"), "fallback"));
  parse("exec 3<&- 4<&- 63<&-; echo \"$(< <(:))\" "
        "\"$(read -u63 -n0 value || printf fallback >fallback)\"");
  CHECK(!document_write(command("fallback"), "fallback"));
  /* The same conditional descriptor read through nested captures. */
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&- 4<&- 63<&-; "
        "echo \"$(<prefix${choice:+<(:)$(read -u63 -n0 inner "
        "|| printf bad >bad)})\" "
        "\"$(read -u63 -n0 value || printf fallback >fallback)\"");
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&- 4<&- 63<&-; "
        "path=${choice:+<(:)$(<prefix$(read -u63 -n0 inner "
        "|| printf bad >bad))} read -u63 -n0 value "
        "|| printf fallback >fallback");
}

static void independent_process_guards(void) {
  static const char *const contexts[] = {
      "%s", "{ %s; }", "(%s)", "time { %s; }", "%s", "%s", "%s", "%s"};
  static const char *const words[] = {
      " ${v%u:+<(printf p%u)}", " ${v%u:+<(printf ignored >sink; printf p%u)}",
      " ${v%u:+<(printf p%u 2>sink)}",
      " ${v%u:+<(read -n0 value >sink; printf p%u)}"};
  for (size_t context = 0; context < sizeof(contexts) / sizeof(contexts[0]);
       context++) {
    size_t previous_source = 0, previous_routes = 0;
    for (unsigned count = 4; count <= 16; count *= 2) {
      char body[2048] = "cat", source[2304];
      size_t length = strlen(body);
      for (unsigned i = 0; i < count; i++)
        length += (size_t)snprintf(
            body + length, sizeof(body) - length,
            words[context < 4 || context == 7 ? 0 : context - 3], i, i);
      if (context == 7)
        snprintf(body + length, sizeof(body) - length, " 2>sink");
      /* The later, unrelated read must not make these private ends observed.
       * Its descriptor is installed before cat, not by one of its pipes. */
      char commands[2200];
      snprintf(commands, sizeof(commands),
               "exec 3<<<payload; %s; read -u3 later_value", body);
      snprintf(source, sizeof(source), contexts[context], commands);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      parse(source);
      unsigned producers = 0;
      for (uint32_t e = 0; e < graph->edge_count; e++) {
        const shell_dep_edge_t *edge = &graph->edges[e];
        if (edge->to == command("cat") && edge->type == SHELL_EDGE_SUBST) {
          CHECK(edge->target_fd == SHELL_DEP_FD_NONE);
          CHECK(!(edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD));
          producers++;
        }
      }
      CHECK(producers == count);
      CHECK(document_input(command("later_value"), "payload"));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t source_work = shellsplit_test_source_scan_work();
      size_t route_work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES) +
          shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_ROUTE_ALTERNATIVES);
      CHECK(source_work && route_work);
      CHECK(!previous_source || source_work <= 3 * previous_source);
      CHECK(!previous_routes || route_work <= 3 * previous_routes);
      previous_source = source_work;
      previous_routes = route_work;
#else
      (void)previous_source;
      (void)previous_routes;
#endif
    }
  }
}

static void observe_process_token(const shell_token_t *token, void *context) {
  (void)token;
  (void)context;
}

static void observe_process_read(const char *word, uint32_t fd, unsigned kind,
                                 const char *parameter, size_t length,
                                 bool identity, void *context) {
  (void)word;
  (void)fd;
  (void)kind;
  (void)parameter;
  (void)length;
  (void)identity;
  (void)context;
}

typedef struct {
  unsigned count, nonempty;
} process_census_t;

static void observe_process_expansion(const char *word, size_t length,
                                      void *context) {
  process_census_t *census = context;
  census->count++;
  census->nonempty += !shell_source_empty_process_word(word, length);
}

static void semantic_process_inventory(void) {
  static const struct {
    const char *source;
    unsigned count, nonempty;
  } cases[] = {{"cat <(:) >(:)", 2, 2},
               {"cat ${choice:+<(:)}", 1, 1},
               {"cat ${outer:+<(:)${inner:+>(:)}}", 2, 2},
               {"echo \"$(cat ${choice:+<(:)})\"", 1, 1},
               {"echo \"$(< <(:))\"", 1, 1},
               {"cat '<(:)' \"<(:)\" # <(:)\n", 0, 0},
               {"cat <() <( \n) <(# comment\n) >()", 4, 0},
               {"cat <<'EOF'\n${choice:+<(:)}\nEOF\n", 0, 0},
               {"cat <<EOF\n$(cat <(:))\nEOF\n", 1, 1}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    current_source = cases[i].source;
    process_census_t census = {0};
    CHECK(shell_tokenizer_inspect_semantics(
              current_source, strlen(current_source), observe_process_token,
              observe_process_read, observe_process_expansion, NULL, NULL,
              &census) == SHELL_SEMANTIC_OK);
    CHECK(census.count == cases[i].count);
    CHECK(census.nonempty == cases[i].nonempty);
  }
}

static void independent_lifetime_guards(void) {
  static const char *const contexts[] = {"time %s",
                                         ": 0<&-; %s",
                                         "(exec 0<&-); %s",
                                         "{ :; } 0<&-; %s",
                                         "exec 0<&-; exec 0<<<restored && %s",
                                         "exec 0<&-; exec 0<input && %s",
                                         "false && exec 0<&-; %s"};
  for (size_t context = 0; context < sizeof(contexts) / sizeof(contexts[0]);
       context++) {
    size_t previous_source = 0, previous_routes = 0;
    for (unsigned count = 4; count <= 16; count *= 2) {
      char body[2048] = "cat", source[2304];
      size_t length = strlen(body);
      for (unsigned i = 0; i < count; i++)
        length += (size_t)snprintf(body + length, sizeof(body) - length,
                                   " ${v%u:+<(printf p%u)}", i, i);
      snprintf(source, sizeof(source), contexts[context], body);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      parse(source);
      unsigned producers = 0;
      for (uint32_t e = 0; e < graph->edge_count; e++) {
        const shell_dep_edge_t *edge = &graph->edges[e];
        if (edge->to == command("cat") && edge->type == SHELL_EDGE_SUBST) {
          CHECK(edge->target_fd == SHELL_DEP_FD_NONE);
          producers++;
        }
      }
      CHECK(producers == count);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t source_work = shellsplit_test_source_scan_work();
      size_t route_work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES) +
          shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_ROUTE_ALTERNATIVES);
      CHECK(source_work && route_work);
      CHECK(!previous_source || source_work <= 3 * previous_source);
      CHECK(!previous_routes || route_work <= 3 * previous_routes);
      previous_source = source_work;
      previous_routes = route_work;
#else
      (void)previous_source;
      (void)previous_routes;
#endif
    }
  }
}

static void conditional_low_pipe_fallback(void) {
  static const char *const values[] = {
      "${choice:+<(printf payload)}",
      "${outer:+${inner:+<(printf payload)}}",
      "${choice:+<()}",
      "${choice:+<(# comment\n)}",
      "${choice:+>(read child_value)}",
      "${outer:+${inner:+>(read child_value)}}"};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    char source[4096] = "";
    size_t length = 0;
    for (unsigned fd = 3; fd < 64; fd++) {
      if ((fd - 3) % 8 == 0)
        length +=
            (size_t)snprintf(source + length, sizeof(source) - length, "exec");
      length += (size_t)snprintf(source + length, sizeof(source) - length,
                                 " %u<>/dev/null", fd);
      if ((fd - 3) % 8 == 7 || fd == 63)
        length +=
            (size_t)snprintf(source + length, sizeof(source) - length, "; ");
    }
    snprintf(source + length, sizeof(source) - length,
             /* Without the substitution stdin stays closed: the read
              * error there is handled by `|| true`. */
             i < 4 ? "exec 0<&-; path=%s read value || true"
                   : "exec 0<&- 1>&-; path=%s printf payload",
             values[i]);
    parse(source);
    if (i >= 4) {
      bool output = false;
      for (uint32_t e = 0; e < graph->edge_count; e++) {
        const shell_dep_edge_t *edge = &graph->edges[e];
        if (edge->from != command("printf") || edge->type != SHELL_EDGE_WRITE ||
            edge->source_fd != 1)
          continue;
        for (uint32_t s = 0; s < graph->edge_count; s++) {
          const shell_dep_edge_t *sink = &graph->edges[s];
          output |= sink->from == edge->to &&
                    sink->to == command("child_value") &&
                    sink->type == SHELL_EDGE_SUBST &&
                    !(sink->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
        }
      }
      CHECK(output);
      continue;
    }
    CHECK(inputs(command("read"), 0, NULL) == (i < 2));
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      if (input_edge(edge, command("read"))) {
        CHECK(edge->from == command("payload"));
        CHECK(!(edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD));
      }
    }
  }
}

static void empty_file_process_substitution(void) {
  static const char *const operands[] = {
      "<()", "<( )", "<(\t\n)", "<(# comment\n)", "<(\\\n)",
      ">()", ">( )", ">(\t\n)", ">(# comment\n)", ">(\\\n)"};
  for (size_t i = 0; i < sizeof(operands) / sizeof(operands[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "value=$(< %s) && printf success >success "
             "|| printf fallback >fallback",
             operands[i]);
    parse(source);
    CHECK(!document_write(command("success"), "success"));
    CHECK(document_write(command("fallback"), "fallback"));
    for (uint32_t e = 0; e < graph->edge_count; e++)
      CHECK(graph->edges[e].type != SHELL_EDGE_SUBST);
    snprintf(source, sizeof(source),
             "printf '%%s' \"$(< %s)\" && printf success >success",
             operands[i]);
    parse(source);
    CHECK(document_write(command("success"), "success"));
    snprintf(source, sizeof(source),
             "echo \"$(value=$(< %s) || printf fallback >fallback)\"",
             operands[i]);
    parse(source);
    CHECK(document_write(command("fallback"), "fallback"));
    snprintf(source, sizeof(source), "{ value=$(< %s); } 2>err", operands[i]);
    parse(source);
    bool diagnostic = false;
    for (uint32_t n = 0; n < graph->node_count; n++)
      if (graph->nodes[n].type == SHELL_NODE_CMD &&
          graph->nodes[n].cmd.token_count == 0)
        diagnostic |= document_write(n, "err");
    CHECK(diagnostic);
  }
  parse("value=$(< <(:)) && printf success >success");
  CHECK(document_write(command("success"), "success"));
  parse("echo \"$(\n# comment\n)\"");
  static const char *const incomplete[] = {
      "value=$(< <(: &&\n))", "value=$(< <(: |\n))", "value=$(< <(!\n))",
      "echo \"$(echo &&\n)\""};
  for (size_t i = 0; i < sizeof(incomplete) / sizeof(incomplete[0]); i++) {
    current_source = incomplete[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
}

static void inline_document_setup(void) {
  static const char *const sources[] = {"cat <<<first <<<second",
                                        "cat <<A <<B\nfirst\nA\nsecond\nB\n",
                                        "read -n0 value <<<first"};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    parse(sources[i]);
    bool first = false;
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      const shell_dep_node_t *node = &graph->nodes[edge->from];
      if (node->type != SHELL_NODE_DOC ||
          node->doc.value_len != (i == 1 ? 6u : 5u) || !node->doc.value ||
          memcmp(node->doc.value, "first", 5))
        continue;
      CHECK(edge->type == SHELL_EDGE_FD_OPEN);
      CHECK(edge->target_fd == 0);
      CHECK(node->doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT);
      first = true;
    }
    CHECK(first);
    if (i < 2)
      CHECK(document_input(command("cat"), i == 1 ? "second\n" : "second"));
    else
      CHECK(inputs(command("read"), 0, NULL) == 0);
  }
}

static void bounded_work(void) {
  /* High-FD occupancy pressure is linear source processing: sixteen static
   * substitutions pin the top-down allocator while the read resolves its
   * descriptor. The precise model may exhaust its fixed decision pool; that
   * must terminate atomically and agree with supplied-fast parsing. (The
   * conditional `${choice:+...}` variant is EUNMODELED: dynamic
   * substitution fds do not resolve; see conditional_process_input.) */
  char uncertain[2048] = "exec 3<&- 4<&- 63<&-; path=";
  for (unsigned i = 0; i < 16; i++)
    strcat(uncertain, "<(:)");
  strcat(uncertain, " read -u63 -n0 value");
  current_source = uncertain;
  shell_dep_error_t pressure =
      shell_dep_graph_parse(uncertain, strlen(uncertain), "/", &limits, graph);
  CHECK(pressure == SHELL_DEP_OK || pressure == SHELL_DEP_ETRUNC);
  CHECK(shell_dep_graph_validate(graph).valid);
  if (pressure == SHELL_DEP_ETRUNC) {
    CHECK(graph->status == SHELL_DEP_STATUS_TRUNCATED);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }
  shell_parse_result_t fast;
  CHECK(shell_parse_fast(uncertain, strlen(uncertain), NULL, &fast) ==
        SHELL_OK);
  CHECK(shell_dep_graph_parse_with_fast(uncertain, strlen(uncertain), "/",
                                        &limits, &fast, other) == pressure);
  CHECK(shellsplit_test_graph_equal(graph, other));
  parse("read value <<<recovered");
  CHECK(document_input(command("value"), "recovered"));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (unsigned family = 0; family < 6; family++) {
    size_t previous_source = 0, previous_read = 0, previous_routes = 0;
    for (unsigned count = 4; count <= 16; count *= 2) {
      char source[2048] = "exec 3<<<payload; ";
      if (family == 0) {
        strcat(source, "read ");
        for (unsigned i = 0; i < count; i++)
          strcat(source, "-r ");
        strcat(source, "-u3 value");
      } else if (family == 1) {
        for (unsigned i = 0; i < count; i++)
          strcat(source, "read -u3 value; ");
      } else if (family == 2) {
        /* Unknown targets may be invalid: `|| true` handles that error. */
        strcat(source, "read -u3 -- first ");
        for (unsigned i = 0; i < count; i++)
          strcat(source, "\"$unknown\" ");
        strcat(source, "|| true");
      } else if (family == 3) {
        strcpy(source, "exec 3<&- 4<&- 63<&-");
        /* Sixteen known free high slots keep this a linear-work test rather
         * than a growing set of unknown inherited allocation worlds. The
         * substitutions are static so their descriptors resolve (reference
         * Bash pins them top-down from 63); the conditional
         * `${choice:+...}` form leaves fd 63 unresolvable and has no model.
         * Sequential `path=<(:) :;` forms are dead by read time: a
         * command-scoped substitution closes when its command completes
         * (reference Bash: "invalid file descriptor"), so only the
         * read-prefixed accumulation below keeps every end live. */
        for (unsigned fd = 48; fd < 63; fd++) {
          char close[16];
          snprintf(close, sizeof(close), " %u<&-", fd);
          strcat(source, close);
        }
        strcat(source, "; path=");
        for (unsigned i = 0; i < count; i++)
          strcat(source, "<(:)");
        strcat(source, " read -u63 -n0 value");
      } else if (family == 4) {
        /* Each iteration redirects stdin from a fresh static substitution
         * and reads a byte through fd 63: every end is live at its read
         * (reference Bash resolves each to fd 63 in turn and assigns the
         * byte). The conditional `${choice:+...}` form and the
         * `path=<(:) :;` accumulation are unmodelable or dead by read
         * time (see family 3). */
        strcpy(source, "exec 3<&- 4<&- 63<&-; ");
        for (unsigned i = 0; i < count; i++)
          strcat(source, "< <(printf payload) read -u63 -n1 value; ");
      } else {
        strcat(source, "export NA");
        for (unsigned i = 0; i < count; i++)
          strcat(source, "<()>()");
        strcat(source, "ME=value; read -u3 value");
      }
      shellsplit_test_source_scan_reset();
      parse(source);
      size_t source_work = shellsplit_test_source_scan_work();
      size_t read_work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_READ_INPUT);
      size_t route_work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
      CHECK(source_work && read_work && route_work);
      CHECK(read_work <= 128 * (count + 6));
      CHECK(!previous_source || source_work <= 3 * previous_source);
      CHECK(!previous_read || read_work <= 3 * previous_read);
      CHECK(!previous_routes || route_work <= 3 * previous_routes);
      previous_source = source_work;
      previous_read = read_work;
      previous_routes = route_work;
    }
  }
#endif
}

static void original_pipe_end_fallback(void) {
  char source[4096] = "";
  size_t length = 0;
  for (unsigned fd = 3; fd < 62; fd++)
    length += (size_t)snprintf(source + length, sizeof(source) - length,
                               "exec %u<>/dev/null; ", fd);
  /* Reference Bash places this word-position substitution on fd 62 (verified
   * /dev/fd/62; the read assigns payload before failing on the extra
   * variable), but the placement depends on Bash's fd-table history: the
   * same substitution takes 63 when high fds were explicitly closed or never
   * touched. The analysis does not place Bash's process-substitution
   * descriptors exactly, so it conservatively reports no model. */
  snprintf(source + length, sizeof(source) - length,
           "exec 62<&- 63<&-; read -u62 value <(printf payload)");
  reject(source);
  length = 0;
  for (unsigned fd = 3; fd < 64; fd++) {
    if ((fd - 3) % 8 == 0)
      length +=
          (size_t)snprintf(source + length, sizeof(source) - length, "exec");
    length += (size_t)snprintf(source + length, sizeof(source) - length,
                               " %u<>/dev/null", fd);
    if ((fd - 3) % 8 == 7 || fd == 63)
      length +=
          (size_t)snprintf(source + length, sizeof(source) - length, "; ");
  }
  /* Reference Bash creates the substitution pipe on the lowest free pair (2
   * and 64 here: 3-63 are all open), so `read -u2` consumes payload
   * (verified value=[payload], rc=1 for the missing newline). The analysis
   * does not place Bash's pipe ends exactly, so it cannot prove fd 2 present
   * and conservatively reports no model. */
  snprintf(source + length, sizeof(source) - length,
           "exec 2>&-; time { read -u2 value; } < <(printf payload)");
  reject(source);
  /* An inherited table with every low/high slot occupied can keep a pipe
   * above the move-to-high search range. Retain that feasible input route. */
  reject("exec 64<&-; read -u64 value <(printf payload)");
  /* The read error is handled: its status is consumed. */
  parse("exec 65<&-; read -u65 value >(:) && printf reached >reached");
  /* Even an otherwise unobserved end can become an ordinary standard stream
   * after an earlier close when Bash cannot move it into the high-FD range. */
  source[0] = '\0';
  length = 0;
  for (unsigned fd = 3; fd < 64; fd++)
    length += (size_t)snprintf(source + length, sizeof(source) - length,
                               "exec %u<>/dev/null; ", fd);
  snprintf(source + length, sizeof(source) - length,
           "exec 0<&-; cat <(printf payload)");
  parse(source);
  bool standard = false;
  for (uint32_t e = 0; e < graph->edge_count; e++) {
    const shell_dep_edge_t *edge = &graph->edges[e];
    standard |= edge->type == SHELL_EDGE_SUBST &&
                edge->from == command("payload") &&
                edge->to == command("cat") && edge->target_fd == 0;
  }
  CHECK(standard);
}

static void capacities(void) {
  static const char *const sources[] = {
      "read -u3 value 3<input <unused",
      "exec {fd}< <(printf payload); read -u \"$fd\" value",
      "printf ignored | { read -u3 value; } 3<input",
      /* The `test ... || exec 3<<<payload` conditional-open variant is
       * EUNMODELED (read missing on the closed path; see
       * conditional_descriptor_versions), so
       * capacities scales the unconditional open instead. */
      "exec 3<<<payload; read -u3 value",
      "exec {fd}<<<payload && read -p\"$fd\" -u\"$fd\" value <unused",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value <unused",
      "read -t4294967296 value <input",
      /* Empty (`<()`) and conditional (`${choice:+...}`) substitution
       * reads are EUNMODELED (see conditional_process_input and the
       * dedicated rejects); capacities only scales modelable sources. */
      "exec 3<&- 4<&- 63<&-; read -u63 value <(printf payload) || true",
      "exec 3<&- 4<&- 63<&-; read -u63 value > <(printf payload)",
      "read -t18446744073709551617 value <input && echo x >reached",
      "cat <<<first <<<second",
      "value=$(< <()) && printf success >success || printf fallback >fallback",
      "value=$(< >( )) && printf success >success || printf fallback >fallback",
      "time cat ${a:+<(:)} ${b:+<(:)} ${c:+<(:)} ${d:+<(:)}",
      "(exec 0<&-); cat ${a:+<(:)} ${b:+<(:)} ${c:+<(:)} ${d:+<(:)}",
      ("cat ${a:+<(:)} ${b:+<(:)} ${c:+<(:)} ${d:+<(:)} "
       "${e:+<(:)} ${f:+<(:)} ${g:+<(:)} ${h:+<(:)}"),
      ("exec 3<&- 4<&- 63<&-; echo \"$(<prefix<(:))\" "
       "\"$(read -u63 -n0 value || printf fallback >fallback)\""),
      /* The dynamic-substitution group-dup variant is EUNMODELED (see
       * conditional_process_input); capacities only scales modelable
       * sources. */
      ("exec {input}<<<payload {out}>out && { "
       "read -u\"$input\" -- first \"$input\" out || true; "
       "printf x >&\"$out\"; }"),
      ("{ time printf payload; } 2>&1 | "
       "{ exec {fd}<&0; read -u\"$fd\" value; }")};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++)
    for (unsigned n = 0; n <= 10; n++)
      for (unsigned e = 0; e <= 14; e++) {
        current_source = sources[i];
        limits.max_nodes = n;
        limits.max_edges = e;
        shell_dep_error_t status = shell_dep_graph_parse(
            current_source, strlen(current_source), "/", &limits, graph);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(graph->node_count <= n && graph->edge_count <= e);
        CHECK(shell_dep_graph_validate(graph).valid);
      }
  limits.max_nodes = SHELL_DEP_MAX_NODES;
  limits.max_edges = SHELL_DEP_MAX_EDGES;
}

static void unknown_occupancy_capacity(void) {
  /* Unlike the checkpoint-growth fixture, leave every inherited descriptor
   * unknown. Resource exhaustion must remain an atomic, valid graph result. */
  static const char *const unknown_occupancy[] = {
      "probe 9> >(true) 8> >(true) 7> >(true) 6> >(true) "
      "5> >(true) 4> >(true) 3> >(true) 2> >(true)",
      "probe 3<> >(cat) 4<> >(cat) 5<> >(cat) 6<> >(cat) "
      "7<> >(cat) 8<> >(cat) 9<> >(cat) 10<> >(cat) &>combined",
      "exec 9>&-; exec 10>base || exit; exec {f11}>initial || exit; "
      "true {f0}>out0 {f1}>out1 {f2}>out2 {f3}>out3 {f4}>out4 {f5}>out5 "
      "{f6}>out6 {f7}>out7 {f8}>out8 {f9}>out9 {f10}>out10 {f11}>out11 "
      "&& printf value >&$f11"};
  for (size_t i = 0;
       i < sizeof(unknown_occupancy) / sizeof(unknown_occupancy[0]); i++) {
    current_source = unknown_occupancy[i];
    shell_dep_error_t bounded = shell_dep_graph_parse(
        current_source, strlen(current_source), "/", &limits, graph);
    CHECK(bounded == SHELL_DEP_OK || bounded == SHELL_DEP_ETRUNC);
    CHECK(shellsplit_test_depgraph_invariants(
        current_source, strlen(current_source), bounded, graph, &limits));
  }
}

/* The second process word is an invalid read target (`/dev/fd/62`), a
 * reported read error which `|| true` handles. */
static void process_lifetime_pressure(void) {
  for (unsigned side = 0; side < 2; side++) {
    size_t previous = 0;
    for (unsigned count = 0; count <= 16; count = count ? count * 2 : 4) {
      char source[2048] = "exec 10<&-; ";
      size_t length = strlen(source);
      if (!side)
        length += (size_t)snprintf(source + length, sizeof(source) - length,
                                   "read -n0 -u63 value <(:) <(:) || true; ");
      for (unsigned i = 0; i < count; i++)
        length += (size_t)snprintf(source + length, sizeof(source) - length,
                                   ": <(:); ");
      if (side)
        snprintf(source + length, sizeof(source) - length,
                 "read -n0 -u63 value <(:) <(:) || true");
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      parse(source);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
      /* Growth must stay linear in the substitution count. Compare its
       * doublings: without substitutions only a small fixed cost remains,
       * so the step from none to four is not one. */
      CHECK(count <= 4 || work <= 3 * previous);
      previous = work;
#else
      (void)previous;
#endif
    }
  }
  for (unsigned count = 4; count <= 16; count *= 2) {
    char source[2048] = "exec 3<&- 4<&- 63<&-; ";
    size_t length = strlen(source);
    for (unsigned i = 0; i < count; i++)
      length += (size_t)snprintf(source + length, sizeof(source) - length,
                                 "path=${v%u:+<(:)} read -u63 -n0 value; ", i);
    snprintf(source + length, sizeof(source) - length, "read -u63 later");
    /* Every substitution has closed again: a certain descriptor error. */
    reject(source);
  }
}

static void process_correlation_limits(void) {
  static const char *const sources[] = {
      "exec 3<&- 4<&- 63<&-; : ${choice:+<(:)} "
      "\"$(read -u63 -n0 first || read -u63 second)\"",
      "exec 3<&- 63<&-; : <(:) <(:) "
      "\"$(read -u3 -n0 probe && read -u62 value)\""};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++)
    for (unsigned n = 0; n <= 10; n++)
      for (unsigned e = 0; e <= 14; e++) {
        current_source = sources[i];
        limits.max_nodes = n;
        limits.max_edges = e;
        shell_dep_error_t status = shell_dep_graph_parse(
            current_source, strlen(current_source), "/", &limits, graph);
        /* Both sources read a closed descriptor on every path reaching it. */
        CHECK(status == SHELL_DEP_EUNMODELED || status == SHELL_DEP_ETRUNC);
        CHECK(graph->node_count <= n && graph->edge_count <= e);
        CHECK(shell_dep_graph_validate(graph).valid);
      }
  limits.max_nodes = SHELL_DEP_MAX_NODES;
  limits.max_edges = SHELL_DEP_MAX_EDGES;
}

static void allocation_routing_contract(void) {
  /* Each probe reads fd 3 after closing it. The read error is handled by
   * `&&`, so the input is modeled, but the probe never succeeds: nothing
   * after it runs, whatever allocations its continuation would make. */
  static const char *const sources[] = {
      "exec 3<&-; : <(:) \"$(read -u3 -n0 probe && "
      "read -u11 value {fd}<<<payload)\"",
      "exec 3<&- 11<>/dev/null && exec {a}<<<first && "
      "{ exec 11<&-; : <(:) \"$(read -u3 -n0 probe && "
      "{ exec {a}<&-; read -u11 value {b}<<<payload; })\"; }",
      "exec 3<&-; : <(:) \"$(read -u3 -n0 probe && "
      "{ exec 8>&9- && read -u11 value {fd}<<<payload; })\"",
      "exec 3<&- 11<&-; : <(:) \"$(read -u3 -n0 probe && "
      "{ exec 8>&9- && read -u11 value {fd}<<<payload; })\""};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    parse(sources[i]);
    expect_document_input(command("value"), "payload", 11, NULL, false);
  }
}

static void allocation_path_correlation(void) {
  static const char *const reuse[] = {
      /* Closed-then-rebound names resolve through retained values
       * resolves to the rebound descriptor in Bash (the name retains its
       * value), and the read path follows it to the rebound binding. */
      "exec {a}<<<first; exec {a}<&-; exec {b}<<<second; read -u\"$a\" value",
      "exec {a}<<<first; : \"$(exec {a}<&-; exec {b}<<<second; read -u\"$a\" "
      "value)\"",
      "exec {a}<<<first; : \"$(: \"$(exec {a}<&-; exec {b}<<<second; read "
      "-u\"$a\" value)\")\"",
      "exec 3<&- 10<&- && exec {a}<<<first && exec {a}<&- && exec {b}<<<second "
      "&& read -u\"$a\" value {a}<<<third",
      "exec {a}<<<first; exec {b}<&\"$a\"; exec {a}<&-; read -u\"$b\" value",
      "exec {a}<<<first && exec {a}<&-; : \"$(exec {b}<<<second; read -u\"$a\" "
      "value)\""};
  for (size_t i = 0; i < sizeof(reuse) / sizeof(reuse[0]); i++) {
    parse(reuse[i]);
    if (i == 4) {
      /* The named copy chain marks the heredoc open required: without it
       * $a stays unset, the copy fails, and the read sees nothing. */
      expect_document_input_flags(command("value"), "first", SHELL_DEP_FD_NAMED,
                                  "b", true, SHELL_DEP_EDGE_FLAG_REQUIRED);
      continue;
    }
    /* Unless an `&&` chain guards the read, the here-string openings it
     * depends on are required: where `second` fails, `$a` names the closed
     * descriptor that `{b}` would have taken. */
    expect_document_input_flags(
        command("value"), "second", SHELL_DEP_FD_NAMED, "a", true,
        i == 3 ? SHELL_DEP_EDGE_FLAG_NONE : SHELL_DEP_EDGE_FLAG_REQUIRED);
    if (i == 3)
      expect_document_input(command("value"), "third", SHELL_DEP_FD_NAMED, "a",
                            false);
  }
  /* A read of the closed descriptor inside the substitution certainly fails
   * (reference Bash reports "Bad file descriptor" and runs `:` with rc=0):
   * a shell-level error which no dependency graph models. */
  reject("exec {a}<<<first && exec {a}<&-; "
         ": <(printf payload) \"$(read -u\"$a\" value)\"");
  static const char *const operands[] = {"{fd}<<<payload", "{fd}<input",
                                         "{fd}<>input"};
  static const char *const probes[] = {"-u3 -n0", "-u3 -N0"};
  for (size_t p = 0; p < sizeof(probes) / sizeof(probes[0]); p++)
    for (size_t i = 0; i < sizeof(operands) / sizeof(operands[0]); i++) {
      char source[512];
      snprintf(source, sizeof(source),
               "exec 11<input; : <(:) \"$(read %s probe && "
               "read -u11 value %s)\"",
               probes[p], operands[i]);
      /* The probe reads the closed fd 3; `&&` handles that read error, so
       * nothing after the probe runs. */
      parse(source);
    }
  /* Bash parks the here-string document on the lowest free fd, so the named
   * allocation lands one higher (11 here) and the read sees it. The analysis
   * does not place Bash's here-document descriptors exactly, so it cannot
   * prove fd 11 present and conservatively reports no model. */
  reject("exec 3<>/dev/null 4<>/dev/null 5<>/dev/null 6<>/dev/null "
         "7<>/dev/null 8<>/dev/null 9<>/dev/null 10<&- 11<&-; "
         "read -u11 value {fd}<<<payload");
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&-; : <(:) \"$(read -u3 -n0 probe && "
        "{ exec {fd}<<<payload && read -u\"$fd\" value; })\"");
  /* Independent named lifetimes are not process-pipe reverse cleanup. */
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&-; : <(:) \"$(read -u3 -n0 probe && "
        "{ exec {a}<<<first {b}<<<second && "
        "{ exec {a}<&-; read -u\"$b\" value; }; })\"");
  for (unsigned close_first = 0; close_first < 2; close_first++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec 3<&- 11<&-; : <(:) \"$(read -u3 -n0 probe && "
             "{ exec 9<&-; exec {a}<<<first {b}<<<second && "
             "{ exec {%s}<&-; read -u\"$%s\" value; }; })\"",
             close_first ? "a" : "b", close_first ? "b" : "a");
    /* The handled probe error leaves the rest unreachable. */
    parse(source);
  }
  /* Temporary saves also cannot select a second free high slot from mutually
   * exclusive availability facts after the fd-3 probe. */
  /* The read error is handled: its status is consumed. */
  parse("exec 11<input; : <(:) \"$(read -u3 -n0 probe && "
        "{ read -u11 value; } 0<<<payload)\"");
  /* The read error is handled: its status is consumed. */
  parse("exec 11<input; : <(:) \"$(read -u3 -n0 probe && "
        "{ read -u11 value; } 8<<<payload)\"");
  /* The read error is handled: its status is consumed. */
  parse("exec 11<input; : <(printf payload) "
        "\"$(read -u3 -n0 probe && read -u11 value {fd}<&3)\"");
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&- 11<&-; : <(printf payload) "
        "\"$(read -u3 -n0 probe && { exec {fd}<&3 && "
        "{ exec 3<&-; read -u\"$fd\" value; }; })\"");
}

static void allocation_correlation_limits(void) {
  static const char *const sources[] = {
      "exec 3<&- 11<>/dev/null && exec {a}<<<first && "
      "{ exec 11<&-; : <(:) \"$(read -u3 -n0 probe && "
      "{ exec {a}<&-; read -u11 value {b}<<<payload; })\"; }",
      "exec 11<input; : <(:) \"$(read -u3 -n0 probe && "
      "read -u11 value {fd}<<<payload)\"",
      "exec 11<input; : <(:) \"$(read -u3 -n0 probe && "
      "{ exec 8>&9- && read -u11 value {fd}<<<payload; })\""};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++)
    for (unsigned n = 8; n <= 16; n += 4)
      for (unsigned e = 8; e <= 24; e += 4) {
        current_source = sources[i];
        limits.max_nodes = n;
        limits.max_edges = e;
        shell_dep_error_t status = shell_dep_graph_parse(
            current_source, strlen(current_source), "/", &limits, graph);
        /* Each probe reads the closed fd 3, a read error `&&` handles. */
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(graph->node_count <= n && graph->edge_count <= e);
        CHECK(shell_dep_graph_validate(graph).valid);
      }
  limits.max_nodes = SHELL_DEP_MAX_NODES;
  limits.max_edges = SHELL_DEP_MAX_EDGES;
}

static void allocation_alias_imports(void) {
  /* A free low resource slot and free fd 63 bound the selected identities to
   * 10..63, including hidden 10..62 choices. Without this bound the high-tail
   * approximation legitimately retains additional alias alternatives. */
  static const char prefix[] =
      "exec 3<&- 63<&- && exec {a}<<<first && exec {a}<&- && "
      "exec {b}<<<second && ";
  for (unsigned depth = 1; depth <= 2; depth++)
    for (unsigned scenario = 0; scenario < 6; scenario++) {
      char body[1024], source[1536];
      const char *name = scenario & 1u ? "b" : "a";
      if (scenario < 2)
        snprintf(body, sizeof(body),
                 "exec {%s}<&-; read -u\"$%s\" child && "
                 "printf forbidden >forbidden",
                 name, scenario & 1u ? "a" : "b");
      else
        snprintf(body, sizeof(body),
                 "read -u\"$%s\" child {a}<<<third %s "
                 "read -u\"$a\" rebound",
                 name, scenario < 4 ? "&&" : ";");
      for (unsigned level = 0; level < depth; level++) {
        char nested[1024];
        int written = snprintf(nested, sizeof(nested), ": \"$(%s)\"", body);
        CHECK(written >= 0 && (size_t)written < sizeof(nested));
        memcpy(body, nested, (size_t)written + 1);
      }
      int written = snprintf(source, sizeof(source),
                             "%s%s && read -u\"$b\" parent", prefix, body);
      CHECK(written >= 0 && (size_t)written < sizeof(source));
      /* b reuses a's descriptor exactly, so closing one name in the child
       * makes reading the other a descriptor error, which `&&` handles. */
      parse(source);
      /* Child close/rebind operations must not escape into its parent. */
      expect_document_input(command("parent"), "second", SHELL_DEP_FD_NAMED,
                            "b", true);
      expect_document_input(command("parent"), "third", SHELL_DEP_FD_NAMED, "b",
                            false);
      /* b reused a's closed descriptor, but each has several possible
       * places, and their equality is a relation between two slots that
       * per-descriptor places do not keep. The child therefore keeps the
       * paths on which closing one name leaves the other open, and the
       * rebinding of a may share the old a's place. */
      if (scenario >= 2) {
        expect_document_input(command("child"), "second", SHELL_DEP_FD_NAMED,
                              name, true);
        expect_document_input(command("rebound"), "third", SHELL_DEP_FD_NAMED,
                              "a", true);
        /* A failed redirect leaves a's old value intact, so after ; the
         * following read may see that old resource. After && it reads only
         * the new a; but that place may be b's, which holds the old
         * resource on other paths, so the input remains possible there. */
        if (scenario >= 4)
          expect_document_input(command("rebound"), "second",
                                SHELL_DEP_FD_NAMED, "a", true);
      }
    }
}

static void outcome_assignment_correlation(void) {
  static const char *const counts[] = {"-n0", "-N0", "-n\"$count\""};
  static const char *const targets[] = {"fd", "first fd", "REPLY", "IFS"};
  for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++)
    for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
      const char *name = t < 2 ? "fd" : targets[t];
      char source[512];
      /* An unresolved timeout may be invalid; `&&` handles that error. */
      snprintf(source, sizeof(source),
               "exec {%s}<input; read %s -t\"$timeout\" %s 0>writeonly && "
               "read -u\"$%s\" value",
               name, counts[c], targets[t], name);
      parse(source);
      CHECK(document_input(command("value"), "input"));
    }
  parse("exec {REPLY}<input; read -n0 -t\"$timeout\" 0>writeonly && "
        "read -u\"$REPLY\" value");
  CHECK(document_input(command("value"), "input"));
  parse("exec {fd}<input; fd=temporary read -n0 -t\"$timeout\" fd "
        "0>writeonly && read -u\"$fd\" value");
  CHECK(document_input(command("value"), "input"));
  /* Failure before assignment preserves the old binding, but a reached
   * zero-count assignment destroys it even though the read then fails. */
  parse("exec {fd}<input; read -n0 -t1 fd 0>writeonly && "
        "read -u\"$fd\" value");
  CHECK(!document_input(command("value"), "input"));
  current_source = "exec {fd}<input; read -n0 -t1 fd 0>writeonly || "
                   "read -u\"$fd\" value";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
}

/* These are outcome-transfer regressions, not predictions about bytes or
 * whether a runtime variable actually contains a valid option operand: the
 * possible operand error is handled by `||`. */
static void read_transfer_regressions(void) {
  static const char *const options[] = {
      "-n \"$count\"", "-N \"$count\"", "-t \"$timeout\" -t1",
      "-n\"$count\"",  "-N\"$count\"",  "-t\"$timeout\" -t1"};
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "read %s -u11 -n0 probe 11<<<input || printf reached >marker",
             options[i]);
    parse(source);
    CHECK(document_write(command("reached"), "marker"));
    CHECK(inputs(command("probe"), 11, NULL) == 0);
    /* A failed earlier operand cannot borrow the later -u proof: the copy
     * still requires the open of input. fd 11 is missing only where that
     * open failed, so printf runs only along that failure. */
    snprintf(source, sizeof(source),
             "exec 11<input; read %s -u11 -n0 probe || "
             "{ true 3<&11 || printf reached >marker; }",
             options[i]);
    parse(source);
    CHECK(document_required("input"));
    CHECK(!document_write(command("reached"), "marker"));
  }
  /* A captured allocation is proven decimal/nonzero; it must not gain the
   * invalid-number alternative belonging only to unknown runtime data. */
  parse("exec {count}<<<input && { read -n \"$count\" -n0 -u11 probe "
        "11<<<input || printf impossible >marker; }");
  CHECK(!document_write(command("impossible"), "marker"));

  static const char *const capture_probes[] = {
      "value=$(read -u1 -n0 probe)",
      "value=$(read -u1 -N0 probe)",
      "value=`read -u1 -n0 probe`",
      "value=$(inner=$(read -u1 -n0 probe))",
      "value=$( (read -u1 -n0 probe) )",
      "value=$(exec 11>&1; read -u11 -n0 probe)"};
  reject("value=$(read -u1 -n0 probe 1>&-)");
  for (size_t i = 0; i < sizeof(capture_probes) / sizeof(capture_probes[0]);
       i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "check >/dev/null; %s; true 3>&1 4>/missing/x || "
             "printf reached >marker",
             capture_probes[i]);
    parse(source);
    CHECK(document_write(command("reached"), "marker"));
    uint32_t probe = command("probe");
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      CHECK(!(edge->type == SHELL_EDGE_WRITE && edge->from == probe &&
              graph->nodes[edge->to].type == SHELL_NODE_FD &&
              graph->nodes[edge->to].fd.number == 1));
    }
  }

  static const struct {
    const char *probe;
    bool input;
  } named_probes[] = {
      {"read -u\"$fd\" -n0 probe", false},
      {"value=$(read -u\"$fd\" -n0 probe)", false},
      {"value=$(read -u\"$fd\" -N0 probe)", false},
      {"value=`read -u\"$fd\" -n0 probe`", false},
      {"value=$(inner=$(read -u\"$fd\" -n0 probe))", false},
      {"value=$( (read -u\"$fd\" -n0 probe) )", false},
      {"value=${choice:+$(read -u\"$fd\" -n0 probe)}", false},
      {"a=$(true) b=${choice:+$(read -u\"$fd\" -n0 probe)}", false},
      {"a=$(false) b=${choice:+$(read -u\"$fd\" -n0 probe)}", true},
      {"a=$(read -u\"$fd\" -n0 probe) b=$(true)", false},
      {"value=$(exec {fd}>writeonly; read -u\"$fd\" -n0 probe)", true}};
  for (size_t i = 0; i < sizeof(named_probes) / sizeof(named_probes[0]); i++) {
    char source[768];
    snprintf(source, sizeof(source),
             "exec 3<&-; exec {fd}<<<input; %s || read -u\"$fd\" result",
             named_probes[i].probe);
    parse(source);
    CHECK(document_input(command("result"), "input") == named_probes[i].input);
  }
  /* A read of the descriptor closed inside the substitution certainly fails
   * with a shell-level error ("invalid file descriptor"): even though only
   * that inner read fails and the fallback still reads, no dependency graph
   * models the input. */
  reject("exec 3<&-; exec {fd}<<<input; "
         "value=$(exec {fd}<&-; read -u\"$fd\" -n0 probe) || "
         "read -u\"$fd\" result");
  reject("exec 3<&-; choice && exec {fd}<<<input || exec {fd}>writeonly; "
         "value=$(read -u\"$fd\" -n0 probe) || read -u\"$fd\" result");

  /* One logical name can arrive from different allocation sites. Both live
   * origins must survive an import; selecting metadata from the first site's
   * import record would silently discard the other successful continuation. */
  parse("choice && exec {fd}<<<first || exec {fd}<<<second; "
        "value=$(read -u\"$fd\" -n0 probe) && read -u\"$fd\" result");
  CHECK(document_input(command("result"), "first"));
  CHECK(document_input(command("result"), "second"));

  /* Nested imports preserve allocation-site identity for named duplicates.
   * Child rebinds and closes remain isolated from the caller. */
  parse("exec {a}<<<input && exec {b}<&\"$a\" && { "
        "value=$(inner=$(read -u\"$b\" -n0 probe)) || read -u\"$a\" result; }");
  CHECK(!document_input(command("result"), "input"));
  /* The same certain inner read error through nested substitutions. */
  reject("exec {fd}<<<input; value=$(exec {fd}<&-; "
         "inner=$(read -u\"$fd\" -n0 probe)) || read -u\"$fd\" result");

  static const char *const capacity_sources[] = {
      "exec 1>/dev/null; value=$(read -u1 -n0 probe)",
      "exec {fd}<<<input; value=$(inner=$(read -u\"$fd\" -n0 probe)) "
      "|| read -u\"$fd\" result"};
  for (size_t s = 0; s < sizeof(capacity_sources) / sizeof(capacity_sources[0]);
       s++)
    for (unsigned n = 0; n <= 16; n += 4)
      for (unsigned e = 0; e <= 24; e += 4) {
        current_source = capacity_sources[s];
        limits.max_nodes = n;
        limits.max_edges = e;
        shell_dep_error_t status = shell_dep_graph_parse(
            current_source, strlen(current_source), "/", &limits, graph);
        if (status != SHELL_DEP_OK && status != SHELL_DEP_ETRUNC)
          fprintf(stderr, "transfer capacity: nodes=%u edges=%u status=%d\n", n,
                  e, status);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(shell_dep_graph_validate(graph).valid);
      }
  limits.max_nodes = SHELL_DEP_MAX_NODES;
  limits.max_edges = SHELL_DEP_MAX_EDGES;
}

/* Empty substitutions preserve this command's last substitution status, not
 * the preceding command's status. File shortcuts replace it just like an
 * ordinary child, including when an earlier read supplied correlated facts. */
static void substitution_completion_transfer(void) {
  /* Observation-driven alternatives can collect the journal before process
   * cleanup; the referenced ownership tree must survive that collection. */
  /* The read error is handled: its status is consumed. */
  parse("exec 3<&- 63<&-; : <(printf first) <(printf second) "
        "\"$(read -u3 -n0 probe && read -u62 value)\"");
  static const char *const skipped[] = {
      "exec 11<input; value=${choice:+$(read -u11 -n0 probe)} && "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; choice || read -u11 -n0 probe && "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; choice && read -u11 -n0 probe || "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; a=$(true) b=${choice:+$(read -u11 -n0 probe)$(true)} && "
      "{ true 3<&11 || printf reached >marker; }",
  };
  /* A skipped read proves nothing about fd 11; the copy requires the open
   * of input, and fails only along that open's failure, where printf runs. */
  for (size_t i = 0; i < sizeof(skipped) / sizeof(skipped[0]); i++) {
    parse(skipped[i]);
    CHECK(document_required("input"));
    CHECK(!document_write(command("reached"), "marker"));
  }
  parse("exec 11<input; value=${choice:+${nested:+$(read -u11 -n0 probe)}} && "
        "{ true 3<&11 || printf reached >marker; }");
  CHECK(document_required("input"));
  CHECK(!document_write(command("reached"), "marker"));
  parse("exec 11<input; a=$(false) "
        "b=${choice:+$(read -u11 -n0 probe)$(false)} && "
        "printf impossible >bad");
  parse("exec 11</dev/null && value=${choice:+$(read -u11 -n0 probe)} && "
        "{ true 3<&11 || printf impossible >bad; }");
  reject("exec 11<&-; value=${choice:+$(read -u11 -n0 probe)} && "
         "{ true 3<&11 || printf reached >marker; }");
  reject("exec 11</dev/null; value=${choice:+$(read -u11 -n0 probe)}; "
         "exec 11<&-; true 3<&11 || printf reached >marker");
  static const struct {
    const char *source;
    bool success;
  } cases[] = {
      {"a=$(true) b=${choice:+$(false)$(true)}", true},
      {"a=$(false) b=${choice:+$(true)$(false)}", false},
      {"a=$(true) b=${choice:+$(false)${nested:+$(false)}$(true)}", true},
      {"a=$(false) b=${choice:+$(true)${nested:+$(true)}$(false)}", false},
      {"a=$(true) b=${choice:+$(false)$()$(true)}", true},
      {"a=$(true) b=${choice:+$(false)<(printf payload)$(true)}", true},
      {"a=$(false) b=$(\\\n)", false},
      {"a=$(false) b=$(\\\n # comment\n)", false},
      {"a=$(true) b=$(\\\n # comment\n)", true},
      {"a=$(false) b=$()", false},
      {"a=$(false) b=$( \t\n)", false},
      {"a=$(false) b=$(# comment\n)", false},
      {"a=$(false) b=``", false},
      {"a=$(false) b=` \n`", false},
      {"a=$(false) b=` # comment\n`", true},
      {"a=$(true) b=$()", true},
      {"a=$(true) b=$(false) c=$()", false},
      {"a=$(false) b=$(true) c=$()", true},
      {"a=$(false) b=$(:)", true},
      {"false; value=$()", true},
      {"false; value=$(# comment\n)", true},
      {"false; value=``", true},
      {"a=$(false) b=${choice:+$()}", false},
      {"a=$(true) b=${choice:+$(# comment\n)}", true},
      {"value=$(a=$(false) b=$())", false},
      {"a=$(false) b=$(inner=$())", true},
      {"a=$(false) b=$(time :)", true},
      {"true \"$(false)$()\"", true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char source[768];
    snprintf(source, sizeof(source), "%s && printf reached >marker",
             cases[i].source);
    parse(source);
    CHECK(document_write(command("reached"), "marker") == cases[i].success);
    snprintf(source, sizeof(source), "%s || printf reached >marker",
             cases[i].source);
    parse(source);
    CHECK(document_write(command("reached"), "marker") != cases[i].success);
  }
  /* A certainly failing setup has no dependency model, in either connector. */
  reject("a=$(true) b=$() >\"\" && printf reached >marker");
  reject("a=$(true) b=$() >\"\" || printf reached >marker");
  static const char *const malformed[] = {
      "value=$(\\\n &&)",
      "value=$(\\\n |)",
      "value=$(\\\n ;)",
      "value=$(\\\n # comment\n &&)",
      /* Rewriting escaped backticks remains deliberately unsupported. */
      "value=`\\\n`",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    current_source = malformed[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
  }
  static const char *const empty[] = {"$()", "$( )", "$(# comment\n)", "``",
                                      "` \n`"};
  for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); i++) {
    char source[768];
    snprintf(source, sizeof(source),
             "exec 11<input; a=$(read -u11 -n0 probe) b=%s && "
             "{ true 3<&11 || printf impossible >bad; }",
             empty[i]);
    parse(source);
    /* Reference Bash never reaches printf: with fd 11 open the copy
     * succeeds, and without it the failed read's status survives b. */
    CHECK(document_required("input"));
    CHECK(!document_write(command("impossible"), "bad"));
  }
  /* fd 11 is missing only where the required open of input failed, so the
   * copy fails, and printf runs, only along that failure. The status
   * transfers these sources pass through are checked directly below. */
  static const char *const required_copies[] = {
      "exec 11<input; a=$(read -u11 -n0 probe) b=$(</dev/null) && "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; a=$(read -u11 -n0 probe) b=` # comment\n` && "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; a=$(read -u11 -n0 probe) b=$(</dev/null) c=$() && "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; outer=$(a=$(read -u11 -n0 probe) b=$(</dev/null)) && "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; a=$(read -u11 -n0 probe) "
      "b=${choice:+$(</dev/null)} && "
      "{ true 3<&11 || printf reached >marker; }",
      /* The redirect phase executes after assignments. */
      "exec 11<input; a=$(read -u11 -n0 probe) >\"$(</dev/null)\" && "
      "{ true 3<&11 || printf reached >marker; }",
  };
  for (size_t i = 0; i < sizeof(required_copies) / sizeof(required_copies[0]);
       i++) {
    parse(required_copies[i]);
    CHECK(document_required("input"));
    CHECK(!document_write(command("reached"), "marker"));
  }
  /* File shortcuts and commented backticks replace an earlier failure; a
   * skipped one keeps it (reference Bash: status 0, 0, 0, 0, then 1 or 0 by
   * choice). */
  static const char *const replacing[] = {
      "a=$(false) b=$(</dev/null)",
      "a=$(false) b=` # comment\n`",
      "a=$(false) b=$(</dev/null) c=$()",
      "outer=$(a=$(false) b=$(</dev/null))",
      "a=$(false) b=${choice:+$(</dev/null)}",
  };
  for (size_t i = 0; i < sizeof(replacing) / sizeof(replacing[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source), "%s && printf reached >marker",
             replacing[i]);
    parse(source);
    CHECK(document_write(command("reached"), "marker"));
  }
  parse("exec 11<input; a=$(read -u11 -n0 probe) b=$(</dev/null) c=$(false) && "
        "printf impossible >bad");
  parse("exec 11<input; a=$(read -u11 -n0 probe) b=$(</missing/x) || "
        "{ true 3<&11 && printf reached >marker; }");
  CHECK(document_write(command("reached"), "marker"));
  /* A real redirect-only child has setup status, even when its body has no
   * ordinary executable. Its possible success replaces the earlier failure. */
  parse("a=$(false) b=$(>sink) && printf reached >marker");
  CHECK(document_write(command("reached"), "marker"));

  static const char *const capacity_sources[] = {
      "exec 11<input; a=$(read -u11 -n0 probe) b=$(</dev/null) && "
      "{ true 3<&11 || printf reached >marker; }",
      "exec 11<input; a=$(read -u11 -n0 probe) b=$() && "
      "{ true 3<&11 || printf impossible >bad; }",
      "exec 11<input; outer=$(a=$(read -u11 -n0 probe) b=$(</missing/x)) || "
      "printf reached >marker",
      "a=$(true) b=${choice:+$(false)${nested:+$(false)}$(true)} || "
      "printf impossible >bad"};
  for (size_t s = 0; s < sizeof(capacity_sources) / sizeof(capacity_sources[0]);
       s++)
    for (unsigned n = 0; n <= 16; n += 4)
      for (unsigned e = 0; e <= 24; e += 4) {
        current_source = capacity_sources[s];
        limits.max_nodes = n;
        limits.max_edges = e;
        shell_dep_error_t status = shell_dep_graph_parse(
            current_source, strlen(current_source), "/", &limits, graph);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(graph->node_count <= n && graph->edge_count <= e);
        CHECK(shell_dep_graph_validate(graph).valid);
      }
  limits.max_nodes = SHELL_DEP_MAX_NODES;
  limits.max_edges = SHELL_DEP_MAX_EDGES;
  /* Completed independent operands must not retain a Cartesian product of
   * decisions. Each final true supersedes the operand's false completion. */
  char guarded_source[4096];
  size_t used =
      (size_t)snprintf(guarded_source, sizeof(guarded_source), "a=$(true)");
  for (unsigned i = 0; i < 24; i++)
    used +=
        (size_t)snprintf(guarded_source + used, sizeof(guarded_source) - used,
                         " v%u=${g%u:+$(false)$(true)}", i, i);
  snprintf(guarded_source + used, sizeof(guarded_source) - used,
           " || printf impossible >bad");
  parse(guarded_source);
  /* Status-only replacements consume the bounded event journal; identities
   * must not. Exhaustion returns an empty truncated graph, then a fresh parse
   * can reuse the same caller workspace without stale events. */
  static char source[(SHELL_DEP_MAX_EDGES + 1) * 16 + 256];
  static const char *const fragments[] = {
      "$()",
      "`# comment\n`",
      "${choice:+$()}",
  };
  const char suffix[] = " && { true 3<&11 || printf impossible >bad; }";
  for (unsigned mode = 0; mode < sizeof(fragments) / sizeof(fragments[0]);
       mode++) {
    size_t length = (size_t)snprintf(
        source, sizeof(source), "exec 11<input; a=$(read -u11 -n0 probe) b=");
    size_t fragment_length = strlen(fragments[mode]);
    for (unsigned i = 0; i <= SHELL_DEP_MAX_EDGES; i++) {
      memcpy(source + length, fragments[mode], fragment_length);
      length += fragment_length;
    }
    memcpy(source + length, suffix, sizeof(suffix));
    /* Without read-outcome version splits, every fragment form, including
     * the empty backtick substitutions, stays within capacity. */
    current_source = source;
    parse(source);
  }
  parse("a=$(false) b=$() || printf reached >marker");
  CHECK(document_write(command("reached"), "marker"));
}

typedef struct {
  const char *source;
  size_t calls;
  size_t last_offset;
} printf_expansion_fixture_t;

static shell_expand_status_t
printf_resolve_data(const shell_expand_word_request_t *request,
                    const char **netargv, size_t *length, void *context) {
  printf_expansion_fixture_t *fixture = context;
  CHECK(request->source == fixture->source);
  CHECK(request->source_length == strlen(fixture->source));
  CHECK(request->word_length == 4);
  CHECK(!memcmp(request->source + request->word_offset, "\"$V\"", 4));
  CHECK(request->purpose == SHELL_EXPAND_WORD_ARGUMENT);
  CHECK(request->cwd_known && request->cwd_absolute);
  CHECK(!strcmp(request->cwd, "/"));
  CHECK(request->owner_offset <= request->word_offset);
  CHECK(request->word_offset + request->word_length <=
        request->owner_offset + request->owner_length);
  CHECK(fixture->calls == 0 || request->word_offset > fixture->last_offset);
  fixture->last_offset = request->word_offset;
  fixture->calls++;
  *netargv = "2:\\c,";
  *length = 5;
  return SHELL_EXPAND_RESOLVED;
}

static void printf_elision_resolution(void) {
  current_source = "resolved workspace";
  size_t required;
  CHECK(shell_dep_resolved_workspace_size(512, &limits, &required));
  CHECK(limits.workspace_size >= required);
  for (size_t i = 0; i < sizeof(shellsplit_test_printf_expansion_cases) /
                             sizeof(shellsplit_test_printf_expansion_cases[0]);
       i++) {
    current_source = shellsplit_test_printf_expansion_cases[i].source;
    printf_expansion_fixture_t fixture = {.source = current_source};
    CHECK(shell_dep_graph_parse_resolved(
              current_source, strlen(current_source), "/", &limits, graph,
              printf_resolve_data, &fixture, NULL) == SHELL_DEP_OK);
    CHECK(fixture.calls == shellsplit_test_printf_expansion_cases[i].queries);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const char *const ordinary[] = {"echo <() \"$V\"",
                                         "exec <() echo <() \"$V\"",
                                         "command <() echo <() \"$V\" 2>err"};
  for (size_t i = 0; i < sizeof(ordinary) / sizeof(ordinary[0]); i++) {
    current_source = ordinary[i];
    printf_expansion_fixture_t fixture = {.source = current_source};
    CHECK(shell_dep_graph_parse_resolved(
              current_source, strlen(current_source), "/", &limits, graph,
              printf_resolve_data, &fixture, NULL) == SHELL_DEP_OK);
    CHECK(fixture.calls == 1);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
}

static void semantic_empty_bodies(void) {
  static const struct {
    const char *source;
    shell_source_empty_kind_t kind;
  } cases[] = {
      {"", SHELL_SOURCE_BLANK},
      {" \t\n", SHELL_SOURCE_BLANK},
      {"\\\n \t\\\n", SHELL_SOURCE_BLANK},
      {"# comment\rfalse", SHELL_SOURCE_COMMENT},
      {" # comment\r\n\t", SHELL_SOURCE_COMMENT},
      {"\\\n# comment\r\n", SHELL_SOURCE_COMMENT},
      {"# comment\nfalse", SHELL_SOURCE_NONEMPTY},
      {"\r", SHELL_SOURCE_NONEMPTY},
      {"\r\n", SHELL_SOURCE_NONEMPTY},
      {"\\\r", SHELL_SOURCE_NONEMPTY},
      {"\\\r\n", SHELL_SOURCE_NONEMPTY},
      {"\v", SHELL_SOURCE_NONEMPTY},
      {"\f", SHELL_SOURCE_NONEMPTY},
      {"'\r'", SHELL_SOURCE_NONEMPTY},
      {"$'\\r'", SHELL_SOURCE_NONEMPTY},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    current_source = cases[i].source;
    CHECK(shell_source_empty_kind(current_source, strlen(current_source)) ==
          cases[i].kind);
    char process[128];
    snprintf(process, sizeof(process), "<(%s\n)", current_source);
    CHECK(shell_source_empty_process_word(process, strlen(process)) ==
          (cases[i].kind != SHELL_SOURCE_NONEMPTY));
  }
  /* These are ordinary executable words. Preserve their possible failure
   * paths rather than manufacturing an empty, successful substitution. */
  for (size_t i = 0; i < sizeof(shellsplit_test_nonblank_bodies) /
                             sizeof(shellsplit_test_nonblank_bodies[0]);
       i++) {
    current_source = shellsplit_test_nonblank_bodies[i];
    for (unsigned strict = 0; strict < 2; strict++) {
      shell_parse_result_t fast;
      shell_limits_t parse_limits = SHELL_LIMITS_DEFAULT;
      parse_limits.strict_mode = strict != 0;
      CHECK(shell_parse_fast(current_source, strlen(current_source),
                             &parse_limits, &fast) == SHELL_OK);
      CHECK(fast.count == 1 && fast.status == SHELL_STATUS_OK);
    }
    parse(current_source);
    static const char *const formats[] = {
        "value=$(%s) || printf fallback >out",
        "value=$(%s) && printf reached >out",
        "value=`%s` || printf fallback >out",
        "cat <(%s) || printf fallback >out",
    };
    for (size_t f = 0; f < sizeof(formats) / sizeof(formats[0]); f++) {
      char source[128];
      snprintf(source, sizeof(source), formats[f],
               shellsplit_test_nonblank_bodies[i]);
      current_source = source;
      parse(source);
      CHECK(document_write(command(f == 1 ? "reached" : "fallback"), "out"));
      shell_processed_commands_t processed = {0};
      CHECK(shell_process_commands(source, strlen(source), NULL, &processed) ==
            SHELL_PROCESS_OK);
      shell_processed_commands_free(&processed);
    }
  }
  static const struct {
    const char *source;
    bool reached;
  } controls[] = {
      {"a=$(false) b=$( \\\n) && printf reached >out", false},
      {"a=$(false) b=$(# comment\rfalse\n) && printf reached >out", false},
      {"a=$(false) b=`# comment\rfalse\n` && printf reached >out", true},
      {"a=$(false) b=$(# comment\r\n) || printf reached >out", true},
      {"a=$(true) b=$(# comment\r\n) || printf reached >out", false},
      {"value=$('\r') || printf reached >out", true},
      {"value=$($'\\r') || printf reached >out", true},
  };
  for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
    parse(controls[i].source);
    CHECK(document_write(command("reached"), "out") == controls[i].reached);
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_nonblank_bodies) /
                             sizeof(shellsplit_test_nonblank_bodies[0]);
       i++) {
    char source[192];
    static const char *const formats[] = {
        "value=$(true;%s) || printf fallback >out",
        "value=`true;%s` || printf fallback >out",
        "value=$( (true;%s) ) || printf fallback >out",
        "{ true;%s\n} || printf fallback >out"};
    for (size_t f = 0; f < sizeof(formats) / sizeof(formats[0]); f++) {
      snprintf(source, sizeof(source), formats[f],
               shellsplit_test_nonblank_bodies[i]);
      parse(source);
      CHECK(document_write(command("fallback"), "out"));
    }
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_control_byte_words) /
                             sizeof(shellsplit_test_control_byte_words[0]);
       i++) {
    current_source = shellsplit_test_control_byte_words[i].source;
    parse(current_source);
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t rendered = {0};
    CHECK(shell_process_commands(current_source, strlen(current_source), NULL,
                                 &processed) == SHELL_PROCESS_OK);
    CHECK(processed.command_count == 1);
    CHECK(shell_render_netargv_buffer(&processed.commands[0], NULL,
                                      &rendered) == SHELL_PROCESS_OK);
    const char *expected = shellsplit_test_control_byte_words[i].netargv;
    CHECK(rendered.length == strlen(expected) &&
          !memcmp(rendered.data, expected, rendered.length));
    shell_netstring_buffer_free(&rendered);
    shell_processed_commands_free(&processed);
  }
  parse("<()\\\r read -n0 value <<<payload || printf fallback >out");
  CHECK(document_input(command("read"), "payload"));
  CHECK(document_write(command("fallback"), "out"));
  parse("read -u $' \r3\t' -n0 value 3<<<payload");
  CHECK(inputs(command("read"), 0, NULL) == 0);
}

static void empty_process_words(void) {
  static const char *const rejected[] = {
      "<() eval 'printf payload'",  "<()>() eval 'printf payload'",
      "<()eval 'printf payload'",   "<() command <() eval '$source'",
      "builtin <() eval '$source'", "<() read -e value",
      "<() shopt -s lastpipe"};
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    current_source = rejected[i];
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
  }
  static const char *const prefixes[] = {
      "<()", ">()", "<( )", "<(# comment\n)", "<()>()", "<(\\\n)"};
  for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source), "exec 3<<<payload; %s read -u3 value",
             prefixes[i]);
    parse(source);
    uint32_t reader = command("value");
    CHECK(graph->nodes[reader].cmd.token_count == 3);
    CHECK(graph->nodes[reader].cmd.effective_command_known);
    CHECK(graph->nodes[reader].cmd.effective_command_token == 0);
    expect_document_input_flags(reader, "payload", 3, NULL, true,
                                SHELL_DEP_EDGE_FLAG_REQUIRED);
    snprintf(source, sizeof(source), "%s read -n0 value <<<payload",
             prefixes[i]);
    parse(source);
    CHECK(inputs(command("value"), 0, NULL) == 0);
    snprintf(source, sizeof(source), "%s exit; printf impossible >marker",
             prefixes[i]);
    parse(source);
    CHECK(!document_write(command("impossible"), "marker"));
  }
  parse("exec 3<<<payload; <()read -u<()3 value");
  expect_document_input_flags(command("value"), "payload", 3, NULL, true,
                              SHELL_DEP_EDGE_FLAG_REQUIRED);
  parse("exec 3<<<payload; command <() read <() -u3 value");
  expect_document_input_flags(command("value"), "payload", 3, NULL, true,
                              SHELL_DEP_EDGE_FLAG_REQUIRED);
  parse("<() X=value");
  CHECK(graph->nodes[command("X=value")].cmd.token_count == 1);
  for (uint32_t i = 0; i < graph->node_count; i++)
    CHECK(graph->nodes[i].type != SHELL_NODE_DOC ||
          graph->nodes[i].doc.kind != SHELL_DOC_ENVVAR);
  parse("printf ''<() \"<()\"");
  CHECK(graph->nodes[command("printf")].cmd.token_count == 3);
  parse("<() cd /next; printf reached");
  CHECK(!strcmp(graph->cwd_buf.data +
                    graph->nodes[command("reached")].cmd.cwd_offset,
                "/next"));
  parse("name=value <(); printf reached");
  bool assignment = false;
  for (uint32_t i = 0; i < graph->node_count; i++)
    assignment |=
        graph->nodes[i].type == SHELL_NODE_DOC &&
        graph->nodes[i].doc.kind == SHELL_DOC_ENVVAR &&
        shell_dep_doc_env_name_equals(&graph->nodes[i].doc, "name", 4);
  CHECK(assignment);
  parse("a=$(false) <() <<<payload && printf reached >marker");
  CHECK(document_write(command("reached"), "marker"));
  parse("a=$(false) <() \"$@\" && printf reached >marker");
  CHECK(document_write(command("reached"), "marker"));
  parse("<() ! eval literal");
  CHECK(graph->nodes[command("!")].cmd.token_count == 3);
  parse("<() if literal");
  CHECK(graph->nodes[command("if")].cmd.token_count == 2);
}

typedef struct {
  size_t bytes, work;
} owner_lifetime_work_t;

static void elided_declarations(void) {
  static const char *const assignments[] = {
      "export fd<()=anything",
      "declare <()fd=anything",
      "typeset f>()d=anything",
      "export fd<()+=anything",
      "export fd+<()=anything",
      "command export f<()>()d=anything",
      "builtin declare f<(# empty\n)d=anything"};
  for (size_t i = 0; i < sizeof(assignments) / sizeof(assignments[0]); i++) {
    char source[512];
    snprintf(source, sizeof(source),
             "exec {fd}<<<old; %s; read -u\"$fd\" value", assignments[i]);
    current_source = source;
    CHECK(shell_dep_graph_parse(source, strlen(source), "/", &limits, graph) ==
          SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
    snprintf(source, sizeof(source),
             "exec {fd}<<<old; exec {other}<<<saved; %s; "
             "read -u\"$other\" value",
             assignments[i]);
    parse(source);
    /* The unhandled here-string open is required: without it the name is
     * unset and the read reports an error. */
    expect_document_input_flags(command("read"), "saved", SHELL_DEP_FD_NAMED,
                                "other", true, SHELL_DEP_EDGE_FLAG_REQUIRED);
  }
  /* Temporary declaration prefixes restore fd; export promotes the binding.
   * Lookup must compare the decoded name, including fragments before +=. */
  parse("exec {fd}<<<saved; fd=shadow declare f<()d=anything; "
        "read -u\"$fd\" value");
  /* The unhandled here-string open is required: without it the name is
   * unset and the read reports an error. */
  expect_document_input_flags(command("read"), "saved", SHELL_DEP_FD_NAMED,
                              "fd", true, SHELL_DEP_EDGE_FLAG_REQUIRED);
  current_source = "exec {fd}<<<saved; fd=shadow export f<()d=anything; "
                   "read -u\"$fd\" value";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  parse("exec {fd}<<<saved; export IF<()S=letters; read -u $fd value");
  /* The unhandled here-string open is required: without it the name is
   * unset and the read reports an error. */
  expect_document_input_flags(command("read"), "saved", SHELL_DEP_FD_NAMED,
                              "fd", true, SHELL_DEP_EDGE_FLAG_REQUIRED);
  current_source = "exec {fd}<<<saved; export IF<()S=0123456789; "
                   "read -u $fd value";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);

  static const struct {
    const char *word;
    const char *raw_name;
    bool append;
  } documents[] = {{"NAME<()=value", "NAME<()", false},
                   {"<()NA>()ME=value", "<()NA>()ME", false},
                   {"NA<(# empty\n)ME=value", "NA<(# empty\n)ME", false},
                   {"NAME<()+=value", "NAME<()", true},
                   {"NAME+<()=value", "NAME", true},
                   {"NA'ME'<()=value", "NA'ME'<()", false}};
  for (size_t i = 0; i < sizeof(documents) / sizeof(documents[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source), "export %s", documents[i].word);
    parse(source);
    unsigned found = 0;
    for (uint32_t n = 0; n < graph->node_count; n++) {
      const shell_dep_node_t *node = &graph->nodes[n];
      if (node->type != SHELL_NODE_DOC || node->doc.kind != SHELL_DOC_ENVVAR)
        continue;
      const shell_dep_doc_t *doc = &node->doc;
      found++;
      CHECK(doc->name == source + strlen("export "));
      CHECK(doc->name_len == strlen(documents[i].raw_name));
      CHECK(!memcmp(doc->name, documents[i].raw_name, doc->name_len));
      CHECK(doc->value == strchr(source, '=') + 1 && doc->value_len == 5);
      CHECK(((doc->flags & SHELL_DEP_DOC_FLAG_ENVVAR_APPEND) != 0) ==
            documents[i].append);
      size_t length = 0, written = 0;
      char name[4];
      CHECK(shell_dep_doc_env_name_length(doc, &length) && length == 4);
      CHECK(shell_dep_doc_write_env_name(doc, name, sizeof(name), &written));
      CHECK(written == 4 && !memcmp(name, "NAME", 4));
      CHECK(shell_dep_doc_env_name_equals(doc, "NAME", 4));
    }
    CHECK(found == 1);
  }
  parse("export NAME<()=$(printf payload)");
  bool substitution = false;
  for (uint32_t e = 0; e < graph->edge_count; e++)
    substitution |= graph->edges[e].type == SHELL_EDGE_SUBST &&
                    graph->edges[e].from == command("printf") &&
                    graph->edges[e].to == command("export");
  CHECK(substitution);

  static const struct {
    const char *source;
    bool stateful;
  } rejected[] = {{"export OPT<()IND='x[$(printf ARITH >&2)0]'", true},
                  {"declare OPT<()IND=1", true},
                  {"typeset RAN<()DOM=1", true},
                  {"command export POSIX<()LY_CORRECT=x", false},
                  {"builtin export BASH<()_COMPAT=x", false},
                  {"export BASH_X<()TRACEFD=2", false},
                  {"readonly v<()=text", false},
                  {"declare -r v<()=text", false}};
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    current_source = rejected[i].source;
    CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
    shell_processed_commands_t structured = {0};
    CHECK(shell_process_commands(current_source, strlen(current_source), NULL,
                                 &structured) ==
          (rejected[i].stateful ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
    CHECK((rejected[i].stateful && structured.command_count != 0) ||
          (!rejected[i].stateful && structured.commands == NULL &&
           structured.command_count == 0));
    shell_command_info_t *flat = NULL;
    size_t count = 0;
    CHECK(shell_process_command(current_source, strlen(current_source), NULL,
                                &flat, &count) ==
          (rejected[i].stateful ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
    CHECK((rejected[i].stateful && count != 0) ||
          (!rejected[i].stateful && flat == NULL && count == 0));
    shell_processed_commands_free(&structured);
    shell_command_infos_free(flat, count);
  }
  /* Neither quote-protected fragments nor command-prefix spellings acquire
   * declaration assignment semantics. Nonempty substitutions stay dynamic. */
  static const char *const unchanged[] = {"export 'fd<()'=anything",
                                          "export fd\\<\\(\\)=anything",
                                          "fd<()=anything"};
  for (size_t i = 0; i < sizeof(unchanged) / sizeof(unchanged[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source),
             "exec {fd}<<<saved; %s; read -u\"$fd\" value", unchanged[i]);
    parse(source);
    /* The unhandled here-string open is required: without it the name is
     * unset and the read reports an error. */
    expect_document_input_flags(command("read"), "saved", SHELL_DEP_FD_NAMED,
                                "fd", true, SHELL_DEP_EDGE_FLAG_REQUIRED);
  }
  current_source = "export fd<(:)=anything";
  CHECK(shell_dep_graph_parse(current_source, strlen(current_source), "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
}

static void owner_lifetime_parse(const char *source,
                                 owner_lifetime_work_t *previous) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_source_scan_reset();
#endif
  parse(source);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t bytes = strlen(source);
  size_t work =
      shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_READ_INPUT) +
      shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP) +
      shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
  /* Normalize by source size: the deliberately shifted read options grow
   * with their ordinal. Permit logarithmic index growth, not path doubling
   * for every independent command or conditional parameter operand. */
  CHECK(!previous->work ||
        2 * work * previous->bytes <= 3 * previous->work * bytes);
  *previous = (owner_lifetime_work_t){bytes, work};
#else
  (void)previous;
#endif
}

static void owner_fact_lifetimes(void) {
  reject("exec 11<&-; true \"$(read -u11 -n0 probe)\" && "
         "{ true 3<&11 || printf reached >marker; }");
  parse(
      "exec 11<<<payload; true \"$(read -u11 -n0 probe)\" && read -u11 value");
  expect_document_input_flags(command("value"), "payload", 11, NULL, true,
                              SHELL_DEP_EDGE_FLAG_REQUIRED);
  owner_lifetime_work_t previous[4] = {{0}};
  for (unsigned count = 4; count <= 16; count *= 2) {
    char source[8192];
    size_t used = 0;
    for (unsigned i = 0; i < count; i++) {
      /* Descriptors above 2 start closed: open each probed one first. */
      used += (size_t)snprintf(
          source + used, sizeof(source) - used,
          "exec %u<input; true \"$(read -u%u -n0 probe)\"; ", 11 + i, 11 + i);
    }
    snprintf(source + used, sizeof(source) - used, "printf reached >marker");
    owner_lifetime_parse(source, &previous[0]);
    CHECK(document_write(command("reached"), "marker"));

    used = (size_t)snprintf(source, sizeof(source),
                            "exec {fd}<<<payload || exit; ");
    for (unsigned i = 0; i < count; i++) {
      used += (size_t)snprintf(source + used, sizeof(source) - used,
                               "gate%u && read -n0 ", i);
      for (unsigned option = 0; option < i; option++)
        used += (size_t)snprintf(source + used, sizeof(source) - used, "-r ");
      used += (size_t)snprintf(source + used, sizeof(source) - used,
                               "-p\"$fd\" value; ");
    }
    snprintf(source + used, sizeof(source) - used, "printf reached >marker");
    owner_lifetime_parse(source, &previous[1]);
    CHECK(document_write(command("reached"), "marker"));

    for (unsigned separate = 0; separate < 2; separate++) {
      used = (size_t)snprintf(source, sizeof(source), "a=$(true)%s",
                              separate ? "; " : " ");
      for (unsigned i = 0; i < count; i++)
        used += (size_t)snprintf(source + used, sizeof(source) - used,
                                 "v%u=${g%u:+$(false)<(:)$(true)}%s", i, i,
                                 separate ? "; " : " ");
      snprintf(source + used, sizeof(source) - used,
               "%s printf reached >marker", separate ? "" : "&&");
      owner_lifetime_parse(source, &previous[2 + separate]);
      CHECK(document_write(command("reached"), "marker"));
    }
  }
}

int main(int argc, char **argv) {
  current_source = "workspace allocation";
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_RESOLVED,
                                      512, 2, false, 0));
  limits = fixture.limits;
  graph = fixture.graph[0];
  other = fixture.graph[1];
  if (argc == 2 && !strcmp(argv[1], "--zero-prefix")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    numeric_operand_classification();
    zero_prefixed_operand_refinement();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--variable-lifecycle")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    predefined_variable_lifecycle();
    inherited_variable_capabilities();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--binding-invalidation")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    binding_invalidation();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--operand-classification")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
    audit_graph_allocations = true;
#endif
    numeric_operand_classification();
    signed_operand_refinement();
    zero_prefixed_operand_refinement();
    irreversible_operand_prefixes();
    fragment_target_classification();
    literal_failure_proofs();
    contextual_capabilities();
    reachable_target_attributes();
    literal_target_refinement();
    exec_exit_elision();
    invalid_target_projection();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
    audit_graph_allocations = false;
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--semantic-words")) {
    printf_elision_resolution();
    semantic_empty_bodies();
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--elided-declarations")) {
    elided_declarations();
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--target-failures")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    dynamic_target_failures();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--owner-lifetimes")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    empty_process_words();
    owner_fact_lifetimes();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--bounded-work")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    bounded_work();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--substitution-status")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    substitution_completion_transfer();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--transfer-regressions")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
    read_transfer_regressions();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--recursive-proofs")) {
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--outcome-effects")) {
    outcome_assignment_correlation();
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--read-proofs")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--private-outcomes")) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    shellsplit_test_alloc_fail_at(0);
#endif
#ifdef SHELLSPLIT_TEST_ALLOCATOR
    CHECK(shellsplit_test_alloc_count() == 0);
    shellsplit_test_alloc_reset();
#endif
    goto done;
  }
  if (argc == 2 && !strcmp(argv[1], "--process-paths")) {
    goto done;
  }
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  shellsplit_test_alloc_fail_at(0);
#endif
  allocation_routing_contract();
  outcome_assignment_correlation();
  read_transfer_regressions();
  substitution_completion_transfer();
  allocation_alias_imports();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  CHECK(shellsplit_test_alloc_count() == 0);
  shellsplit_test_alloc_reset();
#endif
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  shellsplit_test_alloc_fail_at(0);
#endif
  allocation_path_correlation();
  allocation_correlation_limits();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  CHECK(shellsplit_test_alloc_count() == 0);
  shellsplit_test_alloc_reset();
#endif
  if (argc == 2 && !strcmp(argv[1], "--allocation-correlation"))
    goto done;
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  shellsplit_test_alloc_fail_at(0);
#endif
  process_lifetime_pressure();
  process_correlation_limits();
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  CHECK(shellsplit_test_alloc_count() == 0);
  shellsplit_test_alloc_reset();
#endif
  if (argc == 2 && !strcmp(argv[1], "--path-correlation"))
    goto done;
  semantic_process_inventory();
  printf_elision_resolution();
  semantic_empty_bodies();
  conditional_low_pipe_fallback();
  independent_lifetime_guards();
  empty_process_words();
  elided_declarations();
  owner_fact_lifetimes();
  static_selection();
  no_byte_input();
  named_selection();
  recursive_and_pipe_inputs();
  assignment_and_control();
  conditional_descriptor_versions();
  captured_option_values();
  numeric_operand_classification();
  signed_operand_refinement();
  zero_prefixed_operand_refinement();
  irreversible_operand_prefixes();
  fragment_target_classification();
  literal_failure_proofs();
  contextual_capabilities();
  reachable_target_attributes();
  literal_target_refinement();
  exec_exit_elision();
  binding_invalidation();
  predefined_variable_lifecycle();
  inherited_variable_capabilities();
  named_timing_routes();
  contextual_option_roles();
  timeout_conversion();
  captured_target_values();
  invalid_target_projection();
  unrelated_observations();
  observed_classes_with_unrelated_allocations();
  refined_target_mutations();
  dynamic_target_failures();
  input_error_phases();
  group_reader_propagation();
  process_descriptor_input();
  conditional_process_input();
  independent_process_guards();
  empty_file_process_substitution();
  inline_document_setup();
  original_pipe_end_fallback();
  workspace_and_allocation();
  bounded_work();
  capacities();
  unknown_occupancy_capacity();
done:
  shellsplit_graph_fixture_destroy(&fixture);
  puts("read input routing tests passed");
  return 0;
}
