#include "../src/shell_depgraph_internal.h"
#include "../src/shell_processor_internal.h"
#include "depgraph_compare.h"
#include "depgraph_invariants.h"
#include "shell_depgraph.h"
#include "shell_processor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SHELLSPLIT_TEST_ALLOCATOR
#include "test_allocator.h"
#include "test_source_scans.h"
#endif

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static bool command_writes(const shell_dep_graph_t *graph, const char *command,
                           const char *path) {
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type != SHELL_EDGE_WRITE && edge->type != SHELL_EDGE_APPEND)
      continue;
    const shell_dep_node_t *owner = &graph->nodes[edge->from];
    const shell_dep_node_t *file = &graph->nodes[edge->to];
    if (owner->type == SHELL_NODE_CMD && owner->cmd.token_count &&
        owner->cmd.token_lens[0] == strlen(command) &&
        memcmp(owner->cmd.tokens[0], command, strlen(command)) == 0 &&
        file->type == SHELL_NODE_DOC && file->doc.kind == SHELL_DOC_FILE &&
        file->doc.path_len == strlen(path) &&
        memcmp(file->doc.path, path, strlen(path)) == 0)
      return true;
  }
  return false;
}

/* Compare the complete consumer route set, not just one expected document.
 * Setup writes from earlier commands are intentionally outside this set. */
static bool command_routes_exact(const shell_dep_graph_t *graph,
                                 const char *command,
                                 shell_dep_edge_type_t kind,
                                 const char *const *paths, size_t count) {
  size_t seen = 0;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->type != kind)
      continue;
    const shell_dep_node_t *owner =
        &graph->nodes[kind == SHELL_EDGE_READ ? edge->to : edge->from];
    if (owner->type != SHELL_NODE_CMD || !owner->cmd.token_count ||
        owner->cmd.token_lens[0] != strlen(command) ||
        memcmp(owner->cmd.tokens[0], command, strlen(command)))
      continue;
    const shell_dep_node_t *file =
        &graph->nodes[kind == SHELL_EDGE_READ ? edge->from : edge->to];
    if (file->type == SHELL_NODE_FD)
      continue;
    if (file->type != SHELL_NODE_DOC || file->doc.kind != SHELL_DOC_FILE ||
        (kind == SHELL_EDGE_READ ? edge->target_fd : edge->source_fd) !=
            (kind == SHELL_EDGE_READ ? 0u : 1u))
      return false;
    size_t path;
    for (path = 0; path < count; path++)
      if (file->doc.path_len == strlen(paths[path]) &&
          !memcmp(file->doc.path, paths[path], file->doc.path_len))
        break;
    if (path == count || (seen & ((size_t)1 << path)))
      return false;
    seen |= (size_t)1 << path;
  }
  return seen == (((size_t)1 << count) - 1);
}

/* One owner with many possible setup failures, rather than many short owners.
 * Every successful open registers an undo and every later open can fail. The
 * body observes a live save, preventing the non-observable numeric fast path.
 * Both repeated and distinct targets must retain the original tail route. */
static void failure_prefix_scaling(const shell_dep_limits_t *limits,
                                   shell_dep_graph_t *graph) {
  static const char *const original[] = {"/tmp/prefix-original"};
  for (unsigned read = 0; read < 2; read++) {
    for (unsigned distinct = 0; distinct < 2; distinct++) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
      size_t previous_undo = 0;
#endif
      for (unsigned count = 2; count <= 16; count *= 2) {
        char source[8192];
        char direction = read ? '<' : '>';
        int n = snprintf(source, sizeof(source),
                         "exec 3%c/tmp/prefix-original || exit; "
                         "exec 9>&- 10>&- 11>&-; ",
                         direction);
        CHECK(n > 0 && (size_t)n < sizeof(source));
        size_t used = (size_t)n;
        /* This measures cleanup composition, not the cross product of
         * unknown inherited scratch-slot occupancies. Reserve a known-free
         * save range; distinct targets below are reopened after this setup.
         * Unknown-occupancy exhaustion has separate capacity regressions. */
        for (unsigned fd = 12; fd < 25; fd++) {
          unsigned physical = distinct && fd >= 19 ? fd + 17 : fd;
          n = snprintf(source + used, sizeof(source) - used, "%s%u>&-%s",
                       (fd - 12) % 8 == 0 ? "exec " : "", physical,
                       (fd - 11) % 8 == 0 || fd == 24 ? "; " : " ");
          CHECK(n > 0 && (size_t)n < sizeof(source) - used);
          used += (size_t)n;
        }
        if (distinct) {
          n = snprintf(source + used, sizeof(source) - used, "exec 19>&-; ");
          CHECK(n > 0 && (size_t)n < sizeof(source) - used);
          used += (size_t)n;
        }
        if (distinct)
          for (unsigned i = 0; i < count; i++) {
            n = snprintf(source + used, sizeof(source) - used,
                         "exec %u%c/tmp/prefix-original || exit; ", 20 + i,
                         direction);
            CHECK(n > 0 && (size_t)n < sizeof(source) - used);
            used += (size_t)n;
          }
        const char *body =
            read ? "{ /bin/cat <&10; }" : "{ printf BODY >&10; }";
        CHECK(strlen(body) < sizeof(source) - used);
        memcpy(source + used, body, strlen(body) + 1);
        used += strlen(body);
        for (unsigned i = 0; i < count; i++) {
          n = snprintf(source + used, sizeof(source) - used,
                       " %u%c/tmp/prefix-%u", distinct ? 20 + i : 3, direction,
                       i);
          CHECK(n > 0 && (size_t)n < sizeof(source) - used);
          used += (size_t)n;
        }
        const char *tail =
            read ? (distinct ? "; cat <&20" : "; cat <&3")
                 : (distinct ? "; echo TAIL >&20" : "; echo TAIL >&3");
        CHECK(strlen(tail) < sizeof(source) - used);
        memcpy(source + used, tail, strlen(tail) + 1);
        used += strlen(tail);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        shellsplit_test_source_scan_reset();
#endif
        shell_dep_error_t status =
            shell_dep_graph_parse(source, used, "/", limits, graph);
        if (status != SHELL_DEP_OK)
          fprintf(stderr, "failure prefix read%u distinct%u count%u: %d\n%s\n",
                  read, distinct, count, status, source);
        CHECK(status == SHELL_DEP_OK);
        CHECK(command_routes_exact(graph, read ? "cat" : "echo",
                                   read ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                                   original, 1));
        CHECK(command_routes_exact(graph, read ? "/bin/cat" : "printf",
                                   read ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                                   original, 1));
        CHECK(shell_dep_graph_validate(graph).valid);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        size_t undo =
            shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_FAILURE_UNDO);
        size_t work = shellsplit_test_metadata_work(
                          SHELLSPLIT_TEST_WORK_FAILURE_COMPOSITION) +
                      shellsplit_test_metadata_work(
                          SHELLSPLIT_TEST_WORK_FAILURE_DEPENDENCIES);
        unsigned height = 0;
        for (unsigned bound = count; bound; bound >>= 1)
          height++;
        /* The two construction passes have bounded leaf work per open.
         * The old full-prefix replay exceeds this at count 16 (240 visits).
         * Dependency indexing may add logarithmic factors, not prefix replay.
         */
        if (undo > 6 * count ||
            (previous_undo && undo > 3 * previous_undo + 4) ||
            work > 64 * count * height * height)
          fprintf(stderr,
                  "failure scaling read%u distinct%u count%u undo%zu work%zu "
                  "previous%zu\n",
                  read, distinct, count, undo, work, previous_undo);
        /* Direct frame restoration can avoid both composition and evaluated
         * undo leaves. Only excessive work is a regression. */
        CHECK(undo <= 6 * count);
        CHECK(!previous_undo || undo <= 3 * previous_undo + 4);
        CHECK(work <= 64 * count * height * height);
        CHECK(shellsplit_test_source_scan_work() <= 512 * used);
        previous_undo = undo;
        shell_dep_graph_t *reference = malloc(sizeof(*reference));
        CHECK(reference);
        shellsplit_test_failure_cleanup_reference(true);
        CHECK(shell_dep_graph_parse(source, used, "/", limits, reference) ==
              SHELL_DEP_OK);
        shellsplit_test_failure_cleanup_reference(false);
        CHECK(shellsplit_test_graph_equal(graph, reference));
        free(reference);
#endif
      }
    }
  }
}

#ifdef SHELLSPLIT_TEST_ALLOCATOR
/* Compare complete public graphs with literal ordered execution of the same
 * undo leaves. Later operations change an old save, stop cleanup, or allocate
 * persistent descriptors: segment reuse must preserve every correlation. */
static void failure_cleanup_cache_equivalence(const shell_dep_limits_t *limits,
                                              shell_dep_graph_t *graph) {
  shell_dep_graph_t *reference = malloc(sizeof(*reference));
  CHECK(reference);
  const char *const scopes[] = {":", "{ :; }", "time { :; }", "\"$cmd\""};
  for (unsigned read = 0; read < 2; read++) {
    char direction = read ? '<' : '>';
    for (unsigned family = 0; family < 3; family++) {
      for (size_t scope = 0; scope < sizeof(scopes) / sizeof(scopes[0]);
           scope++) {
        for (unsigned count = 2; count <= 4; count *= 2) {
          char source[4096];
          int n = snprintf(source, sizeof(source),
                           "exec 3%c/tmp/cache-original 4%c/tmp/cache-other "
                           "|| exit; exec 8>&- 9>&- 10>&- 11>&- 12>&- 13>&- "
                           "14>&-; %s",
                           direction, direction, scopes[scope]);
          CHECK(n > 0 && (size_t)n < sizeof(source));
          size_t used = (size_t)n;
          for (unsigned i = 0; i < count; i++) {
            if (family == 0)
              n = snprintf(source + used, sizeof(source) - used,
                           " 3%c/tmp/cache-%u 10%c&3", direction, i, direction);
            else if (family == 1)
              n = snprintf(source + used, sizeof(source) - used,
                           " 3%c/tmp/cache-%u 12%c&10-", direction, i,
                           direction);
            else
              n = snprintf(source + used, sizeof(source) - used,
                           " {fd}%c/tmp/cache-%u 3%c&${fd}-", direction, i,
                           direction);
            CHECK(n > 0 && (size_t)n < sizeof(source) - used);
            used += (size_t)n;
          }
          n = snprintf(source + used, sizeof(source) - used,
                       " 7%c&8; echo TAIL >&3; cat <&3", direction);
          CHECK(n > 0 && (size_t)n < sizeof(source) - used);
          used += (size_t)n;
          shell_dep_error_t cached =
              shell_dep_graph_parse(source, used, "/", limits, graph);
          shellsplit_test_failure_cleanup_reference(true);
          shell_dep_error_t ordered =
              shell_dep_graph_parse(source, used, "/", limits, reference);
          shellsplit_test_failure_cleanup_reference(false);
          if (cached != ordered ||
              !shellsplit_test_graph_equal(graph, reference)) {
            fprintf(stderr, "cleanup cache differs: %s (%d/%d)\n", source,
                    cached, ordered);
            exit(EXIT_FAILURE);
          }
          CHECK(cached == SHELL_DEP_OK);
        }
      }
    }
  }
  /* These setups reach journal collection while preserving an operation's
   * entry and sibling read outcomes. Compare public results with the uncached
   * interpreter as well as exercising the lifetime under sanitizers. */
  static const char *const lifetime_cases[] = {
      "exec 4>/tmp/move-b 10>/tmp/move-a || exit; "
      "exec 11>&- 12>&- 13>&- 14>&- 3>&- 63>&-; "
      ": 10>&4- > >(echo next >&12)",
      "exec 4</tmp/move-b 10</tmp/move-a || exit; "
      "exec 11<&- 12<&- 13<&- 14<&-; read line 10<&4- <&12",
  };
  for (size_t i = 0; i < sizeof(lifetime_cases) / sizeof(lifetime_cases[0]);
       i++) {
    const char *source = lifetime_cases[i];
    CHECK(shell_dep_graph_parse(source, strlen(source), "/", limits, graph) ==
          SHELL_DEP_OK);
    shellsplit_test_failure_cleanup_reference(true);
    CHECK(shell_dep_graph_parse(source, strlen(source), "/", limits,
                                reference) == SHELL_DEP_OK);
    shellsplit_test_failure_cleanup_reference(false);
    CHECK(shellsplit_test_graph_equal(graph, reference));
  }
  free(reference);
}
#endif

int main(void) {
  static const struct {
    const char *word;
    shell_process_fd_target_t kind;
    uint32_t fd;
  } words[] = {
      {"3-", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"003-", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"\"3\"-", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"3\\-", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"$'3'-", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"3-\\\n", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"3-\\\n", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"3-\\\n", SHELL_PROCESS_FD_TARGET_MOVE, 3},
      {"\"3-\"", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"$'3-'", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"3-''", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"file-", SHELL_PROCESS_FD_TARGET_MOVE_INVALID, SHELL_PROCESS_FD_NONE},
      {"\"\"-", SHELL_PROCESS_FD_TARGET_MOVE_INVALID, SHELL_PROCESS_FD_NONE},
      {"''-", SHELL_PROCESS_FD_TARGET_MOVE_INVALID, SHELL_PROCESS_FD_NONE},
      {"\"\"", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"\"-\"-", SHELL_PROCESS_FD_TARGET_CLOSE, SHELL_PROCESS_FD_NONE},
      {"2147483648-", SHELL_PROCESS_FD_TARGET_INVALID, SHELL_PROCESS_FD_NONE},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    uint32_t fd;
    CHECK(shell_process_classify_static_fd_target(
              words[i].word, strlen(words[i].word), &fd) == words[i].kind);
    CHECK(fd == words[i].fd);
  }
  static const char *const groups[] = {
      "{ echo ok; } 4>&3-", "{ echo ok; } 4<& 3-", "{ echo ok; }>&\"3\"-",
      "{ echo ok; } 4>&${fd}-", "{ echo ok; } 4>&\"$fd\"-"};
  for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(groups[i], strlen(groups[i]), NULL,
                                 &processed) == SHELL_PROCESS_OK);
    CHECK(processed.group_io_op_count == 1);
    CHECK(processed.group_io_ops[0].kind == SHELL_GROUP_IO_MOVE_FD);
    shell_processed_commands_free(&processed);
  }
  static const char *const failed_groups[] = {
      "{ echo ok; } 4>&\"\"-", "{ echo ok; } 4<&''-", "{ echo ok; } 4>&\"\"",
      "{ echo ok; } 4<&''"};
  for (size_t i = 0; i < sizeof(failed_groups) / sizeof(failed_groups[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(failed_groups[i], strlen(failed_groups[i]),
                                 NULL, &processed) == SHELL_PROCESS_OK);
    CHECK(processed.group_io_op_count == 1);
    CHECK(processed.group_io_ops[0].kind == SHELL_GROUP_IO_FAILED_REDIRECT);
    shell_processed_commands_free(&processed);
  }
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  CHECK(shell_dep_workspace_size(&limits, &limits.workspace_size));
  limits.workspace = malloc(limits.workspace_size);
  shell_dep_graph_t *graph = malloc(sizeof(*graph));
  CHECK(limits.workspace && graph);
  failure_prefix_scaling(&limits, graph);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  failure_cleanup_cache_equivalence(&limits, graph);
#endif
  static const char *const dispatch_a[] = {"/tmp/dispatch-a"};
  static const char *const dispatch_both[] = {"/tmp/dispatch-a",
                                              "/tmp/dispatch-b"};
  static const struct {
    const char *source;
    const char *const *paths;
    size_t count;
  } dispatch_reads[] = {
      {"exec 3</tmp/dispatch-a || exit; exec 10<&- 11<&- 12<&-; "
       "\"$cmd\" 0<&3 {fd}<&3 0<&10",
       dispatch_a, 1},
      {"exec 0</tmp/dispatch-b 3</tmp/dispatch-a || exit; "
       "exec 10<&- 11<&- 12<&-; \"$cmd\" 0<&3 {fd}<&3 0<&10",
       dispatch_both, 2},
  };
  for (size_t i = 0; i < sizeof(dispatch_reads) / sizeof(dispatch_reads[0]);
       i++) {
    CHECK(shell_dep_graph_parse(dispatch_reads[i].source,
                                strlen(dispatch_reads[i].source), "/", &limits,
                                graph) == SHELL_DEP_OK);
    CHECK(command_routes_exact(graph, "\"$cmd\"", SHELL_EDGE_READ,
                               dispatch_reads[i].paths,
                               dispatch_reads[i].count));
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const struct {
    const char *source, *command;
    const char *const *paths;
    size_t count;
  } dispatch_cases[] = {
      {"exec 3>/tmp/dispatch-a || exit; exec 10>&- 11>&- 12>&-; "
       "\"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "\"$cmd\"", dispatch_a, 1},
      {"exec 3>/tmp/dispatch-a || exit; exec 10>&- 11>&- 12>&-; "
       "command \"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "command", dispatch_a, 1},
      {"exec 1>/tmp/dispatch-b 3>/tmp/dispatch-a || exit; "
       "exec 10>&- 11>&- 12>&-; \"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "\"$cmd\"", dispatch_both, 2},
      {"exec 3>/tmp/dispatch-a || exit; exec 10>&- 11>&- 12>&-; "
       "builtin \"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "builtin", dispatch_a, 0},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "! 0<&0 1>&3 2>&10 && printf payload >/tmp/dispatch-a",
       "printf", dispatch_a, 1},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "0<&0 1>&3 2>&10 && printf payload >/tmp/dispatch-a",
       "printf", dispatch_a, 0},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "! 0<<<literal 1>&3 2>&10 && printf payload >/tmp/dispatch-a",
       "printf", dispatch_a, 1},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "! 0<<EOF 1>&3 2>&10 && printf payload >/tmp/dispatch-a\nliteral\nEOF\n",
       "printf", dispatch_a, 1},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "0<&0 1>&3 2>&10 >\"$(printf payload >/tmp/dispatch-a; printf "
       "/dev/null)\"",
       "printf", dispatch_a, 0},
      {"exec 1>/tmp/dispatch-b 3>/tmp/dispatch-a || exit; "
       "exec 10>&- 11>&- 12>&-; \"$cmd\" 1>&3 {fd}>&3 "
       ">\"$(printf payload >&10; printf /dev/null)\"",
       "printf", dispatch_both, 2},
      {"exec 3>/tmp/dispatch-a || exit; exec 4>&- 10>&- 11>&- 12>&-; "
       "\"$cmd\" 4>&3-; echo payload >&3",
       "echo", dispatch_a, 1},
      {"exec 3>/tmp/dispatch-a || exit; exec 10>&- 11>&- 12>&-; "
       "0<&0 1>&3 {fd}>&3 1>&10; echo payload >&10",
       "echo", dispatch_a, 0},
  };
  for (size_t i = 0; i < sizeof(dispatch_cases) / sizeof(dispatch_cases[0]);
       i++) {
    shell_dep_error_t status = shell_dep_graph_parse(
        dispatch_cases[i].source, strlen(dispatch_cases[i].source), "/",
        &limits, graph);
    if (status != SHELL_DEP_OK ||
        !command_routes_exact(graph, dispatch_cases[i].command,
                              SHELL_EDGE_WRITE, dispatch_cases[i].paths,
                              dispatch_cases[i].count)) {
      fprintf(stderr, "dispatch case %zu: %s (status %d)\n", i,
              dispatch_cases[i].source, status);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const char *const publication_a[] = {"/tmp/publication-a"};
  /* Setup failure runs the actual registered undo list. Closing a live save
   * stops restoration, so an older stdout/stdin redirect remains installed. */
  for (unsigned read = 0; read < 2; read++) {
    char direction = read ? '<' : '>';
    unsigned stream = read ? 0 : 1;
    static const char *const scopes[] = {":", "{ :; }", "/bin/true", "\"$cmd\"",
                                         "builtin \"$cmd\""};
    static const char *const temporary[] = {"/tmp/failure-temporary"};
    static const char *const original[] = {"/tmp/failure-original"};
    static const char *const both[] = {"/tmp/failure-temporary",
                                       "/tmp/failure-original"};
    for (unsigned scope = 0; scope < 5; scope++) {
      char source[512];
      int n = snprintf(
          source, sizeof(source),
          "exec %u%c/tmp/failure-original 4%c/tmp/failure-temporary || exit; "
          "exec 10>&- 11>&- 12>&-; %s %u%c&4- 12%c&11- %u%c&11; %s",
          stream, direction, direction, scopes[scope], stream, direction,
          direction, stream, direction, read ? "cat" : "echo next");
      CHECK(n > 0 && (size_t)n < sizeof(source));
      CHECK(shell_dep_graph_parse(source, (size_t)n, "/", &limits, graph) ==
            SHELL_DEP_OK);
      const char *const *expected = scope == 2   ? original
                                    : scope == 3 ? both
                                                 : temporary;
      CHECK(command_routes_exact(graph, read ? "cat" : "echo",
                                 read ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                                 expected, scope == 3 ? 2 : 1));
      CHECK(shell_dep_graph_validate(graph).valid);
    }
  }
  static const struct {
    const char *source;
    const char *command;
    shell_dep_edge_type_t kind;
  } publication_cases[] = {
      {"exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
       "exec 10>&- 11>&- 12>&-; : 4>&- 10>&3-; echo next >&3",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
       "exec 10>&- 11>&- 12>&-; : 4>&1 10>& 3-; echo next >&3",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3</tmp/publication-a 4</tmp/publication-b || exit; "
       "exec 10<&- 11<&- 12<&-; : 4<&- 10<&3-; cat <&3",
       "cat", SHELL_EDGE_READ},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&-; "
       "exec {fd}>&3 {fd}>&3; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&-; "
       ": {fd}>&3 10>&-; echo next >&\"$fd\"",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&-; "
       "{ :; } {fd}>&3 10>&3-; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/publication-a || exit; "
       "builtin command /bin/true {fd}>&3; echo next >&\"$fd\"",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
       "exec 10>&- 11>&-; exec {fd}>&3 {fd}>&4; "
       "echo \"$(printf payload >&10)\"",
       "printf", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&-; "
       ": {fd}>&3 10>&-; echo \"$(printf payload >&\"$fd\")\"",
       "printf", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&-; "
       "probe && { :; } {fd}>&3 10>&- || : {fd}>&3; echo next >&\"$fd\"",
       "echo", SHELL_EDGE_WRITE},
  };
  static const char *const timed_scopes[] = {":", "{ :; }", "/bin/true",
                                             "\"$cmd\""};
  for (unsigned scope = 0; scope < 4; scope++) {
    char source[512];
    int n = snprintf(
        source, sizeof(source),
        "exec 2>/tmp/failure-original 4>/tmp/failure-temporary || exit; "
        "exec 10>&- 11>&- 12>&-; time %s 2>&4- 12>&11- 2>&11",
        timed_scopes[scope]);
    CHECK(n > 0 && (size_t)n < sizeof(source));
    CHECK(shell_dep_graph_parse(source, (size_t)n, "/", &limits, graph) ==
          SHELL_DEP_OK);
    unsigned timer_count = 0, paths = 0;
    for (uint32_t node = 0; node < graph->node_count; node++) {
      const shell_dep_node_t *timer = graph->nodes + node;
      if (timer->type != SHELL_NODE_TIME)
        continue;
      timer_count++;
      CHECK(timer->time.report_route == (scope == 3 ? SHELL_TIME_REPORT_MULTIPLE
                                                    : SHELL_TIME_REPORT_GRAPH));
      for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
        const shell_dep_edge_t *route = graph->edges + edge;
        if (route->from != node || route->type != SHELL_EDGE_WRITE)
          continue;
        const shell_dep_node_t *file = graph->nodes + route->to;
        CHECK(route->source_fd == 2 && file->type == SHELL_NODE_DOC &&
              file->doc.kind == SHELL_DOC_FILE);
        const char *expected =
            scope == 2 ? "/tmp/failure-original" : "/tmp/failure-temporary";
        if (scope == 3 &&
            file->doc.path_len == strlen("/tmp/failure-original") &&
            !memcmp(file->doc.path, "/tmp/failure-original",
                    file->doc.path_len))
          paths |= 2;
        else {
          CHECK(file->doc.path_len == strlen(expected) &&
                !memcmp(file->doc.path, expected, file->doc.path_len));
          paths |= 1;
        }
      }
    }
    CHECK(timer_count == 1 && paths == (scope == 3 ? 3u : 1u));
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  for (size_t i = 0;
       i < sizeof(publication_cases) / sizeof(publication_cases[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        publication_cases[i].source, strlen(publication_cases[i].source), "/",
        &limits, graph);
    if (error != SHELL_DEP_OK ||
        !command_routes_exact(graph, publication_cases[i].command,
                              publication_cases[i].kind, publication_a, 1)) {
      fprintf(stderr, "publication case %zu: %s (error %d)\n", i,
              publication_cases[i].source, error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  /* Each fixture establishes the observed slots, independently of inherited
   * high-FD occupancy. Earlier saves make the move destination live. */
  static const char *const setup_scopes[] = {":", "{ :; }", "/bin/true",
                                             "exec"};
  for (unsigned input = 0; input < 2; input++)
    for (unsigned scope = 0; scope < 4; scope++)
      for (unsigned close = 0; close < 2; close++)
        for (unsigned spelling = 0; spelling < 3; spelling++)
          for (unsigned failure = 0; failure < 2; failure++) {
            const char *direction = input ? "<" : ">";
            const char *move = spelling == 0   ? "3-"
                               : spelling == 1 ? " 3-"
                                               : "\"3\"-";
            char source[512];
            int length = snprintf(
                source, sizeof(source),
                "exec 3%s/tmp/publication-a 4%s/tmp/publication-b || exit; "
                "exec 8>&- 10>&- 11>&- 12>&- 13>&-; %s 4%s&%s 10%s&%s%s; %s",
                direction, direction, setup_scopes[scope], direction,
                close ? "-" : (input ? "0" : "1"), direction, move,
                failure ? " 5>&8" : "", input ? "cat <&3" : "echo next >&3");
            CHECK(length > 0 && (size_t)length < sizeof(source));
            shell_dep_error_t error = shell_dep_graph_parse(
                source, (size_t)length, "/", &limits, graph);
            size_t routes = scope != 3 || failure ? 1 : 0;
            if (error != SHELL_DEP_OK ||
                !command_routes_exact(graph, input ? "cat" : "echo",
                                      input ? SHELL_EDGE_READ
                                            : SHELL_EDGE_WRITE,
                                      publication_a, routes)) {
              fprintf(stderr, "undo matrix: %s (error %d)\n", source, error);
              shell_dep_graph_dump(graph, stderr);
              return EXIT_FAILURE;
            }
            CHECK(shell_dep_graph_validate(graph).valid);
          }
  static const char *const publication_b[] = {"/tmp/publication-b"};
  static const struct {
    const char *source;
    const char *const *paths;
    size_t count;
  } unwind_cases[] = {
      {"exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
       "exec 10>&- 11>&- 12>&-; exec {fd}>&3; "
       ": 3>&${fd}- {fd}>&4; echo MARK >&10",
       publication_a, 1},
      {"exec 3>/tmp/publication-a || exit; "
       "exec 10>&- 11>&- 12>&-; exec {fd}>&3; "
       ": 3>&${fd}- {fd}>&-; echo MARK >&10",
       publication_a, 1},
      {"exec 3>/tmp/publication-a || exit; "
       "exec 10>&- 11>&- 12>&-; exec {fd}>&3; "
       ": 3>&${fd}- 11>&3-; echo MARK >&10",
       publication_a, 1},
      {"exec 4>&-; exec 3>/tmp/publication-a || exit; "
       "{ :; } 4>&3-; echo MARK >&3",
       NULL, 0},
      {"exec 4>&-; exec 3>/tmp/publication-a || exit; "
       "{ :; } 4>&3- || echo MARK >&3",
       NULL, 0},
      {"exec 3>/tmp/publication-a 20>/tmp/publication-b || exit; "
       "exec 10>&- 11>&- 21>&- 22>&-; "
       "{ echo MARK >&10; } 3>&20-",
       publication_b, 1},
      {"exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
       "exec 8>&- 10>&- 11>&- 12>&-; exec {fd}>&3; "
       ": 3>&${fd}- {fd}>&4 5>&8; echo MARK >&10",
       publication_a, 1},
      {"exec 3>/tmp/publication-a || exit; "
       "exec 10>&- 11>&- 12>&-; exec {fd}>&3; "
       "exec {fd}>&- 11>&3-; echo MARK >&11",
       NULL, 0},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&-; "
       "{ exec 10>/tmp/publication-b; echo MARK >&10; } 3>&1",
       publication_a, 1},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&- 12>&-; "
       "{ exec 10>&-; exec 10>&1; exec 10>/tmp/publication-b; } 3>&1; "
       "echo MARK >&3",
       publication_b, 1},
      {"exec 3>/tmp/publication-a || exit; exec 10>&- 11>&- 12>&-; "
       "{ exec 11>&10; exec 11>/tmp/publication-b; echo MARK >&11; } 3>&1",
       publication_a, 1},
  };
  for (size_t i = 0; i < sizeof(unwind_cases) / sizeof(unwind_cases[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        unwind_cases[i].source, strlen(unwind_cases[i].source), "/", &limits,
        graph);
    if (error != SHELL_DEP_OK ||
        !command_routes_exact(graph, "echo", SHELL_EDGE_WRITE,
                              unwind_cases[i].paths, unwind_cases[i].count)) {
      fprintf(stderr, "unwind case %zu: %s (error %d)\n", i,
              unwind_cases[i].source, error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const char *const unwind_scopes[] = {":", "{ :; }", "/bin/true",
                                              "exec"};
  for (unsigned input = 0; input < 2; input++)
    for (unsigned scope = 0; scope < 4; scope++)
      for (unsigned action = 0; action < 3; action++)
        for (unsigned failure = 0; failure < 2; failure++) {
          char tail[64], source[640];
          char direction = input ? '<' : '>';
          if (action == 0)
            snprintf(tail, sizeof(tail), "{fd}%c&4", direction);
          else if (action == 1)
            snprintf(tail, sizeof(tail), "{fd}%c&-", direction);
          else
            snprintf(tail, sizeof(tail), "11%c&3-", direction);
          int length = snprintf(
              source, sizeof(source),
              "exec 3%c/tmp/publication-a 4%c/tmp/publication-b || exit; "
              "exec 8>&- 10>&- 11>&- 12>&- 13>&-; exec {fd}%c&3; "
              "%s 3%c&${fd}- %s%s; %s",
              direction, direction, direction, unwind_scopes[scope], direction,
              tail, failure ? " 5>&8" : "",
              input ? "cat <&10" : "echo MARK >&10");
          CHECK(length > 0 && (size_t)length < sizeof(source));
          size_t count = scope == 3 && !failure && action != 0 ? 0 : 1;
          const char *const *paths = scope == 3 && !failure && action == 0
                                         ? publication_b
                                         : publication_a;
          shell_dep_error_t error = shell_dep_graph_parse(
              source, (size_t)length, "/", &limits, graph);
          if (error != SHELL_DEP_OK ||
              !command_routes_exact(graph, input ? "cat" : "echo",
                                    input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                                    paths, count)) {
            fprintf(stderr, "ordered unwind matrix: %s (error %d)\n", source,
                    error);
            shell_dep_graph_dump(graph, stderr);
            return EXIT_FAILURE;
          }
          CHECK(shell_dep_graph_validate(graph).valid);
        }
  static const char *const nested_unwind[] = {
      "exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
      "exec 10>&- 11>&- 12>&-; exec {fd}>&3; "
      ": 3>&${fd}- {fd}>&4; echo \"$(printf MARK >&10)\"",
      "exec 3>/tmp/publication-a || exit; exec 10>&- 11>&- 12>&-; "
      "exec {fd}>&3; : 3>&${fd}- {fd}>&-; cat < <(printf MARK >&10)",
      "exec 3>/tmp/publication-a || exit; exec 10>&- 11>&- 12>&-; "
      "exec {fd}>&3; : 3>&${fd}- 11>&3-; echo \"$(printf MARK >&10)\"",
  };
  for (size_t i = 0; i < sizeof(nested_unwind) / sizeof(nested_unwind[0]);
       i++) {
    CHECK(shell_dep_graph_parse(nested_unwind[i], strlen(nested_unwind[i]), "/",
                                &limits, graph) == SHELL_DEP_OK);
    CHECK(command_routes_exact(graph, "printf", SHELL_EDGE_WRITE, publication_a,
                               1));
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  /* A child shell inherits the physical saved-FD property, not just bytes.
   * Closing fd 9 makes the group's temporary open unambiguously low, so its
   * saved standard stream is fd 10 regardless of other inherited occupancy. */
  for (unsigned input = 0; input < 2; input++)
    for (unsigned form = 0; form < 4; form++)
      for (unsigned action = 0; action < 3; action++) {
        char body[192], wrapper[256], source[512];
        char direction = input ? '<' : '>';
        int body_length = snprintf(body, sizeof(body),
                                   "%sexec %u%c/tmp/publication-b; %s %c&%u",
                                   action == 1   ? "exec 10>&-; "
                                   : action == 2 ? "exec 11>&10; "
                                                 : "",
                                   action == 2 ? 11u : 10u, direction,
                                   input ? "/bin/cat" : "printf CHILD",
                                   direction, action == 2 ? 11u : 10u);
        CHECK(body_length > 0 && (size_t)body_length < sizeof(body));
        int wrapper_length;
        if (form == 0)
          wrapper_length =
              snprintf(wrapper, sizeof(wrapper), "echo \"$(%s)\"", body);
        else if (form == 1)
          wrapper_length = snprintf(wrapper, sizeof(wrapper),
                                    "echo \"$(echo \"$(%s)\")\"", body);
        else if (form == 2)
          wrapper_length =
              snprintf(wrapper, sizeof(wrapper), "cat < <(%s)", body);
        else
          wrapper_length =
              snprintf(wrapper, sizeof(wrapper), ": > >(%s)", body);
        CHECK(wrapper_length > 0 && (size_t)wrapper_length < sizeof(wrapper));
        int length = snprintf(
            source, sizeof(source),
            "exec %u%c/tmp/publication-a || exit; "
            "exec 9>&- 10>&- 11>&- 12>&-; { %s; } %u%c/tmp/publication-c",
            input ? 0u : 1u, direction, wrapper, input ? 0u : 1u, direction);
        CHECK(length > 0 && (size_t)length < sizeof(source));
        shell_dep_error_t error =
            shell_dep_graph_parse(source, (size_t)length, "/", &limits, graph);
        if (error != SHELL_DEP_OK ||
            !command_routes_exact(graph, input ? "/bin/cat" : "printf",
                                  input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                                  action == 1 ? publication_b : publication_a,
                                  1)) {
          fprintf(stderr, "inherited scratch matrix: %s (error %d)\n", source,
                  error);
          shell_dep_graph_dump(graph, stderr);
          return EXIT_FAILURE;
        }
        CHECK(shell_dep_graph_validate(graph).valid);
      }
  const char *conditional_scratch =
      "exec 1>/tmp/publication-a || exit; exec 9>&- 10>&- 11>&- 12>&-; "
      "exec 10>/tmp/publication-c || exit; probe && exec 10>&-; "
      "{ echo \"$(exec 10>/tmp/publication-b || exit; printf CHILD >&10)\"; } "
      "1>/tmp/publication-c";
  static const char *const conditional_scratch_paths[] = {"/tmp/publication-a",
                                                          "/tmp/publication-b"};
  CHECK(shell_dep_graph_parse(conditional_scratch, strlen(conditional_scratch),
                              "/", &limits, graph) == SHELL_DEP_OK);
  CHECK(command_routes_exact(graph, "printf", SHELL_EDGE_WRITE,
                             conditional_scratch_paths, 2));
  CHECK(shell_dep_graph_validate(graph).valid);
  /* Numeric setup with a post-redirect builtin variable effect still rolls
   * back every possible failure prefix. Neither the temporary stdin nor the
   * unreached read assignment can escape to the next command. Two failure
   * boundaries also exercise the non-observable allocator-fact join. */
  const char *failed_read_setup =
      "exec 0</tmp/publication-a || exit; exec 5<&-; "
      "read value 0</tmp/publication-b 4<&5; /bin/cat";
  CHECK(shell_dep_graph_parse(failed_read_setup, strlen(failed_read_setup), "/",
                              &limits, graph) == SHELL_DEP_OK);
  CHECK(command_routes_exact(graph, "/bin/cat", SHELL_EDGE_READ, publication_a,
                             1));
  CHECK(shell_dep_graph_validate(graph).valid);
  static const char *const local_alias_closes[] = {
      "exec 3>/tmp/publication-a || exit; exec 10>&-; exec {fd}>&3; "
      ": 10>&- 3>&${fd}- || echo MARK >&10",
      "exec 3>/tmp/publication-a || exit; exec 10>&-; exec {fd}>&3; "
      "{ :; } 10>&- 3>&${fd}- || echo MARK >&10",
  };
  for (size_t i = 0;
       i < sizeof(local_alias_closes) / sizeof(local_alias_closes[0]); i++) {
    CHECK(shell_dep_graph_parse(local_alias_closes[i],
                                strlen(local_alias_closes[i]), "/", &limits,
                                graph) == SHELL_DEP_OK);
    CHECK(command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, publication_a,
                               1));
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  for (unsigned input = 0; input < 2; input++)
    for (unsigned scope = 0; scope < 4; scope++)
      for (unsigned modification = 0; modification < 3; modification++)
        for (unsigned failure = 0; failure < 2; failure++) {
          const char *direction = input ? "<" : ">";
          char tail[64], source[512];
          if (modification == 0)
            snprintf(tail, sizeof(tail), "{fd}%s&4", direction);
          else
            snprintf(tail, sizeof(tail), "10%s&%s", direction,
                     modification == 1 ? "-" : "4-");
          int length = snprintf(
              source, sizeof(source),
              "exec 3%s/tmp/publication-a 4%s/tmp/publication-b || exit; "
              "exec 8>&- 10>&- 11>&- 12>&- 13>&-; %s {fd}%s&3 %s%s; %s",
              direction, direction, setup_scopes[scope], direction, tail,
              failure ? " 5>&8" : "", input ? "cat <&10" : "echo next >&10");
          CHECK(length > 0 && (size_t)length < sizeof(source));
          shell_dep_error_t error = shell_dep_graph_parse(
              source, (size_t)length, "/", &limits, graph);
          size_t routes =
              scope == 2 || (scope == 3 && modification == 1 && !failure) ? 0
                                                                          : 1;
          const char *const *paths = scope == 3 && modification == 2 && !failure
                                         ? publication_b
                                         : publication_a;
          if (error != SHELL_DEP_OK ||
              !command_routes_exact(graph, input ? "cat" : "echo",
                                    input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                                    paths, routes)) {
            fprintf(stderr, "allocation matrix: %s (error %d)\n", source,
                    error);
            shell_dep_graph_dump(graph, stderr);
            return EXIT_FAILURE;
          }
          CHECK(shell_dep_graph_validate(graph).valid);
        }
  static const char *const scratch_base[] = {"/tmp/scratch-base"};
  static const char *const scratch_other[] = {"/tmp/scratch-other"};
  static const struct {
    const char *source;
    const char *command;
    shell_dep_edge_type_t kind;
    const char *const *paths;
    size_t count;
  } scratch_cases[] = {
      {"exec 3>/tmp/scratch-base || exit; "
       "exec 4>/tmp/scratch-other || exit; exec 10>&-; "
       "{ printf payload >&10; } 3>&4-",
       "printf", SHELL_EDGE_WRITE, scratch_base, 1},
      {"exec 3>/tmp/scratch-base || exit; "
       "exec 4>/tmp/scratch-other || exit; exec 10>&- 11>&- 12>&-; "
       "{ printf payload >&11; } 3>&4-",
       "printf", SHELL_EDGE_WRITE, scratch_other, 1},
      {"exec 3>/tmp/scratch-base || exit; "
       "exec 4>/tmp/scratch-other || exit; exec 10>&- 11>&- 12>&-; "
       "{ :; } 3>&4-; printf payload >&11",
       "printf", SHELL_EDGE_WRITE, NULL, 0},
      {"exec 3>/tmp/scratch-base || exit; "
       "exec 4>/tmp/scratch-other || exit; exec 10>&- 11>&- 12>&-; "
       "{ :; } 3>&4-; echo \"$(printf payload >&11)\"",
       "printf", SHELL_EDGE_WRITE, NULL, 0},
      {"exec 3>/tmp/scratch-base || exit; exec 11>&- 12>&-; "
       "{ :; } 3>&1; printf payload >&11",
       "printf", SHELL_EDGE_WRITE, NULL, 0},
      {"exec 3</tmp/scratch-base || exit; exec 11<&- 12<&-; "
       "{ :; } 3<&0; cat <&11",
       "cat", SHELL_EDGE_READ, NULL, 0},
      {"exec 3>/tmp/scratch-base || exit; "
       "exec 10>& - 11>& - 12>& -; { printf payload >&11; } 3>&1",
       "printf", SHELL_EDGE_WRITE, NULL, 0},
      {"exec 3</tmp/scratch-base || exit; "
       "exec 10<& - 11<& - 12<& -; { cat <&11; } 3<&0",
       "cat", SHELL_EDGE_READ, NULL, 0},
  };
  for (size_t i = 0; i < sizeof(scratch_cases) / sizeof(scratch_cases[0]);
       i++) {
    shell_dep_error_t status = shell_dep_graph_parse(
        scratch_cases[i].source, strlen(scratch_cases[i].source), "/", &limits,
        graph);
    if (status != SHELL_DEP_OK ||
        !command_routes_exact(graph, scratch_cases[i].command,
                              scratch_cases[i].kind, scratch_cases[i].paths,
                              scratch_cases[i].count)) {
      fprintf(stderr, "scratch case %zu: %s (status %d)\n", i,
              scratch_cases[i].source, status);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const struct {
    const char *source;
    bool writes;
  } cases[] = {
      {"exec 3>/tmp/move-out; exec 1>&3-; echo next", true},
      {"exec 4>&-; exec 3>/tmp/move-out; : 4>&3-; echo next >&3", false},
      {"exec 3>/tmp/move-out 4>&1; : 4>&3-; echo next >&3", true},
      {"exec 3>/tmp/move-out; : >&3-; echo next >&3", true},
      {"exec 3>/tmp/move-out; : 3>&3-; echo next >&3", true},
      {"exec 3>/tmp/move-out 4>&- && /bin/true 4>&3- && echo next >&3", true},
      {"exec 4>&-; exec 3>/tmp/move-out; command /bin/true 4>&3-; "
       "echo next >&3",
       true},
      {"exec 4>&-; exec 3>/tmp/move-out; builtin command /bin/true 4>&3-; "
       "echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; "
       "command builtin command /bin/true 4>&3-; echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; builtin \"$runner\" 4>&3-; "
       "echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; /bin/true 4>&3- 5>&8; "
       "echo next >&3",
       true},
      {"exec 4>&-; exec 3>/tmp/move-out; builtin true 4>&3-; "
       "echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; command true 4>&3-; "
       "echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; builtin /bin/true 4>&3-; "
       "echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; \"$runner\" 4>&3-; "
       "echo next >&3",
       true},
      {"exec 4>&-; exec 3>/tmp/move-out; { exec 3>/tmp/move-out; } "
       "4>&3-; echo next >&3",
       true},
      {"exec 4>&-; exec 3>/tmp/move-out; "
       "{ { exec 3>/tmp/move-out; }; } 4>&3-; echo next >&3",
       true},
      {"exec 4>&-; exec 3>/tmp/old; { exec 3>/tmp/move-out; } "
       "4>&3- 3>/tmp/local; echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/old; { exec 3>/tmp/move-out; } "
       "3>/tmp/local 4>&3-; echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; { :; } 4>&3-; echo next >&3", false},
      {"exec 3>/tmp/move-out 4>&1; { :; } 4>&3-; echo next >&3", true},
      {"exec 4>&- 8>&-; exec 3>/tmp/move-out; : 4>&3- 5>&8; echo next >&3",
       false},
      {"exec 4>&- 8>&-; exec 3>/tmp/move-out; exec 4>&3- 5>&8; echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; : 4>&3- 3>/tmp/local; echo next >&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; : 3>/tmp/local 4>&3-; echo next >&3",
       true},
      {"exec {fd}>/tmp/move-out; exec 1>&${fd}-; echo next", true},
      {"exec {fd}>/tmp/move-out; exec {fd}>&${fd}-; echo next >&$fd", true},
      {"exec {fd}>/tmp/move-out; /bin/true {fd}>/tmp/local; "
       "echo next >&\"$fd\"",
       true},
      {"exec {fd}>/tmp/move-out; /bin/true {fd}>&1-; "
       "echo next >&\"$fd\"",
       true},
      {"exec 10>&-; exec {fd}>/tmp/move-out; exec 10>&${fd}-; "
       "echo next >&\"$fd\"",
       true},
      {"exec 3>/tmp/move-out; : {out}>&3-; echo next >&3", true},
      {"exec 3>/tmp/move-out; {out}>&3-; echo next >&3", true},
      {"exec 4>&-; exec 3>/tmp/move-out; { :; } 4>&3- 3>/tmp/local; echo next "
       ">&3",
       false},
      {"exec 4>&-; exec 3>/tmp/move-out; { :; } 3>/tmp/local 4>&3-; echo next "
       ">&3",
       true},
      {"exec 3>/tmp/move-out; : 4>&\"3-\"; echo next >&3", true},
      {"exec 3>/tmp/move-out; : 4>&$'3-'; echo next >&3", true},
      {"exec 3>/tmp/move-out; : 4>&combined; echo next >&3", true},
      {"exec 3>/tmp/move-out; : >&file-; echo next >&3", true},
      {"exec {fd}>/tmp/move-out; exec 3>&-; IFS=0123456789; "
       ": 3>&${fd}- && echo next >&\"$fd\"",
       true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        cases[i].source, strlen(cases[i].source), "/", &limits, graph);
    if (error != SHELL_DEP_OK ||
        command_writes(graph, "echo", "/tmp/move-out") != cases[i].writes) {
      fprintf(stderr, "move case %zu: %s (error %d)\n", i, cases[i].source,
              error);
      shell_dep_graph_dump(graph, stderr);
      free(graph);
      free(limits.workspace);
      return EXIT_FAILURE;
    }
    CHECK(shellsplit_test_depgraph_invariants(
        cases[i].source, strlen(cases[i].source), error, graph, &limits));
    if (i == 0) {
      uint32_t copy = UINT32_MAX, close = UINT32_MAX;
      for (uint32_t j = 0; j < graph->edge_count; j++) {
        const shell_dep_edge_t *edge = graph->edges + j;
        if (edge->type == SHELL_EDGE_FD_OPEN &&
            edge->flags == SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP &&
            edge->source_fd == 3 && edge->target_fd == 1)
          copy = j;
        if (edge->type == SHELL_EDGE_FD_CLOSE && edge->source_fd == 3)
          close = j;
      }
      CHECK(copy != UINT32_MAX && close != UINT32_MAX && copy < close);
      CHECK(graph->edges[copy].from == graph->edges[close].from);
    }
  }
  static const char *const read_cases[] = {
      "exec 3</tmp/move-in; exec 0<&3-; cat",
      "exec 3</tmp/move-in; : <&3-; cat <&3",
      "echo \"$(exec 3</tmp/move-in; exec 0<&3-; cat)\"",
      "exec {fd}</tmp/move-in; exec 0<&${fd}-; cat",
      "exec {fd}</tmp/move-in; exec 0<&\"$fd\"-; cat",
      "exec 0<&-; exec 3</tmp/move-in; 0<&3-; cat <&3",
      "exec 4<&-; exec 3</tmp/move-in; /bin/true 4<&3-; cat <&3",
      "exec 4<&-; exec 3</tmp/old; { exec 3</tmp/move-in; } 4<&3-; cat <&3",
      ("exec 4<&-; exec 3</tmp/old; "
       "{ { exec 3</tmp/move-in; }; } 4<&3-; cat <&3"),
  };
  for (size_t i = 0; i < sizeof(read_cases) / sizeof(read_cases[0]); i++) {
    CHECK(shell_dep_graph_parse(read_cases[i], strlen(read_cases[i]), "/",
                                &limits, graph) == SHELL_DEP_OK);
    bool read = false;
    for (uint32_t j = 0; j < graph->edge_count; j++) {
      const shell_dep_edge_t *edge = graph->edges + j;
      if (edge->type == SHELL_EDGE_READ &&
          graph->nodes[edge->from].type == SHELL_NODE_DOC &&
          graph->nodes[edge->from].doc.kind == SHELL_DOC_FILE &&
          graph->nodes[edge->from].doc.path_len == sizeof("/tmp/move-in") - 1 &&
          !memcmp(graph->nodes[edge->from].doc.path, "/tmp/move-in",
                  sizeof("/tmp/move-in") - 1) &&
          graph->nodes[edge->to].type == SHELL_NODE_CMD &&
          graph->nodes[edge->to].cmd.token_count &&
          graph->nodes[edge->to].cmd.token_lens[0] == 3 &&
          !memcmp(graph->nodes[edge->to].cmd.tokens[0], "cat", 3))
        read = true;
    }
    CHECK(read && shell_dep_graph_validate(graph).valid);
  }
  static const char conditional[] =
      "exec 4>&1; probe && exec {pad}>/tmp/move-pad {fd}>/tmp/move-a || "
      "exec {fd}>/tmp/move-b; { :; } 4>&${fd}-; echo next >&\"$fd\"";
  CHECK(shell_dep_graph_parse(conditional, sizeof(conditional) - 1, "/",
                              &limits, graph) == SHELL_DEP_OK);
  CHECK(command_writes(graph, "echo", "/tmp/move-a"));
  CHECK(command_writes(graph, "echo", "/tmp/move-b"));
  CHECK(shell_dep_graph_validate(graph).valid);
  static const char *const restored[] = {"/tmp/move-b"};
  static const char *const alternatives[] = {"/tmp/move-a", "/tmp/move-b"};
  /* Later redirects can read the undo saves made earlier in the same setup.
   * Moving 4 into the occupied 10 saves their old values in 12 and 11. */
  static const char scratch_source[] =
      "exec 4>/tmp/move-b 10>/tmp/move-a || exit; "
      "exec 11>&- 12>&-; echo next 10>&4- >&12";
  shell_dep_error_t scratch_error = shell_dep_graph_parse(
      scratch_source, sizeof(scratch_source) - 1, "/", &limits, graph);
  if (scratch_error != SHELL_DEP_OK ||
      !command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, restored, 1)) {
    fprintf(stderr, "same-setup scratch source (error %d)\n", scratch_error);
    shell_dep_graph_dump(graph, stderr);
    return EXIT_FAILURE;
  }
  CHECK(shell_dep_graph_validate(graph).valid);
  static const struct {
    const char *source;
    const char *command;
    shell_dep_edge_type_t kind;
    const char *const *paths;
    size_t count;
  } setup_save_cases[] = {
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "echo next 10>&4 1>&11",
       "echo", SHELL_EDGE_WRITE, alternatives, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "echo next 10>&4- 14>&12- >&14",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "exec 10>&4- 14>&12-; echo next >&14",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "{ echo next >&14; } 10>&4- 14>&12-",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       ": 10>&4- 14>&12; echo next >&4",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       ": 10>&4- 14>&12-; echo next >&4",
       "echo", SHELL_EDGE_WRITE, restored, 0},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "/bin/true 10>&4- 14>&12-; echo next >&4",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "/bin/echo next 10>&4- >&12",
       "/bin/echo", SHELL_EDGE_WRITE, restored, 0},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "{ /bin/echo next >&12; } 10>&4-",
       "/bin/echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "{ :; } 10>&4- 14>&12-; echo next >&4",
       "echo", SHELL_EDGE_WRITE, restored, 0},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       ": 10>&4- >\"$(echo next >&12; printf /dev/null)\"",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       ": \"$(echo next >&12)\" 10>&4-",
       "echo", SHELL_EDGE_WRITE, restored, 0},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&- 3>&- 63>&-; "
       ": 10>&4- > >(echo next >&12)",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&- 3>&- 63>&-; "
       ": <(echo next >&12) 10>&4-",
       "echo", SHELL_EDGE_WRITE, restored, 0},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "{ exec 12>&-; echo next >&14; } 10>&4- 14>&12-",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "{ exec 12>&-; } 10>&4- 14>&12-; echo next >&14",
       "echo", SHELL_EDGE_WRITE, restored, 0},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "time { echo next >&14; } 10>&4- 14>&12-",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 4</tmp/move-b 10</tmp/move-a || exit; exec 11<&- 12<&- 13<&- "
       "14<&-; "
       "exec 10<&4- 14<&12-; cat <&14",
       "cat", SHELL_EDGE_READ, restored, 1},
      {"exec 4</tmp/move-b 10</tmp/move-a || exit; exec 11<&- 12<&- 13<&- "
       "14<&-; "
       "{ cat <&14; } 10<&4- 14<&12-",
       "cat", SHELL_EDGE_READ, restored, 1},
      {"exec 4</tmp/move-b 10</tmp/move-a || exit; exec 11<&- 12<&- 13<&- "
       "14<&-; "
       "read line 10<&4- <&12",
       "read", SHELL_EDGE_READ, restored, 1},
      {"exec 4</tmp/move-b 10</tmp/move-a || exit; exec 11<&- 12<&- 13<&- "
       "14<&-; "
       "cat 10<&4- <&12",
       "cat", SHELL_EDGE_READ, restored, 0},
      {"exec 4</tmp/move-b 10</tmp/move-a || exit; "
       "exec 11<&- 12<&- 13<&- 14<&-; "
       ": 10<&4- >\"$(cat <&12 >/dev/null; printf /dev/null)\"",
       "cat", SHELL_EDGE_READ, restored, 1},
      {"exec 4</tmp/move-b 10</tmp/move-a || exit; "
       "exec 11<&- 12<&- 13<&- 14<&-; : \"$(cat <&12)\" 10<&4-",
       "cat", SHELL_EDGE_READ, restored, 0},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       "probe && exec 10>&4- 14>&12-; echo next >&14",
       "echo", SHELL_EDGE_WRITE, restored, 1},
      {"exec 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- 14>&-; "
       "{ probe && exec 4>/tmp/move-a || exec 4>/tmp/move-b; } && "
       "echo next 10>&4- >&12",
       "echo", SHELL_EDGE_WRITE, alternatives, 2},
      {"exec 4>/tmp/move-b 10>/tmp/move-a || exit; exec 11>&- 12>&- 13>&- "
       "14>&-; "
       ": 10>&4- >&12; echo next 10>&4- >&12",
       "echo", SHELL_EDGE_WRITE, restored, 1},
  };
  for (size_t i = 0; i < sizeof(setup_save_cases) / sizeof(setup_save_cases[0]);
       i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        setup_save_cases[i].source, strlen(setup_save_cases[i].source), "/",
        &limits, graph);
    if (error != SHELL_DEP_OK ||
        !command_routes_exact(
            graph, setup_save_cases[i].command, setup_save_cases[i].kind,
            setup_save_cases[i].paths, setup_save_cases[i].count)) {
      fprintf(stderr, "scratch case %zu: %s (error %d)\n", i,
              setup_save_cases[i].source, error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const char correlated_source[] =
      "exec 3>&- 10>&- 11>&-; "
      "{ probe && exec {fd}>/tmp/move-a || "
      "exec {pad}>/tmp/move-pad {fd}>/tmp/move-b; } && "
      "{ exec 10>&${fd}-; echo next >&10; }";
  static const struct {
    const char *source;
    const char *command;
    shell_dep_edge_type_t kind;
    bool conditional;
  } exact_cases[] = {
      {"exec 3>/tmp/move-a 4>/tmp/move-b; : 3>&4- 3>&4; echo next >&4", "echo",
       SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a 4>/tmp/move-b; exec 3>&4- 3>&4; echo next >&4",
       "echo", SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a 4>/tmp/move-b; { :; } 3>&4- 3>&4; echo next >&4",
       "echo", SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
       "probe && { :; } 3>&4-; echo next >&4",
       "echo", SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a 4>/tmp/move-b; /bin/true 3>&4- 3>&4; echo next >&4",
       "echo", SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a 4>/tmp/move-b; : 3>&4- 3>&4-; echo next >&4", "echo",
       SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a 4>/tmp/move-b; : 4>&1 3>&4- 3>&4; echo next >&4",
       "echo", SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a 4>/tmp/move-b; "
       ": 3>&4- 4>&1 3>&4- 3>&4; echo next >&4",
       "echo", SHELL_EDGE_WRITE, false},
      {"exec 3>/tmp/move-a; exec {fd}>/tmp/move-b; "
       ": 3>&${fd}- 3>&\"$fd\"; echo next >&\"$fd\"",
       "echo", SHELL_EDGE_WRITE, false},
      {"exec 3</tmp/move-a 4</tmp/move-b; : 3<&4- 3<&4; cat <&4", "cat",
       SHELL_EDGE_READ, false},
      {"exec 3</tmp/move-a 4</tmp/move-b; { :; } 3<&4- 3<&4; cat <&4", "cat",
       SHELL_EDGE_READ, false},
      {correlated_source, "echo", SHELL_EDGE_WRITE, true},
      {"exec 3>&- 10>&- 11>&-; "
       "{ probe && exec {fd}>/tmp/move-a || "
       "exec {pad}>/tmp/move-pad {fd}>/tmp/move-b; } && "
       "{ exec 4>&${fd}-; echo next >&4; }",
       "echo", SHELL_EDGE_WRITE, true},
      {"exec 3<&- 10<&- 11<&-; "
       "{ probe && exec {fd}</tmp/move-a || "
       "exec {pad}</tmp/move-pad {fd}</tmp/move-b; } && "
       "{ exec 0<&${fd}-; cat; }",
       "cat", SHELL_EDGE_READ, true},
      {"exec 3>&- 10>&- 11>&-; "
       "{ probe && exec {fd}>/tmp/move-a || "
       "exec {pad}>/tmp/move-pad {fd}>/tmp/move-b; } && "
       "{ exec 4>&${fd}; echo next >&4; }",
       "echo", SHELL_EDGE_WRITE, true},
      {"(exec 3>&- 10>&- 11>&-; "
       "{ probe && exec {fd}>/tmp/move-a || "
       "exec {pad}>/tmp/move-pad {fd}>/tmp/move-b; } && "
       "{ exec 10>&${fd}-; echo next >&10; })",
       "echo", SHELL_EDGE_WRITE, true},
      {"echo \"$(exec 3>&- 10>&- 11>&-; "
       "{ probe && exec {fd}>/tmp/move-a || "
       "exec {pad}>/tmp/move-pad {fd}>/tmp/move-b; } && "
       "{ exec 4>&${fd}-; printf next >&4; })\"",
       "printf", SHELL_EDGE_WRITE, true},
      {"exec 3>&- 10>&- 11>&-; "
       "{ probe && exec {fd}>/tmp/move-a || "
       "exec {pad}>/tmp/move-pad {fd}>/tmp/move-b; } && "
       "echo \"$(exec 4>&${fd}-; printf next >&4)\"",
       "printf", SHELL_EDGE_WRITE, true},
  };
  for (size_t i = 0; i < sizeof(exact_cases) / sizeof(exact_cases[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        exact_cases[i].source, strlen(exact_cases[i].source), "/", &limits,
        graph);
    if (error != SHELL_DEP_OK ||
        !command_routes_exact(
            graph, exact_cases[i].command, exact_cases[i].kind,
            exact_cases[i].conditional ? alternatives : restored,
            exact_cases[i].conditional ? 2 : 1)) {
      fprintf(stderr, "exact move case %zu: %s (error %d)\n", i,
              exact_cases[i].source, error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const struct {
    const char *source;
    const char *command;
    shell_dep_edge_type_t kind;
  } undo_cases[] = {
      {"exec 3>/tmp/move-a || exit; exec 4>/tmp/move-b || exit; "
       "exec 10>&- 11>&- 12>&- 13>&-; "
       ": 3>&4- {fd}>&3; echo next >&12",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/move-a || exit; exec 4>/tmp/move-b || exit; "
       "exec 10>&- 11>&- 12>&- 13>&-; "
       ": 3>&1 3>&4 {fd}>&3; echo next >&12",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/move-a || exit; exec 4>/tmp/move-b || exit; "
       "exec 10>&- 11>&- 12>&-; "
       ": 3>&4-; : {fd}>&4; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/move-a || exit; exec 4>/tmp/move-b || exit; "
       "exec 10>&- 11>&- 12>&-; "
       ": 3>&1 3>&4; : {fd}>&4; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/move-a || exit; exec 4>/tmp/move-b || exit; "
       "exec 10>&- 11>&- 12>&-; "
       "{ :; } 3>&4-; : {fd}>&4; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 4>/tmp/move-b; : 4>&\"\"-; echo next >&4", "echo",
       SHELL_EDGE_WRITE},
      {"exec 4>/tmp/move-b; : 4>&\"\"; echo next >&4", "echo",
       SHELL_EDGE_WRITE},
      {"exec 4>/tmp/move-b; { :; } 4>&''-; echo next >&4", "echo",
       SHELL_EDGE_WRITE},
      {"exec 4</tmp/move-b; : 4<&\"\"-; cat <&4", "cat", SHELL_EDGE_READ},
  };
  for (size_t i = 0; i < sizeof(undo_cases) / sizeof(undo_cases[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        undo_cases[i].source, strlen(undo_cases[i].source), "/", &limits,
        graph);
    if (error != SHELL_DEP_OK ||
        !command_routes_exact(graph, undo_cases[i].command, undo_cases[i].kind,
                              restored, 1)) {
      fprintf(stderr, "undo case %zu: %s (error %d)\n", i, undo_cases[i].source,
              error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  /* A failed restoration stops its whole undo list, leaving older saves and
   * their current destinations live. It does not change the body's status. */
  static const struct {
    const char *source;
    const char *command;
    shell_dep_edge_type_t kind;
  } stopped_undo_cases[] = {
      {"exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
       "exec 10>&3 11>&- 12>&- 13>&-; "
       "exec 3>&10- 11>&4 10>&-; echo next >&11",
       "echo", SHELL_EDGE_WRITE},
      {"exec 1>/tmp/move-b 3>/tmp/move-a 4>/tmp/move-a || exit; "
       "exec 10>&- 11>&- 12>&-; "
       "{ exec 11>&-; } 3>&1 4>&1; echo next >&3",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3</tmp/move-a 4</tmp/move-b || exit; "
       "exec 10<&3 11<&- 12<&- 13<&-; "
       "exec 3<&10- 11<&4 10<&-; cat <&11",
       "cat", SHELL_EDGE_READ},
      {"exec 0</tmp/move-b 3</tmp/move-a 4</tmp/move-a || exit; "
       "exec 10<&- 11<&- 12<&-; "
       "{ exec 11<&-; } 3<&0 4<&0; cat <&3",
       "cat", SHELL_EDGE_READ},
      {"exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
       "exec 10>&- 11>&- 12>&- 13>&-; exec {fd}>&3; "
       "exec 3>&${fd}- 11>&4 {fd}>&- && : || exit; echo next >&11",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
       "exec 10>&3 11>&- 12>&- 13>&-; "
       "exec 3>&10- 11>&4 10>&-; : \"$(echo next >&11)\"",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
       "exec 10>&3 11>&- 12>&- 13>&-; "
       "exec 3>&10- 11>&4 10>&-; : <(echo next >&11)",
       "echo", SHELL_EDGE_WRITE},
      {"exec 1>/tmp/move-b 3>/tmp/move-a 4>/tmp/move-a 5>/tmp/move-a "
       "|| exit; exec 10>&- 11>&- 12>&- 13>&-; "
       "{ { exec 12>&-; } 3>&1 4>&1; } 5>&1; echo next >&3",
       "echo", SHELL_EDGE_WRITE},
      {"exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
       "exec 10>&3 11>&- 12>&- 13>&-; "
       "exec 3>&10- 11>&4 10>&-; exec {next}>&4; echo next >&\"$next\"",
       "echo", SHELL_EDGE_WRITE},
  };
  for (size_t i = 0;
       i < sizeof(stopped_undo_cases) / sizeof(stopped_undo_cases[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        stopped_undo_cases[i].source, strlen(stopped_undo_cases[i].source), "/",
        &limits, graph);
    if (error != SHELL_DEP_OK ||
        !command_routes_exact(graph, stopped_undo_cases[i].command,
                              stopped_undo_cases[i].kind, restored, 1)) {
      fprintf(stderr, "stopped undo case %zu: %s (error %d)\n", i,
              stopped_undo_cases[i].source, error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  /* Three saves exercise a failure at every list position. Newer entries
   * finish normally; the failed entry and all older ones keep their routes. */
  for (unsigned read = 0; read < 2; read++)
    for (unsigned closed = 10; closed <= 12; closed++)
      for (unsigned consumer = 3; consumer <= 5; consumer++) {
        char source[512];
        char direction = read ? '<' : '>';
        unsigned root = read ? 0 : 1;
        int n = snprintf(
            source, sizeof(source),
            "exec %u%c/tmp/move-b 3%c/tmp/move-a 4%c/tmp/move-a "
            "5%c/tmp/move-a || exit; exec 10>&- 11>&- 12>&- 13>&-; "
            "{ exec %u>&-; } 3%c&%u 4%c&%u 5%c&%u && : || exit; %s %c&%u",
            root, direction, direction, direction, direction, closed, direction,
            root, direction, root, direction, root, read ? "cat" : "echo next",
            direction, consumer);
        CHECK(n > 0 && (size_t)n < sizeof(source));
        shell_dep_error_t error =
            shell_dep_graph_parse(source, (size_t)n, "/", &limits, graph);
        const char *const *expected =
            alternatives + (consumer <= closed - 7 ? 1 : 0);
        if (error != SHELL_DEP_OK ||
            !command_routes_exact(graph, read ? "cat" : "echo",
                                  read ? SHELL_EDGE_READ : SHELL_EDGE_WRITE,
                                  expected, 1)) {
          fprintf(stderr, "stopped undo matrix: %s (error %d)\n", source,
                  error);
          shell_dep_graph_dump(graph, stderr);
          return EXIT_FAILURE;
        }
        CHECK(shell_dep_graph_validate(graph).valid);
      }
  static const char independent_outer[] =
      "exec 1>/tmp/move-b 3>/tmp/move-a 4>/tmp/move-a 5>/tmp/move-a "
      "|| exit; exec 10>&- 11>&- 12>&- 13>&-; "
      "{ { exec 12>&-; } 3>&1 4>&1; } 5>&1; echo next >&5";
  CHECK(shell_dep_graph_parse(independent_outer, sizeof(independent_outer) - 1,
                              "/", &limits, graph) == SHELL_DEP_OK);
  CHECK(command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, alternatives, 1));
  static const char *const surviving_saves[] = {
      "exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
      "exec 10>&3 11>&- 12>&- 13>&-; "
      "exec 3>&10- 11>&4 10>&-; echo next >&12",
      "exec 1>/tmp/move-b 3>/tmp/move-a 4>/tmp/move-a || exit; "
      "exec 10>&- 11>&- 12>&-; "
      "{ exec 11>&-; } 3>&1 4>&1; echo next >&10",
      "exec 1>/tmp/move-b 3>/tmp/move-a 4>/tmp/move-a || exit; "
      "exec 10>&- 11>&- 12>&-; "
      "{ exec 11>&-; } 3>&1 4>&1; exec {next}>&4; echo next >&10",
  };
  for (size_t i = 0; i < sizeof(surviving_saves) / sizeof(surviving_saves[0]);
       i++) {
    CHECK(shell_dep_graph_parse(surviving_saves[i], strlen(surviving_saves[i]),
                                "/", &limits, graph) == SHELL_DEP_OK);
    CHECK(
        command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, alternatives, 1));
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const char inherited_save[] =
      "exec 3</tmp/move-a 4</tmp/move-b || exit; "
      "exec 10<&3 11<&- 12<&- 13<&-; "
      "exec 3<&10- 11<&4 10<&-; /bin/cat <&12";
  CHECK(shell_dep_graph_parse(inherited_save, sizeof(inherited_save) - 1, "/",
                              &limits, graph) == SHELL_DEP_OK);
  CHECK(command_routes_exact(graph, "/bin/cat", SHELL_EDGE_READ, alternatives,
                             1));
  CHECK(shell_dep_graph_validate(graph).valid);
  static const char conditional_stop[] =
      "exec 1>/tmp/move-b 3>/tmp/move-a 4>/tmp/move-a || exit; "
      "exec 10>&- 11>&- 12>&-; "
      "{ probe && exec 11>&-; } 3>&1 4>&1; echo next >&3";
  CHECK(shell_dep_graph_parse(conditional_stop, sizeof(conditional_stop) - 1,
                              "/", &limits, graph) == SHELL_DEP_OK);
  CHECK(command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, alternatives, 2));
  CHECK(shell_dep_graph_validate(graph).valid);
  static const char mixed_identity[] =
      "exec 3>&- 10>&- 11>&-; probe && exec {fd}>/tmp/move-a || "
      "exec {pad}>/tmp/move-pad {fd}>/tmp/move-b; exec 10>&${fd}-; "
      "echo next >&10";
  CHECK(shell_dep_graph_parse(mixed_identity, sizeof(mixed_identity) - 1, "/",
                              &limits, graph) == SHELL_DEP_OK);
  CHECK(command_writes(graph, "echo", "/tmp/move-a"));
  CHECK(command_writes(graph, "echo", "/tmp/move-b"));
  CHECK(shell_dep_graph_validate(graph).valid);
  static const char reopen[] =
      "exec 4>&-; exec 3>/tmp/move-a; { exec 3>/tmp/move-out; } 4>&3-; "
      "echo next >&3";
  CHECK(shell_dep_graph_parse(reopen, sizeof(reopen) - 1, "/", &limits,
                              graph) == SHELL_DEP_OK);
  CHECK(command_writes(graph, "echo", "/tmp/move-out"));
  CHECK(shell_dep_graph_validate(graph).valid);
  /* A known free slot plus a duplication allocation proves physical identity
   * without assuming inherited low-FD occupancy for a file-open allocation.
   * No duplicate or source-close transition may be emitted for that no-op. */
  static const char *const self_cases[] = {
      "exec 10>&-; exec {fd}>&1; exec 10>&${fd}-; echo next >&\"$fd\"",
      "exec 10>&-; exec {fd}>&1 10>&${fd}-; echo next >&\"$fd\"",
      "exec 10>&-; exec {fd}<&0; exec 10<&\"$fd\"-; cat <&\"$fd\"",
      "exec 10>&-; exec {fd}<&0 10<&${fd}-; cat <&\"$fd\"",
      "exec 10>&-; exec {fd}>&1; exec {fd}>&-; exec 10>&${fd}-; echo next",
  };
  for (size_t i = 0; i < sizeof(self_cases) / sizeof(self_cases[0]); i++) {
    CHECK(shell_dep_graph_parse(self_cases[i], strlen(self_cases[i]), "/",
                                &limits, graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(graph).valid);
    uint32_t closes = 0, copies = 0;
    for (uint32_t j = 0; j < graph->edge_count; j++) {
      closes += graph->edges[j].type == SHELL_EDGE_FD_CLOSE;
      copies += graph->edges[j].type == SHELL_EDGE_FD_OPEN &&
                graph->edges[j].flags == SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP;
    }
    CHECK(closes == (i == 4 ? 2u : 1u) && copies == 1);
  }
  static const char *const self_route[] = {"/tmp/self-route"};
  static const struct {
    const char *source;
    const char *command;
    shell_dep_edge_type_t kind;
  } closed_self_cases[] = {
      {"exec 1>/tmp/self-route || exit; exec 10>&-; exec 10>&10; "
       "exec {fd}>&1; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 1>/tmp/self-route || exit; exec 10>&-; exec 10>&10-; "
       "exec {fd}>&1; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 1>/tmp/self-route || exit; exec 10>&-; { :; } 10>&10; "
       "exec {fd}>&1; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 1>/tmp/self-route || exit; exec 10>&-; { :; } 10>&10-; "
       "exec {fd}>&1; echo next >&10",
       "echo", SHELL_EDGE_WRITE},
      {"exec 0</tmp/self-route || exit; exec 10<&-; exec 10<&10; "
       "exec {fd}<&0; cat <&10",
       "cat", SHELL_EDGE_READ},
      {"exec 0</tmp/self-route || exit; exec 10<&-; exec 10<&10-; "
       "exec {fd}<&0; cat <&10",
       "cat", SHELL_EDGE_READ},
      {"exec 0</tmp/self-route || exit; exec 10<&-; { :; } 10<&10; "
       "exec {fd}<&0; cat <&10",
       "cat", SHELL_EDGE_READ},
      {"exec 0</tmp/self-route || exit; exec 10<&-; { :; } 10<&10-; "
       "exec {fd}<&0; cat <&10",
       "cat", SHELL_EDGE_READ},
  };
  for (size_t i = 0;
       i < sizeof(closed_self_cases) / sizeof(closed_self_cases[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        closed_self_cases[i].source, strlen(closed_self_cases[i].source), "/",
        &limits, graph);
    if (error != SHELL_DEP_OK ||
        !command_routes_exact(graph, closed_self_cases[i].command,
                              closed_self_cases[i].kind, self_route, 1)) {
      fprintf(stderr, "closed self case %zu: %s (error %d)\n", i,
              closed_self_cases[i].source, error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    uint32_t closes = 0, copies = 0;
    for (uint32_t j = 0; j < graph->edge_count; j++) {
      closes += graph->edges[j].type == SHELL_EDGE_FD_CLOSE;
      copies += graph->edges[j].type == SHELL_EDGE_FD_OPEN &&
                graph->edges[j].flags == SHELL_DEP_EDGE_FLAG_FD_OPEN_DUP;
    }
    CHECK(closes == 1 && copies == 1);
    CHECK(shell_dep_graph_validate(graph).valid);
  }
  static const struct {
    const char *source;
    bool restored;
  } ifs_closes[] = {
      {"exec {out}>/tmp/move-a; exec {fd}>&1; IFS=0123456789; "
       ": {out}>&${fd}-; echo next >&\"$out\"",
       true},
      {"exec {out}>/tmp/move-a; exec {fd}>&1; IFS=0123456789; "
       "{ :; } {out}>&${fd}-; echo next >&\"$out\"",
       true},
      {"exec {out}>/tmp/move-a; exec {fd}>&1; IFS=0123456789; "
       "exec {out}>&${fd}-; echo next",
       false},
  };
  for (size_t i = 0; i < sizeof(ifs_closes) / sizeof(ifs_closes[0]); i++) {
    shell_dep_error_t error = shell_dep_graph_parse(
        ifs_closes[i].source, strlen(ifs_closes[i].source), "/", &limits,
        graph);
    if (error != SHELL_DEP_OK) {
      fprintf(stderr, "IFS close case %zu: %s (error %d)\n", i,
              ifs_closes[i].source, error);
      shell_dep_graph_dump(graph, stderr);
      return EXIT_FAILURE;
    }
    CHECK(command_writes(graph, "echo", "/tmp/move-a") ==
          ifs_closes[i].restored);
    uint32_t named_closes = 0;
    for (uint32_t j = 0; j < graph->edge_count; j++)
      named_closes += graph->edges[j].type == SHELL_EDGE_FD_CLOSE &&
                      graph->edges[j].source_fd == SHELL_DEP_FD_NAMED &&
                      graph->edges[j].source_fd_name_len == 3 &&
                      !memcmp(graph->edges[j].source_fd_name, "out", 3);
    CHECK(named_closes == 1 && shell_dep_graph_validate(graph).valid);
  }
  static const char untracked_ifs_close[] =
      "exec {fd}>&1; IFS=0123456789; : {out}>&${fd}-; echo reached";
  CHECK(shell_dep_graph_parse(untracked_ifs_close,
                              sizeof(untracked_ifs_close) - 1, "/", &limits,
                              graph) == SHELL_DEP_EPARSE);
  CHECK(shellsplit_test_depgraph_invariants(untracked_ifs_close,
                                            sizeof(untracked_ifs_close) - 1,
                                            SHELL_DEP_EPARSE, graph, &limits));
  /* An external child does not install its descriptor variable in the parent.
   * Later use is rejected by the documented untracked-reference boundary. */
  static const char child_binding[] =
      "/bin/true {out}>&1; echo next >&\"$out\"";
  CHECK(shell_dep_graph_parse(child_binding, sizeof(child_binding) - 1, "/",
                              &limits, graph) == SHELL_DEP_EPARSE);
  static const char *const invalidated[] = {
      "exec 10>&-; exec {fd}>&1; fd=notnumber; exec 10>&${fd}-",
      "exec 10>&-; exec {fd}>&1; unset fd; exec 10>&${fd}-",
      "exec 10>&-; exec {fd}>&1; fd=11; exec 10>&${fd}-",
      "exec 10>&-; exec {fd}>&1; probe && unset fd; exec 10>&${fd}-",
  };
  for (size_t i = 0; i < sizeof(invalidated) / sizeof(invalidated[0]); i++)
    CHECK(shell_dep_graph_parse(invalidated[i], strlen(invalidated[i]), "/",
                                &limits, graph) == SHELL_DEP_EPARSE);
  static const char *const capacity_sources[] = {
      "exec 3>/tmp/move-out; exec 1>&3-; echo next",
      exact_cases[0].source,
      correlated_source,
      publication_cases[3].source,
      publication_cases[4].source,
      publication_cases[6].source,
      unwind_cases[0].source,
      unwind_cases[3].source,
      unwind_cases[5].source,
      unwind_cases[6].source,
      unwind_cases[9].source,
      local_alias_closes[0],
      nested_unwind[1],
      stopped_undo_cases[0].source,
      stopped_undo_cases[1].source,
      stopped_undo_cases[2].source,
      stopped_undo_cases[5].source,
      stopped_undo_cases[6].source,
      stopped_undo_cases[7].source,
      conditional_stop,
      surviving_saves[0],
      surviving_saves[1],
      inherited_save,
      scratch_source,
      setup_save_cases[2].source,
      setup_save_cases[10].source,
      setup_save_cases[12].source,
      setup_save_cases[18].source,
  };
  for (size_t i = 0; i < sizeof(capacity_sources) / sizeof(capacity_sources[0]);
       i++)
    for (unsigned dimension = 0; dimension < 2; dimension++)
      for (uint32_t bound = 0; bound < 18; bound++) {
        shell_dep_limits_t limited = limits;
        if (dimension)
          limited.max_edges = bound;
        else
          limited.max_nodes = bound;
        shell_dep_error_t status = shell_dep_graph_parse(
            capacity_sources[i], strlen(capacity_sources[i]), "/", &limited,
            graph);
        if (status != SHELL_DEP_OK && status != SHELL_DEP_ETRUNC)
          fprintf(stderr,
                  "move capacity case%zu dimension%u bound%u status%d\n", i,
                  dimension, bound, status);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        if (!shellsplit_test_depgraph_invariants(capacity_sources[i],
                                                 strlen(capacity_sources[i]),
                                                 status, graph, &limited)) {
          fprintf(stderr,
                  "move graph case%zu dimension%u bound%u status%d\n%s\n", i,
                  dimension, bound, status, capacity_sources[i]);
          shell_dep_graph_dump(graph, stderr);
          shell_dep_graph_validation_t validation =
              shell_dep_graph_validate(graph);
          for (uint32_t error = 0; error < validation.error_count; error++)
            fprintf(stderr, "%s\n", validation.errors[error].msg);
        }
        CHECK(shellsplit_test_depgraph_invariants(capacity_sources[i],
                                                  strlen(capacity_sources[i]),
                                                  status, graph, &limited));
      }
  static const struct {
    const char *source;
    shell_dep_time_report_route_t route;
  } timers[] = {
      {"exec 4>&-; time true 4>&2-", SHELL_TIME_REPORT_CLOSED},
      {"exec 4>&-; time /bin/true 4>&2-", SHELL_TIME_REPORT_EXTERNAL},
      {"exec 4>&-; time command /bin/true 4>&2-", SHELL_TIME_REPORT_EXTERNAL},
      {"exec 4>&-; time builtin true 4>&2-", SHELL_TIME_REPORT_CLOSED},
      {"exec 4>&-; time builtin /bin/true 4>&2-", SHELL_TIME_REPORT_CLOSED},
      {"exec 4>&-; time builtin command /bin/true 4>&2-",
       SHELL_TIME_REPORT_CLOSED},
      {"exec 4>&-; time builtin \"$runner\" 4>&2-", SHELL_TIME_REPORT_CLOSED},
      {"exec 4>&-; time command -v true 4>&2-", SHELL_TIME_REPORT_CLOSED},
      {"exec 4>&-; time \"$runner\" 4>&2-", SHELL_TIME_REPORT_MULTIPLE},
      {"exec 4>&-; (time /bin/true 4>&2-)", SHELL_TIME_REPORT_EXTERNAL},
      {"exec 4>&-; (time true 4>&2-)", SHELL_TIME_REPORT_CLOSED},
  };
  for (size_t i = 0; i < sizeof(timers) / sizeof(timers[0]); i++) {
    CHECK(shell_dep_graph_parse(timers[i].source, strlen(timers[i].source), "/",
                                &limits, graph) == SHELL_DEP_OK);
    bool found = false;
    for (uint32_t j = 0; j < graph->node_count; j++) {
      if (graph->nodes[j].type != SHELL_NODE_TIME)
        continue;
      found = true;
      if (graph->nodes[j].time.report_route != timers[i].route)
        fprintf(stderr, "timer %zu: %s\n", i, timers[i].source);
      CHECK(graph->nodes[j].time.report_route == timers[i].route);
      if (timers[i].route == SHELL_TIME_REPORT_MULTIPLE)
        CHECK(graph->nodes[j].time.report_route_flags ==
              (SHELL_TIME_REPORT_ROUTE_EXTERNAL |
               SHELL_TIME_REPORT_ROUTE_CLOSED));
    }
    CHECK(found && shell_dep_graph_validate(graph).valid);
  }
  static const char timed_unwind[] =
      "exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
      "exec 10>&- 11>&- 12>&-; exec {fd}>&3; "
      ": 3>&${fd}- {fd}>&4; exec 2>&10; time :";
  CHECK(shell_dep_graph_parse(timed_unwind, sizeof(timed_unwind) - 1, "/",
                              &limits, graph) == SHELL_DEP_OK);
  unsigned time_nodes = 0, report_edges = 0;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_TIME) {
      time_nodes++;
      CHECK(graph->nodes[i].time.report_route == SHELL_TIME_REPORT_GRAPH);
      for (uint32_t j = 0; j < graph->edge_count; j++) {
        const shell_dep_edge_t *edge = &graph->edges[j];
        if (edge->from != i || edge->type != SHELL_EDGE_WRITE)
          continue;
        const shell_dep_node_t *target = &graph->nodes[edge->to];
        CHECK(
            target->type == SHELL_NODE_DOC &&
            target->doc.kind == SHELL_DOC_FILE && edge->source_fd == 2 &&
            target->doc.path_len == strlen(publication_a[0]) &&
            !memcmp(target->doc.path, publication_a[0], target->doc.path_len));
        report_edges++;
      }
    }
  CHECK(time_nodes == 1 && report_edges == 1 &&
        shell_dep_graph_validate(graph).valid);
  static const char setup_save_timer[] =
      "exec 4>&- 10>&-; exec 4>/tmp/move-b 10>/tmp/move-a || exit; "
      "exec 11>&- 12>&- 13>&- 14>&-; "
      "time { exec 2>&14; } 10>&4- 14>&12";
  CHECK(shell_dep_graph_parse(setup_save_timer, sizeof(setup_save_timer) - 1,
                              "/", &limits, graph) == SHELL_DEP_OK);
  time_nodes = report_edges = 0;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_TIME) {
      time_nodes++;
      CHECK(graph->nodes[i].time.report_route == SHELL_TIME_REPORT_GRAPH);
      for (uint32_t j = 0; j < graph->edge_count; j++) {
        const shell_dep_edge_t *edge = graph->edges + j;
        if (edge->from != i || edge->type != SHELL_EDGE_WRITE)
          continue;
        const shell_dep_node_t *target = graph->nodes + edge->to;
        CHECK(target->type == SHELL_NODE_DOC &&
              target->doc.kind == SHELL_DOC_FILE && edge->source_fd == 2 &&
              target->doc.path_len == strlen(restored[0]) &&
              !memcmp(target->doc.path, restored[0], target->doc.path_len));
        report_edges++;
      }
    }
  CHECK(time_nodes == 1 && report_edges == 1 &&
        shell_dep_graph_validate(graph).valid);
  static const char stopped_timer[] =
      "exec 2>/tmp/move-a 3>/tmp/move-a 4>/tmp/move-b || exit; "
      "exec 10>&- 11>&- 12>&-; time { exec 11>&-; } 2>&4 3>&4";
  CHECK(shell_dep_graph_parse(stopped_timer, sizeof(stopped_timer) - 1, "/",
                              &limits, graph) == SHELL_DEP_OK);
  time_nodes = report_edges = 0;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_TIME) {
      time_nodes++;
      CHECK(graph->nodes[i].time.report_route == SHELL_TIME_REPORT_GRAPH);
      for (uint32_t j = 0; j < graph->edge_count; j++) {
        const shell_dep_edge_t *edge = graph->edges + j;
        if (edge->from != i || edge->type != SHELL_EDGE_WRITE)
          continue;
        const shell_dep_node_t *target = graph->nodes + edge->to;
        CHECK(target->type == SHELL_NODE_DOC &&
              target->doc.kind == SHELL_DOC_FILE && edge->source_fd == 2 &&
              target->doc.path_len == strlen(restored[0]) &&
              !memcmp(target->doc.path, restored[0], target->doc.path_len));
        report_edges++;
      }
    }
  CHECK(time_nodes == 1 && report_edges == 1 &&
        shell_dep_graph_validate(graph).valid);
  static const char pipeline[] = "exec 3>&-; printf x 3>&1- 1>&3 | cat";
  CHECK(shell_dep_graph_parse(pipeline, sizeof(pipeline) - 1, "/", &limits,
                              graph) == SHELL_DEP_OK);
  bool pipe = false;
  for (uint32_t i = 0; i < graph->edge_count; i++)
    pipe |= graph->edges[i].type == SHELL_EDGE_PIPE &&
            graph->edges[i].source_fd == 1 && graph->edges[i].target_fd == 0;
  CHECK(pipe && shell_dep_graph_validate(graph).valid);
  static const char process[] = "exec 3> >(consumer); printf x 1>&3-";
  CHECK(shell_dep_graph_parse(process, sizeof(process) - 1, "/", &limits,
                              graph) == SHELL_DEP_OK);
  bool process_write = false;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = graph->edges + i;
    process_write |= edge->type == SHELL_EDGE_WRITE && edge->source_fd == 1 &&
                     graph->nodes[edge->to].type == SHELL_NODE_ENDPOINT;
  }
  CHECK(process_write && shell_dep_graph_validate(graph).valid);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  for (uint32_t count = 8; count <= SHELL_DEP_MAX_NODES; count *= 2) {
    shellsplit_test_source_scan_reset();
    CHECK(shellsplit_test_route_state_contract(limits.workspace, count));
    size_t visits =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_ALTERNATIVES);
    size_t membership =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_MEMBERSHIP);
    unsigned height = 0;
    for (uint32_t bound = count; bound; bound >>= 1)
      height++;
    CHECK(visits == count + count / 2 - 2);
    CHECK(membership > 0 && membership <= 12 * count * height);
  }
  const char *allocation_source = "{ echo next; } 4>&3- 5<&\"0\"-";
  shell_processed_commands_t processed = {0};
  shellsplit_test_alloc_reset();
  CHECK(shell_process_commands(allocation_source, strlen(allocation_source),
                               NULL, &processed) == SHELL_PROCESS_OK);
  size_t allocations = shellsplit_test_alloc_count();
  shell_processed_commands_free(&processed);
  CHECK(allocations > 0);
  for (size_t i = 1; i <= allocations; i++) {
    shellsplit_test_alloc_fail_at(i);
    CHECK(shell_process_commands(allocation_source, strlen(allocation_source),
                                 NULL, &processed) == SHELL_PROCESS_ENOMEM);
    CHECK(!processed.commands && !processed.command_count &&
          !processed.groups && !processed.group_count &&
          !processed.group_io_ops && !processed.group_io_op_count);
    shellsplit_test_alloc_reset();
  }
  size_t previous_work = 0;
  for (unsigned count = 4; count <= 16; count *= 2) {
    char source[2048] = "exec 3>/tmp/move-out;";
    size_t used = strlen(source);
    for (unsigned i = 0; i < count; i++) {
      int n = snprintf(source + used, sizeof(source) - used, " : 1>&3-;");
      CHECK(n > 0 && (size_t)n < sizeof(source) - used);
      used += (size_t)n;
    }
    shellsplit_test_source_scan_reset();
    shell_dep_error_t status =
        shell_dep_graph_parse(source, used, "/", &limits, graph);
    if (status != SHELL_DEP_OK)
      fprintf(stderr, "scaling %u: %d %s\n", count, status, source);
    CHECK(status == SHELL_DEP_OK);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    CHECK(work > 0 && (!previous_work || work < previous_work * 3));
    previous_work = work;
  }
  previous_work = 0;
  for (unsigned count = 4; count <= 16; count *= 2) {
    char source[2048] = "exec 3>/tmp/move-a 4>/tmp/move-b || exit;";
    size_t used = strlen(source);
    for (unsigned i = 0; i < count; i++) {
      const char unit[] = " : 3>&4- 3>&4;";
      memcpy(source + used, unit, sizeof(unit));
      used += sizeof(unit) - 1;
    }
    memcpy(source + used, " echo next >&4", sizeof(" echo next >&4"));
    used += sizeof(" echo next >&4") - 1;
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse(source, used, "/", &limits, graph) ==
          SHELL_DEP_OK);
    CHECK(command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, restored, 1));
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_FD_OPERATIONS) +
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION) +
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    if (!work || (previous_work && work > previous_work * 3))
      fprintf(stderr, "failed move scaling count%u work%zu previous%zu\n",
              count, work, previous_work);
    CHECK(work && (!previous_work || work <= previous_work * 3));
    CHECK(shellsplit_test_source_scan_work() <= 512 * used);
    previous_work = work;
  }
  /* Cleanup and scratch reuse must not add rescans as their history
   * grows. Count actual journal work, independently of wall-clock timing. */
  for (unsigned family = 0; family < 3; family++) {
    previous_work = 0;
    for (unsigned count = 4; count <= 16; count *= 2) {
      char source[4096] =
          "exec 1>/tmp/move-b 3>/tmp/move-a 4>/tmp/move-b || exit; "
          "exec 10>&- 11>&- 12>&- 13>&-; ";
      size_t used = strlen(source);
      const char *unit = family == 2 ? "exec 10>&3; : 10>&4- >&12; "
                         : family == 1
                             ? "{ exec 11>&-; } 3>&1 4>&1; "
                             : "exec 10>&3; exec 3>&10- 11>&4 10>&-; ";
      for (unsigned i = 0; i < count; i++) {
        size_t length = strlen(unit);
        CHECK(length < sizeof(source) - used);
        memcpy(source + used, unit, length + 1);
        used += length;
      }
      const char *consumer = family == 2   ? "echo next >&4"
                             : family == 1 ? "echo next >&3"
                                           : "echo next >&11";
      CHECK(strlen(consumer) < sizeof(source) - used);
      memcpy(source + used, consumer, strlen(consumer) + 1);
      used += strlen(consumer);
      shellsplit_test_source_scan_reset();
      CHECK(shell_dep_graph_parse(source, used, "/", &limits, graph) ==
            SHELL_DEP_OK);
      CHECK(command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, restored, 1));
      size_t work =
          shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION) +
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES) +
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
      CHECK(work && (!previous_work || work <= previous_work * 3));
      CHECK(shellsplit_test_source_scan_work() <= 512 * used);
      previous_work = work;
    }
  }
  /* Graph replay uses only the caller workspace. Exercise allocation
   * failures in the owning processed-command boundary for these same inputs. */
  for (unsigned family = 0; family < 4; family++) {
    previous_work = 0;
    for (unsigned count = 3; count <= 12; count *= 2) {
      char source[4096] =
          "exec 3>/tmp/publication-a 4>/tmp/publication-b || exit; "
          "exec 8>&- 10>&- 11>&- 12>&- 13>&-; ";
      size_t used = strlen(source);
      if (family == 0) {
        memcpy(source + used, "exec", sizeof("exec"));
        used += sizeof("exec") - 1;
      } else if (family >= 2) {
        const char allocation[] = "exec {fd}>&3; ";
        memcpy(source + used, allocation, sizeof(allocation));
        used += sizeof(allocation) - 1;
      }
      for (unsigned i = 0; i < count; i++) {
        /* Select successful setup so this measures implementation work rather
         * than the growing set of genuinely different allocation outcomes. */
        const char *unit = family == 0   ? " {fd}>&3"
                           : family == 1 ? "{ :; } {fd}>&3 10>&- || exit; "
                           : family == 2 ? ": 3>&${fd}- {fd}>&4 || exit; "
                                         : ": 3>&${fd}- {fd}>&4 5>&8; ";
        size_t length = strlen(unit);
        CHECK(length < sizeof(source) - used);
        memcpy(source + used, unit, length + 1);
        used += length;
      }
      const char *consumer = family ? "echo next >&10" : "; echo next >&10";
      CHECK(strlen(consumer) < sizeof(source) - used);
      memcpy(source + used, consumer, strlen(consumer) + 1);
      used += strlen(consumer);
      shellsplit_test_source_scan_reset();
      shell_dep_error_t status =
          shell_dep_graph_parse(source, used, "/", &limits, graph);
      if (status != SHELL_DEP_OK)
        fprintf(stderr,
                "allocation scaling parse family%u count%u status%d: %s\n",
                family, count, status, source);
      CHECK(status == SHELL_DEP_OK);
      CHECK(command_routes_exact(graph, "echo", SHELL_EDGE_WRITE, publication_a,
                                 1));
      size_t work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_FD_OPERATIONS) +
          shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION) +
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
      if (!work || (previous_work && work > previous_work * 3 + 64))
        fprintf(stderr,
                "allocation scaling family%u count%u work%zu prior%zu\n",
                family, count, work, previous_work);
      CHECK(work && (!previous_work || work <= previous_work * 3 + 64));
      CHECK(shellsplit_test_source_scan_work() <= 512 * used);
      previous_work = work;
    }
  }
  for (size_t c = 0; c < sizeof(capacity_sources) / sizeof(capacity_sources[0]);
       c++) {
    const char *source = capacity_sources[c];
    shellsplit_test_alloc_reset();
    CHECK(shell_process_commands(source, strlen(source), NULL, &processed) ==
          SHELL_PROCESS_OK);
    allocations = shellsplit_test_alloc_count();
    shell_processed_commands_free(&processed);
    CHECK(allocations > 0);
    for (size_t i = 1; i <= allocations; i++) {
      shellsplit_test_alloc_fail_at(i);
      CHECK(shell_process_commands(source, strlen(source), NULL, &processed) ==
            SHELL_PROCESS_ENOMEM);
      CHECK(!processed.commands && !processed.command_count &&
            !processed.groups && !processed.group_count &&
            !processed.group_io_ops && !processed.group_io_op_count);
      shellsplit_test_alloc_reset();
    }
  }
#endif
  free(graph);
  free(limits.workspace);
  puts("descriptor move tests passed");
  return EXIT_SUCCESS;
}
