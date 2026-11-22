/* How descriptors and redirects flow through compound commands, as the
 * dependency-graph analysis decides it, and how that analysis scales. Each flow
 * section is a base case with a table of variants (see variant_table.h): a row
 * states the status of the analysis and the decisions, edges or reads it must
 * reach. The decision events keep a variant honest: a change that makes it stop
 * reaching the decision it was built for fails the row instead of passing
 * quietly. Sections: merging versions of the state, allocation of named
 * descriptors, the failure of a read, the lists of an if, who owns a redirect
 * on a group, how far an exec reaches around a group, where the output of a
 * substitution goes, and the growth of the analysis with nesting and chaining.
 */
#include "../src/shell_depgraph_internal.h"
#include "depgraph_test_workspace.h"
#include "graph_fixture.h"
#include "shell_depgraph.h"
#include "test_source_scans.h"
#include "variant_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- flow (from depgraph_flow_test.c) --- */
static int flow_failures;

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);     \
      flow_failures++;                                                         \
    }                                                                          \
  } while (0)

#define EV(kind, outcome) ((uint16_t)((kind) * 32 + (outcome)))
#define MAX_EVENTS 4
#define MAX_SLOTS 7
#define MAX_TOKENS 6

typedef struct {
  const char *name; /* what this variant changes in the base */
  unsigned depth;
  const char *slot[MAX_SLOTS]; /* in the template's slot order */
  shell_dep_error_t status;
  uint16_t must[MAX_EVENTS];     /* decisions the analysis must take */
  uint16_t must_not[MAX_EVENTS]; /* decisions it must not take; 0 = none */
  /* Graph oracle, checked when reads is not NULL: for each cat command in
   * order, '1' when a file document is read into it, else '0'; and whether
   * any open is a requirement of a safe run. */
  const char *reads;
  unsigned required;
  /* Edge tokens that must be present or absent in the graph, see edge_token. */
  const char *have[MAX_TOKENS];
  const char *lack[MAX_TOKENS];
} flow_variant_t;

enum { flow_REQ_ANY, flow_REQ_NO, flow_REQ_YES };
#define NO_GRAPH NULL, flow_REQ_ANY, {0}, {0}

typedef struct {
  const char *name, *base;
  const char *slot_name[MAX_SLOTS];
  const flow_variant_t *variants;
  size_t count;
} flow_template_t;

#define WIDEN EV(SHELLSPLIT_TRACE_WIDEN, 1)
#define APART_ROOTS EV(SHELLSPLIT_TRACE_MERGE, 3)
#define REFUSED EV(SHELLSPLIT_TRACE_UNMODELED, 1)
#define VIEWS(n) EV(SHELLSPLIT_TRACE_ALLOC_VIEWS, n)
#define MODES(n) EV(SHELLSPLIT_TRACE_ALLOC_MODES, n)

/* fan-out of versions.
 * Base: depth independent two-armed ifs, each arm leaving descriptor 2# open
 * for reading or for writing, then a read that observes each descriptor's
 * access. Versions that differ in access outcome cannot be merged, so the
 * state carries 2^depth of them, past the limit at depth 4, where the least
 * lossy pair is joined (widening). Slots: wrapper open, wrapper close, arm A,
 * arm B, observation. */
static const char *const flow_fanout_base =
    "@OPEN@{REP}if test -n \"$c#\"; then @A@; else @B@; fi; {/REP}"
    "{REP}@OBSERVE@; {/REP}@CLOSE@";

#define ARM_READ "exec 2#<a"
#define ARM_WRITE "exec 2#>b"
#define ARM_CLOSE "exec 2#<&-"
#define OBS_READ "read -u2# x || :"
#define OBS_CAT "cat <&2# || :"
#define OBS_NONE ":"
#define W_NONE "", ""
#define W_GROUP "{ ", "}"
#define W_THEN "if test -n \"$w\"; then ", "fi"
#define W_SUBSHELL "( ", ")"

/* Columns: name, depth, {wrapper open, wrapper close, arm A, arm B,
 * observation}, status, decisions it must take, decisions it must not take. */
// clang-format off
static const flow_variant_t flow_fanout[] = {
  /* The base case. */
  {"base: depth 4, read or write, observed by read", 4,
   {W_NONE, ARM_READ, ARM_WRITE, OBS_READ}, SHELL_DEP_OK,
   {WIDEN, APART_ROOTS}, {0}, NO_GRAPH},

  /* Depth: 2^3 = 8 versions fit, 2^4 do not. */
  {"depth 1", 1, {W_NONE, ARM_READ, ARM_WRITE, OBS_READ}, SHELL_DEP_OK,
   {APART_ROOTS}, {WIDEN}, NO_GRAPH},
  {"depth 3, the last that fits", 3,
   {W_NONE, ARM_READ, ARM_WRITE, OBS_READ}, SHELL_DEP_OK,
   {APART_ROOTS}, {WIDEN}, NO_GRAPH},
  {"depth 6", 6, {W_NONE, ARM_READ, ARM_WRITE, OBS_READ}, SHELL_DEP_OK,
   {WIDEN}, {0}, NO_GRAPH},

  /* The arms must differ in access for the versions to stay apart. */
  {"arms with the same access", 4,
   {W_NONE, ARM_READ, "exec 2#<c", OBS_READ}, SHELL_DEP_OK,
   {0}, {WIDEN, APART_ROOTS}, NO_GRAPH},
  {"read or close", 4, {W_NONE, ARM_READ, ARM_CLOSE, OBS_READ}, SHELL_DEP_OK,
   {WIDEN}, {0}, NO_GRAPH},
  {"read or nothing", 4, {W_NONE, ARM_READ, ":", OBS_READ}, SHELL_DEP_OK,
   {WIDEN}, {0}, NO_GRAPH},

  /* The observation must read the access. */
  {"no observation", 4, {W_NONE, ARM_READ, ARM_WRITE, OBS_NONE},
   SHELL_DEP_OK, {0}, {WIDEN, APART_ROOTS}, NO_GRAPH},
  {"observed by cat on a writable descriptor", 4,
   {W_NONE, ARM_READ, ARM_WRITE, OBS_CAT}, SHELL_DEP_OK,
   {0}, {WIDEN}, NO_GRAPH},

  /* A read of a descriptor closed on one path is refused, not widened. */
  {"cat on a descriptor closed in one arm", 4,
   {W_NONE, ARM_READ, ARM_CLOSE, OBS_CAT}, SHELL_DEP_EUNMODELED,
   {REFUSED}, {WIDEN}, NO_GRAPH},

  /* The same base inside other constructs. */
  {"inside a group", 4, {W_GROUP, ARM_READ, ARM_WRITE, OBS_READ},
   SHELL_DEP_OK, {WIDEN}, {0}, NO_GRAPH},
  {"inside a then list", 4, {W_THEN, ARM_READ, ARM_WRITE, OBS_READ},
   SHELL_DEP_OK, {WIDEN}, {0}, NO_GRAPH},
  {"inside a subshell", 4, {W_SUBSHELL, ARM_READ, ARM_WRITE, OBS_READ},
   SHELL_DEP_OK, {WIDEN}, {0}, NO_GRAPH},
};
// clang-format on

/* named allocation under an uncertain low-descriptor interval.
 * Descriptors 3 to 9 are closed by contract, so only a conditional open of
 * them makes the lowest free descriptor uncertain. An allocation then runs on
 * views of the state, one per low-interval case; when a later operation can
 * tell the allocated descriptors apart (a named close), the views also follow
 * the inherited case, and a second independent change adds one more. Slots:
 * three conditional changes, the allocation, its use. */
static const char *const flow_allocation_base = "@C1@@C2@@C3@@ALLOC@; @USE@";

#define OPEN_LOW                                                               \
  "if test -n \"$c0\"; then exec 3<>/dev/null 4<>/dev/null 5<>/dev/null "      \
  "6<>/dev/null 7<>/dev/null 8<>/dev/null 9<>/dev/null; fi; "
#define CLOSE_3 "if test -n \"$c1\"; then exec 3<&-; fi; "
#define CLOSE_9 "if test -n \"$c2\"; then exec 9<&-; fi; "
#define ALLOC_EXEC "exec {fd}<<<x"
#define ALLOC_BUILTIN ": {fd}<<<x"
#define USE_CLOSE "exec {fd}>&-"
#define USE_CAT "cat <&$fd"
#define USE_SECOND "exec {g}<<<y; exec {fd}>&-"

/* Columns: name, depth (unused), {change 1, change 2, change 3, allocation,
 * use}, status, decisions it must take, decisions it must not take. */
// clang-format off
static const flow_variant_t flow_allocation[] = {
  /* The base case. */
  {"base: two changes, named close", 0,
   {OPEN_LOW, CLOSE_3, "", ALLOC_EXEC, USE_CLOSE}, SHELL_DEP_OK,
   {VIEWS(11), MODES(1), MODES(2)}, {0}, NO_GRAPH},

  /* The low interval's uncertainty. */
  {"no change: the interval is certain", 0,
   {"", "", "", ALLOC_EXEC, USE_CLOSE}, SHELL_DEP_OK,
   {MODES(1)}, {VIEWS(2), VIEWS(10), VIEWS(11)}, NO_GRAPH},
  {"one change", 0, {OPEN_LOW, "", "", ALLOC_EXEC, USE_CLOSE}, SHELL_DEP_OK,
   {VIEWS(10), MODES(1), MODES(2)}, {VIEWS(11)}, NO_GRAPH},
  {"closing a descriptor that is closed adds nothing", 0,
   {"", CLOSE_3, "", ALLOC_EXEC, USE_CLOSE}, SHELL_DEP_OK,
   {MODES(1)}, {VIEWS(2), VIEWS(10), VIEWS(11)}, NO_GRAPH},
  {"a third change adds no view", 0,
   {OPEN_LOW, CLOSE_3, CLOSE_9, ALLOC_EXEC, USE_CLOSE}, SHELL_DEP_OK,
   {VIEWS(11)}, {0}, NO_GRAPH},

  /* What can tell the allocated descriptors apart. */
  {"used by cat only: views follow the low case, not the origin", 0,
   {OPEN_LOW, CLOSE_3, "", ALLOC_EXEC, USE_CAT}, SHELL_DEP_OK,
   {VIEWS(2)}, {VIEWS(10), VIEWS(11), MODES(1), MODES(2)}, NO_GRAPH},
  {"not used", 0, {OPEN_LOW, CLOSE_3, "", ALLOC_EXEC, ":"}, SHELL_DEP_OK,
   {VIEWS(2)}, {VIEWS(10), VIEWS(11), MODES(1), MODES(2)}, NO_GRAPH},
  {"a second allocation beside the first", 0,
   {OPEN_LOW, CLOSE_3, "", ALLOC_EXEC, USE_SECOND}, SHELL_DEP_OK,
   {VIEWS(2), VIEWS(10), VIEWS(11), MODES(1)}, {0}, NO_GRAPH},

  /* The allocating operation. */
  {"allocated by a builtin's redirection", 0,
   {OPEN_LOW, CLOSE_3, "", ALLOC_BUILTIN, USE_CLOSE}, SHELL_DEP_OK,
   {VIEWS(11), MODES(1), MODES(2)}, {0}, NO_GRAPH},
};
// clang-format on

/* the failure of a read.
 * Base: a read of a descriptor that may be missing, placed in a context. The
 * read then fails with an error Bash reports, which the graph models only
 * where the script handles it: the read ends a condition list, which the if
 * consumes, or the read, or the group or if it ends, is the left side of && or
 * ||, or is negated. A read in the middle of a list, or ending a then or else
 * list of an if nothing consumes, or piped or backgrounded, is refused. The
 * conditions are not constant, so no list is skipped as dead code. Slots: the
 * text before the read, the text after it. */
static const char *const flow_read_base = "@BEFORE@read -u9 x@AFTER@";

#define COND "test -n \"$c\""
#define NOT_HANDLED EV(SHELLSPLIT_TRACE_UNMODELED, 5)

/* Columns: name, depth (unused), {before, after}, status, decisions it must
 * take, decisions it must not take. */
// clang-format off
static const flow_variant_t flow_read_failure[] = {
  /* The read ends the list an if consumes. */
  {"condition of an if", 0, {"if ", "; then :; fi"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"condition of an elif", 0,
   {"if " COND "; then :; elif ", "; then :; fi"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"condition of a nested if", 0,
   {"if " COND "; then if ", "; then :; fi; fi"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"condition that is a group", 0, {"if { ", "; }; then :; fi"},
   SHELL_DEP_OK, {0}, {NOT_HANDLED}, NO_GRAPH},

  {"condition followed by a group in the then list", 0,
   {"if ", "; then { :; }; fi"}, SHELL_DEP_OK, {0}, {NOT_HANDLED}, NO_GRAPH},
  {"condition followed by a subshell in the then list", 0,
   {"if ", "; then ( : ); fi"}, SHELL_DEP_OK, {0}, {NOT_HANDLED}, NO_GRAPH},
  {"elif condition followed by a group", 0,
   {"if " COND "; then :; elif ", "; then { :; }; fi"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  /* The read's own here-string body lies within its span. */
  {"condition with a here-string", 0, {"if ", " <<<y; then :; fi"},
   SHELL_DEP_OK, {0}, {NOT_HANDLED}, NO_GRAPH},
  {"condition with a here-string, group in the then list", 0,
   {"if ", " <<<y; then { :; }; fi"}, SHELL_DEP_OK, {0}, {NOT_HANDLED}, NO_GRAPH},
  {"then list ends with a here-string read", 0,
   {"if " COND "; then ", " <<<y; fi"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},
  {"here-string read followed by ||", 0, {"", " <<<y || :"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},

  /* The read is not the last of its list or group. */
  {"condition list continues", 0, {"if ", "; :; then :; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"elif condition list continues", 0,
   {"if " COND "; then :; elif ", "; :; then :; fi"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},
  {"condition group continues", 0, {"if { ", "; :; }; then :; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"then list continues", 0, {"if " COND "; then ", "; :; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"else list continues", 0, {"if " COND "; then :; else ", "; :; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"group continues", 0, {"{ ", "; :; }"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},
  {"group continues, then ||", 0, {"{ ", "; :; } || :"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},
  {"subshell continues", 0, {"( ", "; :; )"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},

  /* The read ends a then or else list, which ends the if. */
  {"ends a then list", 0, {"if " COND "; then ", "; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"ends an else list", 0, {"if " COND "; then :; else ", "; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"ends the else list of an elif chain", 0,
   {"if " COND "; then :; elif " COND "; then :; else ", "; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"ends a group ending a then list", 0, {"if " COND "; then { ", "; }; fi"},
   SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"ends a then list of a nested if", 0,
   {"if " COND "; then if " COND "; then ", "; fi; fi"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},

  /* The if is handled by what follows it. */
  {"then list, if followed by &&", 0,
   {"if " COND "; then ", "; else :; fi && :"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"else list, if followed by ||", 0,
   {"if " COND "; then :; else ", "; fi || :"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"group in a then list, if followed by ||", 0,
   {"if " COND "; then { ", "; }; fi || :"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"nested then list, if followed by &&", 0,
   {"if " COND "; then if " COND "; then ", "; fi; fi && :"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"negated if", 0, {"! if " COND "; then ", "; fi"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},

  /* The read itself. */
  {"the read alone", 0, {"", ""}, SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"the read followed by ||", 0, {"", " || :"}, SHELL_DEP_OK,
   {0}, {NOT_HANDLED}, NO_GRAPH},
  {"piped", 0, {"", " | cat"}, SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"backgrounded", 0, {"", " &"}, SHELL_DEP_EUNMODELED, {NOT_HANDLED}, {0}, NO_GRAPH},
  {"group piped", 0, {"{ ", "; } | cat"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},
  {"group backgrounded", 0, {"{ ", "; } &"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},
  {"if piped", 0, {"if " COND "; then ", "; fi | cat"}, SHELL_DEP_EUNMODELED,
   {NOT_HANDLED}, {0}, NO_GRAPH},
};
// clang-format on

/* where the descriptor state of an if goes.
 * Base: a condition that opens a descriptor, then, elif and else lists that
 * read it or not, and a read after fi. Each list starts from the outcome of
 * its condition that can reach it, and the lists that finish join at fi, so
 * which command reads the file, whether the open is a requirement of a safe
 * run, and whether the code after fi may read the descriptor all follow from
 * the arms. An exit leaves only the other arms' state after fi. Slots: text
 * before the if, the condition, the then list, an elif part, an else part,
 * the text after fi. */
static const char *const flow_if_base =
    "@PRE@if @COND@; then @THEN@; @ELIF@@ELSE@fi; @AFTER@";

#define IF_THEN_PARKED EV(SHELLSPLIT_TRACE_IF, 0)
#define IF_THEN_ALWAYS EV(SHELLSPLIT_TRACE_IF, 1)
#define IF_ELSE_RESUMES EV(SHELLSPLIT_TRACE_IF, 2)
#define IF_FINISH_NO_ELSE EV(SHELLSPLIT_TRACE_IF, 3)
#define IF_FINISH EV(SHELLSPLIT_TRACE_IF, 4)
#define TEST_C "test -n \"$c\""
#define OPEN_F "exec 3<f"
#define READ_3 "cat <&3"

/* Columns: name, depth (unused), {pre, condition, then, elif part, else part,
 * after}, status, decisions it must take, decisions it must not take, which
 * cat commands read the file, whether an open is a requirement. */
// clang-format off
static const flow_variant_t flow_if_sections[] = {
  /* The base case. */
  {"base: the condition opens; then, else and after fi read", 0,
   {"", OPEN_F, READ_3, "", "else " READ_3 "; ", READ_3}, SHELL_DEP_OK,
   {IF_THEN_PARKED, IF_ELSE_RESUMES, IF_FINISH}, {IF_FINISH_NO_ELSE},
   "101", flow_REQ_YES, {0}, {0}},

  /* Which list sees what the condition opened. */
  {"then reads, nothing else", 0,
   {"", OPEN_F, READ_3, "", "", ":"}, SHELL_DEP_OK,
   {IF_THEN_PARKED, IF_FINISH_NO_ELSE}, {IF_ELSE_RESUMES},
   "1", flow_REQ_NO, {0}, {0}},
  {"then and else read: the else sees the failed open", 0,
   {"", OPEN_F, READ_3, "", "else " READ_3 "; ", ":"}, SHELL_DEP_OK,
   {IF_ELSE_RESUMES}, {IF_FINISH_NO_ELSE},
   "10", flow_REQ_YES, {0}, {0}},
  {"read after fi makes the open a requirement", 0,
   {"", OPEN_F, ":", "", "else :; ", READ_3}, SHELL_DEP_OK,
   {IF_FINISH}, {0},
   "1", flow_REQ_YES, {0}, {0}},

  /* A list that exits leaves only the other lists' state after fi. */
  {"else exits", 0,
   {"", OPEN_F, ":", "", "else exit 1; ", READ_3}, SHELL_DEP_OK,
   {IF_FINISH}, {0},
   "1", flow_REQ_NO, {0}, {0}},
  {"negated condition, then exits", 0,
   {"", "! " OPEN_F, "exit 1", "", "", READ_3}, SHELL_DEP_OK,
   {IF_THEN_PARKED}, {IF_ELSE_RESUMES},
   "1", flow_REQ_NO, {0}, {0}},
  {"then exits, open after", 0,
   {"", TEST_C, "exit 1", "", "", OPEN_F "; " READ_3}, SHELL_DEP_OK,
   {IF_THEN_PARKED}, {0},
   "1", flow_REQ_YES, {0}, {0}},
  {"then opens, else exits", 0,
   {"", TEST_C, OPEN_F, "", "else exit 1; ", READ_3}, SHELL_DEP_OK,
   {IF_FINISH}, {0},
   "1", flow_REQ_YES, {0}, {0}},

  /* The list that runs on a failed condition. */
  {"negated condition: the failure list reads", 0,
   {"", "! " OPEN_F, READ_3, "", "", ":"}, SHELL_DEP_OK,
   {IF_THEN_PARKED}, {0},
   "0", flow_REQ_YES, {0}, {0}},

  /* A descriptor set in only some lists is unknown after fi. */
  {"then opens, no else", 0,
   {"", TEST_C, OPEN_F, "", "", READ_3}, SHELL_DEP_EUNMODELED,
   {IF_FINISH_NO_ELSE}, {0}, NO_GRAPH},
  {"elif chain without else", 0,
   {"", TEST_C, OPEN_F, "elif test -n \"$d\"; then exec 3<g; ", "", READ_3},
   SHELL_DEP_EUNMODELED,
   {IF_ELSE_RESUMES, IF_FINISH_NO_ELSE}, {0}, NO_GRAPH},
  {"then closes", 0,
   {OPEN_F "; ", TEST_C, "exec 3<&-", "", "", READ_3}, SHELL_DEP_EUNMODELED,
   {IF_FINISH_NO_ELSE}, {0}, NO_GRAPH},
  {"both lists close", 0,
   {OPEN_F "; ", TEST_C, "exec 3<&-", "", "else exec 3<&-; ", READ_3},
   SHELL_DEP_EUNMODELED,
   {IF_FINISH}, {IF_FINISH_NO_ELSE}, NO_GRAPH},

  /* Every list sets it. */
  {"both lists open", 0,
   {"", TEST_C, OPEN_F, "", "else exec 3<g; ", READ_3}, SHELL_DEP_OK,
   {IF_FINISH}, {0},
   "1", flow_REQ_YES, {0}, {0}},
  {"elif chain, every list opens", 0,
   {"", TEST_C, OPEN_F, "elif test -n \"$d\"; then exec 3<g; ",
    "else exec 3<h; ", READ_3}, SHELL_DEP_OK,
   {IF_ELSE_RESUMES, IF_FINISH}, {0},
   "1", flow_REQ_YES, {0}, {0}},

  /* A condition in an elif. */
  {"elif condition opens, read in its list", 0,
   {"", TEST_C, ":", "elif " OPEN_F "; then " READ_3 "; ", "", ":"},
   SHELL_DEP_OK,
   {IF_ELSE_RESUMES}, {0},
   "1", flow_REQ_NO, {0}, {0}},
  {"elif condition opens, read in the else", 0,
   {"", TEST_C, ":", "elif " OPEN_F "; then :; ", "else " READ_3 "; ", ":"},
   SHELL_DEP_OK,
   {IF_ELSE_RESUMES, IF_FINISH}, {0},
   "0", flow_REQ_YES, {0}, {0}},

  /* A condition that cannot fail has no failure to park. */
  {"the condition closes and the list reads", 0,
   {OPEN_F "; ", "exec 3<&-", READ_3, "", "", ":"}, SHELL_DEP_EUNMODELED,
   {IF_THEN_ALWAYS}, {IF_THEN_PARKED}, NO_GRAPH},

  /* Condition lists. */
  {"and-list condition", 0,
   {"", OPEN_F " && exec 4<g", READ_3 " <&4", "", "", ":"}, SHELL_DEP_OK,
   {IF_THEN_PARKED}, {0},
   "1", flow_REQ_NO, {0}, {0}},
  {"and-list condition, read the second after fi", 0,
   {"", OPEN_F " && exec 4<g", ":", "", "", "cat <&4"}, SHELL_DEP_EUNMODELED,
   {IF_FINISH_NO_ELSE}, {0}, NO_GRAPH},
  {"or-list condition", 0,
   {"", OPEN_F " || exec 3<g", READ_3, "", "", ":"}, SHELL_DEP_OK,
   {IF_THEN_PARKED}, {0},
   "1", flow_REQ_NO, {0}, {0}},

  /* Nesting. */
  {"nested if opens in both lists", 0,
   {"", TEST_C,
    "if test -n \"$d\"; then exec 3<f; else exec 3<g; fi; " READ_3, "", "",
    ":"},
   SHELL_DEP_OK,
   {IF_FINISH}, {0},
   "1", flow_REQ_YES, {0}, {0}},
  {"nested if opens in one list, read outside", 0,
   {"", TEST_C, "if test -n \"$d\"; then exec 3<f; fi", "", "", READ_3},
   SHELL_DEP_EUNMODELED,
   {IF_FINISH_NO_ELSE}, {0}, NO_GRAPH},
};
// clang-format on

/* who owns a redirect on a group.
 * Base: a pipe into a brace group that has its own stdin, stdout and stderr
 * redirects, around two commands of which one overrides its stdin. A redirect
 * on a group belongs to the group, so the group's redirected descriptors
 * replace what the pipe or the terminal would give it, the commands inside
 * inherit them, and a command's own redirect replaces the group's for that
 * command only. Each row changes one thing and states the edges that appear
 * or disappear. Slots: text before the group, its opening, its body, its
 * closing, the stdin redirect, the output redirects, text after. */
static const char *const flow_group_base =
    "@PRE@@OPEN@@BODY@@CLOSE@@IN@@OUT@@POST@";

#define G_BRACE "{ ", "; }"
#define G_SUBSHELL "( ", " )"
#define G_IF "if :; then ", "; fi"
#define PIPE_IN "./src | "
#define BODY_OVERRIDE "cat < inner; cat"
#define IN_FILE " < outer"
#define OUT_LOG " > log 2>&1"
#define PIPED_SRC "./src[1]>end[0]:|"

/* Columns: name, depth (unused), {before, open, body, close, stdin redirect,
 * output redirects, after}, status, then the unused event and graph-oracle
 * columns (NO_GRAPH), then edges that must be present and edges that must be
 * absent. */
// clang-format off
static const flow_variant_t flow_group_ownership[] = {
  /* The base case: the group's redirects replace the pipe and the terminal. */
  {"base: pipe in, group redirects, inner override", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, IN_FILE, OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:outer>{}[0]:R", "file:inner>cat[0]:R", "{}[1]>file:log:W",
    "{}[2]>file:log:W", PIPED_SRC},
   {"./src[1]>{}[0]:|"}},

  /* The stdin of the group. */
  {"no stdin redirect: the pipe feeds the group", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, "", OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"./src[1]>{}[0]:|"},
   {"file:outer>{}[0]:R", PIPED_SRC}},
  {"stdin from a here-string", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, " <<<text", OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"str>{}[0]:R", PIPED_SRC},
   {"file:outer>{}[0]:R", "./src[1]>{}[0]:|"}},
  {"stdin opened for reading and writing", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, " <> rw", OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:rw>{}[0]:R", "{}[0]>file:rw:W"},
   {"./src[1]>{}[0]:|"}},
  {"no pipe in", 0,
   {"", G_BRACE, BODY_OVERRIDE, IN_FILE, OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:outer>{}[0]:R"},
   {PIPED_SRC, "./src[1]>{}[0]:|"}},

  /* A command's own redirect replaces the group's for that command only. */
  {"no inner override", 0,
   {PIPE_IN, G_BRACE, "cat; cat", IN_FILE, OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:outer>{}[0]:R"},
   {"file:inner>cat[0]:R"}},
  {"the inner command also redirects its output", 0,
   {PIPE_IN, G_BRACE, "cat < inner > innerout; cat", IN_FILE, OUT_LOG},
   SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:inner>cat[0]:R", "cat[1]>file:innerout:W", "{}[1]>file:log:W"},
   {"cat[1]>file:log:W"}},

  /* The output of the group. */
  {"output appended", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, IN_FILE, " >> log 2>&1"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"{}[1]>file:log:A", "{}[2]>file:log:A"},
   {"{}[1]>file:log:W"}},
  {"stdout forced, stderr untouched", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, IN_FILE, " >| log"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"{}[1]>file:log:W"},
   {"{}[2]>file:log:W"}},
  {"stderr joined to the inherited stdout", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, IN_FILE, " 2>&1"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"{}[1]>fd:W", "{}[2]>fd:W"},
   {"{}[1]>file:log:W", "{}[2]>file:log:W"}},
  {"no output redirects, no stdin redirect", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, "", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"./src[1]>{}[0]:|", "{}[1]>fd:W"},
   {"{}[1]>file:log:W", "file:outer>{}[0]:R"}},
  {"the group's stdout is piped on, but it is redirected", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, IN_FILE, OUT_LOG " | ./sink"},
   SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"{}[1]>file:log:W"},
   {"{}[1]>./sink[0]:|"}},
  {"the group's stdout is piped on", 0,
   {PIPE_IN, G_BRACE, BODY_OVERRIDE, IN_FILE, " | ./sink"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"{}[1]>./sink[0]:|"},
   {"{}[1]>file:log:W"}},

  /* A named descriptor opened on the group is not its stdin. */
  {"named open: the pipe still feeds the group", 0,
   {PIPE_IN, G_BRACE, "cat", " {fd}< in", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"./src[1]>{}[0]:|", "file:in>{}[n]:O"},
   {"file:in>{}[0]:R"}},
  {"named open beside a stdin redirect", 0,
   {PIPE_IN, G_BRACE, "cat", " < in", " {fd}> out"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:in>{}[0]:R", PIPED_SRC, "{}[n]>file:out:O"},
   {"./src[1]>{}[0]:|"}},

  /* The same ownership for other compound commands. */
  {"a subshell", 0,
   {PIPE_IN, G_SUBSHELL, BODY_OVERRIDE, IN_FILE, OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:outer>()[0]:R", "()[1]>file:log:W", "file:inner>cat[0]:R"},
   {"file:outer>{}[0]:R"}},
  {"an if", 0,
   {PIPE_IN, G_IF, BODY_OVERRIDE, IN_FILE, OUT_LOG}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:outer>if[0]:R", "if[1]>file:log:W", "file:inner>cat[0]:R"},
   {"file:outer>{}[0]:R"}},
};
// clang-format on

/* how far an exec or a redirect around a group reaches.
 * Base: a brace group that opens descriptor 3, then a read of it. A brace
 * group runs in the shell, so what it opens stays open after it; a subshell, a
 * pipeline member or a background job runs in a copy, so it does not; and a
 * redirect on a group lasts only while the group runs. What a group closes
 * stays closed. Slots: the group's opening and closing, its body, its
 * redirect with the terminator of the group, the text after it. */
static const char *const flow_scope_base = "@OPEN@@BODY@@CLOSE@@REDIR@@AFTER@";

#define READ_FD3 "cat <&3"

/* Columns: name, depth (unused), {open, close, body, redirect, after}, status,
 * unused event and graph-oracle columns, edges present, edges absent. */
// clang-format off
static const flow_variant_t flow_group_scope[] = {
  {"base: a brace group's exec lasts", 0,
   {G_BRACE, "exec 3<f", "; ", READ_FD3}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:f>cat[0]:R"}, {0}},
  {"the group is also redirected", 0,
   {G_BRACE, "exec 3<f", " 2>&1; ", READ_FD3}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:f>cat[0]:R"}, {0}},
  {"an if with a certain condition", 0,
   {"if :; then ", "; fi", "exec 3<f", "; ", READ_FD3}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:f>cat[0]:R"}, {0}},
  {"the read runs after && on the group", 0,
   {G_BRACE, "exec 3<f", " && " READ_FD3 "; ", ":"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:f>cat[0]:R"}, {0}},

  /* A copy of the shell does not leave its descriptors behind. */
  {"a subshell's exec is lost", 0,
   {G_SUBSHELL, "exec 3<f", "; ", READ_FD3}, SHELL_DEP_EUNMODELED,
   {0}, {0}, NULL, flow_REQ_ANY, {0}, {0}},
  {"a pipeline member's exec is lost", 0,
   {G_BRACE, "exec 3<f", " | cat; ", READ_FD3}, SHELL_DEP_EUNMODELED,
   {0}, {0}, NULL, flow_REQ_ANY, {0}, {0}},
  {"a background group's exec is lost", 0,
   {G_BRACE, "exec 3<f", " & ", READ_FD3}, SHELL_DEP_EUNMODELED,
   {0}, {0}, NULL, flow_REQ_ANY, {0}, {0}},

  /* A redirect on a group is temporary, and a close lasts. */
  {"a redirect on the group is undone", 0,
   {G_BRACE, "cat", " 3< a; ", READ_FD3}, SHELL_DEP_EUNMODELED,
   {0}, {0}, NULL, flow_REQ_ANY, {0}, {0}},
  {"a close inside the group lasts", 0,
   {G_BRACE, "exec 3<f; exec 3<&-", "; ", READ_FD3}, SHELL_DEP_EUNMODELED,
   {0}, {0}, NULL, flow_REQ_ANY, {0}, {0}},
};
// clang-format on

/* where the output of a substitution goes.
 * Base: a command with a command substitution as an argument. The substituted
 * command's output is the argument's text, not terminal output, so it reaches
 * its consumer through a substitution edge; the substitution runs in the
 * shell's own context, so a redirect on the consumer does not reach it; and a
 * here-string, here-document or process substitution consumes the output as
 * its content. Slots: the group's opening, the command up to the
 * substitution, the substitution, the rest of the command, the group's
 * closing with its redirect. */
static const char *const flow_subst_base = "@OPEN@@CMD@@SUBST@@REST@@CLOSE@";

/* Columns: name, depth (unused), {open, close, command, substitution, rest},
 * status, unused event and graph-oracle columns, edges present, edges
 * absent. */
// clang-format off
static const flow_variant_t flow_substitution[] = {
  {"base: an argument", 0,
   {"", "", "echo ", "$(cat a)", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>echo:S", "fd>cat[0]:R"}, {"cat[1]>fd:W"}},
  {"the substitution reads its own file", 0,
   {"", "", "echo ", "$(cat < a)", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>echo:S", "file:a>cat[0]:R"}, {"fd>cat[0]:R"}},
  {"a redirect on the consumer does not reach it", 0,
   {"", "", "echo ", "$(cat)", " < in"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"file:in>echo[0]:R", "fd>cat[0]:R"}, {"file:in>cat[0]:R"}},
  {"nested substitutions chain", 0,
   {"", "", "echo ", "$(echo $(cat a))", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>echo:S", "echo[1]>echo:S"}, {"cat[1]>fd:W"}},
  {"two substitutions", 0,
   {"", "", "diff ", "<(cat a) <(cat b)", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>diff:S"}, {"cat[1]>fd:W"}},

  /* The output becomes the content of a document. */
  {"a here-string", 0,
   {"", "", "cat <<<", "$(cat a)", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>str:S", "str>cat[0]:R"}, {0}},
  {"a here-document body", 0,
   {"", "", "cat <<EOF\n", "$(cat a)", "\nEOF\n"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>here:S", "here>cat[0]:R"}, {0}},

  /* A process substitution. */
  {"a process substitution as input", 0,
   {"", "", "cat < ", "<(cat a)", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>cat[0]:S"}, {0}},
  {"a process substitution as output", 0,
   {"", "", "cat > ", ">(tee out)", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>end:W", "end>tee[0]:S"}, {"cat[1]>fd:W"}},

  /* A process substitution bound to a descriptor. */
  {"bound to a numbered descriptor", 0,
   {"", "", "exec 3< ", "<(cat a)", "; cat <&3"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>exec[3]:O", "cat[1]>cat[0]:S"}, {0}},
  {"bound to a named descriptor", 0,
   {"", "", "exec {fd}< ", "<(cat a)", "; cat <&$fd"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>exec[n]:O"}, {0}},
  {"read before the descriptor is bound", 0,
   {"", "", "cat <&3 3< ", "<(cat a)", ""}, SHELL_DEP_EUNMODELED,
   {0}, {0}, NULL, flow_REQ_ANY, {0}, {0}},

  /* The content of a document. */
  {"a here-document keeps its text", 0,
   {"", "", "cat <<EOF\n", "hello", "\nEOF\n"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY, {"doc:here:hello\n"}, {0}},
  {"a tab-stripping here-document drops leading tabs", 0,
   {"", "", "cat <<-EOF\n\t", "hello", "\n\tEOF\n"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"doc:here:hello\n"}, {"doc:here:\thello\n"}},
  {"a here-document with a quoted delimiter is literal", 0,
   {"", "", "cat <<'EOF'\n", "$x", "\nEOF\n"}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY, {"doc:here:$x\n"}, {0}},
  {"a here-string keeps its word", 0,
   {"", "", "cat <<< ", "\"two words\"", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY, {"doc:str:\"two words\""}, {0}},

  /* Around a group. */
  {"in a redirected group", 0,
   {"{ ", "; } > out", "echo ", "$(cat a)", ""}, SHELL_DEP_OK,
   {0}, {0}, NULL, flow_REQ_ANY,
   {"cat[1]>echo:S", "{}[1]>file:out:W"}, {"cat[1]>file:out:W"}},
};
// clang-format on

static const flow_template_t flow_templates[] = {
    {"fan-out",
     flow_fanout_base,
     {"OPEN", "CLOSE", "A", "B", "OBSERVE"},
     flow_fanout,
     sizeof(flow_fanout) / sizeof(flow_fanout[0])},
    {"allocation",
     flow_allocation_base,
     {"C1", "C2", "C3", "ALLOC", "USE"},
     flow_allocation,
     sizeof(flow_allocation) / sizeof(flow_allocation[0])},
    {"read failure",
     flow_read_base,
     {"BEFORE", "AFTER"},
     flow_read_failure,
     sizeof(flow_read_failure) / sizeof(flow_read_failure[0])},
    {"if sections",
     flow_if_base,
     {"PRE", "COND", "THEN", "ELIF", "ELSE", "AFTER"},
     flow_if_sections,
     sizeof(flow_if_sections) / sizeof(flow_if_sections[0])},
    {"group ownership",
     flow_group_base,
     {"PRE", "OPEN", "CLOSE", "BODY", "IN", "OUT", "POST"},
     flow_group_ownership,
     sizeof(flow_group_ownership) / sizeof(flow_group_ownership[0])},
    {"group scope",
     flow_scope_base,
     {"OPEN", "CLOSE", "BODY", "REDIR", "AFTER"},
     flow_group_scope,
     sizeof(flow_group_scope) / sizeof(flow_group_scope[0])},
    {"substitution",
     flow_subst_base,
     {"OPEN", "CLOSE", "CMD", "SUBST", "REST"},
     flow_substitution,
     sizeof(flow_substitution) / sizeof(flow_substitution[0])},
};

static bool flow_recorded(uint16_t event) {
  uint16_t events[512];
  size_t n = shellsplit_test_trace_events(events, 512);
  for (size_t i = 0; i < n && i < 512; i++)
    if (events[i] == event)
      return true;
  return false;
}

/* A node as it appears in an edge token: a file by its path, a here-document
 * or here-string by kind, a group by its delimiters, a command by its first
 * word, and the inherited descriptors as fd. */
static void flow_node_label(const shell_dep_graph_t *g, uint32_t n, char *out,
                            size_t capacity) {
  const shell_dep_node_t *node = &g->nodes[n];
  if (node->type == SHELL_NODE_DOC) {
    if (node->doc.kind == SHELL_DOC_FILE)
      snprintf(out, capacity, "file:%.*s", (int)node->doc.path_len,
               node->doc.path);
    else
      snprintf(out, capacity, "%s",
               node->doc.kind == SHELL_DOC_HEREDOC ? "here" : "str");
  } else if (node->type == SHELL_NODE_GROUP) {
    snprintf(out, capacity, "%s",
             node->group.kind == SHELL_GROUP_BRACE      ? "{}"
             : node->group.kind == SHELL_GROUP_SUBSHELL ? "()"
                                                        : "if");
  } else if (node->type == SHELL_NODE_ENDPOINT) {
    snprintf(out, capacity, "end");
  } else if (node->type == SHELL_NODE_FD) {
    snprintf(out, capacity, "fd");
  } else if (node->type == SHELL_NODE_CMD && node->cmd.token_count) {
    snprintf(out, capacity, "%.*s", (int)node->cmd.token_lens[0],
             node->cmd.tokens[0]);
  } else {
    snprintf(out, capacity, "?");
  }
}

/* The token of a read, write, append or pipe edge: from[fd]>to[fd]:kind, with
 * kind R, W, A, | (pipe), O (open), C (close) or S (substitution) and an fd
 * only where the edge names one, [n] for a named descriptor. False for other
 * edges. */
static bool flow_edge_token(const shell_dep_graph_t *g,
                            const shell_dep_edge_t *edge, char *out,
                            size_t capacity) {
  if (edge->type != SHELL_EDGE_READ && edge->type != SHELL_EDGE_WRITE &&
      edge->type != SHELL_EDGE_APPEND && edge->type != SHELL_EDGE_PIPE &&
      edge->type != SHELL_EDGE_FD_OPEN && edge->type != SHELL_EDGE_FD_CLOSE &&
      edge->type != SHELL_EDGE_SUBST)
    return false;
  char from[64], to[64], source_fd[16] = "", target_fd[16] = "";
  flow_node_label(g, edge->from, from, sizeof(from));
  flow_node_label(g, edge->to, to, sizeof(to));
  if (edge->source_fd == SHELL_DEP_FD_NAMED)
    snprintf(source_fd, sizeof(source_fd), "[n]");
  else if (edge->source_fd != SHELL_DEP_FD_NONE)
    snprintf(source_fd, sizeof(source_fd), "[%u]", (unsigned)edge->source_fd);
  if (edge->target_fd == SHELL_DEP_FD_NAMED)
    snprintf(target_fd, sizeof(target_fd), "[n]");
  else if (edge->target_fd != SHELL_DEP_FD_NONE)
    snprintf(target_fd, sizeof(target_fd), "[%u]", (unsigned)edge->target_fd);
  snprintf(out, capacity, "%s%s>%s%s:%c", from, source_fd, to, target_fd,
           edge->type == SHELL_EDGE_READ       ? 'R'
           : edge->type == SHELL_EDGE_WRITE    ? 'W'
           : edge->type == SHELL_EDGE_APPEND   ? 'A'
           : edge->type == SHELL_EDGE_FD_OPEN  ? 'O'
           : edge->type == SHELL_EDGE_FD_CLOSE ? 'C'
           : edge->type == SHELL_EDGE_SUBST    ? 'S'
                                               : '|');
  return true;
}

/* A document token, "doc:here:text" or "doc:str:text": whether a here-document
 * or here-string node has exactly this content, after the delimiter's
 * tab stripping. */
static bool flow_has_document(const shell_dep_graph_t *g, const char *token) {
  const char *kind = token + 4, *text = strchr(kind, ':') + 1;
  size_t kind_size = (size_t)(text - 1 - kind);
  shell_dep_doc_kind_t wanted = strncmp(kind, "here", kind_size) == 0
                                    ? SHELL_DOC_HEREDOC
                                    : SHELL_DOC_HERESTRING;
  for (uint32_t n = 0; n < g->node_count; n++) {
    const shell_dep_node_t *node = &g->nodes[n];
    char content[256];
    size_t length = 0, written = 0;
    if (node->type == SHELL_NODE_DOC && node->doc.kind == wanted &&
        shell_dep_doc_content_length(&node->doc, &length) &&
        length == strlen(text) && length < sizeof(content) &&
        shell_dep_doc_write_content(&node->doc, content, sizeof(content),
                                    &written) &&
        written == length && memcmp(content, text, length) == 0)
      return true;
  }
  return false;
}

static bool flow_has_edge(const shell_dep_graph_t *g, const char *token) {
  if (strncmp(token, "doc:", 4) == 0)
    return flow_has_document(g, token);
  for (uint32_t e = 0; e < g->edge_count; e++) {
    char buffer[200];
    if (flow_edge_token(g, &g->edges[e], buffer, sizeof(buffer)) &&
        strcmp(buffer, token) == 0)
      return true;
  }
  return false;
}

/* For each cat command in node order, whether a file document is read into
 * it; returns the number of cat commands. */
static size_t flow_cat_reads(const shell_dep_graph_t *g, char *reads,
                             size_t capacity, bool *required) {
  size_t cats = 0;
  *required = false;
  for (uint32_t n = 0; n < g->node_count && cats + 1 < capacity; n++) {
    const shell_dep_node_t *node = &g->nodes[n];
    if (node->type != SHELL_NODE_CMD || node->cmd.token_count == 0 ||
        node->cmd.token_lens[0] != 3 || memcmp(node->cmd.tokens[0], "cat", 3))
      continue;
    reads[cats] = '0';
    for (uint32_t e = 0; e < g->edge_count; e++)
      if (g->edges[e].type == SHELL_EDGE_READ && g->edges[e].to == n &&
          g->nodes[g->edges[e].from].type == SHELL_NODE_DOC)
        reads[cats] = '1';
    cats++;
  }
  for (uint32_t e = 0; e < g->edge_count; e++)
    *required |= (g->edges[e].flags & SHELL_DEP_EDGE_FLAG_REQUIRED) != 0;
  reads[cats] = 0;
  return cats;
}

static void flow_run_template(const flow_template_t *t) {
  for (size_t i = 0; i < t->count; i++) {
    const flow_variant_t *v = &t->variants[i];
    slot_t slots[MAX_SLOTS];
    size_t slot_count = 0;
    for (; slot_count < MAX_SLOTS && t->slot_name[slot_count]; slot_count++)
      slots[slot_count] =
          (slot_t){t->slot_name[slot_count],
                   v->slot[slot_count] ? v->slot[slot_count] : ""};
    char source[4096];
    size_t length = 0;
    CHECK(variant_expand(t->base, slots, slot_count, v->depth, -1, source,
                         sizeof(source), &length));
    static shell_dep_graph_t graph;
    memset(&graph, 0, sizeof(graph));
    shellsplit_test_trace_reset();
    shell_dep_error_t status =
        shell_dep_graph_parse(source, length, "/", NULL, &graph);
    const char *why = status == v->status ? NULL : "status";
    for (size_t e = 0; !why && e < MAX_EVENTS; e++) {
      if (v->must[e] && !flow_recorded(v->must[e]))
        why = "a required decision was not taken";
      else if (v->must_not[e] && flow_recorded(v->must_not[e]))
        why = "a forbidden decision was taken";
    }
    if (!why && status == SHELL_DEP_OK &&
        !shell_dep_graph_validate(&graph).valid)
      why = "the graph is not valid";
    for (size_t k = 0; !why && status == SHELL_DEP_OK && k < MAX_TOKENS; k++) {
      if (v->have[k] && !flow_has_edge(&graph, v->have[k]))
        why = v->have[k];
      else if (v->lack[k] && flow_has_edge(&graph, v->lack[k]))
        why = v->lack[k];
    }
    if (!why && status == SHELL_DEP_OK && v->reads) {
      char reads[32];
      bool required = false;
      size_t cats = flow_cat_reads(&graph, reads, sizeof(reads), &required);
      if (cats != strlen(v->reads) || memcmp(reads, v->reads, cats) != 0)
        why = "which commands read the file";
      else if (v->required != flow_REQ_ANY &&
               required != (v->required == flow_REQ_YES))
        why = "whether an open is a requirement";
    }
    bool ok = !why;
    if (!ok) {
      fprintf(stderr, "FAIL %s / %s: %s (status %d, expected %d)\n  %s\n",
              t->name, v->name, why, (int)status, (int)v->status, source);
      flow_failures++;
    }
  }
}

static int run_flow(int argc, char **argv) {
  (void)argc;
  (void)argv;
  for (size_t i = 0; i < sizeof(flow_templates) / sizeof(flow_templates[0]);
       i++)
    flow_run_template(&flow_templates[i]);
  if (flow_failures) {
    fprintf(stderr, "depgraph flow: %d failed\n", flow_failures);
    return 1;
  }
  printf("depgraph flow passed\n");
  return 0;
}
#undef CHECK
#undef EV
#undef MAX_EVENTS
#undef MAX_SLOTS
#undef MAX_TOKENS
#undef NO_GRAPH
#undef WIDEN
#undef APART_ROOTS
#undef REFUSED
#undef VIEWS
#undef MODES
#undef ARM_READ
#undef ARM_WRITE
#undef ARM_CLOSE
#undef OBS_READ
#undef OBS_CAT
#undef OBS_NONE
#undef W_NONE
#undef W_GROUP
#undef W_THEN
#undef W_SUBSHELL
#undef OPEN_LOW
#undef CLOSE_3
#undef CLOSE_9
#undef ALLOC_EXEC
#undef ALLOC_BUILTIN
#undef USE_CLOSE
#undef USE_CAT
#undef USE_SECOND
#undef COND
#undef NOT_HANDLED
#undef IF_THEN_PARKED
#undef IF_THEN_ALWAYS
#undef IF_ELSE_RESUMES
#undef IF_FINISH_NO_ELSE
#undef IF_FINISH
#undef TEST_C
#undef OPEN_F
#undef READ_3
#undef G_BRACE
#undef G_SUBSHELL
#undef G_IF
#undef PIPE_IN
#undef BODY_OVERRIDE
#undef IN_FILE
#undef OUT_LOG
#undef PIPED_SRC
#undef READ_FD3

/* --- scaling (from fd_scaling_test.c) --- */
/* Scaling suite for the descriptor analysis.
 *
 * Each family repeats one unit n times, n = 4, 8, 16, 32 up to the largest
 * size that fits the graph capacity, and parses the source. Its work is all
 * counted metadata work, including persistent-map steps, so a cost hidden in
 * any analysis structure shows. Two bounds hold per family:
 * - work(2n) / work(n) <= 2.2 * bytes(2n) / bytes(n);
 * - work(n) <= C * n * log2(n), with C fixed per family.
 * Every parse must succeed: work measured after a capacity stop says nothing
 * about the analysis. */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
typedef struct {
  const char *name;
  const char *prefix;
  /* printf format taking the unit's index once, as %1$u. */
  const char *unit;
  const char *suffix;
  /* Largest n within the graph capacity. */
  unsigned maximum;
  /* C: the measured worst work / (n log2 n), plus a quarter, rounded. */
  size_t constant;
  /* Closes each unit's opening, once per unit, after the suffix. */
  const char *closer;
} scaling_family_t;

static const scaling_family_t scaling_families[] = {
    {"opens x substitutions", "",
     "exec {f%1$u}<input || exit; true \"$(read -u\"$f%1$u\" -n0 v)\"; ", "",
     16, 1600, NULL},
    {"opens x redirecting commands", "",
     "exec {f%1$u}<input || exit; cat <&\"$f%1$u\" >out%1$u; ", "", 16, 1600,
     NULL},
    {"substitutions touching no descriptor", "exec {f}<input || exit; ",
     "v%1$u=$(true); ", "", 32, 500, NULL},
    {"nested substitutions", "", "echo \"$(", "", 8, 200, ")\""},
    {"branch ladders over named descriptors", "",
     "choice && exec {f%1$u}>a%1$u || exec {f%1$u}>b%1$u; ", "", 16, 1150,
     NULL},
    {"groups with save and restore", "", "{ echo x; } >out%1$u 2>&1; ", "", 32,
     2500, NULL},
    {"named allocations", "", "exec {f%1$u}>out%1$u; ", "", 32, 500, NULL},
    {"pipelines", "", "printf x | cat >out%1$u; ", "", 32, 600, NULL},
    {"process substitutions", "", "cat <(printf x) >out%1$u; ", "", 32, 420,
     NULL},
    {"here-documents", "", "cat <<EOF >out%1$u\nx\nEOF\n", "", 8, 400, NULL},
    {"if ladders over named descriptors", "",
     "if choice; then exec {f%1$u}>a%1$u; else exec {f%1$u}>b%1$u; fi; ", "", 8,
     1180, NULL},
    {"nested ifs over named descriptors", "",
     "if choice; then exec {f%1$u}>a%1$u; else ", "true; ", 8, 720, "fi; "},
    {"nested ifs over one descriptor", "exec 3>base || exit; ",
     "if choice; then exec 3>a%1$u || exit; else ", "true; ", 8, 700, "fi; "},
    {"nested ifs over duplicated named descriptors", "",
     "if choice; then exec {f%1$u}>&2; else ", "true; ", 16, 1550, "fi; "},
    {"nested ifs over duplicated numbered descriptors", "",
     "if choice; then exec 3>&2 || exit; else ", "true; ", 16, 310, "fi; "},
    {"elif chains over named descriptors", "if choice; then :; ",
     "elif choice%1$u; then exec {f%1$u}>a%1$u; ", "else :; fi", 8, 650, NULL},
    {"if chains over one descriptor", "exec 3>base || exit; ",
     "if choice; then exec 3>a%1$u || exit; fi; ", "", 8, 660, NULL},
};

/* The nested families close what their units opened. */
static size_t scaling_append_suffix(char *source, size_t used, size_t capacity,
                                    const scaling_family_t *family,
                                    unsigned count) {
  size_t length = strlen(family->suffix);
  CHECK(used + length < capacity);
  memcpy(source + used, family->suffix, length + 1);
  used += length;
  length = family->closer ? strlen(family->closer) : 0;
  for (unsigned i = 0; i < count; i++) {
    CHECK(used + length < capacity);
    if (length)
      memcpy(source + used, family->closer, length);
    used += length;
  }
  source[used] = '\0';
  return used;
}

static size_t scaling_total_work(void) {
  size_t work = 0;
  for (unsigned kind = 0; kind < SHELLSPLIT_TEST_WORK_COUNT; kind++)
    work +=
        shellsplit_test_metadata_work((shellsplit_test_metadata_kind_t)kind);
  return work;
}

static unsigned scaling_log2_ceiling(unsigned n) {
  unsigned bits = 0;
  while ((1u << bits) < n)
    bits++;
  return bits;
}

static void scaling_check_families(void) {
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 1,
                                      false, 0));
  shell_dep_limits_t limits = fixture.limits;
  shell_dep_graph_t *graph = fixture.graph[0];
  bool report = getenv("FD_SCALING_REPORT") != NULL;
  for (size_t f = 0; f < sizeof(scaling_families) / sizeof(scaling_families[0]);
       f++) {
    const scaling_family_t *family = &scaling_families[f];
    size_t previous_work = 0, previous_bytes = 0, worst = 0;
    for (unsigned count = 4; count <= family->maximum; count *= 2) {
      static char source[16384];
      size_t used = strlen(family->prefix);
      memcpy(source, family->prefix, used);
      for (unsigned i = 0; i < count; i++) {
        int n = snprintf(source + used, sizeof(source) - used, family->unit, i);
        CHECK(n > 0 && (size_t)n < sizeof(source) - used);
        used += (size_t)n;
      }
      used = scaling_append_suffix(source, used, sizeof(source), family, count);
      shellsplit_test_source_scan_reset();
      shell_dep_error_t status =
          shell_dep_graph_parse(source, used, "/", &limits, graph);
      size_t work = scaling_total_work();
      size_t bound = (size_t)count * scaling_log2_ceiling(count);
      if (report || status != SHELL_DEP_OK)
        fprintf(
            stderr,
            "%-40s n=%2u bytes=%5zu status=%d work=%zu (%.1f per n log n)\n",
            family->name, count, used, status, work,
            (double)work / (double)bound);
      CHECK(status == SHELL_DEP_OK && shell_dep_graph_validate(graph).valid);
      if (previous_work) {
        /* work / previous <= 2.2 * used / previous_bytes, in integers. */
        bool ratio = work * previous_bytes * 10 <= 22 * used * previous_work;
        if (!ratio)
          fprintf(stderr, "%s: n=%u work %zu after %zu, bytes %zu after %zu\n",
                  family->name, count, work, previous_work, used,
                  previous_bytes);
        CHECK(ratio);
      }
      if (work > worst * bound)
        worst = (work + bound - 1) / bound;
      previous_work = work;
      previous_bytes = used;
    }
    if (family->constant) {
      if (worst > family->constant)
        fprintf(stderr, "%s: needs C=%zu, budget %zu\n", family->name, worst,
                family->constant);
      CHECK(worst <= family->constant);
    } else if (report)
      fprintf(stderr, "%s: C=%zu\n", family->name, worst);
  }
  shellsplit_graph_fixture_destroy(&fixture);
}

/* The join of versions is a union of persistent maps: nested conditionals
 * that each write a descriptor of their own join the version holding every
 * write inside with the entry version at every level. A join that walked the
 * keys its two versions differ in would cost the writes inside it each time,
 * quadratic in the depth; the union costs the node pairs the two sides do not
 * share, so doubling the depth doubles the work up to a logarithm. The depth
 * is not bounded by the graph capacity here, since the hook builds versions
 * directly. */
static void scaling_check_nested_join(void) {
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 1,
                                      false, 0));
  bool report = getenv("FD_SCALING_REPORT") != NULL;
  size_t previous = 0;
  for (unsigned depth = 32; depth <= 256; depth *= 2) {
    shellsplit_test_source_scan_reset();
    CHECK(
        shellsplit_test_nested_join_contract(fixture.limits.workspace, depth));
    size_t work = scaling_total_work();
    size_t bound = (size_t)depth * scaling_log2_ceiling(depth);
    if (report)
      fprintf(stderr, "nested joins depth=%3u work=%zu (%.1f per n log n)\n",
              depth, work, (double)work / (double)bound);
    /* Quadratic work would quadruple; n log n grows by at most 2.5x. */
    if (previous)
      CHECK(work * 10 <= 25 * previous);
    CHECK(work <= 400 * bound);
    previous = work;
  }
  /* And through the exact merge, which must factor every level into one
   * version, deciding its exactness from a memoized fold. */
  previous = 0;
  for (unsigned depth = 32; depth <= 256; depth *= 2) {
    shellsplit_test_source_scan_reset();
    CHECK(
        shellsplit_test_nested_merge_contract(fixture.limits.workspace, depth));
    size_t work = scaling_total_work();
    size_t bound = (size_t)depth * scaling_log2_ceiling(depth);
    if (report)
      fprintf(stderr, "nested merges depth=%3u work=%zu (%.1f per n log n)\n",
              depth, work, (double)work / (double)bound);
    if (previous)
      CHECK(work * 10 <= 25 * previous);
    CHECK(work <= 400 * bound);
    previous = work;
  }
  shellsplit_graph_fixture_destroy(&fixture);
}
#endif

static int run_scaling(int argc, char **argv) {
  (void)argc;
  (void)argv;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  scaling_check_families();
  scaling_check_nested_join();
#endif
  puts("fd scaling tests passed");
  return EXIT_SUCCESS;
}
#undef CHECK

int main(int argc, char **argv) {
  int status = 0;
  status |= run_flow(argc, argv);
  status |= run_scaling(argc, argv);
  return status != 0;
}
