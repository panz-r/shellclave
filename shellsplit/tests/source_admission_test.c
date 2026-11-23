/* Source admission: how a source is classified (complete, incomplete, invalid,
 * unsupported), its tokens, delimiters, heredocs and word forms, and the status
 * table the Bash qualification driver also queries. */
#include "shell_sequence.h"
#include "shell_source.h"
#include "syntax_boundary_cases.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
#ifdef SHELLSPLIT_TEST_ALLOCATOR
#include "test_allocator.h"
#endif
#include "../src/shell_depgraph_internal.h"
#include "../src/shell_processor_internal.h"
#include "../src/shell_semantics_internal.h"
#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "../src/shell_word_internal.h"
#include "ansi_nul_cases.h"
#include "ansi_parameter_cases.h"
#include "control_word_cases.h"
#include "graph_fixture.h"
#include "shell_abstract.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#include "source_compare.h"
#include "word_byte_cases.h"

/* --- status (from source_status_test.c) --- */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static shell_source_result_t status_draft;

static void status_check(const char *source, size_t length,
                         shell_source_status_t expected) {
  shell_source_status_t actual =
      shell_parse_draft(source, length, NULL, &status_draft);
  if (actual != expected)
    fprintf(stderr, "source status %d, expected %d: %.*s\n", actual, expected,
            (int)length, source);
  CHECK(actual == expected);
  if (actual != SHELL_SOURCE_COMPLETE && actual != SHELL_SOURCE_INCOMPLETE) {
    CHECK(!status_draft.prefix_length && !status_draft.tail_start &&
          !status_draft.prefix.count && !status_draft.prefix.group_count);
    for (uint32_t i = 0; i < status_draft.header_count; ++i)
      CHECK(!status_draft.headers[i].complete);
  }
}

static void status_heredoc_failure_domains(void) {
  const char *const bodies[] = {"ascii", "é", "日本"};
  const char *const delimiters[] = {"END", "éEOF"};
  static const struct {
    const char *tail;
    shell_source_status_t status;
  } cases[] = {
      {":", SHELL_SOURCE_COMPLETE},
      {"cat <<", SHELL_SOURCE_INCOMPLETE},
      {"cat <<'unfinished", SHELL_SOURCE_INCOMPLETE},
      {"cat <<EO\\\n", SHELL_SOURCE_INCOMPLETE},
      {"cat <<\n", SHELL_SOURCE_INVALID},
      {"cat <<#comment", SHELL_SOURCE_INVALID},
      {"cat <<;", SHELL_SOURCE_INVALID},
      {"cat <<&& :", SHELL_SOURCE_INVALID},
      {"cat <<)", SHELL_SOURCE_INVALID},
      {"cat << < file", SHELL_SOURCE_INVALID},
      {"cat <<; cat <<'Q'\né\nQ\n", SHELL_SOURCE_INVALID},
      {"cat <<$\"END\"\npayload\nEND\n", SHELL_SOURCE_UNSUPPORTED},
      {"cat <<\nprintf é", SHELL_SOURCE_INVALID},
      {"cat <<\nprintf $'é'", SHELL_SOURCE_INVALID},
      {"cat <<\nprintf $((é))", SHELL_SOURCE_UNSUPPORTED},
  };
  for (size_t b = 0; b < sizeof(bodies) / sizeof(bodies[0]); ++b)
    for (size_t d = 0; d < sizeof(delimiters) / sizeof(delimiters[0]); ++d) {
      char source[8192];
      int prefix = snprintf(source, sizeof(source), "cat <<'%s'\n%s\n%s\n",
                            delimiters[d], bodies[b], delimiters[d]);
      CHECK(prefix > 0 && (size_t)prefix < sizeof(source));
      for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        size_t tail = strlen(cases[c].tail);
        CHECK((size_t)prefix + tail < sizeof(source));
        memcpy(source + prefix, cases[c].tail, tail + 1);
        status_check(source, (size_t)prefix + tail, cases[c].status);
        if (cases[c].status == SHELL_SOURCE_INCOMPLETE)
          CHECK(status_draft.prefix_length == (uint32_t)prefix &&
                status_draft.header_count == 2 &&
                status_draft.headers[0].complete);
      }
      for (size_t count = SHELL_MAX_SUBCOMMANDS - 1;
           count <= SHELL_MAX_SUBCOMMANDS + 1; ++count) {
        size_t used = (size_t)prefix;
        memcpy(source + used, "cat ", 4);
        used += 4;
        for (size_t i = 0; i < count; ++i) {
          int written =
              snprintf(source + used, sizeof(source) - used, "<<X%zu ", i);
          CHECK(written > 0 && (size_t)written < sizeof(source) - used);
          used += (size_t)written;
        }
        source[used++] = '\n';
        status_check(source, used,
                     count < SHELL_MAX_SUBCOMMANDS ? SHELL_SOURCE_INCOMPLETE
                                                   : SHELL_SOURCE_TRUNCATED);
        /* The whole-source representation check still precedes both limits
         * and grammar. A late NUL must not become a prefix or a retry. */
        source[used++] = '\0';
        status_check(source, used, SHELL_SOURCE_INVALID_INPUT);
      }
    }
}

static void status_redirect_operator_boundaries(void) {
  const char *const prefixes[] = {"", "2", "{fd}"};
  const char *const invalid[] = {"<<<<x", "<<<>x", ">>&x",
                                 "<>&3",  ">><x",  "<<< >x"};
  const char *const valid[] = {"<file",   ">file",        ">>file", "<>file",
                               ">|file",  "<&0",          ">&1",    "<<<word",
                               "<<<<(:)", "> >(printf x)"};
  const char *const heads[] = {": ", "{ :; } ", "echo $(: "};
  for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); ++p)
    for (size_t h = 0; h < sizeof(heads) / sizeof(heads[0]); ++h) {
      char source[256];
      for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        int n = snprintf(source, sizeof(source), "%s%s%s%s", heads[h],
                         prefixes[p], invalid[i], h == 2 ? ")" : "");
        CHECK(n > 0 && (size_t)n < sizeof(source));
        status_check(source, (size_t)n, SHELL_SOURCE_INVALID);
      }
      for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        int n = snprintf(source, sizeof(source), "%s%s%s%s", heads[h],
                         prefixes[p], valid[i], h == 2 ? ")" : "");
        CHECK(n > 0 && (size_t)n < sizeof(source));
        status_check(source, (size_t)n, SHELL_SOURCE_COMPLETE);
        for (uint32_t j = 0; j < status_draft.header_count; ++j)
          CHECK(status_draft.headers[j].complete);
      }
    }
  const char *const received[] = {": <<<<", ": <<<>", "{ :; } <<<<",
                                  ": <<<\\\n<"};
  for (size_t i = 0; i < sizeof(received) / sizeof(received[0]); ++i) {
    status_check(received[i], strlen(received[i]), SHELL_SOURCE_INCOMPLETE);
    CHECK(status_draft.need == SHELL_SOURCE_NEEDS_SUBSTITUTION);
  }
  status_check("cat <<'Q'\né\nQ\n: <<<<x", strlen("cat <<'Q'\né\nQ\n: <<<<x"),
               SHELL_SOURCE_INVALID);
}

static int run_status(int argc, char **argv) {
  (void)argc;
  (void)argv;
  CHECK(argc == 1);
  status_heredoc_failure_domains();
  status_redirect_operator_boundaries();
  CHECK(SHELL_SOURCE_COMPLETE == 0 && SHELL_SOURCE_INCOMPLETE == 1 &&
        SHELL_SOURCE_INVALID == 2 && SHELL_SOURCE_TRUNCATED == 3);
  static const struct {
    const char *source;
    shell_source_status_t status;
  } cases[] = {
      {"printf ok", SHELL_SOURCE_COMPLETE},
      {"echo before #comment \\\necho after", SHELL_SOURCE_COMPLETE},
      {": #comment \\\na=(x)", SHELL_SOURCE_UNSUPPORTED},
      {": #comment \\\n{ :; }", SHELL_SOURCE_COMPLETE},
      {": | time :", SHELL_SOURCE_COMPLETE},
      {": |& time :", SHELL_SOURCE_COMPLETE},
      {": |\ntime :", SHELL_SOURCE_COMPLETE},
      {": | #comment\ntime :", SHELL_SOURCE_COMPLETE},
      {": | #comment \\\ntime :", SHELL_SOURCE_COMPLETE},
      {": |\\\ntime :", SHELL_SOURCE_COMPLETE},
      {": | time {", SHELL_SOURCE_COMPLETE},
      {": |& time {", SHELL_SOURCE_COMPLETE},
      {": |\ntime {", SHELL_SOURCE_COMPLETE},
      {": |\ntime -p -- {", SHELL_SOURCE_COMPLETE},
      {": |&\n\"time\" {", SHELL_SOURCE_COMPLETE},
      {": |\n\n\\time {", SHELL_SOURCE_COMPLETE},
      {": |&\ntime\"\" {", SHELL_SOURCE_COMPLETE},
      {": |&\ntime :", SHELL_SOURCE_INVALID},
      {": |\n\ntime :", SHELL_SOURCE_INVALID},
      {": |\n#comment\ntime :", SHELL_SOURCE_INVALID},
      {": |& #comment \\\ntime :", SHELL_SOURCE_INVALID},
      {": |&\n\\\ntime :", SHELL_SOURCE_INVALID},
      {"echo before; : |&\ntime -p -- :", SHELL_SOURCE_INVALID},
      {"echo $(: |&\ntime :)", SHELL_SOURCE_INVALID},
      {"cat <(: |\n\ntime :)", SHELL_SOURCE_INVALID},
      {"echo $(: |\ntime {)", SHELL_SOURCE_COMPLETE},
      {": |&\ntime", SHELL_SOURCE_INVALID},
      {": |\ntime", SHELL_SOURCE_COMPLETE},
      {"", SHELL_SOURCE_COMPLETE},
      {"cat /workspace/before.txt\ncat <<\ncat /workspace/not-a-read.txt",
       SHELL_SOURCE_INVALID},
      {"cat <<", SHELL_SOURCE_INCOMPLETE},
      {"cat <<EOF\npayload\n", SHELL_SOURCE_INCOMPLETE},
      {"cat <<EOF\npayload\nEOF\n", SHELL_SOURCE_COMPLETE},
      {"cat <<#comment", SHELL_SOURCE_INVALID},
      {"cat >\nfile", SHELL_SOURCE_INVALID},
      {"echo && ;", SHELL_SOURCE_INVALID},
      {"echo $(echo &&)", SHELL_SOURCE_INVALID},
      {"echo $(cat <<\n)", SHELL_SOURCE_INVALID},
      {"echo )", SHELL_SOURCE_INVALID},
      {"{ :; )", SHELL_SOURCE_INVALID},
      {"echo \\$(whoami)", SHELL_SOURCE_INVALID},
      {"echo \\$((1+2))", SHELL_SOURCE_INVALID},
      {"\\$(whoami)", SHELL_SOURCE_INVALID},
      {"echo before; echo \\$(whoami)", SHELL_SOURCE_INVALID},
      {"echo \\$(whoami", SHELL_SOURCE_INVALID},
      {"echo \"\\$(whoami)\"", SHELL_SOURCE_COMPLETE},
      {"echo '\\$(whoami)'", SHELL_SOURCE_COMPLETE},
      {"echo \\$\\(whoami\\)", SHELL_SOURCE_COMPLETE},
      {"echo \\\\$(whoami)", SHELL_SOURCE_COMPLETE},
      {"echo x\\$(whoami)", SHELL_SOURCE_INVALID},
      {"{ :; } >\\$(whoami)", SHELL_SOURCE_INVALID},
      {": >\\$(whoami)", SHELL_SOURCE_INVALID},
      {"{ :; } >$(printf file)", SHELL_SOURCE_COMPLETE},
      {"echo 'unfinished", SHELL_SOURCE_INCOMPLETE},
      {"echo $(echo 'unfinished", SHELL_SOURCE_INCOMPLETE},
      {"printf '%s' '日本'", SHELL_SOURCE_COMPLETE},
      {"echo $(printf '%s' '日本')", SHELL_SOURCE_COMPLETE},
      {"printf '%s' 日本", SHELL_SOURCE_COMPLETE},
      {"printf '%s' $'日本'", SHELL_SOURCE_COMPLETE},
      {"printf '\001'", SHELL_SOURCE_UNSUPPORTED},
      {"printf '\177'", SHELL_SOURCE_UNSUPPORTED},
      {"if true; then :; fi", SHELL_SOURCE_COMPLETE},
      {"case x in x) :;; esac", SHELL_SOURCE_UNSUPPORTED},
      {"function f { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"f() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"foo.bar() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"foo-bar() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"1f() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"\"f\"() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"f\\ g() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("input"),
       SHELL_SOURCE_UNSUPPORTED},
      {"[[ x -nt y -ot z ]]", SHELL_SOURCE_INVALID},
      {"[[ -n x == y ]]", SHELL_SOURCE_INVALID},
      {"[[ x == y -ef z ]]", SHELL_SOURCE_INVALID},
      {"[[ x -h y ]]", SHELL_SOURCE_INVALID},
      {"[[ x ! ", SHELL_SOURCE_INVALID},
      {"[[ x -nt y -o\\\nt z ]]", SHELL_SOURCE_INVALID},
      {"[[ ( -n x == y ) ]]", SHELL_SOURCE_INVALID},
      {"echo \"$([[ x -nt y -ot z ]])\"", SHELL_SOURCE_INVALID},
      {"cat <([[ x == y -ef z ]])", SHELL_SOURCE_INVALID},
      {"[[ x =~ y ]]", SHELL_SOURCE_UNSUPPORTED},
      {"[[ x < y ]]", SHELL_SOURCE_UNSUPPORTED},
      {"[[ x > y ]]", SHELL_SOURCE_UNSUPPORTED},
      {"[[ x !", SHELL_SOURCE_INCOMPLETE},
      {"[[ x !\\\n", SHELL_SOURCE_INCOMPLETE},
      {"[[ x -nt y &", SHELL_SOURCE_INCOMPLETE},
      {"((1 + 2))", SHELL_SOURCE_COMPLETE},
      {"(( $(printf 1; : 日本) ))", SHELL_SOURCE_COMPLETE},
      {"(( $(printf 日本 &&) ))", SHELL_SOURCE_INVALID},
      {"((日本))", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(if true; then :; fi)", SHELL_SOURCE_COMPLETE},
      {"echo ${x!}", SHELL_SOURCE_UNSUPPORTED},
      {"echo ${x:}", SHELL_SOURCE_UNSUPPORTED},
      {"echo $[1 + (2)]", SHELL_SOURCE_UNSUPPORTED},
      {"echo ok; !\ntrue", SHELL_SOURCE_UNSUPPORTED},
      {"!", SHELL_SOURCE_UNSUPPORTED},
      {"! ! ", SHELL_SOURCE_UNSUPPORTED},
      {"!; :", SHELL_SOURCE_UNSUPPORTED},
      {"! &", SHELL_SOURCE_UNSUPPORTED},
      {"{ !; }", SHELL_SOURCE_UNSUPPORTED},
      {"( !; )", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(!;)", SHELL_SOURCE_UNSUPPORTED},
      {"echo `!`", SHELL_SOURCE_UNSUPPORTED},
      {"echo `! !`", SHELL_SOURCE_UNSUPPORTED},
      {"echo ok; !", SHELL_SOURCE_UNSUPPORTED},
      {"! | :", SHELL_SOURCE_INVALID},
      {"! && :", SHELL_SOURCE_INVALID},
      {"! || :", SHELL_SOURCE_INVALID},
      {"( ! )", SHELL_SOURCE_INVALID},
      {"echo $(!)", SHELL_SOURCE_INVALID},
      {"echo $(!", SHELL_SOURCE_INCOMPLETE},
      {"( !", SHELL_SOURCE_INCOMPLETE},
      {"time !", SHELL_SOURCE_COMPLETE},
      {"! time", SHELL_SOURCE_COMPLETE},
      {": > !", SHELL_SOURCE_COMPLETE},
      {": >!", SHELL_SOURCE_COMPLETE},
      {"> !", SHELL_SOURCE_COMPLETE},
      {": < !", SHELL_SOURCE_COMPLETE},
      {": 2>& !", SHELL_SOURCE_COMPLETE},
      {"{ :; } > !", SHELL_SOURCE_COMPLETE},
      {"( : ) < !", SHELL_SOURCE_COMPLETE},
      {": <<< !", SHELL_SOURCE_COMPLETE},
      {": > \\\n!", SHELL_SOURCE_COMPLETE},
      {"echo a=(x)", SHELL_SOURCE_INVALID},
      {": a+=(y)", SHELL_SOURCE_INVALID},
      {": >a=(x)", SHELL_SOURCE_INVALID},
      {"{ :; } >a=(x)", SHELL_SOURCE_INVALID},
      {"echo a=(", SHELL_SOURCE_INVALID},
      {"de\"clare\" a=(x)", SHELL_SOURCE_INVALID},
      {"declare\"\" a=(x)", SHELL_SOURCE_INVALID},
      {"command declare a=(x)", SHELL_SOURCE_INVALID},
      {">out ! a=(x)", SHELL_SOURCE_INVALID},
      {"x=1 ! a=(x)", SHELL_SOURCE_INVALID},
      {">out !", SHELL_SOURCE_COMPLETE},
      {">out {", SHELL_SOURCE_COMPLETE},
      {">out { }", SHELL_SOURCE_COMPLETE},
      {"2>&1 {", SHELL_SOURCE_COMPLETE},
      {">out ! {", SHELL_SOURCE_COMPLETE},
      {">out \\\n{", SHELL_SOURCE_COMPLETE},
      {">out { :; }", SHELL_SOURCE_INVALID},
      {"{ :; } >out", SHELL_SOURCE_COMPLETE},
      {">out {; { :; }", SHELL_SOURCE_COMPLETE},
      {"builtin declare a=(x)", SHELL_SOURCE_INVALID},
      {"a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=x a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=\"x\" a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]+=x a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=x\"\" a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=$x a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=$(printf x) a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=x\\\ny a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=x declare a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=x export a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {">out a[0]=x a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(a[0]=x a=(x))", SHELL_SOURCE_UNSUPPORTED},
      {"a[0]=x : a=(x)", SHELL_SOURCE_INVALID},
      {"a+=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a=(", SHELL_SOURCE_UNSUPPORTED},
      {"a\\\n=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a=\\\n(x)", SHELL_SOURCE_UNSUPPORTED},
      {"a+\\\n=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"declare a[0]\\\n=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"echo a\\\n=(x)", SHELL_SOURCE_INVALID},
      {": >a=\\\n(x)", SHELL_SOURCE_INVALID},
      {"declare a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"typeset a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"local a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"export a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"readonly a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"de\\\nclare a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"x=1 declare a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {">out declare a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"declare >out a=(x)", SHELL_SOURCE_INVALID},
      {"declare x a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"declare -- a=(x)", SHELL_SOURCE_UNSUPPORTED},
      {"echo a[0]=x", SHELL_SOURCE_COMPLETE},
      {"echo \"a=(x)\"", SHELL_SOURCE_COMPLETE},
      {"echo \"$((1+))\"", SHELL_SOURCE_COMPLETE},
      {"read -nwrong value <<<payload", SHELL_SOURCE_COMPLETE},
      {"echo before; if", SHELL_SOURCE_INCOMPLETE},
      {"echo before; if ", SHELL_SOURCE_INCOMPLETE},
      {"printf '%s' '日本'\ncat <<\n", SHELL_SOURCE_INVALID},
      {"if true; then :; fi\ncat <<\n", SHELL_SOURCE_INVALID},
      {"cat <<\nif true; then :; fi", SHELL_SOURCE_INVALID},
      {"cat <<'EOF'\n日本\nEOF\n", SHELL_SOURCE_COMPLETE},
      {"cat <<$\"EOF\"\npayload\nEOF\n", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(: <<EOF)", SHELL_SOURCE_UNSUPPORTED},
      {"echo \"$(: <<EOF)\"", SHELL_SOURCE_UNSUPPORTED},
      {": <(: <<EOF)", SHELL_SOURCE_UNSUPPORTED},
      {"echo `: <<EOF`", SHELL_SOURCE_UNSUPPORTED},
      {"echo `: <<EOF\npayload\n`", SHELL_SOURCE_UNSUPPORTED},
      {"echo `: <<EOF; !`", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(: <<EOF; !)", SHELL_SOURCE_INVALID},
      {"echo $(: <<'EOF')", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(: <<-EOF)", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(: <<ONE <<TWO)", SHELL_SOURCE_UNSUPPORTED},
      {"echo before; echo $(: <<EOF)", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(: <<)", SHELL_SOURCE_INVALID},
      {"echo $(: <<EOF &&)", SHELL_SOURCE_INVALID},
      {"echo $(: <<EOF >)", SHELL_SOURCE_INVALID},
      {"echo $({ : <<EOF)", SHELL_SOURCE_INVALID},
      {"echo `: <<`", SHELL_SOURCE_INVALID},
      {"echo `: <<EOF &&`", SHELL_SOURCE_INVALID},
      {"echo $(: <<EOF\npayload\nEOF\n)", SHELL_SOURCE_COMPLETE},
      {"echo `: <<EOF\npayload\nEOF\n`", SHELL_SOURCE_COMPLETE},
      {"echo $(: <<EOF", SHELL_SOURCE_INCOMPLETE},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    status_check(cases[i].source, strlen(cases[i].source), cases[i].status);
  const char nul[] = "printf '日本'\0; :";
  status_check(nul, sizeof(nul) - 1, SHELL_SOURCE_INVALID_INPUT);
  const char control_nul[] = "printf '\001'\0; :";
  status_check(control_nul, sizeof(control_nul) - 1,
               SHELL_SOURCE_INVALID_INPUT);

  shell_limits_t limits = SHELL_LIMITS_DEFAULT;
  limits.max_subcommands = 1;
  static const char two_commands[] = "printf a; printf b";
  CHECK(shell_parse_draft(two_commands, sizeof(two_commands) - 1, &limits,
                          &status_draft) == SHELL_SOURCE_TRUNCATED);
  CHECK(!status_draft.prefix_length && !status_draft.prefix.count);
  static const char grouped_delimiter[] =
      "cat <<$(printf EOF)\nbody\n$(printf EOF)\n";
  char tiny[1];
  limits = SHELL_LIMITS_DEFAULT;
  limits.workspace = tiny;
  limits.workspace_size = sizeof(tiny);
  CHECK(shell_parse_draft(grouped_delimiter, sizeof(grouped_delimiter) - 1,
                          &limits, &status_draft) == SHELL_SOURCE_TRUNCATED);
  CHECK(!status_draft.prefix_length && !status_draft.prefix.count);
  CHECK(shell_source_workspace_size(sizeof(grouped_delimiter) - 1,
                                    &limits.workspace_size));
  limits.workspace = malloc(limits.workspace_size);
  CHECK(limits.workspace);
  CHECK(shell_parse_draft(grouped_delimiter, sizeof(grouped_delimiter) - 1,
                          &limits, &status_draft) == SHELL_SOURCE_COMPLETE);
  free(limits.workspace);

  /* A bounded scope stack is an analysis resource, not a syntax judgment. */
  char nested[2048];
  size_t used = 0;
  memcpy(nested, "echo ", 5);
  used = 5;
  for (unsigned i = 0; i <= SHELL_MAX_SUBCOMMANDS; ++i) {
    memcpy(nested + used, "${x:-", 5);
    used += 5;
  }
  nested[used++] = 'x';
  for (unsigned i = 0; i <= SHELL_MAX_SUBCOMMANDS; ++i)
    nested[used++] = '}';
  status_check(nested, used, SHELL_SOURCE_TRUNCATED);
  used = 0;
  for (unsigned i = 0; i <= SHELL_MAX_SUBCOMMANDS; ++i) {
    memcpy(nested + used, "echo $(", 7);
    used += 7;
  }
  nested[used++] = ':';
  for (unsigned i = 0; i <= SHELL_MAX_SUBCOMMANDS; ++i)
    nested[used++] = ')';
  status_check(nested, used, SHELL_SOURCE_TRUNCATED);
  puts("typed source outcomes passed");
  return EXIT_SUCCESS;
}
#undef CHECK

/* --- source (from source_test.c) --- */
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static shell_source_result_t source_draft;
static shell_dep_graph_t source_graph;
static shell_dep_limits_t limits;

static void source_ignore_semantic_token(const shell_token_t *token,
                                         void *context) {
  (void)token;
  (void)context;
}

static void source_ignore_semantic_read(const char *word, uint32_t fd,
                                        unsigned kind, const char *parameter,
                                        size_t parameter_length, bool identity,
                                        void *context) {
  (void)word;
  (void)fd;
  (void)kind;
  (void)parameter;
  (void)parameter_length;
  (void)identity;
  (void)context;
}

static void source_ignore_semantic_process(const char *word, size_t length,
                                           void *context) {
  (void)word;
  (void)length;
  (void)context;
}

static bool source_inspected_unsupported_semantics(const char *source,
                                                   size_t length) {
  unsigned context = 0;
  return shell_tokenizer_inspect_semantics(
             source, length, source_ignore_semantic_token,
             source_ignore_semantic_read, source_ignore_semantic_process, NULL,
             NULL, &context) == SHELL_SEMANTIC_UNSUPPORTED;
}

static void source_parse(const char *source) {
  int error = shell_dep_graph_parse(source, strlen(source), "/workspace",
                                    &limits, &source_graph);
  if (error)
    fprintf(stderr, "graph error %d: %s\n", error, source);
  CHECK(error == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(&source_graph).valid);
}

static void content(const shell_dep_doc_t *doc, const char *expected) {
  size_t size, written;
  char bytes[256];
  CHECK(shell_dep_doc_content_length(doc, &size));
  CHECK(size == strlen(expected));
  CHECK(shell_dep_doc_write_content(doc, bytes, sizeof(bytes), &written));
  CHECK(written == size && !memcmp(bytes, expected, size));
}

static void heredocs(void) {
  static const struct {
    const char *source, *payload;
  } cases[] = {
      {"cat > target.txt <<'EOF'\nalpha\nEOF\n", "alpha\n"},
      {"cat <<-'EOF'\n\talpha\n\tEOF\n", "alpha\n"},
      {"cat <<'EOF'\nEOF\n", ""},
      {"cat <<'EOF\r'\ncat /workspace/body.txt\nEOF\r\ncat "
       "/workspace/after.txt",
       "cat /workspace/body.txt\n"},
      {"cat <<'日本 語'\ncat /workspace/body.txt\n日本 語\ncat "
       "/workspace/after.txt",
       "cat /workspace/body.txt\n"},
      {"cat <<EOF\nalpha\nE\\\nOF\ncat after", "alpha\n"},
      {"cat <<EO\\\nF\n$(printf expanded)\nEOF\n", "$(printf expanded)\n"},
      {"cat <<'EOF'\nalpha\r\nEOF\n", "alpha\r\n"},
      {"cat <<E'O'\\F\nalpha\nEOF", "alpha\n"},
      {"cat <<$'E\\x4fF'\nalpha\nEOF\n", "alpha\n"},
      {"cat <<$'END\\0ignored'\npayload\nEND\n", "payload\n"},
      {"cat <<$'\\0ignored'\npayload\n\n", "payload\n"},
      {"cat <<$'E\\0ignored'X$'Y\\0ignored'W\npayload\nEXYW\n", "payload\n"},
      {"cat <<$'END\\0\\u65e5'\npayload\nEND\n", "payload\n"},
      {"cat <<''\nalpha\n\n", "alpha\n"},
      {"cat <<EOF\n日本 語\nEOF\n", "日本 語\n"},
      {"cat <<EOF\n日本 $((1 + 2)) 語\nEOF\n", "日本 $((1 + 2)) 語\n"},
      {"cat <<EOF\n日本 ${value:1} 語\nEOF\n", "日本 ${value:1} 語\n"},
      {"cat <<EOF\n日本 $((1)) 語 $((2)) 文\nEOF\n",
       "日本 $((1)) 語 $((2)) 文\n"},
      {"cat <<EOF\n日本 ${value:-語} ${value#文} $((2))\nEOF\n",
       "日本 ${value:-語} ${value#文} $((2))\n"},
      {"echo \"$(cat <<'日本 語'\nbody\n日本 語\n)\"", "body\n"},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    source_parse(source);
    unsigned docs = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++)
      if (source_graph.nodes[n].type == SHELL_NODE_DOC &&
          source_graph.nodes[n].doc.kind == SHELL_DOC_HEREDOC) {
        content(&source_graph.nodes[n].doc, cases[c].payload);
        docs++;
      }
    CHECK(docs == 1);
    int status = shell_parse_draft(source, strlen(source), NULL, &source_draft);
    if (status)
      fprintf(stderr, "draft status %d need %d: %s\n", status,
              source_draft.need, source);
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.prefix_length == strlen(source));
    CHECK(source_draft.heredoc_count == 1 && source_draft.heredocs[0].complete);
    content(&source_draft.heredocs[0].content, cases[c].payload);
    CHECK(source_draft.headers[source_draft.heredocs[0].header].word_count ==
          1);
    CHECK(source_draft.redirects[source_draft.heredocs[0].redirect].heredoc ==
          0);
    CHECK(shell_dep_graph_parse_with_fast(
              source, source_draft.prefix_length, "/workspace", &limits,
              &source_draft.prefix, &source_graph) == SHELL_DEP_OK);
  }
}

/* With extglob, Bash reads `$` and then `!(...)`: `$!(foo)` is the special
 * parameter followed by the literal text `(foo)`, and likewise for `$?`, `$@`
 * and `$*`, whose punctuation is also an extglob operator. The lexer splits
 * such a word at the `(`, so it cannot model it; that is not a grammar error.
 * Anything else with a parenthesis after a parameter stays invalid. */
static void source_special_parameter_extglob_tail(void) {
  static const char *const unsupported[] = {
      "echo $!(foo)",      "echo $?(foo)",         "echo $@(foo)",
      "echo $*(foo)",      "echo a$!(foo)b",       "echo $!(foo|bar)",
      "echo $!(foo)/x",    "echo $@(a)$*(b)",      "cat > $!(foo)",
      "cat < $?(foo)",     "echo > $@(foo)",       "echo >$*(foo)",
      "echo $!()",         "echo $!( foo )",       "x=$!(foo)",
      "echo $?(foo) x",    "echo $!(a(b)c)",       "echo $!( ( x ) )",
      "echo $!(foo)\"x\"", "true && echo $!(foo)", "( echo $!(foo) )",
      "{ echo $@(x); }",
  };
  for (size_t c = 0; c < sizeof(unsupported) / sizeof(unsupported[0]); c++) {
    int status = shell_parse_draft(unsupported[c], strlen(unsupported[c]), NULL,
                                   &source_draft);
    if (status != SHELL_SOURCE_UNSUPPORTED)
      fprintf(stderr, "expected UNSUPPORTED (%d): %s\n", status,
              unsupported[c]);
    CHECK(status == SHELL_SOURCE_UNSUPPORTED);
    CHECK(shell_dep_graph_parse(unsupported[c], strlen(unsupported[c]),
                                "/workspace", &limits,
                                &source_graph) == SHELL_DEP_EPARSE);
  }
  static const char *const invalid[] = {
      "echo $1(foo)",     "echo $x(foo)",   "echo ${x}(foo)", "echo foo(foo)",
      "echo $-(foo)",     "echo $#(foo)",   "echo $$(foo)",   "echo $0(foo)",
      "echo $!(foo",      "echo $!(",       "echo $@(foo",    "echo $!(foo))",
      "echo \"$!\"(foo)", "echo '$!'(foo)", "echo $! (foo)",  "echo ${!x}(foo)",
  };
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); c++) {
    int status =
        shell_parse_draft(invalid[c], strlen(invalid[c]), NULL, &source_draft);
    if (status != SHELL_SOURCE_INVALID)
      fprintf(stderr, "expected INVALID (%d): %s\n", status, invalid[c]);
    CHECK(status == SHELL_SOURCE_INVALID);
  }
  /* These already lex as a literal `$` or a complete extglob token. */
  static const char *const complete[] = {
      "echo $+(foo)",  "echo !(foo)",   "echo a@(foo)",  "echo \\$!(foo)",
      "echo $$!(foo)", "echo $!!(foo)", "echo $!+(foo)", "echo \"$!(foo)\"",
  };
  for (size_t c = 0; c < sizeof(complete) / sizeof(complete[0]); c++) {
    int status = shell_parse_draft(complete[c], strlen(complete[c]), NULL,
                                   &source_draft);
    if (status != SHELL_SOURCE_COMPLETE)
      fprintf(stderr, "expected COMPLETE (%d): %s\n", status, complete[c]);
    CHECK(status == SHELL_SOURCE_COMPLETE);
  }
}

/* `[[` is the reserved word only when it is a word by itself. A process
 * substitution begun with no separator continues the word, so `[[<(cmd)` is an
 * ordinary command word, while `[[ <(cmd) ]]` is a conditional expression. */
static void source_conditional_opener_needs_a_word_boundary(void) {
  static const struct {
    const char *source;
    bool conditional;
  } complete[] = {
      {"[[<(echo hi)", false},      {"[[>(echo hi)", false},
      {"[[<(echo hi) x ]]", false}, {"[[>(echo hi) x ]]", false},
      {"[[<(echo hi)x", false},     {"[[<(echo hi) ]]", false},
      {"[[<(a)<(b)", false},        {"[[<(true)>f", false},
      {"echo [[<(echo hi)", false}, {"x=1 [[<(echo hi)", false},
      {"[[ <(echo hi) ]]", true},   {"[[ -f <(echo) ]]", true},
      {"[[ x ]]; echo a", true},    {"[[x]]", false},
  };
  for (size_t c = 0; c < sizeof(complete) / sizeof(complete[0]); c++) {
    const char *source = complete[c].source;
    shell_parse_result_t parsed = {0};
    int status = shell_parse_draft(source, strlen(source), NULL, &source_draft);
    if (status != SHELL_SOURCE_COMPLETE)
      fprintf(stderr, "expected COMPLETE (%d): %s\n", status, source);
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(shell_parse_fast(source, strlen(source), NULL, &parsed) == SHELL_OK);
    bool conditional = false;
    for (uint32_t i = 0; i < parsed.count; i++)
      conditional |= (parsed.cmds[i].features & SHELL_FEAT_CONDITIONALS) != 0;
    if (conditional != complete[c].conditional)
      fprintf(stderr, "wrong role (conditional=%d): %s\n", conditional, source);
    CHECK(conditional == complete[c].conditional);
    CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                &source_graph) == SHELL_DEP_OK);
  }
  static const char *const invalid[] = {
      "[[<", "[[>", "[[<f", "[[ <f ]]", "[[ x ]]<(y)", "[[ ]]",
  };
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); c++) {
    int status =
        shell_parse_draft(invalid[c], strlen(invalid[c]), NULL, &source_draft);
    if (status != SHELL_SOURCE_INVALID)
      fprintf(stderr, "expected INVALID (%d): %s\n", status, invalid[c]);
    CHECK(status == SHELL_SOURCE_INVALID);
  }
  static const char *const incomplete[] = {"[[", "[[ x"};
  for (size_t c = 0; c < sizeof(incomplete) / sizeof(incomplete[0]); c++)
    CHECK(shell_parse_draft(incomplete[c], strlen(incomplete[c]), NULL,
                            &source_draft) == SHELL_SOURCE_INCOMPLETE);
}

/* Bash reads `NAME[...]` at a command word as one word piece, even without an
 * `=`: `a[;] x` is the command `a[;]` with the argument `x`, not `a[`, `;` and
 * `] x`. Only the subscript right after the identifier counts, a raw newline
 * ends it, and in an argument the operators inside split as usual. */
static unsigned source_graph_command_nodes(void) {
  unsigned commands = 0;
  for (uint32_t n = 0; n < source_graph.node_count; n++)
    commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
  return commands;
}

static void source_command_word_subscript(void) {
  static const struct {
    const char *source;
    unsigned commands; /* simple commands the shell runs */
  } cases[] = {
      /* One command named by the subscripted word. */
      {"a[;] x", 1},
      {"a[&&] x", 1},
      {"a[||] x", 1},
      {"a[|] x", 1},
      {"a[&] x", 1},
      {"a[ ] x", 1},
      {"a[ ;] x", 1},
      {"a[<] x", 1},
      {"a[>] x", 1},
      {"a[)] x", 1},
      {"a[(] x", 1},
      {"a[;;] x", 1},
      {"a[b[c;]] x", 1},
      {"a[\"]\"] x", 1},
      {"a[;]x y", 1},
      {"_a1[;] x", 1},
      {"x=1 a[;] x", 1},
      {"x=1 y=2 a[&&] x", 1},
      {"( a[;] x )", 1},
      {"{ a[;] x; }", 1},
      {"a[\\\n;] x", 1},
      /* Several commands, each with its own subscripted word. */
      {"zz1; a[;] x", 2},
      {"a[;] x; b[;] y", 2},
      {"a[;] x | b[;] y", 2},
      {"a[;] x && b[&] y", 2},
      /* Argument position: the operators inside split the command. */
      {"echo a[;] x", 2},
      {"zz1 a[&] x", 2},
      /* A redirect before any assignment leaves the position acceptable; one
       * after an assignment word ends it, as in Bash. */
      {">f a[;] x", 1},
      {">f x=1 a[;] x", 1},
      {"{fd}>f a[;] x", 1},
      {"x=1 >f a[;] x", 2},
      {"x=1 >f y=2 a[;] x", 2},
      {"x=1 2>f a[;] x", 2},
      /* Only the first subscript, directly after the identifier, is part of
       * the word; a raw newline ends it; other prefixes are not identifiers. */
      {"a[x][;] y", 2},
      {"a[;]b[;] c", 2},
      {"a[\n] x", 2},
      {"1a[;] x", 2},
      {"a-b[;] x", 2},
      {"\"a\"[;] x", 2},
      {"a\"b\"[;] x", 2},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    shell_parse_result_t parsed = {0};
    int status = shell_parse_draft(source, strlen(source), NULL, &source_draft);
    if (status != SHELL_SOURCE_COMPLETE)
      fprintf(stderr, "expected COMPLETE (%d): %s\n", status, source);
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(shell_parse_fast(source, strlen(source), NULL, &parsed) == SHELL_OK);
    if (parsed.count != cases[c].commands)
      fprintf(stderr, "fast parser: %u commands, expected %u: %s\n",
              parsed.count, cases[c].commands, source);
    CHECK(parsed.count == cases[c].commands);
    CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                &source_graph) == SHELL_DEP_OK);
    if (source_graph_command_nodes() != cases[c].commands)
      fprintf(stderr, "graph: %u command nodes, expected %u: %s\n",
              source_graph_command_nodes(), cases[c].commands, source);
    CHECK(source_graph_command_nodes() == cases[c].commands);
  }

  /* An operator inside the word is not a background or redirection, and the
   * bracket is still a glob. */
  static const struct {
    const char *source;
    bool background;
    bool globs;
  } features[] = {
      {"a[&] x", false, true},  {"a[&&] x", false, true},
      {"a[;] x", false, true},  {"echo a[&] x", true, false},
      {"a[!] x", false, false},
  };
  for (size_t c = 0; c < sizeof(features) / sizeof(features[0]); c++) {
    shell_parse_result_t parsed = {0};
    CHECK(shell_parse_fast(features[c].source, strlen(features[c].source), NULL,
                           &parsed) == SHELL_OK);
    uint32_t all = 0;
    for (uint32_t i = 0; i < parsed.count; i++)
      all |= parsed.cmds[i].features;
    CHECK(((all & SHELL_FEAT_BACKGROUND) != 0) == features[c].background);
    CHECK(((all & SHELL_FEAT_GLOBS) != 0) == features[c].globs);
  }

  /* The bracket is a glob pattern, so the command name is dynamic, as for
   * `a[x]`; only a bracket that is not a pattern names a fixed command. */
  static const struct {
    const char *source;
    bool known;
  } names[] = {
      {"a[x] y", false},  {"a[;] x", false}, {"a[ ] x", false},
      {"a[&&] x", false}, {"a[!] x", true},  {"a[] x", true},
      {"ab y", true},
  };
  for (size_t c = 0; c < sizeof(names) / sizeof(names[0]); c++) {
    CHECK(shell_dep_graph_parse(names[c].source, strlen(names[c].source),
                                "/workspace", &limits,
                                &source_graph) == SHELL_DEP_OK);
    bool known = false;
    for (uint32_t n = 0; n < source_graph.node_count; n++)
      if (source_graph.nodes[n].type == SHELL_NODE_CMD)
        known = source_graph.nodes[n].cmd.effective_command_known;
    if (known != names[c].known)
      fprintf(stderr, "command name known=%d, expected %d: %s\n", known,
              names[c].known, names[c].source);
    CHECK(known == names[c].known);
  }

  /* Absorbing the subscript must not hide a command it contains: Bash runs
   * the substitution while expanding the word. */
  static const struct {
    const char *source;
    unsigned nodes; /* the outer command plus every nested one */
  } nested[] = {
      {"a[$(echo hi)] x", 2},  {"a[`echo hi`] x", 2},
      {"a[<(echo hi)] x", 2},  {"a[$(rm -rf q; echo)] x", 3},
      {"a[;]$(echo hi) x", 2},
  };
  for (size_t c = 0; c < sizeof(nested) / sizeof(nested[0]); c++) {
    CHECK(shell_dep_graph_parse(nested[c].source, strlen(nested[c].source),
                                "/workspace", &limits,
                                &source_graph) == SHELL_DEP_OK);
    if (source_graph_command_nodes() != nested[c].nodes)
      fprintf(stderr, "graph: %u command nodes, expected %u: %s\n",
              source_graph_command_nodes(), nested[c].nodes, nested[c].source);
    CHECK(source_graph_command_nodes() == nested[c].nodes);
  }
}

/* The parentheses of an extglob delimit a pattern, not a shell fragment: `#`
 * and `<<` are literal pattern bytes there, while quotes, escapes and every
 * substitution stay active, as Bash expands them inside a pattern. */
static void source_extglob_body_is_pattern_text(void) {
  static const char *const complete[] = {
      "echo @(a|#b)",
      "echo @(#b)",
      "echo !(a|#b)",
      "echo +(#b)",
      "echo ?(#b)",
      "echo *(#b)",
      "echo @(a|@(b|#c))",
      "echo a@(#b)c",
      "echo @(a # c)",
      "echo @(#)",
      "echo @(a|# ) x",
      "echo @(<<)",
      "echo @(a<<b)",
      "echo @(a<<<b)",
      "echo @(a<<-b)",
      "echo @(a<<EOF)",
      "echo @(a<<(x))",
      "echo @(<<(x) # y)",
      "echo $(echo @(a|#b))",
      "echo \"x\" @(#b) y",
      "x=@(#b)",
      "( echo @(#b) )",
      "{ echo @(#b); }",
      "echo @(#b) # trailing",
      "echo @(#b); echo @(a|#c)",
      "echo <(echo @(#b))",
      "echo @(a\n|#b)",
  };
  for (size_t c = 0; c < sizeof(complete) / sizeof(complete[0]); c++) {
    int status = shell_parse_draft(complete[c], strlen(complete[c]), NULL,
                                   &source_draft);
    if (status != SHELL_SOURCE_COMPLETE)
      fprintf(stderr, "expected COMPLETE (%d): %s\n", status, complete[c]);
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(shell_dep_graph_parse(complete[c], strlen(complete[c]), "/workspace",
                                &limits, &source_graph) == SHELL_DEP_OK);
  }
  /* A substitution inside the pattern is still a command the graph sees. */
  static const struct {
    const char *source;
    unsigned commands; /* the outer command plus every nested one */
  } nested[] = {
      {"echo @(a|#b)", 1},          {"echo @(a$(echo X)b)", 2},
      {"echo @(a`echo X`b)", 2},    {"echo @(a<(echo hi)b)", 2},
      {"echo @(a<<(x))", 2},        {"echo @(#b|$(echo X))", 2},
      {"echo @(a<<(echo hi)b)", 2},
  };
  for (size_t c = 0; c < sizeof(nested) / sizeof(nested[0]); c++) {
    CHECK(shell_dep_graph_parse(nested[c].source, strlen(nested[c].source),
                                "/workspace", &limits,
                                &source_graph) == SHELL_DEP_OK);
    unsigned commands = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++)
      commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
    if (commands != nested[c].commands)
      fprintf(stderr, "graph: %u command nodes, expected %u: %s\n", commands,
              nested[c].commands, nested[c].source);
    CHECK(commands == nested[c].commands);
  }
  /* Unterminated and over-closed patterns, and a comment inside a nested
   * substitution (Bash fails on it when run), are still not complete. */
  static const char *const rejected[] = {
      "echo @(a|b",
      "echo @(a))",
      "echo @(a|#b",
      "echo @(a|#b))",
      "echo @(a<<(x)",
      "echo @(#b",
      "echo @(",
      "echo @(a|# )x)",
      "echo @($(echo #x))",
      "echo @(a<<(echo #x)b)",
  };
  for (size_t c = 0; c < sizeof(rejected) / sizeof(rejected[0]); c++) {
    int status = shell_parse_draft(rejected[c], strlen(rejected[c]), NULL,
                                   &source_draft);
    if (status == SHELL_SOURCE_COMPLETE)
      fprintf(stderr, "expected not COMPLETE: %s\n", rejected[c]);
    CHECK(status != SHELL_SOURCE_COMPLETE);
  }
}

/* `$$` is the process-ID parameter, and the `{` after it is an ordinary byte:
 * `echo $${x;y}` runs `echo $${x` and then `y}`. Every scanner has to consume
 * the pair together; one that steps over the first `$` reads the second as the
 * opener of `${...}` and disagrees with the others about where words and
 * commands end. */
static void source_dollar_pair_does_not_open_a_parameter(void) {
  static const struct {
    const char *source;
    unsigned commands; /* command nodes the graph holds, nested ones included */
  } complete[] = {
      {"echo $${", 1},
      {"echo $${x..y}", 1},
      {"echo $${x}", 1},
      {"echo $${}", 1},
      {"echo $${}}", 1},
      {"echo $$\\${}", 1},
      {"echo \\${}", 1},
      {"echo $${x:-y}", 1},
      {"echo a$${", 1},
      {"echo $${ x", 1},
      {"echo $${#", 1},
      {"echo $${!", 1},
      {"x=$${", 1},
      {": >$${", 1},
      {": > $${x}", 1},
      {"cat <<< $${", 1},
      {"echo \"$${\"", 1},
      {"echo \"$${x}\"", 1},
      {"echo $$$${x}", 1},
      {"echo $$$${", 1},
      {"echo $$ ${x}", 1},
      {"echo $$\\${", 1},
      {"( echo $${ )", 1},
      {"echo $(echo $${)", 2},
      {"echo $${x;touch y}", 2},
      {"echo $${x|touch y}", 2},
      {"echo $${x&touch y}", 2},
      {"echo $$$${x;touch y}", 2},
      {"echo $${x:-a;b}", 2},
      {"echo $${x>f}", 1},
      {"echo $${x:-$(echo y)}", 2},
      {"echo $${x;b} | cat", 3},
      {"echo $${x:-a;b} | cat", 3},
      {"echo $$$${x:-a;b} | cat", 3},
      {": $${x;b} | cat", 3},
      {"echo $${x:-a;b} && echo z", 3},
      {"echo $${x:-a;b} & echo z", 3},
      /* An odd number of dollars ends in a real `${`. */
      {"echo $$${x}", 1},
      {"echo $$${x:-a;b} | cat", 2},
  };
  for (size_t c = 0; c < sizeof(complete) / sizeof(complete[0]); c++) {
    const char *source = complete[c].source;
    int status = shell_parse_draft(source, strlen(source), NULL, &source_draft);
    if (status != SHELL_SOURCE_COMPLETE)
      fprintf(stderr, "expected COMPLETE (%d): %s\n", status, source);
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                &source_graph) == SHELL_DEP_OK);
    unsigned commands = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++)
      commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
    if (commands != complete[c].commands)
      fprintf(stderr, "graph: %u command nodes, expected %u: %s\n", commands,
              complete[c].commands, source);
    CHECK(commands == complete[c].commands);
  }
  /* The dollars are a parameter and then real syntax, which Bash rejects. */
  static const char *const rejected[] = {
      "echo $$${",    "echo $$(",          "echo $$(echo x)",
      "echo $$((1))", "echo $$$$(echo x)", "echo \\${(touch y)}",
  };
  for (size_t c = 0; c < sizeof(rejected) / sizeof(rejected[0]); c++) {
    int status = shell_parse_draft(rejected[c], strlen(rejected[c]), NULL,
                                   &source_draft);
    if (status == SHELL_SOURCE_COMPLETE)
      fprintf(stderr, "expected not COMPLETE: %s\n", rejected[c]);
    CHECK(status != SHELL_SOURCE_COMPLETE);
  }
}

static void source_selector_recovery(void) {
  static const char *const selectors[] = {
      "${#value}",       "${!value}",       "${!prefix*}",   "${!prefix@}",
      "${value\\\n}",    "${#\\\nvalue}",   "${!\\\nvalue}", "${!prefix*\\\n}",
      "${!prefix@\\\n}", "${value[1]\\\n}",
  };
  static const char *const contexts[] = {"echo %s", "echo \"%s\"", "cat >%s",
                                         "cat <<EOF\n%s\nEOF\n"};
  char source[256], tail[192];
  for (size_t s = 0; s < sizeof(selectors) / sizeof(selectors[0]); s++) {
    for (size_t c = 0; c < sizeof(contexts) / sizeof(contexts[0]); c++) {
      int size = snprintf(tail, sizeof(tail), contexts[c], selectors[s]);
      CHECK(size > 0 && (size_t)size < sizeof(tail));
      size = snprintf(source, sizeof(source), "echo before; %s", tail);
      CHECK(size > 0 && (size_t)size < sizeof(source));
      for (size_t cut = 0; cut <= (size_t)size; cut++) {
        shell_source_status_t status =
            shell_parse_draft(source, cut, NULL, &source_draft);
        if (status != SHELL_SOURCE_COMPLETE &&
            status != SHELL_SOURCE_INCOMPLETE)
          fprintf(stderr, "selector cut %zu status %d: %.*s\n", cut, status,
                  (int)cut, source);
        CHECK(status == SHELL_SOURCE_COMPLETE ||
              status == SHELL_SOURCE_INCOMPLETE);
        if (status == SHELL_SOURCE_INCOMPLETE && cut >= strlen("echo before; "))
          CHECK(source_draft.prefix_length == strlen("echo before;"));
        if (source_draft.prefix_length) {
          shell_limits_t strict = SHELL_LIMITS_DEFAULT;
          strict.strict_mode = true;
          shell_parse_result_t fast;
          CHECK(shell_parse_fast(source, source_draft.prefix_length, &strict,
                                 &fast) == SHELL_OK);
          CHECK(shellsplit_test_parse_equal(&fast, &source_draft.prefix));
        }
      }
      CHECK(source_draft.prefix_length == (size_t)size);
    }
  }
  static const char *const malformed[] = {
      "echo before; echo ${name.other}", "echo before; echo ${#@.}",
      "echo before; echo ${!prefix*x}", "echo before; echo ${name!\\"};
  for (size_t c = 0; c < sizeof(malformed) / sizeof(malformed[0]); c++) {
    CHECK(shell_parse_draft(malformed[c], strlen(malformed[c]), NULL,
                            &source_draft) == SHELL_SOURCE_UNSUPPORTED);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  }
}

static void source_tentative_delimiters(void) {
  static const struct {
    const char *delimiter, *candidate, *suffix;
  } cases[] = {
      {"`日本`", "`日", "本`\n"},
      {"`x``y`", "`x`", "`y`\n"},
      {"`|`tail", "`|`", "tail\n"},
      {"`\"x y\"`tail", "`\"x y\"`", "tail\n"},
      {"`a\\b`tail", "`a\\b`", "tail\n"},
      {"`$'\\x00'`tail", "`$'\\x00'`", "tail\n"},
      {"EOF", "EO\\", "\nF\n"},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    char source[256];
    int size = snprintf(source, sizeof(source), "echo before; cat <<%s\n%s",
                        cases[c].delimiter, cases[c].candidate);
    CHECK(size > 0 && (size_t)size < sizeof(source));
    size_t received = (size_t)size;
    CHECK(shell_parse_draft(source, received, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.prefix_length == strlen("echo before;") &&
          source_draft.header_count == 2);
    CHECK(source_draft.heredoc_count == 1 &&
          source_draft.heredocs[0].delimiter_prefix);
    CHECK(!source_draft.heredocs[0].confirmed_length &&
          !source_draft.heredocs[0].complete);
    content(&source_draft.heredocs[0].content, cases[c].candidate);
    size_t added = strlen(cases[c].suffix);
    CHECK(received + added < sizeof(source));
    memcpy(source + received, cases[c].suffix, added + 1);
    shell_source_status_t status = SHELL_SOURCE_INVALID;
    for (size_t cut = strlen("echo before; "); cut <= received + added; cut++) {
      status = shell_parse_draft(source, cut, NULL, &source_draft);
      if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "delimiter cut %zu case %zu status %d\n", cut, c,
                status);
      CHECK(status == SHELL_SOURCE_COMPLETE ||
            status == SHELL_SOURCE_INCOMPLETE);
      if (status == SHELL_SOURCE_INCOMPLETE)
        CHECK(source_draft.prefix_length == strlen("echo before;"));
    }
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.header_count == 2 && source_draft.heredoc_count == 1 &&
          source_draft.heredocs[0].complete);
    CHECK(!(source_draft.heredocs[0].content.flags &
            SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL));
    content(&source_draft.heredocs[0].content, "");
    source_parse(source);
  }

  /* Actual outer quotes enable quote removal across the whole delimiter,
   * including otherwise-literal backtick interiors. ANSI-looking text inside
   * those interiors is still not an active ANSI-C quote. */
  static const char *const quoted[] = {
      "cat <<`\"x\"`'tail'\n$value\n`x`tail\n",
      "cat <<`$'\\x41'`'tail'\n$value\n`$\\x41`tail\n",
  };
  for (size_t c = 0; c < sizeof(quoted) / sizeof(quoted[0]); c++) {
    CHECK(shell_parse_draft(quoted[c], strlen(quoted[c]), NULL,
                            &source_draft) == SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.header_count == 1 && source_draft.heredoc_count == 1);
    CHECK(source_draft.heredocs[0].content.flags &
          SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL);
    content(&source_draft.heredocs[0].content, "$value\n");
    source_parse(quoted[c]);
  }

  /* A later mismatch makes the candidate real body data. Existing confirmed
   * children survive, and only then does a candidate's closed child appear. */
  char source[256] = "echo before; cat <<`x``y`\n$(printf good)\n`x`";
  size_t received = strlen(source);
  CHECK(shell_parse_draft(source, received, NULL, &source_draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.header_count == 3 &&
        source_draft.heredocs[0].delimiter_prefix);
  CHECK(source_draft.heredocs[0].confirmed_length ==
        strlen("$(printf good)\n"));
  memcpy(source + received, "z\n`x``y`\n", sizeof("z\n`x``y`\n"));
  CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(source_draft.header_count == 4 && source_draft.heredocs[0].complete);
  content(&source_draft.heredocs[0].content, "$(printf good)\n`x`z\n");
  static const struct {
    const char *source;
    shell_source_status_t status;
  } bad_code[] = {
      {"echo before; cat <<`日本`\n`$((日x\n", SHELL_SOURCE_UNSUPPORTED},
      {"echo before; cat <<`|`tail\n`|`z\n", SHELL_SOURCE_INVALID},
  };
  for (size_t c = 0; c < sizeof(bad_code) / sizeof(bad_code[0]); c++) {
    CHECK(shell_parse_draft(bad_code[c].source, strlen(bad_code[c].source),
                            NULL, &source_draft) == bad_code[c].status);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  }
}

static void source_recovery(void) {
  const char *source =
      "cat /workspace/before.txt\ncat <<EOF\ncat /workspace/body.txt\n";
  CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                              &source_graph) == SHELL_DEP_EPARSE);
  CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.prefix_length == strlen("cat /workspace/before.txt\n"));
  CHECK(source_draft.tail_start == source_draft.prefix_length &&
        source_draft.need == SHELL_SOURCE_NEEDS_HEREDOC_BODY);
  CHECK(source_draft.header_count == 2 && source_draft.heredoc_count == 1);
  CHECK(source_draft.headers[1].word_count == 1);
  CHECK(!source_draft.heredocs[0].complete &&
        source_draft.heredocs[0].header_complete);
  content(&source_draft.heredocs[0].content, "cat /workspace/body.txt\n");
  CHECK(shell_dep_graph_parse_with_fast(
            source, source_draft.prefix_length, "/workspace", &limits,
            &source_draft.prefix, &source_graph) == SHELL_DEP_OK);
  CHECK(shell_parse_draft("cat <<EOF\nalpha\nEO",
                          strlen("cat <<EOF\nalpha\nEO"), NULL,
                          &source_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.heredocs[0].delimiter_prefix &&
        source_draft.heredocs[0].confirmed_length == 6);
  CHECK(shell_parse_draft("cat > target <<'EOF'\nalpha\n",
                          strlen("cat > target <<'EOF'\nalpha\n"), NULL,
                          &source_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.headers[0].word_count == 1 &&
        source_draft.headers[0].redirect_count == 2);
  CHECK(source_draft.redirects[0].io.kind == SHELL_GROUP_IO_WRITE_FILE &&
        source_draft.redirects[0].next == 1);
  CHECK(source_draft.redirects[1].io.kind == SHELL_GROUP_IO_HEREDOC);
  static const char *unfinished[] = {
      "cat '",  "cat \"",     "cat $(echo", "cat ${value", "cat \\",
      "(cat",   "{ cat;",     "cat >",      "cat &&",      "cat |",
      "cat <<", "cat <<'EOF", "cat <<EOF"};
  for (size_t n = 0; n < sizeof(unfinished) / sizeof(unfinished[0]); n++) {
    int status = shell_parse_draft(unfinished[n], strlen(unfinished[n]), NULL,
                                   &source_draft);
    if (status != SHELL_SOURCE_INCOMPLETE)
      fprintf(stderr, "unfinished status %d: %s\n", status, unfinished[n]);
    CHECK(status == SHELL_SOURCE_INCOMPLETE && source_draft.prefix_length == 0);
  }
  static const struct {
    const char *source;
    shell_source_status_t status;
  } invalid[] = {
      {"cat >#comment", SHELL_SOURCE_INVALID},
      {"{ cat; } >#comment", SHELL_SOURCE_INVALID},
      {"cat && ;", SHELL_SOURCE_INVALID},
      {"cat >\nfile", SHELL_SOURCE_INVALID},
      {"cat )", SHELL_SOURCE_INVALID},
      {"cat | | echo", SHELL_SOURCE_INVALID},
      {"echo $((日本))", SHELL_SOURCE_UNSUPPORTED},
      {"cat <<EOF\n$(echo $((日本)))\nEOF\n", SHELL_SOURCE_UNSUPPORTED},
      {"({ echo; ) &&", SHELL_SOURCE_INVALID},
      {"echo $(echo &&) &&", SHELL_SOURCE_INVALID},
      {"echo ${bad!} &&", SHELL_SOURCE_UNSUPPORTED}};
  for (size_t n = 0; n < sizeof(invalid) / sizeof(invalid[0]); n++) {
    shell_source_status_t status = shell_parse_draft(
        invalid[n].source, strlen(invalid[n].source), NULL, &source_draft);
    if (status != invalid[n].status)
      fprintf(stderr, "invalid status %d: %s\n", status, invalid[n].source);
    CHECK(status == invalid[n].status && source_draft.prefix_length == 0);
  }
  CHECK(shell_parse_draft("", 0, NULL, &source_draft) ==
            SHELL_SOURCE_COMPLETE &&
        !source_draft.prefix_length);
  static const char whole[] =
      "echo before\n{ cat >target <<'EOF'; }\nalpha\nEOF\necho after";
  for (size_t cut = 0; cut <= sizeof(whole) - 1; cut++) {
    int status = shell_parse_draft(whole, cut, NULL, &source_draft);
    if (status == SHELL_SOURCE_COMPLETE || status == SHELL_SOURCE_INCOMPLETE) {
      CHECK(source_draft.prefix_length <= cut);
      if (source_draft.prefix_length) {
        shell_parse_result_t strict;
        shell_limits_t strict_limits = SHELL_LIMITS_DEFAULT;
        strict_limits.strict_mode = true;
        CHECK(shell_parse_fast(whole, source_draft.prefix_length,
                               &strict_limits, &strict) == SHELL_OK);
        CHECK(shellsplit_test_parse_equal(&strict, &source_draft.prefix));
      }
      for (uint32_t h = 0; h < source_draft.header_count; h++)
        for (uint32_t w = 0; w < source_draft.headers[h].word_count; w++)
          CHECK(source_draft.headers[h].words[w].start +
                    source_draft.headers[h].words[w].length <=
                cut);
    }
  }
}

/* `if` is a compound command: complete only at its `fi`, incomplete while a
 * list is missing, and invalid when a keyword is out of place. */
static void source_if_classification(void) {
  static const struct {
    const char *source;
    shell_source_status_t status;
  } cases[] = {
      {"if true; then :; fi ", SHELL_SOURCE_COMPLETE},
      {"echo before; if true; then :; else :; fi ", SHELL_SOURCE_COMPLETE},
      {"if a; then b; elif c; then d; else e; fi ", SHELL_SOURCE_COMPLETE},
      {"if a; then if b; then c; fi; fi ", SHELL_SOURCE_COMPLETE},
      {"! if a; then b; fi ", SHELL_SOURCE_COMPLETE},
      {"if a; then b; fi > out", SHELL_SOURCE_COMPLETE},
      {"if a; then b; fi | cat", SHELL_SOURCE_COMPLETE},
      {"echo if then elif else fi ", SHELL_SOURCE_COMPLETE},
      {"if true; then :; f", SHELL_SOURCE_INCOMPLETE},
      {"if true", SHELL_SOURCE_INCOMPLETE},
      {"if true; then", SHELL_SOURCE_INCOMPLETE},
      {"if true; then :", SHELL_SOURCE_INCOMPLETE},
      {"if true; then :; else", SHELL_SOURCE_INCOMPLETE},
      {"echo before; if ", SHELL_SOURCE_INCOMPLETE},
      {"if true; fi ", SHELL_SOURCE_INVALID},
      {"if ; then :; fi ", SHELL_SOURCE_INVALID},
      {"if true; then ; fi ", SHELL_SOURCE_INVALID},
      {"if true; then :; else :; else :; fi ", SHELL_SOURCE_INVALID},
      {"if true; then :; else :; elif a; then b; fi ", SHELL_SOURCE_INVALID},
      {"then :", SHELL_SOURCE_INVALID},
      {"fi ", SHELL_SOURCE_INVALID},
      {"echo before; fi ", SHELL_SOURCE_INVALID},
      {"{ if a; then b; }; fi ", SHELL_SOURCE_INVALID},
      {"if a; then b; fi; fi ", SHELL_SOURCE_INVALID},
      {"if a; then while b; do c; done; fi ", SHELL_SOURCE_UNSUPPORTED},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_source_status_t status = shell_parse_draft(
        cases[i].source, strlen(cases[i].source), NULL, &source_draft);
    if (status != cases[i].status)
      fprintf(stderr, "if classification: %s -> %d, want %d\n", cases[i].source,
              status, cases[i].status);
    CHECK(status == cases[i].status);
  }
}

static void source_keyword_recovery(void) {
  static const char *const words[] = {
      "if",     "then",   "else",     "elif", "fi",   "for",
      "while",  "until",  "do",       "done", "case", "esac",
      "select", "coproc", "function", "[[",   "in",   "]]"};
  static const struct {
    const char *opening, *closing;
  } contexts[] = {{"", ""},      {"{ ", "; }"},   {"( ", ")"},     {"! ", ""},
                  {"time ", ""}, {"true | ", ""}, {"true && ", ""}};
  char source[256];
  for (size_t w = 0; w < sizeof(words) / sizeof(words[0]); w++) {
    /* The `if` family is modeled: once complete, `if` opens a list and the
     * other four are structure or a syntax error, never unsupported. */
    bool family = !strcmp(words[w], "if") || !strcmp(words[w], "then") ||
                  !strcmp(words[w], "else") || !strcmp(words[w], "elif") ||
                  !strcmp(words[w], "fi");
    /* A `fi` ends a compound, so unlike a word that may still grow it is not
     * a pending tail: without an `if` around it, it is a syntax error. */
    bool settles = !strcmp(words[w], "fi");
    for (size_t c = 0; c < sizeof(contexts) / sizeof(contexts[0]) && !settles;
         c++) {
      for (unsigned continued = 0; continued < 2; continued++) {
        int length = snprintf(source, sizeof(source), "echo before; %s%s%s",
                              contexts[c].opening, words[w],
                              continued ? "\\\n\\\n" : "");
        CHECK(length > 0 && (size_t)length < sizeof(source));
        CHECK(shell_parse_draft(source, (size_t)length, NULL, &source_draft) ==
              SHELL_SOURCE_INCOMPLETE);
        CHECK(source_draft.need == SHELL_SOURCE_NEEDS_COMMAND);
        CHECK(source_draft.incomplete_at ==
              strlen("echo before; ") + strlen(contexts[c].opening));
        CHECK(source_draft.prefix_length == strlen("echo before;") &&
              source_draft.tail_start == source_draft.prefix_length &&
              source_draft.prefix.count == 1);
        CHECK(source_draft.header_count >= 2 &&
              source_draft.headers[0].complete &&
              !source_draft.headers[source_draft.header_count - 1].complete);
        CHECK(shell_dep_graph_parse(source, (size_t)length, "/workspace",
                                    &limits,
                                    &source_graph) == SHELL_DEP_EPARSE);
        /* EOF is not a word boundary. A suffix repairs exactly this tail,
         * including when physical continuations precede it. */
        snprintf(source + length, sizeof(source) - (size_t)length, "x%s",
                 contexts[c].closing);
        CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE);
      }
    }
    static const char *const boundaries[] = {" ", "\t", "\n", ";", ">"};
    for (size_t b = 0; b < sizeof(boundaries) / sizeof(boundaries[0]); b++) {
      snprintf(source, sizeof(source), "echo before; %s%s", words[w],
               boundaries[b]);
      if (!strcmp(words[w], "[[")) {
        CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
              (b < 3 ? SHELL_SOURCE_INCOMPLETE : SHELL_SOURCE_INVALID));
        if (b < 3) {
          CHECK(source_draft.need == SHELL_SOURCE_NEEDS_CONDITIONAL);
          CHECK(source_draft.prefix_length == strlen("echo before;"));
        } else
          CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
      } else if (!family) {
        CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
              SHELL_SOURCE_UNSUPPORTED);
        CHECK(!source_draft.prefix_length && !source_draft.tail_start &&
              !source_draft.prefix.count);
        for (uint32_t h = 0; h < source_draft.header_count; h++)
          CHECK(!source_draft.headers[h].complete);
      }
    }
    static const char *const closed[] = {"$(%s)", "<(%s)", ">(%s)", "`%s`"};
    for (size_t c = 0; c < sizeof(closed) / sizeof(closed[0]); c++) {
      char word[128];
      snprintf(word, sizeof(word), closed[c], words[w]);
      snprintf(source, sizeof(source), "echo before; echo %s", word);
      if (!family) {
        CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
              SHELL_SOURCE_UNSUPPORTED);
        CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
      }
      char suffixed[64];
      snprintf(suffixed, sizeof(suffixed), "%sx", words[w]);
      snprintf(word, sizeof(word), closed[c], suffixed);
      snprintf(source, sizeof(source), "echo before; echo %s", word);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(source_draft.header_count == 3 && source_draft.headers[2].complete);
    }
    snprintf(source, sizeof(source), "echo before; echo $(echo child; %s",
             words[w]);
    if (settles) {
      CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
            SHELL_SOURCE_INVALID);
    } else {
      CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.prefix_length == strlen("echo before;"));
      CHECK(source_draft.header_count == 4 &&
            source_draft.headers[0].complete &&
            !source_draft.headers[1].complete &&
            source_draft.headers[2].complete &&
            !source_draft.headers[3].complete);
    }
    static const char *const ordinary[] = {"echo %s", "cat >%s",   "'%s'",
                                           "%s\"\"",  "\\%s",      "%sx",
                                           "x=1 %s",  ">target %s"};
    for (size_t c = 0; c < sizeof(ordinary) / sizeof(ordinary[0]); c++) {
      snprintf(source, sizeof(source), ordinary[c], words[w]);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(source_draft.headers[0].complete &&
            source_draft.prefix_length == strlen(source));
      source_parse(source);
    }
  }
  static const char *const invalid[] = {"echo before; name() { :; }",
                                        "echo before; function name"};
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); c++) {
    CHECK(shell_parse_draft(invalid[c], strlen(invalid[c]), NULL,
                            &source_draft) == SHELL_SOURCE_UNSUPPORTED);
    CHECK(!source_draft.prefix_length);
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous_work = 0;
  for (size_t count = 64; count <= 512; count *= 2) {
    char continued[2048];
    size_t at = strlen("echo before; i");
    memcpy(continued, "echo before; i", at);
    for (size_t n = 0; n < count; n++) {
      memcpy(continued + at, "\\\n", 2);
      at += 2;
    }
    continued[at++] = 'f';
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(continued, at, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.prefix_length == strlen("echo before;") &&
          !source_draft.headers[1].complete);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work && (!previous_work || work <= 3 * previous_work));
    previous_work = work;
  }
#endif
}

static void source_backtick_escape_domains(void) {
  static const char *const invalid[] = {
      "echo before; echo `printf \\$value`",
      "echo before; echo `printf \\$value",
      "echo before; echo \"`printf \\\"x\\\"`\"",
      "echo before; echo \"`printf \\\"x",
      "echo before; echo `printf \\`x\\``",
      "echo before; echo `printf \\`x",
      "echo before; echo `printf \\\\`",
      "echo before; echo `printf \\\\",
      "echo before; echo `printf a\\\nb`",
      "echo before; echo `printf a\\\n",
      "echo before; cat <<EOF\n`printf \\$value\n",
  };
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); c++) {
    CHECK(shell_parse_draft(invalid[c], strlen(invalid[c]), NULL,
                            &source_draft) == SHELL_SOURCE_UNSUPPORTED);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
    for (uint32_t h = 0; h < source_draft.header_count; h++)
      CHECK(!source_draft.headers[h].complete);
  }
  static const char *const literal[] = {
      "echo \\`literal",
      "echo '`printf \\$value`'",
      "cat <<'EOF'\n`printf \\$value\nEOF\n",
      "cat <<EOF\n\\`literal\nEOF\n",
      /* Backslash-double-quote is not removed by an unquoted backtick. */
      "echo `printf \\\"x\\\"`",
  };
  for (size_t c = 0; c < sizeof(literal) / sizeof(literal[0]); c++)
    CHECK(shell_parse_draft(literal[c], strlen(literal[c]), NULL,
                            &source_draft) == SHELL_SOURCE_COMPLETE);

  /* Delimiter-only lookup must retain the quote-independent escape facts.
   * Shorter received views must not inherit escapes beyond their own EOF. */
  static const char indexed[] = "`printf \\\"x\\\"`";
  shell_source_operation_begin(indexed, sizeof(indexed) - 1);
  size_t after;
  CHECK(shell_source_scan_backtick(indexed, sizeof(indexed) - 1, 0, false,
                                   &after, NULL));
  CHECK(after == sizeof(indexed) - 1);
  bool sensitive = false;
  CHECK(shell_source_scan_backtick(indexed, sizeof(indexed) - 1, 0, true,
                                   &after, &sensitive));
  CHECK(sensitive);
  CHECK(shell_source_scan_backtick(indexed, sizeof(indexed) - 1, 0, false,
                                   &after, &sensitive));
  CHECK(!sensitive);
  CHECK(!shell_source_scan_backtick(indexed, 8, 0, true, &after, &sensitive));
  CHECK(!sensitive);
  CHECK(!shell_source_scan_backtick(indexed, 10, 0, true, &after, &sensitive));
  CHECK(sensitive);
  CHECK(!shell_source_scan_backtick(indexed, 10, 0, false, &after, &sensitive));
  CHECK(!sensitive);
  shell_source_operation_end();
}

typedef struct {
  size_t end, bytes;
  bool visited[256];
} source_code_regions_t;

static void source_ansi_byte_source(void) {
  static const struct {
    const char *source;
    unsigned commands, substitutions;
  } cases[] = {
      {"$'日本' argument", 1, 0},
      {"name=$'日本'", 1, 0},
      {"name=$'日本' printf ok", 1, 0},
      {"printf %s ${v:-$'日本'}", 1, 0},
      {"printf %s \"${v:-$'日本$(printf child)'}\"", 2, 1},
      {"printf %s $'日本$(printf phantom)`printf phantom`'", 1, 0},
      {"printf %s \"$(printf %s $'日本')\"", 2, 1},
      {"cat < <(printf %s $'日本')", 2, 1},
      {"printf %s `printf %s $'日本'`", 2, 1},
      {"cat <<< $'日本\\t語'", 1, 0},
      {"cat <<$'日本'\npayload\n日本\n", 1, 0},
      {"cat <<$'日\\444'\npayload\n日$\n", 1, 0},
      {"printf %s \"${v:-$'\\444'}\"", 1, 0},
      {"printf %s \"${v:-$'\\474'}\"", 1, 0},
      {"printf %s \"${v:-$'\\450'}\"", 1, 0},
      {"printf %s \"${v:-$\\\n'\\444'}\"", 1, 0},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.prefix_length == strlen(source));
    const char *child = strstr(source, "printf child");
    if (child) {
      CHECK(source_draft.header_count == 2 &&
            source_draft.headers[1].word_count == 2);
      CHECK(source_draft.headers[1].words[0].start ==
                (size_t)(child - source) &&
            source_draft.headers[1].words[0].length == strlen("printf"));
    }
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/workspace",
                                          &limits, &source_draft.prefix,
                                          &source_graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&source_graph).valid);
    source_parse(source);
    unsigned commands = 0, substitutions = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++)
      commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
    for (uint32_t e = 0; e < source_graph.edge_count; e++)
      substitutions += source_graph.edges[e].type == SHELL_EDGE_SUBST;
    if (commands != cases[c].commands ||
        substitutions != cases[c].substitutions)
      fprintf(stderr, "ANSI-C graph commands=%u substitutions=%u: %s\n",
              commands, substitutions, source);
    CHECK(commands == cases[c].commands &&
          substitutions == cases[c].substitutions);
  }
  static const char *const restricted[] = {
      "printf $(( $'日本' ))",
      "printf ${v:$'日本'}",
      "printf ${v[$'日本']}",
      "a[$'日本']=x",
  };
  for (size_t c = 0; c < sizeof(restricted) / sizeof(restricted[0]); c++) {
    CHECK(shell_parse_draft(restricted[c], strlen(restricted[c]), NULL,
                            &source_draft) == SHELL_SOURCE_UNSUPPORTED);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  }
  static const char *const unsupported[] = {
      "printf $'日本\\u65e5'",
      "printf $'日本\\c\\'\\u65e5'",
      "printf $'日本\\U000065e5'",
  };
  for (size_t c = 0; c < sizeof(unsupported) / sizeof(unsupported[0]); c++) {
    CHECK(shell_dep_graph_parse(unsupported[c], strlen(unsupported[c]),
                                "/workspace", &limits,
                                &source_graph) == SHELL_DEP_EPARSE);
    CHECK(!source_graph.node_count && !source_graph.edge_count);
  }
  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_encoded_cases) /
                             sizeof(shellsplit_test_ansi_encoded_cases[0]);
       ++c) {
    const char *source = shellsplit_test_ansi_encoded_cases[c].source;
    size_t length = strlen(source);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_UNSUPPORTED);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_EPARSE &&
          !fast.count);
    shell_processed_commands_t processed = {0};
    shell_process_status_t process_status =
        shell_process_commands(source, length, NULL, &processed);
    if (process_status != shellsplit_test_ansi_encoded_cases[c].process_status)
      fprintf(stderr, "ANSI encoded source process status=%d: %s\n",
              process_status, source);
    CHECK(process_status ==
          shellsplit_test_ansi_encoded_cases[c].process_status);
    CHECK(!processed.commands && !processed.command_count);
    shell_netstring_buffer_t commands = {0}, types = {0};
    size_t stages = 0;
    CHECK(shell_build_anomaly_netseqs_buffer(source, length, NULL, &commands,
                                             &types, &stages) ==
          shellsplit_test_ansi_encoded_cases[c].process_status);
    CHECK(!commands.data && !types.data && !stages);
    CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits,
                                &source_graph) == SHELL_DEP_EPARSE);
    CHECK(!source_graph.node_count && !source_graph.edge_count);
  }
  static const char *const received[] = {
      "printf before; printf $'日本\\t語'",
      "printf before; printf \"${v:-$'日本'}\"",
      "printf before; printf \"$(printf $'日本')\"",
      "printf before; cat <<$'日本'\npayload\n日本\n",
      "printf before; printf $'日本\\c\\\\'",
      "printf before; printf $'日本\\c\\'X'",
  };
  for (size_t c = 0; c < sizeof(received) / sizeof(received[0]); c++) {
    for (size_t cut = 0; cut <= strlen(received[c]); cut++) {
      shell_source_status_t status =
          shell_parse_draft(received[c], cut, NULL, &source_draft);
      if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "ANSI-C cut=%zu status=%d: %.*s\n", cut, status,
                (int)cut, received[c]);
      CHECK(status == SHELL_SOURCE_COMPLETE ||
            status == SHELL_SOURCE_INCOMPLETE);
      if (source_draft.prefix_length) {
        shell_parse_result_t fast;
        shell_limits_t strict = SHELL_LIMITS_DEFAULT;
        strict.strict_mode = true;
        CHECK(shell_parse_fast(received[c], source_draft.prefix_length, &strict,
                               &fast) == SHELL_OK);
        CHECK(shellsplit_test_parse_equal(&fast, &source_draft.prefix));
      }
    }
  }
  static const char unfinished[] = "printf before; printf $'日本\\'";
  CHECK(shell_parse_draft(unfinished, sizeof(unfinished) - 1, NULL,
                          &source_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.prefix_length == strlen("printf before;") &&
        source_draft.need == SHELL_SOURCE_NEEDS_QUOTE);
  static const char nul[] = "printf $'日本\0tail'";
  CHECK(shell_parse_draft(nul, sizeof(nul) - 1, NULL, &source_draft) ==
        SHELL_SOURCE_INVALID_INPUT);
}

static void source_ansi_nul_words(void) {
  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_nul_words) /
                             sizeof(shellsplit_test_ansi_nul_words[0]);
       ++c) {
    const char *word = shellsplit_test_ansi_nul_words[c].word;
    const char *value = shellsplit_test_ansi_nul_words[c].value;
    size_t expected = strlen(value), measured, written;
    char bytes[256], source[512], encoded[512];
    CHECK(shell_visit_static_word(word, strlen(word), NULL, NULL, &measured) &&
          measured == expected);
    CHECK(shell_measure_processed_word(word, strlen(word), &measured) ==
              SHELL_PROCESS_OK &&
          measured == expected);
    CHECK(shell_write_processed_word(word, strlen(word), bytes, expected,
                                     &written) == SHELL_PROCESS_OK &&
          written == expected && !memcmp(bytes, value, expected));
    if (expected) {
      CHECK(shell_process_write_word_value(word, strlen(word), bytes,
                                           expected - 1, &written) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            !written);
    }
    int length = snprintf(source, sizeof(source), "printf %%s %s", word);
    int size = snprintf(encoded, sizeof(encoded), "6:printf,2:%%s,%zu:%s,",
                        expected, value);
    CHECK(length > 0 && (size_t)length < sizeof(source) && size > 0 &&
          (size_t)size < sizeof(encoded));
    CHECK(shell_parse_draft(source, (size_t)length, NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE &&
          source_draft.header_count == 1);
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t argv = {0}, commands = {0}, types = {0};
    size_t count;
    CHECK(shell_process_commands(source, (size_t)length, NULL, &processed) ==
              SHELL_PROCESS_OK &&
          processed.command_count == 1);
    CHECK(shell_render_netargv_buffer(&processed.commands[0], NULL, &argv) ==
              SHELL_PROCESS_OK &&
          argv.length == (size_t)size &&
          !memcmp(argv.data, encoded, argv.length));
    CHECK(shell_build_anomaly_netseqs_buffer(source, (size_t)length, NULL,
                                             &commands, &types,
                                             &count) == SHELL_PROCESS_OK &&
          count == 1);
    shell_netstring_buffer_free(&commands);
    shell_netstring_buffer_free(&types);
    shell_netstring_buffer_free(&argv);
    shell_processed_commands_free(&processed);
    for (unsigned supplied = 0; supplied < 2; ++supplied) {
      CHECK((supplied ? shell_dep_graph_parse_with_fast(
                            source, (size_t)length, "/workspace", &limits,
                            &source_draft.prefix, &source_graph)
                      : shell_dep_graph_parse(source, (size_t)length,
                                              "/workspace", &limits,
                                              &source_graph)) == SHELL_DEP_OK);
      CHECK(shell_dep_graph_validate(&source_graph).valid);
      unsigned commands_seen = 0;
      for (uint32_t n = 0; n < source_graph.node_count; ++n)
        commands_seen += source_graph.nodes[n].type == SHELL_NODE_CMD;
      CHECK(commands_seen == 1);
      for (uint32_t e = 0; e < source_graph.edge_count; ++e)
        CHECK(source_graph.edges[e].type != SHELL_EDGE_SUBST);
    }
  }
  static const char *const unsupported[] = {
      "printf \"${v:-$'a\\0b'}\"",
      "printf \"${v:+$'a\\0b'}\"",
      "printf \"${v:-$'a\\0$(printf phantom)'}\"",
      "printf $'\\u65e5\\0tail'",
      "e$'val\\0ignored' 'printf bypass'",
      "export $'POSIXLY_CORRECT\\0ignored'=1",
  };
  for (size_t c = 0; c < sizeof(unsupported) / sizeof(unsupported[0]); ++c) {
    CHECK(shell_dep_graph_parse(unsupported[c], strlen(unsupported[c]),
                                "/workspace", &limits,
                                &source_graph) == SHELL_DEP_EPARSE &&
          !source_graph.node_count && !source_graph.edge_count);
  }
  static const char *const supported[] = {
      "printf ${v:-$'a\\0$(printf phantom)'}",
      "printf \"${v#$'a\\0b'}\"",
      "printf \"${v/$'a\\0b'/$'c\\0d'}\"",
      "printf $'a\\0$(printf phantom)'$(printf child)",
  };
  for (size_t c = 0; c < sizeof(supported) / sizeof(supported[0]); ++c) {
    source_parse(supported[c]);
    unsigned commands = 0;
    for (uint32_t n = 0; n < source_graph.node_count; ++n)
      commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
    CHECK(commands == (c == 3 ? 2u : 1u));
  }
  static const char received[] = "printf before; printf $'a\\0\\'tail'";
  for (size_t cut = 0; cut <= sizeof(received) - 1; ++cut) {
    shell_source_status_t status =
        shell_parse_draft(received, cut, NULL, &source_draft);
    CHECK(status == SHELL_SOURCE_COMPLETE || status == SHELL_SOURCE_INCOMPLETE);
    if (source_draft.prefix_length) {
      shell_parse_result_t fast;
      CHECK(shell_parse_fast(received, source_draft.prefix_length, NULL,
                             &fast) == SHELL_OK &&
            shellsplit_test_parse_equal(&fast, &source_draft.prefix));
    }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous[4] = {0};
  for (size_t count = 16; count <= 256; count *= 2) {
    char source[8192] = "printf $'head\\0";
    size_t length = strlen(source);
    for (size_t i = 0; i < count; ++i) {
      static const char discarded[] = "\\u65e5$(printf phantom)";
      memcpy(source + length, discarded, sizeof(discarded) - 1);
      length += sizeof(discarded) - 1;
    }
    memcpy(source + length, "'tail", 6);
    length += 5;
    for (unsigned operation = 0; operation < 4; ++operation) {
      shellsplit_test_source_scan_reset();
      if (operation == 0) {
        shell_parse_result_t fast;
        CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
      } else if (operation == 1) {
        CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
                  SHELL_SOURCE_COMPLETE &&
              source_draft.header_count == 1);
      } else if (operation == 2) {
        shell_processed_commands_t processed = {0};
        CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_OK);
        shell_processed_commands_free(&processed);
      } else {
        CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits,
                                    &source_graph) == SHELL_DEP_OK);
      }
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 256 * length + 4096 &&
            (!previous[operation] || work <= 2 * previous[operation] + 4096));
      previous[operation] = work;
    }
  }
#endif
}

static void source_nested_ansi_escape_context(void) {
  static const char *const supported_semantics[] = {
      "printf $'日本\\t語'",
      "echo \"${v:-$'$(echo \"\\$(printf child)\")'}\"",
  };
  for (size_t c = 0;
       c < sizeof(supported_semantics) / sizeof(supported_semantics[0]); ++c) {
    const char *source = supported_semantics[c];
    size_t length = strlen(source);
    CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
    CHECK(!source_inspected_unsupported_semantics(source, length));
  }
  static const char *const syntax_owned[] = {
      "echo \"unfinished",
      "echo )",
  };
  for (size_t c = 0; c < sizeof(syntax_owned) / sizeof(syntax_owned[0]); ++c) {
    const char *source = syntax_owned[c];
    size_t length = strlen(source);
    CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
    CHECK(!source_inspected_unsupported_semantics(source, length));
  }
  for (size_t c = 0;
       c < sizeof(shellsplit_test_ansi_translated_children) /
               sizeof(shellsplit_test_ansi_translated_children[0]);
       ++c) {
    const char *source = shellsplit_test_ansi_translated_children[c];
    size_t length = strlen(source);
    CHECK(shell_tokenizer_has_unsupported_semantics(source, length));
    CHECK(source_inspected_unsupported_semantics(source, length));
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
              SHELL_SOURCE_UNSUPPORTED &&
          !source_draft.prefix_length && !source_draft.prefix.count);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_EPARSE &&
          !processed.commands && !processed.command_count);
    for (unsigned supplied = 0; supplied < 2; ++supplied) {
      CHECK(
          (supplied
               ? shell_dep_graph_parse_with_fast(source, length, "/workspace",
                                                 &limits, &fast, &source_graph)
               : shell_dep_graph_parse(source, length, "/workspace", &limits,
                                       &source_graph)) == SHELL_DEP_EPARSE);
      CHECK(!source_graph.node_count && !source_graph.edge_count);
    }
  }
  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_translated_joins) /
                             sizeof(shellsplit_test_ansi_translated_joins[0]);
       ++c) {
    const char *source = shellsplit_test_ansi_translated_joins[c];
    size_t length = strlen(source);
    CHECK(shell_tokenizer_has_unsupported_semantics(source, length));
    CHECK(source_inspected_unsupported_semantics(source, length));
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
              SHELL_SOURCE_UNSUPPORTED &&
          !source_draft.prefix_length && !source_draft.prefix.count);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_EPARSE &&
          !processed.commands && !processed.command_count);
    for (unsigned supplied = 0; supplied < 2; ++supplied) {
      CHECK(
          (supplied
               ? shell_dep_graph_parse_with_fast(source, length, "/workspace",
                                                 &limits, &fast, &source_graph)
               : shell_dep_graph_parse(source, length, "/workspace", &limits,
                                       &source_graph)) == SHELL_DEP_EPARSE);
      CHECK(!source_graph.node_count && !source_graph.edge_count);
    }
  }
  {
    const char *source = "echo \"${0:+$'$'(printf child >&2)}\"";
    const char *open = strchr(source, '(');
    CHECK(open &&
          shell_parse_draft(source, (size_t)(open - source), NULL,
                            &source_draft) == SHELL_SOURCE_INCOMPLETE &&
          shell_parse_draft(source, (size_t)(open - source) + 1, NULL,
                            &source_draft) == SHELL_SOURCE_UNSUPPORTED &&
          !source_draft.prefix_length && !source_draft.prefix.count);
  }
  static const struct {
    const char *body;
    bool translated;
  } child_bodies[] = {
      {"", false},
      {"echo literal", false},
      {"echo \"\\$(printf child)\"", false},
      {"echo \"\\\\$(printf child)\"", true},
      {"echo \"\\\\\\$(printf child)\"", true},
      {"printf \\n", true},
      {"printf \\u65e5", true},
  };
  for (size_t c = 0; c < sizeof(child_bodies) / sizeof(child_bodies[0]); ++c)
    CHECK(shell_source_ansi_child_needs_translation(
              child_bodies[c].body, 0, strlen(child_bodies[c].body)) ==
          child_bodies[c].translated);

  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_nested_runs) /
                             sizeof(shellsplit_test_ansi_nested_runs[0]);
       ++c) {
    const char *source = shellsplit_test_ansi_nested_runs[c].source;
    unsigned expected = shellsplit_test_ansi_nested_runs[c].children;
    size_t length = strlen(source);
    bool heredoc = source[0] == 'c';
    const char *word = heredoc ? strchr(source, '\n') + 1 : source + 5;
    size_t word_length =
        heredoc ? (size_t)(strstr(word, "\nEOF") - word) : strlen(word);
    const char *opener = strstr(word, "$(printf child");
    size_t child_length = (size_t)(strchr(opener, ')') + 1 - opener);
    shell_source_substitution_scan_t scan = {0};
    scan.scope.heredoc = heredoc;
    scan.scope.suppress_process = heredoc;
    unsigned children = 0;
    size_t start, after;
    shell_source_substitution_kind_t kind;
    shell_source_scan_status_t status;
    while ((status = shell_source_next_word_expansion(word, word_length, &scan,
                                                      &start, &after, &kind)) ==
           SHELL_SOURCE_SCAN_FOUND) {
      CHECK(kind == SHELL_SOURCE_SUBST_COMMAND && scan.scope.conditional &&
            scan.scope.guard_start && scan.scope.guard_parent &&
            start == (size_t)(opener - word) && after == start + child_length);
      children++;
    }
    CHECK(status == SHELL_SOURCE_SCAN_DONE && !scan.scope_count &&
          !scan.has_ansi_nul && children == expected);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE &&
          source_draft.prefix_length == length &&
          source_draft.header_count == 1 + expected);
    if (expected)
      CHECK(source_draft.headers[1].words[0].start ==
            (size_t)(strstr(source, "printf child") - source));
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    shell_processed_commands_free(&processed);
    for (unsigned supplied = 0; supplied < 2; ++supplied) {
      CHECK((supplied
                 ? shell_dep_graph_parse_with_fast(
                       source, length, "/workspace", &limits,
                       &source_draft.prefix, &source_graph)
                 : shell_dep_graph_parse(source, length, "/workspace", &limits,
                                         &source_graph)) == SHELL_DEP_OK);
      CHECK(shell_dep_graph_validate(&source_graph).valid);
      uint32_t outer = UINT32_MAX, child = UINT32_MAX, document = UINT32_MAX;
      unsigned commands = 0;
      for (uint32_t n = 0; n < source_graph.node_count; ++n) {
        const shell_dep_node_t *node = &source_graph.nodes[n];
        if (node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_HEREDOC)
          document = n;
        if (node->type != SHELL_NODE_CMD)
          continue;
        commands++;
        if (node->cmd.tokens[0] == source)
          outer = n;
        else {
          CHECK(node->cmd.tokens[0] == strstr(source, "printf child") &&
                node->cmd.token_count == 2 && node->cmd.token_lens[0] == 6 &&
                node->cmd.token_lens[1] == 5);
          child = n;
        }
      }
      CHECK(commands == 1 + expected && outer != UINT32_MAX &&
            (child != UINT32_MAX) == (expected != 0));
      bool captured = false, stderr_route = false, stdout_route = false;
      for (uint32_t e = 0; e < source_graph.edge_count; ++e) {
        const shell_dep_edge_t *edge = &source_graph.edges[e];
        captured |= edge->type == SHELL_EDGE_SUBST && edge->from == child &&
                    edge->to == (heredoc ? document : outer) &&
                    edge->source_fd == 1 &&
                    edge->flags == SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD;
        if (edge->type == SHELL_EDGE_WRITE && edge->from == child &&
            (edge->source_fd == 1 || edge->source_fd == 2)) {
          const shell_dep_node_t *target = &source_graph.nodes[edge->to];
          bool to_stderr =
              target->type == SHELL_NODE_FD && target->fd.number == 2;
          stderr_route |= edge->source_fd == 2 && to_stderr;
          stdout_route |= edge->source_fd == 1 && to_stderr;
        }
      }
      CHECK(captured ==
                (expected &&
                 !shellsplit_test_ansi_nested_runs[c].stdout_to_stderr) &&
            stdout_route ==
                (expected &&
                 shellsplit_test_ansi_nested_runs[c].stdout_to_stderr) &&
            stderr_route == (expected != 0));
    }
  }

  /* Three slashes expose the first child after ANSI decoding. Outside that
   * fragment two slashes expose the next child using ordinary shell rules.
   * Exercise restoration both within the parameter and after its close. */
  static const char *const restored[] = {
      "echo \"${v:-$'${w:-\\\\\\$(printf before)}'\\\\$(printf after)}\"",
      ("cat <<EOF\n${v#${u:-$'${w:-\\\\\\$(printf before)}\\0tail'"
       "\\\\$(printf after)}}\nEOF\n"),
      "echo \"${v#${u:-$'${w:-\\\\\\$(printf before)}'}}\" \\\\$(printf after)",
      "cat <<EOF\n${0#${0:+${0#$'$(printf before)'}}}$(printf after)\nEOF\n",
      "echo \"${0#${0:+$'<(printf before)'}}\" $(printf after)",
  };
  for (size_t c = 0; c < sizeof(restored) / sizeof(restored[0]); ++c) {
    const char *source = restored[c];
    size_t length = strlen(source);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE &&
          source_draft.header_count == 3);
    CHECK(source_draft.headers[1].words[0].start ==
              (size_t)(strstr(source, "printf before") - source) &&
          source_draft.headers[2].words[0].start ==
              (size_t)(strstr(source, "printf after") - source));
    for (unsigned supplied = 0; supplied < 2; ++supplied) {
      CHECK((supplied
                 ? shell_dep_graph_parse_with_fast(
                       source, length, "/workspace", &limits,
                       &source_draft.prefix, &source_graph)
                 : shell_dep_graph_parse(source, length, "/workspace", &limits,
                                         &source_graph)) == SHELL_DEP_OK);
      unsigned commands = 0;
      for (uint32_t n = 0; n < source_graph.node_count; ++n)
        commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
      CHECK(commands == 3 && shell_dep_graph_validate(&source_graph).valid);
    }
  }

  /* One unknown escape survives ANSI decoding unchanged. The child's own
   * double quote still protects its literal dollar: no grandchild exists. */
  static const char *const unchanged_children[] = {
      "echo \"${v:-$'$(echo \"\\$(printf child)\")'}\"",
      "cat <<EOF\n${v#${u:-$'$(echo \"\\$(printf child)\")\\0tail'}}\nEOF\n",
  };
  for (size_t c = 0;
       c < sizeof(unchanged_children) / sizeof(unchanged_children[0]); ++c) {
    const char *source = unchanged_children[c];
    size_t length = strlen(source);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE &&
          source_draft.header_count == 2);
    for (unsigned supplied = 0; supplied < 2; ++supplied) {
      CHECK((supplied
                 ? shell_dep_graph_parse_with_fast(
                       source, length, "/workspace", &limits,
                       &source_draft.prefix, &source_graph)
                 : shell_dep_graph_parse(source, length, "/workspace", &limits,
                                         &source_graph)) == SHELL_DEP_OK);
      unsigned commands = 0;
      for (uint32_t n = 0; n < source_graph.node_count; ++n) {
        const shell_dep_node_t *node = &source_graph.nodes[n];
        if (node->type == SHELL_NODE_CMD) {
          commands++;
          CHECK(node->cmd.tokens[0] == source ||
                node->cmd.tokens[0] == strstr(source, "$(echo") + 2);
        }
      }
      CHECK(commands == 2 && shell_dep_graph_validate(&source_graph).valid);
    }
  }

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* An outer ANSI-C pass checks its first-level child body once, including
   * all nested commands. It must not repeat that walk for each descendant. */
  for (unsigned form = 0; form < 4; ++form) {
    size_t previous = 0;
    bool heredoc = form >= 2, translated = (form & 1u) != 0;
    for (size_t depth = 4; depth <= 32; depth *= 2) {
      char word[4096];
      strcpy(word, heredoc ? "${v#${u:-$'" : "\"${v:-$'");
      size_t length = strlen(word), child_start = length;
      for (size_t d = 0; d < depth; ++d) {
        memcpy(word + length, "$(echo ", 7);
        length += 7;
      }
      memset(word + length, 'x', depth * 32);
      length += depth * 32;
      if (translated) {
        const char *literal = "\"\\\\$(printf child)\"";
        memcpy(word + length, literal, strlen(literal));
        length += strlen(literal);
      }
      memset(word + length, ')', depth);
      length += depth;
      size_t child_after = length;
      strcpy(word + length, heredoc ? "\\0tail'}}" : "'}\"");
      length += strlen(word + length);
      shell_source_substitution_scan_t scan = {0};
      scan.scope.heredoc = heredoc;
      scan.scope.suppress_process = heredoc;
      size_t start, after;
      shell_source_substitution_kind_t kind;
      shellsplit_test_source_scan_reset();
      shell_source_scan_status_t status = shell_source_next_word_expansion(
          word, length, &scan, &start, &after, &kind);
      if (translated) {
        CHECK(status == SHELL_SOURCE_SCAN_UNSUPPORTED && !scan.has_ansi_nul);
      } else {
        CHECK(status == SHELL_SOURCE_SCAN_FOUND &&
              kind == SHELL_SOURCE_SUBST_COMMAND && start == child_start &&
              after == child_after);
        CHECK(shell_source_next_word_expansion(word, length, &scan, &start,
                                               &after, &kind) ==
              SHELL_SOURCE_SCAN_DONE);
      }
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 32 * length + 512 &&
            (!previous || work <= 2 * previous + 1024));
      previous = work;
    }
  }
#endif
}

static void source_parameter_word_phases(void) {
  shell_dep_graph_t *ordinary = malloc(sizeof(*ordinary));
  CHECK(ordinary);
  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_phase_cases) /
                             sizeof(shellsplit_test_ansi_phase_cases[0]);
       ++c) {
    const char *source = shellsplit_test_ansi_phase_cases[c].source;
    unsigned expected = shellsplit_test_ansi_phase_cases[c].children;
    char opener = shellsplit_test_ansi_phase_cases[c].kind;
    bool heredoc = source[0] == 'c';
    const char *word = heredoc ? strchr(source, '\n') + 1 : source + 5;
    size_t length = strlen(source);
    size_t word_length =
        heredoc ? (size_t)(strstr(word, "\nEOF") - word) : strlen(word);
    const char *body = strstr(source, "printf child");
    const char *closing = strchr(body, opener == '`' ? '`' : ')');
    shell_source_substitution_kind_t expected_kind =
        opener == '$'   ? SHELL_SOURCE_SUBST_COMMAND
        : opener == '`' ? SHELL_SOURCE_SUBST_BACKTICK
        : opener == '<' ? SHELL_SOURCE_SUBST_PROCESS_INPUT
                        : SHELL_SOURCE_SUBST_PROCESS_OUTPUT;
    shell_source_substitution_scan_t scan = {
        .scope = {.heredoc = heredoc, .suppress_process = heredoc}};
    size_t start, after;
    shell_source_substitution_kind_t kind;
    shell_source_scan_status_t status;
    unsigned children = 0;
    while ((status = shell_source_next_word_expansion(word, word_length, &scan,
                                                      &start, &after, &kind)) ==
           SHELL_SOURCE_SCAN_FOUND) {
      CHECK(kind == expected_kind && scan.scope.conditional &&
            scan.scope.guard_start &&
            word + start == body - (opener == '`' ? 1 : 2) &&
            word + after == closing + 1);
      children++;
    }
    if (status != SHELL_SOURCE_SCAN_DONE || scan.scope_count ||
        scan.has_ansi_nul || children != expected)
      fprintf(stderr, "parameter phase case %zu: status=%d children=%u: %s\n",
              c, status, children, source);
    CHECK(status == SHELL_SOURCE_SCAN_DONE && !scan.scope_count &&
          !scan.has_ansi_nul && children == expected);
    CHECK(!shell_tokenizer_has_unsupported_semantics(source, length) &&
          !source_inspected_unsupported_semantics(source, length));
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE &&
          source_draft.prefix_length == length &&
          source_draft.header_count == 1 + expected);
    uint32_t features = 0;
    for (uint32_t r = 0; r < source_draft.prefix.count; ++r)
      features |= source_draft.prefix.cmds[r].features;
    CHECK(((features & SHELL_FEAT_SUBSHELL) != 0) ==
              (expected && (opener == '$' || opener == '`')) &&
          ((features & SHELL_FEAT_PROCESS_SUB) != 0) ==
              (expected && (opener == '<' || opener == '>')));
    if (expected)
      CHECK(source_draft.headers[1].words[0].start == (size_t)(body - source) &&
            source_draft.headers[1].words[0].length == 6);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_OK &&
          processed.command_count == 1);
    shell_processed_commands_free(&processed);
    CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits,
                                ordinary) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          &source_draft.prefix,
                                          &source_graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(ordinary, &source_graph) &&
          shell_dep_graph_validate(&source_graph).valid);
    unsigned commands = 0;
    uint32_t child = UINT32_MAX;
    for (uint32_t n = 0; n < source_graph.node_count; ++n) {
      const shell_dep_node_t *node = &source_graph.nodes[n];
      if (node->type == SHELL_NODE_CMD) {
        commands++;
        if (node->cmd.tokens[0] == body) {
          child = n;
          CHECK(node->cmd.token_count == 2 && node->cmd.token_lens[0] == 6 &&
                node->cmd.token_lens[1] == 5 &&
                node->cmd.tokens[1] == body + 7);
        }
      }
    }
    CHECK(commands == 1 + expected && (child != UINT32_MAX) == (expected != 0));
    bool captured = false, stderr_route = false;
    for (uint32_t e = 0; e < source_graph.edge_count; ++e) {
      const shell_dep_edge_t *edge = &source_graph.edges[e];
      if (edge->from != child)
        continue;
      if (edge->type == SHELL_EDGE_SUBST) {
        captured = true;
        const shell_dep_node_t *target = &source_graph.nodes[edge->to];
        CHECK(edge->source_fd == 1 &&
              edge->flags ==
                  (opener == '<' ? 0 : SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD));
        CHECK(heredoc ? target->type == SHELL_NODE_DOC &&
                            target->doc.kind == SHELL_DOC_HEREDOC
                      : target->type == SHELL_NODE_CMD &&
                            target->cmd.tokens[0] == source);
      }
      if (edge->type == SHELL_EDGE_WRITE && edge->source_fd == 2) {
        const shell_dep_node_t *target = &source_graph.nodes[edge->to];
        stderr_route |= target->type == SHELL_NODE_FD && target->fd.number == 2;
      }
    }
    CHECK(captured == shellsplit_test_ansi_phase_cases[c].captured_stdout &&
          stderr_route == (expected != 0));
  }
  free(ordinary);
  static const char *const received[] = {
      "echo before; cat <<EOF\n${0#${0:+${0#$'$(printf child)'}}}\nEOF\n",
      ("echo before; cat <<EOF\n${0#${0:+${0#$'$(printf "
       "child)\\0tail'}}}\nEOF\n"),
      "echo before; echo \"${0#${0:+$'<(printf child)'}}\"",
      "echo before; echo \"${0#${0:+$'$'\"\"(printf child >&2)}}\"",
      "echo before; cat <<EOF\n${0#\"${0:+${0#$'$(printf child "
      ">&2)'}}\"}\nEOF\n",
      "echo before; cat <<EOF\n${0:+${0#${0:+$'$(printf child "
      ">&2)'}}}\nEOF\n",
      "echo before; cat <<EOF\n${0:+\"${0#${0:+$'$(printf child "
      ">&2)'}}\"}\nEOF\n",
      "echo before; cat <<EOF\n${0:+\"${0#\"${0:+$'$(printf child "
      ">&2)'}\"}\"}\nEOF\n",
      ("echo before; cat <<EOF\n${0:+\"${0#${0:+$'$(printf literal "
       ">&2)'}}\"}${0#${0:+${0#$'$(printf child >&2)'}}}\nEOF\n"),
      ("echo before; cat <<EOF\n${0:+${0#${0:+$'$(printf literal "
       ">&2)'}}}${0#${0:+${0#$'$(printf child >&2)'}}}\nEOF\n"),
  };
  for (size_t c = 0; c < sizeof(received) / sizeof(received[0]); ++c) {
    for (size_t cut = 0; cut <= strlen(received[c]); ++cut) {
      shell_source_status_t status =
          shell_parse_draft(received[c], cut, NULL, &source_draft);
      CHECK(status == SHELL_SOURCE_COMPLETE ||
            status == SHELL_SOURCE_INCOMPLETE);
      if (source_draft.prefix_length) {
        shell_parse_result_t fast;
        CHECK(shell_parse_fast(received[c], source_draft.prefix_length, NULL,
                               &fast) == SHELL_OK &&
              shellsplit_test_parse_equal(&fast, &source_draft.prefix));
      }
    }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* The reset at each heredoc pattern must use the saved local phase rather
   * than search increasingly deep ancestors for a preceding explicit quote. */
  {
    size_t previous = 0;
    for (size_t depth = 4; depth * 2 + 1 <= SHELL_MAX_SUBCOMMANDS; depth *= 2) {
      char word[4096];
      strcpy(word, "${0:+\"");
      size_t length = strlen(word);
      for (size_t d = 0; d < depth; ++d) {
        memcpy(word + length, "${0#${0:+", 9);
        length += 9;
      }
      const char *literal = "$'$(printf child >&2)\\0tail'";
      memcpy(word + length, literal, strlen(literal));
      length += strlen(literal);
      for (size_t d = 0; d < depth; ++d) {
        memcpy(word + length, "}}", 2);
        length += 2;
      }
      memcpy(word + length, "\"}", 2);
      length += 2;
      shell_source_substitution_scan_t scan = {
          .scope = {.heredoc = true, .suppress_process = true}};
      size_t start, after;
      shell_source_substitution_kind_t kind;
      shellsplit_test_source_scan_reset();
      CHECK(shell_source_next_word_expansion(word, length, &scan, &start,
                                             &after,
                                             &kind) == SHELL_SOURCE_SCAN_DONE &&
            !scan.scope_count && !scan.has_ansi_nul);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 64 * length + 1024 &&
            (!previous || work <= 2 * previous + 1024));
      previous = work;
    }
  }
  /* Grow both nested phase transitions and escaped opener runs. Stack saved
   * phase state must not require an ancestor search or a suffix reparse. */
  for (unsigned form = 0; form < 4; ++form) {
    size_t previous = 0;
    for (size_t depth = 4; depth * 2 + 1 <= SHELL_MAX_SUBCOMMANDS; depth *= 2) {
      char word[4096];
      size_t length = 0;
      for (size_t d = 0; d < depth; ++d) {
        memcpy(word + length, "${0#${0:+", 9);
        length += 9;
      }
      const char *pattern = "${0#$'";
      memcpy(word + length, pattern, strlen(pattern));
      length += strlen(pattern);
      memset(word + length, '\\', depth * 4 + (form & 1u ? 2 : 3));
      length += depth * 4 + (form & 1u ? 2 : 3);
      size_t child = length;
      const char *command =
          form >= 2 ? "<(printf child >&2)" : "$(printf child >&2)";
      memcpy(word + length, command, strlen(command));
      length += strlen(command);
      size_t child_after = length;
      memcpy(word + length, "\\0tail'}", 8);
      length += 8;
      for (size_t d = 0; d < depth; ++d) {
        memcpy(word + length, "}}", 2);
        length += 2;
      }
      shell_source_substitution_scan_t scan = {
          .scope = {.heredoc = true, .suppress_process = true}};
      size_t start, after;
      shell_source_substitution_kind_t kind;
      shellsplit_test_source_scan_reset();
      shell_source_scan_status_t status = shell_source_next_word_expansion(
          word, length, &scan, &start, &after, &kind);
      if (!(form & 1u)) {
        CHECK(status == SHELL_SOURCE_SCAN_FOUND && start == child &&
              after == child_after &&
              kind == (form >= 2 ? SHELL_SOURCE_SUBST_PROCESS_INPUT
                                 : SHELL_SOURCE_SUBST_COMMAND));
        status = shell_source_next_word_expansion(word, length, &scan, &start,
                                                  &after, &kind);
      }
      CHECK(status == SHELL_SOURCE_SCAN_DONE && !scan.has_ansi_nul &&
            !scan.scope_count);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 64 * length + 1024 &&
            (!previous || work <= 2 * previous + 1024));
      previous = work;
    }
  }
  /* Harmless escapes and quoted process-looking text must not trigger a
   * child-body rescan for each surrounding byte. Repeated quotes restore the
   * context of the one real child. Framing and semantic consumers stay linear.
   */
  for (unsigned form = 0; form < 8; ++form) {
    size_t previous[4] = {0};
    bool heredoc = (form & 2u) != 0;
    for (size_t count = 16; count <= 256; count *= 2) {
      char source[16384];
      const char *prefix =
          heredoc ? "cat <<EOF\n${0#${0:+${0#$'" : "echo \"${0#${0:+$'";
      size_t length = strlen(prefix);
      memcpy(source, prefix, length);
      for (unsigned side = 0; side < 2; ++side) {
        for (size_t i = 0; i < count; ++i) {
          const char *data =
              form & 4u ? "\"<(literal)>(literal)\"" : "\\n\\t\\x61";
          memcpy(source + length, data, strlen(data));
          length += strlen(data);
        }
        if (!side) {
          const char *child =
              form & 1u ? "`printf child >&2`" : "$(printf child >&2)";
          memcpy(source + length, child, strlen(child));
          length += strlen(child);
        }
      }
      const char *suffix = heredoc ? "\\0tail'}}}\nEOF\n" : "'}}\"";
      memcpy(source + length, suffix, strlen(suffix));
      length += strlen(suffix);
      for (unsigned operation = 0; operation < 4; ++operation) {
        shellsplit_test_source_scan_reset();
        if (operation == 0) {
          shell_parse_result_t fast;
          CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
        } else if (operation == 1) {
          CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
                    SHELL_SOURCE_COMPLETE &&
                source_draft.header_count == 2);
        } else if (operation == 2) {
          shell_processed_commands_t processed = {0};
          CHECK(shell_process_commands(source, length, NULL, &processed) ==
                SHELL_PROCESS_OK);
          shell_processed_commands_free(&processed);
        } else {
          CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits,
                                      &source_graph) == SHELL_DEP_OK);
        }
        size_t work = shellsplit_test_source_scan_work();
        CHECK(work <= 128 * length + 4096 &&
              (!previous[operation] || work <= 2 * previous[operation] + 4096));
        previous[operation] = work;
      }
    }
  }
  /* Empty quote chains are transparent only in shell double-quoted defaults.
   * Ordinary-word and heredoc boundaries stay literal with the same linear
   * traversal, including quote pairs containing only a continuation. */
  for (unsigned form = 0; form < 4; ++form) {
    const char *source_prefixes[] = {"echo \"${0:+$'$'", "echo \"${0#${0:+$'$'",
                                     "cat <<EOF\n${0#${0:+$'$'",
                                     "cat <<EOF\n${0#\"${0:+$'$'"};
    const char *suffixes[] = {"(printf child >&2)}\"", "(printf child >&2)}}\"",
                              "(printf child >&2)}}\nEOF\n",
                              "(printf child >&2)}\"}\nEOF\n"};
    size_t previous[4] = {0};
    for (size_t count = 16; count <= 256; count *= 2) {
      char source[8192];
      size_t length = strlen(source_prefixes[form]);
      memcpy(source, source_prefixes[form], length);
      for (size_t i = 0; i < count; ++i) {
        const char *pair = i & 1u ? "\"\"" : "\"\\\n\"";
        memcpy(source + length, pair, strlen(pair));
        length += strlen(pair);
      }
      memcpy(source + length, suffixes[form], strlen(suffixes[form]));
      length += strlen(suffixes[form]);
      for (unsigned operation = 0; operation < 4; ++operation) {
        shellsplit_test_source_scan_reset();
        if (operation == 0) {
          shell_parse_result_t fast;
          CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
        } else if (operation == 1) {
          CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
                    (form ? SHELL_SOURCE_COMPLETE : SHELL_SOURCE_UNSUPPORTED) &&
                source_draft.header_count == 1 &&
                (form ? source_draft.prefix_length == length
                      : !source_draft.prefix_length &&
                            !source_draft.prefix.count));
        } else if (operation == 2) {
          shell_processed_commands_t processed = {0};
          CHECK(shell_process_commands(source, length, NULL, &processed) ==
                    (form ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE) &&
                (form ? processed.command_count == 1
                      : !processed.commands && !processed.command_count));
          shell_processed_commands_free(&processed);
        } else {
          CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits,
                                      &source_graph) ==
                (form ? SHELL_DEP_OK : SHELL_DEP_EPARSE));
          if (form) {
            unsigned commands = 0;
            for (uint32_t n = 0; n < source_graph.node_count; ++n)
              commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
            CHECK(commands == 1 &&
                  shell_dep_graph_validate(&source_graph).valid);
          } else {
            CHECK(!source_graph.node_count && !source_graph.edge_count);
          }
        }
        size_t work = shellsplit_test_source_scan_work();
        CHECK(work <= 128 * length + 4096 &&
              (!previous[operation] || work <= 2 * previous[operation] + 4096));
        previous[operation] = work;
      }
    }
  }
  /* Quoted heredoc patterns and their unquoted siblings restore phase state
   * at each scope pop. A wider word must not trigger ancestor searches. */
  {
    size_t previous = 0;
    for (size_t count = 16; count <= 128; count *= 2) {
      char word[16384];
      size_t length = 0;
      for (size_t i = 0; i < count; ++i) {
        const char *operand =
            i & 1u ? "${0#${0:+${0#$'$(printf child >&2)'}}}"
                   : "${0#\"${0:+${0#$'$(printf literal >&2)'}}\"}";
        memcpy(word + length, operand, strlen(operand));
        length += strlen(operand);
      }
      shell_source_substitution_scan_t scan = {
          .scope = {.heredoc = true, .suppress_process = true}};
      size_t start, after;
      unsigned children = 0;
      shell_source_substitution_kind_t kind;
      shell_source_scan_status_t status;
      shellsplit_test_source_scan_reset();
      while ((status = shell_source_next_word_expansion(
                  word, length, &scan, &start, &after, &kind)) ==
             SHELL_SOURCE_SCAN_FOUND) {
        CHECK(kind == SHELL_SOURCE_SUBST_COMMAND &&
              after - start == strlen("$(printf child >&2)") &&
              !memcmp(word + start, "$(printf child >&2)", after - start));
        children++;
      }
      CHECK(status == SHELL_SOURCE_SCAN_DONE && !scan.scope_count &&
            children == count / 2);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 64 * length + 1024 &&
            (!previous || work <= 2 * previous + 1024));
      previous = work;
    }
  }
  /* A heredoc word followed by a pattern establishes a literal subtree.
   * Growing later word/pattern pairs must neither reactivate the child nor
   * search the ancestor stack to rediscover the original heredoc. */
  {
    size_t previous = 0;
    for (size_t depth = 2; depth * 2 + 2 <= SHELL_MAX_SUBCOMMANDS; depth *= 2) {
      char word[8192];
      size_t length = 0;
      memcpy(word + length, "${0:+", 5);
      length += 5;
      for (size_t d = 0; d < depth; ++d) {
        memcpy(word + length, "${0#${0:+", 9);
        length += 9;
      }
      const char *literal = "$'$(printf child >&2)\\0tail'";
      memcpy(word + length, literal, strlen(literal));
      length += strlen(literal);
      for (size_t d = 0; d < depth; ++d) {
        memcpy(word + length, "}}", 2);
        length += 2;
      }
      word[length++] = '}';
      shell_source_substitution_scan_t scan = {
          .scope = {.heredoc = true, .suppress_process = true}};
      size_t start, after;
      shell_source_substitution_kind_t kind;
      shellsplit_test_source_scan_reset();
      CHECK(shell_source_next_word_expansion(word, length, &scan, &start,
                                             &after,
                                             &kind) == SHELL_SOURCE_SCAN_DONE &&
            !scan.scope_count && !scan.has_ansi_nul);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 64 * length + 1024 &&
            (!previous || work <= 2 * previous + 1024));
      previous = work;
    }
  }
  /* Empty translated fragments preserve the preceding effective byte. Growing
   * a chain must remain a forward walk, including fragment-local NUL tails. */
  for (unsigned nul = 0; nul < 2; ++nul) {
    size_t previous[4] = {0};
    for (size_t count = 16; count <= 256; count *= 2) {
      char source[8192];
      const char *prefix =
          nul ? "cat <<EOF\n${0#${0:+$'$'" : "echo \"${0:+$'$'";
      size_t length = strlen(prefix);
      memcpy(source, prefix, length);
      const char *empty = nul ? "$'\\0tail'" : "$''";
      for (size_t i = 0; i < count; ++i) {
        memcpy(source + length, empty, strlen(empty));
        length += strlen(empty);
      }
      const char *suffix =
          nul ? "(printf child >&2)}}\nEOF\n" : "(printf child >&2)}\"";
      memcpy(source + length, suffix, strlen(suffix));
      length += strlen(suffix);
      for (unsigned operation = 0; operation < 4; ++operation) {
        shellsplit_test_source_scan_reset();
        if (operation == 0) {
          shell_parse_result_t fast;
          CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
        } else if (operation == 1) {
          CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
                    SHELL_SOURCE_UNSUPPORTED &&
                !source_draft.prefix_length && !source_draft.prefix.count);
        } else if (operation == 2) {
          shell_processed_commands_t processed = {0};
          CHECK(shell_process_commands(source, length, NULL, &processed) ==
                    SHELL_PROCESS_EPARSE &&
                !processed.commands && !processed.command_count);
          shell_processed_commands_free(&processed);
        } else {
          CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits,
                                      &source_graph) == SHELL_DEP_EPARSE);
          CHECK(!source_graph.node_count && !source_graph.edge_count);
        }
        size_t work = shellsplit_test_source_scan_work();
        CHECK(work <= 128 * length + 4096 &&
              (!previous[operation] || work <= 2 * previous[operation] + 4096));
        previous[operation] = work;
      }
    }
  }
#endif
}

typedef struct {
  const char *argument, *path;
  unsigned calls;
} source_word_byte_resolution_t;

/* All allocating adapters own the same operation-sized temporary arena. This
 * checks their public signatures, successful cleanup, and failed publication.
 */
static void source_allocating_adapter(const char *source, size_t length,
                                      unsigned api, bool fail) {
  switch (api) {
  case 0: {
    shell_command_t *commands = NULL;
    size_t count = 0;
    CHECK(shell_tokenize_commands(source, length, &commands, &count) ==
          (fail ? SHELL_TOKENIZE_ENOMEM : SHELL_TOKENIZE_OK));
    CHECK(fail ? !commands && !count : commands && count);
    shell_commands_free(commands, count);
    break;
  }
  case 1: {
    shell_processed_commands_t commands = {0};
    CHECK(shell_process_commands(source, length, NULL, &commands) ==
          (fail ? SHELL_PROCESS_ENOMEM : SHELL_PROCESS_OK));
    CHECK(fail ? !commands.commands && !commands.command_count
               : commands.commands && commands.command_count);
    shell_processed_commands_free(&commands);
    break;
  }
  case 2: {
    shell_command_info_t *commands = NULL;
    size_t count = 0;
    CHECK(shell_process_command(source, length, NULL, &commands, &count) ==
          (fail ? SHELL_PROCESS_ENOMEM : SHELL_PROCESS_OK));
    CHECK(fail ? !commands && !count : commands && count);
    shell_command_infos_free(commands, count);
    break;
  }
  case 3: {
    shell_abstract_command_t *command = NULL;
    CHECK(shell_abstract_command_parse(source, length, &command) ==
          (fail ? SHELL_ABSTRACT_ENOMEM : SHELL_ABSTRACT_OK));
    CHECK(fail ? !command : command != NULL);
    shell_abstract_command_free(command);
    break;
  }
  case 4: {
    shell_transformed_command_t **commands = NULL;
    size_t count = 0;
    CHECK(
        shell_transform_command_line(source, length, NULL, &commands, &count) ==
        (fail ? SHELL_TRANSFORM_ENOMEM : SHELL_TRANSFORM_OK));
    CHECK(fail ? !commands && !count : commands && count);
    shell_transformed_command_list_free(commands, count);
    break;
  }
  default: {
    shell_netstring_buffer_t sequence = {0};
    shell_netstring_buffer_t type = {0};
    size_t count = 0;
    bool features = false;
    shell_process_status_t status;
    if (api == 5)
      status = shell_build_netargv_sequence_buffer(
          source, length, NULL, &sequence, &count, &features);
    else if (api == 6)
      status = shell_build_command_netseq_buffer(source, length, NULL,
                                                 &sequence, &count);
    else if (api == 7)
      status = shell_build_type_netseq_buffer(source, length, NULL, &sequence,
                                              &count);
    else
      status = shell_build_anomaly_netseqs_buffer(source, length, NULL,
                                                  &sequence, &type, &count);
    CHECK(status == (fail ? SHELL_PROCESS_ENOMEM : SHELL_PROCESS_OK));
    CHECK(fail ? !sequence.data && !sequence.length && !count
               : sequence.data && count);
    if (api == 8)
      CHECK(fail ? !type.data && !type.length : type.data != NULL);
    shell_netstring_buffer_free(&sequence);
    shell_netstring_buffer_free(&type);
  }
  }
}

static void source_capacity_and_work(void) {
  char source[16384];
  size_t length = 0;
  for (unsigned h = 0; h <= SHELL_SOURCE_MAX_HEADERS; h++) {
    memcpy(source + length, "echo x;", 7);
    length += 7;
  }
  CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  length = strlen("echo before; echo `");
  memcpy(source, "echo before; echo `", length);
  for (unsigned h = 0; h < SHELL_SOURCE_MAX_HEADERS; h++) {
    memcpy(source + length, "echo x;", 7);
    length += 7;
  }
  CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  static const char no_alloc[] = "cat >target 2>&\"1\" <<'EOF'\nalpha\nEOF\n";
  shellsplit_test_alloc_fail_at(1);
  CHECK(shell_parse_draft(no_alloc, sizeof(no_alloc) - 1, NULL,
                          &source_draft) == SHELL_SOURCE_COMPLETE);
  CHECK(shellsplit_test_alloc_count() == 0);
  shellsplit_test_alloc_reset();
#endif
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t selector_work[2] = {0}, candidate_work = 0;
  for (size_t padding = 128; padding <= 4096; padding *= 2) {
    static const char selector[] = "echo before; echo ${#";
    length = sizeof(selector) - 1;
    memcpy(source, selector, length);
    memset(source + length, 'x', padding);
    length += padding;
    source[length++] = '\\';
    for (unsigned complete = 0; complete < 2; complete++) {
      if (complete) {
        source[length++] = '\n';
        source[length++] = '}';
      }
      shellsplit_test_source_scan_reset();
      CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
            (complete ? SHELL_SOURCE_COMPLETE : SHELL_SOURCE_INCOMPLETE));
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work >= padding);
      CHECK(!selector_work[complete] || work <= selector_work[complete] * 3);
      selector_work[complete] = work;
    }
    /* An unconfirmed line may itself contain a closed substitution. Its
     * increasingly long literal tail must not be repeatedly reclassified. */
    static const char opening[] = "echo before; cat <<`x`";
    length = sizeof(opening) - 1;
    memcpy(source, opening, length);
    memset(source + length, 'y', padding);
    length += padding;
    source[length++] = '\n';
    memcpy(source + length, "`x`", 3);
    length += 3;
    memset(source + length, 'y', padding - 1);
    length += padding - 1;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.header_count == 2 &&
          source_draft.heredocs[0].delimiter_prefix);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!candidate_work || work <= candidate_work * 3);
    candidate_work = work;
  }
  size_t previous_domain_work = 0;
  for (unsigned repetitions = 32; repetitions <= 128; repetitions *= 2) {
    static const char piece[] = "日本 $((1)) ${value:1} 語 ";
    length = strlen("cat <<EOF\n");
    memcpy(source, "cat <<EOF\n", length);
    for (unsigned i = 0; i < repetitions; i++) {
      memcpy(source + length, piece, sizeof(piece) - 1);
      length += sizeof(piece) - 1;
    }
    memcpy(source + length, "\nEOF\n", 5);
    length += 5;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous_domain_work || work <= previous_domain_work * 3);
    previous_domain_work = work;
  }
  /* Nested unfinished parentheses share one received backtick boundary. The
   * long body is visited a bounded number of times, not once per ancestor. */
  for (unsigned depth = 4; depth <= 32; depth *= 2) {
    length = 0;
    for (unsigned d = 0; d < depth; d++) {
      memcpy(source + length, "echo $(", 7);
      length += 7;
    }
    memcpy(source + length, "echo `printf ", 13);
    length += 13;
    size_t leaf = length;
    memset(source + length, 'x', 1024);
    length += 1024;
    shellsplit_test_source_scan_reset();
    shellsplit_test_delimiter_watch(source + leaf, 1024);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.header_count == depth + 2);
    CHECK(shellsplit_test_delimiter_work() <= 8 * 1024);
  }
  for (unsigned depth = 4; depth <= 32; depth *= 2) {
    length = 0;
    for (unsigned d = 0; d < depth; d++) {
      memcpy(source + length, "echo $(", 7);
      length += 7;
    }
    size_t leaf = length;
    memset(source + length, 'x', 1024);
    length += 1024;
    shellsplit_test_source_scan_reset();
    shellsplit_test_delimiter_watch(source + leaf, 1024);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    size_t visits = shellsplit_test_delimiter_work();
    if (visits > 8 * 1024)
      fprintf(stderr, "draft rescanned leaf: depth=%u visits=%zu\n", depth,
              visits);
    CHECK(visits <= 8 * 1024);
    for (unsigned d = 0; d < depth; d++)
      source[length++] = ')';
    source[length++] = '"';
    shellsplit_test_source_scan_reset();
    shellsplit_test_delimiter_watch(source + leaf, 1024);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.header_count == depth + 1);
    CHECK(!source_draft.headers[0].complete &&
          source_draft.headers[depth].complete);
    CHECK(shellsplit_test_delimiter_work() <= 8 * 1024);
  }
  size_t previous_work = 0;
  for (unsigned children = 8; children <= SHELL_MAX_SUBCOMMANDS;
       children *= 2) {
    const char *opening = "echo \"";
    length = strlen(opening);
    memcpy(source, opening, length);
    for (unsigned c = 0; c < children; c++) {
      memcpy(source + length, "$(printf child)", 15);
      length += 15;
    }
    shellsplit_test_source_scan_reset();
    shell_source_status_t status =
        shell_parse_draft(source, length, NULL, &source_draft);
    if (children == SHELL_MAX_SUBCOMMANDS) {
      CHECK(status == SHELL_SOURCE_TRUNCATED);
      CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
      for (uint32_t h = 0; h < source_draft.header_count; h++)
        CHECK(!source_draft.headers[h].complete);
    } else {
      CHECK(status == SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.header_count == children + 1);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(!previous_work || work <= previous_work * 3);
      previous_work = work;
    }
  }
#endif
}

static void source_forward_prefix_products(void) {
  static shell_dep_graph_t ordinary;
  static const struct {
    const char *source;
    unsigned commands, groups, timers;
  } cases[] = {
      {"time printf x { }", 1, 0, 1},
      {"! time printf x \\\n{ }", 1, 0, 1},
      {"printf x | time { }", 2, 0, 0},
      {"time { printf x; } >out | ( ! time printf y )", 2, 2, 2},
      {"time <<<word printf x", 1, 0, 1},
      {"time <<'Q' printf x\npayload\nQ\nprintf after", 2, 0, 1},
      {": <<<x {", 1, 0, 0},
      {": <<<x }", 1, 0, 0},
      {"<<<x {", 1, 0, 0},
      {"time <<<x {", 1, 0, 1},
      {"! time <<<x }", 1, 0, 1},
      {"printf x | time <<<x {", 2, 0, 0},
      {"{ : <<<x }; }", 1, 1, 0},
      {": <<'Q' {\npayload\nQ\n", 1, 0, 0},
      {"time <<'Q' }\npayload\nQ\n", 1, 0, 1},
      {"{ time : <<'Q' }; }\npayload\nQ\n", 1, 1, 1},
      {": {fd}>|out", 1, 0, 0},
      {": {fd}>\\\n|out", 1, 0, 0},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
    const char *source = cases[c].source;
    size_t length = strlen(source);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    for (uint32_t h = 0; h < source_draft.header_count; ++h)
      CHECK(source_draft.headers[h].complete);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    if (processed.command_count != cases[c].commands)
      fprintf(stderr, "forward prefix commands: %s actual=%zu expected=%u\n",
              source, processed.command_count, cases[c].commands);
    CHECK(processed.command_count == cases[c].commands);
    shell_processed_commands_free(&processed);
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          &source_draft.prefix,
                                          &source_graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&source_graph).valid);
    unsigned commands = 0, groups = 0, timers = 0;
    for (uint32_t n = 0; n < source_graph.node_count; ++n) {
      commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
      groups += source_graph.nodes[n].type == SHELL_NODE_GROUP;
      timers += source_graph.nodes[n].type == SHELL_NODE_TIME;
    }
    CHECK(commands == cases[c].commands && groups == cases[c].groups &&
          timers == cases[c].timers);
    CHECK(shell_dep_graph_parse(source, length, "/workspace", &limits,
                                &ordinary) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(&source_graph, &ordinary));
  }
}

static void source_indexed_word_boundaries(void) {
  const char *const assignments[] = {
      "a[1 + 2]=x",          "a[1 + 2]+=x\"\"", "a[$(printf 1) + 2]=x",
      "a[1 + 2]=\"$value\"", "a[1 + 2]=x\\\ny", "a\\\n[1 + 2]\\\n=\\\nx"};
  for (size_t i = 0; i < sizeof(assignments) / sizeof(assignments[0]); ++i) {
    char source[256];
    int n = snprintf(source, sizeof(source), "%s printf x", assignments[i]);
    CHECK(n > 0 && (size_t)n < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)n, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.headers[0].word_count == 3 &&
          source_draft.headers[0].assignment_count == 1);
    CHECK(source_draft.headers[0].words[0].start == 0 &&
          source_draft.headers[0].words[0].length == strlen(assignments[i]));
    n = snprintf(source, sizeof(source), "%s a=(x)", assignments[i]);
    CHECK(n > 0 && (size_t)n < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)n, NULL, &source_draft) ==
          SHELL_SOURCE_UNSUPPORTED);
    CHECK(!source_draft.prefix_length && !source_draft.headers[0].complete);
    CHECK(source_draft.headers[0].words[0].length == strlen(assignments[i]));
  }
  const char *const ordinary[] = {"echo a[1 + 2]=x", "declare >out a[1 + 2]=x"};
  for (size_t i = 0; i < sizeof(ordinary) / sizeof(ordinary[0]); ++i) {
    CHECK(shell_parse_draft(ordinary[i], strlen(ordinary[i]), NULL,
                            &source_draft) == SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.headers[0].word_count == 4 &&
          !source_draft.headers[0].assignment_count);
    CHECK(source_draft.headers[0].words[1].length == 3);
    CHECK(source_draft.headers[0].words[2].length == 1);
    CHECK(source_draft.headers[0].words[3].length == 4);
  }
  static const char *const declarations[] = {"declare", "typeset", "export",
                                             "readonly", "local"};
  for (size_t i = 0; i < sizeof(declarations) / sizeof(declarations[0]); ++i) {
    char source[128];
    int n = snprintf(source, sizeof(source), "%s a[1 + 2]=x", declarations[i]);
    CHECK(n > 0 && (size_t)n < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)n, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.headers[0].word_count == 4 &&
          !source_draft.headers[0].assignment_count);
    static const char *const words[] = {"a[1", "+", "2]=x"};
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, (size_t)n, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == 1 &&
          processed.commands[0].command_token_count == 4);
    for (size_t w = 0; w < 3; ++w) {
      shell_source_span_t span = source_draft.headers[0].words[w + 1];
      const shell_token_t *token = &processed.commands[0].command_tokens[w + 1];
      CHECK(span.length == strlen(words[w]) &&
            !memcmp(source + span.start, words[w], span.length));
      CHECK(token->length == span.length &&
            !memcmp(token->start, words[w], span.length));
    }
    shell_processed_commands_free(&processed);
    CHECK(shell_dep_graph_parse_with_fast(source, (size_t)n, "/workspace",
                                          &limits, &source_draft.prefix,
                                          &source_graph) == SHELL_DEP_OK);
    CHECK(source_graph.nodes[0].type == SHELL_NODE_CMD &&
          source_graph.nodes[0].cmd.token_count == 4);
    n = snprintf(source, sizeof(source), "%s 'a[1 + 2]=x'", declarations[i]);
    CHECK(n > 0 && (size_t)n < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)n, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.headers[0].word_count == 2 &&
          source_draft.headers[0].words[1].length == strlen("'a[1 + 2]=x'"));
  }
}

static void source_indexed_prefix_uncertainty(void) {
  static const char *const sources[] = {"a[1 + (2)]=x",
                                        "a[1 + (2)]=x printf ok",
                                        "a[$(printf 1) + (2)]=x",
                                        "a\\\n[1 + (2)]=x",
                                        "a[${v:-]} + (2)]=x",
                                        "a[${v:-[} + (2)]=x",
                                        "a[${v:-${w:-]}} + (2)]=x",
                                        "a[${v:-$(printf ])} + (2)]=x",
                                        "a[<(printf ]) + (2)]=x",
                                        "a[>(printf [) + (2)]=x",
                                        "a[${indices[0]:-]} + (2)]=x",
                                        "a[$\\\n{v:-]} + (2)]=x",
                                        "a[<\\\n(printf ]) + (2)]=x",
                                        "a\\\n[$\\\n{v:-]} + (2)]\\\n=\\\nx"};
  for (size_t c = 0; c < sizeof(sources) / sizeof(sources[0]); ++c) {
    size_t length = strlen(sources[c]);
    for (size_t end = 0; end <= length; ++end) {
      shell_source_status_t status =
          shell_parse_draft(sources[c], end, NULL, &source_draft);
      if (status == SHELL_SOURCE_INVALID)
        fprintf(stderr, "false INVALID indexed prefix: %.*s\n", (int)end,
                sources[c]);
      CHECK(status != SHELL_SOURCE_INVALID && status != SHELL_SOURCE_TRUNCATED);
      if (status == SHELL_SOURCE_UNSUPPORTED)
        CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
    }
  }
  static const char *const unresolved[] = {
      "a[1 + (",           "a[1 + (2",  "a[1 + (2)",         "a[1 + (2)]",
      "a[$(printf 1) + (", "a=(x\\ y)", "declare a=(x\\ y)", "a[\\(]=(x\\ y)",
      "a[\\(]=(x",         "a[${v:-[}"};
  for (size_t c = 0; c < sizeof(unresolved) / sizeof(unresolved[0]); ++c)
    CHECK(shell_parse_draft(unresolved[c], strlen(unresolved[c]), NULL,
                            &source_draft) == SHELL_SOURCE_UNSUPPORTED);
  static const char *const unfinished[] = {"a[${v:-]", "a[<(printf ]",
                                           "a[>(printf ["};
  for (size_t c = 0; c < sizeof(unfinished) / sizeof(unfinished[0]); ++c)
    CHECK(shell_parse_draft(unfinished[c], strlen(unfinished[c]), NULL,
                            &source_draft) == SHELL_SOURCE_INCOMPLETE);
  static const char *const invalid[] = {"echo a[1 + (2)]=x",
                                        "declare a[1 + (2)]=x"};
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); ++c)
    CHECK(shell_parse_draft(invalid[c], strlen(invalid[c]), NULL,
                            &source_draft) == SHELL_SOURCE_INVALID);
  /* At a command word Bash reads the whole `a[1 + (2)]` as one word, so these
   * are commands with that name, not syntax errors. */
  static const char *const command_words[] = {"a[1 + (2)] ;", "a[1 + (2)] x"};
  for (size_t c = 0; c < sizeof(command_words) / sizeof(command_words[0]); ++c)
    CHECK(shell_parse_draft(command_words[c], strlen(command_words[c]), NULL,
                            &source_draft) == SHELL_SOURCE_COMPLETE);
}

static void source_indexed_boundary_work(void) {
  static const char parent[] = "[[]]", child[] = "[different]";
  shell_source_operation_begin(parent, sizeof(parent) - 1);
  size_t boundary;
  CHECK(shell_source_skip_array_subscript(parent, sizeof(parent) - 1, 0,
                                          &boundary) &&
        boundary == 4);
  shell_source_workspace_scope_t nested =
      shell_source_workspace_begin(child, sizeof(child) - 1, NULL, 0);
  CHECK(shell_source_skip_array_subscript(child, sizeof(child) - 1, 0,
                                          &boundary) &&
        boundary == 11);
  shell_source_workspace_end(nested);
  CHECK(shell_source_skip_array_subscript(parent, sizeof(parent) - 1, 1,
                                          &boundary) &&
        boundary == 3);
  shell_source_operation_end();
  /* Every outer opening shares one forward matching walk, even when skipped
   * expansions contain misleading brackets or reenter subscript matching.
   * Repeat all real candidates after both unfinished and complete walks. */
  static const char *const scopes[] = {
      "[${v:-]} ",     "[${v:-[} ",           "[<(printf ]) ",
      "[>(printf [) ", "[${v:-$(printf ])} ", "[${indices[0]:-]} "};
  for (size_t count = 256; count <= 2048; count *= 2)
    for (size_t c = 0; c < sizeof(scopes) / sizeof(scopes[0]); ++c) {
      size_t piece = strlen(scopes[c]);
      size_t unfinished_length = count * piece;
      size_t length = unfinished_length + count;
      char *source = malloc(length);
      CHECK(source);
      for (size_t i = 0; i < count; ++i)
        memcpy(source + i * piece, scopes[c], piece);
      memset(source + unfinished_length, ']', count);
      size_t size;
      CHECK(shell_source_workspace_size(length, &size));
      void *storage = malloc(size);
      CHECK(storage);
      shell_source_operation_begin(source, length);
      shell_source_workspace_scope_t previous =
          shell_source_workspace_begin(source, length, storage, size);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      for (size_t i = 0; i < count; ++i) {
        size_t after;
        CHECK(!shell_source_skip_array_subscript(source, unfinished_length,
                                                 i * piece, &after));
      }
      for (size_t i = 0; i < count; ++i) {
        size_t after;
        CHECK(shell_source_skip_array_subscript(source, length, i * piece,
                                                &after) &&
              after == length - i);
        CHECK(!shell_source_skip_array_subscript(source, unfinished_length,
                                                 i * piece, &after));
      }
      CHECK(!shell_source_scratch_exhausted());
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work = shellsplit_test_source_scan_work();
      if (work > length * 100)
        fprintf(stderr, "nested subscript work family=%zu count=%zu work=%zu\n",
                c, count, work);
      CHECK(work <= length * 100);
#endif
      shell_source_workspace_end(previous);
      shell_source_operation_end();
      free(storage);
      free(source);
    }
  /* More simultaneously live facts than the evicting lexical index holds.
   * This must succeed with sized scratch, not stop at a new syntax limit. */
  for (size_t count = 1024; count <= 8192; count *= 2) {
    char *source = malloc(count * 6 + 32);
    CHECK(source);
    size_t size;
    CHECK(shell_source_workspace_size(count * 6 + 32, &size));
    unsigned char *storage = malloc(size + 1);
    CHECK(storage);
    shell_limits_t lexical = SHELL_LIMITS_DEFAULT;
    lexical.strict_mode = true;
    lexical.workspace = storage + 1; /* Arbitrary caller alignment. */
    lexical.workspace_size = size;
    for (unsigned form = 0; form < 3; ++form) {
      size_t at = 0;
      if (form != 2) {
        const char *head = form ? "declare " : "printf ";
        at = strlen(head);
        memcpy(source, head, at);
      }
      const char *piece = form == 2 ? "a[; " : "a[ ";
      size_t piece_length = strlen(piece);
      for (size_t i = 0; i < count; ++i) {
        memcpy(source + at, piece, piece_length);
        at += piece_length;
      }
      for (size_t i = 0; i < count; ++i) {
        memcpy(source + at, "] ", 2);
        at += 2;
      }
      source[at] = '\0';
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      if (form != 2) {
        shell_parse_result_t fast;
        CHECK(shell_parse_fast(source, at, &lexical, &fast) == SHELL_OK);
        CHECK(fast.count == 1);
      } else {
        shell_tokenizer_state_t iterator;
        shell_token_t token;
        CHECK(shell_tokenizer_init(&iterator, source, at, &lexical));
        size_t tokens = 0;
        while (shell_tokenizer_next(&iterator, &token))
          ++tokens;
        /* At a command word the balanced brackets are one word. */
        CHECK(!iterator.heredoc_error && tokens == 1);
      }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work = shellsplit_test_source_scan_work();
      if (work > at * 100)
        fprintf(stderr, "array work form=%u count=%zu length=%zu work=%zu\n",
                form, count, at, work);
      CHECK(work <= at * 100);
#endif
    }
    /* Unfinished facts are endpoint-qualified and reusable too. */
    memset(source, '[', count);
    shell_source_operation_begin(source, count);
    shell_source_workspace_scope_t previous = shell_source_workspace_begin(
        source, count, lexical.workspace, lexical.workspace_size);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    for (size_t i = 0; i < count; ++i) {
      size_t after;
      CHECK(!shell_source_skip_array_subscript(source, count, i, &after));
    }
    CHECK(!shell_source_scratch_exhausted());
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    CHECK(shellsplit_test_source_scan_work() <= count * 4);
#endif
    shell_source_workspace_end(previous);
    shell_source_operation_end();
    /* A successful larger-end match must not be reused as a complete match
     * inside a shorter immutable view. */
    memset(source, '[', count);
    memset(source + count, ']', count);
    shell_source_operation_begin(source, count * 2);
    previous = shell_source_workspace_begin(
        source, count * 2, lexical.workspace, lexical.workspace_size);
    size_t after;
    CHECK(!shell_source_skip_array_subscript(source, count, 0, &after));
    CHECK(shell_source_skip_array_subscript(source, count * 2, 0, &after) &&
          after == count * 2);
    CHECK(!shell_source_skip_array_subscript(source, count, 0, &after));
    shell_source_workspace_end(previous);
    shell_source_operation_end();
    if (count == 1024) {
      memcpy(source, "a[", 2);
      memset(source + 2, '[', count);
      memset(source + 2 + count, ']', count + 1);
      memcpy(source + 3 + count * 2, "=x", 2);
      size_t length = count * 2 + 5;
      CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
            SHELL_SOURCE_TRUNCATED);
      CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
      CHECK(shell_parse_draft(source, length, &lexical, &source_draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(source_draft.headers[0].word_count == 1 &&
            source_draft.headers[0].words[0].length == length);
      shell_command_t *owned_commands = NULL;
      size_t owned_count = 0;
      CHECK(shell_tokenize_commands(source, length, &owned_commands,
                                    &owned_count) == SHELL_TOKENIZE_OK);
      CHECK(owned_count == 1);
      shell_commands_free(owned_commands, owned_count);
      shell_tokenizer_state_t first, second;
      shell_token_t token, other_token;
      CHECK(shell_tokenizer_init(&first, source, length, NULL));
      CHECK(!shell_tokenizer_next(&first, &token) && first.heredoc_error);
      /* Alternate independent live iterators after their first negative
       * candidate prepared every nested boundary in separate arenas. */
      for (size_t i = 0; i < count; ++i)
        memcpy(source + i * 4, "a[; ", 4);
      for (size_t i = 0; i < count; ++i)
        memcpy(source + count * 4 + i * 2, "] ", 2);
      length = count * 6;
      shell_limits_t other = lexical;
      other.workspace = malloc(size);
      CHECK(other.workspace);
      CHECK(shell_tokenizer_init(&first, source, length, &lexical));
      CHECK(shell_tokenizer_init(&second, source, length, &other));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      for (;;) {
        bool found = shell_tokenizer_next(&first, &token);
        CHECK(shell_tokenizer_next(&second, &other_token) == found);
        if (!found)
          break;
        CHECK(token.type == other_token.type &&
              token.position == other_token.position &&
              token.length == other_token.length);
      }
      CHECK(!first.heredoc_error && !second.heredoc_error);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      CHECK(shellsplit_test_source_scan_work() <= length * 100);
#endif
      free(other.workspace);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
      shell_command_t *commands = NULL;
      size_t command_count = 0;
      shellsplit_test_alloc_fail_at(1);
      CHECK(shell_tokenize_commands(source, length, &commands,
                                    &command_count) == SHELL_TOKENIZE_ENOMEM);
      CHECK(!commands && !command_count);
      shellsplit_test_alloc_reset();
#endif
    }
    free(storage);
    free(source);
  }
}

static void source_delimiter_phases(void) {
  static const struct {
    const char *source, *payload, *closing;
    bool literal;
  } cases[] = {
      {"cat <<`\"`$'\\x3a'\n``':'\nprintf 'HIDDEN\\n'\n``:\n:\n", "", "``':'\n",
       true},
      {"cat <<`'a\\\nb'`''\npayload\n`ab`\n", "payload\n", "`ab`\n", true},
      {"cat <<`'a\\\nb'`\npayload\n`'ab'`\n", "payload\n", "`'ab'`\n", false},
      {"cat << \\\n  EOF\npayload\nEOF\n", "payload\n", "EOF\n", false},
      {"cat <<- \t\\\n \t\\\n EOF\n\tpayload\n\tEOF\n", "payload\n", "\tEOF\n",
       false},
      {"cat << \\\n -EOF\npayload\n-EOF\n", "payload\n", "-EOF\n", false},
      {"cat << \\\n ''\n$value\n\n", "$value\n", "\n", true},
      {"cat <<$'\\''\npayload\n'\n", "payload\n", "'\n", true},
      {"cat <<$'a\\'b'\npayload\na'b\n", "payload\n", "a'b\n", true},
      {"cat <<`\"`$'\\''\npayload\n``\\'\n", "payload\n", "``\\'\n", true},
      {"cat <<`\"`$'\\'\\''\npayload\n``''\\'''\\'''\n", "payload\n",
       "``''\\'''\\'''\n", true},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    size_t length = strlen(source);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.heredoc_count == 1 && source_draft.heredocs[0].complete);
    const shell_source_heredoc_t *doc = &source_draft.heredocs[0];
    CHECK(!!(doc->content.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL) ==
          cases[c].literal);
    content(&doc->content, cases[c].payload);
    CHECK(doc->closing_delimiter.length == strlen(cases[c].closing));
    CHECK(!memcmp(source + doc->closing_delimiter.start, cases[c].closing,
                  strlen(cases[c].closing)));
    CHECK(doc->content.value == source + doc->body_start);
    CHECK(doc->body_start + doc->content.value_len ==
          doc->closing_delimiter.start);
    source_parse(source);
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          &source_draft.prefix,
                                          &source_graph) == SHELL_DEP_OK);
    if (c == 0) {
      CHECK(source_draft.header_count == 4);
      static const char *const commands[] = {"cat", "printf", "``:", ":"};
      unsigned count = 0;
      for (uint32_t n = 0; n < source_graph.node_count; n++) {
        if (source_graph.nodes[n].type == SHELL_NODE_DOC &&
            source_graph.nodes[n].doc.kind == SHELL_DOC_HEREDOC)
          content(&source_graph.nodes[n].doc, "");
        if (source_graph.nodes[n].type != SHELL_NODE_CMD)
          continue;
        CHECK(count < 4);
        const shell_dep_cmd_t *cmd = &source_graph.nodes[n].cmd;
        CHECK(cmd->token_lens[0] == strlen(commands[count]) &&
              !memcmp(cmd->tokens[0], commands[count], cmd->token_lens[0]));
        count++;
      }
      CHECK(count == 4);
    }
    shell_tokenizer_state_t lexer;
    CHECK(shell_tokenizer_init(&lexer, source, length, NULL));
    shell_token_t token;
    unsigned documents = 0;
    while (shell_tokenizer_next(&lexer, &token))
      documents += token.type == SHELL_TOKEN_HEREDOC;
    CHECK(!lexer.heredoc_error && documents == 1);
  }
  static const char *const gaps[] = {"cat << \\\n \t", "cat <<- \\\n ",
                                     "cat << \\\n \\\n "};
  for (size_t c = 0; c < sizeof(gaps) / sizeof(gaps[0]); c++) {
    CHECK(shell_parse_draft(gaps[c], strlen(gaps[c]), NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.heredoc_count == 1 &&
          source_draft.heredocs[0].redirect == UINT32_MAX &&
          !source_draft.heredocs[0].header_complete &&
          !source_draft.prefix_length);
  }
  static const char single_quoted[] = "cat <<'a\\\nb'\npayload\nab\n";
  CHECK(shell_parse_draft(single_quoted, sizeof(single_quoted) - 1, NULL,
                          &source_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.need == SHELL_SOURCE_NEEDS_HEREDOC_BODY);
  content(&source_draft.heredocs[0].content, "payload\nab\n");

  /* Bash reparses its printed command substitution. Its omitted separator
   * promotes an unquoted leading dash into <<-, exposing EXPOSED as code.
   * Do not publish a graph that silently treats that command as body data. */
  static const char *const reprinted[] = {
      "echo \"$(cat << -EOF\npayload\nEOF\nprintf EXPOSED\n-EOF\n)\"",
      "cat <(cat << \\\n -EOF\npayload\nEOF\nprintf EXPOSED\n-EOF\n)",
  };
  for (size_t c = 0; c < sizeof(reprinted) / sizeof(reprinted[0]); c++) {
    const char *source = reprinted[c];
    CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                                &source_graph) == SHELL_DEP_EPARSE);
    shell_processed_commands_t commands = {0};
    CHECK(shell_process_commands(source, strlen(source), NULL, &commands) ==
          SHELL_PROCESS_EPARSE);
    CHECK(!commands.commands && !commands.command_count);
  }
  static const char *const preserved[] = {
      "echo \"$(cat << '-EOF'\npayload\n-EOF\n)\"",
      "echo \"$(cat <<--EOF\n\tpayload\n\t-EOF\n)\"",
  };
  for (size_t c = 0; c < sizeof(preserved) / sizeof(preserved[0]); c++) {
    source_parse(preserved[c]);
    CHECK(shell_parse_draft(preserved[c], strlen(preserved[c]), NULL,
                            &source_draft) == SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.heredoc_count == 1 && source_draft.heredocs[0].complete);
    content(&source_draft.heredocs[0].content, "payload\n");
  }
}

typedef struct {
  const char *source;
  size_t start, end;
  unsigned calls;
} source_delimiter_resolution_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    delimiter_resolution(const shell_expand_word_request_t *request,
                         const char **records, size_t *length, void *context) {
  source_delimiter_resolution_t *domain = context;
  CHECK(request->source == domain->source);
  CHECK(request->word_offset < domain->start ||
        request->word_offset >= domain->end);
  domain->calls++;
  *records = NULL;
  *length = 0;
  return SHELL_EXPAND_UNRESOLVED;
}

/* Delimiter-only fragments are lexical data. Their normalization must neither
 * introduce executable child headers nor hide commands after the terminator. */
static void source_delimiter_fragments(void) {
  static const struct {
    const char *word, *delimiter;
    bool quoted;
  } cases[] = {
      {"${x:-\"EOF\"}", "${x:-\"EOF\"}", false},
      {"${x:-\"EOF\"}''", "${x:-EOF}", true},
      {"${not!valid}", "${not!valid}", false},
      {"${x:-$'\\x3a'}", "${x:-':'}", false},
      {"${x:-$'\\x3a'}''", "${x:-:}", true},
      {"${x:-$'\\''}", "${x:-\\'}", false},
      {"${x:-$'a\\'b'}", "${x:-'a'\\''b'}", false},
      {"${x:-$''}", "${x:-''}", false},
      {"${x:-$'a\\0b'}", "${x:-'a'}", false},
      {"\"${x:-$'abc'}\"", "${x:-abc}", true},
      {"\"${\\\n#x:-$'a'}\"", "${#x:-a}", true},
      {"\"${\\\n%x:-$'a'}\"", "${%x:-a}", true},
      {"\"${\\\n/x:-$'a'}\"", "${/x:-a}", true},
      {"\"${\\\n^x:-$'a'}\"", "${^x:-a}", true},
      {"\"${\\\n,x:-$'a'}\"", "${,x:-a}", true},
      {"\"${\\\n\\\n#x:-$'a\\0b'}\"TAIL", "${#x:-a", true},
      {"\"${\\\nx\\\n#$'a\\0b'}\"TAIL", "${x#'a'}TAIL", true},
      {"\"${x:\\\n-$'a\\0b'}\"TAIL", "${x:-a", true},
      {"${\\\n#x:-$'a'}", "${#x:-'a'}", false},
      {"${\\\n#x:-$'a'}''", "${#x:-a}", true},
      {"\"${\\\n#x:-${y:-$'a'}}\"", "${#x:-${y:-a}}", true},
      {"${x:-`echo \"x\"`}", "${x:-`echo \"x\"`}", false},
      {"${x:-`echo \"x\"`}''", "${x:-`echo x`}", true},
      {"\"`echo \"x y\"`\"", "`echo x y`", true},
      {"\"`$'\\x3a'`\"", "`$'\\x3a'`", true},
      {"\"${x#$'\\x3a'}\"", "${x#':'}", true},
      {"${x:-${y:-\"EOF\"}}", "${x:-${y:-\"EOF\"}}", false},
      {"$(printf   eof)", "$(printf eof)", false},
      {"\"$(printf   eof)\"", "$(printf eof)", true},
      {"'$(printf   eof)'", "$(printf   eof)", true},
      {"$(a 1>f)", "$(a > f)", false},
      {"$(a 2>f b <&0)", "$(a b 2> f 0<&0)", false},
      {"$(a 03>&01)", "$(a 3>&1)", false},
      {"$(a <&-)", "$(a 0>&-)", false},
      {"$(a|&b)", "$(a 2>&1 | b)", false},
      {"$({ a; b; })", "$({ a; b; })", false},
      {"$( ( a ) )", "$( ( a ))", false},
      {"$(time -- a)", "$(time -p a)", false},
      {"$(a < <(printf   x))", "$(a < <(printf x))", false},
      {"$((1 + (2*3)))", "$((1 + (2*3)))", false},
      {"$((1 + $(printf   2)))", "$((1 + $(printf 2)))", false},
      {"$(a <<EOF; b\nx\nEOF\n)", "$(a <<EOF\nx\nEOF\n b)", false},
      {"$(a <<EOF | b\nx\nEOF\n)", "$(a <<EOF |\nx\nEOF\n  b)", false},
      {"$(a <<EOF && b\nx\nEOF\n)", "$(a <<EOF && \nx\nEOF\n b)", false},
      {"$(a <<EOF\nx\nEOF\nb)", "$(a <<EOF\nx\nEOF\n\nb)", false},
      {"$(a <<EOF;\nx\nEOF\n)", "$(a <<EOF\nx\nEOF\n)", false},
      {"$(a <<-'EOF'\n\tx\n\tEOF\n)", "$(a <<-'EOF'\nx\nEOF\n)", false},
      {"$(a <<EOF\nx\\\ny\nEOF\n)", "$(a <<EOF\nxy\nEOF\n)", false},
      {"$({ a & })", "$({ a & })", false},
      {"$(time !;)", "$(time ! )", false},
      {"$(a 2>&09-)", "$(a 2>&9-)", false},
      {"$[1 + (2)]", "$[1 + (2)]", false},
      {"${}", "${}", false},
      {"$((echo); echo y)", "$((echo); echo y)", false},
      {"$((\\\n1 + 2))", "$((1 + 2))", false},
      {"$((1 + 2)\\\n)", "$((1 + 2))", false},
      {"<(printf   x)", "<(printf x)", false},
      {"$((1+<(printf   x)))", "$((1+<(printf   x)))", false},
      {"$[1+<(printf   x)]", "$[1+<(printf   x)]", false},
      {"$(a &>>f)", "$(a &>> f)", false},
      {"$(a &>f)", "$(a &> f)", false},
      {"$(a >>f)", "$(a >> f)", false},
      {"$(a >|f)", "$(a >| f)", false},
      {"$(a <>f)", "$(a <> f)", false},
      {"$(a <<<x)", "$(a <<< x)", false},
      {"$(a 7>f)", "$(a 7> f)", false},
      {"$(a {fd}>f)", "$(a {fd}> f)", false},
      {"$(a {fd}<&-)", "$(a {fd}>&-)", false},
      {"$(a 1&>f)", "$(a 1 &> f)", false},
      {"$(a 2147483648>f)", "$(a 2147483648 > f)", false},
      {"$(a&&b||c;d|e)", "$(a && b || c; d | e)", false},
      {"$(a & b)", "$(a & b)", false},
      {"$(a <<''\nx\n\n)", "$(a <<''\nx\n\n)", false},
      {"$(a <<$'\\''\nx\n'\n)", "$(a <<\\'\nx\n'\n)", false},
      {"$(a <&-file)", "$(a file 0>&-)", false},
      {"$(a >&-file)", "$(a file 1>&-)", false},
      {"$(a 2>&-\"file\")", "$(a \"file\" 2>&-)", false},
      {"$(a {fd}<&-$(b))", "$(a $(b) {fd}>&-)", false},
      {"$(a >& \\\n-file)", "$(a file 1>&-)", false},
      {"$(a <&-#comment\nb)", "$(a 0>&-\nb)", false},
      {"$(a <&2147483648-)", "$(a 0<&2147483648-)", false},
      {"$(a >&0009-)", "$(a 1>&9-)", false},
      {"$(a >&$fd-)", "$(a 1>&$fd-)", false},
      {"$(a >&file-)", "$(a 1>&file-)", false},
      {"$(a <&\"9\"-)", "$(a 0<&\"9\"-)", false},
      {"$(a >&9\\-)", "$(a 1>&9\\-)", false},
      {"$(a >&file-\\\n)", "$(a 1>&file-)", false},
      {"$(a >&\"9-\")", "$(a >&\"9-\")", false},
      {"$(a >&\\-file)", "$(a >&\\-file)", false},
      {"\"${x:-$'\\0'}\"", "${x:-", true},
      {"A\"${x:-$'a\\0b'}\"TAIL", "A${x:-a", true},
      {"\"${x:-${y:-$'\\0'}}\"TAIL", "${x:-${y:-", true},
      {"\"${x#$'\\0'}\"TAIL", "${x#''}TAIL", true},
      {"${x:-$'\\0'}TAIL", "${x:-''}TAIL", false},
      {"$(printf \"${x:-$'\\0'}\" tail)", "$(printf \"${x:- tail)", false},
      {"$(printf \"${x:-$'\\0'}\" >f; echo z)", "$(printf \"${x:- > f; echo z)",
       false},
      {"$(a >\"${x:-$'\\0'}\" b)", "$(a b > \"${x:-)", false},
      {"$(a >&\"${x:-$'a-\\0b'}\")", "$(a 1>&\"${x:-a-)", false},
      {"$(a >&$(printf \"${x:-$'a-\\0'}\" tail))",
       "$(a >&$(printf \"${x:-a- tail))", false},
      {"$({ printf \"${x:-$'a\\n\\0'}\"; })", "$({ printf \"${x:-a\n })",
       false},
      {"$({ printf \"${x:-$'a &\\0'}\"; })", "$({ printf \"${x:-a & })", false},
      {"$('if')", "$('if')", false},
      {"$(i\\f)", "$(i\\f)", false},
      {"$(i\"f\")", "$(i\"f\")", false},
      {"$(if$tail)", "$(if$tail)", false},
      {"$(>f if)", "$(if > f)", false},
      {"$(>f then)", "$(then > f)", false},
      {"$(x=1 then)", "$(x=1 then)", false},
      {"$(>f [[ x ]])", "$([[ x ]] > f)", false},
      {"$(>f function)", "$(function > f)", false},
      {"$(>f ! echo x)", "$(! echo x > f)", false},
      {"$(>f time echo x)", "$(time echo x > f)", false},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *word = cases[c].word;
    size_t length = strlen(word), size;
    CHECK(shell_source_workspace_size(length, &size));
    unsigned char *scratch = malloc(size + 1);
    CHECK(scratch);
    shell_source_operation_begin(word, length);
    /* Deliberately unaligned; the public capacity query permits this. */
    shell_source_workspace_scope_t previous =
        shell_source_workspace_begin(word, length, scratch + 1, size);
    shell_source_pending_heredoc_t pending;
    shell_source_heredoc_delimiter_t delimiter;
    size_t position = 0;
    CHECK(shell_source_probe_heredoc_delimiter(word, length, &position,
                                               &pending) ==
          SHELL_HEREDOC_WORD_COMPLETE);
    CHECK(position == length);
    CHECK(shell_source_prepare_heredoc(&pending, &delimiter));
    CHECK(delimiter.length == strlen(cases[c].delimiter));
    if (memcmp(delimiter.bytes, cases[c].delimiter, delimiter.length))
      fprintf(stderr, "delimiter case %zu: %.*s\n", c, (int)delimiter.length,
              delimiter.bytes);
    CHECK(!memcmp(delimiter.bytes, cases[c].delimiter, delimiter.length));
    CHECK(delimiter.quoted == cases[c].quoted);
    CHECK(shell_source_heredoc_delimiter_is_quoted(&pending) ==
          cases[c].quoted);
    shell_source_workspace_end(previous);
    shell_source_operation_end();
    free(scratch);

    if (strchr(cases[c].delimiter, '\n'))
      continue; /* Such a delimiter cannot end on one physical body line. */
    char source[1024];
    int count = snprintf(source, sizeof(source),
                         "echo before; cat << %s\npayload\n%s\nprintf AFTER",
                         word, cases[c].delimiter);
    CHECK(count > 0 && (size_t)count < sizeof(source));
    CHECK(shell_source_workspace_size((size_t)count, &size));
    scratch = malloc(size);
    CHECK(scratch);
    shell_limits_t source_limits = SHELL_LIMITS_DEFAULT;
    source_limits.workspace = scratch;
    source_limits.workspace_size = size;
    CHECK(shell_parse_draft(source, (size_t)count, &source_limits,
                            &source_draft) == SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.header_count == 3 && source_draft.heredoc_count == 1);
    content(&source_draft.heredocs[0].content, "payload\n");
    size_t word_start = (size_t)(strstr(source, "<< ") - source) + 3;
    for (size_t cut = word_start; cut <= word_start + strlen(word); cut++) {
      shell_source_status_t status =
          shell_parse_draft(source, cut, &source_limits, &source_draft);
      if (status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "delimiter cut case=%zu cut=%zu status=%d: %.*s\n", c,
                cut, status, (int)cut, source);
      CHECK(status == SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.prefix_length == strlen("echo before;"));
    }
    shell_dep_limits_t graph_limits = limits;
    graph_limits.workspace_size += size;
    graph_limits.workspace = malloc(graph_limits.workspace_size);
    CHECK(graph_limits.workspace);
    CHECK(shell_dep_graph_parse(source, (size_t)count, "/workspace",
                                &graph_limits, &source_graph) == SHELL_DEP_OK);
    unsigned commands = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++)
      commands += source_graph.nodes[n].type == SHELL_NODE_CMD;
    CHECK(commands == 3);
    if (c == 7 || c == 14 || c == 18 || strstr(word, "${\\\n#x") ||
        strstr(word, " >&-file") || !strcmp(word, "\"${x:-$'\\0'}\"") ||
        !strcmp(word, "$(a >&$fd-)")) {
      for (unsigned api = 0; api < 9; api++) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        shellsplit_test_alloc_reset();
#endif
        source_allocating_adapter(source, (size_t)count, api, false);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        size_t allocations = shellsplit_test_alloc_count();
        for (size_t fail = 1; fail <= allocations; fail++) {
          shellsplit_test_alloc_fail_at(fail);
          source_allocating_adapter(source, (size_t)count, api, true);
        }
        shellsplit_test_alloc_reset();
#endif
      }
    }
    free(graph_limits.workspace);
    free(scratch);
  }
  static const char witness[] =
      "unset x; cat <<${x:-\":\"}\n${x:-\":\"}\nprintf "
      "'HIDDEN\\n'\n${x:-:}\n:\n";
  source_parse(witness);
  CHECK(shell_parse_draft(witness, sizeof(witness) - 1, NULL, &source_draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(source_draft.header_count == 5 && source_draft.heredoc_count == 1);
  content(&source_draft.heredocs[0].content, "");

  /* Historic failures accepted the entire source while hiding printf
   * inside a wrongly framed document. The paired terminators expose either
   * direction of drift; inspect the graph and the received source product. */
  static const struct {
    const char *source;
    unsigned commands;
  } exposed[] = {
      {"cat <<$(: >&-file)\n$(: file 1>&-)\nprintf HIDDEN\n"
       "$(: >&-file)\n:\n",
       5},
      {"cat <<\"${x:-$'\\0'}\"\n${x:-\nprintf HIDDEN\n${x:-}\n:\n", 4},
      {"cat <<\"${\\\n#x:-$'a'}\"\n${#x:-a}\nprintf HIDDEN\nexit 0\n"
       "${#x:-'a'}\n:\n",
       5},
  };
  for (size_t c = 0; c < sizeof(exposed) / sizeof(exposed[0]); c++) {
    const char *source = exposed[c].source;
    size_t length = strlen(source), size;
    CHECK(shell_source_workspace_size(length, &size));
    void *scratch = malloc(size);
    CHECK(scratch);
    shell_limits_t source_limits = SHELL_LIMITS_DEFAULT;
    source_limits.workspace = scratch;
    source_limits.workspace_size = size;
    CHECK(shell_parse_draft(source, length, &source_limits, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.heredoc_count == 1 && source_draft.heredocs[0].complete);
    content(&source_draft.heredocs[0].content, "");
    shell_dep_limits_t graph_limits = limits;
    graph_limits.workspace_size += size;
    graph_limits.workspace = malloc(graph_limits.workspace_size);
    CHECK(graph_limits.workspace);
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace",
                                          &graph_limits, &source_draft.prefix,
                                          &source_graph) == SHELL_DEP_OK);
    unsigned commands = 0, visible = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++) {
      const shell_dep_node_t *node = &source_graph.nodes[n];
      if (node->type != SHELL_NODE_CMD)
        continue;
      commands++;
      if (node->cmd.token_count && node->cmd.token_lens[0] == 6 &&
          !memcmp(node->cmd.tokens[0], "printf", 6))
        visible++;
    }
    CHECK(commands == exposed[c].commands && visible == 1);
    CHECK(shell_dep_graph_validate(&source_graph).valid);
    free(graph_limits.workspace);
    free(scratch);
  }

  static const char expanding[] =
      "cat <<${x:-\"EOF\"}\n$(printf INSPECT)\n${x:-\"EOF\"}\n";
  source_parse(expanding);
  CHECK(shell_parse_draft(expanding, sizeof(expanding) - 1, NULL,
                          &source_draft) == SHELL_SOURCE_COMPLETE);
  CHECK(source_draft.header_count == 2 && source_draft.heredoc_count == 1);
  CHECK(!(source_draft.heredocs[0].content.flags &
          SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL));
  content(&source_draft.heredocs[0].content, "$(printf INSPECT)\n");

  static const char resolved_source[] =
      "cat $ARG <<$(printf   eof)\npayload\n$(printf eof)\n";
  source_delimiter_resolution_t domain = {
      .source = resolved_source,
      .start = (size_t)(strstr(resolved_source, "$(printf") - resolved_source),
      .end = (size_t)(strchr(resolved_source, '\n') - resolved_source)};
  shell_dep_limits_t resolved = limits;
  CHECK(shell_dep_resolved_workspace_size(sizeof(resolved_source) - 1,
                                          &resolved, &resolved.workspace_size));
  resolved.workspace = malloc(resolved.workspace_size);
  CHECK(resolved.workspace);
  CHECK(shell_dep_graph_parse_resolved(
            resolved_source, sizeof(resolved_source) - 1, "/workspace",
            &resolved, &source_graph, delimiter_resolution, &domain,
            NULL) == SHELL_DEP_OK);
  CHECK(domain.calls == 1);
  free(resolved.workspace);

  static const char *const unsupported[] = {
      "echo before; cat <<$\"EOF\"\n",
      "echo before; cat <<${x:-$\"EOF\"}\n",
      "echo before; cat <<$(if true; then echo EOF; fi)\n",
      "echo before; cat <<$(echo &&)\n",
      "echo before; cat <<$( ((1)) )\n",
      "echo before; cat <<${ echo  EOF; }\n",
      "echo before; cat <<${|echo EOF;}\n",
      "echo before; cat <<$(a | ! b)\n",
      "echo before; cat <<$(in)\n",
      "echo before; cat <<$(]])\n",
      "echo before; cat <<$'\\u00e9'\n",
      "echo before; cat <<${x:-$'\\u00e9'}\n",
      "echo before; cat <<$(i\\\nf true; th\\\nen :; f\\\ni)\n",
      "echo before; cat <<$(f\\\nor x in a; d\\\no :; d\\\none)\n",
      "echo before; cat <<$(wh\\\nile false; d\\\no :; d\\\none)\n",
  };
  for (size_t c = 0; c < sizeof(unsupported) / sizeof(unsupported[0]); c++) {
    CHECK(shell_parse_draft(unsupported[c], strlen(unsupported[c]), NULL,
                            &source_draft) == SHELL_SOURCE_UNSUPPORTED);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  }

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
#endif
  for (size_t depth = 4; depth <= 48; depth *= 2) {
    char source[2048];
    size_t at = 0;
    memcpy(source, "cat <<", 6);
    at = 6;
    for (size_t d = 0; d < depth; d++) {
      memcpy(source + at, "${\\\n#x:-", 8);
      at += 8;
    }
    size_t leaf = at;
    memset(source + at, 'x', 1024);
    at += 1024;
    memset(source + at, '}', depth);
    at += depth;
    source[at++] = '\n';
    size_t size;
    CHECK(shell_source_workspace_size(at, &size));
    void *scratch = malloc(size);
    CHECK(scratch);
    shell_limits_t storage = SHELL_LIMITS_DEFAULT;
    storage.workspace = scratch;
    storage.workspace_size = size;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
    shellsplit_test_delimiter_watch(source + leaf, 1024);
#endif
    CHECK(shell_parse_draft(source, at, &storage, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t work = shellsplit_test_delimiter_work();
    CHECK(work && work <= 32 * 1024);
    CHECK(!previous || work <= previous + 1024);
    previous = work;
    shellsplit_test_delimiter_watch("", 0);
#else
    (void)leaf;
#endif
    storage.workspace_size = 257;
    CHECK(shell_parse_draft(source, at, &storage, &source_draft) ==
          SHELL_SOURCE_TRUNCATED);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
    free(scratch);
  }

  /* A duplicate operand can contain the next duplicate's whole subtree.
   * Move classification must compose cached lexical tails, not print every
   * ancestor operand just to discover its final byte. */
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  previous = 0;
#endif
  for (size_t depth = 4; depth <= 16; depth *= 2) {
    char source[2048];
    size_t at = 6;
    memcpy(source, "cat <<", at);
    for (size_t d = 0; d < depth; d++) {
      memcpy(source + at, "$(a >&", 6);
      at += 6;
    }
    size_t leaf = at;
    memset(source + at, 'x', 1024);
    at += 1024;
    for (size_t d = 0; d < depth; d++) {
      memcpy(source + at, ")-", 2);
      at += 2;
    }
    source[at++] = '\n';
    size_t size;
    CHECK(shell_source_workspace_size(at, &size));
    void *scratch = malloc(size);
    CHECK(scratch);
    shell_limits_t storage = SHELL_LIMITS_DEFAULT;
    storage.workspace = scratch;
    storage.workspace_size = size;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
    shellsplit_test_delimiter_watch(source + leaf, 1024);
#endif
    CHECK(shell_parse_draft(source, at, &storage, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t work = shellsplit_test_delimiter_work();
    CHECK(work && work <= 32 * 1024);
    CHECK(!previous || work <= previous + 1024);
    previous = work;
#else
    (void)leaf;
#endif
    free(scratch);
  }

  /* Exhaustion while probing a nested document must stop collection before
   * any body matcher consumes a missing prepared delimiter. */
  char nested[1024];
  size_t at = strlen("echo before; cat <<$(cat <<'");
  memcpy(nested, "echo before; cat <<$(cat <<'", at);
  memset(nested + at, 'E', 400);
  at += 400;
  memcpy(nested + at, "'\nbody\n", 7);
  at += 7;
  memset(nested + at, 'E', 400);
  at += 400;
  memcpy(nested + at, "\n)\n", 3);
  at += 3;
  size_t size;
  CHECK(shell_source_workspace_size(at, &size));
  void *scratch = malloc(size);
  CHECK(scratch);
  shell_limits_t storage = SHELL_LIMITS_DEFAULT;
  storage.workspace = scratch;
  storage.workspace_size = 257;
  CHECK(shell_parse_draft(nested, at, &storage, &source_draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  storage.workspace_size = size;
  CHECK(shell_parse_draft(nested, at, &storage, &source_draft) ==
        SHELL_SOURCE_INCOMPLETE);
  free(scratch);
}

static void source_pending_redirectors(void) {
  static const char prefix[] = "echo before; ";
  static const char *const compounds[] = {"{ :; } ", "( : ) ", "time { :; } ",
                                          "{ :; } >existing ",
                                          "( : ) >existing "};
  static const struct {
    const char *received, *completion;
    bool escape;
  } cases[] = {
      {"2", ">out", false},          {"0002", ">out", false},
      {"2147483647", ">out", false}, {"{", "fd}>out", false},
      {"{f", "d}>out", false},       {"{fd", "}>out", false},
      {"{fd}", ">out", false},       {"{_x9}", ">out", false},
      {"00\\\n02", ">out", false},   {"{f\\\nd}", ">out", false},
      {"{fd}\\\n", ">out", false},   {"{\\\n", "fd}>out", false},
      {"2\\", "\n>out", true},       {"{\\", "\nfd}>out", true},
      {"{fd\\", "\n}>out", true},    {"{fd}\\", "\n>out", true},
  };
  static const char *const invalid[] = {
      "2 ",         "2\n",        "2;",
      "2 #comment", "2147483648", "99999999999999999999999999999999999",
      "'2'",        "\\2",        "{9",
      "{}",         "{fd-x",      "{fd}x",
      "{fd} ",      "{fd}\\ ",    "{fd}\\\\",
      "{ ",         "'",          "\"",
      "`",          "$(",         "${",
      "{fd}'",      "{f'",        "2\""};
  static const struct {
    const char *word, *completion;
    shell_source_need_t need;
  } operands[] = {
      {"2>&\"$(printf 1) tail", "\"", SHELL_SOURCE_NEEDS_QUOTE},
      {"> <(printf 1", ")", SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {">\"$(printf out) tail", "\"", SHELL_SOURCE_NEEDS_QUOTE},
      {">file\" tail", "\"", SHELL_SOURCE_NEEDS_QUOTE},
  };
  char source[512];
  for (size_t c = 0; c < sizeof(compounds) / sizeof(compounds[0]); c++) {
    int count = snprintf(source, sizeof(source), "%s%s", prefix, compounds[c]);
    CHECK(count > 0 && (size_t)count < sizeof(source));
    size_t start = (size_t)count;
    CHECK(shell_parse_draft(source, start, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.header_count == 3 && source_draft.headers[2].complete);
    shell_source_header_t child = source_draft.headers[2];
    uint32_t redirects = source_draft.redirect_count;
    shell_source_redirect_t existing = {0};
    if (redirects)
      existing = source_draft.redirects[0];
    for (size_t t = 0; t < sizeof(cases) / sizeof(cases[0]); t++) {
      count = snprintf(source, sizeof(source), "%s%s%s", prefix, compounds[c],
                       cases[t].received);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      size_t length = strlen(source);
      CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.need == (cases[t].escape
                                      ? SHELL_SOURCE_NEEDS_ESCAPE
                                      : SHELL_SOURCE_NEEDS_REDIRECT));
      CHECK(source_draft.incomplete_at ==
            (cases[t].escape ? length - 1 : start));
      CHECK(source_draft.prefix_length == strlen("echo before;") &&
            source_draft.tail_start == source_draft.prefix_length);
      CHECK(source_draft.header_count == 3 &&
            source_draft.headers[0].complete &&
            !source_draft.headers[1].complete &&
            source_draft.headers[1].compound &&
            !source_draft.headers[1].word_count &&
            !source_draft.headers[1].assignment_count);
      CHECK(source_draft.headers[1].source.start +
                source_draft.headers[1].source.length ==
            length);
      CHECK(shellsplit_test_header_equal(&child, &source_draft.headers[2]));
      CHECK(source_draft.redirect_count == redirects);
      if (redirects) {
        bool equal = shellsplit_test_redirect_equal(&existing,
                                                    &source_draft.redirects[0]);
        if (!equal)
          fprintf(stderr, "pending redirector compound %zu case %zu: %s\n", c,
                  t, source);
        CHECK(equal);
      }
      strcpy(source + length, cases[t].completion);
      length = strlen(source);
      CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(source_draft.headers[1].complete &&
            !source_draft.headers[1].word_count &&
            source_draft.redirect_count == redirects + 1);
      CHECK(shellsplit_test_header_equal(&child, &source_draft.headers[2]));
      if (redirects) {
        CHECK(shellsplit_test_io_equal(&existing.io,
                                       &source_draft.redirects[0].io));
        CHECK(existing.header == source_draft.redirects[0].header &&
              existing.heredoc == source_draft.redirects[0].heredoc &&
              source_draft.redirects[0].next == redirects);
      }
      for (size_t cut = 0; cut <= length; cut++) {
        shell_source_status_t status =
            shell_parse_draft(source, cut, NULL, &source_draft);
        if (status != SHELL_SOURCE_COMPLETE &&
            status != SHELL_SOURCE_INCOMPLETE)
          fprintf(stderr, "redirector cut %zu: %.*s (status %d)\n", cut,
                  (int)cut, source, status);
        CHECK(status == SHELL_SOURCE_COMPLETE ||
              status == SHELL_SOURCE_INCOMPLETE);
      }
      count = snprintf(source, sizeof(source), "%secho $( %s%s%s)", prefix,
                       compounds[c], cases[t].received,
                       cases[t].escape ? "\n" : "");
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
      count = snprintf(source, sizeof(source), "%s{ %s%s", prefix, compounds[c],
                       cases[t].received);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.header_count == 4 &&
            !source_draft.headers[1].complete &&
            !source_draft.headers[2].complete &&
            !source_draft.headers[2].word_count &&
            source_draft.headers[3].complete &&
            source_draft.prefix_length == strlen("echo before;"));
      shell_source_header_t nested_child = source_draft.headers[3];
      count += snprintf(source + count, sizeof(source) - (size_t)count, "%s; }",
                        cases[t].completion);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(source_draft.header_count == 4 &&
            source_draft.headers[1].complete &&
            source_draft.headers[2].complete &&
            !source_draft.headers[2].word_count &&
            shellsplit_test_header_equal(&nested_child,
                                         &source_draft.headers[3]));
    }
    for (size_t t = 0; t < sizeof(invalid) / sizeof(invalid[0]); t++) {
      count = snprintf(source, sizeof(source), "%s%s%s", prefix, compounds[c],
                       invalid[t]);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!source_draft.prefix_length && !source_draft.prefix.count &&
            !source_draft.tail_start);
    }
    for (size_t t = 0; t < sizeof(operands) / sizeof(operands[0]); t++) {
      count = snprintf(source, sizeof(source), "%s%s%s", prefix, compounds[c],
                       operands[t].word);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.need == operands[t].need &&
            source_draft.prefix_length == strlen("echo before;") &&
            !source_draft.headers[1].complete &&
            !source_draft.headers[1].word_count);
      CHECK(shellsplit_test_header_equal(&child, &source_draft.headers[2]));
      strcpy(source + count, operands[t].completion);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(!source_draft.headers[1].word_count &&
            shellsplit_test_header_equal(&child, &source_draft.headers[2]));
    }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (unsigned kind = 0; kind < 3; kind++) {
    size_t previous = 0;
    for (size_t length = 256; length <= 2048; length *= 2) {
      char large[8192];
      size_t at = strlen("echo before; { :; } ");
      memcpy(large, "echo before; { :; } ", at);
      large[at++] = kind == 1 ? '{' : '0';
      for (size_t n = 0; n < length; n++) {
        large[at++] = kind == 1 ? 'f' : kind == 2 ? '\\' : '0';
        if (kind == 2)
          large[at++] = '\n';
      }
      shellsplit_test_source_scan_reset();
      CHECK(shell_parse_draft(large, at, NULL, &source_draft) ==
            SHELL_SOURCE_INCOMPLETE);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work >= length && (!previous || work <= 3 * previous));
      previous = work;
    }
  }
#endif
}

static void source_missing_redirect_operands(void) {
  static const char prefix[] = "echo ok; ";
  static const char *const commands[] = {"cat ", "{ :; } ", "( : ) "};
  static const char *const redirects[] = {">&",  "<&",     "2>&",
                                          "0<&", "{fd}>&", "{fd}<&"};
  static const char *const trivia[] = {"", " ", "\t", "\\\n", " \t\\\n "};
  static const char *const invalid[] = {
      "\n", ";",   " #comment", " && cat", " | cat",
      " )", " < ", " > ",       " <\\\n ", " >\\\n "};
  static const char *const operands[] = {
      "1",       " 1",      " \"1\"",      " $(printf 1)",
      " <(cat)", " >(cat)", " <\\\n(cat)", " >\\\n(cat)"};
  char source[256];
  for (size_t c = 0; c < sizeof(commands) / sizeof(commands[0]); c++) {
    for (size_t r = 0; r < sizeof(redirects) / sizeof(redirects[0]); r++) {
      int count = snprintf(source, sizeof(source), "%s%s%s", prefix,
                           commands[c], redirects[r]);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      size_t received = (size_t)count;
      shell_source_header_t closed_child = {0};
      for (size_t t = 0; t < sizeof(trivia) / sizeof(trivia[0]); t++) {
        strcpy(source + received, trivia[t]);
        CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
              SHELL_SOURCE_INCOMPLETE);
        CHECK(source_draft.need == SHELL_SOURCE_NEEDS_REDIRECT);
        CHECK(source_draft.incomplete_at ==
              strlen(prefix) + strlen(commands[c]));
        CHECK(source_draft.prefix_length == strlen("echo ok;") &&
              source_draft.tail_start == source_draft.prefix_length);
        if (!(source_draft.header_count >= 2 &&
              source_draft.headers[0].complete &&
              !source_draft.headers[1].complete))
          fprintf(stderr,
                  "missing redirect header: %s headers=%u first=%d second=%d\n",
                  source, source_draft.header_count,
                  source_draft.headers[0].complete,
                  source_draft.headers[1].complete);
        CHECK(source_draft.header_count >= 2 &&
              source_draft.headers[0].complete &&
              !source_draft.headers[1].complete);
        if (c != 0) {
          CHECK(source_draft.header_count == 3 &&
                source_draft.headers[2].complete);
          if (t == 0)
            closed_child = source_draft.headers[2];
          CHECK(shellsplit_test_header_equal(&closed_child,
                                             &source_draft.headers[2]));
        }
      }
      for (size_t b = 0; b < sizeof(invalid) / sizeof(invalid[0]); b++) {
        strcpy(source + received, invalid[b]);
        CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
              SHELL_SOURCE_INVALID);
        CHECK(!source_draft.prefix_length && !source_draft.prefix.count &&
              !source_draft.tail_start);
        for (uint32_t h = 0; h < source_draft.header_count; h++)
          CHECK(!source_draft.headers[h].complete);
      }
      for (size_t o = 0; o < sizeof(operands) / sizeof(operands[0]); o++) {
        strcpy(source + received, operands[o]);
        size_t length = strlen(source);
        CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE);
        CHECK(source_draft.headers[1].complete &&
              source_draft.prefix_length == length);
        if (c != 0)
          CHECK(shellsplit_test_header_equal(&closed_child,
                                             &source_draft.headers[2]));
        for (size_t cut = 0; cut <= length; cut++) {
          shell_source_status_t status =
              shell_parse_draft(source, cut, NULL, &source_draft);
          if (status != SHELL_SOURCE_COMPLETE &&
              status != SHELL_SOURCE_INCOMPLETE)
            fprintf(stderr, "redirect operand cut %zu: %.*s (status %d)\n", cut,
                    (int)cut, source, status);
          CHECK(status == SHELL_SOURCE_COMPLETE ||
                status == SHELL_SOURCE_INCOMPLETE);
        }
      }
      /* A closing child commits the missing operand. An open child instead
       * retains its local incomplete header under the outer substitution. */
      count = snprintf(source, sizeof(source), "%secho $( %s%s", prefix,
                       commands[c], redirects[r]);
      CHECK(count > 0 && (size_t)count + 2 < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.prefix_length == strlen("echo ok;") &&
            source_draft.header_count >= 3 &&
            !source_draft.headers[1].complete &&
            !source_draft.headers[2].complete);
      strcpy(source + count, ")");
      CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
      strcpy(source + count, ";)");
      CHECK(shell_parse_draft(source, strlen(source), NULL, &source_draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
    }
  }
}

static void source_nested_redirect_recovery(void) {
  static const char prefix[] = "echo before; ";
  static const char reported[] = "echo before; echo $(cat > <(printf out";
  CHECK(shell_parse_draft(reported, sizeof(reported) - 1, NULL,
                          &source_draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.need == SHELL_SOURCE_NEEDS_SUBSTITUTION &&
        source_draft.incomplete_at == strlen("echo before; echo ") &&
        source_draft.prefix_length == strlen("echo before;"));
  static const char *const openings[] = {"echo $( ", "cat <( ", "cat >( ",
                                         "echo `"};
  static const char *const closings[] = {")", ")", ")", "`"};
  static const char *const commands[] = {"cat 2>existing", "{ :; } 2>existing",
                                         "( : ) 2>existing"};
  static const char *const operands[] = {" > <(printf out", " > >(printf out",
                                         " >`printf out"};
  static const char *const ends[] = {")", ")", "`"};
  char source[256];
  for (size_t o = 0; o < sizeof(openings) / sizeof(openings[0]); o++)
    for (size_t c = 0; c < sizeof(commands) / sizeof(commands[0]); c++)
      for (size_t r = 0; r < sizeof(operands) / sizeof(operands[0]); r++) {
        if (o == 3 && r == 2)
          continue; /* Nested backticks require an unsupported escape layer. */
        int count = snprintf(source, sizeof(source), "%s%s%s%s", prefix,
                             openings[o], commands[c], operands[r]);
        CHECK(count > 0 && (size_t)count < sizeof(source));
        size_t received = (size_t)count;
        CHECK(shell_parse_draft(source, received, NULL, &source_draft) ==
              SHELL_SOURCE_INCOMPLETE);
        CHECK(source_draft.need == SHELL_SOURCE_NEEDS_SUBSTITUTION &&
              source_draft.prefix_length == strlen("echo before;") &&
              source_draft.tail_start == source_draft.prefix_length);
        size_t opener =
            (size_t)(strchr(source + strlen(prefix), o == 3 ? '`' : '(') -
                     source);
        CHECK(source_draft.incomplete_at == (o == 3 ? opener : opener - 1));
        uint32_t headers = c == 0 ? 4 : 5;
        /* A pending process-substitution word has no framed operation yet;
         * the lexer can retain the unfinished backtick operand itself. */
        uint32_t redirects = r == 2 ? 2 : 1;
        if (source_draft.header_count != headers ||
            source_draft.redirect_count != redirects ||
            source_draft.redirects[0].header != 2)
          fprintf(
              stderr,
              "nested redirect metadata: %s headers=%u redirects=%u owner=%u\n",
              source, source_draft.header_count, source_draft.redirect_count,
              source_draft.redirects[0].header);
        CHECK(source_draft.header_count == headers &&
              source_draft.headers[0].complete &&
              !source_draft.headers[1].complete &&
              !source_draft.headers[2].complete &&
              source_draft.redirect_count == redirects &&
              source_draft.redirects[0].header == 2);
        shell_group_io_op_t existing = source_draft.redirects[0].io;
        shell_source_header_t leaf = source_draft.headers[headers - 1];
        CHECK(leaf.complete && leaf.word_count == 2 &&
              leaf.source.start ==
                  (size_t)(strstr(source, "printf") - source) &&
              leaf.source.length == strlen("printf out"));
        shell_source_header_t closed = {0};
        if (c != 0) {
          closed = source_draft.headers[3];
          CHECK(closed.complete && !source_draft.headers[2].word_count);
        }
        count += snprintf(source + received, sizeof(source) - received, "%s%s",
                          ends[r], closings[o]);
        CHECK(count > 0 && (size_t)count < sizeof(source));
        CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
              SHELL_SOURCE_COMPLETE);
        CHECK(source_draft.header_count == headers &&
              source_draft.redirect_count == 2 &&
              source_draft.redirects[0].header == 2 &&
              shellsplit_test_io_equal(&existing,
                                       &source_draft.redirects[0].io) &&
              shellsplit_test_header_equal(&leaf,
                                           &source_draft.headers[headers - 1]));
        if (c != 0)
          CHECK(
              shellsplit_test_header_equal(&closed, &source_draft.headers[3]));
        for (size_t cut = 0; cut <= (size_t)count; cut++) {
          shell_source_status_t status =
              shell_parse_draft(source, cut, NULL, &source_draft);
          if (status != SHELL_SOURCE_COMPLETE &&
              status != SHELL_SOURCE_INCOMPLETE)
            fprintf(stderr, "nested redirect cut %zu: %.*s (status %d)\n", cut,
                    (int)cut, source, status);
          CHECK(status == SHELL_SOURCE_COMPLETE ||
                status == SHELL_SOURCE_INCOMPLETE);
          if (cut >= received && cut < (size_t)count)
            CHECK(source_draft.prefix_length == strlen("echo before;"));
        }
      }
  static const char *const invalid[] = {
      "echo before; echo $(cat > <(echo &&) tail",
      "echo before; cat <(cat > >(echo &&) tail",
      "echo before; echo $( { :; } ordinary'",
      "echo before; cat >( ( : ) ordinary\"",
      "echo before; echo $(cat >\n",
      "echo before; echo $(cat 2>&;",
      "echo before; echo $( { :; } {fd}) tail",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    CHECK(shell_parse_draft(invalid[i], strlen(invalid[i]), NULL,
                            &source_draft) == SHELL_SOURCE_INVALID);
    CHECK(!source_draft.prefix_length && !source_draft.prefix.count &&
          !source_draft.tail_start);
  }

  static const struct {
    const char *received, *completion;
    shell_source_need_t need;
  } documents[] = {
      {"echo before; echo $(cat <<DOC\n$(cat > <(printf out", "))\nDOC\n)",
       SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"echo before; cat <<DOC\n$( { :; } > <(printf out", "))\nDOC\n",
       SHELL_SOURCE_NEEDS_HEREDOC_BODY},
  };
  for (size_t d = 0; d < sizeof(documents) / sizeof(documents[0]); d++) {
    size_t length = strlen(documents[d].received);
    CHECK(shell_parse_draft(documents[d].received, length, NULL,
                            &source_draft) == SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.need == documents[d].need &&
          source_draft.prefix_length == strlen("echo before;") &&
          source_draft.header_count == 5 && source_draft.heredoc_count == 1 &&
          !source_draft.heredocs[0].complete &&
          source_draft.heredocs[0].body_started);
    size_t at =
        d == 0 ? strlen("echo before; echo ") : strlen("echo before; cat ");
    CHECK(source_draft.incomplete_at == at);
    shell_source_header_t leaf = source_draft.headers[4];
    CHECK(leaf.complete && leaf.word_count == 2);
    int count = snprintf(source, sizeof(source), "%s%s", documents[d].received,
                         documents[d].completion);
    CHECK(count > 0 && (size_t)count < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)count, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.heredocs[0].complete &&
          shellsplit_test_header_equal(&leaf, &source_draft.headers[4]));
    for (size_t cut = 0; cut <= (size_t)count; cut++) {
      shell_source_status_t status =
          shell_parse_draft(source, cut, NULL, &source_draft);
      CHECK(status == SHELL_SOURCE_COMPLETE ||
            status == SHELL_SOURCE_INCOMPLETE);
    }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned depth = 1; depth <= 8; depth *= 2) {
    char nested[2048];
    size_t at = strlen(prefix);
    memcpy(nested, prefix, at);
    for (unsigned n = 0; n < depth; n++) {
      memcpy(nested + at, "echo $(cat > <(", 15);
      at += 15;
    }
    memcpy(nested + at, "printf ", 7);
    at += 7;
    size_t leaf = at;
    memset(nested + at, 'x', 1024);
    at += 1024;
    shellsplit_test_source_scan_reset();
    shellsplit_test_delimiter_watch(nested + leaf, 1024);
    CHECK(shell_parse_draft(nested, at, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.prefix_length == strlen("echo before;"));
    size_t visits = shellsplit_test_delimiter_work();
    if (visits > 8 * 1024)
      fprintf(stderr, "nested recovery leaf visits: depth=%u visits=%zu\n",
              depth, visits);
    CHECK(visits && visits <= 8 * 1024);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(!previous || work <= 3 * previous);
    previous = work;
  }
#endif
}

static void source_duplication_recovery(void) {
  static const struct {
    const char *received, *suffix;
  } cases[] = {
      {"echo ok; cat 2>&\"${fd", ":-1}\""},
      {"echo ok; cat 2>&\"$(printf 1", ")\""},
      {"echo ok; cat <&\"$((1 +", " 1))\""},
      {"echo ok; cat {target}<& \t\\\n \"${fd", ":-0}\""},
      {"echo ok; cat 2>&\"$(printf 1) ${fd", ":-1}\""},
      {"echo ok; cat >&\"$(printf out) tail", "\""},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].received;
    size_t length = strlen(source);
    CHECK(shell_parse_draft(source, length, NULL, &source_draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.prefix_length == strlen("echo ok;"));
    CHECK(source_draft.headers[0].complete &&
          !source_draft.headers[1].complete);
    CHECK(source_draft.redirect_count == 1);
    const shell_source_redirect_t *redirect = &source_draft.redirects[0];
    CHECK(redirect->io.kind != SHELL_GROUP_IO_FAILED_REDIRECT);
    CHECK(redirect->io.target_fd == SHELL_PROCESS_FD_NONE);
    uint32_t headers = source_draft.header_count;
    bool closed_child = headers > 2 && source_draft.headers[2].complete;
    shell_source_header_t child;
    if (closed_child)
      child = source_draft.headers[2];
    char completed[256];
    int count =
        snprintf(completed, sizeof(completed), "%s%s", source, cases[c].suffix);
    CHECK(count > 0 && (size_t)count < sizeof(completed));
    CHECK(shell_parse_draft(completed, (size_t)count, NULL, &source_draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(source_draft.header_count == headers);
    if (closed_child)
      CHECK(shellsplit_test_header_equal(&child, &source_draft.headers[2]));
    size_t first_quote = (size_t)(strchr(completed, '"') - completed);
    for (size_t cut = first_quote; cut < (size_t)count; cut++) {
      shell_source_status_t status =
          shell_parse_draft(completed, cut, NULL, &source_draft);
      if (status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "duplication cut case=%zu cut=%zu status=%d\n", c, cut,
                status);
      CHECK(status == SHELL_SOURCE_INCOMPLETE);
      CHECK(source_draft.prefix_length == strlen("echo ok;"));
    }
  }
  static const char invalid[] = "echo ok; cat 2>&\"$(echo &&) tail";
  CHECK(shell_parse_draft(invalid, sizeof(invalid) - 1, NULL, &source_draft) ==
        SHELL_SOURCE_INVALID);
  CHECK(!source_draft.prefix_length);
}

typedef struct {
  const char *source;
  size_t length;
  shell_limits_t limits;
  unsigned calls;
} source_reentrant_source_t;

static shell_expand_status_t
source_reentrant_source(const shell_expand_word_request_t *request,
                        const char **records, size_t *record_length,
                        void *context) {
  (void)request;
  (void)records;
  (void)record_length;
  source_reentrant_source_t *input = context;
  input->calls++;
  CHECK(shell_parse_draft(input->source, input->length, NULL, &source_draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(shell_parse_draft(input->source, input->length, &input->limits,
                          &source_draft) == SHELL_SOURCE_COMPLETE);
  return SHELL_EXPAND_UNRESOLVED;
}

static void source_delimiter_workspace(void) {
  size_t word_length = 70000, length = word_length * 2 + 17;
  char *source = malloc(length);
  unsigned char *scratch = malloc(length);
  CHECK(source && scratch);
  size_t at = 0;
  memcpy(source, "cat <<'", 7);
  at += 7;
  memset(source + at, 'E', word_length);
  at += word_length;
  memcpy(source + at, "'\nx\n", 4);
  at += 4;
  memset(source + at, 'E', word_length);
  at += word_length;
  source[at++] = '\n';
  CHECK(at <= length);
  CHECK(shell_parse_draft(source, at, NULL, &source_draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  shell_limits_t scratch_limits = SHELL_LIMITS_DEFAULT;
  scratch_limits.workspace = scratch;
  scratch_limits.workspace_size = length;
  CHECK(shell_parse_draft(source, at, &scratch_limits, &source_draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(source_draft.heredoc_count == 1 && source_draft.heredocs[0].complete);
  content(&source_draft.heredocs[0].content, "x\n");
  shell_parse_result_t fast;
  scratch_limits.strict_mode = true;
  CHECK(shell_parse_fast(source, at, &scratch_limits, &fast) == SHELL_OK);
  CHECK(shell_parse_fast(source, at, NULL, &fast) == SHELL_ETRUNC);
  shell_tokenizer_state_t lexer;
  CHECK(shell_tokenizer_init(&lexer, source, at, &scratch_limits));
  shell_token_t token;
  unsigned documents = 0;
  while (shell_tokenizer_next(&lexer, &token))
    documents += token.type == SHELL_TOKEN_HEREDOC;
  CHECK(!lexer.heredoc_error && documents == 1);
  shell_dep_limits_t fixed_limits = limits;
  CHECK(shell_dep_workspace_size(NULL, &fixed_limits.workspace_size));
  CHECK(shell_dep_graph_parse(source, at, "/workspace", &fixed_limits,
                              &source_graph) == SHELL_DEP_EWORKSPACE);
  size_t original_size = limits.workspace_size;
  void *original_workspace = limits.workspace;
  void *larger = malloc(original_size + length);
  CHECK(larger);
  limits.workspace = larger;
  limits.workspace_size = original_size + length;
  CHECK(shell_dep_graph_parse(source, at, "/workspace", &limits,
                              &source_graph) == SHELL_DEP_OK);
  limits.workspace_size = original_size;
  source_reentrant_source_t input = {source, at, scratch_limits, 0};
  static const char outer[] = "echo \"$word\"";
  size_t resolved_size;
  CHECK(shell_dep_resolved_workspace_size(sizeof(outer) - 1, &limits,
                                          &resolved_size));
  shell_dep_limits_t resolved = limits;
  resolved.workspace = malloc(resolved_size);
  resolved.workspace_size = resolved_size;
  CHECK(resolved.workspace);
  CHECK(shell_dep_graph_parse_resolved(
            outer, sizeof(outer) - 1, "/workspace", &resolved, &source_graph,
            source_reentrant_source, &input, NULL) == SHELL_DEP_OK);
  CHECK(input.calls == 1 && shell_dep_graph_validate(&source_graph).valid);
  free(resolved.workspace);
  /* The same scratch contract applies to a document recovered from the body
   * of an unfinished backtick, not just a complete top-level declaration. */
  char *legacy = malloc(at + 6);
  CHECK(legacy);
  memcpy(legacy, "echo `", 6);
  memcpy(legacy + 6, source, at);
  CHECK(shell_parse_draft(legacy, at + 6, NULL, &source_draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!source_draft.prefix_length && !source_draft.prefix.count);
  CHECK(shell_parse_draft(legacy, at + 6, &scratch_limits, &source_draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(source_draft.header_count == 2 && source_draft.heredoc_count == 1 &&
        source_draft.heredocs[0].complete);
  content(&source_draft.heredocs[0].content, "x\n");
  free(legacy);
  free(larger);
  limits.workspace = original_workspace;
  free(source);
  free(scratch);
}

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
static void source_supplied_fast_reuse(void) {
  static const char opening[] = "cat <<'EOF'\n";
  static const char closing[] = "\nEOF\n";
  static const char tail[] = "echo \"";
  const size_t payload = 64 * 1024;
  const size_t length = sizeof(opening) - 1 + payload + sizeof(closing) - 1;
  char *source = malloc(length + sizeof(tail));
  CHECK(source);
  memcpy(source, opening, sizeof(opening) - 1);
  memset(source + sizeof(opening) - 1, 'x', payload);
  memcpy(source + sizeof(opening) - 1 + payload, closing, sizeof(closing) - 1);
  memcpy(source + length, tail, sizeof(tail));
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  for (unsigned high_bytes = 0; high_bytes < 2; high_bytes++) {
    if (high_bytes)
      memcpy(source + sizeof(opening) - 1 + payload / 2, "日本", 6);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, length, &strict, &fast) == SHELL_OK);
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          &fast,
                                          &source_graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == 0);
    CHECK(shell_dep_graph_validate(&source_graph).valid);

    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, length, "/workspace", &limits, &fast, &source_graph, NULL,
              unresolved) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == 0);
    CHECK(shell_dep_graph_validate(&source_graph).valid);

    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          NULL, &source_graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 1);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == length);

    CHECK(shell_parse_draft(source, length + sizeof(tail) - 1, NULL,
                            &source_draft) == SHELL_SOURCE_INCOMPLETE);
    CHECK(source_draft.prefix_length == length);
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast(
              source, source_draft.prefix_length, "/workspace", &limits,
              &source_draft.prefix, &source_graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == 0);
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, source_draft.prefix_length, "/workspace", &limits,
              &source_draft.prefix, &source_graph, NULL,
              unresolved) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == 0);
  }
  free(source);

  /* Capacity truncation is not a successful parse proof. Nor is an error
   * result: neither can enable the trusted-root shortcut. */
  static const char bounded[] = "echo one; echo two";
  strict.max_subcommands = 1;
  shell_parse_result_t fast;
  CHECK(shell_parse_fast(bounded, sizeof(bounded) - 1, &strict, &fast) ==
        SHELL_ETRUNC);
  shellsplit_test_source_scan_reset();
  CHECK(shell_dep_graph_parse_with_fast(bounded, sizeof(bounded) - 1,
                                        "/workspace", &limits, &fast,
                                        &source_graph) == SHELL_DEP_ETRUNC);
  CHECK(shellsplit_test_metadata_work(
            SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 1);
  /* A high-byte delimiter can exhaust scratch during byte admission, before
   * any ranges are produced. Retry graph diagnostics with sufficient scratch;
   * this truncated result must not bypass the domain validation either. */
  char large[1024];
  const char *declaration = "cat <<'日本";
  size_t at = strlen(declaration);
  memcpy(large, declaration, at);
  memset(large + at, 'E', 300);
  at += 300;
  memcpy(large + at, "'\npayload\n日本", strlen("'\npayload\n日本"));
  at += strlen("'\npayload\n日本");
  memset(large + at, 'E', 300);
  at += 300;
  large[at++] = '\n';
  strict.max_subcommands = SHELL_MAX_SUBCOMMANDS;
  CHECK(shell_parse_fast(large, at, &strict, &fast) == SHELL_ETRUNC);
  CHECK(!fast.count && fast.status == SHELL_STATUS_TRUNCATED);
  shell_dep_limits_t extra = limits;
  extra.workspace_size += at;
  extra.workspace = malloc(extra.workspace_size);
  CHECK(extra.workspace);
  shellsplit_test_source_scan_reset();
  CHECK(shell_dep_graph_parse_with_fast(large, at, "/workspace", &extra, &fast,
                                        &source_graph) == SHELL_DEP_ETRUNC);
  CHECK(shellsplit_test_metadata_work(
            SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 1);
  CHECK(!source_graph.node_count && !source_graph.edge_count);
  free(extra.workspace);
  static const char invalid[] = "echo && ;";
  strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  CHECK(shell_parse_fast(invalid, sizeof(invalid) - 1, &strict, &fast) ==
        SHELL_EPARSE);
  CHECK(shell_dep_graph_parse_with_fast(invalid, sizeof(invalid) - 1,
                                        "/workspace", &limits, &fast,
                                        &source_graph) == SHELL_DEP_EPARSE);
  CHECK(!source_graph.node_count && !source_graph.edge_count);
}

#endif

static void cwd(void) {
  static const struct {
    const char *source;
    const char *expected[4];
  } cases[] = {
      {"cd /workspace/src && cat input.c 2>&1 | head -n 2 other.c",
       {"/workspace", "/workspace/src", "/workspace/src"}},
      {"(cd /workspace/nested && cat 'a file.c'); cat root.c",
       {"/workspace", "/workspace/nested", "/workspace"}},
      {"cd /workspace/src || cat input.c", {"/workspace", "/workspace"}},
      {"cd /workspace/src; cat input.c", {"/workspace", NULL}},
      {"! cd /workspace/src || cat input.c", {"/workspace", "/workspace/src"}},
      {"cd $where && cat input.c", {"/workspace", NULL}},
      {"cd && cat input.c", {"/workspace", NULL}},
      {"HOME=tmp CDPATH=/; cd >&- || pwd", {"/workspace", "/workspace", NULL}},
      {"HOME=tmp CDPATH=/; ! cd >&- && pwd",
       {"/workspace", "/workspace", NULL}},
      {"cd -- >&- || cat input.c", {"/workspace", NULL}},
      {"(cd >&-); pwd", {"/workspace", "/workspace"}},
      {"cd >&- | cat; pwd", {"/workspace", "/workspace", "/workspace"}},
      {"cd >&- & pwd", {"/workspace", "/workspace"}},
      {"cd --invalid >&- || cat input.c", {"/workspace", "/workspace"}},
      {"cd .hidden && cat input.c", {"/workspace", NULL}},
      {"cd ... && cat input.c", {"/workspace", NULL}},
      {"cd ../src && cat input.c", {"/workspace", "/src"}},
      {"OLDPWD=/tmp; cd - >&- || pwd", {"/workspace", "/workspace", NULL}},
      {"CDPATH=/; cd tmp >&- || pwd", {"/workspace", "/workspace", NULL}},
      {"cd -Pe /tmp || pwd", {"/workspace", NULL}},
      {"! cd - >&- && pwd", {"/workspace", NULL}},
      {"cd /workspace/src | cat input.c; cat root.c",
       {"/workspace", "/workspace", "/workspace"}},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    source_parse(cases[c].source);
    unsigned command = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++) {
      if (source_graph.nodes[n].type != SHELL_NODE_CMD)
        continue;
      const shell_dep_cmd_t *cmd = &source_graph.nodes[n].cmd;
      const char *expected = cases[c].expected[command++];
      if (cmd->cwd_known != (expected != NULL))
        fprintf(stderr, "cwd mismatch: %s command %u known=%d\n",
                cases[c].source, command, cmd->cwd_known);
      CHECK(cmd->cwd_known == (expected != NULL));
      if (expected)
        CHECK(!strcmp(source_graph.cwd_buf.data + cmd->cwd_offset, expected));
    }
  }
  static const struct {
    const char *source;
    bool known;
  } files[] = {
      {"cd >&- || cat input.c", false},
      {"! cd >&- && cat input.c", false},
      {"cd --invalid >&- || cat input.c", true},
  };
  for (size_t c = 0; c < sizeof(files) / sizeof(files[0]); c++) {
    source_parse(files[c].source);
    unsigned matched = 0;
    for (uint32_t n = 0; n < source_graph.node_count; n++) {
      const shell_dep_node_t *node = &source_graph.nodes[n];
      if (node->type != SHELL_NODE_DOC || node->doc.kind != SHELL_DOC_FILE ||
          node->doc.path_len != strlen("input.c") ||
          memcmp(node->doc.path, "input.c", strlen("input.c")))
        continue;
      matched++;
      CHECK(node->doc.cwd_known == files[c].known);
      char path[64];
      shell_dep_file_identity_t file_identity = {0};

      CHECK(shell_dep_doc_file_identity_write(&source_graph, &node->doc, path,
                                              sizeof(path), &file_identity) ==
            files[c].known);
      if (files[c].known) {
        CHECK(file_identity.absolute &&
              file_identity.length == strlen("/workspace/input.c"));
        CHECK(!memcmp(path, "/workspace/input.c", file_identity.length));
      }
    }
    CHECK(matched == 1);
  }
}

static int run_source(int argc, char **argv) {
  (void)argc;
  (void)argv;
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 8192,
                                      0, false, 0));
  limits = fixture.limits;
  heredocs();
  source_special_parameter_extglob_tail();
  source_conditional_opener_needs_a_word_boundary();
  source_command_word_subscript();
  source_extglob_body_is_pattern_text();
  source_dollar_pair_does_not_open_a_parameter();
  source_ansi_byte_source();
  source_ansi_nul_words();
  source_nested_ansi_escape_context();
  source_parameter_word_phases();
  source_selector_recovery();
  source_tentative_delimiters();
  source_recovery();
  source_keyword_recovery();
  source_if_classification();
  source_backtick_escape_domains();
  source_capacity_and_work();
  source_forward_prefix_products();
  source_indexed_word_boundaries();
  source_indexed_prefix_uncertainty();
  source_indexed_boundary_work();
  source_delimiter_phases();
  source_delimiter_fragments();
  source_pending_redirectors();
  source_missing_redirect_operands();
  source_nested_redirect_recovery();
  source_duplication_recovery();
  source_delimiter_workspace();
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  source_supplied_fast_reuse();
#endif
  cwd();
  shellsplit_graph_fixture_destroy(&fixture);
  puts("source, draft, and static CWD contracts passed");
  return 0;
}
#undef CHECK

int main(int argc, char **argv) {
  return (run_status(argc, argv) | run_source(argc, argv)) != 0;
}
