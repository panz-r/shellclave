#include "shell_sequence.h"
#include "shell_source.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static shell_source_result_t draft;

static void check(const char *source, size_t length,
                  shell_source_status_t expected) {
  shell_source_status_t actual =
      shell_parse_draft(source, length, NULL, &draft);
  if (actual != expected)
    fprintf(stderr, "source status %d, expected %d: %.*s\n", actual, expected,
            (int)length, source);
  CHECK(actual == expected);
  if (actual != SHELL_SOURCE_COMPLETE && actual != SHELL_SOURCE_INCOMPLETE) {
    CHECK(!draft.prefix_length && !draft.tail_start && !draft.prefix.count &&
          !draft.prefix.group_count);
    for (uint32_t i = 0; i < draft.header_count; ++i)
      CHECK(!draft.headers[i].complete);
  }
}

static void heredoc_failure_domains(void) {
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
        check(source, (size_t)prefix + tail, cases[c].status);
        if (cases[c].status == SHELL_SOURCE_INCOMPLETE)
          CHECK(draft.prefix_length == (uint32_t)prefix &&
                draft.header_count == 2 && draft.headers[0].complete);
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
        check(source, used,
              count < SHELL_MAX_SUBCOMMANDS ? SHELL_SOURCE_INCOMPLETE
                                            : SHELL_SOURCE_TRUNCATED);
        /* The whole-source representation check still precedes both limits
         * and grammar. A late NUL must not become a prefix or a retry. */
        source[used++] = '\0';
        check(source, used, SHELL_SOURCE_INVALID_INPUT);
      }
    }
}

static void redirect_operator_boundaries(void) {
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
        check(source, (size_t)n, SHELL_SOURCE_INVALID);
      }
      for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        int n = snprintf(source, sizeof(source), "%s%s%s%s", heads[h],
                         prefixes[p], valid[i], h == 2 ? ")" : "");
        CHECK(n > 0 && (size_t)n < sizeof(source));
        check(source, (size_t)n, SHELL_SOURCE_COMPLETE);
        for (uint32_t j = 0; j < draft.header_count; ++j)
          CHECK(draft.headers[j].complete);
      }
    }
  const char *const received[] = {": <<<<", ": <<<>", "{ :; } <<<<",
                                  ": <<<\\\n<"};
  for (size_t i = 0; i < sizeof(received) / sizeof(received[0]); ++i) {
    check(received[i], strlen(received[i]), SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.need == SHELL_SOURCE_NEEDS_SUBSTITUTION);
  }
  check("cat <<'Q'\né\nQ\n: <<<<x", strlen("cat <<'Q'\né\nQ\n: <<<<x"),
        SHELL_SOURCE_INVALID);
}

int main(int argc, char **argv) {
  /* The Bash qualification driver supplies bytes without shell evaluation. */
  if (argc == 2 &&
      (!strcmp(argv[1], "--probe") || !strcmp(argv[1], "--argv"))) {
    char source[16384];
    size_t length = fread(source, 1, sizeof(source), stdin);
    CHECK(!ferror(stdin) && length < sizeof(source));
    if (!strcmp(argv[1], "--probe"))
      printf("%d\n", shell_parse_draft(source, length, NULL, &draft));
    else {
      shell_netstring_buffer_t encoded = {0};
      size_t count = 0;
      bool features = false;
      CHECK(shell_build_netargv_sequence_buffer(source, length, NULL, &encoded,
                                                &count,
                                                &features) == SHELL_PROCESS_OK);
      CHECK(count == 1 &&
            fwrite(encoded.data, 1, encoded.length, stdout) == encoded.length);
      shell_netstring_buffer_free(&encoded);
    }
    return EXIT_SUCCESS;
  }
  CHECK(argc == 1);
  heredoc_failure_domains();
  redirect_operator_boundaries();
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
      {"if true; then :; fi", SHELL_SOURCE_UNSUPPORTED},
      {"case x in x) :;; esac", SHELL_SOURCE_UNSUPPORTED},
      {"function f { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"f() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"foo.bar() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"foo-bar() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"1f() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"\"f\"() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"f\\ g() { :; }", SHELL_SOURCE_UNSUPPORTED},
      {"[[ -b input ]]", SHELL_SOURCE_UNSUPPORTED},
      {"((1 + 2))", SHELL_SOURCE_COMPLETE},
      {"(( $(printf 1; : 日本) ))", SHELL_SOURCE_COMPLETE},
      {"(( $(printf 日本 &&) ))", SHELL_SOURCE_INVALID},
      {"((日本))", SHELL_SOURCE_UNSUPPORTED},
      {"echo $(if true; then :; fi)", SHELL_SOURCE_UNSUPPORTED},
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
      {"echo before; if ", SHELL_SOURCE_UNSUPPORTED},
      {"printf '%s' '日本'\ncat <<\n", SHELL_SOURCE_INVALID},
      {"if true; then :; fi\ncat <<\n", SHELL_SOURCE_UNSUPPORTED},
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
    check(cases[i].source, strlen(cases[i].source), cases[i].status);
  const char nul[] = "printf '日本'\0; :";
  check(nul, sizeof(nul) - 1, SHELL_SOURCE_INVALID_INPUT);
  const char control_nul[] = "printf '\001'\0; :";
  check(control_nul, sizeof(control_nul) - 1, SHELL_SOURCE_INVALID_INPUT);

  shell_limits_t limits = SHELL_LIMITS_DEFAULT;
  limits.max_subcommands = 1;
  static const char two_commands[] = "printf a; printf b";
  CHECK(shell_parse_draft(two_commands, sizeof(two_commands) - 1, &limits,
                          &draft) == SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
  static const char grouped_delimiter[] =
      "cat <<$(printf EOF)\nbody\n$(printf EOF)\n";
  char tiny[1];
  limits = SHELL_LIMITS_DEFAULT;
  limits.workspace = tiny;
  limits.workspace_size = sizeof(tiny);
  CHECK(shell_parse_draft(grouped_delimiter, sizeof(grouped_delimiter) - 1,
                          &limits, &draft) == SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
  CHECK(shell_source_workspace_size(sizeof(grouped_delimiter) - 1,
                                    &limits.workspace_size));
  limits.workspace = malloc(limits.workspace_size);
  CHECK(limits.workspace);
  CHECK(shell_parse_draft(grouped_delimiter, sizeof(grouped_delimiter) - 1,
                          &limits, &draft) == SHELL_SOURCE_COMPLETE);
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
  check(nested, used, SHELL_SOURCE_TRUNCATED);
  used = 0;
  for (unsigned i = 0; i <= SHELL_MAX_SUBCOMMANDS; ++i) {
    memcpy(nested + used, "echo $(", 7);
    used += 7;
  }
  nested[used++] = ':';
  for (unsigned i = 0; i <= SHELL_MAX_SUBCOMMANDS; ++i)
    nested[used++] = ')';
  check(nested, used, SHELL_SOURCE_TRUNCATED);
  puts("typed source outcomes passed");
  return EXIT_SUCCESS;
}
