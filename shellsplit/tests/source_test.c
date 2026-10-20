#include "../src/shell_depgraph_internal.h"
#include "../src/shell_source_internal.h"
#include "shell_abstract.h"
#include "shell_sequence.h"
#include "shell_source.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
#ifdef SHELLSPLIT_TEST_ALLOCATOR
#include "test_allocator.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static shell_source_result_t draft;
static shell_dep_graph_t graph;
static shell_dep_limits_t limits;

static void parse(const char *source) {
  int error = shell_dep_graph_parse(source, strlen(source), "/workspace",
                                    &limits, &graph);
  if (error)
    fprintf(stderr, "graph error %d: %s\n", error, source);
  CHECK(error == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(&graph).valid);
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
    parse(source);
    unsigned docs = 0;
    for (uint32_t n = 0; n < graph.node_count; n++)
      if (graph.nodes[n].type == SHELL_NODE_DOC &&
          graph.nodes[n].doc.kind == SHELL_DOC_HEREDOC) {
        content(&graph.nodes[n].doc, cases[c].payload);
        docs++;
      }
    CHECK(docs == 1);
    int status = shell_parse_draft(source, strlen(source), NULL, &draft);
    if (status)
      fprintf(stderr, "draft status %d need %d: %s\n", status, draft.need,
              source);
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(draft.prefix_length == strlen(source));
    CHECK(draft.heredoc_count == 1 && draft.heredocs[0].complete);
    content(&draft.heredocs[0].content, cases[c].payload);
    CHECK(draft.headers[draft.heredocs[0].header].word_count == 1);
    CHECK(draft.redirects[draft.heredocs[0].redirect].heredoc == 0);
    CHECK(shell_dep_graph_parse_with_fast(source, draft.prefix_length,
                                          "/workspace", &limits, &draft.prefix,
                                          &graph) == SHELL_DEP_OK);
  }
}

/* The observer visits code, not the completion event's enclosing span. Quote
 * changes in parameter patterns must not turn heredoc literal bytes into code.
 * Conversely a child cannot hide code preceding it in a math operand. */
static void byte_domains(void) {
  static const char *const invalid[] = {
      "echo before; cat <<EOF\n$(( 日本 + $(printf 1) ))\nEOF\n",
      "echo before; cat <<EOF\n$(( $(printf 1) + 日本 ))\nEOF\n",
      "echo before; cat <<EOF\n${value:日本 + $(printf 1)}\nEOF\n",
      "echo before; cat <<EOF\n${value:$(printf 1) + 日本}\nEOF\n",
      "echo before; cat <<EOF\n$(( 日本",
      "echo before; cat <<EOF\n${value:日本",
      "echo before; cat <<EOF\n$(( $(printf 1) + 日本",
      "echo before; cat <<EOF\n${value:$(printf 1) + 日本",
      "echo before; cat <<EOF\n`echo 日本",
      "echo before; cat <<EOF\n$(echo 日本",
      "echo before; cat <<EOF\n${value[日本]}\nEOF\n",
  };
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); c++) {
    CHECK(shell_parse_draft(invalid[c], strlen(invalid[c]), NULL, &draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length && !draft.prefix.count && !draft.tail_start);
    CHECK(shell_dep_graph_parse(invalid[c], strlen(invalid[c]), "/workspace",
                                &limits, &graph) == SHELL_DEP_EPARSE);
  }
  static const char *const partial[] = {
      "echo before; cat <<EOF\n日本 $((1 +",
      "echo before; cat <<EOF\n日本 ${value:1 +",
      "echo before; cat <<EOF\n日本 ${value#語",
  };
  for (size_t c = 0; c < sizeof(partial) / sizeof(partial[0]); c++) {
    CHECK(shell_parse_draft(partial[c], strlen(partial[c]), NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo before;"));
  }
  static const char nested[] =
      "cat <<EOF\n日本 $(( $(cat <<'INNER'\n語\nINNER\n) + 1 )) 文\nEOF\n";
  CHECK(shell_parse_draft(nested, sizeof(nested) - 1, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.prefix.status == SHELL_STATUS_OK);
  CHECK(draft.heredoc_count == 2);
  content(&draft.heredocs[0].content,
          "日本 $(( $(cat <<'INNER'\n語\nINNER\n) + 1 )) 文\n");
  content(&draft.heredocs[1].content, "語\n");
}

static void selector_recovery(void) {
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
            shell_parse_draft(source, cut, NULL, &draft);
        if (status != SHELL_SOURCE_COMPLETE &&
            status != SHELL_SOURCE_INCOMPLETE)
          fprintf(stderr, "selector cut %zu status %d: %.*s\n", cut, status,
                  (int)cut, source);
        CHECK(status == SHELL_SOURCE_COMPLETE ||
              status == SHELL_SOURCE_INCOMPLETE);
        if (status == SHELL_SOURCE_INCOMPLETE && cut >= strlen("echo before; "))
          CHECK(draft.prefix_length == strlen("echo before;"));
        if (draft.prefix_length) {
          shell_limits_t strict = SHELL_LIMITS_DEFAULT;
          strict.strict_mode = true;
          shell_parse_result_t fast;
          CHECK(shell_parse_fast(source, draft.prefix_length, &strict, &fast) ==
                SHELL_OK);
          CHECK(!memcmp(&fast, &draft.prefix, sizeof(fast)));
        }
      }
      CHECK(draft.prefix_length == (size_t)size);
    }
  }
  static const char *const malformed[] = {
      "echo before; echo ${name.other}", "echo before; echo ${#@.}",
      "echo before; echo ${!prefix*x}", "echo before; echo ${name!\\"};
  for (size_t c = 0; c < sizeof(malformed) / sizeof(malformed[0]); c++) {
    CHECK(shell_parse_draft(malformed[c], strlen(malformed[c]), NULL, &draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length && !draft.prefix.count);
  }
}

static void tentative_delimiters(void) {
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
    CHECK(shell_parse_draft(source, received, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo before;") &&
          draft.header_count == 2);
    CHECK(draft.heredoc_count == 1 && draft.heredocs[0].delimiter_prefix);
    CHECK(!draft.heredocs[0].confirmed_length && !draft.heredocs[0].complete);
    content(&draft.heredocs[0].content, cases[c].candidate);
    size_t added = strlen(cases[c].suffix);
    CHECK(received + added < sizeof(source));
    memcpy(source + received, cases[c].suffix, added + 1);
    shell_source_status_t status = SHELL_SOURCE_INVALID;
    for (size_t cut = strlen("echo before; "); cut <= received + added; cut++) {
      status = shell_parse_draft(source, cut, NULL, &draft);
      if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "delimiter cut %zu case %zu status %d\n", cut, c,
                status);
      CHECK(status == SHELL_SOURCE_COMPLETE ||
            status == SHELL_SOURCE_INCOMPLETE);
      if (status == SHELL_SOURCE_INCOMPLETE)
        CHECK(draft.prefix_length == strlen("echo before;"));
    }
    CHECK(status == SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == 2 && draft.heredoc_count == 1 &&
          draft.heredocs[0].complete);
    CHECK(!(draft.heredocs[0].content.flags &
            SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL));
    content(&draft.heredocs[0].content, "");
    parse(source);
  }

  /* Actual outer quotes enable quote removal across the whole delimiter,
   * including otherwise-literal backtick interiors. ANSI-looking text inside
   * those interiors is still not an active ANSI-C quote. */
  static const char *const quoted[] = {
      "cat <<`\"x\"`'tail'\n$value\n`x`tail\n",
      "cat <<`$'\\x41'`'tail'\n$value\n`$\\x41`tail\n",
  };
  for (size_t c = 0; c < sizeof(quoted) / sizeof(quoted[0]); c++) {
    CHECK(shell_parse_draft(quoted[c], strlen(quoted[c]), NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == 1 && draft.heredoc_count == 1);
    CHECK(draft.heredocs[0].content.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL);
    content(&draft.heredocs[0].content, "$value\n");
    parse(quoted[c]);
  }

  /* A later mismatch makes the candidate real body data. Existing confirmed
   * children survive, and only then does a candidate's closed child appear. */
  char source[256] = "echo before; cat <<`x``y`\n$(printf good)\n`x`";
  size_t received = strlen(source);
  CHECK(shell_parse_draft(source, received, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.header_count == 3 && draft.heredocs[0].delimiter_prefix);
  CHECK(draft.heredocs[0].confirmed_length == strlen("$(printf good)\n"));
  memcpy(source + received, "z\n`x``y`\n", sizeof("z\n`x``y`\n"));
  CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.header_count == 4 && draft.heredocs[0].complete);
  content(&draft.heredocs[0].content, "$(printf good)\n`x`z\n");
  static const char *const bad_code[] = {
      "echo before; cat <<`日本`\n`日x\n",
      "echo before; cat <<`|`tail\n`|`z\n",
  };
  for (size_t c = 0; c < sizeof(bad_code) / sizeof(bad_code[0]); c++) {
    CHECK(shell_parse_draft(bad_code[c], strlen(bad_code[c]), NULL, &draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length && !draft.prefix.count);
  }
}

static void recovery(void) {
  const char *source =
      "cat /workspace/before.txt\ncat <<EOF\ncat /workspace/body.txt\n";
  CHECK(shell_dep_graph_parse(source, strlen(source), "/workspace", &limits,
                              &graph) == SHELL_DEP_EPARSE);
  CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.prefix_length == strlen("cat /workspace/before.txt\n"));
  CHECK(draft.tail_start == draft.prefix_length &&
        draft.need == SHELL_SOURCE_NEEDS_HEREDOC_BODY);
  CHECK(draft.header_count == 2 && draft.heredoc_count == 1);
  CHECK(draft.headers[1].word_count == 1);
  CHECK(!draft.heredocs[0].complete && draft.heredocs[0].header_complete);
  content(&draft.heredocs[0].content, "cat /workspace/body.txt\n");
  CHECK(shell_dep_graph_parse_with_fast(source, draft.prefix_length,
                                        "/workspace", &limits, &draft.prefix,
                                        &graph) == SHELL_DEP_OK);
  CHECK(shell_parse_draft("cat <<EOF\nalpha\nEO",
                          strlen("cat <<EOF\nalpha\nEO"), NULL,
                          &draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.heredocs[0].delimiter_prefix &&
        draft.heredocs[0].confirmed_length == 6);
  CHECK(shell_parse_draft("cat > target <<'EOF'\nalpha\n",
                          strlen("cat > target <<'EOF'\nalpha\n"), NULL,
                          &draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.headers[0].word_count == 1 &&
        draft.headers[0].redirect_count == 2);
  CHECK(draft.redirects[0].io.kind == SHELL_GROUP_IO_WRITE_FILE &&
        draft.redirects[0].next == 1);
  CHECK(draft.redirects[1].io.kind == SHELL_GROUP_IO_HEREDOC);
  static const char *unfinished[] = {
      "cat '",  "cat \"",     "cat $(echo", "cat ${value", "cat \\",
      "(cat",   "{ cat;",     "cat >",      "cat &&",      "cat |",
      "cat <<", "cat <<'EOF", "cat <<EOF"};
  for (size_t n = 0; n < sizeof(unfinished) / sizeof(unfinished[0]); n++) {
    int status =
        shell_parse_draft(unfinished[n], strlen(unfinished[n]), NULL, &draft);
    if (status != SHELL_SOURCE_INCOMPLETE)
      fprintf(stderr, "unfinished status %d: %s\n", status, unfinished[n]);
    CHECK(status == SHELL_SOURCE_INCOMPLETE && draft.prefix_length == 0);
  }
  static const char *invalid[] = {
      "cat >#comment",  "{ cat; } >#comment",
      "cat && ;",       "cat >\nfile",
      "cat )",          "cat | | echo",
      "echo 日本",      "cat <<EOF\n$(echo 日本)\nEOF\n",
      "({ echo; ) &&",  "echo $(echo &&) &&",
      "echo ${bad!} &&"};
  for (size_t n = 0; n < sizeof(invalid) / sizeof(invalid[0]); n++) {
    int status =
        shell_parse_draft(invalid[n], strlen(invalid[n]), NULL, &draft);
    if (status != SHELL_SOURCE_INVALID)
      fprintf(stderr, "invalid status %d: %s\n", status, invalid[n]);
    CHECK(status == SHELL_SOURCE_INVALID && draft.prefix_length == 0);
  }
  CHECK(shell_parse_draft("", 0, NULL, &draft) == SHELL_SOURCE_COMPLETE &&
        !draft.prefix_length);
  static const char whole[] =
      "echo before\n{ cat >target <<'EOF'; }\nalpha\nEOF\necho after";
  for (size_t cut = 0; cut <= sizeof(whole) - 1; cut++) {
    int status = shell_parse_draft(whole, cut, NULL, &draft);
    if (status == SHELL_SOURCE_COMPLETE || status == SHELL_SOURCE_INCOMPLETE) {
      CHECK(draft.prefix_length <= cut);
      if (draft.prefix_length) {
        shell_parse_result_t strict;
        shell_limits_t strict_limits = SHELL_LIMITS_DEFAULT;
        strict_limits.strict_mode = true;
        CHECK(shell_parse_fast(whole, draft.prefix_length, &strict_limits,
                               &strict) == SHELL_OK);
        CHECK(!memcmp(&strict, &draft.prefix, sizeof(strict)));
      }
      for (uint32_t h = 0; h < draft.header_count; h++)
        for (uint32_t w = 0; w < draft.headers[h].word_count; w++)
          CHECK(draft.headers[h].words[w].start +
                    draft.headers[h].words[w].length <=
                cut);
    }
  }
}

static void pending_pipeline_prefixes(void) {
  static const char *const separators[] = {";", "&", "\n", "&&", "||"};
  static const char *const prefixes[] = {"!", "! !"};
  for (size_t s = 0; s < sizeof(separators) / sizeof(separators[0]); s++) {
    for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); p++) {
      char source[128];
      int length = snprintf(source, sizeof(source), "echo ok%s %s",
                            separators[s], prefixes[p]);
      CHECK(length > 0 && (size_t)length < sizeof(source));
      size_t prefix = s < 3 ? strlen("echo ok") + strlen(separators[s]) : 0;
      CHECK(shell_parse_draft(source, (size_t)length, NULL, &draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.need == SHELL_SOURCE_NEEDS_COMMAND &&
            draft.prefix_length == prefix);
      if (prefix)
        CHECK(shell_dep_graph_parse_with_fast(source, prefix, "/workspace",
                                              &limits, &draft.prefix,
                                              &graph) == SHELL_DEP_OK);
      memcpy(source + length, " true", sizeof(" true"));
      for (size_t cut = (size_t)length; cut <= strlen(source); cut++) {
        shell_source_status_t status =
            shell_parse_draft(source, cut, NULL, &draft);
        CHECK(status == SHELL_SOURCE_COMPLETE ||
              status == SHELL_SOURCE_INCOMPLETE);
        if (status == SHELL_SOURCE_INCOMPLETE)
          CHECK(draft.prefix_length == prefix);
      }
      parse(source);
    }
  }
  static const char *const nested[] = {"echo ok; { !", "echo ok; ( !",
                                       "echo ok; echo \"$(!"};
  static const char *const endings[] = {" true; }", " true)", " true)\""};
  for (size_t c = 0; c < sizeof(nested) / sizeof(nested[0]); c++) {
    char source[128];
    CHECK(shell_parse_draft(nested[c], strlen(nested[c]), NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo ok;"));
    snprintf(source, sizeof(source), "%s%s", nested[c], endings[c]);
    CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    parse(source);
  }
  static const char *const timed[] = {"time",
                                      "time !",
                                      "! time",
                                      "echo ok; time",
                                      "echo ok; time -p !",
                                      "echo ok & time !",
                                      "echo ok\ntime !",
                                      "echo ok && time !"};
  for (size_t c = 0; c < sizeof(timed) / sizeof(timed[0]); c++) {
    CHECK(shell_parse_draft(timed[c], strlen(timed[c]), NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    parse(timed[c]);
  }
  static const char invalid[] = "echo ok; !\ntrue";
  CHECK(shell_parse_draft(invalid, sizeof(invalid) - 1, NULL, &draft) ==
        SHELL_SOURCE_INVALID);
  CHECK(!draft.prefix_length);
}

static void keyword_recovery(void) {
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
    for (size_t c = 0; c < sizeof(contexts) / sizeof(contexts[0]); c++) {
      for (unsigned continued = 0; continued < 2; continued++) {
        int length = snprintf(source, sizeof(source), "echo before; %s%s%s",
                              contexts[c].opening, words[w],
                              continued ? "\\\n\\\n" : "");
        CHECK(length > 0 && (size_t)length < sizeof(source));
        CHECK(shell_parse_draft(source, (size_t)length, NULL, &draft) ==
              SHELL_SOURCE_INCOMPLETE);
        CHECK(draft.need == SHELL_SOURCE_NEEDS_COMMAND);
        CHECK(draft.incomplete_at ==
              strlen("echo before; ") + strlen(contexts[c].opening));
        CHECK(draft.prefix_length == strlen("echo before;") &&
              draft.tail_start == draft.prefix_length &&
              draft.prefix.count == 1);
        CHECK(draft.header_count >= 2 && draft.headers[0].complete &&
              !draft.headers[draft.header_count - 1].complete);
        CHECK(shell_dep_graph_parse(source, (size_t)length, "/workspace",
                                    &limits, &graph) == SHELL_DEP_EPARSE);
        /* EOF is not a word boundary. A suffix repairs exactly this tail,
         * including when physical continuations precede it. */
        snprintf(source + length, sizeof(source) - (size_t)length, "x%s",
                 contexts[c].closing);
        CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
              SHELL_SOURCE_COMPLETE);
      }
    }
    static const char *const boundaries[] = {" ", "\t", "\n", ";", ">"};
    for (size_t b = 0; b < sizeof(boundaries) / sizeof(boundaries[0]); b++) {
      snprintf(source, sizeof(source), "echo before; %s%s", words[w],
               boundaries[b]);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!draft.prefix_length && !draft.tail_start && !draft.prefix.count);
      for (uint32_t h = 0; h < draft.header_count; h++)
        CHECK(!draft.headers[h].complete);
    }
    static const char *const closed[] = {"$(%s)", "<(%s)", ">(%s)", "`%s`"};
    for (size_t c = 0; c < sizeof(closed) / sizeof(closed[0]); c++) {
      char word[128];
      snprintf(word, sizeof(word), closed[c], words[w]);
      snprintf(source, sizeof(source), "echo before; echo %s", word);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!draft.prefix_length && !draft.prefix.count);
      char suffixed[64];
      snprintf(suffixed, sizeof(suffixed), "%sx", words[w]);
      snprintf(word, sizeof(word), closed[c], suffixed);
      snprintf(source, sizeof(source), "echo before; echo %s", word);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(draft.header_count == 3 && draft.headers[2].complete);
    }
    snprintf(source, sizeof(source), "echo before; echo $(echo child; %s",
             words[w]);
    CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo before;"));
    CHECK(draft.header_count == 4 && draft.headers[0].complete &&
          !draft.headers[1].complete && draft.headers[2].complete &&
          !draft.headers[3].complete);
    static const char *const ordinary[] = {"echo %s", "cat >%s",   "'%s'",
                                           "%s\"\"",  "\\%s",      "%sx",
                                           "x=1 %s",  ">target %s"};
    for (size_t c = 0; c < sizeof(ordinary) / sizeof(ordinary[0]); c++) {
      snprintf(source, sizeof(source), ordinary[c], words[w]);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(draft.headers[0].complete && draft.prefix_length == strlen(source));
      parse(source);
    }
  }
  static const char *const invalid[] = {"echo before; name() { :; }",
                                        "echo before; function name"};
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); c++) {
    CHECK(shell_parse_draft(invalid[c], strlen(invalid[c]), NULL, &draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length);
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
    CHECK(shell_parse_draft(continued, at, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo before;") &&
          !draft.headers[1].complete);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work && (!previous_work || work <= 3 * previous_work));
    previous_work = work;
  }
#endif
}

static void prefixes(void) {
  /* Syntax/data admission is independent of supported arithmetic semantics. */
  static const char math[] = "echo $(( $(cat <<'日本'\n1\n日本\n) + 1 ))";
  CHECK(shell_parse_draft(math, sizeof(math) - 1, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.heredoc_count == 1);
  content(&draft.heredocs[0].content, "1\n");
  CHECK(shell_dep_graph_parse(math, sizeof(math) - 1, "/workspace", &limits,
                              &graph) == SHELL_DEP_EPARSE);
  static const char *const cases[] = {
      "echo before\ncat >target <<'EOF'\nalpha\nEOF\necho after",
      ("echo before\ncat <<A <<-'B'; printf header\none\nA\n\ttwo\n\tB\necho "
       "after"),
      "echo before\ncat <<'日本 語'\n日本 語 body\n日本 語\necho after",
      "echo before\n(echo 'quoted'; { cat <<EOF; }\nbody\nEOF\n)",
      "echo before\necho \"$(cat <<'EOF'\nbody\nEOF\n)\" >out",
      "time -p ! { printf '%s' \"${x:-$(printf nested)}\"; } |& cat",
      "echo before\ncat <<EOF\nE\\\nOF\necho after",
      "echo before\ncat < <(printf bytes) 2>&\"$fd\"",
      "echo before\ncat >$(printf out)",
      "echo before\ncat >${target:-out}",
      "echo before\ncat >$((1 + 2))",
      "echo before\ncat <<<$(printf bytes)",
      "echo before\n{ :; } >$(printf out)",
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    for (size_t cut = 0; cut <= strlen(cases[c]); cut++) {
      int status = shell_parse_draft(cases[c], cut, NULL, &draft);
      if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "cut %zu status %d: %.*s\n", cut, status, (int)cut,
                cases[c]);
      CHECK(status == SHELL_SOURCE_COMPLETE ||
            status == SHELL_SOURCE_INCOMPLETE);
      if (draft.prefix_length) {
        shell_parse_result_t strict;
        shell_limits_t strict_limits = SHELL_LIMITS_DEFAULT;
        strict_limits.strict_mode = true;
        CHECK(shell_parse_fast(cases[c], draft.prefix_length, &strict_limits,
                               &strict) == SHELL_OK);
      }
    }
  }
}

static void local_completeness(void) {
  static const struct {
    const char *source;
    unsigned headers;
    bool complete[4];
  } cases[] = {
      {"cat <<EOF\n$(echo ok)\n", 2, {true, true}},
      {"{ echo ok;", 2, {false, true}},
      {"( { echo ok; }\n", 3, {false, true, true}},
      {"echo \"$(echo ok; cat >", 3, {false, true, false}},
      {"{ echo ok; } >\"", 2, {false, true}},
      {"cat <<'EO", 1, {false}},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    size_t length = strlen(cases[c].source);
    CHECK(shell_parse_draft(cases[c].source, length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.header_count == cases[c].headers);
    for (uint32_t h = 0; h < draft.header_count; h++) {
      CHECK(draft.headers[h].complete == cases[c].complete[h]);
      CHECK(draft.headers[h].source.length > 0);
      CHECK(draft.headers[h].source.start + draft.headers[h].source.length <=
            length);
    }
    if (draft.headers[0].compound)
      CHECK(draft.headers[0].source.length == length);
  }
  static const struct {
    const char *source;
    unsigned prefix;
  } timing[] = {
      {"time\ncat >", 5},
      {"time -p\ncat >", 8},
      {"echo first\ntime\ncat >", 16},
      {"time;cat >", 5},
      {"time \\\ncat >", 0},
      {"echo ok &&\ntime\ncat >", 16},
      {"time echo ok &&\ncat >", 0},
      {"{ time\ncat >", 0},
      {"time cat <<EOF\nbody\n", 0},
  };
  for (size_t c = 0; c < sizeof(timing) / sizeof(timing[0]); c++) {
    CHECK(shell_parse_draft(timing[c].source, strlen(timing[c].source), NULL,
                            &draft) == SHELL_SOURCE_INCOMPLETE);
    if (draft.prefix_length != timing[c].prefix)
      fprintf(stderr, "timing prefix %u expected %u: %s\n", draft.prefix_length,
              timing[c].prefix, timing[c].source);
    CHECK(draft.prefix_length == timing[c].prefix);
    if (draft.prefix_length) {
      shell_parse_result_t strict;
      shell_limits_t strict_limits = SHELL_LIMITS_DEFAULT;
      strict_limits.strict_mode = true;
      CHECK(shell_parse_fast(timing[c].source, draft.prefix_length,
                             &strict_limits, &strict) == SHELL_OK);
      CHECK(!memcmp(&strict, &draft.prefix, sizeof(strict)));
    }
  }
}

/* A later unfinished suffix must not erase earlier executable children. All
 * cases share the same byte coordinates before the appended completion. */
static void unfinished_children(void) {
  static const struct {
    const char *source, *completion;
    unsigned children;
    bool last_complete;
    shell_source_need_t need;
  } cases[] = {
      {"echo \"$(printf one) tail", "\"", 1, true, SHELL_SOURCE_NEEDS_QUOTE},
      {"echo pre$(printf one)'tail", "'", 1, true, SHELL_SOURCE_NEEDS_QUOTE},
      {"echo $(printf one)\\", "x", 1, true, SHELL_SOURCE_NEEDS_ESCAPE},
      {"echo pre$(printf one)$(printf two", ")", 2, true,
       SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"cat >\"$(printf one) tail", "\"", 1, true, SHELL_SOURCE_NEEDS_QUOTE},
      {"cat >$(printf one)$(printf two", ")", 2, true,
       SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"cat <(printf one)'tail", "'", 1, true, SHELL_SOURCE_NEEDS_QUOTE},
      {"cat >(printf one)>(printf two", ")", 2, true,
       SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"cat < <(printf one)$(printf two", ")", 2, true,
       SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"echo \"`printf one` tail", "\"", 1, true, SHELL_SOURCE_NEEDS_QUOTE},
      {"echo `printf one", "`", 1, true, SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"echo \"`printf one", "`\"", 1, true, SHELL_SOURCE_NEEDS_QUOTE},
      {"cat >`printf one", "`", 1, true, SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"echo ${value:-`printf one", "`}", 1, true,
       SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"echo `printf one; printf two", "`", 2, true,
       SHELL_SOURCE_NEEDS_SUBSTITUTION},
      {"echo `printf one\\", "q`", 1, false, SHELL_SOURCE_NEEDS_ESCAPE},
      {"cat >\"`printf one` tail", "\"", 1, true, SHELL_SOURCE_NEEDS_QUOTE},
      {"echo \"${value:-$(printf one)} tail", "\"", 1, true,
       SHELL_SOURCE_NEEDS_QUOTE},
      {"echo \"$(( $(printf one) + 1 )) tail", "\"", 1, true,
       SHELL_SOURCE_NEEDS_QUOTE},
      {"echo \"$(printf one)$(printf two >", "out)\"", 2, false,
       SHELL_SOURCE_NEEDS_QUOTE},
  };
  const char *prefix = "echo before; ";
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    char source[256];
    int size =
        snprintf(source, sizeof(source), "%s%s", prefix, cases[c].source);
    CHECK(size > 0 && (size_t)size < sizeof(source));
    size_t length = (size_t)size;
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen(prefix) - 1);
    CHECK(draft.need == cases[c].need);
    CHECK(draft.header_count == cases[c].children + 2);
    if (!draft.headers[0].complete || draft.headers[1].complete)
      fprintf(stderr, "unfinished outer header case %zu: %s\n", c, source);
    CHECK(draft.headers[0].complete && !draft.headers[1].complete);
    shell_source_header_t children[2];
    for (uint32_t h = 0; h < cases[c].children; h++) {
      children[h] = draft.headers[h + 2];
      CHECK(children[h].complete ==
            (h + 1 < cases[c].children || cases[c].last_complete));
      CHECK(children[h].word_count > 0);
      CHECK(children[h].words[0].length == strlen("printf"));
      CHECK(!memcmp(source + children[h].words[0].start, "printf", 6));
      if (h)
        CHECK(children[h].source.start > children[h - 1].source.start);
    }
    size_t completed = strlen(cases[c].completion);
    CHECK(length + completed < sizeof(source));
    memcpy(source + length, cases[c].completion, completed);
    CHECK(shell_parse_draft(source, length + completed, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == cases[c].children + 2);
    for (uint32_t h = 0; h < cases[c].children; h++) {
      const shell_source_header_t *child = &draft.headers[h + 2];
      CHECK(child->complete && child->source.start == children[h].source.start);
      if (h + 1 < cases[c].children || cases[c].last_complete)
        CHECK(!memcmp(child, &children[h], sizeof(*child)));
    }
  }

  static const char *invalid[] = {
      "echo before; echo \"$(echo &&) tail",
      "echo before; cat >\"$(echo &&) tail",
      "echo before; cat <(echo &&)'tail",
      "echo before; echo \"`echo &&` tail",
      "echo before; echo $(echo &&)$(printf two",
      "echo before; cat <<EOF\n$(echo &&)\n",
      "echo before; cat <<EOF\n$(printf one)$(echo && ;",
      "echo before; echo \"`echo $(echo &&) tail",
      "echo before; cat >`echo $(echo &&) tail",
      "echo before; echo ${value:-`echo $(echo &&) tail",
      "echo before; cat <<EOF\n`echo $(echo &&)\n",
  };
  for (size_t c = 0; c < sizeof(invalid) / sizeof(invalid[0]); c++) {
    CHECK(shell_parse_draft(invalid[c], strlen(invalid[c]), NULL, &draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length && !draft.prefix.count && !draft.tail_start);
    for (uint32_t h = 0; h < draft.header_count; h++)
      CHECK(!draft.headers[h].complete);
  }

  static const char nested_doc[] =
      "echo before; echo \"$(cat <<'EOF'\nalpha\nEOF\n) tail";
  CHECK(shell_parse_draft(nested_doc, sizeof(nested_doc) - 1, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.prefix_length == strlen(prefix) - 1 && draft.header_count == 3);
  CHECK(draft.headers[2].complete && draft.heredoc_count == 1);
  const shell_source_heredoc_t *doc = &draft.heredocs[0];
  CHECK(doc->header == 2 && doc->header_complete && doc->body_started &&
        doc->complete && !doc->delimiter_prefix);
  CHECK(draft.redirects[doc->redirect].header == 2 &&
        draft.redirects[doc->redirect].heredoc == 0);
  CHECK(doc->content.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL);
  CHECK(doc->body_start == (size_t)(strstr(nested_doc, "alpha") - nested_doc));
  CHECK(doc->closing_delimiter.length == 4);
  content(&doc->content, "alpha\n");

  static const char open_doc[] = "cat <<EOF\n$(printf one)$(printf two";
  CHECK(shell_parse_draft(open_doc, sizeof(open_doc) - 1, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.need == SHELL_SOURCE_NEEDS_HEREDOC_BODY);
  CHECK(draft.header_count == 3 && draft.heredoc_count == 1);
  CHECK(draft.headers[1].complete && draft.headers[2].complete);
  CHECK(!draft.heredocs[0].complete);

  static const char backtick_doc[] =
      "echo before; echo \"`printf one; cat <<'EOF'\n日本\nEOF\n";
  CHECK(shell_parse_draft(backtick_doc, sizeof(backtick_doc) - 1, NULL,
                          &draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.prefix_length == strlen(prefix) - 1 && draft.header_count == 4);
  CHECK(draft.headers[2].complete && draft.headers[3].complete);
  CHECK(draft.heredoc_count == 1 && draft.heredocs[0].header == 3);
  CHECK(draft.heredocs[0].complete);
  content(&draft.heredocs[0].content, "日本\n");
  CHECK(draft.heredocs[0].body_start ==
        (size_t)(strstr(backtick_doc, "日本") - backtick_doc));
  shell_source_heredoc_t saved = draft.heredocs[0];
  char completed[sizeof(backtick_doc) + 2];
  memcpy(completed, backtick_doc, sizeof(backtick_doc) - 1);
  memcpy(completed + sizeof(backtick_doc) - 1, "`\"", 3);
  CHECK(shell_parse_draft(completed, strlen(completed), NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.header_count == 4 && draft.heredoc_count == 1);
  /* Content views borrow different buffers; all source coordinates persist. */
  CHECK(draft.heredocs[0].body_start == saved.body_start &&
        draft.heredocs[0].closing_delimiter.start ==
            saved.closing_delimiter.start);

  static const char expandable[] = "cat <<EOF\n`printf one; printf two";
  CHECK(shell_parse_draft(expandable, sizeof(expandable) - 1, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.need == SHELL_SOURCE_NEEDS_HEREDOC_BODY);
  CHECK(draft.header_count == 3 && draft.headers[1].complete &&
        draft.headers[2].complete);
}

static void backtick_escape_domains(void) {
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
    CHECK(shell_parse_draft(invalid[c], strlen(invalid[c]), NULL, &draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length && !draft.prefix.count);
    for (uint32_t h = 0; h < draft.header_count; h++)
      CHECK(!draft.headers[h].complete);
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
    CHECK(shell_parse_draft(literal[c], strlen(literal[c]), NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);

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
} code_regions_t;

static void record_code(const char *source, size_t start, size_t end,
                        void *context) {
  code_regions_t *regions = context;
  CHECK(start >= regions->end && start < end &&
        end <= sizeof(regions->visited));
  for (size_t i = start; i < end; i++) {
    CHECK(!regions->visited[i] && (unsigned char)source[i] < 0x80);
    regions->visited[i] = true;
  }
  regions->bytes += end - start;
  regions->end = end;
}

static void code_region_stream(void) {
  static const char word[] =
      "日本 $((1 + $(printf 2) + $((3)))) 語 ${value:4} ${value#文}";
  code_regions_t regions = {0};
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = true, .suppress_process = true, .data_domain = true},
      .code_visitor = record_code,
      .code_context = &regions};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t status;
  unsigned children = 0, arithmetic = 0, substrings = 0;
  while ((status = shell_source_next_word_expansion(
              word, sizeof(word) - 1, &scan, &start, &after, &kind)) ==
         SHELL_SOURCE_SCAN_FOUND) {
    children += kind == SHELL_SOURCE_SUBST_COMMAND;
    arithmetic += kind == SHELL_SOURCE_EXPANSION_ARITHMETIC;
    substrings += kind == SHELL_SOURCE_EXPANSION_SUBSTRING;
  }
  CHECK(status == SHELL_SOURCE_SCAN_DONE && children == 1 && arithmetic == 1 &&
        substrings == 1 && regions.bytes > 0);
  CHECK(regions.visited[strchr(word, '1') - word]);
  CHECK(regions.visited[strchr(word, '3') - word]);
  CHECK(regions.visited[strchr(word, '4') - word]);
  CHECK(!regions.visited[strstr(word, "printf") - word]);
  CHECK(!regions.visited[strstr(word, "value#") - word]);
  for (size_t i = 0; i < sizeof(word) - 1; i++)
    if ((unsigned char)word[i] >= 0x80)
      CHECK(!regions.visited[i]);
}

/* All allocating adapters own the same operation-sized temporary arena. This
 * checks their public signatures, successful cleanup, and failed publication.
 */
static void allocating_adapter(const char *source, size_t length, unsigned api,
                               bool fail) {
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

static void allocating_delimiters(void) {
  for (size_t size = 300; size <= 1200; size *= 4) {
    for (unsigned nested = 0; nested < 2; nested++) {
      char source[2600];
      const char *opening = nested ? "echo \"$(cat <<'" : "cat <<'";
      size_t at = strlen(opening);
      memcpy(source, opening, at);
      memset(source + at, 'E', size);
      at += size;
      memcpy(source + at, "'\npayload\n", 10);
      at += 10;
      memset(source + at, 'E', size);
      at += size;
      source[at++] = '\n';
      if (nested) {
        memcpy(source + at, ")\"\n", 3);
        at += 3;
      }
      for (unsigned api = 0; api < 9; api++) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        shellsplit_test_alloc_reset();
#endif
        allocating_adapter(source, at, api, false);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        size_t allocations = shellsplit_test_alloc_count();
        for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
          shellsplit_test_alloc_fail_at(fail_at);
          allocating_adapter(source, at, api, true);
        }
        shellsplit_test_alloc_reset();
        allocating_adapter(source, at, api, false);
#endif
      }
    }
  }
}

static void capacity_and_work(void) {
  char source[16384];
  size_t length = 0;
  for (unsigned h = 0; h <= SHELL_SOURCE_MAX_HEADERS; h++) {
    memcpy(source + length, "echo x;", 7);
    length += 7;
  }
  CHECK(shell_parse_draft(source, length, NULL, &draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
  length = strlen("echo before; echo `");
  memcpy(source, "echo before; echo `", length);
  for (unsigned h = 0; h < SHELL_SOURCE_MAX_HEADERS; h++) {
    memcpy(source + length, "echo x;", 7);
    length += 7;
  }
  CHECK(shell_parse_draft(source, length, NULL, &draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
  static const char no_alloc[] = "cat >target 2>&\"1\" <<'EOF'\nalpha\nEOF\n";
  shellsplit_test_alloc_fail_at(1);
  CHECK(shell_parse_draft(no_alloc, sizeof(no_alloc) - 1, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
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
      CHECK(shell_parse_draft(source, length, NULL, &draft) ==
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
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.header_count == 2 && draft.heredocs[0].delimiter_prefix);
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
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
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
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.header_count == depth + 2);
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
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
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
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.header_count == depth + 1);
    CHECK(!draft.headers[0].complete && draft.headers[depth].complete);
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
        shell_parse_draft(source, length, NULL, &draft);
    if (children == SHELL_MAX_SUBCOMMANDS) {
      CHECK(status == SHELL_SOURCE_TRUNCATED);
      CHECK(!draft.prefix_length && !draft.prefix.count);
      for (uint32_t h = 0; h < draft.header_count; h++)
        CHECK(!draft.headers[h].complete);
    } else {
      CHECK(status == SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.header_count == children + 1);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(!previous_work || work <= previous_work * 3);
      previous_work = work;
    }
  }
#endif
}

static void continued_operators(void) {
  static const char *const operators[] = {"&\\\n&", "|\\\n|", "|\\\n&", "|"};
  char source[128];
  for (size_t i = 0; i < sizeof(operators) / sizeof(operators[0]); i++) {
    int length = snprintf(source, sizeof(source), "cat input %s printf next",
                          operators[i]);
    CHECK(length > 0 && (size_t)length < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)length, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == 2);
    CHECK(draft.headers[0].word_count == 2 && draft.headers[1].word_count == 2);
  }
  static const char literal[] = "cat input \\| \"|\"";
  CHECK(shell_parse_draft(literal, sizeof(literal) - 1, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.header_count == 1 && draft.headers[0].word_count == 4);
  static const char *const ordinary_time[] = {"printf x | time cat",
                                              "printf x |\ntime -p cat",
                                              "time printf x | time cat"};
  for (size_t i = 0; i < sizeof(ordinary_time) / sizeof(ordinary_time[0]);
       i++) {
    CHECK(shell_parse_draft(ordinary_time[i], strlen(ordinary_time[i]), NULL,
                            &draft) == SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == 2 &&
          draft.headers[1].word_count == (i == 1 ? 3u : 2u));
    shell_source_span_t word = draft.headers[1].words[0];
    CHECK(word.length == 4 &&
          !memcmp(ordinary_time[i] + word.start, "time", 4));
  }
}

static void delimiter_regressions(void) {
  static const char *const fragments[] = {"EO\\", "EOF\\", "E\\\nO\\"};
  char source[128];
  for (size_t i = 0; i < sizeof(fragments) / sizeof(fragments[0]); i++) {
    int length =
        snprintf(source, sizeof(source), "cat <<EOF\nalpha\n%s", fragments[i]);
    CHECK(length > 0 && (size_t)length < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.heredocs[0].confirmed_length == 6 &&
          draft.heredocs[0].delimiter_prefix);
    const char *suffix = i == 1 ? "\n" : "\nF\n";
    memcpy(source + length, suffix, strlen(suffix) + 1);
    CHECK(shell_parse_draft(source, (size_t)length + strlen(suffix), NULL,
                            &draft) == SHELL_SOURCE_COMPLETE);
    content(&draft.heredocs[0].content, "alpha\n");
  }
  static const char quoted[] = "cat <<'EOF'\nalpha\nEO\\";
  CHECK(shell_parse_draft(quoted, sizeof(quoted) - 1, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.heredocs[0].confirmed_length == 9 &&
        !draft.heredocs[0].delimiter_prefix);
  static const char continued[] = "cat <<EO\\\nF\n$(printf expanded)\nEOF\n";
  parse(continued);
  unsigned commands = 0;
  for (uint32_t n = 0; n < graph.node_count; n++) {
    commands += graph.nodes[n].type == SHELL_NODE_CMD;
    if (graph.nodes[n].type == SHELL_NODE_DOC &&
        graph.nodes[n].doc.kind == SHELL_DOC_HEREDOC)
      CHECK(!(graph.nodes[n].doc.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL));
  }
  CHECK(commands == 2);
  static const char *const operands[] = {"cat >$(printf out", "cat >${target",
                                         "cat >$((1 +", "cat <<<$(printf out",
                                         "{ :; } >$(printf out"};
  for (size_t i = 0; i < sizeof(operands) / sizeof(operands[0]); i++) {
    int length =
        snprintf(source, sizeof(source), "echo before; %s", operands[i]);
    CHECK(length > 0 && (size_t)length < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo before;") &&
          draft.need == SHELL_SOURCE_NEEDS_SUBSTITUTION);
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (size_t padding = 128; padding <= 1024; padding *= 2) {
    char padded[8192];
    size_t length = 0;
    memcpy(padded, "cat <<E", 7);
    length += 7;
    for (size_t i = 0; i < padding; i++) {
      padded[length++] = '\'';
      padded[length++] = '\'';
    }
    memcpy(padded + length, "OF\n", 3);
    length += 3;
    for (size_t i = 0; i < padding; i++) {
      memcpy(padded + length, "EOX\n", 4);
      length += 4;
    }
    memcpy(padded + length, "EOF\n", 4);
    length += 4;
    shellsplit_test_source_scan_reset();
    CHECK(shell_parse_draft(padded, length, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_HEREDOC_PREPARATION);
    CHECK(work >= padding * 2 && work < length * 24);
    CHECK(shellsplit_test_line_scan_work() < length * 24);
  }
#endif
}

static void delimiter_phases(void) {
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
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.heredoc_count == 1 && draft.heredocs[0].complete);
    const shell_source_heredoc_t *doc = &draft.heredocs[0];
    CHECK(!!(doc->content.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL) ==
          cases[c].literal);
    content(&doc->content, cases[c].payload);
    CHECK(doc->closing_delimiter.length == strlen(cases[c].closing));
    CHECK(!memcmp(source + doc->closing_delimiter.start, cases[c].closing,
                  strlen(cases[c].closing)));
    CHECK(doc->content.value == source + doc->body_start);
    CHECK(doc->body_start + doc->content.value_len ==
          doc->closing_delimiter.start);
    parse(source);
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          &draft.prefix,
                                          &graph) == SHELL_DEP_OK);
    if (c == 0) {
      CHECK(draft.header_count == 4);
      static const char *const commands[] = {"cat", "printf", "``:", ":"};
      unsigned count = 0;
      for (uint32_t n = 0; n < graph.node_count; n++) {
        if (graph.nodes[n].type == SHELL_NODE_DOC &&
            graph.nodes[n].doc.kind == SHELL_DOC_HEREDOC)
          content(&graph.nodes[n].doc, "");
        if (graph.nodes[n].type != SHELL_NODE_CMD)
          continue;
        CHECK(count < 4);
        const shell_dep_cmd_t *cmd = &graph.nodes[n].cmd;
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
    CHECK(shell_parse_draft(gaps[c], strlen(gaps[c]), NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.heredoc_count == 1 &&
          draft.heredocs[0].redirect == UINT32_MAX &&
          !draft.heredocs[0].header_complete && !draft.prefix_length);
  }
  static const char single_quoted[] = "cat <<'a\\\nb'\npayload\nab\n";
  CHECK(shell_parse_draft(single_quoted, sizeof(single_quoted) - 1, NULL,
                          &draft) == SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.need == SHELL_SOURCE_NEEDS_HEREDOC_BODY);
  content(&draft.heredocs[0].content, "payload\nab\n");

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
                                &graph) == SHELL_DEP_EPARSE);
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
    parse(preserved[c]);
    CHECK(shell_parse_draft(preserved[c], strlen(preserved[c]), NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.heredoc_count == 1 && draft.heredocs[0].complete);
    content(&draft.heredocs[0].content, "payload\n");
  }
}

typedef struct {
  const char *source;
  size_t start, end;
  unsigned calls;
} delimiter_resolution_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    delimiter_resolution(const shell_expand_word_request_t *request,
                         const char **records, size_t *length, void *context) {
  delimiter_resolution_t *domain = context;
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
static void delimiter_fragments(void) {
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
    CHECK(shell_parse_draft(source, (size_t)count, &source_limits, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == 3 && draft.heredoc_count == 1);
    content(&draft.heredocs[0].content, "payload\n");
    size_t word_start = (size_t)(strstr(source, "<< ") - source) + 3;
    for (size_t cut = word_start; cut <= word_start + strlen(word); cut++) {
      shell_source_status_t status =
          shell_parse_draft(source, cut, &source_limits, &draft);
      if (status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "delimiter cut case=%zu cut=%zu status=%d: %.*s\n", c,
                cut, status, (int)cut, source);
      CHECK(status == SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.prefix_length == strlen("echo before;"));
    }
    shell_dep_limits_t graph_limits = limits;
    graph_limits.workspace_size += size;
    graph_limits.workspace = malloc(graph_limits.workspace_size);
    CHECK(graph_limits.workspace);
    CHECK(shell_dep_graph_parse(source, (size_t)count, "/workspace",
                                &graph_limits, &graph) == SHELL_DEP_OK);
    unsigned commands = 0;
    for (uint32_t n = 0; n < graph.node_count; n++)
      commands += graph.nodes[n].type == SHELL_NODE_CMD;
    CHECK(commands == 3);
    if (c == 7 || c == 14 || c == 18 || strstr(word, "${\\\n#x") ||
        strstr(word, " >&-file") || !strcmp(word, "\"${x:-$'\\0'}\"") ||
        !strcmp(word, "$(a >&$fd-)")) {
      for (unsigned api = 0; api < 9; api++) {
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        shellsplit_test_alloc_reset();
#endif
        allocating_adapter(source, (size_t)count, api, false);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        size_t allocations = shellsplit_test_alloc_count();
        for (size_t fail = 1; fail <= allocations; fail++) {
          shellsplit_test_alloc_fail_at(fail);
          allocating_adapter(source, (size_t)count, api, true);
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
  parse(witness);
  CHECK(shell_parse_draft(witness, sizeof(witness) - 1, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.header_count == 5 && draft.heredoc_count == 1);
  content(&draft.heredocs[0].content, "");

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
    CHECK(shell_parse_draft(source, length, &source_limits, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.heredoc_count == 1 && draft.heredocs[0].complete);
    content(&draft.heredocs[0].content, "");
    shell_dep_limits_t graph_limits = limits;
    graph_limits.workspace_size += size;
    graph_limits.workspace = malloc(graph_limits.workspace_size);
    CHECK(graph_limits.workspace);
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace",
                                          &graph_limits, &draft.prefix,
                                          &graph) == SHELL_DEP_OK);
    unsigned commands = 0, visible = 0;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const shell_dep_node_t *node = &graph.nodes[n];
      if (node->type != SHELL_NODE_CMD)
        continue;
      commands++;
      if (node->cmd.token_count && node->cmd.token_lens[0] == 6 &&
          !memcmp(node->cmd.tokens[0], "printf", 6))
        visible++;
    }
    CHECK(commands == exposed[c].commands && visible == 1);
    CHECK(shell_dep_graph_validate(&graph).valid);
    free(graph_limits.workspace);
    free(scratch);
  }

  static const char expanding[] =
      "cat <<${x:-\"EOF\"}\n$(printf INSPECT)\n${x:-\"EOF\"}\n";
  parse(expanding);
  CHECK(shell_parse_draft(expanding, sizeof(expanding) - 1, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.header_count == 2 && draft.heredoc_count == 1);
  CHECK(
      !(draft.heredocs[0].content.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL));
  content(&draft.heredocs[0].content, "$(printf INSPECT)\n");

  static const char resolved_source[] =
      "cat $ARG <<$(printf   eof)\npayload\n$(printf eof)\n";
  delimiter_resolution_t domain = {
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
            &resolved, &graph, delimiter_resolution, &domain,
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
                            &draft) == SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length && !draft.prefix.count);
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
    CHECK(shell_parse_draft(source, at, &storage, &draft) ==
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
    CHECK(shell_parse_draft(source, at, &storage, &draft) ==
          SHELL_SOURCE_TRUNCATED);
    CHECK(!draft.prefix_length && !draft.prefix.count);
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
    CHECK(shell_parse_draft(source, at, &storage, &draft) ==
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
  CHECK(shell_parse_draft(nested, at, &storage, &draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
  storage.workspace_size = size;
  CHECK(shell_parse_draft(nested, at, &storage, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  free(scratch);
}

static void pending_redirectors(void) {
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
    CHECK(shell_parse_draft(source, start, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == 3 && draft.headers[2].complete);
    shell_source_header_t child = draft.headers[2];
    uint32_t redirects = draft.redirect_count;
    shell_source_redirect_t existing = {0};
    if (redirects)
      existing = draft.redirects[0];
    for (size_t t = 0; t < sizeof(cases) / sizeof(cases[0]); t++) {
      count = snprintf(source, sizeof(source), "%s%s%s", prefix, compounds[c],
                       cases[t].received);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      size_t length = strlen(source);
      CHECK(shell_parse_draft(source, length, NULL, &draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.need == (cases[t].escape ? SHELL_SOURCE_NEEDS_ESCAPE
                                           : SHELL_SOURCE_NEEDS_REDIRECT));
      CHECK(draft.incomplete_at == (cases[t].escape ? length - 1 : start));
      CHECK(draft.prefix_length == strlen("echo before;") &&
            draft.tail_start == draft.prefix_length);
      CHECK(draft.header_count == 3 && draft.headers[0].complete &&
            !draft.headers[1].complete && draft.headers[1].compound &&
            !draft.headers[1].word_count && !draft.headers[1].assignment_count);
      CHECK(draft.headers[1].source.start + draft.headers[1].source.length ==
            length);
      CHECK(!memcmp(&child, &draft.headers[2], sizeof(child)));
      CHECK(draft.redirect_count == redirects);
      if (redirects)
        CHECK(!memcmp(&existing, &draft.redirects[0], sizeof(existing)));
      strcpy(source + length, cases[t].completion);
      length = strlen(source);
      CHECK(shell_parse_draft(source, length, NULL, &draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(draft.headers[1].complete && !draft.headers[1].word_count &&
            draft.redirect_count == redirects + 1);
      CHECK(!memcmp(&child, &draft.headers[2], sizeof(child)));
      for (size_t cut = 0; cut <= length; cut++) {
        shell_source_status_t status =
            shell_parse_draft(source, cut, NULL, &draft);
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
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!draft.prefix_length && !draft.prefix.count);
      count = snprintf(source, sizeof(source), "%s{ %s%s", prefix, compounds[c],
                       cases[t].received);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.header_count == 4 && !draft.headers[1].complete &&
            !draft.headers[2].complete && !draft.headers[2].word_count &&
            draft.headers[3].complete &&
            draft.prefix_length == strlen("echo before;"));
      shell_source_header_t nested_child = draft.headers[3];
      count += snprintf(source + count, sizeof(source) - (size_t)count, "%s; }",
                        cases[t].completion);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(draft.header_count == 4 && draft.headers[1].complete &&
            draft.headers[2].complete && !draft.headers[2].word_count &&
            !memcmp(&nested_child, &draft.headers[3], sizeof(nested_child)));
    }
    for (size_t t = 0; t < sizeof(invalid) / sizeof(invalid[0]); t++) {
      count = snprintf(source, sizeof(source), "%s%s%s", prefix, compounds[c],
                       invalid[t]);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!draft.prefix_length && !draft.prefix.count && !draft.tail_start);
    }
    for (size_t t = 0; t < sizeof(operands) / sizeof(operands[0]); t++) {
      count = snprintf(source, sizeof(source), "%s%s%s", prefix, compounds[c],
                       operands[t].word);
      CHECK(count > 0 && (size_t)count < sizeof(source));
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.need == operands[t].need &&
            draft.prefix_length == strlen("echo before;") &&
            !draft.headers[1].complete && !draft.headers[1].word_count);
      CHECK(!memcmp(&child, &draft.headers[2], sizeof(child)));
      strcpy(source + count, operands[t].completion);
      CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
            SHELL_SOURCE_COMPLETE);
      CHECK(!draft.headers[1].word_count &&
            !memcmp(&child, &draft.headers[2], sizeof(child)));
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
      CHECK(shell_parse_draft(large, at, NULL, &draft) ==
            SHELL_SOURCE_INCOMPLETE);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work >= length && (!previous || work <= 3 * previous));
      previous = work;
    }
  }
#endif
}

static void missing_redirect_operands(void) {
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
        CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
              SHELL_SOURCE_INCOMPLETE);
        CHECK(draft.need == SHELL_SOURCE_NEEDS_REDIRECT);
        CHECK(draft.incomplete_at == strlen(prefix) + strlen(commands[c]));
        CHECK(draft.prefix_length == strlen("echo ok;") &&
              draft.tail_start == draft.prefix_length);
        CHECK(draft.header_count >= 2 && draft.headers[0].complete &&
              !draft.headers[1].complete);
        if (c != 0) {
          CHECK(draft.header_count == 3 && draft.headers[2].complete);
          if (t == 0)
            closed_child = draft.headers[2];
          CHECK(
              !memcmp(&closed_child, &draft.headers[2], sizeof(closed_child)));
        }
      }
      for (size_t b = 0; b < sizeof(invalid) / sizeof(invalid[0]); b++) {
        strcpy(source + received, invalid[b]);
        CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
              SHELL_SOURCE_INVALID);
        CHECK(!draft.prefix_length && !draft.prefix.count && !draft.tail_start);
        for (uint32_t h = 0; h < draft.header_count; h++)
          CHECK(!draft.headers[h].complete);
      }
      for (size_t o = 0; o < sizeof(operands) / sizeof(operands[0]); o++) {
        strcpy(source + received, operands[o]);
        size_t length = strlen(source);
        CHECK(shell_parse_draft(source, length, NULL, &draft) ==
              SHELL_SOURCE_COMPLETE);
        CHECK(draft.headers[1].complete && draft.prefix_length == length);
        if (c != 0)
          CHECK(
              !memcmp(&closed_child, &draft.headers[2], sizeof(closed_child)));
        for (size_t cut = 0; cut <= length; cut++) {
          shell_source_status_t status =
              shell_parse_draft(source, cut, NULL, &draft);
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
      CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
            SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.prefix_length == strlen("echo ok;") &&
            draft.header_count >= 3 && !draft.headers[1].complete &&
            !draft.headers[2].complete);
      strcpy(source + count, ")");
      CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!draft.prefix_length && !draft.prefix.count);
      strcpy(source + count, ";)");
      CHECK(shell_parse_draft(source, strlen(source), NULL, &draft) ==
            SHELL_SOURCE_INVALID);
      CHECK(!draft.prefix_length && !draft.prefix.count);
    }
  }
}

static void nested_redirect_recovery(void) {
  static const char prefix[] = "echo before; ";
  static const char reported[] = "echo before; echo $(cat > <(printf out";
  CHECK(shell_parse_draft(reported, sizeof(reported) - 1, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.need == SHELL_SOURCE_NEEDS_SUBSTITUTION &&
        draft.incomplete_at == strlen("echo before; echo ") &&
        draft.prefix_length == strlen("echo before;"));
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
        CHECK(shell_parse_draft(source, received, NULL, &draft) ==
              SHELL_SOURCE_INCOMPLETE);
        CHECK(draft.need == SHELL_SOURCE_NEEDS_SUBSTITUTION &&
              draft.prefix_length == strlen("echo before;") &&
              draft.tail_start == draft.prefix_length);
        size_t opener =
            (size_t)(strchr(source + strlen(prefix), o == 3 ? '`' : '(') -
                     source);
        CHECK(draft.incomplete_at == (o == 3 ? opener : opener - 1));
        uint32_t headers = c == 0 ? 4 : 5;
        /* A pending process-substitution word has no framed operation yet;
         * the lexer can retain the unfinished backtick operand itself. */
        uint32_t redirects = r == 2 ? 2 : 1;
        if (draft.header_count != headers ||
            draft.redirect_count != redirects || draft.redirects[0].header != 2)
          fprintf(
              stderr,
              "nested redirect metadata: %s headers=%u redirects=%u owner=%u\n",
              source, draft.header_count, draft.redirect_count,
              draft.redirects[0].header);
        CHECK(draft.header_count == headers && draft.headers[0].complete &&
              !draft.headers[1].complete && !draft.headers[2].complete &&
              draft.redirect_count == redirects &&
              draft.redirects[0].header == 2);
        shell_group_io_op_t existing = draft.redirects[0].io;
        shell_source_header_t leaf = draft.headers[headers - 1];
        CHECK(leaf.complete && leaf.word_count == 2 &&
              leaf.source.start ==
                  (size_t)(strstr(source, "printf") - source) &&
              leaf.source.length == strlen("printf out"));
        shell_source_header_t closed = {0};
        if (c != 0) {
          closed = draft.headers[3];
          CHECK(closed.complete && !draft.headers[2].word_count);
        }
        count += snprintf(source + received, sizeof(source) - received, "%s%s",
                          ends[r], closings[o]);
        CHECK(count > 0 && (size_t)count < sizeof(source));
        CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
              SHELL_SOURCE_COMPLETE);
        CHECK(draft.header_count == headers && draft.redirect_count == 2 &&
              draft.redirects[0].header == 2 &&
              !memcmp(&existing, &draft.redirects[0].io, sizeof(existing)) &&
              !memcmp(&leaf, &draft.headers[headers - 1], sizeof(leaf)));
        if (c != 0)
          CHECK(!memcmp(&closed, &draft.headers[3], sizeof(closed)));
        for (size_t cut = 0; cut <= (size_t)count; cut++) {
          shell_source_status_t status =
              shell_parse_draft(source, cut, NULL, &draft);
          if (status != SHELL_SOURCE_COMPLETE &&
              status != SHELL_SOURCE_INCOMPLETE)
            fprintf(stderr, "nested redirect cut %zu: %.*s (status %d)\n", cut,
                    (int)cut, source, status);
          CHECK(status == SHELL_SOURCE_COMPLETE ||
                status == SHELL_SOURCE_INCOMPLETE);
          if (cut >= received && cut < (size_t)count)
            CHECK(draft.prefix_length == strlen("echo before;"));
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
    CHECK(shell_parse_draft(invalid[i], strlen(invalid[i]), NULL, &draft) ==
          SHELL_SOURCE_INVALID);
    CHECK(!draft.prefix_length && !draft.prefix.count && !draft.tail_start);
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
    CHECK(shell_parse_draft(documents[d].received, length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.need == documents[d].need &&
          draft.prefix_length == strlen("echo before;") &&
          draft.header_count == 5 && draft.heredoc_count == 1 &&
          !draft.heredocs[0].complete && draft.heredocs[0].body_started);
    size_t at =
        d == 0 ? strlen("echo before; echo ") : strlen("echo before; cat ");
    CHECK(draft.incomplete_at == at);
    shell_source_header_t leaf = draft.headers[4];
    CHECK(leaf.complete && leaf.word_count == 2);
    int count = snprintf(source, sizeof(source), "%s%s", documents[d].received,
                         documents[d].completion);
    CHECK(count > 0 && (size_t)count < sizeof(source));
    CHECK(shell_parse_draft(source, (size_t)count, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.heredocs[0].complete &&
          !memcmp(&leaf, &draft.headers[4], sizeof(leaf)));
    for (size_t cut = 0; cut <= (size_t)count; cut++) {
      shell_source_status_t status =
          shell_parse_draft(source, cut, NULL, &draft);
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
    CHECK(shell_parse_draft(nested, at, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo before;"));
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

static void duplication_recovery(void) {
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
    CHECK(shell_parse_draft(source, length, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == strlen("echo ok;"));
    CHECK(draft.headers[0].complete && !draft.headers[1].complete);
    CHECK(draft.redirect_count == 1);
    const shell_source_redirect_t *redirect = &draft.redirects[0];
    CHECK(redirect->io.kind != SHELL_GROUP_IO_FAILED_REDIRECT);
    CHECK(redirect->io.target_fd == SHELL_PROCESS_FD_NONE);
    uint32_t headers = draft.header_count;
    bool closed_child = headers > 2 && draft.headers[2].complete;
    shell_source_header_t child;
    if (closed_child)
      child = draft.headers[2];
    char completed[256];
    int count =
        snprintf(completed, sizeof(completed), "%s%s", source, cases[c].suffix);
    CHECK(count > 0 && (size_t)count < sizeof(completed));
    CHECK(shell_parse_draft(completed, (size_t)count, NULL, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.header_count == headers);
    if (closed_child)
      CHECK(!memcmp(&child, &draft.headers[2], sizeof(child)));
    size_t first_quote = (size_t)(strchr(completed, '"') - completed);
    for (size_t cut = first_quote; cut < (size_t)count; cut++) {
      shell_source_status_t status =
          shell_parse_draft(completed, cut, NULL, &draft);
      if (status != SHELL_SOURCE_INCOMPLETE)
        fprintf(stderr, "duplication cut case=%zu cut=%zu status=%d\n", c, cut,
                status);
      CHECK(status == SHELL_SOURCE_INCOMPLETE);
      CHECK(draft.prefix_length == strlen("echo ok;"));
    }
  }
  static const char invalid[] = "echo ok; cat 2>&\"$(echo &&) tail";
  CHECK(shell_parse_draft(invalid, sizeof(invalid) - 1, NULL, &draft) ==
        SHELL_SOURCE_INVALID);
  CHECK(!draft.prefix_length);
}

typedef struct {
  const char *source;
  size_t length;
  shell_limits_t limits;
  unsigned calls;
} reentrant_source_t;

static shell_expand_status_t
reentrant_source(const shell_expand_word_request_t *request,
                 const char **records, size_t *record_length, void *context) {
  (void)request;
  (void)records;
  (void)record_length;
  reentrant_source_t *input = context;
  input->calls++;
  CHECK(shell_parse_draft(input->source, input->length, NULL, &draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(shell_parse_draft(input->source, input->length, &input->limits,
                          &draft) == SHELL_SOURCE_COMPLETE);
  return SHELL_EXPAND_UNRESOLVED;
}

static void delimiter_workspace(void) {
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
  CHECK(shell_parse_draft(source, at, NULL, &draft) == SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
  shell_limits_t scratch_limits = SHELL_LIMITS_DEFAULT;
  scratch_limits.workspace = scratch;
  scratch_limits.workspace_size = length;
  CHECK(shell_parse_draft(source, at, &scratch_limits, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.heredoc_count == 1 && draft.heredocs[0].complete);
  content(&draft.heredocs[0].content, "x\n");
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
  CHECK(shell_dep_graph_parse(source, at, "/workspace", &limits, &graph) ==
        SHELL_DEP_EWORKSPACE);
  size_t original_size = limits.workspace_size;
  void *larger = realloc(limits.workspace, original_size + length);
  CHECK(larger);
  limits.workspace = larger;
  limits.workspace_size = original_size + length;
  CHECK(shell_dep_graph_parse(source, at, "/workspace", &limits, &graph) ==
        SHELL_DEP_OK);
  limits.workspace_size = original_size;
  reentrant_source_t input = {source, at, scratch_limits, 0};
  static const char outer[] = "echo \"$word\"";
  size_t resolved_size;
  CHECK(shell_dep_resolved_workspace_size(sizeof(outer) - 1, &limits,
                                          &resolved_size));
  shell_dep_limits_t resolved = limits;
  resolved.workspace = malloc(resolved_size);
  resolved.workspace_size = resolved_size;
  CHECK(resolved.workspace);
  CHECK(shell_dep_graph_parse_resolved(outer, sizeof(outer) - 1, "/workspace",
                                       &resolved, &graph, reentrant_source,
                                       &input, NULL) == SHELL_DEP_OK);
  CHECK(input.calls == 1 && shell_dep_graph_validate(&graph).valid);
  free(resolved.workspace);
  /* The same scratch contract applies to a document recovered from the body
   * of an unfinished backtick, not just a complete top-level declaration. */
  char *legacy = malloc(at + 6);
  CHECK(legacy);
  memcpy(legacy, "echo `", 6);
  memcpy(legacy + 6, source, at);
  CHECK(shell_parse_draft(legacy, at + 6, NULL, &draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
  CHECK(shell_parse_draft(legacy, at + 6, &scratch_limits, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.header_count == 2 && draft.heredoc_count == 1 &&
        draft.heredocs[0].complete);
  content(&draft.heredocs[0].content, "x\n");
  free(legacy);
  free(source);
  free(scratch);
}

static void grouped_delimiter_workspace(void) {
  char delimiter[128] = "$(echo";
  for (unsigned i = 0; i < 40; i++)
    strcat(delimiter, " x");
  strcat(delimiter, ")");
  char source[256];
  int count = snprintf(source, sizeof(source), "cat <<%s\npayload\n%s\n",
                       delimiter, delimiter);
  CHECK(count > 0 && (size_t)count < sizeof(source));
  size_t length = (size_t)count, fixed, extra;
  CHECK(shell_dep_workspace_size(NULL, &fixed));
  CHECK(shell_source_workspace_size(length, &extra));
  CHECK(extra <= SIZE_MAX - fixed);
  shell_dep_limits_t storage = limits;
  storage.workspace_size = fixed + extra;
  storage.workspace = malloc(storage.workspace_size);
  CHECK(storage.workspace);
  shell_limits_t lexical = SHELL_LIMITS_DEFAULT;
  lexical.workspace = (char *)storage.workspace + fixed;
  /* A flat-delimiter byte estimate does not cover the command printer's
   * normalization pieces, even though this delimiter keeps its spelling. */
  lexical.workspace_size = 2 * length;
  CHECK(shell_parse_draft(source, length, &lexical, &draft) ==
        SHELL_SOURCE_TRUNCATED);
  CHECK(!draft.prefix_length && !draft.prefix.count);
  storage.workspace_size = fixed + lexical.workspace_size;
  CHECK(shell_dep_graph_parse(source, length, "/workspace", &storage, &graph) ==
        SHELL_DEP_EWORKSPACE);
  lexical.workspace_size = extra;
  CHECK(shell_parse_draft(source, length, &lexical, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.heredoc_count == 1 && draft.header_count == 1);
  content(&draft.heredocs[0].content, "payload\n");
  storage.workspace_size = fixed + extra;
  CHECK(shell_dep_graph_parse(source, length, "/workspace", &storage, &graph) ==
        SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(&graph).valid);
  free(storage.workspace);
}

static void expanded_delimiter_workspace(void) {
  size_t size = 99;
  CHECK(!shell_source_workspace_size(SIZE_MAX / 2 + 1, &size) && !size);
  CHECK(!shell_dep_resolved_workspace_size(SIZE_MAX / 2 + 1, NULL, &size) &&
        !size);
  size_t previous_work = 0;
  for (size_t count = 128; count <= 2048; count *= 2) {
    size_t capacity = 6 * count + 64;
    char *source = malloc(capacity);
    CHECK(source);
    static const char opening[] = "cat <<`\"`$'";
    size_t at = sizeof(opening) - 1;
    memcpy(source, opening, at);
    for (size_t i = 0; i < count; i++) {
      source[at++] = '\\';
      source[at++] = '\'';
    }
    source[at++] = '\'';
    source[at++] = '\n';
    size_t received = at;
    size_t delimiter_size = 4 * count + 4;
    CHECK(delimiter_size > received);
    CHECK(shell_source_workspace_size(received, &size));
    unsigned char *scratch = malloc(size);
    CHECK(scratch);
    shell_limits_t storage = SHELL_LIMITS_DEFAULT;
    storage.workspace = scratch;
    storage.workspace_size = received;
    CHECK(shell_parse_draft(source, received, &storage, &draft) ==
          SHELL_SOURCE_TRUNCATED);
    CHECK(!draft.prefix_length && !draft.prefix.count);
    storage.workspace_size = delimiter_size - 1;
    CHECK(shell_parse_draft(source, received, &storage, &draft) ==
          SHELL_SOURCE_TRUNCATED);
    storage.workspace_size = size;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    CHECK(shell_parse_draft(source, received, &storage, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.need == SHELL_SOURCE_NEEDS_HEREDOC_BODY &&
          draft.heredoc_count == 1 && draft.heredocs[0].header_complete);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_HEREDOC_PREPARATION);
    CHECK(work > count && work < received * 48);
    CHECK(!previous_work || work < 3 * previous_work);
    previous_work = work;
#else
    (void)previous_work;
#endif
    /* The allocating lexical API retains diagnostic prefixes. Do not turn
     * this incomplete document into arena exhaustion by reserving only the
     * shorter received source length. */
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    CHECK(shell_tokenize_commands(source, received, &commands,
                                  &command_count) == SHELL_TOKENIZE_OK);
    CHECK(commands && command_count == 1);
    shell_commands_free(commands, command_count);
    /* Expected spelling is independent of the decoder: the literal backtick
     * opens double-quote removal state, preserving the protected ANSI bytes. */
    memcpy(source + at, "payload\n``'", 11);
    at += 11;
    for (size_t i = 0; i < count; i++) {
      memcpy(source + at, "'\\''", 4);
      at += 4;
    }
    memcpy(source + at, "'\n", 3);
    at += 2;
    CHECK(at < capacity);
    storage.workspace_size = delimiter_size;
    CHECK(shell_parse_draft(source, at, &storage, &draft) ==
          SHELL_SOURCE_COMPLETE);
    CHECK(draft.heredocs[0].closing_delimiter.start == received + 8 &&
          draft.heredocs[0].closing_delimiter.length == delimiter_size + 1);
    content(&draft.heredocs[0].content, "payload\n");
    shell_parse_result_t fast;
    storage.strict_mode = true;
    CHECK(shell_parse_fast(source, at, &storage, &fast) == SHELL_OK);
    shell_dep_limits_t resolved = limits;
    CHECK(shell_dep_resolved_workspace_size(at, &limits,
                                            &resolved.workspace_size));
    resolved.workspace = malloc(resolved.workspace_size);
    CHECK(resolved.workspace);
    CHECK(shell_dep_graph_parse_resolved(source, at, "/workspace", &resolved,
                                         &graph, NULL, NULL,
                                         NULL) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
    if (count == 128) {
      for (unsigned api = 0; api < 9; api++) {
        allocating_adapter(source, at, api, false);
#ifdef SHELLSPLIT_TEST_ALLOCATOR
        shellsplit_test_alloc_fail_at(1);
        allocating_adapter(source, at, api, true);
        shellsplit_test_alloc_reset();
#endif
      }
      reentrant_source_t input = {source, at, storage, 0};
      static const char outer[] = "echo \"$word\"";
      CHECK(shell_dep_graph_parse_resolved(
                outer, sizeof(outer) - 1, "/workspace", &resolved, &graph,
                reentrant_source, &input, NULL) == SHELL_DEP_OK);
      CHECK(input.calls == 1);
    }
    free(resolved.workspace);
    free(scratch);
    free(source);
  }
}

typedef struct {
  const char *source;
  size_t length, prefix, data, data_length;
  unsigned calls;
  bool nested;
  shell_dep_limits_t child_limits;
  shell_dep_graph_t *child_graph;
} overlapping_source_t;

static shell_expand_status_t
overlapping_source(const shell_expand_word_request_t *request,
                   const char **records, size_t *record_length, void *context) {
  (void)request;
  (void)records;
  (void)record_length;
  overlapping_source_t *input = context;
  input->calls++;
  CHECK(shell_parse_draft(input->source, input->prefix, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(draft.heredoc_count == 1 && !draft.heredocs[0].complete);
  CHECK(shell_parse_draft(input->source + input->data, input->data_length, NULL,
                          &draft) == SHELL_SOURCE_INVALID);
  CHECK(shell_parse_draft(input->source, input->length, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(draft.heredoc_count == 1 && draft.heredocs[0].complete);
  if (!input->nested) {
    input->nested = true;
    CHECK(shell_dep_graph_parse_resolved(input->source, input->length,
                                         "/workspace", &input->child_limits,
                                         input->child_graph, overlapping_source,
                                         input, NULL) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(input->child_graph).valid);
  }
  return SHELL_EXPAND_UNRESOLVED;
}

static void callback_domains(void) {
  static const char source[] = "cat <<'EOF'\necho 日本\nEOF\necho \"$word\"";
  overlapping_source_t input = {.source = source,
                                .length = sizeof(source) - 1,
                                .data = 12,
                                .data_length = sizeof("echo 日本") - 1};
  input.data = (size_t)(strstr(source, "echo 日本") - source);
  input.prefix = (size_t)(strstr(source, "\nEOF") - source) + 1;
  CHECK(shell_parse_draft(source, input.prefix, NULL, &draft) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(shell_parse_draft(source + input.data, input.data_length, NULL,
                          &draft) == SHELL_SOURCE_INVALID);
  shell_dep_limits_t resolved = limits;
  CHECK(shell_dep_resolved_workspace_size(input.length, &limits,
                                          &resolved.workspace_size));
  resolved.workspace = malloc(resolved.workspace_size);
  input.child_limits = resolved;
  input.child_limits.workspace = malloc(resolved.workspace_size);
  input.child_graph = malloc(sizeof(*input.child_graph));
  CHECK(resolved.workspace && input.child_limits.workspace &&
        input.child_graph);
  CHECK(shell_dep_graph_parse_resolved(source, input.length, "/workspace",
                                       &resolved, &graph, overlapping_source,
                                       &input, NULL) == SHELL_DEP_OK);
  CHECK(input.calls == 2 && shell_dep_graph_validate(&graph).valid);
  /* The supplied-fast path imports the parent's byte proof, but callbacks
   * must still reject high-byte heredoc data reinterpreted as shell code. */
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  shell_parse_result_t fast;
  CHECK(shell_parse_fast(source, input.length, &strict, &fast) == SHELL_OK);
  shell_expand_cache_t cache;
  shell_dep_limits_t graph_limits = resolved;
  CHECK(shell_expand_cache_init(
      overlapping_source, &input, source, input.length, false,
      resolved.workspace, resolved.workspace_size, &cache,
      &graph_limits.workspace, &graph_limits.workspace_size));
  shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  input.calls = 0;
  input.nested = false;
  CHECK(shell_dep_graph_parse_with_fast_resolver(
            source, input.length, "/workspace", &graph_limits, &fast, &graph,
            &resolver, unresolved) == SHELL_DEP_OK);
  CHECK(cache.error == SHELL_DEP_OK);
  CHECK(input.calls == 2 && shell_dep_graph_validate(&graph).valid);
  free(input.child_graph);
  free(input.child_limits.workspace);
  free(resolved.workspace);
}

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
static void supplied_fast_reuse(void) {
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
                                          &fast, &graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == 0);
    CHECK(shell_dep_graph_validate(&graph).valid);

    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast_resolver(source, length, "/workspace",
                                                   &limits, &fast, &graph, NULL,
                                                   unresolved) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == 0);
    CHECK(shell_dep_graph_validate(&graph).valid);

    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast(source, length, "/workspace", &limits,
                                          NULL, &graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 1);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == length);

    CHECK(shell_parse_draft(source, length + sizeof(tail) - 1, NULL, &draft) ==
          SHELL_SOURCE_INCOMPLETE);
    CHECK(draft.prefix_length == length);
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast(source, draft.prefix_length,
                                          "/workspace", &limits, &draft.prefix,
                                          &graph) == SHELL_DEP_OK);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == 0);
    shellsplit_test_source_scan_reset();
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, draft.prefix_length, "/workspace", &limits, &draft.prefix,
              &graph, NULL, unresolved) == SHELL_DEP_OK);
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
                                        &graph) == SHELL_DEP_ETRUNC);
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
                                        &graph) == SHELL_DEP_ETRUNC);
  CHECK(shellsplit_test_metadata_work(
            SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 1);
  CHECK(!graph.node_count && !graph.edge_count);
  free(extra.workspace);
  static const char invalid[] = "echo && ;";
  strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  CHECK(shell_parse_fast(invalid, sizeof(invalid) - 1, &strict, &fast) ==
        SHELL_EPARSE);
  CHECK(shell_dep_graph_parse_with_fast(invalid, sizeof(invalid) - 1,
                                        "/workspace", &limits, &fast,
                                        &graph) == SHELL_DEP_EPARSE);
  CHECK(!graph.node_count && !graph.edge_count);
}

static shell_expand_status_t
callback_work(const shell_expand_word_request_t *request, const char **records,
              size_t *record_length, void *context) {
  (void)request;
  (void)records;
  (void)record_length;
  unsigned *calls = context;
  (*calls)++;
  static const char source[] = "echo \"$(printf callback)\"";
  CHECK(shell_parse_draft(source, sizeof(source) - 1, NULL, &draft) ==
        SHELL_SOURCE_COMPLETE);
  return SHELL_EXPAND_UNRESOLVED;
}

static void callback_index_work(void) {
  for (unsigned depth = 4; depth <= 16; depth *= 2) {
    char source[2048];
    const char *opening = "echo \"$word\" \"$(";
    size_t at = 0;
    for (unsigned d = 0; d < depth; d++) {
      memcpy(source + at, opening, strlen(opening));
      at += strlen(opening);
    }
    memcpy(source + at, "printf ", 7);
    at += 7;
    size_t leaf = at;
    memset(source + at, 'x', 1024);
    at += 1024;
    for (unsigned d = 0; d < depth; d++) {
      memcpy(source + at, ")\"", 2);
      at += 2;
    }
    shell_dep_limits_t resolved = limits;
    CHECK(shell_dep_resolved_workspace_size(at, &limits,
                                            &resolved.workspace_size));
    resolved.workspace = malloc(resolved.workspace_size);
    CHECK(resolved.workspace);
    unsigned calls = 0;
    shellsplit_test_source_scan_reset();
    shellsplit_test_delimiter_watch(source + leaf, 1024);
    CHECK(shell_dep_graph_parse_resolved(source, at, "/workspace", &resolved,
                                         &graph, callback_work, &calls,
                                         NULL) == SHELL_DEP_OK);
    CHECK(calls >= depth);
    size_t visits = shellsplit_test_delimiter_work();
    if (visits > 8 * 1024)
      fprintf(stderr, "callback rescanned leaf: depth=%u visits=%zu\n", depth,
              visits);
    CHECK(visits <= 8 * 1024);
    free(resolved.workspace);
  }
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
    parse(cases[c].source);
    unsigned command = 0;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      if (graph.nodes[n].type != SHELL_NODE_CMD)
        continue;
      const shell_dep_cmd_t *cmd = &graph.nodes[n].cmd;
      const char *expected = cases[c].expected[command++];
      if (cmd->cwd_known != (expected != NULL))
        fprintf(stderr, "cwd mismatch: %s command %u known=%d\n",
                cases[c].source, command, cmd->cwd_known);
      CHECK(cmd->cwd_known == (expected != NULL));
      if (expected)
        CHECK(!strcmp(graph.cwd_buf.data + cmd->cwd_offset, expected));
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
    parse(files[c].source);
    unsigned matched = 0;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const shell_dep_node_t *node = &graph.nodes[n];
      if (node->type != SHELL_NODE_DOC || node->doc.kind != SHELL_DOC_FILE ||
          node->doc.path_len != strlen("input.c") ||
          memcmp(node->doc.path, "input.c", strlen("input.c")))
        continue;
      matched++;
      CHECK(node->doc.cwd_known == files[c].known);
      char path[64];
      size_t written;
      bool absolute;
      CHECK(shell_dep_doc_file_identity_write(&graph, &node->doc, path,
                                              sizeof(path), &written,
                                              &absolute) == files[c].known);
      if (files[c].known) {
        CHECK(absolute && written == strlen("/workspace/input.c"));
        CHECK(!memcmp(path, "/workspace/input.c", written));
      }
    }
    CHECK(matched == 1);
  }
}

int main(void) {
  limits = SHELL_DEP_LIMITS_DEFAULT;
  CHECK(shell_dep_workspace_size(NULL, &limits.workspace_size));
  limits.workspace = malloc(limits.workspace_size);
  CHECK(limits.workspace);
  heredocs();
  byte_domains();
  selector_recovery();
  tentative_delimiters();
  recovery();
  pending_pipeline_prefixes();
  keyword_recovery();
  prefixes();
  local_completeness();
  unfinished_children();
  backtick_escape_domains();
  code_region_stream();
  allocating_delimiters();
  capacity_and_work();
  continued_operators();
  delimiter_regressions();
  delimiter_phases();
  delimiter_fragments();
  pending_redirectors();
  missing_redirect_operands();
  nested_redirect_recovery();
  duplication_recovery();
  delimiter_workspace();
  grouped_delimiter_workspace();
  expanded_delimiter_workspace();
  callback_domains();
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  supplied_fast_reuse();
  callback_index_work();
#endif
  cwd();
  free(limits.workspace);
  puts("source, draft, and static CWD contracts passed");
  return 0;
}
