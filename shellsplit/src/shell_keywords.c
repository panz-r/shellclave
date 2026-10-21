#include "shell_keywords_internal.h"
#include "shell_source_lexical_internal.h"

/* One spelling and classification table for every frontend projection.
 * Keep spellings sorted so recognition visits only candidates with the same
 * initial byte. Ordinary words do not probe every keyword spelling. */
static const struct {
  const char *word;
  size_t length;
  shell_keyword_t facts;
} keywords[] = {
    {"[[", 2, {SHELL_KEYWORD_TEST_OPEN, 0, SHELL_KEYWORD_DEPTH_NONE, 0}},
    {"]]", 2, {SHELL_KEYWORD_TEST_CLOSE, 0, SHELL_KEYWORD_DEPTH_NONE, 0}},
    {"case",
     4,
     {SHELL_KEYWORD_CASE, SHELL_FEAT_CASE, SHELL_KEYWORD_DEPTH_CASE, 1}},
    {"coproc", 6, {SHELL_KEYWORD_COPROC, 0, SHELL_KEYWORD_DEPTH_NONE, 0}},
    {"do", 2, {SHELL_KEYWORD_DO, 0, SHELL_KEYWORD_DEPTH_NONE, 0}},
    {"done", 4, {SHELL_KEYWORD_DONE, 0, SHELL_KEYWORD_DEPTH_LOOP, -1}},
    {"elif",
     4,
     {SHELL_KEYWORD_ELIF, SHELL_FEAT_CONDITIONALS, SHELL_KEYWORD_DEPTH_NONE,
      0}},
    {"else",
     4,
     {SHELL_KEYWORD_ELSE, SHELL_FEAT_CONDITIONALS, SHELL_KEYWORD_DEPTH_NONE,
      0}},
    {"esac",
     4,
     {SHELL_KEYWORD_ESAC, SHELL_FEAT_CASE, SHELL_KEYWORD_DEPTH_CASE, -1}},
    {"fi",
     2,
     {SHELL_KEYWORD_FI, SHELL_FEAT_CONDITIONALS,
      SHELL_KEYWORD_DEPTH_CONDITIONAL, -1}},
    {"for",
     3,
     {SHELL_KEYWORD_FOR, SHELL_FEAT_LOOPS, SHELL_KEYWORD_DEPTH_LOOP, 1}},
    {"function", 8, {SHELL_KEYWORD_FUNCTION, 0, SHELL_KEYWORD_DEPTH_NONE, 0}},
    {"if",
     2,
     {SHELL_KEYWORD_IF, SHELL_FEAT_CONDITIONALS,
      SHELL_KEYWORD_DEPTH_CONDITIONAL, 1}},
    {"in", 2, {SHELL_KEYWORD_IN, SHELL_FEAT_CASE, SHELL_KEYWORD_DEPTH_NONE, 0}},
    {"select",
     6,
     {SHELL_KEYWORD_SELECT, SHELL_FEAT_LOOPS, SHELL_KEYWORD_DEPTH_LOOP, 1}},
    {"then",
     4,
     {SHELL_KEYWORD_THEN, SHELL_FEAT_CONDITIONALS, SHELL_KEYWORD_DEPTH_NONE,
      0}},
    {"until",
     5,
     {SHELL_KEYWORD_UNTIL, SHELL_FEAT_LOOPS, SHELL_KEYWORD_DEPTH_LOOP, 1}},
    {"while",
     5,
     {SHELL_KEYWORD_WHILE, SHELL_FEAT_LOOPS, SHELL_KEYWORD_DEPTH_LOOP, 1}},
};

const shell_keyword_t *shell_source_keyword(const char *input, size_t end,
                                            size_t position, size_t *after) {
  if (after)
    *after = position;
  position = shell_source_skip_escaped_line_endings(input, end, position);
  if (position == end)
    return NULL;
  SHELL_SOURCE_WORD_SCAN(1);
  unsigned char first = (unsigned char)input[position];
  size_t low = 0, high = sizeof(keywords) / sizeof(keywords[0]);
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    if ((unsigned char)keywords[middle].word[0] < first)
      low = middle + 1;
    else
      high = middle;
  }
  for (size_t i = low; i < sizeof(keywords) / sizeof(keywords[0]) &&
                       (unsigned char)keywords[i].word[0] == first;
       ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    size_t word_end;
    if (shell_source_match_plain_word(input, end, position, keywords[i].word,
                                      keywords[i].length, &word_end)) {
      if (after)
        *after = word_end;
      return &keywords[i].facts;
    }
  }
  return NULL;
}
