#ifndef SHELLSPLIT_CONTROL_WORD_CASES_H
#define SHELLSPLIT_CONTROL_WORD_CASES_H

#include "shell_tokenizer.h"

/* These complete sources contain keyword-shaped fragments, not reserved
 * control words. Count child commands independently of SUBST edges: an output
 * process substitution used as a word retains its child without inventing a
 * descriptor route. Range features are lexical, independent of grammar role. */
static const struct {
  const char *source;
  unsigned producers;
  unsigned subst_edges;
  uint32_t range_control_features;
} shellsplit_test_control_word_fragments[] = {
    {"fi$(printf x)", 1, 1, 0},
    {"if$(printf x) then", 1, 1, SHELL_FEAT_CONDITIONALS},
    {"then<(printf x)", 1, 1, 0},
    {"done>(printf x)", 1, 0, 0},
    {"esac`printf x`", 1, 1, 0},
    {"fi$((1))", 0, 0, 0},
    {"$(printf x)fi", 1, 1, 0},
    {"<(printf x)done", 1, 1, 0},
    {"`printf x`else", 1, 1, 0},
    {"f\\\ni\\\n$(printf x)", 1, 1, 0},
    {"$(printf x)\\\nfi", 1, 1, 0},
    {"time -p fi$(printf x)", 1, 1, 0},
    {"! fi$(printf x) | cat", 1, 1, 0},
    {"true && fi$(printf x)", 1, 1, 0},
    {"{ fi$(printf x); }", 1, 1, 0},
    {"( fi$(printf x) )", 1, 1, 0},
    {"cat >fi$(printf x)", 1, 1, 0},
    {"echo fi$(printf x)", 1, 1, 0},
    {"fi\"$tail\"", 0, 0, 0},
    {"\"fi\"$(printf x)", 1, 1, 0},
    {"\\fi$(printf x)", 1, 1, 0},
    {"echo $(fi$(printf x))", 1, 2, 0},
};

#endif
