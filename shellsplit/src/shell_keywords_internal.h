#ifndef SHELL_KEYWORDS_INTERNAL_H
#define SHELL_KEYWORDS_INTERNAL_H

#include "shell_tokenizer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SHELL_KEYWORD_NONE,
  SHELL_KEYWORD_IF,
  SHELL_KEYWORD_THEN,
  SHELL_KEYWORD_ELSE,
  SHELL_KEYWORD_ELIF,
  SHELL_KEYWORD_FI,
  SHELL_KEYWORD_FOR,
  SHELL_KEYWORD_WHILE,
  SHELL_KEYWORD_UNTIL,
  SHELL_KEYWORD_DO,
  SHELL_KEYWORD_DONE,
  SHELL_KEYWORD_CASE,
  SHELL_KEYWORD_ESAC,
  SHELL_KEYWORD_SELECT,
  SHELL_KEYWORD_COPROC,
  SHELL_KEYWORD_FUNCTION,
  SHELL_KEYWORD_TEST_OPEN,
  SHELL_KEYWORD_IN,
  SHELL_KEYWORD_TEST_CLOSE,
} shell_keyword_kind_t;

typedef enum {
  SHELL_KEYWORD_DEPTH_NONE,
  SHELL_KEYWORD_DEPTH_CONDITIONAL,
  SHELL_KEYWORD_DEPTH_LOOP,
  SHELL_KEYWORD_DEPTH_CASE,
} shell_keyword_depth_t;

/* Lexical spelling facts. Consumers separately decide grammar eligibility,
 * supported execution, or feature presence. Counter effects and fast feature
 * bits intentionally differ for some words, including do/done. */
typedef struct {
  shell_keyword_kind_t kind;
  uint32_t features;
  shell_keyword_depth_t depth;
  int delta;
} shell_keyword_t;

/* Classify the complete unquoted logical word at position <= end in required
 * immutable input[0..end). Quotes, ordinary escapes and adjacent word fragments
 * prevent recognition; removed backslash-LF does not. Return immutable facts,
 * or NULL for no keyword. Optional after receives the matched physical end;
 * on a miss it receives position. Caller establishes a genuine word start and
 * the relevant word role. end must cover following word-forming fragments,
 * unless the caller has already established a real word boundary there; a
 * lexical token's end alone does not establish one. */
const shell_keyword_t *shell_source_keyword(const char *input, size_t end,
                                            size_t position, size_t *after)
    SHELL_NONNULL(1);

#ifdef __cplusplus
}
#endif
#endif
