#ifndef SHELL_TOKEN_REGIONS_INTERNAL_H
#define SHELL_TOKEN_REGIONS_INTERNAL_H

#include "shell_conditional_internal.h"
#include "shell_tokenizer_full_internal.h"

typedef enum {
  SHELL_TOKEN_REGION_WORD,
  SHELL_TOKEN_REGION_CONDITIONAL,
  SHELL_TOKEN_REGION_ARITHMETIC,
} shell_token_region_context_t;

typedef struct {
  const char *text;
  size_t length;
  shell_token_region_context_t context;
} shell_token_region_t;

/* Borrowed expansion-bearing regions, in source order. Conditional grammar
 * and comments are excluded. Zero-length received operands remain available
 * to diagnostic consumers. Only regions[0..count) have meaning; unused entries
 * need not be zero. No source is copied or rescanned by iteration.
 * source is the unchanged base used to obtain condition; its spans are valid
 * for that source, including an incomplete condition. */
typedef struct {
  shell_token_region_t regions[2];
  unsigned count;
} shell_token_regions_t;

static inline SHELL_NONNULL(1, 2) shell_token_regions_t
    shell_conditional_regions(const char *source,
                              const shell_conditional_t *condition) {
  return (shell_token_regions_t){.regions = {{source + condition->operands[0],
                                              condition->operand_lengths[0],
                                              SHELL_TOKEN_REGION_CONDITIONAL},
                                             {source + condition->operands[1],
                                              condition->operand_lengths[1],
                                              SHELL_TOKEN_REGION_CONDITIONAL}},
                                 .count = condition->operand_count};
}

/* A lexer-produced token borrows live immutable source. complete describes
 * arithmetic framing and must be true for an ARITHMETIC expansion token.
 * This initializer recognizes conditional operands once; consumers already
 * holding conditional facts use shell_conditional_regions() instead.
 * Regions do not qualify syntax, completeness or semantic support: callers
 * retain those outcomes at their existing validation/recovery boundaries.
 * Ordinary tokens have one word region; document bodies keep their separate
 * framing and expansion rules at their existing owners. */
static inline SHELL_NONNULL(1) shell_token_regions_t
    shell_token_regions(const shell_token_t *token, bool complete) {
  if (token->type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
    shell_conditional_t condition =
        shell_conditional_parse(token->start, token->length, 0);
    return shell_conditional_regions(token->start, &condition);
  }
  shell_token_regions_t result = {
      .regions = {{token->start, token->length, SHELL_TOKEN_REGION_WORD}},
      .count = 1};
  if (token->type == SHELL_TOKEN_ARITHMETIC ||
      token->type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
    shell_tokenizer_arithmetic_content(token, complete, &result.regions[0].text,
                                       &result.regions[0].length);
    result.regions[0].context = SHELL_TOKEN_REGION_ARITHMETIC;
  }
  return result;
}

#endif
