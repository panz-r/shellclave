#ifndef ST_POLICY_VARIANTS_H
#define ST_POLICY_VARIANTS_H

#include "shelltype.h"

/**
 * @file policy_variants.h
 *
 * Token variant suggestion for policy editing UI.
 *
 * Given a pattern and a position, returns the observed types at that position
 * from the trie context, allowing the UI to present type generalization options.
 */

/**
 * Maximum number of type variants we can return for one token position.
 */
#define ST_MAX_TOKEN_VARIANTS 8

/**
 * Context for token variant lookup.
 * Must be initialized with either a learner OR a policy context.
 */
typedef struct {
    st_learner_t *learner;          /* For trie-based variant lookup (may be NULL) */
    const st_policy_ctx_t *policy_ctx; /* For policy-based lookup (may be NULL) */
} st_variant_ctx_t;

/**
 * Initialize a variant context from a learner.
 */
static inline void st_variant_ctx_init_learner(st_variant_ctx_t *ctx, st_learner_t *learner)
{
    ctx->learner = learner;
    ctx->policy_ctx = NULL;
}

/**
 * Initialize a variant context from a policy context.
 */
static inline void st_variant_ctx_init_policy(st_variant_ctx_t *ctx, const st_policy_ctx_t *policy_ctx)
{
    ctx->learner = NULL;
    ctx->policy_ctx = policy_ctx;
}

#endif /* ST_POLICY_VARIANTS_H */