/* Private shell_depgraph.c implementation, included after dep_parse_context_t.
 * Coverage qualifies facts independently of Boolean reachability and setup
 * success. CWD qualification uses only the source boundary; effect execution
 * also requires effects_active. No state or traversal is added here. */

/* boundary is the current source coverage barrier; position is a source
 * position being qualified, including a conditional primary's end boundary. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline bool dep_coverage_position_blocked(uint32_t boundary,
                                                 size_t position) {
  return position >= boundary;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline SHELL_NONNULL(1) bool dep_coverage_effects_blocked(
    const dep_parse_context_t *context, uint32_t position) {
  return !context->effects_active || position >= *context->semantic_barrier;
}

/* Keep status publication and boundary lowering individually inline so an
 * owner can preserve invalidation between them at its execution point. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline SHELL_NONNULL(1) void dep_record_arithmetic_status(
    shell_dep_graph_t *graph) {
  graph->status |= SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline SHELL_NONNULL(1) void dep_lower_coverage_boundary(
    const dep_parse_context_t *context, uint32_t boundary) {
  if (boundary < *context->semantic_barrier)
    *context->semantic_barrier = boundary;
}

/* graph and the context's coverage state are mutable. boundary belongs to
 * the current source; callers retain owner-specific flags and invalidation. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline SHELL_NONNULL(1, 2) void dep_record_arithmetic_coverage(
    shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t boundary) {
  dep_record_arithmetic_status(graph);
  dep_lower_coverage_boundary(context, boundary);
}

/* Import semantic coverage independently of descriptor and exit-status
 * imports. Only potentially executing children qualify the parent's facts.
 * child is successfully constructed, out and context's coverage state are
 * mutable, and opening points within context's immutable parent source.
 * All pointer arguments remain required when active is false. */
static SHELL_NONNULL(1, 2, 3, 4) void dep_import_child_coverage(
    shell_dep_graph_t *out, const shell_dep_graph_t *child,
    const dep_parse_context_t *context, const char *opening, bool active) {
  if (active && (child->status & SHELL_DEP_STATUS_UNRESOLVED_ARITHMETIC)) {
    dep_record_arithmetic_coverage(out, context,
                                   (uint32_t)(opening - context->cmd));
  }
}
