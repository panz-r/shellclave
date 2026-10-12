# Repository engineering rules

## Component-oriented interfaces

Applications use Shellsplit, Shelltype, and the anomaly API directly for the
operations those components own. Components must not shadow each other with
pass-through APIs, duplicate semantic types, or wrapper layers intended to hide
another component. Shared interface definitions belong to the component that
owns their semantics. Higher-order orchestration with genuinely distinct
behavior is appropriate: combined policy evaluation, coordinated model
learning, calibration, and transactional paired persistence are examples.

Document ownership and borrowing explicitly. Installed policies are logically
immutable: build updates through Shelltype on an uninstalled replacement, then
install that replacement. Evaluation may warm synchronized caches and update
statistics, but must not change rules. Several gates may borrow the same stable
policy. Its owner must keep it alive until all borrowing gates detach and all
readers and borrowed views finish. Replacement and destruction require caller
synchronization; do not add hidden reference counting or repeated ownership
checks to enforce these documented requirements.

## Caller preconditions, not defensive callee checks

The caller is responsible for satisfying a function's documented preconditions.
Express those constraints in interface documentation and compiler annotations;
do not make every callee defensively verify them again.

- Annotate required pointers with the existing `SHELL_NONNULL(...)` macro. A
  required pointer must reference valid storage of the documented size and
  lifetime. Do not add NULL guards, assertions, or fallback behavior for it.
- Document other caller constraints explicitly: span sizes, ownership,
  initialization, empty output destinations, aliasing, immutability, and the
  relationship between supplied objects. Use suitable compiler annotations
  where available.
- Do not reparse, recompute, copy, or traverse data merely to verify a caller
  precondition. For example, supplying an unchanged parse result with its
  original immutable source is a caller requirement, not a reason for the graph
  builder to reparse that source or validate their correspondence.
- Do not enlarge result types or introduce redundant state solely to protect
  against invalid API use. Clarify the contract instead.
- A NULL check is appropriate only when NULL has documented semantic meaning,
  such as a default configuration, an optional output or callback, a cleanup
  no-op, or an empty byte span. An unannotated pointer is not automatically
  nullable: document the accepted NULL cases and any associated conditions.

Place bounds, NULL, framing, and similar checks at clearly documented validation
boundaries where they are actually needed. State what each boundary checks,
which invalid inputs it accepts for rejection, and what guarantees hold after
successful validation. Pointers that a boundary accepts as potentially NULL
must not be annotated as unconditionally non-null.

Pass clearly annotated and documented sanitized or prechecked values from those
boundaries into leaf and near-leaf functions. Those functions rely on the
established guarantees; they must not repeat bounds, NULL, or consistency checks
for the same values. A new check requires a new, genuine validation need, not
merely another function call.

This rule does not remove meaningful runtime validation of untrusted shell
syntax and encoded data, supported features, resource limits, or arithmetic
overflow. Nor does it remove handling of allocation and I/O failures that arise
during an operation. Keep these checks at their appropriate documented
boundaries, separate from caller preconditions.

Tests must respect caller preconditions. Test annotations with compiler
diagnostics, rather than invoking functions with invalid required pointers or
fabricated inconsistent internal objects. Keep runtime tests for malformed
external input, meaningful NULL cases, and genuine operational failures.
