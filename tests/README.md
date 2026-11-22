# Cutting and improving test suites

A procedure for shrinking a test suite while making it harder to pass by
accident. It applies to any suite whose cases are separately selectable and
whose subject code can be mutated. Measurement tooling is throwaway and is not
committed; what lasts is the cases that survive.

## Principles

- A case earns its place by what only it detects, not by the feature that
  motivated it. A suite is not a history of the code's growth.
- Prefer a few hard cases to many easy ones. One base case plus a table of
  variants is the usual shape: the base states the scenario once, each row
  changes one slot and states what must differ in the outcome.
- Features compose. Cases should combine the supported features in layers,
  not exercise each one alone in its own file.
- Evidence decides. Do not remove, merge or keep a case on judgement about
  how redundant it looks.

## Preconditions

1. Every case is individually selectable (an environment variable or an
   argument naming it). A case must not depend on state left by another;
   if cases share a fixture, selecting one must leave the remaining checks
   valid. Verify with a run that selects nothing: it must pass.
2. A coverage build exists, and a way to run the other suites separately from
   the one under analysis. Keep the suite's twin builds (for example a
   variant of the same source built differently) out of that "everything
   else" set, or every result looks covered elsewhere.
3. Work in a scratch copy of the tree for anything that edits sources or
   inserts selection hooks, so the real tree only ever receives the final
   edit.

## Procedure

1. **Per-case coverage.** Run each case alone and record line and branch
   coverage. Record also the checks that run regardless of selection, and the
   coverage of all other suites combined.
2. **Candidates.** A case is a removal candidate when it reaches nothing that
   is not also reached by the other suites or by other cases of the same suite.
   Choose which of two equivalent cases stays with a greedy set cover, so a
   pair of mutually redundant cases is never removed together.
3. **Mutation kill matrix.** Coverage shows execution, not detection. Apply
   many small mechanical mutations (flip a comparison, swap a boolean
   connective, invert a returned flag) to the code under test, one at a time,
   preferring lines the candidates reach. For each mutant record:
   - whether the full suite kills it,
   - which individual cases kill it,
   - whether the rest of the project kills it.
4. **Restore.** A removal is allowed only when every mutant the full suite
   kills is still killed by a kept case or by another suite. Where a kill
   would be lost, restore a killer, preferring one that covers several lost
   kills. Then repeat with a fresh sample: restoring against one sample
   overfits to it, and a second sample routinely finds more. Stop when a
   sample of meaningful size loses nothing.
5. **Apply.** Remove the case bodies and their invocations, then the helpers
   that lost their last caller. Delete dead helpers; do not silence the
   warning. Keep anything another entry point still uses (a special mode of
   the same binary, a shared header).
6. **Verify.** Run every test, then the coverage thresholds the project
   enforces, serially if runs share instrumented objects. Record what the
   suite lost and gained.
7. **Improve.** The mutants that survive everything point at what is untested.
   Write new variant-table rows or templates aimed at them, and confirm each
   new case kills what it was written for.

## Pitfalls seen

- Selection hooks that wrap a call whose result later checks depend on make
  every run fail early. Wrap only self-contained cases, and always run the
  select-nothing baseline.
- A name in the case list that is a library call or helper, not a case:
  confirm each removed name has a case definition before touching its calls.
- A mutant that loops forever. Give every run a short timeout, kill the whole
  process group on expiry, and when the full suite times out record that
  fact once rather than running each case against it. Orphaned processes
  from earlier mutants slow every later one; check for them.
- Estimating a run's remaining time without looking at when it last wrote
  output. Check timestamps.
- Dead helpers appear only when the file is recompiled; touch the files
  before reading the warnings.
- A restoration list that fits one sample is not a result. Resample.

## What to keep out of the repository

The per-case runner, the mutation driver, the coverage and kill matrices and
the scratch copy are measurement aids. Rebuild them when the exercise is
repeated; commit only the resulting test changes.
