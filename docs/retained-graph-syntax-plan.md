# Retained graph I/O boundary correction

Status: graph-level correction implemented. The earlier optional syntax
companion proposal is superseded for this application requirement.

## Original application request

> The gap is specifically in the public retained graph API. Our tests show the
> same graph for:
>
> ```sh
> wc -l file.txt
> wc -l file.txt 2>&1
> ```
>
> Yet `2>&1` changes stderr routing.
>
> Shellsplit's processor API already exposes redirect tokens and
> `has_redirections`. We need that existing metadata accessible alongside the
> graph from the same parse. My earlier wording was too broad.
>
> Can we make this easily available? How should the application access this data?

The initial analysis confirmed that both inputs had the same retained graph:
one CMD, one FILE argument document, and their ARG relation. It proposed a
retained syntax companion because argv tokens do not retain redirects.

## Corrected root cause and approach

The application clarified that the inner command's stderr should connect to
the full command's stdout resource. That is a semantic routing requirement,
not primarily a request for lossless syntax.

Descriptor resolution already computed the inherited destination correctly.
Graph publication omitted inherited/external resources. Adding redirect tokens
would force the caller to reconstruct a relation the library already knows.

The graph-level correction exposes inherited descriptors as `SHELL_NODE_FD`
resources. Each `node.fd.number` names the descriptor inherited at entry to the
complete submitted command. READ/WRITE relations retain the local execution
descriptor and connect to its effective resource. One resource per inherited
number is shared across nested scopes; pipes and captures remain separate.

Ordinary executable standard-stream routes are published by default. For the
original `wc` pair, the stderr WRITE edge targets FD 2 normally and FD 1 after
`2>&1`. In `2>&1 >out`, stderr still targets inherited stdout: descriptor copies
retain the source-order destination rather than a permanent fd-to-fd link.

`cd` is an ordinary command endpoint too. Removing the `cd_as_cmd` option keeps
its stdout and stderr available to captures and inherited/file routes while
retaining the existing CWD tracking. Callers receive the incoming CWD on `cd`
and the analysed continuation CWD on later commands; no caller-side directory
analysis is required. Policies authorize `cd` just like other retained commands.

The graph remains bounded, zero-copy, and allocation-free, using caller-owned
construction workspace. Public graphs retain their nodes and edges independently
of workspace reuse. Existing route resolution supplies the facts; there is no
second shell parse, application-side redirect replay, or Shellgate wrapper.

Resource-key indexing and one structural traversal select the outermost
matching group exposure before storing a command's flow. Temporary storage
does not grow once per redundant intermediate group. Recursive joins preserve
already-coalesced group flows, and root publication creates shared FD resources
only for retained relations. Genuine node or edge exhaustion returns a valid
truncated graph without an orphan boundary node.

These edges describe potential shell routing, not actual program byte use or
OS resource identity. An external boundary must not be treated as an internal
pipe or a substitution collector. All retained alternatives count against the
documented graph capacities; incomplete publication reports truncation.

Publication enumerates one sparse owner-local descriptor inventory, shared by
document, capture, imported, pipe and inherited-boundary projections. Existing
standard entries come from one indexed range walk; auxiliary entries come from
that owner's reached numeric operations. A command never scans its accumulated
inherited descriptor history merely to discard untouched slots. The inventory
uses caller-owned workspace and existing descriptor bounds, with no new public
result state or independent capacity limit.

Setup failure suppresses command-body effects, but not shell-origin stderr.
The same existing CMD/GROUP endpoint now retains diagnostics through the
effective stderr resource at each reached setup or undo failure. This includes
captures, files, pipes, and inherited resources. An indexed, workspace-owned
sink accumulator keeps failure prefixes separate from final body routes;
cached undo results preserve diagnostic routing without replaying prefixes.
Actual GROUP diagnostics remain byte producers during capture reconciliation,
rather than being discarded as merely structural exposures. Graph limits still
fail closed if these additional genuine flows cannot be retained.

Background stdin uses the shared descriptor journal too. Bash's implicit
read-only `/dev/null` is a root-published FILE DOC marked IMPLICIT, separate
from source-written `/dev/null` documents. Its canonical pathname is owned by
the library. An implicit open can fail without aborting the body, so the graph
retains incoming-descriptor alternatives as well. The same transitions drive
expansion snapshots, recursive imports, copies, scope restoration and final
publication. Direct simple-command argv/RHS expansions precede this setup;
redirect operands and bodies follow it. Compound, timed-pipeline and AND/OR
asynchronous interpreters perform the eligible setup before contained
expansions. Exemptions use Bash's redirect instruction classifier and its
interpreter-local stdin marker, not aggregated background flags or fd-0-only
tests. That marker persists across physical newlines in a submitted command.
No public parse-result enlargement or source-correspondence validation was
introduced. Resource publication reserves nodes and edges together and never
creates an unused implicit document.

## Separate concerns

Lossless syntax retention could still serve applications that need original
redirect spelling, source-order no-op operations, or other lexical metadata.
It is not necessary to solve this routing gap and is not part of this change.
Do not restore the earlier companion proposal merely to compensate for missing
semantic graph relations.

The descriptor-move changeset already fixed the separate quadratic undo-prefix
issue. That fix is retained unchanged. Smoke-seed updates and broader shell
syntax support remain outside this correction.
