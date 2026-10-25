# Security model and reporting

Shellclave analyzes and classifies submitted shell source. Applications combine
its policy, I/O, and uncertainty results with their own execution controls.
Until 1.0, deploy these results as defense-in-depth signals alongside operating
system isolation and application-specific access checks.

## Source admission

Applications that distinguish malformed source from unsupported analysis use
Shellsplit's [typed source outcomes](shellsplit/README.md#classifying-input-before-dispatch)
before dispatch. INVALID establishes a grammar error; INVALID_INPUT rejects
embedded NUL. UNSUPPORTED leaves the required judgment unclassified, rather
than proving Bash validity. An application's explicit-review path must bind
approval to the complete unchanged source and execution context. INCOMPLETE
and TRUNCATED retain their separate recovery and resource meanings.

Fast-parser and graph parse errors are coarse; Shellgate's rejection of
unsupported semantics is a policy-evaluation boundary, not proof of a syntax
error. A successful source classification still requires semantic analysis and
application authorization. The [compiled example](examples/source_admission.c)
shows classification and ownership without executing input.

## Interpreting an evaluation

Read the `sg_gate_evaluate()` return code first. `SG_OK` establishes that the
evaluation completed as reported; the verdict and completeness fields describe
its policy result. `SG_ERR_INVALID` can return before initializing the result.
Withhold authorization on every error, including allocation, expansion,
canonical-format, parse, and truncation failures.

| Verdict | Meaning |
|---|---|
| `ALLOW` | Evaluated policy-evaluable commands match the allow policy, with no deny match |
| `ALLOW_CONDITIONAL` | Policy matches carry an outstanding shell-word substitution inspection requirement |
| `DENY` | At least one evaluated command matches the deny policy |
| `REJECT` | Source is rejected by syntax, supported semantics, or the configured feature mask |
| `UNDETERMINED` | Policy coverage or evaluation information is insufficient |

Deny matches take precedence over allow matches. A missing allow rule yields
`UNDETERMINED`. Assignment-only and redirect-only operations, such as `VALUE=x`
and `>output`, also lack argv-policy coverage. Prefix assignments and redirects
on a command have effects separate from its matched argv. The README's
[policy coverage rules](README.md#what-policy-rules-cover) describe these
distinctions, builtins, and nested subjects. Semantic no-ops, such as comment-only
source, can return `ALLOW` with zero policy-evaluable commands.

For a full-input decision, use `SG_EVAL_ALL` and require `truncated == false`
and `short_circuited == false`. Early-stop modes report their evaluated prefix.
The `subcommand_truncated` and `violation_truncated` fields identify affected
result categories. A truncated graph covers only retained metadata.

`SG_ERR_MEMORY` can mean evaluation workspace is insufficient; the size hint
is an initial estimate. Resolved values and diagnostic text may require more
space. Grow the buffer within application limits and retry. `SG_ERR_TRUNC`
may also reflect fixed parser/graph/result capacities, which require reducing
or refusing the input. A diagnostic-buffer overflow can accompany another
primary error. Failed or truncated evaluation leaves anomaly learning unchanged.

## Runtime values and substitution inspection

`unresolved_expansion_flags` distinguishes unresolved argv and pathname values.
These flags can accompany `ALLOW`: policy matching may have used processed
source spelling. Applications needing final-value checks resolve eligible words
through the documented callback or keep the decision pending. The callback
returns canonical netargv valid for every modeled execution state reaching that
word; a value the caller cannot establish remains `SHELL_EXPAND_UNRESOLVED`.
Command identity, assignments, and protected shell-state operands have separate
modeling rules; the ordinary-word callback does not resolve those roles.

`requires_substitution_evaluation` identifies runtime-generated shell-word
content requiring inspection and evaluation in its receiving role. Resolve that
obligation before treating a conditional match as executable authorization.
Keep the decision pending or request review when the required content and
execution context cannot be established. Applications obtain
the detailed routes directly from Shellsplit's dependency graph. A filename
resolution callback establishes a pathname, while substitution inspection
addresses the content delivered along the identified flow.

`has_dynamic_substitution_io` is a broader topology indicator. Ordinary
`cat <(producer)` carries process I/O; `sh < <(producer)` consumes that stream
as a program because of the explicit interpreter. The application evaluates
the receiving command's role. A SUBST edge alone is not a risk classification.
The model's unsupported dynamic re-evaluation forms and runtime-dispatch limits
are listed in the [shell reference](docs/shell-model.md).

## Execution responsibilities

| Concern | Application responsibility |
|---|---|
| Executor | Supply the pinned Bash 5.3.20 reference and the startup state below |
| Source and state | Execute the analyzed source with corresponding CWD, environment, descriptors, and resolved inputs |
| Program behavior | Select trusted executables and enforce program-specific argument and access policies |
| File access | Check graph I/O effects, filesystem identities, symlinks, permissions, and races as required |
| Resource control | Set time, memory, process, filesystem, and network limits for execution |
| Additional findings | Decide how advisory violations and anomaly observations affect review or enforcement |

Argument rules authorize command shapes. For example, both `git status --short`
and `git status --short >report.txt` can match the same argv rule. The second
command also performs output setup, available through Shellsplit's graph.
Known lexical path identities support analysis; filesystem coherence checks
must use the application's actual access boundary.

Violation findings summarize configured heuristics and observed graph facts.
Anomaly scores measure unusualness. Applications may spend more effort on risk
estimation for unusual commands while keeping those concepts separate.

### Executor startup

Use one fresh noninteractive shell for each submitted full command. The supported
basis is the pinned `bash -p -c ...`, with these preparations:

1. Start with `POSIXLY_CORRECT` absent; an empty value still enables POSIX mode.
2. Remove `BASH_COMPAT` and `BASH_XTRACEFD` from the startup environment.
3. Set `LC_ALL` to `C` (the portable default), `POSIX`, or an installed UTF-8
   locale before launching Bash. Make it readonly in trusted startup code so
   submitted source cannot change character interpretation. C/POSIX and UTF-8
   use the same byte-oriented syntax model; literal word and comment bytes are
   preserved without encoding validation or normalization. The embedding
   application's locale is independent: analysis uses fixed byte predicates and
   leaves it unchanged.
4. Make the three cleared names readonly before submitted source.
5. Preserve the modeled option and command-lookup state: no startup aliases or
   traps, imported/shadowing functions, or disabled modeled builtins. Privileged
   Bash ignores `BASH_ENV`, `BASHOPTS`, and `SHELLOPTS` and declines imported
   environment functions.

Keep `nocasematch` disabled so literal and star-pattern comparisons retain
case-sensitive byte matching. Extglob requires enabling `extglob` at executor startup,
before parsing source.
An equivalent launcher must establish these same properties. The application
owns executor selection; version checks run at the test/configuration boundary.
See the [shell model](docs/shell-model.md#executor-and-analysis-boundaries) for
the supported language and configuration distinctions.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
**Security → Report a vulnerability** flow for this repository. If that flow
is unavailable, contact the repository owner privately through the contact
route on the `panz-r` GitHub profile and request a secure reporting channel;
do not include exploit details in the first message.

Only the latest release and the current `main` branch receive security fixes.
No response-time or embargo guarantee is currently offered. Reports should
include the affected revision, platform, minimal reproducer, expected impact,
and sanitizer output when available.

