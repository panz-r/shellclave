<p align="center">
  <img src="shellclave_logo.png" alt="Shellclave logo" width="320">
</p>

# Shellclave

Shellclave is a C11 toolkit for **analyzing and classifying shell commands**.
It identifies commands and their dependencies, matches their arguments against
policy rules, and reports modeled I/O routes, unresolved expansions, and
statistical anomalies.

An application screening commands from an AI agent can use Shellclave to
classify a proposed command, inspect its file and substitution dependencies,
and decide whether to run it, request review, or refuse it. The application
owns execution and its security controls.

Submitted source is the entire input supplied for one evaluation. It can contain
lists, pipelines, groups, and nested substitutions. Policy rules match individual
command argument sequences within that input.

For example, with an allow rule `git status --short` and a deny rule
`git reset --hard`:

| Submitted source | Policy classification |
|---|---|
| `git status --short` | `ALLOW` |
| `git reset --hard` | `DENY` |
| `git log --oneline` | `UNDETERMINED`: no matching rule |

Shellsplit analyzes the source and constructs command and I/O relationships.
Shelltype matches argument sequences against policy rules. Shellgate combines
these operations with advisory violation findings and optional anomaly scoring.

## Security model and limitations

An `ALLOW` verdict means that every command included in policy evaluation
matched an allow rule and none matched a deny rule. The
[policy coverage rules](#what-policy-rules-cover) below define which commands
participate. The fields below identify incomplete coverage and unresolved
argument or pathname expansions.

First check the return code and completeness flags. Then interpret the verdict
and any unresolved-expansion or substitution-inspection requirements. These
conditions can occur together. Verdict names here abbreviate the public
`SG_VERDICT_*` constants.

A shell word is a syntactic unit whose expansion can produce zero or more
arguments. Substitution inspection concerns bytes supplied by substitution
routes and incorporated into a shell word. The flag
`requires_substitution_evaluation` identifies that requirement. The broader
`has_dynamic_substitution_io` flag also covers process-substitution streams and
dynamic filenames. Those I/O roles are distinct from shell-word inspection;
the receiving role determines how the application must inspect the data.

| Result or condition | Application action |
|---|---|
| `SG_OK` and `ALLOW` | Check completeness, unresolved values, and application-specific requirements |
| `ALLOW_CONDITIONAL` | Inspect generated shell-word content in its receiving context before deciding whether to execute; use Shellsplit's graph to locate the substitution routes |
| `DENY` | Refuse according to the explicit deny-policy match |
| `REJECT` | Refuse execution because the source is malformed, uses unsupported semantics, or contains a feature prohibited by the gate configuration |
| `UNDETERMINED` | Keep the execution decision pending until the reason for the indeterminate result has been resolved |
| Any evaluation error | Withhold authorization; diagnose the error or retry within resource limits |
| `truncated` or `short_circuited` | Treat the result as incomplete for a full-command decision |
| Nonzero `unresolved_expansion_flags` | Resolve the relevant values or apply an explicit application rule for uncertainty |

Choose `SG_EVAL_ALL` to evaluate all argv-policy subjects in the modeled input.
Early-stop modes can return an `ALLOW` describing only the evaluated prefix.
For unresolved arguments or paths, matching may use their processed source
spelling rather than their final runtime values. Check
`unresolved_expansion_flags` when that distinction affects the application's
decision. Full-input policy evaluation covers argument matching; execution
authorization also depends on effects and application controls.

### What policy rules cover

Each retained command with an argument sequence is an argv-policy subject.
The command name is `argv[0]`, so a command without operands still receives
matching. Builtins and external programs are both subjects. Prefix assignments
and redirections are separate from the matched arguments; Shellsplit models
their effects alongside the command.

| Submitted source | Argv-policy coverage | Separate analysis |
|---|---|---|
| `whoami` | One subject: `whoami` | Command I/O routes |
| `git status --short >report.txt` | One subject: `git status --short` | File setup and stdout routing |
| `VALUE=example git status --short` | One subject: `git status --short` | Prefix assignment effects |
| `>report.txt` | No subject; `UNDETERMINED` | Redirection setup |
| `VALUE=example` | No subject; `UNDETERMINED` | Shell-state assignment |
| `# comment` | No subject; `ALLOW` | Policy-neutral source |
| `cd /tmp` | One subject: `cd /tmp`; requires a matching rule | CWD changes and command I/O |
| `echo "$(whoami)"` | Two subjects: `echo` with its argument, and `whoami` | Generated shell-word content and substitution routes |

Groups organize their contained subjects. Supported command, backtick, and
process substitutions contribute nested command subjects as well as dependency
routes. Bash's `$(<file)` shortcut instead contributes a file-content route
without an inner argv command. Matching a producer's arguments leaves its
generated content subject to the receiving context's inspection requirements.

An assignment-only or redirect-only operation leaves policy coverage
undetermined even alongside an allowed command; an explicit deny or rejection
still takes precedence. Assignment and redirection effects require authorization
beyond argv matching.
Comment-only input introduces no command or shell-state effects and can return
`ALLOW` with zero subjects. The eligible empty `time` forms are described in the
[shell model reference](docs/shell-model.md#groups-pipelines-background-execution-and-timing).

### I/O effects and additional signals

Policy matching and I/O authorization are separate decisions:
`git status --short >report.txt` has the same command arguments as the plain
form. The redirection can create or truncate `report.txt` during setup, even
when the command produces no output. The graph represents reached setup effects
and possible output routes. Applications enforcing file access rules inspect
Shellsplit's graph directly.

For that command, the graph contains these relationships:

```text
FD(0) --READ(target_fd=0)--> CMD[git status --short]
CMD[git status --short] --WRITE(source_fd=1)--> FILE[report.txt]
CMD[git status --short] --WRITE(source_fd=2)--> FD(2)
```

`FD(n)` is an inherited full-command descriptor resource. These edges describe
possible byte-flow routes; program behavior determines whether bytes travel.
Opening `report.txt` during redirection setup can create or truncate it even
when no bytes traverse the `WRITE` edge. Obtain these facts through Shellsplit's
[`shell_depgraph.h`](shellsplit/include/shell_depgraph.h)
interfaces, using the same source and initial CWD. Use
`shell_dep_graph_parse_resolved()` when supplying word-resolution facts, keeping
those facts consistent with policy evaluation. The
[graph guide](shellsplit/README.md#graph-io-and-state-facts) distinguishes byte
routes from setup effects, including overwritten redirects.

Violation findings are advisory signals that the application can incorporate
into its decision. Anomaly scores measure how unusual an execution-stage
sequence is relative to the learned model. Its entries include simple commands
in lists and nested substitutions, plus redirect-only operations and empty timed
pipelines. This analysis sequence differs from runtime scheduling and from the
commands eligible for argv-policy evaluation. Applications can use higher scores
to prioritize additional risk analysis. These signals have separate meanings
from the policy verdict.

Execution must use the pinned Bash version with the documented startup state.
The [security model](SECURITY.md) defines executor preparation, substitution
inspection, filesystem responsibilities, and pre-1.0 deployment guidance.

## Supported shell model

The reference executor is **Bash 5.3.20**, pinned in
`scripts/reference-bash.sha256`. The analysis assumes that the application
executes the submitted source in a fresh, noninteractive shell. CI and
pre-push verification use that same reference.

| Area | Current analysis support |
|---|---|
| Composition | Lists, `&&`, `\|\|`, pipelines including `\|&`, `!`, `time`, background execution |
| Groups and I/O | Brace and subshell groups, redirects, descriptor copies, moves and closes, named file descriptors, heredocs and here-strings |
| Expansions | Quoting, parameters, substitutions, globs/extglob, arithmetic restricted to numeric literals and operators with bounded nesting |
| Unsupported constructs | `if` constructs, loops, `case`, `select`, `coproc`, functions, arrays, `[[ … ]]`, `(( … ))`, and the builtin forms listed in the reference |
| Runtime uncertainty | Represents multiple possible outcomes and reports unresolved arguments and paths explicitly |

Shellgate's default rejection mask additionally rejects arithmetic, heredocs,
and here-strings. An application may adjust that mask for supported constructs;
unsupported semantics still cause rejection. Extglob requires executor startup
configuration before Bash parses the command.

Ordinary word content retains non-ASCII bytes in unquoted, escaped, and quoted
fragments, including ANSI-C quotes and filenames. For example, `cat résumé.txt`
and `printf '%s\n' $'日本\t語'` are supported. ANSI-C quotes preserve literal
bytes alongside supported escapes; `\u` and `\U` escapes producing non-ASCII
values remain unsupported. Values and offsets remain byte-based, with
no UTF-8 validation or normalization. Analysis and token classification use
fixed byte rules, independent of the application's locale. The executor uses a
fixed C/POSIX or UTF-8 locale, established through the
[startup contract](SECURITY.md#executor-startup).
Comments admit the same literal bytes: `cat résumé.txt # 説明` analyzes the
command while retaining its original source offsets.

The [shell model reference](docs/shell-model.md) describes supported behavior,
startup requirements, substitutions, builtins, I/O, working-directory facts,
and capacity limits. Updates to the reference Bash version include conformance
tests and the required model adaptations.

## Build and install

Library consumers need CMake 3.20+, a C11 compiler, a C++11 compiler, pthreads,
and libm.
Dependencies are pinned submodules; initialize them when cloning.

```sh
git clone --recurse-submodules https://github.com/panz-r/shellclave.git
cd shellclave
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF -DSHELLCLAVE_BUILD_TOOLS=OFF
cmake --build build --parallel 2
cmake --install build --prefix "$PWD/install"
```

With submodules available locally, this build needs neither reference Bash nor
network access. For an existing clone, run
`git submodule update --init --recursive` to obtain missing dependencies.

Using the installed package:

```cmake
find_package(Shellclave CONFIG REQUIRED)
target_link_libraries(example PRIVATE Shellclave::shellgate)
```

Pass `-DCMAKE_PREFIX_PATH=/path/to/install` when configuring the application.
To include Shellclave in a parent CMake project, use
`add_subdirectory(path/to/shellclave)` and the same target names. Set
`BUILD_TESTING=OFF` before adding the subdirectory for a library-only build.
The other targets are `Shellclave::shellsplit` and `Shellclave::shelltype`.

Contributor builds prepare the pinned reference and run conformance tests;
see [Contributing](CONTRIBUTING.md).

## Gate example: inspect evaluation results

The [complete program](examples/gate_policy.c) builds small illustrative policies
and analyzes ten submitted inputs. It reports the policy verdict and each
independent analysis condition, including cases where several occur together.
An application combines these results with graph-based I/O checks and its
execution controls before authorizing execution. This program only analyzes
and reports the inputs.

The rule strings use CPL, Shelltype's human-readable policy notation for argument
sequences. Bare words specify literal arguments, and `*` matches exactly one
argument of any type. Shelltype interprets CPL patterns; Bash interprets the
submitted shell source. See [CPL syntax](docs/canonical-formats.md#netpattern-and-cpl)
for the full policy notation.

The Git rules demonstrate exact matches; the `echo` and `whoami` rules let the
remaining cases demonstrate unresolved values and substitution inspection.

Build and run [the example](examples/gate_policy.c):

```sh
cmake -S . -B build -DBUILD_TESTING=OFF -DSHELLCLAVE_BUILD_TOOLS=ON
cmake --build build --target shellclave_gate_example --parallel 2
./build/shellclave_gate_example
```

The result-reporting excerpt below checks errors before accessing metadata and
marks incomplete coverage before presenting the reported verdict. The complete
source includes policy construction, the `sg_gate_evaluate()` calls, and result
buffer cleanup. The executable's exit status reports whether the demonstration
completed.

<!-- gate-example:start -->
```c
/* Report policy and independent conditions; application authorization is
 * separate. On error, result storage need not contain initialized metadata. */
static SHELL_NONNULL(1, 2, 4) void report_analysis(FILE *output,
                                                   const char *source,
                                                   sg_error_t error,
                                                   const sg_result_t *result) {
  fprintf(output, "%s: ", source);
  if (error != SG_OK) {
    fprintf(output, "evaluation failed (%d)\n", error);
    return;
  }
  if (result->truncated || result->short_circuited)
    fputs("incomplete evaluation; reported ", output);
  fprintf(output, "argv policy %s", sg_verdict_name(result->verdict));
  if (result->requires_substitution_evaluation)
    fputs("; substitution inspection required", output);
  if (result->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV)
    fputs("; unresolved argv", output);
  if (result->unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_PATH)
    fputs("; unresolved pathname", output);
  if (result->has_dynamic_substitution_io)
    fputs("; dynamic substitution I/O present", output);
  fputc('\n', output);
}
```
<!-- gate-example:end -->

Example output:

```text
git status --short: argv policy ALLOW
git reset --hard: argv policy DENY
git log --oneline: argv policy UNDETERMINED
if true; then :; fi: argv policy REJECT
echo "$(whoami)": argv policy ALLOW_CONDITIONAL; substitution inspection required; unresolved argv; dynamic substitution I/O present
echo "$VALUE": argv policy ALLOW; unresolved argv
echo ok >"$OUT": argv policy ALLOW; unresolved pathname
git status --short >report.txt: argv policy ALLOW
echo "$(whoami)" >"$OUT": argv policy ALLOW_CONDITIONAL; substitution inspection required; unresolved argv; unresolved pathname; dynamic substitution I/O present
echo ok < <(whoami): argv policy ALLOW; dynamic substitution I/O present
```

The redirected `git status` command receives `ALLOW` because its arguments match
the policy. Creating or truncating `report.txt` requires separate application
authorization before execution.

The process-substitution case has dynamic I/O without shell-word inspection.
The nested `whoami` command participates in argv-policy matching, while its
process-substitution stream introduces a separate I/O relationship.
`has_dynamic_substitution_io` identifies topology; the application determines
the receiving role and its authorization requirements. The combined substitution
and pathname case retains every condition, so inspecting generated word content
alone leaves the unresolved pathname to be addressed separately.

Check the return code before interpreting result metadata. If evaluation failed
because the supplied buffer was too small, enlarge it within application limits
and retry. Exceeding a fixed parser or graph limit requires reducing or refusing
the input. Failed evaluations retain their error status even when diagnostic
text also overflows.

Result-string pointers refer to storage in the caller-provided evaluation
buffer. Read or copy the strings before freeing or reusing that buffer. The
public headers specify ownership, supported inputs, and concurrency requirements.

## Component interfaces

Use each component directly for the operation it owns:

For pre-dispatch syntax rejection with a separate review path for unsupported
source, use Shellsplit's [typed source admission](shellsplit/README.md#classifying-input-before-dispatch).
The [compiled example](examples/source_admission.c) distinguishes these cases
from incomplete input and resource failures. Unsupported analysis requires an
application decision; it does not establish valid Bash or execution permission.

| Component | Main interfaces | Reference |
|---|---|---|
| Shellsplit | Bounded parsing, retained drafts, canonical arguments, dependency graphs, word-resolution callbacks | [Shellsplit guide](shellsplit/README.md) |
| Shelltype | Argument type classification, pattern learning, policy construction, matching and persistence | [Public API](shelltype/include/shelltype.h) |
| Shellgate | Combined evaluation, policy verdicts, advisory findings, anomaly integration | [Public API](shellgate/include/shellgate.h) |
| Anomaly API | Models, scoring, calibration and persistence | [Anomaly guide](shellgate/docs/ANOMALY.md) |

Netstrings encode byte payloads with explicit lengths. A netargv concatenates
one netstring per argument. A netsequence concatenates outer netstrings; in an
argv sequence, each outer payload is one complete netargv. Use
`shell_build_netargv_sequence_buffer()` for that representation. The anomaly
builders instead produce executable-name or typed execution-stage payloads.
See [Canonical formats](docs/canonical-formats.md) for each variant.

Canonical describes the encoding; argument values can still contain unresolved
source spelling. Shelltype accepts explicit-length views of canonical argument
data. `display_command` and other display strings are human-readable diagnostics.
Use `netargv` and `netargv_length` for programmatic argument handling.

Treat installed policy rules as immutable. Build an updated policy through
Shelltype, then install it as a replacement. Gates can own policies or borrow
policies shared by several gates. The owner must keep a shared policy alive
until every borrowing gate has detached and every reader has finished using it.

## Further reading

- [Security model and vulnerability reporting](SECURITY.md)
- [Shell semantics and execution model](docs/shell-model.md)
- [API migration notes](docs/migration.md)
- [Contributor builds and verification](CONTRIBUTING.md)
- [Dependencies and licenses](THIRD_PARTY.md)
