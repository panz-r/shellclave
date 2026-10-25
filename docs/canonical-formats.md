# Canonical Shellclave formats

Shellclave uses netstrings at API and persistence boundaries where plain text
cannot preserve argument or token boundaries unambiguously. A netstring is
`<decimal byte length>:<payload>,`. Lengths are canonical decimal numbers: zero
is `0`, and non-zero lengths have no leading zero. Payload lengths count bytes,
not characters. Embedded spaces, quotes, commas, colons, and newlines need no
escaping. `shell_netstring.h` provides a length-aware, byte-oriented iterator
for applications that need to validate or traverse these records; it can expose
NUL payload bytes. Canonical netargv, netsequences, and netpatterns support
embedded NUL in their payloads. Keep the enclosing byte length throughout
processing; NUL termination is not part of the canonical transport contract.
Raw shell source rejects literal NUL bytes. For source-derived argv, Bash's
ANSI-C quoting rules truncate each fragment at its first decoded NUL and then
resume subsequent fragments. For example, `pre$'a\0b'post` supplies
`preapost`; `$'\0'` in an argument position supplies an empty argument.
Standalone decoded-word helpers remain byte-faithful, while
`shell_visit_static_word()` exposes the effective static Bash value. Canonical
APIs also accept binary payloads supplied directly by an application or
expansion callback. Keep these explicit-length binary values separate from
source-derived fragment truncation.

## netargv

A netargv is a concatenation of netstrings, one per already-processed argument.
For example, argv `printf`, `two words`, and the empty string is:

```text
6:printf,9:two words,0:,
```

The elements must already describe one isolated subcommand. Shellsplit can
produce this representation after shell parsing, quote-fragment assembly,
escape processing, command-stage isolation, and redirection removal. Another
caller may perform those steps itself. Shelltype decodes these boundaries and
classifies arguments; it does not tokenize shell source.

Shelltype entry points accept `st_netargv_view_t` and use its explicit length
directly, including for embedded NUL bytes. A NULL data pointer is valid only
for an empty view.

Use Shellsplit's `shell_render_netargv_buffer()` or
`shell_build_netargv_sequence_buffer()` to preserve binary payloads in an
owned `shell_netstring_buffer_t`. Release it with
`shell_netstring_buffer_free()` before reuse.

Shellgate publishes this value as `sg_subcommand_result_t.netargv` with an explicit
length. It is the authoritative result for applications. The adjacent
`display_command` member is a readable, lossy diagnostic display and is never shell
source or a replacement for netargv.

## netsequences

A netsequence concatenates outer netstrings, one per item. The producing API
defines the outer payload:

| Sequence | Builder | Outer payload |
|---|---|---|
| Argv sequence | `shell_build_netargv_sequence_buffer()` | One complete canonical netargv per isolated subcommand |
| Raw anomaly sequence | `shell_build_command_netseq_buffer()` | One decoded executable name per execution stage |
| Typed anomaly sequence | `shell_build_type_netseq_buffer()` | One nested netargv signature per execution stage: executable followed by abstract type symbols |

An argv-less redirect-only operation or empty timed pipeline contributes an
empty executable-name sentinel to anomaly sequences. Those stages are distinct
from commands with policy-evaluable argv. A multi-argument executable stage
remains one anomaly item; its arguments are nested in its type signature.

Arithmetic commands have no argv-policy record. Argv-sequence builders omit
them and report shell syntax through their feature output. Processed-command
collections retain their explicit arithmetic kind and expression span; direct
argv rendering produces an empty value. An arithmetic anomaly stage uses the
empty executable sentinel in the raw sequence and the nested signature
`0:,2:AR,` in the typed sequence (the complete outer record is `8:0:,2:AR,,`).
This marker distinguishes arithmetic from other argv-less stages without
inventing an executable command name.

Each arithmetic command contributes exactly one stage, including adjacent
operator/operand spellings such as `((1<<(2)))`. Genuine substitutions in
following shell words and redirection operands keep their separate stages.

Conditional commands have no argv-policy record. Their owned command metadata
retains expression and ordered operand spans with a normalized predicate.
Unary, literal-comparison and star-pattern conditions share CT. In anomaly sequences, one condition has
raw record `0:,` and typed inner signature `0:,2:CT,`, framed as
`8:0:,2:CT,,`. Executable substitutions retain separate stages in the existing
analysis order. This marker is distinct from arithmetic's `AR` and an ordinary
empty stage; existing serialized models remain readable.

Use `shell_build_command_netseq_buffer()`, `shell_build_type_netseq_buffer()`,
or `shell_build_anomaly_netseqs_buffer()` for binary sequence output. Pass
their explicit lengths to the anomaly APIs.

## netpattern and CPL

A netpattern is a canonical sequence of outer netstrings. Each outer payload is
itself two netstrings: a one-byte tag (`L` for a literal, `T` for a type, or
`C` for a compound argument) and its value. A compound value is a nested
sequence of two or three `L`/`T` records with exactly one typed capture and a
literal prefix and/or suffix. Literal payloads and compound affixes preserve
arbitrary bytes, including NUL; typed capture markers remain textual.

CPL is the human-readable policy notation. Bare words are literals, recognized
`#` symbols are types, and `*` is the any-token type. Double quotes force a
literal and support `\"`, `\\`, `\n`, `\r`, `\t`, `\uXXXX`, and `\xHH` for
an arbitrary byte (including `\x00`). Renderers quote
empty literals, literal `*`, every literal beginning with `#`, and text needing
escaping. Braced types describe a typed substring in one argv element:
`--output={#path}` is distinct from the two arguments `--output #path`. Use
`st_netpattern_from_cpl_owned()` at a user-input boundary and
`st_netpattern_to_cpl_view()` for display. The owned `st_netpattern_t` and
borrowed `st_netpattern_view_t` preserve the enclosing length; release owned
patterns with `st_netpattern_free()`. Policy APIs accept canonical netpattern
views, not CPL or NUL-terminated transport strings. Build and edit policies
through Shelltype before installing them in a gate; installed policies are
logically immutable and can be shared by borrowing gates.

`st_netpattern_validate_view()` validates the canonical encoding and policy
command-position grammar. Its optional details output is an owned
`st_token_array_t`, initialized empty before the call and released with
`st_token_array_free()`. It retains exact byte lengths and compound component
metadata, using the decoding allocations directly. Omitting details does not
change validity; failures leave the output empty. Each literal or compound
component has its own decoded-byte limit, so a valid compound's complete
display spelling can exceed an ordinary literal's limit. This is pattern
validation, not shell-source tokenization.

## Framed files

Streams of netargv values use one outer netstring per record. Learner v5 and
policy v3 files likewise frame records, declare record counts, and finish with
a CRC32 over the exact framed records including their newline separators.
Readers reject non-canonical lengths, truncation, count mismatches, checksum
mismatches, and trailing data.
