# Canonical Shellclave formats

Shellclave uses netstrings at API and persistence boundaries where plain text
cannot preserve argument or token boundaries unambiguously. A netstring is
`<decimal byte length>:<payload>,`. Lengths are canonical decimal numbers: zero
is `0`, and non-zero lengths have no leading zero. Payload lengths count bytes,
not characters. Embedded spaces, quotes, commas, colons, and newlines need no
escaping. `shell_netstring.h` provides a length-aware, byte-oriented iterator
for applications that need to validate or traverse these records; it can expose
NUL payload bytes. Shellclave's netargv/netsequence-producing APIs remain
C-string transports, so their payloads do not support embedded NUL bytes.

## netargv

A netargv is a concatenation of netstrings, one per already-processed argument.
For example, argv `printf`, `two words`, and the empty string is:

```text
6:printf,9:two words,0:,
```

The elements must already describe one isolated subcommand. Shellsplit can
produce this representation after shell parsing, quote-fragment assembly,
escape processing, control-flow isolation, and redirection removal. Another
caller may perform those steps itself. Shelltype decodes these boundaries and
classifies arguments; it does not tokenize shell source.

Shellgate publishes this value as `sg_subcmd_result_t.netargv` with an explicit
length. It is the authoritative result for applications. The adjacent
`command` member is a readable, lossy diagnostic display and is never shell
source or a replacement for netargv.

## netsequences

A netsequence is an outer concatenation of netstrings whose payloads are
already-canonical records. Shellsplit uses this framing to return a collection
of isolated netargv values in one buffer. The anomaly raw model uses one outer
record per decoded executable name. Its type model uses one outer record per
subcommand, with a nested netargv signature containing the executable followed
by abstract type symbols. A multi-argument command therefore remains one
anomaly item; command lists and pipelines produce multiple items.

## netpattern and CPL

A netpattern is a canonical sequence of outer netstrings. Each outer payload is
itself two netstrings: a one-byte tag (`L` for a literal, `T` for a type, or
`C` for a compound argument) and its value. A compound value is a nested
sequence of two or three `L`/`T` records with exactly one typed capture and a
literal prefix and/or suffix. Nesting preserves spaces and all other supported
non-NUL bytes without ambiguity.

CPL is the human-readable policy notation. Bare words are literals, recognized
`#` symbols are types, and `*` is the any-token type. Double quotes force a
literal and support `\"`, `\\`, `\n`, `\r`, `\t`, and `\uXXXX`. Renderers quote
empty literals, literal `*`, every literal beginning with `#`, and text needing
escaping. Braced types describe a typed substring in one argv element:
`--output={#path}` is distinct from the two arguments `--output #path`. Use
`st_netpattern_from_cpl()` at a user-input boundary; policy APIs
accept only canonical netpatterns.

## Framed files

Streams of netargv values use one outer netstring per record. Learner v5 and
policy v3 files likewise frame records, declare record counts, and finish with
a CRC32 over the exact framed records including their newline separators.
Readers reject non-canonical lengths, truncation, count mismatches, checksum
mismatches, and trailing data.
