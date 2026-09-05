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
processing; NUL termination is only a convenience for NUL-free compatibility
inputs. Raw shell source still rejects literal NUL bytes; syntactic decoding
of ANSI-C quotes can produce binary canonical payloads.

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

The `*_view` Shelltype entry points accept `st_netargv_view_t` and use its
explicit length directly. Existing C-string entry points remain convenience
wrappers that derive that length with `strlen()`. A NULL data pointer is valid
only for an empty view. The view forms support embedded NUL; the C-string
wrappers are limited to NUL-free encodings.

Use Shellsplit's `shell_render_netargv_buffer()` or
`shell_build_netargv_sequence_buffer()` to preserve binary payloads in an
owned `shell_netstring_buffer_t`. Release it with
`shell_netstring_buffer_free()` before reuse.

Shellgate publishes this value as `sg_subcommand_result_t.netargv` with an explicit
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

Use `shell_build_command_netseq_buffer()`, `shell_build_type_netseq_buffer()`,
or `shell_build_anomaly_netseqs_buffer()` for binary sequence output. Pass
their explicit lengths to the anomaly APIs; legacy C-string builders support
only NUL-free output.

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
patterns with `st_netpattern_free()`. Legacy C-string converters support only
NUL-free netpatterns. Policy APIs accept only canonical netpatterns; use their
view forms for binary patterns.

## Framed files

Streams of netargv values use one outer netstring per record. Learner v5 and
policy v3 files likewise frame records, declare record counts, and finish with
a CRC32 over the exact framed records including their newline separators.
Readers reject non-canonical lengths, truncation, count mismatches, checksum
mismatches, and trailing data.
