# Canonical Shellclave formats

Shellclave uses netstrings at API and persistence boundaries where plain text
cannot preserve argument or token boundaries unambiguously. A netstring is
`<decimal byte length>:<payload>,`. Lengths are canonical decimal numbers: zero
is `0`, and non-zero lengths have no leading zero. Payload lengths count bytes,
not characters. Embedded spaces, quotes, commas, colons, and newlines need no
escaping. NUL bytes remain unsupported because the public transports are C
strings.

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

## netpattern and CPL

A netpattern is a canonical sequence of outer netstrings. Each outer payload is
itself two netstrings: a one-byte tag (`L` for a literal or `T` for a type) and
the literal value or canonical type symbol. Nesting means literals can contain
spaces and all other supported non-NUL bytes without ambiguity.

CPL is the human-readable policy notation. Bare words are literals, recognized
`#` symbols are types, and `*` is the any-token type. Double quotes force a
literal and support `\"`, `\\`, `\n`, `\r`, `\t`, and `\uXXXX`. Renderers quote
empty literals, literal `*`, every literal beginning with `#`, and text needing
escaping. Use `st_netpattern_from_cpl()` at a user-input boundary; policy APIs
accept only canonical netpatterns.

## Framed files

Streams of netargv values use one outer netstring per record. Learner v4 and
policy v2 files likewise frame records, declare record counts, and finish with
a CRC32 over the exact framed records including their newline separators.
Readers reject non-canonical lengths, truncation, count mismatches, checksum
mismatches, and trailing data.
