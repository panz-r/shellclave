#ifndef SHELL_BUILTIN_INTERNAL_H
#define SHELL_BUILTIN_INTERNAL_H

#include "shell_source_internal.h"
#include <limits.h>

/* Private operand roles shared by source validation and named-FD mutation
 * analysis. Supply complete logical words in argv order, omitting redirects.
 * State is initialized once per effective builtin (after wrapper resolution).
 * The source boundary owns general word-feature checks, including ANSI-C NUL
 * rejection; builtin analysis does not duplicate those checks. These helpers
 * validate expansion cardinality/option grammar, not caller storage or the
 * correspondence between tokens and their immutable source. */
enum {
  SHELL_BUILTIN_ROLE_TARGET = 1u,
  SHELL_BUILTIN_ROLE_UNSUPPORTED = 2u,
  SHELL_BUILTIN_ROLE_WRITE = 4u,
  SHELL_BUILTIN_ROLE_DYNAMIC = 8u,
  SHELL_BUILTIN_ROLE_ATTACHED = 16u,
  SHELL_BUILTIN_ROLE_FORMAT = 32u,
  /* A declaration operand makes a same-name command-prefix assignment
   * persist in the current shell. The graph uses this role to invalidate a
   * descriptor-variable binding without rescanning unrelated prefixes. */
  SHELL_BUILTIN_ROLE_PROMOTES_PREFIX = 64u,
};

enum {
  SHELL_READ_OPTIONS = 1u,
  SHELL_READ_DATA = 2u,
  SHELL_READ_NUMBER = 4u,
  SHELL_READ_TIMEOUT = 8u,
  SHELL_READ_TARGETS = 16u,
  SHELL_READ_POSITIONAL = 32u,
};

/* A bounded union of possible getopt paths. An empty attached expansion can
 * make the next word either an operand or an option/target. Keep the timeout
 * mode with each path: a later -t replaces it, but an operand/target error
 * terminates only that path. No source rescanning or runtime evaluation. */
typedef struct {
  unsigned writing, polling;
} shell_builtin_read_t;

typedef enum {
  SHELL_BUILTIN_VARIABLE_STATIC,
  SHELL_BUILTIN_VARIABLE_INVALID,
  SHELL_BUILTIN_VARIABLE_DYNAMIC,
  SHELL_BUILTIN_VARIABLE_READONLY,
  SHELL_BUILTIN_VARIABLE_FROZEN,
  SHELL_BUILTIN_VARIABLE_ARITHMETIC,
} shell_builtin_variable_t;

/* Fresh-shell capabilities, not a shell-variable attribute table. Keep
 * arithmetic writers and descriptor destinations on the same name registry:
 * a stable integer (OPTIND) can hold an allocated FD, but an automatically
 * updated value, readonly variable, or array cannot provide the scalar binding
 * we model. Previous unset/attribute operations do not establish different
 * capabilities without modeling that state. Variables which alter the graph's
 * fixed Bash execution contract are cleared and frozen by the executor. */
enum {
  SHELL_VARIABLE_INTEGER = 1u,
  SHELL_VARIABLE_UNSTABLE = 2u,
  SHELL_VARIABLE_READONLY = 4u,
  SHELL_VARIABLE_ARRAY = 8u,
  SHELL_VARIABLE_FROZEN = 16u,
};
static const struct {
  const char *name;
  size_t length;
  unsigned properties;
} shell_builtin_variable_names[] = {
#define SHELL_VARIABLE(name, properties) {name, sizeof(name) - 1, properties}
    SHELL_VARIABLE("_", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("SECONDS", SHELL_VARIABLE_INTEGER | SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("RANDOM", SHELL_VARIABLE_INTEGER | SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("SRANDOM", SHELL_VARIABLE_INTEGER | SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("OPTIND", SHELL_VARIABLE_INTEGER),
    SHELL_VARIABLE("HISTCMD", SHELL_VARIABLE_INTEGER | SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("POSIXLY_CORRECT", SHELL_VARIABLE_FROZEN),
    SHELL_VARIABLE("BASH_COMPAT", SHELL_VARIABLE_FROZEN),
    SHELL_VARIABLE("BASH_XTRACEFD", SHELL_VARIABLE_FROZEN),
    SHELL_VARIABLE("UID", SHELL_VARIABLE_READONLY),
    SHELL_VARIABLE("EUID", SHELL_VARIABLE_READONLY),
    SHELL_VARIABLE("PPID", SHELL_VARIABLE_READONLY),
    SHELL_VARIABLE("SHELLOPTS", SHELL_VARIABLE_READONLY),
    SHELL_VARIABLE("BASHOPTS", SHELL_VARIABLE_READONLY),
    SHELL_VARIABLE("BASH_VERSINFO",
                   SHELL_VARIABLE_READONLY | SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("EPOCHSECONDS", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("EPOCHREALTIME", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("BASH_MONOSECONDS", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("BASH_COMMAND", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("BASHPID", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("BASH_SUBSHELL", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("LINENO", SHELL_VARIABLE_UNSTABLE),
    SHELL_VARIABLE("BASH_ARGC", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("BASH_ARGV", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("BASH_LINENO", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("BASH_SOURCE", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("DIRSTACK", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("FUNCNAME", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("GROUPS", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("PIPESTATUS", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("BASH_ALIASES", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("BASH_CMDS", SHELL_VARIABLE_ARRAY),
    SHELL_VARIABLE("BASH_REMATCH", SHELL_VARIABLE_ARRAY),
#undef SHELL_VARIABLE
};
enum {
  SHELL_BUILTIN_VARIABLE_NAMES = sizeof(shell_builtin_variable_names) /
                                 sizeof(shell_builtin_variable_names[0]),
};
#define SHELL_BUILTIN_VARIABLE_MASK                                            \
  ((UINT64_C(1) << SHELL_BUILTIN_VARIABLE_NAMES) - 1)

typedef struct {
  size_t length;
  bool valid;
  uint64_t names;
} shell_builtin_variable_scan_t;

static inline SHELL_NONNULL(2) bool shell_builtin_variable_byte(
    unsigned char byte, void *context) {
  shell_builtin_variable_scan_t *scan = context;
  size_t position = scan->length++;
  scan->valid &= position == 0 ? isalpha(byte) || byte == '_'
                               : isalnum(byte) || byte == '_';
  if (scan->names) {
    for (unsigned i = 0; i < SHELL_BUILTIN_VARIABLE_NAMES; i++) {
      if ((scan->names & (UINT64_C(1) << i)) &&
          (position >= shell_builtin_variable_names[i].length ||
           byte !=
               (unsigned char)shell_builtin_variable_names[i].name[position]))
        scan->names &= ~(UINT64_C(1) << i);
    }
  }
  return true;
}

static inline SHELL_NONNULL(1) unsigned shell_builtin_variable_properties(
    const shell_builtin_variable_scan_t *scan) {
  for (unsigned i = 0; i < SHELL_BUILTIN_VARIABLE_NAMES; i++)
    if ((scan->names & (UINT64_C(1) << i)) &&
        scan->length == shell_builtin_variable_names[i].length)
      return shell_builtin_variable_names[i].properties;
  return 0;
}

/* Required static identifier source span from a parsed assignment or named-FD
 * prefix. Physical continuations are decoded without allocating a name. */
static inline SHELL_NONNULL(1) unsigned shell_builtin_name_properties(
    const char *name, size_t length) {
  shell_builtin_variable_scan_t scan = {.valid = true,
                                        .names = SHELL_BUILTIN_VARIABLE_MASK};
  (void)shell_source_visit_static_word(name, length,
                                       shell_builtin_variable_byte, &scan);
  return shell_builtin_variable_properties(&scan);
}

/* Classify a quote-removed scalar target. Static invalid names cannot mutate
 * unrelated bindings; unresolved expansion can. Ordinary readonly targets
 * have builtin-specific effects: read stops, but printf/declarations can keep
 * assigning later targets. FROZEN separately protects variables whose writes
 * would change the launcher's supported shell-semantics or descriptor-state
 * contract.
 */
static inline SHELL_NONNULL(1) shell_builtin_variable_t
    shell_builtin_variable(const char *word, size_t length) {
  shell_builtin_variable_scan_t scan = {.valid = true,
                                        .names = SHELL_BUILTIN_VARIABLE_MASK};
  if (!shell_source_visit_static_word(word, length, shell_builtin_variable_byte,
                                      &scan))
    return SHELL_BUILTIN_VARIABLE_DYNAMIC;
  if (!scan.valid || scan.length == 0)
    return SHELL_BUILTIN_VARIABLE_INVALID;
  unsigned properties = shell_builtin_variable_properties(&scan);
  if (properties & SHELL_VARIABLE_INTEGER)
    return SHELL_BUILTIN_VARIABLE_ARITHMETIC;
  if (properties & SHELL_VARIABLE_FROZEN)
    return SHELL_BUILTIN_VARIABLE_FROZEN;
  return properties & SHELL_VARIABLE_READONLY ? SHELL_BUILTIN_VARIABLE_READONLY
                                              : SHELL_BUILTIN_VARIABLE_STATIC;
}

typedef enum {
  SHELL_PRINTF_OPTIONS,
  SHELL_PRINTF_TARGET,
  SHELL_PRINTF_FORMAT,
  SHELL_PRINTF_DATA,
  SHELL_PRINTF_ERROR,
  SHELL_PRINTF_UNKNOWN,
} shell_builtin_printf_phase_t;

typedef struct {
  size_t argument;
  bool writes;
} shell_builtin_printf_event_t;

enum { SHELL_PRINTF_MAX_EVENTS = 32 };

typedef enum {
  SHELL_PRINTF_LITERAL,
  SHELL_PRINTF_ESCAPE,
  SHELL_PRINTF_FLAGS,
  SHELL_PRINTF_WIDTH,
  SHELL_PRINTF_PRECISION,
  SHELL_PRINTF_PRECISION_DIGITS,
  SHELL_PRINTF_LENGTH,
  SHELL_PRINTF_DATE,
  SHELL_PRINTF_DATE_END,
  SHELL_PRINTF_DONE,
} shell_builtin_printf_format_phase_t;

/* Compile only effect-bearing conversions (%n and potentially terminating
 * %b) into a bounded schedule. Ordinary conversions have no event storage
 * cost. Format reuse walks that schedule, never rescans the format source.
 * Excess events in formats containing %n are rejected at the semantic
 * boundary. Formats without variable writes need no complete schedule. */
typedef struct {
  shell_builtin_printf_event_t events[SHELL_PRINTF_MAX_EVENTS];
  size_t arguments, count, date_depth;
  shell_builtin_printf_format_phase_t phase;
  bool initial, has_count, repeat, unsupported;
} shell_builtin_printf_format_t;

typedef struct {
  shell_builtin_printf_phase_t phase;
  bool has_target;
  size_t argument, event;
  shell_builtin_printf_format_t format;
} shell_builtin_printf_t;

static inline SHELL_NONNULL(2) bool shell_builtin_printf_format_byte(
    unsigned char byte, void *context) {
  SHELL_SOURCE_WORD_SCAN(1);
  shell_builtin_printf_format_t *format = context;
  if (format->phase == SHELL_PRINTF_DONE)
    return true;
  if (format->phase == SHELL_PRINTF_LITERAL) {
    if (byte == '\\')
      format->phase = SHELL_PRINTF_ESCAPE;
    else if (byte == '%') {
      format->phase = SHELL_PRINTF_FLAGS;
      format->initial = true;
    }
    return true;
  }
  if (format->phase == SHELL_PRINTF_ESCAPE) {
    format->phase = SHELL_PRINTF_LITERAL;
    /* Bash leaves the second byte of an unrecognized escape available to
     * format parsing: \%n emits a backslash, then performs %n. Recognized
     * escapes (including numeric escapes) do not reinterpret their output.
     * Percent is the only second byte that can introduce a conversion. */
    if (byte == '%') {
      format->phase = SHELL_PRINTF_FLAGS;
      format->initial = true;
    }
    return true;
  }
  if (format->phase == SHELL_PRINTF_DATE) {
    if (byte == '(')
      format->date_depth++;
    else if (byte == ')' && --format->date_depth == 0)
      format->phase = SHELL_PRINTF_DATE_END;
    return true;
  }
  if (format->phase == SHELL_PRINTF_DATE_END) {
    if (byte == 'T') {
      format->arguments++;
      format->phase = SHELL_PRINTF_LITERAL;
      return true;
    }
    format->repeat = false;
    format->phase = SHELL_PRINTF_DONE;
    return true;
  }
  if (format->phase == SHELL_PRINTF_FLAGS) {
    if (format->initial && byte == '%') {
      format->phase = SHELL_PRINTF_LITERAL;
      return true;
    }
    format->initial = false;
    if (strchr("#-+ 0'", byte))
      return true;
    format->phase = SHELL_PRINTF_WIDTH;
    if (byte == '*') {
      format->arguments++;
      format->phase = SHELL_PRINTF_PRECISION;
      return true;
    }
  }
  if (format->phase == SHELL_PRINTF_WIDTH) {
    if (isdigit(byte))
      return true;
    format->phase = SHELL_PRINTF_PRECISION;
  }
  if (format->phase == SHELL_PRINTF_PRECISION) {
    format->phase = SHELL_PRINTF_LENGTH;
    if (byte == '.') {
      format->phase = SHELL_PRINTF_PRECISION_DIGITS;
      return true;
    }
  }
  if (format->phase == SHELL_PRINTF_PRECISION_DIGITS) {
    if (isdigit(byte))
      return true;
    format->phase = SHELL_PRINTF_LENGTH;
    if (byte == '*') {
      format->arguments++;
      return true;
    }
  }
  if (strchr("hlLjzt", byte))
    return true;
  if (byte == '(') {
    format->phase = SHELL_PRINTF_DATE;
    format->date_depth = 1;
    return true;
  }
  if (!strchr("diouxXfFeEgGaAcsCSbqQn", byte)) {
    /* Invalid/incomplete conversions stop printf after any earlier writes;
     * the successfully parsed prefix is not reused with remaining operands. */
    format->repeat = false;
    format->phase = SHELL_PRINTF_DONE;
    return true;
  }
  if (byte == 'n' || byte == 'b') {
    if (format->count == SHELL_PRINTF_MAX_EVENTS)
      format->unsupported = true;
    else
      format->events[format->count++] =
          (shell_builtin_printf_event_t){format->arguments, byte == 'n'};
    format->has_count |= byte == 'n';
  }
  format->arguments++;
  format->phase = SHELL_PRINTF_LITERAL;
  return true;
}

typedef struct {
  bool escape, stop;
  size_t length;
} shell_builtin_printf_escape_t;

static inline SHELL_NONNULL(2) bool shell_builtin_printf_escape_byte(
    unsigned char byte, void *context) {
  shell_builtin_printf_escape_t *scan = context;
  scan->length++;
  if (scan->escape) {
    scan->stop |= byte == 'c';
    scan->escape = false;
  } else
    scan->escape = byte == '\\';
  return true;
}

typedef struct {
  size_t length;
  bool dash, v, end;
  shell_builtin_variable_scan_t target;
} shell_builtin_printf_option_t;

static inline SHELL_NONNULL(2) bool shell_builtin_printf_option_byte(
    unsigned char byte, void *context) {
  shell_builtin_printf_option_t *scan = context;
  size_t position = scan->length++;
  if (position == 0)
    scan->dash = byte == '-';
  else if (position == 1) {
    scan->v = scan->dash && byte == 'v';
    scan->end = scan->dash && byte == '-';
  } else if (scan->v)
    shell_builtin_variable_byte(byte, &scan->target);
  return true;
}

typedef struct {
  shell_source_builtin_kind_t kind;
  bool options, query, readonly, error, integer, no_integer, promotes_prefix;
} shell_builtin_declaration_t;

typedef struct {
  shell_source_builtin_kind_t kind;
  size_t length;
  unsigned char sign;
  bool option, valid, end, query, readonly, array, attribute, integer;
  bool exports, unexports;
} shell_builtin_declaration_option_t;

static inline SHELL_NONNULL(2) bool shell_builtin_declaration_option_byte(
    unsigned char byte, void *context) {
  shell_builtin_declaration_option_t *scan = context;
  if (scan->length++ == 0) {
    scan->sign = byte;
    scan->option = byte == '-' ||
                   (byte == '+' && scan->kind != SHELL_SOURCE_BUILTIN_EXPORT &&
                    scan->kind != SHELL_SOURCE_BUILTIN_READONLY);
    return true;
  }
  if (!scan->option || !scan->valid)
    return true;
  if (scan->length == 2 && scan->sign == '-' && byte == '-') {
    scan->end = true;
    return true;
  }
  const char *flags = scan->kind == SHELL_SOURCE_BUILTIN_EXPORT ? "fnp"
                      : scan->kind == SHELL_SOURCE_BUILTIN_READONLY
                          ? "aAfnp"
                          : "aAfFgiIlnprtux";
  if (scan->end || byte == '\0' || !strchr(flags, byte)) {
    scan->valid = false;
    return true;
  }
  scan->query |= (byte == 'p' && scan->kind != SHELL_SOURCE_BUILTIN_EXPORT &&
                  scan->kind != SHELL_SOURCE_BUILTIN_READONLY) ||
                 ((byte == 'f' || byte == 'F') && scan->sign == '-');
  scan->readonly |= byte == 'r' && scan->sign == '-';
  scan->array |= byte == 'a' || byte == 'A';
  scan->integer |= byte == 'i';
  scan->exports |= byte == 'x' && scan->sign == '-' &&
                   (scan->kind == SHELL_SOURCE_BUILTIN_DECLARE ||
                    scan->kind == SHELL_SOURCE_BUILTIN_TYPESET);
  scan->unexports |= byte == 'n' && scan->kind == SHELL_SOURCE_BUILTIN_EXPORT;
  /* readonly also accepts an undocumented -n attribute mode; it is not an
   * invalid option that can be treated as a proved non-mutating error. */
  scan->attribute |= byte == 'n' && scan->kind != SHELL_SOURCE_BUILTIN_EXPORT;
  return true;
}

/* Builtin-specific option modes precede operands. Query/option-error paths do
 * not assign; export -p still assigns when operands are supplied. Invalid
 * static identifiers fail individually rather than invalidating unrelated
 * routes. LOCAL has no writes in the supported function-free execution model.
 * TARGET marks operands whose variable syntax needs semantic inspection;
 * WRITE marks a proved scalar assignment and DYNAMIC an unresolved target.
 * Unsupported attribute changes and non-source-aligned assignments are
 * rejected here, at the shared supported-syntax boundary. */
static inline SHELL_NONNULL(1, 2) unsigned shell_builtin_declaration_word(
    shell_builtin_declaration_t *state, const char *word, size_t length) {
  if (state->error)
    return 0;
  if (state->options) {
    shell_builtin_declaration_option_t scan = {.kind = state->kind,
                                               .valid = true};
    if (shell_source_visit_static_word(
            word, length, shell_builtin_declaration_option_byte, &scan) &&
        scan.option && scan.length > 1) {
      if (!scan.valid)
        state->error = true;
      else if (scan.end)
        state->options = false;
      else {
        state->query |= scan.query;
        state->readonly |= scan.readonly;
        if (scan.sign == '-')
          state->integer |= scan.integer;
        else
          state->no_integer |= scan.integer;
        state->promotes_prefix |= scan.exports;
        if (scan.unexports)
          state->promotes_prefix = false;
        if (scan.array || scan.attribute)
          return SHELL_BUILTIN_ROLE_UNSUPPORTED;
      }
      return 0;
    }
    state->options = false;
  }
  if (state->query)
    return 0;
  shell_builtin_variable_scan_t target = {.valid = true,
                                          .names = SHELL_BUILTIN_VARIABLE_MASK};
  shell_source_decoded_assignment_t assignment;
  bool assigned = shell_source_scan_decoded_assignment(
      word, length, shell_builtin_variable_byte, &target, &assignment);
  if (assigned) {
    if (!assignment.source_delimiter ||
        (shell_builtin_variable_properties(&target) & SHELL_VARIABLE_FROZEN))
      return SHELL_BUILTIN_ROLE_UNSUPPORTED;
  } else {
    shell_builtin_variable_t variable = shell_builtin_variable(word, length);
    if (variable == SHELL_BUILTIN_VARIABLE_DYNAMIC)
      return SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_DYNAMIC |
             SHELL_BUILTIN_ROLE_UNSUPPORTED;
    if (variable == SHELL_BUILTIN_VARIABLE_INVALID)
      return SHELL_BUILTIN_ROLE_TARGET;
  }
  if (state->kind == SHELL_SOURCE_BUILTIN_LOCAL)
    return SHELL_BUILTIN_ROLE_TARGET;
  /* An integer attribute makes subsequent assignments (including read and
   * printf writes) arithmetic evaluations that can mutate other names. Keep
   * this stateful feature outside the supported scalar model. Query/error
   * paths and +i cancelations do not install the attribute. */
  if (!state->no_integer &&
      (state->integer ||
       (assigned &&
        (shell_builtin_variable_properties(&target) & SHELL_VARIABLE_INTEGER))))
    return SHELL_BUILTIN_ROLE_UNSUPPORTED;
  if (state->readonly || state->kind == SHELL_SOURCE_BUILTIN_READONLY)
    return SHELL_BUILTIN_ROLE_UNSUPPORTED;
  bool writable = assigned && (shell_builtin_variable_properties(&target) &
                               SHELL_VARIABLE_READONLY) == 0;
  return SHELL_BUILTIN_ROLE_TARGET | (writable ? SHELL_BUILTIN_ROLE_WRITE : 0) |
         (state->promotes_prefix ? SHELL_BUILTIN_ROLE_PROMOTES_PREFIX : 0);
}

typedef struct {
  uintmax_t whole;
  unsigned fraction_digits;
  bool timeout, started, digits, negative, fraction, fractional_nonzero;
  bool trailing_space, invalid;
} shell_builtin_read_number_t;

/* Bash accepts signed decimal integers (with surrounding whitespace) for
 * -n/-N/-u. Timeout operands instead use a decimal seconds/microseconds pair:
 * no whitespace/exponents, and fractional precision is truncated at 6 digits.
 * Keep only the information needed to prove an option error or polling mode. */
static inline SHELL_NONNULL(2) bool shell_builtin_read_number_byte(
    unsigned char byte, void *context) {
  shell_builtin_read_number_t *scan = context;
  if (scan->invalid)
    return true;
  if (!scan->timeout && isspace(byte)) {
    if (scan->started)
      scan->trailing_space = true;
    return true;
  }
  if (scan->trailing_space) {
    scan->invalid = true;
    return true;
  }
  if (!scan->started && (byte == '-' || byte == '+')) {
    scan->started = true;
    scan->negative = byte == '-';
    return true;
  }
  scan->started = true;
  if (scan->timeout && byte == '.' && !scan->fraction) {
    scan->fraction = true;
    return true;
  }
  if (byte < '0' || byte > '9') {
    scan->invalid = true;
    return true;
  }
  scan->digits = true;
  if (scan->fraction) {
    if (scan->fraction_digits < 6) {
      scan->fraction_digits++;
      scan->fractional_nonzero |= byte != '0';
    }
  } else {
    uintmax_t limit = scan->timeout ? (uintmax_t)LONG_MAX : (uintmax_t)INT_MAX;
    unsigned digit = byte - '0';
    if (scan->whole > (limit - digit) / 10)
      scan->invalid = true;
    else
      scan->whole = scan->whole * 10 + digit;
  }
  return true;
}

enum {
  SHELL_READ_VALUE_INVALID,
  SHELL_READ_VALUE_ZERO,
  SHELL_READ_VALUE_NONZERO,
  SHELL_READ_VALUE_UNKNOWN,
};

static inline SHELL_NONNULL(1) unsigned shell_builtin_read_number_value(
    const shell_builtin_read_number_t *scan, bool dynamic) {
  if (dynamic)
    return SHELL_READ_VALUE_UNKNOWN;
  bool zero = scan->whole == 0 && !scan->fractional_nonzero;
  if (scan->invalid || (!scan->timeout && !scan->digits) ||
      (scan->negative && !zero))
    return SHELL_READ_VALUE_INVALID;
  return zero ? SHELL_READ_VALUE_ZERO : SHELL_READ_VALUE_NONZERO;
}

typedef struct {
  size_t position;
  bool option, valid, operand, array, readline, end;
  bool attached_static, attached_dynamic, unresolved;
  unsigned operand_kind;
  shell_builtin_read_number_t number, timeout, payload;
} shell_builtin_read_option_t;

static inline SHELL_NONNULL(2) bool shell_builtin_read_option_byte(
    unsigned char byte, void *context) {
  shell_builtin_read_option_t *scan = context;
  shell_builtin_read_number_byte(byte, &scan->number);
  shell_builtin_read_number_byte(byte, &scan->timeout);
  if (scan->unresolved)
    return true;
  if (scan->position++ == 0) {
    scan->option = byte == '-';
    return true;
  }
  if (!scan->option || !scan->valid)
    return true;
  if (scan->operand) {
    /* Operand bytes are never option letters. Static payload proves that an
     * attached operand cannot disappear even if its quoted expansions do. */
    scan->attached_static = true;
    shell_builtin_read_number_byte(byte, &scan->payload);
    return true;
  }
  switch (byte) {
  case 'a':
    scan->array = true;
    scan->operand = true;
    scan->operand_kind = SHELL_READ_DATA;
    break;
  case 'd':
  case 'i':
  case 'p':
    scan->operand = true;
    scan->operand_kind = SHELL_READ_DATA;
    break;
  case 'n':
  case 'N':
  case 'u':
    scan->operand = true;
    scan->operand_kind = SHELL_READ_NUMBER;
    break;
  case 't':
    scan->operand = true;
    scan->operand_kind = SHELL_READ_TIMEOUT;
    scan->payload.timeout = true;
    break;
  case 'e':
  case 'E':
    /* Readline can expand runtime input as shell source or invoke registered
     * completion/key-binding code. This is not ordinary read target mutation.
     * Only effective option bytes set this flag, never operand payload. */
    scan->readline = true;
    break;
  case 'r':
  case 's':
    break;
  default:
    scan->end = scan->position == 2 && byte == '-';
    scan->valid = false;
    break;
  }
  return true;
}

/* Visit literal fragments and opaque quoted scalar/substitution fragments of
 * a complete word. Success proves exactly one argv entry, including an empty
 * one. List selectors and unquoted expansion have unresolved cardinality and
 * return false; callbacks may already have seen a prefix in that case. The
 * source boundary separately checks supported nested expansion semantics.
 * Visitors consume every fragment; context may be NULL if they allow it. */
typedef void (*shell_builtin_word_dynamic_fn)(void *context);

/* The source scanner has isolated a complete parameter expansion. Prove
 * scalar cardinality without resolving its value or copying its identifier.
 * Complex operators and list selectors remain unknown; length selectors are
 * scalar even for @. Logical continuations do not change that proof. */
static inline SHELL_NONNULL(1) bool shell_builtin_parameter_is_scalar(
    const char *word, size_t length) {
  size_t position = shell_source_skip_escaped_line_endings(word, length, 1);
  size_t end = length;
  if (word[position] == '{') {
    position++;
    end--;
  }
  position = shell_source_skip_escaped_line_endings(word, end, position);
  if (position == end)
    return false;
  unsigned char first = (unsigned char)word[position];
  size_t next = shell_source_skip_escaped_line_endings(word, end, position + 1);
  bool length_selector = first == '#' && next < end;
  if (length_selector) {
    position = next;
    first = (unsigned char)word[position];
    next = shell_source_skip_escaped_line_endings(word, end, position + 1);
  }
  if (strchr("#?$!-*@", first))
    return next == end && (first != '@' || length_selector);
  bool positional = isdigit(first) != 0;
  if (!positional && !(isalpha(first) || first == '_'))
    return false;
  for (position = next; position < end;) {
    unsigned char byte = (unsigned char)word[position];
    if (positional ? !isdigit(byte) : !(isalnum(byte) || byte == '_'))
      return false;
    position = shell_source_skip_escaped_line_endings(word, end, position + 1);
  }
  return true;
}

static inline SHELL_NONNULL(1, 3, 4) bool shell_builtin_visit_single_word(
    const char *word, size_t length, shell_source_byte_visitor_t literal,
    shell_builtin_word_dynamic_fn dynamic, void *context) {
  char quote = 0;
  bool start = true;
  shell_source_brace_scan_t braces = {0};
  shell_source_glob_scan_t glob = {0};
  for (size_t position = 0; position < length;) {
    unsigned char byte = (unsigned char)word[position];
    if (byte == '\\' && quote != '\'' && position + 1 < length) {
      unsigned char next = (unsigned char)word[position + 1];
      if (!quote || next == '$' || next == '`' || next == '"' || next == '\\' ||
          next == '\n' || next == '\r') {
        position += 2;
        if (next == '\r' && position < length && word[position] == '\n')
          position++;
        if (next != '\n' && next != '\r') {
          shell_source_brace_scan_literal(&braces);
          shell_source_glob_scan_step(&glob, next, true);
          literal(next, context);
          start = false;
        }
        continue;
      }
    }
    if (!quote && byte == '$' &&
        shell_source_logical_next_is(word, length, position, '\'', NULL)) {
      shell_source_brace_scan_literal(&braces);
      if (!shell_source_decode_ansi_c_quote(word, length, &position, literal,
                                            context))
        return false;
      start = false;
      continue;
    }
    if (!quote && (byte == '\'' || byte == '"')) {
      shell_source_brace_scan_literal(&braces);
      quote = (char)byte;
      start = false;
      position++;
      continue;
    }
    if (quote && byte == (unsigned char)quote) {
      quote = 0;
      position++;
      continue;
    }
    if (quote != '\'' && (byte == '`' || shell_source_dollar_has_dynamic_syntax(
                                             word, length, position))) {
      if (quote != '"')
        return false;
      size_t after = 0, open = 0;
      if (byte == '`') {
        if (!shell_source_skip_complete_backtick(word, length, position,
                                                 &after))
          return false;
      } else if (shell_source_dollar_arithmetic_open(word, length, position,
                                                     &open)) {
        if (!shell_source_skip_arithmetic_expansion(word, length, position,
                                                    &after))
          return false;
      } else if (shell_source_dollar_parentheses_open(word, length, position,
                                                      &open)) {
        if (!shell_source_find_balanced_parentheses(word, length, open, &after))
          return false;
      } else {
        if (!shell_source_skip_variable_expansion(word, length, position,
                                                  &after) ||
            !shell_builtin_parameter_is_scalar(word + position,
                                               after - position))
          return false;
      }
      dynamic(context);
      position = after;
      continue;
    }
    if (!quote) {
      if (((byte == '<' || byte == '>') &&
           shell_source_process_substitution_open(word, length, position,
                                                  NULL)) ||
          ((byte == '?' || byte == '*' || byte == '+' || byte == '@' ||
            byte == '!') &&
           shell_source_logical_next_is(word, length, position, '(', NULL)) ||
          byte == '*' || byte == '?' || (byte == '~' && start) ||
          shell_source_glob_scan_step(&glob, byte, false) ||
          shell_source_brace_scan_step(&braces, byte))
        return false;
    } else
      shell_source_glob_scan_step(&glob, byte, true);
    literal(byte, context);
    start = false;
    position++;
  }
  return quote == 0;
}

/* getopts accepts an optional --, an optstring, then one variable name. Keep
 * all possible operand positions for a quoted runtime optstring: it might be
 * --, moving the target one word later. Unknown argv cardinality before the
 * target cannot establish that position. TARGET identifies a possible
 * destination; WRITE marks a mutable scalar destination. A surviving DATA
 * phase means an invocation can update OPTIND and OPTARG, including when its
 * destination is invalid or readonly. Option/arity errors before a target
 * leave DATA absent and do not update either implicit variable.
 * State is scanner-local, initialized to SHELL_GETOPTS_OPTIONS; words are
 * complete immutable source spans. */
enum {
  SHELL_GETOPTS_OPTIONS = 1u,
  SHELL_GETOPTS_OPTSTRING = 2u,
  SHELL_GETOPTS_TARGET = 4u,
  SHELL_GETOPTS_DATA = 8u,
};

typedef struct {
  unsigned phases;
} shell_builtin_getopts_t;

typedef struct {
  unsigned char prefix[2];
  size_t length;
  bool dynamic;
} shell_builtin_getopts_word_t;

static inline SHELL_NONNULL(2) bool shell_builtin_getopts_byte(
    unsigned char byte, void *context) {
  shell_builtin_getopts_word_t *scan = context;
  if (!scan->dynamic) {
    if (scan->length < sizeof(scan->prefix))
      scan->prefix[scan->length] = byte;
    scan->length++;
  }
  return true;
}

static inline SHELL_NONNULL(1) void shell_builtin_getopts_dynamic(
    void *context) {
  shell_builtin_getopts_word_t *scan = context;
  scan->dynamic = true;
}

static inline SHELL_NONNULL(1, 2) unsigned shell_builtin_getopts_word(
    shell_builtin_getopts_t *state, const char *word, size_t length) {
  unsigned pending = state->phases & ~SHELL_GETOPTS_DATA;
  if (pending == 0)
    return 0;
  shell_builtin_getopts_word_t scan = {0};
  if (!shell_builtin_visit_single_word(word, length, shell_builtin_getopts_byte,
                                       shell_builtin_getopts_dynamic, &scan))
    return SHELL_BUILTIN_ROLE_UNSUPPORTED;
  unsigned next = state->phases & SHELL_GETOPTS_DATA;
  unsigned roles = 0;
  if (pending & SHELL_GETOPTS_OPTIONS) {
    if (!scan.dynamic) {
      if (scan.length == 2 && scan.prefix[0] == '-' && scan.prefix[1] == '-')
        next |= SHELL_GETOPTS_OPTSTRING;
      else if (!(scan.length > 1 && scan.prefix[0] == '-'))
        next |= SHELL_GETOPTS_TARGET;
      /* Other leading options fail before getopts can write a target. */
    } else if (scan.length != 0 && scan.prefix[0] != '-')
      next |= SHELL_GETOPTS_TARGET;
    else if (!(scan.length > 1 && scan.prefix[0] == '-' &&
               (scan.prefix[1] != '-' || scan.length > 2)))
      next |= SHELL_GETOPTS_OPTSTRING | SHELL_GETOPTS_TARGET;
  }
  if (pending & SHELL_GETOPTS_OPTSTRING)
    next |= SHELL_GETOPTS_TARGET;
  if (pending & SHELL_GETOPTS_TARGET) {
    shell_builtin_variable_t target = shell_builtin_variable(word, length);
    roles = SHELL_BUILTIN_ROLE_TARGET;
    if (target == SHELL_BUILTIN_VARIABLE_DYNAMIC ||
        target == SHELL_BUILTIN_VARIABLE_ARITHMETIC ||
        target == SHELL_BUILTIN_VARIABLE_FROZEN)
      roles |= SHELL_BUILTIN_ROLE_UNSUPPORTED;
    else if (target == SHELL_BUILTIN_VARIABLE_STATIC)
      roles |= SHELL_BUILTIN_ROLE_WRITE;
    next |= SHELL_GETOPTS_DATA;
  }
  state->phases = next;
  return roles;
}

static inline SHELL_NONNULL(1) void shell_builtin_read_dynamic(void *context) {
  shell_builtin_read_option_t *scan = context;
  if (scan->operand)
    scan->attached_dynamic = true;
  else
    scan->unresolved = true;
}

static inline SHELL_NONNULL(1, 3) bool shell_builtin_read_scan_word(
    const char *word, size_t length, shell_builtin_read_option_t *scan) {
  *scan = (shell_builtin_read_option_t){.valid = true,
                                        .timeout = {.timeout = true}};
  return shell_builtin_visit_single_word(word, length,
                                         shell_builtin_read_option_byte,
                                         shell_builtin_read_dynamic, scan);
}

/* `test`/`[` variable-existence operands can re-evaluate an array subscript,
 * even when no array was declared. Classify each complete word once, retaining
 * only operator roles and lookup safety, not copies of source/value strings.
 * Unknown argv cardinality cannot establish expression roles and is rejected.
 * Quoted scalar data still has a known one-word cardinality. */
enum {
  SHELL_TEST_NOT = 1u,
  SHELL_TEST_OPEN = 2u,
  SHELL_TEST_CLOSE = 4u,
  SHELL_TEST_UNARY = 8u,
  SHELL_TEST_LOOKUP = 16u,
  SHELL_TEST_BINARY = 32u,
  SHELL_TEST_JOIN = 64u,
  SHELL_TEST_END = 128u,
};

typedef struct {
  unsigned roles;
  bool dynamic, unsafe_lookup;
} shell_builtin_test_word_t;

typedef struct {
  char spelling[4];
  size_t length;
  bool dynamic, subscript;
} shell_builtin_test_scan_t;

static inline SHELL_NONNULL(2) bool shell_builtin_test_byte(unsigned char byte,
                                                            void *context) {
  SHELL_SOURCE_WORD_SCAN(1);
  shell_builtin_test_scan_t *scan = context;
  if (scan->length < sizeof(scan->spelling) - 1)
    scan->spelling[scan->length] = (char)byte;
  scan->length++;
  scan->subscript |= byte == '[';
  return true;
}

static inline SHELL_NONNULL(1) void shell_builtin_test_dynamic(void *context) {
  shell_builtin_test_scan_t *scan = context;
  scan->dynamic = true;
}

/* A forward recognizer for the general (>3 argument) expression grammar.
 * One-word lookahead distinguishes binary operands from unary operators.
 * Parentheses need a depth, not a tree or rescanning. Truth and short-circuit
 * values are not inferred: every syntactically reached lookup is checked.
 * Unresolved operator positions remain unsupported; unresolved ordinary data
 * operands of a known unary/binary test do not select another operation. */
typedef enum {
  SHELL_TEST_PRIMARY,
  SHELL_TEST_LOOKAHEAD,
  SHELL_TEST_BINARY_VALUE,
  SHELL_TEST_AFTER_PRIMARY,
  SHELL_TEST_ERROR,
} shell_builtin_test_phase_t;

/* An unknown primary followed by a binary operator normally becomes data.
 * If its runtime value is ! or (, Bash instead enters another primary before
 * consuming that operator. Keep those alternatives alive until their grammar
 * fails; an error in the ordinary-data path does not prove they also failed.
 * Six role states, each retaining only the largest reachable parenthesis
 * depth, bound both storage and work independently of expression length. */
enum {
  SHELL_TEST_ALT_PRIMARY,
  SHELL_TEST_ALT_STRING,
  SHELL_TEST_ALT_UNARY,
  SHELL_TEST_ALT_LOOKUP,
  SHELL_TEST_ALT_BINARY_VALUE,
  SHELL_TEST_ALT_AFTER,
  SHELL_TEST_ALT_COUNT,
};

typedef struct {
  unsigned active;
  size_t depth[SHELL_TEST_ALT_COUNT];
} shell_builtin_test_alternatives_t;

static inline SHELL_NONNULL(1) void shell_builtin_test_alternative_add(
    shell_builtin_test_alternatives_t *states, unsigned phase, size_t depth) {
  states->active |= 1u << phase;
  if (depth > states->depth[phase])
    states->depth[phase] = depth;
}

static inline SHELL_NONNULL(1) void shell_builtin_test_alternative_after(
    shell_builtin_test_alternatives_t *next, shell_builtin_test_word_t word,
    size_t depth) {
  if (word.dynamic || (word.roles & SHELL_TEST_JOIN))
    shell_builtin_test_alternative_add(next, SHELL_TEST_ALT_PRIMARY, depth);
  if (depth && (word.dynamic || (word.roles & SHELL_TEST_CLOSE)))
    shell_builtin_test_alternative_add(next, SHELL_TEST_ALT_AFTER, depth - 1);
}

static inline SHELL_NONNULL(1) bool shell_builtin_test_alternatives_word(
    shell_builtin_test_alternatives_t *states, shell_builtin_test_word_t word) {
  shell_builtin_test_alternatives_t next = {0};
  bool unsupported = false;
  for (unsigned phase = 0; phase < SHELL_TEST_ALT_COUNT; phase++) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (!(states->active & (1u << phase)))
      continue;
    size_t depth = states->depth[phase];
    if (phase == SHELL_TEST_ALT_PRIMARY) {
      if (word.dynamic || (word.roles & SHELL_TEST_NOT))
        shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_PRIMARY,
                                           depth);
      if (word.dynamic || (word.roles & SHELL_TEST_OPEN))
        shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_PRIMARY,
                                           depth + 1);
      if (word.dynamic || !(word.roles & (SHELL_TEST_NOT | SHELL_TEST_OPEN))) {
        unsigned head = word.roles & SHELL_TEST_LOOKUP  ? SHELL_TEST_ALT_LOOKUP
                        : word.roles & SHELL_TEST_UNARY ? SHELL_TEST_ALT_UNARY
                                                        : SHELL_TEST_ALT_STRING;
        shell_builtin_test_alternative_add(&next, head, depth);
        if (word.dynamic) {
          shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_LOOKUP,
                                             depth);
          shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_UNARY,
                                             depth);
        }
      }
    } else if (phase == SHELL_TEST_ALT_BINARY_VALUE) {
      shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_AFTER, depth);
    } else if (phase == SHELL_TEST_ALT_AFTER) {
      shell_builtin_test_alternative_after(&next, word, depth);
    } else {
      bool binary = !word.dynamic && (word.roles & SHELL_TEST_BINARY) &&
                    !(word.roles & SHELL_TEST_JOIN);
      if (word.dynamic || binary)
        shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_BINARY_VALUE,
                                           depth);
      if (!binary) {
        if (phase == SHELL_TEST_ALT_STRING)
          shell_builtin_test_alternative_after(&next, word, depth);
        else {
          unsupported |= phase == SHELL_TEST_ALT_LOOKUP && word.unsafe_lookup;
          shell_builtin_test_alternative_add(&next, SHELL_TEST_ALT_AFTER,
                                             depth);
        }
      }
    }
  }
  *states = next;
  return unsupported;
}

typedef struct {
  shell_builtin_test_word_t first[4], last, head;
  size_t count, depth;
  shell_builtin_test_phase_t phase;
  shell_builtin_test_alternatives_t alternatives;
  bool bracket, have_last, unresolved_arity, unsupported;
} shell_builtin_test_t;

static inline SHELL_NONNULL(1) void shell_builtin_test_expression_word(
    shell_builtin_test_t *state, shell_builtin_test_word_t word) {
  state->unsupported |=
      shell_builtin_test_alternatives_word(&state->alternatives, word);
  for (;;) {
    switch (state->phase) {
    case SHELL_TEST_PRIMARY:
      if (word.roles & SHELL_TEST_NOT)
        return;
      if (word.roles & SHELL_TEST_OPEN) {
        state->depth++;
        return;
      }
      state->head = word;
      state->phase = SHELL_TEST_LOOKAHEAD;
      return;
    case SHELL_TEST_LOOKAHEAD:
      if (!word.dynamic && (word.roles & SHELL_TEST_BINARY) &&
          !(word.roles & SHELL_TEST_JOIN)) {
        /* The ordinary interpretation consumes the saved word as data.
         * A !/( value makes this operator the next primary's first word.
         * Both structural alternatives have a plain head; retain their
         * maximum depth until subsequent words establish their roles. */
        if (state->head.dynamic)
          shell_builtin_test_alternative_add(
              &state->alternatives, SHELL_TEST_ALT_STRING, state->depth + 1);
        state->phase = SHELL_TEST_BINARY_VALUE;
        return;
      }
      if (state->head.dynamic) {
        state->unsupported = true;
        state->phase = SHELL_TEST_ERROR;
        return;
      }
      state->phase = SHELL_TEST_AFTER_PRIMARY;
      if (state->head.roles & SHELL_TEST_UNARY) {
        state->unsupported |=
            (state->head.roles & SHELL_TEST_LOOKUP) && word.unsafe_lookup;
        return;
      }
      /* The saved head was a one-word string test. Process this lookahead
       * as its connector/closing delimiter, without revisiting source bytes. */
      break;
    case SHELL_TEST_BINARY_VALUE:
      state->phase = SHELL_TEST_AFTER_PRIMARY;
      return;
    case SHELL_TEST_AFTER_PRIMARY:
      if (word.dynamic)
        state->unsupported = true;
      else if (word.roles & SHELL_TEST_JOIN)
        state->phase = SHELL_TEST_PRIMARY;
      else if ((word.roles & SHELL_TEST_CLOSE) && state->depth)
        state->depth--;
      else
        state->phase = SHELL_TEST_ERROR;
      return;
    case SHELL_TEST_ERROR:
      return;
    }
  }
}

static inline SHELL_NONNULL(1) void shell_builtin_test_append(
    shell_builtin_test_t *state, shell_builtin_test_word_t word) {
  if (state->count < sizeof(state->first) / sizeof(state->first[0]))
    state->first[state->count] = word;
  state->count++;
  shell_builtin_test_expression_word(state, word);
}

/* State was initialized once for the effective builtin. A bracket form delays
 * its last word so the required closing `]` never becomes an expression word.
 * Finish at the simple-command boundary, not after an arbitrary word: Bash's
 * 0..4-argument disambiguation can make a spelling such as `-v` ordinary data.
 */
static inline SHELL_NONNULL(1, 2) void shell_builtin_test_word(
    shell_builtin_test_t *state, const char *word, size_t length) {
  shell_builtin_test_scan_t scan = {0};
  state->unresolved_arity |= !shell_builtin_visit_single_word(
      word, length, shell_builtin_test_byte, shell_builtin_test_dynamic, &scan);
  shell_builtin_test_word_t classified = {
      .dynamic = scan.dynamic,
      .unsafe_lookup = scan.dynamic || scan.subscript,
  };
  if (!scan.dynamic && scan.length < sizeof(scan.spelling)) {
    const char *spelling = scan.spelling;
    if (scan.length == 1) {
      classified.roles =
          spelling[0] == '!'   ? SHELL_TEST_NOT
          : spelling[0] == '(' ? SHELL_TEST_OPEN
          : spelling[0] == ')' ? SHELL_TEST_CLOSE
          : spelling[0] == ']' ? SHELL_TEST_END
          : spelling[0] == '=' || spelling[0] == '<' || spelling[0] == '>'
              ? SHELL_TEST_BINARY
              : 0;
    } else if (scan.length == 2) {
      if (spelling[0] == '-' &&
          strchr("abcdefghkLnNoOprRsStuvwxzG", spelling[1]))
        classified.roles |= SHELL_TEST_UNARY;
      if (spelling[0] == '-' && spelling[1] == 'v')
        classified.roles |= SHELL_TEST_LOOKUP;
      if (!strcmp(spelling, "==") || !strcmp(spelling, "!=") ||
          !strcmp(spelling, "-a") || !strcmp(spelling, "-o"))
        classified.roles |= SHELL_TEST_BINARY;
      if (!strcmp(spelling, "-a") || !strcmp(spelling, "-o"))
        classified.roles |= SHELL_TEST_JOIN;
    } else if (!strcmp(spelling, "-eq") || !strcmp(spelling, "-ne") ||
               !strcmp(spelling, "-lt") || !strcmp(spelling, "-le") ||
               !strcmp(spelling, "-gt") || !strcmp(spelling, "-ge") ||
               !strcmp(spelling, "-nt") || !strcmp(spelling, "-ot") ||
               !strcmp(spelling, "-ef"))
      classified.roles |= SHELL_TEST_BINARY;
  }
  if (state->bracket) {
    if (state->have_last)
      shell_builtin_test_append(state, state->last);
    state->last = classified;
    state->have_last = true;
  } else
    shell_builtin_test_append(state, classified);
}

static inline bool shell_builtin_test_two(shell_builtin_test_word_t first,
                                          shell_builtin_test_word_t second) {
  return !(first.roles & SHELL_TEST_NOT) &&
         (first.dynamic || (first.roles & SHELL_TEST_LOOKUP)) &&
         second.unsafe_lookup;
}

/* Three-argument binary tests take precedence over ! and parentheses. Other
 * static three-word forms fail before evaluating a unary variable lookup. */
static inline bool shell_builtin_test_three(shell_builtin_test_word_t first,
                                            shell_builtin_test_word_t second,
                                            shell_builtin_test_word_t third) {
  if (!second.dynamic && (second.roles & SHELL_TEST_BINARY))
    return false;
  return (first.dynamic || (first.roles & SHELL_TEST_NOT)) &&
         shell_builtin_test_two(second, third);
}

static inline SHELL_NONNULL(1) bool shell_builtin_test_unsupported(
    const shell_builtin_test_t *state) {
  if (state->unresolved_arity)
    return true;
  if (state->bracket) {
    if (!state->have_last)
      return false;
    if (state->last.dynamic)
      return true;
    if (!(state->last.roles & SHELL_TEST_END))
      return false;
  }
  const shell_builtin_test_word_t *words = state->first;
  if (state->count <= 1)
    return false;
  if (state->count == 2)
    return shell_builtin_test_two(words[0], words[1]);
  if (state->count == 3)
    return shell_builtin_test_three(words[0], words[1], words[2]);
  if (state->count == 4) {
    if (!words[0].dynamic && (words[0].roles & SHELL_TEST_NOT))
      return shell_builtin_test_three(words[1], words[2], words[3]);
    if (!words[0].dynamic && (words[0].roles & SHELL_TEST_OPEN) &&
        !words[3].dynamic && (words[3].roles & SHELL_TEST_CLOSE))
      return shell_builtin_test_two(words[1], words[2]);
  }
  return state->unsupported ||
         (state->phase == SHELL_TEST_LOOKAHEAD && state->head.dynamic);
}

/* Consume complete logical argv words once, omitting redirects. TARGET records
 * -v or %n operands (ATTACHED skips two decoded option bytes). FORMAT|WRITE
 * commits the latest -v target; TARGET|WRITE identifies a current %n operand.
 * A compiled schedule handles format reuse in constant time per data word.
 * Invalid names terminate processing except that an empty %n name is a no-op.
 * Static %b '\c' terminates before later writes. Unknown formats have unknown
 * scalar writes; variable-cardinality operands in a %n format are unsupported
 * because they cannot be aligned with the schedule. The source boundary checks
 * target syntax before graph construction. */
static inline SHELL_NONNULL(1, 2) unsigned shell_builtin_printf_word(
    shell_builtin_printf_t *state, const char *word, size_t length) {
  if (state->phase == SHELL_PRINTF_ERROR ||
      state->phase == SHELL_PRINTF_UNKNOWN)
    return 0;
  if (state->phase == SHELL_PRINTF_DATA) {
    shell_builtin_printf_format_t *format = &state->format;
    if (format->arguments == 0)
      return 0;
    if (format->has_count) {
      shell_builtin_read_option_t cardinality;
      if (!shell_builtin_read_scan_word(word, length, &cardinality))
        return SHELL_BUILTIN_ROLE_UNSUPPORTED;
    }
    unsigned roles = 0;
    if (state->event < format->count &&
        format->events[state->event].argument == state->argument) {
      bool writes = format->events[state->event++].writes;
      if (writes) {
        shell_builtin_variable_t variable =
            shell_builtin_variable(word, length);
        roles = SHELL_BUILTIN_ROLE_TARGET;
        if (variable == SHELL_BUILTIN_VARIABLE_DYNAMIC)
          roles |= SHELL_BUILTIN_ROLE_DYNAMIC;
        else if (variable == SHELL_BUILTIN_VARIABLE_FROZEN)
          roles |= SHELL_BUILTIN_ROLE_UNSUPPORTED;
        else if (variable == SHELL_BUILTIN_VARIABLE_STATIC ||
                 variable == SHELL_BUILTIN_VARIABLE_ARITHMETIC)
          roles |= SHELL_BUILTIN_ROLE_WRITE;
        else if (variable == SHELL_BUILTIN_VARIABLE_INVALID) {
          shell_builtin_printf_escape_t scan = {0};
          shell_source_visit_static_word(
              word, length, shell_builtin_printf_escape_byte, &scan);
          if (scan.length != 0)
            state->phase = SHELL_PRINTF_ERROR;
        }
      } else {
        shell_builtin_printf_escape_t scan = {0};
        if (shell_source_visit_static_word(
                word, length, shell_builtin_printf_escape_byte, &scan) &&
            scan.stop)
          state->phase = SHELL_PRINTF_ERROR;
      }
    }
    if (++state->argument == format->arguments) {
      state->argument = 0;
      state->event = 0;
      if (!format->repeat)
        state->phase = SHELL_PRINTF_ERROR;
    }
    return roles;
  }
  if (state->phase == SHELL_PRINTF_TARGET) {
    shell_builtin_variable_t variable = shell_builtin_variable(word, length);
    state->has_target = variable != SHELL_BUILTIN_VARIABLE_READONLY;
    state->phase = variable == SHELL_BUILTIN_VARIABLE_INVALID
                       ? SHELL_PRINTF_ERROR
                       : SHELL_PRINTF_OPTIONS;
    return SHELL_BUILTIN_ROLE_TARGET |
           (variable == SHELL_BUILTIN_VARIABLE_FROZEN ||
                    variable == SHELL_BUILTIN_VARIABLE_ARITHMETIC
                ? SHELL_BUILTIN_ROLE_UNSUPPORTED
                : 0) |
           (variable == SHELL_BUILTIN_VARIABLE_DYNAMIC
                ? SHELL_BUILTIN_ROLE_DYNAMIC
                : 0);
  }
  if (state->phase == SHELL_PRINTF_OPTIONS) {
    shell_builtin_printf_option_t scan = {
        .target = {.valid = true, .names = SHELL_BUILTIN_VARIABLE_MASK}};
    if (!shell_source_visit_static_word(
            word, length, shell_builtin_printf_option_byte, &scan)) {
      state->phase = SHELL_PRINTF_UNKNOWN;
      return SHELL_BUILTIN_ROLE_DYNAMIC;
    }
    if (scan.dash && scan.length > 1) {
      if (scan.end && scan.length == 2)
        state->phase = SHELL_PRINTF_FORMAT;
      else if (scan.v && scan.length == 2)
        state->phase = SHELL_PRINTF_TARGET;
      else if (scan.v) {
        state->has_target = (shell_builtin_variable_properties(&scan.target) &
                             SHELL_VARIABLE_READONLY) == 0;
        state->phase =
            scan.target.valid ? SHELL_PRINTF_OPTIONS : SHELL_PRINTF_ERROR;
        return SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_ATTACHED |
               ((shell_builtin_variable_properties(&scan.target) &
                 (SHELL_VARIABLE_INTEGER | SHELL_VARIABLE_FROZEN))
                    ? SHELL_BUILTIN_ROLE_UNSUPPORTED
                    : 0);
      } else
        state->phase = SHELL_PRINTF_ERROR;
      return 0;
    }
  }
  state->format.repeat = true;
  if (!shell_source_visit_static_word(
          word, length, shell_builtin_printf_format_byte, &state->format)) {
    state->phase = SHELL_PRINTF_UNKNOWN;
    return SHELL_BUILTIN_ROLE_DYNAMIC;
  }
  if (state->format.phase != SHELL_PRINTF_LITERAL &&
      state->format.phase != SHELL_PRINTF_ESCAPE &&
      state->format.phase != SHELL_PRINTF_DONE)
    state->format.repeat = false;
  state->phase = SHELL_PRINTF_DATA;
  return SHELL_BUILTIN_ROLE_FORMAT |
         (state->has_target ? SHELL_BUILTIN_ROLE_WRITE : 0) |
         (state->format.has_count && state->format.unsupported
              ? SHELL_BUILTIN_ROLE_UNSUPPORTED
              : 0);
}

static inline SHELL_NONNULL(4) void shell_builtin_read_operand(
    unsigned kind, unsigned value, unsigned mode, unsigned next[2]) {
  if (kind == SHELL_READ_DATA || value == SHELL_READ_VALUE_UNKNOWN) {
    next[mode] |= SHELL_READ_OPTIONS;
    if (kind == SHELL_READ_TIMEOUT)
      next[1 - mode] |= SHELL_READ_OPTIONS;
  } else if (value != SHELL_READ_VALUE_INVALID) {
    unsigned next_mode = kind == SHELL_READ_TIMEOUT
                             ? (unsigned)(value == SHELL_READ_VALUE_ZERO)
                             : mode;
    next[next_mode] |= SHELL_READ_OPTIONS;
  }
}

static inline SHELL_NONNULL(3) unsigned shell_builtin_read_target(
    shell_builtin_variable_t variable, unsigned mode, unsigned next[2]) {
  unsigned roles = SHELL_BUILTIN_ROLE_TARGET;
  if (!mode && variable == SHELL_BUILTIN_VARIABLE_ARITHMETIC)
    return roles | SHELL_BUILTIN_ROLE_UNSUPPORTED;
  /* Polling returns before target validation/assignment. A writing path
   * stops at its first proven bad/readonly target, preserving earlier writes.
   */
  if (mode || variable == SHELL_BUILTIN_VARIABLE_STATIC ||
      variable == SHELL_BUILTIN_VARIABLE_DYNAMIC) {
    next[mode] |= SHELL_READ_TARGETS;
    if (!mode) {
      roles |= SHELL_BUILTIN_ROLE_WRITE;
      if (variable == SHELL_BUILTIN_VARIABLE_DYNAMIC)
        roles |= SHELL_BUILTIN_ROLE_DYNAMIC;
    }
  }
  return roles;
}

static inline SHELL_NONNULL(1, 2) unsigned shell_builtin_read_word(
    shell_builtin_read_t *state, const char *word, size_t length) {
  unsigned phases[2] = {state->writing, state->polling};
  unsigned next[2] = {0};
  unsigned roles = 0;
  shell_builtin_read_option_t scan = {0};
  unsigned option_phases = SHELL_READ_OPTIONS | SHELL_READ_DATA |
                           SHELL_READ_NUMBER | SHELL_READ_TIMEOUT;
  if ((phases[0] | phases[1]) & option_phases) {
    if (!shell_builtin_read_scan_word(word, length, &scan))
      return SHELL_BUILTIN_ROLE_UNSUPPORTED;
    if (((phases[0] | phases[1]) & SHELL_READ_OPTIONS) &&
        (scan.unresolved || scan.array || scan.readline))
      return SHELL_BUILTIN_ROLE_UNSUPPORTED;
  }
  bool target = ((phases[0] | phases[1]) &
                 (SHELL_READ_TARGETS | SHELL_READ_POSITIONAL)) ||
                (((phases[0] | phases[1]) & SHELL_READ_OPTIONS) &&
                 (!scan.option || scan.position < 2));
  shell_builtin_variable_t variable = target
                                          ? shell_builtin_variable(word, length)
                                          : SHELL_BUILTIN_VARIABLE_INVALID;
  bool dynamic = scan.unresolved || scan.attached_dynamic;
  for (unsigned mode = 0; mode < 2; mode++) {
    if (phases[mode] & (SHELL_READ_TARGETS | SHELL_READ_POSITIONAL))
      roles |= shell_builtin_read_target(variable, mode, next);
    if (phases[mode] & SHELL_READ_DATA)
      shell_builtin_read_operand(SHELL_READ_DATA, SHELL_READ_VALUE_UNKNOWN,
                                 mode, next);
    if (phases[mode] & SHELL_READ_NUMBER)
      shell_builtin_read_operand(
          SHELL_READ_NUMBER,
          shell_builtin_read_number_value(&scan.number, dynamic), mode, next);
    if (phases[mode] & SHELL_READ_TIMEOUT)
      shell_builtin_read_operand(
          SHELL_READ_TIMEOUT,
          shell_builtin_read_number_value(&scan.timeout, dynamic), mode, next);
    if (!(phases[mode] & SHELL_READ_OPTIONS))
      continue;
    if (!scan.option || scan.position < 2)
      roles |= shell_builtin_read_target(variable, mode, next);
    else if (!scan.valid) {
      /* `--` ends options; invalid flags terminate without mutation. */
      if (scan.position == 2 && scan.end)
        next[mode] |= SHELL_READ_POSITIONAL;
    } else if (scan.operand) {
      if (scan.attached_static || scan.attached_dynamic)
        shell_builtin_read_operand(scan.operand_kind,
                                   shell_builtin_read_number_value(
                                       &scan.payload, scan.attached_dynamic),
                                   mode, next);
      if (!scan.attached_static)
        next[mode] |= scan.operand_kind;
    } else
      next[mode] |= SHELL_READ_OPTIONS;
  }
  state->writing = next[0];
  state->polling = next[1];
  return roles;
}

static inline SHELL_NONNULL(1) bool shell_builtin_read_default_write(
    const shell_builtin_read_t *state) {
  return (state->writing & (SHELL_READ_OPTIONS | SHELL_READ_POSITIONAL)) != 0;
}

typedef struct {
  bool options, functions, variables, nameref, error;
} shell_builtin_unset_t;

typedef struct {
  size_t length;
  bool dash, valid, functions, variables, nameref, end;
} shell_builtin_unset_option_t;

static inline SHELL_NONNULL(2) bool shell_builtin_unset_option_byte(
    unsigned char byte, void *context) {
  shell_builtin_unset_option_t *scan = context;
  if (scan->length++ == 0)
    scan->dash = byte == '-';
  else if (byte == 'f')
    scan->functions = true;
  else if (byte == 'v')
    scan->variables = true;
  else if (byte == 'n')
    scan->nameref = true;
  else {
    scan->end = scan->length == 2 && byte == '-';
    scan->valid = false;
  }
  return true;
}

static inline SHELL_NONNULL(1, 2) unsigned shell_builtin_unset_word(
    shell_builtin_unset_t *state, const char *word, size_t length) {
  if (state->error)
    return 0;
  if (state->options) {
    shell_builtin_unset_option_t scan = {.valid = true};
    if (shell_source_visit_static_word(
            word, length, shell_builtin_unset_option_byte, &scan) &&
        scan.dash && scan.length > 1) {
      if (scan.end && scan.length == 2)
        state->options = false;
      else {
        state->functions |= scan.functions;
        state->variables |= scan.variables;
        state->nameref |= scan.nameref;
        state->error = !scan.valid || (state->functions && state->variables);
      }
      return 0;
    }
    state->options = false;
  }
  if (state->functions || state->nameref)
    return 0;
  unsigned roles = SHELL_BUILTIN_ROLE_TARGET;
  shell_builtin_variable_t variable = shell_builtin_variable(word, length);
  if (variable == SHELL_BUILTIN_VARIABLE_STATIC ||
      variable == SHELL_BUILTIN_VARIABLE_ARITHMETIC)
    roles |= SHELL_BUILTIN_ROLE_WRITE;
  else if (variable == SHELL_BUILTIN_VARIABLE_DYNAMIC)
    roles |= SHELL_BUILTIN_ROLE_WRITE | SHELL_BUILTIN_ROLE_DYNAMIC;
  return roles;
}

#endif
