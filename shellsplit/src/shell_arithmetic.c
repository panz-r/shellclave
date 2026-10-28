#include "shell_arithmetic_internal.h"
#include "shell_source_internal.h"
#include <limits.h>

typedef struct {
  const char *source;
  size_t length, position;
  bool valid;
  bool uncertain_expansion;
  bool scalar_names, references, evaluating, mutation;
  shell_arithmetic_reference_fn visitor;
  void *context;
} arithmetic_parser_t;

typedef struct {
  bool known;
  int64_t value;
} arithmetic_value_t;

typedef enum {
  OP_NONE,
  OP_OR,
  OP_AND,
  OP_BITOR,
  OP_XOR,
  OP_BITAND,
  OP_EQ,
  OP_NE,
  OP_LE,
  OP_GE,
  OP_LEFT,
  OP_RIGHT,
  OP_LT,
  OP_GT,
  OP_ADD,
  OP_SUB,
  OP_POWER,
  OP_MUL,
  OP_DIV,
  OP_MOD,
} arithmetic_operator_t;

static const struct {
  const char *text;
  unsigned precedence;
  bool right;
  arithmetic_operator_t op;
} operators[] = {
    {"||", 1, false, OP_OR},    {"&&", 2, false, OP_AND},
    {"|", 3, false, OP_BITOR},  {"^", 4, false, OP_XOR},
    {"&", 5, false, OP_BITAND}, {"==", 6, false, OP_EQ},
    {"!=", 6, false, OP_NE},    {"<=", 7, false, OP_LE},
    {">=", 7, false, OP_GE},    {"<<", 8, false, OP_LEFT},
    {">>", 8, false, OP_RIGHT}, {"<", 7, false, OP_LT},
    {">", 7, false, OP_GT},     {"+", 9, false, OP_ADD},
    {"-", 9, false, OP_SUB},    {"**", 11, true, OP_POWER},
    {"*", 10, false, OP_MUL},   {"/", 10, false, OP_DIV},
    {"%", 10, false, OP_MOD},
};

/* Bash arithmetic skips only space, tab and LF, after removing backslash-LF.
 * CR, VT and FF are significant bytes and must reach grammar rejection.
 * Cursor and output storage are established by the arithmetic boundary. */
static SHELL_NONNULL(1) void skip_space(arithmetic_parser_t *p) {
  for (;;) {
    p->position = shell_source_skip_escaped_line_endings(p->source, p->length,
                                                         p->position);
    if (p->position == p->length ||
        !shell_source_space((unsigned char)p->source[p->position]))
      return;
    p->position++;
  }
}

static SHELL_NONNULL(1, 2) bool match(arithmetic_parser_t *p,
                                      const char *text) {
  size_t saved = p->position;
  for (size_t i = 0; text[i]; ++i) {
    SHELL_SOURCE_WORD_SCAN(1);
    p->position = shell_source_skip_escaped_line_endings(p->source, p->length,
                                                         p->position);
    if (p->position == p->length || p->source[p->position] != text[i]) {
      p->position = saved;
      return false;
    }
    ++p->position;
  }
  return true;
}

static arithmetic_value_t known(int64_t value) {
  return (arithmetic_value_t){true, value};
}

static int64_t signed_bits(uint64_t bits) {
  return bits <= INT64_MAX ? (int64_t)bits : -1 - (int64_t)(UINT64_MAX - bits);
}

static SHELL_NONNULL(3) bool multiply(int64_t a, int64_t b, int64_t *out);

/* The shared lexical scanner establishes valid digits, radix and extent.
 * Conversion supplies proof facts without deriving that metadata again. */
static SHELL_NONNULL(1) arithmetic_value_t number(arithmetic_parser_t *p) {
  shell_source_arithmetic_number_t literal;
  if (!shell_source_scan_arithmetic_number(p->source, p->length, p->position,
                                           &literal)) {
    p->valid = false;
    return (arithmetic_value_t){0};
  }
  unsigned base = literal.base;
  int64_t value = 0;
  bool fits = true;
  for (size_t i = literal.digits; i < literal.after;) {
    SHELL_SOURCE_WORD_SCAN(1);
    i = shell_source_skip_escaped_line_endings(p->source, literal.after, i);
    if (i == literal.after)
      break;
    unsigned char c = (unsigned char)p->source[i++];
    unsigned digit = c >= '0' && c <= '9'   ? (unsigned)(c - '0')
                     : c >= 'a' && c <= 'z' ? 10u + c - 'a'
                     : c >= 'A' && c <= 'Z' ? (base <= 36 ? 10u : 36u) + c - 'A'
                     : c == '@'             ? 62u
                                            : 63u;
    int64_t product;
    if (fits && multiply(value, base, &product) && product <= INT64_MAX - digit)
      value = product + digit;
    else
      fits = false;
  }
  p->position = literal.after;
  return (arithmetic_value_t){fits, fits ? value : 0};
}

static SHELL_NONNULL(3) bool multiply(int64_t a, int64_t b, int64_t *out) {
  if (a > 0
          ? (b > 0 ? a > INT64_MAX / b : b < INT64_MIN / a)
          : (a < 0 && (b > 0 ? a < INT64_MIN / b : b < 0 && a < INT64_MAX / b)))
    return false;
  *out = a * b;
  return true;
}

static arithmetic_value_t binary_value(arithmetic_operator_t op,
                                       arithmetic_value_t left,
                                       arithmetic_value_t right) {
  if (!left.known || !right.known)
    return (arithmetic_value_t){0};
  int64_t a = left.value, b = right.value, result;
  switch (op) {
  case OP_OR:
    return known(a != 0 || b != 0);
  case OP_AND:
    return known(a != 0 && b != 0);
  case OP_BITOR:
    return known(signed_bits((uint64_t)a | (uint64_t)b));
  case OP_XOR:
    return known(signed_bits((uint64_t)a ^ (uint64_t)b));
  case OP_BITAND:
    return known(signed_bits((uint64_t)a & (uint64_t)b));
  case OP_EQ:
    return known(a == b);
  case OP_NE:
    return known(a != b);
  case OP_LE:
    return known(a <= b);
  case OP_GE:
    return known(a >= b);
  case OP_LT:
    return known(a < b);
  case OP_GT:
    return known(a > b);
  case OP_ADD:
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b))
      break;
    return known(a + b);
  case OP_SUB:
    if ((b < 0 && a > INT64_MAX + b) || (b > 0 && a < INT64_MIN + b))
      break;
    return known(a - b);
  case OP_MUL:
    if (multiply(a, b, &result))
      return known(result);
    break;
  case OP_DIV:
  case OP_MOD:
    if (!b || (a == INT64_MIN && b == -1))
      break;
    return known(op == OP_DIV ? a / b : a % b);
  case OP_LEFT:
  case OP_RIGHT:
    if (a < 0 || b < 0 || b >= 63)
      break;
    if (op == OP_RIGHT)
      return known(a >> (unsigned)b);
    if (a > (INT64_MAX >> (unsigned)b))
      break;
    return known(a << (unsigned)b);
  case OP_POWER:
    if (b < 0)
      break;
    result = 1;
    while (b) {
      if ((b & 1) && !multiply(result, a, &result))
        return (arithmetic_value_t){0};
      b >>= 1;
      if (b && !multiply(a, a, &a))
        return (arithmetic_value_t){0};
    }
    return known(result);
  default:
    break;
  }
  return (arithmetic_value_t){0};
}

static SHELL_NONNULL(1) arithmetic_value_t
    parse_comma(arithmetic_parser_t *p, size_t depth);

static SHELL_NONNULL(1) arithmetic_value_t
    primary(arithmetic_parser_t *p, size_t depth) {
  skip_space(p);
  if (depth > SHELL_MAX_SUBCOMMANDS || p->position == p->length) {
    p->valid = false;
    return (arithmetic_value_t){0};
  }
  if (shell_ascii_digit((unsigned char)p->source[p->position]))
    return number(p);
  if (p->scalar_names &&
      (shell_ascii_alpha((unsigned char)p->source[p->position]) ||
       p->source[p->position] == '_')) {
    size_t first = p->position++;
    while (p->position < p->length &&
           (shell_ascii_alnum((unsigned char)p->source[p->position]) ||
            p->source[p->position] == '_'))
      ++p->position;
    size_t after = p->position;
    skip_space(p);
    /* Bash recognizes adjacent signs after a scalar token as postfix
     * mutation, even when more expression bytes follow (count++1). */
    if (match(p, "++") || match(p, "--")) {
      p->mutation = true;
      p->valid = false;
      return (arithmetic_value_t){0};
    }
    p->position = after;
    p->references |= p->evaluating;
    if (p->visitor && p->evaluating)
      p->visitor(p->source + first, p->position - first, p->context);
    return (arithmetic_value_t){0};
  }
  bool nested = match(p, "$((");
  if (!nested && !match(p, "(")) {
    p->valid = false;
    return (arithmetic_value_t){0};
  }
  skip_space(p);
  arithmetic_value_t value;
  if (nested && match(p, ")"))
    value = known(0);
  else {
    value = parse_comma(p, depth + 1);
    skip_space(p);
    if (!match(p, ")"))
      p->valid = false;
  }
  if (nested && !match(p, ")"))
    p->valid = false;
  /* Arithmetic expansion happens before the enclosing expression, including
   * when a logical or conditional operator would skip this operand. */
  if (nested && !value.known)
    p->uncertain_expansion = true;
  return value;
}

/* Consume unary chains forward and apply their operators backwards once,
 * without a recursive call or auxiliary stack for every source byte. Bash
 * treats adjacent signs on literals as unary operators (for example 1--2).
 * In scalar mode, adjacent signs followed by optional whitespace and a name
 * are prefix mutation tokens. Reject them independently of branch execution;
 * separated signs and pairs before numeric literals remain pure operators. */
static SHELL_NONNULL(1) arithmetic_value_t
    unary(arithmetic_parser_t *p, size_t depth) {
  size_t start = p->position;
  for (;;) {
    skip_space(p);
    if (p->scalar_names && p->position < p->length &&
        (p->source[p->position] == '+' || p->source[p->position] == '-')) {
      size_t saved = p->position;
      if (match(p, "++") || match(p, "--")) {
        skip_space(p);
        if (p->position < p->length &&
            (shell_ascii_alpha((unsigned char)p->source[p->position]) ||
             p->source[p->position] == '_')) {
          p->mutation = true;
          p->valid = false;
          return (arithmetic_value_t){0};
        }
      }
      p->position = saved;
    }
    if (!match(p, "+") && !match(p, "-") && !match(p, "!") && !match(p, "~"))
      break;
  }
  size_t end = p->position;
  arithmetic_value_t value = primary(p, depth);
  /* Visit unary source backwards once; physical continuations contain no
   * operator bytes. This preserves exact operator order without a stack. */
  for (size_t i = end; value.known && i > start;) {
    char c = p->source[--i];
    if (c == '-') {
      if (value.value == INT64_MIN)
        value.known = false;
      else
        value.value = -value.value;
    } else if (c == '!')
      value.value = !value.value;
    else if (c == '~')
      value.value = signed_bits(~(uint64_t)value.value);
  }
  return value;
}

static SHELL_NONNULL(1) arithmetic_value_t
    parse_binary(arithmetic_parser_t *p, unsigned minimum, size_t depth) {
  if (depth > SHELL_MAX_SUBCOMMANDS) {
    p->valid = false;
    return (arithmetic_value_t){0};
  }
  arithmetic_value_t left = unary(p, depth);
  while (p->valid) {
    skip_space(p);
    size_t saved = p->position, selected = 0;
    bool found = false;
    for (size_t i = 0; i < sizeof(operators) / sizeof(operators[0]); ++i) {
      if (match(p, operators[i].text)) {
        selected = i;
        found = true;
        break;
      }
    }
    if (!found || operators[selected].precedence < minimum) {
      p->position = saved;
      return left;
    }
    arithmetic_operator_t op = operators[selected].op;
    bool evaluating = p->evaluating;
    if (left.known &&
        ((op == OP_AND && !left.value) || (op == OP_OR && left.value)))
      p->evaluating = false;
    arithmetic_value_t right = parse_binary(
        p, operators[selected].precedence + !operators[selected].right,
        depth + 1);
    p->evaluating = evaluating;
    if (left.known &&
        ((op == OP_AND && !left.value) || (op == OP_OR && left.value)))
      left = known(op == OP_OR);
    else
      left = binary_value(op, left, right);
  }
  return left;
}

static SHELL_NONNULL(1) arithmetic_value_t
    conditional(arithmetic_parser_t *p, size_t depth) {
  arithmetic_value_t condition = parse_binary(p, 1, depth);
  skip_space(p);
  if (!p->valid || !match(p, "?"))
    return condition;
  bool evaluating = p->evaluating;
  if (condition.known && !condition.value)
    p->evaluating = false;
  arithmetic_value_t yes = parse_comma(p, depth + 1);
  p->evaluating = evaluating;
  skip_space(p);
  if (!match(p, ":"))
    p->valid = false;
  if (condition.known && condition.value)
    p->evaluating = false;
  arithmetic_value_t no = conditional(p, depth + 1);
  p->evaluating = evaluating;
  return condition.known ? (condition.value ? yes : no)
                         : (arithmetic_value_t){0};
}

static SHELL_NONNULL(1) arithmetic_value_t
    parse_comma(arithmetic_parser_t *p, size_t depth) {
  arithmetic_value_t value = conditional(p, depth);
  for (;;) {
    skip_space(p);
    if (!p->valid || !match(p, ","))
      return value;
    arithmetic_value_t next = conditional(p, depth);
    value = value.known ? next : (arithmetic_value_t){0};
  }
}

shell_arithmetic_result_t shell_arithmetic_analyze(const char *source,
                                                   size_t length) {
  arithmetic_parser_t p = {.source = source, .length = length, .valid = true};
  skip_space(&p);
  arithmetic_value_t value =
      p.position == length ? known(0) : parse_comma(&p, 1);
  skip_space(&p);
  bool supported = p.valid && p.position == length;
  value.known = value.known && !p.uncertain_expansion;
  return (shell_arithmetic_result_t){supported, supported && value.known,
                                     supported && value.known ? value.value
                                                              : 0};
}

shell_arithmetic_scalar_result_t
shell_arithmetic_analyze_scalar(const char *source, size_t length,
                                shell_arithmetic_reference_fn visitor,
                                void *context) {
  /* Expanded values contain no shell lexical operations. In particular, a
   * protected dollar or backslash cannot acquire source semantics here. */
  if (memchr(source, '$', length) || memchr(source, '\\', length))
    return (shell_arithmetic_scalar_result_t){0};
  arithmetic_parser_t p = {.source = source,
                           .length = length,
                           .valid = true,
                           .scalar_names = true,
                           .evaluating = true,
                           .visitor = visitor,
                           .context = context};
  skip_space(&p);
  arithmetic_value_t value =
      p.position == length ? known(0) : parse_comma(&p, 1);
  skip_space(&p);
  bool supported = p.valid && p.position == length;
  bool proved =
      supported && value.known && !p.uncertain_expansion && !p.references;
  return (shell_arithmetic_scalar_result_t){
      .result = {supported, proved, proved ? value.value : 0},
      .references = p.references,
      .mutation = p.mutation};
}

bool shell_arithmetic_substring_supported(const char *source, size_t length) {
  arithmetic_parser_t p = {.source = source, .length = length, .valid = true};
  skip_space(&p);
  if (p.position < length && source[p.position] != ':')
    (void)parse_comma(&p, 1);
  skip_space(&p);
  if (p.valid && p.position < length) {
    if (!match(&p, ":"))
      return false;
    skip_space(&p);
    if (p.position < length)
      (void)parse_comma(&p, 1);
    skip_space(&p);
  }
  return p.valid && p.position == length;
}
