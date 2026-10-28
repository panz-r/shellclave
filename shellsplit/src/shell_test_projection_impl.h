/* Private shell_test.c implementation. Project accepted grammar roles without
 * enumerating runtime strings. Each interval/nonterminal is visited once for
 * construction and once for operand collection. Only ambiguous programs use
 * this bounded chart; exact programs keep their ordinary expression tree. */
/* Hard variants end at the concrete parser's current `end`. Soft variants
 * still see the following connector or enclosing ')' as lookahead. A small
 * group's counted dispatch preserves that lookahead if it falls back to the
 * general grammar. All eight states fit in the chart/visited byte per interval.
 */
enum {
  PROJECT_TERM = 1,
  PROJECT_AND = 2,
  PROJECT_OR = 4,
  PROJECT_COUNTED = 8,
  PROJECT_HARD_TERM = 16,
  PROJECT_HARD_AND = 32,
  PROJECT_HARD_OR = 64,
  PROJECT_HARD_COUNTED = 128,
};

typedef struct {
  unsigned kind;
  size_t first, last;
} test_projection_ref_t;

typedef struct {
  shell_builtin_test_word_t words[SHELL_DEP_MAX_TOKENS];
  shell_test_program_t *program;
  uint8_t *chart, *visited;
  size_t count, stride;
} test_projection_t;

static SHELL_NONNULL(1) void project_visit(test_projection_t *p,
                                           test_projection_ref_t ref,
                                           bool collect);

static SHELL_NONNULL(1) void project_comparison(test_projection_t *p,
                                                size_t op) {
  const shell_test_value_t *word = &p->program->words[op];
  unsigned kinds = 0;
  if (!word->known)
    kinds = (1u << SHELL_FILE_COMPARISON_COUNT) - 1u;
  else if (word->value_length == 3) {
#define FILE_COMPARISON_PROJECT(kind, name, ordinal, spelling)                 \
  if (!memcmp(word->value, spelling, 3))                                       \
    kinds = SHELL_FILE_COMPARE_##kind;
    SHELL_FILE_COMPARISONS(FILE_COMPARISON_PROJECT)
#undef FILE_COMPARISON_PROJECT
  }
  p->program->file_comparisons[op] |= (uint8_t)kinds;
}

static SHELL_NONNULL(1) bool project_role(const test_projection_t *p,
                                          size_t word,
                                          shell_test_roles_t role) {
  return p->words[word].dynamic || (p->words[word].roles & role) != 0;
}

static SHELL_NONNULL(1) bool project_has(const test_projection_t *p,
                                         test_projection_ref_t ref) {
  return !ref.kind || (p->chart[ref.first * p->stride + ref.last] & ref.kind);
}

static SHELL_NONNULL(1) void project_rule(
    test_projection_t *p, test_projection_ref_t ref, bool collect, bool valid,
    test_projection_ref_t a, test_projection_ref_t b, size_t operand,
    shell_test_roles_t roles) {
  SHELL_SOURCE_WORD_SCAN(1);
  if (!valid || !project_has(p, a) || !project_has(p, b))
    return;
  if (!collect) {
    p->chart[ref.first * p->stride + ref.last] |= (uint8_t)ref.kind;
    return;
  }
  if (roles)
    p->program->operand_roles[operand] |= roles;
  if (a.kind)
    project_visit(p, a, true);
  if (b.kind)
    project_visit(p, b, true);
}

/* Bash searches for a small group's closer from its second interior word.
 * Unknown words can be ordinary data or parentheses. Discard paths that
 * already selected an earlier closer instead of inventing a later boundary. */
static SHELL_NONNULL(1) bool project_group_close(const test_projection_t *p,
                                                 size_t first, size_t last) {
  uint64_t depths = UINT64_C(2);
  for (size_t i = first + 2; i < last; ++i) {
    const shell_builtin_test_word_t *word = &p->words[i];
    if (word->dynamic)
      depths |= (depths << 1) | (depths >> 1);
    else if (word->roles & SHELL_TEST_OPEN)
      depths <<= 1;
    else if (word->roles & SHELL_TEST_CLOSE)
      depths >>= 1;
    depths &= ~UINT64_C(1);
  }
  return project_role(p, last, SHELL_TEST_CLOSE) && (depths & 2u);
}

static SHELL_NONNULL(1) shell_test_roles_t
    project_unary_roles(const shell_builtin_test_word_t *word) {
  return word->dynamic
             ? SHELL_TEST_FILE_ROLES | SHELL_TEST_LOOKUP
             : word->roles & (SHELL_TEST_FILE_ROLES | SHELL_TEST_LOOKUP);
}

static SHELL_NONNULL(1) void project_visit(test_projection_t *p,
                                           test_projection_ref_t ref,
                                           bool collect) {
  size_t first = ref.first, last = ref.last, count = last - first;
  bool hard_end = ref.kind >= PROJECT_HARD_TERM;
  unsigned kind = hard_end ? ref.kind >> 4 : ref.kind;
  test_projection_ref_t none = {0};
  if (collect) {
    uint8_t *visited = &p->visited[first * p->stride + last];
    if ((*visited & ref.kind) || !project_has(p, ref))
      return;
    *visited |= (uint8_t)ref.kind;
  }
  if (kind == PROJECT_COUNTED) {
    shell_test_dispatch_t dispatch =
        shell_test_dispatch(p->words + first, count, p->count >= 4);
    if (count <= 4 &&
        (dispatch.kind == SHELL_TEST_DISPATCH_UNKNOWN ||
         dispatch.kind == SHELL_TEST_DISPATCH_GENERAL) &&
        (dispatch.first || dispatch.count != count)) {
      project_rule(
          p, ref, collect, true,
          (test_projection_ref_t){ref.kind, first + dispatch.first,
                                  first + dispatch.first + dispatch.count},
          none, 0, 0);
      return;
    }
    switch (dispatch.kind) {
    case SHELL_TEST_DISPATCH_ERROR:
      return;
    case SHELL_TEST_DISPATCH_UNARY:
      project_rule(p, ref, collect, true, none, none,
                   first + dispatch.first + 1,
                   project_unary_roles(&p->words[first + dispatch.first]));
      return;
    case SHELL_TEST_DISPATCH_UNKNOWN:
      if (count == 2) {
        project_rule(p, ref, collect, p->words[first].dynamic, none, none,
                     first + 1, project_unary_roles(&p->words[first]));
      } else {
        if (collect && p->words[first + 1].dynamic)
          project_comparison(p, first + 1);
        project_rule(p, ref, collect, p->words[first + 1].dynamic, none, none,
                     0, 0);
        project_rule(p, ref, collect, project_role(p, first, SHELL_TEST_NOT),
                     (test_projection_ref_t){ref.kind, first + 1, last}, none,
                     0, 0);
        project_rule(p, ref, collect,
                     project_role(p, first, SHELL_TEST_OPEN) &&
                         project_role(p, last - 1, SHELL_TEST_CLOSE),
                     none, none, 0, 0);
      }
      return;
    case SHELL_TEST_DISPATCH_GENERAL:
      project_rule(p, ref, collect, true,
                   (test_projection_ref_t){
                       hard_end ? PROJECT_HARD_OR : PROJECT_OR, first, last},
                   none, 0, 0);
      if (count == 4) {
        project_rule(p, ref, collect, project_role(p, first, SHELL_TEST_NOT),
                     (test_projection_ref_t){ref.kind, first + 1, last}, none,
                     0, 0);
        project_rule(
            p, ref, collect,
            project_role(p, first, SHELL_TEST_OPEN) &&
                project_role(p, last - 1, SHELL_TEST_CLOSE),
            (test_projection_ref_t){PROJECT_COUNTED, first + 1, last - 1}, none,
            0, 0);
      }
      return;
    default:
      if (collect && dispatch.kind == SHELL_TEST_DISPATCH_BINARY)
        project_comparison(p, first + dispatch.first + 1);
      project_rule(p, ref, collect, true, none, none, 0, 0);
      return;
    }
  }
  if (!count)
    return;
  if (kind == PROJECT_AND || kind == PROJECT_OR) {
    unsigned child = kind == PROJECT_AND ? PROJECT_TERM : PROJECT_AND;
    unsigned final_child = hard_end ? child << 4 : child;
    shell_test_roles_t connector =
        kind == PROJECT_AND ? SHELL_TEST_AND_JOIN : SHELL_TEST_OR_JOIN;
    project_rule(p, ref, collect, true,
                 (test_projection_ref_t){final_child, first, last}, none, 0, 0);
    for (size_t split = first + 1; split + 1 < last; ++split)
      project_rule(p, ref, collect, project_role(p, split, connector),
                   (test_projection_ref_t){kind, first, split},
                   (test_projection_ref_t){final_child, split + 1, last}, 0, 0);
    return;
  }
  const shell_builtin_test_word_t *head = &p->words[first];
  bool ordinary =
      head->dynamic || !(head->roles & (SHELL_TEST_NOT | SHELL_TEST_OPEN));
  if (count > 1)
    project_rule(p, ref, collect, project_role(p, first, SHELL_TEST_NOT),
                 (test_projection_ref_t){ref.kind, first + 1, last}, none, 0,
                 0);
  if (count >= 3 && project_role(p, first, SHELL_TEST_OPEN) &&
      project_role(p, last - 1, SHELL_TEST_CLOSE)) {
    bool small = count - 2 <= 4 && project_group_close(p, first, last - 1);
    project_rule(p, ref, collect, true,
                 (test_projection_ref_t){small ? PROJECT_COUNTED : PROJECT_OR,
                                         first + 1, last - 1},
                 none, 0, 0);
  }
  if (!ordinary)
    return;
  if (count == 1) {
    bool string =
        head->dynamic || !(head->roles & SHELL_TEST_UNARY) || hard_end;
    if ((head->roles & SHELL_TEST_TERMINAL) && !hard_end && last < p->count) {
      const shell_builtin_test_word_t *next = &p->words[last];
      shell_test_terminal_operand_t operand = shell_test_terminal_operand(
          next->roles, !next->dynamic, next->number, p->count >= 4);
      string |= operand == SHELL_TEST_TERMINAL_IMPLICIT ||
                operand == SHELL_TEST_TERMINAL_UNKNOWN;
    }
    project_rule(p, ref, collect, string, none, none, 0, 0);
  } else if (count == 2) {
    const shell_builtin_test_word_t *next = &p->words[first + 1];
    bool unary =
        (head->dynamic || (head->roles & SHELL_TEST_UNARY)) &&
        (hard_end || (shell_test_lookahead(next->roles, next->dynamic) &
                      SHELL_TEST_LOOKAHEAD_OPERAND));
    if (head->roles & SHELL_TEST_TERMINAL) {
      shell_test_terminal_operand_t operand = shell_test_terminal_operand(
          next->roles, !next->dynamic, next->number, p->count >= 4);
      unary &= operand == SHELL_TEST_TERMINAL_CONSUME ||
               operand == SHELL_TEST_TERMINAL_UNKNOWN;
    }
    project_rule(p, ref, collect, unary, none, none, first + 1,
                 project_unary_roles(head));
  } else if (count == 3) {
    const shell_builtin_test_word_t *next = &p->words[first + 1];
    if (collect && (shell_test_lookahead(next->roles, next->dynamic) &
                    SHELL_TEST_LOOKAHEAD_BINARY))
      project_comparison(p, first + 1);
    project_rule(p, ref, collect,
                 shell_test_lookahead(next->roles, next->dynamic) &
                     SHELL_TEST_LOOKAHEAD_BINARY,
                 none, none, 0, 0);
  }
}

static SHELL_NONNULL(1) bool project_program(shell_test_program_t *program,
                                             size_t count) {
  size_t mark = shell_source_scratch_mark();
  size_t stride = count + 1, cells = stride * stride;
  uint8_t *chart = shell_source_scratch_take(cells * 2);
  if (!chart)
    return false;
  memset(chart, 0, cells * 2);
  memset(program->operand_roles, 0,
         program->word_count * sizeof(*program->operand_roles));
  test_projection_t projection = {.program = program,
                                  .chart = chart,
                                  .visited = chart + cells,
                                  .count = count,
                                  .stride = stride};
  for (size_t i = 0; i < count; ++i) {
    const shell_test_value_t *word = &program->words[i];
    projection.words[i] = (shell_builtin_test_word_t){
        .roles = word->known
                     ? shell_test_static_roles(word->value, word->value_length)
                     : 0,
        .dynamic = !word->known,
        .number = word->number};
  }
  static const unsigned kinds[] = {
      PROJECT_TERM,     PROJECT_AND,     PROJECT_OR,      PROJECT_HARD_TERM,
      PROJECT_HARD_AND, PROJECT_HARD_OR, PROJECT_COUNTED, PROJECT_HARD_COUNTED};
  for (size_t length = 0; length <= count; ++length)
    for (size_t first = 0; first + length <= count; ++first)
      for (size_t kind = 0; kind < sizeof(kinds) / sizeof(*kinds); ++kind)
        project_visit(
            &projection,
            (test_projection_ref_t){kinds[kind], first, first + length}, false);
  test_projection_ref_t root = {PROJECT_HARD_COUNTED, 0, count};
  if (project_has(&projection, root))
    project_visit(&projection, root, true);
  else
    program->proven_error = true;
  shell_source_scratch_release(mark);
  return true;
}
