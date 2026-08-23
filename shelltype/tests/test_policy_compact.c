/* Integration tests for large policy compaction and NFA rendering. */

#include "metadata.h"
#include "shelltype.h"
#include "test_allocator.h"
#include "test_io.h"
#include "test_netargv.h"
#include <ctype.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run;
static int tests_passed;
static int tests_failed;

static int pattern_is_cpl(const char *actual, const char *cpl) {
  if (!actual || !cpl)
    return actual == cpl;
  char *encoded = NULL;
  int equal = st_netpattern_from_cpl(cpl, &encoded) == ST_OK &&
              strcmp(actual, encoded) == 0;
  free(encoded);
  return equal;
}

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    assertion failed: %s at %s:%d\n", #condition, __FILE__,      \
             __LINE__);                                                        \
      return 0;                                                                \
    }                                                                          \
  } while (0)

#define TEST(function)                                                         \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      tests_passed++;                                                          \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      tests_failed++;                                                          \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

static st_policy_t *new_policy(st_policy_ctx_t *context,
                               const char *const *patterns, size_t count) {
  st_policy_t *policy = st_policy_new(context);
  if (!policy)
    return NULL;
  for (size_t i = 0; i < count; i++)
    if (test_st_policy_add(policy, patterns[i]) != ST_OK) {
      st_policy_free(policy);
      return NULL;
    }
  return policy;
}

static int no_atomic_temps(const char *path) {
  char pattern[512];
  glob_t matches = {0};
  if (snprintf(pattern, sizeof(pattern), "%s.*", path) < 0)
    return 0;
  int result = glob(pattern, 0, NULL, &matches);
  globfree(&matches);
  return result == GLOB_NOMATCH;
}

static void remove_atomic_temps(const char *path) {
  char pattern[512];
  glob_t matches = {0};
  if (snprintf(pattern, sizeof(pattern), "%s.*", path) < 0)
    return;
  if (glob(pattern, 0, NULL, &matches) == 0)
    for (size_t i = 0; i < matches.gl_pathc; i++)
      (void)unlink(matches.gl_pathv[i]);
  globfree(&matches);
}

static int eval_matches(st_policy_t *policy, const char *command,
                        const char *expected_pattern) {
  st_eval_result_t result = {0};
  st_error_t error = test_st_policy_eval(policy, command, &result);
  int valid = error == ST_OK && result.matches == (expected_pattern != NULL);
  if (expected_pattern)
    valid = valid && pattern_is_cpl(result.matching_pattern, expected_pattern);
  else
    valid = valid && result.matching_pattern == NULL;
  if (!valid)
    printf("    '%s': matches=%d pattern=%s expected=%s error=%d\n", command,
           result.matches,
           result.matching_pattern ? result.matching_pattern : "-",
           expected_pattern ? expected_pattern : "-", error);
  return valid;
}

static int verify_alternating_policy(st_policy_t *policy, int pattern_count) {
  for (int i = 0; i < pattern_count; i++) {
    char command[128];
    char expected[128];
    snprintf(command, sizeof(command), "cmd%d --option value /path/to/file%d",
             i, i);
    snprintf(expected, sizeof(expected), "cmd%d --option * /path/to/file%d", i,
             i);
    if (!eval_matches(policy, command, i % 2 ? expected : NULL))
      return 0;
  }
  return 1;
}

static int test_large_policy_compaction(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = new_policy(context, NULL, 0);
  ASSERT(policy != NULL);
  ASSERT(st_policy_compact(policy) == ST_OK);
  const int pattern_count = 200;
  for (int i = 0; i < pattern_count; i++) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "cmd%d --option * /path/to/file%d", i,
             i);
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
  }
  ASSERT(st_policy_count(policy) == (size_t)pattern_count);
  size_t populated_states = st_policy_state_count(policy);
  size_t populated_memory = st_policy_memory_usage(policy);
  ASSERT(populated_states > (size_t)pattern_count);
  ASSERT(populated_memory > 0);
  ASSERT(st_policy_working_set(policy) <= populated_memory);
  ASSERT(eval_matches(policy, "cmd42 --option value /path/to/file42",
                      "cmd42 --option * /path/to/file42"));
  ASSERT(eval_matches(policy, "cmd199 --option value /path/to/file199",
                      "cmd199 --option * /path/to/file199"));
  ASSERT(eval_matches(policy, "cmd200 --option value /path/to/file200", NULL));

  for (int i = 0; i < pattern_count; i += 2) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "cmd%d --option * /path/to/file%d", i,
             i);
    ASSERT(test_st_policy_remove(policy, pattern) == ST_OK);
  }
  ASSERT(st_policy_count(policy) == (size_t)pattern_count / 2);
  size_t stale_states = st_policy_state_count(policy);
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_count(policy) == (size_t)pattern_count / 2);
  ASSERT(st_policy_state_count(policy) < stale_states);
  ASSERT(st_policy_memory_usage(policy) < populated_memory);
  ASSERT(verify_alternating_policy(policy, pattern_count));

  size_t compacted_states = st_policy_state_count(policy);
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_state_count(policy) == compacted_states);
  ASSERT(verify_alternating_policy(policy, pattern_count));

  const char *new_pattern = "fresh #n";
  ASSERT(test_st_policy_add(policy, new_pattern) == ST_OK);
  ASSERT(eval_matches(policy, "fresh 17", new_pattern));
  ASSERT(test_st_policy_remove(policy, new_pattern) == ST_OK);
  ASSERT(eval_matches(policy, "fresh 17", NULL));
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(st_policy_state_count(policy) == compacted_states);
  ASSERT(verify_alternating_policy(policy, pattern_count));
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int test_compaction_allocation_failures_are_atomic(void) {
  static const char *patterns[] = {"git status", "copy #path", "probe #n"};
  st_test_alloc_reset();
  st_policy_ctx_t *probe_context = st_policy_ctx_new();
  st_policy_t *probe = new_policy(probe_context, patterns, 3);
  ASSERT(probe_context != NULL && probe != NULL);
  st_test_alloc_reset();
  ASSERT(st_policy_compact(probe) == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_policy_free(probe);
  st_policy_ctx_free(probe_context);
  ASSERT(allocations > 0);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = new_policy(context, patterns, 3);
    ASSERT(context != NULL && policy != NULL);
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_policy_compact(policy);
    st_test_alloc_reset();
    ASSERT(error == ST_OK || error == ST_ERR_MEMORY);
    ASSERT(st_policy_count(policy) == 3);
    ASSERT(eval_matches(policy, "git status", "git status"));
    ASSERT(eval_matches(policy, "copy /tmp/value", "copy #path"));
    ASSERT(eval_matches(policy, "probe 17", "probe #n"));
    ASSERT(test_st_policy_add(policy, "after failure") == ST_OK);
    ASSERT(eval_matches(policy, "after failure", "after failure"));
    st_policy_free(policy);
    st_policy_ctx_free(context);
  }
  return 1;
}

static char *read_file(const char *path) {
  FILE *file = fopen(path, "rb");
  if (!file)
    return NULL;
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return NULL;
  }
  long length = ftell(file);
  if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return NULL;
  }
  char *contents = malloc((size_t)length + 1);
  if (!contents) {
    fclose(file);
    return NULL;
  }
  size_t bytes = fread(contents, 1, (size_t)length, file);
  fclose(file);
  if (bytes != (size_t)length) {
    free(contents);
    return NULL;
  }
  contents[bytes] = '\0';
  return contents;
}

static size_t occurrence_count(const char *text, const char *needle) {
  size_t count = 0;
  size_t length = strlen(needle);
  for (const char *found = strstr(text, needle); found;
       found = strstr(found + length, needle))
    count++;
  return count;
}

typedef struct {
  int symbol;
  size_t target;
} parsed_transition_t;

typedef struct {
  bool accepting;
  char tag[ST_MAX_NETPATTERN_LEN];
  parsed_transition_t *transitions;
  size_t count;
} parsed_nfa_state_t;

typedef struct {
  parsed_nfa_state_t *states;
  size_t count;
  size_t initial;
} parsed_nfa_t;

static void parsed_nfa_free(parsed_nfa_t *nfa) {
  for (size_t i = 0; i < nfa->count; i++)
    free(nfa->states[i].transitions);
  free(nfa->states);
  memset(nfa, 0, sizeof(*nfa));
}

static int parsed_nfa_load(const char *path, parsed_nfa_t *nfa) {
  FILE *file = fopen(path, "r");
  if (!file)
    return 0;
  char line[2048];
  size_t current = SIZE_MAX;
  while (fgets(line, sizeof(line), file)) {
    size_t value;
    if (sscanf(line, "States: %zu", &value) == 1) {
      nfa->states = calloc(value, sizeof(*nfa->states));
      nfa->count = value;
    } else if (sscanf(line, "Initial: %zu", &value) == 1) {
      nfa->initial = value;
    } else if (sscanf(line, "State %zu:", &value) == 1) {
      current = value;
    } else if (current < nfa->count && strstr(line, "EosTarget: yes")) {
      nfa->states[current].accepting = true;
    } else if (current < nfa->count && strstr(line, "  Tags: ") == line) {
      char *tag = line + strlen("  Tags: ");
      tag[strcspn(tag, "\r\n")] = '\0';
      snprintf(nfa->states[current].tag, sizeof(nfa->states[current].tag), "%s",
               tag);
    } else if (current < nfa->count) {
      int symbol;
      size_t target;
      if (sscanf(line, "    Symbol %d -> %zu", &symbol, &target) == 2) {
        parsed_nfa_state_t *state = &nfa->states[current];
        parsed_transition_t *grown =
            realloc(state->transitions,
                    (state->count + 1) * sizeof(*state->transitions));
        if (!grown) {
          fclose(file);
          parsed_nfa_free(nfa);
          return 0;
        }
        state->transitions = grown;
        state->transitions[state->count++] =
            (parsed_transition_t){symbol, target};
      }
    }
  }
  int valid = fclose(file) == 0 && nfa->states && nfa->initial < nfa->count;
  if (!valid)
    parsed_nfa_free(nfa);
  return valid;
}

static void epsilon_closure(const parsed_nfa_t *nfa, bool *active) {
  bool changed;
  do {
    changed = false;
    for (size_t i = 0; i < nfa->count; i++) {
      if (!active[i])
        continue;
      for (size_t j = 0; j < nfa->states[i].count; j++) {
        parsed_transition_t transition = nfa->states[i].transitions[j];
        if (transition.symbol == 257 && !active[transition.target]) {
          active[transition.target] = true;
          changed = true;
        }
      }
    }
  } while (changed);
}

static size_t parsed_nfa_matches(const parsed_nfa_t *nfa, const char *input,
                                 const char **matches, size_t capacity) {
  bool *active = calloc(nfa->count, sizeof(bool));
  bool *next = calloc(nfa->count, sizeof(bool));
  if (!active || !next) {
    free(active);
    free(next);
    return SIZE_MAX;
  }
  active[nfa->initial] = true;
  epsilon_closure(nfa, active);
  for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
    memset(next, 0, nfa->count * sizeof(bool));
    for (size_t i = 0; i < nfa->count; i++) {
      if (!active[i])
        continue;
      for (size_t j = 0; j < nfa->states[i].count; j++) {
        parsed_transition_t transition = nfa->states[i].transitions[j];
        bool accepts = transition.symbol == *p || (transition.symbol == 256) ||
                       (transition.symbol == 259 && *p == ' ') ||
                       (transition.symbol == 260 && *p == '\t');
        if (accepts)
          next[transition.target] = true;
      }
    }
    bool *swap = active;
    active = next;
    next = swap;
    epsilon_closure(nfa, active);
  }
  size_t count = 0;
  for (size_t i = 0; i < nfa->count; i++)
    if (active[i] && nfa->states[i].accepting) {
      if (count < capacity)
        matches[count] = nfa->states[i].tag;
      count++;
    }
  free(active);
  free(next);
  return count;
}

typedef struct {
  const parsed_nfa_t *nfa;
  const st_token_array_t *tokens;
  const char **matches;
  size_t match_count;
  size_t match_capacity;
  char buffer[ST_MAX_NETPATTERN_LEN];
} typed_nfa_ctx_t;

static bool typed_metadata_matches(const st_token_t *token,
                                   const st_metadata_entry_t *metadata) {
  const char *text = token->text;
  if (metadata->type == ST_TYPE_SIZE) {
    const st_metadata_entry_t *observed =
        token->type == ST_TYPE_SIZE
            ? st_metadata_lookup(ST_TYPE_SIZE, st_size_suffix(text))
            : NULL;
    return observed && observed->id == metadata->id;
  }
  if (metadata->type == ST_TYPE_UUID)
    return token->type == ST_TYPE_UUID && strlen(text) == 36 &&
           ((metadata->id == ST_META_UUID_V4 && text[14] == '4') ||
            (metadata->id == ST_META_UUID_V5 && text[14] == '5'));
  if (metadata->type == ST_TYPE_SEMVER)
    return token->type == ST_TYPE_SEMVER;
  if (metadata->type == ST_TYPE_TIMESTAMP) {
    if (token->type != ST_TYPE_TIMESTAMP)
      return false;
    size_t length = strlen(text);
    return (metadata->id == ST_META_TIMESTAMP_DATE && length == 10 &&
            text[4] == '-' && text[7] == '-') ||
           (metadata->id == ST_META_TIMESTAMP_TIME && length == 8 &&
            text[2] == ':' && text[5] == ':') ||
           (metadata->id == ST_META_TIMESTAMP_DATETIME && length >= 19 &&
            (text[10] == 'T' || text[10] == ' '));
  }
  if (metadata->type == ST_TYPE_SHA) {
    if (token->type != ST_TYPE_SHA && token->type != ST_TYPE_HEXHASH)
      return false;
    size_t length = strlen(text);
    for (size_t i = 0; i < length; i++)
      if (!isxdigit((unsigned char)text[i]))
        return false;
    return (metadata->id == ST_META_SHA_SHORT && length == 7) ||
           (metadata->id == ST_META_SHA_40 && length == 40) ||
           (metadata->id == ST_META_SHA_64 && length == 64);
  }
  if (metadata->type == ST_TYPE_FINGERPRINT)
    return token->type == ST_TYPE_FINGERPRINT &&
           ((metadata->id == ST_META_FINGERPRINT_SHA256 &&
             strncmp(text, "SHA256:", 7) == 0) ||
            (metadata->id == ST_META_FINGERPRINT_MD5 && strlen(text) == 47 &&
             text[2] == ':' && text[5] == ':'));
  if (metadata->type == ST_TYPE_DURATION) {
    if (token->type != ST_TYPE_DURATION)
      return false;
    const char *suffix = text;
    if (*suffix == '-')
      suffix++;
    while (*suffix && (isdigit((unsigned char)*suffix) || *suffix == '.'))
      suffix++;
    const st_metadata_entry_t *observed =
        st_metadata_lookup(ST_TYPE_DURATION, suffix);
    return observed && observed->id == metadata->id;
  }
  if (metadata->type == ST_TYPE_RANGE)
    return token->type == ST_TYPE_RANGE;
  if (metadata->type == ST_TYPE_PERM_OCTAL)
    return token->type == ST_TYPE_PERM_OCTAL;
  return false;
}

static void typed_nfa_walk(typed_nfa_ctx_t *ctx, size_t token_index,
                           size_t used) {
  if (token_index == ctx->tokens->count) {
    const char *found[32] = {0};
    size_t count = parsed_nfa_matches(ctx->nfa, ctx->buffer, found, 32);
    for (size_t i = 0; i < count; i++) {
      bool duplicate = false;
      for (size_t j = 0; j < ctx->match_count; j++)
        duplicate = duplicate || strcmp(ctx->matches[j], found[i]) == 0;
      if (!duplicate && ctx->match_count < ctx->match_capacity)
        ctx->matches[ctx->match_count++] = found[i];
    }
    return;
  }
  const st_token_t *token = &ctx->tokens->tokens[token_index];
  const char *forms[8] = {token->text};
  char metadata_forms[6][32];
  size_t form_count = 1;
  if (token->type != ST_TYPE_LITERAL &&
      strcmp(token->text, st_type_symbol[token->type]) != 0)
    forms[form_count++] = st_type_symbol[token->type];
  size_t metadata_form_count = 0;
  for (size_t i = 0;
       i < sizeof(st_metadata_entries) / sizeof(st_metadata_entries[0]); i++) {
    const st_metadata_entry_t *metadata = &st_metadata_entries[i];
    if (!typed_metadata_matches(token, metadata))
      continue;
    if (metadata_form_count >=
        sizeof(metadata_forms) / sizeof(metadata_forms[0]))
      return;
    snprintf(metadata_forms[metadata_form_count],
             sizeof(metadata_forms[metadata_form_count]), "%s.%s",
             st_type_symbol[metadata->type], metadata->name);
    forms[form_count++] = metadata_forms[metadata_form_count++];
  }
  for (size_t form = 0; form < form_count; form++) {
    size_t length = strlen(forms[form]);
    size_t next = used + (token_index != 0) + length;
    if (next >= sizeof(ctx->buffer))
      continue;
    if (token_index != 0)
      ctx->buffer[used++] = ' ';
    memcpy(ctx->buffer + used, forms[form], length + 1);
    typed_nfa_walk(ctx, token_index + 1, next);
    used -= token_index != 0;
  }
}

static size_t parsed_nfa_matches_typed(const parsed_nfa_t *nfa,
                                       const char *command,
                                       const char **matches,
                                       size_t match_capacity) {
  st_token_array_t tokens = {0};
  if (test_st_classify(command, &tokens) != ST_OK)
    return 0;
  typed_nfa_ctx_t ctx = {.nfa = nfa,
                         .tokens = &tokens,
                         .matches = matches,
                         .match_capacity = match_capacity};
  typed_nfa_walk(&ctx, 0, 0);
  st_free_token_array(&tokens);
  return ctx.match_count;
}

static int rendered_nfa_matches(const char *rendered, const char *identifier,
                                unsigned category_mask,
                                unsigned pattern_id_base, bool include_tags) {
  char expected[96];
  snprintf(expected, sizeof(expected), "Identifier: %s\n", identifier);
  if (!strstr(rendered, "NFA_ALPHABET\n") || !strstr(rendered, expected) ||
      !strstr(rendered, "AlphabetSize: 261\n") ||
      !strstr(rendered, "Initial: 0\n") ||
      !strstr(rendered, "Symbol 256: 0-255 (special)") ||
      !strstr(rendered, "Symbol 259 ->") ||
      occurrence_count(rendered, "EosTarget: yes") != 3)
    return 0;

  snprintf(expected, sizeof(expected), "CategoryMask: 0x%02x", category_mask);
  if (occurrence_count(rendered, expected) != 3)
    return 0;
  for (unsigned i = 0; i < 3; i++) {
    snprintf(expected, sizeof(expected), "PatternId: %u\n",
             pattern_id_base + i);
    if (!strstr(rendered, expected))
      return 0;
  }

  static const char *tags[] = {"git commit", "git status", "cat *"};
  if (occurrence_count(rendered, "Tags: ") != (include_tags ? 3u : 0u))
    return 0;
  for (size_t i = 0; include_tags && i < sizeof(tags) / sizeof(tags[0]); i++) {
    snprintf(expected, sizeof(expected), "Tags: %s\n", tags[i]);
    if (!strstr(rendered, expected))
      return 0;
  }
  return 1;
}

static int test_nfa_rendering_contract(void) {
  static const char *patterns[] = {"git commit", "git status", "cat *"};
  const char *path = "test_compact_policy.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *empty = context ? st_policy_new(context) : NULL;
  ASSERT(context != NULL && empty != NULL);
  ASSERT(st_policy_render_nfa(empty, path, NULL) == ST_OK);
  char *empty_rendered = read_file(path);
  ASSERT(empty_rendered != NULL);
  ASSERT(strstr(empty_rendered, "NFA_ALPHABET") != NULL);
  ASSERT(strstr(empty_rendered, "States: 1") != NULL);
  free(empty_rendered);
  st_policy_free(empty);
  st_policy_t *policy = new_policy(context, patterns, 3);
  ASSERT(policy != NULL);
  st_nfa_render_opts_t options = {.category_mask = 0x05,
                                  .pattern_id_base = 7,
                                  .include_tags = true,
                                  .identifier = "compact-policy-test"};
  const struct {
    const st_nfa_render_opts_t *options;
    const char *identifier;
    unsigned category_mask;
    unsigned pattern_id_base;
    bool include_tags;
  } cases[] = {{&options, "compact-policy-test", 0x05, 7, true},
               {NULL, "rbox policy", 0x01, 1, false}};
  ASSERT(st_policy_render_nfa(NULL, path, &options) == ST_ERR_INVALID);
  ASSERT(st_policy_render_nfa(policy, NULL, &options) == ST_ERR_INVALID);
  st_nfa_render_opts_t hostile = options;
  hostile.identifier = "injected\nStates: 0";
  ASSERT(st_policy_render_nfa(policy, path, &hostile) == ST_ERR_INVALID);
  ASSERT(st_policy_render_nfa(policy, ".", &options) == ST_ERR_IO);
  st_nfa_render_opts_t overflowing = options;
  overflowing.pattern_id_base = UINT32_MAX - 1;
  ASSERT(st_policy_render_nfa(policy, path, &overflowing) == ST_ERR_LIMIT);
  if (access("/dev/full", W_OK) == 0)
    ASSERT(st_policy_render_nfa(policy, "/dev/full", &options) == ST_ERR_IO);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(st_policy_render_nfa(policy, path, cases[i].options) == ST_OK);
    char *rendered = read_file(path);
    ASSERT(rendered != NULL);
    ASSERT(rendered_nfa_matches(
        rendered, cases[i].identifier, cases[i].category_mask,
        cases[i].pattern_id_base, cases[i].include_tags));
    free(rendered);
  }
  ASSERT(remove(path) == 0);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int test_nfa_policy_equivalence(void) {
  static const char *patterns[] = {
      "number #n",     "path #path",    "option #opt",  "anything *",
      "literal exact", "cross #n #val", "cross #val #n"};
  static const char *commands[] = {
      "number 42",      "number word",        "path /tmp/file",
      "path word",      "option --verbose",   "option value",
      "anything value", "anything two words", "literal exact",
      "literal other",  "cross 1 2",          "cross one 2",
  };
  const char *path = "test_policy_equivalence.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy =
      new_policy(context, patterns, sizeof(patterns) / sizeof(patterns[0]));
  ASSERT(context != NULL && policy != NULL);
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "equivalence"};
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  parsed_nfa_t nfa = {0};
  ASSERT(parsed_nfa_load(path, &nfa));

  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    const char **policy_matches = NULL;
    size_t policy_count = 0;
    ASSERT(test_st_policy_verify_all(policy, commands[i], &policy_matches,
                                     &policy_count) == ST_OK);
    const char *nfa_matches[16] = {0};
    size_t nfa_count =
        parsed_nfa_matches_typed(&nfa, commands[i], nfa_matches, 16);
    ASSERT(nfa_count == policy_count);
    for (size_t p = 0; p < policy_count; p++) {
      bool found = false;
      for (size_t n = 0; n < nfa_count; n++)
        found = found || pattern_is_cpl(policy_matches[p], nfa_matches[n]);
      ASSERT(found);
    }
    st_policy_free_matches(policy_matches, policy_count);
  }

  parsed_nfa_free(&nfa);
  ASSERT(remove(path) == 0);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int test_nfa_lattice_transition_matrix(void) {
  const char *path = "/tmp/shelltype-nfa-lattice.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  ASSERT(context != NULL && policy != NULL);

  char patterns[ST_TYPE_COUNT][64];
  for (int policy_type = ST_TYPE_LITERAL + 1; policy_type < ST_TYPE_COUNT;
       policy_type++) {
    ASSERT(snprintf(patterns[policy_type], sizeof(patterns[policy_type]),
                    "type%02d %s", policy_type,
                    st_type_symbol[policy_type]) > 0);
    ASSERT(test_st_policy_add(policy, patterns[policy_type]) == ST_OK);
  }

  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "lattice-matrix"};
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  parsed_nfa_t nfa = {0};
  ASSERT(parsed_nfa_load(path, &nfa));

  for (int policy_type = ST_TYPE_LITERAL + 1; policy_type < ST_TYPE_COUNT;
       policy_type++) {
    for (int command_type = ST_TYPE_LITERAL + 1; command_type < ST_TYPE_ANY;
         command_type++) {
      char input[64];
      ASSERT(snprintf(input, sizeof(input), "type%02d %s", policy_type,
                      st_type_symbol[command_type]) > 0);
      const char *matches[2] = {0};
      size_t count = parsed_nfa_matches(&nfa, input, matches, 2);
      bool expected = st_is_compatible((st_token_type_t)command_type,
                                       (st_token_type_t)policy_type);
      ASSERT(count == (expected ? 1u : 0u));
      if (expected)
        ASSERT(strcmp(matches[0], patterns[policy_type]) == 0);
    }

    char literal_input[64];
    ASSERT(snprintf(literal_input, sizeof(literal_input),
                    "type%02d literal-value", policy_type) > 0);
    const char *matches[2] = {0};
    size_t count = parsed_nfa_matches(&nfa, literal_input, matches, 2);
    ASSERT(count == (policy_type == ST_TYPE_ANY ? 1u : 0u));
  }

  parsed_nfa_free(&nfa);
  ASSERT(remove(path) == 0);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int nfa_equivalent_for_commands(st_policy_t *policy, const char *path,
                                       const char *const *commands,
                                       size_t command_count) {
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "lifecycle-equivalence"};
  if (st_policy_render_nfa(policy, path, &options) != ST_OK)
    return 0;
  parsed_nfa_t nfa = {0};
  if (!parsed_nfa_load(path, &nfa))
    return 0;
  int equivalent = 1;
  for (size_t i = 0; i < command_count && equivalent; i++) {
    const char **policy_matches = NULL;
    size_t policy_count = 0;
    if (test_st_policy_verify_all(policy, commands[i], &policy_matches,
                                  &policy_count) != ST_OK) {
      equivalent = 0;
      continue;
    }
    const char *nfa_matches[32] = {0};
    size_t nfa_count =
        parsed_nfa_matches_typed(&nfa, commands[i], nfa_matches, 32);
    if (nfa_count != policy_count)
      equivalent = 0;
    for (size_t p = 0; p < policy_count && equivalent; p++) {
      bool found = false;
      for (size_t n = 0; n < nfa_count; n++)
        found = found || pattern_is_cpl(policy_matches[p], nfa_matches[n]);
      equivalent = found;
    }
    st_policy_free_matches(policy_matches, policy_count);
  }
  parsed_nfa_free(&nfa);
  return equivalent;
}

static int test_nfa_lifecycle_equivalence(void) {
  static const char *commands[] = {
      "cross 1 2",
      "cross word 2",
      "cross 1 word",
      "container 550e8400-e29b-41d4-a716-446655440000",
      "container 550e8400-e29b-51d4-a716-446655440000",
      "allocate 8MiB",
      "allocate 8GiB",
      "copy literal",
      "copy other",
  };
  const char *nfa_path = "/tmp/shelltype-nfa-lifecycle.nfa";
  const char *policy_path = "/tmp/shelltype-nfa-lifecycle.policy";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  ASSERT(context && policy);
  ASSERT(test_st_policy_add(policy, "cross #n #val") == ST_OK);
  ASSERT(test_st_policy_add(policy, "cross #val #n") == ST_OK);
  ASSERT(test_st_policy_add(policy, "container #uuid.v4") == ST_OK);
  ASSERT(test_st_policy_add(policy, "container #uuid.v5") == ST_OK);
  ASSERT(test_st_policy_add(policy, "copy literal") == ST_OK);
  ASSERT(nfa_equivalent_for_commands(policy, nfa_path, commands,
                                     sizeof(commands) / sizeof(commands[0])));

  ASSERT(test_st_policy_remove(policy, "cross #n #val") == ST_OK);
  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(nfa_equivalent_for_commands(policy, nfa_path, commands,
                                     sizeof(commands) / sizeof(commands[0])));

  st_policy_ctx_t *source_context = st_policy_ctx_new();
  st_policy_t *source = source_context ? st_policy_new(source_context) : NULL;
  ASSERT(source && test_st_policy_add(source, "allocate #size.MiB") == ST_OK);
  ASSERT(st_policy_merge(policy, source) == ST_OK);
  st_policy_free(source);
  st_policy_ctx_free(source_context);
  ASSERT(nfa_equivalent_for_commands(policy, nfa_path, commands,
                                     sizeof(commands) / sizeof(commands[0])));

  ASSERT(st_policy_save(policy, policy_path) == ST_OK);
  ASSERT(st_policy_clear(policy) == ST_OK);
  ASSERT(st_policy_load(policy, policy_path, true) == ST_OK);
  ASSERT(nfa_equivalent_for_commands(policy, nfa_path, commands,
                                     sizeof(commands) / sizeof(commands[0])));

  ASSERT(remove(nfa_path) == 0 && remove(policy_path) == 0);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

/* Closed metadata annotations remain distinct on exported base-type
 * transitions even though the final c-dfa interchange format is not frozen. */
static int test_nfa_preserves_parameter_branches(void) {
  static const char *patterns[] = {
      "container #uuid.v4",    "container #uuid.v5", "allocate #size.MiB",
      "install #semver.major", "log #ts.date",       "echo #sha.40",
      "key #fp.sha256",        "sleep #duration.ms", "seq #range.step",
      "chmod #perm.bits",
  };
  const char *path = "test_policy_parameters.nfa";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy =
      new_policy(context, patterns, sizeof(patterns) / sizeof(patterns[0]));
  ASSERT(context != NULL && policy != NULL);
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "parameter-branches"};
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  parsed_nfa_t nfa = {0};
  ASSERT(parsed_nfa_load(path, &nfa));

  const char *matches[2] = {0};
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    ASSERT(parsed_nfa_matches(&nfa, patterns[i], matches, 2) == 1);
    ASSERT(strcmp(matches[0], patterns[i]) == 0);
    memset(matches, 0, sizeof(matches));
  }
  ASSERT(parsed_nfa_matches(&nfa, "container #uuid", matches, 2) == 0);

  static const char *commands[] = {
      "container 550e8400-e29b-41d4-a716-446655440000",
      "container 550e8400-e29b-51d4-a716-446655440000",
      "allocate 8MiB",
      "install 1.2.3",
      "log 2025-01-01",
      "echo 0123456789abcdef0123456789abcdef01234567",
      "key SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE",
      "sleep 10ms",
      "seq 1-5",
      "chmod 0755",
  };
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    const char **policy_matches = NULL;
    size_t policy_count = 0;
    ASSERT(test_st_policy_verify_all(policy, commands[i], &policy_matches,
                                     &policy_count) == ST_OK);
    memset(matches, 0, sizeof(matches));
    size_t nfa_count = parsed_nfa_matches_typed(&nfa, commands[i], matches, 2);
    if (nfa_count != policy_count) {
      printf("    parameter command '%s': NFA=%zu policy=%zu\n", commands[i],
             nfa_count, policy_count);
      return 0;
    }
    for (size_t p = 0; p < policy_count; p++) {
      bool found = false;
      for (size_t n = 0; n < nfa_count; n++)
        found = found || pattern_is_cpl(policy_matches[p], matches[n]);
      ASSERT(found);
    }
    st_policy_free_matches(policy_matches, policy_count);
  }

  parsed_nfa_free(&nfa);
  ASSERT(remove(path) == 0);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

typedef struct {
  const char *command;
  const char *expected[5];
} metadata_match_case_t;

static int metadata_matches_expected(st_policy_t *policy, const char *path,
                                     const metadata_match_case_t *cases,
                                     size_t case_count) {
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = 1,
                                  .include_tags = true,
                                  .identifier = "metadata-cross-product"};
  ASSERT(st_policy_render_nfa(policy, path, &options) == ST_OK);
  parsed_nfa_t nfa = {0};
  ASSERT(parsed_nfa_load(path, &nfa));
  for (size_t i = 0; i < case_count; i++) {
    size_t expected_count = 0;
    while (expected_count < 5 && cases[i].expected[expected_count])
      expected_count++;
    const char **policy_matches = NULL;
    size_t policy_count = 0;
    ASSERT(test_st_policy_verify_all(policy, cases[i].command, &policy_matches,
                                     &policy_count) == ST_OK);
    const char *nfa_matches[8] = {0};
    size_t nfa_count =
        parsed_nfa_matches_typed(&nfa, cases[i].command, nfa_matches, 8);
    ASSERT(policy_count == expected_count);
    ASSERT(nfa_count == expected_count);
    for (size_t expected = 0; expected < expected_count; expected++) {
      bool policy_found = false;
      bool nfa_found = false;
      for (size_t actual = 0; actual < policy_count; actual++)
        policy_found =
            policy_found ||
            pattern_is_cpl(policy_matches[actual], cases[i].expected[expected]);
      for (size_t actual = 0; actual < nfa_count; actual++)
        nfa_found = nfa_found || strcmp(nfa_matches[actual],
                                        cases[i].expected[expected]) == 0;
      if (!policy_found || !nfa_found) {
        printf("    metadata case '%s' missing '%s' (policy=%d nfa=%d, "
               "counts=%zu/%zu)\n",
               cases[i].command, cases[i].expected[expected], policy_found,
               nfa_found, policy_count, nfa_count);
        st_policy_free_matches(policy_matches, policy_count);
        parsed_nfa_free(&nfa);
        return 0;
      }
    }
    st_policy_free_matches(policy_matches, policy_count);
  }
  parsed_nfa_free(&nfa);
  return 1;
}

/* Every closed metadata sibling occupies the same trie position.  Expected
 * match sets are hand-authored so neither the policy matcher nor the typed NFA
 * adapter acts as the oracle for the other. */
static int test_nfa_same_prefix_metadata_cross_product(void) {
  static const char *patterns[] = {
      "size #size.K",          "size #size.M",          "size #size.G",
      "size #size.T",          "size #size.Ki",         "size #size.Mi",
      "size #size.Gi",         "size #size.Ti",         "size #size.KB",
      "size #size.MB",         "size #size.GB",         "size #size.TB",
      "size #size.B",          "size #size.bytes",      "size #size.KiB",
      "size #size.MiB",        "size #size.GiB",        "size #size.TiB",
      "uuid #uuid.v4",         "uuid #uuid.v5",         "semver #semver.major",
      "semver #semver.minor",  "semver #semver.patch",  "semver #semver.*",
      "time #ts.date",         "time #ts.time",         "time #ts.datetime",
      "sha #sha.short",        "sha #sha.40",           "sha #sha.64",
      "finger #fp.sha256",     "finger #fp.md5",        "duration #duration.ns",
      "duration #duration.us", "duration #duration.ms", "duration #duration.s",
      "duration #duration.m",  "duration #duration.h",  "duration #duration.d",
      "duration #duration.w",  "range #range.step",     "perm #perm.bits",
      "uuid-alias #uuid.4",    "size-alias #size.b",
  };
  static const metadata_match_case_t cases[] = {
      {"size 2K", {"size #size.K", NULL}},
      {"size 2M", {"size #size.M", NULL}},
      {"size 2G", {"size #size.G", NULL}},
      {"size 2T", {"size #size.T", NULL}},
      {"size 2Ki", {"size #size.Ki", NULL}},
      {"size 2Mi", {"size #size.Mi", NULL}},
      {"size 2Gi", {"size #size.Gi", NULL}},
      {"size 2Ti", {"size #size.Ti", NULL}},
      {"size 2KB", {"size #size.KB", NULL}},
      {"size 2MB", {"size #size.MB", NULL}},
      {"size 2GB", {"size #size.GB", NULL}},
      {"size 2TB", {"size #size.TB", NULL}},
      {"size 2B", {"size #size.B", NULL}},
      {"size 2bytes", {"size #size.bytes", NULL}},
      {"size 2KiB", {"size #size.KiB", NULL}},
      {"size 2MiB", {"size #size.MiB", NULL}},
      {"size 2GiB", {"size #size.GiB", NULL}},
      {"size 2TiB", {"size #size.TiB", NULL}},
      {"size 2XB", {NULL}},
      {"uuid 550e8400-e29b-41d4-a716-446655440000", {"uuid #uuid.v4", NULL}},
      {"uuid 550e8400-e29b-51d4-a716-446655440000", {"uuid #uuid.v5", NULL}},
      {"uuid 550e8400-e29b-31d4-a716-446655440000", {NULL}},
      {"semver 1.2.3",
       {"semver #semver.major", "semver #semver.minor", "semver #semver.patch",
        "semver #semver.*", NULL}},
      {"time 2025-04-24", {"time #ts.date", NULL}},
      {"time 15:30:00", {"time #ts.time", NULL}},
      {"time 2025-04-24T15:30:00Z", {"time #ts.datetime", NULL}},
      {"sha deadbee", {"sha #sha.short", NULL}},
      {"sha deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", {"sha #sha.40", NULL}},
      {"sha 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
       {"sha #sha.64", NULL}},
      {"finger SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE",
       {"finger #fp.sha256", NULL}},
      {"finger 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d",
       {"finger #fp.md5", NULL}},
      {"duration 10ns", {"duration #duration.ns", NULL}},
      {"duration 10us", {"duration #duration.us", NULL}},
      {"duration 10ms", {"duration #duration.ms", NULL}},
      {"duration 10s", {"duration #duration.s", NULL}},
      {"duration 10m", {"duration #duration.m", NULL}},
      {"duration 10h", {"duration #duration.h", NULL}},
      {"duration 10d", {"duration #duration.d", NULL}},
      {"duration 10w", {"duration #duration.w", NULL}},
      {"duration 10y", {NULL}},
      {"range 1-5", {"range #range.step", NULL}},
      {"perm 0755", {"perm #perm.bits", NULL}},
      {"uuid-alias 550e8400-e29b-41d4-a716-446655440000",
       {"uuid-alias #uuid.v4", NULL}},
      {"size-alias 2B", {"size-alias #size.B", NULL}},
  };
  const char *nfa_path = "/tmp/shelltype-nfa-metadata-matrix.nfa";
  const char *policy_path = "/tmp/shelltype-nfa-metadata-matrix.policy";
  st_policy_ctx_t *source_context = st_policy_ctx_new();
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *source = source_context ? st_policy_new(source_context) : NULL;
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  ASSERT(source && policy);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    ASSERT(test_st_policy_add(source, patterns[i]) == ST_OK);
  ASSERT(st_policy_merge(policy, source) == ST_OK);
  ASSERT(metadata_matches_expected(policy, nfa_path, cases,
                                   sizeof(cases) / sizeof(cases[0])));

  char *rendered = read_file(nfa_path);
  ASSERT(rendered != NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]) - 2; i++)
    ASSERT(strstr(rendered, patterns[i]) != NULL);
  ASSERT(strstr(rendered, "uuid-alias #uuid.v4") != NULL);
  ASSERT(strstr(rendered, "size-alias #size.B") != NULL);
  ASSERT(strstr(rendered, "uuid-alias #uuid.4") == NULL);
  ASSERT(strstr(rendered, "size-alias #size.b") == NULL);
  ASSERT(strstr(rendered, "550e8400-e29b") == NULL);
  ASSERT(strstr(rendered, "uNiVztks") == NULL);
  free(rendered);

  ASSERT(st_policy_compact(policy) == ST_OK);
  ASSERT(metadata_matches_expected(policy, nfa_path, cases,
                                   sizeof(cases) / sizeof(cases[0])));
  ASSERT(st_policy_save(policy, policy_path) == ST_OK);
  ASSERT(st_policy_clear(policy) == ST_OK);
  ASSERT(st_policy_load(policy, policy_path, true) == ST_OK);
  ASSERT(metadata_matches_expected(policy, nfa_path, cases,
                                   sizeof(cases) / sizeof(cases[0])));

  ASSERT(remove(nfa_path) == 0 && remove(policy_path) == 0);
  st_policy_free(policy);
  st_policy_free(source);
  st_policy_ctx_free(context);
  st_policy_ctx_free(source_context);
  return 1;
}

static int test_nfa_allocation_failures(void) {
  static const char *patterns[] = {"git commit", "git status", "cat *"};
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = new_policy(context, patterns, 3);
  ASSERT(context != NULL && policy != NULL);
  char large_pattern[512] = "large ";
  memset(large_pattern + strlen(large_pattern), 'a', 200);
  large_pattern[206] = ' ';
  memset(large_pattern + 207, 'b', 200);
  large_pattern[407] = '\0';
  ASSERT(test_st_policy_add(policy, large_pattern) == ST_OK);
  st_test_alloc_reset();
  ASSERT(st_policy_render_nfa(policy, "/tmp/shelltype-nfa-fail", NULL) ==
         ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  (void)remove("/tmp/shelltype-nfa-fail");
  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    st_error_t err =
        st_policy_render_nfa(policy, "/tmp/shelltype-nfa-fail", NULL);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY)
      observed = true;
    else
      ASSERT(err == ST_OK || err == ST_ERR_IO);
    (void)remove("/tmp/shelltype-nfa-fail");
  }
  ASSERT(observed);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int rendered_identifier_is(const char *path, const char *identifier) {
  char *rendered = read_file(path);
  if (!rendered)
    return 0;
  char expected[128];
  snprintf(expected, sizeof(expected), "Identifier: %s\n", identifier);
  int valid = strstr(rendered, "NFA_ALPHABET\n") &&
              strstr(rendered, expected) && strstr(rendered, "States: ");
  free(rendered);
  return valid;
}

static int test_nfa_atomic_io_and_crash_boundaries(void) {
  char path[] = "/tmp/shelltype-nfa-atomic-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(context);
  ASSERT(context && policy &&
         test_st_policy_add(policy, "git status") == ST_OK);
  st_nfa_render_opts_t old_options = {
      .category_mask = 1, .pattern_id_base = 1, .identifier = "old-nfa"};
  st_nfa_render_opts_t new_options = {
      .category_mask = 1, .pattern_id_base = 1, .identifier = "new-nfa"};

  st_test_io_reset();
  ASSERT(st_policy_render_nfa(policy, path, &new_options) == ST_OK);
  size_t operation_count = st_test_io_count();
  ASSERT(operation_count > 0 && rendered_identifier_is(path, "new-nfa"));
  st_test_io_reset();

  for (size_t fail_at = 1; fail_at <= operation_count; fail_at++) {
    ASSERT(st_policy_render_nfa(policy, path, &old_options) == ST_OK);
    st_test_io_fail_at(fail_at);
    ASSERT(st_policy_render_nfa(policy, path, &new_options) == ST_ERR_IO);
    st_test_io_reset();
    ASSERT(rendered_identifier_is(path, "old-nfa") ||
           rendered_identifier_is(path, "new-nfa"));
    ASSERT(no_atomic_temps(path));
  }

  for (size_t crash_after = 1; crash_after <= operation_count; crash_after++) {
    ASSERT(st_policy_render_nfa(policy, path, &old_options) == ST_OK);
    pid_t child = fork();
    ASSERT(child >= 0);
    if (child == 0) {
      st_test_io_crash_after(crash_after);
      (void)st_policy_render_nfa(policy, path, &new_options);
      _exit(92);
    }
    int status = 0;
    ASSERT(waitpid(child, &status, 0) == child);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 91);
    st_test_io_reset();
    ASSERT(rendered_identifier_is(path, "old-nfa") ||
           rendered_identifier_is(path, "new-nfa"));
    remove_atomic_temps(path);
  }

  st_policy_free(policy);
  st_policy_ctx_free(context);
  ASSERT(unlink(path) == 0);
  return 1;
}

static int test_dot_queue_growth(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(context);
  ASSERT(context != NULL && policy != NULL);
  const size_t pattern_count = 5000;
  for (size_t i = 0; i < pattern_count; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "queue-%zu", i);
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
  }
  ASSERT(st_policy_count(policy) == pattern_count);
  ASSERT(eval_matches(policy, "queue-0", "queue-0"));
  ASSERT(eval_matches(policy, "queue-2500", "queue-2500"));
  ASSERT(eval_matches(policy, "queue-4999", "queue-4999"));
  ASSERT(st_policy_dump_dot(policy, "/tmp/shelltype-large.dot") == ST_OK);
  char *dot = read_file("/tmp/shelltype-large.dot");
  ASSERT(dot != NULL);
  ASSERT(occurrence_count(dot, " [label=") == pattern_count + 1);
  ASSERT(occurrence_count(dot, " -> ") == pattern_count);
  ASSERT(strstr(dot, "\"queue-0\"") != NULL);
  ASSERT(strstr(dot, "\"queue-2500\"") != NULL);
  ASSERT(strstr(dot, "\"queue-4999\"") != NULL);
  free(dot);
  ASSERT(remove("/tmp/shelltype-large.dot") == 0);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

static int test_dot_allocation_failures_are_clean(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  ASSERT(context != NULL && policy != NULL);
  for (size_t i = 0; i < 300; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "dot-failure-%zu", i);
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
  }

  const char *path = "/tmp/shelltype-dot-failure.dot";
  st_test_alloc_reset();
  ASSERT(st_policy_dump_dot(policy, path) == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  (void)remove(path);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_policy_dump_dot(policy, path);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(eval_matches(policy, "dot-failure-299", "dot-failure-299"));
    } else {
      ASSERT(error == ST_OK || error == ST_ERR_IO);
    }
    (void)remove(path);
  }
  ASSERT(observed);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

typedef st_error_t (*atomic_writer_t)(void *object, const char *path);

static st_error_t write_policy(void *object, const char *path) {
  return st_policy_save(object, path);
}

static st_error_t write_nfa(void *object, const char *path) {
  return st_policy_render_nfa(object, path, NULL);
}

static st_error_t write_learner(void *object, const char *path) {
  return st_save(object, path);
}

static int file_mode_is(const char *path, mode_t expected) {
  struct stat status;
  return stat(path, &status) == 0 && S_ISREG(status.st_mode) &&
         (status.st_mode & 07777) == expected;
}

static int test_atomic_writers_preserve_regular_file_modes(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  st_learner_t *learner = st_learner_new(1, 0.0);
  ASSERT(context != NULL && policy != NULL && learner != NULL);
  ASSERT(test_st_policy_add(policy, "copy #p") == ST_OK);
  ASSERT(test_st_feed(learner, "copy /tmp/source") == ST_OK);

  static const struct {
    const char *name;
    atomic_writer_t write;
  } cases[] = {
      {"policy", write_policy}, {"nfa", write_nfa}, {"learner", write_learner}};
  char directory[] = "/tmp/shelltype-modes-XXXXXX";
  ASSERT(mkdtemp(directory) != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    void *object = strcmp(cases[i].name, "learner") == 0 ? (void *)learner
                                                         : (void *)policy;
    char path[256], target[256];
    snprintf(path, sizeof(path), "%s/%s", directory, cases[i].name);
    snprintf(target, sizeof(target), "%s/%s-target", directory, cases[i].name);

    st_test_io_reset();
    ASSERT(cases[i].write(object, path) == ST_OK);
    ASSERT(file_mode_is(path, 0600));
    ASSERT(chmod(path, 0640) == 0);
    ASSERT(cases[i].write(object, path) == ST_OK);
    ASSERT(file_mode_is(path, 0640));

    FILE *target_file = fopen(target, "w");
    ASSERT(target_file != NULL && fputs("unchanged\n", target_file) >= 0 &&
           fclose(target_file) == 0);
    ASSERT(chmod(target, 0664) == 0);
    ASSERT(unlink(path) == 0 && symlink(target, path) == 0);
    ASSERT(cases[i].write(object, path) == ST_OK);
    struct stat destination_status;
    ASSERT(lstat(path, &destination_status) == 0 &&
           S_ISREG(destination_status.st_mode));
    ASSERT(file_mode_is(path, 0600));
    ASSERT(file_mode_is(target, 0664));
    target_file = fopen(target, "r");
    char contents[32] = {0};
    ASSERT(target_file != NULL &&
           fgets(contents, sizeof(contents), target_file) != NULL &&
           fclose(target_file) == 0);
    ASSERT(strcmp(contents, "unchanged\n") == 0);
    ASSERT(unlink(path) == 0 && unlink(target) == 0);
  }
  ASSERT(rmdir(directory) == 0);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_free(context);
  return 1;
}

int main(void) {
  printf("Running compact policy tests...\n\n");
  TEST(test_large_policy_compaction);
  TEST(test_compaction_allocation_failures_are_atomic);
  TEST(test_nfa_rendering_contract);
  TEST(test_nfa_policy_equivalence);
  TEST(test_nfa_lattice_transition_matrix);
  TEST(test_nfa_lifecycle_equivalence);
  TEST(test_nfa_preserves_parameter_branches);
  TEST(test_nfa_same_prefix_metadata_cross_product);
  TEST(test_nfa_allocation_failures);
  TEST(test_nfa_atomic_io_and_crash_boundaries);
  TEST(test_dot_queue_growth);
  TEST(test_dot_allocation_failures_are_clean);
  TEST(test_atomic_writers_preserve_regular_file_modes);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
