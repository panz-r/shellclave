/* The user pointer on a policy object is the caller's association: never
 * interpreted, freed or serialized, and untouched by every other operation. */

#include "../../tests/atomic_file_fixture.h"
#include "shelltype.h"
#include "test_netargv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failed;

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "check failed: %s at %s:%d\n", #condition, __FILE__,     \
              __LINE__);                                                       \
      failed = 1;                                                              \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static int test_association(void) {
  char directory[] = "/tmp/shelltype-user-data-XXXXXX";
  int made = mkdtemp(directory) != NULL;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *first = context ? st_policy_new(context) : NULL;
  st_policy_t *second = context ? st_policy_new(context) : NULL;
  st_policy_t *loaded = context ? st_policy_new(context) : NULL;
  int first_record = 1, second_record = 2, loaded_record = 3;
  char path[256];
  CHECK(made && context && first && second && loaded);

  /* A new policy has no association, and each object keeps its own. */
  CHECK(st_policy_user_data(first) == NULL);
  st_policy_set_user_data(first, &first_record);
  st_policy_set_user_data(second, &second_record);
  CHECK(st_policy_user_data(first) == &first_record);
  CHECK(st_policy_user_data(second) == &second_record);

  /* Rules, evaluation, save, load and clear all leave it alone. */
  CHECK(test_st_policy_add(first, "git status") == ST_OK);
  CHECK(st_policy_user_data(first) == &first_record);
  st_netargv_view_t input = {.data = "3:git,6:status,", .length = 15};
  bool matched = false;
  CHECK(st_policy_match_view(first, input, &matched) == ST_OK && matched);
  CHECK(st_policy_user_data(first) == &first_record);

  snprintf(path, sizeof(path), "%s/policy", directory);
  CHECK(st_policy_save(first, path) == ST_OK);
  st_policy_set_user_data(loaded, &loaded_record);
  CHECK(st_policy_load(loaded, path, true) == ST_OK);
  CHECK(st_policy_user_data(loaded) == &loaded_record);
  CHECK(st_policy_user_data(first) == &first_record);

  CHECK(st_policy_clear(first) == ST_OK);
  CHECK(st_policy_user_data(first) == &first_record);

  /* The caller can clear it, and a policy copied by loading carries none. */
  st_policy_set_user_data(first, NULL);
  CHECK(st_policy_user_data(first) == NULL);
  CHECK(st_policy_user_data(second) == &second_record);

cleanup:
  st_policy_free(first);
  st_policy_free(second);
  st_policy_free(loaded);
  st_policy_ctx_release(context);
  if (made)
    (void)test_atomic_cleanup_directory(directory);
  return failed;
}

int main(void) {
  if (test_association() != 0)
    return 1;
  puts("policy user data tests passed");
  return 0;
}
