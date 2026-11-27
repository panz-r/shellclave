/* A consumer of Shellclave::shelltype alone: no Shellsplit or Shellgate. */
#include <shelltype.h>

#include <stdlib.h>

int main(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  st_netpattern_t pattern = {0};
  int status = EXIT_FAILURE;
  if (policy && st_netpattern_from_cpl_owned("echo *", &pattern) == ST_OK &&
      st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){pattern.data, pattern.length}) ==
          ST_OK &&
      st_policy_rule_count(policy) == 1)
    status = EXIT_SUCCESS;
  st_netpattern_free(&pattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return status;
}
