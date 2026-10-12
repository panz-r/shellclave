#include <limits.h>

// Standalone instrumentation fixture; no library preconditions are violated.
int main(int argc, char **) {
  if (argc > 1)
    return 0;

  volatile int value = INT_MAX;
  volatile int result = value + 1;
  (void)result;
  return 0;
}
