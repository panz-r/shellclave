#include <stddef.h>

int analyzer_c_probe(void) {
  int value = 7;
  int *pointer = &value;
#if ANALYZER_DEFECT
  pointer = NULL;
#endif
  return *pointer;
}
