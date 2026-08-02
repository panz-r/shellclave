#include <stdio.h>

#include "relative_permutation_entropy.h"

int main(void) {
  const char *test_strings[] = {
      "sk_live_abc123XYZ789",    // Secret
      "this_is_a_file_path.txt", // File path
      "hello world",             // Natural language
      "a1b2c3d4e5f6"             // Structured secret
  };

  for (int i = 0; i < 4; i++) {
    const char *s = test_strings[i];
    double ratio_char = relative_entropy_ratio(s, 10, 1);
    double ratio_2gram = relative_entropy_ratio(s, 10, 2);

    printf("String: %s\n", s);
    printf("  Character ratio: %.2f\n", ratio_char);
    printf("  2-gram ratio: %.2f\n", ratio_2gram);
    printf("  Combined score: %.2f\n\n", 0.3 * ratio_char + 0.7 * ratio_2gram);
  }

  return 0;
}
