#ifndef SHELLGATE_TEST_NUMERIC_LOCALE_H
#define SHELLGATE_TEST_NUMERIC_LOCALE_H

#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Tests use a thread-local locale, never mutate the process-global locale.
 * CI provisions en_DK.UTF-8 data in its ephemeral runner's locale archive,
 * avoiding libc's LOCPATH scratch leak. Developer machines may use any of the
 * installed comma-decimal locales below; report unavailable locale data. */
static inline locale_t sg_test_comma_locale(void) {
  static const char *names[] = {"en_DK.UTF-8", "en_DK.utf8", "de_DE.UTF-8",
                                "fr_FR.UTF-8"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    locale_t locale = newlocale(LC_NUMERIC_MASK, names[i], (locale_t)0);
    if (!locale)
      continue;
    locale_t previous = uselocale(locale);
    bool comma = strcmp(localeconv()->decimal_point, ",") == 0;
    uselocale(previous);
    if (comma)
      return locale;
    freelocale(locale);
  }
  printf("    SKIP: comma-decimal locale data unavailable\n");
  return (locale_t)0;
}

#endif
