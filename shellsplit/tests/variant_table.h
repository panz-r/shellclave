/* Variant tables: derive many test cases from one base case.
 *
 * A suite states a base source with named slots, and each row of a table gives
 * the slot texts, a repeat count and what must hold for the variant derived
 * from it. A row changes one thing from the base, so a table reads as a map of
 * the domain: which change matters, and what it changes. The suite supplies the
 * expectations and the checks; this header only derives the source.
 *
 * Base syntax: @NAME@ is replaced by the slot's text; {REP}...{/REP} is
 * repeated depth times and # becomes the repetition's index (0 based). */
#ifndef SHELLCLAVE_VARIANT_TABLE_H
#define SHELLCLAVE_VARIANT_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef struct {
  const char *name, *value;
} slot_t;

/* Append text to out, turning # into the repetition index when index >= 0. */
static inline bool variant_emit(char *out, size_t capacity, size_t *length,
                                const char *text, size_t size, int index) {
  for (size_t i = 0; i < size; i++) {
    if (*length + 2 > capacity)
      return false;
    out[(*length)++] =
        text[i] == '#' && index >= 0 ? (char)('0' + index) : text[i];
  }
  return true;
}

static inline bool variant_expand(const char *base, const slot_t *slots,
                                  size_t slot_count, unsigned depth, int index,
                                  char *out, size_t capacity, size_t *length) {
  for (const char *p = base; *p;) {
    if (strncmp(p, "{REP}", 5) == 0) {
      const char *end = strstr(p, "{/REP}");
      if (!end)
        return false;
      char inner[1024];
      size_t inner_size = (size_t)(end - (p + 5));
      if (inner_size >= sizeof(inner))
        return false;
      memcpy(inner, p + 5, inner_size);
      inner[inner_size] = 0;
      for (unsigned i = 0; i < depth; i++)
        if (!variant_expand(inner, slots, slot_count, depth, (int)i, out,
                            capacity, length))
          return false;
      p = end + 6;
    } else if (*p == '@') {
      const char *end = strchr(p + 1, '@');
      if (!end)
        return false;
      size_t name_size = (size_t)(end - (p + 1)), i = 0;
      while (i < slot_count && (strlen(slots[i].name) != name_size ||
                                strncmp(slots[i].name, p + 1, name_size) != 0))
        i++;
      if (i == slot_count ||
          !variant_emit(out, capacity, length, slots[i].value,
                        strlen(slots[i].value), index))
        return false;
      p = end + 1;
    } else {
      if (!variant_emit(out, capacity, length, p, 1, index))
        return false;
      p++;
    }
  }
  out[*length] = 0;
  return true;
}

#endif
