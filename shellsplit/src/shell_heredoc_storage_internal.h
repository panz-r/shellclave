#ifndef SHELL_HEREDOC_STORAGE_INTERNAL_H
#define SHELL_HEREDOC_STORAGE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

/* Private delimiter-printer layout. Runtime sizing uses the same definition
 * as allocation; no duplicated structure size or runtime sizing call. */
typedef enum {
  LIT_BYTES,
  LIT_SINGLE_BYTES,
  LIT_ANSI,
  LIT_ANSI_RAW,
  LIT_CHILD,
  LIT_WORD,
  LIT_DOCUMENT,
  LIT_QUOTED_CHILD,
} literal_kind_t;

typedef struct literal_piece literal_piece_t;
struct literal_piece {
  literal_piece_t *next, *child;
  const char *text;
  size_t length;
  literal_kind_t kind;
  bool strip_tabs, join_lines;
};

/* Two pieces per source byte cover words, operators and wrappers. Every
 * reservation permits arbitrary caller alignment. */
enum {
  SHELL_HEREDOC_PIECE_FACTOR =
      2 * (sizeof(literal_piece_t) + _Alignof(literal_piece_t) - 1),
};

#endif
