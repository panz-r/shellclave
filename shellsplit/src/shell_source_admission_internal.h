#ifndef SHELL_SOURCE_ADMISSION_INTERNAL_H
#define SHELL_SOURCE_ADMISSION_INTERNAL_H
#include "shell_source.h"

#ifdef __cplusplus
extern "C" {
#endif

/* External byte-admission boundary shared by source, tokenizer and processor.
 * Required immutable source provides length readable bytes, including zero.
 * Reject NUL as INVALID_INPUT, prohibited control/DEL and unmodeled code bytes
 * as UNSUPPORTED, and exhausted resources as TRUNCATED. Words, comments and
 * heredoc data admit literal high bytes under their scoped grammar. ANSI-C
 * fragments inherit their containing word-data or restricted-code domain.
 * Successful root admission is reused by contained implementation spans in
 * this operation; application callbacks have independent admission domains. */
shell_source_status_t shell_source_bytes_status(const char *input,
                                                size_t length) SHELL_NONNULL(1);
/* Boolean projection for consumers with their own coarse failure codes. */
bool shell_source_bytes_valid(const char *input, size_t length)
    SHELL_NONNULL(1);

#ifdef __cplusplus
}
#endif
#endif
