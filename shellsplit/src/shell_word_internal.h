#ifndef SHELL_WORD_INTERNAL_H
#define SHELL_WORD_INTERNAL_H

#include "shell_processor.h"

/* Declaration-only interface for semantic word values. Decoding loops belong
 * to shell_word_decode_internal.h; direct canonical emitters include that
 * header, while callers of these operations need only this interface. */

/* Literal shell-word projection for semantic consumers: ANSI-C NUL truncates
 * only its fragment, and later fragments resume. Dynamic expansions remain
 * unevaluated, but quote and escape processing can change their spelling:
 * ${v:-$'a\0b'} projects to ${v:-a}. Exact-source consumers and expansion
 * callbacks use retained source spans; callers establish staticness separately.
 * Source is an immutable isolated word; outputs are distinct writable storage.
 * Visitor/context have the public decoded-word callback contract. A NULL
 * visitor measures. The writer checks capacity during one forward fill;
 * failures leave written zero and may modify destination bytes. Callers own
 * unpublished output storage and discard it on failure. Standalone
 * public byte decoders deliberately preserve their separate binary semantics.
 */
shell_process_status_t shell_process_visit_word_value(
    const char *text, size_t length, shell_decoded_word_visitor_t visitor,
    void *context, size_t *decoded_length) SHELL_NONNULL(1, 5);
shell_process_status_t shell_process_measure_word_value(const char *text,
                                                        size_t length,
                                                        size_t *decoded_length)
    SHELL_NONNULL(1, 3);
shell_process_status_t
shell_process_write_word_value(const char *text, size_t length,
                               char *destination, size_t destination_size,
                               size_t *written) SHELL_NONNULL(1, 3, 5);

#endif
