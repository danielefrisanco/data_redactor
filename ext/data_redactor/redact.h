#ifndef DATA_REDACTOR_REDACT_H
#define DATA_REDACTOR_REDACT_H

#include <ruby.h>
#include <regex.h>
#include "placeholder.h"

/*
 * Build a boundary-wrapped version of a pattern:
 *   (^|[^0-9A-Za-z])(PATTERN)([^0-9A-Za-z]|$)
 * Caller must free the returned string.
 */
char *wrap_boundary(const char *core);

/*
 * Replace all occurrences of a compiled pattern in `input` with the placeholder.
 * Returns a newly malloc'd string (caller must free), or NULL on allocation failure.
 */
char *replace_all_matches(regex_t *pattern, const char *input,
                          int use_boundary, const placeholder_t *ph);

/*
 * DataRedactor._redact(text, ph_mode, ph_str, enable_bits) -> String
 *
 * `enable_bits` is an Array of Integers, one per pattern index. The first
 * NUM_PATTERNS entries cover built-ins; any extra entries cover currently
 * registered custom patterns in registration order. A 0 entry skips that
 * pattern entirely; non-zero runs it. The Ruby layer compiles `only:` /
 * `except:` (mixed Symbol+String) into this array.
 */
VALUE rb_data_redactor_redact(VALUE self, VALUE rb_text,
                              VALUE rb_ph_mode, VALUE rb_ph_str,
                              VALUE rb_enable_bits);

#endif
