#ifndef DATA_REDACTOR_PATTERNS_H
#define DATA_REDACTOR_PATTERNS_H

#include <regex.h>

#define NUM_PATTERNS 88

extern const char *pattern_strings[NUM_PATTERNS];
extern const int   boundary_wrapped[NUM_PATTERNS];
extern const int   pattern_tags[NUM_PATTERNS];
extern const char *pattern_names[NUM_PATTERNS];

/*
 * Optional case-sensitive literal substring that the input must contain for
 * the pattern to have any chance of matching. NULL means no pre-filter — the
 * pattern runs unconditionally. A non-NULL literal must be a string the
 * regex *requires* (a wrong assignment here is a silent false negative).
 * The redactor memmem()'s the input for the literal before invoking regexec;
 * if absent, the pattern is skipped entirely. Big win for typical inputs
 * where most patterns don't match — saves the per-call O(N) regexec setup.
 */
extern const char *pattern_required_literal[NUM_PATTERNS];

/* Compiled at Init_data_redactor time. */
extern regex_t compiled_patterns[NUM_PATTERNS];

#endif
