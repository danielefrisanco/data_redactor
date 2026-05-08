#ifndef DATA_REDACTOR_PATTERNS_H
#define DATA_REDACTOR_PATTERNS_H

#include <regex.h>

#define NUM_PATTERNS 85

extern const char *pattern_strings[NUM_PATTERNS];
extern const int   boundary_wrapped[NUM_PATTERNS];
extern const int   pattern_tags[NUM_PATTERNS];
extern const char *pattern_names[NUM_PATTERNS];

/* Compiled at Init_data_redactor time. */
extern regex_t compiled_patterns[NUM_PATTERNS];

#endif
