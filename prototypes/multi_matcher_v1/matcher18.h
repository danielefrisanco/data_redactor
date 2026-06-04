/* matcher18.h — v18: v15.1 + per-pattern lazy DFA transition cache. Zero deps. */
#ifndef MATCHER18_H
#define MATCHER18_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm18_match_t;

void   mm18_init(void);
void   mm18_free(void);
size_t mm18_scan(const char *input, size_t len, mm18_match_t *out, size_t max);
const char *mm18_pattern_name(int id);

#endif
