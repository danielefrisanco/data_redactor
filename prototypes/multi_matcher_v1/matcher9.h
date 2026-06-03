/* matcher9.h — v9: 88 separate per-pattern Thompson NFA + lazy DFA caches. */
#ifndef MATCHER9_H
#define MATCHER9_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm9_match_t;

void   mm9_init(void);
void   mm9_free(void);
size_t mm9_scan(const char *input, size_t len, mm9_match_t *out, size_t max);
const char *mm9_pattern_name(int id);

#endif
