/* matcher19.h — v19: v18.1 + merged pure-digit-group scan (one pass replaces 9 patterns). Zero deps. */
#ifndef MATCHER19_H
#define MATCHER19_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm19_match_t;

void   mm19_init(void);
void   mm19_free(void);
size_t mm19_scan(const char *input, size_t len, mm19_match_t *out, size_t max);
const char *mm19_pattern_name(int id);

#endif
