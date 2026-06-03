/* matcher17.h — v17: v15.1 + precomputed initial thread list. Zero deps. */
#ifndef MATCHER17_H
#define MATCHER17_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm17_match_t;

void   mm17_init(void);
void   mm17_free(void);
size_t mm17_scan(const char *input, size_t len, mm17_match_t *out, size_t max);
const char *mm17_pattern_name(int id);

#endif
