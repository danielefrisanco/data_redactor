/* matcher10.h — v10: 88 per-pattern backtracking NFA, fixed O(1) stack. */
#ifndef MATCHER10_H
#define MATCHER10_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm10_match_t;

void   mm10_init(void);
void   mm10_free(void);
size_t mm10_scan(const char *input, size_t len, mm10_match_t *out, size_t max);
const char *mm10_pattern_name(int id);

#endif
