/* matcher12.h — v11: 88 per-pattern Thompson bytecode VM. Zero deps. */
#ifndef MATCHER12_H
#define MATCHER12_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm12_match_t;

void   mm12_init(void);
void   mm12_free(void);
size_t mm12_scan(const char *input, size_t len, mm12_match_t *out, size_t max);
const char *mm12_pattern_name(int id);

#endif
