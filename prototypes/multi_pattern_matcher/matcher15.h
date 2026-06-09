/* matcher15.h — v11: 88 per-pattern Thompson bytecode VM. Zero deps. */
#ifndef MATCHER15_H
#define MATCHER15_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm15_match_t;

void   mm15_init(void);
void   mm15_free(void);
size_t mm15_scan(const char *input, size_t len, mm15_match_t *out, size_t max);
const char *mm15_pattern_name(int id);

#endif
