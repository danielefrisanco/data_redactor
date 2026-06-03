/* matcher14.h — v11: 88 per-pattern Thompson bytecode VM. Zero deps. */
#ifndef MATCHER14_H
#define MATCHER14_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm14_match_t;

void   mm14_init(void);
void   mm14_free(void);
size_t mm14_scan(const char *input, size_t len, mm14_match_t *out, size_t max);
const char *mm14_pattern_name(int id);

#endif
