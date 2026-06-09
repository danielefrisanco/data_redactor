/* matcher11.h — v11: 88 per-pattern Thompson bytecode VM. Zero deps. */
#ifndef MATCHER11_H
#define MATCHER11_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm11_match_t;

void   mm11_init(void);
void   mm11_free(void);
size_t mm11_scan(const char *input, size_t len, mm11_match_t *out, size_t max);
const char *mm11_pattern_name(int id);

#endif
