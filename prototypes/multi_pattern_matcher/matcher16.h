/* matcher16.h — v15.2: v15.1 + cross-pattern union first-byte bitmap. Zero deps. */
#ifndef MATCHER16_H
#define MATCHER16_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm16_match_t;

void   mm16_init(void);
void   mm16_free(void);
size_t mm16_scan(const char *input, size_t len, mm16_match_t *out, size_t max);
const char *mm16_pattern_name(int id);

#endif
