/* matcher18_1.h — v18.1: v18 + anchor lowering (BOL/EOL treated as passable in DFA). Zero deps. */
#ifndef MATCHER18_1_H
#define MATCHER18_1_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm18_1_match_t;

void   mm18_1_init(void);
void   mm18_1_free(void);
size_t mm18_1_scan(const char *input, size_t len, mm18_1_match_t *out, size_t max);
const char *mm18_1_pattern_name(int id);

#endif
