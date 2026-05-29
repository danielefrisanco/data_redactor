#ifndef MULTI_MATCHER7_H
#define MULTI_MATCHER7_H

#include <stddef.h>
#include "patterns_generated.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int    pattern_id;
    size_t start;
    size_t length;
} mm7_match_t;

void        mm7_init(int use_jit);  /* use_jit=0: interpreter, 1: JIT */
void        mm7_free(void);
size_t      mm7_scan(const char *input, size_t len,
                     mm7_match_t *out, size_t max_matches);
const char *mm7_pattern_name(int pattern_id);

#ifdef __cplusplus
}
#endif

#endif
