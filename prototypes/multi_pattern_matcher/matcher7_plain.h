#ifndef MULTI_MATCHER7_PLAIN_H
#define MULTI_MATCHER7_PLAIN_H

#include <stddef.h>
#include "patterns_generated.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int    pattern_id;
    size_t start;
    size_t length;
} mm7p_match_t;

void        mm7p_init(int use_jit);
void        mm7p_free(void);
size_t      mm7p_scan(const char *input, size_t len,
                      mm7p_match_t *out, size_t max_matches);
const char *mm7p_pattern_name(int pattern_id);

#ifdef __cplusplus
}
#endif

#endif
