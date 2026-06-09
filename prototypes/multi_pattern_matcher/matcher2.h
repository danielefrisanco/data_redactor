#ifndef MULTI_MATCHER2_H
#define MULTI_MATCHER2_H

#include <stddef.h>
#include "patterns_generated.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int    pattern_id;
    size_t start;
    size_t length;
} mm88_match_t;

void        mm88_init(void);
void        mm88_free(void);
size_t      mm88_scan(const char *input, size_t len,
                      mm88_match_t *out, size_t max_matches);
const char *mm88_pattern_name(int pattern_id);

#ifdef __cplusplus
}
#endif

#endif
