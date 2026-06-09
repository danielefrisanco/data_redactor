#ifndef MULTI_MATCHER3_H
#define MULTI_MATCHER3_H

#include <stddef.h>
#include "patterns_generated.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int    pattern_id;
    size_t start;
    size_t length;
} mm3_match_t;

void        mm3_init(void);
void        mm3_free(void);
size_t      mm3_scan(const char *input, size_t len,
                     mm3_match_t *out, size_t max_matches);
const char *mm3_pattern_name(int pattern_id);

#ifdef __cplusplus
}
#endif

#endif
