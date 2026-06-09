#ifndef MULTI_MATCHER5_H
#define MULTI_MATCHER5_H

#include <stddef.h>
#include "patterns_generated.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int    pattern_id;
    size_t start;
    size_t length;
} mm6_match_t;

void        mm6_init(void);
void        mm6_free(void);
size_t      mm6_scan(const char *input, size_t len,
                     mm6_match_t *out, size_t max_matches);
const char *mm6_pattern_name(int pattern_id);

#ifdef __cplusplus
}
#endif

#endif
