#ifndef MULTI_MATCHER7_PLAIN_ONIG_H
#define MULTI_MATCHER7_PLAIN_ONIG_H

#include <stddef.h>
#include "patterns_generated.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int    pattern_id;
    size_t start;
    size_t length;
} mm7po_match_t;

void        mm7po_init(void);
void        mm7po_free(void);
size_t      mm7po_scan(const char *input, size_t len,
                       mm7po_match_t *out, size_t max_matches);
const char *mm7po_pattern_name(int pattern_id);

#ifdef __cplusplus
}
#endif

#endif
