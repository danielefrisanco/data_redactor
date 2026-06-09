#ifndef MULTI_MATCHER_V1_H
#define MULTI_MATCHER_V1_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Number of patterns in the prototype. Must match matcher.c. */
#define MM_NUM_PATTERNS 10

/* A single match reported by mm_scan. */
typedef struct {
    int pattern_id;   /* 0..MM_NUM_PATTERNS-1 */
    size_t start;     /* byte offset into input */
    size_t length;    /* match length in bytes */
} mm_match_t;

/* Build internal state (idempotent; safe to call multiple times). */
void mm_init(void);

/* Tear down internal state (frees AC trie + compiled regexes). */
void mm_free(void);

/* Scan `input` of `len` bytes. Writes up to `max_matches` matches into
 * `out`. Returns the number of matches written. Caller owns `out`.
 *
 * Slice 1 reports raw prefix-trie hits (no regexec yet) — pattern_id
 * is the matching prefix, start is its position, length is the prefix
 * length. Slice 2 will swap this for full regex matches. */
size_t mm_scan(const char *input, size_t len,
               mm_match_t *out, size_t max_matches);

/* Pattern name for diagnostic / correctness checks. */
const char *mm_pattern_name(int pattern_id);

#ifdef __cplusplus
}
#endif

#endif
