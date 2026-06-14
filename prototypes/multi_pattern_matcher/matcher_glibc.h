/* matcher_glibc.h — plain sequential glibc regexec baseline (no AC, no BM).
 *
 * Stands in for the gem's PRE-v19 engine (≤ v0.11.0): a flat loop that runs each
 * of the 88 built-in patterns over the whole buffer with POSIX regexec. The
 * original gem code is no longer measurable in-process (0.13.0 ships v19), so this
 * prototype reproduces the same approach — plain regexec, boundary-wrapped, one
 * pass per pattern — as the documented incumbent baseline for the paper. See
 * paper/README.md and research_log.md §8.5 (the original ~0.2x-of-Ruby figure).
 */
#ifndef MATCHER_GLIBC_H
#define MATCHER_GLIBC_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mmg_match_t;

void   mmg_init(void);
void   mmg_free(void);
size_t mmg_scan(const char *input, size_t len, mmg_match_t *out, size_t max);
const char *mmg_pattern_name(int id);

#endif
