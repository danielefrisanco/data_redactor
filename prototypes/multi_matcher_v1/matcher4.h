/* matcher4.h — Option D: Thompson NFA → DFA, zero external dependencies.
 *
 * All 88 patterns compiled into one merged DFA. One byte-at-a-time table
 * lookup replaces 88 separate regex engine calls.
 */
#ifndef MATCHER4_H
#define MATCHER4_H

#include <stddef.h>

typedef struct { int pattern_id; size_t start; size_t length; } mm4_match_t;

/* Compile all 88 patterns into one DFA. Call once before scanning. */
void   mm4_init(void);
/* Release all DFA memory. */
void   mm4_free(void);
/* Scan input[0..len). Write up to max matches into out[]. Return match count. */
size_t mm4_scan(const char *input, size_t len, mm4_match_t *out, size_t max);
/* Walk the DFA once (no per-position restart). Returns count of accepting bytes.
 * Measures raw DFA throughput — the upper bound of what a fully correct
 * single-pass automaton could achieve. */
size_t mm4_walk(const char *input, size_t len);
/* Pattern name by id (0-based). Returns NULL for out-of-range ids. */
const char *mm4_pattern_name(int id);

#endif /* MATCHER4_H */
