/* ci_resolve_check.c — correctness gate for mm_resolve (CI and local runs).
 *
 * mm_resolve checks each event against the LAST kept span only. That is correct
 * only because events are processed in (start asc, length desc, pattern_id asc)
 * order, which makes the kept spans ascending and non-overlapping. If that order
 * or the keep-rule ever changes, the shortcut silently drops or keeps the wrong
 * matches. The Ruby specs can't reach this directly: no built-in pattern emits a
 * zero-length event, and real scans rarely produce pathological overlap shapes.
 *
 * So this feeds mm_resolve hand-built and seeded-random event lists and checks
 * them against a brute-force oracle: the policy written as its definition (keep
 * an event iff it overlaps no kept span, O(n^2)). It also asserts the output
 * contract on its own terms: ascending start, no overlaps, no zero-length
 * events. Deterministic (fixed cases + fixed seed), so it is a hard gate.
 *
 * Build (from repo root):
 *   cc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *      -D_GNU_SOURCE -Iext/data_redactor \
 *      -DMATCHER_SRC='"ext/data_redactor/matcher.c"' \
 *      benchmark/ci_resolve_check.c ext/data_redactor/patterns.c -o /tmp/ci_resolve_check
 *   /tmp/ci_resolve_check
 *
 * Includes matcher.c directly (same as ci_asan_fuzz.c) to reach the resolver
 * and its sort comparator.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include MATCHER_SRC

#define MAX_EV 128

static int failures = 0;

static void print_events(const char *label, const mm_match_t *ev, size_t n) {
    fprintf(stderr, "  %-9s", label);
    for (size_t i = 0; i < n; i++)
        fprintf(stderr, " [%zu+%zu p%d]", ev[i].start, ev[i].length, ev[i].pattern_id);
    fprintf(stderr, "\n");
}

/* The policy as its definition: offer events longest-first at each start, keep
 * an event iff it overlaps no already-kept span, emit in ascending start.
 * Zero-length events redact nothing and are never kept. */
static size_t oracle(const mm_match_t *in, size_t n, mm_match_t *out) {
    mm_match_t ev[MAX_EV];
    memcpy(ev, in, n * sizeof(mm_match_t));
    qsort(ev, n, sizeof(mm_match_t), ev_cmp_resolve);
    size_t nk = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].length == 0) continue;
        size_t s = ev[i].start, e = s + ev[i].length;
        int overlaps = 0;
        for (size_t j = 0; j < nk; j++)
            if (s < out[j].start + out[j].length && out[j].start < e) { overlaps = 1; break; }
        if (!overlaps) out[nk++] = ev[i];
    }
    /* Kept spans never overlap and are non-empty, so their starts are distinct:
     * an insertion sort by start fully determines the order. */
    for (size_t i = 1; i < nk; i++)
        for (size_t j = i; j > 0 && out[j].start < out[j-1].start; j--) {
            mm_match_t t = out[j]; out[j] = out[j-1]; out[j-1] = t;
        }
    return nk;
}

static int contract_ok(const mm_match_t *ev, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (ev[i].length == 0) return 0;
        if (i && ev[i].start < ev[i-1].start + ev[i-1].length) return 0;
    }
    return 1;
}

static void check(const char *what, const mm_match_t *in, size_t n) {
    mm_match_t got[MAX_EV], want[MAX_EV];
    memcpy(got, in, n * sizeof(mm_match_t));
    size_t ng = mm_resolve(got, n);
    size_t nw = oracle(in, n, want);

    int same = ng == nw;
    for (size_t i = 0; same && i < ng; i++)
        same = got[i].pattern_id == want[i].pattern_id &&
               got[i].start == want[i].start && got[i].length == want[i].length;

    if (!same || !contract_ok(got, ng)) {
        failures++;
        fprintf(stderr, "FAIL: %s%s\n", what, same ? " (output contract)" : "");
        print_events("input:", in, n);
        print_events("expected:", want, nw);
        print_events("got:", got, ng);
    }
}

static uint64_t sm_state;
static uint64_t splitmix64(void) {
    uint64_t z = (sm_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

int main(void) {
    /* Hand-built shapes, each written as {pattern_id, start, length}. */
    static const struct { const char *what; size_t n; mm_match_t ev[6]; } cases[] = {
        {"longest at a start wins",         2, {{5, 10, 4}, {9, 10, 8}}},
        {"equal length: lower id wins",     3, {{7, 0, 9}, {3, 0, 9}, {5, 0, 9}}},
        {"earlier start claims the region", 2, {{1, 4, 40}, {0, 0, 40}}},
        {"nested shorter span dropped",     2, {{2, 0, 16}, {1, 3, 11}}},
        {"abutting spans both kept",        3, {{1, 0, 5}, {2, 5, 5}, {3, 10, 5}}},
        {"overlap only the last kept",      3, {{1, 0, 5}, {2, 6, 5}, {3, 9, 4}}},
        {"input in reverse order",          3, {{3, 20, 2}, {2, 10, 2}, {1, 0, 2}}},
        {"empty at start of a kept span",   2, {{1, 5, 10}, {2, 5, 0}}},
        {"empty inside a kept span",        2, {{1, 5, 10}, {2, 8, 0}}},
        {"empty at end of a kept span",     2, {{1, 5, 10}, {2, 15, 0}}},
        {"empty alone",                     1, {{2, 5, 0}}},
        {"empty before a later span",       3, {{2, 5, 0}, {1, 5, 10}, {3, 7, 2}}},
    };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++)
        check(cases[c].what, cases[c].ev, cases[c].n);

    /* Seeded random lists over a small window, so overlaps, shared starts,
     * equal-length ties and ~10% zero-length events are all common. */
    sm_state = 0xC0FFEEULL;
    mm_match_t ev[MAX_EV];
    for (long t = 0; t < 200000 && failures < 5; t++) {
        size_t n = 1 + splitmix64() % 60;
        for (size_t i = 0; i < n; i++) {
            ev[i].pattern_id = (int)(splitmix64() % 90);
            ev[i].start      = splitmix64() % 80;
            ev[i].length     = splitmix64() % 10 == 0 ? 0 : 1 + splitmix64() % 20;
        }
        check("random event list", ev, n);
    }

    if (failures) {
        fprintf(stderr, "FAIL: %d mm_resolve mismatch(es)\n", failures);
        return 1;
    }
    printf("PASS: mm_resolve matches the brute-force oracle "
           "(12 fixed cases + 200000 random lists)\n");
    return 0;
}
