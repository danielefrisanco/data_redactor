/* ci_alloc_gate.c — performance-regression gate for CI (and local runs).
 *
 * The gem's selling point is a zero-allocation steady-state hot path: once a
 * thread's scan state is warm, repeated DataRedactor.redact calls must allocate
 * nothing in the C engine. This gate enforces that invariant deterministically
 * (unlike throughput, it has no run-to-run variance), so a refactor that
 * accidentally reintroduces per-scan malloc/realloc fails the build.
 *
 * It interposes malloc/realloc/calloc/free to count allocations made during a
 * measured window of steady-state scans (after warmup), and exits non-zero if
 * the count is not zero. Throughput is printed as informational only.
 *
 * Build (from repo root):
 *   cc -O2 -D_GNU_SOURCE -Iext/data_redactor \
 *      -DMATCHER_SRC='"ext/data_redactor/matcher.c"' \
 *      benchmark/ci_alloc_gate.c ext/data_redactor/patterns.c -ldl -o /tmp/ci_alloc_gate
 *   /tmp/ci_alloc_gate
 *
 * Includes matcher.c directly so it can warm the (static) per-thread DFA cache;
 * patterns.c is linked for the built-in pattern arrays.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

#include MATCHER_SRC

/* ---- allocation interposition ---------------------------------------- */
static long n_alloc;        /* malloc+realloc+calloc while counting */
static int  counting;

static void *(*real_malloc)(size_t);
static void *(*real_realloc)(void *, size_t);
static void *(*real_calloc)(size_t, size_t);

static void init_real(void) {
    if (!real_malloc) {
        real_malloc  = dlsym(RTLD_NEXT, "malloc");
        real_realloc = dlsym(RTLD_NEXT, "realloc");
        real_calloc  = dlsym(RTLD_NEXT, "calloc");
    }
}
void *malloc(size_t n)           { init_real(); if (counting) n_alloc++; return real_malloc(n); }
void *realloc(void *p, size_t n) { init_real(); if (counting) n_alloc++; return real_realloc(p, n); }
void *calloc(size_t a, size_t b) {
    /* dlsym may call calloc before real_calloc is resolved; bootstrap-allocate. */
    if (!real_calloc) {
        init_real();
        if (!real_calloc) {
            static char buf[16384]; static size_t off;
            size_t need = a * b; void *r = buf + off; off += need; return r;
        }
    }
    if (counting) n_alloc++;
    return real_calloc(a, b);
}

int main(void) {
    mm_init();
    int n = mm_pattern_count();
    int *bits = real_malloc(sizeof(int) * n);
    for (int i = 0; i < n; i++) bits[i] = 1;
    mm_match_t out[4096];

    const char *small = "email user@example.com ip 192.168.1.1 ssn 123-45-6789 end";
    size_t slen = strlen(small);

    /* Warm the lazy per-thread DFA so the measured window is steady state. */
    for (int k = 0; k < 200; k++) mm_scan(small, slen, bits, (size_t)n, out, 4096);

    /* Measured window: steady-state scans must allocate nothing. */
    const long WINDOW = 2000;
    counting = 1;
    for (long k = 0; k < WINDOW; k++) mm_scan(small, slen, bits, (size_t)n, out, 4096);
    counting = 0;

    double per_scan = (double)n_alloc / WINDOW;
    fprintf(stderr, "steady-state allocations: %ld over %ld scans (%.4f/scan)\n",
            n_alloc, WINDOW, per_scan);

    /* Informational throughput (NOT gated — CI runners are too noisy). */
    long iters = 1000000;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long k = 0; k < iters; k++) mm_scan(small, slen, bits, (size_t)n, out, 4096);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    fprintf(stderr, "throughput (informational): %.0f scans/sec (%.1f ns/scan)\n",
            iters / sec, sec / iters * 1e9);

    if (n_alloc != 0) {
        fprintf(stderr, "FAIL: steady-state hot path allocated %ld times (expected 0)\n",
                n_alloc);
        return 1;
    }
    fprintf(stderr, "PASS: zero-allocation steady-state hot path\n");
    return 0;
}
