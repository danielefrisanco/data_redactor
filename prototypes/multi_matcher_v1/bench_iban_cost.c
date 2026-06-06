/* bench_iban_cost.c — isolate the cost of the 18 IBAN patterns (32-49) in v19.
 *
 * Builds against matcher19.c internals via a thin re-include so we can call
 * scan_one directly for a pattern subset. Compile:
 *   cc -O2 -DMM19_BENCH bench_iban_cost.c matcher19.c -o bench_iban_cost
 * (matcher19.c's main() is guarded by MM19_MAIN, so it won't clash.)
 */
#define _POSIX_C_SOURCE 199309L   /* clock_gettime / CLOCK_MONOTONIC under -std=c99 */
#include "matcher19.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* exposed from matcher19.c for this bench */
size_t mm19_scan_range(int lo, int hi, const char *input, size_t len,
                       mm19_match_t *out, size_t max);

static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static char *make_payload(size_t target, int with_ibans) {
    const char *noise = "Lorem ipsum dolor sit amet consectetur adipiscing elit ";
    const char *iban  = "DE89370400440532013000 ";
    size_t nl = strlen(noise), il = strlen(iban);
    char *buf = malloc(target + 256);
    size_t o = 0; int k = 0;
    while (o < target) {
        memcpy(buf + o, noise, nl); o += nl;
        if (with_ibans && (++k % 40 == 0)) { memcpy(buf + o, iban, il); o += il; }
    }
    buf[o] = 0;
    return buf;
}

int main(void) {
    mm19_init();
    size_t TARGET = 1000000;
    mm19_match_t *out = malloc(sizeof(*out) * 200000);

    for (int withi = 0; withi <= 1; withi++) {
        char *buf = make_payload(TARGET, withi);
        size_t len = strlen(buf);
        const int ITERS = 200;

        /* warm */
        mm19_scan(buf, len, out, 200000);
        mm19_scan_range(32, 49, buf, len, out, 200000);

        double t0 = now_ms();
        size_t n_all = 0;
        for (int i = 0; i < ITERS; i++) n_all = mm19_scan(buf, len, out, 200000);
        double t_all = (now_ms() - t0) / ITERS;

        t0 = now_ms();
        size_t n_iban = 0;
        for (int i = 0; i < ITERS; i++)
            n_iban = mm19_scan_range(32, 49, buf, len, out, 200000);
        double t_iban = (now_ms() - t0) / ITERS;

        printf("payload %s IBANs:\n", withi ? "WITH" : "without");
        printf("  full scan      : %7.3f ms/iter  (%zu matches)\n", t_all, n_all);
        printf("  IBAN-group only: %7.3f ms/iter  (%zu matches)  = %.1f%% of full\n",
               t_iban, n_iban, 100.0 * t_iban / t_all);
        free(buf);
    }
    mm19_free();
    free(out);
    return 0;
}
