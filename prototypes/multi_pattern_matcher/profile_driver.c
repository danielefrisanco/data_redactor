/*
 * profile_driver.c — single-engine driver for Callgrind instruction attribution
 * (paper §5.1). NOT wired into the gem or the existing benchmark Makefile; this
 * is a standalone profiling harness built by profile_engines.sh.
 *
 * One engine is selected at compile time and its source is included directly so
 * Callgrind sees the engine's own functions (not an opaque .so boundary):
 *
 *   -DENGINE_GLIBC   glibc regexec incumbent  (matcher_glibc.c, mmg_scan)
 *   -DENGINE_ONIG    plain Onigmo, no AC/BM   (matcher7_plain_onig.c, mm7po_scan)
 *   -DENGINE_V19     shipped lazy-DFA engine  (matcher19.c, mm19_scan)
 *
 * All three see the SAME payload: the seed-42 LCG construction from bench_malloc.c
 * (~1 MB, Lorem-ipsum noise + a 10-hit rotation), copied here rather than shared
 * so no existing file is modified. The point is a like-for-like instruction
 * breakdown across engines on one input, so the absolute scan count is irrelevant;
 * we run a small fixed number of scans (Callgrind counts instructions exactly,
 * it does not sample, so 1 scan already attributes every instruction).
 *
 * Usage: profile_driver <iterations>   (default 1)
 */

#define _GNU_SOURCE   /* matcher19.c uses memmem; superset of _POSIX_C_SOURCE */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ENGINE_GLIBC)
#  include "matcher_glibc.c"
#  define ENGINE_INIT  mmg_init
#  define ENGINE_FREE  mmg_free
#  define ENGINE_SCAN  mmg_scan
   typedef mmg_match_t  match_t;
#  define ENGINE_NAME "glibc"
#elif defined(ENGINE_ONIG)
#  include "matcher7_plain_onig.c"
#  define ENGINE_INIT  mm7po_init
#  define ENGINE_FREE  mm7po_free
#  define ENGINE_SCAN  mm7po_scan
   typedef mm7po_match_t match_t;
#  define ENGINE_NAME "onigmo"
#elif defined(ENGINE_V19)
#  include "matcher19.c"
#  define ENGINE_INIT  mm19_init
#  define ENGINE_FREE  mm19_free
#  define ENGINE_SCAN  mm19_scan
   typedef mm19_match_t match_t;
#  define ENGINE_NAME "v19"
#else
#  error "define one of ENGINE_GLIBC / ENGINE_ONIG / ENGINE_V19"
#endif

/* Deterministic payload — same construction as bench_malloc.c (seed-42 LCG). */
static char *build_payload(size_t *out_len) {
    static const char *hits[] = {
        "key=AKIAIOSFODNN7EXAMPLE",
        "stripe sk_live_abcdefghijklmnopqrstuvwx",
        "iban DE89370400440532013000",
        "ssn 123-45-6789",
        "pesel 12345678901",
        "email foo@bar.com",
        "ip 10.0.0.1",
        "cc 4111111111111111",
        "pem -----BEGIN RSA PRIVATE KEY-----",
        "gpg -----BEGIN PGP PRIVATE KEY BLOCK-----",
    };
    static const int nhits = 10;
    static const char *noise =
        "lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    size_t noise_len = strlen(noise);

    unsigned long rng = 42;
    size_t cap = 1 << 21; /* 2 MB — truncate at 1 MB */
    char *buf = malloc(cap);
    if (!buf) { perror("malloc"); exit(1); }
    size_t pos = 0;

    while (pos < 1000000) {
        size_t avail = cap - pos - 1;
        if (avail < noise_len + 64) break;
        memcpy(buf + pos, noise, noise_len);
        pos += noise_len;
        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        int idx = (int)((rng >> 33) % (unsigned long)nhits);
        size_t hlen = strlen(hits[idx]);
        memcpy(buf + pos, hits[idx], hlen);
        pos += hlen;
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';
    *out_len = pos;
    return buf;
}

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 1;
    if (iters < 1) iters = 1;

    size_t in_len;
    char *payload = build_payload(&in_len);

    static match_t out[1 << 16];

    ENGINE_INIT();

    size_t total = 0;
    for (int k = 0; k < iters; k++)
        total += ENGINE_SCAN(payload, in_len, out, sizeof(out) / sizeof(out[0]));

    ENGINE_FREE();

    /* stderr so it never lands in the callgrind output file */
    fprintf(stderr, "engine=%s payload=%zu bytes iters=%d matches/scan=%zu\n",
            ENGINE_NAME, in_len, iters, total / (size_t)iters);

    free(payload);
    return 0;
}
