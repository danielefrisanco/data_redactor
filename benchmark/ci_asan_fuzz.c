/* ci_asan_fuzz.c — memory-safety gate for CI (and local runs).
 *
 * The v19.1 OP_EOL out-of-bounds read was found by AddressSanitizer: an
 * EOL-anchored match probing one byte past the buffer end. A pure-Ruby spec
 * cannot see that read — it only surfaces under ASan. This harness drives the
 * standalone matcher engine over a corpus of adversarial inputs plus a
 * deterministic pseudo-random fuzz loop, all under -fsanitize=address,undefined.
 * Any OOB access, use-after-free, or UB aborts the process, failing the build.
 * See docs/standalone_matcher_design.md (risk table) for the failure classes.
 *
 * This is a memory-safety gate, NOT a coverage-guided fuzzer: inputs are fixed
 * (the corpus) or derived from a fixed seed (the loop), so a green run is
 * reproducible and a red run is bisectable, like the alloc and musl gates.
 *
 * Build (from repo root):
 *   cc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *      -D_GNU_SOURCE -Iext/data_redactor \
 *      -DMATCHER_SRC='"ext/data_redactor/matcher.c"' \
 *      benchmark/ci_asan_fuzz.c ext/data_redactor/patterns.c -o /tmp/ci_asan_fuzz
 *   /tmp/ci_asan_fuzz
 *
 * Includes matcher.c directly (same as ci_alloc_gate.c) so the static engine
 * state and per-thread DFA cache are reachable; patterns.c is linked for the
 * built-in pattern arrays.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include MATCHER_SRC

#define MAX_EVENTS 4096

/* Scan + resolve one input. The interesting safety paths are inside mm_scan
 * (anchor probing at buffer edges) and mm_resolve (in-place sort/compaction);
 * we exercise both. enable_bits is sized to the current engine count. */
static void drive_scan(const int *bits, size_t n, const char *buf, size_t len) {
    mm_match_t out[MAX_EVENTS];
    size_t got = mm_scan(buf, len, bits, n, out, MAX_EVENTS);
    mm_resolve(out, got);
}

/* Heap-copy the input so ASan's redzones flank the exact [buf, buf+len) extent.
 * A one-past-the-end read (the OP_EOL class) lands in a redzone and aborts;
 * the same read against a stack/.rodata buffer with slack could go unnoticed. */
static void scan_exact(const int *bits, size_t n, const char *src, size_t len) {
    char *buf = (char *)malloc(len ? len : 1);
    if (len) memcpy(buf, src, len);
    drive_scan(bits, n, buf, len);
    free(buf);
}

/* ---- adversarial corpus ---------------------------------------------- *
 * Inputs targeting the documented edge classes: EOL/BOL anchors at buffer
 * bounds, empty/one-byte buffers, all-boundary-byte runs, max-length tokens,
 * and truncated multibyte tails. Tokens are placed flush against the buffer
 * end so anchor evaluation has no trailing slack. */
static void run_corpus(const int *bits, size_t n) {
    static const char *cases[] = {
        "",                       /* empty */
        " ",                      /* single boundary byte */
        "1",                      /* single digit, EOL-flush */
        "a",                      /* single alnum, EOL-flush */
        "\n",                     /* bare newline (BOL/EOL interplay) */
        "123-45-6789",            /* SSN flush to EOL — the OP_EOL repro shape */
        "ssn 123-45-6789",        /* SSN with leading boundary, flush to EOL */
        "iban DE89370400440532013000",     /* IBAN flush to EOL */
        "to alice@example.com",            /* email flush to EOL */
        "k=AKIAIOSFODNN7EXAMPLE",          /* AWS key flush to EOL */
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a", /* GitHub PAT, no trailing byte */
        "192.168.1.1",            /* IPv4 flush to EOL */
        "............",           /* all dots: structured-format boundary stress */
        "------------",           /* all dashes */
        "////////////",           /* all slashes */
        "@@@@@@@@@@@@",           /* all at-signs */
        "000000000000000000000000",        /* long pure-digit run (merge pass) */
        "\xff\xfe\xfd\xfc",       /* high bytes: not UTF-8, must stay in-bounds */
        "abc\xc3",                /* truncated 2-byte UTF-8 lead at EOL */
        "abc\xe2\x82",            /* truncated 3-byte UTF-8 at EOL */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        scan_exact(bits, n, cases[i], strlen(cases[i]));
    }

    /* A max-length token flush to EOL (the hvb {m,n} interval class), plus the
     * same with one trailing boundary byte, to exercise both anchor branches. */
    char big[512];
    memcpy(big, "hvb.", 4);
    memset(big + 4, 'B', 200);
    scan_exact(bits, n, big, 204);          /* flush to EOL */
    big[204] = ' ';
    scan_exact(bits, n, big, 205);          /* trailing boundary */
}

/* ---- deterministic pseudo-random fuzz loop --------------------------- *
 * splitmix64: fixed seed -> reproducible byte stream. Biased toward the
 * alphabet that drives the patterns (digits, dots, dashes, prefixes) so the
 * engine actually advances into anchor-evaluation code instead of failing the
 * first byte. Every iteration heap-allocates the exact length so a one-past
 * read is caught. */
static uint64_t sm_state;
static uint64_t sm_next(void) {
    uint64_t z = (sm_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void run_fuzz(const int *bits, size_t n, long iters) {
    static const char alphabet[] =
        "0123456789abcdefABCDEF.-/@_: \n"
        "ghp_AKIA hvb. DE iban ssn key=";
    const size_t alen = sizeof(alphabet) - 1;
    for (long it = 0; it < iters; it++) {
        size_t len = (size_t)(sm_next() % 64);   /* 0..63, includes empty */
        char *buf = (char *)malloc(len ? len : 1);
        for (size_t i = 0; i < len; i++) buf[i] = alphabet[sm_next() % alen];
        drive_scan(bits, n, buf, len);
        free(buf);
    }
}

int main(void) {
    mm_init();

    /* Built-in patterns only. */
    int n = mm_pattern_count();
    int *bits = (int *)malloc(sizeof(int) * (size_t)n);
    for (int i = 0; i < n; i++) bits[i] = 1;

    run_corpus(bits, (size_t)n);
    sm_state = 0xC0FFEEULL;            /* fixed seed: reproducible */
    run_fuzz(bits, (size_t)n, 200000);

    /* Custom-pattern lifecycle: add appends engines at ids >= NUM_PATTERNS, so
     * the bits/count must grow with it. Exercises mm_add parse, scan over the
     * larger id space, and mm_remove compaction (use-after-free territory). */
    free(bits);
    if (mm_add("CUST-[0-9]{4}", 1) != 0) {
        fprintf(stderr, "FAIL: mm_add rejected a valid custom regex\n");
        return 1;
    }
    if (mm_add("tok_[A-Za-z0-9]{8,32}", 0) != 0) {
        fprintf(stderr, "FAIL: mm_add rejected a valid custom regex\n");
        return 1;
    }
    n = mm_pattern_count();
    bits = (int *)malloc(sizeof(int) * (size_t)n);
    for (int i = 0; i < n; i++) bits[i] = 1;

    scan_exact(bits, (size_t)n, "id CUST-4242 tok_aB3dE9zQ", 25);
    sm_state = 0xBADC0DEULL;
    run_fuzz(bits, (size_t)n, 50000);

    mm_remove(0);                      /* compact: surviving custom shifts down */
    n = mm_pattern_count();
    for (int i = 0; i < n; i++) bits[i] = 1;   /* re-fill to the new count */
    scan_exact(bits, (size_t)n, "tok_aB3dE9zQ CUST-4242", 22);

    mm_clear_custom();
    free(bits);

    fprintf(stderr, "PASS: no ASan/UBSan errors over corpus + fuzz\n");
    return 0;
}
