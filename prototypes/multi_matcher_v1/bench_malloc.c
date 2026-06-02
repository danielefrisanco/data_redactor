/*
 * bench_malloc.c — isolate malloc/free churn vs regexec cost in the current
 * glibc-based redact loop.
 *
 * Three variants, each doing 88-pattern sequential scan over a ~1 MB payload:
 *
 *   A) Current:   88× malloc+free per redact call (one working buffer per pattern)
 *   B) Prealloced: single output buffer, never freed between patterns (measures
 *                  regexec cost without malloc churn)
 *   C) Literals only: skip regexec entirely, just do the strstr pre-filter and
 *                  a memcpy of the input — establishes the floor (pure I/O cost)
 *
 * Variant B is not a correct implementation (it overwrites in-place and does
 * not handle matches that grow the output). It exists solely to measure how
 * much time malloc/free accounts for versus regexec itself.
 *
 * Build:
 *   cc -O2 -std=c99 -Wall -I../../ext/data_redactor \
 *       bench_malloc.c ../../ext/data_redactor/patterns.c \
 *       ../../ext/data_redactor/placeholder.c \
 *       -o bench_malloc
 *
 * The gem source files are included directly so we use the real 88 patterns.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <regex.h>

/* Pull in the real pattern tables from the gem. */
#include "../../ext/data_redactor/patterns.h"
#include "../../ext/data_redactor/placeholder.h"

/* ---- compile patterns (normally done at Ruby Init_ time) ---- */

static regex_t pats[NUM_PATTERNS];

static void compile_all(void) {
    char wrapped[4096];
    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *src = pattern_strings[i];
        const char *pat;
        if (boundary_wrapped[i]) {
            snprintf(wrapped, sizeof(wrapped),
                     "(^|[^0-9A-Za-z])(%s)([^0-9A-Za-z]|$)", src);
            pat = wrapped;
        } else {
            pat = src;
        }
        if (regcomp(&pats[i], pat, REG_EXTENDED) != 0) {
            fprintf(stderr, "regcomp failed for pattern %d\n", i);
            exit(1);
        }
    }
}

/* ---- payload builder (deterministic, no libc rand state) ---- */

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

    /* Seed-42 LCG (same sequence as Ruby's Random.new(42).rand) — close enough
     * for reproducibility without linking anything. */
    unsigned long rng = 42;
    size_t cap = 1 << 21; /* 2 MB — will truncate at 1 MB */
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

/* ---- variant A: current behavior — malloc+free per pattern ---- */

static void variant_a(const char *input, size_t in_len) {
    (void)in_len;
    placeholder_t ph = { .mode = 0, .str = "[REDACTED]" };

    char *working = strdup(input);
    regmatch_t m[4];

    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *lit = pattern_required_literal[i];
        if (lit && !strstr(working, lit)) continue;

        size_t wlen = strlen(working);
        size_t out_cap = wlen * (max_placeholder_len(&ph) + 1) + 1;
        char *result = malloc(out_cap);
        if (!result) { free(working); return; }

        size_t out_pos = 0;
        const char *cur = working;

        while (regexec(&pats[i], cur, 4, m, 0) == 0) {
            regoff_t so = m[0].rm_so, eo = m[0].rm_eo;
            if (so < 0 || eo < so) break;
            regoff_t core_so = so, core_eo = eo;
            if (boundary_wrapped[i]) {
                if (m[1].rm_so >= 0 && m[1].rm_eo > m[1].rm_so) core_so = m[1].rm_eo;
                if (m[3].rm_so >= 0 && m[3].rm_eo > m[3].rm_so) core_eo = m[3].rm_so;
            }
            memcpy(result + out_pos, cur, (size_t)core_so);
            out_pos += (size_t)core_so;
            memcpy(result + out_pos, "[REDACTED]", 10);
            out_pos += 10;
            if (eo > core_eo)
                memcpy(result + out_pos, cur + core_eo, (size_t)(eo - core_eo));
            out_pos += (size_t)(eo - core_eo);
            cur += eo;
            if (eo == so) { if (*cur) result[out_pos++] = *cur++; else break; }
        }
        size_t tail = strlen(cur);
        memcpy(result + out_pos, cur, tail);
        out_pos += tail;
        result[out_pos] = '\0';

        free(working);
        working = result;
    }
    free(working);
}

/* ---- variant B: preallocated — single output buf, reused across patterns ---- */

/*
 * We allocate two buffers of size (in_len * 12 + 1) once and ping-pong.
 * No malloc/free between patterns. This measures pure regexec cost.
 */
static void variant_b(const char *input, size_t in_len) {
    placeholder_t ph = { .mode = 0, .str = "[REDACTED]" };
    size_t buf_cap = in_len * (max_placeholder_len(&ph) + 1) + 1;

    char *bufs[2];
    bufs[0] = malloc(buf_cap);
    bufs[1] = malloc(buf_cap);
    if (!bufs[0] || !bufs[1]) { free(bufs[0]); free(bufs[1]); return; }

    memcpy(bufs[0], input, in_len + 1);
    int cur_buf = 0;

    regmatch_t m[4];

    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *working = bufs[cur_buf];
        const char *lit = pattern_required_literal[i];
        if (lit && !strstr(working, lit)) continue;

        char *result = bufs[1 - cur_buf];
        size_t out_pos = 0;
        const char *cur = working;

        while (regexec(&pats[i], cur, 4, m, 0) == 0) {
            regoff_t so = m[0].rm_so, eo = m[0].rm_eo;
            if (so < 0 || eo < so) break;
            regoff_t core_so = so, core_eo = eo;
            if (boundary_wrapped[i]) {
                if (m[1].rm_so >= 0 && m[1].rm_eo > m[1].rm_so) core_so = m[1].rm_eo;
                if (m[3].rm_so >= 0 && m[3].rm_eo > m[3].rm_so) core_eo = m[3].rm_so;
            }
            memcpy(result + out_pos, cur, (size_t)core_so);
            out_pos += (size_t)core_so;
            memcpy(result + out_pos, "[REDACTED]", 10);
            out_pos += 10;
            if (eo > core_eo)
                memcpy(result + out_pos, cur + core_eo, (size_t)(eo - core_eo));
            out_pos += (size_t)(eo - core_eo);
            cur += eo;
            if (eo == so) { if (*cur) result[out_pos++] = *cur++; else break; }
        }
        size_t tail = strlen(cur);
        memcpy(result + out_pos, cur, tail);
        out_pos += tail;
        result[out_pos] = '\0';

        cur_buf = 1 - cur_buf;
    }
    free(bufs[0]);
    free(bufs[1]);
}

/* ---- variant C: no regexec — just strstr pre-filter + memcpy (I/O floor) ---- */

static void variant_c(const char *input, size_t in_len) {
    char *working = malloc(in_len + 1);
    char *result  = malloc(in_len + 1);
    if (!working || !result) { free(working); free(result); return; }
    memcpy(working, input, in_len + 1);

    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *lit = pattern_required_literal[i];
        if (lit && !strstr(working, lit)) continue;
        /* Simulate the output pass without regexec: just copy verbatim. */
        size_t wlen = strlen(working);
        memcpy(result, working, wlen + 1);
        char *tmp = working; working = result; result = tmp;
    }
    free(working);
    free(result);
}

/* ---- timer ---- */

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---- main ---- */

int main(void) {
    compile_all();

    size_t in_len;
    char *payload = build_payload(&in_len);
    printf("Payload: %zu bytes | %d patterns\n\n", in_len, NUM_PATTERNS);

    const int ITERS = 20;

    /* warm-up */
    variant_a(payload, in_len);
    variant_b(payload, in_len);
    variant_c(payload, in_len);

    double t0, t1;

    t0 = now_sec();
    for (int k = 0; k < ITERS; k++) variant_c(payload, in_len);
    t1 = now_sec();
    double ms_c = (t1 - t0) / ITERS * 1000.0;

    t0 = now_sec();
    for (int k = 0; k < ITERS; k++) variant_b(payload, in_len);
    t1 = now_sec();
    double ms_b = (t1 - t0) / ITERS * 1000.0;

    t0 = now_sec();
    for (int k = 0; k < ITERS; k++) variant_a(payload, in_len);
    t1 = now_sec();
    double ms_a = (t1 - t0) / ITERS * 1000.0;

    printf("Variant C (no regexec, strstr+memcpy only):  %7.1f ms/iter  — I/O floor\n", ms_c);
    printf("Variant B (preallocated, no malloc churn):   %7.1f ms/iter\n", ms_b);
    printf("Variant A (current: 88× malloc+free):        %7.1f ms/iter\n", ms_a);
    printf("\n");
    printf("malloc overhead (A - B):    %.1f ms  (%.0f%%)\n",
           ms_a - ms_b, (ms_a - ms_b) / ms_a * 100.0);
    printf("regexec cost    (B - C):    %.1f ms  (%.0f%%)\n",
           ms_b - ms_c, (ms_b - ms_c) / ms_b * 100.0);

    free(payload);
    for (int i = 0; i < NUM_PATTERNS; i++) regfree(&pats[i]);
    return 0;
}
