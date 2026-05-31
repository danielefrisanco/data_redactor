/*
 * bench_bm_inner.c — prototype: Boyer-Moore bad-character pre-filter *inside*
 * the regexec loop, per pattern.
 *
 * Today's code calls regexec(pattern, cursor, ...) and advances cursor by
 * match_end (or 1 on zero-length match). glibc evaluates the full NFA at
 * every position the cursor lands on — it has no literal pre-filter inside
 * the match loop.
 *
 * This prototype adds a BM bad-character table per pattern (built from the
 * pattern's required literal, same as pattern_required_literal[]). Before
 * calling regexec at each cursor position, we check whether the required
 * literal appears starting at or after cursor. If not, we advance cursor
 * by the BM shift — skipping positions where regexec can never match.
 *
 * For patterns with NULL literal (no distinctive prefix) the inner loop
 * degrades to the current behaviour: regexec at every position.
 *
 * Three variants:
 *   A) Current:   regexec at every cursor position (baseline)
 *   B) BM-inner:  BM shift inside the loop before calling regexec
 *   C) BM-inner + preallocated output buffers (both optimisations)
 *
 * Build:
 *   cc -O2 -std=c99 -Wall -I../../ext/data_redactor \
 *       bench_bm_inner.c \
 *       ../../ext/data_redactor/patterns.c \
 *       ../../ext/data_redactor/placeholder.c \
 *       -o bench_bm_inner
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <regex.h>

#include "../../ext/data_redactor/patterns.h"
#include "../../ext/data_redactor/placeholder.h"

/* ---- compile patterns --------------------------------------------------- */

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

/* ---- Boyer-Moore bad-character table ------------------------------------ */

#define BM_ALPHA 256

typedef struct {
    const char *lit;      /* required literal (NULL = no filter) */
    int         lit_len;
    int         shift[BM_ALPHA]; /* bad-character shift table */
} bm_table_t;

static bm_table_t bm_tables[NUM_PATTERNS];

static void build_bm_tables(void) {
    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *lit = pattern_required_literal[i];
        bm_tables[i].lit = lit;
        if (!lit) {
            bm_tables[i].lit_len = 0;
            continue;
        }
        int n = (int)strlen(lit);
        bm_tables[i].lit_len = n;
        /* Default shift: full literal length (byte not in literal at all). */
        for (int c = 0; c < BM_ALPHA; c++)
            bm_tables[i].shift[c] = n;
        /* For each byte in the literal (except the last), set shift to
         * distance from that position to the end of the literal. */
        for (int j = 0; j < n - 1; j++)
            bm_tables[i].shift[(unsigned char)lit[j]] = n - 1 - j;
        /* Last byte gets shift 1 (advance past it on a mismatch at end). */
        bm_tables[i].shift[(unsigned char)lit[n - 1]] = 1;
    }
}

/*
 * Find the next occurrence of literal `lit` (length `n`) in `[pos, end)`
 * using the bad-character BM table. Returns pointer to first occurrence,
 * or NULL if not found.
 *
 * This is the standard BM bad-character search: scan right-to-left within
 * the literal window, shift on mismatch.
 */
static const char *bm_find(const bm_table_t *t,
                            const char *haystack, size_t hay_len,
                            size_t start_pos) {
    const char *lit = t->lit;
    int n = t->lit_len;
    const char *end = haystack + hay_len;
    const char *cur = haystack + start_pos;

    while (cur + n <= end) {
        int j = n - 1;
        while (j >= 0 && cur[j] == lit[j])
            j--;
        if (j < 0)
            return cur; /* found */
        cur += t->shift[(unsigned char)cur[j]];
    }
    return NULL;
}

/* ---- payload builder ---------------------------------------------------- */

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
    size_t cap = 1 << 21;
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

/* ---- shared output helpers ---------------------------------------------- */

/*
 * Emit one pattern's replacements into `result` (pre-allocated), reading from
 * `working`. Returns the number of bytes written.
 *
 * BM-mode: before each regexec call, advance cursor to the next position where
 * the required literal occurs. This skips regexec at positions that cannot
 * possibly match.
 */
static size_t emit_pattern(int pat_idx, const char *working,
                            char *result, int use_bm) {
    size_t out_pos = 0;
    const char *cur = working;
    size_t working_len = strlen(working);
    regmatch_t m[4];

    while (1) {
        /* BM pre-advance: skip to next candidate position. */
        if (use_bm && bm_tables[pat_idx].lit) {
            size_t pos = (size_t)(cur - working);
            const char *found = bm_find(&bm_tables[pat_idx], working,
                                         working_len, pos);
            if (!found) {
                /* Literal not found from here → no more matches possible. */
                break;
            }
            /*
             * BM found the literal at `found`. The actual regex match may
             * start before `found` (e.g. boundary chars), so we position
             * cursor at max(cur, found - lit_len + 1) to not miss it.
             * Simpler conservative choice: cursor = found (the literal
             * must start at or after cursor for a match to include it).
             * We only move cursor *forward*, never backward.
             */
            if (found > cur)
                cur = found;
        }

        if (regexec(&pats[pat_idx], cur, 4, m, 0) != 0)
            break;

        regoff_t so = m[0].rm_so, eo = m[0].rm_eo;
        if (so < 0 || eo < so) break;

        regoff_t core_so = so, core_eo = eo;
        if (boundary_wrapped[pat_idx]) {
            if (m[1].rm_so >= 0 && m[1].rm_eo > m[1].rm_so) core_so = m[1].rm_eo;
            if (m[3].rm_so >= 0 && m[3].rm_eo > m[3].rm_so) core_eo = m[3].rm_so;
        }

        /* Copy prefix (text before the core match). */
        memcpy(result + out_pos, cur, (size_t)core_so);
        out_pos += (size_t)core_so;

        /* Emit placeholder. */
        memcpy(result + out_pos, "[REDACTED]", 10);
        out_pos += 10;

        /* Copy suffix chars (boundary chars after core, if boundary_wrapped). */
        if (eo > core_eo) {
            memcpy(result + out_pos, cur + core_eo, (size_t)(eo - core_eo));
            out_pos += (size_t)(eo - core_eo);
        }

        cur += eo;
        if (eo == so) {
            if (*cur) result[out_pos++] = *cur++;
            else break;
        }
    }

    /* Copy remaining tail. */
    size_t tail = strlen(cur);
    memcpy(result + out_pos, cur, tail);
    out_pos += tail;
    result[out_pos] = '\0';
    return out_pos;
}

/* ---- variant A: current — regexec at every position, 88× malloc --------- */

static void variant_a(const char *input, size_t in_len) {
    (void)in_len;
    size_t buf_cap = strlen(input) * 12 + 1;
    char *working = strdup(input);

    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *lit = pattern_required_literal[i];
        if (lit && !strstr(working, lit)) continue;

        char *result = malloc(buf_cap);
        if (!result) { free(working); return; }
        emit_pattern(i, working, result, 0 /* no BM inner */);
        free(working);
        working = result;
    }
    free(working);
}

/* ---- variant B: BM-inner, still 88× malloc ------------------------------ */

static void variant_b(const char *input, size_t in_len) {
    (void)in_len;
    size_t buf_cap = strlen(input) * 12 + 1;
    char *working = strdup(input);

    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *lit = pattern_required_literal[i];
        if (lit && !strstr(working, lit)) continue;

        char *result = malloc(buf_cap);
        if (!result) { free(working); return; }
        emit_pattern(i, working, result, 1 /* BM inner */);
        free(working);
        working = result;
    }
    free(working);
}

/* ---- variant C: BM-inner + preallocated (ping-pong) --------------------- */

static void variant_c(const char *input, size_t in_len) {
    size_t buf_cap = in_len * 12 + 1;
    char *bufs[2];
    bufs[0] = malloc(buf_cap);
    bufs[1] = malloc(buf_cap);
    if (!bufs[0] || !bufs[1]) { free(bufs[0]); free(bufs[1]); return; }

    memcpy(bufs[0], input, in_len + 1);
    int cur_buf = 0;

    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *working = bufs[cur_buf];
        const char *lit = pattern_required_literal[i];
        if (lit && !strstr(working, lit)) continue;

        char *result = bufs[1 - cur_buf];
        emit_pattern(i, working, result, 1 /* BM inner */);
        cur_buf = 1 - cur_buf;
    }

    free(bufs[0]);
    free(bufs[1]);
}

/* ---- timer --------------------------------------------------------------- */

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---- main ---------------------------------------------------------------- */

int main(void) {
    compile_all();
    build_bm_tables();

    size_t in_len;
    char *payload = build_payload(&in_len);
    printf("Payload: %zu bytes | %d patterns (%d with literal, %d always-run)\n\n",
           in_len, NUM_PATTERNS,
           (int)(NUM_PATTERNS - /* count NULLs below */ 0),  /* filled below */
           0);

    /* Count patterns with/without literal for the report. */
    int with_lit = 0, without_lit = 0;
    for (int i = 0; i < NUM_PATTERNS; i++) {
        if (pattern_required_literal[i]) with_lit++;
        else without_lit++;
    }
    printf("Payload: %zu bytes | %d patterns (%d with BM literal, %d always-run)\n\n",
           in_len, NUM_PATTERNS, with_lit, without_lit);

    const int ITERS = 20;

    /* warm-up */
    variant_a(payload, in_len);
    variant_b(payload, in_len);
    variant_c(payload, in_len);

    double t0, t1;

    t0 = now_sec();
    for (int k = 0; k < ITERS; k++) variant_a(payload, in_len);
    t1 = now_sec();
    double ms_a = (t1 - t0) / ITERS * 1000.0;

    t0 = now_sec();
    for (int k = 0; k < ITERS; k++) variant_b(payload, in_len);
    t1 = now_sec();
    double ms_b = (t1 - t0) / ITERS * 1000.0;

    t0 = now_sec();
    for (int k = 0; k < ITERS; k++) variant_c(payload, in_len);
    t1 = now_sec();
    double ms_c = (t1 - t0) / ITERS * 1000.0;

    printf("Variant A (current: regexec every position, 88× malloc):  %7.1f ms/iter\n", ms_a);
    printf("Variant B (BM-inner loop, still 88× malloc):               %7.1f ms/iter  %5.2f× vs A\n",
           ms_b, ms_a / ms_b);
    printf("Variant C (BM-inner + preallocated ping-pong):             %7.1f ms/iter  %5.2f× vs A\n",
           ms_c, ms_a / ms_c);

    free(payload);
    for (int i = 0; i < NUM_PATTERNS; i++) regfree(&pats[i]);
    return 0;
}
