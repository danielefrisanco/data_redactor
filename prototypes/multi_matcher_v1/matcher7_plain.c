/* matcher7_plain.c — plain PCRE2 JIT baseline, no AC trie, no BM.
 *
 * Sequential scan: for each of the 88 patterns, call pcre2_jit_match
 * (or pcre2_match if use_jit=0) in a loop over the full input.
 * Equivalent to today's C extension (glibc regexec loop) but with PCRE2.
 *
 * Purpose: isolate the engine contribution from the AC+BM pipeline.
 * Compare this vs v7 (AC+BM+PCRE2 JIT) to see how much the pipeline adds.
 *
 * Build:  make matcher7_plain.so
 * Smoke:  make matcher7_plain && ./matcher7_plain
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#include "matcher7_plain.h"
#include "patterns_generated.h"

#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define WRAP_PREFIX "(^|[^0-9A-Za-z])("
#define WRAP_SUFFIX ")([^0-9A-Za-z]|$)"

static char *make_wrapped_regex(const char *core) {
    size_t len = strlen(WRAP_PREFIX) + strlen(core) + strlen(WRAP_SUFFIX) + 1;
    char *buf = malloc(len);
    if (!buf) { perror("malloc"); exit(1); }
    snprintf(buf, len, "%s%s%s", WRAP_PREFIX, core, WRAP_SUFFIX);
    return buf;
}

static pcre2_code *g_re[MM88_NUM_PATTERNS];
static int         g_compiled_ok = 0;
static int         g_use_jit     = 0;

static void compile_patterns(int use_jit) {
    g_use_jit = use_jit;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *src = MM88_PATTERNS[p].regex;
        char *to_free = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped)
            src = to_free = make_wrapped_regex(src);

        int errcode; PCRE2_SIZE erroffset;
        g_re[p] = pcre2_compile((PCRE2_SPTR)src, PCRE2_ZERO_TERMINATED,
                                 0, &errcode, &erroffset, NULL);
        free(to_free);
        if (!g_re[p]) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
            fprintf(stderr, "pcre2_compile failed for %s: %s\n",
                    MM88_PATTERNS[p].name, errbuf);
            exit(1);
        }
        if (use_jit) {
            int rc = pcre2_jit_compile(g_re[p], PCRE2_JIT_COMPLETE);
            if (rc < 0) {
                PCRE2_UCHAR errbuf[256];
                pcre2_get_error_message(rc, errbuf, sizeof(errbuf));
                fprintf(stderr, "pcre2_jit_compile warning for %s: %s\n",
                        MM88_PATTERNS[p].name, errbuf);
            }
        }
    }
    g_compiled_ok = 1;
}

static int g_initialized = 0;

void mm7p_init(int use_jit) {
    if (g_initialized) return;
    compile_patterns(use_jit);
    g_initialized = 1;
}

void mm7p_free(void) {
    if (g_compiled_ok) {
        for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
            if (g_re[p]) { pcre2_code_free(g_re[p]); g_re[p] = NULL; }
        }
        g_compiled_ok = 0;
    }
    g_initialized = 0;
}

const char *mm7p_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return "<invalid>";
    return MM88_PATTERNS[id].name;
}

size_t mm7p_scan(const char *input, size_t len,
                 mm7p_match_t *out, size_t max_matches) {
    if (!g_initialized) mm7p_init(0);
    size_t written = 0;

    for (int p = 0; p < MM88_NUM_PATTERNS && written < max_matches; p++) {
        size_t pos = 0;
        while (pos < len && written < max_matches) {
            pcre2_match_data *md =
                pcre2_match_data_create_from_pattern(g_re[p], NULL);
            if (!md) break;

            int rc;
            if (g_use_jit)
                rc = pcre2_jit_match(g_re[p], (PCRE2_SPTR)input, len,
                                     pos, 0, md, NULL);
            else
                rc = pcre2_match(g_re[p], (PCRE2_SPTR)input, len,
                                 pos, 0, md, NULL);

            if (rc <= 0) { pcre2_match_data_free(md); break; }

            PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
            size_t mstart, mlen;
            if (MM88_PATTERNS[p].boundary_wrapped && rc > 2) {
                PCRE2_SIZE so = ov[4], eo = ov[5];
                pcre2_match_data_free(md);
                if (so == PCRE2_UNSET || eo <= so) { pos++; continue; }
                mstart = so; mlen = eo - so;
            } else {
                PCRE2_SIZE so = ov[0], eo = ov[1];
                pcre2_match_data_free(md);
                if (eo <= so) { pos++; continue; }
                mstart = so; mlen = eo - so;
            }
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
            pos = mstart + mlen;
            if (pos == 0) break;
        }
    }
    return written;
}

#ifdef MM7P_MAIN
int main(void) {
    mm7p_init(1);
    fprintf(stderr, "plain PCRE2 JIT: %d\n", g_use_jit);
    const char *cases[] = {
        "key=AKIAIOSFODNN7EXAMPLE end",
        "stripe sk_live_abcdefghijklmnopqrstuvwx end",
        "ssn 123-45-6789 end",
        "email foo@bar.com end",
        "ip 10.0.0.1 end",
        "pem -----BEGIN RSA PRIVATE KEY----- end",
        "plain text nothing here",
        NULL
    };
    mm7p_match_t buf[1024];
    for (int i = 0; cases[i]; i++) {
        size_t n = mm7p_scan(cases[i], strlen(cases[i]), buf, 1024);
        printf("[%d] %zu matches: %s\n", i, n, cases[i]);
        for (size_t j = 0; j < n && j < 4; j++)
            printf("    %-30s pos=%zu len=%zu\n",
                   mm7p_pattern_name(buf[j].pattern_id),
                   buf[j].start, buf[j].length);
    }
    mm7p_free();
    return 0;
}
#endif
