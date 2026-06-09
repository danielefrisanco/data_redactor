/* Multi-matcher prototype v7 — AC trie + Boyer-Moore + PCRE2.
 *
 * Same two-stage AC + BM architecture as v5 (matcher5.c), with the
 * confirmation engine swapped from Onigmo to PCRE2.
 *
 * mm7_init(use_jit=0) compiles patterns with PCRE2 interpreter only.
 * mm7_init(use_jit=1) additionally calls pcre2_jit_compile() on each pattern,
 * enabling native-code execution for the confirmation step.
 *
 * This lets us measure three engines head-to-head on the same payload:
 *   v5: AC + BM + Onigmo         (bench5.rb)
 *   v7 no-JIT: AC + BM + PCRE2  (bench7.rb with JIT=0)
 *   v7 JIT:    AC + BM + PCRE2 JIT (bench7.rb with JIT=1)
 *
 * Build:  make matcher7.so
 * Smoke:  make matcher7 && ./matcher7
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#include "matcher7.h"
#include "patterns_generated.h"

#include <pcre2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------- Boundary-wrapper -------------------------------------------- */

#define WRAP_PREFIX  "(^|[^0-9A-Za-z])("
#define WRAP_SUFFIX  ")([^0-9A-Za-z]|$)"

static char *make_wrapped_regex(const char *core) {
    size_t len = strlen(WRAP_PREFIX) + strlen(core) + strlen(WRAP_SUFFIX) + 1;
    char *buf = malloc(len);
    if (!buf) { perror("malloc"); exit(1); }
    snprintf(buf, len, "%s%s%s", WRAP_PREFIX, core, WRAP_SUFFIX);
    return buf;
}

/* ---------- Compiled patterns ------------------------------------------- */

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

        int errcode;
        PCRE2_SIZE erroffset;
        g_re[p] = pcre2_compile(
            (PCRE2_SPTR)src,
            PCRE2_ZERO_TERMINATED,
            0,
            &errcode, &erroffset, NULL);

        free(to_free);

        if (!g_re[p]) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
            fprintf(stderr, "pcre2_compile failed for %s at offset %zu: %s\n",
                    MM88_PATTERNS[p].name, erroffset, errbuf);
            exit(1);
        }

        if (use_jit) {
            int rc = pcre2_jit_compile(g_re[p], PCRE2_JIT_COMPLETE);
            if (rc < 0) {
                /* JIT not available for this pattern — silently continue with
                 * interpreter.  This happens on architectures without a JIT
                 * backend or when mmap(PROT_EXEC) is blocked. */
                PCRE2_UCHAR errbuf[256];
                pcre2_get_error_message(rc, errbuf, sizeof(errbuf));
                fprintf(stderr, "pcre2_jit_compile warning for %s: %s (falling back to interpreter)\n",
                        MM88_PATTERNS[p].name, errbuf);
            }
        }
    }
    g_compiled_ok = 1;
}

/* ---------- Boyer-Moore shift tables (identical to v5) ------------------ */

typedef struct {
    size_t shift[256];
    size_t pat_len;
    const char *pat;
} bm_table_t;

static bm_table_t g_bm[MM88_NUM_PATTERNS];

static void bm_build(int p) {
    const char *lit = MM88_PATTERNS[p].bm_literal;
    if (!lit) { g_bm[p].pat = NULL; g_bm[p].pat_len = 0; return; }
    size_t m = strlen(lit);
    g_bm[p].pat = lit;
    g_bm[p].pat_len = m;
    for (int c = 0; c < 256; c++) g_bm[p].shift[c] = m;
    for (size_t i = 0; i < m - 1; i++)
        g_bm[p].shift[(unsigned char)lit[i]] = m - 1 - i;
}

static const char *bm_search(int p, const char *haystack, size_t len) {
    const bm_table_t *bm = &g_bm[p];
    const char *pat = bm->pat;
    size_t m = bm->pat_len;
    if (!pat || m == 0) return haystack;
    if (m > len) return NULL;
    size_t i = m - 1;
    while (i < len) {
        size_t j = m - 1, k = i;
        while (j != (size_t)-1 && haystack[k] == pat[j]) {
            if (j == 0) break;
            k--; j--;
        }
        if (j == (size_t)-1 || (j == 0 && haystack[k] == pat[0]))
            return haystack + k;
        i += bm->shift[(unsigned char)haystack[i]];
    }
    return NULL;
}

/* ---------- Aho-Corasick (identical to v5) ------------------------------ */

typedef struct ac_node {
    int32_t  goto_tbl[256];
    int32_t  fail;
    uint64_t accept[2];
    uint64_t accept_out[2];
    uint8_t  prefix_len[MM88_NUM_PATTERNS];
} ac_node_t;

static ac_node_t *g_nodes     = NULL;
static int32_t    g_node_count = 0;
static int32_t    g_node_cap   = 0;
static uint64_t   g_always[2]  = {0, 0};

#define BIT_SET(arr, i)   ((arr)[(i)/64] |=  (uint64_t)1 << ((i)%64))
#define BIT_GET(arr, i)   (!!((arr)[(i)/64] &  ((uint64_t)1 << ((i)%64))))
#define BIT_OR(dst, src)  do { (dst)[0] |= (src)[0]; (dst)[1] |= (src)[1]; } while(0)
#define BIT_ANY(arr)      ((arr)[0] || (arr)[1])

static int32_t ac_new_node(void) {
    if (g_node_count == g_node_cap) {
        g_node_cap = g_node_cap ? g_node_cap * 2 : 128;
        g_nodes = realloc(g_nodes, (size_t)g_node_cap * sizeof(ac_node_t));
        if (!g_nodes) { perror("realloc"); exit(1); }
    }
    ac_node_t *n = &g_nodes[g_node_count];
    for (int i = 0; i < 256; i++) n->goto_tbl[i] = -1;
    n->fail = 0;
    n->accept[0] = n->accept[1] = 0;
    n->accept_out[0] = n->accept_out[1] = 0;
    memset(n->prefix_len, 0, sizeof(n->prefix_len));
    return g_node_count++;
}

static void ac_insert(const char *s, int pid) {
    int32_t cur = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)s[i];
        if (g_nodes[cur].goto_tbl[c] == -1) {
            int32_t nx = ac_new_node();
            g_nodes[cur].goto_tbl[c] = nx;
        }
        cur = g_nodes[cur].goto_tbl[c];
    }
    BIT_SET(g_nodes[cur].accept, pid);
    g_nodes[cur].prefix_len[pid] = (uint8_t)(n > 255 ? 255 : n);
}

static void ac_build_failure(void) {
    int32_t *queue = malloc((size_t)g_node_count * sizeof(int32_t));
    if (!queue) { perror("malloc"); exit(1); }
    int qh = 0, qt = 0;
    for (int c = 0; c < 256; c++) {
        int32_t nx = g_nodes[0].goto_tbl[c];
        if (nx == -1) g_nodes[0].goto_tbl[c] = 0;
        else { g_nodes[nx].fail = 0; queue[qt++] = nx; }
    }
    while (qh < qt) {
        int32_t u = queue[qh++];
        BIT_OR(g_nodes[u].accept_out, g_nodes[u].accept);
        BIT_OR(g_nodes[u].accept_out, g_nodes[g_nodes[u].fail].accept_out);
        for (int c = 0; c < 256; c++) {
            int32_t v = g_nodes[u].goto_tbl[c];
            if (v == -1) g_nodes[u].goto_tbl[c] = g_nodes[g_nodes[u].fail].goto_tbl[c];
            else { g_nodes[v].fail = g_nodes[g_nodes[u].fail].goto_tbl[c]; queue[qt++] = v; }
        }
    }
    free(queue);
}

/* ---------- Init / free ------------------------------------------------- */

static int g_initialized = 0;

void mm7_init(int use_jit) {
    if (g_initialized) return;
    ac_new_node();
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *pref = MM88_PATTERNS[p].prefix;
        if (!pref) BIT_SET(g_always, p);
        else ac_insert(pref, p);
    }
    ac_build_failure();
    compile_patterns(use_jit);
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) bm_build(p);
    g_initialized = 1;
}

void mm7_free(void) {
    if (g_compiled_ok) {
        for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
            if (g_re[p]) { pcre2_code_free(g_re[p]); g_re[p] = NULL; }
        }
        g_compiled_ok = 0;
    }
    free(g_nodes); g_nodes = NULL;
    g_node_count = g_node_cap = 0;
    g_always[0] = g_always[1] = 0;
    g_initialized = 0;
}

const char *mm7_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return "<invalid>";
    return MM88_PATTERNS[id].name;
}

/* ---------- Confirmation via PCRE2 (Stage 1) ---------------------------- */

/*
 * PCRE2 match data is allocated per-call here (pcre2_match_data_create_from_pattern).
 * This is simple and correct; a per-thread pre-allocated match_data would be
 * faster but adds state.  Profile first before optimising.
 */
static int confirm_at_pcre2(int p, const char *input, size_t len,
                             size_t pos, size_t *out_start, size_t *out_len) {
    pcre2_match_data *md = pcre2_match_data_create_from_pattern(g_re[p], NULL);
    if (!md) return 0;

    int rc;
    if (g_use_jit)
        rc = pcre2_jit_match(g_re[p], (PCRE2_SPTR)input, len, pos,
                             PCRE2_NOTEMPTY, md, NULL);
    else
        rc = pcre2_match(g_re[p], (PCRE2_SPTR)input, len, pos,
                         PCRE2_NOTEMPTY, md, NULL);

    if (rc <= 0) { pcre2_match_data_free(md); return 0; }

    PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);

    /* For boundary-wrapped patterns, group 2 is the inner token. */
    int found = 0;
    if (MM88_PATTERNS[p].boundary_wrapped && rc > 2) {
        PCRE2_SIZE so = ov[4], eo = ov[5];   /* group 2 = indices 4,5 */
        if (so != PCRE2_UNSET && eo > so) {
            *out_start = so;
            *out_len   = eo - so;
            found = 1;
        }
    } else {
        PCRE2_SIZE so = ov[0], eo = ov[1];
        if (eo > so) {
            *out_start = so;
            *out_len   = eo - so;
            found = 1;
        }
    }
    pcre2_match_data_free(md);
    return found;
}

/* ---------- Always-candidate confirmation via PCRE2 (Stage 2) ----------- */

/*
 * pcre2_match with offset advances along the string.  We call it in a loop
 * from pos until no match, equivalent to onig_search in v5.
 */
static size_t scan_always_pcre2(int p, const char *input, size_t len __attribute__((unused)),
                                 size_t search_start, size_t search_end,
                                 mm7_match_t *out, size_t max_matches,
                                 size_t written) {
    size_t pos = search_start;
    while (pos < search_end && written < max_matches) {
        pcre2_match_data *md = pcre2_match_data_create_from_pattern(g_re[p], NULL);
        if (!md) break;

        int rc;
        if (g_use_jit)
            rc = pcre2_jit_match(g_re[p], (PCRE2_SPTR)input, search_end, pos,
                                 0, md, NULL);
        else
            rc = pcre2_match(g_re[p], (PCRE2_SPTR)input, search_end, pos,
                             0, md, NULL);

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
        if (pos == 0) break;  /* guard against zero-length match at 0 */
    }
    return written;
}

/* ---------- Scan -------------------------------------------------------- */

size_t mm7_scan(const char *input, size_t len,
                mm7_match_t *out, size_t max_matches) {
    if (!g_initialized) mm7_init(0);

    size_t  written = 0;
    int32_t state   = 0;

    /* Stage 1: prefix-filtered patterns. */
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)input[i];
        state = g_nodes[state].goto_tbl[c];
        if (!BIT_ANY(g_nodes[state].accept_out)) continue;

        for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
            if (!BIT_GET(g_nodes[state].accept_out, p)) continue;

            int32_t walk = state;
            uint8_t plen = 0;
            while (walk != 0) {
                if (BIT_GET(g_nodes[walk].accept, p)) {
                    plen = g_nodes[walk].prefix_len[p];
                    break;
                }
                walk = g_nodes[walk].fail;
            }
            size_t pos = i + 1 - plen;
            size_t try_pos = (MM88_PATTERNS[p].boundary_wrapped && pos > 0)
                             ? pos - 1 : pos;

            size_t mstart, mlen;
            if (!confirm_at_pcre2(p, input, len, try_pos, &mstart, &mlen)) continue;
            if (mlen == 0) continue;
            if (written >= max_matches) return written;
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
        }
    }

    /* Stage 2: always-candidate patterns. */
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        if (!BIT_GET(g_always, p)) continue;

        const char *bm_lit = MM88_PATTERNS[p].bm_literal;

        if (!bm_lit || g_bm[p].pat_len == 0) {
            /* No BM literal — scan full input. */
            written = scan_always_pcre2(p, input, len, 0, len, out, max_matches, written);
        } else {
            /* BM pre-filter then confirm in window. */
            const char *scan_from = input;
            size_t      remaining = len;

            while (remaining > 0 && written < max_matches) {
                const char *hit = bm_search(p, scan_from, remaining);
                if (!hit) break;

                size_t hit_off     = (size_t)(hit - input);
                size_t window_start = hit_off > 4096 ? hit_off - 4096 : 0;
                size_t window_end   = hit_off + g_bm[p].pat_len + 4096;
                if (window_end > len) window_end = len;

                size_t prev_written = written;
                written = scan_always_pcre2(p, input, len, window_start, window_end,
                                             out, max_matches, written);

                if (written > prev_written) {
                    /* Advance past the last match found in this window. */
                    size_t next_off = out[written - 1].start + out[written - 1].length;
                    if (next_off >= len) break;
                    scan_from = input + next_off;
                    remaining = len - next_off;
                } else {
                    /* No match in window — advance past this BM hit. */
                    size_t advance = hit_off + g_bm[p].pat_len;
                    if (advance >= len) break;
                    scan_from = input + advance;
                    remaining = len - advance;
                }
            }
        }
    }

    return written;
}

/* ---------- Smoke test -------------------------------------------------- */

#ifdef MM7_MAIN
int main(void) {
    mm7_init(0);  /* change to 1 to test JIT */
    fprintf(stderr, "trie: %d nodes, JIT: %d\n", g_node_count, g_use_jit);

    const char *cases[] = {
        "key=AKIAIOSFODNN7EXAMPLE end",
        "stripe sk_live_abcdefghijklmnopqrstuvwx end",
        "iban DE89370400440532013000 end",
        "ssn 123-45-6789 end",
        "email foo@bar.com end",
        "ip 10.0.0.1 end",
        "bearer Bearer mytoken12345678 end",
        "pem -----BEGIN RSA PRIVATE KEY----- end",
        "plain text nothing here",
        NULL
    };

    mm7_match_t buf[1024];
    for (int i = 0; cases[i]; i++) {
        size_t n = mm7_scan(cases[i], strlen(cases[i]), buf, 1024);
        printf("[%d] %zu matches: %s\n", i, n, cases[i]);
        for (size_t j = 0; j < n && j < 8; j++) {
            printf("    %-30s pos=%zu len=%zu  '%.*s'\n",
                   mm7_pattern_name(buf[j].pattern_id),
                   buf[j].start, buf[j].length,
                   (int)buf[j].length, cases[i] + buf[j].start);
        }
    }
    mm7_free();
    return 0;
}
#endif
