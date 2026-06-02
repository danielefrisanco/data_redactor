/* Multi-matcher prototype v6 — AC trie + Boyer-Moore + glibc regexec.
 *
 * Same two-stage AC architecture as v2 (matcher2.c) but adds BM infix
 * pre-filter for always-candidate patterns, using glibc regexec (no Onigmo).
 *
 * This answers: "does BM compensate for glibc's slower confirmation engine?"
 * Compared directly with v3 (AC+Onigmo, no BM) and v5 (AC+Onigmo+BM).
 *
 * Build:  make matcher6.so
 * Smoke:  make matcher6 && ./matcher6
 */

#include "matcher6.h"
#include "patterns_generated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <regex.h>

/* ---------- Boundary-wrapper -------------------------------------------- */

#define WRAP_PREFIX  "(^|[^0-9A-Za-z])("
#define WRAP_SUFFIX  ")([^0-9A-Za-z]|$)"
#define MAX_SUBMATCH 4

static char *make_wrapped_regex(const char *core) {
    size_t len = strlen(WRAP_PREFIX) + strlen(core) + strlen(WRAP_SUFFIX) + 1;
    char *buf = malloc(len);
    if (!buf) { perror("malloc"); exit(1); }
    snprintf(buf, len, "%s%s%s", WRAP_PREFIX, core, WRAP_SUFFIX);
    return buf;
}

/* ---------- Compiled patterns ------------------------------------------- */

static regex_t g_re[MM88_NUM_PATTERNS];
static int     g_compiled_ok = 0;

static void compile_patterns(void) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *src = MM88_PATTERNS[p].regex;
        char *to_free = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped)
            src = to_free = make_wrapped_regex(src);
        int rc = regcomp(&g_re[p], src, REG_EXTENDED);
        free(to_free);
        if (rc != 0) {
            char err[256]; regerror(rc, &g_re[p], err, sizeof(err));
            fprintf(stderr, "regcomp failed for %s: %s\n", MM88_PATTERNS[p].name, err);
            exit(1);
        }
    }
    g_compiled_ok = 1;
}

/* ---------- Boyer-Moore shift tables ------------------------------------ */

typedef struct { size_t shift[256]; size_t pat_len; const char *pat; } bm_t;
static bm_t g_bm[MM88_NUM_PATTERNS];

static void bm_build(int p) {
    const char *lit = MM88_PATTERNS[p].bm_literal;
    if (!lit) { g_bm[p].pat = NULL; g_bm[p].pat_len = 0; return; }
    size_t m = strlen(lit);
    g_bm[p].pat = lit; g_bm[p].pat_len = m;
    for (int c = 0; c < 256; c++) g_bm[p].shift[c] = m;
    for (size_t i = 0; i < m - 1; i++)
        g_bm[p].shift[(unsigned char)lit[i]] = m - 1 - i;
}

static const char *bm_search(int p, const char *hay, size_t len) {
    const bm_t *bm = &g_bm[p];
    const char *pat = bm->pat;
    size_t m = bm->pat_len;
    if (!pat || m == 0) return hay;
    if (m > len) return NULL;
    size_t i = m - 1;
    while (i < len) {
        size_t j = m - 1, k = i;
        while (j != (size_t)-1 && hay[k] == pat[j]) {
            if (j == 0) break; k--; j--;
        }
        if (j == (size_t)-1 || (j == 0 && hay[k] == pat[0])) return hay + k;
        i += bm->shift[(unsigned char)hay[i]];
    }
    return NULL;
}

/* ---------- Aho-Corasick ------------------------------------------------ */

typedef struct ac_node {
    int32_t  goto_tbl[256];
    int32_t  fail;
    uint64_t accept[2];
    uint64_t accept_out[2];
    uint8_t  prefix_len[MM88_NUM_PATTERNS];
} ac_node_t;

static ac_node_t *g_nodes = NULL;
static int32_t    g_node_count = 0, g_node_cap = 0;
static uint64_t   g_always[2] = {0, 0};

#define BIT_SET(a,i)  ((a)[(i)/64]|=(uint64_t)1<<((i)%64))
#define BIT_GET(a,i)  (!!((a)[(i)/64]&((uint64_t)1<<((i)%64))))
#define BIT_OR(d,s)   do{(d)[0]|=(s)[0];(d)[1]|=(s)[1];}while(0)
#define BIT_ANY(a)    ((a)[0]||(a)[1])

static int32_t ac_new_node(void) {
    if (g_node_count == g_node_cap) {
        g_node_cap = g_node_cap ? g_node_cap * 2 : 128;
        g_nodes = realloc(g_nodes, (size_t)g_node_cap * sizeof(ac_node_t));
        if (!g_nodes) { perror("realloc"); exit(1); }
    }
    ac_node_t *n = &g_nodes[g_node_count];
    for (int i = 0; i < 256; i++) n->goto_tbl[i] = -1;
    n->fail = 0;
    n->accept[0] = n->accept[1] = n->accept_out[0] = n->accept_out[1] = 0;
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

void mm6_init(void) {
    if (g_initialized) return;
    ac_new_node();
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *pref = MM88_PATTERNS[p].prefix;
        if (!pref) BIT_SET(g_always, p);
        else ac_insert(pref, p);
    }
    ac_build_failure();
    compile_patterns();
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) bm_build(p);
    g_initialized = 1;
}

void mm6_free(void) {
    if (g_compiled_ok) {
        for (int p = 0; p < MM88_NUM_PATTERNS; p++) regfree(&g_re[p]);
        g_compiled_ok = 0;
    }
    free(g_nodes); g_nodes = NULL;
    g_node_count = g_node_cap = 0;
    g_always[0] = g_always[1] = 0;
    g_initialized = 0;
}

const char *mm6_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return "<invalid>";
    return MM88_PATTERNS[id].name;
}

/* ---------- Confirmation via glibc regexec ------------------------------ */

static int confirm_at(int p, const char *input, size_t pos,
                      size_t *out_start, size_t *out_len) {
    regmatch_t m[MAX_SUBMATCH];
    int rc = regexec(&g_re[p], input + pos, MAX_SUBMATCH, m,
                     pos > 0 ? REG_NOTBOL : 0);
    if (rc != 0 || m[0].rm_so != 0) return 0;
    if (MM88_PATTERNS[p].boundary_wrapped) {
        if (m[2].rm_so < 0) return 0;
        *out_start = pos + (size_t)m[2].rm_so;
        *out_len   = (size_t)(m[2].rm_eo - m[2].rm_so);
    } else {
        *out_start = pos + (size_t)m[0].rm_so;
        *out_len   = (size_t)(m[0].rm_eo - m[0].rm_so);
    }
    return 1;
}

/* ---------- Scan -------------------------------------------------------- */

size_t mm6_scan(const char *input, size_t len,
                mm6_match_t *out, size_t max_matches) {
    if (!g_initialized) mm6_init();

    size_t  written = 0;
    int32_t state   = 0;

    /* Stage 1: prefix-filtered patterns via AC + glibc regexec (same as v2). */
    for (size_t i = 0; i < len; i++) {
        state = g_nodes[state].goto_tbl[(uint8_t)input[i]];
        if (!BIT_ANY(g_nodes[state].accept_out)) continue;

        for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
            if (!BIT_GET(g_nodes[state].accept_out, p)) continue;
            int32_t walk = state; uint8_t plen = 0;
            while (walk != 0) {
                if (BIT_GET(g_nodes[walk].accept, p)) { plen = g_nodes[walk].prefix_len[p]; break; }
                walk = g_nodes[walk].fail;
            }
            size_t pos = i + 1 - plen;
            size_t try_pos = (MM88_PATTERNS[p].boundary_wrapped && pos > 0) ? pos - 1 : pos;
            size_t mstart, mlen;
            if (!confirm_at(p, input, try_pos, &mstart, &mlen) || mlen == 0) continue;
            if (written >= max_matches) return written;
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
        }
    }

    /* Stage 2: always-candidates — BM infix pre-filter + glibc regexec. */
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        if (!BIT_GET(g_always, p)) continue;

        const char *bm_lit = MM88_PATTERNS[p].bm_literal;

        if (!bm_lit || g_bm[p].pat_len == 0) {
            /* No BM literal: plain regexec over the whole input. */
            size_t pos = 0;
            while (pos < len) {
                regmatch_t m[MAX_SUBMATCH];
                int rc = regexec(&g_re[p], input + pos, MAX_SUBMATCH, m,
                                 pos > 0 ? REG_NOTBOL : 0);
                if (rc != 0) break;
                size_t mstart, mlen;
                if (MM88_PATTERNS[p].boundary_wrapped) {
                    if (m[2].rm_so < 0) { pos++; continue; }
                    mstart = pos + (size_t)m[2].rm_so;
                    mlen   = (size_t)(m[2].rm_eo - m[2].rm_so);
                } else {
                    if (m[0].rm_eo <= m[0].rm_so) { pos++; continue; }
                    mstart = pos + (size_t)m[0].rm_so;
                    mlen   = (size_t)(m[0].rm_eo - m[0].rm_so);
                }
                if (written >= max_matches) return written;
                out[written].pattern_id = p;
                out[written].start      = mstart;
                out[written].length     = mlen;
                written++;
                pos = mstart + mlen;
            }
        } else {
            /* BM pre-filter: find each occurrence of bm_literal, confirm with regexec. */
            const char *scan_from = input;
            size_t      remaining = len;

            while (remaining > 0) {
                const char *hit = bm_search(p, scan_from, remaining);
                if (!hit) break;

                size_t hit_off = (size_t)(hit - input);
                size_t window_start = hit_off > 4096 ? hit_off - 4096 : 0;
                size_t window_end   = hit_off + g_bm[p].pat_len + 4096;
                if (window_end > len) window_end = len;

                /* regexec from window_start, searching up to window_end. */
                /* We can't limit regexec's right end, so we scan from window_start. */
                size_t pos = window_start;
                regmatch_t m[MAX_SUBMATCH];
                int rc = regexec(&g_re[p], input + pos, MAX_SUBMATCH, m,
                                 pos > 0 ? REG_NOTBOL : 0);
                if (rc != 0) {
                    size_t advance = hit_off + g_bm[p].pat_len;
                    if (advance >= len) break;
                    scan_from = input + advance; remaining = len - advance;
                    continue;
                }

                size_t mstart, mlen;
                if (MM88_PATTERNS[p].boundary_wrapped) {
                    if (m[2].rm_so < 0) {
                        size_t adv = hit_off + 1;
                        if (adv >= len) break;
                        scan_from = input + adv; remaining = len - adv; continue;
                    }
                    mstart = pos + (size_t)m[2].rm_so;
                    mlen   = (size_t)(m[2].rm_eo - m[2].rm_so);
                } else {
                    if (m[0].rm_eo <= m[0].rm_so) {
                        size_t adv = hit_off + 1;
                        if (adv >= len) break;
                        scan_from = input + adv; remaining = len - adv; continue;
                    }
                    mstart = pos + (size_t)m[0].rm_so;
                    mlen   = (size_t)(m[0].rm_eo - m[0].rm_so);
                }

                /* Verify the BM literal is actually inside this match (not before it). */
                if (hit_off < mstart || hit_off >= mstart + mlen) {
                    /* The literal was before the match window — advance past hit. */
                    size_t adv = hit_off + 1;
                    if (adv >= len) break;
                    scan_from = input + adv; remaining = len - adv; continue;
                }

                if (written >= max_matches) return written;
                out[written].pattern_id = p;
                out[written].start      = mstart;
                out[written].length     = mlen;
                written++;

                size_t next_off = mstart + mlen;
                if (next_off >= len) break;
                scan_from = input + next_off; remaining = len - next_off;
            }
        }
    }

    return written;
}

/* ---------- Smoke test -------------------------------------------------- */

#ifdef MM6_MAIN
int main(void) {
    mm6_init();
    fprintf(stderr, "trie: %d nodes\n", g_node_count);

    const char *cases[] = {
        "key=AKIAIOSFODNN7EXAMPLE end",
        "stripe sk_live_abcdefghijklmnopqrstuvwx end",
        "ssn 123-45-6789 end",
        "email foo@bar.com end",
        "ip 10.0.0.1 end",
        "bearer Bearer mytoken12345678 end",
        "pem -----BEGIN RSA PRIVATE KEY----- end",
        "plain text nothing here",
        NULL
    };

    /* regexec requires NUL-terminated input */
    mm6_match_t buf[1024];
    for (int i = 0; cases[i]; i++) {
        char tmp[4096];
        strncpy(tmp, cases[i], sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';
        size_t n = mm6_scan(tmp, strlen(tmp), buf, 1024);
        printf("[%d] %zu matches: %s\n", i, n, cases[i]);
        for (size_t j = 0; j < n && j < 8; j++)
            printf("    %-30s pos=%zu len=%zu\n",
                   mm6_pattern_name(buf[j].pattern_id), buf[j].start, buf[j].length);
    }
    mm6_free();
    return 0;
}
#endif
