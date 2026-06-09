/* Multi-matcher prototype v2 — 88 patterns driven from patterns_generated.h.
 *
 * Option B from docs/combined_matcher_plan.md: same AC + regexec architecture
 * as matcher.c but covering all 88 gem patterns, including boundary-wrapped
 * ones. Used to:
 *   1. Validate correctness vs DataRedactor.scan at full pattern set.
 *   2. Benchmark the approach at realistic scale.
 *   3. Serve as the comparison baseline for Option A (AC + Onigmo).
 *
 * Build:  make matcher2.so
 * Smoke:  make matcher2 && ./matcher2
 */

#include "matcher2.h"
#include "patterns_generated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <regex.h>

/* ---------- Boundary-wrapper -----------------------------------------------
 *
 * For boundary_wrapped patterns, the compiled regex is:
 *   (^|[^0-9A-Za-z])(PATTERN)([^0-9A-Za-z]|$)
 *
 * rm_so/rm_eo of sub-match [2] (1-indexed group 2) is the actual token span.
 * We compile with REG_EXTENDED and request 4 sub-matches (full + 3 groups). */

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

/* ---------- Compiled patterns -------------------------------------------- */

static regex_t g_compiled[MM88_NUM_PATTERNS];
static int     g_compiled_ok = 0;

static void compile_patterns(void) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *src = MM88_PATTERNS[p].regex;
        char *to_free = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped) {
            src = to_free = make_wrapped_regex(src);
        }
        int rc = regcomp(&g_compiled[p], src, REG_EXTENDED);
        free(to_free);
        if (rc != 0) {
            char err[256];
            regerror(rc, &g_compiled[p], err, sizeof(err));
            fprintf(stderr, "regcomp failed for %s: %s\n",
                    MM88_PATTERNS[p].name, err);
            exit(1);
        }
    }
    g_compiled_ok = 1;
}

/* ---------- Aho-Corasick -------------------------------------------------- */

typedef struct ac_node {
    int32_t  goto_tbl[256];
    int32_t  fail;
    uint64_t accept[2];     /* two words for 128 bits — we have 88 patterns */
    uint64_t accept_out[2];
    uint8_t  prefix_len[MM88_NUM_PATTERNS];
} ac_node_t;

static ac_node_t *g_nodes = NULL;
static int32_t    g_node_count = 0;
static int32_t    g_node_cap   = 0;

/* Bitmask helpers for two-word 128-bit sets */
#define BIT_SET(arr, i)   ((arr)[(i)/64] |=  (uint64_t)1 << ((i)%64))
#define BIT_CLR(arr, i)   ((arr)[(i)/64] &= ~((uint64_t)1 << ((i)%64)))
#define BIT_GET(arr, i)   (!!((arr)[(i)/64] &  ((uint64_t)1 << ((i)%64))))
#define BIT_OR(dst, src)  do { (dst)[0] |= (src)[0]; (dst)[1] |= (src)[1]; } while(0)
#define BIT_ANY(arr)      ((arr)[0] || (arr)[1])

/* Bitmask of patterns that run at every position (no prefix) */
static uint64_t g_always[2] = {0, 0};

static int32_t ac_new_node(void) {
    if (g_node_count == g_node_cap) {
        g_node_cap = g_node_cap ? g_node_cap * 2 : 128;
        g_nodes = realloc(g_nodes, (size_t)g_node_cap * sizeof(ac_node_t));
        if (!g_nodes) { perror("realloc"); exit(1); }
    }
    ac_node_t *n = &g_nodes[g_node_count];
    for (int i = 0; i < 256; i++) n->goto_tbl[i] = -1;
    n->fail       = 0;
    n->accept[0]  = n->accept[1]  = 0;
    n->accept_out[0] = n->accept_out[1] = 0;
    memset(n->prefix_len, 0, sizeof(n->prefix_len));
    return g_node_count++;
}

static void ac_insert(const char *s, int pid) {
    int32_t cur = 0;
    size_t  n   = strlen(s);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)s[i];
        if (g_nodes[cur].goto_tbl[c] == -1) {
            /* Assign to a local first: ac_new_node may realloc g_nodes,
             * so we must not use a pre-computed &g_nodes[cur] on the LHS. */
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
        if (nx == -1) {
            g_nodes[0].goto_tbl[c] = 0;
        } else {
            g_nodes[nx].fail = 0;
            queue[qt++] = nx;
        }
    }

    while (qh < qt) {
        int32_t u = queue[qh++];
        BIT_OR(g_nodes[u].accept_out, g_nodes[u].accept);
        BIT_OR(g_nodes[u].accept_out, g_nodes[g_nodes[u].fail].accept_out);

        for (int c = 0; c < 256; c++) {
            int32_t v = g_nodes[u].goto_tbl[c];
            if (v == -1) {
                g_nodes[u].goto_tbl[c] = g_nodes[g_nodes[u].fail].goto_tbl[c];
            } else {
                g_nodes[v].fail = g_nodes[g_nodes[u].fail].goto_tbl[c];
                queue[qt++] = v;
            }
        }
    }
    free(queue);
}

/* ---------- Init / free --------------------------------------------------- */

static int g_initialized = 0;

void mm88_init(void) {
    if (g_initialized) return;
    ac_new_node(); /* root = 0 */

    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *pref = MM88_PATTERNS[p].prefix;
        /* prefix is already NULL for infix-prefix patterns (gen_patterns.rb
         * sets ac_prefix=nil for those), so they naturally become always-candidate. */
        if (!pref) {
            BIT_SET(g_always, p);
        } else {
            ac_insert(pref, p);
        }
    }
    ac_build_failure();
    compile_patterns();
    g_initialized = 1;
}

void mm88_free(void) {
    if (g_compiled_ok) {
        for (int p = 0; p < MM88_NUM_PATTERNS; p++) regfree(&g_compiled[p]);
        g_compiled_ok = 0;
    }
    free(g_nodes);
    g_nodes = NULL;
    g_node_count = g_node_cap = 0;
    g_always[0] = g_always[1] = 0;
    g_initialized = 0;
}

const char *mm88_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return "<invalid>";
    return MM88_PATTERNS[id].name;
}

/* ---------- Confirmation -------------------------------------------------- */

/* Run pattern p anchored at `pos` in `input` (length `len`, NUL-terminated).
 * For boundary-wrapped patterns the full match includes surrounding chars;
 * we return the inner group 2 span instead. Returns 0 on no-match. */
static int confirm_at(int p, const char *input, size_t pos,
                      size_t *out_start, size_t *out_len) {
    regmatch_t m[MAX_SUBMATCH];
    int rc = regexec(&g_compiled[p], input + pos,
                     MAX_SUBMATCH, m, pos > 0 ? REG_NOTBOL : 0);
    if (rc != 0) return 0;
    if (m[0].rm_so != 0) return 0;

    if (MM88_PATTERNS[p].boundary_wrapped) {
        /* Group 2 (index 2) is the inner token. */
        if (m[2].rm_so < 0) return 0;
        *out_start = pos + (size_t)m[2].rm_so;
        *out_len   = (size_t)(m[2].rm_eo - m[2].rm_so);
    } else {
        *out_start = pos + (size_t)m[0].rm_so;
        *out_len   = (size_t)(m[0].rm_eo - m[0].rm_so);
    }
    return 1;
}

/* ---------- Scan ---------------------------------------------------------- */

size_t mm88_scan(const char *input, size_t len,
                 mm88_match_t *out, size_t max_matches) {
    if (!g_initialized) mm88_init();

    /* Input must be NUL-terminated for regexec. Callers are responsible. */
    size_t written = 0;
    int32_t state = 0;

    /* Stage 1: prefix-filtered patterns via AC walk. */
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)input[i];
        state = g_nodes[state].goto_tbl[c];

        if (!BIT_ANY(g_nodes[state].accept_out)) continue;

        for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
            if (!BIT_GET(g_nodes[state].accept_out, p)) continue;

            /* Find the accepting node to retrieve prefix_len. */
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
            /* For boundary-wrapped patterns we may need to start one byte
             * earlier to allow the boundary character to match. */
            size_t try_pos = (MM88_PATTERNS[p].boundary_wrapped && pos > 0)
                             ? pos - 1 : pos;

            size_t mstart, mlen;
            if (!confirm_at(p, input, try_pos, &mstart, &mlen)) continue;
            if (mlen == 0) continue;
            if (written >= max_matches) return written;
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
        }
    }

    /* Stage 2: always-candidate patterns, scan forward via regexec. */
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        if (!BIT_GET(g_always, p)) continue;
        size_t pos = 0;
        while (pos < len) {
            regmatch_t m[MAX_SUBMATCH];
            int eflags = (pos > 0) ? REG_NOTBOL : 0;
            int rc = regexec(&g_compiled[p], input + pos, MAX_SUBMATCH, m, eflags);
            if (rc != 0) break;

            size_t mstart, mlen;
            if (MM88_PATTERNS[p].boundary_wrapped) {
                if (m[2].rm_so < 0) { pos += (size_t)m[0].rm_eo; continue; }
                mstart = pos + (size_t)m[2].rm_so;
                mlen   = (size_t)(m[2].rm_eo - m[2].rm_so);
            } else {
                mstart = pos + (size_t)m[0].rm_so;
                mlen   = (size_t)(m[0].rm_eo - m[0].rm_so);
            }
            if (mlen == 0) { pos = mstart + 1; continue; }
            if (written >= max_matches) return written;
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
            pos = mstart + mlen;
        }
    }

    return written;
}

/* ---------- Smoke test ---------------------------------------------------- */

#ifdef MM88_MAIN
int main(void) {
    mm88_init();
    fprintf(stderr, "trie: %d nodes, always-candidate: ", g_node_count);
    int ac_count = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++)
        if (BIT_GET(g_always, p)) ac_count++;
    fprintf(stderr, "%d patterns\n", ac_count);

    const char *cases[] = {
        "key=AKIAIOSFODNN7EXAMPLE end",
        "stripe sk_live_abcdefghijklmnopqrstuvwx end",
        "iban DE89370400440532013000 end",
        "pesel 12345678901 end",
        "ssn 123-45-6789 end",
        "email foo@bar.com end",
        "ip 10.0.0.1 end",
        "pem -----BEGIN RSA PRIVATE KEY----- end",
        "plain text nothing here",
        NULL
    };

    mm88_match_t buf[1024];
    for (int i = 0; cases[i]; i++) {
        size_t n = mm88_scan(cases[i], strlen(cases[i]), buf, 1024);
        printf("[%d] %zu matches: %s\n", i, n, cases[i]);
        for (size_t j = 0; j < n && j < 8; j++) {
            printf("    %-30s pos=%zu len=%zu  '%.*s'\n",
                   mm88_pattern_name(buf[j].pattern_id),
                   buf[j].start, buf[j].length,
                   (int)buf[j].length, cases[i] + buf[j].start);
        }
    }
    mm88_free();
    return 0;
}
#endif
