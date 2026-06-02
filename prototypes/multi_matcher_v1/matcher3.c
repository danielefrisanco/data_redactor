/* Multi-matcher prototype v3 — Option A: AC trie + Onigmo confirmation.
 *
 * Same architecture as matcher2.c but replaces glibc regexec with Onigmo
 * (the regex engine Ruby uses for gsub). This is the "ceiling" measurement:
 * if we can't beat pure-Ruby gsub with the same engine Ruby uses, the AC
 * trie approach is not the answer for always-candidate patterns.
 *
 * Linking: requires libruby.so (exports onig_* symbols) + Onigmo headers.
 * See Makefile target matcher3.so.
 *
 * Build:  make matcher3.so
 * Smoke:  make matcher3 && ./matcher3
 */

#include "matcher3.h"
#include "patterns_generated.h"

#include <oniguruma.h>

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

static OnigRegex g_onig[MM88_NUM_PATTERNS];
static int       g_compiled_ok = 0;

static void compile_patterns(void) {
    onig_init();
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *src = MM88_PATTERNS[p].regex;
        char *to_free = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped) {
            src = to_free = make_wrapped_regex(src);
        }
        OnigErrorInfo einfo;
        int rc = onig_new(&g_onig[p],
                          (const OnigUChar *)src,
                          (const OnigUChar *)(src + strlen(src)),
                          ONIG_OPTION_NONE,
                          ONIG_ENCODING_ASCII,
                          ONIG_SYNTAX_RUBY,  /* same engine Ruby gsub uses */
                          &einfo);
        free(to_free);
        if (rc != ONIG_NORMAL) {
            OnigUChar err[ONIG_MAX_ERROR_MESSAGE_LEN];
            onig_error_code_to_str(err, rc, &einfo);
            fprintf(stderr, "onig_new failed for %s: %s\n",
                    MM88_PATTERNS[p].name, err);
            exit(1);
        }
    }
    g_compiled_ok = 1;
}

/* ---------- Aho-Corasick (identical to matcher2.c) ---------------------- */

typedef struct ac_node {
    int32_t  goto_tbl[256];
    int32_t  fail;
    uint64_t accept[2];
    uint64_t accept_out[2];
    uint8_t  prefix_len[MM88_NUM_PATTERNS];
} ac_node_t;

static ac_node_t *g_nodes = NULL;
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

/* ---------- Init / free ------------------------------------------------- */

static int g_initialized = 0;

void mm3_init(void) {
    if (g_initialized) return;
    ac_new_node();
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *pref = MM88_PATTERNS[p].prefix;
        if (!pref) BIT_SET(g_always, p);
        else ac_insert(pref, p);
    }
    ac_build_failure();
    compile_patterns();
    g_initialized = 1;
}

void mm3_free(void) {
    if (g_compiled_ok) {
        for (int p = 0; p < MM88_NUM_PATTERNS; p++) onig_free(g_onig[p]);
        onig_end();
        g_compiled_ok = 0;
    }
    free(g_nodes); g_nodes = NULL;
    g_node_count = g_node_cap = 0;
    g_always[0] = g_always[1] = 0;
    g_initialized = 0;
}

const char *mm3_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return "<invalid>";
    return MM88_PATTERNS[id].name;
}

/* ---------- Confirmation via Onigmo ------------------------------------- */

/* Use onig_match (anchored at `pos`) for prefix-filtered candidates.
 * For boundary-wrapped patterns we try one byte earlier and extract group 2.
 * Returns 1 on confirmed match, 0 otherwise. */
static int confirm_at_onig(int p, const char *input, size_t len,
                            size_t pos, size_t *out_start, size_t *out_len) {
    const OnigUChar *str   = (const OnigUChar *)input;
    const OnigUChar *end   = str + len;
    const OnigUChar *at    = str + pos;

    OnigRegion *region = onig_region_new();
    if (!region) return 0;

    int rc = onig_match(g_onig[p], str, end, at, region, ONIG_OPTION_NONE);

    int found = 0;
    if (rc >= 0) {
        if (MM88_PATTERNS[p].boundary_wrapped && region->num_regs > 2) {
            int so = region->beg[2], eo = region->end[2];
            if (so >= 0 && eo > so) {
                *out_start = (size_t)so;
                *out_len   = (size_t)(eo - so);
                found = 1;
            }
        } else {
            *out_start = pos;
            *out_len   = (size_t)rc;
            found = *out_len > 0;
        }
    }
    onig_region_free(region, 1);
    return found;
}

/* ---------- Scan -------------------------------------------------------- */

size_t mm3_scan(const char *input, size_t len,
                mm3_match_t *out, size_t max_matches) {
    if (!g_initialized) mm3_init();

    const OnigUChar *str = (const OnigUChar *)input;
    const OnigUChar *end = str + len;

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
            if (!confirm_at_onig(p, input, len, try_pos, &mstart, &mlen)) continue;
            if (mlen == 0) continue;
            if (written >= max_matches) return written;
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
        }
    }

    /* Stage 2: always-candidate patterns via onig_search (finds next match). */
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        if (!BIT_GET(g_always, p)) continue;

        const OnigUChar *pos = str;
        while (pos < end) {
            OnigRegion *region = onig_region_new();
            if (!region) break;

            int rc = onig_search(g_onig[p], str, end, pos, end, region,
                                 ONIG_OPTION_NONE);
            if (rc < 0) { onig_region_free(region, 1); break; }

            size_t mstart, mlen;
            if (MM88_PATTERNS[p].boundary_wrapped && region->num_regs > 2) {
                int so = region->beg[2], eo = region->end[2];
                onig_region_free(region, 1);
                if (so < 0 || eo <= so) { pos++; continue; }
                mstart = (size_t)so;
                mlen   = (size_t)(eo - so);
            } else {
                int so = region->beg[0], eo = region->end[0];
                onig_region_free(region, 1);
                if (eo <= so) { pos++; continue; }
                mstart = (size_t)so;
                mlen   = (size_t)(eo - so);
            }

            if (written >= max_matches) return written;
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
            pos = str + mstart + mlen;
        }
    }

    return written;
}

/* ---------- Smoke test -------------------------------------------------- */

#ifdef MM3_MAIN
int main(void) {
    mm3_init();
    fprintf(stderr, "trie: %d nodes\n", g_node_count);

    const char *cases[] = {
        "key=AKIAIOSFODNN7EXAMPLE end",
        "stripe sk_live_abcdefghijklmnopqrstuvwx end",
        "iban DE89370400440532013000 end",
        "ssn 123-45-6789 end",
        "email foo@bar.com end",
        "ip 10.0.0.1 end",
        "pem -----BEGIN RSA PRIVATE KEY----- end",
        "plain text nothing here",
        NULL
    };

    mm3_match_t buf[1024];
    for (int i = 0; cases[i]; i++) {
        size_t n = mm3_scan(cases[i], strlen(cases[i]), buf, 1024);
        printf("[%d] %zu matches: %s\n", i, n, cases[i]);
        for (size_t j = 0; j < n && j < 8; j++) {
            printf("    %-30s pos=%zu len=%zu  '%.*s'\n",
                   mm3_pattern_name(buf[j].pattern_id),
                   buf[j].start, buf[j].length,
                   (int)buf[j].length, cases[i] + buf[j].start);
        }
    }
    mm3_free();
    return 0;
}
#endif
