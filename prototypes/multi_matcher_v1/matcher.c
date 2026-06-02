/* Multi-matcher prototype v1 — Slice 1: Aho-Corasick trie of literal
 * prefixes. Slice 2 will bolt regexec confirmation on top.
 *
 * Hardcoded for the 10 patterns from docs/multi_matcher_prototype_plan.md.
 *
 * Build:  make matcher.so
 * Smoke:  make matcher && ./matcher
 */

#include "matcher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <regex.h>

/* ---------- Pattern table -------------------------------------------------
 *
 * For each pattern: a name (diagnostic), and zero or more literal
 * prefixes. Patterns with no prefix are flagged "always-candidate";
 * the scanner emits them at every position (Slice 2 will run regexec
 * for them everywhere — same as today's engine).
 *
 * Pattern IDs are array indices; keep stable. */

typedef struct {
    const char *name;
    const char **prefixes;   /* NULL-terminated, or NULL if none */
    const char *regex;       /* POSIX ERE, sourced from ext/data_redactor/patterns.c */
} pattern_def_t;

/* Pattern 0: aws_access_key_id — multi-prefix alternation. */
static const char *prefixes_aws[] = {
    "AKIA", "ASIA", "AROA", "AIDA", "AGPA", "ANPA", "ANVA",
    "A3T", "ABIA", "ACCA",
    NULL
};

/* Pattern 1: email — no useful literal prefix. */

/* Pattern 2: ipv4 — pure digits, no prefix. */

/* Pattern 3: credit_card — pure digit alternation, no prefix. */

/* Pattern 4: slack_webhook_url. */
static const char *prefixes_slack[] = {
    "https://hooks.slack.com/services/",
    NULL
};

/* Pattern 5: stripe_secret_key. */
static const char *prefixes_stripe[] = {
    "sk_live_",
    NULL
};

/* Pattern 6: iban_de. */
static const char *prefixes_iban_de[] = {
    "DE",
    NULL
};

/* Pattern 7: polish_pesel — pure digits. */

/* Pattern 8: pem_private_key. */
static const char *prefixes_pem[] = {
    "-----BEGIN ",
    NULL
};

/* Pattern 9: gpg_private_key — shares -----BEGIN prefix with pem.
 * Listed as the longer form so the trie demonstrates shared-prefix
 * savings (both end up sharing the "-----BEGIN " path). */
static const char *prefixes_gpg[] = {
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    NULL
};

static const pattern_def_t PATTERNS[MM_NUM_PATTERNS] = {
    {"aws_access_key_id", prefixes_aws,
     "(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z2-7]{16}"},
    {"email",             NULL,
     "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"},
    {"ipv4",              NULL,
     "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"},
    {"credit_card",       NULL,
     "(4[0-9]{15}|4[0-9]{12}|5[1-5][0-9]{14}|6011[0-9]{12}|65[0-9]{14}|3[47][0-9]{13}|3[068][0-9]{11}|35[0-9]{14})"},
    {"slack_webhook_url", prefixes_slack,
     "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}"},
    {"stripe_secret_key", prefixes_stripe,
     "sk_live_[0-9a-zA-Z]{24}"},
    {"iban_de",           prefixes_iban_de,
     "DE[0-9]{2}[0-9]{18}"},
    {"polish_pesel",      NULL,
     "[0-9]{11}"},
    {"pem_private_key",   prefixes_pem,
     "-----BEGIN [A-Z ]*PRIVATE KEY-----"},
    {"gpg_private_key",   prefixes_gpg,
     "-----BEGIN PGP PRIVATE KEY BLOCK-----"},
};

static regex_t g_compiled[MM_NUM_PATTERNS];
static int g_compiled_ok = 0;

const char *mm_pattern_name(int id) {
    if (id < 0 || id >= MM_NUM_PATTERNS) return "<invalid>";
    return PATTERNS[id].name;
}

/* ---------- Aho-Corasick automaton ---------------------------------------
 *
 * Byte alphabet (0..255). Each node has a 256-slot goto table (allocated
 * lazily as a flat array per node — small N, simple wins over compact).
 * Failure links via BFS. Each node carries a bitmask of accepting
 * pattern IDs (MM_NUM_PATTERNS <= 64, so uint64_t suffices). */

typedef struct ac_node {
    int32_t goto_tbl[256];   /* -1 = no edge */
    int32_t fail;            /* failure link (node index) */
    uint64_t accept;         /* bitmask of accepting pattern IDs */
    uint64_t accept_out;     /* accept | (accept_out of fail chain) */
    uint8_t prefix_len[64];  /* per-pattern: prefix length matched here.
                                Only meaningful for bits set in accept. */
} ac_node_t;

static ac_node_t *g_nodes = NULL;
static int32_t g_node_count = 0;
static int32_t g_node_cap = 0;

/* Patterns that are "always candidate" (no prefix). Bitmask. */
static uint64_t g_always_candidate = 0;

static int32_t ac_new_node(void) {
    if (g_node_count == g_node_cap) {
        g_node_cap = g_node_cap ? g_node_cap * 2 : 64;
        g_nodes = realloc(g_nodes, (size_t)g_node_cap * sizeof(ac_node_t));
        if (!g_nodes) { perror("realloc"); exit(1); }
    }
    ac_node_t *n = &g_nodes[g_node_count];
    for (int i = 0; i < 256; i++) n->goto_tbl[i] = -1;
    n->fail = 0;
    n->accept = 0;
    n->accept_out = 0;
    memset(n->prefix_len, 0, sizeof(n->prefix_len));
    return g_node_count++;
}

static void ac_insert(const char *s, int pattern_id) {
    int32_t cur = 0;  /* root */
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)s[i];
        if (g_nodes[cur].goto_tbl[c] == -1) {
            int32_t nx = ac_new_node();
            g_nodes[cur].goto_tbl[c] = nx;
        }
        cur = g_nodes[cur].goto_tbl[c];
    }
    g_nodes[cur].accept |= (uint64_t)1 << pattern_id;
    if (n > 255) n = 255;
    g_nodes[cur].prefix_len[pattern_id] = (uint8_t)n;
}

/* Simple ring queue for BFS. */
static void ac_build_failure(void) {
    int32_t *queue = malloc((size_t)g_node_count * sizeof(int32_t));
    if (!queue) { perror("malloc"); exit(1); }
    int qh = 0, qt = 0;

    /* Root's direct children: fail = root. */
    for (int c = 0; c < 256; c++) {
        int32_t nx = g_nodes[0].goto_tbl[c];
        if (nx == -1) {
            g_nodes[0].goto_tbl[c] = 0;   /* root self-loop on miss */
        } else {
            g_nodes[nx].fail = 0;
            queue[qt++] = nx;
        }
    }

    while (qh < qt) {
        int32_t u = queue[qh++];
        g_nodes[u].accept_out = g_nodes[u].accept | g_nodes[g_nodes[u].fail].accept_out;

        for (int c = 0; c < 256; c++) {
            int32_t v = g_nodes[u].goto_tbl[c];
            if (v == -1) {
                /* Path-compress: fold failure transition into goto. */
                g_nodes[u].goto_tbl[c] = g_nodes[g_nodes[u].fail].goto_tbl[c];
            } else {
                g_nodes[v].fail = g_nodes[g_nodes[u].fail].goto_tbl[c];
                queue[qt++] = v;
            }
        }
    }
    free(queue);
}

static int g_initialized = 0;

void mm_init(void) {
    if (g_initialized) return;
    ac_new_node();   /* root = node 0 */

    for (int p = 0; p < MM_NUM_PATTERNS; p++) {
        const char **prefs = PATTERNS[p].prefixes;
        if (prefs == NULL) {
            g_always_candidate |= (uint64_t)1 << p;
            continue;
        }
        for (int i = 0; prefs[i] != NULL; i++) {
            ac_insert(prefs[i], p);
        }
    }
    ac_build_failure();

    for (int p = 0; p < MM_NUM_PATTERNS; p++) {
        int rc = regcomp(&g_compiled[p], PATTERNS[p].regex, REG_EXTENDED);
        if (rc != 0) {
            char err[256];
            regerror(rc, &g_compiled[p], err, sizeof(err));
            fprintf(stderr, "regcomp failed for %s: %s\n", PATTERNS[p].name, err);
            exit(1);
        }
    }
    g_compiled_ok = 1;
    g_initialized = 1;
}

void mm_free(void) {
    if (g_compiled_ok) {
        for (int p = 0; p < MM_NUM_PATTERNS; p++) regfree(&g_compiled[p]);
        g_compiled_ok = 0;
    }
    free(g_nodes);
    g_nodes = NULL;
    g_node_count = 0;
    g_node_cap = 0;
    g_always_candidate = 0;
    g_initialized = 0;
}

/* Run pattern `p`'s compiled regex anchored at position `pos` in `input`.
 * POSIX has no "anchored" flag; we approximate by feeding the substring
 * starting at `pos` and accepting only matches with rm_so == 0.
 *
 * `len` is total input length; we pass `len - pos` via the eflags trick
 * (POSIX regexec walks until NUL, so we rely on input being NUL-terminated
 * or being a contiguous buffer with NUL at len). Caller guarantees this.
 *
 * Returns match length on success, 0 on no-match-at-pos. */
static size_t confirm_at(int p, const char *input, size_t pos) {
    regmatch_t m[1];
    int rc = regexec(&g_compiled[p], input + pos, 1, m, 0);
    if (rc != 0) return 0;
    if (m[0].rm_so != 0) return 0;
    return (size_t)(m[0].rm_eo - m[0].rm_so);
}

/* ---------- Scan ---------------------------------------------------------
 *
 * Walks the input once; at each position emits prefix-match hits.
 * For "always-candidate" patterns we emit one hit per position with
 * length=0 — Slice 2 will run regexec there to confirm or reject.
 *
 * Slice 1 caveat: the always-candidate emission is what makes this
 * comparable to today's engine for #2/#3/#4/#8. The speed win comes
 * from the *other* 6 patterns being filtered.
 */
size_t mm_scan(const char *input, size_t len,
               mm_match_t *out, size_t max_matches) {
    if (!g_initialized) mm_init();
    size_t written = 0;
    int32_t state = 0;

    /* Stage 1: AC walk. For each prefix-hit, run regexec to confirm. */
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)input[i];
        state = g_nodes[state].goto_tbl[c];

        uint64_t hits = g_nodes[state].accept_out;
        if (!hits) continue;

        for (int p = 0; p < MM_NUM_PATTERNS; p++) {
            if (!(hits & ((uint64_t)1 << p))) continue;

            int32_t walk = state;
            uint8_t plen = 0;
            while (walk != 0) {
                if (g_nodes[walk].accept & ((uint64_t)1 << p)) {
                    plen = g_nodes[walk].prefix_len[p];
                    break;
                }
                walk = g_nodes[walk].fail;
            }
            size_t pos = i + 1 - plen;
            size_t mlen = confirm_at(p, input, pos);
            if (mlen == 0) continue;
            if (written >= max_matches) return written;
            out[written].pattern_id = p;
            out[written].start = pos;
            out[written].length = mlen;
            written++;
        }
    }

    /* Stage 2: always-candidate patterns. Run regexec scanning forward
     * (POSIX regexec with no anchor finds the next match). This is the
     * same cost today's engine pays for these patterns. */
    if (g_always_candidate) {
        for (int p = 0; p < MM_NUM_PATTERNS; p++) {
            if (!(g_always_candidate & ((uint64_t)1 << p))) continue;
            size_t pos = 0;
            while (pos < len) {
                regmatch_t m[1];
                int rc = regexec(&g_compiled[p], input + pos, 1, m, 0);
                if (rc != 0) break;
                size_t start = pos + (size_t)m[0].rm_so;
                size_t mlen = (size_t)(m[0].rm_eo - m[0].rm_so);
                if (mlen == 0) { pos = start + 1; continue; }
                if (written >= max_matches) return written;
                out[written].pattern_id = p;
                out[written].start = start;
                out[written].length = mlen;
                written++;
                pos = start + mlen;
            }
        }
    }

    return written;
}

/* ---------- Smoke test (Slice 1) ---------------------------------------- */

#ifdef MM_MAIN
int main(void) {
    mm_init();
    fprintf(stderr, "trie: %d nodes\n", g_node_count);

    const char *cases[] = {
        "key=AKIAIOSFODNN7EXAMPLE end",
        "stripe sk_live_abcdefghijklmnopqrstuvwx other sk_live_short_no_match",
        "iban DE89370400440532013000 short DE12 invalid",
        "url https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/abcdefghijklmnopqrstuvwx",
        "begin -----BEGIN RSA PRIVATE KEY----- body -----END",
        "begin -----BEGIN PGP PRIVATE KEY BLOCK----- body",
        "email foo@bar.com and ip 10.0.0.1 cc 4111111111111111 pesel 12345678901 end",
        "nothing here, no matches at all",
        NULL
    };

    mm_match_t buf[256];
    for (int i = 0; cases[i]; i++) {
        size_t n = mm_scan(cases[i], strlen(cases[i]), buf, 256);
        printf("[%d] %zu confirmed matches in: %s\n", i, n, cases[i]);
        for (size_t j = 0; j < n && j < 16; j++) {
            printf("    pat=%-20s pos=%zu len=%zu  '%.*s'\n",
                   mm_pattern_name(buf[j].pattern_id),
                   buf[j].start, buf[j].length,
                   (int)buf[j].length, cases[i] + buf[j].start);
        }
    }

    mm_free();
    return 0;
}
#endif
