/* matcher_glibc.c — faithful REPRODUCTION of the gem's pre-v19 engine.
 *
 * IMPORTANT FRAMING (for the paper): this is a *reproduction*, not the original
 * code. The original pre-v19 engine (gem ≤ v0.11.0) is no longer measurable in
 * the shipping gem — 0.13.0 replaced it with v19 (redact.c now calls mm_scan).
 * Rather than build an old gem version, we reproduce its approach here and
 * benchmark *against the reproduction*, stating so explicitly. The approach
 * reproduced is exactly what v0.11.0's redact.c did:
 *
 *   - one POSIX regex per built-in pattern, compiled with regcomp(REG_EXTENDED);
 *   - boundary-wrapped patterns compiled as (^|[^0-9A-Za-z])(CORE)([^...]|$),
 *     matching the gem's WRAP_PREFIX/WRAP_SUFFIX;
 *   - a flat sequential scan: for each pattern, regexec forward over the whole
 *     buffer, advancing past each match (REG_NOTBOL after pos 0). No Aho-Corasick
 *     prefix filter, no Boyer-Moore, no literal skip — the plain-regexec baseline.
 *
 * This is scan-only (returns match spans) so it is comparable to the other
 * prototype engines (v15/v18/v19/pcre2jit), which also measure scanning, not the
 * full string rewrite. The rewrite cost was identical across engines in the gem
 * and is not what the crossover figure is about.
 *
 * Pattern source: MM88_PATTERNS in patterns_generated.h (same 88 built-ins,
 * generated from patterns.c — the single source of truth).
 */
#include "matcher_glibc.h"
#include "patterns_generated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#define WRAP_PREFIX "(^|[^0-9A-Za-z])("
#define WRAP_SUFFIX ")([^0-9A-Za-z]|$)"

static regex_t g_compiled[MM88_NUM_PATTERNS];
static int     g_ok[MM88_NUM_PATTERNS];
static int     g_initialized = 0;

void mmg_init(void) {
    if (g_initialized) return;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *core = MM88_PATTERNS[p].regex;
        const char *src  = core;
        char *wrapped = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped) {
            size_t len = strlen(WRAP_PREFIX) + strlen(core) + strlen(WRAP_SUFFIX) + 1;
            wrapped = (char *)malloc(len);
            if (!wrapped) { perror("malloc"); exit(1); }
            snprintf(wrapped, len, "%s%s%s", WRAP_PREFIX, core, WRAP_SUFFIX);
            src = wrapped;
        }
        int rc = regcomp(&g_compiled[p], src, REG_EXTENDED);
        if (rc != 0) {
            char err[256];
            regerror(rc, &g_compiled[p], err, sizeof(err));
            fprintf(stderr, "matcher_glibc: regcomp failed for %s: %s\n",
                    MM88_PATTERNS[p].name, err);
            g_ok[p] = 0;
        } else {
            g_ok[p] = 1;
        }
        free(wrapped);
    }
    g_initialized = 1;
}

void mmg_free(void) {
    if (!g_initialized) return;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++)
        if (g_ok[p]) regfree(&g_compiled[p]);
    g_initialized = 0;
}

/* Plain sequential scan: for each pattern, walk the buffer with regexec,
 * emitting CORE spans (boundary bytes stripped for wrapped patterns), advancing
 * past each match. This mirrors v0.11.0's per-pattern replace loop, minus the
 * rewrite. regexec needs NUL-terminated input; the buffer passed by the harness
 * is a NUL-terminated Ruby String, so `len` is used only for the output cap. */
size_t mmg_scan(const char *input, size_t len, mmg_match_t *out, size_t max) {
    (void)len;
    size_t count = 0;
    regmatch_t m[4];
    for (int p = 0; p < MM88_NUM_PATTERNS && count < max; p++) {
        if (!g_ok[p]) continue;
        const char *cursor = input;
        size_t base = 0;
        int wrapped = MM88_PATTERNS[p].boundary_wrapped;
        while (count < max) {
            int eflags = (base > 0) ? REG_NOTBOL : 0;
            if (regexec(&g_compiled[p], cursor, 4, m, eflags) != 0) break;
            regoff_t full_so = m[0].rm_so, full_eo = m[0].rm_eo;
            if (full_so < 0 || full_eo < full_so) break;

            regoff_t core_so = full_so, core_eo = full_eo;
            if (wrapped) {
                if (m[1].rm_so >= 0 && m[1].rm_eo > m[1].rm_so) core_so = m[1].rm_eo;
                if (m[3].rm_so >= 0 && m[3].rm_eo > m[3].rm_so) core_eo = m[3].rm_so;
            }
            out[count].pattern_id = p;
            out[count].start      = base + (size_t)core_so;
            out[count].length     = (size_t)(core_eo - core_so);
            count++;

            size_t advance = (full_eo > full_so) ? (size_t)full_eo : (size_t)full_so + 1;
            cursor += advance;
            base   += advance;
            if (*cursor == '\0') break;
        }
    }
    return count;
}

const char *mmg_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return NULL;
    return MM88_PATTERNS[id].name;
}

#ifdef MMG_MAIN
int main(void) {
    mmg_init();
    const char *t = "key=AKIAIOSFODNN7EXAMPLE end card 4111111111111111 ip 192.168.1.1\n";
    mmg_match_t out[256];
    size_t n = mmg_scan(t, strlen(t), out, 256);
    printf("matches=%zu\n", n);
    for (size_t i = 0; i < n; i++)
        printf("  [%s] start=%zu len=%zu\n",
               mmg_pattern_name(out[i].pattern_id), out[i].start, out[i].length);
    mmg_free();
    return 0;
}
#endif
