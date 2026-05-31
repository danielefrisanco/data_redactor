/* matcher7_plain_onig.c — plain Onigmo sequential baseline, no AC, no BM.
 *
 * For each of the 88 patterns, call onig_search in a loop over the full
 * input. Equivalent to today's C extension but with Onigmo instead of glibc.
 *
 * Purpose: isolate Onigmo's contribution from the AC+BM pipeline in v3/v5.
 * Compare with plain PCRE2 JIT to see if JIT alone explains the difference,
 * and with v3/v5 to see whether AC+BM helps or hurts Onigmo.
 *
 * Build:  make matcher7_plain_onig.so
 */

#include "matcher7_plain_onig.h"
#include "patterns_generated.h"

#include <oniguruma.h>
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

static OnigRegex g_onig[MM88_NUM_PATTERNS];
static int       g_compiled_ok = 0;
static int       g_initialized = 0;

static void compile_patterns(void) {
    onig_init();
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *src = MM88_PATTERNS[p].regex;
        char *to_free = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped)
            src = to_free = make_wrapped_regex(src);
        OnigErrorInfo einfo;
        int rc = onig_new(&g_onig[p],
                          (const OnigUChar *)src,
                          (const OnigUChar *)(src + strlen(src)),
                          ONIG_OPTION_NONE, ONIG_ENCODING_ASCII,
                          ONIG_SYNTAX_RUBY, &einfo);
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

void mm7po_init(void) {
    if (g_initialized) return;
    compile_patterns();
    g_initialized = 1;
}

void mm7po_free(void) {
    if (g_compiled_ok) {
        for (int p = 0; p < MM88_NUM_PATTERNS; p++) onig_free(g_onig[p]);
        onig_end();
        g_compiled_ok = 0;
    }
    g_initialized = 0;
}

const char *mm7po_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return "<invalid>";
    return MM88_PATTERNS[id].name;
}

size_t mm7po_scan(const char *input, size_t len,
                  mm7po_match_t *out, size_t max_matches) {
    if (!g_initialized) mm7po_init();
    size_t written = 0;

    const OnigUChar *str = (const OnigUChar *)input;
    const OnigUChar *end = str + len;

    for (int p = 0; p < MM88_NUM_PATTERNS && written < max_matches; p++) {
        const OnigUChar *pos = str;
        while (pos < end && written < max_matches) {
            OnigRegion *region = onig_region_new();
            if (!region) break;
            int rc = onig_search(g_onig[p], str, end, pos, end,
                                 region, ONIG_OPTION_NONE);
            if (rc < 0) { onig_region_free(region, 1); break; }

            size_t mstart, mlen;
            if (MM88_PATTERNS[p].boundary_wrapped && region->num_regs > 2) {
                int so = region->beg[2], eo = region->end[2];
                onig_region_free(region, 1);
                if (so < 0 || eo <= so) { pos++; continue; }
                mstart = (size_t)so; mlen = (size_t)(eo - so);
            } else {
                int so = region->beg[0], eo = region->end[0];
                onig_region_free(region, 1);
                if (eo <= so) { pos++; continue; }
                mstart = (size_t)so; mlen = (size_t)(eo - so);
            }
            out[written].pattern_id = p;
            out[written].start      = mstart;
            out[written].length     = mlen;
            written++;
            pos = str + mstart + mlen;
        }
    }
    return written;
}
