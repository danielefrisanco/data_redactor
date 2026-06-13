#include "redact.h"
#include "patterns.h"
#include "placeholder.h"
#include "custom_patterns.h"
#include "matcher.h"
#include "tags.h"
#include <ruby/thread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Inputs at or above this byte size release the GVL around the built-in v19
 * pass so other Ruby threads can run during the scan. Below it, the
 * rb_thread_call_without_gvl bookkeeping costs more than the scan, so we keep
 * the GVL. The Ruby layer chunks inputs > CHUNK_SIZE (64 KB) before calling
 * _redact, so the practical ceiling per call is one chunk; 4 KB cleanly
 * separates per-leaf/log-line calls (keep GVL) from chunk-sized work (release). */
#define GVL_RELEASE_THRESHOLD (4 * 1024)

char *wrap_boundary(const char *core) {
    const char *prefix = "(^|[^0-9A-Za-z])(";
    const char *suffix = ")([^0-9A-Za-z]|$)";
    size_t len = strlen(prefix) + strlen(core) + strlen(suffix) + 1;
    char *buf = (char *)malloc(len);
    if (!buf) return NULL;
    snprintf(buf, len, "%s%s%s", prefix, core, suffix);
    return buf;
}

/*
 * Replace all occurrences of a compiled pattern in `input` with PLACEHOLDER.
 *
 * If `use_boundary` is non-zero the pattern was compiled as:
 *   (^|[^0-9A-Za-z])(CORE)([^0-9A-Za-z]|$)
 * groups: [0]=full match  [1]=left boundary  [2]=CORE  [3]=right boundary
 * We pass nmatch=4 so the engine fills all four slots, then use matches[1].rm_eo
 * and matches[3].rm_so to locate the exact CORE span. The boundary characters
 * are copied back verbatim so they are not lost.
 */
char *replace_all_matches(regex_t *pattern, const char *input,
                          int use_boundary, const placeholder_t *ph) {
    size_t ph_max   = max_placeholder_len(ph);
    size_t in_len   = strlen(input);

    /* Worst case per input byte: it is either copied verbatim (1 byte out) or
     * it is one byte of a match replaced by the longest placeholder (ph_max
     * bytes out). A single byte is never both, but bounding each byte by
     * (1 + ph_max) is safe and sized once — no per-match strlen, no realloc. */
    size_t out_cap  = in_len * (ph_max + 1) + 1;
    char *output = (char *)malloc(out_cap);
    if (!output) return NULL;

    char *ph_buf = (char *)malloc(ph_max + 1);
    if (!ph_buf) { free(output); return NULL; }

    size_t out_len = 0;
    const char *cursor = input;
    regmatch_t matches[4];

    while (regexec(pattern, cursor, 4, matches, 0) == 0) {
        regoff_t full_so = matches[0].rm_so;
        regoff_t full_eo = matches[0].rm_eo;

        if (full_so < 0 || full_eo < full_so) break;

        regoff_t core_so = full_so;
        regoff_t core_eo = full_eo;

        if (use_boundary) {
            if (matches[1].rm_so >= 0 && matches[1].rm_eo > matches[1].rm_so)
                core_so = matches[1].rm_eo;
            if (matches[3].rm_so >= 0 && matches[3].rm_eo > matches[3].rm_so)
                core_eo = matches[3].rm_so;
        }

        size_t prefix_len = (size_t)core_so;
        size_t suffix_len = (size_t)(full_eo - core_eo);
        size_t match_len  = (size_t)(full_eo - full_so);
        size_t core_len   = (size_t)(core_eo - core_so);

        size_t ph_len = write_placeholder(ph_buf, ph, cursor + core_so, core_len);

        memcpy(output + out_len, cursor, prefix_len);
        out_len += prefix_len;

        memcpy(output + out_len, ph_buf, ph_len);
        out_len += ph_len;

        if (suffix_len > 0) {
            memcpy(output + out_len, cursor + core_eo, suffix_len);
            out_len += suffix_len;
        }

        cursor += full_eo;

        if (match_len == 0) {
            if (*cursor) output[out_len++] = *cursor++;
            else break;
        }
    }
    free(ph_buf);

    size_t tail_len = strlen(cursor);
    memcpy(output + out_len, cursor, tail_len);
    out_len += tail_len;
    output[out_len] = '\0';

    return output;
}

/* Look up the i-th entry of the enable_bits Array. Out-of-bounds → 0 (skip). */
static inline int enable_bit(VALUE rb_enable_bits, long i) {
    if (i < 0 || i >= RARRAY_LEN(rb_enable_bits)) return 0;
    VALUE v = rb_ary_entry(rb_enable_bits, i);
    return RTEST(v) && NUM2INT(v) != 0;
}

/* Copy the first NUM_PATTERNS entries of the enable_bits Array into a C int[].
 * Only the built-in slice is needed: the v19 engine runs built-ins only; custom
 * patterns are gated separately in the glibc loop. Caller frees. */
static int *builtin_enable_bits(VALUE rb_enable_bits) {
    int *bits = (int *)malloc((size_t)NUM_PATTERNS * sizeof(int));
    if (!bits) return NULL;
    long alen = RARRAY_LEN(rb_enable_bits);
    for (int i = 0; i < NUM_PATTERNS; i++) {
        if (i < alen) {
            VALUE v = rb_ary_entry(rb_enable_bits, i);
            bits[i] = (RTEST(v) && NUM2INT(v) != 0) ? 1 : 0;
        } else {
            bits[i] = 0;
        }
    }
    return bits;
}

/* Redact the built-in patterns from `input` (len bytes) with the v19 engine,
 * resolved to today's sequential semantics. Returns a newly malloc'd
 * NUL-terminated C string (caller frees) and writes its length to *out_len_p.
 * `bits` gates the built-ins (length NUM_PATTERNS). */
static char *redact_builtins(const char *input, size_t in_len, const int *bits,
                             int ph_mode, const char *ph_str_plain,
                             size_t *out_len_p) {
    /* Scan + resolve. Grow and rescan if the buffer fills exactly (possible
     * truncation), so no built-in match is ever silently dropped. */
    size_t cap = in_len / 4 + 16;
    mm_match_t *ev = NULL;
    size_t n;
    for (;;) {
        mm_match_t *grown = (mm_match_t *)realloc(ev, cap * sizeof(mm_match_t));
        if (!grown) { free(ev); return NULL; }
        ev = grown;
        n = mm_scan(input, in_len, bits, (size_t)NUM_PATTERNS, ev, cap);
        if (n < cap) break;
        cap *= 2;
    }
    n = mm_resolve(ev, n);

    placeholder_t ph;
    ph.mode = ph_mode;
    /* Size against the widest placeholder (longest tag name) so one allocation
     * covers any per-event tag. Each input byte maps to at most (ph_max+1) out
     * bytes (verbatim, or one byte of a CORE span replaced by ph_max). */
    ph.str = (ph_mode == PLACEHOLDER_MODE_PLAIN) ? ph_str_plain : "NATIONAL_ID";
    size_t ph_max = max_placeholder_len(&ph);

    size_t out_cap = in_len * (ph_max + 1) + 1;
    char *output = (char *)malloc(out_cap);
    char *ph_buf = (char *)malloc(ph_max + 1);
    if (!output || !ph_buf) { free(output); free(ph_buf); free(ev); return NULL; }

    size_t out_len = 0, cur = 0;
    for (size_t i = 0; i < n; i++) {
        size_t s = ev[i].start, l = ev[i].length;
        if (s > cur) { memcpy(output + out_len, input + cur, s - cur); out_len += s - cur; }
        ph.str = (ph_mode == PLACEHOLDER_MODE_PLAIN)
                     ? ph_str_plain
                     : tag_name_for_bit(pattern_tags[ev[i].pattern_id]);
        size_t pl = write_placeholder(ph_buf, &ph, input + s, l);
        memcpy(output + out_len, ph_buf, pl); out_len += pl;
        cur = s + l;
    }
    if (cur < in_len) { memcpy(output + out_len, input + cur, in_len - cur); out_len += in_len - cur; }
    output[out_len] = '\0';

    free(ph_buf);
    free(ev);
    *out_len_p = out_len;
    return output;
}

/* Trampoline for running redact_builtins() with the GVL released. Everything it
 * touches is plain C (raw char* in/out, the per-thread engine state); no Ruby
 * VALUE or Ruby API call happens inside, which is the contract for
 * rb_thread_call_without_gvl. */
typedef struct {
    const char  *input;
    size_t       in_len;
    const int   *bits;
    int          ph_mode;
    const char  *ph_str_plain;
    size_t       out_len;
    char        *result;
} builtins_args_t;

static void *redact_builtins_nogvl(void *p) {
    builtins_args_t *a = (builtins_args_t *)p;
    a->result = redact_builtins(a->input, a->in_len, a->bits,
                                a->ph_mode, a->ph_str_plain, &a->out_len);
    return NULL;
}

/* Run the built-in v19 pass, releasing the GVL for inputs large enough that the
 * scan dominates the release bookkeeping. Small inputs run inline under the GVL. */
static char *redact_builtins_maybe_nogvl(const char *input, size_t in_len,
                                         const int *bits, int ph_mode,
                                         const char *ph_str_plain, size_t *out_len_p) {
    if (in_len < GVL_RELEASE_THRESHOLD)
        return redact_builtins(input, in_len, bits, ph_mode, ph_str_plain, out_len_p);

    builtins_args_t a = { input, in_len, bits, ph_mode, ph_str_plain, 0, NULL };
    rb_thread_call_without_gvl(redact_builtins_nogvl, &a, RUBY_UBF_IO, NULL);
    *out_len_p = a.out_len;
    return a.result;
}

VALUE rb_data_redactor_redact(VALUE self, VALUE rb_text,
                              VALUE rb_ph_mode, VALUE rb_ph_str,
                              VALUE rb_enable_bits) {
    Check_Type(rb_text,         T_STRING);
    Check_Type(rb_ph_str,       T_STRING);
    Check_Type(rb_enable_bits,  T_ARRAY);

    int ph_mode = NUM2INT(rb_ph_mode);
    const char *ph_str_plain = StringValueCStr(rb_ph_str);

    const char *input = RSTRING_PTR(rb_text);
    size_t in_len = (size_t)RSTRING_LEN(rb_text);

    /* Stage 1: built-ins through the fast v19 engine (single pass, resolved to
     * earlier-index-wins). */
    int *bits = builtin_enable_bits(rb_enable_bits);
    if (!bits) rb_raise(rb_eNoMemError, "enable_bits allocation failed");
    size_t work_len = 0;
    char *working = redact_builtins_maybe_nogvl(input, in_len, bits, ph_mode, ph_str_plain, &work_len);
    free(bits);
    if (!working) rb_raise(rb_eNoMemError, "built-in redaction allocation failed");

    /* Stage 2: custom patterns through the glibc regexec path, on the buffer the
     * built-ins already rewrote — preserving the sequential built-ins→customs
     * order and full UTF-8 matching for user regex (see Gap 2 hybrid split). The
     * "[REDACTED…]" placeholders introduce none of any custom pattern's literals
     * incidentally beyond what today already did. */
    placeholder_t ph;
    ph.mode = ph_mode;
    custom_patterns_lock();
    int oom = 0;
    for (int i = 0; i < custom_count; i++) {
        if (!enable_bit(rb_enable_bits, NUM_PATTERNS + i)) continue;
        ph.str = (ph_mode == PLACEHOLDER_MODE_PLAIN)
                     ? ph_str_plain
                     : tag_name_for_bit(custom_patterns[i].tag);
        char *result = replace_all_matches(&custom_patterns[i].compiled, working,
                                           custom_patterns[i].boundary, &ph);
        free(working);
        if (!result) { working = NULL; oom = 1; break; }
        working = result;
    }
    custom_patterns_unlock();
    if (oom) rb_raise(rb_eNoMemError, "replace_all_matches allocation failed (custom)");

    VALUE rb_result = rb_str_new_cstr(working);
    free(working);
    /* Preserve the input's encoding. We go through Ruby's force_encoding rather
     * than the C rb_enc_* API because pulling in ruby/encoding.h drags in
     * onigmo.h, whose regex_t collides with the POSIX <regex.h> this TU uses for
     * the custom-pattern path. Placeholders are pure ASCII, valid in every
     * encoding the gem accepts. */
    rb_funcall(rb_result, rb_intern("force_encoding"), 1,
               rb_funcall(rb_text, rb_intern("encoding"), 0));
    return rb_result;
}
