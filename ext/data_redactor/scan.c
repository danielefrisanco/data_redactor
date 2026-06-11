#include "scan.h"
#include "patterns.h"
#include "placeholder.h"
#include "custom_patterns.h"
#include "redact.h"
#include "matcher.h"
#include "tags.h"
#include <regex.h>
#include <string.h>
#include <stdlib.h>

/* Look up the i-th entry of the enable_bits Array. Out-of-bounds → 0 (skip). */
static inline int scan_enable_bit(VALUE rb_enable_bits, long i) {
    if (i < 0 || i >= RARRAY_LEN(rb_enable_bits)) return 0;
    VALUE v = rb_ary_entry(rb_enable_bits, i);
    return RTEST(v) && NUM2INT(v) != 0;
}

/*
 * Map a working-buffer position (after built-in redaction) back to the
 * original-input position.
 *
 * After the built-in pass, the working buffer contains the original input
 * with each matched CORE span replaced by "[REDACTED]" (10 bytes). The
 * ev[] array (sorted by start, non-overlapping) records every replacement
 * in original-frame coordinates. Walking ev[] we can find which verbatim
 * segment or replacement a working position falls in and recover the
 * original position.
 *
 * For a match that lands inside a "[REDACTED]" span we return the start of
 * the corresponding original CORE (can only happen if a custom pattern
 * matches the literal "[REDACTED]" itself, which is a degenerate case).
 */
static long working_to_orig(long wpos, const mm_match_t *ev, size_t n,
                             size_t ph_len) {
    long cum_orig = 0;
    long cum_work = 0;
    for (size_t i = 0; i < n; i++) {
        long seg = (long)ev[i].start - cum_orig;
        if (wpos < cum_work + seg)
            return cum_orig + (wpos - cum_work);
        cum_orig += seg + (long)ev[i].length;
        cum_work += seg + (long)ph_len;
    }
    return cum_orig + (wpos - cum_work);
}

VALUE rb_data_redactor_scan(VALUE self, VALUE rb_text, VALUE rb_enable_bits) {
    Check_Type(rb_text,        T_STRING);
    Check_Type(rb_enable_bits, T_ARRAY);

    const char *input  = RSTRING_PTR(rb_text);
    size_t      in_len = (size_t)RSTRING_LEN(rb_text);

    static const placeholder_t ph_plain = { PLACEHOLDER_MODE_PLAIN, "[REDACTED]" };

    /* ------------------------------------------------------------------ */
    /* Stage 1: built-ins through v19 (original-frame coords, no rewrite  */
    /* coordinate mapping needed).                                         */
    /* ------------------------------------------------------------------ */

    /* Build enable-bits array for built-ins. */
    int *bits = (int *)malloc((size_t)NUM_PATTERNS * sizeof(int));
    if (!bits) rb_raise(rb_eNoMemError, "enable_bits allocation failed");
    long alen = RARRAY_LEN(rb_enable_bits);
    for (int i = 0; i < NUM_PATTERNS; i++) {
        if (i < alen) {
            VALUE v = rb_ary_entry(rb_enable_bits, i);
            bits[i] = (RTEST(v) && NUM2INT(v) != 0) ? 1 : 0;
        } else {
            bits[i] = 0;
        }
    }

    /* Scan + resolve, growing buffer if needed. */
    size_t cap = in_len / 4 + 16;
    mm_match_t *ev = NULL;
    size_t n_ev;
    for (;;) {
        mm_match_t *grown = (mm_match_t *)realloc(ev, cap * sizeof(mm_match_t));
        if (!grown) { free(ev); free(bits); rb_raise(rb_eNoMemError, "mm_scan alloc"); }
        ev = grown;
        n_ev = mm_scan(input, in_len, bits, (size_t)NUM_PATTERNS, ev, cap);
        if (n_ev < cap) break;
        cap *= 2;
    }
    free(bits);
    n_ev = mm_resolve(ev, n_ev);

    /* Collect built-in match hashes. */
    VALUE matches_arr = rb_ary_new();
    for (size_t i = 0; i < n_ev; i++) {
        int   pid = ev[i].pattern_id;
        VALUE h   = rb_hash_new();
        rb_hash_aset(h, ID2SYM(rb_intern("tag")),
                     ID2SYM(rb_intern(tag_name_for_bit(pattern_tags[pid]))));
        rb_hash_aset(h, ID2SYM(rb_intern("name")),
                     rb_str_new_cstr(pattern_names[pid]));
        rb_hash_aset(h, ID2SYM(rb_intern("value")),
                     rb_str_new(input + ev[i].start, ev[i].length));
        rb_hash_aset(h, ID2SYM(rb_intern("start")),
                     LONG2NUM((long)ev[i].start));
        rb_hash_aset(h, ID2SYM(rb_intern("length")),
                     LONG2NUM((long)ev[i].length));
        rb_ary_push(matches_arr, h);
    }

    /* Build the redacted working buffer (same logic as redact_builtins). */
    size_t ph_len  = strlen(ph_plain.str); /* "[REDACTED]" = 10 */
    size_t out_cap = in_len + n_ev * ph_len + 1;
    char *working  = (char *)malloc(out_cap);
    if (!working) { free(ev); rb_raise(rb_eNoMemError, "scan working buffer alloc"); }

    size_t out_len = 0, cur = 0;
    for (size_t i = 0; i < n_ev; i++) {
        size_t s = ev[i].start, l = ev[i].length;
        if (s > cur) { memcpy(working + out_len, input + cur, s - cur); out_len += s - cur; }
        memcpy(working + out_len, ph_plain.str, ph_len);
        out_len += ph_len;
        cur = s + l;
    }
    if (cur < in_len) { memcpy(working + out_len, input + cur, in_len - cur); out_len += in_len - cur; }
    working[out_len] = '\0';

    /* ------------------------------------------------------------------ */
    /* Stage 2: custom patterns via glibc on the rewritten buffer.         */
    /* Original coords recovered via working_to_orig() using ev[].         */
    /* ------------------------------------------------------------------ */
    custom_patterns_lock();
    int oom = 0;
    for (int i = 0; i < custom_count; i++) {
        if (!scan_enable_bit(rb_enable_bits, NUM_PATTERNS + i)) continue;

        const char *cur_ptr = working;
        regmatch_t  m[4];
        while (regexec(&custom_patterns[i].compiled, cur_ptr, 4, m, 0) == 0) {
            regoff_t fso = m[0].rm_so, feo = m[0].rm_eo;
            if (fso < 0 || feo < fso) break;

            regoff_t cso = fso, ceo = feo;
            if (custom_patterns[i].boundary) {
                if (m[1].rm_so >= 0 && m[1].rm_eo > m[1].rm_so) cso = m[1].rm_eo;
                if (m[3].rm_so >= 0 && m[3].rm_eo > m[3].rm_so) ceo = m[3].rm_so;
            }

            long wpos_core  = (long)(cur_ptr - working) + (long)cso;
            long orig_start = working_to_orig(wpos_core, ev, n_ev, ph_len);
            long core_len   = (long)(ceo - cso);

            VALUE h = rb_hash_new();
            rb_hash_aset(h, ID2SYM(rb_intern("tag")),
                         ID2SYM(rb_intern(tag_name_for_bit(custom_patterns[i].tag))));
            rb_hash_aset(h, ID2SYM(rb_intern("name")),
                         rb_str_new_cstr(custom_patterns[i].name));
            rb_hash_aset(h, ID2SYM(rb_intern("value")),
                         rb_str_new(cur_ptr + cso, (size_t)core_len));
            rb_hash_aset(h, ID2SYM(rb_intern("start")),  LONG2NUM(orig_start));
            rb_hash_aset(h, ID2SYM(rb_intern("length")), LONG2NUM(core_len));
            rb_ary_push(matches_arr, h);

            if (feo == fso) { if (*cur_ptr) cur_ptr++; else break; }
            else cur_ptr += feo;
        }

        char *next = replace_all_matches(&custom_patterns[i].compiled, working,
                                         custom_patterns[i].boundary, &ph_plain);
        free(working);
        if (!next) { working = NULL; oom = 1; break; }
        working = next;
    }
    custom_patterns_unlock();
    if (oom) { free(ev); rb_raise(rb_eNoMemError, "replace_all_matches failed in scan"); }

    free(ev);

    VALUE result      = rb_hash_new();
    VALUE rb_redacted = rb_str_new_cstr(working);
    free(working);
    rb_funcall(rb_redacted, rb_intern("force_encoding"), 1,
               rb_funcall(rb_text, rb_intern("encoding"), 0));
    rb_hash_aset(result, ID2SYM(rb_intern("redacted")), rb_redacted);
    rb_hash_aset(result, ID2SYM(rb_intern("matches")),  matches_arr);
    return result;
}
