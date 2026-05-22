#include "redact.h"
#include "patterns.h"
#include "placeholder.h"
#include "custom_patterns.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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

VALUE rb_data_redactor_redact(VALUE self, VALUE rb_text,
                              VALUE rb_ph_mode, VALUE rb_ph_str,
                              VALUE rb_enable_bits) {
    Check_Type(rb_text,         T_STRING);
    Check_Type(rb_ph_str,       T_STRING);
    Check_Type(rb_enable_bits,  T_ARRAY);

    int ph_mode = NUM2INT(rb_ph_mode);
    const char *ph_str_plain = StringValueCStr(rb_ph_str);

    const char *input = StringValueCStr(rb_text);
    char *working = strdup(input);
    if (!working) rb_raise(rb_eNoMemError, "strdup failed");

    placeholder_t ph;
    ph.mode = ph_mode;

    for (int i = 0; i < NUM_PATTERNS; i++) {
        if (!enable_bit(rb_enable_bits, i)) continue;
        ph.str = (ph_mode == PLACEHOLDER_MODE_PLAIN)
                     ? ph_str_plain
                     : tag_name_for_bit(pattern_tags[i]);
        char *result = replace_all_matches(&compiled_patterns[i], working,
                                           boundary_wrapped[i], &ph);
        free(working);
        if (!result) rb_raise(rb_eNoMemError, "replace_all_matches allocation failed");
        working = result;
    }

    for (int i = 0; i < custom_count; i++) {
        if (!enable_bit(rb_enable_bits, NUM_PATTERNS + i)) continue;
        ph.str = (ph_mode == PLACEHOLDER_MODE_PLAIN)
                     ? ph_str_plain
                     : tag_name_for_bit(custom_patterns[i].tag);
        char *result = replace_all_matches(&custom_patterns[i].compiled, working,
                                           custom_patterns[i].boundary, &ph);
        free(working);
        if (!result) rb_raise(rb_eNoMemError, "replace_all_matches allocation failed (custom)");
        working = result;
    }

    VALUE rb_result = rb_str_new_cstr(working);
    free(working);
    return rb_result;
}
