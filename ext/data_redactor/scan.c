#include "scan.h"
#include "patterns.h"
#include "placeholder.h"
#include "custom_patterns.h"
#include "redact.h"
#include <regex.h>
#include <string.h>
#include <stdlib.h>

/*
 * To map working-buffer positions back to original-string positions we
 * maintain a log of every replacement already applied. Each entry records
 * where in the *working* buffer the replacement started (after all prior
 * replacements) and how many bytes were removed (orig_len) vs. inserted
 * (always 10, the length of "[REDACTED]").
 *
 * For a new match at working position W:
 *   cumulative_shift_before_W = sum of (10 - orig_len) for all prior
 *                               replacements whose working_pos <= W
 *   original_pos = W - cumulative_shift_before_W
 */
/* Look up the i-th entry of the enable_bits Array. Out-of-bounds → 0 (skip). */
static inline int scan_enable_bit(VALUE rb_enable_bits, long i) {
    if (i < 0 || i >= RARRAY_LEN(rb_enable_bits)) return 0;
    VALUE v = rb_ary_entry(rb_enable_bits, i);
    return RTEST(v) && NUM2INT(v) != 0;
}

VALUE rb_data_redactor_scan(VALUE self, VALUE rb_text, VALUE rb_enable_bits) {
    Check_Type(rb_text,        T_STRING);
    Check_Type(rb_enable_bits, T_ARRAY);

    const char *input = StringValueCStr(rb_text);

    static const placeholder_t ph_default = { PLACEHOLDER_MODE_PLAIN, "[REDACTED]" };

    char *working = strdup(input);
    if (!working) rb_raise(rb_eNoMemError, "strdup failed");

    VALUE matches_arr = rb_ary_new();

    typedef struct { long wpos; long orig_len; } repl_t;
    repl_t *repl_log = NULL;
    int     repl_count = 0;
    int     repl_cap   = 0;

    #define REPL_LOG_PUSH(_wpos, _olen) do {                                  \
        if (repl_count >= repl_cap) {                                         \
            int _nc = repl_cap == 0 ? 16 : repl_cap * 2;                     \
            repl_t *_t = (repl_t *)realloc(repl_log, sizeof(repl_t) * _nc);  \
            if (!_t) { free(repl_log); free(working); rb_raise(rb_eNoMemError, "repl_log"); } \
            repl_log = _t; repl_cap = _nc;                                    \
        }                                                                     \
        repl_log[repl_count].wpos     = (_wpos);                              \
        repl_log[repl_count].orig_len = (_olen);                              \
        repl_count++;                                                         \
    } while (0)

    #define WORKING_TO_ORIG(_wpos) ({                                         \
        long _shift = 0;                                                      \
        for (int _ri = 0; _ri < repl_count; _ri++) {                         \
            if (repl_log[_ri].wpos <= (_wpos))                                \
                _shift += 10 - repl_log[_ri].orig_len;                       \
        }                                                                     \
        (_wpos) - _shift;                                                     \
    })

    #define COLLECT_AND_REPLACE(pat, use_bnd, tag_bit, pat_name) do {        \
        const char *_cur = working;                                           \
        regmatch_t _m[4];                                                     \
        while (regexec((pat), _cur, 4, _m, 0) == 0) {                        \
            regoff_t _fso = _m[0].rm_so, _feo = _m[0].rm_eo;                 \
            if (_fso < 0 || _feo < _fso) break;                               \
            regoff_t _cso = _fso, _ceo = _feo;                                \
            if (use_bnd) {                                                    \
                if (_m[1].rm_so >= 0 && _m[1].rm_eo > _m[1].rm_so)          \
                    _cso = _m[1].rm_eo;                                       \
                if (_m[3].rm_so >= 0 && _m[3].rm_eo > _m[3].rm_so)          \
                    _ceo = _m[3].rm_so;                                       \
            }                                                                 \
            size_t _vlen = (size_t)(_ceo - _cso);                             \
            long _wpos   = (long)(_cur - working) + (long)_cso;              \
            long _orig   = WORKING_TO_ORIG(_wpos);                            \
            VALUE _match = rb_hash_new();                                     \
            rb_hash_aset(_match, ID2SYM(rb_intern("tag")),                    \
                         ID2SYM(rb_intern(tag_name_for_bit(tag_bit))));       \
            rb_hash_aset(_match, ID2SYM(rb_intern("name")),                  \
                         rb_str_new_cstr(pat_name));                          \
            rb_hash_aset(_match, ID2SYM(rb_intern("value")),                 \
                         rb_str_new(_cur + _cso, _vlen));                     \
            rb_hash_aset(_match, ID2SYM(rb_intern("start")),                 \
                         LONG2NUM(_orig));                                    \
            rb_hash_aset(_match, ID2SYM(rb_intern("length")),                \
                         LONG2NUM((long)_vlen));                              \
            rb_ary_push(matches_arr, _match);                                 \
            REPL_LOG_PUSH(_wpos, (long)_vlen);                                \
            if (_feo == _fso) { if (*_cur) _cur++; else break; }             \
            else _cur += _feo;                                                \
        }                                                                     \
        char *_next = replace_all_matches((pat), working, (use_bnd), &ph_default); \
        free(working);                                                        \
        if (!_next) { free(repl_log); rb_raise(rb_eNoMemError, "replace_all_matches failed in scan"); } \
        working = _next;                                                      \
    } while (0)

    for (int i = 0; i < NUM_PATTERNS; i++) {
        if (!scan_enable_bit(rb_enable_bits, i)) continue;
        /* Same literal pre-filter as redact.c — see commentary there. */
        const char *lit = pattern_required_literal[i];
        if (lit && !strstr(working, lit)) continue;
        COLLECT_AND_REPLACE(&compiled_patterns[i], boundary_wrapped[i],
                            pattern_tags[i], pattern_names[i]);
    }

    for (int i = 0; i < custom_count; i++) {
        if (!scan_enable_bit(rb_enable_bits, NUM_PATTERNS + i)) continue;
        COLLECT_AND_REPLACE(&custom_patterns[i].compiled,
                            custom_patterns[i].boundary,
                            custom_patterns[i].tag, custom_patterns[i].name);
    }

    #undef COLLECT_AND_REPLACE
    #undef WORKING_TO_ORIG
    #undef REPL_LOG_PUSH

    free(repl_log);

    VALUE result = rb_hash_new();
    VALUE rb_redacted = rb_str_new_cstr(working);
    free(working);
    rb_hash_aset(result, ID2SYM(rb_intern("redacted")), rb_redacted);
    rb_hash_aset(result, ID2SYM(rb_intern("matches")),  matches_arr);
    return result;
}
