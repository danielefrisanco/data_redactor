#include "custom_patterns.h"
#include "redact.h" /* wrap_boundary */
#include <string.h>
#include <stdlib.h>

custom_pattern_t *custom_patterns = NULL;
int custom_count = 0;
int custom_cap   = 0;

static int find_custom_by_name(const char *name) {
    for (int i = 0; i < custom_count; i++) {
        if (strcmp(custom_patterns[i].name, name) == 0) return i;
    }
    return -1;
}

static void free_custom_at(int idx) {
    free(custom_patterns[idx].name);
    free(custom_patterns[idx].source);
    regfree(&custom_patterns[idx].compiled);
}

VALUE rb_add_pattern(VALUE self, VALUE rb_name, VALUE rb_source,
                     VALUE rb_tag_bit, VALUE rb_boundary) {
    Check_Type(rb_name,   T_STRING);
    Check_Type(rb_source, T_STRING);

    const char *name    = StringValueCStr(rb_name);
    const char *source  = StringValueCStr(rb_source);
    int tag_bit         = NUM2INT(rb_tag_bit);
    int boundary        = NUM2INT(rb_boundary);

    char *pat_to_compile;
    char *wrapped = NULL;
    if (boundary) {
        wrapped = wrap_boundary(source);
        if (!wrapped) rb_raise(rb_eNoMemError, "wrap_boundary allocation failed");
        pat_to_compile = wrapped;
    } else {
        pat_to_compile = (char *)source;
    }

    regex_t compiled;
    int ret = regcomp(&compiled, pat_to_compile, REG_EXTENDED);
    free(wrapped);

    if (ret != 0) {
        char errbuf[256];
        regerror(ret, &compiled, errbuf, sizeof(errbuf));
        regfree(&compiled);
        VALUE eClass = rb_const_get(rb_define_module("DataRedactor"),
                                    rb_intern("InvalidPatternError"));
        rb_raise(eClass, "%s", errbuf);
    }

    int idx = find_custom_by_name(name);
    if (idx >= 0) {
        free_custom_at(idx);
    } else {
        if (custom_count >= custom_cap) {
            int new_cap = custom_cap == 0 ? 8 : custom_cap * 2;
            custom_pattern_t *tmp = (custom_pattern_t *)realloc(
                custom_patterns, sizeof(custom_pattern_t) * new_cap);
            if (!tmp) {
                regfree(&compiled);
                rb_raise(rb_eNoMemError, "custom_patterns realloc failed");
            }
            custom_patterns = tmp;
            custom_cap = new_cap;
        }
        idx = custom_count++;
    }

    custom_patterns[idx].name     = strdup(name);
    custom_patterns[idx].source   = strdup(source);
    custom_patterns[idx].compiled = compiled;
    custom_patterns[idx].tag      = tag_bit;
    custom_patterns[idx].boundary = boundary;

    if (!custom_patterns[idx].name || !custom_patterns[idx].source) {
        rb_raise(rb_eNoMemError, "strdup failed");
    }

    return Qnil;
}

VALUE rb_remove_pattern(VALUE self, VALUE rb_name) {
    Check_Type(rb_name, T_STRING);
    const char *name = StringValueCStr(rb_name);

    int idx = find_custom_by_name(name);
    if (idx < 0) return Qfalse;

    free_custom_at(idx);

    for (int i = idx; i < custom_count - 1; i++) {
        custom_patterns[i] = custom_patterns[i + 1];
    }
    custom_count--;

    return Qtrue;
}

VALUE rb_clear_custom_patterns(VALUE self) {
    for (int i = 0; i < custom_count; i++) {
        free_custom_at(i);
    }
    custom_count = 0;
    return Qnil;
}

VALUE rb_custom_patterns(VALUE self) {
    VALUE arr = rb_ary_new_capa(custom_count);
    for (int i = 0; i < custom_count; i++) {
        VALUE h = rb_hash_new();
        rb_hash_aset(h, ID2SYM(rb_intern("name")),     rb_str_new_cstr(custom_patterns[i].name));
        rb_hash_aset(h, ID2SYM(rb_intern("source")),   rb_str_new_cstr(custom_patterns[i].source));
        rb_hash_aset(h, ID2SYM(rb_intern("tag_bit")),  INT2NUM(custom_patterns[i].tag));
        rb_hash_aset(h, ID2SYM(rb_intern("boundary")), custom_patterns[i].boundary ? Qtrue : Qfalse);
        rb_ary_push(arr, h);
    }
    return arr;
}
