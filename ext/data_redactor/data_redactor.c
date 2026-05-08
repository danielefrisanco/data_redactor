#include <ruby.h>
#include <regex.h>
#include <stdlib.h>
#include "tags.h"
#include "patterns.h"
#include "placeholder.h"
#include "redact.h"
#include "scan.h"
#include "custom_patterns.h"

void Init_data_redactor(void) {
    /* Compile all built-in regex patterns at load time. */
    for (int i = 0; i < NUM_PATTERNS; i++) {
        const char *pat;
        char *wrapped = NULL;

        if (boundary_wrapped[i]) {
            wrapped = wrap_boundary(pattern_strings[i]);
            if (!wrapped) {
                rb_raise(rb_eNoMemError, "wrap_boundary allocation failed for pattern %d", i);
            }
            pat = wrapped;
        } else {
            pat = pattern_strings[i];
        }

        int ret = regcomp(&compiled_patterns[i], pat, REG_EXTENDED);
        free(wrapped);

        if (ret != 0) {
            char errbuf[256];
            regerror(ret, &compiled_patterns[i], errbuf, sizeof(errbuf));
            rb_raise(rb_eRuntimeError, "Failed to compile pattern %d: %s", i, errbuf);
        }
    }

    VALUE mDataRedactor = rb_define_module("DataRedactor");
    rb_define_module_function(mDataRedactor, "_redact",                rb_data_redactor_redact,    4);
    rb_define_module_function(mDataRedactor, "_scan",                  rb_data_redactor_scan,      2);
    /* Note: _redact(text, ph_mode, ph_str, enable_bits) and _scan(text, enable_bits). */
    rb_define_module_function(mDataRedactor, "_add_pattern",           rb_add_pattern,             4);
    rb_define_module_function(mDataRedactor, "_remove_pattern",        rb_remove_pattern,          1);
    rb_define_module_function(mDataRedactor, "_clear_custom_patterns", rb_clear_custom_patterns,   0);
    rb_define_module_function(mDataRedactor, "_custom_patterns",       rb_custom_patterns,         0);

    /* Frozen array of built-in pattern names, for introspection and only:/except: validation. */
    VALUE builtin_names = rb_ary_new_capa(NUM_PATTERNS);
    VALUE builtin_tag_bits = rb_ary_new_capa(NUM_PATTERNS);
    for (int i = 0; i < NUM_PATTERNS; i++) {
        rb_ary_push(builtin_names, rb_str_new_frozen(rb_str_new_cstr(pattern_names[i])));
        rb_ary_push(builtin_tag_bits, INT2NUM(pattern_tags[i]));
    }
    rb_define_const(mDataRedactor, "BUILTIN_PATTERN_NAMES",    rb_ary_freeze(builtin_names));
    rb_define_const(mDataRedactor, "BUILTIN_PATTERN_TAG_BITS", rb_ary_freeze(builtin_tag_bits));

    /* Placeholder mode constants. */
    rb_define_const(mDataRedactor, "PH_MODE_PLAIN",  INT2NUM(PLACEHOLDER_MODE_PLAIN));
    rb_define_const(mDataRedactor, "PH_MODE_TAGGED", INT2NUM(PLACEHOLDER_MODE_TAGGED));
    rb_define_const(mDataRedactor, "PH_MODE_HASH",   INT2NUM(PLACEHOLDER_MODE_HASH));

    /* Tag bitmask values used by the Ruby wrapper to build only/except masks. */
    rb_define_const(mDataRedactor, "TAG_CREDENTIALS", INT2NUM(TAG_CREDENTIALS));
    rb_define_const(mDataRedactor, "TAG_FINANCIAL",   INT2NUM(TAG_FINANCIAL));
    rb_define_const(mDataRedactor, "TAG_TAX_ID",      INT2NUM(TAG_TAX_ID));
    rb_define_const(mDataRedactor, "TAG_NATIONAL_ID", INT2NUM(TAG_NATIONAL_ID));
    rb_define_const(mDataRedactor, "TAG_CONTACT",     INT2NUM(TAG_CONTACT));
    rb_define_const(mDataRedactor, "TAG_NETWORK",     INT2NUM(TAG_NETWORK));
    rb_define_const(mDataRedactor, "TAG_TRAVEL",      INT2NUM(TAG_TRAVEL));
    rb_define_const(mDataRedactor, "TAG_OTHER",       INT2NUM(TAG_OTHER));
    rb_define_const(mDataRedactor, "TAG_CUSTOM",      INT2NUM(TAG_CUSTOM));
    rb_define_const(mDataRedactor, "TAG_ALL",         INT2NUM(TAG_ALL));
}
