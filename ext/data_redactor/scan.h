#ifndef DATA_REDACTOR_SCAN_H
#define DATA_REDACTOR_SCAN_H

#include <ruby.h>

/*
 * DataRedactor._scan(text, enable_bits) -> { redacted: String, matches: Array<Hash> }
 * enable_bits: same per-pattern 0/1 array as _redact.
 */
VALUE rb_data_redactor_scan(VALUE self, VALUE rb_text, VALUE rb_enable_bits);

#endif
