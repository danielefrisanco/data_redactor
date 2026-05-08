#ifndef DATA_REDACTOR_SCAN_H
#define DATA_REDACTOR_SCAN_H

#include <ruby.h>

/* DataRedactor._scan(text, mask) -> { redacted: String, matches: Array<Hash> } */
VALUE rb_data_redactor_scan(VALUE self, VALUE rb_text, VALUE rb_mask);

#endif
