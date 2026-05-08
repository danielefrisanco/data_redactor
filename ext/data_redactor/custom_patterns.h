#ifndef DATA_REDACTOR_CUSTOM_PATTERNS_H
#define DATA_REDACTOR_CUSTOM_PATTERNS_H

#include <ruby.h>
#include <regex.h>

typedef struct {
    char    *name;
    char    *source;   /* original POSIX ERE string, for introspection */
    regex_t  compiled;
    int      tag;      /* TAG_* bit */
    int      boundary; /* 1 if compiled with boundary wrapper */
} custom_pattern_t;

extern custom_pattern_t *custom_patterns;
extern int custom_count;
extern int custom_cap;

VALUE rb_add_pattern(VALUE self, VALUE rb_name, VALUE rb_source,
                     VALUE rb_tag_bit, VALUE rb_boundary);
VALUE rb_remove_pattern(VALUE self, VALUE rb_name);
VALUE rb_clear_custom_patterns(VALUE self);
VALUE rb_custom_patterns(VALUE self);

#endif
