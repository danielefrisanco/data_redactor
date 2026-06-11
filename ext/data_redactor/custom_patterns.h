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

/* Guards the custom_patterns array against concurrent mutation. redact/scan
 * take it for the duration of their custom-pattern loop (readers); add/remove/
 * clear take it around the array mutation (writers). A plain mutex is enough:
 * contention is low (registration is rare relative to redaction) and the GVL
 * already serialises everything else, so the only race this closes is a writer
 * realloc/shift running against a reader's iteration. Lock is always taken
 * inside the GVL, never the reverse, so there is no lock-ordering hazard. */
void custom_patterns_lock(void);
void custom_patterns_unlock(void);

VALUE rb_add_pattern(VALUE self, VALUE rb_name, VALUE rb_source,
                     VALUE rb_tag_bit, VALUE rb_boundary);
VALUE rb_remove_pattern(VALUE self, VALUE rb_name);
VALUE rb_clear_custom_patterns(VALUE self);
VALUE rb_custom_patterns(VALUE self);

#endif
