#ifndef DATA_REDACTOR_PLACEHOLDER_H
#define DATA_REDACTOR_PLACEHOLDER_H

#include <stddef.h>

#define PLACEHOLDER_MODE_PLAIN  0  /* use ph.str verbatim                  */
#define PLACEHOLDER_MODE_TAGGED 1  /* "[REDACTED:TAGNAME]"                 */
#define PLACEHOLDER_MODE_HASH   2  /* "[TAGNAME_xxxx]" (4-hex djb2 suffix) */

typedef struct {
    int         mode;
    const char *str;      /* plain string (mode 0); tag name (modes 1/2) */
} placeholder_t;

unsigned int djb2(const char *s, size_t len);

/*
 * Write the placeholder for one match into `buf` (which must be large enough).
 * Returns the number of bytes written.
 */
size_t write_placeholder(char *buf, const placeholder_t *ph,
                         const char *match, size_t match_len);

/* Upper bound on placeholder length for a given ph (for buffer sizing). */
size_t max_placeholder_len(const placeholder_t *ph);

/* Map a TAG_* bit to the uppercase tag name used in tagged/hash placeholders. */
const char *tag_name_for_bit(int tag_bit);

#endif
