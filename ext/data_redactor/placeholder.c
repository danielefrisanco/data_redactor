#include "placeholder.h"
#include "tags.h"
#include <stdio.h>
#include <string.h>

/* djb2 — fast, dependency-free, good enough for 4-hex log correlation */
unsigned int djb2(const char *s, size_t len) {
    unsigned int h = 5381;
    for (size_t i = 0; i < len; i++)
        h = h * 33 ^ (unsigned char)s[i];
    return h;
}

size_t write_placeholder(char *buf, const placeholder_t *ph,
                         const char *match, size_t match_len) {
    switch (ph->mode) {
        case PLACEHOLDER_MODE_TAGGED:
            return (size_t)sprintf(buf, "[REDACTED:%s]", ph->str);
        case PLACEHOLDER_MODE_HASH: {
            unsigned int h = djb2(match, match_len) & 0xFFFF;
            return (size_t)sprintf(buf, "[%s_%04x]", ph->str, h);
        }
        case PLACEHOLDER_MODE_LENGTH:
            return (size_t)sprintf(buf, "[REDACTED:%zu]", match_len);
        case PLACEHOLDER_MODE_TAGGED_LENGTH:
            return (size_t)sprintf(buf, "[REDACTED:%s:%zu]", ph->str, match_len);
        default: /* PLACEHOLDER_MODE_PLAIN */
            {
                size_t len = strlen(ph->str);
                memcpy(buf, ph->str, len);
                return len;
            }
    }
}

/* Widest decimal a size_t byte-length can print to (UINT64_MAX is 20 digits). */
#define MAX_LEN_DIGITS 20

size_t max_placeholder_len(const placeholder_t *ph) {
    size_t tag_len = strlen(ph->str);
    switch (ph->mode) {
        case PLACEHOLDER_MODE_TAGGED: return 2 + 9 + tag_len + 1; /* "[REDACTED:" + tag + "]" */
        case PLACEHOLDER_MODE_HASH:   return 1 + tag_len + 1 + 4 + 1; /* "[" + tag + "_" + 4hex + "]" */
        case PLACEHOLDER_MODE_LENGTH: return 10 + MAX_LEN_DIGITS + 1; /* "[REDACTED:" + digits + "]" */
        case PLACEHOLDER_MODE_TAGGED_LENGTH:
            return 10 + tag_len + 1 + MAX_LEN_DIGITS + 1; /* "[REDACTED:" + tag + ":" + digits + "]" */
        default:                      return tag_len;
    }
}

const char *tag_name_for_bit(int tag_bit) {
    switch (tag_bit) {
        case TAG_CREDENTIALS: return "CREDENTIALS";
        case TAG_FINANCIAL:   return "FINANCIAL";
        case TAG_TAX_ID:      return "TAX_ID";
        case TAG_NATIONAL_ID: return "NATIONAL_ID";
        case TAG_CONTACT:     return "CONTACT";
        case TAG_NETWORK:     return "NETWORK";
        case TAG_TRAVEL:      return "TRAVEL";
        case TAG_OTHER:       return "OTHER";
        case TAG_CUSTOM:      return "CUSTOM";
        default:              return "REDACTED";
    }
}
