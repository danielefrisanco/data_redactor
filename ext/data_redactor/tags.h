#ifndef DATA_REDACTOR_TAGS_H
#define DATA_REDACTOR_TAGS_H

/*
 * Tag bits. Each pattern belongs to exactly one tag. Callers can pass a
 * bitmask to restrict which patterns run (only / except). The default mask
 * (TAG_ALL) runs every pattern and matches the historical behaviour of
 * `redact(text)` with no second argument.
 */
#define TAG_CREDENTIALS  (1 << 0)
#define TAG_FINANCIAL    (1 << 1)
#define TAG_TAX_ID       (1 << 2)
#define TAG_NATIONAL_ID  (1 << 3)
#define TAG_CONTACT      (1 << 4)
#define TAG_NETWORK      (1 << 5)
#define TAG_TRAVEL       (1 << 6)
#define TAG_OTHER        (1 << 7)
#define TAG_CUSTOM       (1 << 8)
#define TAG_BUILTIN_ALL  (TAG_CREDENTIALS | TAG_FINANCIAL | TAG_TAX_ID | \
                          TAG_NATIONAL_ID | TAG_CONTACT | TAG_NETWORK | \
                          TAG_TRAVEL | TAG_OTHER)
#define TAG_ALL          (TAG_BUILTIN_ALL | TAG_CUSTOM)

#endif
