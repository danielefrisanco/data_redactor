#include <ruby.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>

#define PLACEHOLDER "[REDACTED]"
#define PLACEHOLDER_LEN 10
#define NUM_PATTERNS 49

static regex_t compiled_patterns[NUM_PATTERNS];

/*
 * Patterns that consist of generic digit/alphanum sequences with no distinctive
 * prefix are wrapped with word-boundary groups:
 *   (^|[^0-9A-Za-z])(PATTERN)([^0-9A-Za-z]|$)
 * The boundary_wrapped flag tells replace_all_matches to use sub-match [2]
 * (the actual sensitive token) rather than the full match, so the surrounding
 * non-word characters are preserved and not replaced.
 */
static const int boundary_wrapped[NUM_PATTERNS] = {
    0, /* 0:  AWS Access Key ID — distinctive prefix */
    0, /* 1:  AWS Secret Key — 40 base64 chars, broad but accepted */
    0, /* 2:  Italian CF (old pattern, superseded by 22) */
    0, /* 3:  Passport letter+digits — letter prefix anchors it */
    1, /* 4:  Passport 9 digits — pure digits, needs boundary */
    0, /* 5:  Google API Key — AIza prefix */
    0, /* 6:  GitHub PAT — github_pat_ prefix */
    0, /* 7:  Slack Webhook — full URL prefix */
    0, /* 8:  Stripe Secret Key — sk_live_ prefix */
    0, /* 9:  PEM header — distinctive literal */
    0, /* 10: Italian IBAN — IT prefix */
    0, /* 11: Credit cards — specific digit prefixes make it self-anchoring */
    0, /* 12: IPv4 — dot separators make it self-anchoring */
    0, /* 13: Scaleway Access Key — SCW prefix */
    0, /* 14: UUID v4 — hyphen structure is self-anchoring */
    0, /* 15: France IBAN — FR prefix */
    0, /* 16: Germany IBAN — DE prefix */
    0, /* 17: Spain IBAN — ES prefix */
    0, /* 18: Netherlands IBAN — NL prefix */
    0, /* 19: Belgium IBAN — BE prefix */
    0, /* 20: Portugal IBAN — PT prefix */
    0, /* 21: Ireland IBAN — IE prefix */
    0, /* 22: Italian CF (omocodia) — fixed structure */
    1, /* 23: French NIR — pure digits, needs boundary */
    1, /* 24: Spanish DNI — 8 digits + letter, needs boundary */
    0, /* 25: Spanish NIE — X/Y/Z prefix */
    1, /* 26: Dutch BSN — pure digits, needs boundary */
    1, /* 27: Polish PESEL — pure digits, needs boundary */
    /* ---- Nordic IBANs ---- */
    0, /* 28: Sweden IBAN — SE prefix */
    0, /* 29: Denmark IBAN — DK prefix */
    0, /* 30: Norway IBAN — NO prefix */
    0, /* 31: Finland IBAN — FI prefix */
    /* ---- Nordic / Belgian national IDs ---- */
    1, /* 32: Belgian National Number (11 digits) — pure digits, needs boundary */
    1, /* 33: Swedish Personnummer (YYMMDD[-+]XXXX) — needs boundary */
    1, /* 34: Danish CPR Number (DDMMYY-XXXX) — needs boundary */
    1, /* 35: Norwegian Fødselsnummer (11 digits) — pure digits, needs boundary */
    1, /* 36: Finnish HETU (DDMMYY[+-A]XXXC) — needs boundary */
    /* ---- Central/Eastern European IBANs ---- */
    0, /* 37: Poland IBAN — PL prefix */
    0, /* 38: Austria IBAN — AT prefix */
    0, /* 39: Switzerland IBAN — CH prefix */
    0, /* 40: Czechia IBAN — CZ prefix */
    0, /* 41: Hungary IBAN — HU prefix */
    0, /* 42: Romania IBAN — RO prefix */
    /* ---- Central/Eastern European national IDs ---- */
    1, /* 43: Polish PESEL duplicate via PL slot — pure digits, needs boundary */
    1, /* 44: Austrian Abgabenkontonummer (9 digits) — pure digits, needs boundary */
    1, /* 45: Swiss AHV Number (756.XXXX.XXXX.XX) — needs boundary */
    1, /* 46: Czech Rodné číslo (YYMMDD/XXXX) — needs boundary */
    1, /* 47: Hungarian Tax ID (8XXXXXXXXX) — needs boundary */
    1  /* 48: Romanian CNP (13 digits starting 1-8) — needs boundary */
};

/*
 * Raw patterns. Boundary-wrapped patterns are stored unwrapped here;
 * the wrapper is applied in Init_data_redactor at compile time.
 */
static const char *pattern_strings[NUM_PATTERNS] = {
    /* 0: AWS Access Key ID (starts with AKIA or ASIA + 16 alphanum) */
    "(AKIA|ASIA)[A-Z0-9]{16}",
    /* 1: AWS Secret Access Key (40 base64 chars) */
    "[A-Za-z0-9/+=]{40}",
    /* 2: Italian Codice Fiscale (basic, superseded by 22) */
    "[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]",
    /* 3: Passport - letter prefix + digits (e.g. AB1234567) */
    "[A-Z]{1,2}[0-9]{6,7}",
    /* 4: Passport - 9 consecutive digits */
    "[0-9]{9}",
    /* 5: Google API Key */
    "AIza[0-9A-Za-z_-]{35}",
    /* 6: GitHub Personal Access Token (fine-grained) */
    "github_pat_[0-9a-zA-Z_]{82}",
    /* 7: Slack Webhook URL */
    "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
    /* 8: Stripe Secret Key */
    "sk_live_[0-9a-zA-Z]{24}",
    /* 9: PEM private key header (RSA, OpenSSH, EC) */
    "-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----",
    /* 10: Italian IBAN (IT + 2 check digits + CIN letter + ABI + CAB + account) */
    "IT[0-9]{2}[A-Z][0-9]{10}[A-Z0-9]{12}",
    /* 11: Credit card numbers (Visa, Mastercard, Amex, Discover, JCB) — outer group required */
    "(4[0-9]{15}|4[0-9]{12}|5[1-5][0-9]{14}|6011[0-9]{12}|65[0-9]{14}|3[47][0-9]{13}|3[068][0-9]{11}|35[0-9]{14})",
    /* 12: IPv4 address */
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
    /* 13: Scaleway Access Key (SCW + 17 uppercase alphanum) */
    "SCW[A-Z0-9]{17}",
    /* 14: UUID v4 / Scaleway Secret Key */
    "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",

    /* ---- European IBANs ---- */
    /* 15: France IBAN (FR, 27 chars) */
    "FR[0-9]{2}[0-9]{10}[A-Z0-9]{11}[0-9]{2}",
    /* 16: Germany IBAN (DE, 22 chars) */
    "DE[0-9]{2}[0-9]{18}",
    /* 17: Spain IBAN (ES, 24 chars) */
    "ES[0-9]{2}[0-9]{20}",
    /* 18: Netherlands IBAN (NL, 18 chars) */
    "NL[0-9]{2}[A-Z]{4}[0-9]{10}",
    /* 19: Belgium IBAN (BE, 16 chars) */
    "BE[0-9]{2}[0-9]{12}",
    /* 20: Portugal IBAN (PT, 25 chars) */
    "PT[0-9]{2}[0-9]{21}",
    /* 21: Ireland IBAN (IE, 22 chars) */
    "IE[0-9]{2}[A-Z]{4}[0-9]{14}",

    /* ---- National Tax / Personal ID Codes ---- */
    /* 22: Italian Codice Fiscale (with omocodia chars) */
    "[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]",
    /* 23: French NIR / Social Security (15 digits) */
    "[12][0-9]{2}[01][0-9][0-9]{2}[0-9]{3}[0-9]{3}[0-9]{2}",
    /* 24: Spanish DNI (8 digits + 1 letter) */
    "[0-9]{8}[A-Z]",
    /* 25: Spanish NIE (X/Y/Z + 7 digits + 1 letter) */
    "[XYZ][0-9]{7}[A-Z]",
    /* 26: Dutch BSN (8 or 9 digits) */
    "[0-9]{8,9}",
    /* 27: Polish PESEL (11 digits, YYMMDDXXXXX) */
    "[0-9]{11}",

    /* ---- Nordic IBANs ---- */
    /* 28: Sweden IBAN (SE, 24 chars) */
    "SE[0-9]{2}[0-9]{20}",
    /* 29: Denmark IBAN (DK, 18 chars) */
    "DK[0-9]{2}[0-9]{14}",
    /* 30: Norway IBAN (NO, 15 chars) */
    "NO[0-9]{2}[0-9]{11}",
    /* 31: Finland IBAN (FI, 18 chars) */
    "FI[0-9]{2}[0-9]{14}",

    /* ---- Nordic / Belgian national IDs ---- */
    /* 32: Belgian National Number (11 digits) */
    "[0-9]{11}",
    /* 33: Swedish Personnummer (YYMMDD[-+]XXXX) */
    "[0-9]{6}[-+][0-9]{4}",
    /* 34: Danish CPR Number (DDMMYY-XXXX) */
    "[0-9]{6}-[0-9]{4}",
    /* 35: Norwegian Fødselsnummer (11 digits) */
    "[0-9]{11}",
    /* 36: Finnish HETU (DDMMYY[+-A]XXXC) */
    "[0-9]{6}[-+A][0-9]{3}[0-9A-Y]",

    /* ---- Central/Eastern European IBANs ---- */
    /* 37: Poland IBAN (PL, 28 chars) */
    "PL[0-9]{2}[0-9]{24}",
    /* 38: Austria IBAN (AT, 20 chars) */
    "AT[0-9]{2}[0-9]{16}",
    /* 39: Switzerland IBAN (CH, 21 chars) */
    "CH[0-9]{2}[0-9]{5}[A-Z0-9]{12}",
    /* 40: Czechia IBAN (CZ, 24 chars) */
    "CZ[0-9]{2}[0-9]{20}",
    /* 41: Hungary IBAN (HU, 28 chars) */
    "HU[0-9]{2}[0-9]{24}",
    /* 42: Romania IBAN (RO, 24 chars) */
    "RO[0-9]{2}[A-Z]{4}[A-Z0-9]{16}",

    /* ---- Central/Eastern European national IDs ---- */
    /* 43: Polish PESEL (11 digits) — same pattern as 27 */
    "[0-9]{11}",
    /* 44: Austrian Abgabenkontonummer (9 digits) */
    "[0-9]{9}",
    /* 45: Swiss AHV Number (756.XXXX.XXXX.XX) */
    "756\\.[0-9]{4}\\.[0-9]{4}\\.[0-9]{2}",
    /* 46: Czech Rodné cislo (YYMMDD/XXXX or YYMMDDXXXX) */
    "[0-9]{6}/?[0-9]{3,4}",
    /* 47: Hungarian Tax ID (starts with 8, 10 digits total) */
    "8[0-9]{9}",
    /* 48: Romanian CNP (13 digits, first digit 1-8) */
    "[1-8][0-9]{12}"
};

/*
 * Replace all occurrences of a compiled pattern in `input` with PLACEHOLDER.
 *
 * If `use_boundary` is non-zero the pattern was compiled as:
 *   (^|[^0-9A-Za-z])(CORE)([^0-9A-Za-z]|$)
 * groups: [0]=full match  [1]=left boundary  [2]=CORE  [3]=right boundary
 * We pass nmatch=4 so the engine fills all four slots, then use matches[1].rm_eo
 * and matches[3].rm_so to locate the exact CORE span.  The boundary characters
 * are copied back verbatim so they are not lost.
 *
 * NOTE: CORE must NOT contain additional capture groups — if it does, group
 * indices shift and matches[2]/[3] will be wrong.  All boundary-wrapped
 * patterns in pattern_strings[] are written without inner groups for this reason.
 *
 * Returns a newly malloc'd string (caller must free), or NULL on failure.
 */
static char *replace_all_matches(regex_t *pattern, const char *input, int use_boundary) {
    size_t out_cap = strlen(input) * 2 + 512;
    char *output = (char *)malloc(out_cap);
    if (!output) return NULL;

    size_t out_len = 0;
    const char *cursor = input;
    regmatch_t matches[4];

    while (regexec(pattern, cursor, 4, matches, 0) == 0) {
        regoff_t full_so = matches[0].rm_so;
        regoff_t full_eo = matches[0].rm_eo;

        if (full_so < 0 || full_eo < full_so) break;

        regoff_t core_so = full_so;
        regoff_t core_eo = full_eo;

        if (use_boundary) {
            /* group 1: left boundary char (or empty at ^) */
            if (matches[1].rm_so >= 0 && matches[1].rm_eo > matches[1].rm_so)
                core_so = matches[1].rm_eo;
            /* group 3: right boundary char (or empty at $) */
            if (matches[3].rm_so >= 0 && matches[3].rm_eo > matches[3].rm_so)
                core_eo = matches[3].rm_so;
        }

        size_t prefix_len  = (size_t)core_so;
        size_t suffix_len  = (size_t)(full_eo - core_eo);
        size_t match_len   = (size_t)(full_eo - full_so);

        size_t needed = out_len + prefix_len + PLACEHOLDER_LEN + suffix_len + strlen(cursor + full_eo) + 1;
        if (needed > out_cap) {
            out_cap = needed * 2;
            char *tmp = (char *)realloc(output, out_cap);
            if (!tmp) { free(output); return NULL; }
            output = tmp;
        }

        /* Copy prefix (includes left boundary char if present) */
        memcpy(output + out_len, cursor, prefix_len);
        out_len += prefix_len;

        /* Replace the core token */
        memcpy(output + out_len, PLACEHOLDER, PLACEHOLDER_LEN);
        out_len += PLACEHOLDER_LEN;

        /* Restore right boundary char */
        if (suffix_len > 0) {
            memcpy(output + out_len, cursor + core_eo, suffix_len);
            out_len += suffix_len;
        }

        cursor += full_eo;

        if (match_len == 0) {
            if (*cursor) output[out_len++] = *cursor++;
            else break;
        }
    }

    /* Copy the remaining unmatched tail */
    size_t tail_len = strlen(cursor);
    size_t needed = out_len + tail_len + 1;
    if (needed > out_cap) {
        out_cap = needed;
        char *tmp = (char *)realloc(output, out_cap);
        if (!tmp) { free(output); return NULL; }
        output = tmp;
    }
    memcpy(output + out_len, cursor, tail_len);
    out_len += tail_len;
    output[out_len] = '\0';

    return output;
}

/*
 * DataRedactor.redact(text) -> String
 *
 * Scans the input text for sensitive patterns and replaces matches
 * with [REDACTED].
 */
static VALUE rb_data_redactor_redact(VALUE self, VALUE rb_text) {
    Check_Type(rb_text, T_STRING);

    const char *input = StringValueCStr(rb_text);
    char *working = strdup(input);
    if (!working) {
        rb_raise(rb_eNoMemError, "strdup failed");
    }

    for (int i = 0; i < NUM_PATTERNS; i++) {
        char *result = replace_all_matches(&compiled_patterns[i], working, boundary_wrapped[i]);
        free(working);
        if (!result) {
            rb_raise(rb_eNoMemError, "replace_all_matches allocation failed");
        }
        working = result;
    }

    VALUE rb_result = rb_str_new_cstr(working);
    free(working);

    return rb_result;
}

/*
 * Build a boundary-wrapped version of a pattern:
 *   (^|[^0-9A-Za-z])(PATTERN)([^0-9A-Za-z]|$)
 * Caller must free the returned string.
 */
static char *wrap_boundary(const char *core) {
    const char *prefix = "(^|[^0-9A-Za-z])(";
    const char *suffix = ")([^0-9A-Za-z]|$)";
    size_t len = strlen(prefix) + strlen(core) + strlen(suffix) + 1;
    char *buf = (char *)malloc(len);
    if (!buf) return NULL;
    snprintf(buf, len, "%s%s%s", prefix, core, suffix);
    return buf;
}

void Init_data_redactor(void) {
    /* Compile all regex patterns at load time */
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
        free(wrapped); /* safe to free after regcomp copies the pattern */

        if (ret != 0) {
            char errbuf[256];
            regerror(ret, &compiled_patterns[i], errbuf, sizeof(errbuf));
            rb_raise(rb_eRuntimeError, "Failed to compile pattern %d: %s", i, errbuf);
        }
    }

    VALUE mDataRedactor = rb_define_module("DataRedactor");
    rb_define_module_function(mDataRedactor, "redact", rb_data_redactor_redact, 1);
}
