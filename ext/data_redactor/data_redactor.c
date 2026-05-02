#include <ruby.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>

#define NUM_PATTERNS 79

#define PLACEHOLDER_MODE_PLAIN  0  /* use ph.str verbatim                  */
#define PLACEHOLDER_MODE_TAGGED 1  /* "[REDACTED:TAGNAME]"                 */
#define PLACEHOLDER_MODE_HASH   2  /* "[TAGNAME_xxxx]" (4-hex djb2 suffix) */

typedef struct {
    int         mode;
    const char *str;      /* plain string (mode 0); tag name (modes 1/2) */
} placeholder_t;

/* djb2 — fast, dependency-free, good enough for 4-hex log correlation */
static unsigned int djb2(const char *s, size_t len) {
    unsigned int h = 5381;
    for (size_t i = 0; i < len; i++)
        h = h * 33 ^ (unsigned char)s[i];
    return h;
}

/*
 * Write the placeholder for one match into `buf` (which must be large enough).
 * Returns the number of bytes written.
 *
 * mode 0 (plain):  writes ph->str verbatim
 * mode 1 (tagged): writes "[REDACTED:TAGNAME]"
 * mode 2 (hash):   writes "[TAGNAME_xxxx]" where xxxx = low 16 bits of djb2(match)
 */
static size_t write_placeholder(char *buf, const placeholder_t *ph,
                                const char *match, size_t match_len) {
    switch (ph->mode) {
        case PLACEHOLDER_MODE_TAGGED:
            return (size_t)sprintf(buf, "[REDACTED:%s]", ph->str);
        case PLACEHOLDER_MODE_HASH: {
            unsigned int h = djb2(match, match_len) & 0xFFFF;
            return (size_t)sprintf(buf, "[%s_%04x]", ph->str, h);
        }
        default: /* PLACEHOLDER_MODE_PLAIN */
            {
                size_t len = strlen(ph->str);
                memcpy(buf, ph->str, len);
                return len;
            }
    }
}

/* Upper bound on placeholder length for a given ph (for buffer sizing). */
static size_t max_placeholder_len(const placeholder_t *ph) {
    size_t tag_len = strlen(ph->str);
    switch (ph->mode) {
        case PLACEHOLDER_MODE_TAGGED: return 2 + 9 + tag_len + 1; /* "[REDACTED:" + tag + "]" */
        case PLACEHOLDER_MODE_HASH:   return 1 + tag_len + 1 + 4 + 1; /* "[" + tag + "_" + 4hex + "]" */
        default:                      return tag_len;
    }
}

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

static regex_t compiled_patterns[NUM_PATTERNS];

/*
 * Patterns that consist of generic digit/alphanum sequences with no distinctive
 * prefix are wrapped with word-boundary groups:
 *   (^|[^0-9A-Za-z])(PATTERN)([^0-9A-Za-z]|$)
 * The boundary_wrapped flag tells replace_all_matches to use sub-match [2]
 * (the actual sensitive token) rather than the full match, so the surrounding
 * non-word characters are preserved and not replaced.
 */
/*
 * ORDERING: Most specific / longest patterns first, most generic last.
 * This prevents shorter patterns from consuming parts of longer matches.
 *
 * Tiers:
 *   1. Full URLs (longest, most distinctive)
 *   2. Long prefixed tokens (API keys, PATs)
 *   3. IBANs (country prefix + fixed length)
 *   4. Structured formats (dots, dashes, slashes)
 *   5. Short prefixed / letter-anchored patterns
 *   6. Boundary-wrapped structured (dash/dot separated digits)
 *   7. Boundary-wrapped pure digits (longest → shortest)
 */
static const int boundary_wrapped[NUM_PATTERNS] = {
    /* ---- Tier 1: Full URLs ---- */
    0, /*  0: AWS S3 Presigned URL */
    0, /*  1: Microsoft Teams Webhook */
    0, /*  2: Slack Webhook URL */
    0, /*  3: MongoDB Connection String */
    0, /*  4: URI with Embedded Password */
    /* ---- Tier 2: Long prefixed tokens ---- */
    0, /*  5: GitHub PAT (fine-grained, 93 chars) */
    0, /*  6: JWT */
    0, /*  7: Grafana API Token */
    0, /*  8: SSH Public Key */
    0, /*  9: Bearer Token */
    0, /* 10: Google API Key (39 chars) */
    0, /* 11: AWS Access Key ID (20 chars) */
    0, /* 12: AWS Secret Access Key (40 base64) */
    0, /* 13: SendGrid API Key */
    0, /* 14: Amazon MWS Auth Token */
    0, /* 15: LaunchDarkly API Key */
    0, /* 16: GitHub Classic PAT (ghp_) */
    0, /* 17: GitHub OAuth Token (gho_) */
    0, /* 18: Stripe Secret Key */
    0, /* 19: ClickUp API Key */
    0, /* 20: Scaleway Access Key */
    0, /* 21: PEM private key header (generic) */
    0, /* 22: GPG Private Key Block */
    /* ---- Tier 3: IBANs (longest → shortest) ---- */
    0, /* 23: Hungary IBAN (28 chars) */
    0, /* 24: Poland IBAN (28 chars) */
    0, /* 25: France IBAN (27 chars) */
    0, /* 26: Italy IBAN (27 chars) */
    0, /* 27: Portugal IBAN (25 chars) */
    0, /* 28: Spain IBAN (24 chars) */
    0, /* 29: Czechia IBAN (24 chars) */
    0, /* 30: Romania IBAN (24 chars) */
    0, /* 31: Sweden IBAN (24 chars) */
    0, /* 32: Germany IBAN (22 chars) */
    0, /* 33: Ireland IBAN (22 chars) */
    0, /* 34: Switzerland IBAN (21 chars) */
    0, /* 35: Austria IBAN (20 chars) */
    0, /* 36: Netherlands IBAN (18 chars) */
    0, /* 37: Denmark IBAN (18 chars) */
    0, /* 38: Finland IBAN (18 chars) */
    0, /* 39: Belgium IBAN (16 chars) */
    0, /* 40: Norway IBAN (15 chars) */
    /* ---- Tier 4: Structured formats (dots, dashes, slashes, @) ---- */
    0, /* 41: Email Address */
    0, /* 42: International Phone Number */
    0, /* 43: Brazilian CNPJ (XX.XXX.XXX/XXXX-XX) */
    0, /* 44: Brazilian CPF (XXX.XXX.XXX-XX) */
    0, /* 45: UUID v4 */
    0, /* 46: IPv4 address */
    0, /* 47: Credit card numbers */
    0, /* 48: Indian Aadhaar (XXXX XXXX XXXX) */
    /* ---- Tier 5: Letter-anchored patterns ---- */
    0, /* 49: Mexican CURP (18 alphanum, distinctive structure) */
    0, /* 50: Italian CF with omocodia (16 chars) */
    0, /* 51: Italian CF basic (16 chars) */
    0, /* 52: UK National Insurance Number */
    0, /* 53: Spanish NIE (X/Y/Z prefix) */
    0, /* 54: Passport letter prefix + digits */
    /* ---- Tier 6: Boundary-wrapped structured (dash/dot/slash separated) ---- */
    1, /* 55: South Korean RRN (YYMMDD-XXXXXXX, 14 chars) */
    1, /* 56: Swiss AHV Number (756.XXXX.XXXX.XX) */
    1, /* 57: Finnish HETU (DDMMYY[+-A]XXXC) */
    1, /* 58: Swedish Personnummer (YYMMDD[-+]XXXX) */
    1, /* 59: Danish CPR Number (DDMMYY-XXXX) */
    1, /* 60: Czech Rodné číslo (YYMMDD/XXXX) */
    1, /* 61: US Social Security Number (XXX-XX-XXXX) */
    1, /* 62: US ITIN (9XX-XX-XXXX) */
    1, /* 63: Canadian SIN (XXX-XXX-XXX) */
    1, /* 64: Australian TFN (XXX-XXX-XXX) */
    1, /* 65: Indian PAN (AAAAA0000A) */
    1, /* 66: Spanish DNI (8 digits + letter) */
    1, /* 67: Hungarian Tax ID (8XXXXXXXXX, 10 digits) */
    /* ---- Tier 7: Boundary-wrapped pure digits (longest → shortest) ---- */
    1, /* 68: French NIR (15 digits) */
    1, /* 69: South African ID (13 digits) */
    1, /* 70: Romanian CNP (13 digits) */
    1, /* 71: Japanese My Number (12 digits) */
    1, /* 72: Polish PESEL (11 digits) */
    1, /* 73: Belgian National Number (11 digits) */
    1, /* 74: Norwegian Fødselsnummer (11 digits) */
    1, /* 75: Passport 9 digits */
    1, /* 76: Dutch BSN (8-9 digits) */
    1, /* 77: Austrian Abgabenkontonummer (9 digits) */
    1  /* 78: Polish PESEL duplicate */
};

/*
 * Tag for each pattern. Exactly one tag per pattern. Used to filter which
 * patterns run when the caller passes a mask (only/except).
 */
static const int pattern_tags[NUM_PATTERNS] = {
    /* 0-22: secrets, API keys, tokens, private keys, webhooks */
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    /* 23-40: IBANs */
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_CONTACT,      /* 41: email */
    TAG_CONTACT,      /* 42: phone */
    TAG_TAX_ID,       /* 43: Brazilian CNPJ */
    TAG_TAX_ID,       /* 44: Brazilian CPF */
    TAG_OTHER,        /* 45: UUID v4 */
    TAG_NETWORK,      /* 46: IPv4 */
    TAG_FINANCIAL,    /* 47: credit card */
    TAG_NATIONAL_ID,  /* 48: Indian Aadhaar */
    TAG_NATIONAL_ID,  /* 49: Mexican CURP */
    TAG_TAX_ID,       /* 50: Italian CF (omocodia) */
    TAG_TAX_ID,       /* 51: Italian CF (basic) */
    TAG_NATIONAL_ID,  /* 52: UK NIN */
    TAG_NATIONAL_ID,  /* 53: Spanish NIE */
    TAG_TRAVEL,       /* 54: passport letter prefix */
    TAG_NATIONAL_ID,  /* 55: Korean RRN */
    TAG_NATIONAL_ID,  /* 56: Swiss AHV */
    TAG_NATIONAL_ID,  /* 57: Finnish HETU */
    TAG_NATIONAL_ID,  /* 58: Swedish Personnummer */
    TAG_NATIONAL_ID,  /* 59: Danish CPR */
    TAG_NATIONAL_ID,  /* 60: Czech Rodné číslo */
    TAG_NATIONAL_ID,  /* 61: US SSN */
    TAG_TAX_ID,       /* 62: US ITIN */
    TAG_NATIONAL_ID,  /* 63: Canadian SIN */
    TAG_TAX_ID,       /* 64: Australian TFN */
    TAG_TAX_ID,       /* 65: Indian PAN */
    TAG_NATIONAL_ID,  /* 66: Spanish DNI */
    TAG_TAX_ID,       /* 67: Hungarian Tax ID */
    TAG_NATIONAL_ID,  /* 68: French NIR */
    TAG_NATIONAL_ID,  /* 69: South African ID */
    TAG_NATIONAL_ID,  /* 70: Romanian CNP */
    TAG_TAX_ID,       /* 71: Japanese My Number */
    TAG_NATIONAL_ID,  /* 72: Polish PESEL */
    TAG_NATIONAL_ID,  /* 73: Belgian National Number */
    TAG_NATIONAL_ID,  /* 74: Norwegian Fødselsnummer */
    TAG_TRAVEL,       /* 75: passport 9 digits */
    TAG_NATIONAL_ID,  /* 76: Dutch BSN */
    TAG_TAX_ID,       /* 77: Austrian Abgabenkontonummer */
    TAG_NATIONAL_ID   /* 78: Polish PESEL duplicate */
};

static const char *pattern_names[NUM_PATTERNS] = {
    "aws_s3_presigned_url",          /*  0 */
    "microsoft_teams_webhook",       /*  1 */
    "slack_webhook_url",             /*  2 */
    "mongodb_connection_string",     /*  3 */
    "uri_with_password",             /*  4 */
    "github_pat_fine_grained",       /*  5 */
    "jwt",                           /*  6 */
    "grafana_api_token",             /*  7 */
    "ssh_public_key",                /*  8 */
    "bearer_token",                  /*  9 */
    "google_api_key",                /* 10 */
    "aws_access_key_id",             /* 11 */
    "aws_secret_access_key",         /* 12 */
    "sendgrid_api_key",              /* 13 */
    "amazon_mws_auth_token",         /* 14 */
    "launchdarkly_api_key",          /* 15 */
    "github_classic_pat",            /* 16 */
    "github_oauth_token",            /* 17 */
    "stripe_secret_key",             /* 18 */
    "clickup_api_key",               /* 19 */
    "scaleway_access_key",           /* 20 */
    "pem_private_key",               /* 21 */
    "gpg_private_key",               /* 22 */
    "iban_hu",                       /* 23 */
    "iban_pl",                       /* 24 */
    "iban_fr",                       /* 25 */
    "iban_it",                       /* 26 */
    "iban_pt",                       /* 27 */
    "iban_es",                       /* 28 */
    "iban_cz",                       /* 29 */
    "iban_ro",                       /* 30 */
    "iban_se",                       /* 31 */
    "iban_de",                       /* 32 */
    "iban_ie",                       /* 33 */
    "iban_ch",                       /* 34 */
    "iban_at",                       /* 35 */
    "iban_nl",                       /* 36 */
    "iban_dk",                       /* 37 */
    "iban_fi",                       /* 38 */
    "iban_be",                       /* 39 */
    "iban_no",                       /* 40 */
    "email",                         /* 41 */
    "phone_e164",                    /* 42 */
    "brazilian_cnpj",                /* 43 */
    "brazilian_cpf",                 /* 44 */
    "uuid_v4",                       /* 45 */
    "ipv4",                          /* 46 */
    "credit_card",                   /* 47 */
    "indian_aadhaar",                /* 48 */
    "mexican_curp",                  /* 49 */
    "italian_cf_omocodia",           /* 50 */
    "italian_cf",                    /* 51 */
    "uk_nin",                        /* 52 */
    "spanish_nie",                   /* 53 */
    "passport_letter_prefix",        /* 54 */
    "korean_rrn",                    /* 55 */
    "swiss_ahv",                     /* 56 */
    "finnish_hetu",                  /* 57 */
    "swedish_personnummer",          /* 58 */
    "danish_cpr",                    /* 59 */
    "czech_rodne_cislo",             /* 60 */
    "us_ssn",                        /* 61 */
    "us_itin",                       /* 62 */
    "canadian_sin",                  /* 63 */
    "australian_tfn",                /* 64 */
    "indian_pan",                    /* 65 */
    "spanish_dni",                   /* 66 */
    "hungarian_tax_id",              /* 67 */
    "french_nir",                    /* 68 */
    "south_african_id",              /* 69 */
    "romanian_cnp",                  /* 70 */
    "japanese_my_number",            /* 71 */
    "polish_pesel",                  /* 72 */
    "belgian_national_number",       /* 73 */
    "norwegian_fodselsnummer",       /* 74 */
    "passport_9digits",              /* 75 */
    "dutch_bsn",                     /* 76 */
    "austrian_abgabenkontonummer",   /* 77 */
    "polish_pesel_2"                 /* 78 */
};

/*
 * Raw patterns. Boundary-wrapped patterns are stored unwrapped here;
 * the wrapper is applied in Init_data_redactor at compile time.
 */
static const char *pattern_strings[NUM_PATTERNS] = {
    /* ---- Tier 1: Full URLs ---- */
    /*  0: AWS S3 Presigned URL */
    "https://[a-z0-9.-]+\\.s3\\.amazonaws\\.com/[^[:space:]?]+\\?[^[:space:]]*X-Amz-Signature=[^[:space:]]+",
    /*  1: Microsoft Teams Incoming Webhook */
    "https://[a-z0-9-]+\\.webhook\\.office\\.com/webhookb2/[a-fA-F0-9-]{36}@[a-fA-F0-9-]{36}/[^/ ]+/[a-fA-F0-9]{32}/[a-fA-F0-9-]{36}",
    /*  2: Slack Webhook URL */
    "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
    /*  3: MongoDB Connection String (with credentials) */
    "mongodb(\\+srv)?://[^[:space:]'\"<>/:@]+:[^[:space:]'\"<>/@]+@[^[:space:]?'\"]+",
    /*  4: URI with Embedded Password (scheme://user:pass@host) */
    "[A-Za-z][A-Za-z0-9+_-]*://[^[:space:]/?#:@]+:[^[:space:]/?#@]+@[A-Za-z0-9.-]+",

    /* ---- Tier 2: Long prefixed tokens ---- */
    /*  5: GitHub PAT fine-grained (github_pat_ + 82 chars) */
    "github_pat_[0-9a-zA-Z_]{82}",
    /*  6: JWT (three base64url segments) */
    "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+",
    /*  7: Grafana API Token (base64 of {"k":") */
    "eyJrIjoi[A-Za-z0-9_=-]{42,}",
    /*  8: SSH Public Key */
    "ssh-(rsa|ed25519|ecdsa) [a-zA-Z0-9/+=]{20,}",
    /*  9: Bearer Token */
    "[Bb]earer [a-zA-Z0-9_.=/+:-]{12,}",
    /* 10: Google API Key (AIza + 35 chars) */
    "AIza[0-9A-Za-z_-]{35}",
    /* 11: AWS Access Key ID (all prefixes + 16 chars) */
    "(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z2-7]{16}",
    /* 12: AWS Secret Access Key (40 base64 chars) */
    "[A-Za-z0-9/+=]{40}",
    /* 13: SendGrid API Key */
    "SG\\.[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{5,}",
    /* 14: Amazon MWS Auth Token */
    "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    /* 15: LaunchDarkly API Key (api-UUID or sdk-UUID) */
    "(api|sdk)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    /* 16: GitHub Classic PAT (ghp_ + 36 chars) */
    "ghp_[0-9a-zA-Z]{36}",
    /* 17: GitHub OAuth Token (gho_ + 36 chars) */
    "gho_[0-9a-zA-Z]{36}",
    /* 18: Stripe Secret Key (sk_live_ + 24 chars) */
    "sk_live_[0-9a-zA-Z]{24}",
    /* 19: ClickUp API Key */
    "pk_[0-9]{6,8}_[A-Z0-9]{32}",
    /* 20: Scaleway Access Key (SCW + 17 chars) */
    "SCW[A-Z0-9]{17}",
    /* 21: PEM private key header (generic) */
    "-----BEGIN [A-Z ]*PRIVATE KEY-----",
    /* 22: GPG Private Key Block */
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",

    /* ---- Tier 3: IBANs (longest → shortest) ---- */
    /* 23: Hungary IBAN (HU, 28 chars) */
    "HU[0-9]{2}[0-9]{24}",
    /* 24: Poland IBAN (PL, 28 chars) */
    "PL[0-9]{2}[0-9]{24}",
    /* 25: France IBAN (FR, 27 chars) */
    "FR[0-9]{2}[0-9]{10}[A-Z0-9]{11}[0-9]{2}",
    /* 26: Italy IBAN (IT, 27 chars) */
    "IT[0-9]{2}[A-Z][0-9]{10}[A-Z0-9]{12}",
    /* 27: Portugal IBAN (PT, 25 chars) */
    "PT[0-9]{2}[0-9]{21}",
    /* 28: Spain IBAN (ES, 24 chars) */
    "ES[0-9]{2}[0-9]{20}",
    /* 29: Czechia IBAN (CZ, 24 chars) */
    "CZ[0-9]{2}[0-9]{20}",
    /* 30: Romania IBAN (RO, 24 chars) */
    "RO[0-9]{2}[A-Z]{4}[A-Z0-9]{16}",
    /* 31: Sweden IBAN (SE, 24 chars) */
    "SE[0-9]{2}[0-9]{20}",
    /* 32: Germany IBAN (DE, 22 chars) */
    "DE[0-9]{2}[0-9]{18}",
    /* 33: Ireland IBAN (IE, 22 chars) */
    "IE[0-9]{2}[A-Z]{4}[0-9]{14}",
    /* 34: Switzerland IBAN (CH, 21 chars) */
    "CH[0-9]{2}[0-9]{5}[A-Z0-9]{12}",
    /* 35: Austria IBAN (AT, 20 chars) */
    "AT[0-9]{2}[0-9]{16}",
    /* 36: Netherlands IBAN (NL, 18 chars) */
    "NL[0-9]{2}[A-Z]{4}[0-9]{10}",
    /* 37: Denmark IBAN (DK, 18 chars) */
    "DK[0-9]{2}[0-9]{14}",
    /* 38: Finland IBAN (FI, 18 chars) */
    "FI[0-9]{2}[0-9]{14}",
    /* 39: Belgium IBAN (BE, 16 chars) */
    "BE[0-9]{2}[0-9]{12}",
    /* 40: Norway IBAN (NO, 15 chars) */
    "NO[0-9]{2}[0-9]{11}",

    /* ---- Tier 4: Structured formats (dots, dashes, slashes, @) ---- */
    /* 41: Email Address */
    "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    /* 42: International Phone Number (E.164) */
    "\\+[0-9]{1,3}[- ]?[0-9][0-9 -]{6,13}[0-9]",
    /* 43: Brazilian CNPJ (XX.XXX.XXX/XXXX-XX) */
    "[0-9]{2}\\.[0-9]{3}\\.[0-9]{3}/[0-9]{4}-[0-9]{2}",
    /* 44: Brazilian CPF (XXX.XXX.XXX-XX) */
    "[0-9]{3}\\.[0-9]{3}\\.[0-9]{3}-[0-9]{2}",
    /* 45: UUID v4 / Scaleway Secret Key */
    "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    /* 46: IPv4 address */
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
    /* 47: Credit card numbers (Visa, Mastercard, Amex, Discover, JCB) */
    "(4[0-9]{15}|4[0-9]{12}|5[1-5][0-9]{14}|6011[0-9]{12}|65[0-9]{14}|3[47][0-9]{13}|3[068][0-9]{11}|35[0-9]{14})",
    /* 48: Indian Aadhaar (XXXX XXXX XXXX or XXXX-XXXX-XXXX) */
    "[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}",

    /* ---- Tier 5: Letter-anchored patterns ---- */
    /* 49: Mexican CURP (18 alphanum, distinctive structure) */
    "[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[A-Z0-9][0-9]",
    /* 50: Italian CF with omocodia (16 chars) */
    "[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]",
    /* 51: Italian CF basic (16 chars) */
    "[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]",
    /* 52: UK National Insurance Number (AA 99 99 99 A-D) */
    "[A-Z]{2} ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D]",
    /* 53: Spanish NIE (X/Y/Z + 7 digits + letter) */
    "[XYZ][0-9]{7}[A-Z]",
    /* 54: Passport - letter prefix + digits (e.g. AB1234567) */
    "[A-Z]{1,2}[0-9]{6,7}",

    /* ---- Tier 6: Boundary-wrapped structured (dash/dot/slash separated) ---- */
    /* 55: South Korean RRN (YYMMDD-XXXXXXX, 14 chars with dash) */
    "[0-9]{6}-[0-9]{7}",
    /* 56: Swiss AHV Number (756.XXXX.XXXX.XX) */
    "756\\.[0-9]{4}\\.[0-9]{4}\\.[0-9]{2}",
    /* 57: Finnish HETU (DDMMYY[+-A]XXXC) */
    "[0-9]{6}[-+A][0-9]{3}[0-9A-Y]",
    /* 58: Swedish Personnummer (YYMMDD[-+]XXXX) */
    "[0-9]{6}[-+][0-9]{4}",
    /* 59: Danish CPR Number (DDMMYY-XXXX) */
    "[0-9]{6}-[0-9]{4}",
    /* 60: Czech Rodné číslo (YYMMDD/XXXX or YYMMDDXXXX) */
    "[0-9]{6}/?[0-9]{3,4}",
    /* 61: US Social Security Number (XXX-XX-XXXX) */
    "[0-9]{3}-[0-9]{2}-[0-9]{4}",
    /* 62: US ITIN (9XX-XX-XXXX) */
    "9[0-9]{2}-[0-9]{2}-[0-9]{4}",
    /* 63: Canadian SIN (XXX-XXX-XXX) */
    "[0-9]{3}-[0-9]{3}-[0-9]{3}",
    /* 64: Australian TFN (XXX-XXX-XXX or XXX XXX XXX) */
    "[0-9]{3}[- ][0-9]{3}[- ][0-9]{3}",
    /* 65: Indian PAN (5 letters + 4 digits + 1 letter) */
    "[A-Z]{5}[0-9]{4}[A-Z]",
    /* 66: Spanish DNI (8 digits + 1 letter) */
    "[0-9]{8}[A-Z]",
    /* 67: Hungarian Tax ID (starts with 8, 10 digits) */
    "8[0-9]{9}",

    /* ---- Tier 7: Boundary-wrapped pure digits (longest → shortest) ---- */
    /* 68: French NIR / Social Security (15 digits) */
    "[12][0-9]{2}[01][0-9][0-9]{2}[0-9]{3}[0-9]{3}[0-9]{2}",
    /* 69: South African ID (13 digits) */
    "[0-9]{13}",
    /* 70: Romanian CNP (13 digits, first digit 1-8) */
    "[1-8][0-9]{12}",
    /* 71: Japanese My Number (12 digits) */
    "[0-9]{12}",
    /* 72: Polish PESEL (11 digits) */
    "[0-9]{11}",
    /* 73: Belgian National Number (11 digits) */
    "[0-9]{11}",
    /* 74: Norwegian Fødselsnummer (11 digits) */
    "[0-9]{11}",
    /* 75: Passport - 9 consecutive digits */
    "[0-9]{9}",
    /* 76: Dutch BSN (8-9 digits) */
    "[0-9]{8,9}",
    /* 77: Austrian Abgabenkontonummer (9 digits) */
    "[0-9]{9}",
    /* 78: Polish PESEL duplicate */
    "[0-9]{11}"
};

static char *wrap_boundary(const char *core); /* forward declaration */

/* ---- Custom pattern registry ---- */

typedef struct {
    char    *name;
    char    *source;   /* original POSIX ERE string, for introspection */
    regex_t  compiled;
    int      tag;      /* TAG_* bit */
    int      boundary; /* 1 if compiled with boundary wrapper */
} custom_pattern_t;

static custom_pattern_t *custom_patterns = NULL;
static int custom_count = 0;
static int custom_cap   = 0;

/*
 * Find index of a custom pattern by name, or -1 if not found.
 */
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

/* ---- Custom pattern Ruby methods ---- */

/*
 * DataRedactor._add_pattern(name, source, tag_bit, boundary) -> nil
 *
 * Compile `source` as POSIX ERE (with boundary wrapper when boundary=1),
 * store under `name`. Replaces any existing pattern with the same name.
 * Raises DataRedactor::InvalidPatternError on regcomp failure.
 */
static VALUE rb_add_pattern(VALUE self, VALUE rb_name, VALUE rb_source,
                             VALUE rb_tag_bit, VALUE rb_boundary) {
    Check_Type(rb_name,   T_STRING);
    Check_Type(rb_source, T_STRING);

    const char *name    = StringValueCStr(rb_name);
    const char *source  = StringValueCStr(rb_source);
    int tag_bit         = NUM2INT(rb_tag_bit);
    int boundary        = NUM2INT(rb_boundary);

    /* Build the pattern string (wrap boundary if requested) */
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

    /* Replace existing or append */
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

/*
 * DataRedactor._remove_pattern(name) -> true/false
 *
 * Remove the named custom pattern. Returns true if found and removed.
 */
static VALUE rb_remove_pattern(VALUE self, VALUE rb_name) {
    Check_Type(rb_name, T_STRING);
    const char *name = StringValueCStr(rb_name);

    int idx = find_custom_by_name(name);
    if (idx < 0) return Qfalse;

    free_custom_at(idx);

    /* Shift remaining entries left */
    for (int i = idx; i < custom_count - 1; i++) {
        custom_patterns[i] = custom_patterns[i + 1];
    }
    custom_count--;

    return Qtrue;
}

/*
 * DataRedactor._clear_custom_patterns -> nil
 */
static VALUE rb_clear_custom_patterns(VALUE self) {
    for (int i = 0; i < custom_count; i++) {
        free_custom_at(i);
    }
    custom_count = 0;
    return Qnil;
}

/*
 * DataRedactor._custom_patterns -> Array<Hash>
 *
 * Returns [{name:, source:, tag_bit:, boundary:}, ...] for each custom pattern.
 */
static VALUE rb_custom_patterns(VALUE self) {
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
static char *replace_all_matches(regex_t *pattern, const char *input,
                                  int use_boundary, const placeholder_t *ph) {
    size_t ph_max   = max_placeholder_len(ph);
    size_t out_cap  = strlen(input) * 2 + 512;
    char *output = (char *)malloc(out_cap);
    if (!output) return NULL;

    /* Scratch buffer for the rendered placeholder (worst-case size). */
    char *ph_buf = (char *)malloc(ph_max + 1);
    if (!ph_buf) { free(output); return NULL; }

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

        size_t prefix_len = (size_t)core_so;
        size_t suffix_len = (size_t)(full_eo - core_eo);
        size_t match_len  = (size_t)(full_eo - full_so);
        size_t core_len   = (size_t)(core_eo - core_so);

        size_t ph_len = write_placeholder(ph_buf, ph, cursor + core_so, core_len);

        size_t needed = out_len + prefix_len + ph_len + suffix_len + strlen(cursor + full_eo) + 1;
        if (needed > out_cap) {
            out_cap = needed * 2;
            char *tmp = (char *)realloc(output, out_cap);
            if (!tmp) { free(output); free(ph_buf); return NULL; }
            output = tmp;
        }

        /* Copy prefix (includes left boundary char if present) */
        memcpy(output + out_len, cursor, prefix_len);
        out_len += prefix_len;

        /* Insert rendered placeholder */
        memcpy(output + out_len, ph_buf, ph_len);
        out_len += ph_len;

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
    free(ph_buf);

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

/* Map a TAG_* bit to a short lowercase name used in tagged/hash placeholders. */
static const char *tag_name_for_bit(int tag_bit) {
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

/*
 * DataRedactor._redact(text, mask, ph_mode, ph_str) -> String
 *
 * `mask`    — integer bitmask of TAG_* values (only / except filtering).
 * `ph_mode` — 0 = plain string, 1 = tagged "[REDACTED:TAG]", 2 = hash "[TAG_xxxx]".
 * `ph_str`  — the plain string for mode 0; ignored for modes 1 and 2.
 *
 * The Ruby wrapper builds all four arguments and is the public API.
 */
static VALUE rb_data_redactor_redact(VALUE self, VALUE rb_text, VALUE rb_mask,
                                     VALUE rb_ph_mode, VALUE rb_ph_str) {
    Check_Type(rb_text,   T_STRING);
    Check_Type(rb_ph_str, T_STRING);

    int mask    = NUM2INT(rb_mask);
    int ph_mode = NUM2INT(rb_ph_mode);
    const char *ph_str_plain = StringValueCStr(rb_ph_str);

    const char *input = StringValueCStr(rb_text);
    char *working = strdup(input);
    if (!working) rb_raise(rb_eNoMemError, "strdup failed");

    placeholder_t ph;
    ph.mode = ph_mode;

    for (int i = 0; i < NUM_PATTERNS; i++) {
        if ((pattern_tags[i] & mask) == 0) continue;
        ph.str = (ph_mode == PLACEHOLDER_MODE_PLAIN)
                     ? ph_str_plain
                     : tag_name_for_bit(pattern_tags[i]);
        char *result = replace_all_matches(&compiled_patterns[i], working,
                                           boundary_wrapped[i], &ph);
        free(working);
        if (!result) rb_raise(rb_eNoMemError, "replace_all_matches allocation failed");
        working = result;
    }

    for (int i = 0; i < custom_count; i++) {
        if ((custom_patterns[i].tag & mask) == 0) continue;
        ph.str = (ph_mode == PLACEHOLDER_MODE_PLAIN)
                     ? ph_str_plain
                     : tag_name_for_bit(custom_patterns[i].tag);
        char *result = replace_all_matches(&custom_patterns[i].compiled, working,
                                           custom_patterns[i].boundary, &ph);
        free(working);
        if (!result) rb_raise(rb_eNoMemError, "replace_all_matches allocation failed (custom)");
        working = result;
    }

    VALUE rb_result = rb_str_new_cstr(working);
    free(working);
    return rb_result;
}

/*
 * DataRedactor._scan(text, mask) -> Hash
 *
 * Returns { redacted: String, matches: Array<Hash> } where each match hash is:
 *   { tag: Symbol, name: String, value: String, start: Integer, length: Integer }
 *
 * Matches are reported in the order they are consumed by the sequential redaction
 * loop (built-ins first, most-specific to most-generic; then custom patterns).
 * `start` and `length` refer to byte positions in the *original* input string.
 * Because patterns run sequentially on a shrinking/expanding working buffer,
 * positions are tracked relative to the original by maintaining a running offset.
 */
static VALUE rb_data_redactor_scan(VALUE self, VALUE rb_text, VALUE rb_mask) {
    Check_Type(rb_text, T_STRING);
    int mask = NUM2INT(rb_mask);

    const char *input     = StringValueCStr(rb_text);
    size_t      input_len = strlen(input);

    /* Working buffer — we redact with the default plain placeholder so the
     * scan result also contains the redacted string.                        */
    static const placeholder_t ph_default = { PLACEHOLDER_MODE_PLAIN, "[REDACTED]" };

    char *working = strdup(input);
    if (!working) rb_raise(rb_eNoMemError, "strdup failed");

    VALUE matches_arr = rb_ary_new();

    /*
     * To map working-buffer positions back to original-string positions we
     * maintain a log of every replacement already applied.  Each entry records
     * where in the *working* buffer the replacement started (after all prior
     * replacements) and how many bytes were removed (orig_len) vs. inserted
     * (always 10, the length of "[REDACTED]").
     *
     * For a new match at working position W:
     *   cumulative_shift_before_W = sum of (10 - orig_len) for all prior
     *                               replacements whose working_pos <= W
     *   original_pos = W - cumulative_shift_before_W
     *
     * Replacements are appended in order so the log is already sorted by
     * working_pos; we just walk it linearly per match.
     */
    typedef struct { long wpos; long orig_len; } repl_t;
    repl_t *repl_log = NULL;
    int     repl_count = 0;
    int     repl_cap   = 0;

    #define REPL_LOG_PUSH(_wpos, _olen) do {                                  \
        if (repl_count >= repl_cap) {                                         \
            int _nc = repl_cap == 0 ? 16 : repl_cap * 2;                     \
            repl_t *_t = (repl_t *)realloc(repl_log, sizeof(repl_t) * _nc);  \
            if (!_t) { free(repl_log); free(working); rb_raise(rb_eNoMemError, "repl_log"); } \
            repl_log = _t; repl_cap = _nc;                                    \
        }                                                                     \
        repl_log[repl_count].wpos     = (_wpos);                              \
        repl_log[repl_count].orig_len = (_olen);                              \
        repl_count++;                                                         \
    } while (0)

    /* Map a position in the current working buffer to original-string position. */
    #define WORKING_TO_ORIG(_wpos) ({                                         \
        long _shift = 0;                                                      \
        for (int _ri = 0; _ri < repl_count; _ri++) {                         \
            if (repl_log[_ri].wpos <= (_wpos))                                \
                _shift += 10 - repl_log[_ri].orig_len;                       \
        }                                                                     \
        (_wpos) - _shift;                                                     \
    })

    /* Collect matches for one pattern on the current working buffer, translate
     * positions to original coordinates, then do the replacement.            */
    #define COLLECT_AND_REPLACE(pat, use_bnd, tag_bit, pat_name) do {        \
        const char *_cur = working;                                           \
        regmatch_t _m[4];                                                     \
        while (regexec((pat), _cur, 4, _m, 0) == 0) {                        \
            regoff_t _fso = _m[0].rm_so, _feo = _m[0].rm_eo;                 \
            if (_fso < 0 || _feo < _fso) break;                               \
            regoff_t _cso = _fso, _ceo = _feo;                                \
            if (use_bnd) {                                                    \
                if (_m[1].rm_so >= 0 && _m[1].rm_eo > _m[1].rm_so)          \
                    _cso = _m[1].rm_eo;                                       \
                if (_m[3].rm_so >= 0 && _m[3].rm_eo > _m[3].rm_so)          \
                    _ceo = _m[3].rm_so;                                       \
            }                                                                 \
            size_t _vlen = (size_t)(_ceo - _cso);                             \
            long _wpos   = (long)(_cur - working) + (long)_cso;              \
            long _orig   = WORKING_TO_ORIG(_wpos);                            \
            VALUE _match = rb_hash_new();                                     \
            rb_hash_aset(_match, ID2SYM(rb_intern("tag")),                    \
                         ID2SYM(rb_intern(tag_name_for_bit(tag_bit))));       \
            rb_hash_aset(_match, ID2SYM(rb_intern("name")),                  \
                         rb_str_new_cstr(pat_name));                          \
            rb_hash_aset(_match, ID2SYM(rb_intern("value")),                 \
                         rb_str_new(_cur + _cso, _vlen));                     \
            rb_hash_aset(_match, ID2SYM(rb_intern("start")),                 \
                         LONG2NUM(_orig));                                    \
            rb_hash_aset(_match, ID2SYM(rb_intern("length")),                \
                         LONG2NUM((long)_vlen));                              \
            rb_ary_push(matches_arr, _match);                                 \
            /* Log this replacement; wpos advances by 10 for subsequent entries */ \
            REPL_LOG_PUSH(_wpos, (long)_vlen);                                \
            /* Re-anchor cursor: skip past the full match in working buf */   \
            if (_feo == _fso) { if (*_cur) _cur++; else break; }             \
            else _cur += _feo;                                                \
        }                                                                     \
        char *_next = replace_all_matches((pat), working, (use_bnd), &ph_default); \
        free(working);                                                        \
        if (!_next) { free(repl_log); rb_raise(rb_eNoMemError, "replace_all_matches failed in scan"); } \
        working = _next;                                                      \
    } while (0)

    for (int i = 0; i < NUM_PATTERNS; i++) {
        if ((pattern_tags[i] & mask) == 0) continue;
        COLLECT_AND_REPLACE(&compiled_patterns[i], boundary_wrapped[i],
                            pattern_tags[i], pattern_names[i]);
    }

    for (int i = 0; i < custom_count; i++) {
        if ((custom_patterns[i].tag & mask) == 0) continue;
        COLLECT_AND_REPLACE(&custom_patterns[i].compiled,
                            custom_patterns[i].boundary,
                            custom_patterns[i].tag, custom_patterns[i].name);
    }

    #undef COLLECT_AND_REPLACE
    #undef WORKING_TO_ORIG
    #undef REPL_LOG_PUSH

    free(repl_log);

    VALUE result = rb_hash_new();
    VALUE rb_redacted = rb_str_new_cstr(working);
    free(working);
    rb_hash_aset(result, ID2SYM(rb_intern("redacted")), rb_redacted);
    rb_hash_aset(result, ID2SYM(rb_intern("matches")),  matches_arr);
    return result;

    (void)input_len; /* suppress unused-variable warning */
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
    rb_define_module_function(mDataRedactor, "_redact",               rb_data_redactor_redact,    4);
    rb_define_module_function(mDataRedactor, "_scan",                 rb_data_redactor_scan,      2);
    rb_define_module_function(mDataRedactor, "_add_pattern",          rb_add_pattern,             4);
    rb_define_module_function(mDataRedactor, "_remove_pattern",       rb_remove_pattern,          1);
    rb_define_module_function(mDataRedactor, "_clear_custom_patterns",rb_clear_custom_patterns,   0);
    rb_define_module_function(mDataRedactor, "_custom_patterns",      rb_custom_patterns,         0);

    /* Placeholder mode constants. */
    rb_define_const(mDataRedactor, "PH_MODE_PLAIN",  INT2NUM(PLACEHOLDER_MODE_PLAIN));
    rb_define_const(mDataRedactor, "PH_MODE_TAGGED", INT2NUM(PLACEHOLDER_MODE_TAGGED));
    rb_define_const(mDataRedactor, "PH_MODE_HASH",   INT2NUM(PLACEHOLDER_MODE_HASH));

    /* Expose tag bitmask values so the Ruby wrapper can build the mask. */
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
