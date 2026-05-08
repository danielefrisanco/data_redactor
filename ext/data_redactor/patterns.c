#include "patterns.h"
#include "tags.h"

regex_t compiled_patterns[NUM_PATTERNS];

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
const int boundary_wrapped[NUM_PATTERNS] = {
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
const int pattern_tags[NUM_PATTERNS] = {
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

const char *pattern_names[NUM_PATTERNS] = {
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
const char *pattern_strings[NUM_PATTERNS] = {
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
    /*  7: Grafana API Token (base64 of {\"k\":\") */
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
