#include "patterns.h"
#include "tags.h"
#include <stddef.h>  /* NULL for pattern_required_literal entries */

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
    0, /*  4: Sentry DSN */
    0, /*  5: URI with Embedded Password */
    /* ---- Tier 2: Long prefixed tokens ---- */
    0, /*  6: GitHub PAT (fine-grained, 93 chars) */
    0, /*  7: JWT */
    0, /*  8: Grafana API Token */
    0, /*  9: SSH Public Key */
    0, /* 10: Bearer Token */
    0, /* 11: Anthropic API Key (sk-ant-api...) */
    0, /* 12: OpenAI Project API Key (sk-proj-...) */
    0, /* 13: Google API Key (39 chars) */
    0, /* 14: AWS Access Key ID (20 chars) */
    0, /* 15: AWS Secret Access Key (40 base64) */
    0, /* 16: SendGrid API Key */
    0, /* 17: Amazon MWS Auth Token */
    0, /* 18: LaunchDarkly API Key */
    0, /* 19: GitHub Classic PAT (ghp_) */
    0, /* 20: GitHub OAuth Token (gho_) */
    0, /* 21: Stripe Secret Key */
    0, /* 22: ClickUp API Key */
    0, /* 23: GitLab Personal Access Token (glpat-) */
    0, /* 24: DigitalOcean PAT (dop_v1_) */
    0, /* 25: Databricks API Token (dapi) */
    0, /* 26: Scaleway Access Key */
    0, /* 27: PEM private key header (generic) */
    0, /* 28: GPG Private Key Block */
    0, /* 29: HashiCorp Vault Service Token (hvs.) */
    0, /* 30: HashiCorp Vault Batch Token (hvb.) */
    0, /* 31: HashiCorp Terraform Cloud API Token (atlasv1) */
    /* ---- Tier 3: IBANs (longest → shortest) ---- */
    0, /* 32: Hungary IBAN (28 chars) */
    0, /* 33: Poland IBAN (28 chars) */
    0, /* 34: France IBAN (27 chars) */
    0, /* 35: Italy IBAN (27 chars) */
    0, /* 36: Portugal IBAN (25 chars) */
    0, /* 37: Spain IBAN (24 chars) */
    0, /* 38: Czechia IBAN (24 chars) */
    0, /* 39: Romania IBAN (24 chars) */
    0, /* 40: Sweden IBAN (24 chars) */
    0, /* 41: Germany IBAN (22 chars) */
    0, /* 42: Ireland IBAN (22 chars) */
    0, /* 43: Switzerland IBAN (21 chars) */
    0, /* 44: Austria IBAN (20 chars) */
    0, /* 45: Netherlands IBAN (18 chars) */
    0, /* 46: Denmark IBAN (18 chars) */
    0, /* 47: Finland IBAN (18 chars) */
    0, /* 48: Belgium IBAN (16 chars) */
    0, /* 49: Norway IBAN (15 chars) */
    /* ---- Tier 4: Structured formats (dots, dashes, slashes, @) ---- */
    0, /* 50: Email Address */
    0, /* 51: International Phone Number */
    0, /* 52: Brazilian CNPJ (XX.XXX.XXX/XXXX-XX) */
    0, /* 53: Brazilian CPF (XXX.XXX.XXX-XX) */
    0, /* 54: UUID v4 */
    0, /* 55: IPv4 address */
    0, /* 56: Credit card numbers */
    0, /* 57: Indian Aadhaar (XXXX XXXX XXXX) */
    /* ---- Tier 5: Letter-anchored patterns ---- */
    0, /* 58: Mexican CURP (18 alphanum, distinctive structure) */
    0, /* 59: Italian CF with omocodia (16 chars) */
    0, /* 60: Italian CF basic (16 chars) */
    0, /* 61: UK National Insurance Number */
    0, /* 62: Spanish NIE (X/Y/Z prefix) */
    0, /* 63: Passport letter prefix + digits */
    /* ---- Tier 6: Boundary-wrapped structured (dash/dot/slash separated) ---- */
    1, /* 64: South Korean RRN (YYMMDD-XXXXXXX, 14 chars) */
    1, /* 65: Swiss AHV Number (756.XXXX.XXXX.XX) */
    1, /* 66: Finnish HETU (DDMMYY[+-A]XXXC) */
    1, /* 67: Swedish Personnummer (YYMMDD[-+]XXXX) */
    1, /* 68: Danish CPR Number (DDMMYY-XXXX) */
    1, /* 69: Czech Rodné číslo (YYMMDD/XXXX) */
    1, /* 70: US Social Security Number (XXX-XX-XXXX) */
    1, /* 71: US ITIN (9XX-XX-XXXX) */
    1, /* 72: Canadian SIN (XXX-XXX-XXX) */
    1, /* 73: Australian TFN (XXX-XXX-XXX) */
    1, /* 74: Indian PAN (AAAAA0000A) */
    1, /* 75: Spanish DNI (8 digits + letter) */
    1, /* 76: Hungarian Tax ID (8XXXXXXXXX, 10 digits) */
    /* ---- Tier 7: Boundary-wrapped pure digits (longest → shortest) ---- */
    1, /* 77: French NIR (15 digits) */
    1, /* 78: South African ID (13 digits) */
    1, /* 79: Romanian CNP (13 digits) */
    1, /* 80: Japanese My Number (12 digits) */
    1, /* 81: Polish PESEL (11 digits) */
    1, /* 82: Belgian National Number (11 digits) */
    1, /* 83: Norwegian Fødselsnummer (11 digits) */
    1, /* 84: Passport 9 digits */
    1, /* 85: Dutch BSN (8-9 digits) */
    1, /* 86: Austrian Abgabenkontonummer (9 digits) */
    1, /* 87: Polish PESEL duplicate */
    0  /* 88: Key-name-anchored secret (KEY=VALUE / KEY: VALUE) */
};

/*
 * keyname_anchored[i] == 1 marks a KEY<sep>VALUE pattern whose match span has
 * the key + separator (and any quotes) stripped so only VALUE is redacted.
 * Mutually exclusive with boundary_wrapped[] above. See patterns.h.
 */
const int keyname_anchored[NUM_PATTERNS] = {
    [88] = 1,
};

/*
 * Tag for each pattern. Exactly one tag per pattern. Used to filter which
 * patterns run when the caller passes a mask (only/except).
 */
const int pattern_tags[NUM_PATTERNS] = {
    /* 0-31: secrets, API keys, tokens, private keys, webhooks */
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    TAG_CREDENTIALS, TAG_CREDENTIALS, TAG_CREDENTIALS,
    /* 32-49: IBANs */
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_FINANCIAL, TAG_FINANCIAL, TAG_FINANCIAL,
    TAG_CONTACT,      /* 50: email */
    TAG_CONTACT,      /* 51: phone */
    TAG_TAX_ID,       /* 52: Brazilian CNPJ */
    TAG_TAX_ID,       /* 53: Brazilian CPF */
    TAG_OTHER,        /* 54: UUID v4 */
    TAG_NETWORK,      /* 55: IPv4 */
    TAG_FINANCIAL,    /* 56: credit card */
    TAG_NATIONAL_ID,  /* 57: Indian Aadhaar */
    TAG_NATIONAL_ID,  /* 58: Mexican CURP */
    TAG_TAX_ID,       /* 59: Italian CF (omocodia) */
    TAG_TAX_ID,       /* 60: Italian CF (basic) */
    TAG_NATIONAL_ID,  /* 61: UK NIN */
    TAG_NATIONAL_ID,  /* 62: Spanish NIE */
    TAG_TRAVEL,       /* 63: passport letter prefix */
    TAG_NATIONAL_ID,  /* 64: Korean RRN */
    TAG_NATIONAL_ID,  /* 65: Swiss AHV */
    TAG_NATIONAL_ID,  /* 66: Finnish HETU */
    TAG_NATIONAL_ID,  /* 67: Swedish Personnummer */
    TAG_NATIONAL_ID,  /* 68: Danish CPR */
    TAG_NATIONAL_ID,  /* 69: Czech Rodné číslo */
    TAG_NATIONAL_ID,  /* 70: US SSN */
    TAG_TAX_ID,       /* 71: US ITIN */
    TAG_NATIONAL_ID,  /* 72: Canadian SIN */
    TAG_TAX_ID,       /* 73: Australian TFN */
    TAG_TAX_ID,       /* 74: Indian PAN */
    TAG_NATIONAL_ID,  /* 75: Spanish DNI */
    TAG_TAX_ID,       /* 76: Hungarian Tax ID */
    TAG_NATIONAL_ID,  /* 77: French NIR */
    TAG_NATIONAL_ID,  /* 78: South African ID */
    TAG_NATIONAL_ID,  /* 79: Romanian CNP */
    TAG_TAX_ID,       /* 80: Japanese My Number */
    TAG_NATIONAL_ID,  /* 81: Polish PESEL */
    TAG_NATIONAL_ID,  /* 82: Belgian National Number */
    TAG_NATIONAL_ID,  /* 83: Norwegian Fødselsnummer */
    TAG_TRAVEL,       /* 84: passport 9 digits */
    TAG_NATIONAL_ID,  /* 85: Dutch BSN */
    TAG_TAX_ID,       /* 86: Austrian Abgabenkontonummer */
    TAG_NATIONAL_ID,  /* 87: Polish PESEL duplicate */
    TAG_CREDENTIALS   /* 88: Key-name-anchored secret */
};

const char *pattern_names[NUM_PATTERNS] = {
    "aws_s3_presigned_url",          /*  0 */
    "microsoft_teams_webhook",       /*  1 */
    "slack_webhook_url",             /*  2 */
    "mongodb_connection_string",     /*  3 */
    "sentry_dsn",                    /*  4 */
    "uri_with_password",             /*  5 */
    "github_pat_fine_grained",       /*  6 */
    "jwt",                           /*  7 */
    "grafana_api_token",             /*  8 */
    "ssh_public_key",                /*  9 */
    "bearer_token",                  /* 10 */
    "anthropic_api_key",             /* 11 */
    "openai_project_api_key",        /* 12 */
    "google_api_key",                /* 13 */
    "aws_access_key_id",             /* 14 */
    "aws_secret_access_key",         /* 15 */
    "sendgrid_api_key",              /* 16 */
    "amazon_mws_auth_token",         /* 17 */
    "launchdarkly_api_key",          /* 18 */
    "github_classic_pat",            /* 19 */
    "github_oauth_token",            /* 20 */
    "stripe_secret_key",             /* 21 */
    "clickup_api_key",               /* 22 */
    "gitlab_pat",                    /* 23 */
    "digitalocean_pat",              /* 24 */
    "databricks_api_token",          /* 25 */
    "scaleway_access_key",           /* 26 */
    "pem_private_key",               /* 27 */
    "gpg_private_key",               /* 28 */
    "hashicorp_vault_service_token", /* 29 */
    "hashicorp_vault_batch_token",   /* 30 */
    "hashicorp_terraform_api_token", /* 31 */
    "iban_hu",                       /* 32 */
    "iban_pl",                       /* 33 */
    "iban_fr",                       /* 34 */
    "iban_it",                       /* 35 */
    "iban_pt",                       /* 36 */
    "iban_es",                       /* 37 */
    "iban_cz",                       /* 38 */
    "iban_ro",                       /* 39 */
    "iban_se",                       /* 40 */
    "iban_de",                       /* 41 */
    "iban_ie",                       /* 42 */
    "iban_ch",                       /* 43 */
    "iban_at",                       /* 44 */
    "iban_nl",                       /* 45 */
    "iban_dk",                       /* 46 */
    "iban_fi",                       /* 47 */
    "iban_be",                       /* 48 */
    "iban_no",                       /* 49 */
    "email",                         /* 50 */
    "phone_e164",                    /* 51 */
    "brazilian_cnpj",                /* 52 */
    "brazilian_cpf",                 /* 53 */
    "uuid_v4",                       /* 54 */
    "ipv4",                          /* 55 */
    "credit_card",                   /* 56 */
    "indian_aadhaar",                /* 57 */
    "mexican_curp",                  /* 58 */
    "italian_cf_omocodia",           /* 59 */
    "italian_cf",                    /* 60 */
    "uk_nin",                        /* 61 */
    "spanish_nie",                   /* 62 */
    "passport_letter_prefix",        /* 63 */
    "korean_rrn",                    /* 64 */
    "swiss_ahv",                     /* 65 */
    "finnish_hetu",                  /* 66 */
    "swedish_personnummer",          /* 67 */
    "danish_cpr",                    /* 68 */
    "czech_rodne_cislo",             /* 69 */
    "us_ssn",                        /* 70 */
    "us_itin",                       /* 71 */
    "canadian_sin",                  /* 72 */
    "australian_tfn",                /* 73 */
    "indian_pan",                    /* 74 */
    "spanish_dni",                   /* 75 */
    "hungarian_tax_id",              /* 76 */
    "french_nir",                    /* 77 */
    "south_african_id",              /* 78 */
    "romanian_cnp",                  /* 79 */
    "japanese_my_number",            /* 80 */
    "polish_pesel",                  /* 81 */
    "belgian_national_number",       /* 82 */
    "norwegian_fodselsnummer",       /* 83 */
    "passport_9digits",              /* 84 */
    "dutch_bsn",                     /* 85 */
    "austrian_abgabenkontonummer",   /* 86 */
    "polish_pesel_2",                /* 87 */
    "keyname_anchored_secret"        /* 88 */
};

/*
 * Required literal substrings for the pre-filter. See pattern_required_literal
 * in patterns.h for the contract. Conservative: only literals provably required
 * by the regex source are listed; the rest are NULL (pattern runs always).
 *
 * Boundary-wrapped patterns (boundary_wrapped[i] == 1) must consider that the
 * compiled regex is wrapped with (^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$), so the
 * required literal of the core pattern is still the required literal of the
 * wrapped form — the wrapper only adds boundary-char classes, no literals.
 *
 * The 2-letter IBAN country prefixes are case-sensitive in the regex source
 * (e.g. "DE", "IT"), so the memmem pre-filter is case-sensitive too. This is
 * consistent with today's matching behaviour.
 */
const char *pattern_required_literal[NUM_PATTERNS] = {
    /* ---- Tier 1: Full URLs ---- */
    "amazonaws.com",  /*  0: AWS S3 presigned URL */
    "webhook.office.com",  /*  1: Microsoft Teams webhook */
    "hooks.slack.com",     /*  2: Slack webhook URL */
    "mongodb",        /*  3: MongoDB connection string — "mongodb" or "mongodb+srv" both contain it */
    "ingest.sentry.io",    /*  4: Sentry DSN */
    "://",            /*  5: URI with embedded password — scheme://...:...@... */

    /* ---- Tier 2: Long prefixed tokens ---- */
    "github_pat_",    /*  6 */
    "eyJ",            /*  7: JWT — all three segments start "eyJ", at least the first must */
    "eyJrIjoi",       /*  8: Grafana API token */
    "ssh-",           /*  9: SSH public key */
    NULL,             /* 10: Bearer token — "[Bb]earer " has two forms, no single literal. Could memmem twice but skip for now. */
    "sk-ant-api",     /* 11: Anthropic API key */
    "sk-proj-",       /* 12: OpenAI project API key */
    "AIza",           /* 13: Google API key */
    NULL,             /* 14: AWS access key ID — many prefix alternations (AKIA|ABIA|...); skip pre-filter */
    NULL,             /* 15: AWS secret access key — pure base64, no literal */
    "SG.",            /* 16: SendGrid API key */
    "amzn.mws.",      /* 17: Amazon MWS auth token */
    NULL,             /* 18: LaunchDarkly — "api-" or "sdk-"; no single literal */
    "ghp_",           /* 19: GitHub classic PAT */
    "gho_",           /* 20: GitHub OAuth token */
    "sk_live_",       /* 21: Stripe secret key */
    "pk_",            /* 22: ClickUp API key */
    "glpat-",         /* 23: GitLab PAT */
    "dop_v1_",        /* 24: DigitalOcean PAT */
    "dapi",           /* 25: Databricks API token */
    "SCW",            /* 26: Scaleway access key */
    "-----BEGIN ",    /* 27: PEM private key header */
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",  /* 28 — full literal, exact match */
    "hvs.",           /* 29: HashiCorp Vault service token */
    "hvb.",           /* 30: HashiCorp Vault batch token */
    ".atlasv1.",      /* 31: HashiCorp Terraform Cloud API token */

    /* ---- Tier 3: IBANs ---- */
    "HU",             /* 32 */
    "PL",             /* 33 */
    "FR",             /* 34 */
    "IT",             /* 35 */
    "PT",             /* 36 */
    "ES",             /* 37 */
    "CZ",             /* 38 */
    "RO",             /* 39 */
    "SE",             /* 40 */
    "DE",             /* 41 */
    "IE",             /* 42 */
    "CH",             /* 43 */
    "AT",             /* 44 */
    "NL",             /* 45 */
    "DK",             /* 46 */
    "FI",             /* 47 */
    "BE",             /* 48 */
    "NO",             /* 49 */

    /* ---- Tier 4: Structured formats ---- */
    "@",              /* 50: email — '@' is rare in typical text, great filter */
    NULL,             /* 51: phone E.164 — '+' is too common to filter usefully (URLs, code) */
    NULL,             /* 52: Brazilian CNPJ — pure digits + separators, no useful literal */
    NULL,             /* 53: Brazilian CPF — same */
    NULL,             /* 54: UUID v4 — '-' too common to filter usefully */
    NULL,             /* 55: IPv4 — digits + '.', no useful literal */
    NULL,             /* 56: credit card — pure digit alternations */
    NULL,             /* 57: Indian Aadhaar — digits + '-' or ' ' too common */

    /* ---- Tier 5: Letter-anchored ---- */
    NULL,             /* 58: Mexican CURP — letter classes only */
    NULL,             /* 59: Italian CF omocodia — letter classes only */
    NULL,             /* 60: Italian CF basic — letter classes only */
    NULL,             /* 61: UK NIN — letter classes only */
    NULL,             /* 62: Spanish NIE — [XYZ] + digits + letter */
    NULL,             /* 63: passport with letter prefix — too generic */

    /* ---- Tier 6: Boundary-wrapped structured ---- */
    NULL,             /* 64: Korean RRN — digits + '-' */
    "756.",           /* 65: Swiss AHV — always starts with "756." */
    NULL,             /* 66: Finnish HETU — digits + [-+A] */
    NULL,             /* 67: Swedish personnummer — digits + [-+] */
    NULL,             /* 68: Danish CPR — digits + '-' */
    NULL,             /* 69: Czech rodne cislo — digits + optional '/' */
    NULL,             /* 70: US SSN — digits + '-' */
    NULL,             /* 71: US ITIN — starts "9", but '9' is too common */
    NULL,             /* 72: Canadian SIN — digits + '-' */
    NULL,             /* 73: Australian TFN — digits + '-' or ' ' */
    NULL,             /* 74: Indian PAN — letters + digits, no required literal */
    NULL,             /* 75: Spanish DNI — 8 digits + letter */
    NULL,             /* 76: Hungarian Tax ID — starts "8", too common */

    /* ---- Tier 7: Boundary-wrapped pure digits ---- */
    NULL,             /* 77: French NIR — pure digits */
    NULL,             /* 78: South African ID — pure digits */
    NULL,             /* 79: Romanian CNP — pure digits */
    NULL,             /* 80: Japanese My Number — pure digits */
    NULL,             /* 81: Polish PESEL — pure digits */
    NULL,             /* 82: Belgian National Number — pure digits */
    NULL,             /* 83: Norwegian Fødselsnummer — pure digits */
    NULL,             /* 84: passport 9 digits — pure digits */
    NULL,             /* 85: Dutch BSN — pure digits */
    NULL,             /* 86: Austrian Abgabenkontonummer — pure digits */
    NULL,             /* 87: Polish PESEL duplicate — pure digits */
    NULL              /* 88: Key-name-anchored — key name is an alternation, no single required literal */
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
    /*  4: Sentry DSN (https://KEY@host.ingest.sentry.io/PROJECT_ID) */
    "https://[a-f0-9]{32}(:[a-f0-9]{32})?@[a-zA-Z0-9.-]+\\.ingest\\.sentry\\.io/[0-9]+",
    /*  5: URI with Embedded Password (scheme://user:pass@host) */
    "[A-Za-z][A-Za-z0-9+_-]*://[^[:space:]/?#:@]+:[^[:space:]/?#@]+@[A-Za-z0-9.-]+",

    /* ---- Tier 2: Long prefixed tokens ---- */
    /*  6: GitHub PAT fine-grained (github_pat_ + 82 chars) */
    "github_pat_[0-9a-zA-Z_]{82}",
    /*  7: JWT (three base64url segments) */
    "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+",
    /*  8: Grafana API Token (base64 of {\"k\":\") */
    "eyJrIjoi[A-Za-z0-9_=-]{42,}",
    /*  9: SSH Public Key */
    "ssh-(rsa|ed25519|ecdsa) [a-zA-Z0-9/+=]{20,}",
    /* 10: Bearer Token */
    "[Bb]earer [a-zA-Z0-9_.=/+:-]{12,}",
    /* 11: Anthropic API Key (sk-ant-apiNN-... ~ 95+ chars) */
    "sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{90,}",
    /* 12: OpenAI Project API Key (sk-proj-...) */
    "sk-proj-[A-Za-z0-9_-]{20,}",
    /* 13: Google API Key (AIza + 35 chars) */
    "AIza[0-9A-Za-z_-]{35}",
    /* 14: AWS Access Key ID (all prefixes + 16 chars) */
    "(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z2-7]{16}",
    /* 15: AWS Secret Access Key (40 base64 chars) */
    "[A-Za-z0-9/+=]{40}",
    /* 16: SendGrid API Key */
    "SG\\.[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{5,}",
    /* 17: Amazon MWS Auth Token */
    "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    /* 18: LaunchDarkly API Key (api-UUID or sdk-UUID) */
    "(api|sdk)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    /* 19: GitHub Classic PAT (ghp_ + 36 chars) */
    "ghp_[0-9a-zA-Z]{36}",
    /* 20: GitHub OAuth Token (gho_ + 36 chars) */
    "gho_[0-9a-zA-Z]{36}",
    /* 21: Stripe Secret Key (sk_live_ + 24 chars) */
    "sk_live_[0-9a-zA-Z]{24}",
    /* 22: ClickUp API Key */
    "pk_[0-9]{6,8}_[A-Z0-9]{32}",
    /* 23: GitLab Personal Access Token (glpat- + 20 chars) */
    "glpat-[0-9a-zA-Z_-]{20}",
    /* 24: DigitalOcean PAT (dop_v1_ + 64 hex chars) */
    "dop_v1_[a-f0-9]{64}",
    /* 25: Databricks API Token (dapi + 32 hex chars) */
    "dapi[a-f0-9]{32}",
    /* 26: Scaleway Access Key (SCW + 17 chars) */
    "SCW[A-Z0-9]{17}",
    /* 27: PEM private key header (generic) */
    "-----BEGIN [A-Z ]*PRIVATE KEY-----",
    /* 28: GPG Private Key Block */
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    /* 29: HashiCorp Vault Service Token (hvs. + 90-120 base64url chars) */
    "hvs\\.[A-Za-z0-9_-]{90,120}",
    /* 30: HashiCorp Vault Batch Token (hvb. + 138+ base64url chars).
     * Upper bound capped at POSIX RE_DUP_MAX (255), not gitleaks' 300: musl's
     * regcomp rejects {m,n} with n>255 ("Invalid contents of {}"), so the gem
     * failed to load on Alpine. 255 still neutralizes the token (prefix + 251+
     * chars redacted); only an unusually long >255-char token leaves a dead tail. */
    "hvb\\.[A-Za-z0-9_-]{138,255}",
    /* 31: HashiCorp Terraform Cloud API Token (14 alphanum + .atlasv1. + 60-70 base64url chars) */
    "[A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9_=-]{60,70}",

    /* ---- Tier 3: IBANs (longest → shortest) ---- */
    /* 32: Hungary IBAN (HU, 28 chars) */
    "HU[0-9]{2}[0-9]{24}",
    /* 33: Poland IBAN (PL, 28 chars) */
    "PL[0-9]{2}[0-9]{24}",
    /* 34: France IBAN (FR, 27 chars) */
    "FR[0-9]{2}[0-9]{10}[A-Z0-9]{11}[0-9]{2}",
    /* 35: Italy IBAN (IT, 27 chars) */
    "IT[0-9]{2}[A-Z][0-9]{10}[A-Z0-9]{12}",
    /* 36: Portugal IBAN (PT, 25 chars) */
    "PT[0-9]{2}[0-9]{21}",
    /* 37: Spain IBAN (ES, 24 chars) */
    "ES[0-9]{2}[0-9]{20}",
    /* 38: Czechia IBAN (CZ, 24 chars) */
    "CZ[0-9]{2}[0-9]{20}",
    /* 39: Romania IBAN (RO, 24 chars) */
    "RO[0-9]{2}[A-Z]{4}[A-Z0-9]{16}",
    /* 40: Sweden IBAN (SE, 24 chars) */
    "SE[0-9]{2}[0-9]{20}",
    /* 41: Germany IBAN (DE, 22 chars) */
    "DE[0-9]{2}[0-9]{18}",
    /* 42: Ireland IBAN (IE, 22 chars) */
    "IE[0-9]{2}[A-Z]{4}[0-9]{14}",
    /* 43: Switzerland IBAN (CH, 21 chars) */
    "CH[0-9]{2}[0-9]{5}[A-Z0-9]{12}",
    /* 44: Austria IBAN (AT, 20 chars) */
    "AT[0-9]{2}[0-9]{16}",
    /* 45: Netherlands IBAN (NL, 18 chars) */
    "NL[0-9]{2}[A-Z]{4}[0-9]{10}",
    /* 46: Denmark IBAN (DK, 18 chars) */
    "DK[0-9]{2}[0-9]{14}",
    /* 47: Finland IBAN (FI, 18 chars) */
    "FI[0-9]{2}[0-9]{14}",
    /* 48: Belgium IBAN (BE, 16 chars) */
    "BE[0-9]{2}[0-9]{12}",
    /* 49: Norway IBAN (NO, 15 chars) */
    "NO[0-9]{2}[0-9]{11}",

    /* ---- Tier 4: Structured formats (dots, dashes, slashes, @) ---- */
    /* 50: Email Address */
    "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    /* 51: International Phone Number (E.164) */
    "\\+[0-9]{1,3}[- ]?[0-9][0-9 -]{6,13}[0-9]",
    /* 52: Brazilian CNPJ (XX.XXX.XXX/XXXX-XX) */
    "[0-9]{2}\\.[0-9]{3}\\.[0-9]{3}/[0-9]{4}-[0-9]{2}",
    /* 53: Brazilian CPF (XXX.XXX.XXX-XX) */
    "[0-9]{3}\\.[0-9]{3}\\.[0-9]{3}-[0-9]{2}",
    /* 54: UUID v4 / Scaleway Secret Key */
    "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    /* 55: IPv4 address */
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
    /* 56: Credit card numbers (Visa, Mastercard, Amex, Discover, JCB) */
    "(4[0-9]{15}|4[0-9]{12}|5[1-5][0-9]{14}|6011[0-9]{12}|65[0-9]{14}|3[47][0-9]{13}|3[068][0-9]{11}|35[0-9]{14})",
    /* 57: Indian Aadhaar (XXXX XXXX XXXX or XXXX-XXXX-XXXX) */
    "[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}",

    /* ---- Tier 5: Letter-anchored patterns ---- */
    /* 58: Mexican CURP (18 alphanum, distinctive structure) */
    "[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[A-Z0-9][0-9]",
    /* 59: Italian CF with omocodia (16 chars) */
    "[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]",
    /* 60: Italian CF basic (16 chars) */
    "[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]",
    /* 61: UK National Insurance Number (AA 99 99 99 A-D) */
    "[A-Z]{2} ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D]",
    /* 62: Spanish NIE (X/Y/Z + 7 digits + letter) */
    "[XYZ][0-9]{7}[A-Z]",
    /* 63: Passport - letter prefix + digits (e.g. AB1234567) */
    "[A-Z]{1,2}[0-9]{6,7}",

    /* ---- Tier 6: Boundary-wrapped structured (dash/dot/slash separated) ---- */
    /* 64: South Korean RRN (YYMMDD-XXXXXXX, 14 chars with dash) */
    "[0-9]{6}-[0-9]{7}",
    /* 65: Swiss AHV Number (756.XXXX.XXXX.XX) */
    "756\\.[0-9]{4}\\.[0-9]{4}\\.[0-9]{2}",
    /* 66: Finnish HETU (DDMMYY[+-A]XXXC) */
    "[0-9]{6}[-+A][0-9]{3}[0-9A-Y]",
    /* 67: Swedish Personnummer (YYMMDD[-+]XXXX) */
    "[0-9]{6}[-+][0-9]{4}",
    /* 68: Danish CPR Number (DDMMYY-XXXX) */
    "[0-9]{6}-[0-9]{4}",
    /* 69: Czech Rodné číslo (YYMMDD/XXXX or YYMMDDXXXX) */
    "[0-9]{6}/?[0-9]{3,4}",
    /* 70: US Social Security Number (XXX-XX-XXXX) */
    "[0-9]{3}-[0-9]{2}-[0-9]{4}",
    /* 71: US ITIN (9XX-XX-XXXX) */
    "9[0-9]{2}-[0-9]{2}-[0-9]{4}",
    /* 72: Canadian SIN (XXX-XXX-XXX) */
    "[0-9]{3}-[0-9]{3}-[0-9]{3}",
    /* 73: Australian TFN (XXX-XXX-XXX or XXX XXX XXX) */
    "[0-9]{3}[- ][0-9]{3}[- ][0-9]{3}",
    /* 74: Indian PAN (5 letters + 4 digits + 1 letter) */
    "[A-Z]{5}[0-9]{4}[A-Z]",
    /* 75: Spanish DNI (8 digits + 1 letter) */
    "[0-9]{8}[A-Z]",
    /* 76: Hungarian Tax ID (starts with 8, 10 digits) */
    "8[0-9]{9}",

    /* ---- Tier 7: Boundary-wrapped pure digits (longest → shortest) ---- */
    /* 77: French NIR / Social Security (15 digits) */
    "[12][0-9]{2}[01][0-9][0-9]{2}[0-9]{3}[0-9]{3}[0-9]{2}",
    /* 78: South African ID (13 digits) */
    "[0-9]{13}",
    /* 79: Romanian CNP (13 digits, first digit 1-8) */
    "[1-8][0-9]{12}",
    /* 80: Japanese My Number (12 digits) */
    "[0-9]{12}",
    /* 81: Polish PESEL (11 digits) */
    "[0-9]{11}",
    /* 82: Belgian National Number (11 digits) */
    "[0-9]{11}",
    /* 83: Norwegian Fødselsnummer (11 digits) */
    "[0-9]{11}",
    /* 84: Passport - 9 consecutive digits */
    "[0-9]{9}",
    /* 85: Dutch BSN (8-9 digits) */
    "[0-9]{8,9}",
    /* 86: Austrian Abgabenkontonummer (9 digits) */
    "[0-9]{9}",
    /* 87: Polish PESEL duplicate */
    "[0-9]{11}",
    /* 88: Key-name-anchored secret (dotenv KEY=VALUE / YAML KEY: VALUE).
     * POSIX ERE has no /i, so each key name is char-class case-folded by hand.
     * Keys ordered longest-first so leftmost-longest picks the full name.
     * The key word may be surrounded by other key-name chars on either side
     * (unanchored left; [A-Za-z0-9_]* right) so compound names match both ways:
     * POSTGRES_DB_PASSWORD= (prefix) and PASSWORD_POSTGRES= (suffix).
     * Separator is = or : with optional surrounding space. Value is either a
     * quoted run ("..."/'...') or an unquoted token of >=6 chars that stops at
     * whitespace, quotes, ; , : =. The matcher strips key+sep (keyname_anchored)
     * so only the value is redacted, the full compound key name is kept. */
    "([Cc][Ll][Ii][Ee][Nn][Tt]_[Ss][Ee][Cc][Rr][Ee][Tt]"
    "|[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]"
    "|[Aa][Pp][Ii]_[Kk][Ee][Yy]"
    "|[Aa][Pp][Ii][Kk][Ee][Yy]"
    "|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]"
    "|[Pp][Aa][Ss][Ss][Ww][Dd]"
    "|[Ss][Ee][Cc][Rr][Ee][Tt]"
    "|[Tt][Oo][Kk][Ee][Nn]"
    "|[Pp][Ww][Dd])"
    "[A-Za-z0-9_]*"
    "[[:space:]]*[=:][[:space:]]*"
    "(\"[^\"]+\"|'[^']+'|[^[:space:]\"';,:=]{6,})"
};
