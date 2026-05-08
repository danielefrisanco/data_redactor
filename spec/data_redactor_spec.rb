require "data_redactor"

RSpec.describe DataRedactor do
  describe ".redact" do

    # ---- Helpers ----
    def redacted?(input, sensitive)
      result = DataRedactor.redact(input)
      expect(result).to include("[REDACTED]"), "expected [REDACTED] in: #{result.inspect}"
      expect(result).not_to include(sensitive), "expected #{sensitive.inspect} to be gone"
    end

    # ---- Pattern 0: AWS Access Key ID ----
    it "redacts AWS Access Key ID (AKIA prefix)" do
      redacted?("key=AKIAIOSFODNN7EXAMPLE rest", "AKIAIOSFODNN7EXAMPLE")
    end

    it "redacts AWS Access Key ID (ASIA prefix)" do
      redacted?("key=ASIAIOSFODNN7EXAMPLE rest", "ASIAIOSFODNN7EXAMPLE")
    end

    # ---- Pattern 1: AWS Secret Access Key (40 base64 chars) ----
    it "redacts AWS Secret Access Key (40 base64 chars)" do
      secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      redacted?("secret=#{secret}", secret)
    end

    # ---- Pattern 2: Italian Codice Fiscale (basic) ----
    it "redacts Italian Codice Fiscale (basic pattern)" do
      redacted?("CF: RSSMRA85M01H501Z end", "RSSMRA85M01H501Z")
    end

    # ---- Pattern 3: Passport letter prefix + digits ----
    it "redacts passport with 1-letter prefix" do
      redacted?("passport: A1234567 end", "A1234567")
    end

    it "redacts passport with 2-letter prefix" do
      redacted?("passport: AB1234567 end", "AB1234567")
    end

    # ---- Pattern 4: Passport 9 consecutive digits ----
    it "redacts 9-digit passport number (boundary)" do
      redacted?("passport: 123456789 end", "123456789")
    end

    it "does NOT redact digits inside a longer number (14+ digits)" do
      result = DataRedactor.redact("ref 12345678901234 ok")
      expect(result).not_to include("[REDACTED]")
    end

    # ---- Pattern 5: Google API Key ----
    it "redacts Google API Key" do
      key = "AIza" + "A" * 35
      redacted?("key=#{key} end", key)
    end

    # ---- Pattern 6: GitHub Personal Access Token ----
    it "redacts GitHub Personal Access Token" do
      token = "github_pat_" + "A" * 82
      redacted?("token=#{token} end", token)
    end

    # ---- Pattern 7: Slack Webhook URL ----
    it "redacts Slack Webhook URL" do
      url = "https://hooks.slack.com/services/T" + "A" * 8 + "/B" + "A" * 8 + "/" + "a" * 24
      redacted?("webhook=#{url} end", url)
    end

    # ---- Pattern 8: Stripe Secret Key ----
    it "redacts Stripe Secret Key" do
      key = "sk_live_" + "a" * 24
      redacted?("key=#{key} end", key)
    end

    # ---- Pattern 9: PEM private key header ----
    it "redacts RSA PEM private key header" do
      redacted?("data: -----BEGIN RSA PRIVATE KEY----- rest", "-----BEGIN RSA PRIVATE KEY-----")
    end

    it "redacts OpenSSH PEM private key header" do
      redacted?("data: -----BEGIN OPENSSH PRIVATE KEY----- rest", "-----BEGIN OPENSSH PRIVATE KEY-----")
    end

    it "redacts EC PEM private key header" do
      redacted?("data: -----BEGIN EC PRIVATE KEY----- rest", "-----BEGIN EC PRIVATE KEY-----")
    end

    # ---- Pattern 10: Italian IBAN ----
    it "redacts Italian IBAN" do
      redacted?("iban: IT60X0542811101000000123456 end", "IT60X0542811101000000123456")
    end

    # ---- Pattern 11: Credit card numbers ----
    it "redacts Visa 16-digit card number" do
      redacted?("card: 4111111111111111 end", "4111111111111111")
    end

    it "redacts Mastercard number" do
      redacted?("card: 5500005555555559 end", "5500005555555559")
    end

    it "redacts Amex card number" do
      redacted?("card: 378282246310005 end", "378282246310005")
    end

    # ---- Pattern 12: IPv4 address ----
    it "redacts IPv4 address" do
      redacted?("ip=192.168.1.100 end", "192.168.1.100")
    end

    # ---- Pattern 13: Scaleway Access Key ----
    it "redacts Scaleway Access Key" do
      redacted?("key=SCW12345ABCDE6789FGHIJ end", "SCW12345ABCDE6789FGHIJ")
    end

    # ---- Pattern 14: UUID v4 / Scaleway Secret Key ----
    it "redacts UUID v4" do
      redacted?("id=550e8400-e29b-41d4-a716-446655440000 end", "550e8400-e29b-41d4-a716-446655440000")
    end

    # ---- Pattern 15: France IBAN ----
    it "redacts French IBAN" do
      redacted?("iban: FR7630006000011234567890189 end", "FR7630006000011234567890189")
    end

    # ---- Pattern 16: Germany IBAN ----
    it "redacts German IBAN" do
      redacted?("iban: DE89370400440532013000 end", "DE89370400440532013000")
    end

    # ---- Pattern 17: Spain IBAN ----
    it "redacts Spanish IBAN" do
      redacted?("iban: ES9121000418450200051332 end", "ES9121000418450200051332")
    end

    # ---- Pattern 18: Netherlands IBAN ----
    it "redacts Dutch IBAN" do
      redacted?("iban: NL91ABNA0417164300 end", "NL91ABNA0417164300")
    end

    # ---- Pattern 19: Belgium IBAN ----
    it "redacts Belgian IBAN" do
      redacted?("iban: BE68539007547034 end", "BE68539007547034")
    end

    # ---- Pattern 20: Portugal IBAN ----
    it "redacts Portuguese IBAN" do
      redacted?("iban: PT50000201231234567890154 end", "PT50000201231234567890154")
    end

    # ---- Pattern 21: Ireland IBAN ----
    it "redacts Irish IBAN" do
      redacted?("iban: IE29AIBK93115212345678 end", "IE29AIBK93115212345678")
    end

    # ---- Pattern 22: Italian Codice Fiscale (omocodia) ----
    it "redacts Italian CF with omocodia characters" do
      redacted?("cf: RSSMRALPMNLH5LMZ end", "RSSMRALPMNLH5LMZ")
    end

    # ---- Pattern 23: French NIR / Social Security ----
    it "redacts French NIR (boundary)" do
      redacted?("nir: 185126203450342 end", "185126203450342")
    end

    # ---- Pattern 24: Spanish DNI ----
    it "redacts Spanish DNI (boundary)" do
      redacted?("dni: 12345678Z end", "12345678Z")
    end

    # ---- Pattern 25: Spanish NIE ----
    it "redacts Spanish NIE" do
      redacted?("nie: X1234567L end", "X1234567L")
    end

    # ---- Pattern 26: Dutch BSN ----
    it "redacts Dutch BSN (boundary)" do
      redacted?("bsn: 123456789 end", "123456789")
    end

    # ---- Pattern 27: Polish PESEL ----
    it "redacts Polish PESEL (boundary)" do
      redacted?("pesel: 85121612345 end", "85121612345")
    end

    # ---- Pattern 28: Sweden IBAN ----
    it "redacts Swedish IBAN" do
      redacted?("iban: SE4550000000058398257466 end", "SE4550000000058398257466")
    end

    # ---- Pattern 29: Denmark IBAN ----
    it "redacts Danish IBAN" do
      redacted?("iban: DK5000400440116243 end", "DK5000400440116243")
    end

    # ---- Pattern 30: Norway IBAN ----
    it "redacts Norwegian IBAN" do
      redacted?("iban: NO9386011117947 end", "NO9386011117947")
    end

    # ---- Pattern 31: Finland IBAN ----
    it "redacts Finnish IBAN" do
      redacted?("iban: FI2112345600000785 end", "FI2112345600000785")
    end

    # ---- Pattern 32: Belgian National Number ----
    it "redacts Belgian National Number (boundary)" do
      redacted?("nn: 85121612345 end", "85121612345")
    end

    # ---- Pattern 33: Swedish Personnummer ----
    it "redacts Swedish Personnummer" do
      redacted?("pnr: 850101-1234 end", "850101-1234")
    end

    # ---- Pattern 34: Danish CPR Number ----
    it "redacts Danish CPR Number" do
      redacted?("cpr: 010185-1234 end", "010185-1234")
    end

    # ---- Pattern 35: Norwegian Fødselsnummer ----
    it "redacts Norwegian Fødselsnummer (boundary)" do
      redacted?("fnr: 01018512345 end", "01018512345")
    end

    # ---- Pattern 36: Finnish HETU ----
    it "redacts Finnish HETU" do
      redacted?("hetu: 010185-123A end", "010185-123A")
    end

    # ---- Pattern 37: Poland IBAN ----
    it "redacts Polish IBAN" do
      redacted?("iban: PL61109010140000071219812874 end", "PL61109010140000071219812874")
    end

    # ---- Pattern 38: Austria IBAN ----
    it "redacts Austrian IBAN" do
      redacted?("iban: AT611904300234573201 end", "AT611904300234573201")
    end

    # ---- Pattern 39: Switzerland IBAN ----
    it "redacts Swiss IBAN" do
      redacted?("iban: CH9300762011623852957 end", "CH9300762011623852957")
    end

    # ---- Pattern 40: Czechia IBAN ----
    it "redacts Czech IBAN" do
      redacted?("iban: CZ6508000000192000145399 end", "CZ6508000000192000145399")
    end

    # ---- Pattern 41: Hungary IBAN ----
    it "redacts Hungarian IBAN" do
      redacted?("iban: HU42117730161111101800000000 end", "HU42117730161111101800000000")
    end

    # ---- Pattern 42: Romania IBAN ----
    it "redacts Romanian IBAN" do
      redacted?("iban: RO49AAAA1B31007593840000 end", "RO49AAAA1B31007593840000")
    end

    # ---- Pattern 43: Polish PESEL (duplicate slot) ----
    it "redacts Polish PESEL via pattern 43 (boundary)" do
      redacted?("id: 90010112345 end", "90010112345")
    end

    # ---- Pattern 44: Austrian Abgabenkontonummer ----
    it "redacts Austrian Abgabenkontonummer (boundary)" do
      redacted?("tax: 123456789 end", "123456789")
    end

    # ---- Pattern 45: Swiss AHV Number ----
    it "redacts Swiss AHV Number" do
      redacted?("ahv: 756.1234.5678.90 end", "756.1234.5678.90")
    end

    # ---- Pattern 46: Czech Rodné číslo ----
    it "redacts Czech Rodné číslo with slash" do
      redacted?("rc: 856121/1234 end", "856121/1234")
    end

    it "redacts Czech Rodné číslo without slash" do
      redacted?("rc: 8561211234 end", "8561211234")
    end

    # ---- Pattern 47: Hungarian Tax ID ----
    it "redacts Hungarian Tax ID (boundary)" do
      redacted?("tax: 8012345678 end", "8012345678")
    end

    # ---- Pattern 48: Romanian CNP ----
    it "redacts Romanian CNP (boundary)" do
      redacted?("cnp: 1850101123456 end", "1850101123456")
    end

    # ---- Pattern 0 upgrade: AWS Access Key ID (all prefixes) ----
    it "redacts AWS Access Key ID with ABIA prefix" do
      redacted?("key=ABIAIOSFODNN7EXAMPLE rest", "ABIAIOSFODNN7EXAMPLE")
    end

    it "redacts AWS Access Key ID with AGPA prefix" do
      redacted?("key=AGPAIOSFODNN7EXAMPLE rest", "AGPAIOSFODNN7EXAMPLE")
    end

    # ---- Pattern 9 upgrade: Generic PEM private key header ----
    it "redacts DSA PEM private key header" do
      redacted?("data: -----BEGIN DSA PRIVATE KEY----- rest", "-----BEGIN DSA PRIVATE KEY-----")
    end

    it "redacts ED25519 PEM private key header" do
      redacted?("data: -----BEGIN PRIVATE KEY----- rest", "-----BEGIN PRIVATE KEY-----")
    end

    # ---- Pattern 49: JWT ----
    it "redacts JWT token" do
      jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456_-xyz"
      redacted?("token=#{jwt} end", jwt)
    end

    # ---- Pattern 50: SendGrid API Key ----
    it "redacts SendGrid API Key" do
      key = "SG.abc123_def.ghi789-jkl012_mno"
      redacted?("key=#{key} end", key)
    end

    # ---- Pattern 51: Grafana API Token ----
    it "redacts Grafana API Token" do
      token = "eyJrIjoi" + "A" * 42
      redacted?("key=#{token} end", token)
    end

    # ---- Pattern 52: Amazon MWS Auth Token ----
    it "redacts Amazon MWS Auth Token" do
      token = "amzn.mws.a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6"
      redacted?("token=#{token} end", token)
    end

    # ---- Pattern 53: Microsoft Teams Webhook ----
    it "redacts Microsoft Teams Webhook URL" do
      url = "https://example.webhook.office.com/webhookb2/a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6@a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6/IncomingWebhook/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6"
      redacted?("webhook=#{url} end", url)
    end

    # ---- Pattern 54: MongoDB Connection String ----
    it "redacts MongoDB connection string with credentials" do
      uri = "mongodb://admin:secretpass@db.example.com:27017/mydb"
      redacted?("db=#{uri} end", uri)
    end

    it "redacts MongoDB+srv connection string" do
      uri = "mongodb+srv://admin:secretpass@cluster0.example.net/mydb"
      redacted?("db=#{uri} end", uri)
    end

    # ---- Pattern 55: URI with Embedded Password ----
    it "redacts URI with embedded password" do
      uri = "postgres://user:s3cret@db.host.com"
      redacted?("conn=#{uri} end", uri)
    end

    # ---- Pattern 56: GPG Private Key ----
    it "redacts GPG private key header" do
      redacted?("data: -----BEGIN PGP PRIVATE KEY BLOCK----- rest", "-----BEGIN PGP PRIVATE KEY BLOCK-----")
    end

    # ---- Pattern 57: LaunchDarkly API Key ----
    it "redacts LaunchDarkly API key" do
      key = "sdk-" + "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12
      redacted?("key=#{key} end", key)
    end

    it "redacts LaunchDarkly API key (api- prefix)" do
      key = "api-" + "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12
      redacted?("key=#{key} end", key)
    end

    # ---- Pattern 58: ClickUp API Key ----
    it "redacts ClickUp API key" do
      key = "pk_1234567_" + "A" * 32
      redacted?("key=#{key} end", key)
    end

    # ---- Pattern 59: AWS S3 Presigned URL ----
    it "redacts AWS S3 presigned URL" do
      url = "https://mybucket.s3.amazonaws.com/myfile.txt?AWSAccessKeyId=AKIA1234&Expires=123&X-Amz-Signature=abc123"
      redacted?("url=#{url} end", url)
    end

    # ---- Pattern 60: SSH Public Key ----
    it "redacts SSH RSA public key" do
      key = "ssh-rsa " + "A" * 40
      redacted?("key=#{key} end", key)
    end

    it "redacts SSH ed25519 public key" do
      key = "ssh-ed25519 " + "A" * 40
      redacted?("key=#{key} end", key)
    end

    # ---- Pattern 61: GitHub Classic PAT ----
    it "redacts GitHub Classic PAT (ghp_ prefix)" do
      token = "ghp_" + "A" * 36
      redacted?("token=#{token} end", token)
    end

    # ---- Pattern 62: GitHub OAuth Token ----
    it "redacts GitHub OAuth Token (gho_ prefix)" do
      token = "gho_" + "A" * 36
      redacted?("token=#{token} end", token)
    end

    # ---- 0.6.1: Anthropic API Key ----
    it "redacts Anthropic API key (sk-ant-api03 prefix)" do
      key = "sk-ant-api03-" + "A" * 95
      redacted?("key=#{key} end", key)
    end

    # ---- 0.6.1: OpenAI Project API Key ----
    it "redacts OpenAI project API key (sk-proj prefix)" do
      key = "sk-proj-" + "A" * 80
      redacted?("key=#{key} end", key)
    end

    # ---- 0.6.1: GitLab Personal Access Token ----
    it "redacts GitLab Personal Access Token (glpat- prefix)" do
      token = "glpat-" + "abcdefghijklmnopqrst"
      redacted?("token=#{token} end", token)
    end

    # ---- 0.6.1: DigitalOcean PAT ----
    it "redacts DigitalOcean PAT (dop_v1_ prefix)" do
      token = "dop_v1_" + "0123456789abcdef" * 4
      redacted?("token=#{token} end", token)
    end

    # ---- 0.6.1: Databricks API Token ----
    it "redacts Databricks API token (dapi prefix)" do
      token = "dapi" + "0123456789abcdef0123456789abcdef"
      redacted?("token=#{token} end", token)
    end

    # ---- 0.6.1: Sentry DSN ----
    it "redacts Sentry DSN" do
      dsn = "https://" + "0" * 32 + "@o123456.ingest.sentry.io/7654321"
      redacted?("dsn=#{dsn} end", dsn)
    end

    it "redacts legacy Sentry DSN with secret" do
      dsn = "https://" + "0" * 32 + ":" + "f" * 32 + "@o123456.ingest.sentry.io/7654321"
      redacted?("dsn=#{dsn} end", dsn)
    end

    # ---- Pattern 63: US Social Security Number ----
    it "redacts US SSN" do
      redacted?("ssn: 123-45-6789 end", "123-45-6789")
    end

    # ---- Pattern 64: US ITIN ----
    it "redacts US ITIN" do
      redacted?("itin: 912-34-5678 end", "912-34-5678")
    end

    # ---- Pattern 65: UK National Insurance Number ----
    it "redacts UK NINO (no spaces)" do
      redacted?("nino: AB123456C end", "AB123456C")
    end

    it "redacts UK NINO (with spaces)" do
      redacted?("nino: AB 12 34 56 C end", "AB 12 34 56 C")
    end

    # ---- Pattern 66: Bearer Token ----
    it "redacts Bearer token" do
      token = "Bearer eyJhbGciOiJIUzI1Ni"
      redacted?("auth: #{token} end", token)
    end

    # ---- Pattern 67: Email Address ----
    it "redacts email address" do
      redacted?("contact: john.doe@example.com end", "john.doe@example.com")
    end

    # ---- Pattern 68: International Phone Number ----
    it "redacts international phone number" do
      redacted?("phone: +1-555-123-4567 end", "+1-555-123-4567")
    end

    it "redacts phone number with spaces" do
      redacted?("phone: +44 20 7946 0958 end", "+44 20 7946 0958")
    end

    # ---- Pattern 69: Canadian SIN ----
    it "redacts Canadian SIN" do
      redacted?("sin: 123-456-789 end", "123-456-789")
    end

    # ---- Pattern 70: Brazilian CPF ----
    it "redacts Brazilian CPF" do
      redacted?("cpf: 123.456.789-09 end", "123.456.789-09")
    end

    # ---- Pattern 71: Brazilian CNPJ ----
    it "redacts Brazilian CNPJ" do
      redacted?("cnpj: 12.345.678/0001-95 end", "12.345.678/0001-95")
    end

    # ---- Pattern 72: South Korean RRN ----
    it "redacts South Korean RRN" do
      redacted?("rrn: 850101-1234567 end", "850101-1234567")
    end

    # ---- Pattern 73: Japanese My Number ----
    it "redacts Japanese My Number (12 digits)" do
      redacted?("mynumber: 123456789012 end", "123456789012")
    end

    # ---- Pattern 74: Australian TFN ----
    it "redacts Australian TFN (dashes)" do
      redacted?("tfn: 123-456-789 end", "123-456-789")
    end

    # ---- Pattern 75: Indian Aadhaar ----
    it "redacts Indian Aadhaar (spaces)" do
      redacted?("aadhaar: 1234 5678 9012 end", "1234 5678 9012")
    end

    it "redacts Indian Aadhaar (dashes)" do
      redacted?("aadhaar: 1234-5678-9012 end", "1234-5678-9012")
    end

    # ---- Pattern 76: Indian PAN ----
    it "redacts Indian PAN" do
      redacted?("pan: ABCDE1234F end", "ABCDE1234F")
    end

    # ---- Pattern 77: Mexican CURP ----
    it "redacts Mexican CURP" do
      redacted?("curp: GARC850101HDFRRL09 end", "GARC850101HDFRRL09")
    end

    # ---- Pattern 78: South African ID ----
    it "redacts South African ID (13 digits)" do
      redacted?("said: 8501015009087 end", "8501015009087")
    end

    # ---- General ----
    it "returns text unchanged when no sensitive data" do
      expect(DataRedactor.redact("Hello, world!")).to eq("Hello, world!")
    end

    it "handles empty string" do
      expect(DataRedactor.redact("")).to eq("")
    end

    it "raises TypeError for non-string input" do
      expect { DataRedactor.redact(123) }.to raise_error(TypeError)
    end

    it "redacts multiple sensitive values in one string" do
      input = "key=AKIAIOSFODNN7EXAMPLE cf=RSSMRA85M01H501Z"
      result = DataRedactor.redact(input)
      expect(result.scan("[REDACTED]").length).to be >= 2
    end
  end

  describe "tag filtering" do
    let(:aws)    { "AKIAIOSFODNN7EXAMPLE" }                        # :credentials
    let(:email)  { "user@example.com" }                            # :contact
    let(:iban)   { "DE89370400440532013000" }                      # :financial
    let(:cf)     { "RSSMRA85M01H501Z" }                            # :tax_id
    let(:ssn)    { "123-45-6789" }                                 # :national_id
    let(:input)  { "k=#{aws} m=#{email} i=#{iban} cf=#{cf} s=#{ssn}" }

    describe ".tags" do
      it "returns the list of supported tags" do
        expect(DataRedactor.tags).to contain_exactly(
          :credentials, :financial, :tax_id, :national_id,
          :contact, :network, :travel, :other, :custom
        )
      end
    end

    describe "only:" do
      it "redacts only patterns in the given tag" do
        result = DataRedactor.redact(input, only: [:credentials])
        expect(result).not_to include(aws)
        expect(result).to include(email, iban, cf, ssn)
      end

      it "accepts multiple tags" do
        result = DataRedactor.redact(input, only: [:credentials, :contact])
        expect(result).not_to include(aws, email)
        expect(result).to include(iban, cf, ssn)
      end

      it "accepts a single symbol (not just an array)" do
        result = DataRedactor.redact(input, only: :financial)
        expect(result).not_to include(iban)
        expect(result).to include(aws, email, cf, ssn)
      end
    end

    describe "except:" do
      it "redacts every tag except the given one" do
        result = DataRedactor.redact(input, except: [:contact])
        expect(result).to include(email)
        expect(result).not_to include(aws, iban, cf, ssn)
      end

      it "accepts multiple tags" do
        # Two-tag case: IBAN digit substrings can overlap national_id shapes,
        # so we only assert about email (no overlap) and that aws/cf/ssn still
        # get redacted.
        result = DataRedactor.redact(input, except: [:contact, :financial])
        expect(result).to include(email)
        expect(result).not_to include(aws, cf, ssn)
      end
    end

    describe "validation" do
      it "allows only: and except: to be combined (e.g. only :contact except email)" do
        text = "user@example.com phone +1-202-555-0173 key AKIAIOSFODNN7EXAMPLE"
        result = DataRedactor.redact(text, only: :contact, except: ["email"])
        expect(result).to include("user@example.com") # email kept
        expect(result).not_to include("+1-202-555-0173") # phone redacted
        expect(result).to include("AKIAIOSFODNN7EXAMPLE") # not in :contact
      end

      it "raises UnknownTagError for an unknown tag" do
        expect { DataRedactor.redact(input, only: [:bogus]) }
          .to raise_error(DataRedactor::UnknownTagError, /bogus/)
      end

      it "raises UnknownPatternError for an unknown pattern name" do
        expect { DataRedactor.redact(input, except: ["nope"]) }
          .to raise_error(DataRedactor::UnknownPatternError, /nope/)
      end

      it "lets except: win over only: when they overlap (same tag → no-op)" do
        text = "user@example.com and +1-202-555-0173"
        expect(DataRedactor.redact(text, only: :contact, except: :contact)).to eq(text)
      end

      it "lets except: win over only: when both name the same pattern" do
        text = "user@example.com is the address"
        expect(DataRedactor.redact(text, only: ["email"], except: ["email"])).to eq(text)
      end

      it "redacts a single named pattern via only: as a String" do
        text = "user@example.com and AKIAIOSFODNN7EXAMPLE"
        result = DataRedactor.redact(text, only: ["aws_access_key_id"])
        expect(result).to include("user@example.com")
        expect(result).not_to include("AKIAIOSFODNN7EXAMPLE")
      end

      it "redacts a tag plus an extra named pattern from another tag" do
        text = "user@example.com and AKIAIOSFODNN7EXAMPLE"
        result = DataRedactor.redact(text, only: [:contact, "aws_access_key_id"])
        expect(result).not_to include("user@example.com")
        expect(result).not_to include("AKIAIOSFODNN7EXAMPLE")
      end
    end

    it "with no filter behaves identically to a fully-enabled call into _redact" do
      all_on = Array.new(DataRedactor::BUILTIN_PATTERN_NAMES.length, 1)
      expect(DataRedactor.redact(input))
        .to eq(DataRedactor._redact(input, DataRedactor::PH_MODE_PLAIN, "[REDACTED]", all_on))
    end
  end

  describe "configurable placeholder" do
    let(:email) { "user@example.com" }
    let(:aws)   { "AKIAIOSFODNN7EXAMPLE" }
    let(:iban)  { "DE89370400440532013000" }

    describe "plain string" do
      it "uses the default [REDACTED] when no placeholder given" do
        expect(DataRedactor.redact(email)).to include("[REDACTED]")
      end

      it "uses a custom plain string" do
        result = DataRedactor.redact(email, placeholder: "***")
        expect(result).to include("***")
        expect(result).not_to include("[REDACTED]")
        expect(result).not_to include(email)
      end

      it "uses an empty string placeholder" do
        result = DataRedactor.redact(email, placeholder: "")
        expect(result).not_to include(email)
        expect(result).not_to include("[REDACTED]")
      end
    end

    describe ":tagged placeholder" do
      it "replaces with [REDACTED:TAGNAME]" do
        result = DataRedactor.redact(email, placeholder: :tagged)
        expect(result).to include("[REDACTED:CONTACT]")
        expect(result).not_to include(email)
      end

      it "uses the correct tag for each pattern" do
        text   = "email #{email} key #{aws} iban #{iban}"
        result = DataRedactor.redact(text, placeholder: :tagged)
        expect(result).to include("[REDACTED:CONTACT]")
        expect(result).to include("[REDACTED:CREDENTIALS]")
        expect(result).to include("[REDACTED:FINANCIAL]")
      end

      it "works with only: filter" do
        result = DataRedactor.redact("#{email} #{aws}", only: :contact, placeholder: :tagged)
        expect(result).to include("[REDACTED:CONTACT]")
        expect(result).to include(aws)
      end
    end

    describe ":hash placeholder" do
      it "replaces with [TAGNAME_xxxx] format" do
        result = DataRedactor.redact(email, placeholder: :hash)
        expect(result).to match(/\[CONTACT_[0-9a-f]{4}\]/)
        expect(result).not_to include(email)
      end

      it "produces the same hash for the same value" do
        result1 = DataRedactor.redact("a #{email} b", placeholder: :hash)
        result2 = DataRedactor.redact("a #{email} b", placeholder: :hash)
        expect(result1).to eq(result2)
      end

      it "produces different hashes for different values" do
        r1 = DataRedactor.redact("user@foo.com", placeholder: :hash)
        r2 = DataRedactor.redact("user@bar.com", placeholder: :hash)
        expect(r1).not_to eq(r2)
      end

      it "uses the correct tag name" do
        result = DataRedactor.redact(aws, placeholder: :hash)
        expect(result).to match(/\[CREDENTIALS_[0-9a-f]{4}\]/)
      end
    end

    describe "validation" do
      it "raises ArgumentError for an invalid placeholder value" do
        expect { DataRedactor.redact(email, placeholder: 42) }
          .to raise_error(ArgumentError, /placeholder/)
      end
    end
  end

  describe "custom patterns" do
    before(:each) { DataRedactor.clear_custom_patterns! }
    after(:each)  { DataRedactor.clear_custom_patterns! }

    describe ".add_pattern / .redact" do
      it "redacts text matching a simple custom pattern" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        result = DataRedactor.redact("id EMP-123456 ok")
        expect(result).to include("[REDACTED]")
        expect(result).not_to include("EMP-123456")
      end

      it "accepts a Regexp and uses its source" do
        DataRedactor.add_pattern(name: "emp_id", regex: /EMP-[0-9]{6}/)
        expect(DataRedactor.redact("id EMP-999999 ok")).to include("[REDACTED]")
      end

      it "replaces an existing pattern with the same name" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{4}")
        expect(DataRedactor.custom_patterns.count { |p| p[:name] == "emp_id" }).to eq(1)
        expect(DataRedactor.redact("id EMP-1234 ok")).to include("[REDACTED]")
      end

      it "runs custom pattern only when :custom tag is included" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        expect(DataRedactor.redact("EMP-123456", only: [:custom])).to include("[REDACTED]")
        expect(DataRedactor.redact("EMP-123456", except: [:custom])).to include("EMP-123456")
      end

      it "supports boundary: true to avoid matching inside longer alphanumeric tokens" do
        DataRedactor.add_pattern(name: "emp_code", regex: "EMP[0-9]{4}", boundary: true)
        # standalone token → redacted
        expect(DataRedactor.redact("code EMP1234 ok", only: [:custom])).to include("[REDACTED]")
        # embedded inside a longer alphanumeric token → NOT redacted
        expect(DataRedactor.redact("XEMP1234Y", only: [:custom])).to include("XEMP1234Y")
      end

      it "supports a built-in tag other than :custom" do
        DataRedactor.add_pattern(name: "internal_key", regex: "INT-[A-Z]{3}", tag: :credentials)
        pattern = DataRedactor.custom_patterns.find { |p| p[:name] == "internal_key" }
        expect(pattern[:tag]).to eq(:credentials)
        expect(DataRedactor.redact("INT-ABC", only: [:credentials])).to include("[REDACTED]")
        expect(DataRedactor.redact("INT-ABC", only: [:custom])).to include("INT-ABC")
      end
    end

    describe ".remove_pattern" do
      it "removes a named pattern and returns true" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        expect(DataRedactor.remove_pattern("emp_id")).to be true
        expect(DataRedactor.redact("EMP-123456")).to include("EMP-123456")
      end

      it "returns false when name is not found" do
        expect(DataRedactor.remove_pattern("nonexistent")).to be false
      end
    end

    describe ".custom_patterns" do
      it "returns an array of hashes with name, source, tag, boundary" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}", boundary: true)
        patterns = DataRedactor.custom_patterns
        expect(patterns.length).to eq(1)
        p = patterns.first
        expect(p[:name]).to eq("emp_id")
        expect(p[:source]).to eq("EMP-[0-9]{6}")
        expect(p[:tag]).to eq(:custom)
        expect(p[:boundary]).to be true
      end

      it "returns empty array when no custom patterns" do
        expect(DataRedactor.custom_patterns).to eq([])
      end
    end

    describe ".clear_custom_patterns!" do
      it "removes all custom patterns" do
        DataRedactor.add_pattern(name: "a", regex: "AAA-[0-9]+")
        DataRedactor.add_pattern(name: "b", regex: "BBB-[0-9]+")
        DataRedactor.clear_custom_patterns!
        expect(DataRedactor.custom_patterns).to be_empty
      end
    end

    describe "validation" do
      it "raises ArgumentError for an empty name" do
        expect { DataRedactor.add_pattern(name: "", regex: "EMP-[0-9]+") }
          .to raise_error(ArgumentError, /non-empty/)
      end

      it "raises ArgumentError for a non-String/Regexp regex" do
        expect { DataRedactor.add_pattern(name: "x", regex: 42) }
          .to raise_error(ArgumentError, /String or Regexp/)
      end

      it "raises InvalidPatternError for \\d (Ruby shorthand)" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP-\\d{6}") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for \\b (word boundary)" do
        expect { DataRedactor.add_pattern(name: "x", regex: "\\bEMP\\b") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for lookahead" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP(?=[0-9])") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for non-greedy quantifier" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP-[0-9]+?") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for invalid POSIX ERE (regcomp rejects it)" do
        expect { DataRedactor.add_pattern(name: "x", regex: "[invalid") }
          .to raise_error(DataRedactor::InvalidPatternError)
      end

      it "raises InvalidPatternError for capture groups with boundary: true" do
        expect { DataRedactor.add_pattern(name: "x", regex: "(EMP)-[0-9]{6}", boundary: true) }
          .to raise_error(DataRedactor::InvalidPatternError, /capture groups/)
      end

      it "raises UnknownTagError for an invalid tag" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP-[0-9]+", tag: :bogus) }
          .to raise_error(DataRedactor::UnknownTagError)
      end
    end
  end

  describe ".scan" do
    let(:email) { "user@example.com" }
    let(:aws)   { "AKIAIOSFODNN7EXAMPLE" }
    let(:iban)  { "DE89370400440532013000" }

    it "returns a hash with :redacted and :matches keys" do
      result = DataRedactor.scan(email)
      expect(result).to be_a(Hash)
      expect(result).to have_key(:redacted)
      expect(result).to have_key(:matches)
    end

    it ":redacted contains [REDACTED] in place of matches" do
      result = DataRedactor.scan(email)
      expect(result[:redacted]).to include("[REDACTED]")
      expect(result[:redacted]).not_to include(email)
    end

    it "returns match hashes with correct keys" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m).to include(:tag, :name, :value, :start, :length)
    end

    it "reports the correct tag symbol" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m[:tag]).to eq(:contact)
    end

    it "reports the correct pattern name" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m[:name]).to eq("email")
    end

    it "reports the matched value" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m[:value]).to eq(email)
    end

    it "reports correct start and length that index into the original string" do
      text = "contact: #{email} end"
      result = DataRedactor.scan(text)
      m = result[:matches].find { |x| x[:name] == "email" }
      expect(text.byteslice(m[:start], m[:length])).to eq(email)
    end

    it "returns correct positions for multiple matches from different patterns" do
      text = "k=#{aws} e=#{email} i=#{iban}"
      result = DataRedactor.scan(text)
      result[:matches].each do |m|
        expect(text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]}: byteslice mismatch"
      end
    end

    it "returns correct positions when a shorter value is replaced before a later one" do
      # email (16 bytes) fires after aws (20 bytes); replacement shifts subsequent offsets
      text = "#{aws} #{email}"
      result = DataRedactor.scan(text)
      result[:matches].each do |m|
        expect(text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]}: byteslice mismatch after earlier replacement"
      end
    end

    it "returns no matches for text with nothing sensitive" do
      result = DataRedactor.scan("hello world")
      expect(result[:matches]).to be_empty
      expect(result[:redacted]).to eq("hello world")
    end

    it "accepts only: filter" do
      text = "#{email} #{aws}"
      result = DataRedactor.scan(text, only: :contact)
      names = result[:matches].map { |m| m[:name] }
      expect(names).to include("email")
      expect(names).not_to include("aws_access_key_id")
    end

    it "accepts except: filter" do
      text = "#{email} #{aws}"
      result = DataRedactor.scan(text, except: :contact)
      names = result[:matches].map { |m| m[:name] }
      expect(names).not_to include("email")
      expect(names).to include("aws_access_key_id")
    end

    it "supports combining only: and except: with mixed Symbols and pattern names" do
      text = "alice@example.com +1-202-555-0173"
      result = DataRedactor.scan(text, only: :contact, except: ["email"])
      names = result[:matches].map { |m| m[:name] }
      expect(names).not_to include("email")
      expect(names).to include("phone_e164")
    end

    it "includes custom pattern matches" do
      DataRedactor.clear_custom_patterns!
      DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
      result = DataRedactor.scan("hire EMP-123456 done")
      m = result[:matches].find { |x| x[:name] == "emp_id" }
      expect(m).not_to be_nil
      expect(m[:tag]).to eq(:custom)
      expect(m[:value]).to eq("EMP-123456")
      DataRedactor.clear_custom_patterns!
    end
  end
end
