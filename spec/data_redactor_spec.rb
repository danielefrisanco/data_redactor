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

    # ---- HashiCorp tokens ----
    it "redacts HashiCorp Vault service token (hvs. prefix)" do
      token = "hvs." + "A" * 95
      redacted?("token=#{token} end", token)
    end

    it "redacts HashiCorp Vault batch token (hvb. prefix)" do
      token = "hvb." + "B" * 150
      redacted?("token=#{token} end", token)
    end

    it "redacts a hvb. token longer than the 255-char cap" do
      # Upper bound is capped at POSIX RE_DUP_MAX (255) for musl portability
      # (was 300; musl regcomp rejects n>255). A 260-char token is still matched
      # and redacted — the original long base64url run no longer survives intact.
      token = "hvb." + "B" * 260
      result = DataRedactor.redact("token=#{token} end")
      expect(result).to include("[REDACTED]")
      expect(result).not_to include("B" * 256)
    end

    it "redacts HashiCorp Terraform Cloud API token (atlasv1)" do
      token = "abcdefghijklmn.atlasv1." + "C" * 65
      redacted?("token=#{token} end", token)
    end

    it "does not redact short hvs. string (below minimum length)" do
      short = "hvs.tooshort"
      expect(DataRedactor.redact(short)).to eq(short)
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

    describe "engine scan-state invalidation across pattern-set changes" do
      # The v19 engine caches per-thread scan state (NFA scratch + lazy DFA),
      # keyed by pattern slot. add_pattern/remove_pattern/clear_custom_patterns!
      # bump a generation counter that drops and rebuilds that cache. This
      # exercises the drop-and-regrow path on the same thread (warm cache, then
      # mutate the pattern set, then redact again) and asserts the built-in
      # cache stays correct and custom patterns appear/disappear as expected.
      it "redacts correctly after add/remove churn between calls" do
        text = "email a@b.com and run EMP-123456 plus card 4111 1111 1111 1111"

        # Warm the cache on built-ins only.
        warm = DataRedactor.redact(text)
        expect(warm).not_to include("a@b.com")
        expect(warm).not_to include("4111 1111 1111 1111")
        expect(warm).to include("EMP-123456") # not a built-in yet

        # Add a custom -> generation bump -> cache dropped & rebuilt next call.
        DataRedactor.add_pattern(name: "emp", regex: "EMP-[0-9]{6}")
        after_add = DataRedactor.redact(text)
        expect(after_add).not_to include("EMP-123456")  # custom now fires
        expect(after_add).not_to include("a@b.com")      # built-ins still fire
        expect(after_add).not_to include("4111 1111 1111 1111")

        # Remove it -> generation bump -> custom gone, built-ins still correct.
        DataRedactor.remove_pattern("emp")
        after_remove = DataRedactor.redact(text)
        expect(after_remove).to eq(warm)
      end

      it "keeps two customs independent after a middle removal compacts slots" do
        # remove_pattern compacts the engine array, so slot p shifts to a
        # different pattern. The generation bump must invalidate the cache so the
        # shifted slot is not served from a stale DFA.
        DataRedactor.add_pattern(name: "x", regex: "XX-[0-9]{3}")
        DataRedactor.add_pattern(name: "y", regex: "YY-[0-9]{3}")
        DataRedactor.add_pattern(name: "z", regex: "ZZ-[0-9]{3}")
        DataRedactor.redact("XX-111 YY-222 ZZ-333") # warm all three slots

        DataRedactor.remove_pattern("y") # compacts: z shifts into y's old slot
        got = DataRedactor.redact("XX-111 YY-222 ZZ-333")
        expect(got).not_to include("XX-111")
        expect(got).to include("YY-222")       # removed
        expect(got).not_to include("ZZ-333")   # still matches despite slot shift
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

    describe "concurrent registration vs redaction" do
      # Functional guard for the custom-pattern mutex. The readers run with
      # custom patterns ENABLED (default redact/scan, no `only:`), so each call
      # iterates the shared custom array while the writer add/remove-churns it.
      #
      # Note on the GVL: this test uses a SMALL input (< the C-layer GVL-release
      # threshold), so redact keeps the GVL here and the custom-array access is
      # serialised. It guards the mutex against deadlock and asserts functional
      # correctness under churn. The large-input sibling test below crosses the
      # threshold so the built-in scan runs GVL-free in true parallel — that one
      # is the real race detector for the per-thread scan-state refactor. The
      # redacted built-ins and the always-present "stable" custom are invariant
      # to the churn, so their absence from the output is a stable assertion
      # regardless of interleaving.
      it "stays correct and crash-free while patterns churn from another thread" do
        # Keep a stable, always-present custom pattern so the reader loop has a
        # real entry to walk even between the writer's add/remove of "churn".
        DataRedactor.add_pattern(name: "stable", regex: "STABLE-[0-9]{4}")
        input = "email user@example.com card 4111 1111 1111 1111 id STABLE-7777"

        stop   = false
        errors = Queue.new

        writer = Thread.new do
          i = 0
          until stop
            DataRedactor.add_pattern(name: "churn#{i % 16}", regex: "ZZZ-[0-9]{4}")
            DataRedactor.remove_pattern("churn#{i % 16}")
            i += 1
          end
        rescue => e
          errors << e
        end

        readers = Array.new(8) do
          Thread.new do
            3_000.times do
              got = DataRedactor.redact(input)
              # Built-ins and the always-present "stable" custom must always fire,
              # regardless of how the churn interleaves.
              raise "email leaked: #{got.inspect}"  if got.include?("user@example.com")
              raise "card leaked: #{got.inspect}"   if got.include?("4111 1111 1111 1111")
              raise "stable leaked: #{got.inspect}" if got.include?("STABLE-7777")
              DataRedactor.scan(input)
            end
          rescue => e
            errors << e
          end
        end

        readers.each(&:join)
        stop = true
        writer.join

        raise errors.pop until errors.empty?
        expect(errors).to be_empty
      end

      # The real race detector for the per-thread scan-state refactor + GVL
      # release. The input is large enough that redact releases the GVL around
      # the built-in v19 pass, so N threads run mm_scan TRULY in parallel — each
      # mutating its own per-thread scan_state_t (NFA scratch + lazy DFA cache).
      # If any of that state were still shared, concurrent scans would corrupt
      # each other's matches or crash on a concurrent realloc. A writer churns
      # the custom registry at the same time (generation-counter invalidation
      # under contention). Correctness gate: every thread's output must equal the
      # single-threaded reference for the same input.
      it "scans large inputs in parallel (GVL released) without corruption" do
        # > the C GVL_RELEASE_THRESHOLD (4 KB) so the GVL is actually released.
        line  = "log email user#{rand(1000)}@example.com ip 10.0.#{rand(255)}.#{rand(255)} " \
                "card 4111 1111 1111 1111 ssn 123-45-6789 iban DE89370400440532013000\n"
        input = line * 200  # ~16 KB, many matches per scan
        reference = DataRedactor.redact(input)
        expect(reference).not_to include("@example.com")

        stop   = false
        errors = Queue.new

        writer = Thread.new do
          i = 0
          until stop
            DataRedactor.add_pattern(name: "churn#{i % 8}", regex: "QQQ-[0-9]{5}")
            DataRedactor.remove_pattern("churn#{i % 8}")
            i += 1
          end
        rescue => e
          errors << e
        end

        readers = Array.new(8) do
          Thread.new do
            200.times do
              got = DataRedactor.redact(input)
              raise "output diverged under parallel GVL-free scan" unless got == reference
            end
          rescue => e
            errors << e
          end
        end

        readers.each(&:join)
        stop = true
        writer.join

        raise errors.pop until errors.empty?
        expect(errors).to be_empty
      end

      # Exercises the pthread_key destructor that frees a thread's per-thread
      # scan state (NFA scratch + DFA cache) at thread exit. Each iteration
      # spawns a fresh thread that warms its own large per-thread cache, then
      # exits — firing the destructor. Many rounds must stay correct and
      # crash-free (a double-free or use-after-free in the destructor would
      # surface here). Memory reclamation itself is checked separately by an
      # RSS-stability bench, not asserted from Ruby.
      it "frees per-thread state across many short-lived threads" do
        input = ("log a@b.com ip 10.0.0.1 ssn 123-45-6789 " * 200) # > GVL threshold
        reference = DataRedactor.redact(input)
        errors = Queue.new

        50.times do
          t = Thread.new do
            5.times do
              raise "diverged" unless DataRedactor.redact(input) == reference
            end
          rescue => e
            errors << e
          end
          t.join # thread exits here -> destructor runs
        end

        raise errors.pop until errors.empty?
        expect(errors).to be_empty
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

    it "returns correct positions for repeated matches of the same pattern" do
      # Three AKIAs across three lines exercises intra-pattern repl_log
      # accumulation; before the fix the 2nd and 3rd reported start offsets
      # were off by +10 per prior match (the placeholder length).
      line = "user mario@example.com ip 192.168.0.1 key AKIAIOSFODNN7EXAMPLE\n"
      text = line * 3
      result = DataRedactor.scan(text)
      result[:matches].each do |m|
        expect(text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]} @ #{m[:start]}: byteslice mismatch (regression of multi-match offset bug)"
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

  describe ".redact_deep" do
    let(:email) { "alice@example.com" }
    let(:key)   { "AKIAIOSFODNN7EXAMPLE" }

    it "redacts string values in a flat hash" do
      result = DataRedactor.redact_deep({ "email" => email, "count" => 3 })
      expect(result["email"]).to eq("[REDACTED]")
      expect(result["count"]).to eq(3)
    end

    it "redacts string values in a nested hash" do
      result = DataRedactor.redact_deep({ "user" => { "email" => email } })
      expect(result["user"]["email"]).to eq("[REDACTED]")
    end

    it "redacts string values inside arrays" do
      result = DataRedactor.redact_deep([email, 42, nil])
      expect(result[0]).to eq("[REDACTED]")
      expect(result[1]).to eq(42)
      expect(result[2]).to be_nil
    end

    it "redacts strings nested inside arrays inside hashes" do
      result = DataRedactor.redact_deep({ "keys" => [key, "safe"] })
      expect(result["keys"][0]).to eq("[REDACTED]")
      expect(result["keys"][1]).to eq("safe")
    end

    it "does not mutate the original structure" do
      original = { "email" => email }
      DataRedactor.redact_deep(original)
      expect(original["email"]).to eq(email)
    end

    it "leaves non-string scalars (Integer, Float, nil, Boolean) unchanged" do
      input = { "n" => 1, "f" => 3.14, "nil" => nil, "bool" => true }
      result = DataRedactor.redact_deep(input)
      expect(result).to eq(input)
    end

    it "does not redact hash keys" do
      result = DataRedactor.redact_deep({ email => "value" })
      expect(result.keys).to include(email)
    end

    it "passes only:/except:/placeholder: through to redact" do
      result = DataRedactor.redact_deep({ "email" => email, "key" => key },
                                        only: :credentials)
      expect(result["email"]).to eq(email)
      expect(result["key"]).to eq("[REDACTED]")
    end

    it "accepts a plain string as top-level input" do
      expect(DataRedactor.redact_deep(email)).to eq("[REDACTED]")
    end

    it "accepts a top-level array" do
      result = DataRedactor.redact_deep([email, key])
      expect(result).to eq(["[REDACTED]", "[REDACTED]"])
    end

    it "passes non-Hash/Array/String values through unchanged" do
      expect(DataRedactor.redact_deep(42)).to eq(42)
      expect(DataRedactor.redact_deep(nil)).to be_nil
    end

    it "raises on circular references in hashes" do
      h = {}
      h["self"] = h
      expect { DataRedactor.redact_deep(h) }.to raise_error(ArgumentError, /circular reference/)
    end

    it "raises on circular references in arrays" do
      a = []
      a << a
      expect { DataRedactor.redact_deep(a) }.to raise_error(ArgumentError, /circular reference/)
    end
  end

  describe ".redact_json" do
    let(:email) { "alice@example.com" }

    it "redacts string values and returns valid JSON" do
      input  = JSON.generate({ "email" => email, "count" => 3 })
      output = DataRedactor.redact_json(input)
      parsed = JSON.parse(output)
      expect(parsed["email"]).to eq("[REDACTED]")
      expect(parsed["count"]).to eq(3)
    end

    it "handles nested structures" do
      input  = JSON.generate({ "user" => { "email" => email } })
      output = DataRedactor.redact_json(input)
      expect(JSON.parse(output).dig("user", "email")).to eq("[REDACTED]")
    end

    it "handles arrays in JSON" do
      input  = JSON.generate([email, 1, nil])
      output = DataRedactor.redact_json(input)
      parsed = JSON.parse(output)
      expect(parsed[0]).to eq("[REDACTED]")
      expect(parsed[1]).to eq(1)
      expect(parsed[2]).to be_nil
    end

    it "raises JSON::ParserError on invalid JSON" do
      expect { DataRedactor.redact_json("not json") }.to raise_error(JSON::ParserError)
    end

    it "forwards only:/except: to redact" do
      key   = "AKIAIOSFODNN7EXAMPLE"
      input = JSON.generate({ "email" => email, "key" => key })
      output = DataRedactor.redact_json(input, only: :credentials)
      parsed = JSON.parse(output)
      expect(parsed["email"]).to eq(email)
      expect(parsed["key"]).to eq("[REDACTED]")
    end
  end

  describe ".name_pattern" do
    after(:each) { DataRedactor.clear_custom_patterns! }

    # Register a generated name pattern and report whether `text` gets redacted.
    def name_redacted?(text, *args, **kwargs)
      DataRedactor.clear_custom_patterns!
      DataRedactor.add_pattern(
        name: "spec_name", regex: DataRedactor.name_pattern(*args, **kwargs), tag: :contact
      )
      DataRedactor.redact("x #{text} y").include?("[REDACTED]")
    end

    it "returns a String POSIX ERE" do
      expect(DataRedactor.name_pattern("Mario", "Rossi")).to be_a(String)
    end

    it "matches the canonical First Last form" do
      expect(name_redacted?("Mario Rossi", "Mario", "Rossi")).to be true
    end

    it "matches case-insensitively" do
      expect(name_redacted?("mario rossi", "Mario", "Rossi")).to be true
      expect(name_redacted?("MARIO ROSSI", "Mario", "Rossi")).to be true
    end

    it "matches the swapped Last First order" do
      expect(name_redacted?("Rossi Mario", "Mario", "Rossi")).to be true
    end

    it "matches the Last, First comma forms" do
      expect(name_redacted?("Rossi, Mario", "Mario", "Rossi")).to be true
      expect(name_redacted?("Rossi,Mario", "Mario", "Rossi")).to be true
    end

    it "matches initial-only forms" do
      expect(name_redacted?("M. Rossi", "Mario", "Rossi")).to be true
      expect(name_redacted?("M Rossi", "Mario", "Rossi")).to be true
      expect(name_redacted?("Mario R.", "Mario", "Rossi")).to be true
      expect(name_redacted?("M.R.", "Mario", "Rossi")).to be true
      expect(name_redacted?("MR", "Mario", "Rossi")).to be true
    end

    it "does not match a name embedded in a longer word" do
      expect(name_redacted?("Mariolino", "Mario", "Rossi")).to be false
      expect(name_redacted?("marioland", "Mario", "Rossi")).to be false
    end

    it "does not match a different name" do
      expect(name_redacted?("Maria Rossi", "Mario", "Rossi")).to be false
      expect(name_redacted?("Mario Russo", "Mario", "Rossi")).to be false
    end

    it "tolerates diacritics on the matched text" do
      expect(name_redacted?("José Muñoz", "Jose", "Munoz")).to be true
      expect(name_redacted?("JOSÉ MUÑOZ", "Jose", "Munoz")).to be true
    end

    it "matches an accented input against the bare ASCII form" do
      expect(name_redacted?("Jose Munoz", "José", "Muñoz")).to be true
    end

    it "treats spaces and hyphens interchangeably in a hyphenated part" do
      expect(name_redacted?("Anne-Marie Berg", "Anne-Marie", "Berg")).to be true
      expect(name_redacted?("Anne Marie Berg", "Anne-Marie", "Berg")).to be true
      expect(name_redacted?("AnneMarie Berg",  "Anne-Marie", "Berg")).to be true
    end

    it "matches either half of a hyphenated part alone" do
      expect(name_redacted?("Anne Berg",  "Anne-Marie", "Berg")).to be true
      expect(name_redacted?("Marie Berg", "Anne-Marie", "Berg")).to be true
    end

    it "matches a multi-word last name" do
      expect(name_redacted?("Jan Van der Berg", "Jan", "Van der Berg")).to be true
      expect(name_redacted?("Jan Van-der-Berg", "Jan", "Van der Berg")).to be true
    end

    it "matches both no-middle and with-middle forms when middle: is given" do
      expect(name_redacted?("Mario Rossi", "Mario", "Rossi", middle: "Luigi")).to be true
      expect(name_redacted?("Mario Luigi Rossi", "Mario", "Rossi", middle: "Luigi")).to be true
      expect(name_redacted?("Rossi Mario Luigi", "Mario", "Rossi", middle: "Luigi")).to be true
    end

    it "is usable through add_pattern with only:/except: filtering" do
      DataRedactor.add_pattern(
        name: "spec_name", regex: DataRedactor.name_pattern("Mario", "Rossi"), tag: :contact
      )
      expect(DataRedactor.redact("x Mario Rossi y", only: :contact)).to include("[REDACTED]")
      expect(DataRedactor.redact("x Mario Rossi y", except: :contact)).to include("Mario Rossi")
    end

    it "raises ArgumentError on an empty or non-String first name" do
      expect { DataRedactor.name_pattern("", "Rossi") }.to raise_error(ArgumentError)
      expect { DataRedactor.name_pattern(nil, "Rossi") }.to raise_error(ArgumentError)
    end

    it "raises ArgumentError on an empty or non-String last name" do
      expect { DataRedactor.name_pattern("Mario", "  ") }.to raise_error(ArgumentError)
      expect { DataRedactor.name_pattern("Mario", 42) }.to raise_error(ArgumentError)
    end

    it "raises ArgumentError when middle: is given but blank" do
      expect { DataRedactor.name_pattern("Mario", "Rossi", middle: "") }.to raise_error(ArgumentError)
    end
  end

  # Inputs larger than DataRedactor::CHUNK_SIZE take a different Ruby code path
  # that splits the input on newlines and runs the C engine per chunk. The
  # observable behaviour must be identical to the single-shot path.
  describe "chunked path (inputs > CHUNK_SIZE)" do
    let(:line) { "user mario@example.com ip 192.168.0.1 key AKIAIOSFODNN7EXAMPLE\n" }
    # Repeat enough times to comfortably exceed CHUNK_SIZE (64 KB).
    let(:big_text) { line * 2000 }  # ~140 KB

    it "produces output identical to running the C engine on the whole input at once" do
      chunked   = DataRedactor.redact(big_text)
      direct    = DataRedactor.send(:_redact, big_text,
                                     DataRedactor::PH_MODE_PLAIN, "[REDACTED]",
                                     DataRedactor.send(:build_enable_bits, nil, nil))
      expect(chunked).to eq(direct)
    end

    it "scan preserves the byteslice invariant across chunk boundaries" do
      result = DataRedactor.scan(big_text)
      expect(result[:matches]).not_to be_empty
      result[:matches].each do |m|
        expect(big_text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]} @ #{m[:start]}: byteslice mismatch across chunks"
      end
    end

    it "redacts a match that sits right at a chunk boundary (last line of chunk)" do
      # Construct an input where a match ends exactly at byte CHUNK_SIZE-1, so
      # the newline that terminates it falls on the boundary.
      cs = DataRedactor::CHUNK_SIZE
      filler = "x" * (cs - line.bytesize)
      text = filler + line + line  # match on the line straddling boundary
      result = DataRedactor.redact(text)
      expect(result.scan("[REDACTED]").size).to be >= 6  # 3 matches × 2 lines
    end
  end

  # Overlap-resolution behaviour. Two sets of specs because today's engine and
  # the future combined matcher resolve overlaps differently — see
  # docs/combined_matcher_plan.md "Prep 2" and docs/standalone_matcher_design.md
  # "Overlap resolution".
  #
  # TODAY (the C engine on glibc regex): patterns run sequentially in array
  # order; once a pattern replaces a span with [REDACTED] later patterns can't
  # re-match those bytes. Net effect: the *earliest pattern by index* wins
  # any region it can match, regardless of length.
  #
  # POST-1.0 (combined matcher): longest-match-wins, with pattern-id as the
  # tiebreak for equal-length matches. This is a deliberate behaviour change
  # — the AKIA+suffix case below shows today's policy leaving secrets partly
  # unredacted, which is the worst kind of failure for a redaction gem.
  describe "overlap resolution — today's pattern-id-priority behaviour" do
    it "earlier-index pattern wins even when a later-index pattern could match a LONGER span" do
      # aws_access_key_id (index 14) matches the leading 20 chars.
      # aws_secret_access_key (index 15) could match all 40 chars.
      # Today's behaviour: AKIA wins the 20-char prefix; the trailing 20 A's
      # are left unredacted.
      # ⚠ This is the case the 1.0 matcher will FIX (see pending specs below).
      input = "AKIAIOSFODNN7EXAMPLE" + ("A" * 20)  # 40 chars
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["aws_access_key_id"])
      expect(result[:matches].first[:value]).to eq("AKIAIOSFODNN7EXAMPLE")
      expect(DataRedactor.redact(input)).to eq("[REDACTED]" + ("A" * 20))
    end

    it "earlier-index pattern wins among multiple patterns matching the same exact span" do
      # 11-digit number: polish_pesel (81), belgian_national_number (82),
      # norwegian_fodselsnummer (83), polish_pesel_2 (87) all match.
      # polish_pesel at the lowest index wins (preserved post-1.0 by the
      # pattern-id tiebreak).
      input = "id 85121612345 end"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["polish_pesel"])
    end

    it "a 9-digit number matches czech_rodne_cislo (its regex allows the / to be optional), winning over more-specific 9-digit patterns at higher indices" do
      # czech_rodne_cislo (index 69) is `[0-9]{6}/?[0-9]{3,4}` — the / is
      # optional so it matches 9 consecutive digits.
      # passport_9digits (84), dutch_bsn (85), austrian_abgabenkontonummer (86)
      # all also match 9 digits — but index 69 < 84,85,86 so czech wins.
      # All four match the same 9-char span so this case is unchanged post-1.0.
      input = "num 123456789 end"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["czech_rodne_cislo"])
    end

    it "credit_card consumes 16 digits, leaving no 11-digit run for national-ID patterns to match" do
      # credit_card (index 56) matches a 16-digit Visa.
      # polish_pesel/belgian/norwegian/etc. (indices 81-87) would each match
      # an 11-digit slice — but credit_card runs first and replaces with
      # [REDACTED], so the digit-only patterns see no 11-digit run.
      # Post-1.0 longest-match also picks credit_card (16 > 11), unchanged.
      input = "card=4111111111111111 end"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["credit_card"])
    end

    # DIVERGENCE (scan, rewrite-dependent): on the original buffer idx-15
    # ([A-Za-z0-9/+=]{40}) matches the full 60-char span [0,60), which overlaps
    # idx-14's [0,20). mm_resolve drops it. The old sequential engine rewrote
    # chars 0-19 first, leaving the 40 x's in isolation for idx-15 to match at
    # working pos 10 → original pos 20. Single-pass can't see that second match.
    it "DIVERGENCE — scan: aws_secret match exposed by rewrite is invisible to single-pass engine" do
      input = "AKIAIOSFODNN7EXAMPLE" + ("x" * 40)  # AKIA (20) + 40 alphanum
      result = DataRedactor.scan(input)
      names = result[:matches].map { |m| m[:name] }
      # Old sequential engine: ["aws_access_key_id", "aws_secret_access_key"]
      # v19 single-pass engine: only aws_access_key_id (idx-15 [0,60) overlaps idx-14 [0,20))
      expect(names).to eq(["aws_access_key_id"])
    end

    it "consumes the 'specific prefix' even when only it matches; later patterns see leftovers verbatim" do
      # Only AKIA fits (need 40 chars for secret; only have 39).
      # No actual overlap — both policies match only AKIA.
      input = "key=AKIAIOSFODNN7EXAMPLEextrabytesfor20"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["aws_access_key_id"])
    end

    # The AKIA-prefix behaviour must be independent of WHICH characters follow,
    # not an artefact of repeated 'A's. aws_secret_access_key is [A-Za-z0-9/+=]{40}
    # so any of these 20-char suffixes COULD form a 40-char secret on the original
    # buffer — yet today's sequential rewrite redacts only the 20-char AKIA prefix
    # because aws_access_key_id (idx 14) rewrites it before idx 15 ever runs.
    # This is the contract the ported engine's overlap resolver (mm_resolve,
    # "index-order greedy claim") must reproduce byte-for-byte. See TODO.md §1d Gap 5.
    {
      "repeated A"  => "A" * 20,
      "repeated B"  => "B" * 20,
      "repeated Z"  => "Z" * 20,
      "repeated 9"  => "9" * 20,
      "mixed alnum" => "B3xQ7mK9pL2wR5tZ8nV4",
      "lowercase"   => "abcdefghijklmnopqrst",
      "with slashes" => "B/B/B/B/B/B/B/B/B/B/",
    }.each do |label, suffix|
      it "redacts only the 20-char AKIA prefix regardless of the following bytes (#{label})" do
        input = "AKIAIOSFODNN7EXAMPLE" + suffix
        # Only the AKIA prefix is claimed; the 40-char-secret pattern is blocked by
        # the prior rewrite, so the suffix survives verbatim.
        expect(DataRedactor.redact(input)).to eq("[REDACTED]" + suffix)
        result = DataRedactor.scan(input)
        expect(result[:matches].map { |m| m[:name] }).to eq(["aws_access_key_id"])
        expect(result[:matches].first[:value]).to eq("AKIAIOSFODNN7EXAMPLE")
      end
    end
  end

  # Rewrite-created/destroyed boundary cases — two sensitive tokens that ABUT with
  # NO separator between them. The glibc engine rewrote patterns sequentially, so a
  # lower-index pattern's [REDACTED] could introduce a '['/']' boundary that an
  # adjacent boundary-wrapped pattern then matched on the rewritten buffer. The v19
  # engine scans the ORIGINAL buffer in one pass and cannot see a boundary the
  # rewrite would create — this is its ONE documented behavioural divergence from
  # the old engine (TODO.md §1d Gap 5, "accepted divergence"): the second token is
  # left unredacted. Accepted because it only arises for directly-abutting secrets
  # with no separator (rare in real text), the old output was itself a rewrite
  # artifact, and the planned 1.0 longest-match policy redacts the whole region.
  describe "overlap resolution — rewrite-created-boundary divergence (accepted)" do
    it "DIVERGENCE: an SSN abutting an IPv4 (no separator) leaves the SSN unredacted under the v19 engine" do
      # 123-45-6789 has no boundary char after '6789' (next byte is '1'), so us_ssn
      # cannot match the original text. The old glibc engine redacted 192.168.1.1
      # first, creating a '[' that then bounded the SSN → "[REDACTED][REDACTED]".
      # The v19 single-pass engine never sees that created boundary, so only ipv4
      # is redacted. This is the accepted Gap-5 divergence.
      input = "123-45-6789192.168.1.1"
      expect(DataRedactor.redact(input)).to eq("123-45-6789[REDACTED]")
    end

    it "a greedy earlier match can leave a mangled half-token (rewrite destroys a boundary)" do
      # ipv4 greedily consumes "192.168.1.1", leaving "123-45-6789"; but the
      # leading digits were eaten, so only "3-45-6789" remains after [REDACTED].
      input = "192.168.1.1123-45-6789"
      expect(DataRedactor.redact(input)).to eq("[REDACTED]3-45-6789")
    end

    it "an alnum run after a prefixed key: aws_secret_access_key (idx 15) claims 40 chars before github (idx 19)" do
      # aws_secret_access_key [A-Za-z0-9/+=]{40} runs before github_classic_pat and
      # matches 40 chars starting just after 'ghp_', swallowing into the digit run:
      # ghp_[REDACTED]1612345. Another earlier-index-wins case, not a clean ghp_ hit.
      input = "ghp_ABCDEFGHIJabcdefghij0123456789ABCDEF85121612345"
      expect(DataRedactor.redact(input)).to eq("ghp_[REDACTED]1612345")
    end
  end

  # Specs marked `pending` describe the INTENDED 1.0 matcher behaviour
  # (longest-match wins, tiebreak by pattern-id). They fail today by design,
  # so they're skipped; the combined-matcher PR will unmark them and remove
  # the corresponding "today's behaviour" specs above.
  describe "overlap resolution — intended 1.0 longest-match-wins behaviour" do
    it "longest-match wins: AKIA+suffix that forms a valid 40-char secret is redacted whole" do
      pending "1.0.0: combined matcher implements longest-match policy"
      input = "AKIAIOSFODNN7EXAMPLE" + ("A" * 20)  # 40 alphanum chars
      # Under longest-match, aws_secret_access_key (40 chars) beats
      # aws_access_key_id (20 chars). Whole span redacted; nothing leaks.
      expect(DataRedactor.redact(input)).to eq("[REDACTED]")
      names = DataRedactor.scan(input)[:matches].map { |m| m[:name] }
      expect(names).to eq(["aws_secret_access_key"])
    end

    it "ties broken by pattern-id (preserving today's behaviour for tied lengths)" do
      # 11-digit number: 4 patterns match the same 11-char span. Today's
      # pattern-id behaviour AND post-1.0 longest-with-id-tiebreak both pick
      # polish_pesel. Not marked pending — this spec passes under either
      # policy and documents the invariant tied lengths preserve.
      input = "id 85121612345 end"
      names = DataRedactor.scan(input)[:matches].map { |m| m[:name] }
      expect(names).to eq(["polish_pesel"])
    end

    it "longest-match safer when uncertain: prefers the more-thorough redaction" do
      pending "1.0.0: combined matcher implements longest-match policy"
      # This is the safety argument: when we can't tell whether bytes are
      # 'one secret' or 'two adjacent secrets', redact more rather than less.
      input = "AKIAIOSFODNN7EXAMPLE" + "B" * 20  # 40 alphanum
      expect(DataRedactor.redact(input)).to eq("[REDACTED]")
    end
  end

  describe "thread safety (GVL serialisation)" do
    # Phase 1 does not release the GVL during mm_scan, so concurrent redact/scan
    # calls are serialised by MRI. These specs verify that N threads running
    # distinct inputs in parallel each produce the same result as single-threaded
    # execution. If the engine had unguarded shared mutable state a race would
    # produce wrong output or a crash.
    N_THREADS = 8
    N_ITERS   = 50

    it "redact is safe under concurrent threads" do
      payloads = [
        ["token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end",
         "token [REDACTED] end"],
        ["key=AKIAIOSFODNN7EXAMPLE rest",
         "key=[REDACTED] rest"],
        ["iban: DE89370400440532013000 here",
         "iban: [REDACTED] here"],
        ["email test@example.com done",
         "email [REDACTED] done"],
        ["ip 192.168.1.1 ok",
         "ip [REDACTED] ok"],
        ["card 4111111111111111 end",
         "card [REDACTED] end"],
        ["ssn 123-45-6789 here",
         "ssn [REDACTED] here"],
        ["plain text no secrets",
         "plain text no secrets"],
      ]

      errors = []
      threads = payloads.map do |(input, expected)|
        Thread.new do
          N_ITERS.times do
            got = DataRedactor.redact(input)
            errors << "#{input.inspect}: expected #{expected.inspect}, got #{got.inspect}" unless got == expected
          end
        end
      end
      threads.each(&:join)
      expect(errors).to be_empty
    end

    it "scan is safe under concurrent threads" do
      payloads = [
        ["token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end", "github_classic_pat"],
        ["key=AKIAIOSFODNN7EXAMPLE rest",                      "aws_access_key_id"],
        ["iban: DE89370400440532013000 here",                  "iban_de"],
        ["email test@example.com done",                        "email"],
        ["ip 192.168.1.1 ok",                                  "ipv4"],
      ]

      errors = []
      threads = payloads.map do |(input, expected_name)|
        Thread.new do
          N_ITERS.times do
            result = DataRedactor.scan(input)
            names  = result[:matches].map { |m| m[:name] }
            errors << "#{input.inspect}: expected [#{expected_name}], got #{names.inspect}" unless names == [expected_name]
          end
        end
      end
      threads.each(&:join)
      expect(errors).to be_empty
    end
  end
end
