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
end
