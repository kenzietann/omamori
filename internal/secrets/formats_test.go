package secrets

import (
	"strings"
	"testing"
)

// Every value here is made up. They have the right shape and no real account behind them.
// Some are written in two pieces, so that secret scanners on the source code do not mistake them for real keys.
const (
	fakeAIKey      = "sk-" + "proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
	fakeAnthropic  = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
	fakeGoogleKey  = "AI" + "zaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE123"
	fakeSlackToken = "xo" + "xb-000000000000-FAKEFAKEFAKEFAKE"
	fakeStripeKey  = "sk_" + "live_FAKEFAKEFAKEFAKEFAKEFAKE"
	fakeJWT        = "eyJFAKEFAKEFAKE.eyJFAKEFAKEFAKE.FAKESIGNATURE12"
)

const fakePrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\nFAKEFAKEFAKEFAKE/+=\n-----END RSA PRIVATE KEY-----"

func TestNewFormatsAreFoundWholeAndWithTheRightKind(t *testing.T) {
	testCases := []struct {
		name     string
		text     string
		wantKind string
		want     string
	}{
		{"an AI provider key", "key=" + fakeAIKey + " ok", "ai-api-key", fakeAIKey},
		{"an Anthropic key", "key=" + fakeAnthropic, "ai-api-key", fakeAnthropic},
		{"an old style AI key", "sk-" + strings.Repeat("A", 48), "ai-api-key", "sk-" + strings.Repeat("A", 48)},
		{"a Google API key", "GOOGLE=" + fakeGoogleKey, "google-api-key", fakeGoogleKey},
		{"a Slack token", "token " + fakeSlackToken, "slack-token", fakeSlackToken},
		{"a Stripe live key", "STRIPE=" + fakeStripeKey, "stripe-key", fakeStripeKey},
		{"a Stripe restricted key", "r" + fakeStripeKey[1:], "stripe-key", "r" + fakeStripeKey[1:]},
		{"a JWT", "Authorization: Bearer " + fakeJWT, "jwt", fakeJWT},
		{"a private key block", "before\n" + fakePrivateKey + "\nafter", "private-key", fakePrivateKey},
		{"an OpenSSH private key block", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----", "private-key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"},
		{"a private key with windows line ends", "-----BEGIN PRIVATE KEY-----\r\nAAAA\r\n-----END PRIVATE KEY-----", "private-key", "-----BEGIN PRIVATE KEY-----\r\nAAAA\r\n-----END PRIVATE KEY-----"},
		{"a password in a database address", "DATABASE_URL=postgres://admin:FakePass123@db.example.com:5432/app", "url-credentials", "postgres://admin:FakePass123@"},
		{"a password in a web address", "see https://user:secret@example.com/x", "url-credentials", "https://user:secret@"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			matches := FindSecrets(testCase.text)

			if len(matches) != 1 || matches[0].Kind != testCase.wantKind || testCase.text[matches[0].Start:matches[0].End] != testCase.want {
				t.Errorf("FindSecrets(%q) = %v, want one %s match of %q", testCase.text, matches, testCase.wantKind, testCase.want)
			}
		})
	}
}

func TestAPrivateKeyWithoutAnEndLineHidesTheRestOfTheText(t *testing.T) {
	text := "-----BEGIN PRIVATE KEY-----\nAAAABBBB\nCCCC"

	matches := FindSecrets(text)

	if len(matches) != 1 || matches[0].Start != 0 || matches[0].End != len(text) {
		t.Errorf("FindSecrets(%q) = %v, want the whole text", text, matches)
	}
}

func TestTextThatLooksLikeASecretButIsNotIsLeftAlone(t *testing.T) {
	for _, text := range []string{
		"sk-learn",
		"scikit-learn and task-runner-configuration-with-a-very-long-name-here-123456",
		"ask-me-anything-about-this-long-identifier-1234567890",
		"sk-short",
		"sk_live_short",
		"risk_live_" + strings.Repeat("a", 30),
		"AIza-too-short",
		"xoxb-",
		"eyJhbGciOiJIUzI1NiJ9",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
		"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
		"https://example.com/path",
		"https://example.com:8080/path",
		"mailto:someone@example.com",
		"ssh://git@github.com/org/repo.git",
		"user:password@host",
		"time 12:30:45 at 10.0.0.1:80",
	} {
		if matches := FindSecrets(text); len(matches) != 0 {
			t.Errorf("FindSecrets(%q) = %v, want nothing", text, matches)
		}
	}
}

func TestSeveralFormatsInOneTextComeInOrder(t *testing.T) {
	text := fakeJWT + " " + fakeStripeKey + " AKIAIOSFODNN7EXAMPLE " + fakePrivateKey

	matches := FindSecrets(text)

	var kinds []string
	for _, match := range matches {
		kinds = append(kinds, match.Kind)
	}
	if got := strings.Join(kinds, ","); got != "jwt,stripe-key,aws-access-key,private-key" {
		t.Errorf("kinds = %s", got)
	}
}

func FuzzFormatsNeverPanicAndStayInsideTheText(f *testing.F) {
	for _, seed := range []string{fakeAIKey, fakeJWT, fakePrivateKey, "-----BEGIN PRIVATE KEY-----", "a://b:c@", "sk-", "xox", "eyJ.eyJ.", strings.Repeat("-----BEGIN PRIVATE KEY-----", 50)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		for _, match := range FindSecrets(text) {
			if match.Start < 0 || match.End > len(text) || match.Start >= match.End {
				t.Fatalf("a match is outside the text: %+v in %d bytes", match, len(text))
			}
		}
	})
}
