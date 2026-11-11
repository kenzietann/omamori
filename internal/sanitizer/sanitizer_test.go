package sanitizer

import (
	"slices"
	"strings"
	"testing"
)

const (
	fakeAWSKey      = "AKIAIOSFODNN7EXAMPLE"
	fakeGitHubToken = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1"
	fakeMyNumber    = "123456789018"
	fakePhoneNumber = "090-1234-5678"
)

func TestSanitize(t *testing.T) {
	testCases := []struct {
		name         string
		inputText    string
		wantText     string
		wantFindings []Finding
	}{
		{"nothing to hide", "hello world", "hello world", nil},
		{"empty text", "", "", nil},
		{"AWS key", "key " + fakeAWSKey + " ok", "key [SECRET:aws-access-key:001] ok",
			[]Finding{{"[SECRET:aws-access-key:001]", 4, 24}}},
		{"My Number", "id " + fakeMyNumber + " ok", "id [MYNUMBER:001] ok",
			[]Finding{{"[MYNUMBER:001]", 3, 15}}},
		{"phone number", "call " + fakePhoneNumber + " now", "call [PHONE:001] now",
			[]Finding{{"[PHONE:001]", 5, 18}}},
		{"all three kinds", "key " + fakeAWSKey + ", id " + fakeMyNumber + ", tel " + fakePhoneNumber,
			"key [SECRET:aws-access-key:001], id [MYNUMBER:001], tel [PHONE:001]",
			[]Finding{{"[SECRET:aws-access-key:001]", 4, 24}, {"[MYNUMBER:001]", 29, 41}, {"[PHONE:001]", 47, 60}}},
		{"same value twice gets two numbers", fakePhoneNumber + " and " + fakePhoneNumber, "[PHONE:001] and [PHONE:002]",
			[]Finding{{"[PHONE:001]", 0, 13}, {"[PHONE:002]", 18, 31}}},
		{"secret kinds are numbered apart", fakeAWSKey + " " + fakeGitHubToken, "[SECRET:aws-access-key:001] [SECRET:github-token:001]",
			[]Finding{{"[SECRET:aws-access-key:001]", 0, 20}, {"[SECRET:github-token:001]", 21, 61}}},
		{"full-width phone in Japanese text", "電話は０９０-１２３４-５６７８です", "電話は[PHONE:001]です",
			[]Finding{{"[PHONE:001]", 9, 44}}},
		{"secret in a file name", "path/" + fakeAWSKey + ".txt", "path/[SECRET:aws-access-key:001].txt",
			[]Finding{{"[SECRET:aws-access-key:001]", 5, 25}}},
		{"phone number inside a key", "AKIA0312345678ABCDEF", "[SECRET:aws-access-key:001]",
			[]Finding{{"[SECRET:aws-access-key:001]", 0, 20}}},
		{"phone number sticking out of a key", "AKIAAAAAAAAAAAAA0312345678", "[SECRET:aws-access-key:001]",
			[]Finding{{"[SECRET:aws-access-key:001]", 0, 26}}},
		{"My Number wins over a phone number", "090 1234 5678 9018", "[MYNUMBER:001]",
			[]Finding{{"[MYNUMBER:001]", 0, 18}}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var sanitizer Sanitizer
			gotText, gotFindings := sanitizer.Sanitize(testCase.inputText)

			if gotText != testCase.wantText {
				t.Errorf("Sanitize(%q) text = %q, want %q", testCase.inputText, gotText, testCase.wantText)
			}
			if !slices.Equal(gotFindings, testCase.wantFindings) {
				t.Errorf("Sanitize(%q) findings = %v, want %v", testCase.inputText, gotFindings, testCase.wantFindings)
			}
		})
	}
}

func TestSanitizeCountsAcrossCalls(t *testing.T) {
	var sanitizer Sanitizer

	firstText, _ := sanitizer.Sanitize("call " + fakePhoneNumber)
	secondText, _ := sanitizer.Sanitize("call 03-1234-5678")

	if firstText != "call [PHONE:001]" {
		t.Errorf("first call = %q, want %q", firstText, "call [PHONE:001]")
	}
	if secondText != "call [PHONE:002]" {
		t.Errorf("second call = %q, want %q", secondText, "call [PHONE:002]")
	}
}

func TestPlantedValuesNeverSurvive(t *testing.T) {
	plantedValues := []string{
		fakeAWSKey,
		"ASIAIOSFODNN7EXAMPLE",
		fakeGitHubToken,
		fakeMyNumber,
		"1234 5678 9018",
		fakePhoneNumber,
		"03-1234-5678",
		"+81 90 1234 5678",
		"0120-123-456",
		"（03）1234-5678",
	}
	inputText := "config/" + fakeAWSKey + ".yml\n" + strings.Join(plantedValues, "\n") + "\nend"

	var sanitizer Sanitizer
	gotText, _ := sanitizer.Sanitize(inputText)

	for _, plantedValue := range plantedValues {
		if strings.Contains(gotText, plantedValue) {
			t.Errorf("the planted value %q is still in the output", plantedValue)
		}
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add("key " + fakeAWSKey + ", id " + fakeMyNumber + ", tel " + fakePhoneNumber)
	f.Add("AKIA0312345678ABCDEF")
	f.Add("090 1234 5678 9018")
	f.Add("電話は０９０-１２３４-５６７８です")
	f.Add("")

	f.Fuzz(func(t *testing.T, inputText string) {
		var sanitizer Sanitizer
		gotText, gotFindings := sanitizer.Sanitize(inputText)

		var rebuilt strings.Builder
		cursor := 0
		for _, finding := range gotFindings {
			if finding.Start < cursor || finding.End <= finding.Start || finding.End > len(inputText) {
				t.Fatalf("bad finding %v for a text of %d bytes", finding, len(inputText))
			}
			rebuilt.WriteString(inputText[cursor:finding.Start])
			rebuilt.WriteString(finding.Placeholder)
			cursor = finding.End
		}
		rebuilt.WriteString(inputText[cursor:])

		if rebuilt.String() != gotText {
			t.Fatalf("the findings do not rebuild the output")
		}
	})
}

func TestAPrivateKeyBlockBecomesOnePlaceholderAndNoLineOfItRemains(t *testing.T) {
	block := "-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKEFAKEFAKE\nFAKEFAKEFAKE/+=\n-----END RSA PRIVATE KEY-----"
	var sanitizer Sanitizer

	got, findings := sanitizer.Sanitize("line one\n" + block + "\nline last\n")

	if got != "line one\n[SECRET:private-key:001]\nline last\n" || len(findings) != 1 {
		t.Errorf("got %q with %d findings", got, len(findings))
	}
}

func TestDigitsInsideADecimalOrANameAreHiddenButLabelledNumberLike(t *testing.T) {
	testCases := []struct {
		name string
		text string
		want string
	}{
		{"a decimal fraction", "x = -0.0643290124;", "x = -0.[NUMBERLIKE:001];"},
		{"a long decimal fraction like a My Number", "y = 0.000428679482,", "y = 0.[NUMBERLIKE:001],"},
		{"an id with letters", "id=abc0312345678", "id=abc[NUMBERLIKE:001]"},
		{"a real number stays a phone number", "Tel: 03-1234-5678.", "Tel: [PHONE:001]."},
		{"a real number after a Japanese word", "電話03-1234-5678です", "電話[PHONE:001]です"},
		{"a bracket number after a word", "TEL（06）6789-0123 FAX", "TEL[PHONE:001] FAX"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var sanitizer Sanitizer

			got, _ := sanitizer.Sanitize(testCase.text)

			if got != testCase.want {
				t.Errorf("Sanitize(%q) = %q, want %q", testCase.text, got, testCase.want)
			}
		})
	}
}
