package secrets

import (
	"slices"
	"testing"
)

func TestFindSecrets(t *testing.T) {
	testCases := []struct {
		name        string
		inputText   string
		wantMatches []Match
	}{
		// AKIAIOSFODNN7EXAMPLE is the example key in the AWS documentation. It is fake.
		{"AWS example key alone", "AKIAIOSFODNN7EXAMPLE", []Match{{0, 20, "aws-access-key"}}},
		{"key in a sentence", "key AKIAIOSFODNN7EXAMPLE ok", []Match{{4, 24, "aws-access-key"}}},
		{"temporary key", "ASIAIOSFODNN7EXAMPLE", []Match{{0, 20, "aws-access-key"}}},
		{"two keys", "AKIAIOSFODNN7EXAMPLE and ASIAIOSFODNN7EXAMPLE", []Match{{0, 20, "aws-access-key"}, {25, 45, "aws-access-key"}}},
		{"15 characters after the prefix", "AKIAIOSFODNN7EXAMPL", nil},
		{"lowercase", "akiaiosfodnn7example", nil},
		{"user ID prefix, not a key", "AIDAIOSFODNN7EXAMPLE", nil},
		{"empty text", "", nil},
		// Open question: with 17 characters after the prefix we match the first 20.
		// A false positive costs less than a missed key.
		{"17 characters after the prefix", "AKIAIOSFODNN7EXAMPLEX", []Match{{0, 20, "aws-access-key"}}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotMatches := FindSecrets(testCase.inputText)

			if !slices.Equal(gotMatches, testCase.wantMatches) {
				t.Errorf("FindSecrets(%q) = %v, want %v", testCase.inputText, gotMatches, testCase.wantMatches)
			}
		})
	}
}

func FuzzFindSecrets(f *testing.F) {
	f.Add("key AKIAIOSFODNN7EXAMPLE ok")
	f.Add("ASIAIOSFODNN7EXAMPLE")
	f.Add("")

	f.Fuzz(func(t *testing.T, inputText string) {
		FindSecrets(inputText)
	})
}
