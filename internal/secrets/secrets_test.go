package secrets

import (
	"slices"
	"testing"
)

const fakeGitHubToken = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1"

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
		// The GitHub examples use a clearly fake token: 4 prefix characters and 36 more.
		{"GitHub token alone", fakeGitHubToken, []Match{{0, 40, "github-token"}}},
		{"GitHub token in a sentence", "token " + fakeGitHubToken + " ok", []Match{{6, 46, "github-token"}}},
		{"GitHub token with lowercase letters", "ghp_exampleEXAMPLEexampleEXAMPLEexample1", []Match{{0, 40, "github-token"}}},
		{"GitHub OAuth token prefix", "gho_" + fakeGitHubToken[4:], []Match{{0, 40, "github-token"}}},
		{"35 characters after the GitHub prefix", fakeGitHubToken[:39], nil},
		{"uppercase GitHub prefix", "GHP_" + fakeGitHubToken[4:], nil},
		{"unknown GitHub prefix", "ghx_" + fakeGitHubToken[4:], nil},
		// The GitHub rule is the second row of the table, so its match must still come first.
		{"GitHub token before AWS key", fakeGitHubToken + " AKIAIOSFODNN7EXAMPLE", []Match{{0, 40, "github-token"}, {41, 61, "aws-access-key"}}},
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
