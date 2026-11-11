package secrets

import (
	"cmp"
	"regexp"
	"slices"
)

type Match struct {
	Start int
	End   int
	Kind  string
}

type rule struct {
	kind    string
	pattern *regexp.Regexp
}

var rules = []rule{
	{kind: "aws-access-key", pattern: regexp.MustCompile(`(AKIA|ASIA)[A-Z0-9]{16}`)},
	{kind: "github-token", pattern: regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}`)},
	// The key of an AI provider (OpenAI and Anthropic). 32 characters or more keeps words like "sk-learn" out.
	{kind: "ai-api-key", pattern: regexp.MustCompile(`\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}`)},
	{kind: "google-api-key", pattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{kind: "slack-token", pattern: regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`)},
	{kind: "stripe-key", pattern: regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,}`)},
	{kind: "jwt", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	// The whole block is one match, because the lines of the body are secret too. A block with no end line
	// runs to the end of the text, which hides more than needed and never less.
	{kind: "private-key", pattern: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=:,. \r\n-]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)`)},
	// A password inside an address, like scheme://user:password@host.
	{kind: "url-credentials", pattern: regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`)},
}

func FindSecrets(text string) []Match {
	var matches []Match

	for _, rule := range rules {
		for _, position := range rule.pattern.FindAllStringIndex(text, -1) {
			matches = append(matches, Match{Start: position[0], End: position[1], Kind: rule.kind})
		}
	}

	slices.SortFunc(matches, func(first, second Match) int {
		return cmp.Compare(first.Start, second.Start)
	})

	return matches
}
