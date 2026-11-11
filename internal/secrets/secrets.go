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
