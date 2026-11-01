package secrets

import "regexp"

// Match says where a possible secret sits in a text. It holds positions and the
// type only, never the text itself, so a log or an error message can not leak it.
// Start is the first byte. End is the byte after the last one, like text[Start:End].
// Kind is the name used in the placeholder, like [SECRET:aws-access-key:001].
type Match struct {
	Start int
	End   int
	Kind  string
}

// An AWS access key ID is 4 prefix characters and 16 more. AKIA is a long-term key
// and ASIA is a temporary key. We accept A-Z and 0-9, not only Base32 (A-Z, 2-7),
// because a false positive costs less than a missed key.
var awsAccessKey = regexp.MustCompile(`(AKIA|ASIA)[A-Z0-9]{16}`)

func FindSecrets(text string) []Match {
	var matches []Match

	for _, position := range awsAccessKey.FindAllStringIndex(text, -1) {
		matches = append(matches, Match{Start: position[0], End: position[1], Kind: "aws-access-key"})
	}

	return matches
}
