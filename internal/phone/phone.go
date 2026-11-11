package phone

import (
	"regexp"
	"strings"
)

type Match struct {
	Start int
	End   int
}

// Each shape is the digit groups of a number without the leading 0, so the same
// shapes also build the +81 form.
var numberShapes = [][]string{
	{`[5-9]0`, `\d{4}`, `\d{4}`},
	{`800`, `\d{3}`, `\d{4}`},
	{`120`, `\d{3}`, `\d{3}`},
	{`[1-9]`, `\d{4}`, `\d{4}`},
	{`[1-9]\d`, `\d{3}`, `\d{4}`},
	{`[1-9]\d{2}`, `\d{2}`, `\d{4}`},
	{`[1-9]\d{3}`, `\d`, `\d{4}`},
}

var phonePattern = buildPattern()

func buildPattern() *regexp.Regexp {
	var alternatives []string

	for _, separator := range []string{"", "-", " "} {
		for _, groups := range numberShapes {
			nationalNumber := strings.Join(groups, regexp.QuoteMeta(separator))
			alternatives = append(alternatives, "0"+nationalNumber, `\+81[- ]?`+nationalNumber)
		}
	}

	pattern := regexp.MustCompile("(?:" + strings.Join(alternatives, "|") + ")")
	pattern.Longest()

	return pattern
}

func isASCIIDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

func FindPhoneNumbers(text string) []Match {
	var matches []Match

	for _, position := range phonePattern.FindAllStringIndex(text, -1) {
		start, end := position[0], position[1]

		if start > 0 && isASCIIDigit(text[start-1]) {
			continue
		}
		if end < len(text) && isASCIIDigit(text[end]) {
			continue
		}

		matches = append(matches, Match{Start: start, End: end})
	}

	return matches
}
