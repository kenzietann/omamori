package phone

import (
	"regexp"
	"strings"
)

type Match struct {
	Start int
	End   int
}

var numberShapes = [][]string{
	{`[5-9]0`, `\d{4}`, `\d{4}`},
	{`800`, `\d{3}`, `\d{4}`},
	{`(?:120|570|180|990)`, `\d{3}`, `\d{3}`},
	{`[1-9]`, `\d{4}`, `\d{4}`},
	{`[1-9]\d`, `\d{3}`, `\d{4}`},
	{`[1-9]\d{2}`, `\d{2}`, `\d{4}`},
	{`[1-9]\d{3}`, `\d`, `\d{4}`},
}

var phonePattern = buildPattern()

func buildPattern() *regexp.Regexp {
	var alternatives []string

	for _, separator := range []string{"", "-", " ", "."} {
		joiner := regexp.QuoteMeta(separator)

		for _, groups := range numberShapes {
			nationalNumber := strings.Join(groups, joiner)
			areaInParentheses := `\(0` + groups[0] + `\)[-. ]?` + strings.Join(groups[1:], joiner)

			alternatives = append(alternatives,
				"0"+nationalNumber,
				areaInParentheses,
				`\+81[-. ]?`+nationalNumber,
				`\+81[-. ]?\(0\)[-. ]?`+nationalNumber,
			)
		}
	}

	pattern := regexp.MustCompile("(?:" + strings.Join(alternatives, "|") + ")")
	pattern.Longest()

	return pattern
}

func normalizeCharacter(character rune) byte {
	switch {
	case character >= '0' && character <= '9':
		return byte(character)
	case character >= '\uFF10' && character <= '\uFF19':
		return byte('0' + (character - '\uFF10'))
	}

	switch character {
	case '-', '\u2010', '\u2011', '\u2012', '\u2013', '\u2014', '\u2015', '\u2212', '\u30FC', '\uFF0D', '\uFF70':
		return '-'
	case ' ', '\u3000':
		return ' '
	case '(', '\uFF08':
		return '('
	case ')', '\uFF09':
		return ')'
	case '+', '\uFF0B':
		return '+'
	case '.', '\uFF0E':
		return '.'
	}

	return 'x'
}

func isASCIIDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

func FindPhoneNumbers(text string) []Match {
	normalized := make([]byte, 0, len(text))
	byteOffsets := make([]int, 0, len(text)+1)

	for byteIndex, character := range text {
		normalized = append(normalized, normalizeCharacter(character))
		byteOffsets = append(byteOffsets, byteIndex)
	}
	byteOffsets = append(byteOffsets, len(text))

	var matches []Match

	for _, position := range phonePattern.FindAllIndex(normalized, -1) {
		start, end := position[0], position[1]

		if start > 0 && isASCIIDigit(normalized[start-1]) {
			continue
		}
		if end < len(normalized) && isASCIIDigit(normalized[end]) {
			continue
		}

		matches = append(matches, Match{Start: byteOffsets[start], End: byteOffsets[end]})
	}

	return matches
}
