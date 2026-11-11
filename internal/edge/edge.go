// Package edge decides if a run of digits that a detector found is only a part of something longer.
// The digits of a decimal fraction (0.0643290124), a hex id or a name with digits in it
// (abc0312345678, x_03123456789) are not a phone number or a My Number.
package edge

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Embedded says whether text[start:end] is a part of a decimal number, or touches a letter or an underscore.
// Only an edge that is a digit counts: a number that starts with a bracket or a plus sign can follow a word (TEL(06)...).
func Embedded(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}

	first, _ := utf8.DecodeRuneInString(text[start:])
	if digit(first) {
		before, beforeSize := utf8.DecodeLastRuneInString(text[:start])
		if beforeSize > 0 {
			if letterLike(before) {
				return true
			}
			if before == '.' {
				if beforeThat, size := utf8.DecodeLastRuneInString(text[:start-beforeSize]); size > 0 && digit(beforeThat) {
					return true
				}
			}
		}
	}

	last, _ := utf8.DecodeLastRuneInString(text[:end])
	if digit(last) {
		after, afterSize := utf8.DecodeRuneInString(text[end:])
		if afterSize > 0 {
			if letterLike(after) {
				return true
			}
			if after == '.' {
				if afterThat, size := utf8.DecodeRuneInString(text[end+afterSize:]); size > 0 && digit(afterThat) {
					return true
				}
			}
		}
	}

	return false
}

func letterLike(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character == '_'
}

func digit(character rune) bool {
	return character >= '0' && character <= '9' || character >= '０' && character <= '９'
}

var uuidPattern = regexp.MustCompile(`[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)

// InUUID says whether text[start:end] is a part of a UUID (00000000-0000-0000-0000-000000000000).
func InUUID(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}

	from, to := max(start-40, 0), min(end+40, len(text))
	for _, found := range uuidPattern.FindAllStringIndex(text[from:to], -1) {
		if from+found[0] < end && from+found[1] > start {
			return true
		}
	}

	return false
}

// InChain says whether text[start:end] is one group in a row of digit groups, like a hex dump or a table
// (0024 8000 0014 0000 0000 0000), or sits between two colons like the account number in an AWS ARN.
func InChain(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}

	if start >= 1 && end < len(text) && text[start-1] == ':' && text[end] == ':' {
		return true
	}
	if start >= 1 && isJoiner(text[start-1]) && digitRunBefore(text, start-1) >= 4 {
		return true
	}

	return end < len(text) && isJoiner(text[end]) && digitRunAfter(text, end+1) >= 4
}

func isJoiner(character byte) bool { return character == ' ' || character == '-' }

func digitRunBefore(text string, end int) int {
	count := 0
	for index := end - 1; index >= 0 && text[index] >= '0' && text[index] <= '9'; index-- {
		count++
	}

	return count
}

func digitRunAfter(text string, start int) int {
	count := 0
	for index := start; index < len(text) && text[index] >= '0' && text[index] <= '9'; index++ {
		count++
	}

	return count
}

// Trivial says whether the digits of a value are the same digit again and again, or count up or down by one
// (0123456789, 9876543210, 0000000000). Nobody has that number. It is a test value.
func Trivial(value string) bool {
	var digits []byte
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
			digits = append(digits, byte(character-'0'))
		case character >= '\uFF10' && character <= '\uFF19':
			digits = append(digits, byte(character-'\uFF10'))
		}
	}
	if len(digits) < 6 {
		return false
	}

	same, up, down := true, true, true
	for index := 1; index < len(digits); index++ {
		if digits[index] != digits[0] {
			same = false
		}
		if digits[index] != (digits[index-1]+1)%10 {
			up = false
		}
		if digits[index] != (digits[index-1]+9)%10 {
			down = false
		}
	}

	return same || up || down
}

var placeholderPasswords = map[string]bool{
	"pass": true, "password": true, "passwd": true, "pwd": true, "secret": true, "mypass": true, "mypassword": true, "mysecret": true,
	"test": true, "testpass": true, "xxx": true, "xxxx": true, "xxxxx": true, "xxxxxx": true, "redacted": true, "changeme": true,
	"example": true, "foo": true, "bar": true, "baz": true, "1234": true, "12345": true, "123456": true, "admin": true, "root": true,
	"guest": true, "demo": true, "user": true, "username": true, "sa": true, "pw": true, "hunter2": true, "letmein": true,
}

// PlaceholderCredentials says whether the user:password part of an address is an example from a document or a test,
// like user:pass or admin:${PASSWORD}.
func PlaceholderCredentials(value string) bool {
	_, rest, found := strings.Cut(value, "://")
	if !found {
		rest = value
	}
	rest = strings.TrimSuffix(rest, "@")
	_, password, found := strings.Cut(rest, ":")
	if !found {
		return false
	}

	lowered := strings.ToLower(password)
	if placeholderPasswords[lowered] || len(password) <= 2 {
		return true
	}
	if strings.ContainsAny(password, "${}<>%*") || strings.Contains(lowered, "redacted") || strings.Contains(lowered, "password") || strings.Contains(lowered, "xxxx") {
		return true
	}

	for _, character := range password {
		if character != rune(password[0]) {
			return false
		}
	}

	return true
}
