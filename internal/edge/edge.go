package edge

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

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
