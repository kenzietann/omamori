package filerules

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Hit is a rule that matched a file.
type Hit struct {
	Rule *Rule
	// Strings are the names of the strings that were found, in the order of their names.
	Strings []string
	// Excerpt is the first text that was found, made safe to show: no control characters, and short.
	// It is a part of a file of someone else, so it is data and nothing else.
	Excerpt string
	// Offset is the place in the file where the excerpt starts.
	Offset int
}

type scan struct {
	data    []byte
	lowered []byte
	found   map[string]bool
	where   map[string][2]int
}

func (current *scan) lower() []byte {
	if current.lowered == nil {
		current.lowered = lowerASCII(current.data)
	}

	return current.lowered
}

// find says whether the string is in the data, and where (start and end). Each string is looked for once.
func (current *scan) find(item *pattern) bool {
	if found, done := current.found[item.name]; done {
		return found
	}
	start, end := item.locate(current)
	current.found[item.name] = start >= 0
	if start >= 0 {
		current.where[item.name] = [2]int{start, end}
	}

	return start >= 0
}

func (item *pattern) locate(current *scan) (int, int) {
	switch {
	case item.regex != nil:
		if place := item.regex.FindIndex(current.data); place != nil {
			return place[0], place[1]
		}
	case item.text != nil:
		data := current.data
		if item.noCase {
			data = current.lower()
		}
		if item.at >= 0 {
			if item.at <= len(data) && bytes.HasPrefix(data[item.at:], item.text) {
				return item.at, item.at + len(item.text)
			}

			return -1, -1
		}
		if index := bytes.Index(data, item.text); index >= 0 {
			return index, index + len(item.text)
		}
	default:
		if item.at >= 0 {
			if item.hexAt(current.data, item.at) {
				return item.at, item.at + len(item.hex)
			}

			return -1, -1
		}
		if index := item.hexIndex(current.data); index >= 0 {
			return index, index + len(item.hex)
		}
	}

	return -1, -1
}

func (item *pattern) hexAt(data []byte, at int) bool {
	if at < 0 || at+len(item.hex) > len(data) {
		return false
	}
	for index, value := range item.hex {
		if item.mask[index] && data[at+index] != value {
			return false
		}
	}

	return true
}

// hexIndex looks for the longest run of fixed bytes with bytes.Index, and checks the rest at each place where
// that run is found. The pattern is at most maxHexBytes long, so the check at each place is short.
func (item *pattern) hexIndex(data []byte) int {
	runStart, runLength := 0, 0
	for start := 0; start < len(item.hex); {
		if !item.mask[start] {
			start++
			continue
		}
		end := start
		for end < len(item.hex) && item.mask[end] {
			end++
		}
		if end-start > runLength {
			runStart, runLength = start, end-start
		}
		start = end
	}
	anchor := item.hex[runStart : runStart+runLength]
	for from := runStart; from <= len(data)-len(anchor); {
		index := bytes.Index(data[from:], anchor)
		if index < 0 {
			return -1
		}
		at := from + index - runStart
		if item.hexAt(data, at) {
			return at
		}
		from += index + 1
	}

	return -1
}

// Match says whether the rule matches a file. name is the path of the file from the top of the system,
// like tmp/x.sh. Without a hit, it gives nil.
func (rule *Rule) Match(name string, data []byte) *Hit {
	return rule.MatchSized(name, int64(len(data)), data)
}

// MatchSized is Match for a file of size bytes of which only data was read.
func (rule *Rule) MatchSized(name string, size int64, data []byte) *Hit {
	if !rule.fits(name) || rule.maxSize > 0 && size > rule.maxSize {
		return nil
	}
	if len(data) > MaxScanBytes {
		data = data[:MaxScanBytes]
	}
	current := &scan{data: data, found: map[string]bool{}, where: map[string][2]int{}}
	if !rule.condition.eval(func(name string) bool { return current.find(rule.byName[name]) }) {
		return nil
	}

	hit := &Hit{Rule: rule, Offset: -1}
	for _, item := range rule.strings {
		if current.find(item) {
			hit.Strings = append(hit.Strings, item.name)
		}
	}
	// The excerpt comes from the found string that is first in the file.
	for _, name := range hit.Strings {
		place := current.where[name]
		if hit.Offset < 0 || place[0] < hit.Offset {
			hit.Offset = place[0]
			hit.Excerpt = excerpt(data, place[0], place[1], rule.byName[name].hex != nil)
		}
	}

	return hit
}

func (rule *Rule) fits(name string) bool {
	if len(rule.Paths) == 0 {
		return true
	}
	for _, folder := range rule.Paths {
		if strings.HasPrefix(name, folder) {
			return true
		}
	}

	return false
}

func excerpt(data []byte, start, end int, binary bool) string {
	if binary {
		return fmt.Sprintf("bytes at offset %d", start)
	}
	if end-start > maxExcerptBytes {
		end = start + maxExcerptBytes
	}
	text := strings.ToValidUTF8(string(data[start:end]), " ")
	text = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f || character == utf8.RuneError {
			return ' '
		}

		return character
	}, text)

	return strings.TrimSpace(text)
}
