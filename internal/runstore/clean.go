package runstore

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	maxNameRunes      = 200
	maxTextRunes      = 2048
	maxReferenceRunes = 4096
)

type cleaner struct {
	sanitizer sanitizer.Sanitizer
	truncated int
	renamed   int
}

func (clean *cleaner) text(text string, limit int) string {
	text, _ = clean.sanitizer.Sanitize(strings.ToValidUTF8(text, "?"))
	text = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || character == '\u2028' || character == '\u2029' {
			return ' '
		}
		return character
	}, text)
	if utf8.RuneCountInString(text) > limit {
		clean.truncated++
		text = string([]rune(text)[:limit-1]) + "…"
	}
	return text
}

func (clean *cleaner) value(field, text string) string {
	if canonical := event.Canonical(field); canonical == event.SourceIP || canonical == event.DestIP {
		if address, err := netip.ParseAddr(text); err == nil && address.Zone() == "" {
			return address.Unmap().String()
		}
	}
	return clean.text(text, maxTextRunes)
}

func (clean *cleaner) texts(texts []string, limit int) []string {
	result := make([]string, 0, len(texts))
	for _, text := range texts {
		result = append(result, clean.text(text, limit))
	}
	return result
}

func (clean *cleaner) fields(fields map[string]string) map[string]string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make(map[string]string, len(fields))
	for _, name := range names {
		label := clean.text(name, maxNameRunes)
		if label == "" {
			label = "unnamed field"
		}
		candidate := label
		for collision := 2; ; collision++ {
			if _, exists := result[candidate]; !exists {
				break
			}
			suffix := fmt.Sprintf(" [field %d]", collision)
			prefix := []rune(label)
			if len(prefix)+len(suffix) > maxNameRunes {
				prefix = prefix[:maxNameRunes-len(suffix)]
			}
			candidate = string(prefix) + suffix
		}
		if candidate != label {
			clean.renamed++
		}
		result[candidate] = clean.value(name, fields[name])
	}
	return result
}
