package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/sanitizer"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var modePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)
var levels = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}

func randomID(prefix string) (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", ErrDatabase
	}
	return prefix + hex.EncodeToString(data[:]), nil
}
func hash(text string) string { sum := sha256.Sum256([]byte(text)); return hex.EncodeToString(sum[:]) }
func validTime(value time.Time) bool {
	year := value.UTC().Year()
	return !value.IsZero() && year >= 1678 && year <= 2261 && time.Unix(0, value.UnixNano()).Equal(value)
}
func stamp(value time.Time) time.Time { return value.UTC().Round(0) }
func cleanText(text string) string {
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(text, "?"))
	cleaned, _ := (&sanitizer.Sanitizer{}).Sanitize(text)
	return cleaned
}
func cleanField(name, value string) string {
	if name == "src_ip" || name == "dst_ip" {
		if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
			return value
		}
	}
	return cleanText(value)
}
func cleanFields(original map[string]string) (map[string]string, error) {
	if len(original) > 500 {
		return nil, ErrInvalid
	}
	cleaned := make(map[string]string, len(original))
	keys := make([]string, 0, len(original))
	for name := range original {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		key := cleanText(name)
		value := cleanField(name, original[name])
		if key == "" || utf8.RuneCountInString(key) > 200 || len(value) > 65536 {
			return nil, ErrInvalid
		}
		if _, exists := cleaned[key]; exists {
			return nil, ErrInvalid
		}
		cleaned[key] = value
	}
	return cleaned, nil
}

func cleanJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 8<<20 {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrInvalid
	}
	var walk func(any, string, int) (any, error)
	walk = func(value any, key string, depth int) (any, error) {
		if depth > 32 {
			return nil, ErrInvalid
		}
		switch typed := value.(type) {
		case string:
			return cleanField(key, typed), nil
		case []any:
			for i, item := range typed {
				cleaned, err := walk(item, "", depth+1)
				if err != nil {
					return nil, err
				}
				typed[i] = cleaned
			}
		case map[string]any:
			cleaned := map[string]any{}
			names := make([]string, 0, len(typed))
			for name := range typed {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				newName := cleanText(name)
				if _, exists := cleaned[newName]; exists {
					return nil, ErrInvalid
				}
				item, err := walk(typed[name], name, depth+1)
				if err != nil {
					return nil, err
				}
				cleaned[newName] = item
			}
			return cleaned, nil
		}
		return value, nil
	}
	value, err := walk(value, "", 0)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	return data, nil
}

func normalizeRun(input RunInput) (RunInput, string, error) {
	if input.ID != "" && !identifier.MatchString(input.ID) || !validTime(input.Made) || !modePattern.MatchString(input.Mode) || len(input.Events) > 1_000_000 || len(input.Alerts) > 500_000 {
		return RunInput{}, "", ErrInvalid
	}
	result := RunInput{Made: stamp(input.Made), Mode: input.Mode, Label: cleanText(input.Label), Events: []Event{}, Alerts: []Alert{}}
	if utf8.RuneCountInString(result.Label) > 512 {
		return RunInput{}, "", ErrInvalid
	}
	var err error
	result.Analysis, err = cleanJSON(input.Analysis)
	if err != nil {
		return RunInput{}, "", err
	}
	result.Coverage, err = cleanJSON(input.Coverage)
	if err != nil {
		return RunInput{}, "", err
	}
	events := map[string]bool{}
	for _, original := range input.Events {
		if !identifier.MatchString(original.ID) || events[original.ID] || !validTime(original.Time) {
			return RunInput{}, "", ErrInvalid
		}
		events[original.ID] = true
		current := Event{ID: original.ID, Time: stamp(original.Time), Source: cleanText(original.Source), Ref: cleanText(original.Ref)}
		if utf8.RuneCountInString(current.Source) > 100 || len(current.Ref) > 16384 {
			return RunInput{}, "", ErrInvalid
		}
		current.Fields, err = cleanFields(original.Fields)
		if err != nil {
			return RunInput{}, "", err
		}
		result.Events = append(result.Events, current)
	}
	alerts := map[string]bool{}
	for _, original := range input.Alerts {
		if !identifier.MatchString(original.ID) || alerts[original.ID] || !levels[original.Level] || original.Count < 1 || !validTime(original.Time) || !validTime(original.First) || !validTime(original.Last) || original.Last.Before(original.First) {
			return RunInput{}, "", ErrInvalid
		}
		alerts[original.ID] = true
		current := Alert{ID: original.ID, Rule: cleanText(original.Rule), Title: cleanText(original.Title), Level: original.Level, Time: stamp(original.Time), First: stamp(original.First), Last: stamp(original.Last), Count: original.Count, EventIDs: append([]string{}, original.EventIDs...)}
		if utf8.RuneCountInString(current.Rule) > 200 || utf8.RuneCountInString(current.Title) > 4096 || len(current.EventIDs) > 100_000 {
			return RunInput{}, "", ErrInvalid
		}
		seen := map[string]bool{}
		for _, id := range current.EventIDs {
			if !events[id] || seen[id] {
				return RunInput{}, "", ErrInvalid
			}
			seen[id] = true
		}
		current.Group, err = cleanFields(original.Group)
		if err != nil {
			return RunInput{}, "", err
		}
		current.Payload, err = cleanJSON(original.Payload)
		if err != nil {
			return RunInput{}, "", err
		}
		result.Alerts = append(result.Alerts, current)
	}
	// The digest covers the normalized record, excluding its identity. It survives retries
	// while a caller-supplied identity can never overwrite different content.
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 256<<20 {
		return RunInput{}, "", ErrInvalid
	}
	digest := hash(string(encoded))
	result.ID = input.ID
	if result.ID == "" {
		result.ID = "r_" + digest
	}
	return result, digest, nil
}

func normalizeQuery(query Query) (Query, error) {
	if query.Limit == 0 {
		query.Limit = 100
	}
	if query.Limit < 1 || query.Limit > 1000 || query.Offset < 0 || query.Offset > 1_000_000 || len(query.Text) > 2000 || len(query.Value) > 65536 || utf8.RuneCountInString(query.Field) > 200 {
		return query, ErrInvalid
	}
	if query.RunID != "" && !identifier.MatchString(query.RunID) || query.CaseID != "" && !identifier.MatchString(query.CaseID) || query.Level != "" && !levels[query.Level] {
		return query, ErrInvalid
	}
	if !query.From.IsZero() && !validTime(query.From) || !query.To.IsZero() && !validTime(query.To) || !query.From.IsZero() && !query.To.IsZero() && query.To.Before(query.From) {
		return query, ErrInvalid
	}
	if query.Field == "" && query.Value != "" {
		return query, ErrInvalid
	}
	query.Field = cleanText(query.Field)
	query.Value = cleanField(query.Field, query.Value)
	query.Text = strings.ToLower(cleanText(query.Text))
	query.Source = cleanText(query.Source)
	query.Rule = cleanText(query.Rule)
	if utf8.RuneCountInString(query.Source) > 100 || utf8.RuneCountInString(query.Rule) > 200 {
		return query, ErrInvalid
	}
	return query, nil
}

func like(text string) string {
	return "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(text) + "%"
}

func normalizeCase(input CaseInput) (CaseInput, error) {
	if input.Status == "" {
		input.Status = "open"
	}
	if input.Status != "open" && input.Status != "investigating" && input.Status != "closed" {
		return input, ErrInvalid
	}
	input.Title = strings.TrimSpace(cleanText(input.Title))
	input.Notes = cleanText(input.Notes)
	if input.Title == "" || utf8.RuneCountInString(input.Title) > 500 || len(input.Notes) > 1<<20 {
		return input, ErrInvalid
	}
	return input, nil
}

func fieldText(fields map[string]string) string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var parts []string
	for _, name := range names {
		parts = append(parts, name, fields[name])
	}
	return strings.Join(parts, "\n")
}
