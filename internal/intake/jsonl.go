package intake

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

const (
	maxJSONDepth  = 6
	maxJSONFields = 300
)

var timeKeys = []string{"timestamp", "@timestamp", "time", "ts", "UtcTime", "EventTime", "eventTime", "datetime", "@t", "Timestamp", "asctime"}

var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z0700", "2006-01-02 15:04:05.999999999Z07:00"}

// jsonParser reads JSON lines: one object for each line. Nested objects become names with dots
// ("alert.signature"). An event must have a time under one of the usual keys.
func jsonParser(options Options) lineParser {
	parse := jsonSourceParser(options)
	return func(line string) (map[string]string, time.Time, bool) {
		fields, moment, _, ok := parse(line)
		return fields, moment, ok
	}
}

func jsonSourceParser(options Options) func(string) (map[string]string, time.Time, string, bool) {
	var inner *innerParser
	object := jsonObjectParser(options)
	return func(line string) (map[string]string, time.Time, string, bool) {
		// The json-file logs of Docker and the JSON export of the journal wrap the real line. The line inside is
		// read with every reader of Omamori, and the time of the wrapper is used when the line has none.
		if inner == nil {
			inner = newInnerParser(options, object)
		}
		if fields, moment, source, ok, wrapped := inner.unwrap(line); wrapped {
			return fields, moment, source, ok
		}

		return object(line, time.Time{})
	}
}

// jsonObjectParser reads one JSON object. fallback is the time to use when the object has none (a JSON line
// inside a Docker log); a zero fallback means that an object without a time is refused.
func jsonObjectParser(options Options) func(string, time.Time) (map[string]string, time.Time, string, bool) {
	return func(line string, fallback time.Time) (map[string]string, time.Time, string, bool) {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "{") {
			return nil, time.Time{}, "", false
		}

		decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
		decoder.UseNumber()
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			return nil, time.Time{}, "", false
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, time.Time{}, "", false
		}

		fields := map[string]string{}
		mapping, recognized := normalizeHostJSON(object, fields)
		if !recognized {
			mapping, recognized = normalizeNetworkJSON(object, fields)
		}
		if options.Format != FormatAuto && options.Format != FormatJSON && (!recognized || mapping.Source != options.Format) {
			return nil, time.Time{}, "", false
		}
		var moment time.Time
		found := false
		if recognized {
			for _, candidate := range mapping.Times {
				if candidate.Value == nil || candidate.Value == "" {
					continue
				}
				location := options.Location
				if candidate.UTC {
					location = time.UTC
				}
				moment, found = jsonTime(candidate.Value, location)
				// An explicitly supplied event time that is malformed must not silently become a collector time.
				if !found {
					return nil, time.Time{}, "", false
				}
				break
			}
		}
		if !found {
			for _, key := range timeKeys {
				if moment, found = jsonTime(object[key], options.Location); found {
					break
				}
			}
		}
		if !found && !fallback.IsZero() {
			moment, found = fallback, true
		}
		if !found {
			return nil, time.Time{}, "", false
		}

		if recognized {
			fields[event.Collector] = mapping.Source
			// Original fields remain available for source-specific rules. Namespacing prevents a raw
			// action/outcome/product field from replacing the normalized interpretation.
			raw := map[string]string{}
			if !flattenOriginal(object, raw) {
				return nil, time.Time{}, "", false
			}
			names := make([]string, 0, len(raw))
			for name := range raw {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if len(fields) >= maxJSONFields {
					break
				}
				fields[name] = raw[name]
			}
			return fields, moment, mapping.Source, true
		}
		fields = map[string]string{}
		flatten("", object, fields, 0)
		appFields(fields)

		return fields, moment, FormatJSON, true
	}
}

// flattenOriginal refuses ambiguous evidence paths: a literal "id.orig_h" key and
// an id.orig_h nested object must not produce one raw field with contradictory values.
// Names are checked even after the retained-field limit, so omission does not choose a winner.
func flattenOriginal(object map[string]any, fields map[string]string) bool {
	seen := map[string]bool{}
	var walk func(string, map[string]any, int) bool
	walk = func(prefix string, object map[string]any, depth int) bool {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			name := prefix + "." + key
			value := object[key]
			if nested, ok := value.(map[string]any); ok {
				if depth < maxJSONDepth && !walk(name, nested, depth+1) {
					return false
				}
				continue
			}
			var text string
			if list, ok := value.([]any); ok {
				var items []string
				for _, item := range list {
					if part, ok := scalar(item); ok {
						items = append(items, part)
					}
				}
				if len(items) == 0 {
					continue
				}
				text = strings.Join(items, ",")
			} else {
				var ok bool
				if text, ok = scalar(value); !ok {
					continue
				}
			}
			name = limit(name, 200)
			if !clean(name) {
				continue
			}
			if seen[name] {
				return false
			}
			seen[name] = true
			if len(fields) < maxJSONFields {
				fields[name] = limit(strings.Map(dropControl, text), maxValueRunes)
			}
		}
		return true
	}
	return walk("raw", object, 0)
}

func jsonTime(raw any, location *time.Location) (time.Time, bool) {
	switch typed := raw.(type) {
	case string:
		for _, layout := range timeLayouts {
			if moment, err := time.Parse(layout, typed); err == nil {
				return moment, true
			}
		}
		for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05,000"} {
			if moment, err := time.ParseInLocation(layout, typed, location); err == nil {
				return moment, true
			}
		}
	case json.Number:
		// Seconds since 1970, with or without a fraction, as Zeek writes them. Milliseconds are also read.
		seconds, err := typed.Float64()
		if err != nil || math.IsNaN(seconds) || seconds < 0 {
			return time.Time{}, false
		}
		if seconds > 1e11 {
			seconds /= 1000
		}
		if seconds > 1e11 {
			return time.Time{}, false
		}
		whole, fraction := math.Modf(seconds)

		return time.Unix(int64(whole), int64(fraction*1e9)).UTC(), true
	}

	return time.Time{}, false
}

func flatten(prefix string, object map[string]any, fields map[string]string, depth int) {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := object[key]
		if len(fields) >= maxJSONFields {
			return
		}
		name := key
		if prefix != "" {
			name = prefix + "." + key
		}

		var text string
		switch typed := value.(type) {
		case map[string]any:
			if depth < maxJSONDepth {
				flatten(name, typed, fields, depth+1)
			}
			continue
		case []any:
			var items []string
			for _, item := range typed {
				if scalar, isScalar := scalar(item); isScalar {
					items = append(items, scalar)
				}
			}
			text = strings.Join(items, ",")
		default:
			var isScalar bool
			if text, isScalar = scalar(value); !isScalar {
				continue
			}
		}

		name = event.Canonical(limit(name, 200))
		if _, taken := fields[name]; taken || !clean(name) {
			continue
		}
		fields[name] = limit(strings.Map(dropControl, text), maxValueRunes)
	}
}

func scalar(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	case bool:
		return strconv.FormatBool(typed), true
	}

	return "", false
}

func dropControl(character rune) rune {
	if (character < 0x20 && character != '\t') || character == 0x7f {
		return ' '
	}

	return character
}
