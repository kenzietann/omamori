package intake

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
)

// A source can carry the original event time as well as a collector's timestamp.
// Ordered candidates prefer the event's time; UTC marks zone-less Sysmon times.
type jsonTimestamp struct {
	Value any
	UTC   bool
}

type jsonMapping struct {
	Source string
	Times  []jsonTimestamp
}

// jsonValue uses explicit path components; a single component may contain dots,
// as Zeek's literal "id.orig_h" key does.
func jsonValue(object map[string]any, keys ...string) any {
	var value any = object
	for _, key := range keys {
		parent, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = parent[key]
	}
	return value
}

func jsonText(object map[string]any, keys ...string) string {
	text, _ := scalar(jsonValue(object, keys...))
	return text
}

func putJSONField(fields map[string]string, name string, value any) {
	text, ok := scalar(value)
	if !ok || strings.TrimSpace(text) == "" || text == "-" {
		return
	}
	fields[name] = limit(strings.Map(dropControl, text), maxValueRunes)
}

func putJSONIP(fields map[string]string, name string, value any) {
	text, ok := value.(string)
	if !ok {
		return
	}
	address, err := netip.ParseAddr(text)
	if err == nil && address.Zone() == "" {
		fields[name] = address.Unmap().String()
	}
}

func putJSONPort(fields map[string]string, name string, value any) {
	putJSONInteger(fields, name, value, 0, 65535)
}

func putJSONInteger(fields map[string]string, name string, value any, minimum, maximum int64) {
	var text string
	switch typed := value.(type) {
	case string:
		text = typed
	case json.Number:
		text = typed.String()
	default:
		return
	}
	number, err := strconv.ParseInt(text, 10, 64)
	if err == nil && number >= minimum && number <= maximum {
		fields[name] = strconv.FormatInt(number, 10)
	}
}
