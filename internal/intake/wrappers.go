package intake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

// innerParser reads the line inside a wrapper (the json-file log of Docker, the JSON export of the journal of
// systemd, or a line of docker logs --timestamps) with every reader of Omamori: JSON, the access log of a web
// server, the formats of the frameworks, and syslog. One parser is made for each file, so that syslog can
// count years and Rails can join the start and the end of a request.
type innerParser struct {
	options Options
	object  func(string, time.Time) (map[string]string, time.Time, string, bool)
	syslog  lineParser
	rails   map[string]map[string]string
}

func newInnerParser(options Options, object func(string, time.Time) (map[string]string, time.Time, string, bool)) *innerParser {
	return &innerParser{options: options, object: object, syslog: newSyslogParser(options), rails: map[string]map[string]string{}}
}

const maxRailsOpen = 10_000

// unwrap reads a JSON line of a wrapper. wrapped is false for every other line, which is then read as it is.
func (parser *innerParser) unwrap(line string) (map[string]string, time.Time, string, bool, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") || !(strings.Contains(trimmed, `"log"`) || strings.Contains(trimmed, `"__REALTIME_TIMESTAMP"`)) {
		return nil, time.Time{}, "", false, false
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	decoder.UseNumber()
	var object map[string]any
	if decoder.Decode(&object) != nil {
		return nil, time.Time{}, "", false, false
	}

	// Docker json-file: {"log":"the line\n","stream":"stdout","time":"2026-11-13T10:00:00.123456789Z"}
	if text, isText := object["log"].(string); isText && len(object) <= 4 {
		stamp, _ := object["time"].(string)
		moment, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return nil, time.Time{}, "", false, true
		}
		fields, inner, source, ok := parser.read(text, moment)
		if ok {
			fields[WrapperField] = "docker"
			if stream, isStream := object["stream"].(string); isStream {
				fields["stream"] = limit(stream, maxNameRunes)
			}
		}
		return fields, inner, source, ok, true
	}

	// journalctl -o json: the time in microseconds, the program, and the message (text, or bytes when it is not
	// UTF-8).
	if _, found := object["__REALTIME_TIMESTAMP"]; found {
		micros, err := strconv.ParseInt(fmt.Sprint(object["__REALTIME_TIMESTAMP"]), 10, 64)
		message, isMessage := journalMessage(object["MESSAGE"])
		if err != nil || micros <= 0 || !isMessage {
			return nil, time.Time{}, "", false, true
		}
		moment := time.UnixMicro(micros).UTC()
		fields, inner, source, ok := parser.journal(object, message, moment)
		if ok {
			fields[WrapperField] = "journald"
			if unit := jsonText(object, "_SYSTEMD_UNIT"); unit != "" {
				fields["unit"] = limit(unit, maxNameRunes)
			}
		}
		return fields, inner, source, ok, true
	}

	return nil, time.Time{}, "", false, false
}

func journalMessage(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case []any:
		data := make([]byte, 0, len(typed))
		for _, item := range typed {
			number, ok := item.(json.Number)
			if !ok {
				return "", false
			}
			byteValue, err := strconv.ParseUint(number.String(), 10, 8)
			if err != nil {
				return "", false
			}
			data = append(data, byte(byteValue))
		}
		return strings.ToValidUTF8(string(data), " "), true
	}

	return "", false
}

// journal reads one entry of the journal. The message of sshd, sudo, cron and the others is read as the syslog
// line that it would have been, with the program and the host of the entry. An application that writes JSON
// or a framework format to the journal is read with those readers.
func (parser *innerParser) journal(object map[string]any, message string, moment time.Time) (map[string]string, time.Time, string, bool) {
	if fields, inner, source, ok := parser.structured(message, moment); ok {
		return fields, inner, source, ok
	}
	program := jsonText(object, "SYSLOG_IDENTIFIER")
	if program == "" {
		program = jsonText(object, "_COMM")
	}
	host := jsonText(object, "_HOSTNAME")
	if host == "" {
		host = "-"
	}
	if program != "" && !strings.ContainsAny(program+host, " \t\n") {
		pid := jsonText(object, "SYSLOG_PID")
		if pid == "" {
			pid = jsonText(object, "_PID")
		}
		if _, err := strconv.Atoi(pid); err == nil {
			program += "[" + pid + "]"
		}
		line := moment.Format(time.RFC3339Nano) + " " + host + " " + program + ": " + strings.Map(dropControl, message)
		if fields, inner, ok := parser.syslog(line); ok {
			return fields, inner, FormatSyslog, true
		}
	}

	return parser.text(message, moment)
}

// read reads a line that came out of Docker or out of docker logs --timestamps.
func (parser *innerParser) read(text string, moment time.Time) (map[string]string, time.Time, string, bool) {
	text = strings.TrimRight(stripANSI(text), "\r\n")
	if fields, inner, source, ok := parser.structured(text, moment); ok {
		return fields, inner, source, ok
	}
	if fields, inner, ok := parser.syslog(text); ok {
		return fields, inner, FormatSyslog, true
	}

	return parser.text(text, moment)
}

// structured tries the readers of formats that Omamori knows: JSON, a web access log, and the frameworks.
func (parser *innerParser) structured(text string, moment time.Time) (map[string]string, time.Time, string, bool) {
	text = strings.TrimRight(stripANSI(text), "\r\n")
	if strings.HasPrefix(strings.TrimSpace(text), "{") {
		if fields, inner, source, ok := parser.object(text, moment); ok {
			return fields, inner, source, true
		}
	}
	if fields, inner, ok := parseWebLine(text); ok {
		return fields, inner, FormatWeb, true
	}
	if fields, inner, ok := parseAppLine(text, parser.options); ok {
		if inner.IsZero() {
			inner = moment
		}
		parser.joinRails(fields)
		return fields, inner, FormatApp, true
	}

	return nil, time.Time{}, "", false
}

// text keeps a line that no reader knows as a message, so that the rules over messages still see it (a stack
// trace that names an SQL error, a "login failed" of an application).
func (parser *innerParser) text(text string, moment time.Time) (map[string]string, time.Time, string, bool) {
	text = strings.TrimSpace(strings.Map(dropControl, stripANSI(text)))
	if text == "" || moment.IsZero() {
		return nil, time.Time{}, "", false
	}
	fields := map[string]string{event.Product: "app"}
	messageFields(fields, text)

	return fields, moment, FormatApp, true
}

// joinRails gives the end of a Rails request (its status) the method, the path and the client of its start,
// found by the request id. The end becomes the request event; the start stays as a line of its own.
func (parser *innerParser) joinRails(fields map[string]string) {
	id := fields["request_id"]
	if fields[FrameworkField] != "rails" || id == "" {
		return
	}
	switch fields[event.Action] {
	case "http_request_started":
		if len(parser.rails) >= maxRailsOpen {
			clear(parser.rails)
		}
		parser.rails[id] = map[string]string{event.Method: fields[event.Method], event.URL: fields[event.URL], event.SourceIP: fields[event.SourceIP]}
	case "http_request_completed":
		started, found := parser.rails[id]
		if !found {
			return
		}
		delete(parser.rails, id)
		request(fields, started[event.Method], started[event.URL], fields[event.Status], started[event.SourceIP])
	}
}

// newAppParser reads a file of framework lines, or of lines of docker logs --timestamps. A line without a time
// of its own and outside of a wrapper cannot be placed in time, and is counted as not read.
func newAppParser(options Options) lineParser {
	inner := newInnerParser(options, jsonObjectParser(options))
	return func(line string) (map[string]string, time.Time, bool) {
		// A framework line goes first: the time of Rust tracing looks like the prefix of docker logs.
		if fields, moment, ok := parseAppLine(line, options); ok && !moment.IsZero() {
			inner.joinRails(fields)
			return fields, moment, true
		}
		if parts := dockerPrefix.FindStringSubmatch(line); parts != nil {
			moment, err := time.Parse(time.RFC3339Nano, parts[1])
			if err != nil {
				return nil, time.Time{}, false
			}
			fields, inner, _, ok := inner.read(parts[2], moment)
			if ok {
				fields[WrapperField] = "docker"
			}
			return fields, inner, ok
		}
		return nil, time.Time{}, false
	}
}

// wrappedBlank says whether a line is an empty line inside a wrapper: Docker writes the empty lines of a program
// (around a banner, between blocks) with a time, and they are blank, not unread.
func wrappedBlank(line string) bool {
	if parts := dockerPrefix.FindStringSubmatch(line); parts != nil {
		return strings.TrimSpace(stripANSI(parts[2])) == ""
	}
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, `{"log":"`) {
		return false
	}
	var object struct {
		Log *string `json:"log"`
	}
	if json.Unmarshal([]byte(trimmed), &object) != nil || object.Log == nil {
		return false
	}

	return strings.TrimSpace(stripANSI(*object.Log)) == ""
}
