package intake

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

// FormatMacOS is the unified log of macOS as `log show` prints it: the styles default, syslog, compact and
// ndjson. The unified log itself (/var/db/diagnostics) is a binary format that only `log` reads, so it is
// read from the text that `log show` writes. /var/log/install.log has the same lines as the syslog style.
const FormatMacOS = "macos"

const (
	ProductMacOS = "macos"

	FieldSubsystem   = "subsystem"
	FieldLogCategory = "log_category"
	FieldLogLevel    = "log_level"
	FieldPID         = "pid"
)

var (
	// 2026-11-16 16:17:33.054282+0900  localhost sshd-session[989]: message (log show --style syslog), and
	// 2026-02-02 21:52:43-08 localhost Installer Progress[57]: message (install.log).
	macSyslogLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,9})?[+-]\d{2}(?:\d{2})?)\s+(\S+) (.+?)\[(\d+)\]: ?(.*)$`)
	// 2026-11-16 16:25:18.792665+0900 0x7998  Default  0x0  381  0  locationd: message (log show).
	macDefaultLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{1,9}[+-]\d{4})\s+0x[0-9a-f]+\s+([A-Za-z]+)\s+0x[0-9a-f]+\s+(\d+)\s+\d+\s+(.+?): ?(.*)$`)
	// 2026-11-16 16:25:18.014 Df mDNSResponder[475:13b0] message (log show --style compact). It has no zone.
	macCompactLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{1,9}) ([A-Za-z]{1,2}) (.+?)\[(\d+):[0-9a-f]+\] ?(.*)$`)
	// The text styles put "(library) [subsystem:category] " in front of the message.
	macLibrary     = regexp.MustCompile(`^\(([^()\s]{1,200})\) `)
	macSubsystem   = regexp.MustCompile(`^\[([^\[\]:\s]{0,200}):([^\[\]]{0,200})\] `)
	macStart       = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
	shutdownCause  = regexp.MustCompile(`(?i)previous shutdown cause:\s*(-?\d{1,6})`)
	compactLevels  = map[string]string{"Df": "Default", "In": "Info", "Db": "Debug", "E": "Error", "Er": "Error", "F": "Fault", "Ft": "Fault", "A": "Activity"}
	macNoiseStarts = []string{"Timestamp ", "Filtering the log data", "Skipping info and debug", "---", "Log      -", "Activity -", "Boundary ", "Signpost", "Statedump", "Loss "}
)

// macOSNoise is a line that `log show` writes around the events: the column titles, the note about the
// filter, the counts at the end, and the lines of a message that goes over more than one line.
func macOSNoise(line string) bool {
	if strings.HasPrefix(strings.TrimSpace(line), `{"count":`) {
		return true
	}
	for _, start := range macNoiseStarts {
		if strings.HasPrefix(line, start) {
			return true
		}
	}

	return !macStart.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "{")
}

func newMacOSParser(options Options) lineParser {
	return func(line string) (map[string]string, time.Time, bool) {
		var moment time.Time
		var host, process, pid, message, level string
		var err error
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), "{"):
			return macOSJSON(line)
		case macDefaultLine.MatchString(line):
			parts := macDefaultLine.FindStringSubmatch(line)
			moment, err = macTime(parts[1], options.Location)
			level, pid, process, message = parts[2], parts[3], parts[4], parts[5]
		case macSyslogLine.MatchString(line):
			parts := macSyslogLine.FindStringSubmatch(line)
			moment, err = macTime(parts[1], options.Location)
			host, process, pid, message = parts[2], parts[3], parts[4], parts[5]
		case macCompactLine.MatchString(line):
			parts := macCompactLine.FindStringSubmatch(line)
			moment, err = macTime(parts[1], options.Location)
			level, process, pid, message = compactLevels[parts[2]], parts[3], parts[4], parts[5]
		default:
			return nil, time.Time{}, false
		}
		if err != nil {
			return nil, time.Time{}, false
		}
		fields := map[string]string{}
		if parts := macLibrary.FindStringSubmatch(message); parts != nil {
			message = message[len(parts[0]):]
		}
		if parts := macSubsystem.FindStringSubmatch(message); parts != nil {
			fields[FieldSubsystem], fields[FieldLogCategory] = limit(parts[1], maxNameRunes*4), limit(parts[2], maxNameRunes*4)
			message = message[len(parts[0]):]
		}
		macOSFields(fields, host, process, pid, level, message)

		return fields, moment, true
	}
}

// macTime reads the times of `log show`. A time without a zone (the compact style) is in the zone of the run.
func macTime(stamp string, location *time.Location) (time.Time, error) {
	if length := len(stamp); length > 3 && (stamp[length-3] == '+' || stamp[length-3] == '-') {
		stamp += "00"
	}
	if length := len(stamp); length > 5 && (stamp[length-5] == '+' || stamp[length-5] == '-') {
		return time.Parse("2006-01-02 15:04:05.999999999-0700", stamp)
	}

	return time.ParseInLocation("2006-01-02 15:04:05.999999999", stamp, location)
}

type macOSEntry struct {
	Timestamp        string          `json:"timestamp"`
	EventMessage     *string         `json:"eventMessage"`
	ProcessImagePath *string         `json:"processImagePath"`
	ProcessID        json.Number     `json:"processID"`
	Subsystem        string          `json:"subsystem"`
	Category         string          `json:"category"`
	MessageType      string          `json:"messageType"`
	EventType        string          `json:"eventType"`
	UserID           json.Number     `json:"userID"`
	Source           json.RawMessage `json:"source"`
}

// macOSJSON reads one line of `log show --style ndjson`. Lines of other JSON logs are refused.
func macOSJSON(line string) (map[string]string, time.Time, bool) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(line))))
	decoder.UseNumber()
	var entry macOSEntry
	if err := decoder.Decode(&entry); err != nil || entry.EventMessage == nil || entry.ProcessImagePath == nil || entry.Timestamp == "" {
		return nil, time.Time{}, false
	}
	moment, err := macTime(entry.Timestamp, time.UTC)
	if err != nil {
		return nil, time.Time{}, false
	}
	fields := map[string]string{}
	if entry.Subsystem != "" {
		fields[FieldSubsystem] = limit(entry.Subsystem, maxNameRunes*4)
	}
	if entry.Category != "" {
		fields[FieldLogCategory] = limit(entry.Category, maxNameRunes*4)
	}
	if entry.UserID != "" {
		fields["uid"] = limit(entry.UserID.String(), 16)
	}
	macOSFields(fields, "", path.Base(*entry.ProcessImagePath), entry.ProcessID.String(), entry.MessageType, *entry.EventMessage)

	return fields, moment, true
}

// macOSFields fills the fields that all styles share, and reads the messages that Omamori knows: those of
// sshd, sudo and su (the same text as on Linux) and the reason of the last shutdown, which the kernel writes
// when the Mac starts.
func macOSFields(fields map[string]string, host, process, pid, level, message string) {
	process = strings.TrimSpace(process)
	service := serviceName(process)
	message = strings.TrimRight(message, " ")
	fields[event.Product], fields[event.Service] = ProductMacOS, service
	fields[event.Process], fields[event.Message] = limit(process, maxNameRunes), limit(message, maxValueRunes)
	if host != "" {
		fields[event.Host] = limit(host, 255)
	}
	if _, err := strconv.Atoi(pid); err == nil {
		fields[FieldPID] = pid
	}
	if level != "" {
		fields[FieldLogLevel] = limit(level, 16)
	}
	programFields(service, message, fields)
	if service != "kernel" {
		return
	}
	switch {
	case shutdownCause.MatchString(message):
		fields[event.Action], fields["cause"] = "shutdown_cause", shutdownCause.FindStringSubmatch(message)[1]
	case strings.Contains(message, "panic(cpu"):
		fields[event.Action] = "kernel_panic"
	}
}
