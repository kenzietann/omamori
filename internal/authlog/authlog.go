// Package authlog reads Linux auth.log lines from sshd (the text format). It finds the events that
// the log triage needs: a failed password and an accepted password. It counts every line that it does
// not use, and every line that it cannot read, so that nothing is dropped silently.
package authlog

import (
	"bufio"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrTooBig   = errors.New("the log is too big")
	ErrBadInput = errors.New("the log cannot be read")
)

const (
	maxLineBytes = 8192
	maxLines     = 2_000_000
	maxEvents    = 500_000
	maxNameRunes = 64
	maxIPRunes   = 45
)

type Kind int

const (
	Failed Kind = iota + 1
	Accepted
)

func (kind Kind) String() string {
	if kind == Failed {
		return "Failed password"
	}

	return "Accepted password"
}

// Event is one failed or accepted password. Line counts from 1. Stamp is the time as it is written in the
// log, with one space between the parts, because the log has no year and the AI cites it as written.
type Event struct {
	Line  int
	Kind  Kind
	Time  time.Time
	Stamp string
	User  string
	IP    string
}

type Parsed struct {
	Events []Event
	Lines  int
	// Ignored are lines that are fine but are not a failed or accepted password: other messages and blank lines.
	Ignored int
	// Malformed are lines that cannot be read as a log line, or look like a password event but have wrong fields.
	Malformed int
}

var (
	linePattern = regexp.MustCompile(`^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([A-Za-z0-9_.-]+)(?:\[\d+\])?: (.*)$`)
	failedText  = regexp.MustCompile(`^Failed password for (?:invalid user )?(\S+) from (\S+) port \d{1,5}(?: ssh2)?$`)
	acceptText  = regexp.MustCompile(`^Accepted password for (\S+) from (\S+) port \d{1,5}(?: ssh2)?$`)
	ipPattern   = regexp.MustCompile(`^[0-9A-Fa-f:.]{2,45}$`)
)

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// Parse reads the log. The year and the time zone come from the caller, because the lines have none.
func Parse(reader io.Reader, year int, location *time.Location) (Parsed, error) {
	if reader == nil || location == nil || year < 1970 || year > 2200 {
		return Parsed{}, ErrBadInput
	}

	var parsed Parsed
	buffered := bufio.NewReaderSize(reader, 64*1024)
	for {
		line, tooLong, err := readLine(buffered)
		if err != nil && !errors.Is(err, io.EOF) {
			return Parsed{}, ErrBadInput
		}
		if errors.Is(err, io.EOF) && line == "" && !tooLong {
			break
		}

		parsed.Lines++
		if parsed.Lines > maxLines {
			return Parsed{}, ErrTooBig
		}
		switch event, outcome := parseLine(line, tooLong, parsed.Lines, year, location); outcome {
		case readEvent:
			parsed.Events = append(parsed.Events, event)
			if len(parsed.Events) > maxEvents {
				return Parsed{}, ErrTooBig
			}
		case readIgnored:
			parsed.Ignored++
		default:
			parsed.Malformed++
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}

	sort.SliceStable(parsed.Events, func(first, second int) bool { return parsed.Events[first].Time.Before(parsed.Events[second].Time) })

	return parsed, nil
}

func readLine(reader *bufio.Reader) (line string, tooLong bool, err error) {
	var collected []byte
	for {
		part, isPrefix, readErr := reader.ReadLine()
		if len(collected)+len(part) > maxLineBytes {
			tooLong = true
		} else {
			collected = append(collected, part...)
		}
		if readErr != nil {
			return string(collected), tooLong, readErr
		}
		if !isPrefix {
			return string(collected), tooLong, nil
		}
	}
}

type outcome int

const (
	readEvent outcome = iota + 1
	readIgnored
	readMalformed
)

func parseLine(line string, tooLong bool, number, year int, location *time.Location) (Event, outcome) {
	if tooLong || !utf8.ValidString(line) || strings.ContainsRune(line, 0) {
		return Event{}, readMalformed
	}
	if strings.TrimSpace(line) == "" {
		return Event{}, readIgnored
	}

	parts := linePattern.FindStringSubmatch(line)
	if parts == nil {
		return Event{}, readMalformed
	}
	month, known := months[parts[1]]
	day, hour, minute, second := atoi(parts[2]), atoi(parts[3]), atoi(parts[4]), atoi(parts[5])
	moment := time.Date(year, month, day, hour, minute, second, 0, location)
	if !known || hour > 23 || minute > 59 || second > 59 || moment.Day() != day || moment.Month() != month {
		return Event{}, readMalformed
	}

	if parts[7] != "sshd" {
		return Event{}, readIgnored
	}

	message := strings.TrimRight(parts[8], " ")
	var kind Kind
	var fields []string
	switch {
	case strings.HasPrefix(message, "Failed password for "):
		kind, fields = Failed, failedText.FindStringSubmatch(message)
	case strings.HasPrefix(message, "Accepted password for "):
		kind, fields = Accepted, acceptText.FindStringSubmatch(message)
	default:
		return Event{}, readIgnored
	}
	if fields == nil || utf8.RuneCountInString(fields[1]) > maxNameRunes || len(fields[2]) > maxIPRunes || !ipPattern.MatchString(fields[2]) {
		return Event{}, readMalformed
	}

	stamp := parts[1] + " " + strings.TrimLeft(parts[2], " ") + " " + parts[3] + ":" + parts[4] + ":" + parts[5]

	return Event{Line: number, Kind: kind, Time: moment, Stamp: stamp, User: fields[1], IP: fields[2]}, readEvent
}

func atoi(text string) int {
	value := 0
	for _, digit := range text {
		value = value*10 + int(digit-'0')
	}

	return value
}
