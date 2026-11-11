package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/kenzietann/omamori/internal/gateway"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const withheld = "[withheld]"

var ErrRecordFailed = errors.New("the event could not be recorded")

type Log struct {
	appender  *reportwriter.Appender
	sanitizer sanitizer.Sanitizer
	now       func() time.Time
	sequence  int
}

type entry struct {
	Sequence int    `json:"sequence"`
	Time     string `json:"time"`
	Kind     string `json:"kind"`
	Tool     string `json:"tool"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
	Note     string `json:"note"`
}

func New(appender *reportwriter.Appender, now func() time.Time) *Log {
	if now == nil {
		now = time.Now
	}

	return &Log{appender: appender, now: now}
}

func (log *Log) clean(text string) string {
	cleaned, _ := log.sanitizer.Sanitize(text)

	return cleaned
}

func encode(recorded entry) (string, error) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(recorded); err != nil {
		return "", ErrRecordFailed
	}

	return buffer.String(), nil
}

func hasFindings(line string) bool {
	var checker sanitizer.Sanitizer
	_, findings := checker.Sanitize(line)

	return len(findings) > 0
}

// Record writes one line. Every text field is sanitized first, because the caller
// may pass text that came from a scanned file or from the AI.
func (log *Log) Record(kind, tool string, allowed bool, reason, note string) error {
	log.sequence++

	recorded := entry{
		Sequence: log.sequence,
		Time:     log.now().UTC().Format(time.RFC3339),
		Kind:     log.clean(kind),
		Tool:     log.clean(tool),
		Allowed:  allowed,
		Reason:   log.clean(reason),
		Note:     log.clean(note),
	}

	line, err := encode(recorded)
	if err != nil {
		return err
	}

	// JSON escapes like & put hex digits next to digits in the text. That can build
	// a number-shaped text that was not in the input, so a line is never written with one.
	if hasFindings(line) {
		recorded.Kind, recorded.Tool, recorded.Reason, recorded.Note = withheld, withheld, withheld, withheld
		if line, err = encode(recorded); err != nil {
			return err
		}
	}

	return log.appender.Append(line)
}

func (log *Log) RecordGatewayEvent(event gateway.Event) error {
	return log.Record("tool_call", event.Tool, event.Allowed, event.Reason, "")
}

func (log *Log) Close() error {
	return log.appender.Close()
}
