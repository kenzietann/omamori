// Package detect is the detection run: log files in, events, rules, alerts, and a report. It connects
// intake, rules and the report, and it sends nothing anywhere. The AI is not part of this package.
package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	maxRows     = 200
	maxDetails  = 30
	maxEvidence = 8
	maxCell     = 160
)

// Outcome is the result of one run.
type Outcome struct {
	Intake intake.Result
	Result rules.Result
	Rules  int
	// RulesFrom says where the rules came from, for the report: "built-in" or "folder".
	RulesFrom string
	Made      time.Time
	Location  *time.Location
}

// Run reads the logs and evaluates the rules.
func Run(paths []string, set rules.Set, rulesFrom string, options intake.Options, now time.Time) (Outcome, error) {
	return RunContext(context.Background(), paths, set, rulesFrom, options, now)
}

// RunContext supports dashboard cancellation while reading input; rule evaluation is a bounded batch.
func RunContext(ctx context.Context, paths []string, set rules.Set, rulesFrom string, options intake.Options, now time.Time) (Outcome, error) {
	read, err := intake.ReadContext(ctx, paths, options)
	if err != nil {
		return Outcome{}, err
	}

	return Outcome{
		Intake: read, Result: set.Evaluate(read.Events), Rules: len(set.Rules()), RulesFrom: rulesFrom,
		Made: now, Location: options.Location,
	}, nil
}

var levelRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

// bySeverity gives the alerts with the most serious first, and the earliest first among equals.
func (outcome Outcome) bySeverity() []*rules.Alert {
	sorted := append([]*rules.Alert{}, outcome.Result.Alerts...)
	sort.SliceStable(sorted, func(first, second int) bool {
		return levelRank[sorted[first].Rule.Level] > levelRank[sorted[second].Rule.Level]
	})

	return sorted
}

// writer makes the texts of a report. Free text from logs passes the sanitizer, so that a token in a URL
// or a number in a message does not land in a file. One sanitizer for one report keeps the placeholders in step.
type writer struct {
	clean    sanitizer.Sanitizer
	location *time.Location
}

// Only validated addresses and numbers bypass the sanitizer: JSON can put arbitrary text in any field.
// Keeping real addresses readable matters because the phone detector can mistake them for personal data.
func (w *writer) value(field, text string) string {
	switch event.Canonical(field) {
	case event.SourceIP, event.DestIP:
		if address, err := netip.ParseAddr(text); err == nil && address.Zone() == "" {
			return plain(text, maxCell)
		}
	case event.Status, event.Bytes:
		if _, err := strconv.ParseUint(text, 10, 64); err == nil {
			return plain(text, maxCell)
		}
	}

	return w.text(text, maxCell)
}

func (w *writer) text(text string, runes int) string {
	text, _ = w.clean.Sanitize(text)
	return plain(text, runes)
}

func (w *writer) time(moment time.Time) string {
	return moment.In(w.location).Format("2006-01-02 15:04:05 -07:00")
}

// plain makes text safe for one line of the report: no control characters, not too long.
func plain(text string, runes int) string {
	text = strings.Map(func(character rune) rune {
		switch {
		case character < 0x20 || character == 0x7f || character == ' ' || character == ' ':
			return ' '
		}

		return character
	}, text)
	text = strings.TrimSpace(text)
	if utf8.RuneCountInString(text) > runes {
		text = string([]rune(text)[:runes]) + "..."
	}
	if text == "" {
		return "-"
	}

	return text
}

// row writes one row of a table. A "|" inside a cell would make a new column, so it is written as "¦".
// It is not written as "/": in a shell command "curl x / sh" would read as something else than "curl x | sh".
func row(out *strings.Builder, cells ...any) {
	out.WriteString("|")
	for _, cell := range cells {
		out.WriteString(" " + strings.ReplaceAll(fmt.Sprint(cell), "|", "¦") + " |")
	}
	out.WriteString("\n")
}

func (w *writer) group(alert *rules.Alert) string {
	if len(alert.Group) == 0 {
		if alert.Rule.IsCorrelation() || len(alert.Events) == 0 {
			return "-"
		}
		var parts []string
		for _, field := range []string{event.SourceIP, event.User, event.Host} {
			if value, found := alert.Events[0].Get(field); found && value != "" {
				parts = append(parts, field+"="+w.value(field, value))
			}
		}
		if len(parts) == 0 {
			return "-"
		}

		return strings.Join(parts, ", ")
	}

	var parts []string
	for _, pair := range alert.Group {
		parts = append(parts, pair.Field+"="+w.value(pair.Field, pair.Value))
	}

	return strings.Join(parts, ", ")
}

func (w *writer) refs(alert *rules.Alert, limit int) string {
	var list []string
	for index, current := range alert.Events {
		if index == limit {
			break
		}
		list = append(list, w.text(current.Ref, 80))
	}
	text := strings.Join(list, ", ")
	if alert.Count > len(list) {
		text += fmt.Sprintf(" and %d more", alert.Count-len(list))
	}

	return text
}

// describe gives the fields of one event that matter most to a reader, in a fixed order.
func (w *writer) describe(current event.Event) string {
	var parts []string
	for _, field := range []string{event.Collector, event.Service, event.EventID, event.Action, event.Outcome, event.User, event.SourceIP, event.SourcePort,
		event.DestIP, event.DestPort, event.Protocol, event.Method, event.URL, event.Status, event.UserAgent, event.Process, event.Command, event.Signature} {
		if value, found := current.Fields[field]; found && value != "" {
			parts = append(parts, field+"="+w.value(field, value))
		}
	}
	if len(parts) == 0 {
		if message, found := current.Fields[event.Message]; found {
			parts = append(parts, w.value(event.Message, message))
		}
	}

	return strings.Join(parts, " ")
}

// Extra changes the report for a run that is more than the detection in logs, such as the forensic triage.
// The zero value gives the plain detection report.
type Extra struct {
	// Title replaces the title of the report.
	Title string
	// Intro lines are added to the list at the top.
	Intro []string
	// Sections gives Markdown that is put before the list of files. It gets the formatter of the report,
	// so that its values pass the same filter and the placeholders keep their numbers.
	Sections func(format *Formatter) string
	// Limits are added to the limits at the end.
	Limits []string
	// OwnTimeline says that Sections has a timeline, so the plain one is left out.
	OwnTimeline bool
}

// Formatter makes texts for a report in the same way as the report itself.
type Formatter struct{ w *writer }

// Value gives the text of a field. Free text passes the filter for secrets and personal numbers.
func (format *Formatter) Value(field, text string) string { return format.w.value(field, text) }

// Text gives free text, filtered, on one line and not longer than the number of characters.
func (format *Formatter) Text(text string, runes int) string { return format.w.text(text, runes) }

// Time gives a time in the zone of the report.
func (format *Formatter) Time(moment time.Time) string { return format.w.time(moment) }

// Group says who an alert is about.
func (format *Formatter) Group(alert *rules.Alert) string { return format.w.group(alert) }

// Row writes one row of a table.
func (format *Formatter) Row(out *strings.Builder, cells ...any) { row(out, cells...) }

// Markdown gives the report. It is also the input of the HTML page.
func Markdown(outcome Outcome) string { return MarkdownWith(outcome, Extra{}) }

// MarkdownWith gives the report with the additions of another kind of run.
func MarkdownWith(outcome Outcome, extra Extra) string {
	w := &writer{location: outcome.Location}
	if w.location == nil {
		w.location = time.UTC
	}
	var out strings.Builder
	alerts := outcome.bySeverity()

	lines, events, malformed := 0, 0, 0
	for _, file := range outcome.Intake.Files {
		lines, events, malformed = lines+file.Lines, events+file.Events, malformed+file.Malformed
	}

	title := "Omamori detection report"
	if extra.Title != "" {
		title = plain(extra.Title, maxCell)
	}
	out.WriteString("# " + title + "\n\n")
	fmt.Fprintf(&out, "- Made: %s\n", w.time(outcome.Made))
	fmt.Fprintf(&out, "- Read: %d files, %d lines, %d events, %d lines that could not be read\n", len(outcome.Intake.Files), lines, events, malformed)
	fmt.Fprintf(&out, "- Rules: %d (%s)\n", outcome.Rules, plain(outcome.RulesFrom, 40))
	fmt.Fprintf(&out, "- Alerts: %d\n", len(alerts))
	for _, line := range extra.Intro {
		out.WriteString("- " + plain(line, 400) + "\n")
	}
	out.WriteString("- No AI was used for this report. Every alert comes from a rule, and the lines that made it fire are listed.\n\n")

	if len(outcome.Result.Cut) > 0 {
		out.WriteString("**Some rules had more matches than one run can count. Their numbers are too low.**\n\n")
	}

	out.WriteString("## Summary\n\n")
	if len(alerts) == 0 {
		out.WriteString("No rule fired. This does not prove that nothing happened. See \"Limits\".\n\n")
	} else {
		type summary struct {
			rule        *rules.Rule
			count       int
			first, last time.Time
		}
		var rows []*summary
		byRule := map[*rules.Rule]*summary{}
		for _, alert := range alerts {
			current := byRule[alert.Rule]
			if current == nil {
				current = &summary{rule: alert.Rule, first: alert.First, last: alert.Last}
				byRule[alert.Rule] = current
				rows = append(rows, current)
			}
			current.count++
			if alert.First.Before(current.first) {
				current.first = alert.First
			}
			if alert.Last.After(current.last) {
				current.last = alert.Last
			}
		}
		out.WriteString("| Level | Rule | Alerts | First event | Last event |\n|---|---|---|---|---|\n")
		for _, current := range rows {
			row(&out, current.rule.Level, plain(current.rule.Title, maxCell), current.count, w.time(current.first), w.time(current.last))
		}
		out.WriteString("\n## Alerts\n\n")
		out.WriteString("The most serious are first. \"Time\" is the moment the rule fired.\n\n")
		out.WriteString("| # | Level | Time | Rule | Who | Events | Lines |\n|---|---|---|---|---|---|---|\n")
		for index, alert := range alerts {
			if index == maxRows {
				break
			}
			row(&out, index+1, alert.Rule.Level, w.time(alert.Time), plain(alert.Rule.Title, maxCell), w.group(alert), alert.Count, w.refs(alert, 3))
		}
		if len(alerts) > maxRows {
			fmt.Fprintf(&out, "\n%d more alerts are in alerts.json.\n", len(alerts)-maxRows)
		}

		out.WriteString("\n## Details\n\n")
		for index, alert := range alerts {
			if index == maxDetails {
				fmt.Fprintf(&out, "Details of the other %d alerts are in alerts.json.\n\n", len(alerts)-maxDetails)
				break
			}
			fmt.Fprintf(&out, "Alert %d (%s): %s. %s\n\n", index+1, alert.Rule.Level, plain(alert.Rule.Title, maxCell), plain(alert.Rule.Description, 400))
			fmt.Fprintf(&out, "- Who: %s\n", w.group(alert))
			fmt.Fprintf(&out, "- Events: %d, from %s to %s\n", alert.Count, w.time(alert.First), w.time(alert.Last))
			if len(alert.Values) > 0 {
				shown := alert.Values
				if len(shown) > 12 {
					shown = shown[:12]
				}
				var values []string
				for _, value := range shown {
					values = append(values, w.value("", value))
				}
				fmt.Fprintf(&out, "- %d different values, for example: %s\n", len(alert.Values), strings.Join(values, ", "))
			}
			for number, part := range alert.Parts {
				fmt.Fprintf(&out, "- Step %d: %s (events: %d, last at %s)\n", number+1, plain(part.Rule.Title, maxCell), part.Count, w.time(part.Last))
			}
			shown := alert.Events
			if len(alert.Parts) > 0 {
				// For a sequence the last event of the last step is the one to read first: it is the success after the failures.
				final := alert.Parts[len(alert.Parts)-1].Events
				shown = append(append([]event.Event{}, final...), shown...)
			}
			for number, current := range shown {
				if number == maxEvidence {
					break
				}
				fmt.Fprintf(&out, "- %s at %s: %s\n", w.text(current.Ref, 80), w.time(current.Time), w.describe(current))
			}
			out.WriteString("\n")
		}

		if !extra.OwnTimeline {
			out.WriteString("## Timeline\n\n| Time | Level | Rule | Who |\n|---|---|---|---|\n")
			for index, alert := range outcome.Result.Alerts {
				if index == maxRows {
					break
				}
				row(&out, w.time(alert.Time), alert.Rule.Level, plain(alert.Rule.Title, maxCell), w.group(alert))
			}
			out.WriteString("\n")
		}
	}
	if extra.Sections != nil {
		out.WriteString(extra.Sections(&Formatter{w}))
	}

	out.WriteString("## Files\n\n| File | Format | Lines | Events | Empty lines | Lines not read |\n|---|---|---|---|---|---|\n")
	for _, file := range outcome.Intake.Files {
		format := file.Format
		if file.Format == intake.FormatJSON && len(file.Sources) > 0 && !(len(file.Sources) == 1 && file.Sources[0] == intake.FormatJSON) {
			format += " (" + strings.Join(file.Sources, ", ") + ")"
		}
		row(&out, w.text(file.File, maxCell), format, file.Lines, file.Events, file.Blank, file.Malformed)
	}
	if len(outcome.Intake.Skipped) > 0 {
		out.WriteString("\nFiles that were not read:\n\n")
		for _, skipped := range outcome.Intake.Skipped {
			fmt.Fprintf(&out, "- %s\n", w.text(skipped, maxCell))
		}
	}

	out.WriteString("\n## Limits\n\n")
	out.WriteString("- Only the files above were read. An attacker who can change a log can remove lines from it.\n")
	out.WriteString("- A rule fires at its limit. Slow guessing under the limit (for example one try every few minutes) gives no alert.\n")
	out.WriteString("- Classic syslog lines have no year and no time zone. The year and the zone of this run were used for them.\n")
	out.WriteString("- Values from the logs were passed through the filter for secrets and personal numbers. A placeholder like [SECRET:...] stands for a removed value.\n")
	out.WriteString("- Compressed files are not read yet.\n")
	out.WriteString("- In the tables, \"¦\" stands for the character \"|\" of the original text.\n")
	for _, line := range extra.Limits {
		out.WriteString("- " + plain(line, 400) + "\n")
	}

	return out.String()
}

type jsonEvent struct {
	Ref    string            `json:"ref"`
	Time   string            `json:"time"`
	Source string            `json:"source,omitempty"`
	Fields map[string]string `json:"fields"`
}

type jsonAlert struct {
	Number      int               `json:"number"`
	Rule        string            `json:"rule"`
	RuleID      string            `json:"rule_id,omitempty"`
	Title       string            `json:"title"`
	Level       string            `json:"level"`
	Tags        []string          `json:"tags,omitempty"`
	Time        string            `json:"time"`
	First       string            `json:"first"`
	Last        string            `json:"last"`
	Group       map[string]string `json:"group,omitempty"`
	Count       int               `json:"count"`
	Values      []string          `json:"values,omitempty"`
	Steps       []string          `json:"steps,omitempty"`
	Events      []jsonEvent       `json:"events"`
	EventsShown int               `json:"events_shown"`
}

// JSON gives the alerts for other tools, in the same order and with the same numbers as the report.
func JSON(outcome Outcome) (string, error) {
	w := &writer{location: outcome.Location}
	if w.location == nil {
		w.location = time.UTC
	}
	stamp := func(moment time.Time) string { return moment.In(w.location).Format(time.RFC3339) }

	list := []jsonAlert{}
	for index, alert := range outcome.bySeverity() {
		current := jsonAlert{
			Number: index + 1, Rule: alert.Rule.Name, RuleID: alert.Rule.ID, Title: alert.Rule.Title, Level: alert.Rule.Level, Tags: alert.Rule.Tags,
			Time: stamp(alert.Time), First: stamp(alert.First), Last: stamp(alert.Last), Count: alert.Count, EventsShown: len(alert.Events),
		}
		for _, pair := range alert.Group {
			if current.Group == nil {
				current.Group = map[string]string{}
			}
			current.Group[pair.Field] = w.value(pair.Field, pair.Value)
		}
		for _, value := range alert.Values {
			current.Values = append(current.Values, w.value("", value))
		}
		for _, part := range alert.Parts {
			current.Steps = append(current.Steps, part.Rule.Name)
		}
		for _, item := range alert.Events {
			// The names are taken in a fixed order, so that the placeholders get the same numbers in every run.
			names := make([]string, 0, len(item.Fields))
			for name := range item.Fields {
				names = append(names, name)
			}
			sort.Strings(names)
			fields := make(map[string]string, len(names))
			for _, name := range names {
				fields[w.text(name, maxCell)] = w.value(name, item.Fields[name])
			}
			source := ""
			if item.Source != "" {
				source = w.text(item.Source, 40)
			}
			current.Events = append(current.Events, jsonEvent{Ref: w.text(item.Ref, maxCell), Time: stamp(item.Time), Source: source, Fields: fields})
		}
		list = append(list, current)
	}

	data, err := json.MarshalIndent(map[string]any{"made": stamp(outcome.Made), "alerts": list, "rules_cut": outcome.Result.Cut}, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data) + "\n", nil
}
