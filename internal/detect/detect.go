package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/knowngood"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	maxRows     = 200
	maxDetails  = 30
	maxEvidence = 8
	maxCell     = 160
)

type Outcome struct {
	Intake    intake.Result
	Result    rules.Result
	Rules     int
	RulesFrom string
	Made      time.Time
	Location  *time.Location

	// Hashes are the SHA-256 of the files that a forensic run read, by path, and Host is the name of the
	// machine. They go into the fingerprints of the alerts, for the known-good list. Detection over logs
	// has neither.
	Hashes map[string]string
	Host   string
	// KnownGood is the known-good list applied to the alerts. Nil when no list was given.
	KnownGood *knowngood.Applied
}

// ApplyKnownGood looks up the alerts in a list. It only marks alerts: none is removed.
func (outcome *Outcome) ApplyKnownGood(list *knowngood.List, path string) {
	outcome.KnownGood = knowngood.Apply(list, path, outcome.Result.Alerts, outcome.Hashes, outcome.Host, outcome.Made)
}

// Active gives the alerts that are not known good, the most serious first.
func (outcome Outcome) Active() []*rules.Alert {
	var active []*rules.Alert
	for _, alert := range outcome.bySeverity() {
		if !outcome.KnownGood.KnownGood(alert) {
			active = append(active, alert)
		}
	}

	return active
}

// Lowered gives the alerts that the known-good list covers, the most serious first.
func (outcome Outcome) Lowered() []*rules.Alert {
	var lowered []*rules.Alert
	for _, alert := range outcome.bySeverity() {
		if outcome.KnownGood.KnownGood(alert) {
			lowered = append(lowered, alert)
		}
	}

	return lowered
}

// LevelOf gives the level of an alert as a report shows it: "known good" for an alert of the list.
func (outcome Outcome) LevelOf(alert *rules.Alert) string {
	if outcome.KnownGood.KnownGood(alert) {
		return "known good"
	}

	return alert.Rule.Level
}

// Summary gives the counts of a run for the terminal, like "15 alerts, 13 high, 2 low". Alerts of the
// known-good list are counted apart.
func (outcome Outcome) Summary() string {
	active := outcome.Active()
	counts := map[string]int{}
	for _, alert := range active {
		counts[alert.Rule.Level]++
	}
	text := fmt.Sprintf("%d alerts", len(active))
	for _, level := range []string{"critical", "high", "medium", "low", "informational"} {
		if counts[level] > 0 {
			text += fmt.Sprintf(", %d %s", counts[level], level)
		}
	}
	if outcome.KnownGood != nil {
		text += fmt.Sprintf(". %d known good, from your list", outcome.KnownGood.Lowered)
	}

	return text
}

// reviewNote says what the list says about an alert that stays an alert.
func (outcome Outcome) reviewNote(alert *rules.Alert) string {
	if outcome.KnownGood == nil {
		return ""
	}
	mark := outcome.KnownGood.Marks[alert]
	if len(mark.Entries) == 0 {
		return ""
	}
	switch mark.State {
	case knowngood.StateChanged:
		return "changed since you allowed it on " + mark.Entries[0].Added + ", look again"
	case knowngood.StateExpired:
		return "your entry expired on " + mark.Entries[0].Expires + ", look again"
	}

	return ""
}

func Run(paths []string, set rules.Set, rulesFrom string, options intake.Options, now time.Time) (Outcome, error) {
	return RunContext(context.Background(), paths, set, rulesFrom, options, now)
}

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

// FileWarnings gives the warnings of every file that was read, each starting with the name of its file.
func FileWarnings(read intake.Result) []string {
	var warnings []string
	for _, file := range read.Files {
		for _, warning := range file.Warnings() {
			warnings = append(warnings, filepath.Base(file.File)+": "+warning)
		}
	}

	return warnings
}

var levelRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

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

type Extra struct {
	Title       string
	Intro       []string
	Sections    func(format *Formatter) string
	Limits      []string
	OwnTimeline bool
}

type Formatter struct{ w *writer }

// Value gives the text of a field. Free text passes the filter for secrets and personal numbers.
func (format *Formatter) Value(field, text string) string { return format.w.value(field, text) }

func (format *Formatter) Text(text string, runes int) string { return format.w.text(text, runes) }

func (format *Formatter) Time(moment time.Time) string { return format.w.time(moment) }

func (format *Formatter) Group(alert *rules.Alert) string { return format.w.group(alert) }

func (format *Formatter) Row(out *strings.Builder, cells ...any) { row(out, cells...) }

func Markdown(outcome Outcome) string { return MarkdownWith(outcome, Extra{}) }

func MarkdownWith(outcome Outcome, extra Extra) string {
	w := &writer{location: outcome.Location}
	if w.location == nil {
		w.location = time.UTC
	}
	var out strings.Builder
	alerts := outcome.Active()

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
	if applied := outcome.KnownGood; applied != nil {
		fmt.Fprintf(&out, "- Known-good list: %s, %d entries, SHA-256 %s. %d alerts are known good; they are listed apart and stay in the timeline.\n",
			plain(applied.Path, 120), len(applied.List.Entries), applied.List.SHA256, applied.Lowered)
	}
	for _, line := range extra.Intro {
		out.WriteString("- " + plain(line, 400) + "\n")
	}
	out.WriteString("- No AI was used for this report. Every alert comes from a rule, and the lines that made it fire are listed.\n\n")

	if len(outcome.Result.Cut) > 0 {
		out.WriteString("**Some rules had more matches than one run can count. Their numbers are too low.**\n\n")
	}

	out.WriteString("## Summary\n\n")
	if len(alerts) == 0 && len(outcome.Lowered()) > 0 {
		out.WriteString("Every alert is on your known-good list (see \"Known good\"). This does not prove that nothing happened. See \"Limits\".\n\n")
	} else if len(alerts) == 0 {
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
			title := plain(alert.Rule.Title, maxCell)
			if note := outcome.reviewNote(alert); note != "" {
				title += " (" + note + ")"
			}
			row(&out, index+1, alert.Rule.Level, w.time(alert.Time), title, w.group(alert), alert.Count, w.refs(alert, 3))
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
			if note := outcome.reviewNote(alert); note != "" {
				fmt.Fprintf(&out, "- Known-good list: %s\n", note)
			}
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

	}
	out.WriteString(outcome.knownGoodSection(w))
	if len(outcome.Result.Alerts) > 0 && !extra.OwnTimeline {
		out.WriteString("## Timeline\n\n| Time | Level | Rule | Who |\n|---|---|---|---|\n")
		for index, alert := range outcome.Result.Alerts {
			if index == maxRows {
				break
			}
			row(&out, w.time(alert.Time), outcome.LevelOf(alert), plain(alert.Rule.Title, maxCell), w.group(alert))
		}
		out.WriteString("\n")
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

	if warnings := FileWarnings(outcome.Intake); len(warnings) > 0 {
		out.WriteString("\n## Warnings\n\nThe rules may be blind on these files. No alert from them does not mean no attack.\n\n")
		for _, warning := range warnings {
			out.WriteString("- " + w.text(warning, 400) + "\n")
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

// knownGoodSection lists the alerts of the known-good list, with the note of the person who allowed them.
func (outcome Outcome) knownGoodSection(w *writer) string {
	lowered := outcome.Lowered()
	if len(lowered) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString("## Known good, from your list\n\n")
	out.WriteString("These alerts fired, and every event of each is on your known-good list. They are not counted as alerts. " +
		"Each one comes back when what it is about changes, or when its entry expires.\n\n")
	out.WriteString("| Level | Time | Rule | Who | Lines | Your note | Added | Expires |\n|---|---|---|---|---|---|---|---|\n")
	for index, alert := range lowered {
		if index == maxRows {
			fmt.Fprintf(&out, "\n%d more are in alerts.json.\n", len(lowered)-maxRows)
			break
		}
		entry := outcome.KnownGood.Marks[alert].Entries[0]
		row(&out, alert.Rule.Level, w.time(alert.Time), plain(alert.Rule.Title, maxCell), w.group(alert), w.refs(alert, 3),
			w.text(entry.Note, maxCell), entry.Added, entry.Expires)
	}
	out.WriteString("\n")

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
	// Match is what the known-good list needs to cover the alert: the host and one item for each event.
	// Complete is false when the alert keeps fewer events than it counts; such an alert cannot be listed.
	Match jsonMatch `json:"match"`
	// KnownGood is the entry that covers the alert, for an alert of the list.
	KnownGood *jsonEntry `json:"known_good,omitempty"`
	// Review is what the list says about an alert that stays an alert ("changed", "expired").
	Review string `json:"review,omitempty"`
}

type jsonMatch struct {
	Host     string           `json:"host,omitempty"`
	Complete bool             `json:"complete"`
	Items    []knowngood.Item `json:"items,omitempty"`
}

type jsonEntry struct {
	Note    string `json:"note"`
	Added   string `json:"added"`
	Expires string `json:"expires"`
}

func JSON(outcome Outcome) (string, error) {
	w := &writer{location: outcome.Location}
	if w.location == nil {
		w.location = time.UTC
	}
	stamp := func(moment time.Time) string { return moment.In(w.location).Format(time.RFC3339) }

	list, lowered := []jsonAlert{}, []jsonAlert{}
	for index, alert := range append(outcome.Active(), outcome.Lowered()...) {
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
		// The items are hashes that Omamori made, not text from the evidence, so they need no filter.
		current.Match.Items, current.Match.Complete = knowngood.Items(alert, outcome.Hashes)
		current.Match.Host = w.text(outcome.Host, 255)
		if current.Match.Host == "-" {
			current.Match.Host = ""
		}
		if outcome.KnownGood.KnownGood(alert) {
			entry := outcome.KnownGood.Marks[alert].Entries[0]
			current.KnownGood = &jsonEntry{Note: w.text(entry.Note, 300), Added: entry.Added, Expires: entry.Expires}
			lowered = append(lowered, current)
			continue
		}
		current.Review = outcome.reviewNote(alert)
		list = append(list, current)
	}

	document := map[string]any{"made": stamp(outcome.Made), "alerts": list, "rules_cut": outcome.Result.Cut}
	if applied := outcome.KnownGood; applied != nil {
		document["known_good_alerts"] = lowered
		document["known_good_list"] = map[string]any{"sha256": applied.List.SHA256, "entries": len(applied.List.Entries), "file": w.text(applied.Path, 300)}
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data) + "\n", nil
}
