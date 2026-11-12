// Package runstore turns detector and checked-analyst results into immutable,
// sanitized storage records. It has no CLI, HTTP or provider dependencies.
package runstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/store"
)

var ErrOutcome = errors.New("the run cannot be prepared for storage")

// Analysis is the checked service result, deliberately excluding output paths,
// database IDs, provider credentials and untrusted raw provider responses.
// Callers must supply the result of the local checker, not a client request body.
type Analysis struct {
	Version         int            `json:"version"`
	Analysis        analyst.Result `json:"analysis"`
	Complete        bool           `json:"complete"`
	Status          string         `json:"status"`
	Reason          string         `json:"reason,omitempty"`
	Requests        int            `json:"requests"`
	Tokens          int            `json:"tokens"`
	Mode            string         `json:"mode"`
	RecordingStatus string         `json:"recording_status"`
}

type Coverage struct {
	Version              int      `json:"version"`
	Rules                int      `json:"rules"`
	RulesFrom            string   `json:"rules_from"`
	Files                []File   `json:"files"`
	Skipped              []string `json:"skipped_files"`
	RulesCut             []string `json:"rules_cut"`
	EventsStored         int      `json:"events_stored"`
	AlertEvidenceOmitted int      `json:"alert_evidence_omitted_at_least"`
	TruncatedValues      int      `json:"truncated_values"`
	RenamedFields        int      `json:"renamed_fields"`
}

type File struct {
	Name      string   `json:"name"`
	Format    string   `json:"format"`
	Sources   []string `json:"sources"`
	Lines     int      `json:"lines"`
	Events    int      `json:"events"`
	Blank     int      `json:"blank"`
	Malformed int      `json:"malformed"`
}

type alertPayload struct {
	RuleID          string            `json:"rule_id,omitempty"`
	Description     string            `json:"description,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	Values          []string          `json:"values,omitempty"`
	Steps           []Step            `json:"steps,omitempty"`
	AnalystEvidence map[string]string `json:"analyst_evidence"`
	EvidenceOmitted int               `json:"evidence_omitted_at_least"`
}

type Step struct {
	Rule     string    `json:"rule"`
	Title    string    `json:"title"`
	Count    int       `json:"count"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	EventIDs []string  `json:"event_ids"`
}

type Writer interface {
	SaveRun(context.Context, store.RunInput) (store.Run, error)
}

// Save prepares and saves a complete local detection run in one store transaction.
func Save(ctx context.Context, writer Writer, outcome detect.Outcome, analysis *Analysis) (store.Run, error) {
	if writer == nil {
		return store.Run{}, ErrOutcome
	}
	input, err := Build(outcome, analysis)
	if err != nil {
		return store.Run{}, err
	}
	return writer.SaveRun(ctx, input)
}

func Build(outcome detect.Outcome, analysis *Analysis) (store.RunInput, error) {
	if outcome.Made.IsZero() || outcome.Rules < 0 {
		return store.RunInput{}, ErrOutcome
	}
	builder := cleaner{}
	input := store.RunInput{Made: outcome.Made.UTC(), Mode: "detect", Label: "Local detection",
		Events: []store.Event{}, Alerts: []store.Alert{}}
	coverage := Coverage{Version: 1, Rules: outcome.Rules, RulesFrom: builder.text(outcome.RulesFrom, maxTextRunes),
		Files: []File{}, Skipped: []string{}, RulesCut: []string{}}
	for _, file := range outcome.Intake.Files {
		if file.Lines < 0 || file.Events < 0 || file.Blank < 0 || file.Malformed < 0 {
			return store.RunInput{}, ErrOutcome
		}
		coverage.Files = append(coverage.Files, File{Name: builder.text(file.File, maxReferenceRunes),
			Format: builder.text(file.Format, maxNameRunes), Sources: builder.texts(file.Sources, maxNameRunes),
			Lines: file.Lines, Events: file.Events, Blank: file.Blank, Malformed: file.Malformed})
	}
	coverage.Skipped = builder.texts(outcome.Intake.Skipped, maxReferenceRunes)
	coverage.RulesCut = builder.texts(outcome.Result.Cut, maxTextRunes)

	ordered := append([]event.Event(nil), outcome.Intake.Events...)
	event.Sort(ordered)
	identities := make(map[[32]byte][]string, len(ordered))
	for index, original := range ordered {
		if original.Time.IsZero() {
			return store.RunInput{}, ErrOutcome
		}
		id := fmt.Sprintf("e%d", index+1)
		key, err := fingerprint(original)
		if err != nil {
			return store.RunInput{}, ErrOutcome
		}
		identities[key] = append(identities[key], id)
		input.Events = append(input.Events, store.Event{ID: id, Time: original.Time.UTC(),
			Source: builder.text(original.Source, 100), Ref: builder.text(original.Ref, maxReferenceRunes),
			Fields: builder.fields(original.Fields)})
	}
	coverage.EventsStored = len(input.Events)

	alerts := append([]*rules.Alert(nil), outcome.Result.Alerts...)
	for _, alert := range alerts {
		if alert == nil || alert.Rule == nil || alert.Count < 1 || alert.Time.IsZero() || alert.First.IsZero() ||
			alert.Last.IsZero() || alert.Last.Before(alert.First) {
			return store.RunInput{}, ErrOutcome
		}
		if _, known := severity[alert.Rule.Level]; !known {
			return store.RunInput{}, ErrOutcome
		}
	}
	sort.SliceStable(alerts, func(first, second int) bool {
		return severity[alerts[first].Rule.Level] > severity[alerts[second].Rule.Level]
	})
	for number, alert := range alerts {
		alertID := fmt.Sprintf("a%d", number+1)
		links, err := evidenceLinks(alert.Events, identities)
		if err != nil {
			return store.RunInput{}, err
		}
		group := make(map[string]string, len(alert.Group))
		for _, pair := range alert.Group {
			if _, duplicate := group[pair.Field]; duplicate {
				return store.RunInput{}, ErrOutcome
			}
			group[pair.Field] = pair.Value
		}
		payload := alertPayload{RuleID: builder.text(alert.Rule.ID, maxTextRunes), Description: builder.text(alert.Rule.Description, maxTextRunes),
			Tags: builder.texts(alert.Rule.Tags, maxTextRunes), Values: builder.texts(alert.Values, maxTextRunes), AnalystEvidence: map[string]string{}}
		sampled, err := occurrenceLinks(analyst.SampleEvidence(alert.Events), identities)
		if err != nil {
			return store.RunInput{}, err
		}
		for index, id := range sampled {
			payload.AnalystEvidence[fmt.Sprintf("%s_e%d", alertID, index+1)] = id
		}
		for _, part := range alert.Parts {
			if part == nil || part.Rule == nil || part.Count < 1 || part.First.IsZero() || part.Last.IsZero() || part.Last.Before(part.First) {
				return store.RunInput{}, ErrOutcome
			}
			partLinks, err := evidenceLinks(part.Events, identities)
			if err != nil {
				return store.RunInput{}, err
			}
			payload.Steps = append(payload.Steps, Step{Rule: builder.text(part.Rule.Name, maxTextRunes), Title: builder.text(part.Rule.Title, maxTextRunes),
				Count: part.Count, First: part.First.UTC(), Last: part.Last.UTC(), EventIDs: partLinks})
			links = unionLinks(links, partLinks)
		}
		payload.EvidenceOmitted = max(0, alert.Count-max(len(alert.Events), len(links)))
		coverage.AlertEvidenceOmitted += payload.EvidenceOmitted
		encoded, err := json.Marshal(payload)
		if err != nil {
			return store.RunInput{}, ErrOutcome
		}
		input.Alerts = append(input.Alerts, store.Alert{ID: alertID, Rule: builder.text(alert.Rule.Name, maxNameRunes),
			Title: builder.text(alert.Rule.Title, maxTextRunes), Level: alert.Rule.Level, Time: alert.Time.UTC(), First: alert.First.UTC(),
			Last: alert.Last.UTC(), Count: alert.Count, Group: builder.fields(group), EventIDs: links, Payload: encoded})
	}
	coverage.TruncatedValues, coverage.RenamedFields = builder.truncated, builder.renamed
	encoded, err := json.Marshal(coverage)
	if err != nil {
		return store.RunInput{}, ErrOutcome
	}
	input.Coverage = encoded
	return WithAnalysis(input, analysis)
}

func unionLinks(first, second []string) []string {
	seen := make(map[string]bool, len(first)+len(second))
	for _, id := range first {
		seen[id] = true
	}
	for _, id := range second {
		if !seen[id] {
			first = append(first, id)
			seen[id] = true
		}
	}
	return first
}

var severity = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

func fingerprint(original event.Event) ([32]byte, error) {
	// This identity exists only in memory. It distinguishes underlying values before redaction,
	// so two secrets replaced by similar display labels cannot link unrelated evidence.
	encoded, err := json.Marshal(struct {
		Time   time.Time         `json:"time"`
		Source string            `json:"source"`
		Ref    string            `json:"ref"`
		Fields map[string]string `json:"fields"`
	}{original.Time.UTC(), original.Source, original.Ref, original.Fields})
	return sha256.Sum256(encoded), err
}

func evidenceLinks(events []event.Event, identities map[[32]byte][]string) ([]string, error) {
	links, err := occurrenceLinks(events, identities)
	return unionLinks([]string{}, links), err
}

func occurrenceLinks(events []event.Event, identities map[[32]byte][]string) ([]string, error) {
	links := []string{}
	used := map[[32]byte]int{}
	for _, original := range events {
		key, err := fingerprint(original)
		candidates := identities[key]
		if err != nil || len(candidates) == 0 {
			return nil, ErrOutcome
		}
		position := used[key]
		if position >= len(candidates) {
			position = 0
		}
		used[key]++
		id := candidates[position]
		links = append(links, id)
	}
	return links, nil
}
