package runstore

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/store"
)

var (
	alertIDPattern    = regexp.MustCompile(`^a[1-9][0-9]*$`)
	evidenceIDPattern = regexp.MustCompile(`^(a[1-9][0-9]*)_e([1-8])$`)
	entityIDPattern   = regexp.MustCompile(`^n[1-9][0-9]*$`)
)

// WithAnalysis attaches a checked service result to a previously frozen detector
// input. The input is copied so a service can preserve its original detection
// snapshot while provider work runs. It never accepts raw model response text.
func WithAnalysis(input store.RunInput, attached *Analysis) (store.RunInput, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return store.RunInput{}, ErrOutcome
	}
	var copied store.RunInput
	if err := json.Unmarshal(encoded, &copied); err != nil {
		return store.RunInput{}, ErrOutcome
	}
	if attached == nil {
		return copied, nil
	}
	encoded, err = json.Marshal(attached)
	if err != nil {
		return store.RunInput{}, ErrOutcome
	}
	var analysis Analysis
	if err := json.Unmarshal(encoded, &analysis); err != nil || !validAnalysis(copied, analysis) {
		return store.RunInput{}, ErrOutcome
	}
	clean := cleaner{}
	analysis.Reason = clean.text(analysis.Reason, maxTextRunes)
	alerts := make(map[string]store.Alert, len(copied.Alerts))
	for _, alert := range copied.Alerts {
		alerts[alert.ID] = alert
	}
	catalog := map[string]analyst.Action{}
	for _, action := range analyst.Actions() {
		catalog[action.ID] = action
	}
	for index := range analysis.Analysis.Verified {
		finding := &analysis.Analysis.Verified[index]
		for number := range finding.Evidence {
			evidence := &finding.Evidence[number]
			evidence.Ref = clean.text(evidence.Ref, maxReferenceRunes)
			evidence.Fields = clean.fields(evidence.Fields)
		}
		if finding.Entity != nil {
			finding.Entity.Value = clean.value(finding.Entity.Field, finding.Entity.Value)
		}
		// Reconstruct the same factual prose as the checker instead of retaining any caller-supplied narrative.
		if finding.Kind == "alert" {
			alert := alerts[finding.Alerts[0]]
			finding.Summary = analyst.AlertSummary(alert.ID, alert.Title, alert.Count)
		} else {
			finding.Summary = analyst.RelatedSummary(len(finding.Alerts), *finding.Entity)
		}
		finding.WeakTimes = analyst.HasWeakTimes(finding.Evidence)
		finding.Summary += analyst.WeakTimeNote(finding.WeakTimes)
		for number, action := range finding.Actions {
			finding.Actions[number] = catalog[action.ID]
		}
	}
	for index := range analysis.Analysis.Rejected {
		analysis.Analysis.Rejected[index].Reason = clean.text(analysis.Analysis.Rejected[index].Reason, maxTextRunes)
	}
	encoded, err = json.Marshal(analysis)
	if err != nil {
		return store.RunInput{}, ErrOutcome
	}
	copied.Analysis = encoded
	copied.Mode = analysis.Mode
	copied.Label = "Checked AI analysis"
	if analysis.Mode == "replay" {
		copied.Label = "REPLAY: checked AI analysis"
	} else if analysis.Mode == "scripted_replay" {
		copied.Label = "REPLAY (scripted answers): checked AI analysis"
	} else if analysis.Mode == "local" {
		copied.Label = "Local analysis; no AI request"
	}
	return copied, nil
}

func validAnalysis(input store.RunInput, result Analysis) bool {
	if result.Version != 1 || result.Analysis.Version != analyst.Version || result.Requests < 0 || result.Tokens < 0 ||
		!slices.Contains([]string{"live", "replay", "scripted_replay", "local"}, result.Mode) ||
		!slices.Contains([]string{"complete", "incomplete"}, result.Status) ||
		!slices.Contains([]string{"saved", "none", "replayed", "unavailable"}, result.RecordingStatus) ||
		!slices.Contains([]string{analyst.StatusComplete, analyst.StatusPartial, analyst.StatusInvalid, analyst.StatusNotRun}, result.Analysis.Status) {
		return false
	}
	if result.Complete && (result.Status != "complete" || result.Analysis.Status != analyst.StatusComplete) {
		return false
	}
	coverage := result.Analysis.Coverage
	if coverage.TotalAlerts != len(input.Alerts) || coverage.IncludedAlerts < 0 || coverage.IncludedAlerts > len(input.Alerts) ||
		coverage.OmittedAlerts != len(input.Alerts)-coverage.IncludedAlerts || coverage.OmittedEvidence < 0 || coverage.TruncatedFields < 0 ||
		coverage.MalformedLines < 0 || coverage.SkippedFiles < 0 || coverage.RulesCut < 0 {
		return false
	}
	alerts := make(map[string]store.Alert, len(input.Alerts))
	for _, alert := range input.Alerts {
		alerts[alert.ID] = alert
	}
	actions := map[string]bool{}
	for _, action := range analyst.Actions() {
		actions[action.ID] = true
	}
	covered := map[string]bool{}
	for _, finding := range result.Analysis.Verified {
		if !validFinding(finding, alerts, actions) {
			return false
		}
		for _, id := range finding.Alerts {
			covered[id] = true
		}
	}
	unreviewed := map[string]bool{}
	for _, id := range result.Analysis.Unreviewed {
		if _, exists := alerts[id]; !exists || covered[id] || unreviewed[id] {
			return false
		}
		unreviewed[id] = true
	}
	return true
}

func validFinding(finding analyst.Finding, alerts map[string]store.Alert, actions map[string]bool) bool {
	if finding.Kind != "alert" && finding.Kind != "related" || len(finding.Alerts) == 0 || len(finding.Alerts) > analyst.MaxRelated ||
		len(finding.Evidence) == 0 || len(finding.Evidence) > analyst.MaxEvidence*analyst.MaxRelated {
		return false
	}
	seen := map[string]bool{}
	var first, last time.Time
	for _, id := range finding.Alerts {
		alert, found := alerts[id]
		if !found || !alertIDPattern.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
		if first.IsZero() || alert.First.Before(first) {
			first = alert.First
		}
		if last.IsZero() || alert.Last.After(last) {
			last = alert.Last
		}
	}
	if finding.First != first.UTC().Format(time.RFC3339Nano) || finding.Last != last.UTC().Format(time.RFC3339Nano) {
		return false
	}
	if finding.Kind == "alert" {
		if len(finding.Alerts) != 1 || finding.Count != alerts[finding.Alerts[0]].Count || finding.Entity != nil {
			return false
		}
	} else if len(finding.Alerts) < 2 || finding.Count != 0 || finding.Entity == nil ||
		!entityIDPattern.MatchString(finding.Entity.ID) || !slices.Contains([]string{event.SourceIP, event.User, event.Host}, finding.Entity.Field) ||
		last.Sub(first) > 24*time.Hour {
		return false
	}
	citations := map[string]bool{}
	cited := map[string]bool{}
	for _, evidence := range finding.Evidence {
		parts := evidenceIDPattern.FindStringSubmatch(evidence.ID)
		if len(parts) == 0 || !seen[parts[1]] || citations[evidence.ID] || evidence.TruncatedFields < 0 {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, evidence.Time); err != nil {
			return false
		}
		for _, entity := range evidence.Entities {
			if !entityIDPattern.MatchString(entity) {
				return false
			}
		}
		if finding.Entity != nil && !slices.Contains(evidence.Entities, finding.Entity.ID) {
			return false
		}
		citations[evidence.ID], cited[parts[1]] = true, true
	}
	for id := range seen {
		if !cited[id] {
			return false
		}
	}
	chosen := map[string]bool{}
	for _, action := range finding.Actions {
		if !actions[action.ID] || chosen[action.ID] || strings.TrimSpace(action.ID) != action.ID {
			return false
		}
		chosen[action.ID] = true
	}
	return true
}
