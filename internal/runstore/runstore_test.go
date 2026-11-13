package runstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/store"
)

var made = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func sample() detect.Outcome {
	first := event.Event{Time: made.Add(-time.Minute), Source: "syslog", Ref: "auth.log:1", Fields: map[string]string{"action": "login", "outcome": "failure", "src_ip": "203.0.113.9", "user": "root"}}
	second := event.Event{Time: made.Add(-30 * time.Second), Source: "syslog", Ref: "auth.log:2", Fields: map[string]string{"action": "login", "outcome": "success", "src_ip": "203.0.113.9", "user": "root"}}
	benign := event.Event{Time: made.Add(-90 * time.Second), Source: "web", Ref: "access.log:1", Fields: map[string]string{"url": "/healthz", "src_ip": "198.51.100.1"}}
	return detect.Outcome{Made: made, Location: time.UTC, Rules: 2, RulesFrom: "test",
		Intake: intake.Result{Events: []event.Event{first, second, benign}, Files: []intake.Stats{{File: "auth.log", Format: "syslog", Sources: []string{"syslog"}, Lines: 2, Events: 2}, {File: "access.log", Format: "web", Sources: []string{"web"}, Lines: 1, Events: 1}}},
		Result: rules.Result{Alerts: []*rules.Alert{
			{Rule: &rules.Rule{Name: "failure", Title: "Login failure", Level: "medium"}, Time: first.Time, First: first.Time, Last: first.Time, Count: 1, Events: []event.Event{first}},
			{Rule: &rules.Rule{Name: "sequence", Title: "Failure then success", Level: "critical"}, Time: second.Time, First: first.Time, Last: second.Time, Count: 2, Group: []rules.Pair{{Field: "src_ip", Value: "203.0.113.9"}}, Events: []event.Event{first, second}},
		}},
	}
}

func checked(t *testing.T, outcome detect.Outcome) *Analysis {
	t.Helper()
	snapshot, err := analyst.BuildSnapshot(outcome)
	if err != nil {
		t.Fatal(err)
	}
	response := analyst.Response{Claims: []analyst.Claim{}}
	for _, alert := range snapshot.Alerts {
		count := alert.Count
		response.Claims = append(response.Claims, analyst.Claim{Kind: "alert", Alerts: []string{alert.ID}, Evidence: []string{alert.Evidence[0].ID}, Count: &count, Actions: []string{"preserve_evidence"}})
	}
	encoded, _ := json.Marshal(response)
	return &Analysis{Version: 1, Analysis: analyst.Check(snapshot, string(encoded)), Complete: true, Status: "complete", Reason: "checked", Requests: 1, Tokens: 100, Mode: "live", RecordingStatus: "saved"}
}

func TestBuildCapturesAllEventsAndStableAlertLinks(t *testing.T) {
	outcome := sample()
	input, err := Build(outcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Events) != 3 || input.Events[0].Ref != "access.log:1" || input.Events[0].ID != "e1" || input.Events[2].ID != "e3" {
		t.Fatalf("all events were not retained in chronological order: %+v", input.Events)
	}
	if input.Alerts[0].ID != "a1" || input.Alerts[0].Rule != "sequence" || !reflect.DeepEqual(input.Alerts[0].EventIDs, []string{"e2", "e3"}) {
		t.Fatalf("severity order or evidence links differ: %+v", input.Alerts)
	}
	var payload alertPayload
	if err := json.Unmarshal(input.Alerts[0].Payload, &payload); err != nil || !reflect.DeepEqual(payload.AnalystEvidence, map[string]string{"a1_e1": "e2", "a1_e2": "e3"}) {
		t.Fatalf("AI citations cannot resolve full stored events: %+v %v", payload, err)
	}
	if outcome.Intake.Events[0].Ref != "auth.log:1" || outcome.Result.Alerts[0].Rule.Name != "failure" {
		t.Fatal("building storage reordered the caller's data")
	}
	again, err := Build(outcome, nil)
	if err != nil || !reflect.DeepEqual(input, again) {
		t.Fatal("identical input did not produce identical storage data")
	}
	outcome.Intake.Events[0].Fields["user"] = "changed"
	if input.Events[1].Fields["user"] != "root" {
		t.Fatal("the stored snapshot shares a mutable field map")
	}
}

func TestEvidenceIdentityIsResolvedBeforeRedaction(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	first := event.Event{Time: made, Source: "json", Ref: "same.log:1", Fields: map[string]string{"user": secret}}
	second := event.Event{Time: made, Source: "json", Ref: "same.log:1", Fields: map[string]string{"user": "[SECRET:aws-access-key:001]"}}
	outcome := detect.Outcome{Made: made, Intake: intake.Result{Events: []event.Event{first, second}}, Result: rules.Result{Alerts: []*rules.Alert{{Rule: &rules.Rule{Name: "second", Title: "Second event", Level: "low"}, Time: made, First: made, Last: made, Count: 1, Events: []event.Event{second}}}}}
	input, err := Build(outcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	if input.Events[0].Fields["user"] != input.Events[1].Fields["user"] || !reflect.DeepEqual(input.Alerts[0].EventIDs, []string{"e2"}) {
		t.Fatalf("redacted display labels changed evidence identity: %+v", input)
	}
	encoded, _ := json.Marshal(input)
	if strings.Contains(string(encoded), secret) {
		t.Fatal("secret reached the stored snapshot")
	}
}

func TestDuplicateEventsRemainDistinctAndRepeatedLinksDoNotInventEvents(t *testing.T) {
	outcome := sample()
	entry := outcome.Intake.Events[0]
	outcome.Intake.Events = []event.Event{entry, entry}
	outcome.Result.Alerts = []*rules.Alert{{Rule: &rules.Rule{Name: "twice", Title: "Repeated", Level: "low"}, Time: entry.Time, First: entry.Time, Last: entry.Time, Count: 2, Events: []event.Event{entry, entry}}}
	input, err := Build(outcome, nil)
	if err != nil || len(input.Events) != 2 || !reflect.DeepEqual(input.Alerts[0].EventIDs, []string{"e1", "e2"}) {
		t.Fatalf("duplicate records lost: %+v %v", input, err)
	}
	var payload alertPayload
	if err := json.Unmarshal(input.Alerts[0].Payload, &payload); err != nil || !reflect.DeepEqual(payload.AnalystEvidence, map[string]string{"a1_e1": "e1", "a1_e2": "e2"}) {
		t.Fatal("separate duplicate input occurrences lost their citation links")
	}
	outcome.Intake.Events = []event.Event{entry}
	input, err = Build(outcome, nil)
	if err != nil || len(input.Events) != 1 || !reflect.DeepEqual(input.Alerts[0].EventIDs, []string{"e1"}) {
		t.Fatalf("repeated correlation evidence invented events: %+v %v", input, err)
	}
	if err := json.Unmarshal(input.Alerts[0].Payload, &payload); err != nil || !reflect.DeepEqual(payload.AnalystEvidence, map[string]string{"a1_e1": "e1", "a1_e2": "e1"}) {
		t.Fatal("repeated evidence references lost one of their citation IDs")
	}
}

func TestMissingEvidenceRefusesTheRun(t *testing.T) {
	outcome := sample()
	outcome.Intake.Events = outcome.Intake.Events[1:]
	if _, err := Build(outcome, nil); !errors.Is(err, ErrOutcome) {
		t.Fatalf("orphan evidence was accepted: %v", err)
	}
}

func TestEveryDataSurfaceIsCleanedWithoutDroppingCollidingFields(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	outcome := sample()
	outcome.RulesFrom = secret
	outcome.Intake.Files[0].File = secret + ".log"
	outcome.Intake.Skipped = []string{secret + ".gz: compressed"}
	outcome.Result.Cut = []string{secret}
	entry := &outcome.Intake.Events[0]
	entry.Ref = secret + ".log:1"
	entry.Fields[secret] = secret
	entry.Fields["phone"] = "090-1234-5678"
	entry.Fields["src_ip"] = "2001:db8::1"
	name := strings.Repeat("x", 210)
	entry.Fields[name+"a"] = "one"
	entry.Fields[name+"b"] = "two"
	entry.Fields["long"] = strings.Repeat("a", 3000)
	for _, alert := range outcome.Result.Alerts {
		alert.Rule.Name, alert.Rule.Title, alert.Rule.ID, alert.Rule.Description = secret, secret, secret, secret
		alert.Rule.Tags, alert.Values = []string{secret}, []string{secret}
		for index := range alert.Events {
			if alert.Events[index].Ref == "auth.log:1" {
				alert.Events[index] = *entry
			}
		}
	}
	input, err := Build(outcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(input)
	for _, forbidden := range []string{secret, "090-1234-5678"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("stored metadata includes %s", forbidden)
		}
	}
	var coverage Coverage
	if err := json.Unmarshal(input.Coverage, &coverage); err != nil || coverage.RenamedFields != 1 || coverage.TruncatedValues == 0 {
		t.Fatalf("missing truncation/collision coverage: %+v %v", coverage, err)
	}
	if input.Events[1].Fields["src_ip"] != "2001:db8::1" || len(input.Events[1].Fields) != len(entry.Fields) {
		t.Fatal("canonical address or colliding original fields were lost")
	}
}

func TestWithAnalysisFreezesCheckedDataAndRejectsStaleCounts(t *testing.T) {
	outcome := sample()
	frozen, err := Build(outcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	analysis := checked(t, outcome)
	analysis.Analysis.Verified[0].Summary = "untrusted text must not become stored finding prose"
	analysis.Analysis.Verified[0].Actions[0].Text = "execute an invented action"
	input, err := WithAnalysis(frozen, analysis)
	if err != nil || input.Mode != "live" || len(input.Analysis) == 0 || len(frozen.Analysis) != 0 {
		t.Fatalf("attach: %+v %v", input, err)
	}
	if strings.Contains(string(input.Analysis), "untrusted text") || strings.Contains(string(input.Analysis), "invented action") {
		t.Fatal("caller narrative was stored instead of canonical explanations")
	}
	analysis.Analysis.Verified[0].Evidence[0].Fields["user"] = "changed after attachment"
	if strings.Contains(string(input.Analysis), "changed after attachment") {
		t.Fatal("attached analysis was not frozen")
	}
	analysis.Analysis.Verified[0].Count++
	if _, err := WithAnalysis(frozen, analysis); !errors.Is(err, ErrOutcome) {
		t.Fatalf("stale analysis count accepted: %v", err)
	}
}

func TestScenarioStoresAllEventsBeyondRetainedEvidence(t *testing.T) {
	location := time.FixedZone("JST", 9*3600)
	folder := t.TempDir()
	for name, text := range scenario.Generate(3, time.Date(2026, 11, 10, 0, 0, 0, 0, location), true).Files {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := detect.Run([]string{folder}, set, "built-in", intake.Options{Year: 2026, Location: location}, made)
	if err != nil {
		t.Fatal(err)
	}
	input, err := Build(outcome, checked(t, outcome))
	if err != nil || len(input.Events) != 1254 || len(input.Alerts) != 15 {
		t.Fatalf("scenario build: %d events, %d alerts, %v", len(input.Events), len(input.Alerts), err)
	}
	linked := map[string]bool{}
	for _, alert := range input.Alerts {
		for _, id := range alert.EventIDs {
			linked[id] = true
		}
	}
	if len(linked) >= len(input.Events) {
		t.Fatal("fixture does not prove that non-alert events are stored")
	}
	if input.Alerts[0].Count != 41 || len(input.Alerts[0].EventIDs) != 41 {
		t.Fatal("the successful-login sequence lost retained evidence from its failure step")
	}
	packet, err := analyst.BuildSnapshot(outcome)
	if err != nil {
		t.Fatal(err)
	}
	byEvent := map[string]store.Event{}
	for _, event := range input.Events {
		byEvent[event.ID] = event
	}
	for index, alert := range packet.Alerts {
		var payload alertPayload
		if err := json.Unmarshal(input.Alerts[index].Payload, &payload); err != nil || len(payload.AnalystEvidence) != len(alert.Evidence) {
			t.Fatalf("citation map differs from the actual snapshot: %v", err)
		}
		for _, citation := range alert.Evidence {
			stored, found := byEvent[payload.AnalystEvidence[citation.ID]]
			if !found || stored.Time.UTC().Format(time.RFC3339Nano) != citation.Time {
				t.Fatalf("citation %s does not resolve its stored event", citation.ID)
			}
			if index == 0 && citation.ID == alert.Evidence[len(alert.Evidence)-1].ID && stored.Fields["outcome"] != "success" {
				t.Fatal("the sequence's final citation did not resolve to the successful login")
			}
		}
	}
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "runs.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	saved, err := db.SaveRun(ctx, input)
	if err != nil || saved.EventCount != 1254 || saved.AlertCount != 15 {
		t.Fatalf("store scenario: %+v %v", saved, err)
	}
	events, err := db.SearchEvents(ctx, store.Query{RunID: saved.ID, Field: "url", Value: "/healthz", Limit: 1000})
	if err != nil || len(events) != 288 {
		t.Fatalf("benign events missing from search: %d %v", len(events), err)
	}
	again, err := db.SaveRun(ctx, input)
	if err != nil || again.ID != saved.ID {
		t.Fatalf("identical run was not idempotent: %+v %v", again, err)
	}
	incident, err := db.CreateCase(ctx, store.CaseInput{Title: "Review the observed SSH sequence", Status: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddCaseAlert(ctx, incident.ID, saved.ID, "a1"); err != nil {
		t.Fatal(err)
	}
	timeline, err := db.Timeline(ctx, store.Query{CaseID: incident.ID, Limit: 1000})
	if err != nil || len(timeline) != 42 {
		t.Fatalf("case timeline lost step evidence: %d entries, %v", len(timeline), err)
	}
	for index := 1; index < len(timeline); index++ {
		if timeline[index].Time.Before(timeline[index-1].Time) {
			t.Fatal("case timeline is not chronological")
		}
	}
}

func TestCitationTargetsRemainScopedToTheirRun(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "runs.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	first, err := Save(ctx, db, sample(), nil)
	if err != nil {
		t.Fatal(err)
	}
	secondOutcome := sample()
	secondOutcome.Made = made.Add(time.Hour)
	for _, event := range secondOutcome.Intake.Events {
		if event.Fields["user"] != "" {
			event.Fields["user"] = "deploy"
		}
	}
	second, err := Save(ctx, db, secondOutcome, nil)
	if err != nil || first.ID == second.ID {
		t.Fatalf("two runs were merged: %+v %v", second, err)
	}
	for runID, user := range map[string]string{first.ID: "root", second.ID: "deploy"} {
		alerts, err := db.SearchAlerts(ctx, store.Query{RunID: runID, Level: "critical"})
		if err != nil || len(alerts) != 1 {
			t.Fatalf("run alerts: %v", err)
		}
		var payload alertPayload
		if err := json.Unmarshal(alerts[0].Payload, &payload); err != nil {
			t.Fatal(err)
		}
		events, err := db.SearchEvents(ctx, store.Query{RunID: runID, Field: "user", Value: user})
		if err != nil || len(events) != 2 {
			t.Fatalf("run events: %d %v", len(events), err)
		}
		found := false
		for _, event := range events {
			if event.ID == payload.AnalystEvidence["a1_e1"] && event.RunID == runID && event.Fields["user"] == user {
				found = true
			}
		}
		if !found {
			t.Fatalf("run-scoped citation resolved to another run's event: %s", runID)
		}
	}
}
