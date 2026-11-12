package analysisrun

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/store"
)

type captureStore struct {
	input store.RunInput
	err   error
	calls int
}

func (capture *captureStore) SaveRun(_ context.Context, input store.RunInput) (store.Run, error) {
	capture.calls++
	capture.input = input
	if capture.err != nil {
		return store.Run{}, capture.err
	}
	return store.Run{ID: "r_saved", Made: input.Made, EventCount: len(input.Events), AlertCount: len(input.Alerts)}, nil
}

func TestStoredAnalysisUsesFrozenEvidence(t *testing.T) {
	f := newFixture(t)
	sink := &captureStore{}
	f.config.Store = sink
	session := f.prepare(t)
	f.outcome.Intake.Events[0].Fields["user"] = "changed after preparation"
	f.outcome.Result.Alerts[0].Count = 99
	session.Confirm()
	result, err := session.Run(context.Background(), nil)
	if err != nil || !result.Complete || result.RunID != "r_saved" || sink.calls != 1 {
		t.Fatalf("stored run: %#v, %v, calls %d", result, err, sink.calls)
	}
	if len(sink.input.Events) != 1 || sink.input.Events[0].Fields["user"] != "test-user" || sink.input.Alerts[0].Count != 1 {
		t.Fatal("the store used mutated caller evidence")
	}
	var storedResult Result
	if err := json.Unmarshal(sink.input.Analysis, &storedResult); err != nil || !storedResult.Complete || len(storedResult.Analysis.Verified) != 1 {
		t.Fatalf("checked analysis was not persisted: %v %s", err, sink.input.Analysis)
	}
	if text := read(t, result.SavedTo, "analysis.json"); !strings.Contains(text, `"run_id": "r_saved"`) {
		t.Fatal("the report lost the stored run reference")
	}
}

func TestStoreFailurePreservesReportsWithoutExposingDatabaseErrors(t *testing.T) {
	f := newFixture(t)
	sink := &captureStore{err: errors.New("private database password: " + plantedSecret)}
	f.config.Store = sink
	session := f.prepare(t)
	session.Confirm()
	result, err := session.Run(context.Background(), nil)
	if err != nil || result.Complete || result.RunID != "" || !strings.Contains(result.Reason, "could not be stored") {
		t.Fatalf("storage failure: %#v %v", result, err)
	}
	for _, name := range []string{"report.md", "report.html", "analysis.json", "alerts.json", "events.jsonl"} {
		text := read(t, result.SavedTo, name)
		if strings.Contains(text, plantedSecret) || strings.Contains(text, "private database password") {
			t.Fatalf("%s exposed the database error", name)
		}
	}
	if !strings.Contains(read(t, result.SavedTo, "report.md"), "New account") || len(result.Analysis.Verified) != 1 {
		t.Fatal("storage failure discarded deterministic findings or checked analysis")
	}
}
