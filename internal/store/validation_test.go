package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSQLiteFilesArePrivateAndUnsafePathsAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "events.sqlite")
	database, err := Open(context.Background(), Config{DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{path, 0600}, {filepath.Dir(path), 0700}} {
		info, err := os.Stat(entry.path)
		if err != nil || info.Mode().Perm() != entry.mode {
			t.Fatalf("private file mode: %v %v", info, err)
		}
	}
	link := filepath.Join(t.TempDir(), "link.sqlite")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{link, t.TempDir(), "file:elsewhere?mode=memory", path + "?_pragma=foreign_keys(0)"} {
		if db, err := Open(context.Background(), Config{DSN: bad}); err == nil {
			db.Close()
			t.Fatalf("unsafe SQLite path accepted: %q", bad)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	absent := filepath.Join(t.TempDir(), "no", "database.sqlite")
	if _, err := Open(cancelled, Config{DSN: absent}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled open: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(absent)); !os.IsNotExist(err) {
		t.Fatal("cancelled open created files")
	}
}

func TestSaveSanitizesEveryPersistedTextAndKeepsStableIdentity(t *testing.T) {
	database, err := Open(context.Background(), Config{DSN: filepath.Join(t.TempDir(), "events.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	const secret = "AKIAIOSFODNN7EXAMPLE"
	now := time.Date(2026, 11, 12, 1, 2, 3, 4, time.UTC)
	input := RunInput{Made: now, Mode: "detect", Label: secret, Events: []Event{{ID: "e1", Time: now, Source: "json", Ref: secret + ".jsonl:1", Fields: map[string]string{"message": secret, secret: "secret field name", "src_ip": "203.0.113.9", "path": `C:\Windows\test%file`}}}, Alerts: []Alert{{ID: "a1", Rule: secret, Title: secret, Level: "high", Time: now, First: now, Last: now, Count: 1, Group: map[string]string{"user": secret}, EventIDs: []string{"e1"}, Payload: json.RawMessage(`{"value":"` + secret + `"}`)}}, Analysis: json.RawMessage(`{"note":"` + secret + `"}`)}
	run, err := database.SaveRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == "" || run.Digest == "" {
		t.Fatal("automatic identity missing")
	}
	again, err := database.SaveRun(context.Background(), input)
	if err != nil || again.ID != run.ID {
		t.Fatalf("retry changed identity: %v", err)
	}
	for _, tableColumn := range []string{"omamori_events.document", "omamori_alerts.document", "omamori_runs.analysis", "omamori_runs.label"} {
		parts := strings.Split(tableColumn, ".")
		var text string
		if err := database.sql.QueryRow("SELECT " + parts[1] + " FROM " + parts[0]).Scan(&text); err != nil || strings.Contains(text, secret) {
			t.Fatalf("raw sensitive value persisted in %s: %v", tableColumn, err)
		}
	}
	for _, query := range []Query{{Field: "src_ip", Value: "203.0.113.9"}, {Text: `C:\Windows\test%file`}} {
		found, err := database.SearchEvents(context.Background(), query)
		if err != nil || len(found) != 1 {
			t.Fatalf("preserved literal field lookup: %d %v", len(found), err)
		}
	}
	if input.Events[0].Fields["message"] != secret {
		t.Fatal("SaveRun mutated caller evidence")
	}
}

func TestConcurrentIdempotentSave(t *testing.T) {
	database, err := Open(context.Background(), Config{DSN: filepath.Join(t.TempDir(), "events.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	input := RunInput{Made: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), Mode: "detect"}
	var wait sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() { defer wait.Done(); _, err := database.SaveRun(context.Background(), input); results <- err }()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	runs, err := database.ListRuns(context.Background(), Query{})
	if err != nil || len(runs) != 1 {
		t.Fatalf("concurrent save: %d runs %v", len(runs), err)
	}
}

func TestStoredTimeRangeAndQueryBounds(t *testing.T) {
	database, err := Open(context.Background(), Config{DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, year := range []int{1600, 2300} {
		if _, err := database.SaveRun(context.Background(), RunInput{Mode: "detect", Made: time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overflow year accepted: %d %v", year, err)
		}
	}
	for _, query := range []Query{{Limit: 1001}, {Offset: -1}, {Field: "", Value: "value"}, {From: time.Now(), To: time.Now().Add(-time.Hour)}, {RunID: "' OR 1=1"}, {Status: "closed"}} {
		if _, err := database.SearchEvents(context.Background(), query); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid query accepted: %#v %v", query, err)
		}
	}
}

func TestCaseFiltersCannotBorrowAnUnattachedAlert(t *testing.T) {
	database, err := Open(context.Background(), Config{DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	run, err := database.SaveRun(context.Background(), RunInput{Made: now, Mode: "detect", Events: []Event{{ID: "e1", Time: now, Source: "json", Fields: map[string]string{"user": "alice"}}}, Alerts: []Alert{
		{ID: "low", Rule: "low", Level: "low", Time: now, First: now, Last: now, Count: 1, EventIDs: []string{"e1"}},
		{ID: "high", Rule: "high", Level: "high", Time: now, First: now, Last: now, Count: 1, EventIDs: []string{"e1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	caseRecord, err := database.CreateCase(context.Background(), CaseInput{Title: "Only the low alert is attached"})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AddCaseAlert(context.Background(), caseRecord.ID, run.ID, "low"); err != nil {
		t.Fatal(err)
	}
	query := Query{CaseID: caseRecord.ID, Level: "high"}
	if found, err := database.SearchEvents(context.Background(), query); err != nil || len(found) != 0 {
		t.Fatalf("borrowed an unattached high alert for event filtering: %d %v", len(found), err)
	}
	if found, err := database.ListRuns(context.Background(), query); err != nil || len(found) != 0 {
		t.Fatalf("borrowed an unattached high alert for run filtering: %d %v", len(found), err)
	}
}
