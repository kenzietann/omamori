package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func contractID(t *testing.T) string {
	t.Helper()
	var data [12]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal(err)
	}
	return "contract" + hex.EncodeToString(data[:])
}

// The same contract runs against SQLite by default and isolated PostgreSQL/MariaDB
// databases when their explicit test DSNs are supplied. It never drops a database or table.
func TestBackendContract(t *testing.T) {
	backends := []struct {
		name string
		dsn  string
	}{
		{"sqlite", filepath.Join(t.TempDir(), "contract.sqlite")},
		{"postgres", os.Getenv("OMAMORI_TEST_POSTGRES_DSN")},
		{"mariadb", os.Getenv("OMAMORI_TEST_MARIADB_DSN")},
	}
	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			if backend.dsn == "" {
				t.Skip("an isolated database DSN was not supplied")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			config := Config{Driver: backend.name, DSN: backend.dsn}
			database, err := Open(ctx, config)
			if err != nil {
				t.Fatalf("open %s: %v", backend.name, err)
			}
			t.Cleanup(func() { _ = database.Close() })
			prefix := contractID(t)
			start := time.Date(2026, 11, 12, 10, 0, 0, 123456789, time.UTC)
			input := RunInput{
				ID: prefix + "_one", Made: start.Add(time.Minute), Mode: "detect", Label: "first " + prefix,
				Events: []Event{
					{ID: "e1", Time: start, Source: "syslog", Ref: "auth.log:1", Fields: map[string]string{"user": "Alice", "src_ip": "203.0.113.9", "message": "literal 100% ready_under!done", "marker": prefix}},
					{ID: "e2", Time: start.Add(time.Second), Source: "windows", Ref: "windows.jsonl:1", Fields: map[string]string{"user": "alice", "src_ip": "203.0.113.9", "message": "ordinary readyXunder", "marker": prefix}},
					{ID: "e3", Time: start.Add(2 * time.Second), Source: "json", Ref: "events.jsonl:1", Fields: map[string]string{"user": "Alice ", "user ": "separate field", "message": "CAFÉ 東京", "marker": prefix}},
				},
				Alerts: []Alert{
					{ID: "a1", Rule: "contract_rule", Title: "Two observations " + prefix, Level: "high", Time: start.Add(time.Second), First: start, Last: start.Add(time.Second), Count: 2,
						Group: map[string]string{"src_ip": "203.0.113.9"}, EventIDs: []string{"e1", "e2"}, Payload: json.RawMessage(`{"kind":"observation"}`)},
					{ID: "a2", Rule: "other_rule", Title: "One observation " + prefix, Level: "low", Time: start.Add(2 * time.Second), First: start.Add(2 * time.Second), Last: start.Add(2 * time.Second), Count: 1, EventIDs: []string{"e3"}},
				},
				Analysis: json.RawMessage(`{"version":1,"status":"not_run"}`),
				Coverage: json.RawMessage(`{"events":3,"alerts":2}`),
			}
			run, err := database.SaveRun(ctx, input)
			if err != nil || run.ID != input.ID || run.EventCount != 3 || run.AlertCount != 2 || run.Digest == "" {
				t.Fatalf("save run: %#v %v", run, err)
			}
			if again, err := database.SaveRun(ctx, input); err != nil || again.ID != run.ID || again.Digest != run.Digest {
				t.Fatalf("idempotent save: %#v %v", again, err)
			}
			changed := input
			changed.Label = "changed " + prefix
			if _, err := database.SaveRun(ctx, changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("immutable run accepted different content: %v", err)
			}
			stored, err := database.GetRun(ctx, run.ID)
			if err != nil || stored.Label != input.Label || !stored.Made.Equal(input.Made) || !jsonEqual(stored.Analysis, input.Analysis) || !jsonEqual(stored.Coverage, input.Coverage) {
				t.Fatalf("run did not round trip: %#v %v", stored, err)
			}
			for _, value := range []string{"Alice", "alice", "Alice "} {
				found, err := database.SearchEvents(ctx, Query{RunID: run.ID, Field: "user", Value: value})
				if err != nil || len(found) != 1 || found[0].Fields["user"] != value {
					t.Fatalf("exact entity %q: %#v %v", value, found, err)
				}
			}
			if found, err := database.SearchEvents(ctx, Query{RunID: run.ID, Field: "user ", Value: "separate field"}); err != nil || len(found) != 1 || found[0].ID != "e3" {
				t.Fatalf("exact field-name matching: %#v %v", found, err)
			}
			for _, literal := range []string{"%", "ready_under", "under!done", "100%", "café 東京"} {
				found, err := database.SearchEvents(ctx, Query{RunID: run.ID, Text: literal})
				if err != nil || len(found) != 1 {
					t.Fatalf("literal substring %q: %d results, %v", literal, len(found), err)
				}
			}
			if found, err := database.SearchEvents(ctx, Query{RunID: run.ID, Text: "' OR 1=1 --"}); err != nil || len(found) != 0 {
				t.Fatalf("search text became SQL: %d results, %v", len(found), err)
			}
			all, err := database.SearchEvents(ctx, Query{RunID: run.ID})
			if err != nil || len(all) != 3 {
				t.Fatalf("event list: %d results, %v", len(all), err)
			}
			page, err := database.SearchEvents(ctx, Query{RunID: run.ID, Limit: 1, Offset: 1})
			if err != nil || len(page) != 1 || page[0].ID != all[1].ID || page[0].RunID != run.ID {
				t.Fatalf("event pagination: %#v %v", page, err)
			}
			bounded, err := database.SearchEvents(ctx, Query{RunID: run.ID, From: start.Add(time.Second), To: start.Add(time.Second)})
			if err != nil || len(bounded) != 1 || bounded[0].ID != "e2" || !bounded[0].Time.Equal(start.Add(time.Second)) {
				t.Fatalf("inclusive nanosecond time boundary: %#v %v", bounded, err)
			}
			if found, err := database.SearchEvents(ctx, Query{RunID: run.ID, Source: "windows"}); err != nil || len(found) != 1 || found[0].ID != "e2" {
				t.Fatalf("source filter: %#v %v", found, err)
			}
			if found, err := database.SearchAlerts(ctx, Query{RunID: run.ID, Level: "high", Rule: "contract_rule"}); err != nil || len(found) != 1 || !reflect.DeepEqual(found[0].EventIDs, []string{"e1", "e2"}) {
				t.Fatalf("alert filter or evidence links: %#v %v", found, err)
			}
			if found, err := database.SearchAlerts(ctx, Query{RunID: run.ID, Source: "windows"}); err != nil || len(found) != 1 || found[0].ID != "a1" {
				t.Fatalf("alert source filter: %#v %v", found, err)
			}
			if found, err := database.SearchAlerts(ctx, Query{RunID: run.ID, Field: "user", Value: "Alice "}); err != nil || len(found) != 1 || found[0].ID != "a2" {
				t.Fatalf("alert evidence-field filter: %#v %v", found, err)
			}

			second := RunInput{ID: prefix + "_two", Made: start.Add(2 * time.Minute), Mode: "analyze", Label: "second " + prefix,
				Events: []Event{{ID: "e1", Time: start.Add(10 * time.Second), Source: "syslog", Ref: "auth.log:1", Fields: map[string]string{"user": "Alice", "marker": prefix}}},
				Alerts: []Alert{{ID: "a1", Rule: "contract_rule", Title: "Later observation " + prefix, Level: "critical", Time: start.Add(10 * time.Second), First: start.Add(10 * time.Second), Last: start.Add(10 * time.Second), Count: 1, EventIDs: []string{"e1"}}},
			}
			if _, err := database.SaveRun(ctx, second); err != nil {
				t.Fatalf("a second run could not reuse local IDs: %v", err)
			}
			if found, err := database.ListRuns(ctx, Query{Text: prefix}); err != nil || len(found) != 2 {
				t.Fatalf("run search: %d, %v", len(found), err)
			}
			caseRecord, err := database.CreateCase(ctx, CaseInput{Title: "Investigation " + prefix, Notes: "Check the original logs; planted secret AKIAIOSFODNN7EXAMPLE", Status: "open"})
			if err != nil || caseRecord.ID == "" || caseRecord.Version < 1 {
				t.Fatalf("create case: %#v %v", caseRecord, err)
			}
			if strings.Contains(caseRecord.Notes, "AKIAIOSFODNN7EXAMPLE") || !strings.Contains(caseRecord.Notes, "[SECRET:") {
				t.Fatal("case notes were not sanitized")
			}
			if found, err := database.ListCases(ctx, Query{Text: prefix, Status: "open"}); err != nil || len(found) != 1 || found[0].ID != caseRecord.ID {
				t.Fatalf("case search: %#v %v", found, err)
			}
			if err := database.AddCaseAlert(ctx, caseRecord.ID, run.ID, "missing"); err == nil {
				t.Fatal("an alert that does not exist was attached")
			}
			if err := database.AddCaseAlert(ctx, caseRecord.ID, run.ID, "a1"); err != nil {
				t.Fatal(err)
			}
			attached, err := database.GetCase(ctx, caseRecord.ID)
			if err != nil || len(attached.Alerts) != 1 || attached.Version <= caseRecord.Version {
				t.Fatalf("attach case alert: %#v %v", attached, err)
			}
			if err := database.AddCaseAlert(ctx, caseRecord.ID, run.ID, "a1"); err != nil {
				t.Fatal(err)
			}
			duplicate, err := database.GetCase(ctx, caseRecord.ID)
			if err != nil || duplicate.Version != attached.Version || len(duplicate.Alerts) != 1 {
				t.Fatalf("duplicate case attachment was not idempotent: %#v %v", duplicate, err)
			}
			if _, err := database.UpdateCase(ctx, caseRecord.ID, caseRecord.Version, CaseInput{Title: "Stale " + prefix, Status: "closed"}); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale case update accepted: %v", err)
			}
			if err := database.AddCaseAlert(ctx, caseRecord.ID, second.ID, "a1"); err != nil {
				t.Fatal(err)
			}
			timeline, err := database.Timeline(ctx, Query{CaseID: caseRecord.ID})
			if err != nil || len(timeline) != 5 {
				t.Fatalf("case timeline has %d entries, want two alerts and their three linked events: %v", len(timeline), err)
			}
			seen := map[string]bool{}
			for index, item := range timeline {
				key := item.Kind + ":" + item.RunID + ":" + item.ID
				if seen[key] || (index > 0 && item.Time.Before(timeline[index-1].Time)) || (item.Kind == "event" && item.RunID == run.ID && item.ID == "e3") {
					t.Fatalf("duplicate, unordered or unrelated timeline entry: %#v", item)
				}
				seen[key] = true
			}
			pageTimeline, err := database.Timeline(ctx, Query{CaseID: caseRecord.ID, Limit: 2, Offset: 1})
			if err != nil || !reflect.DeepEqual(pageTimeline, timeline[1:3]) {
				t.Fatalf("timeline pagination differs: %#v %v", pageTimeline, err)
			}
			current, err := database.GetCase(ctx, caseRecord.ID)
			if err != nil {
				t.Fatal(err)
			}
			results := make(chan error, 2)
			for _, status := range []string{"investigating", "closed"} {
				go func(status string) {
					_, err := database.UpdateCase(ctx, current.ID, current.Version, CaseInput{Title: current.Title, Notes: current.Notes, Status: status})
					results <- err
				}(status)
			}
			success, conflicts := 0, 0
			for range 2 {
				err := <-results
				if err == nil {
					success++
				} else if errors.Is(err, ErrConflict) {
					conflicts++
				} else {
					t.Fatalf("concurrent case update: %v", err)
				}
			}
			if success != 1 || conflicts != 1 {
				t.Fatalf("optimistic case update: %d succeeded, %d conflicted", success, conflicts)
			}
			if err := database.RemoveCaseAlert(ctx, current.ID, run.ID, "a1"); err != nil {
				t.Fatal(err)
			}
			detached, err := database.GetCase(ctx, current.ID)
			if err != nil || len(detached.Alerts) != 1 || detached.Alerts[0].RunID != second.ID {
				t.Fatalf("detach: %#v %v", detached, err)
			}
			if err := database.RemoveCaseAlert(ctx, current.ID, run.ID, "a1"); err != nil {
				t.Fatal(err)
			}
			again, err := database.GetCase(ctx, current.ID)
			if err != nil || again.Version != detached.Version {
				t.Fatal("repeated detach changed the case")
			}

			bad := input
			bad.ID = prefix + "_invalid"
			bad.Alerts = append([]Alert(nil), input.Alerts...)
			bad.Alerts[0].EventIDs = []string{"missing"}
			if _, err := database.SaveRun(ctx, bad); err == nil {
				t.Fatal("a dangling evidence reference was accepted")
			}
			if _, err := database.GetRun(ctx, bad.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a failed run was partly stored: %v", err)
			}
			cancelled, stop := context.WithCancel(ctx)
			stop()
			if _, err := database.SearchEvents(cancelled, Query{RunID: run.ID}); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled query: %v", err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(ctx, config)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer reopened.Close()
			if durable, err := reopened.GetRun(ctx, run.ID); err != nil || durable.Digest != run.Digest {
				t.Fatalf("run did not survive reopen: %#v %v", durable, err)
			}
			if durable, err := reopened.GetCase(ctx, caseRecord.ID); err != nil || len(durable.Alerts) != 1 {
				t.Fatalf("case did not survive reopen: %#v %v", durable, err)
			}
		})
	}
}

func jsonEqual(first, second json.RawMessage) bool {
	var left, right any
	return json.Unmarshal(first, &left) == nil && json.Unmarshal(second, &right) == nil && reflect.DeepEqual(left, right)
}

func TestDatabaseErrorsDoNotExposeCredentials(t *testing.T) {
	const secret = "not-a-real-database-password"
	for _, driver := range []string{"postgres", "mariadb"} {
		t.Run(driver, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			dsn := "postgres://test:" + secret + "@127.0.0.1:1/test?sslmode=disable"
			if driver == "mariadb" {
				dsn = "test:" + secret + "@tcp(127.0.0.1:1)/test?timeout=100ms"
			}
			database, err := Open(ctx, Config{Driver: driver, DSN: dsn})
			if database != nil {
				_ = database.Close()
			}
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), dsn) {
				t.Fatalf("credential-safe open failure: %v", err)
			}
		})
	}
}

func TestSaveRunRollsBackAfterADatabaseWriteFails(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollback.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	// Fail the second event after the run, first event and its field index have been inserted.
	if _, err := database.sql.ExecContext(ctx, `CREATE TRIGGER contract_refuse_event BEFORE INSERT ON omamori_events WHEN NEW.event_id='e2' BEGIN SELECT RAISE(ABORT,'contract write failure'); END`); err != nil {
		t.Fatal(err)
	}
	moment := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	input := RunInput{ID: "rollback_case", Made: moment, Mode: "detect", Events: []Event{
		{ID: "e1", Time: moment, Source: "json", Fields: map[string]string{"user": "first"}},
		{ID: "e2", Time: moment.Add(time.Second), Source: "json", Fields: map[string]string{"user": "second"}},
	}}
	if _, err := database.SaveRun(ctx, input); !errors.Is(err, ErrDatabase) {
		t.Fatalf("injected database failure: %v", err)
	}
	if _, err := database.GetRun(ctx, input.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed run was retained: %v", err)
	}
	if events, err := database.SearchEvents(ctx, Query{RunID: input.ID}); err != nil || len(events) != 0 {
		t.Fatalf("partially stored events: %d, %v", len(events), err)
	}
	var indexed int
	if err := database.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM omamori_event_fields`).Scan(&indexed); err != nil || indexed != 0 {
		t.Fatalf("partially stored field index: %d, %v", indexed, err)
	}
	if _, err := database.sql.ExecContext(ctx, `DROP TRIGGER contract_refuse_event`); err != nil {
		t.Fatal(err)
	}
	if run, err := database.SaveRun(ctx, input); err != nil || run.EventCount != 2 {
		t.Fatalf("retry after rollback: %#v, %v", run, err)
	}
}

func TestSchemaVersionAndForeignKeyEnforcement(t *testing.T) {
	ctx := context.Background()
	config := Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "schema.sqlite")}
	database, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	var enabled int
	if err := database.sql.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("foreign key enforcement: %d, %v", enabled, err)
	}
	if _, err := database.sql.ExecContext(ctx, `INSERT INTO omamori_case_alerts(case_id,run_id,alert_id) VALUES('missing','missing','missing')`); err == nil {
		t.Fatal("foreign key constraints accepted an orphan link")
	}
	if _, err := database.sql.ExecContext(ctx, `UPDATE omamori_schema SET version=999`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(ctx, config)
	if opened != nil {
		_ = opened.Close()
	}
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("a newer schema was not refused: %v", err)
	}
}
