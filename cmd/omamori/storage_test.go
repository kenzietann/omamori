package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/store"
)

func storedCommand(t *testing.T, database string, args ...string) detectRun {
	t.Helper()
	return runAt(t, detectNow, append(append([]string{"store"}, args...), "--db", database)...)
}

func decodeStored[T any](t *testing.T, result detectRun) T {
	t.Helper()
	var value T
	if result.code != exitOK {
		t.Fatalf("command failed: %d %s %s", result.code, result.stdout, result.stderr)
	}
	if err := json.Unmarshal([]byte(result.stdout), &value); err != nil {
		t.Fatalf("invalid JSON: %v %s", err, result.stdout)
	}
	return value
}

func TestStoredRunsSearchCasesAndTimelineThroughCLI(t *testing.T) {
	logs, _ := analystFixture(t, true)
	before := snapshot(t, logs)
	database := filepath.Join(t.TempDir(), "database", "omamori.db")
	output := filepath.Join(t.TempDir(), "reports")
	detected := runAt(t, detectNow, "detect", logs, "--year", "2026", "--timezone", "Asia/Tokyo", "--store", "--db", database, "--output", output)
	if detected.code != exitOK || !strings.Contains(detected.stdout, "Stored run:") {
		t.Fatalf("stored detection: %d %s %s", detected.code, detected.stdout, detected.stderr)
	}
	runs := decodeStored[[]store.Run](t, storedCommand(t, database, "runs"))
	if len(runs) != 1 || runs[0].EventCount != 1254 || runs[0].AlertCount != 15 {
		t.Fatalf("run counts: %#v", runs)
	}
	first := runs[0]
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "intake")
	second := runAt(t, detectNow, "detect", filepath.Join(fixture, "logs"), "--rules", filepath.Join(fixture, "rules"), "--year", "2026", "--timezone", "UTC",
		"--db", database, "--output", filepath.Join(t.TempDir(), "second"))
	if second.code != exitOK {
		t.Fatalf("second run: %d %s %s", second.code, second.stdout, second.stderr)
	}
	runs = decodeStored[[]store.Run](t, storedCommand(t, database, "runs"))
	if len(runs) != 2 || runs[0].ID == runs[1].ID {
		t.Fatalf("two independent runs were not retained: %#v", runs)
	}
	secondID := runs[0].ID
	if secondID == first.ID {
		secondID = runs[1].ID
	}
	events := decodeStored[[]store.Event](t, storedCommand(t, database, "search", "--run", first.ID, "--field", "src_ip", "--value", "203.0.113.9"))
	if len(events) < 40 {
		t.Fatalf("source search found only %d events", len(events))
	}
	for _, event := range events {
		if event.RunID != first.ID || event.Fields["src_ip"] != "203.0.113.9" {
			t.Fatal("search escaped its run or entity filter")
		}
	}
	injected := decodeStored[[]store.Event](t, storedCommand(t, database, "search", "--text", "' OR 1=1 --"))
	if len(injected) != 0 {
		t.Fatal("SQL-shaped text became a query")
	}
	alerts := decodeStored[[]store.Alert](t, storedCommand(t, database, "search", "--kind", "alerts", "--level", "critical"))
	if len(alerts) != 1 || alerts[0].RunID != first.ID {
		t.Fatalf("critical alerts: %#v", alerts)
	}
	created := decodeStored[store.Case](t, storedCommand(t, database, "cases", "create", "--title", "Synthetic investigation", "--notes", "Review the cited evidence"))
	attached := decodeStored[store.Case](t, storedCommand(t, database, "cases", "add", created.ID, "--run", first.ID, "--alert", "a1"))
	attached = decodeStored[store.Case](t, storedCommand(t, database, "cases", "add", created.ID, "--run", secondID, "--alert", "a1"))
	if len(attached.Alerts) != 2 || attached.Version <= created.Version {
		t.Fatalf("case links: %#v", attached)
	}
	linked := decodeStored[[]store.Alert](t, storedCommand(t, database, "search", "--kind", "alerts", "--case", created.ID))
	allowed := map[string]bool{}
	for _, alert := range linked {
		allowed[alert.RunID+":alert:"+alert.ID] = true
		for _, eventID := range alert.EventIDs {
			allowed[alert.RunID+":event:"+eventID] = true
		}
	}
	timeline := decodeStored[[]store.TimelineEntry](t, storedCommand(t, database, "timeline", "--case", created.ID, "--limit", "500"))
	if len(timeline) != len(allowed) {
		t.Fatalf("case timeline has %d entries, expected %d", len(timeline), len(allowed))
	}
	for index, entry := range timeline {
		if !allowed[entry.RunID+":"+entry.Kind+":"+entry.ID] || index > 0 && entry.Time.Before(timeline[index-1].Time) {
			t.Fatal("timeline included unrelated evidence or was out of order")
		}
	}
	updated := decodeStored[store.Case](t, storedCommand(t, database, "cases", "update", created.ID, "--version", fmt.Sprint(attached.Version), "--status", "investigating"))
	if updated.Title != created.Title || updated.Notes != created.Notes || updated.Status != "investigating" {
		t.Fatalf("partial case update changed unspecified fields: %#v", updated)
	}
	stale := storedCommand(t, database, "cases", "update", created.ID, "--version", fmt.Sprint(attached.Version), "--status", "closed")
	if stale.code != exitFailed || !strings.Contains(stale.stderr, "conflict") {
		t.Fatalf("stale update: %d %s", stale.code, stale.stderr)
	}
	remaining := decodeStored[store.Case](t, storedCommand(t, database, "cases", "remove", created.ID, "--run", first.ID, "--alert", "a1"))
	if len(remaining.Alerts) != 1 || remaining.Alerts[0].RunID != secondID {
		t.Fatal("detaching an alert changed the wrong case evidence")
	}
	all := decodeStored[[]store.Event](t, storedCommand(t, database, "search", "--run", first.ID, "--limit", "5"))
	page := decodeStored[[]store.Event](t, storedCommand(t, database, "search", "--run", first.ID, "--limit", "2", "--offset", "2"))
	if len(page) != 2 || page[0].ID != all[2].ID || page[1].ID != all[3].ID {
		t.Fatal("pagination was not stable")
	}
	for path, content := range before {
		if snapshot(t, logs)[path] != content {
			t.Fatal("persistent detection changed its input")
		}
	}
}

func TestAnalysisPersistenceAndPreview(t *testing.T) {
	logs, packet := analystFixture(t, true)
	database := filepath.Join(t.TempDir(), "analysis.db")
	provider := &analystProvider{answer: analystAnswers(t, packet)}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }
	common := []string{"analyze", logs, "--provider", "openai", "--model", "test", "--year", "2026", "--timezone", "Asia/Tokyo", "--db", database}
	preview := analyzeCommand(t, factory, append(append([]string{}, common...), "--dry-run")...)
	if preview.code != exitOK || len(provider.sent) != 0 {
		t.Fatalf("preview: %d %s", preview.code, preview.stderr)
	}
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatal("preview opened the persistent store")
	}
	output := filepath.Join(t.TempDir(), "reports")
	live := analyzeCommand(t, factory, append(common, "--yes", "--output", output)...)
	if live.code != exitOK || !strings.Contains(live.stdout, "Stored run:") {
		t.Fatalf("analysis store: %d %s %s", live.code, live.stdout, live.stderr)
	}
	runs := decodeStored[[]store.Run](t, storedCommand(t, database, "runs"))
	if len(runs) != 1 || runs[0].EventCount != 1254 || runs[0].AlertCount != 15 || len(runs[0].Analysis) == 0 {
		t.Fatalf("analysis persistence: %#v", runs)
	}
	var result analysisrun.Result
	data, _ := os.ReadFile(analysisFiles(t, output)["analysis.json"])
	if err := json.Unmarshal(data, &result); err != nil || result.RunID != runs[0].ID || !result.Complete {
		t.Fatalf("report run reference: %v %s", err, data)
	}
}

func TestStorageConfigurationAndInputBoundaries(t *testing.T) {
	for _, driver := range []string{"postgres", "mariadb"} {
		const secretDSN = "private-user:private-password@private-host/database"
		env := environment{lookupEnv: func(name string) string {
			if name == "OMAMORI_DB_DRIVER" {
				return driver
			}
			if name == "OMAMORI_DB_DSN" {
				return secretDSN
			}
			return ""
		}}
		config, err := (storageFlags{}).config(env)
		if err != nil || config.Driver != driver || config.DSN != secretDSN {
			t.Fatal("configured backend was not preserved")
		}
		_, err = (storageFlags{path: "wrong.db"}).config(env)
		if err == nil || strings.Contains(err.Error(), secretDSN) || strings.Contains(err.Error(), "private-password") {
			t.Fatal("conflicting configuration accepted or credentials exposed")
		}
	}
	base := t.TempDir()
	path := filepath.Join(base, "store.db")
	for _, source := range []string{base, path, path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := (storageFlags{path: path}).open(context.Background(), environment{}, []string{source}); err == nil {
			t.Errorf("database overlapped input %s", source)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("refused store created a file")
	}
}
