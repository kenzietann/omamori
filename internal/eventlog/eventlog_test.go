package eventlog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/gateway"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/reportwriter"
)

const (
	fakeAWSKey      = "AKIAIOSFODNN7EXAMPLE"
	fakeGitHubToken = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1"
	fakeMyNumber    = "123456789018"
	fakePhoneNumber = "090-1234-5678"
)

var plantedValues = []string{fakeAWSKey, fakeGitHubToken, fakeMyNumber, fakePhoneNumber}

func fixedClock() time.Time {
	return time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
}

func makeLog(t testing.TB) (log *Log, logDirectory, project string) {
	t.Helper()

	workspace := t.TempDir()
	project = filepath.Join(workspace, "project")
	logDirectory = filepath.Join(workspace, "logs")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}

	writer, err := reportwriter.New(project, logDirectory)
	if err != nil {
		t.Fatal(err)
	}
	appender, err := writer.Open("events.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	return New(appender, fixedClock), logDirectory, project
}

func readLogLines(t testing.TB, logDirectory string) []string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(logDirectory, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
	}

	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func TestRecordWritesOneJSONObjectPerLine(t *testing.T) {
	log, logDirectory, _ := makeLog(t)

	if err := log.Record("tool_call", "read_file", true, "allowed", "first"); err != nil {
		t.Fatal(err)
	}
	if err := log.Record("decision", "", false, "path not allowed", "line one\nline \"two\""); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	gotLines := readLogLines(t, logDirectory)
	if len(gotLines) != 2 {
		t.Fatalf("the log has %d lines, want 2", len(gotLines))
	}

	wantEntries := []entry{
		{1, "2026-11-12T09:30:00Z", "tool_call", "read_file", true, "allowed", "first"},
		{2, "2026-11-12T09:30:00Z", "decision", "", false, "path not allowed", "line one\nline \"two\""},
	}
	for index, line := range gotLines {
		var gotEntry entry
		if err := json.Unmarshal([]byte(line), &gotEntry); err != nil {
			t.Fatalf("line %d is not JSON: %v", index+1, err)
		}
		if gotEntry != wantEntries[index] {
			t.Errorf("line %d = %+v, want %+v", index+1, gotEntry, wantEntries[index])
		}
	}
}

func TestPlantedValuesNeverReachTheLog(t *testing.T) {
	log, logDirectory, _ := makeLog(t)

	text := strings.Join(plantedValues, " and ")
	if err := log.Record(text, text, true, text, text); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(logDirectory, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, plantedValue := range plantedValues {
		if strings.Contains(string(data), plantedValue) {
			t.Errorf("the planted value %q is in the log", plantedValue)
		}
	}
	if !strings.Contains(string(data), "[SECRET:aws-access-key:") {
		t.Errorf("the log has no placeholder: %s", data)
	}
}

func TestEveryCreatedFileIsFreeOfPlantedValues(t *testing.T) {
	log, logDirectory, project := makeLog(t)

	for name, content := range map[string]string{
		fakeAWSKey + ".txt": "id " + fakeMyNumber + "\n",
		"notes.txt":         "call " + fakePhoneNumber + " token " + fakeGitHubToken + "\n",
	} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	toolGateway := gateway.New(root, gateway.DefaultLimits)
	toolGateway.Observe(log.RecordGatewayEvent)

	calls := []struct {
		toolName  string
		arguments map[string]any
	}{
		{"read_file", map[string]any{"path": fakeAWSKey + ".txt"}},
		{"read_file", map[string]any{"path": fakeAWSKey + "/../../" + fakePhoneNumber}},
		{fakeAWSKey, map[string]any{"path": "notes.txt"}},
		{"list_dir", nil},
		{"search_text", map[string]any{"query": fakePhoneNumber}},
		{"run_detectors", map[string]any{"path": "."}},
	}
	for _, call := range calls {
		toolGateway.Call(context.Background(), call.toolName, call.arguments)
	}
	if err := log.Record("note", "", true, "scan finished", "checked "+fakeAWSKey+".txt"); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	createdFiles, err := os.ReadDir(logDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(createdFiles) != 1 {
		t.Fatalf("the output folder has %d files, want 1", len(createdFiles))
	}

	gotLines := readLogLines(t, logDirectory)
	if len(gotLines) != len(calls)+1 {
		t.Errorf("the log has %d lines, want %d (one per call and one note)", len(gotLines), len(calls)+1)
	}
	for _, file := range createdFiles {
		data, err := os.ReadFile(filepath.Join(logDirectory, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, plantedValue := range plantedValues {
			if strings.Contains(string(data), plantedValue) || strings.Contains(file.Name(), plantedValue) {
				t.Errorf("the planted value %q is in %q", plantedValue, file.Name())
			}
		}
	}
}

func TestLogRefusesAnExistingFile(t *testing.T) {
	_, logDirectory, project := makeLog(t)

	writer, err := reportwriter.New(project, logDirectory)
	if err != nil {
		t.Fatal(err)
	}

	_, err = writer.Open("events.jsonl")

	if !errors.Is(err, reportwriter.ErrExists) {
		t.Errorf("Open error = %v, want %v", err, reportwriter.ErrExists)
	}
}

func TestClosedLogStopsTheGateway(t *testing.T) {
	log, _, project := makeLog(t)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	toolGateway := gateway.New(root, gateway.DefaultLimits)
	toolGateway.Observe(log.RecordGatewayEvent)

	gotResult, err := toolGateway.Call(context.Background(), "list_dir", nil)

	if !errors.Is(err, gateway.ErrLogFailed) {
		t.Errorf("Call error = %v, want %v", err, gateway.ErrLogFailed)
	}
	if gotResult != (gateway.Result{}) {
		t.Errorf("a call that could not be logged returned data: %+v", gotResult)
	}
}

func TestEscapingCannotCreateAFinding(t *testing.T) {
	log, logDirectory, _ := makeLog(t)

	err := log.Record("", "", true, "", "\x00"+"00000000A")
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	gotLines := readLogLines(t, logDirectory)
	if len(gotLines) != 1 {
		t.Fatalf("the log has %d lines, want 1", len(gotLines))
	}
	var gotEntry entry
	if err := json.Unmarshal([]byte(gotLines[0]), &gotEntry); err != nil {
		t.Fatalf("the line is not JSON: %v", err)
	}
	if hasFindings(gotLines[0]) {
		t.Errorf("the detectors find something in the line: %s", gotLines[0])
	}
}

func FuzzRecord(f *testing.F) {
	f.Add("tool_call", "read_file", "allowed", "note")
	f.Add(fakeAWSKey, fakePhoneNumber, fakeMyNumber, fakeGitHubToken)
	f.Add("line\nbreak", "quote\"", "\x00\xff", "電話 ０９０-１２３４-５６７８")

	logDirectory := f.TempDir()
	project := filepath.Join(f.TempDir(), "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		f.Fatal(err)
	}
	writer, err := reportwriter.New(project, logDirectory)
	if err != nil {
		f.Fatal(err)
	}
	appender, err := writer.Open("events.jsonl")
	if err != nil {
		f.Fatal(err)
	}
	reader, err := os.Open(filepath.Join(logDirectory, "events.jsonl"))
	if err != nil {
		f.Fatal(err)
	}
	log := New(appender, fixedClock)

	var readOffset int64
	f.Fuzz(func(t *testing.T, kind, tool, reason, note string) {
		if err := log.Record(kind, tool, true, reason, note); err != nil {
			t.Fatalf("Record failed: %v", err)
		}

		info, err := reader.Stat()
		if err != nil {
			t.Fatal(err)
		}
		newBytes := make([]byte, info.Size()-readOffset)
		if _, err := reader.ReadAt(newBytes, readOffset); err != nil {
			t.Fatal(err)
		}
		readOffset = info.Size()

		line := string(newBytes)
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
			t.Fatalf("one record made %d lines", strings.Count(line, "\n"))
		}
		var gotEntry entry
		if err := json.Unmarshal(newBytes, &gotEntry); err != nil {
			t.Fatalf("the line is not JSON: %v", err)
		}
		if hasFindings(line) {
			t.Fatalf("the detectors find something in the line")
		}
	})
}
