package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/alertsink"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
)

const guessRule = `title: Guess
name: guess
logsource: {}
detection:
  s:
    action: login_failed
  condition: s
`

func mustSet(t *testing.T, text string) rules.Set {
	t.Helper()
	parsed, err := rules.Parse([]byte(text), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	set, err := rules.NewSet(parsed)
	if err != nil {
		t.Fatal(err)
	}

	return set
}

// recordingSink captures every batch it is given, so a test can inspect exactly what was delivered.
type recordingSink struct {
	batches [][]alertsink.Alert
	fail    bool
}

func (sink *recordingSink) Send(ctx context.Context, alerts []alertsink.Alert) error {
	if sink.fail {
		return errAlways
	}
	sink.batches = append(sink.batches, alerts)
	return nil
}

var errAlways = &staticError{"sink always fails in this test"}

type staticError struct{ text string }

func (err *staticError) Error() string { return err.text }

func writeLog(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func baseConfig(t *testing.T, logPath, statePath string, sink alertsink.Sink) Config {
	t.Helper()
	return Config{
		Paths:     []string{logPath},
		Rules:     mustSet(t, guessRule),
		RulesFrom: "test",
		Options:   intake.Options{Year: 2026, Location: time.UTC},
		StatePath: statePath,
		Sinks:     []alertsink.Sink{sink},
		MinLevel:  "low",
		Once:      true,
		Now:       func() time.Time { return baseTime },
	}
}

func TestRunDeliversANewAlertOnce(t *testing.T) {
	directory := t.TempDir()
	logPath := writeLog(t, directory, "auth.log",
		`{"time":"2026-11-26T09:00:00Z","action":"login_failed","src_ip":"203.0.113.5"}`+"\n")
	statePath := filepath.Join(directory, "state.json")
	sink := &recordingSink{}

	if err := Run(context.Background(), baseConfig(t, logPath, statePath, sink)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(sink.batches) != 1 || len(sink.batches[0]) != 1 {
		t.Fatalf("expected one batch of one alert, got %v", sink.batches)
	}

	// A second run over the same unchanged log must not deliver the same alert again.
	if err := Run(context.Background(), baseConfig(t, logPath, statePath, sink)); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(sink.batches) != 1 {
		t.Fatalf("the already-sent alert must not be delivered twice, got %d batches", len(sink.batches))
	}
}

func TestRunDeliversANewEventOnATailedLog(t *testing.T) {
	directory := t.TempDir()
	logPath := writeLog(t, directory, "auth.log",
		`{"time":"2026-11-26T09:00:00Z","action":"login_failed","src_ip":"203.0.113.5"}`+"\n")
	statePath := filepath.Join(directory, "state.json")
	sink := &recordingSink{}

	if err := Run(context.Background(), baseConfig(t, logPath, statePath, sink)); err != nil {
		t.Fatalf("first run: %v", err)
	}

	appended, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appended.WriteString(`{"time":"2026-11-26T09:05:00Z","action":"login_failed","src_ip":"203.0.113.9"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	appended.Close()

	if err := Run(context.Background(), baseConfig(t, logPath, statePath, sink)); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(sink.batches) != 2 || len(sink.batches[1]) != 1 {
		t.Fatalf("a genuinely new event must be delivered, got %v", sink.batches)
	}
}

func TestRunRespectsSeverityFilter(t *testing.T) {
	directory := t.TempDir()
	logPath := writeLog(t, directory, "auth.log",
		`{"time":"2026-11-26T09:00:00Z","action":"login_failed","src_ip":"203.0.113.5"}`+"\n")
	statePath := filepath.Join(directory, "state.json")
	sink := &recordingSink{}

	config := baseConfig(t, logPath, statePath, sink)
	config.MinLevel = "critical" // the sample rule has no explicit level, so it defaults below critical.

	if err := Run(context.Background(), config); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sink.batches) != 0 {
		t.Fatalf("an alert below the minimum severity must not be delivered, got %v", sink.batches)
	}
}

func TestRunContinuesWhenASinkFails(t *testing.T) {
	directory := t.TempDir()
	logPath := writeLog(t, directory, "auth.log",
		`{"time":"2026-11-26T09:00:00Z","action":"login_failed","src_ip":"203.0.113.5"}`+"\n")
	statePath := filepath.Join(directory, "state.json")
	failing := &recordingSink{fail: true}
	working := &recordingSink{}

	config := baseConfig(t, logPath, statePath, failing)
	config.Sinks = []alertsink.Sink{failing, working}

	if err := Run(context.Background(), config); err != nil {
		t.Fatalf("a failing sink must not stop the run, got %v", err)
	}
	if len(working.batches) != 1 {
		t.Fatalf("the working sink must still receive the alert, got %v", working.batches)
	}
}

func TestNoRequestsWarningWaitsForNewAppLines(t *testing.T) {
	seen := &memory{warned: map[string]bool{}, firstApp: map[string]int{}}
	startup := intake.Result{Files: []intake.Stats{{File: "/logs/api.log", AppEvents: 59}}}

	// Right after the app started: startup lines only, which is not yet a sign of a blind log.
	if got := seen.warnings(startup, false); len(got) != 0 {
		t.Fatalf("warned at startup: %v", got)
	}
	if got := seen.warnings(startup, false); len(got) != 0 {
		t.Fatalf("warned without new lines: %v", got)
	}
	// The app logs more (it is in use), and still no request: now the log is blind.
	later := intake.Result{Files: []intake.Stats{{File: "/logs/api.log", AppEvents: 70}}}
	if got := seen.warnings(later, false); len(got) != 1 || got[0] != "api.log: "+intake.WarningNoRequests {
		t.Fatalf("no warning once the app logged more: %v", got)
	}
	// A single check warns at once, as detect does.
	fresh := &memory{warned: map[string]bool{}, firstApp: map[string]int{}}
	if got := fresh.warnings(startup, true); len(got) != 1 {
		t.Fatalf("a single check must warn: %v", got)
	}
}

func TestRunCancelledContextStopsBeforeInterval(t *testing.T) {
	directory := t.TempDir()
	logPath := writeLog(t, directory, "auth.log", "")
	statePath := filepath.Join(directory, "state.json")

	config := baseConfig(t, logPath, statePath, &recordingSink{})
	config.Once = false
	config.Interval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- Run(ctx, config) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run with a cancelled context: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return promptly after the context was cancelled")
	}
}
