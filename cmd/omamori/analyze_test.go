package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/taskrun"
)

type analystProvider struct {
	answer string
	sent   []outbound.Request
}

func (*analystProvider) Name() string { return "test analyst" }
func (provider *analystProvider) Send(_ context.Context, request outbound.SafeRequest) (outbound.Response, error) {
	provider.sent = append(provider.sent, request.Request())
	return outbound.Response{Text: provider.answer, TokensUsed: 100}, nil
}

func analyzeCommand(t *testing.T, factory taskrun.ProviderFactory, args ...string) detectRun {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, environment{
		stdout: &stdout, stderr: &stderr, home: homeAt(t.TempDir()), now: func() time.Time { return detectNow },
		lookupEnv: func(name string) string {
			if name == "OPENAI_API_KEY" {
				return "fake-test-key"
			}
			return ""
		},
		newProvider: factory,
	})
	return detectRun{code, stdout.String(), stderr.String()}
}

func analystFixture(t *testing.T, attacks bool) (string, analyst.Snapshot) {
	t.Helper()
	folder := t.TempDir()
	location := time.FixedZone("JST", 9*3600)
	day := time.Date(2026, 11, 10, 0, 0, 0, 0, location)
	for name, content := range scenario.Generate(3, day, attacks).Files {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := detect.Run([]string{folder}, set, "built-in", intake.Options{Year: 2026, Location: location}, detectNow)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := analyst.BuildSnapshot(outcome)
	if err != nil {
		t.Fatal(err)
	}
	return folder, snapshot
}

func analystAnswers(t *testing.T, snapshot analyst.Snapshot) string {
	t.Helper()
	response := analyst.Response{Claims: []analyst.Claim{}}
	for _, alert := range snapshot.Alerts {
		count := alert.Count
		claim := analyst.Claim{Kind: "alert", Alerts: []string{alert.ID}, Count: &count}
		for _, evidence := range alert.Evidence {
			claim.Evidence = append(claim.Evidence, evidence.ID)
		}
		response.Claims = append(response.Claims, claim)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func analysisFiles(t *testing.T, base string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			files[entry.Name()] = path
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return files
}

func TestAnalyzePreviewSendsNothingAndWritesNothing(t *testing.T) {
	logs, snapshot := analystFixture(t, true)
	provider := &analystProvider{answer: analystAnswers(t, snapshot)}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }
	for _, extra := range [][]string{nil, {"--dry-run"}} {
		output := filepath.Join(t.TempDir(), "reports")
		args := []string{"analyze", "--provider", "openai", "--model", "test", "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output, logs}
		got := analyzeCommand(t, factory, append(args, extra...)...)
		if got.code != exitOK || !strings.Contains(got.stdout, "Nothing was sent") || len(provider.sent) != 0 {
			t.Fatalf("preview: %d %s %s, sent %d", got.code, got.stdout, got.stderr, len(provider.sent))
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("preview created an output folder")
		}
	}
}

func TestAnalyzeLiveAndReplayThroughTheCLI(t *testing.T) {
	logs, snapshot := analystFixture(t, true)
	before := snapshotFiles(t, logs)
	provider := &analystProvider{answer: analystAnswers(t, snapshot)}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }
	liveOutput := filepath.Join(t.TempDir(), "live")
	got := analyzeCommand(t, factory, "analyze", logs, "--yes", "--provider", "openai", "--model", "test", "--year", "2026", "--timezone", "Asia/Tokyo", "--output", liveOutput)
	if got.code != exitOK || len(provider.sent) != 1 {
		t.Fatalf("live: %d %s %s, calls %d", got.code, got.stdout, got.stderr, len(provider.sent))
	}
	files := analysisFiles(t, liveOutput)
	for _, name := range []string{"report.md", "report.html", "alerts.json", "analysis.json", "events.jsonl", "recording.json"} {
		if files[name] == "" {
			t.Errorf("missing %s", name)
		}
	}
	data, err := os.ReadFile(files["analysis.json"])
	var result analysisrun.Result
	if err != nil || json.Unmarshal(data, &result) != nil || !result.Complete || len(result.Analysis.Verified) != 15 {
		t.Fatalf("analysis JSON: %v, %s", err, data)
	}
	noProvider := func(_, _, _, _ string) (outbound.Provider, error) {
		t.Fatal("replay created a live provider")
		return nil, nil
	}
	for _, command := range []string{"analyze", "replay"} {
		output := filepath.Join(t.TempDir(), "replay")
		args := []string{command, "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output}
		if command == "analyze" {
			args = append(args, "--replay", files["recording.json"], logs)
		} else {
			args = append(args, files["recording.json"], logs)
		}
		replayed := analyzeCommand(t, noProvider, args...)
		if replayed.code != exitOK || !strings.Contains(replayed.stdout, "REPLAY") {
			t.Fatalf("%s replay: %d %s %s", command, replayed.code, replayed.stdout, replayed.stderr)
		}
		report, _ := os.ReadFile(analysisFiles(t, output)["report.md"])
		if !strings.Contains(string(report), "REPLAY") {
			t.Fatal("the report did not label its replay")
		}
	}
	for name, content := range before {
		if snapshotFiles(t, logs)[name] != content {
			t.Fatal("an input log changed")
		}
	}
}

func snapshotFiles(t *testing.T, folder string) map[string]string { return snapshot(t, folder) }

func TestAnalyzeRejectsUnverifiedModelProseButKeepsDetection(t *testing.T) {
	logs, _ := analystFixture(t, true)
	const prose = "invented compromise with no evidence"
	provider := &analystProvider{answer: prose}
	output := filepath.Join(t.TempDir(), "reports")
	got := analyzeCommand(t, func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }, "analyze", "--yes", "--provider", "openai", "--model", "test", "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output, logs)
	if got.code != exitFailed {
		t.Fatalf("invalid answer: %d %s %s", got.code, got.stdout, got.stderr)
	}
	files := analysisFiles(t, output)
	for _, name := range []string{"report.md", "report.html", "analysis.json", "events.jsonl"} {
		data, err := os.ReadFile(files[name])
		if err != nil || strings.Contains(string(data), prose) {
			t.Fatalf("%s contains unverified prose or is missing: %v", name, err)
		}
	}
	alerts, _ := os.ReadFile(files["alerts.json"])
	if !strings.Contains(string(alerts), "ssh_brute_force_success") {
		t.Fatal("deterministic detection disappeared after the invalid answer")
	}
}

func TestAnalyzeWithNoAlertsNeedsNoProvider(t *testing.T) {
	logs, _ := analystFixture(t, false)
	output := filepath.Join(t.TempDir(), "reports")
	got := analyzeCommand(t, func(_, _, _, _ string) (outbound.Provider, error) {
		t.Fatal("a quiet run created a provider")
		return nil, nil
	}, "analyze", "--yes", "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output, logs)
	if got.code != exitOK || !strings.Contains(got.stdout, "0 verified findings") {
		t.Fatalf("quiet run: %d %s %s", got.code, got.stdout, got.stderr)
	}
	if analysisFiles(t, output)["recording.json"] != "" {
		t.Fatal("a quiet run invented a recording")
	}
}

func TestBundledAnalystReplay(t *testing.T) {
	logs, _ := analystFixture(t, true)
	output := filepath.Join(t.TempDir(), "reports")
	got := analyzeCommand(t, func(_, _, _, _ string) (outbound.Provider, error) {
		t.Fatal("the bundled demo created a live provider")
		return nil, nil
	}, "analyze", logs, "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output,
		"--replay", filepath.Join("..", "..", "testdata", "fixtures", "analyst", "recording.json"))
	if got.code != exitOK || !strings.Contains(got.stdout, "16 verified findings") || !strings.Contains(got.stdout, "REPLAY (scripted answers)") {
		t.Fatalf("bundled demo: %d %s %s", got.code, got.stdout, got.stderr)
	}
	data, err := os.ReadFile(analysisFiles(t, output)["analysis.json"])
	var result analysisrun.Result
	if err != nil || json.Unmarshal(data, &result) != nil || len(result.Analysis.Verified) != 16 || result.Analysis.Verified[15].Kind != "related" {
		t.Fatalf("the demo did not verify its related-alert claim: %v", err)
	}
}

func TestAnalyzeFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"analyze"}, {"analyze", "--yes", "--dry-run", "."},
		{"analyze", "--timeout", "0s", "."}, {"analyze", "--unknown", "."},
	} {
		if got := analyzeCommand(t, nil, args...); got.code != exitUsage {
			t.Errorf("%v: code %d, %s", args, got.code, got.stderr)
		}
	}
}
