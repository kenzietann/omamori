package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/triage"
	"github.com/kenzietann/omamori/internal/tui"
)

func ruleBackend(t *testing.T, logs string, provider outbound.Provider) backend {
	t.Helper()
	return backend{config: taskrun.Config{Target: logs, OutputBase: filepath.Join(t.TempDir(), "reports"), Limits: agent.Limits{MaxTokens: 300000},
		Triage: &triage.Config{Year: 2026, Location: time.UTC}, Now: func() time.Time { return detectNow },
		NewProvider: func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }}}
}

var cronRule = tui.RuleInput{Goal: "cron jobs that download a script and pipe it to a shell", Examples: "web01/auth.log:68", Title: "Cron download piped to a shell", Level: "high"}

func TestHomeRuleDraftPreviewsThenRunsTheSameChecks(t *testing.T) {
	logs := campaignFolder(t)
	before := snapshotFiles(t, logs)
	provider := &analystProvider{answer: cronRuleAnswer}
	b := ruleBackend(t, logs, provider)
	plan, err := b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "fake-key", Rule: cronRule})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Local || plan.Title != "Task C: Rule draft" || !strings.Contains(plan.Preview, "examples_that_must_match") || len(provider.sent) != 0 {
		t.Fatalf("plan %+v, sent %d", plan.Title, len(provider.sent))
	}
	if _, err := os.Stat(b.config.OutputBase); !os.IsNotExist(err) {
		t.Fatal("the preparation wrote something")
	}
	if _, err := plan.Run(context.Background(), nil); err == nil || len(provider.sent) != 0 {
		t.Fatal("an unconfirmed plan ran")
	}

	plan, err = b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "fake-key", Rule: cronRule})
	if err != nil {
		t.Fatal(err)
	}
	plan.Confirm()
	var steps []string
	result, err := plan.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil || !result.Complete || result.SavedTo == "" || len(provider.sent) != 1 || len(steps) == 0 {
		t.Fatalf("result %+v %v, sent %d", result, err, len(provider.sent))
	}
	if !strings.Contains(result.Report, "A rule was accepted") || !strings.Contains(result.Report, "web01/auth.log:68") {
		t.Fatalf("report:\n%s", result.Report)
	}
	saved, err := os.ReadFile(filepath.Join(result.SavedTo, "rule.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := rules.Parse(saved, "rule.yml"); err != nil || len(parsed) != 1 || parsed[0].Title != cronRule.Title {
		t.Fatalf("the saved rule: %v", err)
	}
	if after := snapshotFiles(t, logs); !reflect.DeepEqual(before, after) {
		t.Fatal("the logs were changed")
	}
}

func TestHomeRuleDraftRefusesBadInputBeforeAnythingIsSent(t *testing.T) {
	logs := campaignFolder(t)
	provider := &analystProvider{answer: cronRuleAnswer}
	b := ruleBackend(t, logs, provider)
	testCases := []struct {
		name string
		rule tui.RuleInput
		want string
	}{
		{"an example that is not there", tui.RuleInput{Goal: "x", Examples: "web01/auth.log:999999"}, "is not exactly one event"},
		{"no example", tui.RuleInput{Goal: "x", Examples: " , "}, "example events"},
		{"no goal", tui.RuleInput{Examples: "web01/auth.log:68"}, "goal"},
		{"an unknown level", tui.RuleInput{Goal: "x", Examples: "web01/auth.log:68", Level: "urgent"}, "level"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "fake-key", Rule: testCase.rule})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %v, want %q", err, testCase.want)
			}
		})
	}
	if _, err := b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, Replay: true}); err == nil || !strings.Contains(err.Error(), "give the recording") {
		t.Fatalf("a replay from the home screen: %v", err)
	}
	empty := ruleBackend(t, t.TempDir(), provider)
	if _, err := empty.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: cronRule}); err == nil {
		t.Fatal("a folder without logs was accepted")
	}
	if len(provider.sent) != 0 {
		t.Fatal("something was sent")
	}
	if _, err := os.Stat(b.config.OutputBase); !os.IsNotExist(err) {
		t.Fatal("a refused preparation wrote something")
	}
}

func TestHomeRuleDraftThatIsRefusedIsIncompleteAndWritesNoRule(t *testing.T) {
	logs := campaignFolder(t)
	provider := &analystProvider{answer: strings.Replace(cronRuleAnswer, "expect: {alerts: 1}", "expect: {alerts: 3}", 1)}
	b := ruleBackend(t, logs, provider)
	plan, err := b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "fake-key", Rule: cronRule})
	if err != nil {
		t.Fatal(err)
	}
	plan.Confirm()
	result, err := plan.Run(context.Background(), nil)
	if err != nil || result.Complete || len(provider.sent) != 3 || !strings.Contains(result.Report, "No rule was accepted") {
		t.Fatalf("result %+v %v, sent %d", result, err, len(provider.sent))
	}
	if _, err := os.Stat(filepath.Join(result.SavedTo, "rule.yml")); !os.IsNotExist(err) {
		t.Fatal("a refused rule was written")
	}
}

func TestSplitExamples(t *testing.T) {
	got := splitExamples(" web01/auth.log:68, auth.log:3\tauth.log:4,,")
	if !reflect.DeepEqual(got, []string{"web01/auth.log:68", "auth.log:3", "auth.log:4"}) {
		t.Fatalf("got %q", got)
	}
}

// cleanFolder writes one log file that holds the given lines, in a folder apart from the campaign.
func cleanFolder(t *testing.T, name string, lines ...string) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "clean logs")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return folder
}

func lineOf(t *testing.T, path string, number int) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(data), "\n")[number-1]
}

func TestHomeRuleDraftUsesTheCleanLogs(t *testing.T) {
	logs := campaignFolder(t)
	example := lineOf(t, filepath.Join(logs, "web01", "auth.log"), 68)
	backup := lineOf(t, filepath.Join(logs, "web01", "auth.log"), 69)
	if !strings.Contains(example, "u.sh | sh") || !strings.Contains(backup, "backup.sh") {
		t.Fatalf("the campaign lines moved: %q %q", example, backup)
	}

	quiet := cleanFolder(t, "auth.log", backup, backup)
	provider := &analystProvider{answer: cronRuleAnswer}
	b := ruleBackend(t, logs, provider)
	rule := cronRule
	rule.Benign = quiet
	plan, err := b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Summary, "none of the 2 events of the clean logs") {
		t.Fatalf("summary %q", plan.Summary)
	}
	plan.Confirm()
	result, err := plan.Run(context.Background(), nil)
	if err != nil || !result.Complete || !strings.Contains(result.Report, "| 1 | accepted | 1 of 1 |") || !strings.Contains(result.Report, "0 of 2 |") {
		t.Fatalf("result %v:\n%s", err, result.Report)
	}

	noisy := cleanFolder(t, "auth.log", backup, example)
	provider = &analystProvider{answer: cronRuleAnswer}
	b = ruleBackend(t, logs, provider)
	rule.Benign = quiet + " , " + noisy
	plan, err = b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	plan.Confirm()
	result, err = plan.Run(context.Background(), nil)
	if err != nil || result.Complete || len(provider.sent) != 3 || !strings.Contains(result.Report, "1 events of the logs that the user gave as clean") {
		t.Fatalf("result %v, sent %d:\n%s", err, len(provider.sent), result.Report)
	}
	if _, err := os.Stat(filepath.Join(result.SavedTo, "rule.yml")); !os.IsNotExist(err) {
		t.Fatal("a rule that matches the clean logs was written")
	}
	if !strings.Contains(provider.sent[1].Messages[2].Text, "logs that the user gave as clean") {
		t.Fatal("the reason was not sent back")
	}
}

func TestHomeRuleDraftRefusesBadCleanLogsBeforeAnythingIsSent(t *testing.T) {
	logs := campaignFolder(t)
	home := t.TempDir()
	inHome := filepath.Join(home, "clean")
	if err := os.Mkdir(inHome, 0o700); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	provider := &analystProvider{answer: cronRuleAnswer}
	b := ruleBackend(t, logs, provider)
	b.env.home = homeAt(home)
	many := strings.Repeat(empty+",", maxBenign+1)
	testCases := []struct {
		name, benign, want string
	}{
		{"inside the logs", filepath.Join(logs, "web01"), "must be apart from the logs"},
		{"the logs themselves", logs, "must be apart from the logs"},
		{"around the logs", filepath.Dir(logs), "must be apart from the logs"},
		{"not there", filepath.Join(empty, "missing.log"), "cannot be read"},
		{"no events", empty, "no event could be read from the clean logs"},
		{"in the home folder, empty", "~/clean", "no event could be read from the clean logs"},
		{"too many", many, "at most 20"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			rule := cronRule
			rule.Benign = testCase.benign
			_, err := b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: rule})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %v, want %q", err, testCase.want)
			}
		})
	}
	if len(provider.sent) != 0 {
		t.Fatal("something was sent")
	}
	if _, err := os.Stat(b.config.OutputBase); !os.IsNotExist(err) {
		t.Fatal("a refused preparation wrote something")
	}
}

func TestSplitPathsKeepsSpacesAndExpandsHome(t *testing.T) {
	b := backend{env: environment{home: homeAt("/home/someone")}}
	got, err := b.splitPaths(" ~/clean logs/day one , /var/log/ok.log,, ~ ")
	if err != nil || !reflect.DeepEqual(got, []string{"/home/someone/clean logs/day one", "/var/log/ok.log", "/home/someone"}) {
		t.Fatalf("got %q %v", got, err)
	}
	if got, err := b.splitPaths("  "); err != nil || len(got) != 0 {
		t.Fatalf("empty: %q %v", got, err)
	}
	noHome := backend{env: environment{home: func() (string, error) { return "", nil }}}
	if _, err := noHome.splitPaths("~/x"); err == nil {
		t.Fatal("~ without a home folder was accepted")
	}
}
