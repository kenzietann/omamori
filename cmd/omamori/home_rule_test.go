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
	if _, err := b.Prepare(tui.Setup{Task: tui.TaskRuleDraft, Replay: true}); err == nil || !strings.Contains(err.Error(), "--replay") {
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
