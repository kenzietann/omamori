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
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/triage"
	"github.com/kenzietann/omamori/internal/tui"
)

// campaignWithLists writes the campaign logs and, apart from them, its asset list and indicator list.
func campaignWithLists(t *testing.T) (logs, assetsFile, indicatorsFile string) {
	t.Helper()
	logs = campaignFolder(t)
	made := scenario.GenerateCampaign(1, time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC), true)
	lists := t.TempDir()
	assetsFile, indicatorsFile = filepath.Join(lists, "assets.yml"), filepath.Join(lists, "indicators.yml")
	for path, text := range map[string]string{assetsFile: made.Assets, indicatorsFile: made.Indicators} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return logs, assetsFile, indicatorsFile
}

func homeBackend(t *testing.T, target string, provider outbound.Provider) backend {
	t.Helper()
	home := t.TempDir()
	return backend{env: environment{home: homeAt(home)}, config: taskrun.Config{Target: target, OutputBase: filepath.Join(t.TempDir(), "reports"),
		Limits: agent.Limits{MaxTokens: 300000}, Triage: &triage.Config{Year: 2026, Location: time.UTC}, Now: func() time.Time { return detectNow },
		LookupEnv: func(string) string { return "" },
		NewProvider: func(_, _, _, _ string) (outbound.Provider, error) {
			if provider == nil {
				t.Fatal("a provider was asked for")
			}
			return provider, nil
		}}}
}

func runPlan(t *testing.T, b backend, setup tui.Setup) (tui.Plan, tui.Result) {
	t.Helper()
	plan, err := b.Prepare(setup)
	if err != nil {
		t.Fatalf("%s: %v", setup.Task, err)
	}
	plan.Confirm()
	result, err := plan.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("%s: %v", setup.Task, err)
	}
	return plan, result
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestHomeDetectUsesTheListsTheRulesAndTheFormat(t *testing.T) {
	logs, assetsFile, indicatorsFile := campaignWithLists(t)
	b := homeBackend(t, logs, nil)
	_, plain := runPlan(t, b, tui.Setup{Task: tui.TaskDetect})
	_, listed := runPlan(t, homeBackend(t, logs, nil), tui.Setup{Task: tui.TaskDetect, Options: tui.Options{Assets: assetsFile, Indicators: indicatorsFile}})
	plainAlerts, listedAlerts := readText(t, filepath.Join(plain.SavedTo, "alerts.json")), readText(t, filepath.Join(listed.SavedTo, "alerts.json"))
	if strings.Contains(plainAlerts, "intel_indicator_seen") || !strings.Contains(listedAlerts, "intel_indicator_seen") || !strings.Contains(listedAlerts, "203.0.113.80") {
		t.Fatal("the indicator list was not used")
	}

	rulesFolder := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesFolder, "cron.yml"), []byte(cronRuleFile), 0o600); err != nil {
		t.Fatal(err)
	}
	_, own := runPlan(t, homeBackend(t, logs, nil), tui.Setup{Task: tui.TaskDetect, Options: tui.Options{Rules: rulesFolder}})
	ownAlerts := readText(t, filepath.Join(own.SavedTo, "alerts.json"))
	if !strings.Contains(ownAlerts, "home_test_cron_pipe") || strings.Contains(ownAlerts, "intel_indicator") || strings.Count(ownAlerts, "\"rule\":") > strings.Count(plainAlerts, "\"rule\":") {
		t.Fatal("the rules folder did not replace the built-in rules")
	}

	if _, err := homeBackend(t, logs, nil).Prepare(tui.Setup{Task: tui.TaskDetect, Options: tui.Options{Format: "windows"}}); err == nil {
		t.Fatal("the campaign was read as Windows events")
	}
	for name, options := range map[string]tui.Options{
		"a missing asset list":     {Assets: filepath.Join(t.TempDir(), "no.yml")},
		"a missing indicator list": {Indicators: filepath.Join(t.TempDir(), "no.yml")},
		"an empty rules folder":    {Rules: t.TempDir()},
		"a missing rules folder":   {Rules: filepath.Join(t.TempDir(), "none")},
	} {
		if _, err := b.Prepare(tui.Setup{Task: tui.TaskDetect, Options: options}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

const cronRuleFile = `title: Home test cron pipe
name: home_test_cron_pipe
level: high
logsource: {product: linux, service: cron}
detection:
  pipe:
    command|contains|all: [curl, '| sh']
  condition: pipe
tests:
  - name: hit
    events: [{product: linux, service: cron, command: "curl x | sh"}]
    expect: {alerts: 1}
  - name: miss
    events: [{product: linux, service: cron, command: "curl x"}]
    expect: {alerts: 0}
`

func TestHomeStoreOpensTheDatabaseOnlyForTheRun(t *testing.T) {
	logs := campaignFolder(t)
	b := homeBackend(t, logs, nil)
	home, _ := b.env.home()
	database := filepath.Join(home, "omamori-data", "omamori.db")
	plan, err := b.Prepare(tui.Setup{Task: tui.TaskDetect, Options: tui.Options{Store: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Summary, database) || !plan.Local {
		t.Fatalf("summary %q, local %v", plan.Summary, plan.Local)
	}
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatal("the preparation made the database")
	}
	plan.Confirm()
	result, err := plan.Run(context.Background(), nil)
	if err != nil || !strings.Contains(result.Report, "Stored run: ") {
		t.Fatalf("detect with storage: %v", err)
	}

	provider := &analystProvider{}
	analyst := homeBackend(t, logs, provider)
	analyst.env = b.env
	review, err := analyst.Prepare(tui.Setup{Task: tui.TaskAnalyze, ProviderID: "openai", Model: "test", Key: "k", Options: tui.Options{Store: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := review.Run(context.Background(), nil); err == nil || len(provider.sent) != 0 {
		t.Fatal("an unconfirmed review with storage ran")
	}
	review.Confirm()
	reviewed, err := review.Run(context.Background(), nil)
	if err != nil || len(provider.sent) != 1 || !strings.Contains(reviewed.Report, "Stored run: ") {
		t.Fatalf("analyze with storage: %v, sent %d", err, len(provider.sent))
	}

	db, err := store.Open(context.Background(), store.Config{Driver: "sqlite", DSN: database})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	runs, err := db.ListRuns(context.Background(), store.Query{Limit: 10})
	if err != nil || len(runs) != 2 {
		t.Fatalf("stored runs: %d %v", len(runs), err)
	}
}

func TestHomeAnalyzeReplaysARecordingWithoutAProvider(t *testing.T) {
	logs, snapshot := analystFixture(t, true)
	provider := &analystProvider{answer: analystAnswers(t, snapshot)}
	tokyo := &triage.Config{Year: 2026, Location: time.FixedZone("JST", 9*3600)}
	first := homeBackend(t, logs, provider)
	first.config.Triage = tokyo
	_, live := runPlan(t, first, tui.Setup{Task: tui.TaskAnalyze, ProviderID: "openai", Model: "test", Key: "k"})
	if !live.Complete {
		t.Fatal("the live review is incomplete")
	}
	recording := filepath.Join(live.SavedTo, "recording.json")

	again := homeBackend(t, logs, nil)
	again.config.Triage = tokyo
	plan, err := again.Prepare(tui.Setup{Task: tui.TaskAnalyze, Replay: true, Options: tui.Options{Recording: recording}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Label != "REPLAY" || !strings.HasPrefix(plan.ConsentText, "REPLAY") {
		t.Fatalf("label %q, consent %q", plan.Label, plan.ConsentText)
	}
	plan.Confirm()
	replayed, err := plan.Run(context.Background(), nil)
	if err != nil || !replayed.Complete || len(provider.sent) != 1 {
		t.Fatalf("replay %+v %v", replayed, err)
	}
	if _, err := again.Prepare(tui.Setup{Task: tui.TaskAnalyze, Replay: true}); err == nil {
		t.Fatal("a replay without a recording was accepted")
	}
	if _, err := again.Prepare(tui.Setup{Task: tui.TaskDetect, Replay: true, Options: tui.Options{Recording: recording}}); err == nil {
		t.Fatal("a replay of a task without AI was accepted")
	}
}

func TestHomeForensicsReadsTheSnapshotsAndVerifyChecksTheHashes(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "host")
	if err := scenario.WriteHost(folder, scenario.GenerateHost(3, time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), true)); err != nil {
		t.Fatal(err)
	}
	system := filepath.Join(folder, "root")
	without, err := homeBackend(t, system, nil).Prepare(tui.Setup{Task: tui.TaskForensics})
	if err != nil {
		t.Fatal(err)
	}
	snapshots := tui.Options{Processes: filepath.Join(folder, "snapshots", "ps.txt"), Sockets: filepath.Join(folder, "snapshots", "ss.txt")}
	with, result := runPlan(t, homeBackend(t, system, nil), tui.Setup{Task: tui.TaskForensics, Options: snapshots})
	if with.Summary == without.Summary || !strings.Contains(result.Report, "ps.txt") {
		t.Fatalf("the snapshots were not read:\n%s\n%s", without.Summary, with.Summary)
	}
	if _, err := homeBackend(t, system, nil).Prepare(tui.Setup{Task: tui.TaskForensics, Options: tui.Options{Processes: filepath.Join(system, "nope.txt")}}); err == nil {
		t.Fatal("a missing ps file was accepted")
	}

	manifest := filepath.Join(result.SavedTo, "manifest.json")
	verify := homeBackend(t, system, nil)
	plan, checked := runPlan(t, verify, tui.Setup{Task: tui.TaskVerify, Options: tui.Options{Manifest: manifest}})
	if !plan.Local || !checked.Complete || checked.SavedTo != "" || !strings.Contains(checked.Report, " 0 are not as the manifest says") {
		t.Fatalf("verify:\n%s", checked.Report)
	}
	if err := os.WriteFile(filepath.Join(system, "etc", "crontab"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, changed := runPlan(t, verify, tui.Setup{Task: tui.TaskVerify, Options: tui.Options{Manifest: manifest}})
	if changed.Complete || !strings.Contains(changed.Report, "etc/crontab") {
		t.Fatalf("a changed file was not found:\n%s", changed.Report)
	}
	if _, err := verify.Prepare(tui.Setup{Task: tui.TaskVerify, Options: tui.Options{Manifest: filepath.Join(t.TempDir(), "none.json")}}); err == nil {
		t.Fatal("a missing manifest was accepted")
	}
}

func TestHomeDemoMakesEveryKind(t *testing.T) {
	target := t.TempDir()
	testCases := []struct {
		kind  string
		files []string
	}{
		{"", []string{"logs/auth.log", "host/root/etc/crontab", "host/snapshots/ps.txt"}},
		{"benign", []string{"logs/auth.log", "host/root/etc/crontab"}},
		{"campaign", []string{"logs/web01/auth.log", "logs/sensor/eve.json", "assets.yml", "indicators.yml", "expected.json"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.kind, func(t *testing.T) {
			_, result := runPlan(t, homeBackend(t, target, nil), tui.Setup{Task: tui.TaskDemo, Options: tui.Options{Kind: testCase.kind, Seed: "5"}})
			for _, name := range testCase.files {
				if _, err := os.Stat(filepath.Join(result.SavedTo, filepath.FromSlash(name))); err != nil {
					t.Errorf("missing %s", name)
				}
			}
		})
	}
	attack, err := os.ReadFile(filepath.Join(homeOutput(t, target, ""), "logs", "auth.log"))
	if err != nil {
		t.Fatal(err)
	}
	quiet, err := os.ReadFile(filepath.Join(homeOutput(t, target, "benign"), "logs", "auth.log"))
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(attack, quiet) {
		t.Fatal("the day without attacks is the same as the day with them")
	}
	for _, options := range []tui.Options{{Seed: "seven"}, {Kind: "other"}} {
		if _, err := homeBackend(t, target, nil).Prepare(tui.Setup{Task: tui.TaskDemo, Options: options}); err == nil {
			t.Errorf("%+v was accepted", options)
		}
	}
}

func homeOutput(t *testing.T, target, kind string) string {
	t.Helper()
	_, result := runPlan(t, homeBackend(t, target, nil), tui.Setup{Task: tui.TaskDemo, Options: tui.Options{Kind: kind, Seed: "5"}})
	return result.SavedTo
}

func TestHomeRuleDraftTakesTheOptionsAndReplays(t *testing.T) {
	logs, assetsFile, indicatorsFile := campaignWithLists(t)
	refused := strings.Replace(cronRuleAnswer, "expect: {alerts: 1}", "expect: {alerts: 3}", 1)
	provider := &analystProvider{answer: refused}
	plan, result := runPlan(t, homeBackend(t, logs, provider), tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: cronRule,
		Options: tui.Options{Attempts: "1", Assets: assetsFile, Indicators: indicatorsFile, Format: ""}})
	if plan.MaxRequests != 1 || result.Complete || len(provider.sent) != 1 {
		t.Fatalf("one answer: max %d, sent %d", plan.MaxRequests, len(provider.sent))
	}
	if _, err := homeBackend(t, logs, provider).Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: cronRule, Options: tui.Options{Attempts: "9"}}); err == nil {
		t.Fatal("nine answers were accepted")
	}
	if _, err := homeBackend(t, logs, provider).Prepare(tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: cronRule, Options: tui.Options{Format: "windows"}}); err == nil {
		t.Fatal("the campaign was read as Windows events")
	}

	provider = &analystProvider{answer: cronRuleAnswer}
	_, live := runPlan(t, homeBackend(t, logs, provider), tui.Setup{Task: tui.TaskRuleDraft, ProviderID: "openai", Model: "test", Key: "k", Rule: cronRule})
	if !live.Complete {
		t.Fatal("the live draft was refused")
	}
	replayPlan, replayed := runPlan(t, homeBackend(t, logs, nil), tui.Setup{Task: tui.TaskRuleDraft, Replay: true, Rule: cronRule,
		Options: tui.Options{Recording: filepath.Join(live.SavedTo, "recording.json")}})
	if replayPlan.Label != "REPLAY" || replayPlan.MaxRequests != 1 || !replayed.Complete || readText(t, filepath.Join(replayed.SavedTo, "rule.yml")) != readText(t, filepath.Join(live.SavedTo, "rule.yml")) {
		t.Fatalf("the replay: label %q, %+v", replayPlan.Label, replayed)
	}
}

func TestExpandPath(t *testing.T) {
	b := backend{env: environment{home: homeAt("/home/someone")}}
	working, _ := os.Getwd()
	for text, want := range map[string]string{" ~/a b/c.yml ": "/home/someone/a b/c.yml", "~": "/home/someone", "rel/x.yml": filepath.Join(working, "rel", "x.yml"), "/abs/y": "/abs/y"} {
		if got, err := b.expandPath(text); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", text, got, err, want)
		}
	}
	if _, err := b.expandPath("  "); err == nil {
		t.Fatal("an empty path was accepted")
	}
}
