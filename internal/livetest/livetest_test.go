package livetest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const fixtures = "../../testdata/fixtures"

// fakeAI answers like a good AI, or like a lazy one that finds nothing.
type fakeAI struct {
	lazy   bool
	tokens int
}

func (provider *fakeAI) Name() string { return "FakeAI" }

func (provider *fakeAI) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	request := safe.Request()
	instruction := request.Messages[0].Text
	for _, message := range request.Messages {
		if message.Role == "user" {
			instruction = message.Text
			break
		}
	}
	used := provider.tokens * len(request.Messages)

	if strings.Contains(instruction, "sshd log") {
		return outbound.Response{Text: provider.claims(instruction), TokensUsed: used}, nil
	}
	if len(request.Messages) == 1 && !provider.lazy {
		return outbound.Response{ToolCalls: []outbound.ToolCall{{ID: "c1", Name: "run_detectors", Arguments: map[string]string{"path": "."}}}, TokensUsed: used}, nil
	}

	return outbound.Response{Text: "done", TokensUsed: used}, nil
}

func (provider *fakeAI) claims(instruction string) string {
	if provider.lazy {
		return "BEGIN_CLAIMS\n[]\nEND_CLAIMS"
	}
	for _, log := range []string{"guessing.log", "spraying.log", "benign.log", "malformed.log"} {
		if !strings.Contains(instruction, `"`+log+`"`) {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(fixtures, "triage", "expected_findings.json"))
		var all map[string]json.RawMessage
		_ = json.Unmarshal(data, &all)

		return "BEGIN_CLAIMS\n" + string(all[log]) + "\nEND_CLAIMS"
	}

	return "BEGIN_CLAIMS\n[]\nEND_CLAIMS"
}

func options(t testing.TB, provider *fakeAI, runs, tokenCap int) Options {
	t.Helper()

	return Options{
		Config: taskrun.Config{
			Limits:      agent.Limits{MaxSteps: 10, MaxTokens: 100000},
			LookupEnv:   func(name string) string { return map[string]string{"OPENAI_API_KEY": "sk-fake-key-for-tests"}[name] },
			Now:         func() time.Time { return time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC) },
			NewProvider: func(id, key, model, reasoning string) (outbound.Provider, error) { return provider, nil },
		},
		ProviderID: "openai", Model: "fake-model", Fixtures: fixtures, Runs: runs, TokenCap: tokenCap, OutputBase: t.TempDir(),
	}
}

func TestAGoodAIPassesEveryCase(t *testing.T) {
	provider := &fakeAI{tokens: 100}

	summary, err := Run(context.Background(), options(t, provider, 2, 1000000))
	if err != nil {
		t.Fatal(err)
	}

	if len(summary.Cases) != 5 {
		t.Fatalf("%d cases, want 5", len(summary.Cases))
	}
	for _, result := range summary.Cases {
		if len(result.Runs) != 2 {
			t.Errorf("%s: %d runs, want 2", result.Case.Name, len(result.Runs))
		}
		for _, run := range result.Runs {
			if !run.Verdict.Passed || run.Error != "" || run.Requests == 0 || run.Tokens == 0 {
				t.Errorf("%s: %+v", result.Case.Name, run)
			}
		}
	}
	if summary.TotalTokens == 0 || summary.CapReached {
		t.Errorf("tokens %d, cap reached %v", summary.TotalTokens, summary.CapReached)
	}
}

func TestALazyAIFailsTheCasesWithFindings(t *testing.T) {
	provider := &fakeAI{lazy: true, tokens: 100}

	summary, err := Run(context.Background(), options(t, provider, 1, 1000000))
	if err != nil {
		t.Fatal(err)
	}

	passed := map[string]bool{}
	for _, result := range summary.Cases {
		passed[result.Case.Name] = result.Runs[0].Verdict.Passed
	}
	want := map[string]bool{"Task A: exposure fixture": false, "Task B: guessing.log": false, "Task B: spraying.log": false, "Task B: benign.log": true, "Task B: malformed.log": false}
	for name, wantPassed := range want {
		if passed[name] != wantPassed {
			t.Errorf("%s: passed = %v, want %v", name, passed[name], wantPassed)
		}
	}
}

func TestTheTokenCapStopsTheSeries(t *testing.T) {
	provider := &fakeAI{tokens: 100}

	summary, err := Run(context.Background(), options(t, provider, 3, 450))
	if err != nil {
		t.Fatal(err)
	}

	skipped := 0
	for _, result := range summary.Cases {
		skipped += result.Skipped
	}
	if !summary.CapReached || skipped == 0 {
		t.Errorf("cap reached %v, skipped %d", summary.CapReached, skipped)
	}
	if summary.TotalTokens > 450+300 {
		t.Errorf("%d tokens used with a cap of 450", summary.TotalTokens)
	}
}

func TestBadOptionsAreRefused(t *testing.T) {
	provider := &fakeAI{}
	for _, mutate := range []func(*Options){
		func(o *Options) { o.Runs = 0 },
		func(o *Options) { o.TokenCap = 0 },
		func(o *Options) { o.Fixtures = filepath.Join(t.TempDir(), "missing") },
	} {
		current := options(t, provider, 1, 1000)
		mutate(&current)
		if _, err := Run(context.Background(), current); err == nil {
			t.Error("bad options were accepted")
		}
	}
}

func TestTheTableHoldsNumbersAndFixedWordsOnly(t *testing.T) {
	provider := &fakeAI{tokens: 100}
	summary, err := Run(context.Background(), options(t, provider, 1, 1000000))
	if err != nil {
		t.Fatal(err)
	}

	text := summary.Markdown(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC))

	for _, want := range []string{"| Task A: exposure fixture | 1 of 1 |", "| Task B: benign.log | 1 of 1 |", "Model: fake-model", "Date: 2026-11-12", "Tokens used in all runs:"} {
		if !strings.Contains(text, want) {
			t.Errorf("the table has no %q:\n%s", want, text)
		}
	}
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "090-1234-5678", "sk-fake-key-for-tests"} {
		if strings.Contains(text, secret) {
			t.Errorf("the table holds %q", secret)
		}
	}
}

func TestResultsAreWrittenToANewFileOnly(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "series")
	date := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)

	path, err := WriteResults(folder, "one", date)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteResults(folder, "two", date); err == nil {
		t.Error("an existing file was overwritten")
	}
	if data, _ := os.ReadFile(path); string(data) != "one" {
		t.Errorf("the file holds %q", data)
	}
}

func TestScoringReadsTheReportsExactly(t *testing.T) {
	expected, err := LoadExposure(filepath.Join(fixtures, "exposure", "expected_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	report := "## Findings\n\n| ID | Severity | Type | File | Line |\n|---|---|---|---|---|\n"
	for _, want := range expected {
		report += "| " + want + " |\n"
	}

	if verdict := ScoreExposure(report, expected); !verdict.Passed {
		t.Errorf("an exact report: %+v", verdict)
	}
	if verdict := ScoreExposure(strings.Replace(report, "| 3 |", "| 4 |", 1), expected); verdict.Passed || !strings.Contains(verdict.Detail, "1 missing, 1 extra") {
		t.Errorf("a wrong line: %+v", verdict)
	}
	if verdict := ScoreExposure(report+"| [PHONE:003] | medium | phone | x.txt | 1 |\n", expected); verdict.Passed {
		t.Errorf("an extra finding passed: %+v", verdict)
	}

	triageReport := "## Verified findings (checked by Omamori)\n\n| T-001 | a |\n| T-002 | a |\n\n## Claims of the AI\n\n2 claims\n\n## Found by Omamori, not claimed by the AI\n\nNone.\n"
	if verdict := ScoreTriage(triageReport, 2); !verdict.Passed {
		t.Errorf("a good triage: %+v", verdict)
	}
	if verdict := ScoreTriage(triageReport, 3); verdict.Passed {
		t.Errorf("a missed finding passed: %+v", verdict)
	}
	rejected := strings.Replace(triageReport, "2 claims\n", "2 claims\n\n- Claim 1: nope\n", 1)
	if verdict := ScoreTriage(rejected, 2); verdict.Passed {
		t.Errorf("a rejected claim passed: %+v", verdict)
	}
	missed := strings.Replace(triageReport, "None.", "| M-001 | a |", 1)
	if verdict := ScoreTriage(missed, 2); verdict.Passed {
		t.Errorf("a finding that the AI did not claim passed: %+v", verdict)
	}
}
