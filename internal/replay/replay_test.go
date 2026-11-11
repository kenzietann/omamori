package replay

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/outbound"
)

const (
	fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"
	fakePhone  = "090-1234-5678"
)

type scriptedProvider struct {
	answers  []outbound.Response
	failWith error
	calls    int
}

func (provider *scriptedProvider) Name() string { return "FakeAI" }

func (provider *scriptedProvider) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	provider.calls++
	if provider.failWith != nil {
		return outbound.Response{}, provider.failWith
	}
	answer := provider.answers[(provider.calls-1)%len(provider.answers)]

	return answer, nil
}

func newSender(t testing.TB, provider outbound.Provider) *outbound.Sender {
	t.Helper()

	sender, err := outbound.New(provider, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sender.Authorize()

	return sender
}

func request(text string) outbound.Request {
	return outbound.Request{System: "system", Messages: []outbound.Message{{Role: "user", Text: text}}}
}

func goodRecording() Recording {
	return Recording{Version: Version, Source: SourceLive, Task: "exposure", Provider: "FakeAI", Model: "m",
		Steps: []Step{{RequestHash: strings.Repeat("a", 64), Answer: Answer{Text: "hello", TokensUsed: 5}}}}
}

func TestValidateChecksTheSchema(t *testing.T) {
	testCases := []struct {
		name   string
		change func(*Recording)
		valid  bool
	}{
		{"a good live recording", func(*Recording) {}, true},
		{"a scripted step without a hash", func(recording *Recording) {
			recording.Source = SourceScripted
			recording.Steps[0].RequestHash = ""
		}, true},
		{"a tool call answer", func(recording *Recording) {
			recording.Steps[0].Answer = Answer{ToolCalls: []Call{{ID: "call_1", Name: "run_detectors", Arguments: map[string]string{"path": "."}}}}
		}, true},
		{"a log name", func(recording *Recording) { recording.Log = "logs/auth.log" }, true},
		{"another version", func(recording *Recording) { recording.Version = 2 }, false},
		{"an unknown source", func(recording *Recording) { recording.Source = "magic" }, false},
		{"a task with odd characters", func(recording *Recording) { recording.Task = "Exposure!" }, false},
		{"no steps", func(recording *Recording) { recording.Steps = nil }, false},
		{"too many steps", func(recording *Recording) { recording.Steps = make([]Step, maxSteps+1) }, false},
		{"a live step without a hash", func(recording *Recording) { recording.Steps[0].RequestHash = "" }, false},
		{"a hash that is not hex", func(recording *Recording) { recording.Steps[0].RequestHash = strings.Repeat("z", 64) }, false},
		{"a short hash", func(recording *Recording) { recording.Steps[0].RequestHash = "abc" }, false},
		{"an empty answer", func(recording *Recording) { recording.Steps[0].Answer = Answer{} }, false},
		{"negative tokens", func(recording *Recording) { recording.Steps[0].Answer.TokensUsed = -1 }, false},
		{"a text that is too long", func(recording *Recording) { recording.Steps[0].Answer.Text = strings.Repeat("x", maxTextRunes+1) }, false},
		{"text that is not UTF-8", func(recording *Recording) { recording.Steps[0].Answer.Text = "a\xffb" }, false},
		{"a tool name with a space", func(recording *Recording) {
			recording.Steps[0].Answer = Answer{ToolCalls: []Call{{Name: "read file"}}}
		}, false},
		{"a tool call id with odd characters", func(recording *Recording) {
			recording.Steps[0].Answer = Answer{ToolCalls: []Call{{ID: "a b", Name: "read_file"}}}
		}, false},
		{"an argument name with odd characters", func(recording *Recording) {
			recording.Steps[0].Answer = Answer{ToolCalls: []Call{{Name: "read_file", Arguments: map[string]string{"pa th": "."}}}}
		}, false},
		{"too many tool calls", func(recording *Recording) {
			recording.Steps[0].Answer = Answer{ToolCalls: make([]Call, maxCalls+1)}
		}, false},
		{"a log name with a space", func(recording *Recording) { recording.Log = "my log" }, false},
		{"a provider name that is too long", func(recording *Recording) { recording.Provider = strings.Repeat("p", maxNameRunes+1) }, false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recording := goodRecording()
			testCase.change(&recording)

			err := recording.Validate()

			if (err == nil) != testCase.valid || (err != nil && !errors.Is(err, ErrBadRecording)) {
				t.Errorf("err = %v, want valid %v", err, testCase.valid)
			}
		})
	}
}

func TestParseRefusesUnknownFieldsAndExtraData(t *testing.T) {
	good, err := goodRecording().JSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("a recording that was written by JSON() cannot be read: %v", err)
	}

	for name, text := range map[string]string{
		"an unknown field":  strings.Replace(good, `"task"`, `"extra": 1, "task"`, 1),
		"a second document": good + good,
		"not JSON":          "hello",
		"empty":             "",
		"a list":            "[]",
		"too big":           strings.Repeat(" ", maxFileBytes+1),
	} {
		if _, err := Parse([]byte(text)); !errors.Is(err, ErrBadRecording) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestLoadReadsOnlyARegularFileThatIsNotTooBig(t *testing.T) {
	directory := t.TempDir()
	good, _ := goodRecording().JSON()
	path := filepath.Join(directory, "recording.json")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}

	if recording, err := Load(path); err != nil || recording.Task != "exposure" {
		t.Errorf("err = %v", err)
	}
	for name, target := range map[string]string{"a missing file": filepath.Join(directory, "none.json"), "a folder": directory, "a symlink": link} {
		if _, err := Load(target); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	bad := filepath.Join(directory, "bad.json")
	os.WriteFile(bad, []byte(`{"version":9}`), 0o600)
	if _, err := Load(bad); !errors.Is(err, ErrBadRecording) {
		t.Errorf("a bad recording: err = %v", err)
	}
}

func TestFingerprintChangesWithAnyPartOfTheRequest(t *testing.T) {
	base := outbound.Request{System: "s", Messages: []outbound.Message{{Role: "user", Text: "t", ToolCalls: []outbound.ToolCall{{ID: "c", Name: "n", Arguments: map[string]string{"a": "b", "c": "d"}}}}}, Tools: []outbound.ToolSpec{{Name: "x", Description: "d", Parameters: []outbound.ToolParameter{{Name: "p", Required: true}}}}}
	want := Fingerprint(base)

	if Fingerprint(base) != want || len(want) != 64 {
		t.Fatal("the fingerprint is not stable")
	}
	changes := map[string]func(*outbound.Request){
		"the system prompt": func(r *outbound.Request) { r.System = "S" },
		"a message":         func(r *outbound.Request) { r.Messages[0].Text = "T" },
		"a role":            func(r *outbound.Request) { r.Messages[0].Role = "assistant" },
		"an argument":       func(r *outbound.Request) { r.Messages[0].ToolCalls[0].Arguments["a"] = "z" },
		"a tool":            func(r *outbound.Request) { r.Tools[0].Description = "e" },
		"a parameter":       func(r *outbound.Request) { r.Tools[0].Parameters[0].Required = false },
		"one more message":  func(r *outbound.Request) { r.Messages = append(r.Messages, outbound.Message{Role: "user", Text: "x"}) },
	}
	for name, change := range changes {
		copied := base
		copied.Messages = append([]outbound.Message(nil), base.Messages...)
		copied.Messages[0].ToolCalls = []outbound.ToolCall{{ID: "c", Name: "n", Arguments: map[string]string{"a": "b", "c": "d"}}}
		copied.Tools = []outbound.ToolSpec{{Name: "x", Description: "d", Parameters: []outbound.ToolParameter{{Name: "p", Required: true}}}}
		change(&copied)

		if Fingerprint(copied) == want {
			t.Errorf("changing %s did not change the fingerprint", name)
		}
	}
}

func TestARecordedRunIsPlayedBackThroughTheRealSender(t *testing.T) {
	live := &scriptedProvider{answers: []outbound.Response{
		{ToolCalls: []outbound.ToolCall{{ID: "call_1", Name: "run_detectors", Arguments: map[string]string{"path": "."}}}, TokensUsed: 40},
		{Text: "all done", TokensUsed: 60},
	}}
	recorder := NewRecorder(live, "exposure", "model-x", "")
	liveSender := newSender(t, recorder)
	first, err := liveSender.Send(context.Background(), request("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := liveSender.Send(context.Background(), request("second"))
	if err != nil {
		t.Fatal(err)
	}

	text, err := recorder.Recording().JSON()
	if err != nil {
		t.Fatal(err)
	}
	recording, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if recording.Source != SourceLive || recording.Provider != "FakeAI" || recording.Model != "model-x" || len(recording.Steps) != 2 {
		t.Fatalf("recording = %+v", recording)
	}

	player, err := NewPlayer(recording)
	if err != nil {
		t.Fatal(err)
	}
	replaySender := newSender(t, player)
	gotFirst, err := replaySender.Send(context.Background(), request("first"))
	if err != nil || len(gotFirst.ToolCalls) != 1 || gotFirst.ToolCalls[0].Name != "run_detectors" || gotFirst.ToolCalls[0].Arguments["path"] != "." || gotFirst.TokensUsed != first.TokensUsed {
		t.Fatalf("first answer = %+v, err = %v", gotFirst, err)
	}
	gotSecond, err := replaySender.Send(context.Background(), request("second"))
	if err != nil || gotSecond.Text != second.Text || gotSecond.TokensUsed != 60 {
		t.Fatalf("second answer = %+v, err = %v", gotSecond, err)
	}
	if live.calls != 2 {
		t.Errorf("the live provider was called %d times, the replay must not call it", live.calls)
	}
	if player.Name() != "REPLAY" || player.Source() != SourceLive {
		t.Errorf("name %q, source %q", player.Name(), player.Source())
	}
}

func TestAnotherRequestStopsTheReplayAndItNeverGoesLive(t *testing.T) {
	live := &scriptedProvider{answers: []outbound.Response{{Text: "answer one"}, {Text: "answer two"}}}
	recorder := NewRecorder(live, "exposure", "m", "")
	sender := newSender(t, recorder)
	sender.Send(context.Background(), request("first"))
	sender.Send(context.Background(), request("second"))
	callsAfterRecording := live.calls

	player, _ := NewPlayer(recorder.Recording())
	replaySender := newSender(t, player)

	_, err := replaySender.Send(context.Background(), request("a different first request"))

	var providerError *outbound.ProviderError
	if !errors.As(err, &providerError) || providerError.Detail != "replay: request 1 does not match the recording" {
		t.Fatalf("err = %v", err)
	}
	if _, again := replaySender.Send(context.Background(), request("a different first request")); again == nil {
		t.Error("the mismatch was forgotten")
	}
	if _, right := replaySender.Send(context.Background(), request("first")); right != nil {
		t.Errorf("the right request is refused after a wrong one: %v", right)
	}
	if live.calls != callsAfterRecording {
		t.Error("the replay called the live provider")
	}
}

func TestARunThatAsksForMoreThanWasRecordedStopsWithAClearError(t *testing.T) {
	live := &scriptedProvider{answers: []outbound.Response{{Text: "only answer"}}}
	recorder := NewRecorder(live, "exposure", "m", "")
	newSender(t, recorder).Send(context.Background(), request("first"))
	player, _ := NewPlayer(recorder.Recording())
	sender := newSender(t, player)
	if _, err := sender.Send(context.Background(), request("first")); err != nil {
		t.Fatal(err)
	}

	_, err := sender.Send(context.Background(), request("second"))

	var providerError *outbound.ProviderError
	if !errors.As(err, &providerError) || providerError.Detail != "replay: the recording has no answer for request 2" {
		t.Errorf("err = %v", err)
	}
}

func TestAScriptedRecordingIsPlayedInOrderWithoutHashes(t *testing.T) {
	recording := Recording{Version: Version, Source: SourceScripted, Task: "exposure", Steps: []Step{
		{Answer: Answer{Text: "one"}}, {Answer: Answer{Text: "two", TokensUsed: 3}},
	}}
	player, err := NewPlayer(recording)
	if err != nil {
		t.Fatal(err)
	}
	sender := newSender(t, player)

	first, _ := sender.Send(context.Background(), request("anything"))
	second, _ := sender.Send(context.Background(), request("something else"))

	if first.Text != "one" || second.Text != "two" || player.Source() != SourceScripted {
		t.Errorf("%+v %+v", first, second)
	}
}

func TestACancelledRunGetsNoAnswer(t *testing.T) {
	player, _ := NewPlayer(Recording{Version: Version, Source: SourceScripted, Task: "exposure", Steps: []Step{{Answer: Answer{Text: "one"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := player.Send(ctx, outbound.SafeRequest{}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestTheRecorderRemovesSensitiveValuesFromTheAnswersAndKeepsFailuresOut(t *testing.T) {
	live := &scriptedProvider{answers: []outbound.Response{
		{Text: "I found " + fakeAWSKey + " and " + fakePhone, ToolCalls: []outbound.ToolCall{{ID: "c1", Name: "search_text", Arguments: map[string]string{"query": fakeAWSKey, "path": "."}}}, TokensUsed: 9},
	}}
	recorder := NewRecorder(live, "exposure", "m", "")
	sender := newSender(t, recorder)
	if _, err := sender.Send(context.Background(), request("first")); err != nil {
		t.Fatal(err)
	}
	failing := newSender(t, NewRecorder(&scriptedProvider{failWith: errors.New("boom")}, "exposure", "m", ""))
	failingRecorder := NewRecorder(&scriptedProvider{failWith: errors.New("boom")}, "exposure", "m", "")
	failing = newSender(t, failingRecorder)
	failing.Send(context.Background(), request("first"))

	text, err := recorder.Recording().JSON()
	if err != nil {
		t.Fatal(err)
	}

	for _, planted := range []string{fakeAWSKey, fakePhone} {
		if strings.Contains(text, planted) {
			t.Errorf("the recording holds %q:\n%s", planted, text)
		}
	}
	if !strings.Contains(text, "[SECRET:aws-access-key:001]") || !strings.Contains(text, "[PHONE:001]") {
		t.Errorf("the placeholders are missing:\n%s", text)
	}
	if len(failingRecorder.Recording().Steps) != 0 {
		t.Error("a failed request was recorded")
	}
}

func TestTheRecorderReturnsACopy(t *testing.T) {
	recorder := NewRecorder(&scriptedProvider{answers: []outbound.Response{{Text: "a"}}}, "exposure", "m", "")
	newSender(t, recorder).Send(context.Background(), request("first"))

	copied := recorder.Recording()
	copied.Steps[0].Answer.Text = "changed"

	if recorder.Recording().Steps[0].Answer.Text != "a" {
		t.Error("the recording of the recorder was changed from outside")
	}
}

func TestThePackageHasNoNetworkCode(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if strings.HasPrefix(path, "net") || path == "os/exec" || strings.Contains(path, "anthropic") || strings.Contains(path, "openaicompat") {
				t.Errorf("%s imports %s: the replay must make no network call", entry.Name(), path)
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	good, _ := goodRecording().JSON()
	f.Add([]byte(good))
	f.Add([]byte(`{"version":1,"source":"scripted","task":"exposure","steps":[{"answer":{"text":"x"}}]}`))
	f.Add([]byte("\x00\xff{"))

	f.Fuzz(func(t *testing.T, data []byte) {
		recording, err := Parse(data)
		if err != nil {
			return
		}
		text, err := recording.JSON()
		if err != nil {
			t.Fatalf("a recording that was read cannot be written: %v", err)
		}
		if again, err := Parse([]byte(text)); err != nil || len(again.Steps) != len(recording.Steps) {
			t.Fatalf("the round trip failed: %v", err)
		}
	})
}

func TestTheTriageSettingsOfARecordingAreChecked(t *testing.T) {
	good := Settings{WindowMinutes: 10, FailureThreshold: 5, SprayThreshold: 5, Year: 2026, TimeZone: "UTC"}
	testCases := []struct {
		name   string
		change func(*Settings)
		valid  bool
	}{
		{"good settings", func(*Settings) {}, true},
		{"a window of 0", func(s *Settings) { s.WindowMinutes = 0 }, false},
		{"a window of two days", func(s *Settings) { s.WindowMinutes = 2881 }, false},
		{"a threshold of 1", func(s *Settings) { s.FailureThreshold = 1 }, false},
		{"a spray threshold that is too big", func(s *Settings) { s.SprayThreshold = 1001 }, false},
		{"a year in the past", func(s *Settings) { s.Year = 1969 }, false},
		{"no time zone", func(s *Settings) { s.TimeZone = "" }, false},
		{"a time zone that is too long", func(s *Settings) { s.TimeZone = strings.Repeat("z", maxNameRunes+1) }, false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			settings := good
			testCase.change(&settings)
			recording := goodRecording()
			recording.Triage = &settings

			if err := recording.Validate(); (err == nil) != testCase.valid {
				t.Errorf("err = %v, want valid %v", err, testCase.valid)
			}
		})
	}
}

func TestTheSettingsAreRecordedAndSurviveTheFile(t *testing.T) {
	recorder := NewRecorder(&scriptedProvider{answers: []outbound.Response{{Text: "a"}}}, "triage", "m", "auth.log")
	recorder.SetTriage(Settings{WindowMinutes: 15, FailureThreshold: 3, SprayThreshold: 4, Year: 2025, TimeZone: "Asia/Tokyo"})
	newSender(t, recorder).Send(context.Background(), request("first"))

	text, err := recorder.Recording().JSON()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Parse([]byte(text))
	if err != nil || loaded.Triage == nil || *loaded.Triage != (Settings{WindowMinutes: 15, FailureThreshold: 3, SprayThreshold: 4, Year: 2025, TimeZone: "Asia/Tokyo"}) || loaded.Log != "auth.log" {
		t.Errorf("loaded %+v, err %v", loaded, err)
	}

	copied := recorder.Recording()
	copied.Triage.Year = 1999
	if recorder.Recording().Triage.Year != 2025 {
		t.Error("the settings of the recorder were changed from outside")
	}
	if exposure := NewRecorder(&scriptedProvider{answers: []outbound.Response{{Text: "a"}}}, "exposure", "m", ""); exposure.Recording().Triage != nil {
		t.Error("an exposure recording has triage settings")
	}
}
