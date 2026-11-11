package taskrun

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/replay"
)

type refusingTransport struct{ calls atomic.Int32 }

func (transport *refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)

	return nil, errors.New("the network must not be used")
}

// liveRecording runs the exposure check with a scripted provider and returns the recording that the run saved.
func liveRecording(t *testing.T, setup testSetup) (replay.Recording, Result) {
	t.Helper()

	session := setup.session(t)
	session.Confirm()
	result, err := session.Run(context.Background(), func(string) {})
	if err != nil || !result.Complete {
		t.Fatalf("the live run: complete %v, err %v", result.Complete, err)
	}
	recording, err := replay.Load(filepath.Join(result.SavedTo, "recording.json"))
	if err != nil {
		t.Fatalf("the saved recording cannot be read: %v", err)
	}

	return recording, result
}

func replayConfig(setup testSetup) Config {
	config := setup.config
	config.OutputBase = filepath.Join(filepath.Dir(setup.output), "replay-out")
	config.NewProvider = func(id, key, model, reasoning string) (outbound.Provider, error) {
		return nil, errors.New("a replay must not build a provider")
	}

	return config
}

func TestALiveRunSavesARecordingOfEveryAnswerWithoutPlantedValues(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("I found 5 problems."))

	recording, _ := liveRecording(t, setup)

	if recording.Source != replay.SourceLive || recording.Task != "exposure" || recording.Provider != "FakeAI" || recording.Model != "claude-opus-5-5" || len(recording.Steps) != 2 {
		t.Fatalf("recording = %+v", recording)
	}
	if recording.Steps[0].Answer.ToolCalls[0].Name != "run_detectors" || recording.Steps[1].Answer.Text != "I found 5 problems." {
		t.Errorf("the answers are wrong: %+v", recording.Steps)
	}
	for _, step := range recording.Steps {
		if len(step.RequestHash) != 64 {
			t.Errorf("a step has the hash %q", step.RequestHash)
		}
	}
	for name, content := range outputFiles(t, filepath.Dir(setup.output)) {
		for _, planted := range plantedValues {
			if strings.Contains(content, planted) {
				t.Errorf("%s holds the planted value %q", name, planted)
			}
		}
	}
}

func TestARecordedRunIsReplayedThroughTheRealPipelineWithoutTheNetworkOrAProvider(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("I found 5 problems."))
	recording, live := liveRecording(t, setup)

	transport := &refusingTransport{}
	previousTransport, previousClient := http.DefaultTransport, http.DefaultClient
	http.DefaultTransport = transport
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultTransport, http.DefaultClient = previousTransport, previousClient })

	config := replayConfig(setup)
	session, err := Prepare(config, Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	if session.Label() != "REPLAY" || !strings.Contains(session.ConsentText(), "REPLAY") || !strings.Contains(session.ConsentText(), "Nothing is sent to any provider.") {
		t.Errorf("label %q, consent %q", session.Label(), session.ConsentText())
	}
	summary, _ := session.Summary()
	preview, _ := session.Preview()
	for _, text := range []string{summary, preview} {
		if !strings.Contains(text, "REPLAY") || !strings.Contains(text, "Nothing is sent") && !strings.Contains(text, "nothing is sent") {
			t.Errorf("a dry run text does not say that it is a replay:\n%s", text)
		}
		if strings.Contains(text, "Provider: FakeAI") {
			t.Errorf("a replay names a provider:\n%s", text)
		}
	}

	session.Confirm()
	var steps []string
	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil || !result.Complete {
		t.Fatalf("complete %v, err %v, steps %q", result.Complete, err, steps)
	}

	if transport.calls.Load() != 0 {
		t.Errorf("the replay made %d network attempts", transport.calls.Load())
	}
	if !strings.HasPrefix(filepath.Base(result.SavedTo), "replay-") || !strings.HasPrefix(result.Report, "**REPLAY: recorded answers were played back. Nothing was sent.**\n\n# Omamori report: exposure check") {
		t.Errorf("saved to %q, report starts with %q", result.SavedTo, result.Report[:min(len(result.Report), 120)])
	}
	if strings.TrimPrefix(result.Report, "**REPLAY: recorded answers were played back. Nothing was sent.**\n\n") != live.Report {
		t.Error("the replayed report differs from the report of the live run: the same pipeline must give the same findings")
	}
	if len(setup.provider.recorded) != 2 {
		t.Errorf("the live provider got %d requests in total, the replay must add none", len(setup.provider.recorded))
	}
	files := outputFiles(t, config.OutputBase)
	if len(files) != 3 {
		t.Errorf("a replay writes the report (two forms) and the log only, got %d files", len(files))
	}
}

func TestAReplayStopsWhenTheProjectChangedAndNeverGoesLive(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("done"))
	project := filepath.Join(t.TempDir(), "project")
	copyTree(t, setup.project, project)
	setup.project, setup.config.Target = project, project
	recording, _ := liveRecording(t, setup)
	if err := os.WriteFile(filepath.Join(setup.project, "app", "new_secret.txt"), []byte("token ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE9\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	session, err := Prepare(replayConfig(setup), Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	session.Confirm()
	var steps []string
	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })

	if err != nil || result.Complete {
		t.Fatalf("complete %v, err %v", result.Complete, err)
	}
	if !strings.Contains(strings.Join(steps, "\n"), "run finished: provider failed (replay: request 2 does not match the recording)") {
		t.Errorf("the stop is not explained:\n%s", strings.Join(steps, "\n"))
	}
	if len(setup.provider.recorded) != 2 {
		t.Errorf("the live provider was used again: %d requests", len(setup.provider.recorded))
	}
}

func TestAReplayStopsWhenTheRecordingRunsOut(t *testing.T) {
	recording := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "exposure", Steps: []replay.Step{
		{Answer: replay.Answer{ToolCalls: []replay.Call{{ID: "call_1", Name: "run_detectors", Arguments: map[string]string{"path": "."}}}}},
	}}
	setup := newSetup(t)
	session, err := Prepare(replayConfig(setup), Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	session.Confirm()

	var steps []string
	result, _ := session.Run(context.Background(), func(text string) { steps = append(steps, text) })

	if result.Complete || !strings.Contains(strings.Join(steps, "\n"), "replay: the recording has no answer for request 2") {
		t.Errorf("complete %v, steps:\n%s", result.Complete, strings.Join(steps, "\n"))
	}
}

func TestAScriptedRecordingIsLabelledAndWorks(t *testing.T) {
	recording := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "exposure", Steps: []replay.Step{
		{Answer: replay.Answer{ToolCalls: []replay.Call{{ID: "call_1", Name: "run_detectors", Arguments: map[string]string{"path": "."}}}}},
		{Answer: replay.Answer{Text: "A scripted summary."}},
	}}
	setup := newSetup(t)
	session, err := Prepare(replayConfig(setup), Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	session.Confirm()

	result, err := session.Run(context.Background(), func(string) {})

	if err != nil || !result.Complete || session.Label() != "REPLAY (scripted answers)" || !strings.HasPrefix(result.Report, "**REPLAY (scripted answers):") || !strings.Contains(result.Report, "A scripted summary.") {
		t.Errorf("complete %v, err %v, label %q, report:\n%s", result.Complete, err, session.Label(), result.Report)
	}
}

func TestTheStepLimitStillAppliesToAReplay(t *testing.T) {
	recording := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "exposure", Steps: []replay.Step{
		{Answer: replay.Answer{ToolCalls: []replay.Call{{ID: "c1", Name: "list_dir", Arguments: map[string]string{"path": "."}}}}},
		{Answer: replay.Answer{ToolCalls: []replay.Call{{ID: "c2", Name: "list_dir", Arguments: map[string]string{"path": "."}}}}},
		{Answer: replay.Answer{Text: "done"}},
	}}
	setup := newSetup(t)
	config := replayConfig(setup)
	config.Limits = agent.Limits{MaxSteps: 1, MaxTokens: 100000}
	session, err := Prepare(config, Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	session.Confirm()

	var steps []string
	result, _ := session.Run(context.Background(), func(text string) { steps = append(steps, text) })

	if result.Complete || !strings.Contains(strings.Join(steps, "\n"), "step limit reached") {
		t.Errorf("complete %v, steps:\n%s", result.Complete, strings.Join(steps, "\n"))
	}
}

func TestAReplayNeedsConfirmationLikeALiveRun(t *testing.T) {
	recording := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "exposure", Steps: []replay.Step{{Answer: replay.Answer{Text: "x"}}}}
	setup := newSetup(t)
	session, _ := Prepare(replayConfig(setup), Setup{Recording: &recording})

	if _, err := session.Run(context.Background(), func(string) {}); !errors.Is(err, ErrNotConfirmed) {
		t.Errorf("err = %v", err)
	}
}

func TestARecordingThatIsNotUsableIsRefusedWithAFixedError(t *testing.T) {
	setup := newSetup(t)
	for name, recording := range map[string]replay.Recording{
		"a recording that is not valid": {Version: 9},
		"a task that does not exist":    {Version: replay.Version, Source: replay.SourceScripted, Task: "magic", Steps: []replay.Step{{Answer: replay.Answer{Text: "x"}}}},
	} {
		session, err := Prepare(replayConfig(setup), Setup{Recording: &recording})

		if err != ErrRecording || session != nil {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	good := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "exposure", Steps: []replay.Step{{Answer: replay.Answer{Text: "x"}}}}
	config := replayConfig(setup)
	config.Target = "/no/such/folder/anywhere"
	if _, err := Prepare(config, Setup{Recording: &good}); !errors.Is(err, ErrTarget) {
		t.Errorf("a folder that is not there: %v", err)
	}
	if _, err := Prepare(setup.config, Setup{Task: "magic", ProviderID: "anthropic", Key: testKey}); err != ErrUnknownTask {
		t.Errorf("an unknown task: %v", err)
	}
}
