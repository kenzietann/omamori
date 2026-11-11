package tui

import (
	"errors"
	"strings"
	"testing"
)

func TestTaskBGoesThroughTheSameSetupAndAsksTheBackendForTheTask(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", title: "Task B: Log triage", runner: finishedRunner("the report", true)}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "enter", "enter", "enter")

	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0].Task != TaskTriage || backend.setups[0].Replay {
		t.Fatalf("step = %d, setups = %+v", model.step, backend.setups)
	}

	taskA, _ := pressAll(t, newModelWith("/work/project", &fakeBackend{choices: []Choice{localChoice}, preview: "p"}, Defaults{}), "enter", "enter", "enter")
	if taskA.step != stepConsent {
		t.Fatalf("step = %d", taskA.step)
	}
}

func TestTaskBStartsDirectlyWithSavedChoicesAndPassesTheTask(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, preview: "p", runner: finishedRunner("r", true)}

	model := newModelWith("/work/project", backend, Defaults{ProviderID: "openai", Model: "gpt-x"}).WithTask(TaskTriage)

	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0] != (Setup{Task: TaskTriage, ProviderID: "openai", Model: "gpt-x"}) {
		t.Errorf("step = %d, setups = %+v", model.step, backend.setups)
	}

	blocked := newModelWith("/work/project", &fakeBackend{choices: []Choice{savedChoice}, taskReadyErr: errors.New("no log")}, Defaults{ProviderID: "openai", Model: "gpt-x"}).WithTask(TaskTriage)
	if blocked.step != stepMenu || !strings.Contains(blocked.View(), "no log") {
		t.Errorf("a task that is not ready started: step = %d", blocked.step)
	}
}

func TestTheNameOfTheTaskIsUsedOnTheRunHeaderTheStatusLineAndTheResults(t *testing.T) {
	testCases := []struct {
		name        string
		title       string
		label       string
		wantHeader  string
		wantStatus  string
		wantResults string
	}{
		{"no title means task A", "", "", "● Task A: Exposure check", "Running: Task A, exposure check", "● Results: Task A, complete"},
		{"task B", "Task B: Log triage", "", "● Task B: Log triage", "Running: Task B, log triage", "● Results: Task B, complete"},
		{"a replay", "Task A: Exposure check", "REPLAY", "● Task A: Exposure check · REPLAY", "Running: Task A, exposure check · REPLAY", "● Results: Task A, complete · REPLAY"},
		{"a scripted replay of task B", "Task B: Log triage", "REPLAY (scripted answers)", "● Task B: Log triage · REPLAY (scripted answers)", "Running: Task B, log triage · REPLAY (scripted answers)", "● Results: Task B, complete · REPLAY (scripted answers)"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", title: testCase.title, label: testCase.label, runner: finishedRunner("the report", true, "a step")}
			model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")
			started, command := press(t, model, "enter")

			if status := started.View(); !strings.Contains(status, testCase.wantStatus) {
				t.Errorf("the status line is %q, want %q", status, testCase.wantStatus)
			}
			printed := settle(started, command).Printed()
			for _, want := range []string{testCase.wantHeader, testCase.wantResults} {
				if !strings.Contains(printed, want) {
					t.Errorf("the printed text has no %q:\n%s", want, printed)
				}
			}
			if testCase.label == "" && strings.Contains(printed+started.View(), "REPLAY") {
				t.Error("a live run is labelled as a replay")
			}
		})
	}
}

func TestTheTitleAndTheLabelAreShownSafely(t *testing.T) {
	hostile := "evil\x1b[2J\u202e"
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", title: "Task Z: " + hostile, label: hostile, runner: finishedRunner("r", true)}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")
	started, command := press(t, model, "enter")
	finished := settle(started, command)

	for _, text := range []string{started.View(), finished.Printed()} {
		for _, character := range styleCodes.ReplaceAllString(text, "") {
			if character != '\n' && (character < ' ' || character == 0x1b || character == 0x202e) {
				t.Errorf("the text holds the character %U", character)
			}
		}
	}
}

func TestAReplayStartsAtTheDryRunWithoutAProviderAndSavesNoSettings(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, summary: "REPLAY SUMMARY", preview: "FULL", label: "REPLAY", consent: "This is a REPLAY. Nothing is sent to any provider.", runner: finishedRunner("the report", true)}

	model := newModelWith("/work/project", backend, Defaults{}).WithReplay()

	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0] != (Setup{Replay: true}) {
		t.Fatalf("step = %d, setups = %+v: a replay needs no provider, model or key", model.step, backend.setups)
	}
	if view := model.View(); !strings.Contains(view, "This is a REPLAY. Nothing is sent to any provider.") || !strings.Contains(view, "REPLAY SUMMARY") {
		t.Errorf("the dry run page:\n%s", view)
	}
	if len(backend.modelCalls) != 0 {
		t.Error("a replay asked for a list of models")
	}

	started, command := press(t, model, "enter")
	finished := settle(started, command)
	if backend.confirmed != 1 || len(backend.savedSettings) != 0 || !strings.Contains(finished.Printed(), "● Results: Task A, complete · REPLAY") {
		t.Errorf("confirmed %d, saved settings %+v:\n%s", backend.confirmed, backend.savedSettings, finished.Printed())
	}

	cancelled, _ := press(t, model, "esc")
	if cancelled.step != stepMenu || backend.confirmed != 1 || !strings.Contains(cancelled.View(), "Nothing was sent.") {
		t.Errorf("cancel: step = %d", cancelled.step)
	}
}

func TestAReplayThatCannotStartSaysWhyInTheMenuAndStartsNothing(t *testing.T) {
	failing := &fakeBackend{choices: []Choice{localChoice}, prepareErr: errors.New("the recording cannot be used for this task")}

	model := newModelWith("/work/project", failing, Defaults{}).WithReplay()

	if model.step != stepMenu || !strings.Contains(model.View(), "The recording cannot be replayed: the recording cannot be used for this task") || failing.confirmed != 0 {
		t.Errorf("step = %d:\n%s", model.step, model.View())
	}
	if none := New("/work", nil, Defaults{}).WithReplay(); none.step != stepMenu || !strings.Contains(none.View(), "There is nothing to replay.") {
		t.Errorf("without a backend:\n%s", none.View())
	}
}
