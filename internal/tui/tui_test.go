package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"
)

var keyMessages = map[string]tea.KeyMsg{
	"up":        {Type: tea.KeyUp},
	"down":      {Type: tea.KeyDown},
	"enter":     {Type: tea.KeyEnter},
	"backspace": {Type: tea.KeyBackspace},
	"esc":       {Type: tea.KeyEsc},
	"pgup":      {Type: tea.KeyPgUp},
	"pgdown":    {Type: tea.KeyPgDown},
	"ctrl+c":    {Type: tea.KeyCtrlC},
	"q":         {Type: tea.KeyRunes, Runes: []rune{'q'}},
	"b":         {Type: tea.KeyRunes, Runes: []rune{'b'}},
	"n":         {Type: tea.KeyRunes, Runes: []rune{'n'}},
	"y":         {Type: tea.KeyRunes, Runes: []rune{'y'}},
	"x":         {Type: tea.KeyRunes, Runes: []rune{'x'}},
}

func press(t testing.TB, model Model, key string) (Model, tea.Cmd) {
	t.Helper()

	message, known := keyMessages[key]
	if !known {
		t.Fatalf("unknown key %q", key)
	}
	updated, command := model.Update(message)

	return updated.(Model), command
}

func isQuit(command tea.Cmd) bool {
	if command == nil {
		return false
	}
	_, quits := command().(tea.QuitMsg)

	return quits
}

// settle runs commands and feeds their messages back into the model, the way the Bubble Tea
// program does, until no command is left.
func settle(model Model, command tea.Cmd) Model {
	queue := []tea.Cmd{command}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			continue
		}

		message := current()
		if batch, isBatch := message.(tea.BatchMsg); isBatch {
			queue = append(queue, batch...)
			continue
		}

		updated, next := model.Update(message)
		model = updated.(Model)
		queue = append(queue, next)
	}

	return model
}

func finishedRunner(report string, complete bool, steps ...string) Runner {
	return func(ctx context.Context, step func(string)) (Result, error) {
		for _, text := range steps {
			step(text)
		}

		return Result{Report: report, Complete: complete}, nil
	}
}

func lastLine(view string) string {
	lines := strings.Split(view, "\n")

	return lines[len(lines)-1]
}

type modelCall struct {
	providerID string
	key        string
}

type fakeBackend struct {
	consent    string
	choices    []Choice
	runner     Runner
	prepareErr error
	preview    string
	setups     []Setup
	confirmed  int
	// models is the list the provider gives. nil means a short default list, and an empty list means none.
	models     []string
	modelsErr  error
	modelCalls []modelCall
	// reasoning is what the model offers. nil means no choice, and then the step is skipped.
	reasoning       []ReasoningChoice
	reasoningModels []string
}

func (backend *fakeBackend) ReasoningChoices(providerID, model string) []ReasoningChoice {
	backend.reasoningModels = append(backend.reasoningModels, model)

	return backend.reasoning
}

func (backend *fakeBackend) Providers() []Choice { return backend.choices }

func (backend *fakeBackend) Models(ctx context.Context, providerID, key string) ([]string, error) {
	backend.modelCalls = append(backend.modelCalls, modelCall{providerID, key})
	if backend.modelsErr != nil {
		return nil, backend.modelsErr
	}
	if backend.models == nil {
		return []string{"m", "other-model"}, nil
	}

	return backend.models, nil
}

func (backend *fakeBackend) Prepare(setup Setup) (Plan, error) {
	backend.setups = append(backend.setups, setup)
	if backend.prepareErr != nil {
		return Plan{}, backend.prepareErr
	}

	consent := backend.consent
	if consent == "" {
		consent = "Omamori will send sanitized content to FakeAI during this run."
	}

	return Plan{
		ConsentText: consent,
		Preview:     backend.preview,
		Confirm:     func() { backend.confirmed++ },
		Run:         backend.runner,
	}, nil
}

var localChoice = Choice{ID: "fake", Name: "FakeAI", Local: true, DefaultModel: "m"}

func newModelWith(target string, backend *fakeBackend, defaults Defaults) Model {
	return New(target, backend, defaults)
}

func newModel(target string, runner Runner) Model {
	return New(target, &fakeBackend{choices: []Choice{localChoice}, runner: runner, preview: "first request text"}, Defaults{})
}

// beginRun goes through the whole setup of a provider that needs no key: choose Task A, accept the
// provider, pick the default model from the list, and confirm on the consent screen.
func beginRun(t testing.TB, model Model) (Model, tea.Cmd) {
	t.Helper()

	return pressAll(t, model, "enter", "enter", "enter", "enter")
}

func startedRun(t testing.TB, runner Runner) (Model, tea.Cmd) {
	t.Helper()

	return beginRun(t, newModel("/work/project", runner))
}

func TestHomeMenuMovesAndStaysInsideTheMenu(t *testing.T) {
	testCases := []struct {
		name       string
		keys       []string
		wantCursor int
	}{
		{"start", nil, 0},
		{"down", []string{"down"}, 1},
		{"down to the end and past it", []string{"down", "down", "down", "down"}, 2},
		{"up at the top", []string{"up"}, 0},
		{"down then up", []string{"down", "down", "up"}, 1},
		{"other keys do nothing", []string{"b", "pgup", "esc"}, 0},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			model := newModel("/work/project", nil)
			for _, key := range testCase.keys {
				model, _ = press(t, model, key)
			}

			if model.cursor != testCase.wantCursor || model.screen != homeScreen {
				t.Errorf("cursor = %d, screen = %d, want %d on the home screen", model.cursor, model.screen, testCase.wantCursor)
			}
		})
	}
}

func pressAll(t testing.TB, model Model, keys ...string) (Model, tea.Cmd) {
	t.Helper()

	var command tea.Cmd
	for _, key := range keys {
		model, command = press(t, model, key)
		// The list of models comes over the network. The fake answers at once, so it is applied here.
		if model.modelsLoading {
			model, command = settle(model, command), nil
		}
	}

	return model, command
}

func TestHomeChoices(t *testing.T) {
	model := newModel("/work/project", finishedRunner("r", true))

	taskB, command := pressAll(t, model, "down", "enter")
	if taskB.screen != homeScreen || command != nil || !strings.Contains(taskB.View(), "Task B is not built yet.") {
		t.Errorf("Task B: screen = %d, view:\n%s", taskB.screen, taskB.View())
	}

	moved, _ := press(t, taskB, "up")
	if moved.notice != "" {
		t.Error("the notice stayed after moving")
	}

	_, quitCommand := pressAll(t, model, "down", "down", "enter")
	if !isQuit(quitCommand) {
		t.Error("Quit in the menu does not quit")
	}
}

func TestNoTargetOrNoBackendStartsNothing(t *testing.T) {
	calls := 0
	counting := func(ctx context.Context, step func(string)) (Result, error) {
		calls++
		return Result{}, nil
	}

	for name, model := range map[string]Model{"no target": newModel("", counting), "no backend": New("/work/project", nil, Defaults{})} {
		after, command := press(t, model, "enter")

		if after.screen != homeScreen || command != nil || after.notice == "" || calls != 0 {
			t.Errorf("%s: screen = %d, notice = %q, calls = %d", name, after.screen, after.notice, calls)
		}
	}
}

func TestACompleteRunEndsOnTheResultsScreen(t *testing.T) {
	model, command := startedRun(t, finishedRunner("# Report\nfinding one", true, "Scanning", "Reading files"))
	if model.screen != runScreen || !model.running {
		t.Fatalf("screen = %d, running = %v, want the run screen", model.screen, model.running)
	}

	model = settle(model, command)

	view := model.View()
	for _, want := range []string{"Results: Task A, complete", "# Report", "finding one", "Timeline", "- Scanning", "- Reading files"} {
		if !strings.Contains(view, want) {
			t.Errorf("the results screen has no %q:\n%s", want, view)
		}
	}
	if model.screen != resultsScreen || model.running {
		t.Errorf("screen = %d, running = %v", model.screen, model.running)
	}
}

func TestAnIncompleteOrFailedRunIsLabelledIncomplete(t *testing.T) {
	failing := func(ctx context.Context, step func(string)) (Result, error) {
		return Result{}, errors.New("provider failed")
	}

	testCases := []struct {
		name   string
		runner Runner
		want   []string
	}{
		{"a result that is not complete", finishedRunner("partial report", false), []string{"Results: Task A, incomplete", "partial report"}},
		{"an error", failing, []string{"Results: Task A, incomplete", "The run stopped: provider failed"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			model, command := startedRun(t, testCase.runner)
			view := settle(model, command).View()

			for _, want := range testCase.want {
				if !strings.Contains(view, want) {
					t.Errorf("the view has no %q:\n%s", want, view)
				}
			}
		})
	}
}

func TestEscCancelsTheRunAndKeepsThePartialResult(t *testing.T) {
	waiting := func(ctx context.Context, step func(string)) (Result, error) {
		step("Working")
		<-ctx.Done()

		return Result{Report: "partial report", Complete: false}, nil
	}
	model, command := startedRun(t, waiting)
	batch := command().(tea.BatchMsg)

	finished := make(chan tea.Msg, 1)
	go func() { finished <- batch[0]() }()

	model, _ = press(t, model, "esc")
	if !strings.Contains(model.View(), "Cancelling") {
		t.Errorf("the screen does not say it is cancelling:\n%s", model.View())
	}

	select {
	case message := <-finished:
		updated, _ := model.Update(message)
		model = updated.(Model)
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not stop after esc")
	}

	if model.screen != resultsScreen || !strings.Contains(model.View(), "incomplete") || !strings.Contains(model.View(), "partial report") {
		t.Errorf("after cancel the view is:\n%s", model.View())
	}
}

func TestQuitWorksOnEveryScreenAndStopsARunningTask(t *testing.T) {
	var runContext context.Context
	waiting := func(ctx context.Context, step func(string)) (Result, error) {
		runContext = ctx
		<-ctx.Done()

		return Result{}, nil
	}

	screens := map[string]func() Model{
		"home": func() Model { return newModel("/work/project", waiting) },
		"run": func() Model {
			model, command := startedRun(t, waiting)
			batch := command().(tea.BatchMsg)
			go batch[0]()
			for runContext == nil {
				time.Sleep(time.Millisecond)
			}
			return model
		},
		"results": func() Model {
			model, command := startedRun(t, finishedRunner("r", true))
			return settle(model, command)
		},
	}

	for name, build := range screens {
		for _, key := range []string{"q", "ctrl+c"} {
			t.Run(name+" "+key, func(t *testing.T) {
				runContext = nil
				model := build()

				_, command := press(t, model, key)

				if !isQuit(command) {
					t.Error("the program does not quit")
				}
				if name == "run" && runContext.Err() == nil {
					t.Error("the running task was not cancelled")
				}
			})
		}
	}
}

func TestEveryScreenShowsItsKeysOnTheLastLine(t *testing.T) {
	home := newModel("/work/project", finishedRunner("r", true))
	running, command := startedRun(t, finishedRunner("r", true))
	results := settle(running, command)

	testCases := []struct {
		name  string
		model Model
		want  []string
	}{
		{"home", home, []string{"up/down", "enter", "q: quit"}},
		{"run", running, []string{"esc: cancel", "q: quit"}},
		{"results", results, []string{"up/down", "b: back", "q: quit"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			footer := lastLine(testCase.model.View())

			for _, want := range testCase.want {
				if !strings.Contains(footer, want) {
					t.Errorf("the last line %q has no %q", footer, want)
				}
			}
		})
	}
}

func TestBackToHomeAndRunAgain(t *testing.T) {
	model, command := startedRun(t, finishedRunner("first", true, "step"))
	model = settle(model, command)

	for _, key := range []string{"b", "esc"} {
		back, _ := press(t, model, key)
		if back.screen != homeScreen {
			t.Errorf("%q did not go back home", key)
		}
	}

	home, _ := press(t, model, "b")
	again, command := beginRun(t, home)
	if again.screen != runScreen || len(again.steps) != 0 || again.report != "" || again.runID != 2 {
		t.Errorf("a new run starts with old data: %+v", again)
	}
	if !strings.Contains(settle(again, command).View(), "first") {
		t.Error("the second run did not finish")
	}
}

func TestResultsScroll(t *testing.T) {
	var lines []string
	for number := 1; number <= 40; number++ {
		lines = append(lines, fmt.Sprintf("line %d", number))
	}
	model, command := startedRun(t, finishedRunner(strings.Join(lines, "\n"), true))
	model = settle(model, command)
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	model = updated.(Model)

	if view := model.View(); !strings.Contains(view, "line 1\n") || strings.Contains(view, "line 7\n") {
		t.Fatalf("the first window is wrong:\n%s", view)
	}
	if strings.Count(model.View(), "\n")+1 != 10 {
		t.Errorf("the screen has %d lines, want 10", strings.Count(model.View(), "\n")+1)
	}

	model, _ = press(t, model, "down")
	if model.scroll != 1 {
		t.Errorf("scroll = %d after down", model.scroll)
	}
	model, _ = press(t, model, "pgdown")
	if model.scroll != 1+model.viewHeight() {
		t.Errorf("scroll = %d after pgdown", model.scroll)
	}

	for step := 0; step < 100; step++ {
		model, _ = press(t, model, "down")
	}
	if model.scroll != model.maxScroll() || !strings.Contains(model.View(), "(no steps)") {
		t.Errorf("scroll = %d, max = %d; the end of the text is not shown:\n%s", model.scroll, model.maxScroll(), model.View())
	}

	for step := 0; step < 100; step++ {
		model, _ = press(t, model, "up")
	}
	model, _ = press(t, model, "pgup")
	if model.scroll != 0 {
		t.Errorf("scroll = %d at the top", model.scroll)
	}
}

func TestAnOldRunCannotChangeANewRun(t *testing.T) {
	model, command := startedRun(t, finishedRunner("first", true))
	model = settle(model, command)
	model, _ = press(t, model, "b")
	model, _ = beginRun(t, model)

	for _, message := range []tea.Msg{
		stepMsg{run: 1, text: "from the old run"},
		doneMsg{run: 1, result: Result{Report: "old report", Complete: true}},
	} {
		updated, _ := model.Update(message)
		model = updated.(Model)
	}

	if !model.running || model.screen != runScreen || len(model.steps) != 0 || model.report != "" {
		t.Errorf("an old message changed the new run: %+v", model)
	}
}

func TestUntrustedTextIsCleanedBeforeItIsShown(t *testing.T) {
	hostile := "a\x1b[31mred\x1b]0;title\x07 b\u202eevil\u200b c\x00d\re\tf\xffg"
	runner := func(ctx context.Context, step func(string)) (Result, error) {
		step(hostile)
		return Result{Report: hostile, Complete: true}, nil
	}

	home := newModel(hostile, runner)
	running, command := beginRun(t, home)
	results := settle(running, command)
	failed, failCommand := startedRun(t, func(ctx context.Context, step func(string)) (Result, error) {
		return Result{}, errors.New(hostile)
	})
	failed = settle(failed, failCommand)

	for name, model := range map[string]Model{"home": home, "run": running, "results": results, "error": failed} {
		for _, character := range model.View() {
			if character != '\n' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
				t.Errorf("%s: the view holds the character %U", name, character)
			}
		}
	}
}

func TestLongLinesAreCutToTheWidth(t *testing.T) {
	model, command := startedRun(t, finishedRunner(strings.Repeat("x", 200), true))
	model = settle(model, command)
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 20, Height: 12})
	model = updated.(Model)

	for _, line := range strings.Split(model.View(), "\n") {
		if len([]rune(line)) > 20 {
			t.Errorf("the line %q is longer than the width", line)
		}
	}
}

func TestSafeText(t *testing.T) {
	testCases := []struct {
		name      string
		inputText string
		want      string
	}{
		{"plain", "hello", "hello"},
		{"newline kept", "a\nb", "a\nb"},
		{"tab becomes a space", "a\tb", "a b"},
		{"escape character", "a\x1b[31mb", "a?[31mb"},
		{"bell and null", "a\x07\x00b", "a??b"},
		{"carriage return", "a\rb", "a?b"},
		{"right-to-left override", "a\u202eb", "a?b"},
		{"zero-width space", "a\u200bb", "a?b"},
		{"invalid UTF-8", "a\xffb", "a?b"},
		{"Japanese text is kept", "日本語のファイル", "日本語のファイル"},
		{"empty", "", ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := safeText(testCase.inputText); got != testCase.want {
				t.Errorf("safeText(%q) = %q, want %q", testCase.inputText, got, testCase.want)
			}
		})
	}
}

func FuzzView(f *testing.F) {
	f.Add("/work", "report\nline", "step", 80, 24)
	f.Add("a\x1b[2J", "\u202e\x00", "\x07", 0, 0)
	f.Add("", "", "", 3, 1)

	f.Fuzz(func(t *testing.T, target, report, step string, width, height int) {
		withProfile(t, termenv.TrueColor)
		runner := func(ctx context.Context, send func(string)) (Result, error) {
			send(step)
			return Result{Report: report, Complete: true}, nil
		}

		model, command := beginRun(t, newModel(target, runner))
		updated, _ := model.Update(tea.WindowSizeMsg{Width: width % 500, Height: height % 200})
		model = settle(updated.(Model), command)

		for _, key := range []string{"down", "pgdown", "pgup", "up"} {
			model, _ = press(t, model, key)
		}
		for _, shown := range []Model{model, newModel(target, runner)} {
			for _, character := range styleCodes.ReplaceAllString(shown.View(), "") {
				if character != '\n' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
					t.Fatalf("the view holds the character %U", character)
				}
			}
		}
	})
}
