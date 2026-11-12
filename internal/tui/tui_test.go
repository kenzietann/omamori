package tui

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
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
	"home":      {Type: tea.KeyHome},
	"end":       {Type: tea.KeyEnd},
	"c":         {Type: tea.KeyRunes, Runes: []rune{'c'}},
	"m":         {Type: tea.KeyRunes, Runes: []rune{'m'}},
	"d":         {Type: tea.KeyRunes, Runes: []rune{'d'}},
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
		if fmt.Sprintf("%T", message) == "tea.sequenceMsg" {
			list := reflect.ValueOf(message)
			var ordered []tea.Cmd
			for index := range list.Len() {
				ordered = append(ordered, list.Index(index).Interface().(tea.Cmd))
			}
			queue = append(ordered, queue...)
			continue
		}

		updated, next := model.Update(message)
		model = updated.(Model)
		queue = append(queue, next)
	}

	return model
}

func batchOf(t testing.TB, command tea.Cmd) tea.BatchMsg {
	t.Helper()

	message := command()
	if batch, isBatch := message.(tea.BatchMsg); isBatch {
		return batch
	}
	if fmt.Sprintf("%T", message) == "tea.sequenceMsg" {
		list := reflect.ValueOf(message)
		for index := range list.Len() {
			if inner, isBatch := list.Index(index).Interface().(tea.Cmd)().(tea.BatchMsg); isBatch {
				return inner
			}
		}
	}
	t.Fatalf("no batch of commands in %T", message)

	return nil
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
	summary    string
	setups     []Setup
	confirmed  int
	models     []string
	modelsErr  error
	modelCalls []modelCall
	reasoning       []ReasoningChoice
	reasoningModels []string
	canSaveKeys     bool
	savedKeys       []modelCall
	saveKeyErr      error
	forgotKeys      []string
	forgetKeyErr    error
	savedSettings   []Defaults
	saveSettingsErr error
	taskChecks      []string
	taskReadyErr    error
	title           string
	label           string
}

func (backend *fakeBackend) TaskReady(task string) error {
	backend.taskChecks = append(backend.taskChecks, task)

	return backend.taskReadyErr
}

func (backend *fakeBackend) KeysCanBeSaved() bool { return backend.canSaveKeys }

func (backend *fakeBackend) SaveKey(ctx context.Context, providerID, key string) error {
	backend.savedKeys = append(backend.savedKeys, modelCall{providerID, key})

	return backend.saveKeyErr
}

func (backend *fakeBackend) ForgetKey(providerID string) error {
	backend.forgotKeys = append(backend.forgotKeys, providerID)
	if backend.forgetKeyErr == nil {
		for index := range backend.choices {
			if backend.choices[index].ID == providerID {
				backend.choices[index].KeySaved = false
			}
		}
	}

	return backend.forgetKeyErr
}

func (backend *fakeBackend) SaveSettings(defaults Defaults) error {
	backend.savedSettings = append(backend.savedSettings, defaults)

	return backend.saveSettingsErr
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
		Title:       backend.title,
		Label:       backend.label,
		ConsentText: consent,
		Summary:     backend.summary,
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

	var command tea.Cmd
	for range 6 {
		model, command = press(t, model, "enter")
		if model.modelsLoading {
			model, command = settle(model, command), nil
		}
		if model.screen == runScreen {
			return model, command
		}
	}

	// Some tests ask for a setup that cannot start a run, for example an empty target.
	return model, nil
}

func startedRun(t testing.TB, runner Runner) (Model, tea.Cmd) {
	t.Helper()

	return beginRun(t, newModel("/work/project", runner))
}

func TestHomeMenuMovesAndGoesAroundTheEnds(t *testing.T) {
	last := len(menuItems) - 1
	downs := func(count int) []string { return slices.Repeat([]string{"down"}, count) }
	testCases := []struct {
		name       string
		keys       []string
		wantCursor int
	}{
		{"start", nil, 0},
		{"down", []string{"down"}, 1},
		{"down to the end", downs(last), last},
		{"down past the end goes to the top", downs(last + 1), 0},
		{"down around once and a bit more", downs(last + 2), 1},
		{"up at the top goes to the bottom", []string{"up"}, last},
		{"up twice from the top", []string{"up", "up"}, last - 1},
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
		if model.modelsLoading {
			model, command = settle(model, command), nil
		}
	}

	return model, command
}

func TestHomeChoices(t *testing.T) {
	model := newModel("/work/project", finishedRunner("r", true))

	taskB, command := pressAll(t, model, "down", "enter")
	if taskB.step != stepProvider || command != nil || taskB.task != TaskTriage {
		t.Errorf("Task B: step = %d, task = %q, the provider choice must start", taskB.step, taskB.task)
	}

	notReady := &fakeBackend{choices: []Choice{localChoice}, taskReadyErr: errors.New("Task B needs the log file auth.log in the target folder.")}
	blocked, _ := pressAll(t, newModelWith("/work/project", notReady, Defaults{}), "down", "enter")
	if blocked.step != stepMenu || !strings.Contains(blocked.View(), "Task B needs the log file auth.log") || len(notReady.taskChecks) != 1 || notReady.taskChecks[0] != TaskTriage {
		t.Errorf("a task that is not ready: step = %d, checks = %q, view:\n%s", blocked.step, notReady.taskChecks, blocked.View())
	}
	moved, _ := press(t, blocked, "up")
	if moved.notice != "" {
		t.Error("the notice stayed after moving")
	}
	if _, command := pressAll(t, newModelWith("/work/project", notReady, Defaults{}), "enter"); command != nil {
		t.Error("Task A asked if the log is there")
	}
	if len(notReady.taskChecks) != 1 {
		t.Errorf("Task A checked a task: %q", notReady.taskChecks)
	}

	_, quitCommand := pressAll(t, model, "up", "enter")
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

func TestACompleteRunPrintsItsStepsAndResultsAndOffersTheMenu(t *testing.T) {
	model, command := startedRun(t, finishedRunner("# Report\nfinding one", true, "Scanning", "Reading files"))
	if model.screen != runScreen || !model.running {
		t.Fatalf("screen = %d, running = %v, want the run screen", model.screen, model.running)
	}

	model = settle(model, command)

	printed := strings.Join(model.transcript, "\n")
	for _, want := range []string{"⎿ Scanning", "⎿ Reading files", "● Results: Task A, complete", "# Report", "finding one"} {
		if !strings.Contains(printed, want) {
			t.Errorf("the printed text has no %q:\n%s", want, printed)
		}
	}
	if strings.Index(printed, "Reading files") > strings.Index(printed, "Results: Task A") {
		t.Errorf("a step is printed after the results:\n%s", printed)
	}
	if model.screen != runScreen || model.running || !strings.Contains(model.View(), "enter: back to the menu") {
		t.Errorf("screen = %d, running = %v:\n%s", model.screen, model.running, model.View())
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
			printed := strings.Join(settle(model, command).transcript, "\n")

			for _, want := range testCase.want {
				if !strings.Contains(printed, want) {
					t.Errorf("the printed text has no %q:\n%s", want, printed)
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
	batch := batchOf(t, command)

	finished := make(chan struct{})
	go func() { batch[0](); close(finished) }()

	model, _ = press(t, model, "esc")
	if !strings.Contains(model.View(), "Cancelling") {
		t.Errorf("the screen does not say it is cancelling:\n%s", model.View())
	}

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not stop after esc")
	}
	model = settle(model, batch[1])

	printed := strings.Join(model.transcript, "\n")
	if model.screen != runScreen || model.running || !strings.Contains(printed, "incomplete") || !strings.Contains(printed, "partial report") || !strings.Contains(printed, "⎿ Working") {
		t.Errorf("after cancel the printed text is:\n%s", printed)
	}
}

func TestQuitWorksOnEveryScreenAndStopsARunningTask(t *testing.T) {
	var runContext context.Context
	started := make(chan context.Context, 1)
	waiting := func(ctx context.Context, step func(string)) (Result, error) {
		started <- ctx
		<-ctx.Done()

		return Result{}, nil
	}

	screens := map[string]func() Model{
		"home": func() Model { return newModel("/work/project", waiting) },
		"run": func() Model {
			model, command := startedRun(t, waiting)
			batch := batchOf(t, command)
			go batch[0]()
			select {
			case runContext = <-started:
			case <-time.After(5 * time.Second):
				model.cancel()
				t.Fatal("the run did not start")
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
	running, _ := startedRun(t, finishedRunner("r", true))

	testCases := []struct {
		name  string
		model Model
		want  []string
	}{
		{"home", home, []string{"up/down", "enter", "q: quit"}},
		{"run", running, []string{"esc: cancel", "q: quit"}},
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

func TestARunCanBeStartedAgainAfterTheResults(t *testing.T) {
	model, command := startedRun(t, finishedRunner("first", true, "step"))
	model = settle(model, command)

	home, _ := press(t, model, "enter")
	again, command := beginRun(t, home)
	if again.screen != runScreen || len(again.steps) != 0 || again.runID != 2 {
		t.Errorf("a new run starts with old data: %+v", again)
	}
	finished := settle(again, command)
	if strings.Count(strings.Join(finished.transcript, "\n"), "● Results: Task A, complete") != 2 || finished.screen != runScreen || finished.running {
		t.Errorf("the second run did not finish: %q", finished.transcript)
	}
}

func TestAnOldRunCannotChangeANewRun(t *testing.T) {
	model, command := startedRun(t, finishedRunner("first", true))
	model = settle(model, command)
	model, _ = beginRun(t, model)
	printedBefore := len(model.transcript)

	for _, message := range []tea.Msg{
		stepMsg{run: 1, text: "from the old run"},
		doneMsg{run: 1, result: Result{Report: "old report", Complete: true}},
	} {
		updated, _ := model.Update(message)
		model = updated.(Model)
	}

	if !model.running || model.screen != runScreen || len(model.steps) != 0 || len(model.transcript) != printedBefore {
		t.Errorf("an old message changed the new run: %+v", model)
	}
}

func TestUntrustedTextIsCleanedBeforeItIsShown(t *testing.T) {
	hostile := "a\x1b[31mred\x1b]0;title\x07 b\u202eevil\u200b c\x00d\re\tf\xffg"
	runner := func(ctx context.Context, step func(string)) (Result, error) {
		step(hostile)
		return Result{Report: hostile, Complete: true, SavedTo: hostile}, nil
	}

	home := newModel(hostile, runner)
	running, command := beginRun(t, home)
	results := settle(running, command)
	failed, failCommand := startedRun(t, func(ctx context.Context, step func(string)) (Result, error) {
		return Result{}, errors.New(hostile)
	})
	failed = settle(failed, failCommand)

	for name, model := range map[string]Model{"home": home, "run": running, "results": results, "error": failed} {
		for _, character := range model.View() + strings.Join(model.transcript, "\n") {
			if character != '\n' && character != '\x1b' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
				t.Errorf("%s: the text holds the character %U", name, character)
			}
		}
	}
}

func TestLongReportLinesArePrintedWholeAndTheLiveAreaIsCutToTheWidth(t *testing.T) {
	model, command := startedRun(t, finishedRunner(strings.Repeat("x", 200), true))
	model = sized(settle(model, command), 20, 12)

	if !strings.Contains(strings.Join(model.transcript, "\n"), strings.Repeat("x", 200)) {
		t.Error("a long report line was cut, but the terminal wraps it and it can be copied whole")
	}
	for _, line := range strings.Split(model.View(), "\n") {
		if len([]rune(line)) > 20 {
			t.Errorf("the live area line %q is longer than the width", line)
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

		for _, key := range []string{"down", "up", "enter", "esc"} {
			model, _ = press(t, model, key)
		}
		for _, shown := range []Model{model, newModel(target, runner)} {
			for _, character := range styleCodes.ReplaceAllString(shown.View()+strings.Join(shown.transcript, "\n"), "") {
				if character != '\n' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
					t.Fatalf("the view holds the character %U", character)
				}
			}
		}
	})
}
