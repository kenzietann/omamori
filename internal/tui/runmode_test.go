package tui

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
)

func effectsOf(command tea.Cmd) []string {
	var effects []string

	var visit func(tea.Cmd)
	visit = func(current tea.Cmd) {
		if current == nil {
			return
		}
		done := make(chan tea.Msg, 1)
		go func() { done <- current() }()
		var message tea.Msg
		select {
		case message = <-done:
		case <-time.After(50 * time.Millisecond):
			return
		}

		switch kind := fmt.Sprintf("%T", message); {
		case kind == "tea.BatchMsg":
			for _, inner := range message.(tea.BatchMsg) {
				visit(inner)
			}
		case kind == "tea.sequenceMsg":
			list := reflect.ValueOf(message)
			for index := range list.Len() {
				visit(list.Index(index).Interface().(tea.Cmd))
			}
		case kind == "tea.exitAltScreenMsg":
			effects = append(effects, "exit-alt")
		case kind == "tea.enterAltScreenMsg":
			effects = append(effects, "enter-alt")
		case strings.HasPrefix(kind, "tea.printLineMessage"):
			effects = append(effects, "print:"+fmt.Sprintf("%v", message))
		}
	}
	visit(command)

	return effects
}

func printedBy(command tea.Cmd) []string {
	var printed []string
	for _, effect := range effectsOf(command) {
		if text, isPrint := strings.CutPrefix(effect, "print:"); isPrint {
			printed = append(printed, text)
		}
	}

	return printed
}

func summaryBackend() *fakeBackend {
	var full []string
	for number := 1; number <= 60; number++ {
		full = append(full, fmt.Sprintf("full line %d", number))
	}

	return &fakeBackend{choices: []Choice{localChoice}, summary: "SUMMARY LINE\nsecond summary line", preview: strings.Join(full, "\n"), runner: finishedRunner("the report", true, "a step")}
}

func TestStartingTheRunLeavesFullScreenFirstAndThenPrintsWhatWasConfirmed(t *testing.T) {
	backend := summaryBackend()
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}).WithVersion("v1.2"), "enter", "enter", "enter")
	if model.step != stepConsent {
		t.Fatalf("step = %d", model.step)
	}

	started, command := press(t, model, "enter")
	effects := effectsOf(command)

	if len(effects) < 2 || effects[0] != "exit-alt" || !strings.HasPrefix(effects[1], "print:") {
		t.Fatalf("the terminal must leave full-screen mode before the text is printed: %q", effects)
	}
	for _, want := range []string{"Task A: Exposure check", "Omamori v1.2 · Target folder: /work/project", "SUMMARY LINE", "second summary line"} {
		if !strings.Contains(effects[1], want) {
			t.Errorf("the first printed text has no %q:\n%s", want, effects[1])
		}
	}
	if strings.Contains(effects[1], "full line") {
		t.Error("the whole request was printed, not the summary")
	}
	if started.screen != runScreen || !started.running {
		t.Errorf("screen = %d, running = %v", started.screen, started.running)
	}
}

func TestARunWithoutASummaryPrintsTheWholeRequest(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "WHOLE REQUEST", runner: finishedRunner("r", true)}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")

	_, command := press(t, model, "enter")

	if printed := printedBy(command); len(printed) != 1 || !strings.Contains(printed[0], "WHOLE REQUEST") {
		t.Errorf("printed %q", printed)
	}
}

func TestWhileTheRunLastsThereIsOneStatusLineAndNoFrame(t *testing.T) {
	waiting := func(ctx context.Context, step func(string)) (Result, error) { <-ctx.Done(); return Result{}, nil }
	model, _ := startedRun(t, waiting)

	view := model.View()
	if strings.Contains(view, "\n") || strings.Contains(view, "─") || !strings.Contains(view, "Running: Task A, exposure check") || !strings.Contains(view, "esc: cancel") {
		t.Errorf("the run view must be one line without a frame:\n%q", view)
	}
	narrow := sized(model, 30, 10)
	if strings.Contains(narrow.View(), "\n") || runewidth.StringWidth(styleCodes.ReplaceAllString(narrow.View(), "")) > 30 {
		t.Errorf("the status line is wrong in a narrow window: %q", narrow.View())
	}
	cancelling, _ := press(t, model, "esc")
	if !strings.Contains(cancelling.View(), "Cancelling") || strings.Contains(cancelling.View(), "\n") {
		t.Errorf("cancelling: %q", cancelling.View())
	}
	model.cancel()
}

func TestAfterTheRunOneLineOffersTheMenuOrQuit(t *testing.T) {
	model, command := startedRun(t, finishedRunner("the report", true, "a step"))
	model = settle(model, command)

	if model.running || model.screen != runScreen {
		t.Fatalf("running = %v, screen = %d: the program stays in the normal terminal after the run", model.running, model.screen)
	}
	view := model.View()
	if strings.Contains(view, "\n") || strings.Contains(view, "─") || !strings.Contains(view, "enter: back to the menu") || !strings.Contains(view, "q: quit") {
		t.Errorf("the line after the run is wrong: %q", view)
	}
	if !strings.Contains(model.Printed(), "● Results: Task A, complete") {
		t.Error("the results were not printed")
	}
}

func TestEnterGoesBackToTheFullScreenMenuAfterTheRun(t *testing.T) {
	model, command := startedRun(t, finishedRunner("the report", true))
	model = settle(model, command)

	for _, key := range []string{"enter", "esc", "b"} {
		back, command := press(t, model, key)

		if back.screen != homeScreen || back.step != stepMenu || !strings.Contains(back.View(), "Task A: Exposure check") {
			t.Errorf("%s did not go back to the menu", key)
		}
		if effects := effectsOf(command); len(effects) != 1 || effects[0] != "enter-alt" {
			t.Errorf("%s: the terminal must go back to full-screen mode: %q", key, effects)
		}
	}
	for _, key := range []string{"up", "down", "x", "c"} {
		same, command := press(t, model, key)
		if same.screen != runScreen || command != nil {
			t.Errorf("%s changed the screen after the run", key)
		}
	}
}

func TestEnterDuringTheRunDoesNothingAndQuitStopsTheRun(t *testing.T) {
	waiting := func(ctx context.Context, step func(string)) (Result, error) { <-ctx.Done(); return Result{}, nil }
	model, _ := startedRun(t, waiting)

	for _, key := range []string{"enter", "b", "up"} {
		if same, command := press(t, model, key); same.screen != runScreen || !same.running || command != nil {
			t.Errorf("%s changed a running run", key)
		}
	}
	quit, command := press(t, model, "q")
	if !isQuit(command) || quit.View() != "" {
		t.Error("q did not quit")
	}
}

func TestEachStepIsPrintedOnItsOwnAsItArrives(t *testing.T) {
	waiting := func(ctx context.Context, step func(string)) (Result, error) { <-ctx.Done(); return Result{}, nil }
	model, _ := startedRun(t, waiting)

	for _, text := range []string{"tool run_detectors: ok", "tool read_file: refused (outside the folder)", "report saved", "run finished: limit reached"} {
		updated, command := model.Update(stepMsg{run: model.runID, text: text})
		model = updated.(Model)

		lines := printedBy(command)
		if len(lines) != 1 || !strings.Contains(lines[0], text) || !strings.Contains(lines[0], "⎿") {
			t.Errorf("the step %q was not printed as one line: %q", text, lines)
		}
		if effects := effectsOf(command); len(effects) != 1 {
			t.Errorf("a step must only print: %q", effects)
		}
	}
	model.cancel()
}

func TestTheResultsComeAfterEveryStepEvenWhenThereAreManySteps(t *testing.T) {
	var steps []string
	for number := 1; number <= 200; number++ {
		steps = append(steps, fmt.Sprintf("step %03d", number))
	}
	model, command := startedRun(t, finishedRunner("the report", true, steps...))
	model = settle(model, command)

	printed := model.Printed()
	results := strings.Index(printed, "● Results: Task A, complete")
	last := strings.Index(printed, "step 200")
	if results < 0 || last < 0 || last > results {
		t.Errorf("a step was printed after the results (results at %d, last step at %d)", results, last)
	}
	for index := 1; index < 200; index++ {
		if strings.Index(printed, fmt.Sprintf("step %03d", index)) > strings.Index(printed, fmt.Sprintf("step %03d", index+1)) {
			t.Fatalf("the steps are not in order at %d", index)
		}
	}
}

func TestTheRunningMarkAnimatesOnlyWhileTheRunLasts(t *testing.T) {
	waiting := func(ctx context.Context, step func(string)) (Result, error) { <-ctx.Done(); return Result{}, nil }
	model, _ := startedRun(t, waiting)
	seen := map[string]bool{}

	for range 8 {
		seen[strings.Fields(model.View())[0]] = true
		updated, command := model.Update(spinnerMsg{run: model.runID})
		model = updated.(Model)
		if command == nil {
			t.Fatal("the spinner stopped while the run is going")
		}
	}
	if len(seen) != len(spinnerFrames) {
		t.Errorf("the mark shows %d different frames, want %d", len(seen), len(spinnerFrames))
	}

	updated, command := model.Update(spinnerMsg{run: model.runID + 1})
	if command != nil || updated.(Model).frame != model.frame {
		t.Error("the spinner of another run changed this one")
	}
	model.cancel()
	finished, _ := model.Update(doneMsg{run: model.runID, result: Result{Report: "r", Complete: true}})
	if _, command := finished.Update(spinnerMsg{run: model.runID}); command != nil {
		t.Error("the spinner went on after the run ended")
	}
}

func TestAfterQuitNothingIsLeftOnTheScreen(t *testing.T) {
	model := sized(newModel("/work/project", nil), 80, 24)
	if model.View() == "" {
		t.Fatal("the page is empty before the quit")
	}

	for _, key := range []string{"q", "ctrl+c"} {
		quit, command := press(t, model, key)
		if !isQuit(command) || quit.View() != "" {
			t.Errorf("%s: quit %v, view %q", key, isQuit(command), quit.View())
		}
	}
	down, _ := pressAll(t, model, "up", "enter")
	if down.View() != "" {
		t.Error("choosing Quit in the menu left the page on the screen")
	}
}

func TestNoPageHasFrameLines(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{keyedChoice, localChoice}, models: []string{"a", "b"}, reasoning: testLevels, preview: "p", summary: "s", runner: finishedRunner("r", true)}
	base := sized(newModelWith("/work/project", backend, Defaults{}), 72, 30)

	provider, _ := press(t, base, "enter")
	key, _ := pressAll(t, base, "enter", "enter")
	list, _ := pressAll(t, base, "enter", "down", "enter")
	reasoning, _ := pressAll(t, base, "enter", "down", "enter", "enter")
	consent, _ := pressAll(t, base, "enter", "down", "enter", "enter", "enter")
	settings, _ := pressAll(t, base, "up", "up", "enter")

	for name, model := range map[string]Model{"menu": base, "provider": provider, "key": key, "models": list, "reasoning": reasoning, "consent": consent, "settings": settings} {
		if strings.Contains(model.View(), "───") {
			t.Errorf("%s has a frame line:\n%s", name, model.View())
		}
		if lines := strings.Split(model.View(), "\n"); !strings.Contains(styleCodes.ReplaceAllString(lines[len(lines)-1], ""), ": ") {
			t.Errorf("%s: the last line is not the keys: %q", name, lines[len(lines)-1])
		}
	}
}

func TestEveryPageFitsEveryWindowHeightWithAHundredChoices(t *testing.T) {
	var names []string
	for number := 1; number <= 100; number++ {
		names = append(names, fmt.Sprintf("model-%03d", number))
	}
	var providers []Choice
	for number := range 30 {
		providers = append(providers, Choice{ID: fmt.Sprintf("p%d", number), Name: fmt.Sprintf("Provider%02d", number), Local: true})
	}

	for _, backend := range []*fakeBackend{
		{choices: []Choice{localChoice}, models: names, reasoning: testLevels, preview: "p"},
		{choices: providers},
	} {
		for height := 12; height <= 40; height += 4 {
			model := sized(newModelWith("/work/project", backend, Defaults{}), 80, height)
			model, _ = pressAll(t, model, "enter")
			if len(backend.choices) == 1 {
				model, _ = pressAll(t, model, "enter")
			}

			for step := range 120 {
				if count := strings.Count(model.View(), "\n") + 1; count > height {
					t.Fatalf("height %d, step %d: the page has %d lines", height, step, count)
				}
				if !strings.Contains(model.View(), "❯ ") {
					t.Fatalf("height %d, step %d: the cursor is not in view", height, step)
				}
				model, _ = press(t, model, "down")
			}
		}
	}
}

func TestTheDryRunPageShowsTheSummaryFirstAndTheFullRequestOnD(t *testing.T) {
	model := sized(newModelWith("/work/project", summaryBackend(), Defaults{}), 80, 24)
	model, _ = pressAll(t, model, "enter", "enter", "enter")

	view := model.View()
	if !strings.Contains(view, "SUMMARY LINE") || strings.Contains(view, "full line 1") || !strings.Contains(view, "This is a summary of the first request:") {
		t.Fatalf("the summary is not shown first:\n%s", view)
	}
	if footer := lastLine(view); !strings.Contains(footer, "d: full request") || !strings.Contains(footer, "enter: send and start") {
		t.Errorf("the footer is %q", footer)
	}

	full, _ := press(t, model, "d")
	view = full.View()
	if !strings.Contains(view, "full line 1\n") || strings.Contains(view, "SUMMARY LINE") || !strings.Contains(view, "This is the dry run:") {
		t.Fatalf("the full request is not shown:\n%s", view)
	}
	if footer := lastLine(view); !strings.Contains(footer, "d: summary") {
		t.Errorf("the footer is %q", footer)
	}
	if count := strings.Count(view, "\n") + 1; count > 24 {
		t.Errorf("%d lines in a window of 24", count)
	}
	if back, _ := press(t, full, "d"); !strings.Contains(back.View(), "SUMMARY LINE") {
		t.Error("d did not go back to the summary")
	}
	if len(model.Printed()) != 0 {
		t.Errorf("the dry run page printed something before the run: %q", model.Printed())
	}
}

func TestTheDryRunPageScrollsAndSwitchingStartsAtTheTop(t *testing.T) {
	model := sized(newModelWith("/work/project", summaryBackend(), Defaults{}), 80, 24)
	model, _ = pressAll(t, model, "enter", "enter", "enter", "d")
	height := model.consentViewHeight()

	down, _ := pressAll(t, model, "down", "pgdown")
	if down.consentScroll != 1+height {
		t.Errorf("scroll = %d after down and pgdown, want %d", down.consentScroll, 1+height)
	}
	end, _ := press(t, model, "end")
	if end.consentScroll != end.maxConsentScroll() || !strings.Contains(end.View(), "full line 60") || end.consentScroll == 0 {
		t.Errorf("the end is not reachable (scroll %d, max %d)", end.consentScroll, end.maxConsentScroll())
	}
	home, _ := press(t, end, "home")
	up, _ := pressAll(t, down, "pgup", "pgup", "up")
	if home.consentScroll != 0 || up.consentScroll != 0 {
		t.Errorf("home %d, up %d, want 0", home.consentScroll, up.consentScroll)
	}
	switched, _ := pressAll(t, end, "d", "d")
	if switched.consentScroll != 0 || !strings.Contains(switched.View(), "full line 1\n") {
		t.Errorf("scroll = %d after switching twice", switched.consentScroll)
	}
}

func TestLongDryRunLinesAreWrappedOnThePage(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "backend/node_modules/@angular-devkit/core/node_modules/rxjs/CHANGELOG.md and some more words after it"}
	model := sized(newModelWith("/work/project", backend, Defaults{}), 30, 24)
	model, _ = pressAll(t, model, "enter", "enter", "enter")

	flat := strings.ReplaceAll(model.View(), "\n", "")
	if !strings.Contains(flat, "backend/node_modules/@angular-devkit/core/node_modules/rxjs/CHANGELOG.md") {
		t.Errorf("a long line was cut off:\n%s", model.View())
	}
	for _, line := range strings.Split(styleCodes.ReplaceAllString(model.View(), ""), "\n") {
		if runewidth.StringWidth(line) > 30 {
			t.Errorf("the line %q is wider than the window", line)
		}
	}
}

func TestWithoutASummaryTheDKeyAndTheHintAreAbsent(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "FULL TEXT ONLY"}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")

	after, _ := press(t, model, "d")

	if !strings.Contains(model.View(), "FULL TEXT ONLY") || strings.Contains(lastLine(model.View()), "d:") || after.consentFull {
		t.Errorf("view:\n%s", model.View())
	}
}

func TestANewPlanAndTheSavedChoicesPathStartWithTheSummary(t *testing.T) {
	backend := summaryBackend()
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter", "d", "esc")
	model, _ = pressAll(t, model, "enter", "enter", "enter")
	if model.consentFull || !strings.Contains(model.View(), "SUMMARY LINE") {
		t.Errorf("the second plan began with the full request:\n%s", model.View())
	}

	saved := summaryBackend()
	saved.choices = []Choice{savedChoice}
	quick := newModelWith("/work/project", saved, Defaults{ProviderID: "openai", Model: "gpt-x"})
	quick, _ = pressAll(t, quick, "enter", "d", "esc")
	quick, _ = press(t, quick, "enter")
	if quick.step != stepConsent || quick.consentFull || !strings.Contains(quick.View(), "SUMMARY LINE") {
		t.Errorf("the second quick start began with the full request:\n%s", quick.View())
	}
}

func TestCancellingTheDryRunPrintsNothingAndSaysSoInTheMenu(t *testing.T) {
	model, _ := pressAll(t, newModelWith("/work/project", summaryBackend(), Defaults{}), "enter", "enter", "enter")

	cancelled, command := press(t, model, "esc")

	if effects := effectsOf(command); len(effects) != 0 || cancelled.Printed() != "" || !strings.Contains(cancelled.View(), "Nothing was sent.") {
		t.Errorf("effects %q, view:\n%s", effects, cancelled.View())
	}
}

func TestPrintedTextIsCleanOfControlCharactersExceptOurColors(t *testing.T) {
	hostile := "evil\x1b[2J\u202e\x07 text"
	backend := &fakeBackend{choices: []Choice{localChoice}, summary: hostile, preview: hostile, consent: hostile,
		runner: func(ctx context.Context, step func(string)) (Result, error) {
			step(hostile)
			return Result{Report: hostile, Complete: true, SavedTo: hostile}, nil
		}}
	model, _ := pressAll(t, newModelWith(hostile, backend, Defaults{}).WithVersion(hostile), "enter", "enter", "enter")
	started, command := press(t, model, "enter")
	finished := settle(started, command)

	for _, character := range styleCodes.ReplaceAllString(finished.Printed(), "") {
		if character != '\n' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
			t.Errorf("the printed text holds the character %U", character)
		}
	}
}

func FuzzScreens(f *testing.F) {
	f.Add("FakeAI", "a note", 80, 24, uint8(3))
	f.Add("a\x1b[2J\u202e", "\x00\x07", 0, 0, uint8(77))
	f.Add("", "", 3, 1, uint8(200))

	f.Fuzz(func(t *testing.T, name, note string, width, height int, seed uint8) {
		backend := &fakeBackend{
			choices: []Choice{{ID: "a", Name: name, KeyEnv: name, DefaultModel: note}, {ID: "b", Name: note, Local: true}},
			models:  []string{note, name}, reasoning: []ReasoningChoice{{"", note}, {"high", name}},
			summary: note, preview: note, consent: note, canSaveKeys: true,
			runner: finishedRunner(note, true, note, name),
		}
		model := sized(newModelWith(note, backend, Defaults{ProviderID: "b", Model: note}), 1+(width%200+200)%200, 4+(height%60+60)%60)

		keys := []string{"enter", "down", "up", "esc", "d", "x", "backspace", "pgdown", "pgup", "home", "end", "b"}
		for step := range 60 {
			var command tea.Cmd
			model, command = press(t, model, keys[(int(seed)*7+step*5+step/3)%len(keys)])
			if model.modelsLoading {
				model = settle(model, func() tea.Msg { return modelsMsg{fetch: model.fetchID, models: []string{note}} })
			}
			if model.running {
				model = settle(model, command)
			}

			view := styleCodes.ReplaceAllString(model.View(), "")
			for _, character := range view {
				if character != '\n' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
					t.Fatalf("step %d: the view has the character %U", step, character)
				}
			}
			for _, line := range strings.Split(view, "\n") {
				if runewidth.StringWidth(line) > max(model.width, 1)+1 {
					t.Fatalf("step %d: the line %q is wider than the window %d", step, line, model.width)
				}
			}
		}
	})
}

func TestOnlyTheStepsThatMatterToTheUserArePrinted(t *testing.T) {
	waiting := func(ctx context.Context, step func(string)) (Result, error) { <-ctx.Done(); return Result{}, nil }
	model, _ := startedRun(t, waiting)

	for _, text := range []string{"run started", "sending request 1 to OpenAI", "answer received (step 1, 460 tokens used in total)", "run finished: finished"} {
		updated, command := model.Update(stepMsg{run: model.runID, text: text})
		model = updated.(Model)

		if lines := printedBy(command); len(lines) != 0 {
			t.Errorf("the step %q was printed: %q", text, lines)
		}
	}
	model.cancel()
}

func TestTheLiveLineShowsTheBudgetThatIsUsed(t *testing.T) {
	testCases := []struct {
		name  string
		steps []string
		want  []string
	}{
		{"before the first request", nil, []string{"[░░░░░░░░░░░░] 0%", "starting"}},
		{"after the first request", []string{"sending request 1 to OpenAI"}, []string{"6%", "request 1 of up to 15", "0 tokens", "OpenAI"}},
		{"tokens count more than requests", []string{"sending request 2 to OpenAI", "answer received (step 2, 150000 tokens used in total)"}, []string{"[██████░░░░░░] 50%", "request 2 of up to 15", "150,000 tokens"}},
		{"never more than a full bar", []string{"sending request 9 to OpenAI", "answer received (step 9, 900000 tokens used in total)"}, []string{"[████████████] 100%", "900,000 tokens"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			waiting := func(ctx context.Context, step func(string)) (Result, error) { <-ctx.Done(); return Result{}, nil }
			model, _ := startedRun(t, waiting)
			model.progress.maxRequests, model.progress.maxTokens = 15, 300000
			for _, text := range testCase.steps {
				updated, _ := model.Update(stepMsg{run: model.runID, text: text})
				model = updated.(Model)
			}

			view := model.View()
			for _, want := range testCase.want {
				if !strings.Contains(view, want) {
					t.Errorf("the live line has no %q:\n%s", want, view)
				}
			}
			model.cancel()
		})
	}
}

func TestAnUnknownStepIsStillPrinted(t *testing.T) {
	var current progress
	if current.read("something new happened") {
		t.Error("an unknown step was hidden")
	}
}
