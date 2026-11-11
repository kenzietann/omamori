package tui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
	"github.com/muesli/termenv"
)

func typeText(t testing.TB, model Model, text string) Model {
	t.Helper()

	for _, character := range text {
		message := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{character}}
		if character == ' ' {
			message = tea.KeyMsg{Type: tea.KeySpace}
		}
		updated, command := model.Update(message)
		if command != nil {
			t.Fatalf("typing %q returned a command, so it would quit or start something", character)
		}
		model = updated.(Model)
	}

	return model
}

func pasteText(t testing.TB, model Model, text string) Model {
	t.Helper()

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text), Paste: true})

	return updated.(Model)
}

var (
	keyedChoice  = Choice{ID: "anthropic", Name: "Anthropic", KeyEnv: "ANTHROPIC_API_KEY", DefaultModel: "claude-test"}
	foundChoice  = Choice{ID: "found", Name: "FoundAI", KeyEnv: "FOUND_API_KEY", KeyFound: true}
	noModelCheck = Choice{ID: "bare", Name: "BareAI", KeyEnv: "BARE_API_KEY"}
)

func hasNoUnsafeCharacters(view string) (rune, bool) {
	for _, character := range view {
		if character != '\n' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
			return character, false
		}
	}

	return 0, true
}

func TestTheSetupFlowForAProviderWithoutAKey(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, runner: finishedRunner("the report", true, "a step"), preview: "FIRST REQUEST LINE"}
	model := newModelWith("/work/project", backend, Defaults{})

	model, _ = press(t, model, "enter")
	if model.step != stepProvider || !strings.Contains(model.View(), "Choose the AI provider") || !strings.Contains(model.View(), "FakeAI   no key needed") {
		t.Fatalf("the provider step is wrong:\n%s", model.View())
	}

	model, command := press(t, model, "enter")
	if model.step != stepModel || !model.modelsLoading || command == nil || !strings.Contains(model.View(), "Getting the list of models from FakeAI") {
		t.Fatalf("the model list is not loading:\n%s", model.View())
	}
	if len(backend.setups) != 0 {
		t.Error("the backend was asked to prepare before the user chose a model")
	}

	model = settle(model, command)
	if model.modelsLoading || !strings.Contains(model.View(), "Choose the model:") || !strings.Contains(model.View(), "> m\n") || !strings.Contains(model.View(), "  other-model\n") || !strings.Contains(model.View(), "Type a model name myself") {
		t.Fatalf("the model list is wrong:\n%s", model.View())
	}
	if backend.modelCalls[0] != (modelCall{"fake", ""}) {
		t.Errorf("the model list was asked with %+v", backend.modelCalls)
	}

	model, _ = press(t, model, "enter")
	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0] != (Setup{ProviderID: "fake", Model: "m"}) {
		t.Fatalf("step = %d, setups = %+v", model.step, backend.setups)
	}
	view := model.View()
	for _, want := range []string{"Please confirm before anything is sent", "Omamori will send sanitized content to FakeAI during this run.", "Nothing has been sent yet", "FIRST REQUEST LINE"} {
		if !strings.Contains(view, want) {
			t.Errorf("the consent screen has no %q:\n%s", want, view)
		}
	}
	if backend.confirmed != 0 || model.screen != homeScreen {
		t.Error("something started before the user confirmed")
	}
	if footer := lastLine(view); !strings.Contains(footer, "enter: send and start") || !strings.Contains(footer, "esc: cancel") || !strings.Contains(footer, "q: quit") {
		t.Errorf("the consent footer is %q", footer)
	}

	model, command = press(t, model, "enter")
	if backend.confirmed != 1 || model.screen != runScreen || !model.running {
		t.Fatalf("confirmed = %d, screen = %d, running = %v", backend.confirmed, model.screen, model.running)
	}
	model = settle(model, command)
	if model.screen != resultsScreen || !strings.Contains(model.View(), "the report") || !strings.Contains(model.View(), "- a step") {
		t.Errorf("the run did not end on the results screen:\n%s", model.View())
	}
}

func TestTheProviderListShowsWhereEachKeyComes(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{keyedChoice, foundChoice, localChoice}}
	model, _ := press(t, newModelWith("/work/project", backend, Defaults{}), "enter")

	view := model.View()
	for _, want := range []string{"Anthropic   needs a key (ANTHROPIC_API_KEY)", "FoundAI   key found in FOUND_API_KEY", "FakeAI   no key needed"} {
		if !strings.Contains(view, want) {
			t.Errorf("the list has no %q:\n%s", want, view)
		}
	}
	if footer := lastLine(view); !strings.Contains(footer, "esc: back") || !strings.Contains(footer, "up/down") {
		t.Errorf("the footer is %q", footer)
	}
}

func TestTheProviderThatIsPreselected(t *testing.T) {
	testCases := []struct {
		name       string
		choices    []Choice
		defaults   Defaults
		wantCursor int
	}{
		{"the first one when nothing is known", []Choice{keyedChoice, noModelCheck}, Defaults{}, 0},
		{"the first one with a key in the environment", []Choice{keyedChoice, noModelCheck, foundChoice}, Defaults{}, 2},
		{"the one named in the settings", []Choice{keyedChoice, foundChoice, noModelCheck}, Defaults{ProviderID: "bare"}, 2},
		{"the settings win over the key", []Choice{keyedChoice, foundChoice}, Defaults{ProviderID: "anthropic"}, 0},
		{"an unknown name in the settings", []Choice{keyedChoice, foundChoice}, Defaults{ProviderID: "nope"}, 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			model, _ := press(t, newModelWith("/work/project", &fakeBackend{choices: testCase.choices}, testCase.defaults), "enter")

			if model.providerCursor != testCase.wantCursor {
				t.Errorf("cursor = %d, want %d", model.providerCursor, testCase.wantCursor)
			}
		})
	}
}

func TestTheProviderListMovesAndGoesBack(t *testing.T) {
	model, _ := press(t, newModelWith("/work/project", &fakeBackend{choices: []Choice{keyedChoice, foundChoice, localChoice}}, Defaults{}), "enter")

	for keys, want := range map[string]int{"down": 2, "up": 0} {
		moved := model
		for range 5 {
			moved, _ = press(t, moved, keys)
		}
		if moved.providerCursor != want {
			t.Errorf("after pressing %s five times the cursor is %d, want %d", keys, moved.providerCursor, want)
		}
	}

	back, _ := press(t, model, "esc")
	if back.step != stepMenu || back.screen != homeScreen {
		t.Errorf("esc did not go back to the menu: step %d", back.step)
	}

	if _, command := press(t, model, "q"); !isQuit(command) {
		t.Error("q does not quit on the provider list")
	}
}

func TestNoProvidersOrNoBackendStopsTheSetup(t *testing.T) {
	model, _ := press(t, newModelWith("/work/project", &fakeBackend{}, Defaults{}), "enter")

	if model.step != stepMenu || !strings.Contains(model.View(), "No AI provider is available.") {
		t.Errorf("step = %d:\n%s", model.step, model.View())
	}
}

func TestTheModelListMovesAndChooses(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, models: []string{"alpha", "beta", "gamma"}, preview: "p", runner: finishedRunner("r", true)}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter")

	if want := []string{"m", "alpha", "beta", "gamma"}; !slices.Equal(model.models, want) || model.modelCursor != 0 {
		t.Fatalf("models = %q, cursor = %d: the default model is added on top and selected", model.models, model.modelCursor)
	}

	for keys, want := range map[string]int{"down": 4, "up": 0, "pgdown": 4, "pgup": 0} {
		moved := model
		for range 6 {
			moved, _ = press(t, moved, keys)
		}
		if moved.modelCursor != want {
			t.Errorf("after pressing %s six times the cursor is %d, want %d (4 is the line to type a name)", keys, moved.modelCursor, want)
		}
	}

	model, _ = pressAll(t, model, "down", "down", "enter")
	if model.step != stepConsent || backend.setups[0].Model != "beta" {
		t.Errorf("step = %d, setups = %+v, want beta", model.step, backend.setups)
	}
}

func TestTypingAModelNameIsTheLastLineOfTheList(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", runner: finishedRunner("r", true)}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "down", "down", "enter")

	if !model.modelTyping || len(model.modelInput) != 0 || !strings.Contains(model.View(), "Model name:") {
		t.Fatalf("the typing screen is wrong:\n%s", model.View())
	}

	if model, _ = press(t, model, "enter"); model.step != stepModel || !strings.Contains(model.View(), needsModelText) || len(backend.setups) != 0 {
		t.Errorf("an empty model was accepted:\n%s", model.View())
	}
	model = typeText(t, model, "  ")
	if model, _ = press(t, model, "enter"); model.step != stepModel || !strings.Contains(model.View(), needsModelText) {
		t.Error("a model of only spaces was accepted")
	}

	model = typeText(t, model, "quick-model v2")
	if !strings.Contains(model.View(), "quick-model v2_") || model.setupError != "" {
		t.Errorf("typing is wrong (q is a letter here, and an edit clears the error):\n%s", model.View())
	}
	model, _ = pressAll(t, model, "backspace", "backspace", "backspace")
	if !strings.Contains(model.View(), "quick-model_") || strings.Contains(model.View(), "v2") {
		t.Errorf("backspace is wrong:\n%s", model.View())
	}
	for range 40 {
		model, _ = press(t, model, "backspace")
	}
	if len(model.modelInput) != 0 {
		t.Errorf("backspace left %q", string(model.modelInput))
	}

	if _, command := press(t, model, "ctrl+c"); !isQuit(command) {
		t.Error("ctrl+c does not quit during typing")
	}
	if back, _ := press(t, model, "esc"); back.step != stepModel || back.modelTyping {
		t.Errorf("esc must go back to the list: step %d, typing %v", back.step, back.modelTyping)
	}

	model = typeText(t, model, "my-model")
	model, _ = press(t, model, "enter")
	if model.step != stepConsent || backend.setups[0].Model != "my-model" {
		t.Errorf("step = %d, setups = %+v", model.step, backend.setups)
	}
}

func TestWhenTheListFailsTheUserTypesTheNameWithAHint(t *testing.T) {
	testCases := []struct {
		name     string
		backend  *fakeBackend
		wantText string
	}{
		{"the provider fails", &fakeBackend{modelsErr: errors.New("the list of models could not be loaded")}, noListText},
		{"the list is empty", &fakeBackend{models: []string{}}, emptyListText},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.backend.choices = []Choice{keyedChoice, foundChoice}
			testCase.backend.preview = "p"
			model, _ := pressAll(t, newModelWith("/work/project", testCase.backend, Defaults{ProviderID: "found", Model: "from-settings"}), "enter", "enter")

			if !model.modelTyping || string(model.modelInput) != "from-settings" || !strings.Contains(model.View(), testCase.wantText) || strings.Contains(model.View(), "Choose the model") {
				t.Fatalf("typing = %v, input = %q:\n%s", model.modelTyping, string(model.modelInput), model.View())
			}
			if back, _ := press(t, model, "esc"); back.step != stepProvider {
				t.Errorf("esc went to step %d, want the provider list because there is no list", back.step)
			}

			model, _ = press(t, model, "enter")
			if model.step != stepConsent || testCase.backend.setups[0].Model != "from-settings" {
				t.Errorf("step = %d, setups = %+v", model.step, testCase.backend.setups)
			}
		})
	}
}

func TestEscapeDuringLoadingGoesBackAndALateAnswerIsIgnored(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter")
	model, command := press(t, model, "enter")

	for _, key := range []string{"enter", "down", "x"} {
		if model, _ = press(t, model, key); !model.modelsLoading || model.step != stepModel {
			t.Fatalf("%q changed the loading screen", key)
		}
	}

	model, _ = press(t, model, "esc")
	late := settle(model, command)

	if late.step != stepProvider || late.modelTyping || late.models != nil {
		t.Errorf("a late answer changed the screen: step %d, typing %v, models %q", late.step, late.modelTyping, late.models)
	}

	again, secondCommand := press(t, late, "enter")
	staleThenNew := settle(again, secondCommand)
	if staleThenNew.step != stepModel || len(staleThenNew.models) == 0 {
		t.Errorf("the second load failed: step %d", staleThenNew.step)
	}
	if updated, _ := staleThenNew.Update(modelsMsg{fetch: 1, models: []string{"old"}}); slices.Contains(updated.(Model).models, "old") {
		t.Error("an answer of an old load was used")
	}
}

func TestQuitAndCtrlCWorkOnTheLoadingScreenAndTheList(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}}
	loading, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter")
	loading, _ = press(t, loading, "enter")
	listed := settle(loading, func() tea.Msg { return modelsMsg{fetch: loading.fetchID, models: []string{"a"}} })

	for name, model := range map[string]Model{"loading": loading, "list": listed} {
		for _, key := range []string{"q", "ctrl+c"} {
			if _, command := press(t, model, key); !isQuit(command) {
				t.Errorf("%s does not quit on %s", key, name)
			}
		}
	}
}

func TestALongListScrollsInsideTheWindow(t *testing.T) {
	var names []string
	for number := 1; number <= 100; number++ {
		names = append(names, fmt.Sprintf("model-%03d", number))
	}
	backend := &fakeBackend{choices: []Choice{localChoice}, models: names, preview: "p"}
	model := sized(newModelWith("/work/project", backend, Defaults{}), 80, 14)
	model, _ = pressAll(t, model, "enter", "enter")

	if count := strings.Count(model.View(), "\n") + 1; count > 14 {
		t.Errorf("the list has %d lines in a window of 14", count)
	}
	if !strings.Contains(model.View(), "> m\n") {
		t.Errorf("the first window is wrong:\n%s", model.View())
	}

	for range 60 {
		model, _ = press(t, model, "down")
		if count := strings.Count(model.View(), "\n") + 1; count > 14 {
			t.Fatalf("the list has %d lines after moving", count)
		}
		if !strings.Contains(model.View(), "> ") {
			t.Fatalf("the cursor left the window at %d:\n%s", model.modelCursor, model.View())
		}
	}
	for range 100 {
		model, _ = press(t, model, "down")
	}
	if !strings.Contains(model.View(), "> Type a model name myself") || !strings.Contains(model.View(), "model-100") {
		t.Errorf("the end of the list is not reachable:\n%s", model.View())
	}
}

func TestNamesFromTheProviderAreShownSafely(t *testing.T) {
	hostile := "evil\x1b[2J\u202emodel"
	backend := &fakeBackend{choices: []Choice{localChoice}, models: []string{hostile, strings.Repeat("w", 400)}}
	model := sized(newModelWith("/work/project", backend, Defaults{}), 40, 20)
	model, _ = pressAll(t, model, "enter", "enter")

	if character, ok := hasNoUnsafeCharacters(model.View()); !ok {
		t.Errorf("the list has the character %U", character)
	}
	for _, line := range strings.Split(model.View(), "\n") {
		if runewidth.StringWidth(line) > 40 {
			t.Errorf("the line %q is wider than the window", line)
		}
	}
}

func TestTheDefaultModelIsSelectedAndTheSettingsCanChangeIt(t *testing.T) {
	testCases := []struct {
		name      string
		defaults  Defaults
		models    []string
		wantModel string
		wantFirst string
	}{
		{"the provider's default", Defaults{}, []string{"a", "claude-test", "z"}, "claude-test", "a"},
		{"the default is added when the list lacks it", Defaults{}, []string{"a", "z"}, "claude-test", "claude-test"},
		{"the model from the settings for that provider", Defaults{ProviderID: "anthropic", Model: "z"}, []string{"a", "claude-test", "z"}, "z", "a"},
		{"a model from the settings for another provider is not used", Defaults{ProviderID: "other", Model: "z"}, []string{"a", "claude-test", "z"}, "claude-test", "a"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{choices: []Choice{keyedChoice}, models: testCase.models}
			model, _ := pressAll(t, newModelWith("/work/project", backend, testCase.defaults), "enter", "enter", "x", "enter")

			if model.models[model.modelCursor] != testCase.wantModel || model.models[0] != testCase.wantFirst {
				t.Errorf("selected %q, first %q, want %q and %q", model.models[model.modelCursor], model.models[0], testCase.wantModel, testCase.wantFirst)
			}
		})
	}
}

func TestPastedAndLongInputIsCleaned(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{noModelCheck}, modelsErr: errors.New("no list")}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "x", "enter")

	model = pasteText(t, model, "a\nb\x00c\x1b[31md\u202ee\r\tf")
	if got := string(model.modelInput); got != "abc[31mdef" {
		t.Errorf("model = %q, want the control characters removed", got)
	}

	model = pasteText(t, model, strings.Repeat("x", 500))
	if len(model.modelInput) != maxModelRunes {
		t.Errorf("the model name has %d characters, want the limit %d", len(model.modelInput), maxModelRunes)
	}
	if character, ok := hasNoUnsafeCharacters(model.View()); !ok {
		t.Errorf("the view has the character %U", character)
	}
}

func TestTheKeyStepHidesTheKeyEverywhere(t *testing.T) {
	const key = "sk-SECRET-key-123456"
	backend := &fakeBackend{choices: []Choice{keyedChoice}, preview: "p", runner: finishedRunner("the report", true, "step")}
	model := newModelWith("/work/project", backend, Defaults{})
	model, _ = pressAll(t, model, "enter", "enter")

	if model.step != stepKey || !strings.Contains(model.View(), "API key (hidden):") || !strings.Contains(model.View(), "set ANTHROPIC_API_KEY") || len(backend.modelCalls) != 0 {
		t.Fatalf("the key step is wrong:\n%s", model.View())
	}

	if model, _ = press(t, model, "enter"); !strings.Contains(model.View(), needsKeyText) || model.step != stepKey || len(backend.modelCalls) != 0 {
		t.Error("an empty key was accepted")
	}

	model = typeText(t, model, key)
	if view := model.View(); strings.Contains(view, key) || strings.Contains(view, "SECRET") || !strings.Contains(view, strings.Repeat("•", len(key))+"_") {
		t.Errorf("the key is shown, or the dots are missing:\n%s", view)
	}
	model = pasteText(t, model, "\nPASTED-TAIL")
	if strings.Contains(model.View(), "PASTED") {
		t.Error("a pasted part of the key is shown")
	}

	model, _ = press(t, model, "backspace")
	model, _ = press(t, model, "esc")
	if model.step != stepProvider || model.keyInput != nil || strings.Contains(model.View(), "SECRET") {
		t.Errorf("going back must forget the key: step %d, key %q", model.step, string(model.keyInput))
	}

	model, _ = pressAll(t, model, "enter")
	model = typeText(t, model, key)
	model, _ = pressAll(t, model, "enter")

	if model.step != stepModel || len(backend.modelCalls) != 1 || backend.modelCalls[0] != (modelCall{"anthropic", key}) {
		t.Fatalf("step = %d, model calls = %+v: the list must be asked with the typed key", model.step, backend.modelCalls)
	}
	if view := model.View(); strings.Contains(view, key) || !strings.Contains(view, "Choose the model:") {
		t.Errorf("the list screen is wrong:\n%s", view)
	}

	model, _ = press(t, model, "enter")
	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0] != (Setup{ProviderID: "anthropic", Model: "claude-test", Key: key}) {
		t.Fatalf("step = %d, setups = %+v", model.step, backend.setups)
	}
	if model.keyInput != nil {
		t.Error("the model still holds the key after the backend took it")
	}

	model, command := press(t, model, "enter")
	views := []string{model.View()}
	model = settle(model, command)
	views = append(views, model.View())
	for index, view := range views {
		if strings.Contains(view, key) || strings.Contains(view, "SECRET") {
			t.Errorf("screen %d shows the key:\n%s", index, view)
		}
	}
}

func TestAKeyInTheEnvironmentSkipsTheKeyStep(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{foundChoice}, models: []string{"some-model"}, preview: "p", runner: finishedRunner("r", true)}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter")

	if model.step != stepModel || backend.modelCalls[0] != (modelCall{"found", ""}) {
		t.Fatalf("step = %d, model calls = %+v, want the key step skipped and no key passed", model.step, backend.modelCalls)
	}
	model, _ = press(t, model, "enter")

	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0] != (Setup{ProviderID: "found", Model: "some-model", Key: ""}) {
		t.Errorf("step = %d, setups = %+v", model.step, backend.setups)
	}
}

func TestSetupErrorsAreShownWhereTheUserCanFixThem(t *testing.T) {
	const key = "wrong-key"
	backend := &fakeBackend{choices: []Choice{keyedChoice}, prepareErr: errors.New("the provider could not be set up")}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter")
	model = typeText(t, model, key)
	model, _ = pressAll(t, model, "enter")

	model, _ = press(t, model, "enter")

	if model.step != stepModel || !strings.Contains(model.View(), "the provider could not be set up") || strings.Contains(model.View(), key) {
		t.Errorf("step = %d:\n%s", model.step, model.View())
	}
	if string(model.keyInput) != key {
		t.Error("the key must stay so that a second try can work")
	}

	backend.prepareErr = nil
	if model, _ = press(t, model, "enter"); model.step != stepConsent || backend.setups[1].Key != key || model.keyInput != nil {
		t.Errorf("a second try failed: step %d, setups %+v", model.step, backend.setups)
	}

	typing := &fakeBackend{choices: []Choice{localChoice}, modelsErr: errors.New("x"), prepareErr: errors.New("the project folder is not usable")}
	again, _ := pressAll(t, newModelWith("/work/project", typing, Defaults{}), "enter", "enter", "enter")
	if again.step != stepModel || !strings.Contains(again.View(), "the project folder is not usable") {
		t.Errorf("an error on the typing screen is not shown:\n%s", again.View())
	}
	typed := typeText(t, again, "x")
	if typed.setupError != "" {
		t.Error("the error stays after the user edits")
	}

	listed := &fakeBackend{choices: []Choice{localChoice}, prepareErr: errors.New("the project folder is not usable")}
	onList, _ := pressAll(t, newModelWith("/work/project", listed, Defaults{}), "enter", "enter", "enter")
	if onList.step != stepModel || onList.modelTyping || !strings.Contains(onList.View(), "the project folder is not usable") {
		t.Errorf("an error on the list is not shown:\n%s", onList.View())
	}
}

func TestCancellingTheConsentSendsNothing(t *testing.T) {
	for _, key := range []string{"esc", "n"} {
		t.Run(key, func(t *testing.T) {
			calls := 0
			backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", runner: func(context.Context, func(string)) (Result, error) { calls++; return Result{}, nil }}
			model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")

			model, command := press(t, model, key)

			if model.step != stepMenu || model.plan != nil || command != nil || backend.confirmed != 0 || calls != 0 {
				t.Errorf("step = %d, plan = %v, confirmed = %d, run calls = %d", model.step, model.plan, backend.confirmed, calls)
			}
			if !strings.Contains(model.View(), "Nothing was sent.") {
				t.Errorf("the menu does not say that nothing was sent:\n%s", model.View())
			}
			if _, command := press(t, model, "enter"); command != nil && backend.confirmed != 0 {
				t.Error("a later enter confirmed the old plan")
			}
		})
	}
}

func TestNothingStartsUntilEnterOnTheConsentScreen(t *testing.T) {
	calls := 0
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: strings.Repeat("line\n", 50), runner: func(context.Context, func(string)) (Result, error) {
		calls++
		return Result{Report: "r", Complete: true}, nil
	}}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")

	for _, key := range []string{"up", "down", "pgup", "pgdown", "b", "x"} {
		model, _ = press(t, model, key)
	}
	if calls != 0 || backend.confirmed != 0 || model.step != stepConsent {
		t.Fatalf("something started early: run calls = %d, confirmed = %d, step = %d", calls, backend.confirmed, model.step)
	}

	model, command := press(t, model, "y")
	settle(model, command)
	if calls != 1 || backend.confirmed != 1 {
		t.Errorf("run calls = %d, confirmed = %d, want 1 and 1", calls, backend.confirmed)
	}

	// A second enter on the same plan cannot start a second run.
	again, command := press(t, model, "enter")
	if again.step == stepConsent || (command != nil && calls > 1) {
		t.Error("the same plan was confirmed twice")
	}
}

func TestQuitOnTheConsentScreenStartsNothing(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", runner: finishedRunner("r", true)}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")

	_, command := press(t, model, "q")

	if !isQuit(command) || backend.confirmed != 0 {
		t.Errorf("quit = %v, confirmed = %d", isQuit(command), backend.confirmed)
	}
}

func TestTheDryRunScrollsAndFitsTheWindow(t *testing.T) {
	var lines []string
	for number := 1; number <= 60; number++ {
		lines = append(lines, fmt.Sprintf("preview line %d", number))
	}
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: strings.Join(lines, "\n"), runner: finishedRunner("r", true)}
	model := sized(newModelWith("/work/project", backend, Defaults{}), 80, 24)
	model, _ = pressAll(t, model, "enter", "enter", "enter")

	view := model.View()
	if count := strings.Count(view, "\n") + 1; count > 24 {
		t.Errorf("the consent screen has %d lines in a window of 24", count)
	}
	if !strings.Contains(view, "preview line 1\n") || strings.Contains(view, "preview line 15\n") || !strings.Contains(view, "Omamori will send sanitized content") {
		t.Errorf("the first window is wrong:\n%s", view)
	}

	model, _ = press(t, model, "down")
	model, _ = press(t, model, "pgdown")
	if model.consentScroll != 1+model.consentViewHeight() {
		t.Errorf("scroll = %d after down and pgdown", model.consentScroll)
	}
	for range 100 {
		model, _ = press(t, model, "down")
	}
	if model.consentScroll != model.maxConsentScroll() || !strings.Contains(model.View(), "preview line 60") {
		t.Errorf("the end of the preview is not reachable (scroll %d, max %d):\n%s", model.consentScroll, model.maxConsentScroll(), model.View())
	}
	for range 100 {
		model, _ = press(t, model, "up")
	}
	if model.consentScroll != 0 {
		t.Errorf("scroll = %d at the top", model.consentScroll)
	}
	if model, _ = press(t, model, "pgup"); model.consentScroll != 0 {
		t.Error("pgup went above the top")
	}
}

func TestTheSavedFolderIsShownOnTheResultsScreen(t *testing.T) {
	runner := func(ctx context.Context, step func(string)) (Result, error) {
		return Result{Report: "the report\nline two\nline three\nline four\nline five\nline six", Complete: true, SavedTo: "/home/me/omamori-output/run-1"}, nil
	}
	model, command := startedRun(t, runner)
	model = settle(model, command)

	if !strings.Contains(model.View(), "Saved to: /home/me/omamori-output/run-1") {
		t.Errorf("the saved folder is not shown:\n%s", model.View())
	}

	small := sized(model, 60, 9)
	if lines := strings.Count(small.View(), "\n") + 1; lines > 9 {
		t.Errorf("the results screen has %d lines in a window of 9", lines)
	}
	for range 10 {
		small, _ = press(t, small, "down")
	}
	if !strings.Contains(small.View(), "Timeline") {
		t.Errorf("the end of the report is not reachable when a saved line takes room:\n%s", small.View())
	}

	next, command := beginRun(t, func() Model { home, _ := press(t, model, "b"); return home }())
	if next.saved != "" || strings.Contains(next.View(), "Saved to") {
		t.Error("the saved folder of the old run is still shown")
	}
	_ = command
}

func TestUntrustedSetupTextIsCleaned(t *testing.T) {
	hostile := "a\x1b[999mred\x1b]0;title\x07 b\u202eevil\u200b c\x00d"
	for _, profile := range []termenv.Profile{termenv.Ascii, termenv.TrueColor} {
		withProfile(t, profile)

		backend := &fakeBackend{
			choices:    []Choice{{ID: "x", Name: hostile, KeyEnv: hostile, DefaultModel: hostile}},
			models:     []string{hostile, "fine"},
			consent:    hostile,
			preview:    hostile + "\n" + hostile,
			runner:     hostileRunner(hostile),
			prepareErr: errors.New(hostile),
		}
		model := newModelWith(hostile, backend, Defaults{ProviderID: hostile, Model: hostile})

		var views []string
		model, _ = press(t, model, "enter")
		views = append(views, model.View())
		model, _ = press(t, model, "enter")
		views = append(views, model.View())
		model = typeText(t, model, hostile)
		model, _ = pressAll(t, model, "enter")
		views = append(views, model.View())
		model, _ = press(t, model, "enter")
		views = append(views, model.View())
		backend.prepareErr = nil
		model, _ = press(t, model, "enter")
		views = append(views, model.View())
		model, command := press(t, model, "enter")
		views = append(views, model.View())
		model = settle(model, command)
		views = append(views, model.View())

		for index, view := range views {
			if strings.Contains(view, "\x1b[999m") || strings.Contains(view, "\x1b]") {
				t.Errorf("profile %v, screen %d: an escape code from the input got through", profile, index)
			}
			if character, ok := hasNoUnsafeCharacters(styleCodes.ReplaceAllString(view, "")); !ok {
				t.Errorf("profile %v, screen %d: the view has the character %U", profile, index, character)
			}
		}
	}
}

func FuzzSetup(f *testing.F) {
	f.Add("FakeAI", "model-1", "KEY-abcdefgh", "a note", 80, 24)
	f.Add("a\x1b[2J\u202e", "\x00\x07", "KEY-\n\t\x1b", "\x1b]0;x\x07", 0, 0)
	f.Add("", "", "", "", 3, 1)

	f.Fuzz(func(t *testing.T, name, modelText, keyText, note string, width, height int) {
		backend := &fakeBackend{
			choices: []Choice{{ID: "a", Name: name, KeyEnv: name, DefaultModel: note}},
			models:  []string{"m-" + modelText, note},
			preview: note, runner: finishedRunner(note, true, note), prepareErr: errors.New(note),
		}
		secret := "KEY-" + keyText
		model := sized(newModelWith(note, backend, Defaults{}), width%300, height%100)

		var views []string
		for _, step := range []func(Model) Model{
			func(m Model) Model { m, _ = press(t, m, "enter"); return m },
			func(m Model) Model { m, _ = press(t, m, "enter"); return m },
			func(m Model) Model { return pasteText(t, m, secret) },
			func(m Model) Model { views = append(views, m.View()); m, _ = pressAll(t, m, "enter"); return m },
			func(m Model) Model { m, _ = press(t, m, "down"); return m },
			func(m Model) Model { m, _ = press(t, m, "enter"); return m },
			func(m Model) Model { backend.prepareErr = nil; m, _ = press(t, m, "enter"); return m },
			func(m Model) Model { m, _ = press(t, m, "down"); return m },
		} {
			model = step(model)
			views = append(views, model.View())
		}

		cleanedSecret := cleanInput(secret)
		if len([]rune(cleanedSecret)) > maxKeyRunes {
			cleanedSecret = string([]rune(cleanedSecret)[:maxKeyRunes])
		}
		for index, view := range views {
			if character, ok := hasNoUnsafeCharacters(view); !ok {
				t.Fatalf("screen %d has the character %U", index, character)
			}
			if len([]rune(cleanedSecret)) >= 12 && strings.Contains(view, cleanedSecret) {
				t.Fatalf("screen %d shows the key", index)
			}
		}
	})
}

func hostileRunner(hostile string) Runner {
	return func(ctx context.Context, step func(string)) (Result, error) {
		step(hostile)

		return Result{Report: hostile, Complete: true, SavedTo: hostile}, nil
	}
}

func TestAVeryLongDefaultModelIsCut(t *testing.T) {
	long := Choice{ID: "long", Name: "LongAI", KeyFound: true}
	model, _ := pressAll(t, newModelWith("/work/project", &fakeBackend{choices: []Choice{long}}, Defaults{ProviderID: "long", Model: strings.Repeat("m", 500)}), "enter", "enter")

	if len(model.models[0]) != maxModelRunes {
		t.Errorf("the model from the settings has %d characters, want the limit %d", len(model.models[0]), maxModelRunes)
	}
}

func TestSeveralPastesCannotGrowThePastTheLimit(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{noModelCheck}, modelsErr: errors.New("no list")}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "x", "enter")

	for range 5 {
		model = pasteText(t, model, strings.Repeat("x", 150))
	}

	if len(model.modelInput) != maxModelRunes {
		t.Errorf("five pastes made %d characters, want the limit %d", len(model.modelInput), maxModelRunes)
	}
}

func TestGoingBackFromTheModelListForgetsTheKey(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{keyedChoice}}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter")
	model = typeText(t, model, "sk-SECRET")
	model, _ = pressAll(t, model, "enter")
	if model.step != stepModel || len(model.keyInput) == 0 {
		t.Fatalf("step = %d: the key must be held while the user chooses a model", model.step)
	}

	back, _ := press(t, model, "esc")

	if back.step != stepProvider || back.keyInput != nil {
		t.Errorf("step = %d, key = %q", back.step, string(back.keyInput))
	}
}
