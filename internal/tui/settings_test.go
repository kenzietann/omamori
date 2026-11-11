package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/mattn/go-runewidth"
)

var (
	savedChoice = Choice{ID: "openai", Name: "OpenAI", KeyEnv: "OPENAI_API_KEY", KeySaved: true}
	plainChoice = Choice{ID: "anthropic", Name: "Anthropic", KeyEnv: "ANTHROPIC_API_KEY", DefaultModel: "claude-test"}
)

func TestTheKeyStepSaysTheTruthAboutSaving(t *testing.T) {
	for canSave, want := range map[bool]string{
		true:  "After it works, the key is saved in your Keychain",
		false: "This system cannot save keys",
	} {
		backend := &fakeBackend{choices: []Choice{plainChoice}, canSaveKeys: canSave}

		model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter")

		if !strings.Contains(model.View(), want) {
			t.Errorf("can save %v: the key step has no %q:\n%s", canSave, want, model.View())
		}
		if strings.Contains(model.View(), "never shown, saved, or logged") {
			t.Error("the old promise that nothing is saved is still shown")
		}
	}
}

func TestATypedKeyIsSavedOnlyAfterTheProviderAcceptedIt(t *testing.T) {
	const key = "sk-SECRET-key-123456"
	testCases := []struct {
		name       string
		backend    *fakeBackend
		wantSaved  bool
		wantNotice string
	}{
		{"the list loads", &fakeBackend{canSaveKeys: true}, true, "The key was saved in your Keychain."},
		{"saving fails", &fakeBackend{canSaveKeys: true, saveKeyErr: errors.New("no")}, true, "The key could not be saved. You will need to type it next time."},
		{"this system cannot save", &fakeBackend{canSaveKeys: false}, false, ""},
		{"the list fails", &fakeBackend{canSaveKeys: true, modelsErr: errors.New("no list")}, false, ""},
		{"the list is empty", &fakeBackend{canSaveKeys: true, models: []string{}}, false, ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.backend.choices = []Choice{plainChoice}
			model, _ := pressAll(t, newModelWith("/work/project", testCase.backend, Defaults{}), "enter", "enter")
			model = typeText(t, model, key)

			model, _ = pressAll(t, model, "enter")

			if saved := len(testCase.backend.savedKeys) == 1 && testCase.backend.savedKeys[0] == (modelCall{"anthropic", key}); saved != testCase.wantSaved {
				t.Errorf("saved keys = %+v, want saved %v", testCase.backend.savedKeys, testCase.wantSaved)
			}
			if testCase.wantNotice != "" && !strings.Contains(model.View(), testCase.wantNotice) {
				t.Errorf("the screen has no %q:\n%s", testCase.wantNotice, model.View())
			}
			if testCase.wantNotice == "" && strings.Contains(model.View(), "Keychain") {
				t.Errorf("a notice about saving is shown:\n%s", model.View())
			}
			if strings.Contains(model.View(), key) || strings.Contains(model.View(), "SECRET") {
				t.Error("the key is shown")
			}
		})
	}
}

func TestAKeyThatIsNotTypedIsNeverSavedAgain(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice, foundChoice}, canSaveKeys: true, models: []string{"m1"}}

	pressAll(t, newModelWith("/work/project", backend, Defaults{ProviderID: "openai"}), "enter", "enter")
	pressAll(t, newModelWith("/work/project", backend, Defaults{ProviderID: "found"}), "enter", "enter")

	if len(backend.savedKeys) != 0 {
		t.Errorf("saved keys = %+v: a key from the environment or the store must not be written again", backend.savedKeys)
	}
}

func TestASavedKeySkipsTheKeyStepAndIsShownInTheList(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{plainChoice, savedChoice}, models: []string{"gpt-x"}, preview: "p"}
	model, _ := press(t, newModelWith("/work/project", backend, Defaults{}), "enter")

	if !strings.Contains(model.View(), "OpenAI   key saved in your Keychain") || model.providerCursor != 1 {
		t.Errorf("cursor = %d:\n%s", model.providerCursor, model.View())
	}

	model, _ = pressAll(t, model, "enter")
	if model.step != stepModel || backend.modelCalls[0] != (modelCall{"openai", ""}) {
		t.Errorf("step = %d, model calls = %+v: no key may be typed or passed for a saved key", model.step, backend.modelCalls)
	}
}

func TestAKeyTheProviderRejectsAsksForANewKey(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, modelsErr: ErrKeyRejected, canSaveKeys: true, preview: "p"}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter")

	if model.step != stepKey || model.keyInput != nil || !strings.Contains(model.View(), "The provider rejected the key. Type a new key.") || !strings.Contains(model.View(), "API key (hidden):") {
		t.Fatalf("step = %d:\n%s", model.step, model.View())
	}
	if len(backend.savedKeys) != 0 {
		t.Error("a rejected key was saved")
	}

	backend.modelsErr = nil
	model = typeText(t, model, "sk-new-key")
	model, _ = pressAll(t, model, "enter")

	if model.step != stepModel || backend.modelCalls[1] != (modelCall{"openai", "sk-new-key"}) || backend.savedKeys[0] != (modelCall{"openai", "sk-new-key"}) {
		t.Errorf("step = %d, model calls = %+v, saved = %+v", model.step, backend.modelCalls, backend.savedKeys)
	}
}

func TestTheHomeMenuHasSettingsBeforeQuit(t *testing.T) {
	model := newModel("/work/project", nil)

	if !strings.Contains(model.View(), "Settings") || strings.Index(model.View(), "Settings") > strings.Index(model.View(), "Quit") {
		t.Errorf("the menu is wrong:\n%s", model.View())
	}
	opened, _ := pressAll(t, model, "down", "down", "enter")
	if opened.step != stepSettings {
		t.Errorf("step = %d", opened.step)
	}
	quit, command := pressAll(t, model, "up", "enter")
	if !isQuit(command) || quit.step == stepSettings {
		t.Error("up from the top must reach Quit")
	}
}

func TestSettingsShowTheCurrentChoices(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{plainChoice, savedChoice}}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{ProviderID: "openai", Model: "gpt-x", Reasoning: "high"}), "down", "down", "enter")

	for _, want := range []string{"Settings", "Provider:   OpenAI", "Model:      gpt-x", "Reasoning:  high", "API key:    key saved in your Keychain", "❯ Change provider, model and reasoning level", "Forget the saved key of OpenAI", "Back to the home screen"} {
		if !strings.Contains(model.View(), want) {
			t.Errorf("the settings have no %q:\n%s", want, model.View())
		}
	}

	empty, _ := pressAll(t, newModelWith("/work/project", &fakeBackend{choices: []Choice{plainChoice}}, Defaults{}), "down", "down", "enter")
	for _, want := range []string{"Provider:   (not chosen)", "Model:      (not chosen)", "Reasoning:  provider default"} {
		if !strings.Contains(empty.View(), want) {
			t.Errorf("the empty settings have no %q:\n%s", want, empty.View())
		}
	}
	if strings.Contains(empty.View(), "Forget") {
		t.Error("a forget line is shown without a saved key")
	}
}

func TestSettingsMoveAroundAndGoBack(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "down", "enter")

	up, _ := press(t, model, "up")
	down, _ := pressAll(t, model, "down", "down", "down")
	if up.settingsCursor != 2 || down.settingsCursor != 0 {
		t.Errorf("up from the first: %d (want 2), three downs: %d (want 0)", up.settingsCursor, down.settingsCursor)
	}

	for name, keys := range map[string][]string{"esc": {"esc"}, "the back line": {"up", "enter"}} {
		back, _ := pressAll(t, model, keys...)
		if back.step != stepMenu || back.settingsMode {
			t.Errorf("%s: step = %d", name, back.step)
		}
	}
	if _, command := press(t, model, "q"); !isQuit(command) {
		t.Error("q does not quit in the settings")
	}
}

func TestChangingTheSettingsSavesThemAndNeverAsksForAPlan(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{plainChoice, savedChoice}, models: []string{"gpt-a", "gpt-b"}, reasoning: testLevels, preview: "p"}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "down", "enter", "enter")

	if model.step != stepProvider || !model.settingsMode || model.providerCursor != 0 {
		t.Fatalf("step = %d", model.step)
	}
	model, _ = pressAll(t, model, "down", "enter")
	if model.step != stepModel {
		t.Fatalf("step = %d", model.step)
	}
	model, _ = pressAll(t, model, "enter")
	if model.step != stepReasoning {
		t.Fatalf("step = %d", model.step)
	}
	model, _ = pressAll(t, model, "down", "enter")

	want := Defaults{ProviderID: "openai", Model: "gpt-a", Reasoning: "low"}
	if model.step != stepSettings || len(backend.savedSettings) != 1 || backend.savedSettings[0] != want || model.defaults != want {
		t.Fatalf("step = %d, saved = %+v, defaults = %+v", model.step, backend.savedSettings, model.defaults)
	}
	if len(backend.setups) != 0 || backend.confirmed != 0 {
		t.Error("the settings asked for a plan, which could start a run")
	}
	for _, text := range []string{"Settings saved.", "Provider:   OpenAI", "Model:      gpt-a", "Reasoning:  low"} {
		if !strings.Contains(model.View(), text) {
			t.Errorf("the settings screen has no %q:\n%s", text, model.View())
		}
	}
}

func TestTheSettingsFlowStartsWhereTheSavedChoicesAre(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{plainChoice, savedChoice}, models: []string{"gpt-a", "gpt-b", "gpt-c"}, reasoning: testLevels}
	saved := Defaults{ProviderID: "openai", Model: "gpt-b", Reasoning: "high"}
	model, _ := pressAll(t, newModelWith("/work/project", backend, saved), "down", "down", "enter", "enter")

	if model.providerCursor != 1 {
		t.Errorf("the provider cursor is %d, want the saved provider", model.providerCursor)
	}
	model, _ = pressAll(t, model, "enter")
	if model.models[model.modelCursor] != "gpt-b" {
		t.Errorf("the model cursor is on %q", model.models[model.modelCursor])
	}
	model, _ = pressAll(t, model, "enter")
	if model.step != stepReasoning || model.reasonChoices[model.reasonCursor].Value != "high" {
		t.Errorf("step = %d, the level cursor is %d", model.step, model.reasonCursor)
	}
}

func TestEscapeInTheSettingsFlowGoesBackToTheSettings(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "down", "enter", "enter")

	back, _ := press(t, model, "esc")

	if back.step != stepSettings || len(backend.savedSettings) != 0 {
		t.Errorf("step = %d, saved = %+v", back.step, backend.savedSettings)
	}
}

func TestASettingsSaveErrorIsShownAndTheFlowStays(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, models: []string{"gpt-a"}, saveSettingsErr: errors.New("the settings file cannot be written")}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "down", "enter", "enter", "enter", "enter")

	if model.step != stepModel || !strings.Contains(model.View(), "the settings file cannot be written") || model.defaults != (Defaults{}) {
		t.Errorf("step = %d, defaults = %+v:\n%s", model.step, model.defaults, model.View())
	}

	backend.saveSettingsErr = nil
	if model, _ = press(t, model, "enter"); model.step != stepSettings || model.defaults.Model != "gpt-a" {
		t.Errorf("the second try failed: step %d", model.step)
	}
}

func TestSettingsWithATypedKeyWipeItWhenDone(t *testing.T) {
	const key = "sk-SECRET-key-123456"
	backend := &fakeBackend{choices: []Choice{plainChoice}, models: []string{"claude-test"}, canSaveKeys: true}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "down", "enter", "enter", "enter")
	model = typeText(t, model, key)

	model, _ = pressAll(t, model, "enter", "enter")

	if model.step != stepSettings || model.keyInput != nil || backend.savedKeys[0] != (modelCall{"anthropic", key}) {
		t.Errorf("step = %d, key kept = %v, saved = %+v", model.step, model.keyInput != nil, backend.savedKeys)
	}
	if strings.Contains(model.View(), key) {
		t.Error("the key is shown")
	}
}

func TestForgettingASavedKey(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice, {ID: "gemini", Name: "Gemini", KeySaved: true}}}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "down", "enter", "down", "enter")

	if len(backend.forgotKeys) != 1 || backend.forgotKeys[0] != "openai" || !strings.Contains(model.View(), "The saved key was removed.") {
		t.Fatalf("forgot = %q:\n%s", backend.forgotKeys, model.View())
	}
	if strings.Contains(model.View(), "Forget the saved key of OpenAI") || !strings.Contains(model.View(), "Forget the saved key of Gemini") {
		t.Errorf("the list was not refreshed:\n%s", model.View())
	}
	if model.settingsCursor != 0 {
		t.Errorf("the cursor is %d after the list changed", model.settingsCursor)
	}
}

func TestAKeyThatCannotBeForgottenSaysSo(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, forgetKeyErr: errors.New("details that must not be shown")}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "down", "down", "enter", "down", "enter")

	if !strings.Contains(model.View(), "The saved key could not be removed.") || strings.Contains(model.View(), "details") || !strings.Contains(model.View(), "Forget the saved key of OpenAI") {
		t.Errorf("the screen is wrong:\n%s", model.View())
	}
}

func TestSettingsTextFromTheBackendIsShownSafelyAndFits(t *testing.T) {
	hostile := "evil\x1b[2J\u202e" + strings.Repeat("w", 100)
	backend := &fakeBackend{choices: []Choice{{ID: "x", Name: hostile, KeySaved: true}}}
	model := sized(newModelWith("/work/project", backend, Defaults{ProviderID: "x", Model: hostile, Reasoning: hostile}), 40, 24)
	model, _ = pressAll(t, model, "down", "down", "enter")

	if character, ok := hasNoUnsafeCharacters(model.View()); !ok {
		t.Errorf("the view has the character %U", character)
	}
	for _, line := range strings.Split(model.View(), "\n") {
		if runewidth.StringWidth(line) > 40 {
			t.Errorf("the line %q is wider than the window", line)
		}
	}
}

func TestTaskAGoesStraightToTheConsentScreenWithCompleteSavedChoices(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{plainChoice, savedChoice}, preview: "FIRST REQUEST", runner: finishedRunner("r", true), reasoning: testLevels}
	saved := Defaults{ProviderID: "openai", Model: "gpt-x", Reasoning: "high"}

	model, _ := press(t, newModelWith("/work/project", backend, saved), "enter")

	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0] != (Setup{ProviderID: "openai", Model: "gpt-x", Reasoning: "high"}) {
		t.Fatalf("step = %d, setups = %+v", model.step, backend.setups)
	}
	if len(backend.modelCalls) != 0 {
		t.Error("the model list was asked for although the choices are saved")
	}
	if !strings.Contains(model.View(), "Please confirm before anything is sent") || !strings.Contains(model.View(), "FIRST REQUEST") {
		t.Errorf("the consent page is wrong:\n%s", model.View())
	}
	if backend.confirmed != 0 || model.screen != homeScreen {
		t.Error("something started before the user confirmed")
	}

	cancelled, _ := press(t, model, "esc")
	if cancelled.step != stepMenu || backend.confirmed != 0 {
		t.Errorf("step = %d, confirmed = %d", cancelled.step, backend.confirmed)
	}
	started, command := press(t, model, "enter")
	if started.screen != runScreen || backend.confirmed != 1 {
		t.Fatalf("screen = %d, confirmed = %d", started.screen, backend.confirmed)
	}
	if len(backend.savedSettings) != 0 {
		t.Errorf("unchanged settings were saved again: %+v", backend.savedSettings)
	}
	_ = settle(started, command)
}

func TestTaskAUsesTheNormalStepsWhenTheSavedChoicesAreNotUsable(t *testing.T) {
	testCases := []struct {
		name     string
		choices  []Choice
		defaults Defaults
	}{
		{"no model saved", []Choice{savedChoice}, Defaults{ProviderID: "openai"}},
		{"no provider saved", []Choice{savedChoice}, Defaults{Model: "gpt-x"}},
		{"the provider is not in the list", []Choice{savedChoice}, Defaults{ProviderID: "nope", Model: "gpt-x"}},
		{"the provider has no key", []Choice{plainChoice}, Defaults{ProviderID: "anthropic", Model: "claude-test"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{choices: testCase.choices}

			model, _ := press(t, newModelWith("/work/project", backend, testCase.defaults), "enter")

			if model.step != stepProvider || len(backend.setups) != 0 {
				t.Errorf("step = %d, setups = %+v", model.step, backend.setups)
			}
		})
	}
}

func TestSavedChoicesThatFailShowWhyAndPointToTheSettings(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, prepareErr: errors.New("this reasoning level is not available for this model")}

	model, command := press(t, newModelWith("/work/project", backend, Defaults{ProviderID: "openai", Model: "gpt-x", Reasoning: "max"}), "enter")

	if model.step != stepMenu || command != nil || backend.confirmed != 0 {
		t.Fatalf("step = %d", model.step)
	}
	for _, want := range []string{"Your saved settings did not work: this reasoning level is not available for this model.", "Open Settings to change them."} {
		if !strings.Contains(model.View(), want) {
			t.Errorf("the menu has no %q:\n%s", want, model.View())
		}
	}
}

func TestTheChoicesOfAConfirmedRunAreSavedForTheNextRun(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, models: []string{"gpt-a", "gpt-b"}, preview: "p", runner: finishedRunner("r", true), reasoning: testLevels}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "down", "enter", "down", "enter")

	if len(backend.savedSettings) != 0 {
		t.Fatalf("settings were saved before the user confirmed: %+v", backend.savedSettings)
	}
	started, command := press(t, model, "enter")
	want := Defaults{ProviderID: "openai", Model: "gpt-b", Reasoning: "low"}
	if len(backend.savedSettings) != 1 || backend.savedSettings[0] != want || started.defaults != want {
		t.Fatalf("saved = %+v, defaults = %+v", backend.savedSettings, started.defaults)
	}

	home, _ := press(t, settle(started, command), "b")
	next, _ := press(t, home, "enter")
	if next.step != stepConsent || backend.setups[len(backend.setups)-1] != (Setup{ProviderID: "openai", Model: "gpt-b", Reasoning: "low"}) {
		t.Errorf("the next run did not start at the consent screen: step %d", next.step)
	}
}

func TestAFailureToSaveTheChoicesDoesNotStopTheRun(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, models: []string{"gpt-a"}, preview: "p", runner: finishedRunner("r", true), saveSettingsErr: errors.New("disk full")}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter", "enter")

	started, command := press(t, model, "enter")
	finished := settle(started, command)

	if finished.screen != runScreen || finished.running || len(finished.transcript) == 0 || finished.defaults != (Defaults{}) || strings.Contains(finished.View()+strings.Join(finished.transcript, "\n"), "disk full") {
		t.Errorf("screen = %d, defaults = %+v", finished.screen, finished.defaults)
	}
}

func FuzzSettings(f *testing.F) {
	f.Add("OpenAI", "gpt-x", "high", "sk-FUZZ-key-123456", 80, 24)
	f.Add("a\x1b[2J‮", "\x00\x07", "\x1b]0;x\x07", "KEY-\n\t\x1b", 0, 0)
	f.Add("", "", "", "", 3, 1)

	f.Fuzz(func(t *testing.T, name, modelText, level, keyText string, width, height int) {
		backend := &fakeBackend{
			choices:     []Choice{{ID: "x", Name: name, KeySaved: true, KeyEnv: name, DefaultModel: modelText}, {ID: "y", Name: name, KeyEnv: name}},
			models:      []string{modelText, name},
			reasoning:   []ReasoningChoice{{"", level}, {"high", name}},
			canSaveKeys: true, preview: level, runner: finishedRunner(level, true),
		}
		secret := "KEY-" + keyText
		model := sized(newModelWith(level, backend, Defaults{ProviderID: "x", Model: modelText, Reasoning: level}), width%300, height%100)

		var views []string
		for _, keys := range [][]string{
			{"down", "down", "enter"},
			{"enter", "enter"},
			{"enter", "enter", "enter"},
			{"esc", "esc", "down", "enter"},
			{"down", "enter", "enter"},
			{"esc", "up", "enter"},
			{"enter", "down", "enter"},
		} {
			for _, key := range keys {
				model, _ = pressAll(t, model, key)
				views = append(views, model.View())
				if model.step == stepKey {
					model = pasteText(t, model, secret)
					views = append(views, model.View())
				}
			}
		}

		cleanedSecret := cleanInput(secret)
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

func TestATypedKeyThatIsRejectedIsWipedFromMemory(t *testing.T) {
	const key = "sk-SECRET-wrong-key-123"
	backend := &fakeBackend{choices: []Choice{plainChoice}, modelsErr: ErrKeyRejected}
	model, _ := pressAll(t, newModelWith("/work/project", backend, Defaults{}), "enter", "enter")
	model = typeText(t, model, key)
	held := model.keyInput

	model, _ = pressAll(t, model, "enter")

	if model.step != stepKey || model.keyInput != nil || strings.Contains(string(held), "SECRET") || strings.Contains(model.View(), key) {
		t.Errorf("step = %d, the old key memory is %q", model.step, string(held))
	}
}
