package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func pressType(t testing.TB, model Model, kind tea.KeyType) Model {
	t.Helper()
	updated, _ := model.Update(tea.KeyMsg{Type: kind})

	return updated.(Model)
}

// openTask moves the menu to a task and presses enter.
func openTask(t testing.TB, backend *fakeBackend, defaults Defaults, task string) Model {
	t.Helper()
	index := slices.IndexFunc(menuItems, func(item menuItem) bool { return item.task == task })
	if index < 0 {
		t.Fatalf("the menu has no %s", task)
	}
	model, _ := pressAll(t, newModelWith("/work/logs", backend, defaults), append(slices.Repeat([]string{"down"}, index), "enter")...)

	return model
}

func openForm(t testing.TB, backend *fakeBackend, defaults Defaults, task string) Model {
	t.Helper()
	model := openTask(t, backend, defaults, task)
	if model.step != stepForm || model.task != task {
		t.Fatalf("step = %d, notice %q", model.step, model.notice)
	}

	return model
}

// fieldAt moves the cursor to the field with the key.
func fieldAt(t testing.TB, model Model, key string) Model {
	t.Helper()
	index := slices.IndexFunc(forms[model.task], func(field formField) bool { return field.key == key })
	if index < 0 {
		t.Fatalf("the form of %s has no %s", model.task, key)
	}
	for model.formCursor != index {
		model = pressType(t, model, tea.KeyDown)
	}

	return model
}

func fill(t testing.TB, model Model, key, text string) Model {
	t.Helper()
	return typeText(t, fieldAt(t, model, key), text)
}

func choose(t testing.TB, model Model, key, value string) Model {
	t.Helper()
	model = fieldAt(t, model, key)
	for range 20 {
		if model.fieldValue(forms[model.task][model.formCursor]) == value {
			return model
		}
		model = pressType(t, model, tea.KeyRight)
	}
	t.Fatalf("%s has no choice %q", key, value)

	return model
}

func ruleForm(t testing.TB, backend *fakeBackend, defaults Defaults, goal, examples string) Model {
	t.Helper()
	model := openForm(t, backend, defaults, TaskRuleDraft)
	if goal != "" {
		model = fill(t, model, "goal", goal)
	}
	if examples != "" {
		model = fill(t, model, "examples", examples)
	}

	return model
}

func TestEveryFormTaskIsInTheMenu(t *testing.T) {
	for task := range forms {
		if !slices.ContainsFunc(menuItems, func(item menuItem) bool { return item.task == task }) {
			t.Errorf("the form of %s has no menu line", task)
		}
		for _, field := range forms[task] {
			if field.key == "" || field.label == "" || len(field.choices) == 0 && field.limit < 1 || len(field.choices) > 0 && field.required != "" {
				t.Errorf("%s: the field %+v is not usable", task, field)
			}
		}
	}
}

func TestRuleDraftFormGoesThroughTheSameSetupAndPassesTheFields(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", title: "Task C: Rule draft", runner: finishedRunner("r", true)}
	model := ruleForm(t, backend, Defaults{}, "cron jobs that pipe a download to a shell", "web01/auth.log:68 web01/auth.log:70")
	model = fill(t, model, "benign", " /clean/day one , /clean/day2 ")
	model = fill(t, model, "title", "Cron download")
	model = choose(t, model, "level", "high")
	model = choose(t, model, "attempts", "5")
	model = choose(t, model, "format", "syslog")
	model = fill(t, model, "assets", "~/assets.yml")
	view := model.View()
	for _, want := range []string{"Rule draft", "Example events", "‹ high ›", "‹ 5 ›", "‹ syslog ›"} {
		if !strings.Contains(view, want) {
			t.Fatalf("the form has no %q:\n%s", want, view)
		}
	}
	model, _ = pressAll(t, model, "enter")
	if model.step != stepProvider || len(backend.setups) != 0 {
		t.Fatalf("step = %d, setups %d", model.step, len(backend.setups))
	}
	model, _ = pressAll(t, model, "enter", "enter")
	if model.step != stepConsent || len(backend.setups) != 1 || backend.confirmed != 0 {
		t.Fatalf("step = %d, setups %+v, error %q", model.step, backend.setups, model.setupError)
	}
	got := backend.setups[0]
	wantRule := RuleInput{Goal: "cron jobs that pipe a download to a shell", Examples: "web01/auth.log:68 web01/auth.log:70", Benign: "/clean/day one , /clean/day2", Title: "Cron download", Level: "high"}
	wantOptions := Options{Attempts: "5", Format: "syslog", Assets: "~/assets.yml"}
	if got.Task != TaskRuleDraft || got.Rule != wantRule || got.Options != wantOptions || got.ProviderID != "fake" || got.Replay {
		t.Fatalf("setup %+v", got)
	}
}

func TestRuleDraftDefaultsAreMediumAndThreeAnswers(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, preview: "p"}
	model, _ := pressAll(t, ruleForm(t, backend, Defaults{ProviderID: "openai", Model: "gpt-x"}, "goal", "auth.log:3"), "enter")
	if model.step != stepConsent || len(backend.setups) != 1 || backend.confirmed != 0 {
		t.Fatalf("step = %d, setups %+v", model.step, backend.setups)
	}
	if got := backend.setups[0]; got.Rule != (RuleInput{Goal: "goal", Examples: "auth.log:3", Level: "medium"}) || got.Options != (Options{Attempts: "3"}) {
		t.Fatalf("setup %+v", got)
	}
}

func TestFormTextIsTextAndQDoesNotQuit(t *testing.T) {
	model := openForm(t, &fakeBackend{choices: []Choice{localChoice}}, Defaults{}, TaskRuleDraft)
	model, command := press(t, model, "q")
	if isQuit(command) || model.quitting || model.formValue("goal") != "q" {
		t.Fatalf("q quit or was lost: %q", model.formValue("goal"))
	}
	model = pasteText(t, model, "a\x1b[31mb\u200bc")
	if got := model.formValue("goal"); got != "qa[31mbc" {
		t.Fatalf("control characters were kept: %q", got)
	}
	model = pasteText(t, model, strings.Repeat("x", 1000))
	if len([]rune(model.formValues["goal"])) != 300 {
		t.Fatalf("the goal is %d runes long", len([]rune(model.formValues["goal"])))
	}
	model = pressType(t, model, tea.KeyBackspace)
	if len([]rune(model.formValues["goal"])) != 299 {
		t.Fatal("backspace did not remove a rune")
	}
	model = pressType(t, model, tea.KeyUp)
	if model.formCursor != len(forms[TaskRuleDraft])-1 {
		t.Fatalf("up from the first field went to %d", model.formCursor)
	}
}

func TestChoiceFieldsTurnAndCannotBeTyped(t *testing.T) {
	model := fieldAt(t, openForm(t, &fakeBackend{choices: []Choice{localChoice}}, Defaults{}, TaskDetect), "store")
	if model.formOptions().Store {
		t.Fatal("storage is on by default")
	}
	model = pressType(t, model, tea.KeyRight)
	if !model.formOptions().Store || !strings.Contains(model.View(), "‹ yes ›") {
		t.Fatal("right did not turn storage on")
	}
	model = pressType(t, model, tea.KeyRight)
	if model.formOptions().Store {
		t.Fatal("right at the last choice did not go around")
	}
	model = pressType(t, model, tea.KeyLeft)
	model = pressType(t, model, tea.KeySpace)
	model = typeText(t, model, "xyz")
	model = pressType(t, model, tea.KeyBackspace)
	if model.formOptions().Store || model.formValues["store"] != "" {
		t.Fatalf("a choice field took text or did not turn: %q", model.formValues["store"])
	}
	format := choose(t, model, "format", "windows")
	if format.formOptions().Format != "windows" {
		t.Fatal("the format was not chosen")
	}
	format = pressType(t, format, tea.KeyRight)
	if format.formOptions().Format != "" || !strings.Contains(format.View(), "look at the first lines") {
		t.Fatal("the format did not go around to the default")
	}
}

func TestDetectFormPassesTheOptionsToALocalRun(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", runner: finishedRunner("r", true)}
	model := openForm(t, backend, Defaults{}, TaskDetect)
	model = fill(t, model, "rules", "./my rules")
	model = fill(t, model, "assets", "assets.yml")
	model = fill(t, model, "indicators", "bad.yml")
	model = choose(t, model, "format", "zeek")
	model = choose(t, model, "store", "yes")
	model, _ = pressAll(t, model, "enter")
	if model.step != stepConsent || len(backend.setups) != 1 || len(backend.modelCalls) != 0 {
		t.Fatalf("step = %d, setups %+v", model.step, backend.setups)
	}
	want := Options{Rules: "./my rules", Assets: "assets.yml", Indicators: "bad.yml", Format: "zeek", Store: true}
	if got := backend.setups[0]; got.Task != TaskDetect || got.Options != want || got.Rule != (RuleInput{}) {
		t.Fatalf("setup %+v", got)
	}
	if model.plan.Local {
		t.Fatal("a plan the backend did not mark local is shown as local")
	}
}

func TestFormValuesAreSharedButOnlyTheFieldsOfTheTaskAreSent(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p"}
	model := ruleForm(t, backend, Defaults{}, "goal", "auth.log:1")
	model = fill(t, model, "assets", "assets.yml")
	model = choose(t, model, "format", "web")
	model, _ = press(t, model, "esc")
	model.cursor = slices.IndexFunc(menuItems, func(item menuItem) bool { return item.task == TaskForensics })
	model, _ = pressAll(t, model, "enter")
	if model.step != stepForm || !strings.Contains(model.View(), "assets.yml") {
		t.Fatalf("the asset list was not kept: step %d", model.step)
	}
	model, _ = pressAll(t, model, "enter")
	if got := backend.setups[0]; got.Options != (Options{Assets: "assets.yml"}) || got.Rule != (RuleInput{}) {
		t.Fatalf("forensics got %+v", got)
	}

	model.cursor = 0
	model.step = stepMenu
	model, _ = pressAll(t, model, "enter", "enter", "enter")
	if got := backend.setups[len(backend.setups)-1]; got.Task != "" || got.Options != (Options{}) || got.Rule != (RuleInput{}) {
		t.Fatalf("the exposure check got %+v", got)
	}
}

func TestARecordingOnTheFormSkipsTheProviderAndIsAReplay(t *testing.T) {
	for _, task := range []string{TaskAnalyze, TaskForensicsAnalyze, TaskRuleDraft} {
		t.Run(task, func(t *testing.T) {
			backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", label: "REPLAY"}
			model := openForm(t, backend, Defaults{}, task)
			if task == TaskRuleDraft {
				model = fill(t, fill(t, model, "goal", "g"), "examples", "a.log:1")
			}
			model = fill(t, model, "recording", "run/recording.json")
			model, _ = pressAll(t, model, "enter")
			if model.step != stepConsent || len(backend.setups) != 1 || len(backend.modelCalls) != 0 || model.hasPending {
				t.Fatalf("step = %d, setups %+v", model.step, backend.setups)
			}
			if got := backend.setups[0]; !got.Replay || got.ProviderID != "" || got.Options.Recording != "run/recording.json" {
				t.Fatalf("setup %+v", got)
			}
			if model.plan == nil || model.plan.Label != "REPLAY" {
				t.Fatal("the plan of the replay was not kept")
			}
		})
	}
}

func TestVerifyNeedsAManifestAndDemoPassesTheKind(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p"}
	model, _ := pressAll(t, openForm(t, backend, Defaults{}, TaskVerify), "enter")
	if model.step != stepForm || !strings.Contains(model.View(), "Type the path of the manifest") || len(backend.setups) != 0 {
		t.Fatalf("step = %d", model.step)
	}
	model, _ = pressAll(t, typeText(t, model, "out/manifest.json"), "enter")
	if model.step != stepConsent || backend.setups[0].Options != (Options{Manifest: "out/manifest.json"}) {
		t.Fatalf("step = %d, setups %+v", model.step, backend.setups)
	}

	demo := choose(t, openForm(t, backend, Defaults{}, TaskDemo), "kind", "campaign")
	demo = fill(t, demo, "seed", "7")
	demo, _ = pressAll(t, demo, "enter")
	if got := backend.setups[len(backend.setups)-1]; got.Task != TaskDemo || got.Options != (Options{Kind: "campaign", Seed: "7"}) {
		t.Fatalf("demo setup %+v", got)
	}
}

func TestRuleDraftNeedsAGoalAndAnExample(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}}
	for _, testCase := range []struct {
		goal, examples string
		field          string
		want           string
	}{
		{"", "auth.log:1", "goal", "Type what the rule is for"},
		{"   ", "auth.log:1", "goal", "Type what the rule is for"},
		{"goal", "", "examples", "at least one example"},
	} {
		model := openForm(t, backend, Defaults{}, TaskRuleDraft)
		model = fill(t, fill(t, model, "goal", testCase.goal), "examples", testCase.examples)
		model, _ = pressAll(t, model, "enter")
		if model.step != stepForm || forms[TaskRuleDraft][model.formCursor].key != testCase.field || !strings.Contains(model.View(), testCase.want) {
			t.Fatalf("step = %d, cursor %d, view:\n%s", model.step, model.formCursor, model.View())
		}
	}
	if len(backend.setups) != 0 || len(backend.modelCalls) != 0 {
		t.Fatal("an incomplete form reached the backend")
	}
}

func TestFormErrorsGoBackToTheFormWithTheTextKept(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, prepareErr: errors.New("the example \"x:1\" is not exactly one event")}
	model, _ := pressAll(t, ruleForm(t, backend, Defaults{}, "goal", "x:1"), "enter", "enter", "enter")
	if model.step != stepForm || !strings.Contains(model.View(), "is not exactly one event") || model.formValue("examples") != "x:1" {
		t.Fatalf("step = %d, view:\n%s", model.step, model.View())
	}

	saved := &fakeBackend{choices: []Choice{savedChoice}, prepareErr: errors.New("no such example")}
	model, _ = pressAll(t, ruleForm(t, saved, Defaults{ProviderID: "openai", Model: "gpt-x"}, "goal", "x:1"), "enter")
	if model.step != stepForm || !strings.Contains(model.View(), "no such example") || strings.Contains(model.View(), "saved settings") {
		t.Fatalf("step = %d, view:\n%s", model.step, model.View())
	}

	local := &fakeBackend{choices: []Choice{localChoice}, prepareErr: errors.New("the asset list cannot be read")}
	model, _ = pressAll(t, fill(t, openForm(t, local, Defaults{}, TaskDetect), "assets", "nope.yml"), "enter")
	if model.step != stepForm || !strings.Contains(model.View(), "the asset list cannot be read") || model.formValue("assets") != "nope.yml" {
		t.Fatalf("a local task: step = %d, view:\n%s", model.step, model.View())
	}

	replayed := &fakeBackend{choices: []Choice{localChoice}, prepareErr: errors.New("the recording is not valid")}
	model, _ = pressAll(t, fill(t, openForm(t, replayed, Defaults{}, TaskAnalyze), "recording", "r.json"), "enter")
	if model.step != stepForm || !strings.Contains(model.View(), "the recording is not valid") {
		t.Fatalf("a replay: step = %d, view:\n%s", model.step, model.View())
	}

	blocked := &fakeBackend{choices: []Choice{localChoice}, taskReadyErr: errors.New("no logs here")}
	menu := openTask(t, blocked, Defaults{}, TaskRuleDraft)
	if menu.step != stepMenu || !strings.Contains(menu.View(), "no logs here") {
		t.Fatalf("a task that is not ready opened: step = %d", menu.step)
	}
}

func TestFormEscGoesBackOneStep(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}}
	model, _ := pressAll(t, ruleForm(t, backend, Defaults{}, "goal", "auth.log:1"), "enter")
	if model.step != stepProvider {
		t.Fatalf("step = %d", model.step)
	}
	model, _ = press(t, model, "esc")
	if model.step != stepForm || model.formValue("goal") != "goal" {
		t.Fatalf("esc from the provider: step = %d", model.step)
	}
	model, _ = press(t, model, "esc")
	if model.step != stepMenu {
		t.Fatalf("esc from the form: step = %d", model.step)
	}

	other, _ := pressAll(t, newModelWith("/work/logs", &fakeBackend{choices: []Choice{localChoice}}, Defaults{}), "enter", "esc")
	if other.step != stepMenu {
		t.Fatalf("esc from the provider of a task without a form: step = %d", other.step)
	}
}

func TestALongFormScrollsToTheChosenField(t *testing.T) {
	model := openForm(t, &fakeBackend{choices: []Choice{localChoice}}, Defaults{}, TaskRuleDraft)
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	model = fieldAt(t, updated.(Model), "recording")
	view := model.View()
	if !strings.Contains(view, "Replay a recording") || strings.Contains(view, "Goal, what the rule is for") || !strings.Contains(view, "More fields above or below") {
		t.Fatalf("view:\n%s", view)
	}
	if lines := strings.Count(view, "\n") + 1; lines > 24 {
		t.Fatalf("the form has %d lines in a window of 24", lines)
	}
}
