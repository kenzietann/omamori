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

// openRuleDraft moves the menu to the rule draft and opens its input page.
func openRuleDraft(t testing.TB, backend *fakeBackend, defaults Defaults) Model {
	t.Helper()
	index := slices.IndexFunc(menuItems, func(item menuItem) bool { return item.task == TaskRuleDraft })
	if index < 0 {
		t.Fatal("the menu has no rule draft")
	}
	model := newModelWith("/work/logs", backend, defaults)
	model, _ = pressAll(t, model, append(slices.Repeat([]string{"down"}, index), "enter")...)
	if model.step != stepRuleInput {
		t.Fatalf("step = %d, notice %q", model.step, model.notice)
	}

	return model
}

func fillRule(t testing.TB, model Model, goal, examples, title, level string) Model {
	t.Helper()
	for index, text := range []string{goal, examples, title, level} {
		if text != "" {
			model = typeText(t, model, text)
		}
		if index < ruleFieldCount-1 {
			model = pressType(t, model, tea.KeyTab)
		}
	}

	return model
}

func TestRuleDraftInputGoesThroughTheSameSetupAndPassesTheFields(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p", title: "Task C: Rule draft", runner: finishedRunner("r", true)}
	model := openRuleDraft(t, backend, Defaults{})
	if !strings.Contains(model.View(), "Rule draft") || !strings.Contains(model.View(), "Example events") {
		t.Fatalf("view:\n%s", model.View())
	}
	model = fillRule(t, model, "cron jobs that pipe a download to a shell", "web01/auth.log:68 web01/auth.log:70", "Cron download", " HIGH ")
	model, _ = pressAll(t, model, "enter")
	if model.step != stepProvider || len(backend.setups) != 0 {
		t.Fatalf("step = %d, setups %d", model.step, len(backend.setups))
	}
	model, _ = pressAll(t, model, "enter", "enter")
	if model.step != stepConsent || len(backend.setups) != 1 {
		t.Fatalf("step = %d, setups %+v, error %q", model.step, backend.setups, model.setupError)
	}
	want := RuleInput{Goal: "cron jobs that pipe a download to a shell", Examples: "web01/auth.log:68 web01/auth.log:70", Title: "Cron download", Level: "high"}
	if got := backend.setups[0]; got.Task != TaskRuleDraft || got.Rule != want || got.ProviderID != "fake" {
		t.Fatalf("setup %+v", got)
	}
	if backend.confirmed != 0 {
		t.Fatal("the consent page was skipped")
	}
}

func TestRuleDraftWithSavedSettingsStillStopsAtTheConsentPage(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{savedChoice}, preview: "p"}
	model := fillRule(t, openRuleDraft(t, backend, Defaults{ProviderID: "openai", Model: "gpt-x"}), "goal", "auth.log:3", "", "")
	model, _ = pressAll(t, model, "enter")
	if model.step != stepConsent || len(backend.setups) != 1 || backend.setups[0].Rule != (RuleInput{Goal: "goal", Examples: "auth.log:3"}) || backend.confirmed != 0 {
		t.Fatalf("step = %d, setups %+v", model.step, backend.setups)
	}
}

func TestRuleDraftInputIsTextAndQDoesNotQuit(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}}
	model := openRuleDraft(t, backend, Defaults{})
	model, command := press(t, model, "q")
	if isQuit(command) || model.quitting || string(model.ruleFields[ruleGoal]) != "q" {
		t.Fatalf("q quit or was lost: %q", string(model.ruleFields[ruleGoal]))
	}
	model = typeText(t, model, "a\x1b[31mb​c")
	if got := string(model.ruleFields[ruleGoal]); got != "qa[31mbc" {
		t.Fatalf("control characters were kept: %q", got)
	}
	model = pasteText(t, model, strings.Repeat("x", 1000))
	if len(model.ruleFields[ruleGoal]) != ruleLimits[ruleGoal] {
		t.Fatalf("the goal is %d runes long", len(model.ruleFields[ruleGoal]))
	}
	model = pressType(t, model, tea.KeyBackspace)
	if len(model.ruleFields[ruleGoal]) != ruleLimits[ruleGoal]-1 {
		t.Fatal("backspace did not remove a rune")
	}
	model = pressType(t, model, tea.KeyUp)
	if model.ruleCursor != ruleLevel {
		t.Fatalf("up from the first field went to %d", model.ruleCursor)
	}
}

func TestRuleDraftNeedsAGoalAndAnExample(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}}
	for _, testCase := range []struct {
		goal, examples string
		field          int
		want           string
	}{
		{"", "auth.log:1", ruleGoal, "Type what the rule is for"},
		{"   ", "auth.log:1", ruleGoal, "Type what the rule is for"},
		{"goal", "", ruleExamples, "at least one example"},
	} {
		model := fillRule(t, openRuleDraft(t, backend, Defaults{}), testCase.goal, testCase.examples, "", "")
		model, _ = pressAll(t, model, "enter")
		if model.step != stepRuleInput || model.ruleCursor != testCase.field || !strings.Contains(model.View(), testCase.want) {
			t.Fatalf("step = %d, cursor %d, view:\n%s", model.step, model.ruleCursor, model.View())
		}
	}
	if len(backend.setups) != 0 || len(backend.modelCalls) != 0 {
		t.Fatal("an incomplete input reached the backend")
	}
}

func TestRuleDraftErrorsGoBackToTheInputWithTheFieldsKept(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, prepareErr: errors.New("the example \"x:1\" is not exactly one event")}
	model := fillRule(t, openRuleDraft(t, backend, Defaults{}), "goal", "x:1", "", "")
	model, _ = pressAll(t, model, "enter", "enter", "enter")
	if model.step != stepRuleInput || !strings.Contains(model.View(), "is not exactly one event") || string(model.ruleFields[ruleExamples]) != "x:1" {
		t.Fatalf("step = %d, view:\n%s", model.step, model.View())
	}

	saved := &fakeBackend{choices: []Choice{savedChoice}, prepareErr: errors.New("no such example")}
	model = fillRule(t, openRuleDraft(t, saved, Defaults{ProviderID: "openai", Model: "gpt-x"}), "goal", "x:1", "", "")
	model, _ = pressAll(t, model, "enter")
	if model.step != stepRuleInput || !strings.Contains(model.View(), "no such example") || strings.Contains(model.View(), "saved settings") {
		t.Fatalf("step = %d, view:\n%s", model.step, model.View())
	}

	blocked := &fakeBackend{choices: []Choice{localChoice}, taskReadyErr: errors.New("no logs here")}
	index := slices.IndexFunc(menuItems, func(item menuItem) bool { return item.task == TaskRuleDraft })
	menu, _ := pressAll(t, newModelWith("/work/logs", blocked, Defaults{}), append(slices.Repeat([]string{"down"}, index), "enter")...)
	if menu.step != stepMenu || !strings.Contains(menu.View(), "no logs here") {
		t.Fatalf("a task that is not ready opened: step = %d", menu.step)
	}
}

func TestRuleDraftEscGoesBackOneStep(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}}
	model := fillRule(t, openRuleDraft(t, backend, Defaults{}), "goal", "auth.log:1", "", "")
	model, _ = pressAll(t, model, "enter")
	if model.step != stepProvider {
		t.Fatalf("step = %d", model.step)
	}
	model, _ = press(t, model, "esc")
	if model.step != stepRuleInput || string(model.ruleFields[ruleGoal]) != "goal" {
		t.Fatalf("esc from the provider: step = %d", model.step)
	}
	model, _ = press(t, model, "esc")
	if model.step != stepMenu {
		t.Fatalf("esc from the input: step = %d", model.step)
	}

	other, _ := pressAll(t, newModelWith("/work/logs", &fakeBackend{choices: []Choice{localChoice}}, Defaults{}), "enter", "esc")
	if other.step != stepMenu {
		t.Fatalf("esc from the provider of another task: step = %d", other.step)
	}
}

func TestOtherTasksSendNoRuleInput(t *testing.T) {
	backend := &fakeBackend{choices: []Choice{localChoice}, preview: "p"}
	model := fillRule(t, openRuleDraft(t, backend, Defaults{}), "goal", "auth.log:1", "", "")
	model, _ = press(t, model, "esc")
	model.cursor = 0
	model, _ = pressAll(t, model, "enter", "enter", "enter")
	if len(backend.setups) != 1 || backend.setups[0].Rule != (RuleInput{}) {
		t.Fatalf("setups %+v", backend.setups)
	}
}
