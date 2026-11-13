package tui

import (
	"maps"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// RuleInput is what the user types for a rule draft. Examples are event references, as reports name
// them, separated by spaces or commas. Benign is files or folders of clean logs, separated by commas.
type RuleInput struct {
	Goal     string
	Examples string
	Benign   string
	Title    string
	Level    string
}

// Options are the choices of a form that the commands take as flags. They are text: the backend reads
// the files and refuses what is wrong. An empty value means the default of the command.
type Options struct {
	Rules      string
	FileRules  string
	Assets     string
	Indicators string
	Format     string
	Store      bool
	Processes  string
	Sockets    string
	Attempts   string
	Recording  string
	Kind       string
	Seed       string
	Manifest   string
}

type choice struct{ value, label string }

// formField is one line of a form. A field with choices is changed with left and right, never typed.
type formField struct {
	key      string
	label    string
	limit    int
	choices  []choice
	required string
}

const pathLimit = 1000

var (
	fieldRules      = formField{key: "rules", label: "Rules folder, optional (empty: the built-in rules):", limit: pathLimit}
	fieldFileRules  = formField{key: "filerules", label: "File rules folder, optional (empty: the built-in file rules, none: no file rules):", limit: pathLimit}
	fieldAssets     = formField{key: "assets", label: "Asset list, optional (YAML: names and addresses of your machines):", limit: pathLimit}
	fieldIndicators = formField{key: "indicators", label: "Indicator list, optional (YAML: known bad addresses, domains, hashes):", limit: pathLimit}
	fieldFormat     = formField{key: "format", label: "Log format:", choices: []choice{{"", "look at the first lines"}, {"syslog", "syslog"}, {"web", "web"},
		{"json", "json"}, {"suricata", "suricata"}, {"zeek", "zeek"}, {"wazuh", "wazuh"}, {"windows", "windows"}, {"pcap", "pcap"}, {"app", "app (framework logs)"}}}
	fieldStore     = formField{key: "store", label: "Store the run for search, cases and timelines:", choices: []choice{{"", "no"}, {"yes", "yes"}}}
	fieldRecording = formField{key: "recording", label: "Replay a recording, optional (recording.json; nothing is sent):", limit: pathLimit}
	fieldProcesses = formField{key: "processes", label: "Saved \"ps aux\" or \"ps -ef\" output, optional:", limit: pathLimit}
	fieldSockets   = formField{key: "sockets", label: "Saved \"ss -tulpn\" or \"netstat -tulpn\" output, optional:", limit: pathLimit}

	forms = map[string][]formField{
		TaskDetect:           {fieldRules, fieldAssets, fieldIndicators, fieldFormat, fieldStore},
		TaskAnalyze:          {fieldRules, fieldAssets, fieldIndicators, fieldFormat, fieldStore, fieldRecording},
		TaskForensics:        {fieldProcesses, fieldSockets, fieldRules, fieldFileRules, fieldAssets, fieldIndicators, fieldStore},
		TaskForensicsAnalyze: {fieldProcesses, fieldSockets, fieldRules, fieldFileRules, fieldAssets, fieldIndicators, fieldStore, fieldRecording},
		TaskRuleDraft: {
			{key: "goal", label: "Goal, what the rule is for:", limit: 300, required: "Type what the rule is for."},
			{key: "examples", label: "Example events (like web01/auth.log:68, separated by spaces):", limit: 2000, required: "Type at least one example event, as a report names it."},
			{key: "benign", label: "Clean logs, optional (files or folders, separated by commas; the rule must match none of them):", limit: 2000},
			{key: "title", label: "Title (empty: the goal):", limit: 100},
			{key: "level", label: "Level:", choices: []choice{{"medium", "medium"}, {"informational", "informational"}, {"low", "low"}, {"high", "high"}, {"critical", "critical"}}},
			{key: "attempts", label: "Answers the AI may give (after a refusal it is told the fixed reasons):", choices: []choice{{"3", "3"}, {"1", "1"}, {"2", "2"}, {"4", "4"}, {"5", "5"}}},
			fieldFormat, fieldAssets, fieldIndicators, fieldRecording,
		},
		TaskVerify: {{key: "manifest", label: "Manifest (manifest.json of an earlier forensic run):", limit: pathLimit, required: "Type the path of the manifest."}},
		TaskDemo: {
			{key: "kind", label: "What to make:", choices: []choice{{"", "logs of one server and a synthetic Linux system"}, {"campaign", "an attack through three hosts, with network sensor logs"}, {"benign", "a day of one server without attacks"}}},
			{key: "seed", label: "Seed, optional (a number; the same seed makes the same data):", limit: 18},
		},
	}

	formIntro = map[string][]string{
		TaskRuleDraft: {"The AI writes only the matching part of one rule. Omamori accepts it only if",
			"it loads, passes its tests, matches every example and is silent on days without",
			"an attack. You see the request before anything is sent."},
		TaskVerify: {"The folder is the evidence. Its files are hashed again and compared with the manifest.", "Nothing is written."},
	}
)

func hasForm(task string) bool {
	_, found := forms[task]
	return found
}

func (model Model) menuLabel(task string) string {
	for _, item := range menuItems {
		if item.task == task {
			return item.label
		}
	}

	return ""
}

func (model Model) openForm(task string) Model {
	model.settingsMode = false
	model.task = task
	model.notice = ""
	if model.target == "" || model.backend == nil {
		model.notice = "There is no target folder. Start Omamori with a folder: omamori ui <folder>"
		return model
	}
	if err := model.backend.TaskReady(task); err != nil {
		model.notice = err.Error()
		return model
	}
	model.setupError = ""
	model.formCursor = 0
	model.step = stepForm

	return model
}

func (model Model) fieldValue(field formField) string {
	value, found := model.formValues[field.key]
	if !found && len(field.choices) > 0 {
		return field.choices[0].value
	}

	return value
}

// formValue gives the value of a field only when the form of the current task has it, so a task never
// gets a choice that was made on the form of another task and that it does not show.
func (model Model) formValue(key string) string {
	for _, field := range forms[model.task] {
		if field.key == key {
			return strings.TrimSpace(model.fieldValue(field))
		}
	}

	return ""
}

func (model Model) ruleSetup() RuleInput {
	if model.task != TaskRuleDraft {
		return RuleInput{}
	}

	return RuleInput{Goal: model.formValue("goal"), Examples: model.formValue("examples"), Benign: model.formValue("benign"),
		Title: model.formValue("title"), Level: model.formValue("level")}
}

func (model Model) formOptions() Options {
	return Options{Rules: model.formValue("rules"), FileRules: model.formValue("filerules"), Assets: model.formValue("assets"), Indicators: model.formValue("indicators"),
		Format: model.formValue("format"), Store: model.formValue("store") == "yes", Processes: model.formValue("processes"),
		Sockets: model.formValue("sockets"), Attempts: model.formValue("attempts"), Recording: model.formValue("recording"),
		Kind: model.formValue("kind"), Seed: model.formValue("seed"), Manifest: model.formValue("manifest")}
}

func (model *Model) setField(key, value string) {
	values := maps.Clone(model.formValues)
	if values == nil {
		values = map[string]string{}
	}
	values[key] = value
	model.formValues = values
	model.setupError = ""
}

// handleFormKey edits a form. Every key is text or a move here, so q does not quit.
func (model Model) handleFormKey(message tea.KeyMsg) (Model, tea.Cmd) {
	fields := forms[model.task]
	field := fields[model.formCursor]
	value := []rune(model.fieldValue(field))
	turn := func(step int) {
		index := slices.IndexFunc(field.choices, func(option choice) bool { return option.value == string(value) })
		model.setField(field.key, field.choices[(max(index, 0)+step+len(field.choices))%len(field.choices)].value)
	}
	switch message.Type {
	case tea.KeyEsc:
		model.setupError = ""
		model.step = stepMenu
	case tea.KeyUp, tea.KeyShiftTab:
		model.formCursor = moveUp(model.formCursor, len(fields))
	case tea.KeyDown, tea.KeyTab:
		model.formCursor = moveDown(model.formCursor, len(fields))
	case tea.KeyEnter:
		return model.submitForm(), nil
	case tea.KeyLeft:
		if len(field.choices) > 0 {
			turn(-1)
		}
	case tea.KeyRight:
		if len(field.choices) > 0 {
			turn(1)
		}
	case tea.KeySpace:
		if len(field.choices) > 0 {
			turn(1)
		} else if len(value) < field.limit {
			model.setField(field.key, string(append(value, ' ')))
		}
	case tea.KeyBackspace:
		if len(field.choices) == 0 {
			model.setField(field.key, string(value[:max(len(value)-1, 0)]))
		}
	case tea.KeyRunes:
		if len(field.choices) == 0 {
			typed := []rune(cleanInput(string(message.Runes)))
			model.setField(field.key, string(append(value, typed[:min(len(typed), max(field.limit-len(value), 0))]...)))
		}
	}

	return model, nil
}

func (model Model) submitForm() Model {
	for index, field := range forms[model.task] {
		if field.required != "" && model.formValue(field.key) == "" {
			model.formCursor, model.setupError = index, field.required
			return model
		}
	}
	model.setupError = ""
	var next Model
	switch {
	case model.formValue("recording") != "":
		next = model.startReplay()
	case slices.ContainsFunc(menuItems, func(item menuItem) bool { return item.task == model.task && item.ai }):
		next = model.startTask(model.task)
	default:
		next = model.startLocal(model.task)
	}
	if next.notice != "" {
		next.step = stepForm
		next.setupError, next.notice = next.notice, ""
	}

	return next
}

// startReplay goes to the dry run of a recording. No provider, model or key is chosen: nothing is sent.
func (model Model) startReplay() Model {
	plan, err := model.backend.Prepare(Setup{Task: model.task, Replay: true, Rule: model.ruleSetup(), Options: model.formOptions()})
	if err != nil {
		model.notice = err.Error()
		return model
	}
	model.plan = &plan
	model.consentFull = false
	model.consentScroll = 0
	model.hasPending = false
	model.step = stepConsent

	return model
}
