package tui

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	homeScreen screen = iota
	runScreen
)

type homeStep int

const (
	stepMenu homeStep = iota
	stepProvider
	stepModel
	stepKey
	stepReasoning
	stepConsent
	stepSettings
	stepRuleInput
)

type menuItem struct {
	label string
	note  string
	task  string
	ai    bool
	kind  menuKind
}

type menuKind int

const (
	menuTask menuKind = iota
	menuOpenSettings
	menuLeave
)

var menuItems = []menuItem{
	{label: "Exposure check", note: "secrets and personal data in a project, with AI", task: "", ai: true},
	{label: "Log triage", note: "sshd auth.log, with AI", task: TaskTriage, ai: true},
	{label: "Detect", note: "run the rules over the logs in the folder, no AI", task: TaskDetect},
	{label: "Analyze", note: "detect, then the AI reviews the alerts and every claim is checked", task: TaskAnalyze, ai: true},
	{label: "Forensics", note: "read a Linux system in the folder: hashes, rules, timeline, no AI", task: TaskForensics},
	{label: "Forensics + AI review", note: "the same, then the AI reviews the alerts", task: TaskForensicsAnalyze, ai: true},
	{label: "Rule draft", note: "point at log lines; the AI writes a rule and code decides if it is accepted", task: TaskRuleDraft, ai: true},
	{label: "Dashboard", note: "start the local web dashboard on 127.0.0.1 for alerts, evidence and cases", task: TaskDashboard},
	{label: "Stored runs", note: "list what is in the local database", task: TaskStored},
	{label: "Make demo data", note: "write synthetic logs and a synthetic system to try the above", task: TaskDemo},
	{label: "Settings", kind: menuOpenSettings},
	{label: "Quit", kind: menuLeave},
}

func menuIndex(kind menuKind) int {
	for index, item := range menuItems {
		if item.kind == kind {
			return index
		}
	}

	return 0
}

const (
	stepBuffer     = 256
	maxModelRunes  = 200
	maxKeyRunes    = 400
	needsModelText = "Type the model name for this provider."
	needsKeyText   = "Type the API key."
	listWait       = 25 * time.Second
	noListText     = "The list of models could not be loaded. Type the model name."
	emptyListText  = "The provider listed no models for this key. Type the model name."
)

type Result struct {
	Report   string
	Complete bool
	SavedTo  string
}

type Runner func(ctx context.Context, step func(text string)) (Result, error)

type Choice struct {
	ID           string
	Name         string
	Local        bool
	KeyFound     bool
	KeySaved     bool
	KeyEnv       string
	DefaultModel string
}

// HasKey says whether the provider can be used without typing a key.
func (choice Choice) HasKey() bool {
	return choice.Local || choice.KeyFound || choice.KeySaved
}

var ErrKeyRejected = errors.New("the provider rejected the key")

// RuleInput is what the user types for a rule draft. Examples are event references, as reports name
// them, separated by spaces or commas.
type RuleInput struct {
	Goal     string
	Examples string
	Title    string
	Level    string
}

const (
	ruleGoal = iota
	ruleExamples
	ruleTitle
	ruleLevel
	ruleFieldCount
)

var (
	ruleLabels = [ruleFieldCount]string{"Goal, what the rule is for:", "Example events (like web01/auth.log:68, separated by spaces):", "Title (empty: the goal):", "Level (informational, low, medium, high or critical; empty: medium):"}
	ruleLimits = [ruleFieldCount]int{300, 2000, 100, 20}
)

type Setup struct {
	Task string
	// Rule is only set for a rule draft.
	Rule RuleInput
	// Replay makes the run a replay of the recording that the backend holds. No provider, model or key is needed.
	Replay     bool
	ProviderID string
	Model      string
	Key        string
	Reasoning  string
}

type ReasoningChoice struct {
	Value string
	Label string
}

const (
	TaskTriage           = "triage"
	TaskDetect           = "detect"
	TaskAnalyze          = "analyze"
	TaskForensics        = "forensics"
	TaskForensicsAnalyze = "forensics-analyze"
	TaskStored           = "stored"
	TaskDemo             = "demo"
	TaskDashboard        = "dashboard"
	TaskRuleDraft        = "rule-draft"
)

type Plan struct {
	ConsentText string
	Title       string
	// Label is shown next to the title when the run is a replay, for example "REPLAY".
	Label   string
	Summary string
	Preview string
	// MaxRequests and MaxTokens are the limits of the run. The progress bar shows how much of them is used.
	MaxRequests int
	MaxTokens   int
	Confirm     func()
	Run         Runner
	// Local says that the run stays on this computer: nothing is sent to anyone. The page that asks for the
	// confirmation says so, and the running line shows no budget of requests and tokens.
	Local bool
}

// Backend does the real work for the screen. It is defined here, where it is used,
// so this package never imports the code that talks to a provider.
type Backend interface {
	Providers() []Choice
	Models(ctx context.Context, providerID, key string) ([]string, error)
	ReasoningChoices(providerID, model string) []ReasoningChoice
	Prepare(setup Setup) (Plan, error)
	TaskReady(task string) error
	KeysCanBeSaved() bool
	SaveKey(ctx context.Context, providerID, key string) error
	ForgetKey(providerID string) error
	// SaveSettings keeps the choices for the next runs. It never holds a key.
	SaveSettings(defaults Defaults) error
}

type Defaults struct {
	ProviderID string
	Model      string
	Reasoning  string
}

type keySaveResult int

const (
	keyNotSaved keySaveResult = iota
	keySaved
	keySaveFailed
)

type stepMsg struct {
	run  int
	text string
}

type modelsMsg struct {
	fetch  int
	models []string
	err    error
	key    keySaveResult
}

type doneMsg struct {
	run    int
	result Result
	err    error
}

type Model struct {
	screen          screen
	step            homeStep
	target          string
	backend         Backend
	defaults        Defaults
	cursor          int
	notice          string
	choices         []Choice
	providerCursor  int
	modelInput      []rune
	models          []string
	modelCursor     int
	modelsLoading   bool
	modelTyping     bool
	modelsNotice    string
	fetchID         int
	reasonChoices   []ReasoningChoice
	reasonCursor    int
	reasoning       string
	settingsMode    bool
	settingsCursor  int
	keyNotice       string
	consentFull     bool
	localRun        bool
	consentScroll   int
	task            string
	title           string
	label           string
	outbox          []string
	transcript      []string
	version         string
	quitting        bool
	frame           int
	leaveFullScreen bool
	enterFullScreen bool
	pending         Defaults
	hasPending      bool
	keyInput        []rune
	ruleFields      [ruleFieldCount][]rune
	ruleCursor      int
	setupError      string
	plan            *Plan
	steps           []string
	progress        progress
	running         bool
	cancelling      bool
	cancel          context.CancelFunc
	runID           int
	stepChannel     chan tea.Msg
	width           int
	height          int
}

func New(target string, backend Backend, defaults Defaults) Model {
	return Model{target: target, backend: backend, defaults: defaults}
}

func (model Model) WithVersion(version string) Model {
	model.version = version

	return model
}

func (model Model) WithTaskA() Model {
	return model.startTask("")
}

func (model Model) WithTask(task string) Model {
	return model.startTask(task)
}

// WithReplay opens the screen at the dry run of a replay. The backend holds the recording.
func (model Model) WithReplay() Model {
	if model.backend == nil {
		model.notice = "There is nothing to replay."
		return model
	}

	plan, err := model.backend.Prepare(Setup{Replay: true})
	if err != nil {
		model.notice = "The recording cannot be replayed: " + err.Error()
		return model
	}
	model.plan = &plan
	model.consentFull = false
	model.consentScroll = 0
	model.hasPending = false
	model.step = stepConsent

	return model
}

func (model Model) Init() tea.Cmd {
	return nil
}

func (model Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	updated, command := model.update(message)

	next, isModel := updated.(Model)
	if !isModel {
		return updated, command
	}

	var ordered []tea.Cmd
	if next.leaveFullScreen {
		next.leaveFullScreen = false
		ordered = append(ordered, tea.ExitAltScreen)
	}
	if len(next.outbox) > 0 {
		text := strings.Join(next.outbox, "\n")
		next.transcript = append(slices.Clone(next.transcript), next.outbox...)
		next.outbox = nil
		ordered = append(ordered, tea.Println(text))
	}
	if next.enterFullScreen {
		next.enterFullScreen = false
		ordered = append(ordered, tea.EnterAltScreen)
	}
	if len(ordered) == 0 {
		return next, command
	}

	// The terminal must change its mode before the text is printed, and the text is printed
	// in the normal terminal, so these commands run one after the other.
	return next, tea.Sequence(append(ordered, command)...)
}

func (model Model) update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = message.Width, message.Height
		model.consentScroll = min(model.consentScroll, model.maxConsentScroll())

		return model, nil
	case tea.KeyMsg:
		return model.handleKey(message)
	case modelsMsg:
		return model.receiveModels(message), nil
	case spinnerMsg:
		if message.run != model.runID || !model.running {
			return model, nil
		}
		model.frame++

		return model, spinnerTick(model.runID)
	case stepMsg:
		if message.run != model.runID {
			return model, nil
		}
		model.steps = append(slices.Clone(model.steps), message.text)
		if !model.progress.read(message.text) {
			model = model.say(styleDim.Render("  ⎿ " + safeText(message.text)))
		}

		return model, waitForMessage(model.stepChannel)
	case doneMsg:
		if message.run != model.runID || !model.running {
			return model, nil
		}
		model.running = false
		model.cancelling = false
		model.cancel()
		model = model.say(model.resultsText(message))

		return model, nil
	}

	return model, nil
}

func (model Model) Printed() string {
	return strings.Join(append(slices.Clone(model.transcript), model.outbox...), "\n")
}

// say queues text to be printed above the live area. The text must already be clean.
func (model Model) say(text string) Model {
	model.outbox = append(slices.Clone(model.outbox), text)

	return model
}

func (model Model) sayRunStart(plan *Plan) Model {
	text := plan.Summary
	if text == "" {
		text = plan.Preview
	}

	info := "  Target folder: " + safeText(model.target)
	if model.version != "" {
		info = "  Omamori " + safeText(model.version) + " · Target folder: " + safeText(model.target)
	}
	model.title, model.label = plan.Title, plan.Label
	heading := model.titleText()
	if model.label != "" {
		heading += " · " + safeText(model.label)
	}
	lines := []string{"", styleAccent.Render("● " + heading), styleDim.Render(info), ""}
	for _, line := range strings.Split(safeText(text), "\n") {
		lines = append(lines, "  "+line)
	}
	model.leaveFullScreen = true

	return model.say(strings.Join(lines, "\n"))
}

func (model Model) titleText() string {
	if model.title == "" {
		return "Task A: Exposure check"
	}

	return safeText(model.title)
}

func (model Model) shortTitle() string {
	short, _, _ := strings.Cut(model.titleText(), ":")

	return short
}

func (model Model) runningTitle() string {
	short, rest, found := strings.Cut(model.titleText(), ": ")
	if !found {
		return short
	}
	runes := []rune(rest)
	if len(runes) > 0 {
		runes[0] = unicode.ToLower(runes[0])
	}

	return short + ", " + string(runes)
}

func (model Model) resultsText(done doneMsg) string {
	report := done.result.Report
	if done.err != nil {
		report = "The run stopped: " + done.err.Error()
	}
	state, style := "complete", styleGood
	if done.err != nil || !done.result.Complete {
		state, style = "incomplete", styleWarn
	}
	title := "Results: " + model.shortTitle() + ", " + state
	if model.label != "" {
		title += " · " + safeText(model.label)
	}

	lines := []string{"", style.Render("● " + title)}
	if done.result.SavedTo != "" {
		lines = append(lines, styleDim.Render("  Saved to: "+safeText(done.result.SavedTo)))
	}
	lines = append(lines, "")
	for _, line := range strings.Split(safeText(report), "\n") {
		lines = append(lines, styleReportLine(line).Render(line))
	}

	return strings.Join(lines, "\n")
}

func (model Model) handleKey(message tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := message.String()

	if key == "ctrl+c" {
		model.stopRun()
		model.quitting = true

		return model, tea.Quit
	}

	if model.screen == homeScreen && (model.step == stepKey || model.step == stepModel && model.modelTyping) {
		return model.handleEntryKey(message)
	}
	if model.screen == homeScreen && model.step == stepRuleInput {
		return model.handleRuleKey(message)
	}

	if key == "q" {
		model.stopRun()
		model.quitting = true

		return model, tea.Quit
	}

	switch model.screen {
	case homeScreen:
		return model.handleHomeKey(key)
	case runScreen:
		switch {
		case model.running && key == "esc" && !model.cancelling:
			model.cancelling = true
			model.cancel()
		case !model.running && (key == "enter" || key == "esc" || key == "b"):
			model.screen = homeScreen
			model.step = stepMenu
			model.notice = ""
			model.enterFullScreen = true
		}
	}

	return model, nil
}

func (model Model) handleHomeKey(key string) (tea.Model, tea.Cmd) {
	switch model.step {
	case stepProvider:
		return model.handleProviderKey(key)
	case stepModel:
		return model.handleModelListKey(key)
	case stepReasoning:
		return model.handleReasoningKey(key)
	case stepConsent:
		return model.handleConsentKey(key)
	case stepSettings:
		return model.handleSettingsKey(key)
	}

	switch key {
	case "up":
		model.cursor = moveUp(model.cursor, len(menuItems))
		model.notice = ""
	case "down":
		model.cursor = moveDown(model.cursor, len(menuItems))
		model.notice = ""
	case "enter":
		item := menuItems[model.cursor]
		switch {
		case item.kind == menuOpenSettings:
			return model.openSettings(), nil
		case item.kind == menuLeave:
			model.quitting = true

			return model, tea.Quit
		case item.task == TaskRuleDraft:
			return model.openRuleInput(), nil
		case item.ai:
			return model.startTask(item.task), nil
		default:
			return model.startLocal(item.task), nil
		}
	}

	return model, nil
}

func (model Model) startLocal(task string) Model {
	model.settingsMode = false
	model.task = task
	model.notice = ""
	if model.target == "" || model.backend == nil {
		model.notice = "There is no target folder. Start Omamori with a folder: omamori ui <folder>"
		return model
	}

	plan, err := model.backend.Prepare(Setup{Task: task})
	if err != nil {
		model.notice = err.Error()
		return model
	}
	plan.Local = true
	model.plan = &plan
	model.consentFull = false
	model.consentScroll = 0
	model.hasPending = false
	model.step = stepConsent

	return model
}

func (model Model) beginSetup() Model {
	if model.target == "" || model.backend == nil {
		model.notice = "There is no target folder. Start Omamori with a folder: omamori check <folder>"
		return model
	}

	model.choices = model.backend.Providers()
	if len(model.choices) == 0 {
		model.notice = "No AI provider is available."
		return model
	}

	model.notice = ""
	model.setupError = ""
	model.keyNotice = ""
	model.providerCursor = model.preselected()
	model.step = stepProvider

	return model
}

// startTask goes straight to the consent screen when the saved choices are complete and a key is
// available. The consent screen and the dry run are never skipped. Otherwise the setup steps start.
func (model Model) startTask(task string) Model {
	model.settingsMode = false
	model.task = task

	if task != "" && model.backend != nil {
		if err := model.backend.TaskReady(task); err != nil {
			model.notice = err.Error()
			return model
		}
	}

	started := model.beginSetup()
	if started.step != stepProvider {
		return started
	}

	index := started.savedProviderIndex()
	if index < 0 || started.defaults.Model == "" || !started.choices[index].HasKey() {
		return started
	}

	chosen := started.choices[index]
	setup := Setup{Task: task, ProviderID: chosen.ID, Model: started.defaults.Model, Reasoning: started.defaults.Reasoning, Rule: started.ruleSetup()}
	plan, err := started.backend.Prepare(setup)
	if err != nil && task == TaskRuleDraft {
		model.step = stepRuleInput
		model.setupError = err.Error()

		return model
	}
	if err != nil {
		model.step = stepMenu
		model.notice = "Your saved settings did not work: " + err.Error() + ". Open Settings to change them."

		return model
	}

	started.providerCursor = index
	started.plan = &plan
	started.consentFull = false
	started.pending = started.defaults
	started.hasPending = true
	started.consentScroll = 0
	started.step = stepConsent

	return started
}

func (model Model) savedProviderIndex() int {
	if model.defaults.ProviderID == "" {
		return -1
	}

	return slices.IndexFunc(model.choices, func(choice Choice) bool { return choice.ID == model.defaults.ProviderID })
}

func (model Model) preselected() int {
	for index, choice := range model.choices {
		if model.defaults.ProviderID != "" && choice.ID == model.defaults.ProviderID {
			return index
		}
	}
	for index, choice := range model.choices {
		if choice.KeyFound || choice.KeySaved {
			return index
		}
	}

	return 0
}

func (model Model) handleProviderKey(key string) (Model, tea.Cmd) {
	switch key {
	case "up":
		model.providerCursor = moveUp(model.providerCursor, len(model.choices))
	case "down":
		model.providerCursor = moveDown(model.providerCursor, len(model.choices))
	case "esc":
		model.step = stepMenu
		if model.settingsMode {
			model.step = stepSettings
		} else if model.task == TaskRuleDraft {
			model.step = stepRuleInput
		}
	case "enter":
		chosen := model.choices[model.providerCursor]
		model.setupError = ""
		if !chosen.HasKey() {
			model.step = stepKey
			return model, nil
		}

		return model.loadModels()
	}

	return model, nil
}

func (model Model) initialModel() string {
	chosen := model.choices[model.providerCursor]
	initial := chosen.DefaultModel
	if model.defaults.ProviderID == chosen.ID && model.defaults.Model != "" {
		initial = model.defaults.Model
	}

	runes := []rune(cleanInput(initial))
	if len(runes) > maxModelRunes {
		runes = runes[:maxModelRunes]
	}

	return string(runes)
}

// loadModels asks the provider for its models. Only the key is sent, never project data.
func (model Model) loadModels() (Model, tea.Cmd) {
	chosen := model.choices[model.providerCursor]

	model.fetchID++
	model.step = stepModel
	model.modelsLoading = true
	model.modelTyping = false
	model.modelsNotice = ""
	model.models = nil
	model.modelCursor = 0
	model.setupError = ""

	backend, fetch, key := model.backend, model.fetchID, string(model.keyInput)
	command := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), listWait)
		defer cancel()
		models, err := backend.Models(ctx, chosen.ID, key)

		saved := keyNotSaved
		if err == nil && len(models) > 0 && key != "" && backend.KeysCanBeSaved() {
			saved = keySaved
			if backend.SaveKey(ctx, chosen.ID, key) != nil {
				saved = keySaveFailed
			}
		}

		return modelsMsg{fetch: fetch, models: models, err: err, key: saved}
	}

	return model, command
}

func (model Model) receiveModels(message modelsMsg) Model {
	if message.fetch != model.fetchID || model.step != stepModel || !model.modelsLoading {
		return model
	}
	model.modelsLoading = false

	if errors.Is(message.err, ErrKeyRejected) {
		model.forgetKey()
		model.step = stepKey
		model.setupError = "The provider rejected the key. Type a new key."

		return model
	}

	switch message.key {
	case keySaved:
		model.keyNotice = "The key was saved in your Keychain."
	case keySaveFailed:
		model.keyNotice = "The key could not be saved. You will need to type it next time."
	}

	initial := model.initialModel()
	if message.err != nil || len(message.models) == 0 {
		model.modelsNotice = noListText
		if message.err == nil {
			model.modelsNotice = emptyListText
		}
		model.modelTyping = true
		model.modelInput = []rune(initial)

		return model
	}

	model.models = slices.Clone(message.models)
	if initial != "" && !slices.Contains(model.models, initial) {
		model.models = append([]string{initial}, model.models...)
	}
	model.modelCursor = max(slices.Index(model.models, initial), 0)

	return model
}

func moveUp(cursor, length int) int {
	if cursor <= 0 {
		return max(length-1, 0)
	}

	return cursor - 1
}

func moveDown(cursor, length int) int {
	if cursor >= length-1 {
		return 0
	}

	return cursor + 1
}

// moveUpInModels goes from the first model to the last model, because the newest models are at the
// bottom. The line below them, which is the way to type a name, is reached with the down key.
func moveUpInModels(cursor, models int) int {
	if cursor > 0 {
		return cursor - 1
	}

	return max(models-1, 0)
}

func (model Model) handleModelListKey(key string) (Model, tea.Cmd) {
	if key == "esc" {
		return model.goBack(), nil
	}
	if model.modelsLoading {
		return model, nil
	}

	last := len(model.models)
	pageSize := max(model.room(4), 1)

	switch key {
	case "up":
		model.modelCursor = moveUpInModels(model.modelCursor, last)
	case "down":
		model.modelCursor = moveDown(model.modelCursor, last+1)
	case "pgup":
		model.modelCursor = max(model.modelCursor-pageSize, 0)
	case "pgdown":
		model.modelCursor = min(model.modelCursor+pageSize, last)
	case "enter":
		if model.modelCursor == last {
			model.modelTyping = true
			model.modelInput = nil
			model.modelsNotice = ""

			return model, nil
		}
		model.modelInput = []rune(model.models[model.modelCursor])

		return model.afterModel(), nil
	}

	return model, nil
}

func cleanInput(text string) string {
	runes := make([]rune, 0, len(text))
	for _, character := range text {
		if !unicode.IsControl(character) && !unicode.Is(unicode.Cf, character) {
			runes = append(runes, character)
		}
	}

	return string(runes)
}

func (model Model) handleEntryKey(message tea.KeyMsg) (Model, tea.Cmd) {
	limit := maxModelRunes
	if model.step == stepKey {
		limit = maxKeyRunes
	}

	switch message.Type {
	case tea.KeyEsc:
		return model.goBack(), nil
	case tea.KeyEnter:
		return model.submitEntry()
	case tea.KeyBackspace:
		model.editInput(func(input []rune) []rune { return input[:max(len(input)-1, 0)] })
	case tea.KeySpace:
		model.editInput(func(input []rune) []rune { return append(slices.Clone(input), ' ') })
	case tea.KeyRunes:
		typed := []rune(cleanInput(string(message.Runes)))
		model.editInput(func(input []rune) []rune {
			return append(slices.Clone(input), typed[:min(len(typed), max(limit-len(input), 0))]...)
		})
	}

	return model, nil
}

func (model *Model) editInput(change func([]rune) []rune) {
	if model.step == stepKey {
		model.keyInput = change(model.keyInput)
	} else {
		model.modelInput = change(model.modelInput)
	}
	model.setupError = ""
}

func (model Model) goBack() Model {
	model.setupError = ""
	model.keyNotice = ""
	model.fetchID++
	model.modelsLoading = false

	if model.step == stepReasoning {
		model.step = stepModel

		return model
	}

	if model.step == stepModel && model.modelTyping && len(model.models) > 0 {
		model.modelTyping = false

		return model
	}

	model.forgetKey()
	model.modelTyping = false
	model.step = stepProvider

	return model
}

func (model *Model) forgetKey() {
	clear(model.keyInput)
	model.keyInput = nil
}

func (model Model) submitEntry() (Model, tea.Cmd) {
	model.setupError = ""

	if model.step == stepKey {
		if strings.TrimSpace(string(model.keyInput)) == "" {
			model.setupError = needsKeyText
			return model, nil
		}

		return model.loadModels()
	}

	if strings.TrimSpace(string(model.modelInput)) == "" {
		model.setupError = needsModelText
		return model, nil
	}

	return model.afterModel(), nil
}

// afterModel shows the reasoning step when the model has documented levels, and goes on otherwise.
func (model Model) afterModel() Model {
	chosen := model.choices[model.providerCursor]
	model.reasoning = ""
	model.reasonCursor = 0
	model.reasonChoices = nil

	choices := model.backend.ReasoningChoices(chosen.ID, strings.TrimSpace(string(model.modelInput)))
	if len(choices) < 2 {
		return model.finish()
	}

	model.reasonChoices = choices
	if model.defaults.ProviderID == chosen.ID && model.defaults.Model == strings.TrimSpace(string(model.modelInput)) {
		model.reasonCursor = max(slices.IndexFunc(choices, func(choice ReasoningChoice) bool { return choice.Value == model.defaults.Reasoning }), 0)
	}
	model.setupError = ""
	model.step = stepReasoning

	return model
}

// finish ends the setup. In the settings it saves the choices. Otherwise it asks for the plan.
func (model Model) finish() Model {
	if model.settingsMode {
		return model.saveSettings()
	}

	return model.prepare()
}

func (model Model) saveSettings() Model {
	chosen := model.choices[model.providerCursor]
	saved := Defaults{ProviderID: chosen.ID, Model: strings.TrimSpace(string(model.modelInput)), Reasoning: model.reasoning}

	if err := model.backend.SaveSettings(saved); err != nil {
		model.setupError = err.Error()
		return model
	}

	model.defaults = saved
	model.forgetKey()
	model.modelTyping = false
	model.setupError = ""
	model.choices = model.backend.Providers()
	model.settingsCursor = 0
	model.notice = "Settings saved."
	model.step = stepSettings

	return model
}

func (model Model) handleReasoningKey(key string) (Model, tea.Cmd) {
	last := len(model.reasonChoices) - 1

	switch key {
	case "esc":
		return model.goBack(), nil
	case "up":
		model.reasonCursor = moveUp(model.reasonCursor, len(model.reasonChoices))
	case "down":
		model.reasonCursor = moveDown(model.reasonCursor, len(model.reasonChoices))
	case "enter":
		model.reasoning = model.reasonChoices[min(model.reasonCursor, last)].Value

		return model.finish(), nil
	}

	return model, nil
}

func (model Model) prepare() Model {
	chosen := model.choices[model.providerCursor]

	plan, err := model.backend.Prepare(Setup{Task: model.task, ProviderID: chosen.ID, Model: string(model.modelInput), Key: string(model.keyInput), Reasoning: model.reasoning, Rule: model.ruleSetup()})
	if err != nil && model.task == TaskRuleDraft {
		// The input of the rule is the most likely cause, so the user goes back to it. The key is not kept.
		model.forgetKey()
		model.modelTyping = false
		model.step = stepRuleInput
		model.setupError = err.Error()
		return model
	}
	if err != nil {
		model.setupError = err.Error()
		return model
	}
	model.forgetKey()

	model.pending = Defaults{ProviderID: chosen.ID, Model: strings.TrimSpace(string(model.modelInput)), Reasoning: model.reasoning}
	model.hasPending = true
	model.plan = &plan
	model.consentFull = false
	model.setupError = ""
	model.modelTyping = false
	model.consentScroll = 0
	model.step = stepConsent

	return model
}

func (model Model) handleConsentKey(key string) (tea.Model, tea.Cmd) {
	pageSize := max(model.consentViewHeight(), 1)

	switch key {
	case "up":
		model.consentScroll = max(model.consentScroll-1, 0)
	case "down":
		model.consentScroll = min(model.consentScroll+1, model.maxConsentScroll())
	case "pgup":
		model.consentScroll = max(model.consentScroll-pageSize, 0)
	case "pgdown":
		model.consentScroll = min(model.consentScroll+pageSize, model.maxConsentScroll())
	case "home":
		model.consentScroll = 0
	case "end":
		model.consentScroll = model.maxConsentScroll()
	case "d":
		if model.plan != nil && model.plan.Summary != "" {
			model.consentFull = !model.consentFull
			model.consentScroll = 0
		}
	case "esc", "n":
		model.notice = "Nothing was sent."
		if model.plan != nil && model.plan.Local {
			model.notice = "Nothing was started."
		}
		model.plan = nil
		model.step = stepMenu
	case "enter", "y":
		return model.confirm()
	}

	return model, nil
}

func (model Model) confirm() (tea.Model, tea.Cmd) {
	plan := model.plan
	if plan == nil || plan.Confirm == nil || plan.Run == nil {
		return model, nil
	}

	model = model.sayRunStart(plan)
	model.progress = progress{maxRequests: plan.MaxRequests, maxTokens: plan.MaxTokens}
	model.localRun = plan.Local
	model.plan = nil
	model.step = stepMenu
	plan.Confirm()

	if model.hasPending && model.pending != model.defaults && model.backend.SaveSettings(model.pending) == nil {
		model.defaults = model.pending
	}

	return model.startRun(plan.Run)
}

func (model *Model) stopRun() {
	if model.running && model.cancel != nil {
		model.cancel()
	}
}

func (model Model) startRun(runner Runner) (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	messages := make(chan tea.Msg, stepBuffer)

	model.runID++
	model.screen = runScreen
	model.running = true
	model.cancelling = false
	model.cancel = cancel
	model.stepChannel = messages
	model.steps = nil
	model.frame = 0
	model.notice = ""

	runID := model.runID
	runCommand := func() tea.Msg {
		result, err := runner(ctx, func(text string) {
			select {
			case messages <- stepMsg{run: runID, text: text}:
			default:
			}
		})
		messages <- doneMsg{run: runID, result: result, err: err}

		return nil
	}

	return model, tea.Batch(runCommand, waitForMessage(messages), spinnerTick(runID))
}

var spinnerInterval = 150 * time.Millisecond

type spinnerMsg struct{ run int }

func spinnerTick(runID int) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(spinnerInterval)

		return spinnerMsg{run: runID}
	}
}

func waitForMessage(messages <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		return <-messages
	}
}

type settingsItemKind int

const (
	itemChange settingsItemKind = iota
	itemForget
	itemBack
)

type settingsItem struct {
	kind       settingsItemKind
	providerID string
	label      string
}

func (model Model) settingsItems() []settingsItem {
	items := []settingsItem{{kind: itemChange, label: "Change provider, model and reasoning level"}}
	for _, choice := range model.choices {
		if choice.KeySaved {
			items = append(items, settingsItem{kind: itemForget, providerID: choice.ID, label: "Forget the saved key of " + choice.Name})
		}
	}

	return append(items, settingsItem{kind: itemBack, label: "Back to the home screen"})
}

func (model Model) openSettings() Model {
	if model.backend == nil {
		model.notice = "Settings are not available."
		return model
	}

	model.choices = model.backend.Providers()
	model.settingsCursor = 0
	model.settingsMode = false
	model.notice = ""
	model.step = stepSettings

	return model
}

func (model Model) handleSettingsKey(key string) (tea.Model, tea.Cmd) {
	items := model.settingsItems()
	model.settingsCursor = min(model.settingsCursor, len(items)-1)

	switch key {
	case "up":
		model.settingsCursor = moveUp(model.settingsCursor, len(items))
		model.notice = ""
	case "down":
		model.settingsCursor = moveDown(model.settingsCursor, len(items))
		model.notice = ""
	case "esc":
		model.leaveSettings()
	case "enter":
		item := items[model.settingsCursor]
		switch item.kind {
		case itemBack:
			model.leaveSettings()
		case itemChange:
			model.settingsMode = true
			model.setupError = ""
			model.keyNotice = ""
			model.notice = ""
			model.providerCursor = max(model.savedProviderIndex(), 0)
			model.step = stepProvider
		case itemForget:
			model.notice = "The saved key was removed."
			if err := model.backend.ForgetKey(item.providerID); err != nil {
				model.notice = "The saved key could not be removed."
			}
			model.choices = model.backend.Providers()
			model.settingsCursor = 0
		}
	}

	return model, nil
}

func (model *Model) leaveSettings() {
	model.settingsMode = false
	model.notice = ""
	model.step = stepMenu
}

func (model Model) openRuleInput() Model {
	model.settingsMode = false
	model.task = TaskRuleDraft
	model.notice = ""
	if model.target == "" || model.backend == nil {
		model.notice = "There is no target folder. Start Omamori with a folder of logs: omamori ui <folder>"
		return model
	}
	if err := model.backend.TaskReady(TaskRuleDraft); err != nil {
		model.notice = err.Error()
		return model
	}
	model.setupError = ""
	model.ruleCursor = ruleGoal
	model.step = stepRuleInput

	return model
}

func (model Model) ruleSetup() RuleInput {
	if model.task != TaskRuleDraft {
		return RuleInput{}
	}
	text := func(field int) string { return strings.TrimSpace(string(model.ruleFields[field])) }

	return RuleInput{Goal: text(ruleGoal), Examples: text(ruleExamples), Title: text(ruleTitle), Level: strings.ToLower(text(ruleLevel))}
}

// handleRuleKey edits the fields of a rule draft. Every key is text here, so q does not quit.
func (model Model) handleRuleKey(message tea.KeyMsg) (Model, tea.Cmd) {
	field := &model.ruleFields[model.ruleCursor]
	limit := ruleLimits[model.ruleCursor]
	switch message.Type {
	case tea.KeyEsc:
		model.setupError = ""
		model.step = stepMenu
	case tea.KeyUp, tea.KeyShiftTab:
		model.ruleCursor = moveUp(model.ruleCursor, ruleFieldCount)
	case tea.KeyDown, tea.KeyTab:
		model.ruleCursor = moveDown(model.ruleCursor, ruleFieldCount)
	case tea.KeyEnter:
		if model.ruleCursor < ruleFieldCount-1 {
			model.ruleCursor++
			return model, nil
		}
		return model.submitRule(), nil
	case tea.KeyBackspace:
		*field = slices.Clone((*field)[:max(len(*field)-1, 0)])
		model.setupError = ""
	case tea.KeySpace:
		if len(*field) < limit {
			*field = append(slices.Clone(*field), ' ')
		}
		model.setupError = ""
	case tea.KeyRunes:
		typed := []rune(cleanInput(string(message.Runes)))
		*field = append(slices.Clone(*field), typed[:min(len(typed), max(limit-len(*field), 0))]...)
		model.setupError = ""
	}

	return model, nil
}

func (model Model) submitRule() Model {
	input := model.ruleSetup()
	switch {
	case input.Goal == "":
		model.ruleCursor, model.setupError = ruleGoal, "Type what the rule is for."
		return model
	case input.Examples == "":
		model.ruleCursor, model.setupError = ruleExamples, "Type at least one example event, as a report names it."
		return model
	}
	model.setupError = ""
	started := model.startTask(TaskRuleDraft)
	if started.notice != "" {
		started.step = stepRuleInput
		started.setupError, started.notice = started.notice, ""
	}

	return started
}
