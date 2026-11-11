package tui

import (
	"context"
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
	resultsScreen
)

// The home screen has steps. They are dialogs of the home screen, so the program still has three screens.
type homeStep int

const (
	stepMenu homeStep = iota
	stepProvider
	stepModel
	stepKey
	stepReasoning
	stepConsent
)

const (
	menuTaskA = iota
	menuTaskB
	menuQuit
)

const (
	stepBuffer     = 256
	maxModelRunes  = 200
	maxKeyRunes    = 400
	consentChrome  = 10
	needsModelText = "Type the model name for this provider."
	needsKeyText   = "Type the API key."
	listWait       = 25 * time.Second
	listChrome     = 9
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
	KeyEnv       string
	DefaultModel string
}

type Setup struct {
	ProviderID string
	Model      string
	Key        string
	// Reasoning is empty for the provider's default.
	Reasoning string
}

// ReasoningChoice is one level of reasoning. The first choice of a list is the default, with an empty Value.
type ReasoningChoice struct {
	Value string
	Label string
}

// A Plan is what the user is asked to confirm. Nothing has been sent when a Plan exists.
type Plan struct {
	ConsentText string
	Preview     string
	Confirm     func()
	Run         Runner
}

// Backend does the real work for the screen. It is defined here, where it is used,
// so this package never imports the code that talks to a provider.
type Backend interface {
	Providers() []Choice
	Models(ctx context.Context, providerID, key string) ([]string, error)
	// ReasoningChoices is empty when the model has no documented choice. Then the step is skipped.
	ReasoningChoices(providerID, model string) []ReasoningChoice
	Prepare(setup Setup) (Plan, error)
}

type Defaults struct {
	ProviderID string
	Model      string
}

type stepMsg struct {
	run  int
	text string
}

type stepsEndedMsg struct{}

type modelsMsg struct {
	fetch  int
	models []string
	err    error
}

type doneMsg struct {
	run    int
	result Result
	err    error
}

type Model struct {
	screen         screen
	step           homeStep
	target         string
	backend        Backend
	defaults       Defaults
	cursor         int
	notice         string
	choices        []Choice
	providerCursor int
	modelInput     []rune
	models         []string
	modelCursor    int
	modelsLoading  bool
	modelTyping    bool
	modelsNotice   string
	fetchID        int
	reasonChoices  []ReasoningChoice
	reasonCursor   int
	reasoning      string
	keyInput       []rune
	setupError     string
	plan           *Plan
	consentScroll  int
	steps          []string
	report         string
	saved          string
	stopped        bool
	running        bool
	cancelling     bool
	cancel         context.CancelFunc
	runID          int
	stepChannel    chan string
	scroll         int
	width          int
	height         int
}

func New(target string, backend Backend, defaults Defaults) Model {
	return Model{target: target, backend: backend, defaults: defaults}
}

// WithTaskA opens the screen at the setup of Task A, as if the user had chosen it in the menu.
func (model Model) WithTaskA() Model {
	return model.beginSetup()
}

func (model Model) Init() tea.Cmd {
	return nil
}

func (model Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = message.Width, message.Height
		model.scroll = min(model.scroll, model.maxScroll())
		model.consentScroll = min(model.consentScroll, model.maxConsentScroll())

		return model, nil
	case tea.KeyMsg:
		return model.handleKey(message)
	case modelsMsg:
		return model.receiveModels(message), nil
	case stepMsg:
		if message.run != model.runID {
			return model, nil
		}
		model.steps = append(slices.Clone(model.steps), message.text)

		return model, waitForStep(model.runID, model.stepChannel)
	case doneMsg:
		if message.run != model.runID || !model.running {
			return model, nil
		}
		model.running = false
		model.cancelling = false
		model.cancel()
		model.stopped = message.err != nil || !message.result.Complete
		model.report = message.result.Report
		model.saved = message.result.SavedTo
		if message.err != nil {
			model.report = "The run stopped: " + message.err.Error()
		}
		model.screen = resultsScreen
		model.scroll = 0

		return model, nil
	}

	return model, nil
}

func (model Model) handleKey(message tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := message.String()

	if key == "ctrl+c" {
		model.stopRun()

		return model, tea.Quit
	}

	// While text is typed, q is a letter. Only ctrl+c quits.
	if model.screen == homeScreen && (model.step == stepKey || model.step == stepModel && model.modelTyping) {
		return model.handleEntryKey(message)
	}

	if key == "q" {
		model.stopRun()

		return model, tea.Quit
	}

	switch model.screen {
	case homeScreen:
		return model.handleHomeKey(key)
	case runScreen:
		if key == "esc" && !model.cancelling {
			model.cancelling = true
			model.cancel()
		}
	case resultsScreen:
		return model.handleResultsKey(key), nil
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
	}

	switch key {
	case "up":
		model.cursor = max(model.cursor-1, 0)
		model.notice = ""
	case "down":
		model.cursor = min(model.cursor+1, menuQuit)
		model.notice = ""
	case "enter":
		switch model.cursor {
		case menuTaskA:
			return model.beginSetup(), nil
		case menuTaskB:
			model.notice = "Task B is not built yet."
		case menuQuit:
			return model, tea.Quit
		}
	}

	return model, nil
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
	model.providerCursor = model.preselected()
	model.step = stepProvider

	return model
}

// preselected is the provider named in the settings, or else the first one whose key is already set.
func (model Model) preselected() int {
	for index, choice := range model.choices {
		if model.defaults.ProviderID != "" && choice.ID == model.defaults.ProviderID {
			return index
		}
	}
	for index, choice := range model.choices {
		if choice.KeyFound {
			return index
		}
	}

	return 0
}

func (model Model) handleProviderKey(key string) (Model, tea.Cmd) {
	switch key {
	case "up":
		model.providerCursor = max(model.providerCursor-1, 0)
	case "down":
		model.providerCursor = min(model.providerCursor+1, len(model.choices)-1)
	case "esc":
		model.step = stepMenu
	case "enter":
		chosen := model.choices[model.providerCursor]
		model.setupError = ""
		if !chosen.Local && !chosen.KeyFound {
			model.step = stepKey
			return model, nil
		}

		return model.loadModels()
	}

	return model, nil
}

// initialModel is the model from the settings for this provider, or else the provider's default.
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

		return modelsMsg{fetch: fetch, models: models, err: err}
	}

	return model, command
}

func (model Model) receiveModels(message modelsMsg) Model {
	if message.fetch != model.fetchID || model.step != stepModel || !model.modelsLoading {
		return model
	}
	model.modelsLoading = false

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

// A list has one more line than the models: the way to type a name.
func (model Model) handleModelListKey(key string) (Model, tea.Cmd) {
	if key == "esc" {
		return model.goBack(), nil
	}
	if model.modelsLoading {
		return model, nil
	}

	last := len(model.models)
	pageSize := max(model.listRoom(), 1)

	switch key {
	case "up":
		model.modelCursor = max(model.modelCursor-1, 0)
	case "down":
		model.modelCursor = min(model.modelCursor+1, last)
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

// goBack leaves the key behind. From a typed model name it goes to the list when there is one.
func (model Model) goBack() Model {
	model.setupError = ""
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
		return model.prepare()
	}

	model.reasonChoices = choices
	model.setupError = ""
	model.step = stepReasoning

	return model
}

func (model Model) handleReasoningKey(key string) (Model, tea.Cmd) {
	last := len(model.reasonChoices) - 1

	switch key {
	case "esc":
		return model.goBack(), nil
	case "up":
		model.reasonCursor = max(model.reasonCursor-1, 0)
	case "down":
		model.reasonCursor = min(model.reasonCursor+1, last)
	case "enter":
		model.reasoning = model.reasonChoices[min(model.reasonCursor, last)].Value

		return model.prepare(), nil
	}

	return model, nil
}

// prepare asks the backend for the plan. The key is passed on and wiped from this model once the plan exists.
func (model Model) prepare() Model {
	chosen := model.choices[model.providerCursor]

	plan, err := model.backend.Prepare(Setup{ProviderID: chosen.ID, Model: string(model.modelInput), Key: string(model.keyInput), Reasoning: model.reasoning})
	if err != nil {
		model.setupError = err.Error()
		return model
	}
	model.forgetKey()

	model.plan = &plan
	model.consentScroll = 0
	model.setupError = ""
	model.modelTyping = false
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
	case "esc", "n":
		model.plan = nil
		model.step = stepMenu
		model.notice = "Nothing was sent."
	case "enter", "y":
		return model.confirm()
	}

	return model, nil
}

// confirm is the only way to start a run: the user has read the dry run and agreed.
func (model Model) confirm() (tea.Model, tea.Cmd) {
	plan := model.plan
	if plan == nil || plan.Confirm == nil || plan.Run == nil {
		return model, nil
	}

	model.plan = nil
	model.step = stepMenu
	plan.Confirm()

	return model.startRun(plan.Run)
}

func (model Model) handleResultsKey(key string) Model {
	pageSize := max(model.viewHeight(), 1)

	switch key {
	case "b", "esc":
		model.screen = homeScreen
		model.step = stepMenu
		model.notice = ""
	case "up":
		model.scroll = max(model.scroll-1, 0)
	case "down":
		model.scroll = min(model.scroll+1, model.maxScroll())
	case "pgup":
		model.scroll = max(model.scroll-pageSize, 0)
	case "pgdown":
		model.scroll = min(model.scroll+pageSize, model.maxScroll())
	}

	return model
}

func (model *Model) stopRun() {
	if model.running && model.cancel != nil {
		model.cancel()
	}
}

func (model Model) startRun(runner Runner) (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	steps := make(chan string, stepBuffer)

	model.runID++
	model.screen = runScreen
	model.running = true
	model.cancelling = false
	model.cancel = cancel
	model.stepChannel = steps
	model.steps = nil
	model.report = ""
	model.saved = ""
	model.stopped = false
	model.notice = ""

	runID := model.runID
	runCommand := func() tea.Msg {
		result, err := runner(ctx, func(text string) {
			select {
			case steps <- text:
			default:
			}
		})
		close(steps)

		return doneMsg{run: runID, result: result, err: err}
	}

	return model, tea.Batch(runCommand, waitForStep(runID, steps))
}

func waitForStep(runID int, steps <-chan string) tea.Cmd {
	return func() tea.Msg {
		text, open := <-steps
		if !open {
			return stepsEndedMsg{}
		}

		return stepMsg{run: runID, text: text}
	}
}
