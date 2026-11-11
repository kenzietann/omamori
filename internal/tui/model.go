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

// The home screen has steps. They are dialogs of the home screen, so the program still has three screens.
type homeStep int

const (
	stepMenu homeStep = iota
	stepProvider
	stepModel
	stepKey
	stepReasoning
	stepConsent
	stepSettings
)

const (
	menuTaskA = iota
	menuTaskB
	menuSettings
	menuQuit
)

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
	ID       string
	Name     string
	Local    bool
	KeyFound bool
	// KeySaved is true when a key of this provider is kept between runs.
	KeySaved     bool
	KeyEnv       string
	DefaultModel string
}

// HasKey says whether the provider can be used without typing a key.
func (choice Choice) HasKey() bool {
	return choice.Local || choice.KeyFound || choice.KeySaved
}

// ErrKeyRejected is what a backend returns when the provider says the key is wrong.
var ErrKeyRejected = errors.New("the provider rejected the key")

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
	// Summary is the short form of Preview. It is shown first when it is there.
	Summary string
	Preview string
	Confirm func()
	Run     Runner
}

// Backend does the real work for the screen. It is defined here, where it is used,
// so this package never imports the code that talks to a provider.
type Backend interface {
	Providers() []Choice
	Models(ctx context.Context, providerID, key string) ([]string, error)
	// ReasoningChoices is empty when the model has no documented choice. Then the step is skipped.
	ReasoningChoices(providerID, model string) []ReasoningChoice
	Prepare(setup Setup) (Plan, error)
	// KeysCanBeSaved says whether a key can be kept between runs on this system.
	KeysCanBeSaved() bool
	SaveKey(ctx context.Context, providerID, key string) error
	ForgetKey(providerID string) error
	// SaveSettings keeps the choices for the next runs. It never holds a key.
	SaveSettings(defaults Defaults) error
}

type Defaults struct {
	ProviderID string
	Model      string
	// Reasoning is empty for the provider's default.
	Reasoning string
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
	settingsMode   bool
	settingsCursor int
	keyNotice      string
	consentFull    bool
	consentScroll  int
	outbox         []string
	transcript     []string
	version        string
	quitting       bool
	frame          int
	// leaveFullScreen and enterFullScreen ask Update to switch the terminal between the full-screen
	// pages and the normal terminal, where a run prints its steps and its report.
	leaveFullScreen bool
	enterFullScreen bool
	pending         Defaults
	hasPending      bool
	keyInput        []rune
	setupError      string
	plan            *Plan
	steps           []string
	running         bool
	cancelling      bool
	cancel          context.CancelFunc
	runID           int
	stepChannel     chan tea.Msg
	width           int
	height          int
}

// New makes the screen. It prints into the terminal like a normal program, and keeps only a small live
// area at the bottom, so that the scrollback, the wheel and the selection of the terminal all work.
func New(target string, backend Backend, defaults Defaults) Model {
	return Model{target: target, backend: backend, defaults: defaults}
}

// WithVersion sets the version that the banner shows.
func (model Model) WithVersion(version string) Model {
	model.version = version

	return model
}

// WithTaskA opens the screen at the setup of Task A, as if the user had chosen it in the menu.
func (model Model) WithTaskA() Model {
	return model.startTaskA()
}

func (model Model) Init() tea.Cmd {
	return nil
}

// Update handles a message. Text that the model wants to show above the live area is collected
// in the outbox, and is printed here, so that it stays in the scrollback of the terminal.
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
		model = model.say(styleDim.Render("  ⎿ " + safeText(message.text)))

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

// Printed is everything that was printed above the live area, and what waits to be printed.
func (model Model) Printed() string {
	return strings.Join(append(slices.Clone(model.transcript), model.outbox...), "\n")
}

// say queues text to be printed above the live area. The text must already be clean.
func (model Model) say(text string) Model {
	model.outbox = append(slices.Clone(model.outbox), text)

	return model
}

// resultsText is what the user reads when a run ends: the state, the saved folder, and the report.
// sayRunStart is the first text of a run, printed in the normal terminal: what was confirmed.
func (model Model) sayRunStart(plan *Plan) Model {
	text := plan.Summary
	if text == "" {
		text = plan.Preview
	}

	info := "  Target folder: " + safeText(model.target)
	if model.version != "" {
		info = "  Omamori " + safeText(model.version) + " · Target folder: " + safeText(model.target)
	}
	lines := []string{"", styleAccent.Render("● Task A: Exposure check"), styleDim.Render(info), ""}
	for _, line := range strings.Split(safeText(text), "\n") {
		lines = append(lines, "  "+line)
	}
	model.leaveFullScreen = true

	return model.say(strings.Join(lines, "\n"))
}

func (model Model) resultsText(done doneMsg) string {
	report := done.result.Report
	if done.err != nil {
		report = "The run stopped: " + done.err.Error()
	}
	title, style := "Results: Task A, complete", styleGood
	if done.err != nil || !done.result.Complete {
		title, style = "Results: Task A, incomplete", styleWarn
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

	// While text is typed, q is a letter. Only ctrl+c quits.
	if model.screen == homeScreen && (model.step == stepKey || model.step == stepModel && model.modelTyping) {
		return model.handleEntryKey(message)
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
		model.cursor = moveUp(model.cursor, menuQuit+1)
		model.notice = ""
	case "down":
		model.cursor = moveDown(model.cursor, menuQuit+1)
		model.notice = ""
	case "enter":
		switch model.cursor {
		case menuTaskA:
			return model.startTaskA(), nil
		case menuTaskB:
			model.notice = "Task B is not built yet."
		case menuSettings:
			return model.openSettings(), nil
		case menuQuit:
			model.quitting = true

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
	model.keyNotice = ""
	model.providerCursor = model.preselected()
	model.step = stepProvider

	return model
}

// startTaskA goes straight to the consent screen when the saved choices are complete and a key is
// available. The consent screen and the dry run are never skipped. Otherwise the setup steps start.
func (model Model) startTaskA() Model {
	model.settingsMode = false

	started := model.beginSetup()
	if started.step != stepProvider {
		return started
	}

	index := started.savedProviderIndex()
	if index < 0 || started.defaults.Model == "" || !started.choices[index].HasKey() {
		return started
	}

	chosen := started.choices[index]
	setup := Setup{ProviderID: chosen.ID, Model: started.defaults.Model, Reasoning: started.defaults.Reasoning}
	plan, err := started.backend.Prepare(setup)
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

// savedProviderIndex is the place of the provider in the settings, or -1.
func (model Model) savedProviderIndex() int {
	if model.defaults.ProviderID == "" {
		return -1
	}

	return slices.IndexFunc(model.choices, func(choice Choice) bool { return choice.ID == model.defaults.ProviderID })
}

// preselected is the provider named in the settings, or else the first one whose key is already set.
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

		// A typed key is kept for the next runs only after the provider has accepted it.
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

// moveUp and moveDown go around the end of a list, so that a long list can be crossed fast.
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

// A list has one more line than the models: the way to type a name.
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

// goBack leaves the key behind. From a typed model name it goes to the list when there is one.
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

// prepare asks the backend for the plan. The key is passed on and wiped from this model once the plan exists.
func (model Model) prepare() Model {
	chosen := model.choices[model.providerCursor]

	plan, err := model.backend.Prepare(Setup{ProviderID: chosen.ID, Model: string(model.modelInput), Key: string(model.keyInput), Reasoning: model.reasoning})
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

	model = model.sayRunStart(plan)
	model.plan = nil
	model.step = stepMenu
	plan.Confirm()

	// The choices of a confirmed run are kept, so the next run needs no setup. A failure to save is not worth a stop.
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

// startRun starts the work. The steps and the end of the run go through one channel, so that the
// reader sees them in the order in which they happened, and no step is printed after the results.
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

// spinnerInterval is how often the mark in front of the running line changes.
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

// settingsItems has one line to change the choices, one line for each saved key, and the way back.
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
