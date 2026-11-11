// Package taskrun runs Task A from start to finish: it sets up the provider, shows what will be
// sent, waits for the user's confirmation, runs the guarded agent, and saves the report and the
// event log in a new folder outside the project. It knows nothing about the screen.
package taskrun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/eventlog"
	"github.com/kenzietann/omamori/internal/exposure"
	"github.com/kenzietann/omamori/internal/gateway"
	"github.com/kenzietann/omamori/internal/githistory"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/triage"
)

const (
	maxLoggedTextRunes = 1500
	maxLoggedRunes     = 6000
)

// The texts are shown to the user and never hold a path, a key, or file content.
var (
	ErrTarget          = errors.New("the project folder is not usable")
	ErrUnknownProvider = errors.New("this provider is not known")
	ErrNeedsModel      = errors.New("this provider needs a model name")
	ErrNeedsKey        = errors.New("this provider needs an API key")
	ErrSetup           = errors.New("the provider could not be set up")
	ErrReasoning       = errors.New("this reasoning level is not available for this model")
	ErrKeyStore        = errors.New("the key could not be saved or removed")
	ErrKeyRejected     = errors.New("the provider rejected the key")
	ErrRecording       = errors.New("the recording cannot be used for this task")
	ErrUnknownTask     = errors.New("this task is not known")
	ErrLogFile         = errors.New("the log file cannot be used")
	ErrModelList       = errors.New("the list of models could not be loaded")
	ErrNotConfirmed    = errors.New("the user has not confirmed the run")
	ErrOutput          = errors.New("the output folder cannot be used: it must be outside the project and new files must be possible")
)

type ProviderFactory func(id, apiKey, model, reasoning string) (outbound.Provider, error)

// Task is the work that a run does.
type Task string

const (
	TaskExposure Task = "exposure"
	TaskTriage   Task = "triage"

	// DefaultLog is the log that the triage reads when none is named, relative to the project folder.
	DefaultLog = "auth.log"
)

var logNamePattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)

type ModelLister func(ctx context.Context, id, apiKey string) ([]string, error)

// KeyStore keeps API keys between runs. The keystore package is the real one.
type KeyStore interface {
	Available() bool
	Get(ctx context.Context, providerID string) (string, error)
	Set(ctx context.Context, providerID, key string) error
	Delete(ctx context.Context, providerID string) error
}

type Config struct {
	Target     string
	OutputBase string
	Limits     agent.Limits
	// Triage holds the settings of the log triage. Without it, the defaults are used.
	Triage *triage.Config
	// LookupEnv, Now, NewProvider and ListModels default to the real ones. Tests replace them.
	LookupEnv   func(string) string
	Now         func() time.Time
	NewProvider ProviderFactory
	ListModels  ModelLister
	// Keys is optional. Without it, keys come only from the environment and from the user.
	Keys KeyStore
}

type Choice struct {
	ID           string
	Name         string
	Local        bool
	KeyFound     bool
	KeySaved     bool
	KeyEnv       string
	DefaultModel string
}

type Setup struct {
	// Task is empty for the exposure check.
	Task Task
	// Log is the log of the triage, relative to the project folder. Empty means auth.log.
	Log string
	// Recording makes the run a replay: the answers come from the recording, and nothing is sent.
	Recording  *replay.Recording
	ProviderID string
	Model      string
	Key        string
	// Reasoning is empty for the provider's default.
	Reasoning string
}

// ReasoningChoice is one level for the user to pick. The first choice is always the default.
type ReasoningChoice struct {
	Value string
	Label string
}

// ReasoningChoices lists the documented levels for this model. It is empty when the model has none.
func ReasoningChoices(providerID, model string) []ReasoningChoice {
	var choices []ReasoningChoice
	for _, option := range outbound.ReasoningOptions(providerID, strings.TrimSpace(model)) {
		choices = append(choices, ReasoningChoice{Value: option.Value, Label: option.Label})
	}

	return choices
}

type Result struct {
	Report   string
	Complete bool
	SavedTo  string
}

func (config Config) lookup(name string) string {
	if config.LookupEnv != nil {
		return config.LookupEnv(name)
	}

	return os.Getenv(name)
}

func (config Config) now() time.Time {
	if config.Now != nil {
		return config.Now()
	}

	return time.Now()
}

func (config Config) factory() ProviderFactory {
	if config.NewProvider != nil {
		return config.NewProvider
	}

	return outbound.NewProvider
}

func (config Config) lister() ModelLister {
	if config.ListModels != nil {
		return config.ListModels
	}

	return outbound.ListModels
}

// Models asks the provider which models it offers. It sends the key and nothing else.
// An empty key means the key from the environment.
func (config Config) Models(ctx context.Context, providerID, apiKey string) ([]string, error) {
	chosen := config.choice(providerID)
	if chosen == nil {
		return nil, ErrUnknownProvider
	}

	key, err := config.resolveKey(ctx, chosen, apiKey)
	if err != nil {
		return nil, err
	}

	models, err := config.lister()(ctx, chosen.ID, key)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		if errors.Is(err, outbound.ErrAuth) {
			return nil, ErrKeyRejected
		}

		return nil, ErrModelList
	}

	return models, nil
}

// info describes a provider without asking the key store, which is slow.
func (config Config) info(info outbound.Info) Choice {
	return Choice{
		ID: info.ID, Name: info.Name, Local: info.Local, KeyEnv: info.KeyEnv, DefaultModel: info.DefaultModel,
		KeyFound: info.KeyEnv != "" && config.lookup(info.KeyEnv) != "",
	}
}

func (config Config) choice(providerID string) *Choice {
	for _, info := range outbound.Providers() {
		if info.ID == providerID {
			choice := config.info(info)
			return &choice
		}
	}

	return nil
}

// resolveKey picks the key: the one just typed, else the one in the environment, else the saved one.
func (config Config) resolveKey(ctx context.Context, chosen *Choice, typed string) (string, error) {
	if chosen.Local {
		return "", nil
	}

	if key := strings.TrimSpace(typed); key != "" {
		return key, nil
	}
	if key := strings.TrimSpace(config.lookup(chosen.KeyEnv)); key != "" {
		return key, nil
	}
	if config.Keys != nil {
		if key, err := config.Keys.Get(ctx, chosen.ID); err == nil && key != "" {
			return key, nil
		}
	}

	return "", ErrNeedsKey
}

// Providers lists the providers and says for each one whether its key is already in the environment
// or saved.
func (config Config) Providers() []Choice {
	var choices []Choice
	for _, info := range outbound.Providers() {
		choice := config.info(info)
		if !choice.Local && !choice.KeyFound && config.Keys != nil {
			_, err := config.Keys.Get(context.Background(), choice.ID)
			choice.KeySaved = err == nil
		}
		choices = append(choices, choice)
	}

	return choices
}

// KeysCanBeSaved says whether a key can be kept between runs on this system.
func (config Config) KeysCanBeSaved() bool {
	return config.Keys != nil && config.Keys.Available()
}

// SaveKey keeps a key for the next runs. The error texts are fixed and never hold the key.
func (config Config) SaveKey(ctx context.Context, providerID, key string) error {
	chosen := config.choice(providerID)
	if chosen == nil || chosen.Local {
		return ErrUnknownProvider
	}
	if !config.KeysCanBeSaved() {
		return ErrKeyStore
	}
	if config.Keys.Set(ctx, providerID, strings.TrimSpace(key)) != nil {
		return ErrKeyStore
	}

	return nil
}

// ForgetKey removes the saved key of a provider.
func (config Config) ForgetKey(ctx context.Context, providerID string) error {
	if config.choice(providerID) == nil {
		return ErrUnknownProvider
	}
	if !config.KeysCanBeSaved() || config.Keys.Delete(ctx, providerID) != nil {
		return ErrKeyStore
	}

	return nil
}

type Session struct {
	task         Task
	log          string
	logPath      string
	triage       triage.Config
	replay       *replay.Player
	recorder     *replay.Recorder
	providerName string
	model        string
	reasoning    string
	config       Config
	gateway      *gateway.Gateway
	sender       *outbound.Sender
	specs        []outbound.ToolSpec
	confirmed    bool
}

// Prepare builds everything except the run itself. It sends nothing and creates no file.
func Prepare(config Config, setup Setup) (*Session, error) {
	root, err := pathguard.NewRoot(config.Target)
	if err != nil {
		return nil, ErrTarget
	}

	task := setup.Task
	if task == "" {
		task = TaskExposure
	}
	if setup.Recording != nil {
		return prepareReplay(config, root, *setup.Recording, setup.Log)
	}
	if task != TaskExposure && task != TaskTriage {
		return nil, ErrUnknownTask
	}
	log, logPath, triageConfig, err := prepareTask(config, root, task, setup.Log, nil)
	if err != nil {
		return nil, err
	}

	resolved, err := ResolveProvider(context.Background(), config, setup)
	if err != nil {
		return nil, err
	}
	provider, model := resolved.Provider, resolved.Model
	// Every live run is recorded, so that it can be played back later without a network.
	recorder := replay.NewRecorder(provider, string(task), model, log)
	if task == TaskTriage {
		recorder.SetTriage(replay.Settings{WindowMinutes: int(triageConfig.Window.Minutes()), FailureThreshold: triageConfig.FailureThreshold,
			SprayThreshold: triageConfig.SprayThreshold, Year: triageConfig.Year, TimeZone: triageConfig.ZoneName})
	}
	sender, err := outbound.New(recorder, config.Target)
	if err != nil {
		return nil, ErrSetup
	}

	toolGateway := gateway.New(root, gateway.DefaultLimits)

	return &Session{task: task, log: log, logPath: logPath, triage: triageConfig, recorder: recorder, providerName: provider.Name(), model: model, reasoning: setup.Reasoning, config: config, gateway: toolGateway, sender: sender, specs: agent.SpecsFromGateway(toolGateway.Specs())}, nil
}

// prepareReplay builds a session that plays a recording back. It has no provider, no key and no model:
// the player answers, and it has no network code.
func prepareReplay(config Config, root *pathguard.Root, recording replay.Recording, logOverride string) (*Session, error) {
	player, err := replay.NewPlayer(recording)
	task := Task(recording.Task)
	if err != nil || (task != TaskExposure && task != TaskTriage) {
		return nil, ErrRecording
	}
	logName := recording.Log
	if logOverride != "" {
		logName = logOverride
	}
	log, logPath, triageConfig, err := prepareTask(config, root, task, logName, recording.Triage)
	if err != nil {
		return nil, err
	}
	sender, err := outbound.New(player, config.Target)
	if err != nil {
		return nil, ErrSetup
	}

	toolGateway := gateway.New(root, gateway.DefaultLimits)

	return &Session{task: task, log: log, logPath: logPath, triage: triageConfig, replay: player, providerName: player.Name(), model: recording.Model, config: config, gateway: toolGateway, sender: sender, specs: agent.SpecsFromGateway(toolGateway.Specs())}, nil
}

// prepareTask checks what the task needs. The exposure check needs nothing. The triage needs a log file
// inside the project folder, and its settings.
func prepareTask(config Config, root *pathguard.Root, task Task, logName string, recorded *replay.Settings) (log, logPath string, settings triage.Config, err error) {
	if task != TaskTriage {
		return "", "", triage.Config{}, nil
	}

	if logName == "" {
		logName = DefaultLog
	}
	if !logNamePattern.MatchString(logName) {
		return "", "", triage.Config{}, ErrLogFile
	}
	resolved, resolveErr := root.Resolve(logName)
	if resolveErr != nil {
		return "", "", triage.Config{}, ErrLogFile
	}
	if info, statErr := os.Lstat(resolved); statErr != nil || !info.Mode().IsRegular() {
		return "", "", triage.Config{}, ErrLogFile
	}

	// The settings of the user come first, then the ones in the recording, then the defaults.
	settings = triage.Defaults(config.now())
	switch {
	case config.Triage != nil:
		settings = *config.Triage
	case recorded != nil:
		fromRecording, recordingErr := TriageFromRecording(*recorded)
		if recordingErr != nil {
			return "", "", triage.Config{}, ErrLogFile
		}
		settings = fromRecording
	}
	if settings.Validate() != nil {
		return "", "", triage.Config{}, ErrLogFile
	}

	return logName, resolved, settings, nil
}

// TriageFromRecording turns the settings in a recording into the settings of a run.
func TriageFromRecording(recorded replay.Settings) (triage.Config, error) {
	location, err := time.LoadLocation(recorded.TimeZone)
	if err != nil {
		return triage.Config{}, ErrRecording
	}
	config := triage.Config{Window: time.Duration(recorded.WindowMinutes) * time.Minute, FailureThreshold: recorded.FailureThreshold,
		SprayThreshold: recorded.SprayThreshold, Year: recorded.Year, Location: location, ZoneName: recorded.TimeZone}

	return config, config.Validate()
}

// ValidLogName says whether a name can be the log of the triage.
func ValidLogName(name string) bool {
	return logNamePattern.MatchString(name)
}

// CheckTask says whether a task has what it needs in the project folder. The exposure check needs nothing.
func (config Config) CheckTask(task Task, logName string) error {
	root, err := pathguard.NewRoot(config.Target)
	if err != nil {
		return ErrTarget
	}
	_, _, _, err = prepareTask(config, root, task, logName, nil)

	return err
}

// Label is shown on the screen and in the report when the run is a replay. It is empty for a live run.
func (session *Session) Label() string {
	if session.replay == nil {
		return ""
	}
	if session.replay.Source() == replay.SourceScripted {
		return "REPLAY (scripted answers)"
	}

	return "REPLAY"
}

// Budget is the most requests and tokens that the run may use.
func (session *Session) Budget() (requests, tokens int) {
	return session.config.Limits.MaxSteps, session.config.Limits.MaxTokens
}

// Title names the task for the screen.
func (session *Session) Title() string {
	if session.task == TaskTriage {
		return "Task B: Log triage"
	}

	return "Task A: Exposure check"
}

func (session *Session) instruction() string {
	if session.task == TaskTriage {
		return triage.Instruction(session.log, session.triage)
	}

	return exposure.Instruction
}

// ConsentText is what the user confirms. It is made from the same provider name that the sender uses.
func (session *Session) ConsentText() string {
	if session.replay != nil {
		return "This is a " + session.Label() + ". Recorded answers are played back through the real guard. Nothing is sent to any provider."
	}

	return session.sender.ConsentText()
}

// Preview is the dry run: the first request exactly as it would be sent, after cleaning.
// It sends nothing.
func (session *Session) Preview() (string, error) {
	cleaned, err := session.sender.Preview(agent.FirstRequest(session.instruction(), session.specs))
	if err != nil {
		return "", err
	}

	var preview strings.Builder
	if session.replay != nil {
		fmt.Fprintf(&preview, "%s. This is the first request. It is checked against the recording, and nothing is sent.\n", session.Label())
	} else {
		fmt.Fprintf(&preview, "This is the first request, as it would be sent.\n")
	}
	fmt.Fprintf(&preview, "Limits for this run: up to %d requests and %d tokens.\n", session.config.Limits.MaxSteps, session.config.Limits.MaxTokens)
	if session.replay == nil {
		fmt.Fprintf(&preview, "Model: %s\n", session.model)
	}
	if session.reasoning != "" {
		fmt.Fprintf(&preview, "Reasoning level: %s\n", session.reasoning)
	}
	fmt.Fprintf(&preview, "Later requests also hold the files that the AI chooses to read. They are cleaned the same way, and every request is saved in the event log.\n\n")
	fmt.Fprintf(&preview, "System prompt:\n%s\n\n", cleaned.System)
	for _, message := range cleaned.Messages {
		fmt.Fprintf(&preview, "Message (%s):\n%s\n\n", message.Role, message.Text)
	}
	fmt.Fprintf(&preview, "Tools the AI may call (all read-only):\n")
	for _, spec := range cleaned.Tools {
		fmt.Fprintf(&preview, "- %s: %s\n", spec.Name, spec.Description)
	}

	return preview.String(), nil
}

// Summary is the short form of the dry run: what is chosen, the limits, and the instruction.
// The fixed system prompt and the tool list are left out. Preview has them.
func (session *Session) Summary() (string, error) {
	cleaned, err := session.sender.Preview(agent.FirstRequest(session.instruction(), session.specs))
	if err != nil {
		return "", err
	}

	var summary strings.Builder
	if session.replay != nil {
		fmt.Fprintf(&summary, "Mode: %s. The answers come from a recording. Nothing is sent.\n", session.Label())
		if session.model != "" {
			fmt.Fprintf(&summary, "Recorded with the model: %s\n", session.model)
		}
	} else {
		fmt.Fprintf(&summary, "Provider: %s\n", session.providerName)
		fmt.Fprintf(&summary, "Model: %s\n", session.model)
	}
	if session.reasoning != "" {
		fmt.Fprintf(&summary, "Reasoning level: %s\n", session.reasoning)
	}
	if session.task == TaskTriage {
		fmt.Fprintf(&summary, "Log: %s (read by Omamori too, to check every claim of the AI)\n", session.log)
		fmt.Fprintf(&summary, "Settings: window %d minutes, failure threshold %d, spray threshold %d, year %d, time zone %s\n",
			int(session.triage.Window.Minutes()), session.triage.FailureThreshold, session.triage.SprayThreshold, session.triage.Year, session.triage.ZoneName)
	}
	fmt.Fprintf(&summary, "Limits for this run: up to %d requests and %d tokens.\n\n", session.config.Limits.MaxSteps, session.config.Limits.MaxTokens)
	fmt.Fprintf(&summary, "The first request holds only the instruction below, a fixed system prompt, and a list of %d read-only tools. It holds no file content.\n", len(cleaned.Tools))
	fmt.Fprintf(&summary, "Later requests also hold the files that the AI chooses to read. They are cleaned the same way, and every request is saved in the event log.\n")
	for _, message := range cleaned.Messages {
		fmt.Fprintf(&summary, "\nInstruction (%s):\n%s\n", message.Role, message.Text)
	}

	return summary.String(), nil
}

func (session *Session) Confirm() {
	session.sender.Authorize()
	session.confirmed = true
}

type stepRecorder struct {
	log  *eventlog.Log
	step func(string)
}

func (recorder *stepRecorder) Record(kind, tool string, allowed bool, reason, note string) error {
	if err := recorder.log.Record(kind, tool, allowed, reason, note); err != nil {
		return err
	}

	switch kind {
	case "run_start":
		recorder.step("run started")
	case "provider_response":
		recorder.step("answer received (" + note + ")")
	case "run_end":
		if note != "" {
			reason += " (" + note + ")"
		}
		recorder.step("run finished: " + reason)
	}

	return nil
}

// Run does the task. The report and the event log go to a new folder, and nothing is overwritten.
func (session *Session) Run(ctx context.Context, step func(string)) (Result, error) {
	if !session.confirmed {
		return Result{}, ErrNotConfirmed
	}

	prefix := "run-"
	if session.replay != nil {
		prefix = "replay-"
	}
	directory := filepath.Join(session.config.OutputBase, prefix+session.config.now().UTC().Format("20060102-150405"))
	writer, err := reportwriter.New(session.config.Target, directory)
	if err != nil {
		return Result{}, ErrOutput
	}
	appender, err := writer.Open("events.jsonl")
	if err != nil {
		return Result{}, ErrOutput
	}
	log := eventlog.New(appender, session.config.now)
	defer log.Close()

	session.gateway.Observe(func(event gateway.Event) error {
		if event.Allowed {
			step("tool " + event.Tool + ": ok")
		} else if event.Tool != "" {
			step("tool " + event.Tool + ": refused (" + event.Reason + ")")
		} else {
			step("a tool call was refused (" + event.Reason + ")")
		}

		return log.RecordGatewayEvent(event)
	})

	requests := 0
	session.sender.Observe(func(request outbound.Request) error {
		requests++
		step(fmt.Sprintf("sending request %d to %s", requests, session.providerName))

		return log.Record("provider_request", "", true, "sent", describeRequest(request, requests))
	})

	var tools agent.Tools = session.gateway
	var collector *exposure.Collector
	if session.task == TaskExposure {
		collector = exposure.NewCollector(session.gateway)
		collector.SetHistory(githistory.New(session.config.Target))
		tools = collector
	}
	runner, err := agent.New(session.sender, tools, &stepRecorder{log: log, step: step}, session.config.Limits, session.specs)
	if err != nil {
		return Result{}, ErrSetup
	}

	var report string
	var outcome agent.Outcome
	if session.task == TaskTriage {
		report, outcome, err = triage.Run(ctx, runner, triage.Source{Path: session.logPath, Name: session.log}, session.triage)
	} else {
		report, outcome, err = exposure.Run(ctx, runner, collector)
	}
	if err != nil {
		return Result{}, err
	}
	if label := session.Label(); label != "" {
		report = "**" + label + ": recorded answers were played back. Nothing was sent.**\n\n" + report
	}
	if err := writer.Write("report.md", report); err != nil {
		return Result{}, ErrOutput
	}
	if err := writer.Write("report.html", htmlreport.Render(report)); err != nil {
		return Result{}, ErrOutput
	}
	step("report saved")
	if session.recorder != nil {
		if recorded := session.recorder.Recording(); len(recorded.Steps) > 0 {
			text, err := recorded.JSON()
			if err != nil || writer.Write("recording.json", text) != nil {
				return Result{}, ErrOutput
			}
			step("recording saved")
		}
	}

	return Result{Report: report, Complete: outcome.Status == agent.Complete, SavedTo: directory}, nil
}

// describeRequest is the log entry for one request. It holds the newest turn, because the
// earlier turns were logged with the earlier requests.
func describeRequest(request outbound.Request, attempt int) string {
	start := 0
	for index, message := range request.Messages {
		if message.Role == "assistant" {
			start = index
		}
	}

	var newest strings.Builder
	for _, message := range request.Messages[start:] {
		fmt.Fprintf(&newest, " [%s] %s", message.Role, truncate(message.Text, maxLoggedTextRunes))
		for _, call := range message.ToolCalls {
			fmt.Fprintf(&newest, " (calls %s)", call.Name)
		}
	}

	return fmt.Sprintf("request %d: %d messages, %d tools. Newest turn:%s", attempt, len(request.Messages), len(request.Tools), truncate(newest.String(), maxLoggedRunes))
}

func truncate(text string, limit int) string {
	if utf8.RuneCountInString(text) <= limit {
		return text
	}

	return string([]rune(text)[:limit]) + "…"
}
