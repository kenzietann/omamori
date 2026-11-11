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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/eventlog"
	"github.com/kenzietann/omamori/internal/exposure"
	"github.com/kenzietann/omamori/internal/gateway"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/reportwriter"
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
	ErrModelList       = errors.New("the list of models could not be loaded")
	ErrNotConfirmed    = errors.New("the user has not confirmed the run")
	ErrOutput          = errors.New("the output folder cannot be used: it must be outside the project and new files must be possible")
)

type ProviderFactory func(id, apiKey, model string) (outbound.Provider, error)

type ModelLister func(ctx context.Context, id, apiKey string) ([]string, error)

type Config struct {
	Target     string
	OutputBase string
	Limits     agent.Limits
	// LookupEnv, Now, NewProvider and ListModels default to the real ones. Tests replace them.
	LookupEnv   func(string) string
	Now         func() time.Time
	NewProvider ProviderFactory
	ListModels  ModelLister
}

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
	var chosen *Choice
	for _, choice := range config.Providers() {
		if choice.ID == providerID {
			chosen = &choice
			break
		}
	}
	if chosen == nil {
		return nil, ErrUnknownProvider
	}

	key := ""
	if !chosen.Local {
		if key = strings.TrimSpace(apiKey); key == "" {
			key = strings.TrimSpace(config.lookup(chosen.KeyEnv))
		}
		if key == "" {
			return nil, ErrNeedsKey
		}
	}

	models, err := config.lister()(ctx, chosen.ID, key)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}

		return nil, ErrModelList
	}

	return models, nil
}

// Providers lists the providers and says for each one whether its key is already in the environment.
func (config Config) Providers() []Choice {
	var choices []Choice
	for _, info := range outbound.Providers() {
		choices = append(choices, Choice{
			ID: info.ID, Name: info.Name, Local: info.Local, KeyEnv: info.KeyEnv, DefaultModel: info.DefaultModel,
			KeyFound: info.KeyEnv != "" && config.lookup(info.KeyEnv) != "",
		})
	}

	return choices
}

type Session struct {
	providerName string
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

	var chosen *Choice
	for _, choice := range config.Providers() {
		if choice.ID == setup.ProviderID {
			chosen = &choice
			break
		}
	}
	if chosen == nil {
		return nil, ErrUnknownProvider
	}

	model := strings.TrimSpace(setup.Model)
	if model == "" {
		model = chosen.DefaultModel
	}
	if model == "" {
		return nil, ErrNeedsModel
	}

	key := ""
	if !chosen.Local {
		if key = strings.TrimSpace(setup.Key); key == "" {
			key = strings.TrimSpace(config.lookup(chosen.KeyEnv))
		}
		if key == "" {
			return nil, ErrNeedsKey
		}
	}

	provider, err := config.factory()(chosen.ID, key, model)
	if err != nil {
		return nil, ErrSetup
	}
	sender, err := outbound.New(provider, config.Target)
	if err != nil {
		return nil, ErrSetup
	}

	toolGateway := gateway.New(root, gateway.DefaultLimits)

	return &Session{providerName: provider.Name(), config: config, gateway: toolGateway, sender: sender, specs: agent.SpecsFromGateway(toolGateway.Specs())}, nil
}

// ConsentText is what the user confirms. It is made from the same provider name that the sender uses.
func (session *Session) ConsentText() string {
	return session.sender.ConsentText()
}

// Preview is the dry run: the first request exactly as it would be sent, after cleaning.
// It sends nothing.
func (session *Session) Preview() (string, error) {
	cleaned, err := session.sender.Preview(agent.FirstRequest(exposure.Instruction, session.specs))
	if err != nil {
		return "", err
	}

	var preview strings.Builder
	fmt.Fprintf(&preview, "This is the first request, as it would be sent.\n")
	fmt.Fprintf(&preview, "Limits for this run: up to %d requests and %d tokens.\n", session.config.Limits.MaxSteps, session.config.Limits.MaxTokens)
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
		recorder.step("run finished: " + reason)
	}

	return nil
}

// Run does the task. The report and the event log go to a new folder, and nothing is overwritten.
func (session *Session) Run(ctx context.Context, step func(string)) (Result, error) {
	if !session.confirmed {
		return Result{}, ErrNotConfirmed
	}

	directory := filepath.Join(session.config.OutputBase, "run-"+session.config.now().UTC().Format("20060102-150405"))
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

	collector := exposure.NewCollector(session.gateway)
	runner, err := agent.New(session.sender, collector, &stepRecorder{log: log, step: step}, session.config.Limits, session.specs)
	if err != nil {
		return Result{}, ErrSetup
	}

	report, outcome, err := exposure.Run(ctx, runner, collector)
	if err != nil {
		return Result{}, err
	}
	if err := writer.Write("report.md", report); err != nil {
		return Result{}, ErrOutput
	}
	step("report saved")

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
