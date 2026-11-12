package main

import (
	"context"
	"errors"
	"time"

	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

const keyActionWait = 15 * time.Second

type backend struct {
	config taskrun.Config
	env    environment
	settingsPath string
	log string
	// recording is what a replay plays back. Without it, there is no replay.
	recording *replay.Recording
}

var errNoRecording = errors.New("there is no recording to replay")

func (backend backend) TaskReady(task string) error {
	if task != tui.TaskTriage {
		return nil
	}

	log := backend.log
	if log == "" {
		log = taskrun.DefaultLog
	}
	if backend.config.CheckTask(taskrun.TaskTriage, log) != nil {
		return errors.New("Task B needs the log file " + log + " in the target folder. Start Omamori with the log: omamori triage <log file>")
	}

	return nil
}

func (backend backend) Providers() []tui.Choice {
	var choices []tui.Choice
	for _, choice := range backend.config.Providers() {
		choices = append(choices, tui.Choice{
			ID: choice.ID, Name: choice.Name, Local: choice.Local, KeyFound: choice.KeyFound, KeySaved: choice.KeySaved, KeyEnv: choice.KeyEnv, DefaultModel: choice.DefaultModel,
		})
	}

	return choices
}

func (backend backend) Models(ctx context.Context, providerID, key string) ([]string, error) {
	models, err := backend.config.Models(ctx, providerID, key)
	if errors.Is(err, taskrun.ErrKeyRejected) {
		return nil, tui.ErrKeyRejected
	}

	return models, err
}

func (backend backend) KeysCanBeSaved() bool { return backend.config.KeysCanBeSaved() }

func (backend backend) SaveKey(ctx context.Context, providerID, key string) error {
	return backend.config.SaveKey(ctx, providerID, key)
}

func (backend backend) ForgetKey(providerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyActionWait)
	defer cancel()

	return backend.config.ForgetKey(ctx, providerID)
}

func (backend backend) SaveSettings(defaults tui.Defaults) error {
	if backend.settingsPath == "" {
		return appconfig.ErrWrite
	}

	return appconfig.Save(backend.settingsPath, appconfig.Settings{Provider: defaults.ProviderID, Model: defaults.Model, Reasoning: defaults.Reasoning})
}

func (backend backend) ReasoningChoices(providerID, model string) []tui.ReasoningChoice {
	var choices []tui.ReasoningChoice
	for _, choice := range taskrun.ReasoningChoices(providerID, model) {
		choices = append(choices, tui.ReasoningChoice{Value: choice.Value, Label: choice.Label})
	}

	return choices
}

func (backend backend) Prepare(setup tui.Setup) (tui.Plan, error) {
	switch setup.Task {
	case tui.TaskDetect, tui.TaskAnalyze, tui.TaskForensics, tui.TaskForensicsAnalyze, tui.TaskStored, tui.TaskDemo, tui.TaskDashboard:
		return backend.prepareHome(setup)
	}
	prepared := taskrun.Setup{ProviderID: setup.ProviderID, Model: setup.Model, Key: setup.Key, Reasoning: setup.Reasoning, Log: backend.log}
	if setup.Task == tui.TaskTriage {
		prepared.Task = taskrun.TaskTriage
	}
	if setup.Replay {
		if backend.recording == nil {
			return tui.Plan{}, errNoRecording
		}
		prepared.Recording = backend.recording
	}

	session, err := taskrun.Prepare(backend.config, prepared)
	if err != nil {
		return tui.Plan{}, err
	}

	preview, err := session.Preview()
	if err != nil {
		return tui.Plan{}, taskrun.ErrSetup
	}

	summary, err := session.Summary()
	if err != nil {
		return tui.Plan{}, taskrun.ErrSetup
	}

	maxRequests, maxTokens := session.Budget()

	return tui.Plan{
		Title:       session.Title(),
		Label:       session.Label(),
		ConsentText: session.ConsentText(),
		Summary:     summary,
		Preview:     preview,
		MaxRequests: maxRequests,
		MaxTokens:   maxTokens,
		Confirm:     session.Confirm,
		Run: func(ctx context.Context, step func(string)) (tui.Result, error) {
			result, err := session.Run(ctx, step)

			return tui.Result{Report: result.Report, Complete: result.Complete, SavedTo: result.SavedTo}, err
		},
	}, nil
}
