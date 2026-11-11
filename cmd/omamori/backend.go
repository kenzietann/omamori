package main

import (
	"context"
	"errors"
	"time"

	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

const keyActionWait = 15 * time.Second

// backend connects the screen to the core. It only converts types and holds no rules.
type backend struct {
	// copyText puts text on the clipboard. Empty means the default for this system.
	copyText func(text string) error
	config   taskrun.Config
	// settingsPath is where the choices are kept. Empty means that they are not kept.
	settingsPath string
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
	session, err := taskrun.Prepare(backend.config, taskrun.Setup{ProviderID: setup.ProviderID, Model: setup.Model, Key: setup.Key, Reasoning: setup.Reasoning})
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

	return tui.Plan{
		ConsentText: session.ConsentText(),
		Summary:     summary,
		Preview:     preview,
		Confirm:     session.Confirm,
		Run: func(ctx context.Context, step func(string)) (tui.Result, error) {
			result, err := session.Run(ctx, step)

			return tui.Result{Report: result.Report, Complete: result.Complete, SavedTo: result.SavedTo}, err
		},
	}, nil
}
