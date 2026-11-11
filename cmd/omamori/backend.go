package main

import (
	"context"

	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

// backend connects the screen to the core. It only converts types and holds no rules.
type backend struct {
	config taskrun.Config
}

func (backend backend) Providers() []tui.Choice {
	var choices []tui.Choice
	for _, choice := range backend.config.Providers() {
		choices = append(choices, tui.Choice{
			ID: choice.ID, Name: choice.Name, Local: choice.Local, KeyFound: choice.KeyFound, KeyEnv: choice.KeyEnv, DefaultModel: choice.DefaultModel,
		})
	}

	return choices
}

func (backend backend) Models(ctx context.Context, providerID, key string) ([]string, error) {
	return backend.config.Models(ctx, providerID, key)
}

func (backend backend) Prepare(setup tui.Setup) (tui.Plan, error) {
	session, err := taskrun.Prepare(backend.config, taskrun.Setup{ProviderID: setup.ProviderID, Model: setup.Model, Key: setup.Key})
	if err != nil {
		return tui.Plan{}, err
	}

	preview, err := session.Preview()
	if err != nil {
		return tui.Plan{}, taskrun.ErrSetup
	}

	return tui.Plan{
		ConsentText: session.ConsentText(),
		Preview:     preview,
		Confirm:     session.Confirm,
		Run: func(ctx context.Context, step func(string)) (tui.Result, error) {
			result, err := session.Run(ctx, step)

			return tui.Result{Report: result.Report, Complete: result.Complete, SavedTo: result.SavedTo}, err
		},
	}, nil
}
