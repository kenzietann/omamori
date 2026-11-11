package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

// version is set when building: go build -ldflags "-X main.version=v1.0.0"
var version = "dev"

const (
	exitOK      = 0
	exitFailed  = 1
	exitUsage   = 2
	modelsWait  = 30 * time.Second
	helpMessage = `Omamori is an AI helper for blue team work, with a guard around it.

Usage:
  omamori <command> [flags] [arguments]

Commands:
  check <folder>      Task A: check a project for leaked data (opens the screen)
  ui <folder>         open the home screen, where you choose a task
  providers           list the AI providers and say whether their key is set
  models <provider>   list the models that a provider offers for your key
  version             print the version
  help                print this help

Flags for check and ui:
  --provider id       AI provider (or set OMAMORI_PROVIDER)
  --model name        model name (or set OMAMORI_MODEL)
  --output folder     where reports are saved (default ~/omamori-output)
  --max-steps n       limit of requests in one run (default 15)
  --max-tokens n      limit of tokens in one run (default 300000)

API keys are never read from the command line. Set the key of your provider in the
environment (for example ANTHROPIC_API_KEY) or type it in the screen. It is not saved.
`
)

type environment struct {
	stdout, stderr io.Writer
	lookupEnv      func(string) string
	home           func() (string, error)
	openScreen     func(tui.Model) error
	// listModels replaces the real request in tests.
	listModels taskrun.ModelLister
}

func run(args []string, env environment) int {
	if len(args) == 0 {
		fmt.Fprint(env.stdout, helpMessage)
		return exitOK
	}

	command, rest := args[0], args[1:]
	switch command {
	case "help", "-h", "--help":
		fmt.Fprint(env.stdout, helpMessage)
		return exitOK
	case "version", "-v", "--version":
		fmt.Fprintln(env.stdout, "omamori", version)
		return exitOK
	case "providers":
		return runProviders(rest, env)
	case "models":
		return runModels(rest, env)
	case "check", "ui":
		return runScreen(command, rest, env)
	}

	fmt.Fprintf(env.stderr, "omamori: %q is not a command. Run omamori help to see the commands.\n", command)

	return exitUsage
}

func runProviders(args []string, env environment) int {
	if len(args) != 0 {
		fmt.Fprintln(env.stderr, "usage: omamori providers")
		return exitUsage
	}

	table := tabwriter.NewWriter(env.stdout, 0, 4, 3, ' ', 0)
	fmt.Fprintln(table, "ID\tNAME\tKEY")
	for _, choice := range (taskrun.Config{LookupEnv: env.lookupEnv}).Providers() {
		status := "no key needed"
		switch {
		case choice.Local:
		case choice.KeyFound:
			status = choice.KeyEnv + " is set"
		default:
			status = choice.KeyEnv + " is not set"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\n", choice.ID, choice.Name, status)
	}
	table.Flush()

	return exitOK
}

func runModels(args []string, env environment) int {
	if len(args) != 1 {
		fmt.Fprintln(env.stderr, "usage: omamori models <provider>")
		return exitUsage
	}

	config := taskrun.Config{LookupEnv: env.lookupEnv, ListModels: env.listModels}
	ctx, cancel := context.WithTimeout(context.Background(), modelsWait)
	defer cancel()

	models, err := config.Models(ctx, args[0], "")
	switch {
	case errors.Is(err, taskrun.ErrUnknownProvider):
		fmt.Fprintf(env.stderr, "omamori: the provider %q is not known. Run omamori providers to see them.\n", args[0])
		return exitUsage
	case errors.Is(err, taskrun.ErrNeedsKey):
		fmt.Fprintf(env.stderr, "omamori: no key found. Set %s and run the command again.\n", keyName(config, args[0]))
		return exitFailed
	case err != nil:
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}

	for _, model := range models {
		fmt.Fprintln(env.stdout, model)
	}

	return exitOK
}

func keyName(config taskrun.Config, providerID string) string {
	for _, choice := range config.Providers() {
		if choice.ID == providerID {
			return choice.KeyEnv
		}
	}

	return "the key of the provider"
}

func runScreen(command string, args []string, env environment) int {
	chosen, err := parseSettings(args, env.lookupEnv, env.home)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		if err == errUsage {
			return exitUsage
		}

		return exitFailed
	}

	config := taskrun.Config{
		Target:     chosen.target,
		OutputBase: chosen.output,
		Limits:     agent.Limits{MaxSteps: chosen.maxSteps, MaxTokens: chosen.maxTokens},
		LookupEnv:  env.lookupEnv,
		ListModels: env.listModels,
	}
	model := tui.New(chosen.target, backend{config: config}, tui.Defaults{ProviderID: chosen.provider, Model: chosen.model})
	if command == "check" {
		model = model.WithTaskA()
	}

	if err := env.openScreen(model); err != nil {
		fmt.Fprintln(env.stderr, "omamori: the screen stopped:", err)
		return exitFailed
	}

	return exitOK
}
