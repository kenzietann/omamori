package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/livetest"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const (
	usageEval          = "usage: omamori eval --yes [--runs n] [--token-cap n] [--fixtures folder] [--provider id] [--model name] [--output folder] [--max-steps n] [--max-tokens n]"
	defaultEvalRuns    = 3
	defaultEvalTokens  = 600000
	defaultFixturePath = "testdata/fixtures"
)

// runEval is the bounded live test (FR-19). It sends sanitized fixture content to the provider, so it
// does nothing until the user agrees with --yes. The token cap stops the series.
func runEval(args []string, env environment) int {
	flags := flag.NewFlagSet("omamori eval", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	agreed := flags.Bool("yes", false, "agree to send the sanitized fixtures to the provider")
	runs := flags.Int("runs", defaultEvalRuns, "runs for each case")
	tokenCap := flags.Int("token-cap", defaultEvalTokens, "most tokens for the whole series")
	fixtures := flags.String("fixtures", defaultFixturePath, "folder of the fixtures")
	provider := flags.String("provider", env.lookupEnv("OMAMORI_PROVIDER"), "provider id")
	model := flags.String("model", env.lookupEnv("OMAMORI_MODEL"), "model name")
	output := flags.String("output", "", "folder for the results")
	maxSteps := flags.Int("max-steps", defaultMaxSteps, "limit of requests in one run")
	maxTokens := flags.Int("max-tokens", defaultMaxTokens, "limit of tokens in one run")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(env.stderr, "omamori:", usageEval)
		return exitUsage
	}
	if *runs < 1 || *tokenCap < 1 || *maxSteps < 1 || *maxTokens < 1 {
		fmt.Fprintln(env.stderr, "omamori: the numbers must be whole numbers above 0")
		return exitUsage
	}

	if *provider == "" && env.settingsPath != nil {
		if path, err := env.settingsPath(); err == nil {
			saved, _ := appconfig.Load(path)
			*provider = saved.Provider
			if *model == "" {
				*model = saved.Model
			}
		}
	}
	if *provider == "" || !knownProvider(*provider) {
		fmt.Fprintln(env.stderr, "omamori: choose a known provider with --provider. Run omamori providers to see them.")
		return exitUsage
	}

	base := &settings{output: *output}
	if err := base.chooseOutput(env.home); err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}

	cases, _, err := livetest.Cases(mustAbs(*fixtures))
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	total := len(cases) * *runs
	fmt.Fprintf(env.stdout, "Live test: %d cases, %d runs each, %d runs in all.\nProvider: %s. Model: %s.\nCost cap: %d tokens for the whole series (up to %d requests and %d tokens in one run).\nWhat is sent: the fake fixtures, cleaned by the guard. No real data.\n\n",
		len(cases), *runs, total, *provider, modelText(*model), *tokenCap, *maxSteps, *maxTokens)
	if !*agreed {
		fmt.Fprintln(env.stderr, "omamori: nothing was sent. Add --yes to agree.")
		return exitUsage
	}

	now := time.Now()
	series := filepath.Join(base.output, "live-"+now.UTC().Format("20060102-150405"))
	summary, err := livetest.Run(context.Background(), livetest.Options{
		Config: taskrun.Config{
			Limits:      agent.Limits{MaxSteps: *maxSteps, MaxTokens: *maxTokens},
			LookupEnv:   env.lookupEnv,
			ListModels:  env.listModels,
			Keys:        env.keys,
			Now:         env.now,
			NewProvider: env.newProvider,
		},
		ProviderID: *provider,
		Model:      *model,
		Fixtures:   *fixtures,
		Runs:       *runs,
		TokenCap:   *tokenCap,
		OutputBase: series,
		Progress:   func(line string) { fmt.Fprintln(env.stdout, line) },
	})
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}

	text := summary.Markdown(now)
	path, err := livetest.WriteResults(series, text, now)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	fmt.Fprintf(env.stdout, "\n%s\nSaved to: %s\n", text, path)

	return exitOK
}

func modelText(model string) string {
	if model == "" {
		return "the default of the provider"
	}

	return model
}

func mustAbs(path string) string {
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}

	return path
}
