package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/assets"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/indicators"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/ruledraft"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const usageRule = `usage: omamori rule draft --goal text --example ref [--example ref]... [--title text] [--level informational|low|medium|high|critical]
       [--benign log]... [--attempts n] [--yes | --dry-run | --replay recording.json] [--provider id] [--model name] [--reasoning level]
       [--timeout duration] [--max-tokens n] [--assets file] [--indicators file] [--format name] [--year n] [--timezone name]
       [--output folder] <log file or folder>...`

type repeated []string

func (list *repeated) String() string { return strings.Join(*list, ",") }
func (list *repeated) Set(value string) error {
	*list = append(*list, value)
	return nil
}

func runRule(args []string, env environment) int {
	if len(args) == 0 || args[0] != "draft" {
		fmt.Fprintln(env.stderr, usageRule)
		return exitUsage
	}
	lookup := env.lookupEnv
	if lookup == nil {
		lookup = func(string) string { return "" }
	}
	flags := flag.NewFlagSet("rule draft", flag.ContinueOnError)
	var chosen settings
	var examples, benign repeated
	var goal, title, level, format, recordingPath, reasoning, assetsPath, indicatorsPath string
	var confirmed, dryRun bool
	var attempts, maxTokens int
	var timeout time.Duration
	flags.StringVar(&goal, "goal", "", "what the rule is for, in your words")
	flags.Var(&examples, "example", "an event that the rule must match, as in a report, for example web01/auth.log:68")
	flags.StringVar(&title, "title", "", "title of the rule (default: the goal)")
	flags.StringVar(&level, "level", "medium", "level of the rule")
	flags.Var(&benign, "benign", "a log file or folder that you know to be clean")
	flags.IntVar(&attempts, "attempts", 3, "how many answers the AI may give")
	flags.IntVar(&maxTokens, "max-tokens", 300000, "limit of tokens in one run")
	flags.StringVar(&chosen.provider, "provider", lookup("OMAMORI_PROVIDER"), "AI provider")
	flags.StringVar(&chosen.model, "model", lookup("OMAMORI_MODEL"), "model name")
	flags.StringVar(&reasoning, "reasoning", "", "reasoning level")
	flags.StringVar(&format, "format", "", "syslog, web, json, suricata, zeek, wazuh or windows")
	flags.IntVar(&chosen.year, "year", 0, "year of classic syslog lines")
	flags.StringVar(&chosen.zone, "timezone", "", "time zone of classic syslog lines")
	flags.StringVar(&assetsPath, "assets", "", "asset list")
	flags.StringVar(&indicatorsPath, "indicators", "", "indicator list")
	flags.StringVar(&chosen.output, "output", "", "folder for reports")
	flags.StringVar(&recordingPath, "replay", "", "replay recorded answers offline")
	flags.BoolVar(&confirmed, "yes", false, "send the sanitized events to the selected provider")
	flags.BoolVar(&dryRun, "dry-run", false, "show the guarded request without sending or writing")
	flags.DurationVar(&timeout, "timeout", 3*time.Minute, "maximum time for this run")
	paths, err := splitFlags(flags, args[1:])
	if err != nil || len(paths) == 0 || confirmed && dryRun || dryRun && recordingPath != "" || timeout <= 0 || maxTokens < 1 ||
		strings.TrimSpace(goal) == "" || len(examples) == 0 {
		fmt.Fprintln(env.stderr, usageRule)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	if err := chosen.chooseOutput(env.home); err != nil {
		return fail(err)
	}
	location, err := zone(chosen.zone)
	if err != nil {
		return fail(err)
	}
	now := env.clock()
	if chosen.year == 0 {
		chosen.year = now.In(location).Year()
	}
	options := intake.Options{Year: chosen.year, Location: location, Format: format}
	if assetsPath != "" {
		if options.Assets, err = assets.Load(assetsPath); err != nil {
			return fail(err)
		}
	}
	if indicatorsPath != "" {
		if options.Indicators, err = indicators.Load(indicatorsPath); err != nil {
			return fail(err)
		}
	}
	var sources []string
	for _, path := range append(append([]string(nil), paths...), benign...) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fail(errors.New("a log path is not usable"))
		}
		sources = append(sources, absolute)
	}
	read, err := intake.Read(paths, options)
	if err != nil {
		return fail(err)
	}
	if len(read.Events) == 0 {
		return fail(errors.New("no event could be read from the logs. Give the format with --format"))
	}
	var clean []event.Event
	if len(benign) > 0 {
		readClean, err := intake.Read(benign, options)
		if err != nil {
			return fail(err)
		}
		clean = readClean.Events
	}

	setup, err := aiSetup(env, flags, chosen, reasoning, recordingPath)
	if err != nil {
		return fail(err)
	}
	if recordingPath == "" && !knownProvider(setup.ProviderID) {
		fmt.Fprintln(env.stderr, "omamori: choose a known provider with --provider. Run omamori providers to see them.")
		return exitUsage
	}
	target := sources[0]
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		target = filepath.Dir(target)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	config := ruledraft.Config{
		Provider: taskrun.Config{Target: target, OutputBase: chosen.output, Limits: agent.Limits{MaxTokens: maxTokens}, LookupEnv: lookup,
			Keys: env.keys, Now: env.now, NewProvider: env.newProvider},
		Sources:  sources,
		Attempts: attempts,
	}
	input := ruledraft.Input{Goal: goal, Title: title, Level: level, Events: read.Events, Examples: examples, Benign: clean, Now: now}
	session, err := ruledraft.NewSession(ctx, config, input, setup)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "Read %d events from %d files for a rule from %d examples.\n%s\n", len(read.Events), len(read.Files), len(examples), session.ConsentText())
	if dryRun || recordingPath == "" && !confirmed {
		preview, err := session.Preview()
		if err != nil {
			return fail(err)
		}
		encoded, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return fail(errors.New("the request preview could not be written"))
		}
		fmt.Fprintf(env.stdout, "\nGuarded request preview:\n%s\n\nNothing was sent and nothing was written. Add --yes to ask the AI, or --replay to use a recording offline.\n", encoded)
		return exitOK
	}

	session.Confirm()
	result, err := session.Run(ctx, func(message string) { fmt.Fprintln(env.stdout, message) })
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "Report: %s\n", filepath.Join(result.SavedTo, "report.html"))
	if !result.Accepted {
		fmt.Fprintln(env.stderr, "omamori: no rule was accepted:", result.Reason)
		return exitFailed
	}
	fmt.Fprintf(env.stdout, "Rule: %s\nRead the report before you use it. Accepted means it passed Omamori's checks, not that it is quiet on your network.\n", result.RuleFile)
	return exitOK
}
