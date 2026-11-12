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
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const usageAnalyze = "usage: omamori analyze [--yes | --dry-run | --replay recording.json] [--provider id] [--model name] [--reasoning level] [--rules folder] [--format syslog|web|json|suricata|zeek|wazuh|windows] [--year n] [--timezone name] [--output folder] [--store] [--db SQLite-file] <log file or folder>..."

// runAnalyze is the terminal adapter for the shared analysis service. The future local dashboard
// can use the same Prepare/Preview/Confirm/Run lifecycle without invoking this command or a TUI.
func runAnalyze(args []string, env environment) int {
	lookup := env.lookupEnv
	if lookup == nil {
		lookup = func(string) string { return "" }
	}
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	var chosen settings
	var database storageFlags
	database.bind(flags, true)
	var rulesFolder, format, recordingPath, reasoning string
	var confirmed, dryRun bool
	var timeout time.Duration
	flags.StringVar(&chosen.provider, "provider", lookup("OMAMORI_PROVIDER"), "AI provider")
	flags.StringVar(&chosen.model, "model", lookup("OMAMORI_MODEL"), "model name")
	flags.StringVar(&reasoning, "reasoning", "", "reasoning level")
	flags.StringVar(&rulesFolder, "rules", "", "custom rules, replacing the built-in set")
	flags.StringVar(&format, "format", "", "syslog, web, json, suricata, zeek, wazuh or windows")
	flags.IntVar(&chosen.year, "year", 0, "year of classic syslog lines")
	flags.StringVar(&chosen.zone, "timezone", "", "time zone of classic syslog lines")
	flags.StringVar(&chosen.output, "output", "", "folder for reports")
	flags.StringVar(&recordingPath, "replay", "", "replay recorded analyst answers offline")
	flags.BoolVar(&confirmed, "yes", false, "send the sanitized alert snapshot to the selected provider")
	flags.BoolVar(&dryRun, "dry-run", false, "show the guarded request without sending or writing reports")
	flags.DurationVar(&timeout, "timeout", 2*time.Minute, "maximum time for this analysis run")
	paths, err := splitFlags(flags, args)
	if err != nil || len(paths) == 0 || confirmed && dryRun || timeout <= 0 {
		fmt.Fprintln(env.stderr, usageAnalyze)
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
	var sources []string
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fail(errors.New("a log path is not usable"))
		}
		sources = append(sources, absolute)
	}
	loaded, err := rules.Builtin()
	rulesFrom := "built-in"
	if rulesFolder != "" {
		loaded, err = rules.Load(rulesFolder)
		rulesFrom = "from a folder"
	}
	if err != nil {
		return fail(err)
	}
	if len(loaded.Rules()) == 0 {
		return fail(errors.New("the rules folder has no rule"))
	}
	outcome, err := detect.Run(sources, loaded, rulesFrom, intake.Options{Year: chosen.year, Location: location, Format: format}, now)
	if err != nil {
		return fail(err)
	}
	if len(outcome.Intake.Files) == 0 {
		return fail(errors.New("no log file could be read. Give the format with --format syslog, web, json, suricata, zeek, wazuh or windows"))
	}

	target := sources[0]
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		target = filepath.Dir(target)
	}
	review := analystFlags{reasoning: reasoning, recordingPath: recordingPath, confirmed: confirmed, dryRun: dryRun, timeout: timeout}
	summary := fmt.Sprintf("Detected %d alerts from %d events in %d files.", len(outcome.Result.Alerts), len(outcome.Intake.Events), len(outcome.Intake.Files))

	return reviewOutcome(env, flags, chosen, review, database, outcome, sources, target, analysisrun.Base{}, summary)
}

// analystFlags are the choices of one AI review, from the command line.
type analystFlags struct {
	reasoning, recordingPath string
	confirmed, dryRun        bool
	timeout                  time.Duration
}

// reviewOutcome is the terminal side of one checked AI review: provider choice, preview, confirmation, run.
// analyze and forensics both end here, so a forensic run is previewed, guarded, recorded and replayed
// in the same way as a detection run.
func reviewOutcome(env environment, flags *flag.FlagSet, chosen settings, review analystFlags, database storageFlags,
	outcome detect.Outcome, sources []string, target string, base analysisrun.Base, summary string) int {
	lookup := env.lookupEnv
	if lookup == nil {
		lookup = func(string) string { return "" }
	}
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	recordingPath, reasoning, confirmed, dryRun, timeout := review.recordingPath, review.reasoning, review.confirmed, review.dryRun, review.timeout
	var err error

	setup := taskrun.Setup{}
	if recordingPath != "" {
		recorded, err := replay.Load(recordingPath)
		if err != nil {
			return fail(err)
		}
		setup.Recording = &recorded
	} else {
		var saved appconfig.Settings
		if env.settingsPath != nil {
			if path, err := env.settingsPath(); err == nil {
				saved, _ = appconfig.Load(path)
			}
		}
		defaults := mergeDefaults(chosen, saved)
		setup.ProviderID, setup.Model, setup.Reasoning = defaults.ProviderID, defaults.Model, defaults.Reasoning
		reasoningSet := false
		flags.Visit(func(option *flag.Flag) {
			if option.Name == "reasoning" {
				reasoningSet = true
			}
		})
		if reasoningSet {
			setup.Reasoning = reasoning
		}
		if len(outcome.Result.Alerts) > 0 && !knownProvider(setup.ProviderID) {
			fmt.Fprintln(env.stderr, "omamori: choose a known provider with --provider. Run omamori providers to see them.")
			return exitUsage
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	config := analysisrun.Config{
		Provider: taskrun.Config{Target: target, OutputBase: chosen.output, LookupEnv: lookup, Keys: env.keys, Now: env.now, NewProvider: env.newProvider},
		Sources:  sources,
		Base:     base,
	}
	// Preview never opens or initializes a database. Persistence is enabled only for an actual run.
	if database.wanted() && !dryRun && (confirmed || recordingPath != "") {
		var db *store.DB
		db, err = database.open(ctx, env, sources)
		if err != nil {
			return fail(err)
		}
		defer db.Close()
		config.Store = db
	}
	session, err := analysisrun.Prepare(ctx, config, outcome, setup)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "%s\n%s\n", summary, session.ConsentText())
	if dryRun || recordingPath == "" && !confirmed {
		preview, err := session.Preview()
		if err != nil {
			return fail(err)
		}
		encoded, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return fail(errors.New("the request preview could not be written"))
		}
		fmt.Fprintf(env.stdout, "\nGuarded request preview:\n%s\n\nNothing was sent and no reports were written. Add --yes to run the analyst, or --replay to use a recording offline.\n", encoded)
		return exitOK
	}

	session.Confirm()
	result, err := session.Run(ctx, func(progress analysisrun.Progress) {
		fmt.Fprintln(env.stdout, progress.Message)
	})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "Analyst: %s. %d verified findings, %d rejected claims, %d unreviewed alerts.\nReport: %s\nAnalysis JSON: %s\n",
		result.Status, len(result.Analysis.Verified), len(result.Analysis.Rejected), len(result.Analysis.Unreviewed),
		filepath.Join(result.SavedTo, "report.html"), filepath.Join(result.SavedTo, "analysis.json"))
	if result.RunID != "" {
		fmt.Fprintf(env.stdout, "Stored run: %s\n", result.RunID)
	}
	if !result.Complete {
		fmt.Fprintln(env.stderr, "omamori: analysis is incomplete:", result.Reason)
		return exitFailed
	}
	return exitOK
}
