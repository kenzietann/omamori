package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/triage"
	"github.com/kenzietann/omamori/internal/tui"
)

var version = "dev"

const (
	exitOK      = 0
	exitFailed  = 1
	exitUsage   = 2
	modelsWait  = 30 * time.Second
	helpMessage = `Omamori is an AI blue-team tool, with a guard around its access to evidence.

Usage:
  omamori <command> [flags] [arguments]

Commands:
  check <folder>      Task A: check a project for leaked data (opens the screen)
  triage <log file>   Task B: triage an sshd auth.log for guessing and password spraying
  detect <logs>...    read logs, run local rules, write a report (no AI; optional SQL storage)
  analyze <logs>...   detect, ask the AI to review alerts, and verify its claims against the evidence
  forensics <folder>  read the artifacts of a Linux system from a folder (read-only): hash them, run rules,
                      write a report with a timeline. "forensics verify <manifest> <folder>" checks the hashes again
  scenario <folder>   write synthetic logs of one day with attacks into a new folder, for demos and tests
                      (--host: a whole synthetic system for forensics; --campaign: one attack
                      through three hosts, with host logs and network sensor logs)
  rule draft <logs>...
                      Task C: the AI writes the matching part of a detection rule for events that you
                      point at, and Omamori accepts it only if it passes fixed checks (see below)
  dashboard [folder]  local web dashboard: investigations and confirmed runs
  store <command>    stored runs, event/alert search, cases and timelines (run "omamori store" for usage)
  ui <folder>         open the home screen, where you choose a task
  replay <recording> [folder or log file]
                      play back the recorded answers of an earlier run. Nothing is sent. For an analyst run,
                      give the --rules, --assets, --indicators and --format that it used
  peek <report> <project>
                      show what a report matched, on your screen only (add --reveal for full values)
  eval --yes          run the fixed live tests on the fake fixtures and score them (costs tokens)
  providers           list the AI providers and say whether their key is set
  models <provider>   list the models that a provider offers for your key
  version             print the version
  help                print this help

Flags for check, triage, ui and replay:
  --provider id       AI provider (or set OMAMORI_PROVIDER)
  --model name        model name (or set OMAMORI_MODEL)
  --output folder     where reports are saved (default ~/omamori-output)
  --max-steps n       limit of requests in one run (default 15)
  --max-tokens n      limit of tokens in one run (default 300000)

Flags for the triage (Task B). The log lines have no year and no time zone:
  --year n            year of the log lines (default: this year)
  --timezone name     time zone of the log lines, for example Asia/Tokyo (default: this computer)
  --triage-config f   file with window_minutes, failure_threshold and spray_threshold

Flags for detect:
  --rules folder      use the rules of a folder in place of the built-in rules (Sigma format, see docs/rules.md)
  --assets file       names and addresses of your own machines (YAML). Events of a host and events of its
                      address are then known to be one machine, and rules and the AI review can join them
  --indicators file   addresses, domains and SHA-256 hashes that are known to be bad (YAML). Events that name
                      one are marked in every kind of log, and one alert is given for each indicator
  --format name       syslog, web, json, suricata, zeek, wazuh or windows (default: look at the first lines of each file)
  --year, --timezone  for syslog lines, which have no year and no time zone
  --output folder     where the report folder is made (default ~/omamori-output)
  --store             persist the sanitized run for search, cases and timelines
  --db file           choose a SQLite file and enable storage (default ~/omamori-data/omamori.db)

Flags for forensics (also --rules, --year, --timezone, --output, --store and --db, as for detect):
  --processes file    saved output of "ps aux" or "ps -ef" from the system
  --sockets file      saved output of "ss -tulpn" or "netstat -tulpn" from the system
  --file-rules folder file rules (YARA-like) in place of the built-in ones; --no-file-rules turns them off
  --analyze           let the AI analyst review the alerts; takes --yes, --dry-run, --replay, --provider and
                      --model as analyze does. Without --yes it only shows the guarded request
The evidence folder is the top of the system: a mounted image, an unpacked copy, or / itself.
Nothing in it is changed or run. Password hashes, private keys and credential files are never read.

SQL storage defaults to SQLite. For PostgreSQL or MariaDB, set OMAMORI_DB_DRIVER
to postgres or mariadb and provide OMAMORI_DB_DSN in the environment. Database
credentials are never command-line flags. The same store is used by detect and analyze.

Flags for analyze (also accepts the detect flags):
  --provider, --model, --reasoning  provider settings, or use saved settings
  --yes               send the sanitized alert snapshot; without it, show a preview only
  --dry-run           show the guarded request without sending or writing reports
  --replay file       use recorded analyst answers offline, with the same logs and rules
  --timeout duration  maximum run time (default 2m)

Flags for rule draft (also --assets, --indicators, --format, --year, --timezone and --output):
  --goal text         what the rule is for, in your words (required)
  --example ref       an event that the rule must match, as a report names it, like web01/auth.log:68
                      (required, up to 20 times)
  --title, --level    title and level of the saved rule (default: the goal, and medium)
  --benign path       logs that you know to be clean; the rule must match nothing in them (repeatable,
                      up to 20, apart from the searched logs, and they must give at least one event)
  --attempts n        answers the AI may give; after a refusal it is told the fixed reasons (default 3, max 5)
  --yes, --dry-run, --replay, --provider, --model, --reasoning, --timeout, --max-tokens  as for analyze
The AI writes only the log source, the detection and tests. A rule is accepted only if it loads, passes its
tests, matches every example, matches nothing on built-in synthetic days without an attack or in --benign
logs, and is not too broad on your logs. rule.yml is written only for an accepted rule.

Every live run saves recording.json next to its report. "omamori replay" plays it back through
the same guard, tools and report. A replay is labeled REPLAY, and it makes no network call.

API keys are never read from the command line. Set the key of your provider in the
environment (for example ANTHROPIC_API_KEY) or type it in the screen. On macOS a key that works
is saved in your Keychain, and you can remove it in Settings.
`
)

type environment struct {
	stdout, stderr io.Writer
	lookupEnv      func(string) string
	home           func() (string, error)
	openScreen     func(tui.Model) error

	listModels taskrun.ModelLister
	// keys keeps API keys between runs. Without it, keys are not saved.
	keys taskrun.KeyStore
	// settingsPath says where the choices are kept. Without it, they are not kept.
	settingsPath func() (string, error)
	now          func() time.Time
	newProvider  taskrun.ProviderFactory
}

func mergeDefaults(chosen settings, saved appconfig.Settings) tui.Defaults {
	defaults := tui.Defaults{ProviderID: chosen.provider, Model: chosen.model}

	if defaults.ProviderID == "" {
		defaults.ProviderID = saved.Provider
	}
	if defaults.ProviderID == saved.Provider && defaults.Model == "" {
		defaults.Model = saved.Model
	}
	if defaults.ProviderID == saved.Provider && defaults.Model == saved.Model {
		defaults.Reasoning = saved.Reasoning
	}

	return defaults
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
	case "check", "ui", "triage":
		return runScreen(command, rest, env)
	case "replay":
		return runReplay(rest, env)
	case "eval":
		return runEval(rest, env)
	case "peek":
		return runPeek(rest, env)
	case "detect":
		return runDetect(rest, env)
	case "forensics":
		return runForensics(rest, env)
	case "analyze":
		return runAnalyze(rest, env)
	case "scenario":
		return runScenario(rest, env)
	case "dashboard":
		return runDashboard(rest, env)
	case "store":
		return runStore(rest, env)
	case "rule":
		return runRule(rest, env)
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
	for _, choice := range (taskrun.Config{LookupEnv: env.lookupEnv, Keys: env.keys}).Providers() {
		status := "no key needed"
		switch {
		case choice.Local:
		case choice.KeyFound:
			status = choice.KeyEnv + " is set"
		case choice.KeySaved:
			status = "key saved in your Keychain"
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

	config := taskrun.Config{LookupEnv: env.lookupEnv, ListModels: env.listModels, Keys: env.keys}
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

// loadTriageConfig reads the settings of Task B: the file, then the flags. It is used for the commands that can
// run Task B. A settings file that is broken stops them, because a wrong window or year gives wrong findings.
func loadTriageConfig(chosen settings, env environment) (triage.Config, error) {
	return layerTriageConfig(chosen, env, nil)
}

// layerTriageConfig reads the settings of Task B. The base is the settings of a recording, when a replay has them;
// a settings file replaces the base, and the flags are put on top. Without a base, the defaults are the base.
func layerTriageConfig(chosen settings, env environment, recorded *replay.Settings) (triage.Config, error) {
	path := chosen.triageFile
	if path == "" && recorded == nil && env.settingsPath != nil {
		if found, err := env.settingsPath(); err == nil {
			path = filepath.Join(filepath.Dir(found), "triage.json")
		}
	}

	config, err := triage.LoadConfig(path, time.Now())
	if err != nil {
		return triage.Config{}, err
	}
	if recorded != nil && chosen.triageFile == "" {
		if config, err = taskrun.TriageFromRecording(*recorded); err != nil {
			return triage.Config{}, err
		}
	}
	if chosen.year != 0 {
		config.Year = chosen.year
	}
	if chosen.zone != "" {
		location, err := time.LoadLocation(chosen.zone)
		if err != nil {
			return triage.Config{}, errors.New("the time zone is not known")
		}
		config.Location, config.ZoneName = location, chosen.zone
	}

	return config, config.Validate()
}

func runScreen(command string, args []string, env environment) int {
	parse := parseSettings
	if command == "triage" {
		parse = parseTriage
	}
	chosen, err := parse(args, env.lookupEnv, env.home)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		if isUsage(err) {
			return exitUsage
		}

		return exitFailed
	}

	config := taskrun.Config{
		Target:      chosen.target,
		OutputBase:  chosen.output,
		Limits:      agent.Limits{MaxSteps: chosen.maxSteps, MaxTokens: chosen.maxTokens},
		LookupEnv:   env.lookupEnv,
		ListModels:  env.listModels,
		Keys:        env.keys,
		Now:         env.now,
		NewProvider: env.newProvider,
	}
	if command != "check" || chosen.triageFile != "" {
		triageConfig, err := loadTriageConfig(chosen, env)
		if err != nil {
			fmt.Fprintln(env.stderr, "omamori:", err)
			return exitFailed
		}
		config.Triage = &triageConfig
	}

	var path string
	var saved appconfig.Settings
	if env.settingsPath != nil {
		if found, err := env.settingsPath(); err == nil {
			path = found
			saved, _ = appconfig.Load(path)
		}
	}
	model := tui.New(chosen.target, backend{config: config, env: env, settingsPath: path, log: chosen.log}, mergeDefaults(chosen, saved)).WithVersion(version)
	switch command {
	case "check":
		model = model.WithTask("")
	case "triage":
		model = model.WithTask(tui.TaskTriage)
	}

	if err := env.openScreen(model); err != nil {
		fmt.Fprintln(env.stderr, "omamori: the screen stopped:", err)
		return exitFailed
	}

	return exitOK
}

// runReplay plays a recording back. It needs no provider and no key, and it sends nothing.
func runReplay(args []string, env environment) int {
	chosen, err := parseReplay(args, env.lookupEnv, env.home)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		if isUsage(err) {
			return exitUsage
		}

		return exitFailed
	}

	recording, err := replay.Load(chosen.recording)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	detection := chosen.rules != "" || chosen.assets != "" || chosen.indicators != "" || chosen.format != ""
	if recording.Task == "ruledraft" {
		fmt.Fprintln(env.stderr, "omamori: replay a rule draft with omamori rule draft --replay, with the same goal, examples and logs")
		return exitUsage
	}
	if recording.Task != "analyst" && detection {
		fmt.Fprintln(env.stderr, "omamori: --rules, --assets, --indicators and --format only fit the recording of an analyst run")
		return exitUsage
	}
	if recording.Task == "analyst" {
		arguments := []string{"--replay", chosen.recording, "--output", chosen.output}
		for _, flag := range []struct{ name, value string }{{"--rules", chosen.rules}, {"--assets", chosen.assets}, {"--indicators", chosen.indicators}, {"--format", chosen.format}} {
			if flag.value != "" {
				arguments = append(arguments, flag.name, flag.value)
			}
		}
		if chosen.year != 0 {
			arguments = append(arguments, "--year", fmt.Sprint(chosen.year))
		}
		if chosen.zone != "" {
			arguments = append(arguments, "--timezone", chosen.zone)
		}
		return runAnalyze(append(arguments, "--", chosen.target), env)
	}

	target, log := chosen.target, ""
	info, err := os.Stat(target)
	switch {
	case err != nil:
		fmt.Fprintln(env.stderr, "omamori: the project folder or log file is not there")
		return exitFailed
	case info.Mode().IsRegular() && recording.Task == string(taskrun.TaskTriage):
		target, log = filepath.Dir(target), filepath.Base(target)
	case !info.IsDir():
		fmt.Fprintln(env.stderr, "omamori: the target is not a folder")
		return exitFailed
	}

	config := taskrun.Config{
		Target:     target,
		OutputBase: chosen.output,
		Limits:     agent.Limits{MaxSteps: chosen.maxSteps, MaxTokens: chosen.maxTokens},
		LookupEnv:  env.lookupEnv,
	}
	// A replay reads the log with the settings of the recording. Settings that the user gives win.
	if chosen.year != 0 || chosen.zone != "" || chosen.triageFile != "" {
		triageConfig, err := layerTriageConfig(chosen, env, recording.Triage)
		if err != nil {
			fmt.Fprintln(env.stderr, "omamori:", err)
			return exitFailed
		}
		config.Triage = &triageConfig
	}
	model := tui.New(target, backend{config: config, log: log, recording: &recording}, tui.Defaults{}).WithVersion(version).WithReplay()

	if err := env.openScreen(model); err != nil {
		fmt.Fprintln(env.stderr, "omamori: the screen stopped:", err)
		return exitFailed
	}

	return exitOK
}
