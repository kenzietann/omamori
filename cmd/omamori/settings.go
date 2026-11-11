package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const (
	defaultMaxSteps  = 15
	defaultMaxTokens = 300000
	usageText        = "usage: omamori check|ui [--provider id] [--model name] [--output folder] [--max-steps n] [--max-tokens n] <project folder>"
	usageTriage      = "usage: omamori triage [--year n] [--timezone name] [--triage-config file] [--provider id] [--model name] [--output folder] <log file>"
	usageReplay      = "usage: omamori replay [--output folder] [--max-steps n] [--max-tokens n] <recording file> [<project folder or log file>]"
)

type settings struct {
	target    string
	output    string
	provider  string
	model     string
	maxSteps  int
	maxTokens int
	// log is the log of the triage, relative to the target folder.
	log string
	// year and zone are the settings of the triage from the command line. Zero and empty mean "not given".
	year       int
	zone       string
	triageFile string
	// recording is the file that a replay plays back.
	recording string
}

var (
	errUsage       = errors.New(usageText)
	errUsageTriage = errors.New(usageTriage)
	errUsageReplay = errors.New(usageReplay)
)

func isUsage(err error) bool {
	return err == errUsage || err == errUsageTriage || err == errUsageReplay
}

// parseFlags reads the flags that all commands share, and gives back the other arguments in order.
// A flag may come before or after the arguments, like in most tools. It never reads a key.
func parseFlags(name string, args []string, lookupEnv func(string) string, usage error) (settings, []string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var parsed settings
	flags.StringVar(&parsed.output, "output", "", "folder for the reports")
	flags.StringVar(&parsed.provider, "provider", lookupEnv("OMAMORI_PROVIDER"), "provider id")
	flags.StringVar(&parsed.model, "model", lookupEnv("OMAMORI_MODEL"), "model name")
	flags.IntVar(&parsed.year, "year", 0, "year of the log lines")
	flags.StringVar(&parsed.zone, "timezone", "", "time zone of the log lines")
	flags.StringVar(&parsed.triageFile, "triage-config", "", "file with the settings of the triage")

	maxSteps, maxTokens := strconv.Itoa(defaultMaxSteps), strconv.Itoa(defaultMaxTokens)
	flags.StringVar(&maxSteps, "max-steps", maxSteps, "limit of requests")
	flags.StringVar(&maxTokens, "max-tokens", maxTokens, "limit of tokens")

	var positional []string
	if err := flags.Parse(args); err != nil {
		return settings{}, nil, usage
	}
	for flags.NArg() > 0 {
		positional = append(positional, flags.Arg(0))
		if err := flags.Parse(flags.Args()[1:]); err != nil {
			return settings{}, nil, usage
		}
	}

	var err error
	if parsed.maxSteps, err = positiveNumber(maxSteps); err != nil {
		return settings{}, nil, fmt.Errorf("--max-steps must be a whole number above 0")
	}
	if parsed.maxTokens, err = positiveNumber(maxTokens); err != nil {
		return settings{}, nil, fmt.Errorf("--max-tokens must be a whole number above 0")
	}
	if parsed.provider != "" && !knownProvider(parsed.provider) {
		return settings{}, nil, fmt.Errorf("the provider %q is not known", parsed.provider)
	}

	return parsed, positional, nil
}

func (parsed *settings) chooseOutput(homeDirectory func() (string, error)) error {
	if parsed.output == "" {
		home, err := homeDirectory()
		if err != nil || home == "" {
			return errors.New("no home folder was found, so choose a report folder with --output")
		}
		parsed.output = filepath.Join(home, "omamori-output")
	}

	absolute, err := filepath.Abs(parsed.output)
	if err != nil {
		return errors.New("the report folder is not usable")
	}
	parsed.output = absolute

	return nil
}

// parseSettings reads the command line of check and ui: one project folder. A setting from the command line
// wins over one from the environment.
func parseSettings(args []string, lookupEnv func(string) string, homeDirectory func() (string, error)) (settings, error) {
	parsed, positional, err := parseFlags("omamori", args, lookupEnv, errUsage)
	if err != nil {
		return settings{}, err
	}
	if len(positional) != 1 {
		return settings{}, errUsage
	}

	target, err := filepath.Abs(positional[0])
	if err != nil {
		return settings{}, errors.New("the project folder is not usable")
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return settings{}, errors.New("the target is not a folder")
	}
	parsed.target = target
	parsed.log = taskrun.DefaultLog

	if err := parsed.chooseOutput(homeDirectory); err != nil {
		return settings{}, err
	}

	return parsed, nil
}

// parseTriage reads the command line of triage: one log file. The folder around it is the project folder.
func parseTriage(args []string, lookupEnv func(string) string, homeDirectory func() (string, error)) (settings, error) {
	parsed, positional, err := parseFlags("omamori triage", args, lookupEnv, errUsageTriage)
	if err != nil {
		return settings{}, err
	}
	if len(positional) != 1 {
		return settings{}, errUsageTriage
	}

	path, err := filepath.Abs(positional[0])
	if err != nil {
		return settings{}, errors.New("the log file is not usable")
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return settings{}, errors.New("the target is not a log file")
	}
	parsed.target, parsed.log = filepath.Dir(path), filepath.Base(path)
	if !taskrun.ValidLogName(parsed.log) {
		return settings{}, errors.New("the name of the log file may only have letters, digits, dots, dashes and underscores")
	}

	if err := parsed.chooseOutput(homeDirectory); err != nil {
		return settings{}, err
	}

	return parsed, nil
}

// parseReplay reads the command line of replay: a recording, and the project folder or the log file that it was made for.
func parseReplay(args []string, lookupEnv func(string) string, homeDirectory func() (string, error)) (settings, error) {
	parsed, positional, err := parseFlags("omamori replay", args, lookupEnv, errUsageReplay)
	if err != nil {
		return settings{}, err
	}
	if len(positional) < 1 || len(positional) > 2 {
		return settings{}, errUsageReplay
	}

	recording, err := filepath.Abs(positional[0])
	if err != nil {
		return settings{}, errors.New("the recording is not usable")
	}
	if info, err := os.Stat(recording); err != nil || !info.Mode().IsRegular() {
		return settings{}, errors.New("the recording is not a file")
	}
	parsed.recording = recording

	where := "."
	if len(positional) == 2 {
		where = positional[1]
	}
	target, err := filepath.Abs(where)
	if err != nil {
		return settings{}, errors.New("the project folder is not usable")
	}
	if _, err := os.Stat(target); err != nil {
		return settings{}, errors.New("the project folder or log file is not there")
	}
	parsed.target = target

	if err := parsed.chooseOutput(homeDirectory); err != nil {
		return settings{}, err
	}

	return parsed, nil
}

func positiveNumber(text string) (int, error) {
	number, err := strconv.Atoi(text)
	if err != nil || number < 1 {
		return 0, errors.New("not a positive number")
	}

	return number, nil
}

func knownProvider(id string) bool {
	for _, info := range outbound.Providers() {
		if info.ID == id {
			return true
		}
	}

	return false
}
