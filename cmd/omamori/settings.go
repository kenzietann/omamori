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
)

const (
	defaultMaxSteps  = 15
	defaultMaxTokens = 300000
	usageText        = "usage: omamori check|ui [--provider id] [--model name] [--output folder] [--max-steps n] [--max-tokens n] <project folder>"
)

type settings struct {
	target    string
	output    string
	provider  string
	model     string
	maxSteps  int
	maxTokens int
}

var errUsage = errors.New(usageText)

// parseSettings reads the command line. A setting from the command line wins over one from the
// environment. It never reads a key: keys are read later, for the provider that the user chooses.
func parseSettings(args []string, lookupEnv func(string) string, homeDirectory func() (string, error)) (settings, error) {
	flags := flag.NewFlagSet("omamori", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var parsed settings
	flags.StringVar(&parsed.output, "output", "", "folder for the reports")
	flags.StringVar(&parsed.provider, "provider", lookupEnv("OMAMORI_PROVIDER"), "provider id")
	flags.StringVar(&parsed.model, "model", lookupEnv("OMAMORI_MODEL"), "model name")

	maxSteps, maxTokens := strconv.Itoa(defaultMaxSteps), strconv.Itoa(defaultMaxTokens)
	flags.StringVar(&maxSteps, "max-steps", maxSteps, "limit of requests")
	flags.StringVar(&maxTokens, "max-tokens", maxTokens, "limit of tokens")

	// The folder may come before or after the flags, like in most tools.
	if err := flags.Parse(args); err != nil || flags.NArg() == 0 {
		return settings{}, errUsage
	}
	folder := flags.Arg(0)
	if err := flags.Parse(flags.Args()[1:]); err != nil || flags.NArg() != 0 {
		return settings{}, errUsage
	}

	var err error
	if parsed.maxSteps, err = positiveNumber(maxSteps); err != nil {
		return settings{}, fmt.Errorf("--max-steps must be a whole number above 0")
	}
	if parsed.maxTokens, err = positiveNumber(maxTokens); err != nil {
		return settings{}, fmt.Errorf("--max-tokens must be a whole number above 0")
	}

	if parsed.provider != "" && !knownProvider(parsed.provider) {
		return settings{}, fmt.Errorf("the provider %q is not known", parsed.provider)
	}

	target, err := filepath.Abs(folder)
	if err != nil {
		return settings{}, errors.New("the project folder is not usable")
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return settings{}, errors.New("the target is not a folder")
	}
	parsed.target = target

	if parsed.output == "" {
		home, err := homeDirectory()
		if err != nil || home == "" {
			return settings{}, errors.New("no home folder was found, so choose a report folder with --output")
		}
		parsed.output = filepath.Join(home, "omamori-output")
	}
	if parsed.output, err = filepath.Abs(parsed.output); err != nil {
		return settings{}, errors.New("the report folder is not usable")
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
