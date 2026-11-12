package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/ruledraft"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

// readTime gives the time of the run and how classic syslog lines are read: the triage settings when the
// screen has them, this computer's zone otherwise.
func (b backend) readTime() (time.Time, *time.Location, int) {
	now := time.Now()
	if b.config.Now != nil {
		now = b.config.Now()
	}
	location, year := time.Local, now.Year()
	if b.config.Triage != nil {
		location, year = b.config.Triage.Location, b.config.Triage.Year
	}

	return now, location, year
}

// splitPaths reads the clean logs of the home screen: separated by commas, so that a path may hold a space.
func (b backend) splitPaths(text string) ([]string, error) {
	var paths []string
	for _, part := range strings.Split(text, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		path, err := b.expandPath(part)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}

	return paths, nil
}

func splitExamples(text string) []string {
	return strings.FieldsFunc(text, func(character rune) bool { return character == ',' || character == ' ' || character == '\t' })
}

// prepareRuleDraft is the home screen side of "omamori rule draft": the logs of the target folder, the
// built-in days without an attack, and the same session, preview and confirmation as the command.
func (b backend) prepareRuleDraft(setup tui.Setup) (tui.Plan, error) {
	if setup.Replay && setup.Options.Recording == "" {
		return tui.Plan{}, errors.New("give the recording on the form of the rule draft")
	}
	now, location, year := b.readTime()
	machines, known, err := b.homeLists(setup.Options)
	if err != nil {
		return tui.Plan{}, err
	}
	options := intake.Options{Year: year, Location: location, Format: setup.Options.Format, Assets: machines, Indicators: known}
	read, err := intake.Read([]string{b.config.Target}, options)
	if err != nil {
		return tui.Plan{}, err
	}
	if len(read.Events) == 0 {
		return tui.Plan{}, errors.New("no recognized logs were found in this folder. Choose the log format on the form")
	}
	attempts := 3
	if setup.Options.Attempts != "" {
		if attempts, err = strconv.Atoi(setup.Options.Attempts); err != nil {
			return tui.Plan{}, errors.New("the number of answers is not a number")
		}
	}
	runSetup := taskrun.Setup{ProviderID: setup.ProviderID, Model: setup.Model, Key: setup.Key, Reasoning: setup.Reasoning}
	if setup.Options.Recording != "" {
		recorded, err := b.homeRecording(setup.Options)
		if err != nil {
			return tui.Plan{}, err
		}
		runSetup = taskrun.Setup{Recording: recorded}
		attempts = len(recorded.Steps)
	}
	benign, err := b.splitPaths(setup.Rule.Benign)
	if err != nil {
		return tui.Plan{}, err
	}
	clean, err := readBenign(benign, []string{b.config.Target}, options)
	if err != nil {
		return tui.Plan{}, err
	}
	examples := splitExamples(setup.Rule.Examples)
	input := ruledraft.Input{Goal: setup.Rule.Goal, Title: setup.Rule.Title, Level: setup.Rule.Level, Events: read.Events, Examples: examples, Benign: clean, Now: now}
	session, err := ruledraft.NewSession(context.Background(), ruledraft.Config{Provider: b.config, Sources: append([]string{b.config.Target}, benign...), Attempts: attempts}, input, runSetup)
	if err != nil {
		return tui.Plan{}, err
	}
	request, err := session.Preview()
	if err != nil {
		return tui.Plan{}, err
	}
	preview, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return tui.Plan{}, err
	}
	summary := fmt.Sprintf("Draft a rule from %d example events in %d events of %d files. Omamori checks every answer; rule.yml is written only for an accepted rule.",
		len(examples), len(read.Events), len(read.Files))
	if len(clean) > 0 {
		summary += fmt.Sprintf(" The rule must match none of the %d events of the clean logs.", len(clean))
	}

	return tui.Plan{Title: "Task C: Rule draft", Label: session.Label(), ConsentText: session.ConsentText(), Summary: summary, Preview: string(preview),
		MaxRequests: attempts, MaxTokens: b.config.Limits.MaxTokens, Confirm: session.Confirm,
		Run: func(ctx context.Context, step func(string)) (tui.Result, error) {
			result, err := session.Run(ctx, step)
			report := ""
			if result.SavedTo != "" {
				text, _ := os.ReadFile(filepath.Join(result.SavedTo, "report.md"))
				report = string(text)
			}
			return tui.Result{Report: report, Complete: result.Accepted, SavedTo: result.SavedTo}, err
		}}, nil
}
