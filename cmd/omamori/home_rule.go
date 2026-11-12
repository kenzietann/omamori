package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func splitExamples(text string) []string {
	return strings.FieldsFunc(text, func(character rune) bool { return character == ',' || character == ' ' || character == '\t' })
}

// prepareRuleDraft is the home screen side of "omamori rule draft": the logs of the target folder, the
// built-in days without an attack, and the same session, preview and confirmation as the command.
func (b backend) prepareRuleDraft(setup tui.Setup) (tui.Plan, error) {
	if setup.Replay {
		return tui.Plan{}, errors.New("replay a rule draft with: omamori rule draft --replay recording.json")
	}
	now, location, year := b.readTime()
	read, err := intake.Read([]string{b.config.Target}, intake.Options{Year: year, Location: location})
	if err != nil {
		return tui.Plan{}, err
	}
	if len(read.Events) == 0 {
		return tui.Plan{}, errors.New("no recognized logs were found in this folder")
	}
	examples := splitExamples(setup.Rule.Examples)
	input := ruledraft.Input{Goal: setup.Rule.Goal, Title: setup.Rule.Title, Level: setup.Rule.Level, Events: read.Events, Examples: examples, Now: now}
	session, err := ruledraft.NewSession(context.Background(), ruledraft.Config{Provider: b.config, Sources: []string{b.config.Target}}, input,
		taskrun.Setup{ProviderID: setup.ProviderID, Model: setup.Model, Key: setup.Key, Reasoning: setup.Reasoning})
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

	return tui.Plan{Title: "Task C: Rule draft", ConsentText: session.ConsentText(), Summary: summary, Preview: string(preview),
		MaxRequests: 3, MaxTokens: b.config.Limits.MaxTokens, Confirm: session.Confirm,
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
