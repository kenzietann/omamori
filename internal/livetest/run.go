package livetest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/triage"
)

// Case is one fixture and the task that runs on it.
type Case struct {
	Name     string
	Task     taskrun.Task
	Target   string
	Log      string
	Expected int
	Rows     []string
}

type Options struct {
	Config     taskrun.Config
	ProviderID string
	Model      string
	Fixtures   string
	Runs       int
	// TokenCap is the most tokens that the whole series may use. It is the cost cap.
	TokenCap   int
	OutputBase string
	Progress   func(string)
}

type RunResult struct {
	Verdict  Verdict
	Requests int
	Tokens   int
	Error    string
}

type CaseResult struct {
	Case    Case
	Runs    []RunResult
	Skipped int
}

type Summary struct {
	Model       string
	Provider    string
	Cases       []CaseResult
	TotalTokens int
	CapReached  bool
}

var (
	requestPattern = regexp.MustCompile(`^sending request (\d+) to `)
	tokenPattern   = regexp.MustCompile(`\((?:step \d+, )?(\d+) tokens used in total\)$`)
)

// Cases builds the fixed set: the exposure fixture and four logs.
func Cases(fixtures string) ([]Case, int, error) {
	rows, err := LoadExposure(Path(fixtures, "exposure", "expected_findings.json"))
	if err != nil {
		return nil, 0, err
	}
	counts, year, err := LoadTriage(Path(fixtures, "triage", "expected_findings.json"))
	if err != nil {
		return nil, 0, err
	}

	cases := []Case{{Name: "Task A: exposure fixture", Task: taskrun.TaskExposure, Target: Path(fixtures, "exposure", "project"), Expected: len(rows), Rows: rows}}
	for _, log := range []string{"guessing.log", "spraying.log", "benign.log", "malformed.log"} {
		count, found := counts[log]
		if !found {
			return nil, 0, errors.New("the expected findings have no entry for " + log)
		}
		cases = append(cases, Case{Name: "Task B: " + log, Task: taskrun.TaskTriage, Target: Path(fixtures, "triage"), Log: log, Expected: count})
	}

	return cases, year, nil
}

// Run does the series. It stops starting new runs when the token cap is used.
func Run(ctx context.Context, options Options) (Summary, error) {
	if options.Runs < 1 || options.TokenCap < 1 {
		return Summary{}, errors.New("runs and the token cap must be above 0")
	}
	fixtures, err := filepath.Abs(options.Fixtures)
	if err != nil {
		return Summary{}, errors.New("the fixtures folder is not usable")
	}
	cases, year, err := Cases(fixtures)
	if err != nil {
		return Summary{}, err
	}

	summary := Summary{Model: options.Model, Provider: options.ProviderID}
	for _, current := range cases {
		result := CaseResult{Case: current}
		for number := 1; number <= options.Runs; number++ {
			remaining := options.TokenCap - summary.TotalTokens
			if remaining <= 0 || ctx.Err() != nil {
				summary.CapReached = summary.CapReached || remaining <= 0
				result.Skipped++
				continue
			}

			run := oneRun(ctx, options, current, year, number, remaining)
			summary.TotalTokens += run.Tokens
			result.Runs = append(result.Runs, run)
			if options.Progress != nil {
				status := "failed"
				if run.Verdict.Passed {
					status = "passed"
				}
				options.Progress(fmt.Sprintf("%s, run %d of %d: %s (%d requests, %d tokens)", current.Name, number, options.Runs, status, run.Requests, run.Tokens))
			}
		}
		summary.Cases = append(summary.Cases, result)
	}

	return summary, nil
}

func oneRun(ctx context.Context, options Options, current Case, year, number, remaining int) RunResult {
	config := options.Config
	config.Target = current.Target
	config.OutputBase = filepath.Join(options.OutputBase, strings.NewReplacer(" ", "-", ":", "", ".", "-").Replace(strings.ToLower(current.Name))+"-"+strconv.Itoa(number))
	config.Limits = agent.Limits{MaxSteps: options.Config.Limits.MaxSteps, MaxTokens: min(options.Config.Limits.MaxTokens, remaining)}
	if current.Task == taskrun.TaskTriage {
		config.Triage = &triage.Config{Window: 10 * time.Minute, FailureThreshold: 5, SprayThreshold: 5, Year: year, Location: time.UTC, ZoneName: "UTC"}
	}

	session, err := taskrun.Prepare(config, taskrun.Setup{Task: current.Task, Log: current.Log, ProviderID: options.ProviderID, Model: options.Model})
	if err != nil {
		return RunResult{Error: err.Error(), Verdict: Verdict{Detail: "the run could not start"}}
	}
	session.Confirm()

	var run RunResult
	result, err := session.Run(ctx, func(text string) {
		if match := requestPattern.FindStringSubmatch(text); match != nil {
			run.Requests, _ = strconv.Atoi(match[1])
		}
		if match := tokenPattern.FindStringSubmatch(text); match != nil {
			run.Tokens, _ = strconv.Atoi(match[1])
		}
	})
	if err != nil {
		run.Error = err.Error()
		run.Verdict = Verdict{Detail: "the run failed"}

		return run
	}
	if !result.Complete {
		run.Verdict = Verdict{Detail: "the run did not finish (limit reached or provider error)"}

		return run
	}

	if current.Task == taskrun.TaskTriage {
		run.Verdict = ScoreTriage(result.Report, current.Expected)
	} else {
		run.Verdict = ScoreExposure(result.Report, current.Rows)
	}

	return run
}

func (summary Summary) Markdown(date time.Time) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Omamori live test results\n\nDate: %s  \nProvider: %s  \nModel: %s\n\n", date.UTC().Format("2006-01-02"), summary.Provider, summary.Model)
	out.WriteString("Scored on the findings and their locations, not on the wording. Synthetic data only.\n\n")
	out.WriteString("| Case | Passed | Avg requests | Avg tokens | Notes |\n|---|---|---|---|---|\n")
	for _, result := range summary.Cases {
		passed, requests, tokens := 0, 0, 0
		notes := []string{}
		for _, run := range result.Runs {
			if run.Verdict.Passed {
				passed++
			} else {
				notes = append(notes, run.Verdict.Detail)
			}
			requests += run.Requests
			tokens += run.Tokens
		}
		average := func(total int) int {
			if len(result.Runs) == 0 {
				return 0
			}

			return total / len(result.Runs)
		}
		if result.Skipped > 0 {
			notes = append(notes, fmt.Sprintf("%d not run (cost cap)", result.Skipped))
		}
		fmt.Fprintf(&out, "| %s | %d of %d | %d | %d | %s |\n", result.Case.Name, passed, len(result.Runs), average(requests), average(tokens), strings.Join(dedupe(notes), "; "))
	}
	fmt.Fprintf(&out, "\nTokens used in all runs: %d.\n", summary.TotalTokens)
	if summary.CapReached {
		out.WriteString("The cost cap was reached, so some runs were skipped.\n")
	}

	return out.String()
}

func dedupe(values []string) []string {
	var out []string
	for _, value := range values {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}

	return out
}

// WriteResults saves the table in a new file. It never overwrites.
func WriteResults(folder, text string, date time.Time) (string, error) {
	if err := os.MkdirAll(folder, 0o755); err != nil {
		return "", errors.New("the results folder could not be created")
	}
	path := filepath.Join(folder, "live-results-"+date.UTC().Format("20060102-150405")+".md")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", errors.New("the results file could not be created")
	}
	defer file.Close()
	if _, err := file.WriteString(text); err != nil {
		return "", errors.New("the results file could not be written")
	}

	return path, nil
}
