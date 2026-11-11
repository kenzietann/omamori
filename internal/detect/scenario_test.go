package detect

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
)

var tokyo = time.FixedZone("JST", 9*3600)

func scenarioDay() time.Time { return time.Date(2026, 11, 10, 0, 0, 0, 0, tokyo) }

// runScenario writes the logs of a scenario into a new folder and runs the real path: files, parsers, rules.
func runScenario(t *testing.T, made scenario.Scenario) Outcome {
	t.Helper()
	folder := t.TempDir()
	for name, text := range made.Files {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := Run([]string{folder}, set, "built-in", intake.Options{Year: 2026, Location: tokyo}, scenarioDay())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range outcome.Intake.Files {
		if file.Malformed != 0 || file.Events == 0 {
			t.Fatalf("%s: %d lines were not read and %d events were made. The generator and the parser do not agree", file.File, file.Malformed, file.Events)
		}
	}
	if len(outcome.Intake.Files) != len(made.Files) {
		t.Fatalf("%d files were read, and the scenario has %d", len(outcome.Intake.Files), len(made.Files))
	}

	return outcome
}

func found(outcome Outcome) map[scenario.Expected]int {
	got := map[scenario.Expected]int{}
	for _, alert := range outcome.Result.Alerts {
		who := ""
		if len(alert.Group) > 0 {
			who = alert.Group[0].Value
		}
		got[scenario.Expected{Rule: alert.Rule.Name, Who: who}]++
	}

	return got
}

// The measurement of the slice: over 25 different days, every attack that the rules are meant to find is found,
// and nothing else gives an alert. The numbers are printed with -v.
func TestScenarioDetectionAndFalsePositives(t *testing.T) {
	const seeds = 25
	expectedTotal, detected, falseAlerts, benignAlerts, benignEvents := 0, 0, 0, 0, 0

	for seed := int64(1); seed <= seeds; seed++ {
		made := scenario.Generate(seed, scenarioDay(), true)
		got := found(runScenario(t, made))

		for _, wanted := range made.Expected {
			expectedTotal++
			if got[wanted] == 0 {
				t.Errorf("seed %d: missed %s for %q", seed, wanted.Rule, wanted.Who)
				continue
			}
			detected++
			delete(got, wanted)
		}
		var extra []scenario.Expected
		for unexpected := range got {
			extra = append(extra, unexpected)
		}
		sort.Slice(extra, func(first, second int) bool {
			return extra[first].Rule+extra[first].Who < extra[second].Rule+extra[second].Who
		})
		for _, unexpected := range extra {
			falseAlerts++
			t.Errorf("seed %d: alert that the scenario does not expect: %s for %q", seed, unexpected.Rule, unexpected.Who)
		}
		if len(made.KnownMisses) != 1 {
			t.Errorf("seed %d: the scenario must name its one known miss", seed)
		}

		benign := runScenario(t, scenario.Generate(seed, scenarioDay(), false))
		benignEvents += len(benign.Intake.Events)
		for _, alert := range benign.Result.Alerts {
			benignAlerts++
			t.Errorf("seed %d: alert on a day without attacks: %s %v", seed, alert.Rule.Name, alert.Group)
		}
	}

	t.Logf("days: %d. expected alerts found: %d of %d. unexpected alerts on attack days: %d. alerts on %d benign events: %d. known miss on each attack day: slow guessing",
		seeds, detected, expectedTotal, falseAlerts, benignEvents, benignAlerts)
}

func TestScenarioIsTheSameForTheSameSeed(t *testing.T) {
	first, second := scenario.Generate(7, scenarioDay(), true), scenario.Generate(7, scenarioDay(), true)
	for name, text := range first.Files {
		if second.Files[name] != text {
			t.Fatalf("%s differs between two runs with the same seed", name)
		}
	}
	if other := scenario.Generate(8, scenarioDay(), true); other.Files["auth.log"] == first.Files["auth.log"] {
		t.Fatal("another seed gave the same log")
	}
}
