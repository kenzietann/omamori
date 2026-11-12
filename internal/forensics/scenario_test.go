package forensics

import (
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
)

var tokyo = time.FixedZone("JST", 9*3600)

func day() time.Time { return time.Date(2026, 11, 10, 0, 0, 0, 0, tokyo) }

// triage writes a synthetic system into a new folder and runs the real path over it: files, hashes, parsers, rules.
func triage(t *testing.T, host scenario.Host) (Result, string) {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "evidence")
	if err := scenario.WriteHost(folder, host); err != nil {
		t.Fatal(err)
	}
	set, err := rules.BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(filepath.Join(folder, "root"), set, "built-in", Options{
		Year: 2026, Location: tokyo, Processes: filepath.Join(folder, "snapshots", "ps.txt"), Sockets: filepath.Join(folder, "snapshots", "ss.txt"),
	}, day().Add(30*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	return result, folder
}

func found(result Result) map[scenario.Expected]int {
	got := map[scenario.Expected]int{}
	for _, alert := range result.Outcome.Result.Alerts {
		who := ""
		if len(alert.Group) > 0 {
			who = alert.Group[0].Value
		}
		got[scenario.Expected{Rule: alert.Rule.Name, Who: who}]++
	}

	return got
}

// The measurement of the slice. Over 25 systems: every trace that the rules are meant to find is found, in the
// logs and in the artifacts, nothing else gives an alert, and the same server without the attack gives none.
func TestHostScenarioDetectionAndFalsePositives(t *testing.T) {
	const seeds = 25
	expected, detected, extra, benignAlerts, benignArtifacts := 0, 0, 0, 0, 0
	for seed := int64(1); seed <= seeds; seed++ {
		host := scenario.GenerateHost(seed, day(), true)
		result, _ := triage(t, host)
		for _, file := range result.Outcome.Intake.Files {
			if file.Malformed != 0 {
				t.Fatalf("seed %d: %s has %d lines that were not read. The generator and the parser do not agree", seed, file.File, file.Malformed)
			}
		}
		got := found(result)
		for _, wanted := range host.Expected {
			expected++
			if got[wanted] == 0 {
				t.Errorf("seed %d: missed %s for %q", seed, wanted.Rule, wanted.Who)
				continue
			}
			detected++
			delete(got, wanted)
		}
		var unexpected []string
		for other := range got {
			unexpected = append(unexpected, other.Rule+" "+other.Who)
		}
		sort.Strings(unexpected)
		for _, other := range unexpected {
			extra++
			t.Errorf("seed %d: alert that the scenario does not expect: %s", seed, other)
		}

		benign, _ := triage(t, scenario.GenerateHost(seed, day(), false))
		for _, current := range benign.Outcome.Intake.Events {
			if current.Source == Source {
				benignArtifacts++
			}
		}
		for _, alert := range benign.Outcome.Result.Alerts {
			benignAlerts++
			t.Errorf("seed %d: alert on the system without an attack: %s at %s", seed, alert.Rule.Name, alert.Events[0].Ref)
		}
	}
	t.Logf("systems: %d. expected alerts found: %d of %d. unexpected alerts: %d. alerts on %d benign artifact events: %d",
		seeds, detected, expected, extra, benignArtifacts, benignAlerts)
}
