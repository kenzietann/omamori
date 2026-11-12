package detect

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
)

func runCampaign(t *testing.T, made scenario.Host) Outcome {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "campaign")
	if err := scenario.WriteHost(folder, made); err != nil {
		t.Fatal(err)
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := Run([]string{folder}, set, "built-in", intake.Options{Year: 2026, Location: tokyo}, scenarioDay())
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Intake.Files) != len(made.Files) || len(outcome.Intake.Skipped) != 0 {
		t.Fatalf("%d of %d files were read, skipped: %v", len(outcome.Intake.Files), len(made.Files), outcome.Intake.Skipped)
	}
	for _, file := range outcome.Intake.Files {
		if file.Malformed != 0 || file.Events == 0 {
			t.Fatalf("%s: %d lines were not read and %d events were made. The generator and the parser do not agree", file.File, file.Malformed, file.Events)
		}
	}

	return outcome
}

// The measurement of slice 7: one attack through three hosts, in the logs of the hosts and of two network
// sensors. Over 25 days every step that the rules are meant to find is found, nothing else gives an alert,
// and the same network without the attack is quiet.
func TestCampaignDetectionAndFalsePositives(t *testing.T) {
	const seeds = 25
	expected, detected, extra, benignEvents, benignAlerts := 0, 0, 0, 0, 0
	for seed := int64(1); seed <= seeds; seed++ {
		made := scenario.GenerateCampaign(seed, scenarioDay(), true)
		outcome := runCampaign(t, made)
		got := found(outcome)
		for _, wanted := range made.Expected {
			expected++
			if got[wanted] == 0 {
				t.Errorf("seed %d: missed %s for %q", seed, wanted.Rule, wanted.Who)
				continue
			}
			detected++
			delete(got, wanted)
		}
		var others []string
		for other := range got {
			others = append(others, other.Rule+" "+other.Who)
		}
		sort.Strings(others)
		for _, other := range others {
			extra++
			t.Errorf("seed %d: alert that the scenario does not expect: %s", seed, other)
		}
		if len(made.KnownMisses) != 3 {
			t.Errorf("seed %d: the campaign must name its three known misses, it names %d", seed, len(made.KnownMisses))
		}

		benign := runCampaign(t, scenario.GenerateCampaign(seed, scenarioDay(), false))
		benignEvents += len(benign.Intake.Events)
		for _, alert := range benign.Result.Alerts {
			benignAlerts++
			t.Errorf("seed %d: alert on a day without the attack: %s %v at %s", seed, alert.Rule.Name, alert.Group, alert.Events[0].Ref)
		}
	}
	t.Logf("days: %d. expected alerts found: %d of %d. unexpected alerts: %d. alerts on %d benign events: %d",
		seeds, detected, expected, extra, benignEvents, benignAlerts)
}

// The report of the campaign names evidence from every kind of source, and the alerts of the movement
// inside the network stand in the order of the story.
func TestCampaignReportCoversEverySource(t *testing.T) {
	outcome := runCampaign(t, scenario.GenerateCampaign(3, scenarioDay(), true))
	report := Markdown(outcome)
	for _, want := range []string{
		"web01/auth.log:", "web01/access.log:", "app01/auth.log:", "sensor/conn.log:", "sensor/eve.json:",
		"| db01/auth.log | syslog |", "| sensor/conn.log | json (zeek) |", "| sensor/eve.json | json (suricata) |",
		"SSH login succeeded after guessing from an internal address | src_ip=10.0.1.10",
		"Large amount of data sent to an external address | src_ip=10.0.2.30",
		"One internal address tries many internal addresses | src_ip=10.0.1.10",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not have %q", want)
		}
	}
	timeline := report[strings.Index(report, "## Timeline"):]
	last := -1
	for _, title := range []string{"SSH login succeeded after password guessing", "One internal address tries many internal addresses",
		"SSH login succeeded after guessing from an internal address", "Large amount of data sent to an external address", "SSH password spraying from one address"} {
		at := strings.Index(timeline, title)
		if at < 0 || at < last {
			t.Errorf("%q is missing from the timeline or out of its place", title)
		}
		last = at
	}
}
