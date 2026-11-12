package detect

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/assets"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
)

func runCampaign(t *testing.T, made scenario.Host) Outcome {
	t.Helper()

	return runCampaignWith(t, made, nil)
}

func runCampaignWith(t *testing.T, made scenario.Host, machines *assets.List) Outcome {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "campaign")
	if err := scenario.WriteHost(folder, made); err != nil {
		t.Fatal(err)
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := Run([]string{folder}, set, "built-in", intake.Options{Year: 2026, Location: tokyo, Assets: machines}, scenarioDay())
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

// With the asset list of the network, the first host of the story and the address that moves inside are one
// machine, and one more alert joins the two halves. Without the list that alert is absent, which the
// measurement above shows. The list must add nothing on a day without the attack.
func TestCampaignWithTheAssetListJoinsTheStory(t *testing.T) {
	for seed := int64(1); seed <= 25; seed++ {
		made := scenario.GenerateCampaign(seed, scenarioDay(), true)
		machines, err := assets.Parse([]byte(made.Assets))
		if err != nil {
			t.Fatal(err)
		}
		outcome := runCampaignWith(t, made, machines)
		got := found(outcome)
		for _, wanted := range append(append([]scenario.Expected{}, made.Expected...), made.ExpectedWithAssets...) {
			if got[wanted] == 0 {
				t.Errorf("seed %d: missed %s for %q", seed, wanted.Rule, wanted.Who)
			}
			delete(got, wanted)
		}
		for other := range got {
			t.Errorf("seed %d: alert that the scenario does not expect: %s %s", seed, other.Rule, other.Who)
		}
		if len(made.ExpectedWithAssets) != 1 {
			t.Fatalf("the campaign must name the one alert that needs the asset list")
		}

		for _, alert := range outcome.Result.Alerts {
			if alert.Rule.Name != "host_takeover_then_internal_guessing" {
				continue
			}
			// The two steps come from the logs of two different hosts.
			if len(alert.Parts) != 2 || !strings.HasPrefix(alert.Parts[0].Events[0].Ref, "web01/auth.log:") || !strings.HasPrefix(alert.Parts[1].Events[0].Ref, "app01/auth.log:") {
				t.Errorf("seed %d: the steps of the joined alert are not from web01 and then app01", seed)
			}
		}

		quiet := scenario.GenerateCampaign(seed, scenarioDay(), false)
		for _, alert := range runCampaignWith(t, quiet, machines).Result.Alerts {
			t.Errorf("seed %d: alert on a day without the attack, with the asset list: %s", seed, alert.Rule.Name)
		}
	}

	report := Markdown(runCampaignWith(t, scenario.GenerateCampaign(3, scenarioDay(), true), mustAssets(t)))
	if !strings.Contains(report, "A host was logged in to after password guessing and then guesses passwords inside | machine=web01") {
		t.Error("the report does not show the joined alert with its machine")
	}
}

func mustAssets(t *testing.T) *assets.List {
	t.Helper()
	machines, err := assets.Parse([]byte(scenario.GenerateCampaign(3, scenarioDay(), true).Assets))
	if err != nil {
		t.Fatal(err)
	}

	return machines
}
