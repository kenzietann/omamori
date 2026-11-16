package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func runWithInput(t *testing.T, now time.Time, input string, args ...string) detectRun {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, environment{
		stdout: &stdout, stderr: &stderr, stdin: strings.NewReader(input), lookupEnv: func(string) string { return "" },
		home: homeAt(t.TempDir()), now: func() time.Time { return now },
	})

	return detectRun{code, stdout.String(), stderr.String()}
}

type alertsFile struct {
	Alerts []struct {
		Number int    `json:"number"`
		Rule   string `json:"rule"`
		Count  int    `json:"count"`
		Review string `json:"review"`
		Match  struct {
			Complete bool `json:"complete"`
		} `json:"match"`
	} `json:"alerts"`
	KnownGood []struct {
		Rule      string `json:"rule"`
		KnownGood struct {
			Note string `json:"note"`
		} `json:"known_good"`
	} `json:"known_good_alerts"`
}

func readAlerts(t *testing.T, folder string) alertsFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(folder, "alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed alertsFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	return parsed
}

func onlyFolder(t *testing.T, parent string) string {
	t.Helper()
	found, _ := filepath.Glob(filepath.Join(parent, "forensics-*"))
	if len(found) != 1 {
		t.Fatalf("report folders: %v", found)
	}

	return found[0]
}

func TestKnownGoodThroughTheCommandLine(t *testing.T) {
	host := hostFixture(t, false)
	lists := t.TempDir()
	list := filepath.Join(lists, "known-good.yml")

	one := filepath.Join(t.TempDir(), "one")
	first := runAt(t, detectNow, forensicsArgs(host, one)...)
	if first.code != exitOK {
		t.Fatalf("first run: %s %s", first.stdout, first.stderr)
	}
	report := onlyFolder(t, one)
	before := readAlerts(t, report)
	var pinned, declined int
	var pinnedRule string
	for _, alert := range before.Alerts {
		if !alert.Match.Complete || alert.Count != 1 {
			continue
		}
		if pinned == 0 {
			pinned, pinnedRule = alert.Number, alert.Rule
		} else if declined == 0 && alert.Rule != pinnedRule {
			declined = alert.Number
		}
	}
	if pinned == 0 || declined == 0 {
		t.Fatal("the scenario has no two alerts of one event")
	}

	// No answer adds nothing, and the list is not made.
	silent := runWithInput(t, detectNow, "", "known-good", "add", "--list", list, "--note", "reviewed", report, strconv.Itoa(pinned))
	if silent.code != exitOK || !strings.Contains(silent.stdout, "Nothing was added") {
		t.Fatalf("no answer: %d %s %s", silent.code, silent.stdout, silent.stderr)
	}
	if _, err := os.Stat(list); err == nil {
		t.Fatal("a list was made without an answer")
	}
	for _, args := range [][]string{
		{"known-good", "add", "--list", list, report, "1"},                  // no note
		{"known-good", "add", "--list", list, "--note", "x", report},        // no alert
		{"known-good", "add", "--list", list, "--note", "x", report, "one"}, // not a number
		{"known-good", "add", "--list", list, "--note", "x", "--days", "400", report, "1"},
	} {
		if got := runWithInput(t, detectNow, "yes\n", args...); got.code == exitOK {
			t.Errorf("%v was taken: %s", args, got.stdout)
		}
	}

	added := runWithInput(t, detectNow, "yes\nno\n", "known-good", "add", "--list", list, "--note", "my own installer", report, strconv.Itoa(pinned), strconv.Itoa(declined))
	if added.code != exitOK || !strings.Contains(added.stdout, "Added 1 entries") || !strings.Contains(added.stdout, "was not added") {
		t.Fatalf("add: %d %s %s", added.code, added.stdout, added.stderr)
	}
	if info, err := os.Stat(list); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the list: %v %v", info, err)
	}
	again := runWithInput(t, detectNow, "yes\n", "known-good", "add", "--list", list, "--note", "again", report, strconv.Itoa(pinned))
	if !strings.Contains(again.stdout, "on the list already") {
		t.Errorf("a second add: %s", again.stdout)
	}
	shown := runWithInput(t, detectNow, "", "known-good", "show", "--list", list)
	if shown.code != exitOK || !strings.Contains(shown.stdout, "1 entries") || !strings.Contains(shown.stdout, "my own installer") || !strings.Contains(shown.stdout, "until 2027-02-09") {
		t.Fatalf("show: %s %s", shown.stdout, shown.stderr)
	}

	// The second run lowers the one alert, and only that one.
	output := filepath.Join(t.TempDir(), "two")
	second := runAt(t, detectNow, forensicsArgs(host, output, "--known-good", list)...)
	if second.code != exitOK || !strings.Contains(second.stdout, ". 1 known good, from your list") {
		t.Fatalf("second run: %s %s", second.stdout, second.stderr)
	}
	after := readAlerts(t, onlyFolder(t, output))
	if len(after.Alerts) != len(before.Alerts)-1 || len(after.KnownGood) != 1 || after.KnownGood[0].Rule != pinnedRule || after.KnownGood[0].KnownGood.Note != "my own installer" {
		t.Fatalf("after: %d alerts (before %d), known good %+v", len(after.Alerts), len(before.Alerts), after.KnownGood)
	}
	markdown, _ := os.ReadFile(filepath.Join(onlyFolder(t, output), "report.md"))
	for _, want := range []string{"## Known good, from your list", "| my own installer | 2026-11-11 | 2027-02-09 |", "- Known-good list: " + list, "| known good |"} {
		if !strings.Contains(string(markdown), want) {
			t.Errorf("the report has no %q", want)
		}
	}

	// After the entry expires, the alert is back, with a note to look again.
	late := filepath.Join(t.TempDir(), "late")
	expired := runAt(t, detectNow.AddDate(0, 0, 100), forensicsArgs(host, late, "--known-good", list)...)
	if expired.code != exitOK || !strings.Contains(expired.stdout, ". 0 known good") {
		t.Fatalf("expired: %s %s", expired.stdout, expired.stderr)
	}
	back := readAlerts(t, onlyFolder(t, late))
	reviewed := false
	for _, alert := range back.Alerts {
		reviewed = reviewed || alert.Rule == pinnedRule && strings.Contains(alert.Review, "expired on 2027-02-09")
	}
	if len(back.Alerts) != len(before.Alerts) || !reviewed {
		t.Fatalf("expired alerts: %+v", back.Alerts)
	}

	// A list inside the evidence, a list that is not valid, and a list with --store are refused.
	inside := filepath.Join(host, "root", "etc", "known-good.yml")
	data, _ := os.ReadFile(list)
	os.WriteFile(inside, data, 0o600)
	defer os.Remove(inside)
	broken := filepath.Join(lists, "broken.yml")
	os.WriteFile(broken, []byte("version: 1\nentries:\n  - rule: x\n    allow: everything\n"), 0o600)
	for name, args := range map[string][]string{
		"inside the evidence": forensicsArgs(host, filepath.Join(t.TempDir(), "a"), "--known-good", inside),
		"not valid":           forensicsArgs(host, filepath.Join(t.TempDir(), "b"), "--known-good", broken),
		"with --store":        forensicsArgs(host, filepath.Join(t.TempDir(), "c"), "--known-good", list, "--store"),
		"missing":             forensicsArgs(host, filepath.Join(t.TempDir(), "d"), "--known-good", filepath.Join(lists, "none.yml")),
	} {
		if got := runAt(t, detectNow, args...); got.code != exitFailed || !strings.Contains(got.stderr, "known-good") && !strings.Contains(got.stderr, "list") {
			t.Errorf("%s: %d %s", name, got.code, got.stderr)
		}
	}
}

func TestKnownGoodWithDetect(t *testing.T) {
	logs := filepath.Join(t.TempDir(), "logs")
	if got := runAt(t, detectNow, "scenario", "--seed", "3", "--date", "2026-11-10", "--timezone", "Asia/Tokyo", logs); got.code != exitOK {
		t.Fatalf("scenario: %s", got.stderr)
	}
	output := filepath.Join(t.TempDir(), "out")
	first := runAt(t, detectNow, "detect", "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output, logs)
	if first.code != exitOK {
		t.Fatalf("detect: %s", first.stderr)
	}
	found, _ := filepath.Glob(filepath.Join(output, "detect-*"))
	report := found[0]
	alerts := readAlerts(t, report)
	var counted int
	for _, alert := range alerts.Alerts {
		if !alert.Match.Complete {
			counted = alert.Number
			break
		}
	}
	if counted == 0 {
		t.Fatal("the scenario has no alert that counts many events")
	}
	// An alert that counts more events than it keeps (password guessing) cannot be pinned.
	list := filepath.Join(t.TempDir(), "known-good.yml")
	got := runWithInput(t, detectNow, "yes\n", "known-good", "add", "--list", list, "--note", "x", report, strconv.Itoa(counted))
	if !strings.Contains(got.stdout, "cannot be pinned exactly") || !strings.Contains(got.stdout, "Nothing was added") {
		t.Fatalf("a counted alert: %s %s", got.stdout, got.stderr)
	}
	// A list inside the logs is refused.
	inside := filepath.Join(logs, "known-good.yml")
	os.WriteFile(inside, []byte("version: 1\nentries: []\n"), 0o600)
	if got := runAt(t, time.Now(), "detect", "--output", filepath.Join(t.TempDir(), "x"), "--known-good", inside, logs); got.code != exitFailed || !strings.Contains(got.stderr, "inside the evidence") {
		t.Errorf("a list inside the logs: %d %s", got.code, got.stderr)
	}
}
