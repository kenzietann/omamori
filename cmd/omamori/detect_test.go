package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type detectRun struct {
	code           int
	stdout, stderr string
}

func runAt(t *testing.T, now time.Time, args ...string) detectRun {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, environment{
		stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" },
		home: homeAt(t.TempDir()), now: func() time.Time { return now },
	})

	return detectRun{code, stdout.String(), stderr.String()}
}

var detectNow = time.Date(2026, 11, 11, 3, 4, 5, 0, time.UTC)

func TestSplitFlagsPreservesTheDelimiter(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		paths     []string
		output    string
		benign    bool
		wantError bool
	}{
		{"mixed arguments", []string{"a.log", "--output", "reports", "b.log", "--benign"}, []string{"a.log", "b.log"}, "reports", true, false},
		{"delimiter first", []string{"--", "-a.log", "-b.log", "--benign"}, []string{"-a.log", "-b.log", "--benign"}, "", false, false},
		{"delimiter after flags", []string{"a.log", "--output=reports", "--", "-b.log", "--benign"}, []string{"a.log", "-b.log", "--benign"}, "reports", false, false},
		{"delimiter as a flag value", []string{"--output", "--", "a.log", "--benign"}, []string{"a.log"}, "--", true, false},
		{"boolean with an explicit value", []string{"--benign=false", "a.log"}, []string{"a.log"}, "", false, false},
		{"missing value", []string{"a.log", "--output"}, nil, "", false, true},
		{"unknown flag", []string{"a.log", "--unknown"}, nil, "", false, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			output := flags.String("output", "", "output folder")
			benign := flags.Bool("benign", false, "benign scenario")
			got, err := splitFlags(flags, testCase.args)
			if testCase.wantError {
				if err == nil {
					t.Fatal("invalid flags were accepted")
				}
				return
			}
			if err != nil || !slices.Equal(got, testCase.paths) || *output != testCase.output || *benign != testCase.benign {
				t.Fatalf("paths %q, output %q, benign %v, error %v", got, *output, *benign, err)
			}
		})
	}
}

func snapshot(t *testing.T, folder string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(folder, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		files[path] = string(data)

		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	return files
}

func TestScenarioThenDetect(t *testing.T) {
	base := t.TempDir()
	logs, output := filepath.Join(base, "logs"), filepath.Join(base, "out")

	made := runAt(t, detectNow, "scenario", "--seed", "3", "--date", "2026-11-10", "--timezone", "Asia/Tokyo", logs)
	if made.code != exitOK {
		t.Fatalf("scenario: %d %s", made.code, made.stderr)
	}
	before := snapshot(t, logs)
	if len(before) != 3 {
		t.Fatalf("the scenario wrote %d files", len(before))
	}
	var expected struct {
		Alerts []struct{ Rule, Who string } `json:"expected_alerts"`
		Misses []string                     `json:"known_misses"`
	}
	if err := json.Unmarshal([]byte(before[filepath.Join(logs, "expected.json")]), &expected); err != nil || len(expected.Alerts) != 12 || len(expected.Misses) != 1 {
		t.Fatalf("expected.json: %v, %d alerts, %d misses", err, len(expected.Alerts), len(expected.Misses))
	}

	found := runAt(t, detectNow, "detect", logs, "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output)
	if found.code != exitOK {
		t.Fatalf("detect: %d %s", found.code, found.stderr)
	}
	if !strings.Contains(found.stdout, "Read 2 files and 1254 events. 26 rules. 14 alerts, 1 critical, 5 high, 8 medium.") {
		t.Errorf("the summary is %q", found.stdout)
	}

	folder := filepath.Join(output, "detect-20261111-030405")
	report, err := os.ReadFile(filepath.Join(folder, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := os.ReadFile(filepath.Join(folder, "report.html"))
	alerts, _ := os.ReadFile(filepath.Join(folder, "alerts.json"))
	if !strings.Contains(string(report), "SSH login succeeded after password guessing | src_ip=203.0.113.9") ||
		!strings.Contains(string(page), "<td>critical</td>") || !strings.Contains(string(page), "default-src 'none'") {
		t.Error("the reports do not show the critical alert")
	}
	for _, wanted := range expected.Alerts {
		if !strings.Contains(string(alerts), `"rule": "`+wanted.Rule+`"`) {
			t.Errorf("alerts.json does not have %s", wanted.Rule)
		}
	}
	// expected.json is JSON without a time, so it is tried and skipped. It must be said, not hidden.
	if !strings.Contains(string(report), "expected.json: the format was not recognized") {
		t.Error("the report does not name the file that was skipped")
	}

	after := snapshot(t, logs)
	if len(after) != len(before) {
		t.Fatal("the run changed the number of files in the logs folder")
	}
	for path, text := range before {
		if after[path] != text {
			t.Fatalf("%s was changed", path)
		}
	}

	again := runAt(t, detectNow, "detect", logs, "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output)
	if again.code != exitFailed || !strings.Contains(again.stderr, "exists already") {
		t.Errorf("a second run in the same second gave %d %q", again.code, again.stderr)
	}
	if now, _ := os.ReadFile(filepath.Join(folder, "report.md")); string(now) != string(report) {
		t.Error("the first report was changed")
	}
}

func TestDetectRefusals(t *testing.T) {
	base := t.TempDir()
	logs := filepath.Join(base, "logs")
	if made := runAt(t, detectNow, "scenario", logs); made.code != exitOK {
		t.Fatal(made.stderr)
	}
	empty := filepath.Join(base, "empty")
	badRules := filepath.Join(base, "rules")
	for _, folder := range []string{empty, badRules} {
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(badRules, "r.yml"), []byte("title: T\ndetection:\n  s: {a|unknownmodifier: b}\n  condition: s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(base, "out")

	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no logs", []string{"detect"}, exitUsage, "usage: omamori detect"},
		{"unknown flag", []string{"detect", "--speed", "9", logs}, exitUsage, "usage: omamori detect"},
		{"missing log", []string{"detect", filepath.Join(base, "nothing.log"), "--output", output}, exitFailed, "cannot be read"},
		{"unknown format", []string{"detect", "--format", "xml", logs, "--output", output}, exitFailed, "format is not known"},
		{"unknown time zone", []string{"detect", "--timezone", "Mars/Olympus", logs, "--output", output}, exitFailed, "time zone"},
		{"report folder inside the logs", []string{"detect", logs, "--output", filepath.Join(logs, "out")}, exitFailed, "must not be inside the logs"},
		{"paths with .. in them are still usable", []string{"detect", filepath.Join(base, "detect-20261111-030405", "..", "logs"), "--output", base + "/logs/.."}, exitOK, ""},
		{"folder without logs", []string{"detect", empty, "--output", output}, exitFailed, "no log file could be read"},
		{"rules folder with a bad rule", []string{"detect", "--rules", badRules, logs, "--output", output}, exitFailed, "modifier"},
		{"rules folder without rules", []string{"detect", "--rules", empty, logs, "--output", output}, exitFailed, "no rule"},
		{"rules folder that is missing", []string{"detect", "--rules", filepath.Join(base, "none"), logs, "--output", output}, exitFailed, "cannot be read"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := runAt(t, detectNow, testCase.args...)
			if got.code != testCase.code || !strings.Contains(got.stderr, testCase.want) {
				t.Fatalf("code %d, stderr %q", got.code, got.stderr)
			}
		})
	}

	if _, err := os.Stat(output); err == nil {
		entries, _ := os.ReadDir(output)
		t.Fatalf("refused runs left %d entries in the output folder", len(entries))
	}
}

func TestDetectWithRulesFromAFolder(t *testing.T) {
	base := t.TempDir()
	logs, rulesFolder, output := filepath.Join(base, "logs"), filepath.Join(base, "rules"), filepath.Join(base, "out")
	if made := runAt(t, detectNow, "scenario", "--benign", "--date", "2026-11-10", "--timezone", "Asia/Tokyo", logs); made.code != exitOK {
		t.Fatal(made.stderr)
	}
	if err := os.Mkdir(rulesFolder, 0o700); err != nil {
		t.Fatal(err)
	}
	rule := "title: Health check seen\nid: 11111111-2222-3333-4444-555555555555\nlevel: low\nlogsource:\n  category: webserver\n" +
		"detection:\n  selection:\n    cs-uri-stem|endswith: '/healthz'\n    sc-status: 200\n  condition: selection\n---\n" +
		"title: Many health checks\nlevel: informational\ncorrelation:\n  type: event_count\n  rules:\n    - 11111111-2222-3333-4444-555555555555\n  group-by:\n    - c-ip\n  timespan: 1h\n  condition:\n    gte: 10\n"
	if err := os.WriteFile(filepath.Join(rulesFolder, "health.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}

	got := runAt(t, detectNow, "detect", "--rules", rulesFolder, "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output, logs)
	if got.code != exitOK || !strings.Contains(got.stdout, "2 rules. 1 alerts, 1 informational.") {
		t.Fatalf("code %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
	}
}

func TestDetectReportsAnUnusableOutputFolder(t *testing.T) {
	base := t.TempDir()
	logs, output := filepath.Join(base, "logs"), filepath.Join(base, "output")
	if made := runAt(t, detectNow, "scenario", logs); made.code != exitOK {
		t.Fatal(made.stderr)
	}
	if err := os.WriteFile(output, []byte("keep this file"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, logs)
	got := runAt(t, detectNow, "detect", logs, "--output", output)
	if got.code != exitFailed || !strings.Contains(got.stderr, "output folder is not usable") || got.stdout != "" {
		t.Fatalf("code %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
	}
	if content, err := os.ReadFile(output); err != nil || string(content) != "keep this file" {
		t.Fatal("the file blocking the output folder was changed")
	}
	after := snapshot(t, logs)
	if len(after) != len(before) {
		t.Fatal("the failed run changed the input files")
	}
	for path, content := range before {
		if after[path] != content {
			t.Fatalf("the failed run changed %s", path)
		}
	}
}

func TestScenarioRefusals(t *testing.T) {
	existing := t.TempDir()
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no folder", []string{"scenario"}, exitUsage, "usage: omamori scenario"},
		{"folder that exists", []string{"scenario", existing}, exitFailed, "exists already"},
		{"bad date", []string{"scenario", "--date", "tomorrow", filepath.Join(existing, "a")}, exitFailed, "date"},
		{"bad seed", []string{"scenario", "--seed", "x", filepath.Join(existing, "b")}, exitUsage, "usage"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := runAt(t, detectNow, testCase.args...)
			if got.code != testCase.code || !strings.Contains(got.stderr, testCase.want) {
				t.Fatalf("code %d, stderr %q", got.code, got.stderr)
			}
		})
	}
	if entries, _ := os.ReadDir(existing); len(entries) != 0 {
		t.Fatal("a refused scenario wrote something")
	}
}

func TestScenarioSuggestedCommandKeepsItsTimezoneAndPath(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "day's logs $HOME `false`")
	got := runAt(t, detectNow, "scenario", "--date", "2026-11-10", "--timezone", "America/New_York", directory)
	if got.code != exitOK {
		t.Fatal(got.stderr)
	}
	want := "Try: omamori detect --year 2026 --timezone 'America/New_York' -- '" + filepath.Join(base, "day") + "'\\''s logs $HOME `false`'\n"
	if !strings.Contains(got.stdout, want) {
		t.Fatalf("suggested command lost the timezone or literal path: %q", got.stdout)
	}
}

func TestHelpNamesTheNewCommands(t *testing.T) {
	got := runAt(t, detectNow, "help")
	for _, want := range []string{"detect <logs>...", "scenario <folder>", "--rules folder"} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("help does not have %q", want)
		}
	}
}

func TestCampaignScenarioThenDetect(t *testing.T) {
	base := t.TempDir()
	campaign, output := filepath.Join(base, "campaign"), filepath.Join(base, "out")
	made := runAt(t, detectNow, "scenario", "--campaign", "--seed", "3", "--date", "2026-11-10", "--timezone", "Asia/Tokyo", campaign)
	if made.code != exitOK || !strings.Contains(made.stdout, "Wrote 6 log files of three hosts and two network sensors") {
		t.Fatalf("scenario --campaign: %d %s %s", made.code, made.stdout, made.stderr)
	}
	text, err := os.ReadFile(filepath.Join(campaign, "expected.json"))
	var expected struct {
		Story  []string                     `json:"story"`
		Alerts []struct{ Rule, Who string } `json:"expected_alerts"`
		Misses []string                     `json:"known_misses"`
	}
	if err != nil || json.Unmarshal(text, &expected) != nil || len(expected.Alerts) != 17 || len(expected.Misses) != 3 || len(expected.Story) != 7 {
		t.Fatalf("expected.json: %v, %d alerts, %d misses, %d steps", err, len(expected.Alerts), len(expected.Misses), len(expected.Story))
	}
	before := snapshot(t, campaign)

	found := runAt(t, detectNow, "detect", filepath.Join(campaign, "logs"), "--year", "2026", "--timezone", "Asia/Tokyo", "--output", output)
	if found.code != exitOK || !strings.Contains(found.stdout, "Read 6 files and ") || !strings.Contains(found.stdout, "26 rules. 19 alerts, 2 critical, 9 high, 8 medium.") {
		t.Fatalf("detect: %d %s %s", found.code, found.stdout, found.stderr)
	}
	alerts, _ := os.ReadFile(filepath.Join(output, "detect-20261111-030405", "alerts.json"))
	for _, wanted := range expected.Alerts {
		if !strings.Contains(string(alerts), `"rule": "`+wanted.Rule+`"`) {
			t.Errorf("alerts.json does not have %s", wanted.Rule)
		}
	}
	after := snapshot(t, campaign)
	for path, state := range before {
		if after[path] != state {
			t.Fatalf("%s was changed", path)
		}
	}

	both := runAt(t, detectNow, "scenario", "--campaign", "--host", filepath.Join(base, "x"))
	if both.code != exitUsage {
		t.Fatalf("--campaign with --host gave %d", both.code)
	}
	quiet := filepath.Join(base, "quiet")
	if made := runAt(t, detectNow, "scenario", "--campaign", "--benign", "--date", "2026-11-10", "--timezone", "Asia/Tokyo", quiet); made.code != exitOK {
		t.Fatal(made.stderr)
	}
	calm := runAt(t, detectNow, "detect", filepath.Join(quiet, "logs"), "--year", "2026", "--timezone", "Asia/Tokyo", "--output", filepath.Join(base, "out2"))
	if calm.code != exitOK || !strings.Contains(calm.stdout, "26 rules. 0 alerts.") {
		t.Fatalf("the quiet campaign: %d %s", calm.code, calm.stdout)
	}
}
