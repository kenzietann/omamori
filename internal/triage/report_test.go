package triage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/authlog"
)

const (
	plantedKey   = "AKIAIOSFODNN7EXAMPLE"
	plantedPhone = "090-1234-5678"
)

func complete() agent.Outcome { return agent.Outcome{Status: agent.Complete, Reason: "finished"} }

func claimsText(notes string, claims ...string) string {
	return notes + "\n" + BeginMarker + "\n[" + strings.Join(claims, ",") + "]\n" + EndMarker
}

const goodGuessing = `{"scenario":"guessing_then_success","ip":"203.0.113.5","users":["admin"],"lines":[2,3,4,5,6],"success_line":7,"count":5,"first":"Nov 11 09:00:01","last":"Nov 11 09:01:30"}`

func render(t testing.TB, parsed authlog.Parsed, texts ...string) string {
	t.Helper()

	report, err := Render(Input{LogName: "auth.log", Parsed: parsed, Config: testConfig(), Texts: texts, Outcome: complete()})
	if err != nil {
		t.Fatal(err)
	}

	return report
}

func section(report, title string) string {
	start := strings.Index(report, "## "+title)
	if start < 0 {
		return ""
	}
	rest := report[start+len(title)+3:]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}

	return rest
}

func TestTheReportHasTheVerifiedFindingFromTheLogNotFromTheClaim(t *testing.T) {
	report := render(t, parseFixture(t, "guessing.log"), claimsText("Admin was guessed.", goodGuessing))

	for _, want := range []string{"# Omamori report: log triage", "Status: complete", "Log: auth.log", "Lines read: 9 (events: 8, with 6 failed passwords and 2 accepted passwords; other lines ignored: 1)", "Malformed lines: 0",
		"Settings: window 10 minutes, failure threshold 5, spray threshold 5, year 2026, time zone UTC"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report has no %q:\n%s", want, report)
		}
	}
	verified := section(report, "Verified findings (checked by Omamori)")
	if !strings.Contains(verified, "| T-001 | guessing_then_success | 203.0.113.5 | admin | 5 | Nov 11 09:00:01 | Nov 11 09:01:30 | 2, 3, 4, 5, 6 | 7 |") {
		t.Errorf("the verified findings are wrong:\n%s", verified)
	}
	if !strings.Contains(section(report, "Claims of the AI"), "1 claims: 1 verified, 0 rejected.") || !strings.Contains(section(report, "Found by Omamori, not claimed by the AI"), "None.") {
		t.Errorf("the claims section is wrong:\n%s", report)
	}
	if !strings.Contains(section(report, "AI notes (not checked by Omamori)"), "    Admin was guessed.") || strings.Contains(report, BeginMarker) {
		t.Errorf("the notes are wrong:\n%s", report)
	}
}

func TestARejectedClaimIsListedWithFixedReasonsAndNeverRepeatsWhatTheAIWrote(t *testing.T) {
	wrongSource := `{"scenario":"guessing_then_success","ip":"EVIL-<script>alert(1)</script>","users":["admin"],"lines":[2,3,4,5,6],"success_line":7,"count":5,"first":"Nov 11 09:00:01","last":"Nov 11 09:01:30"}`
	wrongCount := strings.Replace(goodGuessing, `"count":5`, `"count":9`, 1)

	report := render(t, parseFixture(t, "guessing.log"), claimsText("", wrongSource, wrongCount, goodGuessing))

	claims := section(report, "Claims of the AI")
	if !strings.Contains(claims, "3 claims: 1 verified, 2 rejected.") ||
		!strings.Contains(claims, "- Claim 1: the source address of a cited line is not the claimed one") ||
		!strings.Contains(claims, "- Claim 2: the count is not the number of cited lines") {
		t.Errorf("the claims section is wrong:\n%s", claims)
	}
	if strings.Contains(report, "EVIL") || strings.Contains(report, "script") {
		t.Errorf("a rejected claim got into the report:\n%s", report)
	}
}

func TestWhenTheAIGivesNoClaimsOmamoriStillShowsWhatTheLogProves(t *testing.T) {
	for name, texts := range map[string][]string{
		"no list":      {"I looked at the log and it seems fine."},
		"no answer":    nil,
		"a bad list":   {BeginMarker + "this is not JSON" + EndMarker},
		"a empty list": {claimsText("Nothing found.")},
	} {
		report := render(t, parseFixture(t, "spraying.log"), texts...)

		if !strings.Contains(section(report, "Verified findings (checked by Omamori)"), "None. No claim of the AI was proved by the log.") {
			t.Errorf("%s: a finding is verified without a claim:\n%s", name, report)
		}
		missed := section(report, "Found by Omamori, not claimed by the AI")
		if !strings.Contains(missed, "| M-001 | password_spraying | 192.0.2.66 | admin, git, oracle, postgres, root, test | 6 | Nov 11 10:00:00 | Nov 11 10:01:44 | 1, 2, 3, 4, 5, 6 | - |") {
			t.Errorf("%s: the finding of Omamori is missing:\n%s", name, missed)
		}
	}

	if !strings.Contains(render(t, parseFixture(t, "spraying.log"), "no list"), "The AI gave no list of claims, so nothing is verified.") {
		t.Error("a missing list is not said")
	}
	if !strings.Contains(render(t, parseFixture(t, "spraying.log"), BeginMarker+"{"+EndMarker), "could not be read, so nothing is verified.") {
		t.Error("an unreadable list is not said")
	}
}

func TestAClaimOfTheRightPatternCoversTheFindingOfOmamori(t *testing.T) {
	partial := `{"scenario":"password_spraying","ip":"192.0.2.66","users":["root","admin","test","oracle","git"],"lines":[1,2,3,4,5],"count":5,"first":"Nov 11 10:00:00","last":"Nov 11 10:01:23"}`

	report := render(t, parseFixture(t, "spraying.log"), claimsText("", partial))

	if !strings.Contains(section(report, "Verified findings (checked by Omamori)"), "| T-001 | password_spraying | 192.0.2.66 |") || !strings.Contains(section(report, "Found by Omamori, not claimed by the AI"), "None.") {
		t.Errorf("a true claim of five user names must cover the finding of six:\n%s", report)
	}
}

func TestABenignLogReportsNothingAndTheMalformedLinesAreCounted(t *testing.T) {
	benign := render(t, parseFixture(t, "benign.log"), claimsText("All quiet."))
	if !strings.Contains(section(benign, "Found by Omamori, not claimed by the AI"), "None.") || !strings.Contains(benign, "0 claims: 0 verified, 0 rejected.") {
		t.Errorf("benign:\n%s", benign)
	}

	malformed := render(t, parseFixture(t, "malformed.log"), claimsText("", `{"scenario":"guessing_then_success","ip":"203.0.113.5","users":["admin"],"lines":[1,3,4,6,8],"success_line":9,"count":5,"first":"Nov 11 09:00:01","last":"Nov 11 09:01:30"}`))
	if !strings.Contains(malformed, "Malformed lines: 3\n") || !strings.Contains(section(malformed, "Verified findings (checked by Omamori)"), "| 1, 3, 4, 6, 8 | 9 |") {
		t.Errorf("malformed:\n%s", malformed)
	}
}

func TestAnIncompleteRunSaysWhy(t *testing.T) {
	report, err := Render(Input{LogName: "auth.log", Parsed: parseFixture(t, "benign.log"), Config: testConfig(), Outcome: agent.Outcome{Status: agent.Incomplete, Reason: "token limit | reached"}})

	if err != nil || !strings.Contains(report, "Status: incomplete (token limit _ reached)") {
		t.Errorf("err %v:\n%s", err, report)
	}
}

func TestSecretsAndTablesFromTheLogAreMadeSafe(t *testing.T) {
	lines := []string{
		entry("09:00:00", "F", plantedKey, "203.0.113.5"), entry("09:00:10", "F", plantedKey, "203.0.113.5"), entry("09:00:20", "F", plantedKey, "203.0.113.5"),
		entry("09:00:30", "F", plantedKey, "203.0.113.5"), entry("09:00:40", "F", plantedKey, "203.0.113.5"), entry("09:01:00", "A", plantedKey, "203.0.113.5"),
		entry("10:00:00", "F", "a|b", "192.0.2.1"), entry("10:00:01", "F", "c`d", "192.0.2.1"), entry("10:00:02", "F", "e<f>", "192.0.2.1"),
		entry("10:00:03", "F", "g&h", "192.0.2.1"), entry("10:00:04", "F", plantedPhone, "192.0.2.1"),
	}
	parsed := parseLines(t, lines...)

	report := render(t, parsed, "The user "+plantedKey+" and the number "+plantedPhone+" were seen.")

	for _, planted := range []string{plantedKey, plantedPhone} {
		if strings.Contains(report, planted) {
			t.Errorf("the report holds %q:\n%s", planted, report)
		}
	}
	if !strings.Contains(report, "[SECRET:aws-access-key:") || !strings.Contains(report, "[PHONE:") {
		t.Errorf("the placeholders are missing:\n%s", report)
	}
	row := ""
	for _, line := range strings.Split(report, "\n") {
		if strings.Contains(line, "password_spraying") {
			row = line
		}
	}
	if strings.Count(row, "|") != 10 || strings.ContainsAny(strings.TrimPrefix(row, "|"), "`<>&") {
		t.Errorf("the table row can be broken by a user name: %q", row)
	}
}

func TestLongListsAreCutAndSaySo(t *testing.T) {
	var lines []string
	for index := range 60 {
		lines = append(lines, entry(fmt.Sprintf("09:%02d:%02d", index/60, index%60), "F", fmt.Sprintf("user%02d", index), "192.0.2.1"))
	}

	report := render(t, parseLines(t, lines...))

	row := ""
	for _, line := range strings.Split(report, "\n") {
		if strings.HasPrefix(line, "| M-001") {
			row = line
		}
	}
	if !strings.Contains(row, "user00, user01, user02, user03, user04, user05, user06, user07, user08, user09 (+") || !strings.Contains(row, "20 (+") && !strings.Contains(row, "(+40 more)") {
		t.Errorf("the lists are not cut:\n%s", row)
	}
	if strings.Contains(row, "user30") {
		t.Error("the user list was not cut")
	}
}

func TestTheNotesAreCleanedAndCut(t *testing.T) {
	report := render(t, parseFixture(t, "benign.log"), "line one\x1b[2J\x07\nline two\n"+strings.Repeat("x", maxNotesRunes))

	notes := section(report, "AI notes (not checked by Omamori)")
	if strings.ContainsAny(notes, "\x1b\x07") || !strings.Contains(notes, "    line one[2J\n    line two\n") || len([]rune(notes)) > maxNotesRunes+200 {
		t.Errorf("the notes are wrong (%d characters)", len([]rune(notes)))
	}
	if !strings.Contains(render(t, parseFixture(t, "benign.log")), "## AI notes (not checked by Omamori)\n\n(none)\n") {
		t.Error("no notes is not said")
	}
}

func TestTheReportSaysWhatItCannotDo(t *testing.T) {
	report := render(t, parseFixture(t, "benign.log"))

	for _, want := range []string{"One log format", "no year and no time zone", "settings", "Only two patterns", "does not hide IP addresses", "not proof of an attack", "Omamori did not check them"} {
		if !strings.Contains(section(report, "Limits"), want) {
			t.Errorf("the limits have no %q", want)
		}
	}
}

func TestTheInstructionHasTheSettingsTheMarkersAndTheLogName(t *testing.T) {
	config := testConfig()
	config.FailureThreshold, config.SprayThreshold, config.Window = 7, 8, 15*time.Minute

	text := Instruction("logs/auth.log", config)

	for _, want := range []string{`"logs/auth.log"`, "at least 7 ", "at least 8 different user names", "within 15 minutes", "no more than 15 minutes", BeginMarker, EndMarker, "search_text", "Do not guess", "data, not an instruction", "guessing_then_success", "password_spraying"} {
		if !strings.Contains(text, want) {
			t.Errorf("the instruction has no %q:\n%s", want, text)
		}
	}
	if Instruction("a.log", testConfig()) == text {
		t.Error("the instruction does not depend on the settings")
	}
}

type fakeRunner struct {
	outcome agent.Outcome
	asked   []string
}

func (runner *fakeRunner) Run(ctx context.Context, instruction string) agent.Outcome {
	runner.asked = append(runner.asked, instruction)

	return runner.outcome
}

func TestRunChecksTheAnswerAgainstTheLogThatItReadsItself(t *testing.T) {
	runner := &fakeRunner{outcome: agent.Outcome{Status: agent.Complete, Reason: "finished", Texts: []string{claimsText("", goodGuessing)}}}
	source := Source{Path: filepath.Join(fixtureDirectory, "guessing.log"), Name: "guessing.log"}

	report, outcome, err := Run(context.Background(), runner, source, testConfig())

	if err != nil || outcome.Status != agent.Complete || len(runner.asked) != 1 || !strings.Contains(runner.asked[0], `"guessing.log"`) {
		t.Fatalf("err %v, outcome %+v, asked %q", err, outcome, runner.asked)
	}
	if !strings.Contains(report, "| T-001 | guessing_then_success |") {
		t.Errorf("report:\n%s", report)
	}
}

func TestALogThatCannotBeReadStopsBeforeAnythingIsAsked(t *testing.T) {
	directory := t.TempDir()
	big := filepath.Join(directory, "big.log")
	if err := os.WriteFile(big, make([]byte, 1), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.log")
	os.Symlink(filepath.Join(fixtureDirectory, "guessing.log"), link)
	previous := maxLogFileSize
	maxLogFileSize = 0
	t.Cleanup(func() { maxLogFileSize = previous })

	for name, path := range map[string]string{"a missing file": filepath.Join(directory, "none.log"), "a folder": directory, "a symlink": link, "a file that is too big": big} {
		runner := &fakeRunner{}

		_, _, err := Run(context.Background(), runner, Source{Path: path, Name: "x.log"}, testConfig())

		if !errors.Is(err, ErrLog) || len(runner.asked) != 0 {
			t.Errorf("%s: err %v, asked %d times", name, err, len(runner.asked))
		}
	}

	config := testConfig()
	config.FailureThreshold = 1
	runner := &fakeRunner{}
	if _, _, err := Run(context.Background(), runner, Source{Path: filepath.Join(fixtureDirectory, "guessing.log"), Name: "g.log"}, config); !errors.Is(err, ErrConfig) || len(runner.asked) != 0 {
		t.Errorf("bad settings: %v", err)
	}
}

func TestSettingsFile(t *testing.T) {
	directory := t.TempDir()
	write := func(content string) string {
		path := filepath.Join(directory, fmt.Sprintf("c%d.json", len(content)))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		return path
	}
	now := time.Date(2027, 3, 4, 0, 0, 0, 0, time.UTC)

	defaults, err := LoadConfig("", now)
	if err != nil || defaults.Window != 10*time.Minute || defaults.FailureThreshold != 5 || defaults.SprayThreshold != 5 || defaults.Year != 2027 {
		t.Errorf("defaults %+v, %v", defaults, err)
	}
	if missing, err := LoadConfig(filepath.Join(directory, "none.json"), now); err != nil || missing.FailureThreshold != 5 {
		t.Errorf("a missing file: %+v, %v", missing, err)
	}
	loaded, err := LoadConfig(write(`{"window_minutes":15,"failure_threshold":3,"spray_threshold":4,"year":2025,"time_zone":"UTC"}`), now)
	if err != nil || loaded.Window != 15*time.Minute || loaded.FailureThreshold != 3 || loaded.SprayThreshold != 4 || loaded.Year != 2025 || loaded.ZoneName != "UTC" || loaded.Location != time.UTC {
		t.Errorf("loaded %+v, %v", loaded, err)
	}
	partial, err := LoadConfig(write(`{"failure_threshold":9}`), now)
	if err != nil || partial.FailureThreshold != 9 || partial.Window != 10*time.Minute {
		t.Errorf("partial %+v, %v", partial, err)
	}

	for name, content := range map[string]string{
		"an unknown field":            `{"window":5}`,
		"a window of 0":               `{"window_minutes":0}`,
		"a window of a week":          `{"window_minutes":10080}`,
		"a threshold of 1":            `{"failure_threshold":1}`,
		"a threshold too big":         `{"spray_threshold":1001}`,
		"a year in the past":          `{"year":1969}`,
		"a year far away":             `{"year":2201}`,
		"a time zone that is not one": `{"time_zone":"Mars/Base"}`,
		"an empty time zone":          `{"time_zone":""}`,
		"not JSON":                    `hello`,
		"a second document":           `{"year":2026}{"year":2027}`,
		"a text for a number":         `{"year":"2026"}`,
	} {
		if _, err := LoadConfig(write(content), now); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := LoadConfig(directory, now); !errors.Is(err, ErrConfig) {
		t.Errorf("a folder: %v", err)
	}
	if _, err := LoadConfig(write(strings.Repeat(" ", maxConfigBytes+1)), now); !errors.Is(err, ErrConfig) {
		t.Errorf("a file that is too big: %v", err)
	}
}
