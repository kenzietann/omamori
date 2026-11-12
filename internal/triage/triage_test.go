package triage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/authlog"
)

const fixtureDirectory = "../../testdata/fixtures/triage"

func testConfig() Config {
	return Config{Window: 10 * time.Minute, FailureThreshold: 5, SprayThreshold: 5, Year: 2026, Location: time.UTC, ZoneName: "UTC"}
}

func entry(clock, kind, user, ip string) string {
	text := "Failed password for " + user
	if kind == "A" {
		text = "Accepted password for " + user
	}

	return fmt.Sprintf("Nov 11 %s web sshd[1]: %s from %s port 22 ssh2", clock, text, ip)
}

func parseLines(t testing.TB, lines ...string) authlog.Parsed {
	t.Helper()

	parsed, err := authlog.Parse(strings.NewReader(strings.Join(lines, "\n")+"\n"), 2026, time.UTC)
	if err != nil {
		t.Fatal(err)
	}

	return parsed
}

type expectedFinding struct {
	Scenario    string   `json:"scenario"`
	IP          string   `json:"ip"`
	Users       []string `json:"users"`
	Lines       []int    `json:"lines"`
	SuccessLine int      `json:"success_line"`
	Count       int      `json:"count"`
	First       string   `json:"first"`
	Last        string   `json:"last"`
}

func loadExpected(t testing.TB) (map[string][]expectedFinding, map[string]int) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(fixtureDirectory, "expected_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	findings := map[string][]expectedFinding{}
	var malformed map[string]int
	for name, value := range raw {
		switch name {
		case "year":
		case "malformed_lines":
			if err := json.Unmarshal(value, &malformed); err != nil {
				t.Fatal(err)
			}
		default:
			var list []expectedFinding
			if err := json.Unmarshal(value, &list); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			findings[name] = list
		}
	}

	return findings, malformed
}

func parseFixture(t testing.TB, name string) authlog.Parsed {
	t.Helper()

	file, err := os.Open(filepath.Join(fixtureDirectory, name))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := authlog.Parse(file, 2026, time.UTC)
	if err != nil {
		t.Fatal(err)
	}

	return parsed
}

func TestTheFixturesGiveTheExpectedFindingsWithTheRightLines(t *testing.T) {
	expected, malformed := loadExpected(t)

	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			parsed := parseFixture(t, name)

			got := Detect(parsed, testConfig())

			if len(got) != len(want) {
				t.Fatalf("%d findings, want %d: %+v", len(got), len(want), got)
			}
			for index, finding := range got {
				wanted := want[index]
				if finding.Scenario != wanted.Scenario || finding.IP != wanted.IP || !slices.Equal(finding.Users, wanted.Users) || !slices.Equal(finding.FailureLines, wanted.Lines) ||
					finding.SuccessLine != wanted.SuccessLine || finding.Count != wanted.Count || finding.FirstStamp != wanted.First || finding.LastStamp != wanted.Last {
					t.Errorf("finding %d = %+v, want %+v", index, finding, wanted)
				}
			}
			if parsed.Malformed != malformed[name] {
				t.Errorf("%d malformed lines, want %d", parsed.Malformed, malformed[name])
			}
		})
	}
}

func TestTheExpectedFindingsAreVerifiedWhenTheAIClaimsThemExactly(t *testing.T) {
	expected, _ := loadExpected(t)

	for name, list := range expected {
		parsed := parseFixture(t, name)
		checker := NewChecker(parsed, testConfig())
		for _, wanted := range list {
			claim := Claim{Scenario: wanted.Scenario, IP: wanted.IP, Users: wanted.Users, Lines: wanted.Lines, SuccessLine: wanted.SuccessLine, Count: wanted.Count, First: wanted.First, Last: wanted.Last}

			if verdict := checker.Check(claim); !verdict.Verified {
				t.Errorf("%s: the right claim is rejected: %q", name, verdict.Reasons)
			}
		}
	}
}

func TestGuessingNeedsFiveFailuresInTheWindowAndASuccessThatFollows(t *testing.T) {
	failures := func(clocks ...string) []string {
		var lines []string
		for _, clock := range clocks {
			lines = append(lines, entry(clock, "F", "admin", "203.0.113.5"))
		}

		return lines
	}
	testCases := []struct {
		name  string
		lines []string
		want  int
	}{
		{"five failures then a success", append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"), entry("09:01:00", "A", "admin", "203.0.113.5")), 1},
		{"four failures are one below the threshold", append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30"), entry("09:01:00", "A", "admin", "203.0.113.5")), 0},
		{"five failures spanning exactly 10 minutes 0 seconds", append(failures("09:00:00", "09:02:30", "09:05:00", "09:07:30", "09:10:00"), entry("09:10:05", "A", "admin", "203.0.113.5")), 1},
		{"five failures spanning 10 minutes 1 second are just outside", append(failures("09:00:00", "09:02:30", "09:05:00", "09:07:30", "09:10:01"), entry("09:10:05", "A", "admin", "203.0.113.5")), 0},
		{"a success exactly 10 minutes after the last failure", append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"), entry("09:10:40", "A", "admin", "203.0.113.5")), 1},
		{"a success 10 minutes 1 second after the last failure", append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"), entry("09:10:41", "A", "admin", "203.0.113.5")), 0},
		{"a success from another address", append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"), entry("09:01:00", "A", "admin", "203.0.113.6")), 0},
		{"a success for another user name", append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"), entry("09:01:00", "A", "root", "203.0.113.5")), 0},
		{"a success before the failures", append([]string{entry("08:59:00", "A", "admin", "203.0.113.5")}, failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40")...), 0},
		{"failures and no success", failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"), 0},
		{"failures from five addresses are not one source", []string{
			entry("09:00:00", "F", "admin", "203.0.113.1"), entry("09:00:10", "F", "admin", "203.0.113.2"), entry("09:00:20", "F", "admin", "203.0.113.3"),
			entry("09:00:30", "F", "admin", "203.0.113.4"), entry("09:00:40", "F", "admin", "203.0.113.5"), entry("09:01:00", "A", "admin", "203.0.113.5")}, 0},
		{"failures for five user names are not one user", []string{
			entry("09:00:00", "F", "a", "203.0.113.5"), entry("09:00:10", "F", "b", "203.0.113.5"), entry("09:00:20", "F", "c", "203.0.113.5"),
			entry("09:00:30", "F", "d", "203.0.113.5"), entry("09:00:40", "F", "e", "203.0.113.5"), entry("09:01:00", "A", "e", "203.0.113.5")}, 0},
		{"a second success does not need new failures to be counted twice", append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"),
			entry("09:01:00", "A", "admin", "203.0.113.5"), entry("09:02:00", "A", "admin", "203.0.113.5")), 1},
		{"a later round of failures and a success is a second finding", append(append(failures("09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"),
			entry("09:01:00", "A", "admin", "203.0.113.5")), append(failures("11:00:00", "11:00:10", "11:00:20", "11:00:30", "11:00:40"), entry("11:01:00", "A", "admin", "203.0.113.5"))...), 2},
		{"six failures where the last five are in the window", append(failures("08:00:00", "09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40"), entry("09:01:00", "A", "admin", "203.0.113.5")), 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var guessing int
			for _, finding := range Detect(parseLines(t, testCase.lines...), testConfig()) {
				if finding.Scenario == GuessingThenSuccess {
					guessing++
				}
			}

			if guessing != testCase.want {
				t.Errorf("%d guessing findings, want %d", guessing, testCase.want)
			}
		})
	}
}

func TestTheGuessingFindingNamesTheCountedFailuresAndTheSuccess(t *testing.T) {
	parsed := parseLines(t,
		entry("08:00:00", "F", "admin", "203.0.113.5"),
		entry("09:00:00", "F", "admin", "203.0.113.5"), entry("09:00:10", "F", "admin", "203.0.113.5"), entry("09:00:20", "F", "admin", "203.0.113.5"),
		entry("09:00:30", "F", "admin", "203.0.113.5"), entry("09:00:40", "F", "admin", "203.0.113.5"), entry("09:01:00", "A", "admin", "203.0.113.5"))

	findings := Detect(parsed, testConfig())

	if len(findings) != 1 || !slices.Equal(findings[0].FailureLines, []int{2, 3, 4, 5, 6}) || findings[0].SuccessLine != 7 || findings[0].Count != 5 || findings[0].FirstStamp != "Nov 11 09:00:00" || findings[0].LastStamp != "Nov 11 09:00:40" {
		t.Errorf("%+v", findings)
	}
	if findings[0].Describe() != "5 failed passwords, then success on line 7" {
		t.Errorf("describe = %q", findings[0].Describe())
	}
}

func TestSprayingNeedsFiveDifferentUserNamesFromOneAddressInTheWindow(t *testing.T) {
	spray := func(ip string, clocks []string, users []string) []string {
		var lines []string
		for index, clock := range clocks {
			lines = append(lines, entry(clock, "F", users[index%len(users)], ip))
		}

		return lines
	}
	five := []string{"a", "b", "c", "d", "e"}
	testCases := []struct {
		name  string
		lines []string
		want  int
	}{
		{"five user names", spray("192.0.2.1", []string{"09:00:00", "09:01:00", "09:02:00", "09:03:00", "09:04:00"}, five), 1},
		{"four user names are one below the threshold", spray("192.0.2.1", []string{"09:00:00", "09:01:00", "09:02:00", "09:03:00", "09:04:00"}, []string{"a", "b", "c", "d"}), 0},
		{"exactly 10 minutes 0 seconds is inside", spray("192.0.2.1", []string{"09:00:00", "09:02:30", "09:05:00", "09:07:30", "09:10:00"}, five), 1},
		{"10 minutes 1 second is outside", spray("192.0.2.1", []string{"09:00:00", "09:02:30", "09:05:00", "09:07:30", "09:10:01"}, five), 0},
		{"one user name tried many times is not spraying", spray("192.0.2.1", []string{"09:00:00", "09:00:10", "09:00:20", "09:00:30", "09:00:40", "09:00:50"}, []string{"a"}), 0},
		{"user names from different addresses do not add up", append(
			spray("192.0.2.1", []string{"09:00:00", "09:00:10", "09:00:20"}, five), spray("192.0.2.2", []string{"09:00:30", "09:00:40", "09:00:50"}, []string{"d", "e", "f"})...), 0},
		{"an accepted password is not a failure", append(spray("192.0.2.1", []string{"09:00:00", "09:01:00", "09:02:00", "09:03:00"}, five), entry("09:04:00", "A", "e", "192.0.2.1")), 0},
		{"two separate rounds are two findings", append(
			spray("192.0.2.1", []string{"09:00:00", "09:01:00", "09:02:00", "09:03:00", "09:04:00"}, five), spray("192.0.2.1", []string{"12:00:00", "12:01:00", "12:02:00", "12:03:00", "12:04:00"}, five)...), 2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var spraying int
			for _, finding := range Detect(parseLines(t, testCase.lines...), testConfig()) {
				if finding.Scenario == PasswordSpraying {
					spraying++
				}
			}

			if spraying != testCase.want {
				t.Errorf("%d spraying findings, want %d", spraying, testCase.want)
			}
		})
	}
}

func TestTheNumbersAreSettings(t *testing.T) {
	lines := []string{entry("09:00:00", "F", "a", "192.0.2.1"), entry("09:01:00", "F", "b", "192.0.2.1"), entry("09:02:00", "F", "c", "192.0.2.1")}
	parsed := parseLines(t, lines...)

	if len(Detect(parsed, testConfig())) != 0 {
		t.Error("three user names are a finding with the default threshold")
	}
	config := testConfig()
	config.SprayThreshold = 3
	if found := Detect(parsed, config); len(found) != 1 {
		t.Errorf("with a threshold of 3: %+v", found)
	}
	config.Window = time.Minute
	if found := Detect(parsed, config); len(found) != 0 {
		t.Errorf("with a window of 1 minute: %+v", found)
	}
}

func TestEqualTimestampsGiveAStableOrderOfTheLines(t *testing.T) {
	parsed := parseFixture(t, "equal_times.log")

	first := Detect(parsed, testConfig())
	second := Detect(parseFixture(t, "equal_times.log"), testConfig())

	if len(first) != 1 || !slices.Equal(first[0].FailureLines, []int{1, 2, 3, 4, 5}) || first[0].SuccessLine != 6 || fmt.Sprint(first) != fmt.Sprint(second) {
		t.Errorf("%+v", first)
	}

	before := parseLines(t, entry("09:00:00", "A", "root", "203.0.113.9"), entry("09:00:00", "F", "root", "203.0.113.9"), entry("09:00:00", "F", "root", "203.0.113.9"),
		entry("09:00:00", "F", "root", "203.0.113.9"), entry("09:00:00", "F", "root", "203.0.113.9"), entry("09:00:00", "F", "root", "203.0.113.9"))
	if found := Detect(before, testConfig()); len(found) != 0 {
		t.Errorf("a success that is listed before the failures at the same second is not 'followed by': %+v", found)
	}
}

func TestABenignLogGivesNoFinding(t *testing.T) {
	if found := Detect(parseFixture(t, "benign.log"), testConfig()); len(found) != 0 {
		t.Errorf("%+v", found)
	}
}

func TestAClaimIsRejectedWhenTheLogDoesNotProveIt(t *testing.T) {
	parsed := parseFixture(t, "guessing.log")
	checker := NewChecker(parsed, testConfig())
	good := Claim{Scenario: GuessingThenSuccess, IP: "203.0.113.5", Users: []string{"admin"}, Lines: []int{2, 3, 4, 5, 6}, SuccessLine: 7, Count: 5, First: "Nov 11 09:00:01", Last: "Nov 11 09:01:30"}
	if verdict := checker.Check(good); !verdict.Verified {
		t.Fatalf("the good claim is rejected: %q", verdict.Reasons)
	}

	testCases := []struct {
		name   string
		change func(*Claim)
		reason string
	}{
		{"the wrong source address (the AI names B, the lines show A)", func(c *Claim) { c.IP = "203.0.113.6" }, "the source address of a cited line is not the claimed one"},
		{"another user name", func(c *Claim) { c.Users = []string{"root"} }, "the user names are not the ones of the cited lines"},
		{"one more user name", func(c *Claim) { c.Users = []string{"admin", "root"} }, "the user names are not the ones of the cited lines"},
		{"the same user name twice", func(c *Claim) { c.Users = []string{"admin", "admin"} }, "the user names are not the ones of the cited lines"},
		{"no user names", func(c *Claim) { c.Users = nil }, "the user names are not the ones of the cited lines"},
		{"a count that is too high", func(c *Claim) { c.Count = 6 }, "the count is not the number of cited lines"},
		{"a count that is too low", func(c *Claim) { c.Count = 4 }, "the count is not the number of cited lines"},
		{"line numbers that do not exist", func(c *Claim) { c.Lines = []int{2, 3, 4, 5, 60} }, "a cited line is not a failed or accepted password in the log"},
		{"a line number of 0", func(c *Claim) { c.Lines = []int{0, 3, 4, 5, 6} }, "a cited line is not a failed or accepted password in the log"},
		{"a negative line number", func(c *Claim) { c.Lines = []int{-1, 3, 4, 5, 6} }, "a cited line is not a failed or accepted password in the log"},
		{"a line that is a cron line", func(c *Claim) { c.Lines = []int{2, 3, 4, 5, 9} }, "a cited line is not a failed or accepted password in the log"},
		{"a line that is an accepted password among the failures", func(c *Claim) { c.Lines = []int{2, 3, 4, 5, 7} }, "a cited line is not a failed password"},
		{"a line cited twice", func(c *Claim) { c.Lines = []int{2, 3, 3, 4, 5, 6}; c.Count = 6 }, "a line is cited twice"},
		{"lines that are not in time order", func(c *Claim) { c.Lines = []int{3, 2, 4, 5, 6} }, "the cited lines are not in time order"},
		{"fewer lines than the threshold", func(c *Claim) { c.Lines = []int{2, 3, 4, 5}; c.Count = 4; c.Last = "Nov 11 09:01:05" }, "there are fewer failed passwords than the threshold"},
		{"a wrong first time", func(c *Claim) { c.First = "Nov 11 09:00:02" }, "the first or the last time is not the one of the cited lines"},
		{"a wrong last time", func(c *Claim) { c.Last = "Nov 11 09:01:31" }, "the first or the last time is not the one of the cited lines"},
		{"a time with a year", func(c *Claim) { c.First = "2026-11-11T09:00:01Z" }, "the first or the last time is not the one of the cited lines"},
		{"no success line", func(c *Claim) { c.SuccessLine = 0 }, "the success line is not an accepted password in the log"},
		{"a success line that is a failure", func(c *Claim) { c.SuccessLine = 6 }, "the success line is not an accepted password in the log"},
		{"a success line that does not exist", func(c *Claim) { c.SuccessLine = 99 }, "the success line is not an accepted password in the log"},
		{"a success of another user at another address", func(c *Claim) { c.SuccessLine = 1 }, "the accepted password is from another address or for another user name"},
		{"an unknown scenario", func(c *Claim) { c.Scenario = "magic" }, "the scenario is not one of the two that are checked"},
		{"no scenario", func(c *Claim) { c.Scenario = "" }, "the scenario is not one of the two that are checked"},
		{"no lines", func(c *Claim) { c.Lines = nil }, "the claim cites no lines"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			claim := good
			claim.Users = slices.Clone(good.Users)
			claim.Lines = slices.Clone(good.Lines)
			testCase.change(&claim)

			verdict := checker.Check(claim)

			if verdict.Verified || !slices.Contains(verdict.Reasons, testCase.reason) {
				t.Errorf("verified %v, reasons %q, want the reason %q", verdict.Verified, verdict.Reasons, testCase.reason)
			}
		})
	}
}

func TestTheWindowAndTheSuccessTimeAreCheckedForClaimsToo(t *testing.T) {
	lines := []string{
		entry("09:00:00", "F", "admin", "203.0.113.5"), entry("09:02:30", "F", "admin", "203.0.113.5"), entry("09:05:00", "F", "admin", "203.0.113.5"),
		entry("09:07:30", "F", "admin", "203.0.113.5"), entry("09:10:01", "F", "admin", "203.0.113.5"), entry("09:10:30", "A", "admin", "203.0.113.5"),
		entry("09:30:00", "A", "admin", "203.0.113.5"),
	}
	checker := NewChecker(parseLines(t, lines...), testConfig())
	claim := Claim{Scenario: GuessingThenSuccess, IP: "203.0.113.5", Users: []string{"admin"}, Lines: []int{1, 2, 3, 4, 5}, SuccessLine: 6, Count: 5, First: "Nov 11 09:00:00", Last: "Nov 11 09:10:01"}

	if verdict := checker.Check(claim); verdict.Verified || !slices.Contains(verdict.Reasons, "the cited lines are not within the window") {
		t.Errorf("a claim that spans 10 minutes 1 second: %+v", verdict)
	}

	inside := Claim{Scenario: GuessingThenSuccess, IP: "203.0.113.5", Users: []string{"admin"}, Lines: []int{1, 2, 3, 4}, SuccessLine: 7, Count: 4, First: "Nov 11 09:00:00", Last: "Nov 11 09:07:30"}
	if verdict := checker.Check(inside); verdict.Verified {
		t.Errorf("a claim with four lines and a late success: %+v", verdict)
	}
}

func TestAClaimedSuccessBeforeTheLastFailureIsRejected(t *testing.T) {
	lines := []string{
		entry("09:00:00", "A", "admin", "203.0.113.5"),
		entry("09:01:00", "F", "admin", "203.0.113.5"), entry("09:02:00", "F", "admin", "203.0.113.5"), entry("09:03:00", "F", "admin", "203.0.113.5"),
		entry("09:04:00", "F", "admin", "203.0.113.5"), entry("09:05:00", "F", "admin", "203.0.113.5"),
	}
	checker := NewChecker(parseLines(t, lines...), testConfig())
	claim := Claim{Scenario: GuessingThenSuccess, IP: "203.0.113.5", Users: []string{"admin"}, Lines: []int{2, 3, 4, 5, 6}, SuccessLine: 1, Count: 5, First: "Nov 11 09:01:00", Last: "Nov 11 09:05:00"}

	verdict := checker.Check(claim)
	if verdict.Verified || !slices.Contains(verdict.Reasons, "the accepted password is not within the window after the last failure") {
		t.Errorf("a success that comes before the failures: %+v", verdict)
	}
}

func TestSprayingClaims(t *testing.T) {
	parsed := parseFixture(t, "spraying.log")
	checker := NewChecker(parsed, testConfig())
	good := Claim{Scenario: PasswordSpraying, IP: "192.0.2.66", Users: []string{"root", "admin", "test", "oracle", "git", "postgres"}, Lines: []int{1, 2, 3, 4, 5, 6}, Count: 6, First: "Nov 11 10:00:00", Last: "Nov 11 10:01:44"}

	if verdict := checker.Check(good); !verdict.Verified || !slices.Equal(verdict.Finding.Users, []string{"admin", "git", "oracle", "postgres", "root", "test"}) {
		t.Fatalf("the good claim: %+v", verdict)
	}

	withSuccess := good
	withSuccess.SuccessLine = 9
	if verdict := checker.Check(withSuccess); verdict.Verified || !slices.Contains(verdict.Reasons, "spraying has no success line") {
		t.Errorf("a success line for spraying: %+v", verdict)
	}
	fewer := Claim{Scenario: PasswordSpraying, IP: "192.0.2.66", Users: []string{"root", "admin", "test", "oracle"}, Lines: []int{1, 2, 3, 4}, Count: 4, First: "Nov 11 10:00:00", Last: "Nov 11 10:01:02"}
	if verdict := checker.Check(fewer); verdict.Verified || !slices.Contains(verdict.Reasons, "there are fewer different user names than the threshold") {
		t.Errorf("four user names: %+v", verdict)
	}
	wrongAddress := good
	wrongAddress.IP = "198.51.100.20"
	if verdict := checker.Check(wrongAddress); verdict.Verified {
		t.Error("a claim with another address was verified")
	}
	missingName := good
	missingName.Users = []string{"root", "admin", "test", "oracle", "git"}
	if verdict := checker.Check(missingName); verdict.Verified {
		t.Error("a claim that leaves out a user name of the cited lines was verified")
	}
}

func TestATimeWrittenWithTwoSpacesIsTheSameTime(t *testing.T) {
	parsed := parseLines(t,
		"Nov  1 09:00:00 web sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2", "Nov  1 09:00:10 web sshd[1]: Failed password for b from 192.0.2.1 port 22 ssh2",
		"Nov  1 09:00:20 web sshd[1]: Failed password for c from 192.0.2.1 port 22 ssh2", "Nov  1 09:00:30 web sshd[1]: Failed password for d from 192.0.2.1 port 22 ssh2",
		"Nov  1 09:00:40 web sshd[1]: Failed password for e from 192.0.2.1 port 22 ssh2")
	claim := Claim{Scenario: PasswordSpraying, IP: "192.0.2.1", Users: []string{"a", "b", "c", "d", "e"}, Lines: []int{1, 2, 3, 4, 5}, Count: 5, First: "Nov  1 09:00:00", Last: "Nov 1   09:00:40"}

	if verdict := NewChecker(parsed, testConfig()).Check(claim); !verdict.Verified {
		t.Errorf("%q", verdict.Reasons)
	}
}

func TestExtractClaims(t *testing.T) {
	claimText := `[{"scenario":"password_spraying","ip":"192.0.2.1","users":["a"],"lines":[1],"count":1,"first":"Nov 11 09:00:00","last":"Nov 11 09:00:00"}]`
	testCases := []struct {
		name       string
		text       string
		wantClaims int
		wantErr    error
		wantRest   string
	}{
		{"a list between the markers", "Summary.\n" + BeginMarker + "\n" + claimText + "\n" + EndMarker + "\nBye.", 1, nil, "Summary.\n\nBye."},
		{"an empty list", BeginMarker + "[]" + EndMarker, 0, nil, ""},
		{"a list in a code block", BeginMarker + "\n```json\n" + claimText + "\n```\n" + EndMarker, 1, nil, ""},
		{"the last list wins", BeginMarker + "[]" + EndMarker + "\n" + BeginMarker + claimText + EndMarker, 1, nil, BeginMarker + "[]" + EndMarker},
		{"no markers", "I found nothing special.", 0, ErrNoClaims, "I found nothing special."},
		{"no end marker", BeginMarker + claimText, 0, ErrNoClaims, BeginMarker + claimText},
		{"an end marker before the begin marker", EndMarker + " " + BeginMarker + claimText, 0, ErrNoClaims, EndMarker + " " + BeginMarker + claimText},
		{"text that is not JSON", BeginMarker + "not json" + EndMarker, 0, ErrBadClaims, ""},
		{"JSON that is not a list", BeginMarker + `{"a":1}` + EndMarker, 0, ErrBadClaims, ""},
		{"a claim with a number in place of a text", BeginMarker + `[{"scenario":5}]` + EndMarker, 0, ErrBadClaims, ""},
		{"too many claims", BeginMarker + "[" + strings.Repeat("{},", maxClaims) + "{}]" + EndMarker, 0, ErrBadClaims, ""},
		{"a claim with too many lines", BeginMarker + `[{"lines":[` + strings.Repeat("1,", maxClaimLines) + `1]}]` + EndMarker, 0, ErrBadClaims, ""},
		{"a text that is too long", BeginMarker + `[{"ip":"` + strings.Repeat("x", maxClaimText+1) + `"}]` + EndMarker, 0, ErrBadClaims, ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			claims, rest, err := ExtractClaims(testCase.text)

			if err != testCase.wantErr || len(claims) != testCase.wantClaims || rest != testCase.wantRest {
				t.Errorf("claims %d, err %v, rest %q", len(claims), err, rest)
			}
		})
	}
}

func FuzzExtractClaimsAndCheck(f *testing.F) {
	f.Add(BeginMarker + `[{"scenario":"password_spraying","ip":"1.2.3.4","users":["a"],"lines":[1,2],"count":2,"first":"x","last":"y"}]` + EndMarker)
	f.Add("\x00" + BeginMarker + "[" + EndMarker)
	parsed := parseFixture(f, "spraying.log")
	checker := NewChecker(parsed, testConfig())

	f.Fuzz(func(t *testing.T, text string) {
		claims, _, _ := ExtractClaims(text)
		for _, claim := range claims {
			verdict := checker.Check(claim)
			if verdict.Verified && (len(verdict.Finding.FailureLines) == 0 || verdict.Finding.Count != len(verdict.Finding.FailureLines)) {
				t.Fatalf("a verified claim without proof: %+v", verdict)
			}
			if !verdict.Verified && len(verdict.Reasons) == 0 {
				t.Fatal("a rejected claim without a reason")
			}
		}
	})
}

func TestTheInstructionSaysThatWeakPatternsAreNotFindings(t *testing.T) {
	text := Instruction("guessing.log", testConfig())

	if !strings.Contains(text, "Claim only a pattern that meets the numbers above") {
		t.Errorf("the instruction does not warn against weak claims:\n%s", text)
	}
}

func TestTheInstructionSaysThatInvalidUserLinesCount(t *testing.T) {
	text := Instruction("guessing.log", testConfig())

	if !strings.Contains(text, `"Failed password for invalid user NAME from ..." the user name is NAME`) {
		t.Errorf("the instruction does not explain invalid user lines:\n%s", text)
	}
}
