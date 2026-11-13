package triage

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/authlog"
)

func isoGuessingLog() string {
	var lines []string
	start := time.Date(2026, 11, 12, 14, 3, 28, 0, time.UTC)
	for index := range 7 {
		stamp := start.Add(time.Duration(index*3) * time.Second).Format("2006-01-02T15:04:05.000000-07:00")
		lines = append(lines, fmt.Sprintf("%s web01 sshd-session[%d]: Failed password for alice from 172.21.0.3 port %d ssh2", stamp, 100+index, 40000+index))
	}
	lines = append(lines, start.Add(25*time.Second).Format("2006-01-02T15:04:05.000000-07:00")+" web01 sshd-session[200]: Accepted password for alice from 172.21.0.3 port 41000 ssh2")
	return strings.Join(lines, "\n") + "\n"
}

func TestAGuessingClaimOnAnISOLogIsVerified(t *testing.T) {
	parsed, err := authlog.Parse(strings.NewReader(isoGuessingLog()), 2026, time.UTC)
	if err != nil || len(parsed.Events) != 8 || parsed.Zoned != 8 {
		t.Fatalf("parsed %+v %v", parsed, err)
	}
	first, last := parsed.Events[0].Stamp, parsed.Events[6].Stamp
	claim := fmt.Sprintf(`[{"scenario":"guessing_then_success","ip":"172.21.0.3","users":["alice"],"lines":[1,2,3,4,5,6,7],"success_line":8,"count":7,"first":%q,"last":%q}]`, first, last)
	text := BeginMarker + "\n" + claim + "\n" + EndMarker
	report, err := Render(Input{LogName: "auth.log", Parsed: parsed, Config: testConfig(), Texts: []string{text}, Outcome: complete()})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 verified", "read as written", "events: 8"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report has no %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "WARNING: no failed or accepted password") || strings.Contains(report, "Classic syslog lines have no year") {
		t.Errorf("the report warns about a log it read:\n%s", report)
	}
}

func TestALogWithoutPasswordEventsIsNotShownAsClean(t *testing.T) {
	parsed, err := authlog.Parse(strings.NewReader("Nov 12 14:00:35 web01 useradd[50]: new user: name=support2\nnot a log line\n"), 2026, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Render(Input{LogName: "auth.log", Parsed: parsed, Config: testConfig(), Outcome: complete()})
	if err != nil || !strings.Contains(report, "WARNING: no failed or accepted password was read") || !strings.Contains(report, "Do not read this report as clean") {
		t.Fatalf("report %v:\n%s", err, report)
	}
	empty, err := Render(Input{LogName: "auth.log", Parsed: authlog.Parsed{}, Config: testConfig(), Outcome: complete()})
	if err != nil || strings.Contains(empty, "WARNING: no failed") {
		t.Fatal("an empty file got the warning for unread lines")
	}
}

func TestTheTimeOfAnISOLineMayBeWrittenTheClassicWay(t *testing.T) {
	parsed, err := authlog.Parse(strings.NewReader(isoGuessingLog()), 2026, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	checker := NewChecker(parsed, testConfig())
	claim := func(first, last string) Verdict {
		return checker.Check(Claim{Scenario: GuessingThenSuccess, IP: "172.21.0.3", Users: []string{"alice"}, Lines: []int{1, 2, 3, 4, 5, 6, 7},
			SuccessLine: 8, Count: 7, First: first, Last: last})
	}
	for _, accepted := range [][2]string{
		{"Nov 12 14:03:28", "Nov 12 14:03:46"},
		{"2026-11-12T14:03:28Z", "2026-11-12T14:03:46Z"},
		{"2026-11-12 14:03:28", "2026-11-12 14:03:46"},
		{parsed.Events[0].Stamp, parsed.Events[6].Stamp},
	} {
		if verdict := claim(accepted[0], accepted[1]); !verdict.Verified {
			t.Errorf("%q was refused: %v", accepted, verdict.Reasons)
		}
	}
	for _, refused := range [][2]string{
		{"Nov 12 14:03:29", "Nov 12 14:03:46"},
		{"Nov 12 14:03:28", "Nov 12 14:03:47"},
		{"Nov 12 23:03:28", "Nov 12 23:03:46"},
		{"2026-11-12T14:03:28+09:00", "2026-11-12T14:03:46+09:00"},
		{"Nov 11 14:03:28", "Nov 11 14:03:46"},
	} {
		if verdict := claim(refused[0], refused[1]); verdict.Verified {
			t.Errorf("%q was accepted", refused)
		}
	}
}

func TestAClassicLineMustStillBeCitedAsWritten(t *testing.T) {
	var lines []string
	for index := range 7 {
		lines = append(lines, fmt.Sprintf("Nov 12 14:03:%02d web01 sshd[%d]: Failed password for alice from 172.21.0.3 port %d ssh2", 28+index*3, 100+index, 40000+index))
	}
	lines = append(lines, "Nov 12 14:03:53 web01 sshd[200]: Accepted password for alice from 172.21.0.3 port 41000 ssh2")
	parsed, err := authlog.Parse(strings.NewReader(strings.Join(lines, "\n")), 2026, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	verdict := NewChecker(parsed, testConfig()).Check(Claim{Scenario: GuessingThenSuccess, IP: "172.21.0.3", Users: []string{"alice"}, Lines: []int{1, 2, 3, 4, 5, 6, 7},
		SuccessLine: 8, Count: 7, First: "2026-11-12T14:03:28Z", Last: "2026-11-12T14:03:46Z"})
	if verdict.Verified {
		t.Fatal("a classic line was matched by a time that is not written in the log")
	}
}
