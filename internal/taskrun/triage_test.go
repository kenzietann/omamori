package taskrun

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/triage"
)

const triageFixtures = "../../testdata/fixtures/triage"

const goodClaim = `{"scenario":"guessing_then_success","ip":"203.0.113.5","users":["admin"],"lines":[2,3,4,5,6],"success_line":7,"count":5,"first":"Nov 11 09:00:01","last":"Nov 11 09:01:30"}`

func triageConfig() *triage.Config {
	return &triage.Config{Window: 10 * time.Minute, FailureThreshold: 5, SprayThreshold: 5, Year: 2026, Location: time.UTC, ZoneName: "UTC"}
}

func triageSetup(t *testing.T, final string) testSetup {
	t.Helper()

	project := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(filepath.Join(triageFixtures, "guessing.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "auth.log"), log, 0o600); err != nil {
		t.Fatal(err)
	}

	search := reply{response: outbound.Response{TokensUsed: 50, ToolCalls: []outbound.ToolCall{{ID: "call_1", Name: "search_text", Arguments: map[string]string{"query": "Failed password", "path": "auth.log"}}}}}
	setup := newSetup(t, search, reply{response: outbound.Response{TokensUsed: 60, Text: final}})
	setup.project, setup.config.Target = project, project
	setup.config.Triage = triageConfig()

	return setup
}

func triageSession(t *testing.T, setup testSetup) *Session {
	t.Helper()

	session, err := Prepare(setup.config, Setup{Task: TaskTriage, ProviderID: "anthropic", Key: testKey})
	if err != nil {
		t.Fatal(err)
	}

	return session
}

func runTriage(t *testing.T, session *Session) (Result, []string) {
	t.Helper()

	session.Confirm()
	var steps []string
	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil {
		t.Fatal(err)
	}

	return result, steps
}

func TestTheTriageRunChecksTheClaimAgainstTheLogAndSavesTheFiles(t *testing.T) {
	setup := triageSetup(t, "The admin account was guessed.\nBEGIN_CLAIMS\n["+goodClaim+"]\nEND_CLAIMS")
	session := triageSession(t, setup)

	if session.Title() != "Task B: Log triage" || session.Label() != "" {
		t.Errorf("title %q, label %q", session.Title(), session.Label())
	}
	result, steps := runTriage(t, session)

	if !result.Complete || !strings.Contains(result.Report, "# Omamori report: log triage") ||
		!strings.Contains(result.Report, "| T-001 | guessing_then_success | 203.0.113.5 | admin | 5 | Nov 11 09:00:01 | Nov 11 09:01:30 | 2, 3, 4, 5, 6 | 7 |") {
		t.Fatalf("complete %v, steps %q, report:\n%s", result.Complete, steps, result.Report)
	}
	files := outputFiles(t, setup.output)
	if len(files) != 4 {
		t.Errorf("%d files, want the report (two forms), the event log and the recording", len(files))
	}
	recording, err := replay.Load(filepath.Join(result.SavedTo, "recording.json"))
	if err != nil || recording.Task != "triage" || recording.Log != "auth.log" || len(recording.Steps) != 2 {
		t.Errorf("recording %+v, err %v", recording, err)
	}

	first := setup.provider.recorded[0]
	if !strings.Contains(first.Messages[0].Text, `"auth.log"`) || !strings.Contains(first.Messages[0].Text, "BEGIN_CLAIMS") {
		t.Errorf("the instruction is wrong: %q", first.Messages[0].Text)
	}
	if !strings.Contains(strings.Join(steps, "\n"), "tool search_text: ok") {
		t.Errorf("steps %q", steps)
	}
}

func TestAWrongClaimIsRejectedAndTheRunStillCompletes(t *testing.T) {
	wrong := strings.Replace(goodClaim, "203.0.113.5", "203.0.113.99", 1)
	setup := triageSetup(t, "BEGIN_CLAIMS\n["+wrong+"]\nEND_CLAIMS")

	result, _ := runTriage(t, triageSession(t, setup))

	report := result.Report
	if !result.Complete || !strings.Contains(report, "None. No claim of the AI was proved by the log.") || !strings.Contains(report, "- Claim 1: the source address of a cited line is not the claimed one") ||
		!strings.Contains(report, "| M-001 | guessing_then_success | 203.0.113.5 |") || strings.Contains(report, "203.0.113.99") {
		t.Errorf("report:\n%s", report)
	}
}

func TestThePreviewAndTheSummaryOfTheTriageShowTheLogAndTheSettings(t *testing.T) {
	setup := triageSetup(t, "x")
	setup.config.Triage.FailureThreshold = 3
	session := triageSession(t, setup)

	summary, _ := session.Summary()
	preview, _ := session.Preview()

	for _, want := range []string{"Log: auth.log", "Settings: window 10 minutes, failure threshold 3, spray threshold 5, year 2026, time zone UTC"} {
		if !strings.Contains(summary, want) {
			t.Errorf("the summary has no %q:\n%s", want, summary)
		}
	}
	if !strings.Contains(preview, "at least 3 ") || !strings.Contains(preview, "BEGIN_CLAIMS") {
		t.Errorf("the preview has no instruction with the settings:\n%s", preview)
	}
}

func TestTheTriageNeedsALogInsideTheProject(t *testing.T) {
	setup := triageSetup(t, "x")
	outside := filepath.Join(filepath.Dir(setup.project), "outside.log")
	os.WriteFile(outside, []byte("Nov 11 09:00:00 h sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2\n"), 0o600)
	os.Symlink(outside, filepath.Join(setup.project, "link.log"))
	os.Mkdir(filepath.Join(setup.project, "folder.log"), 0o755)

	for name, log := range map[string]string{
		"a log that is not there": "missing.log", "a log outside the project": "../outside.log", "an absolute path": outside,
		"a symlink": "link.log", "a folder": "folder.log", "a name with a space": "my log", "a name with odd characters": "a;rm.log",
	} {
		if _, err := Prepare(setup.config, Setup{Task: TaskTriage, Log: log, ProviderID: "anthropic", Key: testKey}); err != ErrLogFile {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	bad := *triageConfig()
	bad.FailureThreshold = 1
	setup.config.Triage = &bad
	if _, err := Prepare(setup.config, Setup{Task: TaskTriage, ProviderID: "anthropic", Key: testKey}); err != ErrLogFile {
		t.Errorf("bad settings: %v", err)
	}
}

func TestADifferentLogNameInAFolderIsUsed(t *testing.T) {
	setup := triageSetup(t, "x")
	os.MkdirAll(filepath.Join(setup.project, "logs"), 0o755)
	data, _ := os.ReadFile(filepath.Join(setup.project, "auth.log"))
	os.WriteFile(filepath.Join(setup.project, "logs", "ssh.log"), data, 0o600)

	session, err := Prepare(setup.config, Setup{Task: TaskTriage, Log: "logs/ssh.log", ProviderID: "anthropic", Key: testKey})
	if err != nil {
		t.Fatal(err)
	}

	if preview, _ := session.Preview(); !strings.Contains(preview, `"logs/ssh.log"`) {
		t.Errorf("the log name is not in the instruction:\n%s", preview)
	}
}

func TestARecordedTriageIsReplayedWithoutTheNetworkAndGivesTheSameFindings(t *testing.T) {
	setup := triageSetup(t, "BEGIN_CLAIMS\n["+goodClaim+"]\nEND_CLAIMS")
	live, _ := runTriage(t, triageSession(t, setup))
	recording, err := replay.Load(filepath.Join(live.SavedTo, "recording.json"))
	if err != nil {
		t.Fatal(err)
	}

	transport := &refusingTransport{}
	previousTransport, previousClient := http.DefaultTransport, http.DefaultClient
	http.DefaultTransport, http.DefaultClient = transport, &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultTransport, http.DefaultClient = previousTransport, previousClient })

	config := replayConfig(setup)
	session, err := Prepare(config, Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	if session.Title() != "Task B: Log triage" || session.Label() != "REPLAY" {
		t.Errorf("title %q, label %q", session.Title(), session.Label())
	}
	result, steps := runTriage(t, session)

	if !result.Complete || transport.calls.Load() != 0 {
		t.Fatalf("complete %v, network attempts %d, steps %q", result.Complete, transport.calls.Load(), steps)
	}
	body := strings.TrimPrefix(result.Report, "**REPLAY: recorded answers were played back. Nothing was sent.**\n\n")
	if body != live.Report {
		t.Errorf("the replay gives another report:\n%s\n---\n%s", body, live.Report)
	}
	if len(setup.provider.recorded) != 2 {
		t.Errorf("the live provider got %d requests, the replay must add none", len(setup.provider.recorded))
	}
}

func TestAReplayOfTheTriageStopsWhenTheLogChanged(t *testing.T) {
	setup := triageSetup(t, "BEGIN_CLAIMS\n["+goodClaim+"]\nEND_CLAIMS")
	live, _ := runTriage(t, triageSession(t, setup))
	recording, _ := replay.Load(filepath.Join(live.SavedTo, "recording.json"))
	changed := "Nov 11 09:00:01 web sshd[1001]: Failed password for root from 203.0.113.77 port 1 ssh2\n"
	if err := os.WriteFile(filepath.Join(setup.project, "auth.log"), []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}

	session, err := Prepare(replayConfig(setup), Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	result, steps := runTriage(t, session)

	if result.Complete || !strings.Contains(strings.Join(steps, "\n"), "replay: request 2 does not match the recording") {
		t.Errorf("complete %v, steps:\n%s", result.Complete, strings.Join(steps, "\n"))
	}
}

func TestAReplayNeedsItsLogAndItsLogNameCanBeGiven(t *testing.T) {
	setup := triageSetup(t, "BEGIN_CLAIMS\n["+goodClaim+"]\nEND_CLAIMS")
	live, _ := runTriage(t, triageSession(t, setup))
	recording, _ := replay.Load(filepath.Join(live.SavedTo, "recording.json"))

	empty := replayConfig(setup)
	empty.Target = t.TempDir()
	if _, err := Prepare(empty, Setup{Recording: &recording}); err != ErrLogFile {
		t.Errorf("a folder without the log: %v", err)
	}
	renamed := replayConfig(setup)
	os.Rename(filepath.Join(setup.project, "auth.log"), filepath.Join(setup.project, "ssh.log"))
	if _, err := Prepare(renamed, Setup{Recording: &recording, Log: "ssh.log"}); err != nil {
		t.Errorf("a log with another name: %v", err)
	}
	if _, err := Prepare(renamed, Setup{Recording: &recording}); !errors.Is(err, ErrLogFile) {
		t.Errorf("the recorded name is gone: %v", err)
	}
}

func TestNoLogLineOrAddressReachesAFileThatContainsAPlantedValue(t *testing.T) {
	setup := triageSetup(t, "The user AKIAIOSFODNN7EXAMPLE called 090-1234-5678.")
	data := "Nov 11 09:00:00 web sshd[1]: Failed password for AKIAIOSFODNN7EXAMPLE from 192.0.2.9 port 22 ssh2\nNov 11 09:00:01 web sshd[1]: Failed password for 090-1234-5678 from 192.0.2.9 port 22 ssh2\n"
	if err := os.WriteFile(filepath.Join(setup.project, "auth.log"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	result, _ := runTriage(t, triageSession(t, setup))

	for name, content := range outputFiles(t, setup.output) {
		for _, planted := range plantedValues {
			if strings.Contains(content, planted) {
				t.Errorf("%s holds %q", name, planted)
			}
		}
	}
	for _, request := range setup.provider.recorded {
		for _, message := range request.Messages {
			for _, planted := range plantedValues {
				if strings.Contains(message.Text, planted) {
					t.Errorf("a request holds %q", planted)
				}
			}
		}
	}
	if strings.Contains(result.Report, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("the report holds the planted key")
	}
}

func TestAReplayReadsTheLogWithTheSettingsOfTheRecordingUnlessTheUserGivesOthers(t *testing.T) {
	setup := triageSetup(t, "BEGIN_CLAIMS\n["+goodClaim+"]\nEND_CLAIMS")
	live, _ := runTriage(t, triageSession(t, setup))
	recording, err := replay.Load(filepath.Join(live.SavedTo, "recording.json"))
	if err != nil || recording.Triage == nil || recording.Triage.Year != 2026 || recording.Triage.TimeZone != "UTC" || recording.Triage.WindowMinutes != 10 {
		t.Fatalf("the settings were not recorded: %+v, %v", recording.Triage, err)
	}

	config := replayConfig(setup)
	config.Triage = nil
	config.Now = func() time.Time { return time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC) }
	session, err := Prepare(config, Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	result, _ := runTriage(t, session)
	if body := strings.TrimPrefix(result.Report, "**REPLAY: recorded answers were played back. Nothing was sent.**\n\n"); body != live.Report || strings.Contains(result.Report, "year 2031") {
		t.Errorf("the replay did not use the recorded settings:\n%s", result.Report)
	}

	other := replayConfig(setup)
	other.Triage = &triage.Config{Window: 10 * time.Minute, FailureThreshold: 5, SprayThreshold: 5, Year: 2020, Location: time.UTC, ZoneName: "UTC"}
	session, err = Prepare(other, Setup{Recording: &recording})
	if err != nil {
		t.Fatal(err)
	}
	if summary, _ := session.Summary(); !strings.Contains(summary, "year 2020") {
		t.Errorf("settings of the user do not win:\n%s", summary)
	}

	scripted := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "triage", Log: "auth.log", Steps: []replay.Step{{Answer: replay.Answer{Text: "x"}}}}
	defaults, err := Prepare(config, Setup{Recording: &scripted})
	if err != nil {
		t.Fatal(err)
	}
	if summary, _ := defaults.Summary(); !strings.Contains(summary, "year 2031") || !strings.Contains(summary, "window 10 minutes") {
		t.Errorf("a recording without settings uses the defaults:\n%s", summary)
	}
}

func TestARecordingWithATimeZoneThatThisComputerDoesNotKnowIsRefused(t *testing.T) {
	setup := triageSetup(t, "x")
	recording := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "triage", Log: "auth.log",
		Triage: &replay.Settings{WindowMinutes: 10, FailureThreshold: 5, SprayThreshold: 5, Year: 2026, TimeZone: "Mars/Base"}, Steps: []replay.Step{{Answer: replay.Answer{Text: "x"}}}}
	config := replayConfig(setup)
	config.Triage = nil

	if _, err := Prepare(config, Setup{Recording: &recording}); err != ErrLogFile {
		t.Errorf("err = %v", err)
	}
}
