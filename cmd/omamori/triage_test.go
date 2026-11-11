package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/tui"
)

func triageLog(t testing.TB) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "triage", "guessing.log"))
	if err != nil {
		t.Fatal(err)
	}

	return path
}

func exposureProject(t testing.TB) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "exposure", "project"))
	if err != nil {
		t.Fatal(err)
	}

	return path
}

func writeRecording(t testing.TB, task, log string) string {
	t.Helper()

	recording := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: task, Log: log, Steps: []replay.Step{
		{Answer: replay.Answer{ToolCalls: []replay.Call{{ID: "call_1", Name: "list_dir", Arguments: map[string]string{"path": "."}}}}},
		{Answer: replay.Answer{Text: "done"}},
	}}
	text, err := recording.JSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recording.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func press(t testing.TB, model tui.Model, keys ...tea.KeyType) tui.Model {
	t.Helper()

	for _, key := range keys {
		updated, _ := model.Update(tea.KeyMsg{Type: key})
		model = updated.(tui.Model)
	}

	return model
}

func TestParseTriageTakesTheLogAndUsesItsFolderAsTheProject(t *testing.T) {
	log := triageLog(t)

	parsed, err := parseTriage([]string{"--year", "2026", "--timezone", "UTC", log, "--triage-config", "t.json", "--output", "out"}, noEnvironment, homeAt(t.TempDir()))

	if err != nil || parsed.target != filepath.Dir(log) || parsed.log != "guessing.log" || parsed.year != 2026 || parsed.zone != "UTC" || parsed.triageFile != "t.json" || !filepath.IsAbs(parsed.output) {
		t.Errorf("parsed %+v, err %v", parsed, err)
	}
}

func TestParseTriageRefusesWhatIsNotALogFile(t *testing.T) {
	directory := t.TempDir()
	spaced := filepath.Join(directory, "my log")
	os.WriteFile(spaced, []byte("x"), 0o600)

	testCases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no log", nil, usageTriage},
		{"two logs", []string{triageLog(t), triageLog(t)}, usageTriage},
		{"an unknown flag", []string{"--nope", triageLog(t)}, usageTriage},
		{"a folder", []string{directory}, "the target is not a log file"},
		{"a file that is not there", []string{filepath.Join(directory, "none.log")}, "the target is not a log file"},
		{"a name with a space", []string{spaced}, "the name of the log file may only have letters, digits, dots, dashes and underscores"},
		{"a year that is not a number", []string{"--year", "abc", triageLog(t)}, usageTriage},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := parseTriage(testCase.args, noEnvironment, homeAt(t.TempDir()))

			if err == nil || err.Error() != testCase.wantErr {
				t.Errorf("err = %v, want %q", err, testCase.wantErr)
			}
		})
	}
}

func TestParseReplay(t *testing.T) {
	recording := writeRecording(t, "exposure", "")
	project := exposureProject(t)

	parsed, err := parseReplay([]string{recording, project, "--output", "out"}, noEnvironment, homeAt(t.TempDir()))
	if err != nil || parsed.recording != recording || parsed.target != project {
		t.Errorf("parsed %+v, err %v", parsed, err)
	}
	here, err := parseReplay([]string{recording}, noEnvironment, homeAt(t.TempDir()))
	if cwd, _ := os.Getwd(); err != nil || here.target != cwd {
		t.Errorf("the default target is %q, want the current folder: %v", here.target, err)
	}

	for name, args := range map[string][]string{
		"no arguments":                  nil,
		"three arguments":               {recording, project, project},
		"a recording that is a folder":  {project},
		"a recording that is not there": {filepath.Join(project, "none.json")},
	} {
		_, err := parseReplay(args, noEnvironment, homeAt(t.TempDir()))
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := parseReplay([]string{recording, filepath.Join(project, "none")}, noEnvironment, homeAt(t.TempDir())); err == nil || err.Error() != "the project folder or log file is not there" {
		t.Errorf("a target that is not there: %v", err)
	}
}

func TestTheTriageCommandOpensTheProviderChoiceForTaskB(t *testing.T) {
	result := runCommand(t, []string{"triage", triageLog(t)}, nil, nil)

	if result.code != exitOK || len(result.screens) != 1 {
		t.Fatalf("code %d, stderr %q", result.code, result.stderr)
	}
	if view := result.screens[0].View(); !strings.Contains(view, "Choose the AI provider") {
		t.Errorf("the triage must start at the provider choice:\n%s", view)
	}
}

func TestTheTriageSettingsComeFromTheFlagsAndTheFileAndAreShownBeforeAnythingIsSent(t *testing.T) {
	file := filepath.Join(t.TempDir(), "triage.json")
	os.WriteFile(file, []byte(`{"failure_threshold":3,"window_minutes":20}`), 0o600)

	result := runCommand(t, []string{"triage", triageLog(t), "--provider", "ollama", "--model", "llama", "--year", "2025", "--timezone", "UTC", "--triage-config", file}, nil, nil)

	if result.code != exitOK || len(result.screens) != 1 {
		t.Fatalf("code %d, stderr %q", result.code, result.stderr)
	}
	view := result.screens[0].View()
	for _, want := range []string{"Please confirm before anything is sent", "Log: guessing.log", "Settings: window 20 minutes, failure threshold 3, spray threshold 5, year 2025, time zone UTC"} {
		if !strings.Contains(view, want) {
			t.Errorf("the dry run has no %q:\n%s", want, view)
		}
	}
}

func TestTheTriageSettingsThatAreWrongStopBeforeTheScreen(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "triage.json")
	os.WriteFile(broken, []byte(`{"failure_threshold":1}`), 0o600)

	for name, args := range map[string][]string{
		"a time zone that does not exist": {"triage", triageLog(t), "--timezone", "Mars/Base"},
		"a broken settings file":          {"triage", triageLog(t), "--triage-config", broken},
		"a year in the past":              {"triage", triageLog(t), "--year", "1900"},
		"a ui with a broken file":         {"ui", exposureProject(t), "--triage-config", broken},
	} {
		result := runCommand(t, args, nil, nil)

		if result.code != exitFailed || len(result.screens) != 0 || result.stderr == "" {
			t.Errorf("%s: code %d, screens %d, stderr %q", name, result.code, len(result.screens), result.stderr)
		}
	}
	if result := runCommand(t, []string{"check", exposureProject(t), "--provider", "ollama"}, nil, nil); result.code != exitOK {
		t.Errorf("check needs no triage settings: code %d, %q", result.code, result.stderr)
	}
}

func TestTaskBInTheMenuNeedsAnAuthLogInTheFolder(t *testing.T) {
	without := runCommand(t, []string{"ui", t.TempDir()}, nil, nil)
	blocked := press(t, without.screens[0], tea.KeyDown, tea.KeyEnter)
	if !strings.Contains(blocked.View(), "Task B needs the log file auth.log in the target folder. Start Omamori with the log: omamori triage <log file>") {
		t.Errorf("a folder without auth.log:\n%s", blocked.View())
	}

	folder := t.TempDir()
	data, _ := os.ReadFile(triageLog(t))
	os.WriteFile(filepath.Join(folder, "auth.log"), data, 0o600)
	with := runCommand(t, []string{"ui", folder}, nil, nil)
	started := press(t, with.screens[0], tea.KeyDown, tea.KeyEnter)
	if !strings.Contains(started.View(), "Choose the AI provider") {
		t.Errorf("a folder with auth.log:\n%s", started.View())
	}
}

func TestTheReplayCommandOpensTheDryRunLabelledAsAReplayAndMakesNoRequest(t *testing.T) {
	recording := writeRecording(t, "exposure", "")

	result := runCommand(t, []string{"replay", recording, exposureProject(t)}, nil, nil)

	if result.code != exitOK || len(result.screens) != 1 || len(result.listedAs) != 0 {
		t.Fatalf("code %d, stderr %q, model lists %q", result.code, result.stderr, result.listedAs)
	}
	view := result.screens[0].View()
	for _, want := range []string{"Please confirm before anything is sent", "This is a REPLAY (scripted answers). Recorded answers are played back through the real guard. Nothing is sent to any provider.", "Mode: REPLAY (scripted answers)"} {
		if !strings.Contains(view, want) {
			t.Errorf("the replay page has no %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Choose the AI provider") || strings.Contains(view, "key") && strings.Contains(view, "API") {
		t.Errorf("a replay asked for a provider or a key:\n%s", view)
	}
}

func TestAReplayOfTheTriageTakesTheLogFileAsTheTarget(t *testing.T) {
	recording := writeRecording(t, "triage", "guessing.log")

	result := runCommand(t, []string{"replay", recording, triageLog(t)}, nil, nil)

	if result.code != exitOK || len(result.screens) != 1 {
		t.Fatalf("code %d, stderr %q", result.code, result.stderr)
	}
	if view := result.screens[0].View(); !strings.Contains(view, "Log: guessing.log") || !strings.Contains(view, "REPLAY") {
		t.Errorf("the replay of the triage:\n%s", view)
	}
}

func TestAReplayThatCannotWorkIsRefusedInPlainWords(t *testing.T) {
	good := writeRecording(t, "exposure", "")
	broken := filepath.Join(t.TempDir(), "recording.json")
	os.WriteFile(broken, []byte(`{"version":9}`), 0o600)

	testCases := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"no arguments", []string{"replay"}, exitUsage, "usage: omamori replay"},
		{"a recording that is not valid", []string{"replay", broken, exposureProject(t)}, exitFailed, "the recording is not valid"},
		{"a recording that is not there", []string{"replay", filepath.Join(t.TempDir(), "none.json")}, exitFailed, "the recording is not a file"},
		{"a project that is not there", []string{"replay", good, filepath.Join(t.TempDir(), "none")}, exitFailed, "the project folder or log file is not there"},
		{"a log file for an exposure recording", []string{"replay", good, triageLog(t)}, exitFailed, "the target is not a folder"},
		{"a bad triage setting", []string{"replay", good, exposureProject(t), "--timezone", "Mars/Base"}, exitFailed, "the time zone is not known"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := runCommand(t, testCase.args, nil, nil)

			if result.code != testCase.wantCode || len(result.screens) != 0 || !strings.Contains(result.stderr, testCase.wantStderr) {
				t.Errorf("code %d, screens %d, stderr %q", result.code, len(result.screens), result.stderr)
			}
		})
	}
}

func TestAReplayForAFolderWithoutItsLogShowsTheReasonInTheMenu(t *testing.T) {
	recording := writeRecording(t, "triage", "auth.log")

	result := runCommand(t, []string{"replay", recording, t.TempDir()}, nil, nil)

	if view := result.screens[0].View(); result.code != exitOK || !strings.Contains(view, "The recording cannot be replayed: the log file cannot be used") || strings.Contains(view, "Please confirm") {
		t.Errorf("code %d:\n%s", result.code, view)
	}
}

func TestTheHelpListsTheNewCommands(t *testing.T) {
	result := runCommand(t, []string{"help"}, nil, nil)

	for _, want := range []string{"triage <log file>", "replay <recording>", "--year n", "--timezone name", "--triage-config", "recording.json", "labeled REPLAY", "saved in your Keychain"} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("the help has no %q", want)
		}
	}
	if strings.Contains(result.stdout, "It is not saved.") {
		t.Error("the help still says that the key is not saved")
	}
}

func TestTheAdapterSaysWhatTaskBIsMissing(t *testing.T) {
	adapter, _, _ := newTestBackend(t)

	if err := adapter.TaskReady(""); err != nil {
		t.Errorf("task A: %v", err)
	}
	if err := adapter.TaskReady(tui.TaskTriage); err == nil || !strings.Contains(err.Error(), "Task B needs the log file auth.log in the target folder") {
		t.Errorf("a folder without a log: %v", err)
	}
	adapter.config.Target = filepath.Dir(triageLog(t))
	adapter.log = "guessing.log"
	if err := adapter.TaskReady(tui.TaskTriage); err != nil {
		t.Errorf("a folder with the log: %v", err)
	}
}

func TestTheAdapterBuildsTaskBAndReplayPlansWithTheirTitles(t *testing.T) {
	adapter, _, _ := newTestBackend(t)
	adapter.config.Target = filepath.Dir(triageLog(t))
	adapter.log = "guessing.log"

	plan, err := adapter.Prepare(tui.Setup{Task: tui.TaskTriage, ProviderID: "anthropic", Key: adapterKey})
	if err != nil || plan.Title != "Task B: Log triage" || plan.Label != "" || !strings.Contains(plan.Summary, "Log: guessing.log") {
		t.Errorf("title %q, label %q, err %v", plan.Title, plan.Label, err)
	}

	if _, err := adapter.Prepare(tui.Setup{Replay: true}); err != errNoRecording {
		t.Errorf("a replay without a recording: %v", err)
	}
	recording, err := replay.Load(writeRecording(t, "triage", "guessing.log"))
	if err != nil {
		t.Fatal(err)
	}
	adapter.recording = &recording
	plan, err = adapter.Prepare(tui.Setup{Replay: true})
	if err != nil || plan.Title != "Task B: Log triage" || plan.Label != "REPLAY (scripted answers)" || !strings.Contains(plan.ConsentText, "Nothing is sent to any provider.") {
		t.Errorf("title %q, label %q, err %v", plan.Title, plan.Label, err)
	}
}

func TestAReplayUsesTheSettingsOfTheRecordingAndTheUserCanChangeThem(t *testing.T) {
	recording := replay.Recording{Version: replay.Version, Source: replay.SourceScripted, Task: "triage", Log: "guessing.log",
		Triage: &replay.Settings{WindowMinutes: 15, FailureThreshold: 3, SprayThreshold: 4, Year: 2031, TimeZone: "UTC"}, Steps: []replay.Step{{Answer: replay.Answer{Text: "x"}}}}
	text, _ := recording.JSON()
	path := filepath.Join(t.TempDir(), "recording.json")
	os.WriteFile(path, []byte(text), 0o600)

	recorded := runCommand(t, []string{"replay", path, triageLog(t)}, nil, nil)
	changed := runCommand(t, []string{"replay", path, triageLog(t), "--year", "2032"}, nil, nil)

	if view := recorded.screens[0].View(); !strings.Contains(view, "Settings: window 15 minutes, failure threshold 3, spray threshold 4, year 2031, time zone UTC") {
		t.Errorf("the recorded settings are not used:\n%s", view)
	}
	if view := changed.screens[0].View(); !strings.Contains(view, "year 2032") || !strings.Contains(view, "window 15 minutes") || !strings.Contains(view, "failure threshold 3") {
		t.Errorf("a flag must win, and the other settings stay the recorded ones:\n%s", view)
	}
	file := filepath.Join(t.TempDir(), "triage.json")
	os.WriteFile(file, []byte(`{"window_minutes":20,"year":2040,"time_zone":"UTC"}`), 0o600)
	fromFile := runCommand(t, []string{"replay", path, triageLog(t), "--triage-config", file, "--year", "2041"}, nil, nil)
	if view := fromFile.screens[0].View(); !strings.Contains(view, "window 20 minutes") || !strings.Contains(view, "failure threshold 5") || !strings.Contains(view, "year 2041") {
		t.Errorf("a settings file replaces the recorded settings, and a flag is put on top:\n%s", view)
	}
}
