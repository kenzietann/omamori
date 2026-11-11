package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

const commandKey = "sk-FAKE-command-key-123456"

type commandRun struct {
	code     int
	stdout   string
	stderr   string
	screens  []tui.Model
	listedAs []string
}

func runCommand(t testing.TB, args []string, environmentValues map[string]string, screenErr error) commandRun {
	t.Helper()

	var result commandRun
	var stdout, stderr bytes.Buffer
	result.code = run(args, environment{
		stdout:    &stdout,
		stderr:    &stderr,
		lookupEnv: func(name string) string { return environmentValues[name] },
		home:      homeAt(t.TempDir()),
		openScreen: func(model tui.Model) error {
			result.screens = append(result.screens, model)
			return screenErr
		},
		listModels: func(ctx context.Context, id, key string) ([]string, error) {
			result.listedAs = append(result.listedAs, id+":"+key)
			return []string{"model-a", "model-b"}, nil
		},
	})
	result.stdout, result.stderr = stdout.String(), stderr.String()

	return result
}

func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}} {
		result := runCommand(t, args, nil, nil)

		if result.code != exitOK || result.stderr != "" || !strings.Contains(result.stdout, "omamori <command>") || !strings.Contains(result.stdout, "check <folder>") {
			t.Errorf("%v: code %d, stderr %q, stdout %q", args, result.code, result.stderr, result.stdout)
		}
	}

	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		if result := runCommand(t, args, nil, nil); result.code != exitOK || result.stdout != "omamori "+version+"\n" {
			t.Errorf("%v: code %d, stdout %q", args, result.code, result.stdout)
		}
	}
}

func TestAnUnknownCommandIsAUsageError(t *testing.T) {
	for _, command := range []string{"nope", "CHECK", "--nope", "/tmp", "."} {
		result := runCommand(t, []string{command}, nil, nil)

		if result.code != exitUsage || result.stdout != "" || !strings.Contains(result.stderr, "is not a command") || len(result.screens) != 0 {
			t.Errorf("%q: code %d, stdout %q, stderr %q", command, result.code, result.stdout, result.stderr)
		}
	}
}

func TestProvidersShowsWhereEachKeyComesFromAndNeverTheKey(t *testing.T) {
	result := runCommand(t, []string{"providers"}, map[string]string{"OPENAI_API_KEY": commandKey}, nil)

	if result.code != exitOK {
		t.Fatalf("code %d, stderr %q", result.code, result.stderr)
	}
	for _, want := range []string{"ID", "anthropic", "ANTHROPIC_API_KEY is not set", "OPENAI_API_KEY is set", "ollama", "no key needed"} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("the list has no %q:\n%s", want, result.stdout)
		}
	}
	if strings.Contains(result.stdout+result.stderr, commandKey) {
		t.Error("the key is printed")
	}
	if result := runCommand(t, []string{"providers", "extra"}, nil, nil); result.code != exitUsage {
		t.Errorf("an extra argument: code %d", result.code)
	}
}

func TestModelsPrintsOneNamePerLine(t *testing.T) {
	result := runCommand(t, []string{"models", "openai"}, map[string]string{"OPENAI_API_KEY": commandKey}, nil)

	if result.code != exitOK || result.stdout != "model-a\nmodel-b\n" || result.stderr != "" {
		t.Errorf("code %d, stdout %q, stderr %q", result.code, result.stdout, result.stderr)
	}
	if len(result.listedAs) != 1 || result.listedAs[0] != "openai:"+commandKey {
		t.Errorf("asked as %q", result.listedAs)
	}

	local := runCommand(t, []string{"models", "ollama"}, nil, nil)
	if local.code != exitOK || local.listedAs[0] != "ollama:" {
		t.Errorf("a local provider: code %d, asked %q", local.code, local.listedAs)
	}
}

func TestModelsProblemsAreSaidInPlainWords(t *testing.T) {
	testCases := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"no provider", []string{"models"}, exitUsage, "usage: omamori models <provider>"},
		{"two providers", []string{"models", "openai", "groq"}, exitUsage, "usage: omamori models <provider>"},
		{"an unknown provider", []string{"models", "nope"}, exitUsage, `the provider "nope" is not known`},
		{"no key", []string{"models", "openai"}, exitFailed, "Set OPENAI_API_KEY and run the command again"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := runCommand(t, testCase.args, nil, nil)

			if result.code != testCase.wantCode || result.stdout != "" || !strings.Contains(result.stderr, testCase.wantStderr) || len(result.listedAs) != 0 {
				t.Errorf("code %d, stdout %q, stderr %q, asked %q", result.code, result.stdout, result.stderr, result.listedAs)
			}
		})
	}
}

func TestModelsFailureDoesNotPrintTheKey(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"models", "openai"}, environment{
		stdout: &bytes.Buffer{}, stderr: &stderr,
		lookupEnv:  func(string) string { return commandKey },
		listModels: func(context.Context, string, string) ([]string, error) { return nil, errors.New("boom " + commandKey) },
	})

	if code != exitFailed || strings.Contains(stderr.String(), commandKey) || !strings.Contains(stderr.String(), "the list of models could not be loaded") {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
}

func TestCheckOpensTheScreenAtTheProviderChoice(t *testing.T) {
	project := t.TempDir()

	result := runCommand(t, []string{"check", project}, nil, nil)

	if result.code != exitOK || len(result.screens) != 1 {
		t.Fatalf("code %d, screens %d, stderr %q", result.code, len(result.screens), result.stderr)
	}
	if view := result.screens[0].View(); !strings.Contains(view, "Choose the AI provider") {
		t.Errorf("check must start at the provider choice:\n%s", view)
	}
}

func TestUiOpensTheHomeMenu(t *testing.T) {
	result := runCommand(t, []string{"ui", t.TempDir()}, nil, nil)

	if view := result.screens[0].View(); result.code != exitOK || !strings.Contains(view, "Task A: Exposure check") || strings.Contains(view, "Choose the AI provider") {
		t.Errorf("code %d:\n%s", result.code, view)
	}
}

func TestFlagsMayComeBeforeOrAfterTheFolder(t *testing.T) {
	project := t.TempDir()

	for _, args := range [][]string{
		{"check", "--provider", "ollama", "--model", "m", project},
		{"check", project, "--provider", "ollama", "--model", "m"},
		{"check", "--provider", "ollama", project, "--model", "m"},
	} {
		result := runCommand(t, args, nil, nil)

		if result.code != exitOK || len(result.screens) != 1 {
			t.Errorf("%v: code %d, stderr %q", args, result.code, result.stderr)
		}
	}
}

func TestScreenCommandsReportProblems(t *testing.T) {
	project := t.TempDir()
	testCases := []struct {
		name       string
		args       []string
		screenErr  error
		wantCode   int
		wantStderr string
	}{
		{"check without a folder", []string{"check"}, nil, exitUsage, "usage: omamori check|ui"},
		{"ui with two folders", []string{"ui", project, project}, nil, exitUsage, "usage: omamori check|ui"},
		{"a folder that is not there", []string{"check", project + "/missing"}, nil, exitFailed, "the target is not a folder"},
		{"an unknown provider", []string{"check", "--provider", "nope", project}, nil, exitFailed, `the provider "nope" is not known`},
		{"the screen stops", []string{"check", project}, errors.New("no terminal"), exitFailed, "the screen stopped: no terminal"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := runCommand(t, testCase.args, nil, testCase.screenErr)

			if result.code != testCase.wantCode || !strings.Contains(result.stderr, testCase.wantStderr) {
				t.Errorf("code %d, stderr %q", result.code, result.stderr)
			}
		})
	}
}

func TestAKeyCannotBeGivenOnTheCommandLine(t *testing.T) {
	project := t.TempDir()

	for _, args := range [][]string{{"check", "--key", commandKey, project}, {"check", "--api-key=" + commandKey, project}, {"models", "openai", commandKey}} {
		result := runCommand(t, args, nil, nil)

		if result.code == exitOK || len(result.screens) != 0 || strings.Contains(result.stdout+result.stderr, commandKey) {
			t.Errorf("%v: code %d, stderr %q", args, result.code, result.stderr)
		}
	}
}

func TestMergeDefaults(t *testing.T) {
	saved := appconfig.Settings{Provider: "openai", Model: "gpt-x", Reasoning: "high"}
	testCases := []struct {
		name  string
		given settings
		want  tui.Defaults
	}{
		{"nothing given uses everything saved", settings{}, tui.Defaults{ProviderID: "openai", Model: "gpt-x", Reasoning: "high"}},
		{"the same provider keeps the saved model and level", settings{provider: "openai"}, tui.Defaults{ProviderID: "openai", Model: "gpt-x", Reasoning: "high"}},
		{"a different model drops the saved level", settings{provider: "openai", model: "gpt-y"}, tui.Defaults{ProviderID: "openai", Model: "gpt-y"}},
		{"a different provider drops the saved model and level", settings{provider: "mistral"}, tui.Defaults{ProviderID: "mistral"}},
		{"a model without a provider is used with the saved provider and drops the level", settings{model: "gpt-y"}, tui.Defaults{ProviderID: "openai", Model: "gpt-y"}},
		{"the same model on the same provider keeps the level", settings{provider: "openai", model: "gpt-x"}, tui.Defaults{ProviderID: "openai", Model: "gpt-x", Reasoning: "high"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := mergeDefaults(testCase.given, saved); got != testCase.want {
				t.Errorf("got %+v, want %+v", got, testCase.want)
			}
		})
	}
	if got := mergeDefaults(settings{provider: "mistral", model: "m"}, appconfig.Settings{}); got != (tui.Defaults{ProviderID: "mistral", Model: "m"}) {
		t.Errorf("with nothing saved: %+v", got)
	}
	if got := mergeDefaults(settings{}, appconfig.Settings{}); got != (tui.Defaults{}) {
		t.Errorf("with nothing at all: %+v", got)
	}
}

func runWithSettings(t testing.TB, args []string, saved *appconfig.Settings, keys taskrun.KeyStore) (commandRun, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "omamori", "settings.json")
	if saved != nil {
		if err := appconfig.Save(path, *saved); err != nil {
			t.Fatal(err)
		}
	}

	var result commandRun
	var stdout, stderr bytes.Buffer
	result.code = run(args, environment{
		stdout: &stdout, stderr: &stderr,
		lookupEnv: func(string) string { return "" },
		home:      homeAt(t.TempDir()),
		openScreen: func(model tui.Model) error {
			result.screens = append(result.screens, model)
			return nil
		},
		keys:         keys,
		settingsPath: func() (string, error) { return path, nil },
	})
	result.stdout, result.stderr = stdout.String(), stderr.String()

	return result, path
}

func TestCheckUsesTheSavedSettingsAndGoesToTheConsentScreen(t *testing.T) {
	saved := appconfig.Settings{Provider: "ollama", Model: "llama"}

	result, _ := runWithSettings(t, []string{"check", t.TempDir()}, &saved, nil)

	if result.code != exitOK || len(result.screens) != 1 {
		t.Fatalf("code %d, stderr %q", result.code, result.stderr)
	}
	view := result.screens[0].View()
	if !strings.Contains(view, "Please confirm before anything is sent") || !strings.Contains(view, "Model: llama") || !strings.Contains(view, "Provider: Ollama") {
		t.Errorf("check did not go to the consent screen with the saved choices:\n%s", view)
	}
}

func TestTheCommandLineBeatsTheSavedSettings(t *testing.T) {
	saved := appconfig.Settings{Provider: "ollama", Model: "llama"}

	result, _ := runWithSettings(t, []string{"check", "--model", "other-model", t.TempDir()}, &saved, nil)

	if view := result.screens[0].View(); !strings.Contains(view, "Model: other-model") {
		t.Errorf("the flag did not win:\n%s", view)
	}
}

func TestWithoutSavedSettingsCheckStartsTheSetup(t *testing.T) {
	for name, saved := range map[string]*appconfig.Settings{"no file": nil, "an empty file": {}} {
		result, _ := runWithSettings(t, []string{"check", t.TempDir()}, saved, nil)

		if view := result.screens[0].View(); !strings.Contains(view, "Choose the AI provider") {
			t.Errorf("%s:\n%s", name, view)
		}
	}
}

func TestABrokenSettingsFileIsIgnored(t *testing.T) {
	var result commandRun
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("not json {"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer

	result.code = run([]string{"check", t.TempDir()}, environment{
		stdout: &bytes.Buffer{}, stderr: &stderr, lookupEnv: func(string) string { return "" }, home: homeAt(t.TempDir()),
		openScreen:   func(model tui.Model) error { result.screens = append(result.screens, model); return nil },
		settingsPath: func() (string, error) { return path, nil },
	})

	if result.code != exitOK || len(result.screens) != 1 || stderr.Len() != 0 || !strings.Contains(result.screens[0].View(), "Choose the AI provider") {
		t.Errorf("code %d, stderr %q", result.code, stderr.String())
	}
}

func TestProvidersAndModelsUseTheSavedKey(t *testing.T) {
	keys := &memoryKeys{saved: map[string]string{"openai": commandKey}, available: true}
	var stdout, stderr bytes.Buffer
	var asked []string
	env := environment{
		stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" }, keys: keys,
		listModels: func(ctx context.Context, id, key string) ([]string, error) {
			asked = append(asked, id+":"+key)
			return []string{"m"}, nil
		},
	}

	if code := run([]string{"providers"}, env); code != exitOK || !strings.Contains(stdout.String(), "key saved in your Keychain") || strings.Contains(stdout.String(), commandKey) {
		t.Errorf("providers: code %d:\n%s", code, stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"models", "openai"}, env); code != exitOK || len(asked) != 1 || asked[0] != "openai:"+commandKey || strings.Contains(stdout.String()+stderr.String(), commandKey) {
		t.Errorf("models: code %d, asked %q, stderr %q", code, asked, stderr.String())
	}
}

func TestTheSettingsFileNeverHoldsAKeyAfterARun(t *testing.T) {
	keys := &memoryKeys{saved: map[string]string{"openai": commandKey}, available: true}
	saved := appconfig.Settings{Provider: "openai", Model: "gpt-x"}

	result, path := runWithSettings(t, []string{"check", t.TempDir()}, &saved, keys)
	if _, err := result.screens[0].View(), error(nil); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), commandKey) || strings.Contains(result.stdout+result.stderr+result.screens[0].View(), commandKey) {
		t.Error("the key is in the settings file or on the screen")
	}
}

func TestTheProgramStartsFullScreenAndNeverTakesTheMouse(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(source), "tea.WithAltScreen()") {
		t.Error("main.go does not start full-screen, so the pages before a run are not pages")
	}
	for _, option := range []string{"WithMouseCellMotion", "WithMouseAllMotion"} {
		if strings.Contains(string(source), "tea."+option) {
			t.Errorf("main.go uses %s. The mouse must stay with the terminal, so that text can be selected.", option)
		}
	}
}
