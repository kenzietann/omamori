package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noEnvironment(string) string { return "" }

func homeAt(path string) func() (string, error) {
	return func() (string, error) { return path, nil }
}

func TestSettingsFromTheCommandLine(t *testing.T) {
	project := t.TempDir()
	home := t.TempDir()

	testCases := []struct {
		name    string
		args    []string
		env     map[string]string
		check   func(settings) string
		wantErr string
	}{
		{"only a folder", []string{project}, nil, func(s settings) string {
			switch {
			case s.target != project, s.output != filepath.Join(home, "omamori-output"), s.provider != "", s.model != "", s.maxSteps != 15, s.maxTokens != 300000:
				return "the defaults are wrong"
			}
			return ""
		}, ""},
		{"everything on the command line", []string{"--provider", "openai", "--model", "a-model", "--output", "reports", "--max-steps", "5", "--max-tokens", "1000", project}, nil, func(s settings) string {
			cwd, _ := os.Getwd()
			switch {
			case s.provider != "openai", s.model != "a-model", s.maxSteps != 5, s.maxTokens != 1000, s.output != filepath.Join(cwd, "reports"):
				return "the flags were not used"
			}
			return ""
		}, ""},
		{"the environment sets the provider and the model", []string{project}, map[string]string{"OMAMORI_PROVIDER": "mistral", "OMAMORI_MODEL": "env-model"}, func(s settings) string {
			if s.provider != "mistral" || s.model != "env-model" {
				return "the environment was not used"
			}
			return ""
		}, ""},
		{"the command line beats the environment", []string{"--provider", "groq", "--model", "flag-model", project}, map[string]string{"OMAMORI_PROVIDER": "mistral", "OMAMORI_MODEL": "env-model"}, func(s settings) string {
			if s.provider != "groq" || s.model != "flag-model" {
				return "the environment won"
			}
			return ""
		}, ""},
		{"a relative folder becomes absolute", []string{"."}, nil, func(s settings) string {
			if !filepath.IsAbs(s.target) {
				return "the target is not absolute"
			}
			return ""
		}, ""},
		{"no folder", nil, nil, nil, usageText},
		{"two folders", []string{project, project}, nil, nil, usageText},
		{"an unknown flag", []string{"--nope", project}, nil, nil, usageText},
		{"a flag without a value", []string{project, "--model"}, nil, nil, usageText},
		{"a folder that is not there", []string{filepath.Join(project, "missing")}, nil, nil, "the target is not a folder"},
		{"a file, not a folder", []string{writeFile(t, project)}, nil, nil, "the target is not a folder"},
		{"an unknown provider on the command line", []string{"--provider", "nope", project}, nil, nil, `the provider "nope" is not known`},
		{"an unknown provider in the environment", []string{project}, map[string]string{"OMAMORI_PROVIDER": "nope"}, nil, `the provider "nope" is not known`},
		{"zero steps", []string{"--max-steps", "0", project}, nil, nil, "--max-steps must be a whole number above 0"},
		{"negative tokens", []string{"--max-tokens", "-5", project}, nil, nil, "--max-tokens must be a whole number above 0"},
		{"steps that are not a number", []string{"--max-steps", "many", project}, nil, nil, "--max-steps must be a whole number above 0"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			environment := testCase.env
			lookup := func(name string) string { return environment[name] }

			got, err := parseSettings(testCase.args, lookup, homeAt(home))

			if testCase.wantErr != "" {
				if err == nil || err.Error() != testCase.wantErr {
					t.Errorf("err = %v, want %q", err, testCase.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if problem := testCase.check(got); problem != "" {
				t.Errorf("%s: %+v", problem, got)
			}
		})
	}
}

func writeFile(t testing.TB, directory string) string {
	t.Helper()

	path := filepath.Join(directory, "a-file.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestTheReportFolderNeedsAHomeOrAnExplicitChoice(t *testing.T) {
	project := t.TempDir()

	noHome := func() (string, error) { return "", errors.New("no home") }
	if _, err := parseSettings([]string{project}, noEnvironment, noHome); err == nil || !strings.Contains(err.Error(), "--output") {
		t.Errorf("err = %v, want a hint to use --output", err)
	}
	emptyHome := func() (string, error) { return "", nil }
	if _, err := parseSettings([]string{project}, noEnvironment, emptyHome); err == nil {
		t.Error("an empty home folder was accepted")
	}

	got, err := parseSettings([]string{"--output", filepath.Join(project, "..", "chosen"), project}, noEnvironment, noHome)
	if err != nil || filepath.Base(got.output) != "chosen" {
		t.Errorf("an explicit folder should not need a home: output = %q, err = %v", got.output, err)
	}
}

func TestSettingsNeverHoldAKey(t *testing.T) {
	project := t.TempDir()
	environment := map[string]string{"ANTHROPIC_API_KEY": "sk-ant-api03-FAKEFAKEFAKE", "OPENAI_API_KEY": "sk-FAKEFAKEFAKE"}

	got, err := parseSettings([]string{project}, func(name string) string { return environment[name] }, homeAt(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(strings.ToLower(strings.Join([]string{got.target, got.output, got.provider, got.model}, " ")), "fake") {
		t.Errorf("the settings hold a key: %+v", got)
	}
}
