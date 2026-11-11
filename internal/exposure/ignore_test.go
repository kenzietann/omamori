package exposure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/gateway"
	"github.com/kenzietann/omamori/internal/githistory"
	"github.com/kenzietann/omamori/internal/pathguard"
)

// The key is made up and written in two pieces, so that secret scanners on the source code do not flag it.
const fakeEnvKey = "sk-" + "proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"

func scanProject(t *testing.T, files map[string]string) (*Collector, *gateway.Gateway) {
	t.Helper()

	project := t.TempDir()
	for name, content := range files {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	tools := gateway.New(root, gateway.DefaultLimits)
	collector := NewCollector(tools)
	if _, err := collector.Call(context.Background(), "run_detectors", map[string]any{"path": "."}); err != nil {
		t.Fatal(err)
	}

	return collector, tools
}

func findingIn(t *testing.T, collector *Collector, file string) Finding {
	t.Helper()

	for _, finding := range collector.Findings() {
		if finding.File == file {
			return finding
		}
	}
	t.Fatalf("no finding in %s: %+v", file, collector.Findings())

	return Finding{}
}

func TestAKeyInAnEnvFileDependsOnTheGitignore(t *testing.T) {
	env := "# local\nAI_KEY=" + fakeEnvKey + "\n"
	testCases := []struct {
		name         string
		files        map[string]string
		file         string
		wantSeverity string
		wantAdvice   string
	}{
		{"ignored by a rule", map[string]string{".env": env, ".gitignore": "node_modules\n.env\n"}, ".env", SeverityKeptOut, "keeps this file out of git"},
		{"ignored by a star rule", map[string]string{".env.local": env, ".gitignore": ".env*\n"}, ".env.local", SeverityKeptOut, "keeps this file out of git"},
		{"there is no gitignore", map[string]string{".env": env}, ".env", "high", "No .gitignore rule"},
		{"the gitignore does not list it", map[string]string{".env": env, ".gitignore": "node_modules\n*.log\n"}, ".env", "high", "No .gitignore rule"},
		{"the gitignore takes it back", map[string]string{".env": env, ".gitignore": ".env*\n!.env\n"}, ".env", "high", "No .gitignore rule"},
		{"a folder rule covers it", map[string]string{"backend/.env": env, ".gitignore": "backend/\n"}, "backend/.env", SeverityKeptOut, "keeps this file out of git"},
		{"a rule of the root reaches a deep file", map[string]string{"backend/api/.env": env, ".gitignore": ".env\n"}, "backend/api/.env", SeverityKeptOut, "keeps this file out of git"},
		{"a gitignore of the folder", map[string]string{"backend/.env": env, "backend/.gitignore": ".env\n"}, "backend/.env", SeverityKeptOut, "keeps this file out of git"},
		{"a deeper gitignore takes it back", map[string]string{"backend/.env": env, ".gitignore": ".env\n", "backend/.gitignore": "!.env\n"}, "backend/.env", "high", "No .gitignore rule"},
		{"a gitignore of another folder does not count", map[string]string{"backend/.env": env, "web/.gitignore": ".env\n"}, "backend/.env", "high", "No .gitignore rule"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			collector, _ := scanProject(t, testCase.files)

			collector.CheckIgnore(context.Background())

			finding := findingIn(t, collector, testCase.file)
			if finding.Severity != testCase.wantSeverity || !strings.Contains(finding.Advice, testCase.wantAdvice) || finding.Type != "ai-api-key" {
				t.Errorf("severity %q, advice %q, type %q; want %q and advice with %q", finding.Severity, finding.Advice, finding.Type, testCase.wantSeverity, testCase.wantAdvice)
			}
		})
	}
}

func TestOtherFindingsDoNotChangeBecauseOfTheGitignore(t *testing.T) {
	collector, _ := scanProject(t, map[string]string{
		".gitignore":  "*\n",
		"app.py":      "KEY = '" + fakeEnvKey + "'\n",
		".env":        "PHONE=090-1234-5678\n",
		"aws.env.txt": "AKIAIOSFODNN7EXAMPLE\n",
	})

	collector.CheckIgnore(context.Background())

	if finding := findingIn(t, collector, "app.py"); finding.Severity != "high" || strings.Contains(finding.Advice, ".gitignore") {
		t.Errorf("a key in code: %+v", finding)
	}
	if finding := findingIn(t, collector, ".env"); finding.Severity != "medium" || finding.Type != "phone" || strings.Contains(finding.Advice, ".gitignore") {
		t.Errorf("a phone number in .env: %+v", finding)
	}
	if finding := findingIn(t, collector, "aws.env.txt"); finding.Severity != "high" || strings.Contains(finding.Advice, "keeps this file out") {
		t.Errorf("a key in a file that only has env in its name: %+v", finding)
	}
}

func TestWhenTheGitignoreCannotBeReadTheFirstAdviceStays(t *testing.T) {
	collector := NewCollector(&fakeTools{result: gateway.Result{Text: "backend/.env:6: [SECRET:ai-api-key:001]"}})
	collector.Call(context.Background(), "run_detectors", nil)
	tools := &fakeTools{err: gateway.ErrToolFailed}
	collector.inner = tools

	collector.CheckIgnore(context.Background())

	finding := findingIn(t, collector, "backend/.env")
	if finding.Severity != "high" || !strings.Contains(finding.Advice, "normal place") || tools.calls == 0 {
		t.Errorf("finding %+v after %d calls", finding, tools.calls)
	}
}

func TestCheckingTheGitignoreOnlyUsesReadOnlyToolsAndReadsEachFolderOnce(t *testing.T) {
	project := t.TempDir()
	for name, content := range map[string]string{".env": "K=" + fakeEnvKey + "\n", "backend/.env": "K=" + fakeEnvKey + "\n", ".gitignore": ".env\n"} {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	tools := gateway.New(root, gateway.DefaultLimits)
	var used []string
	tools.Observe(func(event gateway.Event) error { used = append(used, event.Tool); return nil })
	collector := NewCollector(tools)
	collector.Call(context.Background(), "run_detectors", map[string]any{"path": "."})
	used = nil

	collector.CheckIgnore(context.Background())

	listed, read := 0, 0
	for _, tool := range used {
		switch tool {
		case "list_dir":
			listed++
		case "read_file":
			read++
		default:
			t.Errorf("the tool %q was used", tool)
		}
	}
	if listed != 2 || read != 1 {
		t.Errorf("%d folders listed and %d files read, want 2 and 1 (the folder backend has no .gitignore): %v", listed, read, used)
	}
}

func TestAKeyThatGitIgnoresIsNotAFindingAndHasItsOwnSection(t *testing.T) {
	collector, _ := scanProject(t, map[string]string{
		".gitignore":      ".env\n",
		"backend/.env":    "K=" + fakeEnvKey + "\n",
		"web/config.json": "{\"phone\": \"090-1234-5678\"}\n",
	})
	collector.CheckIgnore(context.Background())

	report, err := Render(collector.Findings(), collector.Stats(), agent.Outcome{Status: agent.Complete})
	if err != nil {
		t.Fatal(err)
	}

	table := report[strings.Index(report, "## Findings"):strings.Index(report, "## Kept out of git")]
	if strings.Contains(table, "backend/.env") || !strings.Contains(table, "web/config.json") {
		t.Errorf("the table must hold the phone number and not the ignored key:\n%s", table)
	}
	section := report[strings.Index(report, "## Kept out of git"):]
	for _, want := range []string{"not counted as findings", "- backend/.env:1 [SECRET:ai-api-key:001] (ai-api-key)", "the normal setup for a key", "could not ask git about the history", "git log --all --oneline -- the-file", "revoke it and create a new one"} {
		if !strings.Contains(section, want) {
			t.Errorf("the section has no %q:\n%s", want, section)
		}
	}
	if strings.Contains(report[strings.Index(report, "## Fixes"):strings.Index(report, "## Kept out of git")], "ai-api-key") {
		t.Error("the ignored key has a fix line")
	}
}

func TestWhenOnlyIgnoredKeysAreFoundTheReportSaysNoExposedData(t *testing.T) {
	collector, _ := scanProject(t, map[string]string{".gitignore": ".env\n", ".env": "K=" + fakeEnvKey + "\n"})
	collector.CheckIgnore(context.Background())

	report, err := Render(collector.Findings(), collector.Stats(), agent.Outcome{Status: agent.Complete})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"reported no exposed data", "## Kept out of git", "- .env:1 [SECRET:ai-api-key:001]"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report has no %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "| ID | Severity") || strings.Contains(report, "## Fixes") {
		t.Errorf("the report has a table or fixes for a key that is kept out of git:\n%s", report)
	}
}

type fakeHistory struct {
	answers map[string]githistory.Answer
	asked   []string
}

func (history *fakeHistory) Commits(ctx context.Context, path string) githistory.Answer {
	history.asked = append(history.asked, path)

	return history.answers[path]
}

func TestAnIgnoredEnvFileThatWasCommittedBeforeIsAFindingAndOneThatWasNeverIsNot(t *testing.T) {
	collector, _ := scanProject(t, map[string]string{
		".gitignore":   ".env\n",
		"old/.env":     "K=" + fakeEnvKey + "\n",
		"fresh/.env":   "K=" + fakeEnvKey + "\n",
		"unknown/.env": "K=" + fakeEnvKey + "\n",
		"app.py":       "x = 1\n",
	})
	history := &fakeHistory{answers: map[string]githistory.Answer{
		"old/.env":   {Checked: true, Commits: []string{"8007644", "3c2786b"}},
		"fresh/.env": {Checked: true},
	}}
	collector.SetHistory(history)

	collector.CheckIgnore(context.Background())

	old := findingIn(t, collector, "old/.env")
	if old.Severity != "high" || !strings.Contains(old.Advice, "is ignored by .gitignore today, but git has it in its history (commits 8007644, 3c2786b)") || !strings.Contains(old.Advice, "revoke it and create a new one") {
		t.Errorf("a file in the history: %+v", old)
	}
	if fresh := findingIn(t, collector, "fresh/.env"); fresh.Severity != SeverityKeptOut || fresh.History != "clean" {
		t.Errorf("a file never committed: %+v", fresh)
	}
	if unknown := findingIn(t, collector, "unknown/.env"); unknown.Severity != SeverityKeptOut || unknown.History != "unchecked" {
		t.Errorf("a file that git could not be asked about: %+v", unknown)
	}
	if len(history.asked) != 3 {
		t.Errorf("git was asked about %v, want the three ignored env files", history.asked)
	}

	report, err := Render(collector.Findings(), collector.Stats(), agent.Outcome{Status: agent.Complete})
	if err != nil {
		t.Fatal(err)
	}
	table := report[strings.Index(report, "## Findings"):strings.Index(report, "## Kept out of git")]
	if !strings.Contains(table, "| high | ai-api-key | old/.env |") || strings.Contains(table, "fresh/.env") {
		t.Errorf("the table:\n%s", table)
	}
	if !strings.Contains(report, "- ai-api-key in an env file that is in the git history (1): This env file is ignored by .gitignore today, but git has it in its history") {
		t.Errorf("the fixes do not name the file in the history:\n%s", report)
	}
}

func TestWhenGitSaysEveryIgnoredEnvFileWasNeverCommittedTheReportSaysSo(t *testing.T) {
	collector, _ := scanProject(t, map[string]string{".gitignore": ".env\n", ".env": "K=" + fakeEnvKey + "\n"})
	collector.SetHistory(&fakeHistory{answers: map[string]githistory.Answer{".env": {Checked: true}}})
	collector.CheckIgnore(context.Background())

	report, err := Render(collector.Findings(), collector.Stats(), agent.Outcome{Status: agent.Complete})
	if err != nil {
		t.Fatal(err)
	}

	section := report[strings.Index(report, "## Kept out of git"):]
	if !strings.Contains(section, "Omamori asked git about the history of each file: none of them was ever committed.") || strings.Contains(section, "could not ask git") {
		t.Errorf("the section:\n%s", section)
	}
}

func TestGitIsNotAskedAboutFilesThatAreNotIgnoredEnvFiles(t *testing.T) {
	collector, _ := scanProject(t, map[string]string{".env": "K=" + fakeEnvKey + "\n", "app.py": "K = '" + fakeEnvKey + "'\n"})
	history := &fakeHistory{}
	collector.SetHistory(history)

	collector.CheckIgnore(context.Background())

	if len(history.asked) != 0 {
		t.Errorf("git was asked about %v", history.asked)
	}
}
