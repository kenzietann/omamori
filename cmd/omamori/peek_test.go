package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func peekSetup(t *testing.T) (report, project string) {
	t.Helper()

	project = t.TempDir()
	report = filepath.Join(t.TempDir(), "run-1")
	if err := os.MkdirAll(filepath.Join(project, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "web", "lib.js"), []byte("var help='call 0120-123-456 now';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(report, 0o755); err != nil {
		t.Fatal(err)
	}
	text := "# Omamori report\n\n## Library and generated files (not counted as findings)\n\n- web/lib.js:1 [PHONE:001] (phone)\n- web/gone.js:3 [PHONE:002] (phone)\n"
	if err := os.WriteFile(filepath.Join(report, "report.md"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	return report, project
}

func listing(t *testing.T, folders ...string) string {
	t.Helper()

	var out strings.Builder
	for _, folder := range folders {
		filepath.WalkDir(folder, func(path string, entry os.DirEntry, err error) error {
			out.WriteString(path + "\n")
			return nil
		})
	}

	return out.String()
}

func TestPeekShowsMaskedMatchesOnTheScreenAndWritesNothing(t *testing.T) {
	report, project := peekSetup(t)
	before := listing(t, report, project)
	var stdout, stderr bytes.Buffer

	code := run([]string{"peek", report, project}, environment{stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" }})

	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	for _, want := range []string{"[PHONE:001]  web/lib.js:1", "value:   012*-***-*56", "context: var help='call 012*-***-*56 now';", "[PHONE:002]  web/gone.js:3", "not shown: the file is not there", "Nothing is saved, and nothing is sent"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "123") {
		t.Errorf("the middle of the number is shown:\n%s", stdout.String())
	}
	if after := listing(t, report, project); after != before {
		t.Errorf("peek changed the files:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestPeekRevealShowsTheValueAndAReportFileWorksAsWellAsAFolder(t *testing.T) {
	report, project := peekSetup(t)
	var stdout, stderr bytes.Buffer

	code := run([]string{"peek", filepath.Join(report, "report.md"), "--reveal", project}, environment{stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" }})

	if code != exitOK || !strings.Contains(stdout.String(), "value:   0120-123-456") || !strings.Contains(stdout.String(), "shown as they are") {
		t.Errorf("code %d, stdout:\n%s\nstderr %q", code, stdout.String(), stderr.String())
	}
}

func TestPeekRefusesBadArguments(t *testing.T) {
	report, project := peekSetup(t)
	empty := t.TempDir()
	testCases := []struct {
		name     string
		args     []string
		wantCode int
		wantText string
	}{
		{"no arguments", []string{"peek"}, exitUsage, "usage: omamori peek"},
		{"one argument", []string{"peek", report}, exitUsage, "usage: omamori peek"},
		{"an unknown flag", []string{"peek", "--nope", report, project}, exitUsage, "usage: omamori peek"},
		{"no report there", []string{"peek", empty, project}, exitFailed, "no report was found"},
		{"a report with no matches", []string{"peek", writeReport(t, "# nothing\n"), project}, exitFailed, "lists no matches"},
		{"no project folder", []string{"peek", report, filepath.Join(empty, "missing")}, exitFailed, "project folder is not usable"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(testCase.args, environment{stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" }})

			if code != testCase.wantCode || !strings.Contains(stderr.String(), testCase.wantText) || strings.Contains(stdout.String(), "value:") {
				t.Errorf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func writeReport(t *testing.T, text string) string {
	t.Helper()

	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "report.md"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	return folder
}
