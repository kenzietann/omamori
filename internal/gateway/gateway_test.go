package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/pathguard"
)

const (
	fakeAWSKey      = "AKIAIOSFODNN7EXAMPLE"
	outsideAWSKey   = "ASIAIOSFODNN7EXAMPLE"
	fakePhoneNumber = "090-1234-5678"
	fakeMyNumber    = "123456789018"
)

var testLimits = Limits{
	MaxFileBytes:    200,
	MaxLines:        10,
	MaxResults:      3,
	MaxFiles:        20,
	MaxStringLength: 50,
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func makeSymlink(t *testing.T, target, link string) {
	t.Helper()

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func makeGateway(t *testing.T, limits Limits) *Gateway {
	t.Helper()

	workspace := t.TempDir()
	project := filepath.Join(workspace, "project")
	outside := filepath.Join(workspace, "outside")

	writeFile(t, filepath.Join(project, "notes.txt"), "line one\nline two with token\nline three\n")
	writeFile(t, filepath.Join(project, "sub", "config.txt"), "aws = "+fakeAWSKey+"\nphone "+fakePhoneNumber+"\n")
	writeFile(t, filepath.Join(project, fakeAWSKey+".txt"), "id "+fakeMyNumber+"\n")
	writeFile(t, filepath.Join(project, "big.txt"), strings.Repeat("x", 300))
	writeFile(t, filepath.Join(project, "many.txt"), strings.Repeat("a\n", 12))
	writeFile(t, filepath.Join(project, "hits.txt"), strings.Repeat("hit\n", 4))
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside content "+outsideAWSKey+"\n")

	makeSymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(project, "escape-file"))
	makeSymlink(t, outside, filepath.Join(project, "escape-dir"))
	makeSymlink(t, "notes.txt", filepath.Join(project, "inside-link"))

	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}

	return New(root, limits)
}

func TestCallRefusals(t *testing.T) {
	testCases := []struct {
		name      string
		toolName  string
		arguments map[string]any
		wantError error
	}{
		{"unknown tool", "delete_file", map[string]any{"path": "notes.txt"}, ErrUnknownTool},
		{"tool name in capitals", "READ_FILE", map[string]any{"path": "notes.txt"}, ErrUnknownTool},
		{"shell tool", "run_shell", map[string]any{"command": "ls"}, ErrUnknownTool},
		{"empty tool name", "", nil, ErrUnknownTool},
		{"missing required argument", "read_file", map[string]any{}, ErrInvalidArguments},
		{"no arguments at all", "read_file", nil, ErrInvalidArguments},
		{"argument is a number", "read_file", map[string]any{"path": 123}, ErrInvalidArguments},
		{"argument is a list", "read_file", map[string]any{"path": []string{"notes.txt"}}, ErrInvalidArguments},
		{"argument is null", "read_file", map[string]any{"path": nil}, ErrInvalidArguments},
		{"unknown argument", "read_file", map[string]any{"path": "notes.txt", "mode": "write"}, ErrInvalidArguments},
		{"argument too long", "read_file", map[string]any{"path": strings.Repeat("a", 51)}, ErrInvalidArguments},
		{"NUL byte in an argument", "read_file", map[string]any{"path": "notes\x00.txt"}, ErrInvalidArguments},
		{"empty required argument", "search_text", map[string]any{"query": ""}, ErrInvalidArguments},
		{"path in a tool that has no path", "search_text", map[string]any{"query": "a", "file": "notes.txt"}, ErrInvalidArguments},
		{"parent folder", "read_file", map[string]any{"path": "../outside/secret.txt"}, ErrPathNotAllowed},
		{"absolute path", "read_file", map[string]any{"path": "/etc/hosts"}, ErrPathNotAllowed},
		{"escape through dot segments", "read_file", map[string]any{"path": "sub/../../outside/secret.txt"}, ErrPathNotAllowed},
		{"symlink to an outside file", "read_file", map[string]any{"path": "escape-file"}, ErrPathNotAllowed},
		{"file behind a symlink to an outside folder", "read_file", map[string]any{"path": "escape-dir/secret.txt"}, ErrPathNotAllowed},
		{"missing file", "read_file", map[string]any{"path": "missing.txt"}, ErrPathNotAllowed},
		{"list an outside folder", "list_dir", map[string]any{"path": ".."}, ErrPathNotAllowed},
		{"list a folder behind a symlink", "list_dir", map[string]any{"path": "escape-dir"}, ErrPathNotAllowed},
		{"search an outside folder", "search_text", map[string]any{"query": "a", "path": "../outside"}, ErrPathNotAllowed},
		{"run detectors on an outside file", "run_detectors", map[string]any{"path": "../outside/secret.txt"}, ErrPathNotAllowed},
		{"file bigger than the limit", "read_file", map[string]any{"path": "big.txt"}, ErrLimitExceeded},
		{"file with more lines than the limit", "read_file", map[string]any{"path": "many.txt"}, ErrLimitExceeded},
		{"detectors on a single file over the limit", "run_detectors", map[string]any{"path": "big.txt"}, ErrLimitExceeded},
		{"read a folder", "read_file", map[string]any{"path": "sub"}, ErrInvalidArguments},
		{"list a file", "list_dir", map[string]any{"path": "notes.txt"}, ErrInvalidArguments},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gateway := makeGateway(t, testLimits)

			gotResult, err := gateway.Call(context.Background(), testCase.toolName, testCase.arguments)

			if !errors.Is(err, testCase.wantError) {
				t.Fatalf("Call error = %v, want %v", err, testCase.wantError)
			}
			if gotResult != (Result{}) {
				t.Errorf("a refused call returned data: %v", gotResult)
			}

			gotEvents := gateway.Events()
			if len(gotEvents) != 1 || gotEvents[0].Allowed || gotEvents[0].Reason != testCase.wantError.Error() {
				t.Errorf("events = %v, want one refused event with reason %q", gotEvents, testCase.wantError)
			}
		})
	}
}

func TestCallSucceeds(t *testing.T) {
	testCases := []struct {
		name          string
		toolName      string
		arguments     map[string]any
		wantText      string
		wantTruncated bool
		wantSkipped   int
	}{
		{"read a file", "read_file", map[string]any{"path": "notes.txt"}, "line one\nline two with token\nline three\n", false, 0},
		{"read through a symlink that stays inside", "read_file", map[string]any{"path": "inside-link"}, "line one\nline two with token\nline three\n", false, 0},
		{"list a folder", "list_dir", map[string]any{"path": "sub"}, "config.txt", false, 0},
		{"list the project, cut at the limit", "list_dir", map[string]any{}, fakeAWSKey + ".txt\nbig.txt\nescape-dir", true, 0},
		{"search one folder", "search_text", map[string]any{"query": "phone", "path": "sub"}, "sub/config.txt:2: phone " + fakePhoneNumber, false, 0},
		{"search the project", "search_text", map[string]any{"query": "token"}, "notes.txt:2: line two with token", false, 2},
		{"search does not follow symlinks", "search_text", map[string]any{"query": "outside"}, "", false, 2},
		{"search cut at the limit", "search_text", map[string]any{"query": "hit", "path": "hits.txt"}, "hits.txt:1: hit\nhits.txt:2: hit\nhits.txt:3: hit", true, 0},
		{"detectors on one file", "run_detectors", map[string]any{"path": "sub/config.txt"},
			"sub/config.txt:1: [SECRET:aws-access-key:001]\nsub/config.txt:2: [PHONE:001]", false, 0},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gateway := makeGateway(t, testLimits)

			gotResult, err := gateway.Call(context.Background(), testCase.toolName, testCase.arguments)

			if err != nil {
				t.Fatalf("Call returned an error: %v", err)
			}
			wantResult := Result{Text: testCase.wantText, Truncated: testCase.wantTruncated, Skipped: testCase.wantSkipped}
			if gotResult != wantResult {
				t.Errorf("Call = %+v, want %+v", gotResult, wantResult)
			}

			gotEvents := gateway.Events()
			if len(gotEvents) != 1 || !gotEvents[0].Allowed {
				t.Errorf("events = %v, want one allowed event", gotEvents)
			}
		})
	}
}

func TestRunDetectorsHidesTheValues(t *testing.T) {
	gateway := makeGateway(t, testLimits)

	gotResult, err := gateway.Call(context.Background(), "run_detectors", map[string]any{"path": "."})
	if err != nil {
		t.Fatal(err)
	}

	wantText := "[SECRET:aws-access-key:001].txt:1: [MYNUMBER:001]\n" +
		"sub/config.txt:1: [SECRET:aws-access-key:002]\n" +
		"sub/config.txt:2: [PHONE:001]"
	if gotResult.Text != wantText {
		t.Errorf("run_detectors text = %q, want %q", gotResult.Text, wantText)
	}
	if gotResult.Skipped != 2 {
		t.Errorf("skipped files = %d, want 2", gotResult.Skipped)
	}

	for _, plantedValue := range []string{fakeAWSKey, fakePhoneNumber, fakeMyNumber, outsideAWSKey} {
		if strings.Contains(gotResult.Text, plantedValue) {
			t.Errorf("the planted value %q is in the result", plantedValue)
		}
	}
}

func TestEventsNeverHoldArguments(t *testing.T) {
	gateway := makeGateway(t, testLimits)
	calls := []struct {
		toolName  string
		arguments map[string]any
	}{
		{fakeAWSKey, map[string]any{"path": "notes.txt"}},
		{"read_file", map[string]any{"path": fakeAWSKey + "/../../" + fakePhoneNumber}},
		{"read_file", map[string]any{"path": fakeAWSKey + ".txt"}},
		{"read_file", map[string]any{fakeAWSKey: "value"}},
	}

	for _, call := range calls {
		_, err := gateway.Call(context.Background(), call.toolName, call.arguments)
		if err != nil && (strings.Contains(err.Error(), fakeAWSKey) || strings.Contains(err.Error(), fakePhoneNumber)) {
			t.Errorf("the error text holds an argument: %q", err.Error())
		}
	}

	for _, event := range gateway.Events() {
		if strings.Contains(event.Tool, fakeAWSKey) || strings.Contains(event.Reason, fakeAWSKey) || strings.Contains(event.Reason, fakePhoneNumber) {
			t.Errorf("the event holds an argument: %v", event)
		}
	}
}

func TestObserverSeesEveryEvent(t *testing.T) {
	gateway := makeGateway(t, testLimits)
	var seen []Event
	gateway.Observe(func(event Event) error {
		seen = append(seen, event)
		return nil
	})

	gateway.Call(context.Background(), "read_file", map[string]any{"path": "notes.txt"})
	gateway.Call(context.Background(), "read_file", map[string]any{"path": "../outside/secret.txt"})
	gateway.Call(context.Background(), "delete_file", nil)

	if len(seen) != 3 || !seen[0].Allowed || seen[1].Allowed || seen[2].Allowed {
		t.Errorf("the observer saw %v, want three events: allowed, refused, refused", seen)
	}
}

func TestFailedObserverStopsTheResult(t *testing.T) {
	gateway := makeGateway(t, testLimits)
	gateway.Observe(func(Event) error { return errors.New("disk full") })

	gotResult, err := gateway.Call(context.Background(), "read_file", map[string]any{"path": "notes.txt"})

	if !errors.Is(err, ErrLogFailed) {
		t.Errorf("Call error = %v, want %v", err, ErrLogFailed)
	}
	if gotResult != (Result{}) {
		t.Errorf("a call that could not be logged returned data: %+v", gotResult)
	}
}

func TestCancelledContext(t *testing.T) {
	gateway := makeGateway(t, testLimits)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := gateway.Call(ctx, "read_file", map[string]any{"path": "notes.txt"})

	if !errors.Is(err, ErrCancelled) {
		t.Errorf("Call error = %v, want %v", err, ErrCancelled)
	}
	gotEvents := gateway.Events()
	if len(gotEvents) != 1 || gotEvents[0].Allowed {
		t.Errorf("events = %v, want one refused event", gotEvents)
	}
}

func TestFileLimitStopsTheWalk(t *testing.T) {
	limits := testLimits
	limits.MaxFiles = 2
	gateway := makeGateway(t, limits)

	gotResult, err := gateway.Call(context.Background(), "search_text", map[string]any{"query": "token"})
	if err != nil {
		t.Fatal(err)
	}

	if !gotResult.Truncated {
		t.Error("the result is not marked as cut, but the walk stopped at the file limit")
	}
}

func TestSpecsDescribeExactlyTheAllowedTools(t *testing.T) {
	root, err := pathguard.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	toolGateway := New(root, DefaultLimits)

	specs := toolGateway.Specs()

	wantNames := []string{"list_dir", "read_file", "run_detectors", "search_text"}
	var gotNames []string
	for _, spec := range specs {
		gotNames = append(gotNames, spec.Name)

		if spec.Description == "" {
			t.Errorf("the tool %s has no description", spec.Name)
		}
		for _, parameter := range spec.Parameters {
			if parameter.Name == "" || parameter.Description == "" {
				t.Errorf("the tool %s has a parameter without a name or a description: %+v", spec.Name, parameter)
			}
		}

		// A described tool must be a tool that the gateway really runs: an empty call is
		// refused because of its arguments, never because the tool is unknown.
		if _, err := toolGateway.Call(context.Background(), spec.Name, map[string]any{"unknown_argument": "x"}); errors.Is(err, ErrUnknownTool) {
			t.Errorf("the tool %s is described but the gateway does not know it", spec.Name)
		}
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("tool names = %v, want %v", gotNames, wantNames)
	}

	required := map[string][]string{"read_file": {"path"}, "list_dir": nil, "search_text": {"query"}, "run_detectors": {"path"}}
	for _, spec := range specs {
		var gotRequired []string
		for _, parameter := range spec.Parameters {
			if parameter.Required {
				gotRequired = append(gotRequired, parameter.Name)
			}
		}
		if !slices.Equal(gotRequired, required[spec.Name]) {
			t.Errorf("tool %s: required parameters = %v, want %v", spec.Name, gotRequired, required[spec.Name])
		}
	}

	if !reflect.DeepEqual(specs, toolGateway.Specs()) {
		t.Error("the specs changed between two calls")
	}
}

func gitProject(t *testing.T) *Gateway {
	t.Helper()

	project := filepath.Join(t.TempDir(), "project")
	writeFile(t, filepath.Join(project, "app.txt"), "ok "+fakeAWSKey+"\n")
	writeFile(t, filepath.Join(project, ".git", "logs", "HEAD"), "commit "+fakeMyNumber+"\n")
	writeFile(t, filepath.Join(project, "vendor", ".git", "config"), "id "+fakeMyNumber+"\n")
	writeFile(t, filepath.Join(project, "worktree", ".git"), "gitdir: "+fakeMyNumber+"\n")
	writeFile(t, filepath.Join(project, "worktree", "next.txt"), "phone "+fakePhoneNumber+"\n")
	writeFile(t, filepath.Join(project, ".github", "workflow.txt"), "phone "+fakePhoneNumber+"\n")
	writeFile(t, filepath.Join(project, ".gitignore"), "id "+fakeMyNumber+"\n")
	writeFile(t, filepath.Join(project, "my.git", "file.txt"), "id "+fakeMyNumber+"\n")

	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}

	limits := testLimits
	limits.MaxResults = 50

	return New(root, limits)
}

func TestTheGitFolderIsNotScanned(t *testing.T) {
	gateway := gitProject(t)

	detected, err := gateway.Call(context.Background(), "run_detectors", map[string]any{"path": "."})
	if err != nil {
		t.Fatal(err)
	}
	wantText := ".git/logs/HEAD"
	for _, notScanned := range []string{wantText, "vendor/.git/config", "worktree/.git:"} {
		if strings.Contains(detected.Text, notScanned) {
			t.Errorf("run_detectors looked into %s:\n%s", notScanned, detected.Text)
		}
	}
	for _, scanned := range []string{"app.txt", "worktree/next.txt", ".github/workflow.txt", ".gitignore", "my.git/file.txt"} {
		if !strings.Contains(detected.Text, scanned) {
			t.Errorf("run_detectors skipped %s, which is not a .git folder:\n%s", scanned, detected.Text)
		}
	}

	searched, err := gateway.Call(context.Background(), "search_text", map[string]any{"query": "commit"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(searched.Text, ".git/logs") {
		t.Errorf("search_text looked into .git:\n%s", searched.Text)
	}
}

func TestAPathThatIsTheGitFolderItselfIsStillScanned(t *testing.T) {
	gateway := gitProject(t)

	detected, err := gateway.Call(context.Background(), "run_detectors", map[string]any{"path": ".git"})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(detected.Text, "logs/HEAD") {
		t.Errorf("a scan of the .git folder by name found nothing:\n%s", detected.Text)
	}
}

func TestDependencyFoldersAndGeneratedFilesAreNotScanned(t *testing.T) {
	project := filepath.Join(t.TempDir(), "project")
	hit := "id " + fakeMyNumber + "\n"
	notScanned := []string{
		"node_modules/pkg/index.js", "backend/node_modules/@scope/pkg/CHANGELOG.md", "vendor/lib/code.go",
		"__pycache__/mod.txt", ".venv/lib/x.txt", "venv/lib/x.txt",
		"package-lock.json", "web/yarn.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock", "composer.lock", "poetry.lock", "Gemfile.lock",
		"dist/tsconfig.build.tsbuildinfo", "tsconfig.tsbuildinfo",
	}
	scanned := []string{
		"src/app.txt", "dist/bundle.txt", "build/out.txt", "node_modules_backup/x.txt", "my-vendor/x.txt", "venv2/x.txt",
		"package-lock.json.bak", "yarn.lock.txt", "tsbuildinfo.txt", "notes/vendor.txt",
	}
	for _, name := range append(append([]string{}, notScanned...), scanned...) {
		writeFile(t, filepath.Join(project, name), hit)
	}
	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	limits := testLimits
	limits.MaxResults, limits.MaxFiles = 100, 100
	gateway := New(root, limits)

	detected, err := gateway.Call(context.Background(), "run_detectors", map[string]any{"path": "."})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range notScanned {
		if strings.Contains(detected.Text, name+":") {
			t.Errorf("%s was scanned:\n%s", name, detected.Text)
		}
	}
	for _, name := range scanned {
		if !strings.Contains(detected.Text, name+":") {
			t.Errorf("%s was not scanned, but its name is not on the list:\n%s", name, detected.Text)
		}
	}
}

func TestAPathInsideADependencyFolderOrALockFileIsScannedWhenNamed(t *testing.T) {
	project := filepath.Join(t.TempDir(), "project")
	hit := "id " + fakeMyNumber + "\n"
	writeFile(t, filepath.Join(project, "node_modules", "pkg", "a.txt"), hit)
	writeFile(t, filepath.Join(project, "node_modules", "pkg", "node_modules", "deep", "b.txt"), hit)
	writeFile(t, filepath.Join(project, "package-lock.json"), hit)
	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	gateway := New(root, testLimits)

	named, err := gateway.Call(context.Background(), "run_detectors", map[string]any{"path": "node_modules/pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(named.Text, "a.txt:1") || strings.Contains(named.Text, "deep/b.txt") {
		t.Errorf("a named folder is walked, but its own dependency folders are not:\n%s", named.Text)
	}

	file, err := gateway.Call(context.Background(), "run_detectors", map[string]any{"path": "package-lock.json"})
	if err != nil || !strings.Contains(file.Text, "package-lock.json:1") {
		t.Errorf("a lock file named as the path was not scanned (err %v):\n%s", err, file.Text)
	}
}

func TestSkippedEntry(t *testing.T) {
	testCases := []struct {
		name  string
		isDir bool
		want  bool
	}{
		{".git", true, true}, {".git", false, true}, {"node_modules", true, true}, {"node_modules", false, false},
		{"vendor", true, true}, {"vendor", false, false}, {"venv", true, true}, {".venv", true, true}, {"__pycache__", true, true},
		{"dist", true, false}, {"build", true, false}, {"Node_Modules", true, false},
		{"go.sum", false, true}, {"go.sum", true, false}, {"x.tsbuildinfo", false, true}, {".tsbuildinfo", false, true},
		{"x.tsbuildinfo.txt", false, false}, {"main.go", false, false}, {"", false, false},
		{"Pods", true, true}, {"SourcePackages", true, true}, {".angular", true, true}, {".gradle", true, true}, {"site-packages", true, true},
		{"skills", true, false}, {"plugins", true, false},
	}

	for _, testCase := range testCases {
		if got := skippedEntry(testCase.name, "project", testCase.isDir); got != testCase.want {
			t.Errorf("skippedEntry(%q, %v) = %v, want %v", testCase.name, testCase.isDir, got, testCase.want)
		}
	}
}

func TestSkillsAndPluginsOfAICodingToolsAreSkippedOnlyInsideThoseToolFolders(t *testing.T) {
	for _, testCase := range []struct {
		name, parent string
		want         bool
	}{
		{"skills", ".agents", true}, {"skills", ".claude", true}, {"plugins", ".claude", true}, {"extensions", ".cursor", true},
		{"marketplace", ".codex", true}, {"skills", "src", false}, {"plugins", "app", false}, {"skills", "", false}, {"commands", ".claude", false},
		{"agents", ".claude", false},
	} {
		if got := skippedEntry(testCase.name, testCase.parent, true); got != testCase.want {
			t.Errorf("skippedEntry(%q, parent %q, dir) = %v, want %v", testCase.name, testCase.parent, got, testCase.want)
		}
	}
}

func TestFullScanFindsWhatTheCappedScanMissedWithTheSamePlaceholders(t *testing.T) {
	project := t.TempDir()
	for index := 0; index < 8; index++ {
		write(t, project, fmt.Sprintf("aaa/noise%d.txt", index), "tel 03-1234-5678\n")
	}
	write(t, project, "zzz/app.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits
	limits.MaxResults = 3
	tools := New(root, limits)

	capped, err := tools.Call(context.Background(), "run_detectors", map[string]any{"path": "."})
	if err != nil {
		t.Fatal(err)
	}
	full, err := tools.FullScan(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}

	if !capped.Truncated || strings.Contains(capped.Text, "zzz/app.py") || len(strings.Split(capped.Text, "\n")) != 3 {
		t.Errorf("the capped scan: truncated %v\n%s", capped.Truncated, capped.Text)
	}
	if full.Truncated || !strings.Contains(full.Text, "zzz/app.py:1: [SECRET:aws-access-key:001]") || len(strings.Split(full.Text, "\n")) != 9 {
		t.Errorf("the full scan: truncated %v\n%s", full.Truncated, full.Text)
	}
	if !strings.HasPrefix(full.Text, capped.Text) {
		t.Errorf("the placeholders of the AI's scan are not the same as in the full scan:\ncapped:\n%s\nfull:\n%s", capped.Text, full.Text)
	}
}

func TestTheFileLimitDoesNotHideTheFoldersAfterIt(t *testing.T) {
	project := t.TempDir()
	for index := 0; index < 6; index++ {
		write(t, project, fmt.Sprintf("aaa/file%d.txt", index), "nothing\n")
	}
	write(t, project, "zzz/app.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits
	limits.MaxFiles = 4
	tools := New(root, limits)

	capped, _ := tools.Call(context.Background(), "run_detectors", map[string]any{"path": "."})
	full, err := tools.FullScan(context.Background(), ".")

	if err != nil || !capped.Truncated || capped.Text != "" || full.Truncated || !strings.Contains(full.Text, "zzz/app.py:1") {
		t.Errorf("capped %+v, full %+v, err %v", capped, full, err)
	}
}

func TestFullScanIsLoggedAndRefusesPathsOutsideTheProject(t *testing.T) {
	project := t.TempDir()
	root, _ := pathguard.NewRoot(project)
	tools := New(root, DefaultLimits)
	var events []Event
	tools.Observe(func(event Event) error { events = append(events, event); return nil })

	if _, err := tools.FullScan(context.Background(), "."); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.FullScan(context.Background(), "../outside"); err == nil {
		t.Error("a path outside the project was scanned")
	}

	if len(events) != 2 || events[0].Tool != "full_scan" || !events[0].Allowed || events[1].Allowed {
		t.Errorf("events = %+v", events)
	}
}

func write(t *testing.T, project, name, content string) {
	t.Helper()

	path := filepath.Join(project, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryFilesAreCountedApartFromFilesThatCouldNotBeRead(t *testing.T) {
	project := t.TempDir()
	write(t, project, "notes.txt", "tel 03-1234-5678\n")
	write(t, project, "logo.png", "\x89PNG\x00\x00\x00 09012345678")
	write(t, project, "font.woff", "wOFF\x00\x01")
	write(t, project, "big.txt", strings.Repeat("a", int(DefaultLimits.MaxFileBytes)+10))
	root, _ := pathguard.NewRoot(project)
	tools := New(root, DefaultLimits)

	capped, err := tools.Call(context.Background(), "run_detectors", map[string]any{"path": "."})
	full, fullErr := tools.FullScan(context.Background(), ".")

	for name, result := range map[string]Result{"run_detectors": capped, "full scan": full} {
		if result.Binary != 2 || result.Skipped != 1 || !strings.Contains(result.Text, "notes.txt:1: [PHONE:001]") {
			t.Errorf("%s: binary %d, skipped %d, text %q", name, result.Binary, result.Skipped, result.Text)
		}
	}
	if err != nil || fullErr != nil {
		t.Errorf("errors: %v, %v", err, fullErr)
	}
}

func TestAToolThatIsAskedToReadABinaryFileSaysToolFailedAndNothingMore(t *testing.T) {
	project := t.TempDir()
	write(t, project, "logo.png", "\x89PNG\x00\x00 09012345678")
	root, _ := pathguard.NewRoot(project)
	tools := New(root, DefaultLimits)
	var events []Event
	tools.Observe(func(event Event) error { events = append(events, event); return nil })

	for _, call := range []struct {
		tool      string
		arguments map[string]any
	}{
		{"read_file", map[string]any{"path": "logo.png"}},
		{"search_text", map[string]any{"query": "PNG", "path": "logo.png"}},
		{"run_detectors", map[string]any{"path": "logo.png"}},
	} {
		_, err := tools.Call(context.Background(), call.tool, call.arguments)

		if !errors.Is(err, ErrToolFailed) {
			t.Errorf("%s: err = %v, want ErrToolFailed", call.tool, err)
		}
	}
	for _, event := range events {
		if event.Allowed || event.Reason != ErrToolFailed.Error() {
			t.Errorf("event %+v must say only that the tool failed", event)
		}
	}
}
