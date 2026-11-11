package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
