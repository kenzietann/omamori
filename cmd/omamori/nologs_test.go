package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectOnACodeFolderSaysWhatWasLookedAt(t *testing.T) {
	code := t.TempDir()
	for name, text := range map[string]string{"main.go": "package main\n", "README.md": "# hello\n", "node_modules/x/index.js": "module.exports = 1\n"} {
		path := filepath.Join(code, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := runAt(t, detectNow, "detect", "--output", filepath.Join(t.TempDir(), "out"), code)
	if got.code != exitFailed || !strings.Contains(got.stderr, "none of the 2 files here looks like a log") {
		t.Fatalf("%d %s", got.code, got.stderr)
	}
}
