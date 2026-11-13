package intake

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const oneSSHLine = "Nov 12 14:06:09 web01 sshd[1]: Failed password for root from 172.21.0.3 port 35336 ssh2\n"

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDependencyAndCacheFoldersAreSkippedAndListed(t *testing.T) {
	root := writeTree(t, map[string]string{
		"logs/auth.log":                     oneSSHLine,
		"node_modules/pkg/auth.log":         oneSSHLine,
		"web/vendor/lib/auth.log":           oneSSHLine,
		"target/CACHEDIR.TAG":               "Signature: 8a477f597d28d172789f06886806bc55\n",
		"target/debug/auth.log":             oneSSHLine,
		"build/auth.log":                    oneSSHLine,
		"notes/CACHEDIR.TAG/not-a-file.txt": "a folder with the name is not the marker\n",
		"notes/auth.log":                    oneSSHLine,
	})
	read, err := Read([]string{root}, Options{Year: 2026, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range read.Files {
		names = append(names, file.File)
	}
	slices.Sort(names)
	if want := []string{"build/auth.log", "logs/auth.log", "notes/auth.log"}; !slices.Equal(names, want) {
		t.Fatalf("read %q, want %q", names, want)
	}
	for _, skipped := range []string{"node_modules: a folder of dependencies or a cache, not read", "web/vendor: a folder of dependencies or a cache, not read", "target: a folder of dependencies or a cache, not read"} {
		if !slices.Contains(read.Skipped, skipped) {
			t.Errorf("not listed as skipped: %q in %q", skipped, read.Skipped)
		}
	}
}

func TestAFolderThatIsGivenIsReadEvenIfItsNameIsSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{"vendor/auth.log": oneSSHLine})
	read, err := Read([]string{filepath.Join(root, "vendor")}, Options{Year: 2026, Location: time.UTC})
	if err != nil || len(read.Files) != 1 {
		t.Fatalf("read %+v %v", read, err)
	}
}

func TestTooManyFilesIsNotCalledTooManyEvents(t *testing.T) {
	files := map[string]string{}
	for index := range maxFiles + 1 {
		files[fmt.Sprintf("src/file%04d.txt", index)] = "x\n"
	}
	_, err := Read([]string{writeTree(t, files)}, Options{Year: 2026, Location: time.UTC})
	if !errors.Is(err, ErrTooManyFiles) || errors.Is(err, ErrTooBig) || !strings.Contains(err.Error(), "not a whole project") {
		t.Fatalf("error %v", err)
	}
}
