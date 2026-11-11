// Package githistory asks git if a file was ever committed. A .gitignore file only keeps a file out of the
// future: a key that was committed once and ignored later is still in the history, and anyone who can read
// the repository can read it.
//
// It runs git itself, with the one question "which commits touched this path". The repository is not trusted:
// its configuration could name programs that git would run, so git is started with a clean environment, the
// settings that run programs are turned off, no pager and no patch output are used, and it has a time limit.
// The answer is a count and short commit ids. No file content is read, and no value comes back.
package githistory

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	timeLimit  = 15 * time.Second
	maxCommits = 5
)

var commitID = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// Answer says what the history shows for one file.
type Answer struct {
	// Checked is false when git could not be asked: no git program, no repository, an error, or too slow.
	Checked bool
	// Commits are the short ids of the newest commits that touched the file. At most maxCommits.
	Commits []string
	// More is true when there are more commits than the ones listed.
	More bool
}

// Reader asks git about files inside one project folder.
type Reader struct {
	root string
	git  string
}

// New makes a reader for a project folder. Without a git program, every answer is "not checked".
func New(root string) *Reader {
	reader := &Reader{root: root}
	if path, err := exec.LookPath("git"); err == nil {
		reader.git = path
	}

	return reader
}

// Commits lists the commits that touched a file. The path is relative to the project folder.
func (reader *Reader) Commits(ctx context.Context, path string) Answer {
	if reader == nil || reader.git == "" || path == "" || strings.ContainsRune(path, 0) {
		return Answer{}
	}

	repository, relative, found := reader.repositoryOf(path)
	if !found {
		return Answer{}
	}

	ctx, cancel := context.WithTimeout(ctx, timeLimit)
	defer cancel()

	// --no-pager, no hooks, no file system monitor, no external diff or text conversion: nothing in the
	// repository can make git start a program. ":(literal)" stops the path from being read as a pattern.
	command := exec.CommandContext(ctx, reader.git,
		"--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
		"-c", "core.askPass=", "-c", "core.sshCommand=", "-c", "diff.external=", "-c", "log.showSignature=false",
		"log", "--all", "--no-textconv", "--no-ext-diff", "--format=%h", "-n", "6", "--", ":(literal)"+relative)
	command.Dir = repository
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_ASKPASS=/bin/false",
		"LC_ALL=C",
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = nil
	command.Stdin = nil

	if err := command.Run(); err != nil {
		return Answer{}
	}

	answer := Answer{Checked: true}
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !commitID.MatchString(line) {
			return Answer{}
		}
		if len(answer.Commits) == maxCommits {
			answer.More = true
			break
		}
		answer.Commits = append(answer.Commits, line)
	}

	return answer
}

// repositoryOf finds the nearest folder with a .git entry, from the folder of the file upward. A project folder
// can hold several repositories, or sit inside one that is above it. The file may be new in that repository: then
// git has no commit for it, and that is a true answer.
func (reader *Reader) repositoryOf(path string) (repository, relative string, found bool) {
	absolute := filepath.Join(reader.root, filepath.FromSlash(path))
	rootWithSeparator := filepath.Clean(reader.root) + string(filepath.Separator)
	if !strings.HasPrefix(absolute, rootWithSeparator) {
		return "", "", false
	}

	for directory := filepath.Dir(absolute); ; directory = filepath.Dir(directory) {
		if _, err := os.Lstat(filepath.Join(directory, ".git")); err == nil {
			relative, err := filepath.Rel(directory, absolute)
			if err != nil {
				return "", "", false
			}

			return directory, filepath.ToSlash(relative), true
		}
		if parent := filepath.Dir(directory); parent == directory {
			return "", "", false
		}
	}
}
