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

type Answer struct {
	Checked bool
	Commits []string
	More bool
}

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
