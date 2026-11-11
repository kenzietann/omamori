package githistory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireGit(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

func git(t *testing.T, directory string, arguments ...string) {
	t.Helper()

	command := exec.Command("git", arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
}

func write(t *testing.T, directory, name, content string) {
	t.Helper()

	path := filepath.Join(directory, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func repositoryWithHistory(t *testing.T) string {
	t.Helper()
	requireGit(t)

	directory := t.TempDir()
	git(t, directory, "init", "-q")
	write(t, directory, ".env", "A=1\n")
	write(t, directory, "keep.txt", "x\n")
	git(t, directory, "add", ".")
	git(t, directory, "commit", "-q", "-m", "first")
	git(t, directory, "rm", "-q", ".env")
	git(t, directory, "commit", "-q", "-m", "delete env")
	write(t, directory, ".env", "A=2\n")
	write(t, directory, ".gitignore", ".env\n")
	git(t, directory, "add", ".gitignore")
	git(t, directory, "commit", "-q", "-m", "ignore env")

	return directory
}

func TestAFileThatWasCommittedAndDeletedIsStillInTheHistory(t *testing.T) {
	directory := repositoryWithHistory(t)

	answer := New(directory).Commits(context.Background(), ".env")

	if !answer.Checked || len(answer.Commits) != 2 || answer.More {
		t.Errorf("answer = %+v, want 2 commits (the add and the delete)", answer)
	}
}

func TestAFileThatWasNeverCommittedHasNoCommits(t *testing.T) {
	directory := repositoryWithHistory(t)
	write(t, directory, "never.env", "K=1\n")

	answer := New(directory).Commits(context.Background(), "never.env")

	if !answer.Checked || len(answer.Commits) != 0 {
		t.Errorf("answer = %+v, want checked with no commits", answer)
	}
}

func TestARepositoryInsideTheProjectFolderIsFoundAndItsHistoryUsed(t *testing.T) {
	requireGit(t)
	project := t.TempDir()
	repository := filepath.Join(project, "backend")
	if err := os.MkdirAll(repository, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, repository, "init", "-q")
	write(t, repository, ".env", "A=1\n")
	git(t, repository, "add", ".")
	git(t, repository, "commit", "-q", "-m", "add")

	answer := New(project).Commits(context.Background(), "backend/.env")

	if !answer.Checked || len(answer.Commits) != 1 {
		t.Errorf("answer = %+v", answer)
	}
}

func TestMoreThanFiveCommitsAreCutAndSaidSo(t *testing.T) {
	requireGit(t)
	directory := t.TempDir()
	git(t, directory, "init", "-q")
	for index := 0; index < 8; index++ {
		write(t, directory, ".env", strings.Repeat("a", index+1)+"\n")
		git(t, directory, "add", ".")
		git(t, directory, "commit", "-q", "-m", "change")
	}

	answer := New(directory).Commits(context.Background(), ".env")

	if !answer.Checked || len(answer.Commits) != maxCommits || !answer.More {
		t.Errorf("answer = %+v", answer)
	}
}

func TestWithoutARepositoryOrGitTheAnswerIsNotChecked(t *testing.T) {
	directory := t.TempDir()
	write(t, directory, ".env", "A=1\n")

	if answer := New(directory).Commits(context.Background(), ".env"); answer.Checked {
		t.Errorf("a folder with no repository was checked: %+v", answer)
	}
	if answer := (&Reader{root: directory}).Commits(context.Background(), ".env"); answer.Checked {
		t.Errorf("a reader with no git program checked: %+v", answer)
	}
	var none *Reader
	if answer := none.Commits(context.Background(), ".env"); answer.Checked {
		t.Errorf("a nil reader checked: %+v", answer)
	}
}

func TestOddPathsAreRefusedOrFindNothing(t *testing.T) {
	directory := repositoryWithHistory(t)
	reader := New(directory)

	for _, path := range []string{"", "../outside", "a\x00b", "--all", "-n1", ":(top).env", "*", ".e?v"} {
		if answer := reader.Commits(context.Background(), path); len(answer.Commits) != 0 {
			t.Errorf("path %q gave commits: %+v", path, answer)
		}
	}
}

func TestARepositoryCannotMakeGitRunAProgram(t *testing.T) {
	requireGit(t)
	directory := t.TempDir()
	git(t, directory, "init", "-q")
	write(t, directory, ".env", "A=1\n")
	git(t, directory, "add", ".")
	git(t, directory, "commit", "-q", "-m", "add")

	marker := filepath.Join(t.TempDir(), "pwned")
	script := filepath.Join(t.TempDir(), "run.sh")
	write(t, filepath.Dir(script), filepath.Base(script), "#!/bin/sh\ntouch "+marker+"\n")
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	hostile := "\n[core]\n\tfsmonitor = " + script + "\n\tpager = " + script + "\n\tsshCommand = " + script + "\n\thooksPath = " + filepath.Dir(script) +
		"\n[diff]\n\texternal = " + script + "\n[alias]\n\tlog = !" + script + "\n[log]\n\tshowSignature = true\n[gpg]\n\tprogram = " + script + "\n"
	file, err := os.OpenFile(filepath.Join(directory, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(hostile); err != nil {
		t.Fatal(err)
	}
	file.Close()
	write(t, directory, ".gitattributes", "*.env diff=evil\n")
	write(t, directory, ".git/info/attributes", "* diff=evil\n")

	answer := New(directory).Commits(context.Background(), ".env")

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a program from the repository was run")
	}
	if !answer.Checked || len(answer.Commits) != 1 {
		t.Errorf("answer = %+v, the hostile repository must still be answered", answer)
	}
}

func TestACommitIdThatLooksOddMakesTheAnswerUnchecked(t *testing.T) {
	if commitID.MatchString("abc123; rm -rf") || commitID.MatchString("ABCDEF1") || commitID.MatchString("abc") || !commitID.MatchString("abc1234") {
		t.Error("the commit id pattern is wrong")
	}
}
