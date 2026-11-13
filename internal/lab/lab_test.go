package lab

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type entry struct {
	name, link, body string
	kind             byte
	mode             int64
	size             int64
}

func tarOf(t *testing.T, entries []entry) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	when := time.Date(2026, 11, 13, 2, 50, 0, 0, time.UTC)
	for _, current := range entries {
		header := &tar.Header{Name: current.name, Linkname: current.link, Typeflag: current.kind, Mode: current.mode, ModTime: when, Size: int64(len(current.body))}
		if current.size != 0 {
			header.Size = current.size
		}
		if header.Mode == 0 {
			header.Mode = 0o644
		}
		if current.kind != tar.TypeReg {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if current.kind == tar.TypeReg && current.size == 0 {
			writer.Write([]byte(current.body))
		}
	}
	writer.Close()

	return out.Bytes()
}

func TestExtractKeepsTheCopyInsideItsFolder(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	os.Mkdir(outside, 0o700)
	data := tarOf(t, []entry{
		{name: "etc/", kind: tar.TypeDir},
		{name: "etc/passwd", kind: tar.TypeReg, body: "root:x:0:0::/root:/bin/bash\n"},
		{name: "tmp/.u.sh", kind: tar.TypeReg, body: "#!/bin/sh\n", mode: 0o4777},
		{name: "../escape", kind: tar.TypeReg, body: "out"},
		{name: "/abs/file", kind: tar.TypeReg, body: "abs"},
		{name: "home/alice/.bash_history", kind: tar.TypeSymlink, link: "/dev/null"},
		{name: "evil", kind: tar.TypeSymlink, link: outside},
		{name: "evil/planted", kind: tar.TypeReg, body: "planted"},
		{name: "evil2", kind: tar.TypeSymlink, link: "../../outside"},
		{name: "evil2/planted", kind: tar.TypeReg, body: "planted"},
		{name: "dev/sda", kind: tar.TypeBlock},
		{name: "etc/hardlink", kind: tar.TypeLink, link: "etc/passwd"},
	})
	root := filepath.Join(base, "root")
	skipped, err := Extract(bytes.NewReader(data), root)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("a file was written outside: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(base, "escape")); err == nil {
		t.Fatal("../escape was written")
	}
	if text, _ := os.ReadFile(filepath.Join(root, "etc", "passwd")); string(text) != "root:x:0:0::/root:/bin/bash\n" {
		t.Fatalf("passwd: %q", text)
	}
	info, err := os.Stat(filepath.Join(root, "tmp", ".u.sh"))
	if err != nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !info.ModTime().Equal(time.Date(2026, 11, 13, 2, 50, 0, 0, time.UTC)) {
		t.Fatalf("mode %v time %v err %v", info.Mode(), info.ModTime(), err)
	}
	if link, err := os.Readlink(filepath.Join(root, "home", "alice", ".bash_history")); err != nil || link != "/dev/null" {
		t.Fatalf("the link to /dev/null was not kept as a link: %q %v", link, err)
	}
	// Not kept: ../escape, the absolute name, the two planted files, the device and the hard link.
	if _, err := os.Stat(filepath.Join(root, "abs")); err == nil {
		t.Error("an absolute name was kept")
	}
	if skipped != 6 {
		t.Errorf("skipped %d, want 6", skipped)
	}
}

func TestExtractRefusesAnOldFolderAndALargeCopy(t *testing.T) {
	base := t.TempDir()
	if _, err := Extract(bytes.NewReader(nil), base); !errors.Is(err, ErrFailed) {
		t.Fatalf("an existing folder: %v", err)
	}
	large := tarOf(t, []entry{{name: "big", kind: tar.TypeReg, size: maxExtractFile + 1}})
	if _, err := Extract(bytes.NewReader(large), filepath.Join(base, "large")); !errors.Is(err, ErrFailed) {
		t.Fatalf("a large file: %v", err)
	}
	if _, err := Extract(strings.NewReader("not a tar stream at all, just text that goes on"), filepath.Join(base, "broken")); !errors.Is(err, ErrFailed) {
		t.Fatalf("a broken stream: %v", err)
	}
}

// fakeDocker answers like docker and writes down every command.
type fakeDocker struct {
	commands [][]string
	stdin    []string
	tar      []byte
	down     bool
	failOn   string
}

func (fake *fakeDocker) Run(_ context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	fake.commands = append(fake.commands, args)
	if stdin != nil {
		data, _ := io.ReadAll(stdin)
		fake.stdin = append(fake.stdin, string(data))
	}
	joined := strings.Join(args, " ")
	switch {
	case fake.down && args[0] == "version":
		return errors.New("cannot connect")
	case fake.failOn != "" && strings.Contains(joined, fake.failOn):
		io.WriteString(stderr, "something went wrong")
		return errors.New("exit 1")
	case args[0] == "version":
		io.WriteString(stdout, "28.0.1\n")
	case strings.Contains(joined, "pgrep"):
		io.WriteString(stdout, "ready\n")
	case strings.Contains(joined, "(alice) CMD"):
		io.WriteString(stdout, "ran\n")
	case strings.Contains(joined, "ps aux"):
		io.WriteString(stdout, "USER PID COMMAND\nroot 1 sleep infinity\n")
	case strings.Contains(joined, "ss -tulpn"):
		io.WriteString(stdout, "Netid State Local\n")
	case strings.Contains(joined, "cat "+capturePath):
		io.WriteString(stdout, "capture bytes")
	case strings.Contains(joined, "tar -C /"):
		stdout.Write(fake.tar)
		// Like GNU tar, the stream goes on after the end of the archive, and a writer that stops early fails.
		if _, err := stdout.Write(make([]byte, 10240)); err != nil {
			return err
		}
	case args[0] == "ps" || args[0] == "network" && args[1] == "ls":
		io.WriteString(stdout, "abc123\n")
	}

	return nil
}

func (fake *fakeDocker) lines() []string {
	var lines []string
	for _, command := range fake.commands {
		lines = append(lines, strings.Join(command, " "))
	}

	return lines
}

func (fake *fakeDocker) has(words ...string) bool {
	for _, command := range fake.commands {
		joined := " " + strings.Join(command, " ") + " "
		all := true
		for _, word := range words {
			if !strings.Contains(joined, " "+word+" ") {
				all = false
			}
		}
		if all {
			return true
		}
	}

	return false
}

func quick(folder string) Options {
	return Options{Folder: folder, Sleep: func(time.Duration) {}, Wait: time.Second}
}

func TestARunStaysOnItsOwnNetworkAndCleansUp(t *testing.T) {
	fake := &fakeDocker{tar: tarOf(t, []entry{{name: "var/log/auth.log", kind: tar.TypeReg, body: "x\n"}})}
	folder := filepath.Join(t.TempDir(), "evidence")
	evidence, err := Run(context.Background(), fake, quick(folder))
	if err != nil {
		t.Fatal(err)
	}
	if !fake.has("network", "create", "--internal", "--label", Label, evidence.Network) {
		t.Error("the network is not internal")
	}
	for _, name := range []string{evidence.Victim, evidence.Attacker} {
		if !fake.has("run", "--name", name, "--network", evidence.Network, "--label", Label) {
			t.Errorf("%s is not on the lab network with the label", name)
		}
	}
	for _, command := range fake.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, "--network host") || strings.Contains(joined, "--privileged") || strings.Contains(joined, "-p ") || strings.Contains(joined, "-v ") {
			t.Errorf("a command opens the lab: %s", joined)
		}
	}
	// Found in the live run: with whole seconds, the key looked older than the login of the same second.
	if !strings.Contains(strings.Join(fake.lines(), "\n"), "tar -C / --format=posix") {
		t.Error("the copy does not keep the times of files to the nanosecond")
	}
	// Found in the live run: the lab ended before cron ran the job of the attacker.
	if !strings.Contains(strings.Join(fake.lines(), "\n"), "(alice) CMD") {
		t.Error("the lab does not wait for cron")
	}
	if len(fake.stdin) != 1 || !strings.Contains(fake.stdin[0], "T=web01") || !fake.has("exec", "-i", evidence.Attacker, "bash", "-s") {
		t.Error("the attack script did not go to the attacker")
	}
	if !fake.has("rm", "-f", evidence.Victim, evidence.Attacker) || !fake.has("network", "rm", evidence.Network) {
		t.Error("the containers or the network were not removed")
	}
	for _, path := range []string{evidence.Processes, evidence.Sockets, evidence.Capture, filepath.Join(evidence.Root, "var", "log", "auth.log")} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestTheAttackHasOnlyTheLabServerAsTarget(t *testing.T) {
	script, err := files.ReadFile("files/attack.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if !strings.Contains(text, "T=web01\n") || strings.Count(text, "T=") != 1 || strings.Contains(text, "$1") || strings.Contains(text, "${1") {
		t.Fatal("the target of the attack is not fixed to web01")
	}
	for _, address := range []string{"203.0.113.80"} {
		if !strings.Contains(text, address) {
			t.Errorf("the documentation address %s is gone", address)
		}
	}
}

func TestAFailedRunStillCleansUpAndKeepKeeps(t *testing.T) {
	fake := &fakeDocker{failOn: "bash -s"}
	_, err := Run(context.Background(), fake, quick(filepath.Join(t.TempDir(), "evidence")))
	if !errors.Is(err, ErrFailed) || !strings.Contains(err.Error(), "something went wrong") {
		t.Fatalf("got %v", err)
	}
	if !fake.has("rm", "-f") || !fake.has("network", "rm") {
		t.Error("a failed run left its containers")
	}

	kept := &fakeDocker{tar: tarOf(t, nil)}
	options := quick(filepath.Join(t.TempDir(), "evidence"))
	options.Keep = true
	if _, err := Run(context.Background(), kept, options); err != nil {
		t.Fatal(err)
	}
	if kept.has("rm", "-f") || kept.has("network", "rm") {
		t.Error("--keep removed the containers")
	}
}

func TestDockerThatDoesNotAnswerAndAnOldFolder(t *testing.T) {
	if _, err := Run(context.Background(), &fakeDocker{down: true}, quick(filepath.Join(t.TempDir(), "e"))); !errors.Is(err, ErrDocker) {
		t.Fatalf("got %v", err)
	}
	fake := &fakeDocker{}
	if _, err := Run(context.Background(), fake, quick(t.TempDir())); !errors.Is(err, ErrFailed) || len(fake.commands) != 0 {
		t.Fatalf("an existing folder: %v, %d commands", err, len(fake.commands))
	}
	if _, err := Clean(context.Background(), &fakeDocker{down: true}, false); !errors.Is(err, ErrDocker) {
		t.Fatalf("clean: %v", err)
	}
}

func TestCleanRemovesOnlyWhatHasTheLabel(t *testing.T) {
	fake := &fakeDocker{}
	removed, err := Clean(context.Background(), fake, true)
	if err != nil || removed != 4 {
		t.Fatalf("removed %d, %v", removed, err)
	}
	if !fake.has("ps", "-aq", "--filter", "label="+Label) || !fake.has("network", "ls", "-q", "--filter", "label="+Label) || !fake.has("image", "rm", VictimImage) {
		t.Errorf("commands: %v", fake.commands)
	}
}

func TestGrade(t *testing.T) {
	system, capture := map[string]int{}, map[string]int{"net_port_scan": 1, "web_scanner_tool": 2, "net_internal_sweep": 1}
	for _, check := range Checks {
		if check.From == FromSystem && check.Rule != "file_web_shell" {
			system[check.Rule] = 1
		}
	}
	system["ssh_internal_guessing"] = 3
	score := Grade(system, capture)
	missed := []string{}
	for _, check := range score.Missed {
		missed = append(missed, check.From+"/"+check.Rule)
	}
	want := "capture/web_injection_attempt,system/file_web_shell,capture/web_shell_command"
	if strings.Join(missed, ",") != want {
		t.Fatalf("missed %v, want %s", missed, want)
	}
	if strings.Join(score.More, ",") != "net_internal_sweep (capture, 1),ssh_internal_guessing (system, 3)" {
		t.Fatalf("more %v", score.More)
	}
	text := score.Markdown()
	if !strings.Contains(text, "Found 21 of 24 expected detections.") || !strings.Contains(text, "| tools | a PHP web shell in an upload folder | `file_web_shell` | system | **no** |") {
		t.Fatalf("markdown:\n%s", text)
	}
}
