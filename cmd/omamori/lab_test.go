package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/tui"
)

// labDocker answers like docker, with the synthetic attacked system as the copy of web01.
type labDocker struct {
	copy     []byte
	commands []string
}

func (fake *labDocker) Run(_ context.Context, stdin io.Reader, stdout, _ io.Writer, args ...string) error {
	joined := strings.Join(args, " ")
	fake.commands = append(fake.commands, joined)
	if stdin != nil {
		io.Copy(io.Discard, stdin)
	}
	switch {
	case args[0] == "version":
		io.WriteString(stdout, "28.0.1\n")
	case strings.Contains(joined, "pgrep"):
		io.WriteString(stdout, "ready\n")
	case strings.Contains(joined, "(alice) CMD"):
		io.WriteString(stdout, "ran\n")
	case strings.Contains(joined, "tar -C /"):
		stdout.Write(fake.copy)
	case strings.Contains(joined, "bash -s"):
		io.WriteString(stdout, "stage scan: ports 1 to 200\nstage done\n")
	case strings.Contains(joined, "ps aux"):
		io.WriteString(stdout, "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.0 0.0 1 1 ? Ss 00:00 0:00 sleep infinity\n")
	}

	return nil
}

func syntheticCopy(t *testing.T) []byte {
	t.Helper()
	host := scenario.GenerateHost(3, time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), true)
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	for name, file := range host.Files {
		inside, found := strings.CutPrefix(name, "root/")
		if !found || file.Link != "" {
			continue
		}
		writer.WriteHeader(&tar.Header{Name: inside, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(file.Text)), ModTime: file.Modified})
		writer.Write([]byte(file.Text))
	}
	writer.Close()

	return out.Bytes()
}

func TestTheLabCommandScoresWhatItRead(t *testing.T) {
	fake := &labDocker{copy: syntheticCopy(t)}
	output := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	code := run([]string{"lab", "--output", output}, environment{
		stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" }, home: homeAt(t.TempDir()),
		now: func() time.Time { return detectNow }, dockerRunner: fake,
	})
	// The synthetic system has most of the files and logs of an attack and no capture, so some checks are missed
	// and the run ends with an error code: a lab run that misses a step must not look like a success.
	if code != exitFailed || !strings.Contains(stdout.String(), "expected detections") || !strings.Contains(stdout.String(), "missed: net_port_scan (capture)") {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	base := filepath.Join(output, "lab-20261111-030405")
	for _, name := range []string{"score/lab.md", "score/lab.html", "score/attack.txt", "forensics/report.html", "forensics/manifest.json", "capture/report.md", "evidence/root/etc/passwd", "evidence/ps.txt"} {
		if _, err := os.Stat(filepath.Join(base, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	score, _ := os.ReadFile(filepath.Join(base, "score", "lab.md"))
	if !strings.Contains(string(score), "| tools | a reverse shell in /var/tmp | `file_reverse_shell` | system | yes |") {
		t.Errorf("the score does not count the reverse shell that the synthetic system has:\n%s", score)
	}
	if !strings.Contains(strings.Join(fake.commands, "\n"), "network rm") {
		t.Error("the lab network was not removed")
	}
}

func TestLabUsageAndClean(t *testing.T) {
	for _, args := range [][]string{{"lab", "extra"}, {"lab", "--timeout", "0s"}, {"lab", "clean", "now"}, {"lab", "--target", "10.0.0.1"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, environment{stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" }, home: homeAt(t.TempDir()), dockerRunner: &labDocker{}}); code != exitUsage {
			t.Errorf("%v: code %d", args, code)
		}
	}
	var stdout, stderr bytes.Buffer
	fake := &labDocker{}
	if code := run([]string{"lab", "clean", "--images"}, environment{stdout: &stdout, stderr: &stderr, lookupEnv: func(string) string { return "" }, dockerRunner: fake}); code != exitOK || !strings.Contains(stdout.String(), "Removed") {
		t.Fatalf("clean: %d %s %s", code, stdout.String(), stderr.String())
	}
}

func TestTheHomeScreenRunsTheLab(t *testing.T) {
	b := homeBackend(t, t.TempDir(), nil)
	b.env.dockerRunner = &labDocker{copy: syntheticCopy(t)}
	plan, err := b.Prepare(tui.Setup{Task: tui.TaskLab})
	if err != nil || !strings.Contains(plan.Summary, "no way out") || !strings.Contains(plan.Summary, "Needs Docker") {
		t.Fatalf("plan: %v %q", err, plan.Summary)
	}
	plan.Confirm()
	result, err := plan.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || !strings.Contains(result.Report, "expected detections") || !strings.Contains(result.Report, "## Run") || result.SavedTo == "" {
		t.Fatalf("result: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(result.SavedTo, "score", "lab.md")); err != nil {
		t.Fatal(err)
	}
}
