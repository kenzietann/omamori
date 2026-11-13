// Package lab runs a fixed attack against a server that it makes itself, and collects what the server saw, so
// that Omamori can be checked end to end on real logs, real files and real traffic.
//
// The lab makes two containers with Docker: web01 (Debian with sshd, nginx, cron and rsyslog) and an attacker.
// They share one Docker network that is made with --internal, so neither can reach any other machine. The
// attack is a script that is part of Omamori, and its only target is web01. There is no way to give it another
// target: the lab is a test of the tool, not a tool to attack systems.
package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed files
var files embed.FS

const (
	Label         = "omamori.lab=1"
	VictimImage   = "omamori-lab-victim:1"
	AttackerImage = "omamori-lab-attacker:1"
	capturePath   = "/var/lib/omamori-lab/capture.pcap"
	cronWait      = 75 * time.Second
)

// exported are the folders of web01 that are copied out after the attack: the places that forensics reads.
var exported = []string{"etc", "home", "root", "tmp", "var/tmp", "var/log", "var/spool", "var/www", "srv", "opt", "usr/local", "dev/shm"}

var (
	ErrDocker = errors.New("docker does not answer. Start Docker (or colima) and try again")
	ErrFailed = errors.New("the lab could not be run")
)

// Runner runs the docker command with the arguments. stdin may be nil.
type Runner interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error
}

type Options struct {
	// Folder is a new folder that the evidence goes into. It must not exist.
	Folder string
	// Keep leaves the containers and the network running after the run, for a look by hand.
	Keep bool
	// Progress gets one line for each step.
	Progress io.Writer
	// Wait is how long to wait for sshd in web01. Zero means 60 seconds.
	Wait time.Duration
	// Sleep waits between tries; tests make it return at once.
	Sleep func(time.Duration)
}

// Evidence is what the lab collected.
type Evidence struct {
	Root      string
	Processes string
	Sockets   string
	Capture   string
	// Names of the containers and the network, for --keep.
	Victim, Attacker, Network string
	// Attack is what the attack script printed.
	Attack string
}

type run struct {
	ctx     context.Context
	runner  Runner
	options Options
}

func (current run) docker(stdin io.Reader, stdout io.Writer, args ...string) error {
	var stderr bytes.Buffer
	if err := current.runner.Run(current.ctx, stdin, stdout, &stderr, args...); err != nil {
		text := strings.TrimSpace(stderr.String())
		if len(text) > 300 {
			text = text[len(text)-300:]
		}
		return fmt.Errorf("%w: docker %s: %s", ErrFailed, args[0], text)
	}

	return nil
}

func (current run) output(args ...string) (string, error) {
	var out bytes.Buffer
	err := current.docker(nil, &out, args...)

	return strings.TrimSpace(out.String()), err
}

func (current run) say(format string, values ...any) {
	if current.options.Progress != nil {
		fmt.Fprintf(current.options.Progress, format+"\n", values...)
	}
}

// Run builds the images, runs the attack and copies the evidence out. The containers and the network are
// removed at the end, also after an error, unless Keep is set.
func Run(ctx context.Context, runner Runner, options Options) (evidence Evidence, err error) {
	current := run{ctx: ctx, runner: runner, options: options}
	if options.Wait == 0 {
		options.Wait = 60 * time.Second
	}
	if options.Sleep == nil {
		options.Sleep = time.Sleep
	}
	current.options = options
	if _, statErr := os.Lstat(options.Folder); statErr == nil {
		return Evidence{}, fmt.Errorf("%w: the folder %s exists already", ErrFailed, filepath.Base(options.Folder))
	}
	if _, err := current.output("version", "--format", "{{.Server.Version}}"); err != nil {
		return Evidence{}, ErrDocker
	}

	build, err := os.MkdirTemp("", "omamori-lab-")
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: no temporary folder", ErrFailed)
	}
	defer os.RemoveAll(build)
	if err := unpack(build); err != nil {
		return Evidence{}, err
	}
	current.say("building the images (the first time, this downloads Debian and its packages)")
	for _, image := range []struct{ tag, folder string }{{VictimImage, "victim"}, {AttackerImage, "attacker"}} {
		if err := current.docker(nil, io.Discard, "build", "-q", "-t", image.tag, filepath.Join(build, image.folder)); err != nil {
			return Evidence{}, err
		}
	}

	id := make([]byte, 4)
	rand.Read(id)
	name := "omamori-lab-" + hex.EncodeToString(id)
	evidence = Evidence{Victim: name + "-web01", Attacker: name + "-attacker", Network: name}
	if !options.Keep {
		defer func() {
			// The cleaning must happen even when the run was stopped, so it has its own context.
			clean := run{ctx: context.WithoutCancel(ctx), runner: runner, options: options}
			clean.docker(nil, io.Discard, "rm", "-f", evidence.Victim, evidence.Attacker)
			clean.docker(nil, io.Discard, "network", "rm", evidence.Network)
		}()
	}
	current.say("starting web01 and the attacker on a network with no way out (%s)", evidence.Network)
	if err := current.docker(nil, io.Discard, "network", "create", "--internal", "--label", Label, evidence.Network); err != nil {
		return evidence, err
	}
	if err := current.docker(nil, io.Discard, "run", "-d", "--name", evidence.Victim, "--hostname", "web01", "--network", evidence.Network,
		"--network-alias", "web01", "--label", Label, "-e", "TZ=UTC", VictimImage); err != nil {
		return evidence, err
	}
	if err := current.docker(nil, io.Discard, "run", "-d", "--name", evidence.Attacker, "--hostname", "attacker", "--network", evidence.Network,
		"--label", Label, AttackerImage); err != nil {
		return evidence, err
	}
	if err := current.waitForServices(evidence.Victim); err != nil {
		return evidence, err
	}
	if err := current.docker(nil, io.Discard, "exec", "-d", evidence.Victim, "tcpdump", "-i", "eth0", "-U", "-w", capturePath); err != nil {
		return evidence, err
	}
	options.Sleep(time.Second)

	current.say("running the attack (scan, web probes, password spraying and guessing, persistence, tools)")
	script, _ := files.ReadFile("files/attack.sh")
	var printed bytes.Buffer
	progress := io.Writer(&printed)
	if options.Progress != nil {
		progress = io.MultiWriter(&printed, prefixed{options.Progress, "  "})
	}
	if err := current.docker(bytes.NewReader(script), progress, "exec", "-i", evidence.Attacker, "bash", "-s"); err != nil {
		return evidence, err
	}
	evidence.Attack = printed.String()
	// The cron job of alice runs at the start of a minute. The lab waits for it, so that the log has the run.
	current.say("waiting up to %s for cron to run the job of alice", cronWait)
	current.waitFor(evidence.Victim, "grep -q '(alice) CMD' /var/log/syslog && echo ran", "ran", cronWait)
	// Let the logs and the capture catch up, then stop the capture so that its file is whole.
	options.Sleep(2 * time.Second)
	current.docker(nil, io.Discard, "exec", evidence.Victim, "pkill", "-INT", "-x", "tcpdump")
	options.Sleep(time.Second)

	current.say("copying the logs, files, process and socket lists, and the capture out of web01")
	if err := os.MkdirAll(options.Folder, 0o700); err != nil {
		return evidence, fmt.Errorf("%w: the folder cannot be made", ErrFailed)
	}
	evidence.Root = filepath.Join(options.Folder, "root")
	evidence.Processes = filepath.Join(options.Folder, "ps.txt")
	evidence.Sockets = filepath.Join(options.Folder, "ss.txt")
	evidence.Capture = filepath.Join(options.Folder, "capture.pcap")
	for _, snapshot := range []struct {
		file string
		args []string
	}{
		{evidence.Processes, []string{"exec", evidence.Victim, "ps", "aux"}},
		{evidence.Sockets, []string{"exec", evidence.Victim, "ss", "-tulpn"}},
		{evidence.Capture, []string{"exec", evidence.Victim, "cat", capturePath}},
	} {
		if err := current.toFile(snapshot.file, snapshot.args...); err != nil {
			return evidence, err
		}
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		// The posix format keeps the times of files to the nanosecond: with whole seconds, a key written in the
		// same second as a login can look older than the login. Exit code 1 of GNU tar means that a file changed
		// while it was read (a log that was written to); the copy is still whole up to that moment.
		script := "tar -C / --format=posix --ignore-failed-read -cf - " + strings.Join(exported, " ") + "; [ $? -le 1 ]"
		err := current.docker(nil, writer, "exec", evidence.Victim, "sh", "-c", script)
		writer.CloseWithError(err)
		done <- err
	}()
	skipped, extractErr := Extract(reader, evidence.Root)
	// tar pads its stream after the end of the archive. It is read to its end, so that docker can finish writing.
	io.Copy(io.Discard, reader)
	reader.CloseWithError(errors.New("stopped"))
	tarErr := <-done
	if extractErr != nil {
		return evidence, extractErr
	}
	if tarErr != nil {
		return evidence, tarErr
	}
	if skipped > 0 {
		current.say("%d entries of the copy were not kept (devices, hard links, or names that leave the folder)", skipped)
	}
	if options.Keep {
		current.say("the containers are still running: %s and %s. Remove them with: omamori lab clean", evidence.Victim, evidence.Attacker)
	}

	return evidence, nil
}

func (current run) waitForServices(victim string) error {
	if !current.waitFor(victim, "pgrep -x sshd >/dev/null && pgrep -x nginx >/dev/null && pgrep -x rsyslogd >/dev/null && echo ready", "ready", current.options.Wait) {
		return fmt.Errorf("%w: the services of web01 did not start", ErrFailed)
	}

	return nil
}

// waitFor runs a check in the container until it prints the answer, or the time is over.
func (current run) waitFor(container, check, answer string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		if out, err := current.output("exec", container, "sh", "-c", check); err == nil && out == answer {
			return true
		}
		if time.Now().After(deadline) || current.ctx.Err() != nil {
			return false
		}
		current.options.Sleep(time.Second)
	}
}

func (current run) toFile(path string, args ...string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %s cannot be written", ErrFailed, filepath.Base(path))
	}
	limited := &limitWriter{writer: file, left: 1 << 30}
	runErr := current.docker(nil, limited, args...)
	closeErr := file.Close()
	if runErr != nil {
		return runErr
	}
	if closeErr != nil || limited.over {
		return fmt.Errorf("%w: %s could not be written whole", ErrFailed, filepath.Base(path))
	}

	return nil
}

type limitWriter struct {
	writer io.Writer
	left   int64
	over   bool
}

func (limited *limitWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > limited.left {
		limited.over = true
		return 0, errors.New("too large")
	}
	limited.left -= int64(len(data))

	return limited.writer.Write(data)
}

type prefixed struct {
	writer io.Writer
	prefix string
}

func (out prefixed) Write(data []byte) (int, error) {
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			fmt.Fprint(out.writer, out.prefix+line)
		}
	}

	return len(data), nil
}

func unpack(folder string) error {
	return fs.WalkDir(files, "files", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(folder, filepath.FromSlash(strings.TrimPrefix(name, "files")))
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := files.ReadFile(name)
		if err != nil {
			return err
		}

		return os.WriteFile(target, data, 0o600)
	})
}

// Clean removes every container and network with the label of the lab, and the images when asked.
func Clean(ctx context.Context, runner Runner, images bool) (int, error) {
	current := run{ctx: ctx, runner: runner}
	if _, err := current.output("version", "--format", "{{.Server.Version}}"); err != nil {
		return 0, ErrDocker
	}
	removed := 0
	containers, err := current.output("ps", "-aq", "--filter", "label="+Label)
	if err != nil {
		return 0, err
	}
	if ids := strings.Fields(containers); len(ids) > 0 {
		if err := current.docker(nil, io.Discard, append([]string{"rm", "-f"}, ids...)...); err != nil {
			return removed, err
		}
		removed += len(ids)
	}
	networks, err := current.output("network", "ls", "-q", "--filter", "label="+Label)
	if err != nil {
		return removed, err
	}
	if ids := strings.Fields(networks); len(ids) > 0 {
		if err := current.docker(nil, io.Discard, append([]string{"network", "rm"}, ids...)...); err != nil {
			return removed, err
		}
		removed += len(ids)
	}
	if images {
		for _, image := range []string{VictimImage, AttackerImage} {
			if current.docker(nil, io.Discard, "image", "rm", image) == nil {
				removed++
			}
		}
	}

	return removed, nil
}
