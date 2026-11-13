package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/filerules"
	"github.com/kenzietann/omamori/internal/forensics"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/lab"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/rules"
)

const usageLab = "usage: omamori lab [--output folder] [--keep] [--timeout duration]\n" +
	"       omamori lab clean [--images]"

// dockerRunner runs the docker command of the machine.
type dockerRunner struct{}

func (dockerRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	path, err := exec.LookPath("docker")
	if err != nil {
		return lab.ErrDocker
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr

	return command.Run()
}

func (env environment) docker() lab.Runner {
	if env.dockerRunner != nil {
		return env.dockerRunner
	}

	return dockerRunner{}
}

func runLab(args []string, env environment) int {
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	if len(args) > 0 && args[0] == "clean" {
		flags := flag.NewFlagSet("lab clean", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		images := flags.Bool("images", false, "also remove the images of the lab")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			fmt.Fprintln(env.stderr, usageLab)
			return exitUsage
		}
		removed, err := lab.Clean(context.Background(), env.docker(), *images)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(env.stdout, "Removed %d containers, networks and images of the lab.\n", removed)
		return exitOK
	}

	flags := flag.NewFlagSet("lab", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var chosen settings
	flags.StringVar(&chosen.output, "output", "", "folder for the evidence and the reports")
	keep := flags.Bool("keep", false, "leave the containers running after the run")
	timeout := flags.Duration("timeout", 20*time.Minute, "longest time for the whole run")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *timeout <= 0 {
		fmt.Fprintln(env.stderr, usageLab)
		return exitUsage
	}
	if err := chosen.chooseOutput(env.home); err != nil {
		return fail(err)
	}
	now := env.clock()
	base := filepath.Join(chosen.output, "lab-"+now.UTC().Format("20060102-150405"))
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	score, err := labRun(ctx, env, base, *keep, now)
	if err != nil {
		return fail(err)
	}
	if len(score.Missed) > 0 {
		return exitFailed
	}

	return exitOK
}

// labRun runs the lab into the folder base, reads what it collected, writes the reports and the score, and
// prints the score. The command and the home screen both use it.
func labRun(ctx context.Context, env environment, base string, keep bool, now time.Time) (lab.Score, error) {
	evidenceFolder := filepath.Join(base, "evidence")
	fmt.Fprintln(env.stdout, "Omamori lab: two containers on a Docker network with no way out. The attacker attacks only the lab server web01.")
	evidence, err := lab.Run(ctx, env.docker(), lab.Options{Folder: evidenceFolder, Keep: keep, Progress: env.stdout})
	if err != nil {
		return lab.Score{}, err
	}

	fmt.Fprintln(env.stdout, "reading web01 with forensics, and its traffic with detect")
	system, systemReport, err := labForensics(evidence, now)
	if err != nil {
		return lab.Score{}, err
	}
	capture, captureReport, err := labCapture(evidence, now)
	if err != nil {
		return lab.Score{}, err
	}
	score := lab.Grade(fired(system), fired(capture))
	summary := score.Markdown()

	sources := []string{evidenceFolder}
	for _, folder := range []struct {
		name  string
		files map[string]string
	}{
		{"forensics", systemReport},
		{"capture", captureReport},
		{"score", map[string]string{"lab.md": summary, "lab.html": htmlreport.Render(summary), "attack.txt": evidence.Attack}},
	} {
		writer, err := reportwriter.NewRun(sources, filepath.Join(base, folder.name))
		if err != nil {
			return lab.Score{}, fmt.Errorf("the report folder %s cannot be made", folder.name)
		}
		for name, content := range folder.files {
			if err := writer.Write(name, content); err != nil {
				return lab.Score{}, fmt.Errorf("%s: %w", name, err)
			}
		}
	}

	total := len(score.Found) + len(score.Missed)
	fmt.Fprintf(env.stdout, "Found %d of %d expected detections.\n", len(score.Found), total)
	for _, check := range score.Missed {
		fmt.Fprintf(env.stdout, "  missed: %s (%s) - stage %s, %s\n", check.Rule, check.From, check.Stage, check.What)
	}
	fmt.Fprintf(env.stdout, "Score: %s\nForensic report: %s\nCapture report: %s\nEvidence: %s\n",
		filepath.Join(base, "score", "lab.html"), filepath.Join(base, "forensics", "report.html"), filepath.Join(base, "capture", "report.html"), evidenceFolder)

	return score, nil
}

func fired(outcome detect.Outcome) map[string]int {
	counts := map[string]int{}
	for _, alert := range outcome.Result.Alerts {
		counts[alert.Rule.Name]++
	}

	return counts
}

func labForensics(evidence lab.Evidence, now time.Time) (detect.Outcome, map[string]string, error) {
	set, err := rules.BuiltinForensics()
	if err != nil {
		return detect.Outcome{}, nil, err
	}
	files, err := filerules.Builtin()
	if err != nil {
		return detect.Outcome{}, nil, err
	}
	result, err := forensics.Run(evidence.Root, set, "built-in, with the rules for artifacts", forensics.Options{
		Year: now.UTC().Year(), Location: time.UTC, Processes: evidence.Processes, Sockets: evidence.Sockets, FileRules: &files,
	}, now)
	if err != nil {
		return detect.Outcome{}, nil, err
	}
	report := forensics.Markdown(result)
	alerts, err := detect.JSON(result.Outcome)
	if err != nil {
		return detect.Outcome{}, nil, errors.New("the alerts could not be written")
	}

	return result.Outcome, map[string]string{
		"report.md": report, "report.html": htmlreport.Render(report), "alerts.json": alerts,
		"manifest.json": result.ManifestText, "manifest.sha256": result.ManifestSHA256 + "  manifest.json\n",
	}, nil
}

func labCapture(evidence lab.Evidence, now time.Time) (detect.Outcome, map[string]string, error) {
	set, err := rules.Builtin()
	if err != nil {
		return detect.Outcome{}, nil, err
	}
	outcome, err := detect.Run([]string{evidence.Capture}, set, "built-in", intake.Options{Year: now.UTC().Year(), Location: time.UTC, Format: intake.FormatPCAP}, now)
	if err != nil {
		return detect.Outcome{}, nil, err
	}
	report := detect.Markdown(outcome)
	alerts, err := detect.JSON(outcome)
	if err != nil {
		return detect.Outcome{}, nil, errors.New("the alerts could not be written")
	}

	return outcome, map[string]string{"report.md": report, "report.html": htmlreport.Render(report), "alerts.json": alerts}, nil
}
