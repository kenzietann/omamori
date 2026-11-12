package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/peek"
)

const (
	usagePeek      = "usage: omamori peek [--reveal] <report folder or report.md> <project folder>"
	maxReportBytes = 4 << 20
)

func runPeek(args []string, env environment) int {
	flags := flag.NewFlagSet("omamori peek", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	reveal := flags.Bool("reveal", false, "show the matched values as they are")

	var positional []string
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(env.stderr, "omamori:", usagePeek)
		return exitUsage
	}
	for flags.NArg() > 0 {
		positional = append(positional, flags.Arg(0))
		if err := flags.Parse(flags.Args()[1:]); err != nil {
			fmt.Fprintln(env.stderr, "omamori:", usagePeek)
			return exitUsage
		}
	}
	if len(positional) != 2 {
		fmt.Fprintln(env.stderr, "omamori:", usagePeek)
		return exitUsage
	}

	reportPath := positional[0]
	if info, err := os.Stat(reportPath); err == nil && info.IsDir() {
		reportPath = filepath.Join(reportPath, "report.md")
	}
	report, err := readSmallFile(reportPath, maxReportBytes)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", peek.ErrNoReport)
		return exitFailed
	}
	items, err := peek.ReadReport(report)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	root, err := pathguard.NewRoot(positional[1])
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori: the project folder is not usable")
		return exitFailed
	}

	mode := "The middle of each value is hidden."
	if *reveal {
		mode = "The matched values are shown as they are."
	}
	fmt.Fprintf(env.stdout, "Matches of this report, found again in the files. %s\nThis is for your screen only. Nothing is saved, and nothing is sent to the AI or anywhere else.\n\n", mode)
	for _, shown := range peek.Show(root, items, *reveal) {
		fmt.Fprintf(env.stdout, "%s  %s:%d\n", shown.Placeholder, shown.File, shown.Line)
		if shown.Problem != "" {
			fmt.Fprintf(env.stdout, "  not shown: %s\n\n", shown.Problem)
			continue
		}
		fmt.Fprintf(env.stdout, "  value:   %s\n", shown.Value)
		if shown.Context != "" {
			fmt.Fprintf(env.stdout, "  context: %s\n", shown.Context)
		}
		fmt.Fprintln(env.stdout)
	}

	return exitOK
}

func readSmallFile(path string, limit int64) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	data, err := io.ReadAll(io.LimitReader(handle, limit))
	if err != nil {
		return "", err
	}

	return string(data), nil
}
