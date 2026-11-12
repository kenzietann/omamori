package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/runstore"
	"github.com/kenzietann/omamori/internal/scenario"
)

const (
	usageDetect   = "usage: omamori detect [--rules folder] [--format syslog|web|json|suricata|zeek|wazuh|windows] [--year n] [--timezone name] [--output folder] [--store] [--db SQLite-file] <log file or folder>..."
	usageScenario = "usage: omamori scenario [--seed n] [--date 2026-11-10] [--timezone name] [--benign] [--host] <new folder>"
)

func (env environment) clock() time.Time {
	if env.now != nil {
		return env.now()
	}

	return time.Now()
}

func zone(name string) (*time.Location, error) {
	if name == "" {
		return time.Local, nil
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("the time zone %q is not known. Write it like Asia/Tokyo", name)
	}

	return location, nil
}

// splitFlags lets flags stand before or after the other arguments.
func splitFlags(flags *flag.FlagSet, args []string) ([]string, error) {
	flags.SetOutput(io.Discard)
	var positional []string
	for len(args) > 0 {
		if args[0] == "--" {
			return append(positional, args[1:]...), nil
		}
		if args[0] == "-" || !strings.HasPrefix(args[0], "-") {
			positional = append(positional, args[0])
			args = args[1:]
			continue
		}

		// Parse one flag and its value together, so a value of "--" is not
		// mistaken for the delimiter. Boolean flags do not consume a value.
		name, _, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(args[0], "-"), "-"), "=")
		count := 1
		if option := flags.Lookup(name); option != nil && !hasValue {
			boolean, ok := option.Value.(interface{ IsBoolFlag() bool })
			if !ok || !boolean.IsBoolFlag() {
				count = min(2, len(args))
			}
		}
		if err := flags.Parse(args[:count]); err != nil {
			return nil, err
		}
		args = args[count:]
	}

	return positional, nil
}

// runDetect reads logs, runs rules and writes a report. Optional storage can use a configured SQL server;
// without storage the command stays local, and it never uses an AI provider.
func runDetect(args []string, env environment) int {
	flags := flag.NewFlagSet("detect", flag.ContinueOnError)
	var chosen settings
	var database storageFlags
	database.bind(flags, true)
	var rulesFolder, format string
	flags.StringVar(&rulesFolder, "rules", "", "folder with rules, in place of the built-in rules")
	flags.StringVar(&format, "format", "", "syslog, web, json, suricata, zeek, wazuh or windows")
	flags.IntVar(&chosen.year, "year", 0, "year of syslog lines")
	flags.StringVar(&chosen.zone, "timezone", "", "time zone of syslog lines")
	flags.StringVar(&chosen.output, "output", "", "folder for the reports")
	paths, err := splitFlags(flags, args)
	if err != nil || len(paths) == 0 {
		fmt.Fprintln(env.stderr, usageDetect)
		return exitUsage
	}

	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	now := env.clock()
	location, err := zone(chosen.zone)
	if err != nil {
		return fail(err)
	}
	if chosen.year == 0 {
		chosen.year = now.In(location).Year()
	}
	if err := chosen.chooseOutput(env.home); err != nil {
		return fail(err)
	}

	rulesFrom := "built-in"
	loaded, err := rules.Builtin()
	if rulesFolder != "" {
		rulesFrom = "from a folder"
		loaded, err = rules.Load(rulesFolder)
	}
	if err != nil {
		return fail(err)
	}
	if len(loaded.Rules()) == 0 {
		return fail(errors.New("the rules folder has no rule"))
	}

	directory := filepath.Join(chosen.output, "detect-"+now.UTC().Format("20060102-150405"))
	if _, err := os.Lstat(directory); err == nil {
		return fail(errors.New("the report folder of this second exists already. Run again"))
	}
	var sources []string
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fail(errors.New("a log path is not usable"))
		}
		if err := pathguard.CheckOutputFolder(absolute, directory); err != nil {
			return fail(errors.New("the report folder must not be inside the logs, and the logs must not be inside the report folder"))
		}
		sources = append(sources, absolute)
	}

	outcome, err := detect.Run(paths, loaded, rulesFrom, intake.Options{Year: chosen.year, Location: location, Format: format}, now)
	if err != nil {
		return fail(err)
	}
	if len(outcome.Intake.Files) == 0 {
		return fail(errors.New("no log file could be read. Give the format with --format syslog, web, json, suricata, zeek, wazuh or windows"))
	}

	report := detect.Markdown(outcome)
	alerts, err := detect.JSON(outcome)
	if err != nil {
		return fail(errors.New("the alerts could not be written"))
	}
	// Nothing was written until here. The folder is made only now, when there is a report to put into it.
	writer, err := reportwriter.NewRun(sources, directory)
	if err != nil {
		return fail(err)
	}
	for _, file := range []struct{ name, content string }{{"report.md", report}, {"report.html", htmlreport.Render(report)}, {"alerts.json", alerts}} {
		if err := writer.Write(file.name, file.content); err != nil {
			return fail(fmt.Errorf("%s: %w", file.name, err))
		}
	}

	events := 0
	for _, file := range outcome.Intake.Files {
		events += file.Events
	}
	counts := map[string]int{}
	for _, alert := range outcome.Result.Alerts {
		counts[alert.Rule.Level]++
	}
	fmt.Fprintf(env.stdout, "Read %d files and %d events. %d rules. %d alerts", len(outcome.Intake.Files), events, outcome.Rules, len(outcome.Result.Alerts))
	for _, level := range []string{"critical", "high", "medium", "low", "informational"} {
		if counts[level] > 0 {
			fmt.Fprintf(env.stdout, ", %d %s", counts[level], level)
		}
	}
	fmt.Fprintf(env.stdout, ".\nReport: %s\n", filepath.Join(directory, "report.html"))
	if database.wanted() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		db, err := database.open(ctx, env, sources)
		if err != nil {
			return fail(err)
		}
		defer db.Close()
		run, err := runstore.Save(ctx, db, outcome, nil)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(env.stdout, "Stored run: %s\n", run.ID)
	}

	return exitOK
}

// runScenario writes synthetic logs of one day into a new folder, with the list of alerts that must fire.
// The logs are made up. They are for demos and for tests of rules.
func runScenario(args []string, env environment) int {
	flags := flag.NewFlagSet("scenario", flag.ContinueOnError)
	var seed int64
	var date, zoneName string
	var benign bool
	flags.Int64Var(&seed, "seed", 1, "seed of the random choices")
	flags.StringVar(&date, "date", "", "day of the logs")
	flags.StringVar(&zoneName, "timezone", "", "time zone of the server")
	flags.BoolVar(&benign, "benign", false, "a day without attacks")
	var host bool
	flags.BoolVar(&host, "host", false, "write a whole synthetic system for the forensic triage")
	positional, err := splitFlags(flags, args)
	if err != nil || len(positional) != 1 {
		fmt.Fprintln(env.stderr, usageScenario)
		return exitUsage
	}

	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	location, err := zone(zoneName)
	if err != nil {
		return fail(err)
	}
	day := env.clock().In(location).AddDate(0, 0, -1)
	if date != "" {
		if day, err = time.ParseInLocation("2006-01-02", date, location); err != nil {
			return fail(errors.New("write the date like 2026-11-10"))
		}
	}
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, location)

	directory, err := filepath.Abs(positional[0])
	if err != nil {
		return fail(errors.New("the folder is not usable"))
	}
	if _, err := os.Lstat(directory); err == nil {
		return fail(errors.New("the folder exists already. Give a new folder, so that nothing is written over"))
	}
	if host {
		return writeHostScenario(env, directory, seed, day, location, benign)
	}
	writer, err := reportwriter.NewFolder(directory)
	if err != nil {
		return fail(err)
	}

	made := scenario.Generate(seed, day, !benign)
	expected, err := json.MarshalIndent(map[string]any{
		"note": "Synthetic logs made by omamori scenario. No line comes from a real system.", "seed": seed, "date": day.Format("2006-01-02"),
		"expected_alerts": append([]scenario.Expected{}, made.Expected...), "known_misses": append([]string{}, made.KnownMisses...),
	}, "", "  ")
	if err != nil {
		return fail(errors.New("the list of expected alerts could not be written"))
	}
	made.Files["expected.json"] = string(expected) + "\n"

	names := make([]string, 0, len(made.Files))
	for name := range made.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writer.Write(name, made.Files[name]); err != nil {
			return fail(fmt.Errorf("%s: %w", name, err))
		}
	}
	fmt.Fprintf(env.stdout, "Wrote %d files of synthetic logs for %s to %s\nTry: omamori detect --year %d --timezone %s -- %s\n",
		len(names), day.Format("2006-01-02"), directory, day.Year(), shellArgument(location.String()), shellArgument(directory))

	return exitOK
}

// shellArgument keeps a copied command's values literal, including spaces, quotes and shell expansions.
func shellArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
