package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/assets"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/filerules"
	"github.com/kenzietann/omamori/internal/forensics"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/indicators"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/runstore"
	"github.com/kenzietann/omamori/internal/scenario"
)

const (
	usageForensics = "usage: omamori forensics [--processes file] [--sockets file] [--rules folder] [--file-rules folder | --no-file-rules] [--assets file] [--indicators file] [--year n] [--timezone name] [--output folder] [--store] [--db SQLite-file] <evidence folder>\n" +
		"       omamori forensics --analyze [--yes | --dry-run | --replay recording.json] [--provider id] [--model name] [--reasoning level] ... <evidence folder>\n" +
		"       omamori forensics verify <manifest.json> <evidence folder>"
	maxManifestBytes = forensics.MaxManifestBytes
)

func runForensics(args []string, env environment) int {
	if len(args) > 0 && args[0] == "verify" {
		return runForensicsVerify(args[1:], env)
	}

	flags := flag.NewFlagSet("forensics", flag.ContinueOnError)
	var chosen settings
	var database storageFlags
	database.bind(flags, true)
	var rulesFolder, processes, sockets string
	flags.StringVar(&rulesFolder, "rules", "", "folder with rules, in place of the built-in rules")
	var fileRulesFolder string
	var noFileRules bool
	flags.StringVar(&fileRulesFolder, "file-rules", "", "folder with file rules, in place of the built-in file rules")
	flags.BoolVar(&noFileRules, "no-file-rules", false, "do not look at the content of files with file rules")
	flags.StringVar(&processes, "processes", "", "file with the output of ps aux or ps -ef")
	flags.StringVar(&sockets, "sockets", "", "file with the output of ss -tulpn or netstat -tulpn")
	flags.IntVar(&chosen.year, "year", 0, "year of syslog lines")
	flags.StringVar(&chosen.zone, "timezone", "", "time zone of syslog lines")
	flags.StringVar(&chosen.output, "output", "", "folder for the reports")
	var assetsPath, indicatorsPath string
	flags.StringVar(&assetsPath, "assets", "", "asset list: names and addresses of your own machines")
	flags.StringVar(&indicatorsPath, "indicators", "", "indicator list: addresses, domains and hashes that are known to be bad")
	lookup := env.lookupEnv
	if lookup == nil {
		lookup = func(string) string { return "" }
	}
	var review analystFlags
	var analyze bool
	flags.BoolVar(&analyze, "analyze", false, "let the AI analyst review the alerts, with every claim checked")
	flags.StringVar(&chosen.provider, "provider", lookup("OMAMORI_PROVIDER"), "AI provider")
	flags.StringVar(&chosen.model, "model", lookup("OMAMORI_MODEL"), "model name")
	flags.StringVar(&review.reasoning, "reasoning", "", "reasoning level")
	flags.StringVar(&review.recordingPath, "replay", "", "replay recorded analyst answers offline")
	flags.BoolVar(&review.confirmed, "yes", false, "send the sanitized alert snapshot to the selected provider")
	flags.BoolVar(&review.dryRun, "dry-run", false, "show the guarded request without sending or writing reports")
	flags.DurationVar(&review.timeout, "timeout", 2*time.Minute, "maximum time for the analysis")
	paths, err := splitFlags(flags, args)
	// The choices of the analyst mean nothing without --analyze. They are refused, so that nobody thinks
	// that --yes alone sent something, or that --dry-run alone kept the reports from being written.
	alone := !analyze && (review.confirmed || review.dryRun || review.recordingPath != "")
	if err != nil || len(paths) != 1 || alone || noFileRules && fileRulesFolder != "" || review.confirmed && review.dryRun || review.timeout <= 0 {
		fmt.Fprintln(env.stderr, usageForensics)
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

	rulesFrom := "built-in, with the rules for artifacts"
	loaded, err := rules.BuiltinForensics()
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

	fileRules, err := loadFileRules(fileRulesFolder, noFileRules)
	if err != nil {
		return fail(err)
	}

	var machines *assets.List
	if assetsPath != "" {
		if machines, err = assets.Load(assetsPath); err != nil {
			return fail(err)
		}
	}
	var known *indicators.List
	if indicatorsPath != "" {
		if known, err = indicators.Load(indicatorsPath); err != nil {
			return fail(err)
		}
	}
	evidence, err := filepath.Abs(paths[0])
	if err != nil {
		return fail(errors.New("the evidence folder is not usable"))
	}
	sources := []string{evidence}
	for _, snapshot := range []string{processes, sockets} {
		if snapshot != "" {
			absolute, err := filepath.Abs(snapshot)
			if err != nil {
				return fail(errors.New("a snapshot file is not usable"))
			}
			sources = append(sources, absolute)
		}
	}
	directory := filepath.Join(chosen.output, "forensics-"+now.UTC().Format("20060102-150405"))

	for _, source := range sources {
		if err := pathguard.CheckOutputFolder(source, directory); err != nil {
			return fail(errors.New("the report folder must be new, and it must not be inside the evidence folder or around it"))
		}
	}

	result, err := forensics.Run(evidence, loaded, rulesFrom, forensics.Options{Year: chosen.year, Location: location, Processes: processes, Sockets: sockets, Assets: machines, Indicators: known, FileRules: fileRules}, now)
	if err != nil {
		return fail(err)
	}
	if len(result.Manifest.Entries) == 0 {
		return fail(errors.New("no artifact was found. The folder must be the top of a Linux system, with folders like etc, var and home in it"))
	}

	report := forensics.Markdown(result)
	alerts, err := detect.JSON(result.Outcome)
	if err != nil {
		return fail(errors.New("the alerts could not be written"))
	}
	artifacts := 0
	for _, current := range result.Outcome.Intake.Events {
		if current.Source == forensics.Source {
			artifacts++
		}
	}
	read := fmt.Sprintf("Read and hashed %d files: %d log events and %d artifacts. %d rules. %d alerts",
		len(result.Manifest.Entries), len(result.Outcome.Intake.Events)-artifacts, artifacts, result.Outcome.Rules, len(result.Outcome.Result.Alerts))
	if analyze {
		base := analysisrun.Base{Report: report, Prefix: "forensics", Files: map[string]string{
			"manifest.json": result.ManifestText, "manifest.sha256": result.ManifestSHA256 + "  manifest.json\n",
		}}

		return reviewOutcome(env, flags, chosen, review, database, result.Outcome, sources, evidence, base, read+".\nManifest SHA-256: "+result.ManifestSHA256)
	}

	// Nothing was written until here. The report folder must be new and away from the evidence: the triage
	// must never put a file into the system that it looks at.
	writer, err := reportwriter.NewRun(sources, directory)
	if err != nil {
		if errors.Is(err, reportwriter.ErrExists) {
			return fail(errors.New("the report folder of this second exists already. Run again"))
		}

		return fail(errors.New("the report folder must be new, and it must not be inside the evidence folder or around it"))
	}
	for _, file := range []struct{ name, content string }{
		{"report.md", report}, {"report.html", htmlreport.Render(report)}, {"alerts.json", alerts},
		{"manifest.json", result.ManifestText}, {"manifest.sha256", result.ManifestSHA256 + "  manifest.json\n"},
	} {
		if err := writer.Write(file.name, file.content); err != nil {
			return fail(fmt.Errorf("%s: %w", file.name, err))
		}
	}

	counts := map[string]int{}
	for _, alert := range result.Outcome.Result.Alerts {
		counts[alert.Rule.Level]++
	}
	fmt.Fprint(env.stdout, read)
	for _, level := range []string{"critical", "high", "medium", "low", "informational"} {
		if counts[level] > 0 {
			fmt.Fprintf(env.stdout, ", %d %s", counts[level], level)
		}
	}
	fmt.Fprintf(env.stdout, ".\nManifest SHA-256: %s\nReport: %s\n", result.ManifestSHA256, filepath.Join(directory, "report.html"))

	if database.wanted() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		db, err := database.open(ctx, env, sources)
		if err != nil {
			return fail(err)
		}
		defer db.Close()
		run, err := runstore.Save(ctx, db, result.Outcome, nil)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(env.stdout, "Stored run: %s\n", run.ID)
	}

	return exitOK
}

// loadFileRules gives the built-in file rules, the file rules of a folder, or none.
func loadFileRules(folder string, none bool) (*filerules.Set, error) {
	if none {
		return nil, nil
	}
	set, err := filerules.Builtin()
	if folder != "" {
		set, err = filerules.Load(folder)
	}
	if err != nil {
		return nil, err
	}
	if len(set.Rules()) == 0 {
		return nil, errors.New("the file rules folder has no file rule")
	}

	return &set, nil
}

func runForensicsVerify(args []string, env environment) int {
	flags := flag.NewFlagSet("forensics verify", flag.ContinueOnError)
	paths, err := splitFlags(flags, args)
	if err != nil || len(paths) != 2 {
		fmt.Fprintln(env.stderr, usageForensics)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}

	info, err := os.Stat(paths[0])
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return fail(errors.New("the manifest cannot be read"))
	}
	manifest, err := os.ReadFile(paths[0])
	if err != nil {
		return fail(errors.New("the manifest cannot be read"))
	}
	differences, checked, err := forensics.Verify(paths[1], manifest)
	if err != nil {
		return fail(err)
	}

	changed := 0
	for _, difference := range differences {
		fmt.Fprintf(env.stdout, "%s: %s\n", difference.Path, difference.Reason)
		if !difference.NotChecked {
			changed++
		}
	}
	fmt.Fprintf(env.stdout, "Checked %d files. %d are not as the manifest says.\n", checked, changed)
	fmt.Fprintln(env.stdout, "This compares the files with this manifest. Compare the SHA-256 of the manifest itself with the one you wrote down when it was made.")
	if changed > 0 {
		return exitFailed
	}

	return exitOK
}

func writeHostScenario(env environment, directory string, seed int64, day time.Time, location *time.Location, benign bool) int {
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	host := scenario.GenerateHost(seed, day, !benign)
	expected, err := json.MarshalIndent(map[string]any{
		"note": "Synthetic system made by omamori scenario --host. No file comes from a real system.", "seed": seed, "date": day.Format("2006-01-02"),
		"expected_alerts": append([]scenario.Expected{}, host.Expected...), "known_misses": append([]string{}, host.KnownMisses...),
	}, "", "  ")
	if err != nil {
		return fail(errors.New("the list of expected alerts could not be written"))
	}
	host.Files["expected.json"] = scenario.HostFile{Text: string(expected) + "\n", Modified: env.clock()}
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return fail(errors.New("the folder cannot be made"))
	}
	if err := scenario.WriteHost(directory, host); err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "Wrote a synthetic system of %d files for %s to %s\nTry: omamori forensics --year %d --timezone %s --processes %s --sockets %s -- %s\n",
		len(host.Files), day.Format("2006-01-02"), directory, day.Year(), shellArgument(location.String()),
		shellArgument(filepath.Join(directory, "snapshots", "ps.txt")), shellArgument(filepath.Join(directory, "snapshots", "ss.txt")), shellArgument(filepath.Join(directory, "root")))

	return exitOK
}
