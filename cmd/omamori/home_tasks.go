package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/forensics"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

func (b backend) prepareHome(setup tui.Setup) (tui.Plan, error) {
	if setup.Replay && (setup.Options.Recording == "" || setup.Task != tui.TaskAnalyze && setup.Task != tui.TaskForensicsAnalyze) {
		return tui.Plan{}, errors.New("open an analyst recording with the replay command, or give it on the form of Analyze")
	}
	now, location, year := b.readTime()
	options := setup.Options
	switch setup.Task {
	case tui.TaskDemo:
		return b.prepareDemo(options, now, location, year)
	case tui.TaskVerify:
		return b.prepareVerify(options)
	}
	if setup.Task == tui.TaskDashboard {
		env := b.storageEnv()
		cfg, err := (storageFlags{}).config(env)
		if err != nil {
			return tui.Plan{}, err
		}
		where := "the configured database server"
		if cfg.Driver == "sqlite" {
			where = cfg.DSN
		}
		summary := "Start the local dashboard on 127.0.0.1, on a free port, for the folder " + b.config.Target + ".\n" +
			"It uses the store at " + where + " and makes it when it does not exist.\n" +
			"A private link is printed. The dashboard runs until you press esc.\n" +
			"Runs with an AI provider are started in the dashboard, and each one asks you there before anything is sent."
		plan := localHomePlan("Dashboard", summary, func(ctx context.Context) (tui.Result, error) { return tui.Result{}, nil })
		run := plan.Run
		plan.Run = func(ctx context.Context, step func(string)) (tui.Result, error) {
			if _, err := run(ctx, nil); err != nil {
				return tui.Result{}, err
			}
			link := ""
			err := serveDashboard(ctx, env, b.config.Target, b.config.OutputBase, 0, storageFlags{}, func(url, _ string) {
				link = url
				if step != nil {
					step("the dashboard is running. Open this private link: " + url)
				}
			})
			if err != nil {
				return tui.Result{}, err
			}
			report := "The dashboard was stopped. Its link no longer works."
			if link == "" {
				report = "The dashboard did not start."
			}
			return tui.Result{Complete: link != "", Report: report}, nil
		}
		plan.ConsentText = "Start a web server that only this computer can reach. Nothing is sent by starting it."
		return plan, nil
	}
	if setup.Task == tui.TaskStored {
		cfg, err := (storageFlags{}).config(b.storageEnv())
		if err != nil {
			return tui.Plan{}, err
		}
		if cfg.Driver == "sqlite" {
			if _, err := os.Stat(cfg.DSN); err != nil {
				return tui.Plan{}, errors.New("no local store exists yet; run detect or analyze with --store first")
			}
		}
		plan := localHomePlan("Stored runs", "Read up to 100 saved runs from the configured database.", func(ctx context.Context) (tui.Result, error) {
			db, err := store.Open(ctx, cfg)
			if err != nil {
				return tui.Result{}, err
			}
			defer db.Close()
			runs, err := db.ListRuns(ctx, store.Query{Limit: 100})
			if err != nil {
				return tui.Result{}, err
			}
			data, err := json.MarshalIndent(runs, "", "  ")
			return tui.Result{Complete: err == nil, Report: "# Stored runs\n\n" + string(data)}, err
		})
		if cfg.Driver != "sqlite" {
			plan.Local = false
			plan.ConsentText = "Read saved runs from the configured database server. No AI provider is used."
		}
		return plan, nil
	}
	forensic := setup.Task == tui.TaskForensics || setup.Task == tui.TaskForensicsAnalyze
	ai := setup.Task == tui.TaskAnalyze || setup.Task == tui.TaskForensicsAnalyze
	set, rulesFrom, err := b.homeRules(options, forensic)
	if err != nil {
		return tui.Plan{}, err
	}
	machines, known, err := b.homeLists(options)
	if err != nil {
		return tui.Plan{}, err
	}
	sources := []string{b.config.Target}
	var outcome detect.Outcome
	base := analysisrun.Base{}
	title := "Detect"
	if forensic {
		processes, sockets, err := b.homeSnapshots(options)
		if err != nil {
			return tui.Plan{}, err
		}
		for _, snapshot := range []string{processes, sockets} {
			if snapshot != "" {
				sources = append(sources, snapshot)
			}
		}
		result, err := forensics.Run(b.config.Target, set, rulesFrom, forensics.Options{Year: year, Location: location, Processes: processes, Sockets: sockets, Assets: machines, Indicators: known}, now)
		if err != nil {
			return tui.Plan{}, err
		}
		if len(result.Manifest.Entries) == 0 {
			return tui.Plan{}, errors.New("no artifact was found. The folder must be the top of a Linux system, with folders like etc, var and home in it")
		}
		outcome = result.Outcome
		title = "Forensics"
		base = analysisrun.Base{Report: forensics.Markdown(result), Prefix: "forensics", Files: map[string]string{"manifest.json": result.ManifestText, "manifest.sha256": result.ManifestSHA256 + "  manifest.json\n"}}
	} else {
		outcome, err = detect.Run([]string{b.config.Target}, set, rulesFrom, intake.Options{Year: year, Location: location, Format: options.Format, Assets: machines, Indicators: known}, now)
		if err != nil {
			return tui.Plan{}, err
		}
		if len(outcome.Intake.Files) == 0 || len(outcome.Intake.Events) == 0 {
			return tui.Plan{}, errors.New("no event could be read from the logs in this folder. Choose the log format on the form")
		}
	}
	storeText := ""
	if options.Store {
		where, err := b.storeWhere()
		if err != nil {
			return tui.Plan{}, err
		}
		storeText = " The run is then stored in " + where + "."
	}
	if ai {
		return b.prepareReview(setup, outcome, base, sources, title, storeText)
	}
	report := base.Report
	if report == "" {
		report = detect.Markdown(outcome)
	}
	alerts, err := detect.JSON(outcome)
	if err != nil {
		return tui.Plan{}, err
	}
	prefix := "detect"
	if forensic {
		prefix = "forensics"
	}
	directory := filepath.Join(b.config.OutputBase, prefix+"-"+now.UTC().Format("20060102-150405"))
	plan := localHomePlan(title, fmt.Sprintf("Read-only collection found %d events and %d alerts. Write reports to %s.%s", len(outcome.Intake.Events), len(outcome.Result.Alerts), directory, storeText), func(ctx context.Context) (tui.Result, error) {
		if ctx.Err() != nil {
			return tui.Result{}, ctx.Err()
		}
		writer, err := reportwriter.NewRun(sources, directory)
		if err != nil {
			return tui.Result{}, err
		}
		files := map[string]string{"report.md": report, "report.html": htmlreport.Render(report), "alerts.json": alerts}
		for name, text := range base.Files {
			files[name] = text
		}
		for name, text := range files {
			if err := writer.Write(name, text); err != nil {
				return tui.Result{}, err
			}
		}
		shown := report
		if options.Store {
			id, err := b.storeOutcome(ctx, outcome, sources)
			if err != nil {
				return tui.Result{Report: report, SavedTo: directory}, err
			}
			shown += "\n\nStored run: " + id + "\n"
		}
		return tui.Result{Report: shown, Complete: true, SavedTo: directory}, nil
	})
	if options.Store {
		plan.ConsentText = "Read local evidence, write the described output and store the run. No AI provider is used."
		plan.Local = !strings.Contains(storeText, "database server")
	}
	return plan, nil
}

// prepareReview is the checked AI review of the home screen, live or from a recording. With storage, the
// database is opened only when the run starts, and the run is made again from the same alerts with the store,
// so the request that is sent is the one that was shown.
func (b backend) prepareReview(setup tui.Setup, outcome detect.Outcome, base analysisrun.Base, sources []string, title, storeText string) (tui.Plan, error) {
	runSetup := taskrun.Setup{ProviderID: setup.ProviderID, Model: setup.Model, Key: setup.Key, Reasoning: setup.Reasoning}
	if setup.Options.Recording != "" {
		recorded, err := b.homeRecording(setup.Options)
		if err != nil {
			return tui.Plan{}, err
		}
		runSetup = taskrun.Setup{Recording: recorded}
	}
	config := analysisrun.Config{Provider: b.config, Sources: sources, Base: base}
	session, err := analysisrun.Prepare(context.Background(), config, outcome, runSetup)
	if err != nil {
		return tui.Plan{}, err
	}
	request, err := session.Preview()
	if err != nil {
		return tui.Plan{}, err
	}
	preview, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return tui.Plan{}, err
	}
	var confirmed atomic.Bool
	return tui.Plan{Title: title + " + AI review", Label: session.Label(), ConsentText: session.ConsentText(),
		Summary: fmt.Sprintf("Review %d detected alerts. Every AI claim is checked against the evidence.%s", len(outcome.Result.Alerts), storeText),
		Preview: string(preview), MaxRequests: 3, MaxTokens: b.config.Limits.MaxTokens,
		Confirm: func() { confirmed.Store(true); session.Confirm() },
		Run: func(ctx context.Context, step func(string)) (tui.Result, error) {
			current := session
			if setup.Options.Store {
				if !confirmed.Load() {
					return tui.Result{}, taskrun.ErrNotConfirmed
				}
				db, err := b.openStore(ctx, sources)
				if err != nil {
					return tui.Result{}, err
				}
				defer db.Close()
				stored := config
				stored.Store = db
				if current, err = analysisrun.Prepare(ctx, stored, outcome, runSetup); err != nil {
					return tui.Result{}, err
				}
				current.Confirm()
			}
			result, err := current.Run(ctx, func(p analysisrun.Progress) {
				if step != nil {
					step(p.Message)
				}
			})
			report := ""
			if result.SavedTo != "" {
				text, _ := os.ReadFile(filepath.Join(result.SavedTo, "report.md"))
				report = string(text)
			}
			if result.RunID != "" {
				report += "\n\nStored run: " + result.RunID + "\n"
			}
			return tui.Result{Report: report, Complete: result.Complete, SavedTo: result.SavedTo}, err
		}}, nil
}

func (b backend) prepareDemo(options tui.Options, now time.Time, location *time.Location, year int) (tui.Plan, error) {
	seed, err := parseSeed(options.Seed, 3)
	if err != nil {
		return tui.Plan{}, err
	}
	folder := filepath.Join(b.config.OutputBase, "demo-"+now.UTC().Format("20060102-150405"))
	day := time.Date(year, now.Month(), now.Day(), 0, 0, 0, 0, location)
	what := map[string]string{"": "synthetic logs and a synthetic Linux system", "benign": "synthetic logs and a synthetic Linux system of a day without attacks",
		"campaign": "the synthetic campaign: logs of three hosts and two network sensors, an asset list and an indicator list"}[options.Kind]
	if what == "" {
		return tui.Plan{}, errors.New("this kind of demo data is not known")
	}
	return localHomePlan("Make demo data", fmt.Sprintf("Create %s (seed %d) in %s", what, seed, folder), func(ctx context.Context) (tui.Result, error) {
		if ctx.Err() != nil {
			return tui.Result{}, ctx.Err()
		}
		if err := pathguard.CheckOutputFolder(b.config.Target, folder); err != nil {
			return tui.Result{}, err
		}
		if options.Kind == "campaign" {
			var out, problems strings.Builder
			env := environment{stdout: &out, stderr: &problems, now: b.config.Now}
			if writeCampaignScenario(env, folder, seed, day, location, false) != exitOK {
				return tui.Result{}, errors.New(strings.TrimSpace(strings.TrimPrefix(problems.String(), "omamori: ")))
			}
			return tui.Result{Complete: true, SavedTo: folder, Report: "# Synthetic campaign\n\n" + out.String() + "\nOpen the logs folder with omamori ui and give assets.yml and indicators.yml on the form of Detect.\n"}, nil
		}
		attacks := options.Kind != "benign"
		if _, err := reportwriter.NewRun([]string{b.config.Target}, folder); err != nil {
			return tui.Result{}, err
		}
		logs, err := reportwriter.NewFolder(filepath.Join(folder, "logs"))
		if err != nil {
			return tui.Result{}, err
		}
		for name, text := range scenario.Generate(seed, day, attacks).Files {
			if err := logs.Write(name, text); err != nil {
				return tui.Result{}, err
			}
		}
		if err := scenario.WriteHost(filepath.Join(folder, "host"), scenario.GenerateHost(seed, day, attacks)); err != nil {
			return tui.Result{}, err
		}
		return tui.Result{Complete: true, SavedTo: folder, Report: fmt.Sprintf("# Synthetic demo data\n\nLogs: %s\n\nLinux artifacts: %s\n\nSaved ps and ss output: %s\n\nOpen the corresponding folder with omamori ui to inspect it.\n",
			filepath.Join(folder, "logs"), filepath.Join(folder, "host", "root"), filepath.Join(folder, "host", "snapshots"))}, nil
	}), nil
}

// prepareVerify hashes the files of the target folder again and compares them with a manifest. It writes nothing.
func (b backend) prepareVerify(options tui.Options) (tui.Plan, error) {
	path, err := b.expandPath(options.Manifest)
	if err != nil {
		return tui.Plan{}, err
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return tui.Plan{}, errors.New("the manifest cannot be read")
	}
	plan := localHomePlan("Verify hashes", "Hash the files of "+b.config.Target+" again and compare them with "+path+". Nothing is written.", func(ctx context.Context) (tui.Result, error) {
		manifest, err := os.ReadFile(path)
		if err != nil {
			return tui.Result{}, errors.New("the manifest cannot be read")
		}
		differences, checked, err := forensics.Verify(b.config.Target, manifest)
		if err != nil {
			return tui.Result{}, err
		}
		var report strings.Builder
		report.WriteString("# Hash check\n\n")
		changed := 0
		for _, difference := range differences {
			fmt.Fprintf(&report, "- %s: %s\n", difference.Path, difference.Reason)
			if !difference.NotChecked {
				changed++
			}
		}
		fmt.Fprintf(&report, "\nChecked %d files. %d are not as the manifest says.\n\n", checked, changed)
		report.WriteString("This compares the files with this manifest. Compare the SHA-256 of the manifest itself with the one you wrote down when it was made.\n")
		return tui.Result{Complete: changed == 0, Report: report.String()}, nil
	})
	plan.ConsentText = "Read the evidence folder and the manifest. Nothing is written and no AI provider is used."
	return plan, nil
}

func localHomePlan(title, summary string, run func(context.Context) (tui.Result, error)) tui.Plan {
	var confirmed, started atomic.Bool
	return tui.Plan{Title: title, Local: true, ConsentText: "Read local evidence and write the described output. No AI provider is used.", Summary: summary, Preview: summary, Confirm: func() { confirmed.Store(true) }, Run: func(ctx context.Context, step func(string)) (tui.Result, error) {
		if !confirmed.Load() {
			return tui.Result{}, taskrun.ErrNotConfirmed
		}
		if step != nil {
			step("running " + title)
		}
		if !started.CompareAndSwap(false, true) {
			return tui.Result{}, errors.New("this plan has already run")
		}
		return run(ctx)
	}}
}
