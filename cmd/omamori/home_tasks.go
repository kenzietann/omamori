package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/forensics"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

func (b backend) prepareHome(setup tui.Setup) (tui.Plan, error) {
	if setup.Replay {
		return tui.Plan{}, errors.New("open an analyst recording with the replay command")
	}
	now := time.Now()
	if b.config.Now != nil {
		now = b.config.Now()
	}
	location := time.Local
	year := now.Year()
	if b.config.Triage != nil {
		location = b.config.Triage.Location
		year = b.config.Triage.Year
	}
	if setup.Task == tui.TaskDemo {
		folder := filepath.Join(b.config.OutputBase, "demo-"+now.UTC().Format("20060102-150405"))
		return localHomePlan("Make demo data", "Create synthetic logs and a synthetic Linux system in "+folder, func(ctx context.Context) (tui.Result, error) {
			if ctx.Err() != nil {
				return tui.Result{}, ctx.Err()
			}
			_, err := reportwriter.NewRun([]string{b.config.Target}, folder)
			if err != nil {
				return tui.Result{}, err
			}
			day := time.Date(year, now.Month(), now.Day(), 0, 0, 0, 0, location)
			logs, err := reportwriter.NewFolder(filepath.Join(folder, "logs"))
			if err != nil {
				return tui.Result{}, err
			}
			for name, text := range scenario.Generate(3, day, true).Files {
				if err := logs.Write(name, text); err != nil {
					return tui.Result{}, err
				}
			}
			if err := scenario.WriteHost(filepath.Join(folder, "host"), scenario.GenerateHost(3, day, true)); err != nil {
				return tui.Result{}, err
			}
			return tui.Result{Complete: true, SavedTo: folder, Report: fmt.Sprintf("# Synthetic demo data\n\nLogs: %s\n\nLinux artifacts: %s\n\nOpen the corresponding folder with omamori ui to inspect it.\n", filepath.Join(folder, "logs"), filepath.Join(folder, "host", "root"))}, nil
		}), nil
	}
	if setup.Task == tui.TaskDashboard {
		env := b.env
		if env.home == nil {
			env.home = os.UserHomeDir
		}
		if env.lookupEnv == nil {
			env.lookupEnv = b.config.LookupEnv
		}
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
		env := b.env
		if env.home == nil {
			env.home = os.UserHomeDir
		}
		if env.lookupEnv == nil {
			env.lookupEnv = b.config.LookupEnv
		}
		cfg, err := (storageFlags{}).config(env)
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
	set, err := rules.Builtin()
	if forensic {
		set, err = rules.BuiltinForensics()
	}
	if err != nil {
		return tui.Plan{}, err
	}
	var outcome detect.Outcome
	base := analysisrun.Base{}
	title := "Detect"
	if forensic {
		result, err := forensics.Run(b.config.Target, set, "built-in, with the rules for artifacts", forensics.Options{Year: year, Location: location}, now)
		if err != nil {
			return tui.Plan{}, err
		}
		outcome = result.Outcome
		title = "Forensics"
		base = analysisrun.Base{Report: forensics.Markdown(result), Prefix: "forensics", Files: map[string]string{"manifest.json": result.ManifestText, "manifest.sha256": result.ManifestSHA256 + "  manifest.json\n"}}
	} else {
		outcome, err = detect.Run([]string{b.config.Target}, set, "built-in", intake.Options{Year: year, Location: location}, now)
		if err != nil {
			return tui.Plan{}, err
		}
		if len(outcome.Intake.Files) == 0 {
			return tui.Plan{}, errors.New("no recognized logs were found in this folder")
		}
	}
	if ai {
		session, err := analysisrun.Prepare(context.Background(), analysisrun.Config{Provider: b.config, Sources: []string{b.config.Target}, Base: base}, outcome, taskrun.Setup{ProviderID: setup.ProviderID, Model: setup.Model, Key: setup.Key, Reasoning: setup.Reasoning})
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
		return tui.Plan{Title: title + " + AI review", ConsentText: session.ConsentText(), Summary: fmt.Sprintf("Review %d detected alerts. Every AI claim is checked against the evidence.", len(outcome.Result.Alerts)), Preview: string(preview), MaxRequests: 3, MaxTokens: b.config.Limits.MaxTokens, Confirm: session.Confirm, Run: func(ctx context.Context, step func(string)) (tui.Result, error) {
			result, err := session.Run(ctx, func(p analysisrun.Progress) {
				if step != nil {
					step(p.Message)
				}
			})
			report := ""
			if result.SavedTo != "" {
				text, _ := os.ReadFile(filepath.Join(result.SavedTo, "report.md"))
				report = string(text)
			}
			return tui.Result{Report: report, Complete: result.Complete, SavedTo: result.SavedTo}, err
		}}, nil
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
	return localHomePlan(title, fmt.Sprintf("Read-only collection found %d events and %d alerts. Write reports to %s.", len(outcome.Intake.Events), len(outcome.Result.Alerts), directory), func(ctx context.Context) (tui.Result, error) {
		if ctx.Err() != nil {
			return tui.Result{}, ctx.Err()
		}
		writer, err := reportwriter.NewRun([]string{b.config.Target}, directory)
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
		return tui.Result{Report: report, Complete: true, SavedTo: directory}, nil
	}), nil
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
