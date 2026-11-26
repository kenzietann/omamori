package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kenzietann/omamori/internal/alertsink"
	"github.com/kenzietann/omamori/internal/assets"
	"github.com/kenzietann/omamori/internal/indicators"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/watch"
)

const usageWatch = "usage: omamori watch [--interval duration] [--severity level] [--webhook url] " +
	"[--smtp-host host --smtp-port n --smtp-from addr --smtp-to addr[,addr...]] [--state file] " +
	"[--rules folder] [--assets file] [--indicators file] [--format name] [--year n] [--timezone name] " +
	"[--once] <logs>..."

// runWatch polls the given log paths on a fixed interval, runs the same rules detect does, and sends
// alerts that have not been sent before to any configured sinks. It never writes a report and never
// calls an AI provider: it is a continuous version of detect's own matching, not a new analysis path.
func runWatch(args []string, env environment) int {
	flags := flag.NewFlagSet("watch", flag.ContinueOnError)
	var chosen settings
	var rulesFolder, format, statePath string
	var severity string
	var interval time.Duration
	var once bool
	flags.StringVar(&rulesFolder, "rules", "", "folder with rules, in place of the built-in rules")
	flags.StringVar(&format, "format", "", "syslog, web, json, app, macos, suricata, zeek, wazuh, windows or pcap")
	flags.IntVar(&chosen.year, "year", 0, "year of syslog lines")
	flags.StringVar(&chosen.zone, "timezone", "", "time zone of syslog lines")
	flags.StringVar(&severity, "severity", "low", "minimum level sent to a sink: informational, low, medium, high or critical")
	flags.DurationVar(&interval, "interval", 15*time.Second, "how often to re-check the logs")
	flags.StringVar(&statePath, "state", "", "where to keep the record of alerts already sent (default: next to the first log path)")
	flags.BoolVar(&once, "once", false, "run a single check and exit, instead of looping")
	var assetsPath, indicatorsPath string
	flags.StringVar(&assetsPath, "assets", "", "asset list: names and addresses of your own machines")
	flags.StringVar(&indicatorsPath, "indicators", "", "indicator list: addresses, domains and hashes that are known to be bad")
	var webhookURL string
	flags.StringVar(&webhookURL, "webhook", "", "URL to POST new alerts to (a Slack or Discord incoming webhook also works)")
	var smtpHost, smtpFrom, smtpTo string
	var smtpPort int
	var smtpTLS bool
	flags.StringVar(&smtpHost, "smtp-host", "", "SMTP server for email alerts")
	flags.IntVar(&smtpPort, "smtp-port", 587, "SMTP port")
	flags.StringVar(&smtpFrom, "smtp-from", "", "From address for email alerts")
	flags.StringVar(&smtpTo, "smtp-to", "", "comma-separated To addresses for email alerts")
	flags.BoolVar(&smtpTLS, "smtp-tls", true, "use STARTTLS (set --smtp-tls=false only for a trusted local relay)")

	paths, err := splitFlags(flags, args)
	if err != nil || len(paths) == 0 {
		fmt.Fprintln(env.stderr, usageWatch)
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
	if _, ok := map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}[severity]; !ok {
		return fail(errors.New("--severity must be informational, low, medium, high or critical"))
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

	if statePath == "" {
		absolute, err := filepath.Abs(paths[0])
		if err != nil {
			return fail(errors.New("the first log path is not usable"))
		}
		statePath = filepath.Join(filepath.Dir(absolute), ".omamori-watch-state.json")
	}

	sinks, err := buildSinks(webhookURL, smtpHost, smtpPort, smtpFrom, smtpTo, smtpTLS, env)
	if err != nil {
		return fail(err)
	}
	if len(sinks) == 0 {
		fmt.Fprintln(env.stdout, "omamori: no --webhook or --smtp-* given. Alerts will only be printed here, not delivered anywhere.")
		sinks = append(sinks, printSink{out: env.stdout})
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	config := watch.Config{
		Paths:     paths,
		Rules:     loaded,
		RulesFrom: rulesFrom,
		Options:   intake.Options{Year: chosen.year, Location: location, Format: format, Assets: machines, Indicators: known},
		StatePath: statePath,
		Sinks:     sinks,
		MinLevel:  severity,
		Interval:  interval,
		Once:      once,
		Now:       env.now,
		OnTick:    func(line string) { fmt.Fprintln(env.stdout, "omamori watch:", line) },
	}

	if once {
		fmt.Fprintf(env.stdout, "omamori watch: %d rule(s), one check, severity %s or above.\n", len(loaded.Rules()), severity)
	} else {
		fmt.Fprintf(env.stdout, "omamori watch: %d rule(s), checking every %s, severity %s or above. Ctrl-C to stop.\n", len(loaded.Rules()), interval, severity)
	}

	if err := watch.Run(ctx, config); err != nil {
		return fail(err)
	}

	return exitOK
}

// printSink writes each new alert to the terminal, for a watch with no webhook and no email. The alerts are
// already sanitized by alertsink.FromAlerts.
type printSink struct{ out io.Writer }

func (sink printSink) Send(_ context.Context, alerts []alertsink.Alert) error {
	for _, alert := range alerts {
		fmt.Fprintf(sink.out, "ALERT [%s] %s (%s): %s\n", alert.Level, alert.Title, alert.Rule, alert.Summary)
	}

	return nil
}

func buildSinks(webhookURL, smtpHost string, smtpPort int, smtpFrom, smtpTo string, smtpTLS bool, env environment) ([]alertsink.Sink, error) {
	var sinks []alertsink.Sink

	if webhookURL != "" {
		sink, err := alertsink.NewWebhookSink(webhookURL)
		if err != nil {
			return nil, errors.New("--webhook is not a usable URL")
		}
		sinks = append(sinks, sink)
	}

	if smtpHost != "" {
		if smtpFrom == "" || smtpTo == "" {
			return nil, errors.New("--smtp-host needs --smtp-from and --smtp-to")
		}
		var to []string
		for _, address := range strings.Split(smtpTo, ",") {
			address = strings.TrimSpace(address)
			if address != "" {
				to = append(to, address)
			}
		}
		sink, err := alertsink.NewSMTPSink(alertsink.SMTPConfig{
			Host: smtpHost, Port: smtpPort, From: smtpFrom, To: to, UseTLS: smtpTLS,
			Username: env.lookupEnv("OMAMORI_SMTP_USER"), Password: env.lookupEnv("OMAMORI_SMTP_PASSWORD"),
		})
		if err != nil {
			return nil, errors.New("the SMTP settings are not usable")
		}
		sinks = append(sinks, sink)
	}

	return sinks, nil
}
