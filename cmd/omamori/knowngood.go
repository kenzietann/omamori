package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/kenzietann/omamori/internal/knowngood"
)

const (
	usageKnownGood = "usage: omamori known-good add --list file --note text [--days n] [--any-host] <report folder> <alert number>...\n" +
		"       omamori known-good show --list file"
	maxAlertsJSON = 64 << 20
)

func runKnownGood(args []string, env environment) int {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr, usageKnownGood)
		return exitUsage
	}
	switch args[0] {
	case "add":
		return runKnownGoodAdd(args[1:], env)
	case "show":
		return runKnownGoodShow(args[1:], env)
	}
	fmt.Fprintln(env.stderr, usageKnownGood)

	return exitUsage
}

type reportAlert struct {
	Number int               `json:"number"`
	Rule   string            `json:"rule"`
	Title  string            `json:"title"`
	Level  string            `json:"level"`
	Time   string            `json:"time"`
	Group  map[string]string `json:"group"`
	Count  int               `json:"count"`
	Events []struct {
		Ref    string            `json:"ref"`
		Fields map[string]string `json:"fields"`
	} `json:"events"`
	Match struct {
		Host     string           `json:"host"`
		Complete bool             `json:"complete"`
		Items    []knowngood.Item `json:"items"`
	} `json:"match"`
}

// runKnownGoodAdd adds alerts of a report to a known-good list. Each alert is shown, and only an answer of
// yes adds it: there is no flag to skip the question, so that a list is always the choice of a person.
func runKnownGoodAdd(args []string, env environment) int {
	flags := flag.NewFlagSet("known-good add", flag.ContinueOnError)
	var listPath, note string
	var days int
	var anyHost bool
	flags.StringVar(&listPath, "list", "", "the known-good list (made if it does not exist)")
	flags.StringVar(&note, "note", "", "why these alerts are known good, in your words")
	flags.IntVar(&days, "days", knowngood.DefaultDays, "how many days the entries hold")
	flags.BoolVar(&anyHost, "any-host", false, "let the entries hold on every machine, not only the one of the report")
	positional, err := splitFlags(flags, args)
	if err != nil || len(positional) < 2 || listPath == "" || strings.TrimSpace(note) == "" {
		fmt.Fprintln(env.stderr, usageKnownGood)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	var numbers []int
	for _, text := range positional[1:] {
		number, err := strconv.Atoi(text)
		if err != nil || number < 1 {
			fmt.Fprintln(env.stderr, usageKnownGood)
			return exitUsage
		}
		if !slices.Contains(numbers, number) {
			numbers = append(numbers, number)
		}
	}
	added, expires, err := knowngood.Dates(env.clock(), days)
	if err != nil {
		return fail(err)
	}

	alerts, err := readReportAlerts(positional[0])
	if err != nil {
		return fail(err)
	}
	list := &knowngood.List{Version: knowngood.Version}
	if _, err := os.Lstat(listPath); err == nil {
		if list, err = knowngood.Load(listPath); err != nil {
			return fail(err)
		}
	}

	input := bufio.NewReader(env.input())
	made := 0
	for _, number := range numbers {
		alert, found := alerts[number]
		switch {
		case !found:
			return fail(fmt.Errorf("the report has no alert %d. Use the numbers of the alerts in report.md", number))
		case !alert.Match.Complete || len(alert.Match.Items) == 0:
			fmt.Fprintf(env.stdout, "Alert %d (%s) counts more events than it keeps, so it cannot be pinned exactly. It was not added.\n", number, oneLine(alert.Title, 120))
			continue
		case onList(list, alert):
			fmt.Fprintf(env.stdout, "Alert %d is on the list already.\n", number)
			continue
		}
		describeAlert(env.stdout, number, alert, anyHost)
		fmt.Fprint(env.stdout, "Add it to the known-good list? Type yes to add: ")
		answer, _ := input.ReadString('\n')
		if answer = strings.ToLower(strings.TrimSpace(answer)); answer != "yes" && answer != "y" {
			fmt.Fprintf(env.stdout, "Alert %d was not added.\n", number)
			continue
		}
		entry := knowngood.Entry{
			Rule: alert.Rule, Title: oneLine(alert.Title, 200), Note: strings.TrimSpace(note), Added: added, Expires: expires,
			Items: alert.Match.Items,
		}
		if !anyHost {
			entry.Host = alert.Match.Host
		}
		list.Entries = append(list.Entries, entry)
		made++
	}
	if made == 0 {
		fmt.Fprintln(env.stdout, "Nothing was added; the list is as it was.")
		return exitOK
	}

	// The new list is checked like a list that is read, before it replaces the old one.
	text, err := list.Text()
	if err != nil {
		return fail(err)
	}
	checked, err := knowngood.Parse([]byte(text))
	if err != nil {
		return fail(err)
	}
	if err := writeAtomically(listPath, text); err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "Added %d entries to %s, until %s. The list has %d entries, SHA-256 %s.\n", made, listPath, expires, len(checked.Entries), checked.SHA256)

	return exitOK
}

// loadKnownGood reads the list of --known-good for a run. It must be outside every place that the run reads:
// whoever controls the evidence must not control which alerts are lowered. Version 1 does not store the marks
// or send them to the analyst, so those are refused instead of being half done.
func loadKnownGood(path string, places []string, storing, analyzing bool) (*knowngood.List, error) {
	if path == "" {
		return nil, nil
	}
	if storing || analyzing {
		return nil, errors.New("--known-good does not work with --store or --analyze yet. Run without them, or without the list")
	}
	if err := knowngood.Outside(path, places); err != nil {
		return nil, err
	}

	return knowngood.Load(path)
}

func readReportAlerts(folder string) (map[int]reportAlert, error) {
	file, err := os.Open(filepath.Join(folder, "alerts.json"))
	if err != nil {
		return nil, errors.New("the report folder has no alerts.json. Give the folder that a detect or forensics run made")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAlertsJSON+1))
	if err != nil || len(data) > maxAlertsJSON {
		return nil, errors.New("alerts.json cannot be read")
	}
	var report struct {
		Alerts []reportAlert `json:"alerts"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, errors.New("alerts.json is not a report of Omamori")
	}
	alerts := map[int]reportAlert{}
	for _, alert := range report.Alerts {
		alerts[alert.Number] = alert
	}

	return alerts, nil
}

func onList(list *knowngood.List, alert reportAlert) bool {
	for _, entry := range list.Entries {
		if entry.Rule == alert.Rule && slices.Equal(entry.Items, alert.Match.Items) && (entry.Host == "" || entry.Host == alert.Match.Host) {
			return true
		}
	}

	return false
}

// describeAlert shows what the person is about to allow. The texts come from alerts.json, where they passed
// the filter for secrets already.
func describeAlert(out io.Writer, number int, alert reportAlert, anyHost bool) {
	fmt.Fprintf(out, "\nAlert %d: %s (%s), %d events, at %s\n", number, oneLine(alert.Title, 160), oneLine(alert.Level, 20), alert.Count, oneLine(alert.Time, 40))
	for index, current := range alert.Events {
		if index == 5 {
			fmt.Fprintf(out, "  and %d more events\n", len(alert.Events)-5)
			break
		}
		var parts []string
		for _, field := range []string{"label", "command", "file", "programs", "user", "src_ip", "process", "panic", "boot_faults"} {
			if value := current.Fields[field]; value != "" {
				parts = append(parts, field+"="+oneLine(value, 200))
			}
		}
		fmt.Fprintf(out, "  %s: %s\n", oneLine(current.Ref, 160), strings.Join(parts, " "))
	}
	switch {
	case anyHost || alert.Match.Host == "":
		fmt.Fprintln(out, "  It will hold on every machine.")
	default:
		fmt.Fprintf(out, "  It will hold on the machine %s only.\n", oneLine(alert.Match.Host, 100))
	}
}

func oneLine(text string, runes int) string {
	text = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, text)
	if len([]rune(text)) > runes {
		return string([]rune(text)[:runes]) + "..."
	}

	return text
}

// writeAtomically writes the list to a new file next to it and renames it, so that a list is never half
// written. The file is readable by its owner only.
func writeAtomically(path, text string) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".known-good-*.yml")
	if err != nil {
		return errors.New("the list cannot be written in its folder")
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return errors.New("the list cannot be written")
	}
	if _, err := file.WriteString(text); err != nil {
		file.Close()
		return errors.New("the list cannot be written")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("the list cannot be written")
	}
	if err := file.Close(); err != nil {
		return errors.New("the list cannot be written")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("the list is not a normal file")
	}

	return os.Rename(name, path)
}

func runKnownGoodShow(args []string, env environment) int {
	flags := flag.NewFlagSet("known-good show", flag.ContinueOnError)
	var listPath string
	flags.StringVar(&listPath, "list", "", "the known-good list")
	positional, err := splitFlags(flags, args)
	if err != nil || len(positional) != 0 || listPath == "" {
		fmt.Fprintln(env.stderr, usageKnownGood)
		return exitUsage
	}
	list, err := knowngood.Load(listPath)
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	today := env.clock().UTC().Format("2006-01-02")
	fmt.Fprintf(env.stdout, "%s: %d entries, SHA-256 %s\n", listPath, len(list.Entries), list.SHA256)
	for index, entry := range list.Entries {
		state := "until " + entry.Expires
		if entry.Expires <= today {
			state = "EXPIRED on " + entry.Expires
		}
		host := "every machine"
		if entry.Host != "" {
			host = oneLine(entry.Host, 100)
		}
		fmt.Fprintf(env.stdout, "%d. %s (%s), %d events, %s, added %s, %s\n   %s\n", index+1, oneLine(entry.Title, 120), entry.Rule,
			len(entry.Items), host, entry.Added, state, oneLine(entry.Note, 300))
	}

	return exitOK
}
