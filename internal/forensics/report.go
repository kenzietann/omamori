package forensics

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
)

const (
	maxTableRows    = 100
	maxManifestRows = 300
)

type Result struct {
	Outcome        detect.Outcome
	Manifest       Manifest
	ManifestText   string
	ManifestSHA256 string
	// Label is the name of the evidence folder, without the folders above it.
	Label string
}

// manifestLimit is MaxManifestBytes. A test makes it small, because a real manifest of that size needs
// hundreds of thousands of files.
var manifestLimit = MaxManifestBytes

func Run(folder string, set rules.Set, rulesFrom string, options Options, now time.Time) (Result, error) {
	if options.FileRules != nil {
		merged, err := WithFileRules(set, *options.FileRules)
		if err != nil {
			return Result{}, err
		}
		set = merged
	}
	collected, err := Collect(folder, options)
	if err != nil {
		return Result{}, err
	}
	text, digest, err := collected.Manifest.JSON()
	if err != nil {
		return Result{}, err
	}
	// Checked before any file of the report is written, so that a run never stops with half a report.
	if len(text) > manifestLimit {
		return Result{}, fmt.Errorf("%w: the manifest would be larger than %d MB", ErrTooBig, MaxManifestBytes>>20)
	}

	return Result{
		Outcome: detect.Outcome{
			Intake: intake.Result{Events: collected.Events, Files: collected.Files, Skipped: collected.Manifest.Skipped},
			Result: set.Evaluate(collected.Events), Rules: len(set.Rules()), RulesFrom: rulesFrom, Made: now, Location: options.Location,
		},
		Manifest: collected.Manifest, ManifestText: text, ManifestSHA256: digest, Label: filepath.Base(filepath.Clean(folder)),
	}, nil
}

func timeNote(alert *rules.Alert) string {
	if len(alert.Events) == 0 {
		return "-"
	}
	first := alert.Events[0]
	if first.Source != Source {
		return "log line"
	}
	if first.Fields[TimeField] == TimeRecorded {
		return "written in the history"
	}

	return "last change of the file (the entry can be older)"
}

func Markdown(result Result) string {
	return detect.MarkdownWith(result.Outcome, detect.Extra{
		Title: "Omamori forensic triage report",
		Intro: []string{
			fmt.Sprintf("Evidence: %d files were read and hashed. Nothing in the evidence folder was changed or run.", len(result.Manifest.Entries)),
			"SHA-256 of manifest.json: " + result.ManifestSHA256,
		},
		OwnTimeline: true,
		Sections:    func(format *detect.Formatter) string { return sections(result, format) },
		Limits: []string{
			"Only a fixed list of places was read as artifacts: login and web logs, crontabs, systemd units in /etc and in home folders, authorized_keys, shell histories, /etc/passwd, and the snapshot files that were given. Other places to hide (kernel modules, shell start files, changed programs, at jobs) were not read as artifacts.",
			"The file rules (when they were on) looked at the content of the files in tmp, var/tmp, dev/shm, root, home, etc, var/spool/cron, usr/local, opt, srv and var/www, without following links. Programs of the system in /usr/bin and /usr/lib were not looked at. A packed or encrypted program shows none of its strings.",
			"Password hashes (/etc/shadow), private keys and files of credentials are never read.",
			"Most artifacts do not say when they were made. Their time in the timeline is the last change of the file. A copy of a file can have a new time, and an attacker can set the time of a file.",
			"Deleted files are not seen. A system that is still running and has a rootkit can show files that are not what is on the disk.",
			"A hit of a rule on an artifact says that it needs a look. An administrator can have made it.",
			"Snapshot files of processes and sockets are text that someone saved. Their content is taken as it is.",
		},
	})
}

func sections(result Result, format *detect.Formatter) string {
	var out strings.Builder
	alerts := result.Outcome.Result.Alerts

	if len(alerts) > 0 {
		out.WriteString("## Attack timeline\n\n")
		out.WriteString("Alerts from the logs and from the artifacts in one order of time. Read the column \"Time comes from\" before you trust the order: only log lines and history entries with a time say when the thing happened.\n\n")
		out.WriteString("| Time | Time comes from | Level | What | Who | Where |\n|---|---|---|---|---|---|\n")
		for index, alert := range alerts {
			if index == maxManifestRows {
				fmt.Fprintf(&out, "\n%d more alerts are in alerts.json.\n", len(alerts)-maxManifestRows)
				break
			}
			where := "-"
			if len(alert.Events) > 0 {
				where = format.Text(alert.Events[0].Ref, 80)
			}
			format.Row(&out, format.Time(alert.Time), timeNote(alert), alert.Rule.Level, format.Text(alert.Rule.Title, 160), format.Group(alert), where)
		}
		out.WriteString("\n")
	}

	byKind := map[string][]event.Event{}
	for _, current := range result.Outcome.Intake.Events {
		if current.Source == Source {
			byKind[current.Fields[event.Service]] = append(byKind[current.Fields[event.Service]], current)
		}
	}
	table := func(title, note string, events []event.Event, header []string, fields []string) {
		if len(events) == 0 {
			return
		}
		out.WriteString("## " + title + "\n\n")
		if note != "" {
			out.WriteString(note + "\n\n")
		}
		out.WriteString("| Where | " + strings.Join(header, " | ") + " |\n|" + strings.Repeat("---|", len(header)+1) + "\n")
		for index, current := range events {
			if index == maxTableRows {
				break
			}
			cells := []any{format.Text(current.Ref, 80)}
			for _, field := range fields {
				value := current.Fields[field]
				if value == "" {
					cells = append(cells, "-")
					continue
				}
				cells = append(cells, format.Value(field, value))
			}
			format.Row(&out, cells...)
		}
		if len(events) > maxTableRows {
			fmt.Fprintf(&out, "\n%d more are not shown here.\n", len(events)-maxTableRows)
		}
		out.WriteString("\n")
	}

	var logins []event.Event
	for _, account := range byKind[KindAccounts] {
		if account.Fields["can_login"] == "true" || account.Fields["uid"] == "0" {
			logins = append(logins, account)
		}
	}
	table("Accounts that can log in", "From /etc/passwd: accounts with a login shell, and every account with user number 0.", logins,
		[]string{"User", "Number", "Shell", "Home"}, []string{event.User, "uid", "shell", "home"})
	table("Keys that can log in", "From authorized_keys. Compare the fingerprints with the keys that you know.", byKind[KindKeys],
		[]string{"User", "Type", "Fingerprint", "Comment", "Options"}, []string{event.User, "key_type", "fingerprint", "key_comment", "key_options"})
	table("Scheduled jobs", "From the crontabs.", byKind[KindCron],
		[]string{"User", "When", "Command"}, []string{event.User, "schedule", event.Command})
	table("Programs that systemd starts", "From the units in /etc/systemd/system and in home folders. Units of installed packages (/usr/lib) are not read.", byKind[KindUnit],
		[]string{"Unit", "User", "Command"}, []string{"unit", event.User, event.Command})
	table("Listening sockets", "From the snapshot file.", byKind[KindSockets],
		[]string{"Protocol", "Address", "Port", "Process", "Process number"}, []string{event.Protocol, "local_address", "local_port", event.Process, "pid"})

	out.WriteString("## Evidence manifest\n\n")
	fmt.Fprintf(&out, "Evidence folder: %s. The full list is in manifest.json. To check later that the files are the same, run \"omamori forensics verify\" with manifest.json and the folder.\n\n", format.Text(result.Label, 80))
	out.WriteString("| File | Kind | Bytes | SHA-256 | Last change (UTC) | Events |\n|---|---|---|---|---|---|\n")
	entries := append([]Entry{}, result.Manifest.Entries...)
	sort.SliceStable(entries, func(first, second int) bool { return entries[first].Path < entries[second].Path })
	for index, entry := range entries {
		if index == maxManifestRows {
			break
		}
		name := format.Text(entry.Path, 120)
		if entry.Note != "" {
			name += " (" + format.Text(entry.Note, 80) + ")"
		}
		format.Row(&out, name, entry.Kind, entry.Size, entry.SHA256, entry.Modified, entry.Events)
	}
	if len(entries) > maxManifestRows {
		fmt.Fprintf(&out, "\n%d more files are in manifest.json.\n", len(entries)-maxManifestRows)
	}
	out.WriteString("\n")

	return out.String()
}
