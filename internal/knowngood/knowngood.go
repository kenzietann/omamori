// Package knowngood keeps the list of alerts that a person reviewed and found to be their own: an installer
// they ran, an agent they installed. An alert that the list covers is lowered to "known good". It is never
// removed: it stays in the report, in its own section and in the timeline, and its events stay in every rule
// that counts them.
//
// The list holds no values from the evidence. Each item is a SHA-256 fingerprint of one event of an alert:
// the rule, the fields of the event, and, for an artifact that is a whole file (a launchd item, a crash
// report), the hash of that file. Anything that changes gives another fingerprint, and the alert comes back.
//
// The list decides what a run shows, so it is kept away from the evidence, and its hash is in every report.
// It is a plain file in version 1, not signed: a person with root on the machine that holds it can change it.
package knowngood

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
)

const (
	Version = 1

	StateKnownGood = "known_good"
	StateChanged   = "changed"
	StateExpired   = "expired"

	// DefaultDays is how long an entry holds. After it, the alert comes back, and the person looks again.
	DefaultDays = 90
	MaxDays     = 366

	maxListBytes = 4 << 20
	maxEntries   = 10_000
	maxItems     = 200
	maxNoteRunes = 300
	dateLayout   = "2006-01-02"
)

var (
	ErrList  = errors.New("the known-good list cannot be used")
	hexHash  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ruleName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)
)

// volatile are fields that differ between two runs over the same thing: the number of a process, and what
// Omamori writes about where an event came from.
var volatile = map[string]bool{
	"pid": true, event.Collector: true, "time_source": true, "log_level": true,
}

// Item is one event of an alert, as two hashes. Fingerprint is the event itself. Subject names the thing the
// event is about when that thing can change and still be the same thing (one launchd item, one report file);
// for other events it is the fingerprint.
type Item struct {
	Subject     string `yaml:"subject" json:"subject"`
	Fingerprint string `yaml:"fingerprint" json:"fingerprint"`
}

type Entry struct {
	Rule string `yaml:"rule"`
	// Title is the title of the rule when the entry was made. It is for the person who reads the list.
	Title string `yaml:"title,omitempty"`
	// Host limits the entry to one machine. Empty is every machine.
	Host    string `yaml:"host,omitempty"`
	Note    string `yaml:"note"`
	Added   string `yaml:"added"`
	Expires string `yaml:"expires"`
	Items   []Item `yaml:"items"`
}

type List struct {
	Version int     `yaml:"version"`
	Entries []Entry `yaml:"entries"`

	// SHA256 is the hash of the file as it was read, for the report.
	SHA256 string `yaml:"-"`
}

// Fingerprint gives the item of one event of an alert of a rule. hashes holds the SHA-256 of the files that
// were read, by the path that event references use; it can be nil (logs have no file hashes).
func Fingerprint(rule string, current event.Event, hashes map[string]string) Item {
	names := make([]string, 0, len(current.Fields))
	for name := range current.Fields {
		if !volatile[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var text strings.Builder
	fmt.Fprintf(&text, "omamori known-good v1\nrule=%q\n", rule)
	for _, name := range names {
		fmt.Fprintf(&text, "%q=%q\n", name, current.Fields[name])
	}
	file, whole := wholeFile(current)
	if whole {
		fmt.Fprintf(&text, "file=%q sha256=%q\n", file, hashes[file])
	}
	fingerprint := digest(text.String())
	subject := fingerprint
	if whole {
		subject = digest(fmt.Sprintf("omamori known-good v1 subject\nrule=%q\nfile=%q\n", rule, file))
	}

	return Item{Subject: subject, Fingerprint: fingerprint}
}

// wholeFile says whether an event stands for a whole file: an artifact whose reference has no line number.
// Then the file is the thing that was reviewed, and its hash is part of the fingerprint.
func wholeFile(current event.Event) (string, bool) {
	if current.Source != "forensics" || current.Ref == "" || strings.HasPrefix(current.Ref, "snapshot:") {
		return "", false
	}
	if index := strings.LastIndex(current.Ref, ":"); index >= 0 && strings.Trim(current.Ref[index+1:], "0123456789") == "" {
		return "", false
	}

	return current.Ref, true
}

func digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// Items gives the items of every event of an alert. complete is false when the alert holds more events than
// it keeps (a count over many lines): such an alert cannot be pinned exactly, and the list never covers it.
func Items(alert *rules.Alert, hashes map[string]string) (items []Item, complete bool) {
	if len(alert.Events) == 0 || alert.Count > len(alert.Events) || len(alert.Events) > maxItems {
		return nil, false
	}
	for _, current := range alert.Events {
		items = append(items, Fingerprint(alert.Rule.Name, current, hashes))
	}

	return items, true
}

// Load reads a list. A missing file is an error: a run that names a list must use it.
func Load(path string) (*List, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s cannot be opened", ErrList, filepath.Base(path))
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxListBytes+1))
	if err != nil || len(data) > maxListBytes {
		return nil, fmt.Errorf("%w: it cannot be read, or it is larger than %d MB", ErrList, maxListBytes>>20)
	}

	return Parse(data)
}

// Parse reads the text of a list and checks every entry.
func Parse(data []byte) (*List, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var list List
	if err := decoder.Decode(&list); err != nil {
		return nil, fmt.Errorf("%w: it is not a valid list (%v)", ErrList, err)
	}
	if list.Version != Version {
		return nil, fmt.Errorf("%w: version %d is not known; this Omamori reads version %d", ErrList, list.Version, Version)
	}
	if len(list.Entries) > maxEntries {
		return nil, fmt.Errorf("%w: it has more than %d entries", ErrList, maxEntries)
	}
	for index, entry := range list.Entries {
		if err := entry.check(); err != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", ErrList, index+1, err)
		}
	}
	list.SHA256 = digest(string(data))

	return &list, nil
}

func (entry Entry) check() error {
	added, err := time.Parse(dateLayout, entry.Added)
	if err != nil {
		return errors.New("added must be a date like 2026-11-16")
	}
	expires, err := time.Parse(dateLayout, entry.Expires)
	if err != nil {
		return errors.New("expires must be a date like 2027-02-14")
	}
	switch {
	case !ruleName.MatchString(entry.Rule):
		return errors.New("rule must name a rule")
	case strings.TrimSpace(entry.Note) == "":
		// The note is what a later reader sees: why this was allowed. An entry without one is refused.
		return errors.New("note must say why this is known good")
	case len([]rune(entry.Note)) > maxNoteRunes:
		return fmt.Errorf("note is longer than %d characters", maxNoteRunes)
	case !expires.After(added) || expires.Sub(added) > MaxDays*24*time.Hour:
		return fmt.Errorf("expires must be after added, and at most %d days later", MaxDays)
	case len(entry.Items) == 0 || len(entry.Items) > maxItems:
		return fmt.Errorf("items must hold 1 to %d items", maxItems)
	case len(entry.Host) > 255 || strings.ContainsAny(entry.Host, "\n\r\t"):
		return errors.New("host is not a host name")
	}
	for _, item := range entry.Items {
		if !hexHash.MatchString(item.Subject) || !hexHash.MatchString(item.Fingerprint) {
			return errors.New("each item must have a subject and a fingerprint of 64 hex characters")
		}
	}

	return nil
}

// Text gives the list as YAML, with a header that says what it is.
func (list *List) Text() (string, error) {
	data, err := yaml.Marshal(list)
	if err != nil {
		return "", err
	}

	return "# Omamori known-good list. Each entry was confirmed by a person, with the reason in its note.\n" +
		"# An entry lowers the alerts whose events have these fingerprints to \"known good\"; it never hides them.\n" +
		"# Keep this file away from the systems you check: Omamori refuses a list inside the evidence.\n" +
		string(data), nil
}

// Mark is what the list says about one alert.
type Mark struct {
	State string
	// Entries are the entries that cover the alert (known good), or the ones it relates to (changed, expired).
	Entries []*Entry
}

// Applied is the outcome of a list over the alerts of one run.
type Applied struct {
	List  *List
	Path  string
	Marks map[*rules.Alert]Mark
	// Lowered is the number of alerts that are known good.
	Lowered int
}

// KnownGood says whether an alert is lowered. A nil Applied lowers nothing.
func (applied *Applied) KnownGood(alert *rules.Alert) bool {
	return applied != nil && applied.Marks[alert].State == StateKnownGood
}

// Apply looks up every alert in the list. An alert is known good when every one of its events has an item in
// a live entry of the same rule and host. An alert that shares the subject of an entry but not its fingerprint
// is "changed": the reviewed thing is not the same any more. An alert that only an expired entry covers is
// "expired". Both stay alerts. host is the name of the machine of the run, for events that carry none.
func Apply(list *List, path string, alerts []*rules.Alert, hashes map[string]string, host string, now time.Time) *Applied {
	applied := &Applied{List: list, Path: path, Marks: map[*rules.Alert]Mark{}}
	if list == nil {
		return applied
	}
	today := now.UTC().Format(dateLayout)
	byRule := map[string][]*Entry{}
	for index := range list.Entries {
		entry := &list.Entries[index]
		byRule[entry.Rule] = append(byRule[entry.Rule], entry)
	}
	for _, alert := range alerts {
		entries := byRule[alert.Rule.Name]
		if len(entries) == 0 {
			continue
		}
		items, complete := Items(alert, hashes)
		if !complete {
			continue
		}
		var live, expired, changed []*Entry
		covered, coveredExpired := true, true
		for index, item := range items {
			eventHost := alert.Events[index].Fields[event.Host]
			if eventHost == "" {
				eventHost = host
			}
			found, foundExpired := false, false
			for _, entry := range entries {
				if entry.Host != "" && !strings.EqualFold(entry.Host, eventHost) {
					continue
				}
				for _, pinned := range entry.Items {
					switch {
					case pinned.Fingerprint == item.Fingerprint && entry.Expires > today:
						found = true
						live = appendOnce(live, entry)
					case pinned.Fingerprint == item.Fingerprint:
						foundExpired = true
						expired = appendOnce(expired, entry)
					case pinned.Subject == item.Subject && pinned.Subject != pinned.Fingerprint:
						changed = appendOnce(changed, entry)
					}
				}
			}
			covered = covered && found
			coveredExpired = coveredExpired && (found || foundExpired)
		}
		switch {
		case covered:
			applied.Marks[alert] = Mark{State: StateKnownGood, Entries: live}
			applied.Lowered++
		case len(changed) > 0:
			applied.Marks[alert] = Mark{State: StateChanged, Entries: changed}
		case coveredExpired && len(expired) > 0:
			applied.Marks[alert] = Mark{State: StateExpired, Entries: expired}
		}
	}

	return applied
}

func appendOnce(list []*Entry, entry *Entry) []*Entry {
	for _, present := range list {
		if present == entry {
			return list
		}
	}

	return append(list, entry)
}

// Dates gives the dates of a new entry: today, and the day it expires.
func Dates(now time.Time, days int) (added, expires string, err error) {
	if days < 1 || days > MaxDays {
		return "", "", fmt.Errorf("an entry holds 1 to %d days", MaxDays)
	}
	day := now.UTC()

	return day.Format(dateLayout), day.AddDate(0, 0, days).Format(dateLayout), nil
}

// Outside checks that the list is not inside any of the places that a run reads. A list inside the evidence
// would be part of the system that is looked at, and whoever controls that system would control the list.
func Outside(list string, places []string) error {
	absolute, err := resolve(list)
	if err != nil {
		return ErrList
	}
	for _, place := range places {
		base, err := resolve(place)
		if err != nil {
			continue
		}
		if relative, err := filepath.Rel(base, absolute); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%w: the list must not be inside the evidence or the places that are read (%s)", ErrList, place)
		}
	}

	return nil
}

// resolve gives the real path of a file or folder, with every link resolved. For a path that does not exist
// yet, the nearest folder above it that exists is resolved: on a Mac /var is a link to /private/var, and a
// new file under it must still be found inside /private/var.
func resolve(name string) (string, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	var rest []string
	for current := absolute; ; current = filepath.Dir(current) {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(append([]string{resolved}, rest...)...), nil
		}
		if filepath.Dir(current) == current {
			return absolute, nil
		}
		rest = append([]string{filepath.Base(current)}, rest...)
	}
}
