// Package forensics reads the artifacts of a Linux system from a folder: a mounted disk image, an unpacked
// collection, or a live system. It only reads. Every file it opens is hashed, and the hashes go into a
// manifest, so that someone else can later check that the evidence is the same.
//
// The artifacts become events of the same shape as log events. The same rules look at them, the same store
// keeps them, and they stand in one timeline with the alerts from the logs.
//
// The folder is someone else's system, and after a break-in it is the attacker's. Nothing in it is run, no
// link is followed to a place outside of it, and every text from it is treated as data.
package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
)

const (
	KindLog       = "log"
	KindCron      = "cron_file"
	KindCronJob   = "cron_script"
	KindHistory   = "shell_history"
	KindUnit      = "systemd_unit"
	KindKeys      = "authorized_keys"
	KindAccounts  = "passwd"
	KindProcesses = "process_snapshot"
	KindSockets   = "socket_snapshot"
)

const (
	TimeRecorded = "recorded"
	TimeFileChange = "file_modified"
	TimeField      = "time_source"
)

const (
	Source = "forensics"

	maxArtifactBytes = 8 << 20
	maxEntries       = 50_000
	maxLinesPerFile  = 50_000
	maxEvents        = 500_000
	maxValueRunes    = 2048
	maxNameRunes     = 64
	maxMatches       = 2000
	ManifestVersion = 1
)

var (
	ErrRoot   = errors.New("the evidence folder cannot be read")
	ErrTooBig = errors.New("the evidence folder holds more than one run can take")
	ErrInput  = errors.New("the settings of the collection are not valid")
)

type Options struct {
	Year     int
	Location *time.Location
	Processes string
	Sockets   string
}

type Entry struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	Modified string `json:"modified"`
	SHA256   string `json:"sha256"`
	Events int `json:"events"`
	Note string `json:"note,omitempty"`
}

type Manifest struct {
	Version int     `json:"version"`
	Note    string  `json:"note"`
	Entries []Entry `json:"entries"`
	Skipped []string `json:"skipped"`
}

type Collection struct {
	Events   []event.Event
	Files    []intake.Stats
	Manifest Manifest
}

func (manifest Manifest) JSON() (text, digest string, err error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", "", err
	}
	data = append(data, '\n')
	sum := sha256.Sum256(data)

	return string(data), hex.EncodeToString(sum[:]), nil
}

type pattern struct {
	glob string
	kind string
	format string
}

var patterns = []pattern{
	{"var/log/auth.log", KindLog, intake.FormatSyslog}, {"var/log/auth.log.1", KindLog, intake.FormatSyslog},
	{"var/log/secure", KindLog, intake.FormatSyslog}, {"var/log/secure.1", KindLog, intake.FormatSyslog},
	{"var/log/syslog", KindLog, intake.FormatSyslog}, {"var/log/syslog.1", KindLog, intake.FormatSyslog},
	{"var/log/messages", KindLog, intake.FormatSyslog}, {"var/log/cron", KindLog, intake.FormatSyslog},
	{"var/log/nginx/access.log", KindLog, intake.FormatWeb}, {"var/log/nginx/access.log.1", KindLog, intake.FormatWeb},
	{"var/log/apache2/access.log", KindLog, intake.FormatWeb}, {"var/log/apache2/access.log.1", KindLog, intake.FormatWeb},
	{"var/log/httpd/access_log", KindLog, intake.FormatWeb},
	{"etc/passwd", KindAccounts, ""},
	{"etc/crontab", KindCron, ""}, {"etc/cron.d/*", KindCron, ""},
	{"var/spool/cron/crontabs/*", KindCron, ""}, {"var/spool/cron/*", KindCron, ""},
	{"etc/cron.hourly/*", KindCronJob, ""}, {"etc/cron.daily/*", KindCronJob, ""}, {"etc/cron.weekly/*", KindCronJob, ""}, {"etc/cron.monthly/*", KindCronJob, ""},
	{"etc/systemd/system/*.service", KindUnit, ""}, {"etc/systemd/system/*.timer", KindUnit, ""},
	{"root/.config/systemd/user/*.service", KindUnit, ""}, {"home/*/.config/systemd/user/*.service", KindUnit, ""},
	{"root/.ssh/authorized_keys", KindKeys, ""}, {"root/.ssh/authorized_keys2", KindKeys, ""},
	{"home/*/.ssh/authorized_keys", KindKeys, ""}, {"home/*/.ssh/authorized_keys2", KindKeys, ""},
	{"root/.bash_history", KindHistory, ""}, {"root/.zsh_history", KindHistory, ""},
	{"home/*/.bash_history", KindHistory, ""}, {"home/*/.zsh_history", KindHistory, ""},
}

type collector struct {
	root    *os.Root
	options Options
	result  Collection
	seen    map[string]bool
}

func Collect(folder string, options Options) (Collection, error) {
	if options.Location == nil || options.Year < 1970 || options.Year > 2200 {
		return Collection{}, ErrInput
	}
	info, err := os.Stat(folder)
	if err != nil || !info.IsDir() {
		return Collection{}, ErrRoot
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return Collection{}, ErrRoot
	}
	defer root.Close()

	c := &collector{root: root, options: options, seen: map[string]bool{}}
	c.result.Manifest = Manifest{
		Version: ManifestVersion,
		Note:    "Files read by omamori forensics. Paths are relative to the evidence folder. Each hash is the SHA-256 of the whole file.",
		Entries: []Entry{}, Skipped: []string{},
	}
	for _, current := range patterns {
		for _, name := range c.expand(current.glob) {
			if c.seen[name] {
				continue
			}
			c.seen[name] = true
			if err := c.file(name, current); err != nil {
				return Collection{}, err
			}
		}
	}
	for _, snapshot := range []struct{ file, kind string }{{options.Processes, KindProcesses}, {options.Sockets, KindSockets}} {
		if snapshot.file == "" {
			continue
		}
		if err := c.snapshot(snapshot.file, snapshot.kind); err != nil {
			return Collection{}, err
		}
	}

	event.Sort(c.result.Events)
	sort.Strings(c.result.Manifest.Skipped)

	return c.result, nil
}

func (c *collector) expand(glob string) []string {
	names := []string{""}
	for _, part := range strings.Split(glob, "/") {
		var next []string
		for _, base := range names {
			if !strings.Contains(part, "*") {
				next = append(next, path.Join(base, part))
				continue
			}
			directory, err := c.root.Open(orDot(base))
			if err != nil {
				continue
			}
			entries, _ := directory.ReadDir(maxMatches + 1)
			directory.Close()
			if len(entries) > maxMatches {
				c.skip(base, "the folder has too many entries, only some were looked at")
				entries = entries[:maxMatches]
			}
			for _, entry := range entries {
				if matched, _ := path.Match(part, entry.Name()); matched {
					next = append(next, path.Join(base, entry.Name()))
				}
			}
		}
		names = next
	}
	sort.Strings(names)

	return names
}

func orDot(name string) string {
	if name == "" {
		return "."
	}

	return name
}

func (c *collector) skip(name, reason string) {
	c.result.Manifest.Skipped = append(c.result.Manifest.Skipped, name+": "+reason)
}

func (c *collector) file(name string, found pattern) error {
	info, err := c.root.Lstat(name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			c.skip(name, "cannot be looked at")
		}

		return nil
	}
	switch {
	case info.IsDir():
		return nil
	case info.Mode()&fs.ModeSymlink != 0:
		c.link(name, found, info)

		return nil
	case !info.Mode().IsRegular():
		c.skip(name, "not a normal file")

		return nil
	}

	// The file is opened without following a link, and looked at again after it is open, so that a file
	// that is swapped between the two looks is not read by mistake.
	file, err := c.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		c.skip(name, "cannot be opened")

		return nil
	}
	defer file.Close()
	if info, err = file.Stat(); err != nil || !info.Mode().IsRegular() {
		c.skip(name, "not a normal file")

		return nil
	}

	return c.read(file, info, name, found)
}

// link notes a link without following it. A shell history that is a link to /dev/null is a known way to
// leave no history, so the link itself becomes an event.
func (c *collector) link(name string, found pattern, info fs.FileInfo) {
	target, err := c.root.Readlink(name)
	if err != nil {
		target = ""
	}
	c.skip(name, "a link, not followed")
	if found.kind == KindHistory {
		c.add(found.kind, name, 0, info.ModTime(), TimeFileChange, map[string]string{
			event.Action: "history_link", event.User: owner(name), "target": target,
		})
	}
}

func (c *collector) read(reader io.Reader, info fs.FileInfo, name string, found pattern) error {
	if len(c.result.Manifest.Entries) >= maxEntries {
		return ErrTooBig
	}
	hasher := sha256.New()
	tee := io.TeeReader(reader, hasher)
	entry := Entry{Path: name, Kind: found.kind, Mode: info.Mode().String(), Modified: info.ModTime().UTC().Format(time.RFC3339)}
	before := len(c.result.Events)

	if found.kind == KindLog {
		events, stats, err := intake.Parse(tee, name, intake.Options{Year: c.options.Year, Location: c.options.Location, Format: found.format})
		switch {
		case errors.Is(err, intake.ErrTooBig):
			return ErrTooBig
		case err != nil:
			entry.Note = "could not be read as a log"
		default:
			c.result.Events = append(c.result.Events, events...)
			c.result.Files = append(c.result.Files, stats)
		}
	} else {
		data, err := io.ReadAll(io.LimitReader(tee, maxArtifactBytes+1))
		if err != nil {
			entry.Note = "could not be read to its end"
		}
		if len(data) > maxArtifactBytes {
			data = data[:maxArtifactBytes]
			entry.Note = fmt.Sprintf("only the first %d bytes were looked at", maxArtifactBytes)
		}
		stats := intake.Stats{File: name, Format: found.kind, Sources: []string{Source}}
		c.parse(found.kind, name, data, info.ModTime(), &stats)
		stats.Events = len(c.result.Events) - before
		c.result.Files = append(c.result.Files, stats)
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		entry.Note = "could not be read to its end"
	}
	if len(c.result.Events) > maxEvents {
		return ErrTooBig
	}

	entry.Size = info.Size()
	entry.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	entry.Events = len(c.result.Events) - before
	c.result.Manifest.Entries = append(c.result.Manifest.Entries, entry)

	return nil
}

func (c *collector) snapshot(file, kind string) error {
	name := "snapshot:" + filepath.Base(file)
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: the snapshot file %s is not a normal file", ErrInput, filepath.Base(file))
	}
	opened, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("%w: the snapshot file %s cannot be opened", ErrInput, filepath.Base(file))
	}
	defer opened.Close()

	return c.read(opened, info, name, pattern{kind: kind})
}

func (c *collector) add(kind, name string, line int, when time.Time, timeSource string, fields map[string]string) {
	made := map[string]string{
		event.Product: "linux", event.Category: "forensics", event.Service: kind, event.Collector: Source, TimeField: timeSource,
	}
	for field, value := range fields {
		if value = tidy(value, maxValueRunes); value != "" {
			made[field] = value
		}
	}
	ref := name
	if line > 0 {
		ref = fmt.Sprintf("%s:%d", name, line)
	}
	c.result.Events = append(c.result.Events, event.Event{Time: when, Source: Source, Ref: ref, Fields: made})
}

func tidy(text string, runes int) string {
	text = strings.TrimSpace(strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f || character == '\uFFFD' {
			return ' '
		}

		return character
	}, strings.ToValidUTF8(text, " ")))
	if count := 0; len(text) > runes {
		for index := range text {
			if count == runes {
				return text[:index]
			}
			count++
		}
	}

	return text
}

func owner(name string) string {
	parts := strings.Split(name, "/")
	switch {
	case parts[0] == "root":
		return "root"
	case parts[0] == "home" && len(parts) > 2:
		return tidy(parts[1], maxNameRunes)
	case len(parts) > 0:
		return tidy(parts[len(parts)-1], maxNameRunes)
	}

	return ""
}

type Difference struct {
	Path   string
	Reason string
	NotChecked bool
}

// Verify hashes the files of a manifest again and says which are different, missing or cannot be read.
// Snapshot files are outside the evidence folder and are named as not checked.
func Verify(folder string, manifestText []byte) ([]Difference, int, error) {
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestText)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Version != ManifestVersion || len(manifest.Entries) > maxEntries {
		return nil, 0, fmt.Errorf("%w: the manifest cannot be read", ErrInput)
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, 0, ErrRoot
	}
	defer root.Close()

	var differences []Difference
	checked := 0
	for _, entry := range manifest.Entries {
		if strings.HasPrefix(entry.Path, "snapshot:") {
			differences = append(differences, Difference{tidy(entry.Path, 200), "a snapshot file is outside the evidence folder and was not checked", true})
			continue
		}
		reason := verifyOne(root, entry)
		checked++
		if reason != "" {
			differences = append(differences, Difference{Path: tidy(entry.Path, 200), Reason: reason})
		}
	}

	return differences, checked, nil
}

func verifyOne(root *os.Root, entry Entry) string {
	if !fs.ValidPath(entry.Path) {
		return "the path in the manifest is not valid"
	}
	info, err := root.Lstat(entry.Path)
	if err != nil {
		return "missing"
	}
	if !info.Mode().IsRegular() {
		return "not a normal file any more"
	}
	file, err := root.OpenFile(entry.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "cannot be opened"
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "cannot be read"
	}
	if hex.EncodeToString(hasher.Sum(nil)) != entry.SHA256 {
		return "the content has changed"
	}

	return ""
}
