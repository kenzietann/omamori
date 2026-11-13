// Package intake reads log files and turns their lines into events. It only reads. A line that cannot be
// read is counted and left out, and it never stops the file, so one bad line cannot hide the others.
//
// Log text comes from outside: a user name or a URL in a log is written by whoever sent the request.
// Parsers treat every part as data. They check addresses, cut long values and refuse control characters.
package intake

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/assets"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/indicators"
	"github.com/kenzietann/omamori/internal/pcap"
)

const (
	FormatAuto     = ""
	FormatSyslog   = "syslog"
	FormatWeb      = "web"
	FormatJSON     = "json"
	FormatSuricata = "suricata"
	FormatZeek     = "zeek"
	FormatWazuh    = "wazuh"
	FormatWindows  = "windows"
	FormatPCAP     = "pcap"
)

const (
	maxLineBytes  = 64 << 10
	maxFiles      = 2000
	maxEvents     = 1_000_000
	maxValueRunes = 2048
	maxNameRunes  = 64
	sniffLines    = 20
)

var (
	ErrTooBig = errors.New("the logs hold more events than one run can take")
	// ErrTooManyFiles is for a folder with more files than one run reads. It is most often a project folder,
	// not a folder of logs.
	ErrTooManyFiles = errors.New("the folder holds more than 2000 files to read. Give the folder of the logs, not a whole project")
	ErrBadInput     = errors.New("the log cannot be read")
	ErrFormat       = errors.New("the format is not known. Use syslog, web, json, suricata, zeek, wazuh, windows or pcap")
)

// Options say how to read lines that do not say everything themselves.
type Options struct {
	Year     int
	Location *time.Location
	Format   string
	// Assets is optional: the list of your own machines.
	Assets *assets.List
	// Indicators is optional: the list of addresses, domains and hashes that are known to be bad.
	Indicators *indicators.List
}

type Stats struct {
	File      string
	Format    string
	Sources   []string
	Lines     int
	Events    int
	Blank     int
	Malformed int
}

type Result struct {
	Events  []event.Event
	Files   []Stats
	Skipped []string
}

func (options Options) valid() error {
	if options.Location == nil || options.Year < 1970 || options.Year > 2200 {
		return ErrBadInput
	}
	switch options.Format {
	case FormatAuto, FormatSyslog, FormatWeb, FormatJSON, FormatSuricata, FormatZeek, FormatWazuh, FormatWindows, FormatPCAP:
		return nil
	}

	return ErrFormat
}

func Read(paths []string, options Options) (Result, error) {
	return ReadContext(context.Background(), paths, options)
}

func ReadContext(ctx context.Context, paths []string, options Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := options.valid(); err != nil {
		return Result{}, err
	}

	var result Result
	type target struct{ path, name string }
	var targets []target
	seen := make(map[string]bool)
	addTarget := func(path, name string) error {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return ErrBadInput
		}
		if seen[absolute] {
			return nil
		}
		if len(targets) >= maxFiles {
			return ErrTooManyFiles
		}
		seen[absolute] = true
		targets = append(targets, target{absolute, name})

		return nil
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s", ErrBadInput, filepath.Base(path))
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return Result{}, fmt.Errorf("%w: %s is not a normal file", ErrBadInput, filepath.Base(path))
			}
			if err := addTarget(path, filepath.Base(path)); err != nil {
				return Result{}, err
			}
			continue
		}
		err = filepath.WalkDir(path, func(found string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return walkErr
			}
			name, _ := filepath.Rel(path, found)
			name = filepath.ToSlash(name)
			switch {
			case entry.IsDir():
				if found != path && strings.HasPrefix(entry.Name(), ".") {
					return filepath.SkipDir
				}
				if found != path && skippedFolder(found, entry.Name()) {
					result.Skipped = append(result.Skipped, name+": a folder of dependencies or a cache, not read")
					return filepath.SkipDir
				}
			case !entry.Type().IsRegular():
				result.Skipped = append(result.Skipped, name+": not a normal file")
			case strings.HasPrefix(entry.Name(), "."):
				result.Skipped = append(result.Skipped, name+": hidden file")
			case compressed(entry.Name()):
				result.Skipped = append(result.Skipped, name+": compressed files are not read yet")
			default:
				return addTarget(found, name)
			}

			return nil
		})
		if err != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			if errors.Is(err, ErrTooBig) || errors.Is(err, ErrTooManyFiles) {
				return Result{}, err
			}
			return Result{}, fmt.Errorf("%w: %s", ErrBadInput, filepath.Base(path))
		}
	}
	// Names are relative to each input, so distinct inputs can otherwise both produce "auth.log:1".
	// Add the parent for collisions, and use the absolute path when that still conflicts with any label.
	names := make(map[string]int)
	for _, current := range targets {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		names[current.name]++
	}
	ambiguous := make([]bool, len(targets))
	for index := range targets {
		current := &targets[index]
		if names[current.name] > 1 {
			ambiguous[index] = true
			current.name = filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(current.path)), filepath.Base(current.path)))
		}
	}
	clear(names)
	for _, current := range targets {
		names[current.name]++
	}
	for index := range targets {
		if ambiguous[index] && names[targets[index].name] > 1 {
			targets[index].name = filepath.ToSlash(targets[index].path)
		}
	}
	sort.SliceStable(targets, func(first, second int) bool { return targets[first].name < targets[second].name })

	for _, current := range targets {
		file, err := os.Open(current.path)
		if err != nil {
			result.Skipped = append(result.Skipped, current.name+": cannot be opened")
			continue
		}
		events, stats, err := Parse(contextReader{ctx, file}, current.name, options)
		file.Close()
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if errors.Is(err, ErrFormat) {
			result.Skipped = append(result.Skipped, current.name+": the format was not recognized")
			continue
		}
		if err != nil {
			return Result{}, err
		}
		result.Files = append(result.Files, stats)
		if result.Events = append(result.Events, events...); len(result.Events) > maxEvents {
			return Result{}, ErrTooBig
		}
	}
	options.Assets.Enrich(result.Events)
	options.Indicators.Enrich(result.Events)
	event.Sort(result.Events)

	return result, nil
}

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.context.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func readCapture(reader io.Reader, name string) ([]event.Event, Stats, error) {
	events, read, err := pcap.Read(reader, name)
	switch {
	case errors.Is(err, pcap.ErrFormat):
		return nil, Stats{}, ErrFormat
	case errors.Is(err, pcap.ErrTooBig):
		return nil, Stats{}, ErrTooBig
	case err != nil:
		return nil, Stats{}, ErrBadInput
	}
	if len(events) > maxEvents {
		return nil, Stats{}, ErrTooBig
	}
	// For a capture, a line is a packet. Packets of kinds that are not read count as blank.
	stats := Stats{File: name, Format: FormatPCAP, Lines: read.Packets + read.NoTime, Events: len(events), Blank: read.Skipped + read.NoTime, Malformed: read.Malformed}
	if len(events) > 0 {
		stats.Sources = []string{pcap.Product}
	}

	return events, stats, nil
}

func compressed(name string) bool {
	for _, suffix := range []string{".gz", ".bz2", ".xz", ".zst", ".zip"} {
		if strings.HasSuffix(strings.ToLower(name), suffix) {
			return true
		}
	}

	return false
}

type lineParser func(line string) (fields map[string]string, moment time.Time, ok bool)

func Parse(reader io.Reader, name string, options Options) ([]event.Event, Stats, error) {
	if reader == nil {
		return nil, Stats{}, ErrBadInput
	}
	if err := options.valid(); err != nil {
		return nil, Stats{}, err
	}

	buffered := bufio.NewReaderSize(reader, 128<<10)
	format := options.Format
	// A capture is binary. It is known by its first bytes, and read by its own reader.
	if head, _ := buffered.Peek(4); format == FormatPCAP || format == FormatAuto && pcap.Sniff(head) {
		return readCapture(buffered, name)
	}
	if format == FormatAuto {
		head, _ := buffered.Peek(32 << 10)
		if format = sniff(string(head), options); format == FormatAuto {
			return nil, Stats{}, ErrFormat
		}
	}

	var parse lineParser
	var parseJSON func(string) (map[string]string, time.Time, string, bool)
	switch format {
	case FormatSyslog:
		parse = newSyslogParser(options)
	case FormatWeb:
		parse = parseWebLine
	default:
		parseJSON = jsonSourceParser(options)
	}

	stats := Stats{File: name, Format: format}
	var events []event.Event
	sources := map[string]bool{}
	for {
		line, tooLong, err := readLine(buffered)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, Stats{}, ErrBadInput
		}
		if errors.Is(err, io.EOF) && line == "" && !tooLong {
			break
		}

		stats.Lines++
		switch {
		case tooLong || !clean(line):
			stats.Malformed++
		case strings.TrimSpace(line) == "":
			stats.Blank++
		default:
			var fields map[string]string
			var moment time.Time
			source, ok := format, false
			if parseJSON != nil {
				fields, moment, source, ok = parseJSON(line)
			} else {
				fields, moment, ok = parse(line)
			}
			if ok {
				sources[source] = true
				events = append(events, event.Event{Time: moment, Source: source, Ref: fmt.Sprintf("%s:%d", name, stats.Lines), Fields: fields})
				if len(events) > maxEvents {
					return nil, Stats{}, ErrTooBig
				}
			} else {
				stats.Malformed++
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	stats.Events = len(events)
	for source := range sources {
		stats.Sources = append(stats.Sources, source)
	}
	sort.Strings(stats.Sources)

	return events, stats, nil
}

func sniff(head string, options Options) string {
	lines := strings.Split(head, "\n")
	if len(lines) > sniffLines {
		lines = lines[:sniffLines]
	}

	syslog := newSyslogParser(options)
	jsonLine := jsonParser(options)
	counts := map[string]int{}
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || !clean(line) {
			continue
		}
		if _, _, ok := jsonLine(line); ok {
			counts[FormatJSON]++
		} else if _, _, ok := parseWebLine(line); ok {
			counts[FormatWeb]++
		} else if _, _, ok := syslog(line); ok {
			counts[FormatSyslog]++
		}
	}

	best, most := FormatAuto, 0
	for _, format := range []string{FormatSyslog, FormatWeb, FormatJSON} {
		if counts[format] > most {
			best, most = format, counts[format]
		}
	}

	return best
}

func readLine(reader *bufio.Reader) (line string, tooLong bool, err error) {
	var collected []byte
	for {
		part, isPrefix, readErr := reader.ReadLine()
		if len(collected)+len(part) > maxLineBytes {
			tooLong = true
		} else {
			collected = append(collected, part...)
		}
		if readErr != nil {
			return string(collected), tooLong, readErr
		}
		if !isPrefix {
			return string(collected), tooLong, nil
		}
	}
}

func clean(line string) bool {
	if !utf8.ValidString(line) {
		return false
	}
	for _, character := range line {
		if (character < 0x20 && character != '\t') || character == 0x7f {
			return false
		}
	}

	return true
}

func limit(text string, runes int) string {
	if utf8.RuneCountInString(text) <= runes {
		return text
	}

	return string([]rune(text)[:runes])
}

// These folders hold the code of other people or files that a tool made, not logs. They are skipped like the
// exposure check skips them, so that a project folder can be read for its logs.
var dependencyFolders = map[string]bool{
	"node_modules": true, "vendor": true, "__pycache__": true, "venv": true, "site-packages": true, "Pods": true,
	"SourcePackages": true, "DerivedData": true, "Carthage": true, "bower_components": true, "jspm_packages": true,
}

// skippedFolder is a dependency folder, or a folder that marks itself as a cache with the standard CACHEDIR.TAG
// file (the target folder of Rust does).
func skippedFolder(path, name string) bool {
	if dependencyFolders[name] {
		return true
	}
	info, err := os.Lstat(filepath.Join(path, "CACHEDIR.TAG"))

	return err == nil && info.Mode().IsRegular()
}
