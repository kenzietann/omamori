package forensics

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io/fs"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
)

const (
	KindLaunchd    = "launchd_plist"
	KindDiagnostic = "diagnostic_report"

	ProductLinux = "linux"
	ProductMacOS = intake.ProductMacOS

	// macMarker is a file that every macOS system has. A folder with it is read as a Mac.
	macMarker = "System/Library/CoreServices/SystemVersion.plist"
)

// macPatterns are the artifacts of macOS. /etc, /var and /tmp of a Mac are links into /private, so the real
// places are named, and no link has to be followed. Homes are in /Users, and the home of root is
// /private/var/root.
var macPatterns = []pattern{
	{"private/var/log/system.log", KindLog, intake.FormatSyslog},
	{"private/var/log/install.log", KindLog, intake.FormatMacOS},
	{"private/var/log/apache2/access_log", KindLog, intake.FormatWeb},
	{"private/etc/passwd", KindAccounts, ""},
	{"private/etc/crontab", KindCron, ""}, {"private/var/at/tabs/*", KindCron, ""},
	{"Library/LaunchDaemons/*.plist", KindLaunchd, ""}, {"Library/LaunchAgents/*.plist", KindLaunchd, ""},
	{"Users/*/Library/LaunchAgents/*.plist", KindLaunchd, ""}, {"private/var/root/Library/LaunchAgents/*.plist", KindLaunchd, ""},
	{"private/var/root/.ssh/authorized_keys", KindKeys, ""}, {"Users/*/.ssh/authorized_keys", KindKeys, ""}, {"Users/*/.ssh/authorized_keys2", KindKeys, ""},
	{"private/var/root/.zsh_history", KindHistory, ""}, {"private/var/root/.bash_history", KindHistory, ""},
	{"Users/*/.zsh_history", KindHistory, ""}, {"Users/*/.bash_history", KindHistory, ""}, {"Users/*/.zsh_sessions/*.history", KindHistory, ""},
	{"Library/Logs/DiagnosticReports/*.panic", KindDiagnostic, ""}, {"Library/Logs/DiagnosticReports/Retired/*.panic", KindDiagnostic, ""},
	{"Library/Logs/DiagnosticReports/ResetCounter-*.diag", KindDiagnostic, ""}, {"Library/Logs/DiagnosticReports/*.ips", KindDiagnostic, ""},
	{"Users/*/Library/Logs/DiagnosticReports/*.ips", KindDiagnostic, ""},
}

// macScanFolders are the places of a Mac that the file rules look at, in the same order as on Linux: the
// folders that everyone can write first, the homes last.
var macScanFolders = []string{
	"private/tmp", "private/var/tmp", "Users/Shared", "Library/LaunchDaemons", "Library/LaunchAgents", "Library/StartupItems",
	"usr/local/bin", "opt", "private/etc", "private/var/root", "Users",
}

func isMac(root interface {
	Lstat(string) (fs.FileInfo, error)
}) bool {
	info, err := root.Lstat(macMarker)

	return err == nil && info.Mode().IsRegular()
}

// launchd reads a property list of launchd: the program that it starts, and when. A LaunchDaemon runs as root
// (or as UserName), a LaunchAgent as the user who logs in. Property lists are XML or binary.
func (c *collector) launchd(name string, data []byte, modified time.Time, stats *intake.Stats) {
	stats.Lines = 1
	values, err := readPlist(data)
	if err != nil {
		stats.Malformed++
		c.add(KindLaunchd, name, 0, modified, TimeFileChange, map[string]string{
			event.Action: "launchd_item", "file": name, "label": path.Base(name), "note": "the property list could not be read",
		})
		return
	}
	runAs := ""
	switch {
	case strings.HasPrefix(name, "Library/LaunchDaemons/"):
		runAs = "root"
	case strings.HasPrefix(name, "Users/"), strings.HasPrefix(name, "private/var/root/"):
		runAs = owner(name)
	}
	if user, isText := values["UserName"].(string); isText && user != "" {
		runAs = tidy(user, maxNameRunes)
	}
	var arguments []string
	if list, isList := values["ProgramArguments"].([]any); isList {
		for _, argument := range list {
			if text, isText := argument.(string); isText {
				arguments = append(arguments, quoteArgument(text))
			}
		}
	}
	program, _ := values["Program"].(string)
	if program != "" && (len(arguments) == 0 || strings.Trim(arguments[0], `"`) != program) {
		arguments = append([]string{quoteArgument(program)}, arguments...)
	}
	label, _ := values["Label"].(string)
	if label == "" {
		label = path.Base(name)
	}
	fields := map[string]string{
		event.Action: "launchd_item", "file": name, "label": label, event.Command: strings.Join(arguments, " "), event.User: runAs,
		"agent": strconv.FormatBool(strings.Contains(name, "LaunchAgents/")),
		// The hashes of the programs it starts. A known-good entry for the item stops fitting when one changes.
		"programs": c.programs(strings.Join(arguments, " ")),
	}
	if run, isBool := values["RunAtLoad"].(bool); isBool {
		fields["run_at_load"] = strconv.FormatBool(run)
	}
	switch keep := values["KeepAlive"].(type) {
	case bool:
		fields["keep_alive"] = strconv.FormatBool(keep)
	case map[string]any:
		fields["keep_alive"] = "true"
	}
	c.add(KindLaunchd, name, 0, modified, TimeFileChange, fields)
}

func quoteArgument(text string) string {
	if strings.ContainsAny(text, " \t") {
		return strconv.Quote(text)
	}

	return text
}

const (
	maxPlistDepth   = 8
	maxPlistObjects = 20_000
)

var errPlist = errors.New("not a property list")

// readPlist reads the top dictionary of an XML or binary property list. Values are strings, bools, numbers
// (as strings), lists and dictionaries. Dates and data are left out.
func readPlist(data []byte) (map[string]any, error) {
	var value any
	var err error
	if bytes.HasPrefix(data, []byte("bplist00")) {
		value, err = readBinaryPlist(data)
	} else {
		value, err = readXMLPlist(data)
	}
	if err != nil {
		return nil, err
	}
	top, isDict := value.(map[string]any)
	if !isDict {
		return nil, errPlist
	}

	return top, nil
}

func readXMLPlist(data []byte) (any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	// A property list names its DTD. Nothing outside the file is ever loaded.
	decoder.Entity = map[string]string{}
	objects := 0
	var value func(start xml.StartElement, depth int) (any, error)
	value = func(start xml.StartElement, depth int) (any, error) {
		if objects++; depth > maxPlistDepth || objects > maxPlistObjects {
			return nil, errPlist
		}
		switch start.Name.Local {
		case "dict":
			result := map[string]any{}
			key := ""
			for {
				token, err := decoder.Token()
				if err != nil {
					return nil, errPlist
				}
				switch token := token.(type) {
				case xml.EndElement:
					return result, nil
				case xml.StartElement:
					if token.Name.Local == "key" {
						var text string
						if err := decoder.DecodeElement(&text, &token); err != nil {
							return nil, errPlist
						}
						key = text
						continue
					}
					item, err := value(token, depth+1)
					if err != nil {
						return nil, err
					}
					result[key] = item
				}
			}
		case "array":
			var result []any
			for {
				token, err := decoder.Token()
				if err != nil {
					return nil, errPlist
				}
				switch token := token.(type) {
				case xml.EndElement:
					return result, nil
				case xml.StartElement:
					item, err := value(token, depth+1)
					if err != nil {
						return nil, err
					}
					result = append(result, item)
				}
			}
		case "true", "false":
			if err := decoder.Skip(); err != nil {
				return nil, errPlist
			}
			return start.Name.Local == "true", nil
		default:
			var text string
			if err := decoder.DecodeElement(&text, &start); err != nil {
				return nil, errPlist
			}
			if start.Name.Local == "data" || start.Name.Local == "date" {
				return nil, nil
			}
			return text, nil
		}
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, errPlist
		}
		if start, isStart := token.(xml.StartElement); isStart && start.Name.Local != "plist" {
			return value(start, 0)
		}
	}
}

// readBinaryPlist reads the format "bplist00": a table of offsets at the end points to the objects, and lists
// and dictionaries refer to other objects by their number. Every number is checked against the size of the
// file, and a list that refers back to itself stops at the limit of depth.
func readBinaryPlist(data []byte) (any, error) {
	if len(data) < 8+32 {
		return nil, errPlist
	}
	trailer := data[len(data)-32:]
	offsetSize, refSize := int(trailer[6]), int(trailer[7])
	count, top, table := binary.BigEndian.Uint64(trailer[8:]), binary.BigEndian.Uint64(trailer[16:]), binary.BigEndian.Uint64(trailer[24:])
	end := uint64(len(data) - 32)
	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 || count == 0 || count > maxPlistObjects || top >= count ||
		table >= end || count*uint64(offsetSize) > end-table {
		return nil, errPlist
	}
	number := func(at uint64, size int) (uint64, bool) {
		if at+uint64(size) > end {
			return 0, false
		}
		var result uint64
		for _, part := range data[at : at+uint64(size)] {
			result = result<<8 | uint64(part)
		}
		return result, true
	}
	objects := 0
	var object func(index uint64, depth int) (any, error)
	object = func(index uint64, depth int) (any, error) {
		if objects++; index >= count || depth > maxPlistDepth || objects > maxPlistObjects {
			return nil, errPlist
		}
		at, ok := number(table+index*uint64(offsetSize), offsetSize)
		if !ok || at >= table {
			return nil, errPlist
		}
		marker := data[at]
		kind, length := marker>>4, uint64(marker&0x0f)
		at++
		if length == 0x0f && (kind == 0x5 || kind == 0x6 || kind == 0xa || kind == 0xd) {
			if at >= end || data[at]>>4 != 0x1 {
				return nil, errPlist
			}
			size := 1 << (data[at] & 0x0f)
			if size > 8 {
				return nil, errPlist
			}
			if length, ok = number(at+1, size); !ok || length > end {
				return nil, errPlist
			}
			at += 1 + uint64(size)
		}
		switch kind {
		case 0x0:
			switch marker {
			case 0x08:
				return false, nil
			case 0x09:
				return true, nil
			}
			return nil, nil
		case 0x1:
			size := 1 << length
			if size > 8 {
				return nil, errPlist
			}
			value, ok := number(at, size)
			if !ok {
				return nil, errPlist
			}
			if size == 8 {
				return strconv.FormatInt(int64(value), 10), nil
			}
			return strconv.FormatUint(value, 10), nil
		case 0x2:
			size := 1 << length
			value, ok := number(at, size)
			if !ok || (size != 4 && size != 8) {
				return nil, errPlist
			}
			if size == 4 {
				return strconv.FormatFloat(float64(math.Float32frombits(uint32(value))), 'g', -1, 32), nil
			}
			return strconv.FormatFloat(math.Float64frombits(value), 'g', -1, 64), nil
		case 0x5:
			if at+length > end {
				return nil, errPlist
			}
			return string(data[at : at+length]), nil
		case 0x6:
			if length > end || at+2*length > end {
				return nil, errPlist
			}
			units := make([]uint16, length)
			for index := range units {
				units[index] = binary.BigEndian.Uint16(data[at+2*uint64(index):])
			}
			return string(utf16.Decode(units)), nil
		case 0xa, 0xd:
			pairs := uint64(1)
			if kind == 0xd {
				pairs = 2
			}
			if length > maxPlistObjects || at+pairs*length*uint64(refSize) > end {
				return nil, errPlist
			}
			reference := func(position uint64) (any, error) {
				target, _ := number(at+position*uint64(refSize), refSize)
				return object(target, depth+1)
			}
			if kind == 0xa {
				result := make([]any, 0, length)
				for index := uint64(0); index < length; index++ {
					item, err := reference(index)
					if err != nil {
						return nil, err
					}
					result = append(result, item)
				}
				return result, nil
			}
			result := map[string]any{}
			for index := uint64(0); index < length; index++ {
				key, err := reference(index)
				if err != nil {
					return nil, err
				}
				item, err := reference(length + index)
				if err != nil {
					return nil, err
				}
				if text, isText := key.(string); isText {
					result[text] = item
				}
			}
			return result, nil
		}

		// Dates, data, UIDs and sets are not needed for launchd.
		return nil, nil
	}

	return object(top, 0)
}

type reportHeader struct {
	BugType   string `json:"bug_type"`
	Timestamp string `json:"timestamp"`
	Name      string `json:"name"`
	AppName   string `json:"app_name"`
	OSVersion string `json:"os_version"`
	Incident  string `json:"incident_id"`
}

var (
	panicString = regexp.MustCompile(`"(?:macOSPanicString|panicString)"\s*:\s*"((?:[^"\\]|\\.){1,1000})`)
	panicText   = regexp.MustCompile(`panic\(cpu [^\n"\\]{1,400}`)
	bootFaults  = regexp.MustCompile(`(?m)^Boot faults:[ \t]*(.*)$`)
	bootFailure = regexp.MustCompile(`(?m)^Boot failure count:[ \t]*(\d+)`)
	resetCount  = regexp.MustCompile(`(?m)^Reset count:[ \t]*(\d+)`)
)

// diagnostic reads a report of the crash reporter: a kernel panic, a reset of the Mac, a program that crashed
// or a process that was stopped for memory. The first line of each report is a JSON header with the kind
// (bug_type) and the time. The rest is the report, as JSON or as text.
func (c *collector) diagnostic(name string, data []byte, modified time.Time, stats *intake.Stats) {
	headerLine, body, _ := bytes.Cut(data, []byte("\n"))
	stats.Lines = bytes.Count(data, []byte("\n")) + 1
	var header reportHeader
	if err := json.Unmarshal(headerLine, &header); err != nil {
		// Older reports have no header; a panic is still known by its text.
		header, body = reportHeader{}, data
	}
	when, source := modified, TimeFileChange
	if parsed, err := reportTime(header.Timestamp); err == nil {
		when, source = parsed, TimeRecorded
	}
	base := path.Base(name)
	process := header.AppName
	if process == "" {
		process = header.Name
	}
	fields := map[string]string{
		"file": name, "bug_type": header.BugType, "os_version": header.OSVersion, "incident": header.Incident, event.Process: process,
	}
	switch {
	case strings.HasSuffix(base, ".panic") || header.BugType == "210" || header.BugType == "110":
		fields[event.Action] = "kernel_panic"
		if parts := panicString.FindSubmatch(body); parts != nil {
			var text string
			if json.Unmarshal(append(append([]byte(`"`), parts[1]...), '"'), &text) == nil {
				fields["panic"], _, _ = strings.Cut(strings.TrimSpace(text), "\n")
			}
		}
		if fields["panic"] == "" {
			fields["panic"] = string(panicText.Find(body))
		}
	case header.BugType == "115" || strings.HasPrefix(base, "ResetCounter-"):
		fields[event.Action] = "reset"
		if parts := bootFaults.FindSubmatch(body); parts != nil {
			fields["boot_faults"] = string(parts[1])
		}
		if parts := bootFailure.FindSubmatch(body); parts != nil {
			fields["boot_failure_count"] = string(parts[1])
		}
		if parts := resetCount.FindSubmatch(body); parts != nil {
			fields["reset_count"] = string(parts[1])
		}
		fields["reset_kind"] = resetKind(fields["boot_faults"])
	case header.BugType == "309" || header.BugType == "109":
		fields[event.Action] = "crash"
		var report struct {
			ProcPath  string `json:"procPath"`
			Exception struct {
				Type   string `json:"type"`
				Signal string `json:"signal"`
			} `json:"exception"`
		}
		if json.Unmarshal(body, &report) == nil {
			fields["exception"] = strings.TrimSpace(report.Exception.Type + " " + report.Exception.Signal)
			fields["path"] = report.ProcPath
		}
	case header.BugType == "298" || strings.HasPrefix(base, "JetsamEvent-"):
		fields[event.Action] = "jetsam"
	default:
		fields[event.Action] = "diagnostic_report"
	}
	c.add(KindDiagnostic, name, 0, when, source, fields)
}

// resetKind says what the boot faults of a ResetCounter report point to. btn_rst and btn_seq_reset are a reset
// with the power button (held down, or the key sequence); wdog is the watchdog, which resets a Mac that hangs.
func resetKind(faults string) string {
	switch {
	case faults == "":
		return "unknown"
	case strings.Contains(faults, "wdog") || strings.Contains(faults, "watchdog"):
		return "watchdog"
	case strings.Contains(faults, "btn_rst") || strings.Contains(faults, "btn_seq_reset"):
		return "power_button"
	case strings.Contains(faults, "panic"):
		return "panic"
	}

	return "other"
}

func reportTime(stamp string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999 -0700", "2006-01-02 15:04:05 -0700"} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(stamp)); err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, errPlist
}
