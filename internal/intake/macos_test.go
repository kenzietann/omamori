package intake

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readMacFixture(t *testing.T, name, format string) ([]map[string]string, []time.Time, Stats) {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "testdata", "fixtures", "macos", name))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	events, stats, err := Parse(file, name, Options{Year: 2026, Location: tokyo, Format: format})
	if err != nil {
		t.Fatal(err)
	}
	var fields []map[string]string
	var times []time.Time
	for _, current := range events {
		fields = append(fields, current.Fields)
		times = append(times, current.Time)
	}

	return fields, times, stats
}

func TestMacOSStylesOfLogShow(t *testing.T) {
	for _, format := range []string{FormatMacOS, FormatAuto} {
		t.Run("syslog style "+format, func(t *testing.T) {
			fields, times, stats := readMacFixture(t, "unified-syslog.log", format)
			if stats.Format != FormatMacOS || stats.Events != 6 || stats.Malformed != 0 {
				t.Fatalf("stats = %+v", stats)
			}
			want := []map[string]string{
				{"product": "macos", "service": "sshd", "action": "login", "outcome": "failure", "user": "admin", "src_ip": "203.0.113.50", "host": "mac-mini", "pid": "2201"},
				{"action": "login", "outcome": "failure"},
				{"action": "login", "outcome": "success", "user": "aiko", "src_ip": "198.51.100.7"},
				{"service": "sudo", "action": "sudo", "user": "aiko", "target_user": "root", "command": "/bin/launchctl load /Library/LaunchDaemons/com.example.helper.plist"},
				{"service": "kernel", "action": "shutdown_cause", "cause": "-128", "subsystem": "com.apple.kernel", "log_category": "smc", "message": "Previous shutdown cause: -128"},
				{"process": "ContinuityCaptureAgent", "subsystem": "com.apple.CMContinuityCapture", "message": "RapportDevices : ("},
			}
			for index, expected := range want {
				for key, value := range expected {
					if fields[index][key] != value {
						t.Errorf("event %d %s = %q, want %q", index, key, fields[index][key], value)
					}
				}
			}
			if got := times[0].UTC().Format(time.RFC3339Nano); got != "2026-11-16T00:12:01.104512Z" {
				t.Errorf("time = %s", got)
			}
		})
	}

	t.Run("ndjson", func(t *testing.T) {
		fields, times, stats := readMacFixture(t, "unified.ndjson", FormatAuto)
		if stats.Format != FormatMacOS || stats.Events != 3 || stats.Malformed != 0 || stats.Blank != 1 {
			t.Fatalf("stats = %+v", stats)
		}
		if fields[0]["action"] != "login" || fields[0]["user"] != "root" || fields[0]["process"] != "sshd-session" || fields[0]["service"] != "sshd" {
			t.Errorf("first = %v", fields[0])
		}
		if fields[1]["action"] != "shutdown_cause" || fields[1]["cause"] != "5" {
			t.Errorf("second = %v", fields[1])
		}
		if fields[2]["log_level"] != "Error" || fields[2]["log_category"] != "Server" || fields[2]["uid"] != "0" {
			t.Errorf("third = %v", fields[2])
		}
		if got := times[2].UTC().Format(time.RFC3339Nano); got != "2026-11-16T00:16:00.5Z" {
			t.Errorf("time = %s", got)
		}
	})

	t.Run("default style", func(t *testing.T) {
		fields, _, stats := readMacFixture(t, "unified-default.log", FormatAuto)
		if stats.Format != FormatMacOS || stats.Events != 2 || stats.Malformed != 0 {
			t.Fatalf("stats = %+v", stats)
		}
		if fields[0]["action"] != "sudo" || fields[0]["outcome"] != "failure" || fields[0]["log_level"] != "Default" {
			t.Errorf("sudo = %v", fields[0])
		}
		if fields[1]["process"] != "Claude Helper" || fields[1]["subsystem"] != "com.apple.xpc" || fields[1]["message"] != "activating connection" {
			t.Errorf("helper = %v", fields[1])
		}
	})

	t.Run("compact style has the zone of the run", func(t *testing.T) {
		fields, times, stats := readMacFixture(t, "unified-compact.log", FormatAuto)
		if stats.Format != FormatMacOS || stats.Events != 2 || stats.Malformed != 0 {
			t.Fatalf("stats = %+v", stats)
		}
		if fields[0]["action"] != "login" || fields[0]["user"] != "aiko" || fields[1]["process"] != "mDNSResponder" || fields[1]["log_level"] != "Error" {
			t.Errorf("fields = %v", fields)
		}
		if got := times[0].UTC().Format(time.RFC3339Nano); got != "2026-11-16T00:12:01.104Z" {
			t.Errorf("time = %s", got)
		}
	})
}

func TestMacOSInstallLogAndRefusals(t *testing.T) {
	parse := newMacOSParser(Options{Year: 2026, Location: time.UTC})
	fields, moment, ok := parse("2026-02-02 21:52:43-08 localhost Installer Progress[57]: Progress UI App Starting")
	if !ok || fields["process"] != "Installer Progress" || moment.UTC().Format(time.RFC3339) != "2026-02-03T05:52:43Z" {
		t.Fatalf("install.log line = %v %v %v", fields, moment, ok)
	}
	// sudo -n without a cached password runs nothing: it is a refusal, not a sudo that worked.
	fields, _, ok = parse("2026-11-16 16:22:01.000000+0900  mac-mini sudo[901]: kenzie : a password is required ; PWD=/Users/kenzie ; USER=root ; COMMAND=/usr/bin/true")
	if !ok || fields["action"] != "sudo" || fields["outcome"] != "failure" || fields["reason"] != "a password is required" {
		t.Errorf("sudo -n = %v", fields)
	}
	for _, line := range []string{
		"Nov 16 00:08:38 keng syslogd[566]: ASL Sender Statistics",
		`{"timestamp":"2026-11-16T00:00:00Z","message":"another JSON log"}`,
		`{"timestamp":"2026-11-16 09:00:00+0900","eventMessage":"no process"}`,
		"2026-13-40 09:00:00.1+0900  host p[1]: a date that does not exist",
	} {
		if _, _, ok := parse(line); ok {
			t.Errorf("read %q", line)
		}
	}
}
