package intake

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

const wazuhLoginFixture = `{"timestamp":"2026-11-12T09:00:00+0900","rule":{"id":"60122","level":5,"description":"Authentication failure"},"agent":{"id":"007","name":"forwarder"},"decoder":{"name":"windows_eventchannel"},"action":"invented","outcome":"success","user":"wrong-user","data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","channel":"Security","eventID":"4625","computer":"workstation-1","systemTime":"2026-11-11T12:00:00.1234567Z"},"eventdata":{"targetUserName":"aiko","targetDomainName":"EXAMPLE","subjectUserName":"SYSTEM","ipAddress":"::ffff:203.0.113.9","ipPort":"49152","logonType":"3","authenticationPackageName":"NTLM","status":"0xc000006d"}}}}`

const wazuhSysmonFixture = `{"timestamp":"2026-11-12T09:00:00+0900","rule":{"id":"61603","level":3,"description":"Process created"},"agent":{"id":"007","name":"forwarder"},"decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","channel":"Microsoft-Windows-Sysmon/Operational","eventID":"1","computer":"workstation-1","systemTime":"2026-11-11T12:00:01Z"},"eventdata":{"utcTime":"2026-11-11 12:00:00.123","image":"C:\\Windows\\System32\\notepad.exe","commandLine":"notepad.exe notes.txt","user":"EXAMPLE\\aiko","processId":"1234","processGuid":"test-guid","parentImage":"C:\\Windows\\explorer.exe","parentCommandLine":"explorer.exe","parentProcessId":"1230"}}}}`

const winlogNetworkFixture = `{"@timestamp":"2026-11-11T12:00:02Z","winlog":{"event_id":3,"provider_name":"Microsoft-Windows-Sysmon","channel":"Microsoft-Windows-Sysmon/Operational","computer_name":"workstation-1","event_data":{"UtcTime":"2026-11-11 12:00:00.250","Image":"C:\\Windows\\System32\\notepad.exe","User":"EXAMPLE\\aiko","SourceIp":"203.0.113.9","DestinationIp":"2001:db8::1","SourcePort":49152,"DestinationPort":"443","Protocol":"TCP","ProcessId":"1234"}}}`

const nxlogLoginFixture = `{"EventTime":"2026-11-11T21:00:00+09:00","EventID":4624,"SourceName":"Microsoft-Windows-Security-Auditing","Channel":"Security","Hostname":"workstation-2","SourceModuleType":"im_msvistalog","TargetUserName":"mei","SubjectUserName":"SYSTEM","IpAddress":"198.51.100.8","IpPort":"12345","LogonType":10,"AuthenticationPackageName":"Negotiate","ProcessName":"C:\\Windows\\System32\\svchost.exe","outcome":"failure"}`

func TestHostJSONSourceMappings(t *testing.T) {
	cases := []struct {
		name, format, line, source, moment string
		fields                             map[string]string
	}{
		{"wazuh generic alert", FormatWazuh,
			`{"timestamp":"2026-11-11T21:00:00+0900","rule":{"id":"5715","level":3,"description":"Successful login"},"agent":{"id":"004","name":"linux-1"},"decoder":{"name":"sshd"},"data":{"srcip":"203.0.113.8","dstuser":"aiko"},"outcome":"success","full_log":"untrusted ordinary message"}`,
			"wazuh", "2026-11-11T12:00:00Z", map[string]string{"product": "wazuh", "service": "sshd", "action": "alert", "category": "alert", "host": "linux-1", "src_ip": "203.0.113.8", "user": "aiko", "wazuh_rule_id": "5715", "wazuh_level": "3", "signature": "Successful login", "outcome": "", "raw.outcome": "success"}},
		{"wazuh security failure", FormatWazuh, wazuhLoginFixture, "wazuh", "2026-11-11T12:00:00.1234567Z",
			map[string]string{"product": "windows", "service": "security", "category": "authentication", "action": "login", "outcome": "failure", "user": `EXAMPLE\aiko`, "target_user": "aiko", "user_domain": "EXAMPLE", "host": "workstation-1", "src_ip": "203.0.113.9", "src_port": "49152", "logon_type": "3", "auth_method": "NTLM", "auth_status": "0xc000006d", "event_id": "4625", "raw.outcome": "success", "raw.user": "wrong-user"}},
		{"wazuh sysmon process", FormatWazuh, wazuhSysmonFixture, "wazuh", "2026-11-11T12:00:00.123Z",
			map[string]string{"product": "windows", "service": "sysmon", "category": "process_creation", "action": "process_create", "event_id": "1", "process": `C:\Windows\System32\notepad.exe`, "command": "notepad.exe notes.txt", "user": `EXAMPLE\aiko`, "process_id": "1234", "parent_process_id": "1230", "parent_process": `C:\Windows\explorer.exe`, "outcome": ""}},
		{"winlogbeat sysmon network", FormatWindows, winlogNetworkFixture, "windows", "2026-11-11T12:00:00.25Z",
			map[string]string{"product": "windows", "service": "sysmon", "category": "network_connection", "action": "network_connect", "event_id": "3", "host": "workstation-1", "src_ip": "203.0.113.9", "dst_ip": "2001:db8::1", "src_port": "49152", "dst_port": "443", "protocol": "tcp", "outcome": ""}},
		{"nxlog security success", FormatWindows, nxlogLoginFixture, "windows", "2026-11-11T12:00:00Z",
			map[string]string{"product": "windows", "service": "security", "action": "login", "outcome": "success", "event_id": "4624", "user": "mei", "src_ip": "198.51.100.8", "src_port": "12345", "logon_type": "10", "auth_method": "Negotiate", "raw.outcome": "failure"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []string{test.format, FormatJSON, FormatAuto} {
				got, stats := parseOne(t, format, test.line)
				if stats.Events != 1 || stats.Malformed != 0 || got.Source != test.source || got.Time.UTC().Format(time.RFC3339Nano) != test.moment {
					t.Fatalf("%s: source %q, time %s, stats %#v", format, got.Source, got.Time.Format(time.RFC3339Nano), stats)
				}
				wantFields(t, got, test.fields)
				if got.Fields["collector"] != test.source {
					t.Error("the original collector label was lost")
				}
			}
		})
	}
}

func TestHostIDsNeedTheRightProviderAndChannel(t *testing.T) {
	cases := []struct{ name, line, service string }{
		{"security id from another provider", strings.Replace(nxlogLoginFixture, "Microsoft-Windows-Security-Auditing", "Unrelated-Provider", 1), "eventlog"},
		{"security id on another channel", strings.Replace(nxlogLoginFixture, `"Channel":"Security"`, `"Channel":"Application"`, 1), "eventlog"},
		{"sysmon id from another provider", strings.Replace(winlogNetworkFixture, `"provider_name":"Microsoft-Windows-Sysmon"`, `"provider_name":"Unrelated-Provider"`, 1), "eventlog"},
		{"sysmon id on another channel", strings.Replace(winlogNetworkFixture, `"channel":"Microsoft-Windows-Sysmon/Operational"`, `"channel":"Application"`, 1), "eventlog"},
		{"unknown security id", strings.Replace(nxlogLoginFixture, `"EventID":4624`, `"EventID":4648`, 1), "security"},
		{"unknown sysmon id", strings.Replace(winlogNetworkFixture, `"event_id":3`, `"event_id":99`, 1), "sysmon"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, stats := parseOne(t, FormatWindows, test.line)
			if stats.Events != 1 || got.Fields["service"] != test.service {
				t.Fatalf("metadata missing: %#v, %#v", got, stats)
			}
			for _, field := range []string{"action", "outcome", "user", "src_ip", "dst_ip", "command", "process"} {
				if got.Fields[field] != "" {
					t.Errorf("%s was inferred without the known provider/channel/event combination: %q", field, got.Fields[field])
				}
			}
		})
	}
}

func TestHostMalformedSchemasAndTimesAreRefused(t *testing.T) {
	cases := []struct{ format, line string }{
		{FormatWindows, `{"timestamp":"2026-11-11T12:00:00Z","EventID":4624,"TargetUserName":"fake"}`},
		{FormatWindows, strings.Replace(nxlogLoginFixture, `"EventID":4624`, `"EventID":true`, 1)},
		{FormatWindows, strings.Replace(nxlogLoginFixture, `"EventID":4624`, `"EventID":65536`, 1)},
		{FormatWindows, strings.Replace(nxlogLoginFixture, `"SourceName":"Microsoft-Windows-Security-Auditing"`, `"SourceName":true`, 1)},
		{FormatWindows, strings.Replace(nxlogLoginFixture, `"Channel":"Security"`, `"Channel":42`, 1)},
		{FormatWindows, strings.Replace(nxlogLoginFixture, `"EventTime":"2026-11-11T21:00:00+09:00"`, `"EventTime":{}`, 1)},
		{FormatWazuh, strings.Replace(wazuhLoginFixture, `"level":5`, `"level":false`, 1)},
		{FormatWazuh, strings.Replace(wazuhLoginFixture, `"id":"60122"`, `"id":true`, 1)},
		{FormatWazuh, strings.Replace(wazuhLoginFixture, `"systemTime":"2026-11-11T12:00:00.1234567Z"`, `"systemTime":"invalid"`, 1)},
		{FormatWazuh, strings.Replace(wazuhSysmonFixture, `"utcTime":"2026-11-11 12:00:00.123"`, `"utcTime":"invalid"`, 1)},
		{FormatWazuh, nxlogLoginFixture},
		{FormatWindows, wazuhLoginFixture},
	}
	for index, test := range cases {
		got, stats := parseOne(t, test.format, test.line)
		if stats.Events != 0 || stats.Malformed != 1 || !got.Time.IsZero() {
			t.Errorf("case %d accepted a malformed or wrong-source record: %#v, %#v", index, got, stats)
		}
	}
}

func TestHostTextFieldsAreNotCoercedAndAccountsKeepTheirDomain(t *testing.T) {
	line := strings.Replace(nxlogLoginFixture, `"TargetUserName":"mei"`, `"TargetUserName":true`, 1)
	line = strings.Replace(line, `"Hostname":"workstation-2"`, `"Hostname":42`, 1)
	got, stats := parseOne(t, FormatWindows, line)
	if stats.Events != 1 || got.Fields["user"] != "" || got.Fields["host"] != "" {
		t.Fatalf("malformed text became an identity: %#v, %#v", got, stats)
	}
	for _, malformed := range []string{`"a\nb"`, `"a\tb"`, `"` + strings.Repeat("x", maxValueRunes+1) + `"`} {
		line := strings.Replace(nxlogLoginFixture, `"TargetUserName":"mei"`, `"TargetUserName":`+malformed, 1)
		got, stats := parseOne(t, FormatWindows, line)
		if stats.Events != 1 || got.Fields["user"] != "" || got.Fields["target_user"] != "" {
			t.Fatal("a malformed identity was repaired into a different, usable account")
		}
	}
	for _, malformed := range []string{`true`, `"A\nB"`} {
		line := strings.Replace(wazuhLoginFixture, `"targetDomainName":"EXAMPLE"`, `"targetDomainName":`+malformed, 1)
		got, stats := parseOne(t, FormatWazuh, line)
		if stats.Events != 1 || got.Fields["user"] != "" {
			t.Fatal("a malformed domain was silently discarded from the account identity")
		}
	}
	first, _ := parseOne(t, FormatWazuh, wazuhLoginFixture)
	second, _ := parseOne(t, FormatWazuh, strings.Replace(wazuhLoginFixture, `"targetDomainName":"EXAMPLE"`, `"targetDomainName":"OTHER"`, 1))
	process, _ := parseOne(t, FormatWazuh, wazuhSysmonFixture)
	if first.Fields["user"] == second.Fields["user"] || first.Fields["user"] != process.Fields["user"] {
		t.Fatalf("account identity lost its domain: %q, %q, %q", first.Fields["user"], second.Fields["user"], process.Fields["user"])
	}
}

func TestHostInvalidAddressesAndPortsStayOutOfCanonicalFields(t *testing.T) {
	line := strings.ReplaceAll(winlogNetworkFixture, `"SourceIp":"203.0.113.9"`, `"SourceIp":"not-an-address"`)
	line = strings.ReplaceAll(line, `"DestinationIp":"2001:db8::1"`, `"DestinationIp":"fe80::1%eth0"`)
	line = strings.ReplaceAll(line, `"SourcePort":49152`, `"SourcePort":-1`)
	line = strings.ReplaceAll(line, `"DestinationPort":"443"`, `"DestinationPort":"70000"`)
	got, stats := parseOne(t, FormatWindows, line)
	if stats.Events != 1 {
		t.Fatal("invalid optional network fields should not hide the event")
	}
	for _, name := range []string{"src_ip", "dst_ip", "src_port", "dst_port"} {
		if got.Fields[name] != "" {
			t.Errorf("invalid %s was kept: %s", name, got.Fields[name])
		}
	}
	if got.Fields["raw.winlog.event_data.SourceIp"] != "not-an-address" {
		t.Fatal("the original network value was not kept as raw evidence")
	}
	missing := strings.ReplaceAll(nxlogLoginFixture, `"IpAddress":"198.51.100.8"`, `"IpAddress":"-"`)
	got, _ = parseOne(t, FormatWindows, missing)
	if got.Fields["src_ip"] != "" || got.Fields["outcome"] != "success" {
		t.Fatal("a missing source address changed the explicit security event outcome")
	}
}

func TestHostNormalizationClearsConflictingCanonicalValues(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(winlogNetworkFixture))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{"action": "login", "outcome": "success", "host": "fake", "user": "fake", "src_ip": "1.1.1.1", "command": "fake", "category": "authentication"}
	if _, ok := normalizeHostJSON(object, fields); !ok {
		t.Fatal("fixture was not recognized")
	}
	if fields["action"] != "network_connect" || fields["outcome"] != "" || fields["command"] != "" || fields["host"] != "workstation-1" {
		t.Fatalf("canonical values leaked through normalization: %#v", fields)
	}
}

func FuzzHostJSON(f *testing.F) {
	for _, line := range []string{wazuhLoginFixture, wazuhSysmonFixture, winlogNetworkFixture, nxlogLoginFixture, `{}`, `{"winlog":[]}`} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > maxLineBytes*2 {
			t.Skip()
		}
		for _, format := range []string{FormatWazuh, FormatWindows} {
			events, _, err := Parse(strings.NewReader(line), "synthetic.json", Options{Year: 2026, Location: time.UTC, Format: format})
			if err != nil {
				continue
			}
			for _, current := range events {
				if current.Source != format || current.Time.IsZero() || len(current.Fields) > maxJSONFields {
					t.Fatalf("invalid normalized event: %#v", current)
				}
				if current.Fields[event.Action] == "login" {
					if current.Fields[event.Service] != "security" || (current.Fields["event_id"] != "4624" && current.Fields["event_id"] != "4625") {
						t.Fatal("login was inferred without a supported Security event")
					}
				}
			}
		}
	})
}
