package intake

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

var (
	tokyo   = time.FixedZone("JST", 9*3600)
	options = Options{Year: 2026, Location: tokyo}
)

func parseOne(t *testing.T, format, line string) (event.Event, Stats) {
	t.Helper()
	chosen := options
	chosen.Format = format
	events, stats, err := Parse(strings.NewReader(line+"\n"), "x.log", chosen)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		return event.Event{}, stats
	}

	return events[0], stats
}

func wantFields(t *testing.T, got event.Event, want map[string]string) {
	t.Helper()
	for name, value := range want {
		if got.Fields[name] != value {
			t.Errorf("%s is %q, want %q", name, got.Fields[name], value)
		}
	}
}

func TestSyslogLines(t *testing.T) {
	cases := []struct {
		name string
		line string
		want map[string]string
	}{
		{"failed password", "Nov 10 08:15:02 web01 sshd[812]: Failed password for root from 203.0.113.9 port 51234 ssh2",
			map[string]string{"service": "sshd", "product": "linux", "host": "web01", "action": "login", "outcome": "failure", "user": "root", "src_ip": "203.0.113.9", "auth_method": "password"}},
		{"failed password for invalid user", "Nov 10 08:15:02 web01 sshd[812]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2",
			map[string]string{"action": "login", "outcome": "failure", "user": "admin", "user_known": "false"}},
		{"accepted password", "Nov  3 08:15:02 web01 sshd[812]: Accepted password for aiko from 198.51.100.10 port 40000 ssh2",
			map[string]string{"action": "login", "outcome": "success", "user": "aiko", "src_ip": "198.51.100.10", "auth_method": "password"}},
		{"accepted key", "Nov 10 08:15:02 web01 sshd[812]: Accepted publickey for aiko from 2001:db8::7 port 40000 ssh2: ED25519 SHA256:Zm9yLXRlc3Rz",
			map[string]string{"action": "login", "outcome": "success", "user": "aiko", "src_ip": "2001:db8::7", "auth_method": "publickey"}},
		{"address written as IPv4 in IPv6", "Nov 10 08:15:02 web01 sshd[812]: Failed password for root from ::ffff:203.0.113.9 port 51234 ssh2",
			map[string]string{"src_ip": "203.0.113.9"}},
		{"new sshd process name", "Nov 10 08:15:02 web01 sshd-session[812]: Failed password for root from 203.0.113.9 port 51234 ssh2",
			map[string]string{"service": "sshd", "action": "login"}},
		{"invalid user line is not a second failure", "Nov 10 08:15:02 web01 sshd[812]: Invalid user admin from 203.0.113.9 port 51234",
			map[string]string{"action": "invalid_user", "user": "admin", "outcome": ""}},
		{"too many tries", "Nov 10 08:15:02 web01 sshd[812]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 51234 ssh2 [preauth]",
			map[string]string{"action": "max_auth_attempts", "outcome": "failure", "user": "root"}},
		{"other sshd line keeps its message", "Nov 10 08:15:02 web01 sshd[812]: Connection closed by 203.0.113.9 port 51234 [preauth]",
			map[string]string{"service": "sshd", "action": "", "message": "Connection closed by 203.0.113.9 port 51234 [preauth]"}},
		{"sudo", "Nov 10 08:15:02 web01 sudo:     aiko : TTY=pts/0 ; PWD=/home/aiko ; USER=root ; COMMAND=/usr/bin/apt update",
			map[string]string{"service": "sudo", "action": "sudo", "outcome": "success", "user": "aiko", "target_user": "root", "command": "/usr/bin/apt update", "directory": "/home/aiko"}},
		{"sudo command with separators in it", "Nov 10 08:15:02 web01 sudo: aiko : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c echo a ; USER=nobody ; user NOT in sudoers",
			map[string]string{"outcome": "success", "target_user": "root", "command": "/bin/sh -c echo a ; USER=nobody ; user NOT in sudoers"}},
		{"sudo refused", "Nov 10 08:15:02 web01 sudo: www-data : user NOT in sudoers ; TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
			map[string]string{"action": "sudo", "outcome": "failure", "user": "www-data", "reason": "user NOT in sudoers"}},
		{"sudo wrong passwords", "Nov 10 08:15:02 web01 sudo: mei : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/mei ; USER=root ; COMMAND=/bin/ls",
			map[string]string{"outcome": "failure", "user": "mei"}},
		{"sudo session line is not a command", "Nov 10 08:15:02 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by aiko(uid=1000)",
			map[string]string{"service": "sudo", "action": ""}},
		{"cron job", "Nov 10 08:17:01 web01 CRON[4411]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
			map[string]string{"service": "cron", "action": "cron_run", "user": "root", "command": "   cd / && run-parts --report /etc/cron.hourly"}},
		{"cron job with brackets in it", "Nov 10 08:17:01 web01 crond[4411]: (root) CMD (test -x /a || ( cd / && run ))",
			map[string]string{"service": "cron", "action": "cron_run", "command": "test -x /a || ( cd / && run )"}},
		{"crontab changed", "Nov 10 08:17:01 web01 crontab[4411]: (root) REPLACE (root)",
			map[string]string{"service": "crontab", "action": "cron_edit", "user": "root", "cron_change": "REPLACE"}},
		{"new user", "Nov 10 08:17:01 web01 useradd[99]: new user: name=support2, UID=1002, GID=1002, home=/home/support2, shell=/bin/bash, from=/dev/pts/1",
			map[string]string{"service": "useradd", "action": "user_created", "user": "support2"}},
		{"group", "Nov 10 08:17:01 web01 usermod[99]: add 'support2' to group 'sudo'",
			map[string]string{"action": "group_add", "user": "support2", "group": "sudo"}},
		{"su failed", "Nov 10 08:17:01 web01 su[99]: FAILED SU (to root) mei on pts/2",
			map[string]string{"action": "su", "outcome": "failure", "user": "mei", "target_user": "root"}},
		{"program with a path", "Nov 10 08:17:01 web01 /usr/sbin/cron[99]: (root) CMD (true)",
			map[string]string{"service": "cron", "action": "cron_run"}},
		{"time with zone", "2026-11-10T08:15:02.123456+09:00 web01 sshd[812]: Failed password for root from 203.0.113.9 port 51234 ssh2",
			map[string]string{"action": "login", "outcome": "failure"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, stats := parseOne(t, FormatSyslog, testCase.line)
			if stats.Events != 1 || stats.Malformed != 0 {
				t.Fatalf("stats are %+v", stats)
			}
			wantFields(t, got, testCase.want)
			if got.Ref != "x.log:1" || got.Source != FormatSyslog {
				t.Errorf("ref %q, source %q", got.Ref, got.Source)
			}
		})
	}
}

func TestSyslogTimes(t *testing.T) {
	classic, _ := parseOne(t, FormatSyslog, "Nov  3 08:15:02 web01 sshd[1]: x")
	if want := time.Date(2026, 11, 3, 8, 15, 2, 0, tokyo); !classic.Time.Equal(want) {
		t.Errorf("classic time is %v, want %v", classic.Time, want)
	}
	withZone, _ := parseOne(t, FormatSyslog, "2025-01-02T03:04:05.5-0500 web01 sshd[1]: x")
	if want := time.Date(2025, 1, 2, 8, 4, 5, 500_000_000, time.UTC); !withZone.Time.Equal(want) {
		t.Errorf("time with zone is %v, want %v", withZone.Time, want)
	}
}

// The classic format has no year. A file that goes from December to January is in two years.
func TestSyslogYearGoesUpAtNewYear(t *testing.T) {
	log := "Dec 31 23:59:58 h sshd[1]: a\nJan  1 00:00:03 h sshd[1]: b\nJan  1 00:00:04 h sshd[1]: c\n"
	events, _, err := Parse(strings.NewReader(log), "x.log", Options{Year: 2026, Location: tokyo, Format: FormatSyslog})
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Time.Year() != 2026 || events[1].Time.Year() != 2027 || events[2].Time.Year() != 2027 {
		t.Fatalf("years are %d %d %d", events[0].Time.Year(), events[1].Time.Year(), events[2].Time.Year())
	}
	if !events[1].Time.After(events[0].Time) {
		t.Fatal("the first second of the new year must be after the last second of the old year")
	}
	if elapsed := events[1].Time.Sub(events[0].Time); elapsed != 5*time.Second {
		t.Fatalf("the year boundary spans %v, want 5 seconds", elapsed)
	}
}

func TestSyslogRolloverUsesTheNewYearsLeapDay(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		year          int
		wantEvents    int
		wantMalformed int
	}{
		{"new year is a leap year", 2027, 3, 0},
		{"old year was a leap year", 2028, 2, 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			log := "Dec 31 23:59:58 h sshd[1]: a\nFeb 29 12:00:00 h sshd[1]: b\nMar  1 12:00:00 h sshd[1]: c\n"
			events, stats, err := Parse(strings.NewReader(log), "x.log", Options{Year: testCase.year, Location: tokyo, Format: FormatSyslog})
			if err != nil || stats.Events != testCase.wantEvents || stats.Malformed != testCase.wantMalformed {
				t.Fatalf("stats are %+v, error %v", stats, err)
			}
			last := events[len(events)-1]
			if want := time.Date(testCase.year+1, time.March, 1, 12, 0, 0, 0, tokyo); !last.Time.Equal(want) {
				t.Fatalf("March time is %v, want %v", last.Time, want)
			}
			if testCase.wantMalformed == 0 && (events[1].Time.Month() != time.February || events[1].Time.Day() != 29) {
				t.Fatalf("leap day became %v", events[1].Time)
			}
		})
	}
}

// Whoever connects chooses the user name, and sshd writes it into the log as it is. A name that looks like the
// end of a log line must not move the address, and must not make the line unreadable (that would hide the try).
func TestSSHUserNameCannotForgeTheAddress(t *testing.T) {
	cases := []string{
		"Nov 10 08:15:02 web01 sshd[812]: Failed password for invalid user root from 198.51.100.10 port 22 ssh2 from 203.0.113.9 port 51234 ssh2",
		"Nov 10 08:15:02 web01 sshd[812]: Failed password for invalid user a from 198.51.100.10 port 22: b from 203.0.113.9 port 51234 ssh2",
		"Nov 10 08:15:02 web01 sshd[812]: Failed password for invalid user Accepted password for root from 198.51.100.10 port 22 ssh2 from 203.0.113.9 port 51234 ssh2",
		"Nov 10 08:15:02 web01 sshd[812]: Failed password for invalid user " + strings.Repeat("A", 500) + " from 203.0.113.9 port 51234 ssh2",
	}
	for _, line := range cases {
		got, stats := parseOne(t, FormatSyslog, line)
		if stats.Events != 1 {
			t.Fatalf("the line was dropped: %s", line[:80])
		}
		wantFields(t, got, map[string]string{"action": "login", "outcome": "failure", "src_ip": "203.0.113.9"})
		if len([]rune(got.Fields["user"])) > maxNameRunes {
			t.Errorf("the user name has %d characters", len([]rune(got.Fields["user"])))
		}
	}
}

func TestSSHLineWithATextThatIsNoAddressIsNotALogin(t *testing.T) {
	got, stats := parseOne(t, FormatSyslog, "Nov 10 08:15:02 web01 sshd[812]: Failed password for root from not-an-address port 51234 ssh2")
	if stats.Events != 1 || got.Fields["action"] != "" || got.Fields["src_ip"] != "" {
		t.Fatalf("fields are %v", got.Fields)
	}
}

func TestLinesThatCannotBeRead(t *testing.T) {
	cases := []struct{ name, format, line string }{
		{"syslog without a header", FormatSyslog, "Failed password for root from 203.0.113.9 port 1 ssh2"},
		{"syslog with a month that does not exist", FormatSyslog, "Foo 10 08:15:02 web01 sshd[1]: x"},
		{"syslog with a day that does not exist", FormatSyslog, "Feb 30 08:15:02 web01 sshd[1]: x"},
		{"syslog with an hour that does not exist", FormatSyslog, "Nov 10 25:15:02 web01 sshd[1]: x"},
		{"syslog with a control character", FormatSyslog, "Nov 10 08:15:02 web01 sshd[1]: a\x1b[2Jb"},
		{"syslog with a zero byte", FormatSyslog, "Nov 10 08:15:02 web01 sshd[1]: a\x00b"},
		{"syslog that is not UTF-8", FormatSyslog, "Nov 10 08:15:02 web01 sshd[1]: \xff\xfe"},
		{"web without a time", FormatWeb, `203.0.113.77 - - "GET / HTTP/1.1" 200 5`},
		{"web with a bad time", FormatWeb, `203.0.113.77 - - [99/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 200 5`},
		{"web with a name in place of an address", FormatWeb, `evil.example.test - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 200 5`},
		{"web with a status of four digits", FormatWeb, `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 2000 5`},
		{"json that is cut", FormatJSON, `{"timestamp":"2026-11-10T08:15:02Z","a":`},
		{"json list", FormatJSON, `["2026-11-10T08:15:02Z"]`},
		{"json without a time", FormatJSON, `{"a":"b"}`},
		{"json with a time that is no time", FormatJSON, `{"timestamp":"yesterday"}`},
		{"json with a negative time", FormatJSON, `{"ts":-5}`},
		{"json with two objects", FormatJSON, `{"timestamp":"2026-11-10T08:15:02Z"} {"timestamp":"2026-11-10T08:15:02Z"}`},
		{"json with a trailing closing brace", FormatJSON, `{"timestamp":"2026-11-10T08:15:02Z"}}`},
		{"json with a trailing closing bracket", FormatJSON, `{"timestamp":"2026-11-10T08:15:02Z"}]`},
		{"json with a trailing scalar", FormatJSON, `{"timestamp":"2026-11-10T08:15:02Z"} true`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, stats := parseOne(t, testCase.format, testCase.line)
			if stats.Events != 0 || stats.Malformed != 1 || stats.Lines != 1 {
				t.Fatalf("stats are %+v, want one malformed line", stats)
			}
		})
	}
}

func TestWebLines(t *testing.T) {
	cases := []struct {
		name string
		line string
		want map[string]string
	}{
		{"combined", `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET /index.html?a=1 HTTP/1.1" 200 512 "https://example.test/" "Mozilla/5.0 (X11)"`,
			map[string]string{"category": "webserver", "src_ip": "203.0.113.77", "method": "GET", "url": "/index.html?a=1", "status": "200", "bytes": "512", "referrer": "https://example.test/", "user_agent": "Mozilla/5.0 (X11)", "user": ""}},
		{"common, without agent", `203.0.113.77 - aiko [10/Nov/2026:08:15:02 +0900] "POST /login HTTP/2.0" 302 -`,
			map[string]string{"method": "POST", "url": "/login", "status": "302", "user": "aiko", "bytes": "", "user_agent": ""}},
		{"IPv6", `2001:db8::1 - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 200 5 "-" "-"`,
			map[string]string{"src_ip": "2001:db8::1", "referrer": "", "user_agent": ""}},
		{"quote inside the agent", `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 200 5 "-" "a \"quoted\" agent"`,
			map[string]string{"user_agent": `a \"quoted\" agent`, "status": "200"}},
		{"request that is not HTTP", `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "\x16\x03\x01\x02" 400 150 "-" "-"`,
			map[string]string{"method": "", "url": `\x16\x03\x01\x02`, "status": "400"}},
		{"a forged second entry inside the agent stays inside the agent", `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 404 5 "-" "x\" 200 5 \"-\" \"ok"`,
			map[string]string{"status": "404", "src_ip": "203.0.113.77"}},
		{"extra fields at the end", `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 200 5 "-" "curl/8.5.0" 0.004 "-"`,
			map[string]string{"user_agent": "curl/8.5.0"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, stats := parseOne(t, FormatWeb, testCase.line)
			if stats.Events != 1 {
				t.Fatalf("stats are %+v", stats)
			}
			wantFields(t, got, testCase.want)
			if want := time.Date(2026, 11, 10, 8, 15, 2, 0, tokyo); !got.Time.Equal(want) {
				t.Errorf("time is %v, want %v", got.Time, want)
			}
		})
	}
}

func TestJSONLines(t *testing.T) {
	got, _ := parseOne(t, FormatJSON, `{"timestamp":"2026-11-10T08:15:02.123456+0900","event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.0.0.5","alert":{"signature":"ET SCAN x","severity":2,"metadata":{"tag":["a","b"]}},"ok":true,"none":null}`)
	wantFields(t, got, map[string]string{"event_type": "alert", "src_ip": "203.0.113.9", "dst_ip": "10.0.0.5", "alert.signature": "ET SCAN x", "alert.severity": "2", "alert.metadata.tag": "a,b", "ok": "true"})
	if _, found := got.Fields["none"]; found {
		t.Error("null became a field")
	}
	if want := time.Date(2026, 11, 10, 8, 15, 2, 123456000, tokyo); !got.Time.Equal(want) {
		t.Errorf("time is %v, want %v", got.Time, want)
	}

	times := map[string]time.Time{
		`{"ts":1794266102.5}`:                    time.Unix(1794266102, 500_000_000),
		`{"ts":1794266102500}`:                   time.Unix(1794266102, 500_000_000),
		`{"@timestamp":"2026-11-10T08:15:02Z"}`:  time.Date(2026, 11, 10, 8, 15, 2, 0, time.UTC),
		`{"UtcTime":"2026-11-10 08:15:02.123"}`:  time.Date(2026, 11, 10, 8, 15, 2, 123_000_000, tokyo),
		`{"time":"2026-11-10T08:15:02"}`:         time.Date(2026, 11, 10, 8, 15, 2, 0, tokyo),
		`  {"timestamp":"2026-11-10T08:15:02Z"}`: time.Date(2026, 11, 10, 8, 15, 2, 0, time.UTC),
	}
	for line, want := range times {
		if got, stats := parseOne(t, FormatJSON, line); stats.Events != 1 || got.Time.Sub(want).Abs() > time.Millisecond {
			t.Errorf("%s: time is %v, want %v", line, got.Time, want)
		}
	}
}

func TestJSONValuesAreCleanedAndLimited(t *testing.T) {
	deep := `{"timestamp":"2026-11-10T08:15:02Z","a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":"too deep"}}}}}}}},"msg":"line one\nline two\u001b[2J","big":"` + strings.Repeat("x", 5000) + `"}`
	got, stats := parseOne(t, FormatJSON, deep)
	if stats.Events != 1 {
		t.Fatalf("stats are %+v", stats)
	}
	if got.Fields["msg"] != "line one line two [2J" {
		t.Errorf("msg is %q", got.Fields["msg"])
	}
	if len(got.Fields["big"]) != maxValueRunes {
		t.Errorf("big has %d bytes", len(got.Fields["big"]))
	}
	for name := range got.Fields {
		if strings.Count(name, ".") > maxJSONDepth {
			t.Errorf("the name %q is too deep", name)
		}
	}
}

func TestCountsOfLines(t *testing.T) {
	log := "Nov 10 08:15:02 h sshd[1]: a\n\nnot a line\n   \nNov 10 08:15:03 h sshd[1]: b\r\n" + strings.Repeat("x", maxLineBytes+10) + "\nNov 10 08:15:04 h sshd[1]: last line without a line end"
	events, stats, err := Parse(strings.NewReader(log), "x.log", Options{Year: 2026, Location: tokyo, Format: FormatSyslog})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Lines != 7 || stats.Events != 3 || stats.Blank != 2 || stats.Malformed != 2 || len(events) != 3 {
		t.Fatalf("stats are %+v", stats)
	}
	if events[2].Ref != "x.log:7" || events[1].Fields["message"] != "b" {
		t.Fatalf("last ref is %s, second message is %q", events[2].Ref, events[1].Fields["message"])
	}
}

func TestFormatIsFoundFromTheFirstLines(t *testing.T) {
	cases := map[string]string{
		FormatSyslog: "garbage first\nNov 10 08:15:02 h sshd[1]: a\nNov 10 08:15:03 h sshd[1]: b\n",
		FormatWeb:    `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 200 5` + "\n",
		FormatJSON:   `{"timestamp":"2026-11-10T08:15:02Z","a":1}` + "\n",
	}
	for want, log := range cases {
		_, stats, err := Parse(strings.NewReader(log), "x", options)
		if err != nil || stats.Format != want {
			t.Errorf("format is %q (%v), want %q", stats.Format, err, want)
		}
	}
	for _, log := range []string{"", "just some text\nand more\n", "\x00\x01\x02binary"} {
		if _, _, err := Parse(strings.NewReader(log), "x", options); !errors.Is(err, ErrFormat) {
			t.Errorf("%q: error is %v, want ErrFormat", log, err)
		}
	}
}

func TestBadOptionsAreRefused(t *testing.T) {
	for _, bad := range []Options{{Year: 2026}, {Year: 1, Location: tokyo}, {Year: 2026, Location: tokyo, Format: "xml"}} {
		if _, _, err := Parse(strings.NewReader("x"), "x", bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
		if _, err := Read([]string{t.TempDir()}, bad); err == nil {
			t.Errorf("%+v was accepted by Read", bad)
		}
	}
	if _, _, err := Parse(nil, "x", options); !errors.Is(err, ErrBadInput) {
		t.Error("a nil reader was accepted")
	}
}

func TestReadAFolder(t *testing.T) {
	folder := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		path := filepath.Join(folder, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("auth.log", "Nov 10 08:15:05 h sshd[1]: late\n")
	write("nginx/access.log", `203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET / HTTP/1.1" 200 5`+"\n")
	write("notes.txt", "this is no log\n")
	write("old.log.gz", "\x1f\x8b")
	write(".hidden.log", "Nov 10 08:15:05 h sshd[1]: hidden\n")
	write(".git/config", "Nov 10 08:15:05 h sshd[1]: hidden\n")
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(outside, []byte("Nov 10 08:15:05 h sshd[1]: outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(folder, "link.log")); err != nil {
		t.Skip("links cannot be made here")
	}

	result, err := Read([]string{folder}, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 2 || len(result.Events) != 2 {
		t.Fatalf("%d files and %d events were read: %+v", len(result.Files), len(result.Events), result.Files)
	}
	// Events of all files are in the order of time, and the reference names the file inside the folder.
	if result.Events[0].Ref != "nginx/access.log:1" || result.Events[1].Ref != "auth.log:1" {
		t.Fatalf("refs are %s, %s", result.Events[0].Ref, result.Events[1].Ref)
	}
	skipped := strings.Join(result.Skipped, "\n")
	for _, want := range []string{"notes.txt: the format was not recognized", "old.log.gz: compressed", ".hidden.log: hidden", "link.log: not a normal file"} {
		if !strings.Contains(skipped, want) {
			t.Errorf("skipped does not say %q:\n%s", want, skipped)
		}
	}
	for _, event := range result.Events {
		if strings.Contains(event.Fields["message"], "outside") || strings.Contains(event.Fields["message"], "hidden") {
			t.Error("a file that must be skipped was read")
		}
	}

	if _, err := Read([]string{filepath.Join(folder, "missing.log")}, options); !errors.Is(err, ErrBadInput) {
		t.Errorf("a missing file gave %v", err)
	}
	if _, err := Read([]string{filepath.Join(folder, "link.log")}, options); !errors.Is(err, ErrBadInput) {
		t.Errorf("a link gave %v", err)
	}
}

// CLI inputs can overlap (for example, a folder and one of its files). Those are one log, not extra events.
func TestReadOverlappingPathsOnlyOnce(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "auth.log")
	if err := os.WriteFile(file, []byte("Nov 10 08:15:05 h sshd[1]: one event\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{
		{folder, file},
		{file, folder},
		{file, file, filepath.Join(folder, ".") + "/auth.log"},
	} {
		result, err := Read(paths, options)
		if err != nil || len(result.Files) != 1 || len(result.Events) != 1 {
			t.Fatalf("paths %v gave %d files, %d events, error %v", paths, len(result.Files), len(result.Events), err)
		}
	}
}

func TestReadKeepsSourceReferencesDistinct(t *testing.T) {
	base := t.TempDir()
	paths := []string{
		filepath.Join(base, "first", "auth.log"),
		filepath.Join(base, "second", "auth.log"),
		filepath.Join(base, "third", "other.log"),
	}
	// This unambiguous relative name must stay intact, even though it is a candidate label for the first file.
	folder := filepath.Join(base, "fourth")
	files := append(append([]string{}, paths...), filepath.Join(folder, "first", "auth.log"))
	for _, path := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("Nov 10 08:15:05 h sshd[1]: event\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths = append(paths, folder)
	want := map[string]bool{
		filepath.ToSlash(files[0]) + ":1": true,
		"second/auth.log:1":               true,
		"other.log:1":                     true,
		"first/auth.log:1":                true,
	}
	for _, inputs := range [][]string{paths, {paths[3], paths[2], paths[1], paths[0]}} {
		result, err := Read(inputs, options)
		if err != nil || len(result.Events) != len(want) {
			t.Fatalf("read gave %d events, error %v", len(result.Events), err)
		}
		seen := make(map[string]bool)
		for _, made := range result.Events {
			if !want[made.Ref] || seen[made.Ref] {
				t.Errorf("unexpected or duplicate reference %q", made.Ref)
			}
			seen[made.Ref] = true
		}
		for _, stats := range result.Files {
			if !seen[stats.File+":1"] {
				t.Errorf("file stats label %q does not match its event reference", stats.File)
			}
		}
	}
}

// What must hold for every event, whatever the line was.
func checkEvents(t *testing.T, events []event.Event, stats Stats) {
	t.Helper()
	if stats.Events != len(events) || stats.Events+stats.Blank+stats.Malformed != stats.Lines {
		t.Fatalf("the counts do not add up: %+v", stats)
	}
	for _, made := range events {
		if made.Time.IsZero() || made.Ref == "" {
			t.Fatalf("event without a time or a reference: %+v", made)
		}
		for name, value := range made.Fields {
			if !clean(name) || !clean(value) {
				t.Fatalf("control character in %q=%q", name, value)
			}
			if len([]rune(value)) > maxValueRunes {
				t.Fatalf("%s has %d characters", name, len([]rune(value)))
			}
		}
		if ip, found := made.Fields[event.SourceIP]; found && made.Source != FormatJSON {
			if _, valid := address(ip); !valid {
				t.Fatalf("src_ip %q is no address", ip)
			}
		}
	}
}

func fuzzFormat(f *testing.F, format string, seeds ...string) {
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, log string) {
		events, stats, err := Parse(strings.NewReader(log), "f.log", Options{Year: 2026, Location: tokyo, Format: format})
		if err != nil {
			t.Fatalf("a log must never stop the reader: %v", err)
		}
		checkEvents(t, events, stats)
	})
}

func FuzzSyslog(f *testing.F) {
	fuzzFormat(f, FormatSyslog,
		"Nov 10 08:15:02 web01 sshd[812]: Failed password for invalid user root from 198.51.100.10 port 22 ssh2 from 203.0.113.9 port 51234 ssh2\n",
		"Dec 31 23:59:58 h sudo: aiko : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\nJan  1 00:00:03 h CRON[1]: (root) CMD (a)\n",
		"2026-11-10T08:15:02.1+09:00 web01 useradd[1]: new user: name=a, UID=1\n", "Feb 30 08:15:02 h su[1]: FAILED SU (to root) mei on pts/2")
}

func FuzzWeb(f *testing.F) {
	fuzzFormat(f, FormatWeb,
		`203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET /index.html?a=1 HTTP/1.1" 200 512 "https://example.test/" "Mozilla/5.0 (X11)"`+"\n",
		`2001:db8::1 - u [10/Nov/2026:08:15:02 +0900] "\x16\x03" 400 - "-" "a \"b\" c"`)
}

func FuzzJSON(f *testing.F) {
	fuzzFormat(f, FormatJSON,
		`{"timestamp":"2026-11-10T08:15:02.123456+0900","src_ip":"203.0.113.9","alert":{"signature":"x","tag":["a",1,null,{"b":2}]}}`+"\n",
		`{"ts":1794266102.5,"id.orig_h":"10.0.0.1","c-ip":"1.1.1.1","src_ip":"2.2.2.2"}`, `{"time":1e400}`, `{"ts":1e11}`)
}

func FuzzAutoFormat(f *testing.F) {
	f.Add("Nov 10 08:15:02 h sshd[1]: a\n")
	f.Add(`{"timestamp":"2026-11-10T08:15:02Z"}` + "\n")
	f.Fuzz(func(t *testing.T, log string) {
		events, stats, err := Parse(strings.NewReader(log), "f.log", options)
		if err != nil {
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("unexpected error: %v", err)
			}

			return
		}
		checkEvents(t, events, stats)
	})
}
