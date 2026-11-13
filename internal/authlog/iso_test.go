package authlog

import (
	"strings"
	"testing"
	"time"
)

func TestCurrentRsyslogAndOpenSSHLinesAreRead(t *testing.T) {
	testCases := []struct {
		name    string
		line    string
		kind    Kind
		ignored bool
		zoned   bool
		when    time.Time
		stamp   string
	}{
		{"ISO header and sshd-session", "2026-11-12T14:00:10.984780+00:00 web01 sshd-session[28]: Failed password for root from 172.21.0.3 port 48128 ssh2",
			Failed, false, true, time.Date(2026, 11, 12, 14, 0, 10, 984780000, time.UTC), "2026-11-12T14:00:10.984780+00:00"},
		{"ISO header with a zone without colon", "2026-11-12T23:03:48+0900 web01 sshd[123]: Accepted password for alice from 2001:db8::5 port 34968 ssh2",
			Accepted, false, true, time.Date(2026, 11, 12, 14, 3, 48, 0, time.UTC), "2026-11-12T23:03:48+0900"},
		{"ISO header in UTC", "2026-11-12T14:03:47Z web01 sshd-auth[9]: Failed password for invalid user admin from 172.21.0.3 port 46422 ssh2",
			Failed, false, true, time.Date(2026, 11, 12, 14, 3, 47, 0, time.UTC), "2026-11-12T14:03:47Z"},
		{"classic header and sshd-session", "Nov 12 14:06:09 web01 sshd-session[199]: Failed password for root from 172.21.0.3 port 35336 ssh2",
			Failed, false, false, time.Date(2026, 11, 12, 14, 6, 9, 0, time.UTC), "Nov 12 14:06:09"},
		{"ISO header, other message", "2026-11-12T14:00:11.4+00:00 web01 sshd-session[28]: Connection closed by authenticating user root 172.21.0.3 port 48128 [preauth]",
			0, true, true, time.Time{}, ""},
		{"ISO header, other program", "2026-11-12T14:00:35.29+00:00 web01 useradd[50]: new user: name=support2", 0, true, true, time.Time{}, ""},
		{"a program that only starts with sshd", "Nov 12 14:06:09 web01 sshd-evil[1]: Failed password for root from 172.21.0.3 port 1 ssh2", 0, true, false, time.Time{}, ""},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := Parse(strings.NewReader(testCase.line+"\n"), 2026, time.UTC)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Malformed != 0 || (parsed.Zoned == 1) != testCase.zoned {
				t.Fatalf("parsed %+v", parsed)
			}
			if testCase.ignored {
				if parsed.Ignored != 1 || len(parsed.Events) != 0 {
					t.Fatalf("parsed %+v, want ignored", parsed)
				}
				return
			}
			if len(parsed.Events) != 1 {
				t.Fatalf("parsed %+v, want one event", parsed)
			}
			event := parsed.Events[0]
			if event.Kind != testCase.kind || !event.Time.Equal(testCase.when) || event.Stamp != testCase.stamp || event.Line != 1 {
				t.Fatalf("event %+v", event)
			}
		})
	}
}

func TestBrokenISOHeadersAreMalformed(t *testing.T) {
	for _, line := range []string{
		"2026-13-40T25:61:61+00:00 web01 sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2",
		"2026-11-12T14:00:10+99:99 web01 sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2",
		"2026-11-12T14:00:10+00:00 web01 sshd[1]: Failed password for root from not-an-address port 1 ssh2",
		"2026-11-12 14:00:10 web01 sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2",
	} {
		parsed, err := Parse(strings.NewReader(line), 2026, time.UTC)
		if err != nil || parsed.Malformed != 1 || len(parsed.Events) != 0 || parsed.Zoned != 0 {
			t.Errorf("%q: %+v %v", line, parsed, err)
		}
	}
}

func FuzzParseISO(f *testing.F) {
	f.Add("2026-11-12T14:00:10.984780+00:00 web01 sshd-session[28]: Failed password for root from 172.21.0.3 port 48128 ssh2")
	f.Add("2026-11-12T23:03:48+0900 h sshd[1]: Accepted password for a from ::1 port 1")
	f.Fuzz(func(t *testing.T, line string) {
		parsed, err := Parse(strings.NewReader(line), 2026, time.UTC)
		if err != nil {
			return
		}
		if parsed.Zoned > parsed.Lines || len(parsed.Events)+parsed.Ignored+parsed.Malformed != parsed.Lines {
			t.Fatalf("counts do not add up: %+v", parsed)
		}
		for _, event := range parsed.Events {
			if event.IP == "" || event.User == "" || event.Stamp == "" {
				t.Fatalf("an event without fields: %+v", event)
			}
		}
	})
}
