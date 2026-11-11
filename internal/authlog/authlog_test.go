package authlog

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func tokyo(t testing.TB) *time.Location {
	t.Helper()

	location, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip("no time zone database")
	}

	return location
}

func parseText(t testing.TB, text string) Parsed {
	t.Helper()

	parsed, err := Parse(strings.NewReader(text), 2026, time.UTC)
	if err != nil {
		t.Fatal(err)
	}

	return parsed
}

func TestEachLineIsAnEventIgnoredOrMalformed(t *testing.T) {
	testCases := []struct {
		name string
		line string
		want string
	}{
		{"a failed password", "Nov 11 09:00:01 host sshd[1234]: Failed password for root from 203.0.113.5 port 52244 ssh2", "event"},
		{"a failed password for an invalid user", "Nov 11 09:00:02 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52245 ssh2", "event"},
		{"an accepted password", "Nov 11 09:00:03 host sshd[1234]: Accepted password for alice from 198.51.100.7 port 41000 ssh2", "event"},
		{"an IPv6 address", "Nov 11 09:00:04 host sshd[1]: Failed password for bob from 2001:db8::1 port 22 ssh2", "event"},
		{"no pid", "Nov 11 09:00:05 host sshd: Failed password for bob from 192.0.2.1 port 22 ssh2", "event"},
		{"a day with one digit", "Nov  1 09:00:06 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2", "event"},
		{"trailing spaces", "Nov 11 09:00:07 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2  ", "event"},
		{"a connection message", "Nov 11 09:00:08 host sshd[1]: Connection closed by 192.0.2.1 port 22 [preauth]", "ignored"},
		{"a public key login", "Nov 11 09:00:09 host sshd[1]: Accepted publickey for alice from 192.0.2.1 port 22 ssh2: RSA SHA256:abc", "ignored"},
		{"an invalid user message", "Nov 11 09:00:10 host sshd[1]: Invalid user x from 192.0.2.1 port 22", "ignored"},
		{"a failed password text from another program", "Nov 11 09:00:11 host login[7]: Failed password for bob from 192.0.2.1 port 22 ssh2", "ignored"},
		{"a cron line", "Nov 11 09:00:11 host CRON[99]: (root) CMD (run)", "ignored"},
		{"a sudo line", "Nov 11 09:00:12 host sudo:   alice : TTY=pts/0 ; COMMAND=/bin/ls", "ignored"},
		{"a blank line", "", "ignored"},
		{"a line of spaces", "   ", "ignored"},
		{"not a log line", "hello world", "malformed"},
		{"no host", "Nov 11 09:00:13", "malformed"},
		{"a month that does not exist", "Foo 11 09:00:14 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2", "malformed"},
		{"a date that does not exist", "Feb 30 09:00:15 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2", "malformed"},
		{"an hour that does not exist", "Nov 11 25:00:16 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2", "malformed"},
		{"a minute that does not exist", "Nov 11 09:61:17 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2", "malformed"},
		{"a failed password with no user", "Nov 11 09:00:18 host sshd[1]: Failed password for from 192.0.2.1 port 22 ssh2", "malformed"},
		{"a failed password with no address", "Nov 11 09:00:19 host sshd[1]: Failed password for bob from port 22 ssh2", "malformed"},
		{"an address with odd characters", "Nov 11 09:00:20 host sshd[1]: Failed password for bob from 1.2.3.4;rm port 22 ssh2", "malformed"},
		{"a port that is not a number", "Nov 11 09:00:21 host sshd[1]: Failed password for bob from 192.0.2.1 port abc ssh2", "malformed"},
		{"an accepted password that is cut", "Nov 11 09:00:22 host sshd[1]: Accepted password for alice from", "malformed"},
		{"a user name that is too long", "Nov 11 09:00:23 host sshd[1]: Failed password for " + strings.Repeat("u", maxNameRunes+1) + " from 192.0.2.1 port 22 ssh2", "malformed"},
		{"a line that is too long", "Nov 11 09:00:24 host sshd[1]: " + strings.Repeat("x", maxLineBytes), "malformed"},
		{"a line with a NUL", "Nov 11 09:00:25 host sshd[1]: Failed password for b\x00b from 192.0.2.1 port 22 ssh2", "malformed"},
		{"bytes that are not UTF-8", "Nov 11 09:00:26 host sshd[1]: Failed password for b\xffb from 192.0.2.1 port 22 ssh2", "malformed"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed := parseText(t, testCase.line+"\n")

			got := "malformed"
			switch {
			case len(parsed.Events) == 1:
				got = "event"
			case parsed.Ignored == 1:
				got = "ignored"
			}
			if got != testCase.want || parsed.Lines != 1 || len(parsed.Events)+parsed.Ignored+parsed.Malformed != 1 {
				t.Errorf("%+v, want %s", parsed, testCase.want)
			}
		})
	}
}

func TestAnEventHoldsWhatTheLineSays(t *testing.T) {
	parsed := parseText(t, "Nov  1 09:05:07 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52244 ssh2\n"+
		"Nov 11 23:59:59 host sshd[1]: Accepted password for alice from 2001:db8::1 port 22 ssh2\n")

	first, second := parsed.Events[0], parsed.Events[1]
	if first.Line != 1 || first.Kind != Failed || first.User != "admin" || first.IP != "203.0.113.5" || first.Stamp != "Nov 1 09:05:07" ||
		!first.Time.Equal(time.Date(2026, time.November, 1, 9, 5, 7, 0, time.UTC)) {
		t.Errorf("first = %+v", first)
	}
	if second.Line != 2 || second.Kind != Accepted || second.User != "alice" || second.IP != "2001:db8::1" || second.Stamp != "Nov 11 23:59:59" {
		t.Errorf("second = %+v", second)
	}
	if Failed.String() != "Failed password" || Accepted.String() != "Accepted password" {
		t.Error("the names of the kinds are wrong")
	}
}

func TestTheYearAndTheTimeZoneComeFromTheCaller(t *testing.T) {
	line := "Mar  3 10:00:00 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2\n"

	utc, err := Parse(strings.NewReader(line), 2024, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	japan, err := Parse(strings.NewReader(line), 2025, tokyo(t))
	if err != nil {
		t.Fatal(err)
	}

	if utc.Events[0].Time.Year() != 2024 || japan.Events[0].Time.Year() != 2025 {
		t.Errorf("years %d and %d", utc.Events[0].Time.Year(), japan.Events[0].Time.Year())
	}
	if difference := utc.Events[0].Time.Sub(time.Date(2024, 3, 3, 10, 0, 0, 0, tokyo(t))); difference != 9*time.Hour {
		t.Errorf("the same hour in two zones is %v apart, want 9h", difference)
	}
	if leap, err := Parse(strings.NewReader("Feb 29 10:00:00 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2\n"), 2024, time.UTC); err != nil || len(leap.Events) != 1 {
		t.Errorf("February 29 in a leap year: %+v, %v", leap, err)
	}
	if noLeap, _ := Parse(strings.NewReader("Feb 29 10:00:00 host sshd[1]: Failed password for bob from 192.0.2.1 port 22 ssh2\n"), 2025, time.UTC); noLeap.Malformed != 1 {
		t.Errorf("February 29 in a year without it: %+v", noLeap)
	}
}

func TestEventsAreSortedByTimeAndEqualTimesKeepTheOrderOfTheLines(t *testing.T) {
	parsed := parseText(t, strings.Join([]string{
		"Nov 11 09:00:05 h sshd[1]: Failed password for c from 192.0.2.3 port 22 ssh2",
		"Nov 11 09:00:01 h sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2",
		"Nov 11 09:00:05 h sshd[1]: Failed password for d from 192.0.2.4 port 22 ssh2",
		"Nov 11 09:00:03 h sshd[1]: Failed password for b from 192.0.2.2 port 22 ssh2",
		"Nov 11 09:00:05 h sshd[1]: Accepted password for e from 192.0.2.5 port 22 ssh2",
	}, "\n"))

	var order []string
	for _, event := range parsed.Events {
		order = append(order, event.User)
	}
	if strings.Join(order, "") != "abcde" {
		t.Errorf("order = %v, want a b c d e (the three events at 09:00:05 keep their line order)", order)
	}
	if parsed.Events[2].Line != 1 || parsed.Events[3].Line != 3 || parsed.Events[4].Line != 5 {
		t.Errorf("the line numbers were changed by the sort: %+v", parsed.Events)
	}
}

func TestMalformedLinesAreCountedNeverDropped(t *testing.T) {
	parsed := parseText(t, strings.Join([]string{
		"Nov 11 09:00:01 h sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2",
		"this is not a log line",
		"Nov 11 09:00:02 h CRON[2]: something",
		"",
		"Nov 11 09:00:03 h sshd[1]: Failed password for from port",
		"Nov 11 09:00:04 h sshd[1]: Failed password for b from 192.0.2.1 port 22 ssh2",
	}, "\n"))

	if parsed.Lines != 6 || len(parsed.Events) != 2 || parsed.Ignored != 2 || parsed.Malformed != 2 {
		t.Errorf("%+v", parsed)
	}
}

func TestTheLastLineNeedsNoNewlineAndWindowsLineEndingsWork(t *testing.T) {
	lines := "Nov 11 09:00:01 h sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2\r\nNov 11 09:00:02 h sshd[1]: Failed password for b from 192.0.2.1 port 22 ssh2"

	parsed := parseText(t, lines)

	if parsed.Lines != 2 || len(parsed.Events) != 2 || parsed.Malformed != 0 {
		t.Errorf("%+v", parsed)
	}
	if empty := parseText(t, ""); empty.Lines != 0 || len(empty.Events) != 0 {
		t.Errorf("an empty log: %+v", empty)
	}
	if onlyNewlines := parseText(t, "\n\n\n"); onlyNewlines.Lines != 3 || onlyNewlines.Ignored != 3 {
		t.Errorf("three blank lines: %+v", onlyNewlines)
	}
}

func TestALongLineDoesNotHideTheLinesAfterIt(t *testing.T) {
	parsed := parseText(t, strings.Repeat("x", 3*maxLineBytes)+"\nNov 11 09:00:01 h sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2\n")

	if parsed.Lines != 2 || parsed.Malformed != 1 || len(parsed.Events) != 1 || parsed.Events[0].Line != 2 {
		t.Errorf("%+v", parsed)
	}
}

func TestBadArgumentsAreRefused(t *testing.T) {
	if _, err := Parse(nil, 2026, time.UTC); !errors.Is(err, ErrBadInput) {
		t.Errorf("a nil reader: %v", err)
	}
	if _, err := Parse(strings.NewReader(""), 2026, nil); !errors.Is(err, ErrBadInput) {
		t.Errorf("a nil location: %v", err)
	}
	for _, year := range []int{0, 1969, 2201, -5} {
		if _, err := Parse(strings.NewReader(""), year, time.UTC); !errors.Is(err, ErrBadInput) {
			t.Errorf("year %d: %v", year, err)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("disk problem with /secret/path")
}

func TestAReadErrorIsAFixedError(t *testing.T) {
	_, err := Parse(failingReader{}, 2026, time.UTC)

	if err != ErrBadInput || strings.Contains(err.Error(), "secret") {
		t.Errorf("err = %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("Nov 11 09:00:01 host sshd[1234]: Failed password for root from 203.0.113.5 port 52244 ssh2\n")
	f.Add("Feb 30 25:61:61 h sshd[1]: Accepted password for \x00 from ::1 port 1\n\n\r\n")
	f.Add(strings.Repeat("x", 9000))

	f.Fuzz(func(t *testing.T, text string) {
		parsed, err := Parse(strings.NewReader(text), 2026, time.UTC)
		if err != nil {
			t.Fatalf("err = %v", err)
		}

		if parsed.Lines != len(parsed.Events)+parsed.Ignored+parsed.Malformed {
			t.Fatalf("a line was lost: %d lines, %d events, %d ignored, %d malformed", parsed.Lines, len(parsed.Events), parsed.Ignored, parsed.Malformed)
		}
		for index, event := range parsed.Events {
			if event.Line < 1 || event.Line > parsed.Lines || event.User == "" || event.IP == "" || strings.ContainsAny(event.User+event.IP+event.Stamp, "\n\r\x00") {
				t.Fatalf("a bad event: %+v", event)
			}
			if index > 0 && event.Time.Before(parsed.Events[index-1].Time) {
				t.Fatal("the events are not sorted")
			}
			if index > 0 && event.Time.Equal(parsed.Events[index-1].Time) && event.Line < parsed.Events[index-1].Line {
				t.Fatal("equal times lost the order of the lines")
			}
		}
	})
}
