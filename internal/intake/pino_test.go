package intake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

func readLines(t *testing.T, lines ...string) Result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := Read([]string{path}, Options{Year: 2026, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}

	return read
}

// Times of the lines below: 1795699128662 is 2026-11-26T13:18:48.662Z.
const (
	incoming  = `{"level":30,"time":1795699128662,"pid":7,"hostname":"api","reqId":"req-1","req":{"method":"GET","url":"/.env","host":"x","remoteAddress":"203.0.113.5","remotePort":5},"msg":"incoming request"}`
	completed = `{"level":30,"time":1795699128683,"pid":7,"hostname":"api","reqId":"req-1","res":{"statusCode":404},"responseTime":2.5,"msg":"request completed"}`
)

func requests(read Result) []event.Event {
	var found []event.Event
	for _, current := range read.Events {
		if current.Fields[event.Category] == "webserver" {
			found = append(found, current)
		}
	}

	return found
}

func TestFastifyLinesAreJoinedIntoOneRequest(t *testing.T) {
	read := readLines(t, incoming, completed)
	got := requests(read)
	if len(got) != 1 {
		t.Fatalf("got %d requests, want 1", len(got))
	}
	fields := got[0].Fields
	if fields[event.Method] != "GET" || fields[event.URL] != "/.env" || fields[event.Status] != "404" || fields[event.SourceIP] != "203.0.113.5" {
		t.Errorf("joined request: %v", fields)
	}
	if len(read.Events) != 2 || read.Files[0].Events != 2 {
		t.Errorf("both lines must stay events, got %d", len(read.Events))
	}
	if warnings := read.Files[0].Warnings(); len(warnings) != 0 {
		t.Errorf("a joined log must not warn: %v", warnings)
	}
}

func TestFastifyUserAgentAndReferrerAreRead(t *testing.T) {
	// The request serializer of matchingg-backend adds the user agent and the Referer under req.headers.
	withHeaders := strings.Replace(incoming, `"remotePort":5}`,
		`"remotePort":5,"headers":{"user-agent":"sqlmap/1.8","referer":"http://x/?id=1%2527%2520OR%2520%25271"}}`, 1)
	got := requests(readLines(t, withHeaders, completed))
	if len(got) != 1 {
		t.Fatalf("got %d requests", len(got))
	}
	fields := got[0].Fields
	if fields[event.UserAgent] != "sqlmap/1.8" || fields[ReferrerDecoded] != "http://x/?id=1' OR '1" {
		t.Errorf("fields: %v", fields)
	}
}

func TestFastifyLinesOfAnotherProcessAreNotJoined(t *testing.T) {
	// After a restart, Fastify counts request ids from req-1 again. Another pid is another request.
	other := strings.Replace(completed, `"pid":7`, `"pid":8`, 1)
	read := readLines(t, incoming, other)
	if got := requests(read); len(got) != 0 {
		t.Fatalf("lines of two processes were joined: %v", got)
	}
	if read.Files[0].PartialRequests != 1 {
		t.Errorf("the request without a status must be counted, stats %+v", read.Files[0])
	}
}

func TestFastifyCompletionTooLateIsNotJoined(t *testing.T) {
	late := strings.Replace(completed, "1795699128683", "1795699928683", 1) // 800 seconds later
	if got := requests(readLines(t, incoming, late)); len(got) != 0 {
		t.Fatalf("a completion past the window was joined: %v", got)
	}
}

func TestRequestsWithoutStatusWarn(t *testing.T) {
	warnings := readLines(t, incoming).Files[0].Warnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "1 requests have no status") {
		t.Errorf("warnings: %v", warnings)
	}
}

func TestAppLogWithoutRequestsWarns(t *testing.T) {
	// Nest's default logger: startup lines only, never a request.
	read := readLines(t,
		"[Nest] 41241  - 11/26/2026, 10:17:27 PM     LOG [NestFactory] Starting Nest application...",
		"[Nest] 41241  - 11/26/2026, 10:17:27 PM     LOG [NestApplication] Nest application successfully started",
	)
	if read.Files[0].AppEvents == 0 {
		t.Fatalf("Nest lines must be app events, stats %+v", read.Files[0])
	}
	warnings := read.Files[0].Warnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "no request lines") {
		t.Errorf("warnings: %v", warnings)
	}
}

func TestAppLogWithBareAccessLines(t *testing.T) {
	// Nest's own lines and a combined access log in one standard output, as under pm2 or systemd.
	read := readLines(t,
		"[Nest] 41241  - 11/26/2026, 10:17:27 PM     LOG [NestApplication] Nest application successfully started",
		"[Nest] 41241  - 11/26/2026, 10:17:28 PM    WARN [AuthService] Failed login for admin from 203.0.113.5",
		`203.0.113.5 - - [26/Nov/2026:13:17:28 +0000] "POST /auth/login HTTP/1.1" 401 73 "-" "sqlmap/1.8"`,
	)
	file := read.Files[0]
	if file.Format != FormatApp || file.Malformed != 0 || file.Requests != 1 {
		t.Fatalf("stats %+v", file)
	}
	if warnings := file.Warnings(); len(warnings) != 0 {
		t.Errorf("a log with requests must not warn: %v", warnings)
	}
	got := requests(read)
	if fields := got[0].Fields; fields[event.Status] != "401" || fields[event.UserAgent] != "sqlmap/1.8" || fields[event.SourceIP] != "203.0.113.5" {
		t.Errorf("request: %v", fields)
	}
}

func TestSyslogDoesNotWarn(t *testing.T) {
	// A system log is not an application log: having no requests is normal there.
	read := readLines(t, "Nov 26 09:00:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2")
	if warnings := read.Files[0].Warnings(); len(warnings) != 0 {
		t.Errorf("a syslog file must not warn: %v", warnings)
	}
}
