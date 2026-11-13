package intake

import (
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

func readText(t *testing.T, text string, format string) ([]event.Event, Stats) {
	t.Helper()
	events, stats, err := Parse(strings.NewReader(text), "app.log", Options{Year: 2026, Location: time.UTC, Format: format})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	return events, stats
}

func one(t *testing.T, text string) event.Event {
	t.Helper()
	events, stats := readText(t, text+"\n", FormatAuto)
	if len(events) != 1 {
		t.Fatalf("%d events from %q (stats %+v)", len(events), text, stats)
	}

	return events[0]
}

func want(t *testing.T, got event.Event, fields map[string]string) {
	t.Helper()
	for name, value := range fields {
		if got.Fields[name] != value {
			t.Errorf("%s = %q, want %q (all: %v)", name, got.Fields[name], value, got.Fields)
		}
	}
}

var request401 = map[string]string{event.Category: "webserver", event.Action: "http_request", event.Method: "POST", event.URL: "/auth/login", event.Status: "401", event.SourceIP: "203.0.113.77"}

func TestTheTextFormatsOfTheFrameworks(t *testing.T) {
	cases := []struct {
		name, line string
		at         time.Time
		fields     map[string]string
	}{
		{"gin", `[GIN] 2026/11/13 - 10:00:00 | 401 |      12.3ms |    203.0.113.77 | POST     "/auth/login"`, time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
			map[string]string{event.Method: "POST", event.URL: "/auth/login", event.Status: "401", event.SourceIP: "203.0.113.77", FrameworkField: "gin"}},
		{"chi", `2026/11/13 10:00:00 "POST http://web01:8080/auth/login?next=/ HTTP/1.1" from 203.0.113.77:51234 - 401 32B in 1.2ms`, time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
			map[string]string{event.URL: "/auth/login?next=/", event.Status: "401", event.SourceIP: "203.0.113.77", FrameworkField: "chi"}},
		{"nest", `[Nest] 4123  - 11/13/2026, 10:02:11 AM    WARN [AuthService] Failed login for admin from ::ffff:203.0.113.77`, time.Date(2026, 11, 13, 10, 2, 11, 0, time.UTC),
			map[string]string{"level": "warn", "context": "AuthService", event.Product: "app", FrameworkField: "nestjs"}},
		{"nest in the afternoon", `[Nest] 1  - 11/13/2026, 2:02:11 PM     LOG [NestApplication] Nest application successfully started`, time.Date(2026, 11, 13, 14, 2, 11, 0, time.UTC),
			map[string]string{"level": "log"}},
		{"spring 3", `2026-11-13T10:00:00.123+09:00  WARN 1 --- [lab] [nio-8080-exec-1] AuthService                              : Failed login for admin from 203.0.113.77`, time.Date(2026, 11, 13, 1, 0, 0, 123e6, time.UTC),
			map[string]string{"level": "warn", "thread": "nio-8080-exec-1", "logger": "AuthService", event.SourceIP: "203.0.113.77", "src_ip_from": "message", FrameworkField: "spring"}},
		{"spring 2", `2026-11-13 10:00:00.123  INFO 1 --- [           main] lab.LabApplication                       : Started LabApplication`, time.Date(2026, 11, 13, 10, 0, 0, 123e6, time.UTC),
			map[string]string{"level": "info", "thread": "main", FrameworkField: "spring"}},
		{"laravel", `[2026-11-13 10:00:00] production.WARNING: Failed login {"email":"user1@example.test","ip":"203.0.113.77"} `, time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
			map[string]string{"level": "warning", event.Message: "Failed login", event.User: "user1@example.test", event.SourceIP: "203.0.113.77", FrameworkField: "laravel"}},
		{"flask", `203.0.113.77 - - [13/Nov/2026 10:00:00] "POST /auth/login HTTP/1.1" 401 -`, time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
			map[string]string{event.Status: "401", event.SourceIP: "203.0.113.77", FrameworkField: "flask"}},
		{"django runserver", `[13/Nov/2026 10:00:00] "POST /auth/login HTTP/1.1" 401 31`, time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
			map[string]string{event.Status: "401", FrameworkField: "django"}},
		{"rust tracing", "2026-11-13T10:00:00.123456Z DEBUG request{method=POST uri=/auth/login version=HTTP/1.1}: tower_http::trace::on_response: finished processing request latency=0 ms status=401", time.Date(2026, 11, 13, 10, 0, 0, 123456e3, time.UTC),
			map[string]string{event.Method: "POST", event.URL: "/auth/login", event.Status: "401", FrameworkField: "tracing"}},
		{"actix", `[2026-11-13T10:00:00Z INFO  actix_web::middleware::logger] 203.0.113.77 "POST /auth/login HTTP/1.1" 401 32 "-" "curl/8.14.1" 0.000123`, time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
			map[string]string{event.Status: "401", event.SourceIP: "203.0.113.77", event.UserAgent: "curl/8.14.1", FrameworkField: "actix"}},
		{"rails with the Logger format", `I, [2026-11-13T10:00:00.123456 #1]  INFO -- : [ab12] Started POST "/auth/login" for 203.0.113.77 at 2026-11-13 10:00:00 +0000`, time.Date(2026, 11, 13, 10, 0, 0, 123456e3, time.UTC),
			map[string]string{event.Action: "http_request_started", event.Category: "webserver", event.SourceIP: "203.0.113.77", "request_id": "ab12", FrameworkField: "rails"}},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			got := one(t, current.line)
			if !got.Time.Equal(current.at) {
				t.Errorf("time %v, want %v", got.Time, current.at)
			}
			want(t, got, current.fields)
		})
	}
}

func TestDockerJSONAndTimestamps(t *testing.T) {
	docker := `{"log":"INFO:     203.0.113.77:51234 - \"POST /auth/login HTTP/1.1\" 401 Unauthorized\n","stream":"stdout","time":"2026-11-13T10:00:00.123456789Z"}`
	got := one(t, docker)
	want(t, got, request401)
	want(t, got, map[string]string{WrapperField: "docker", "stream": "stdout", FrameworkField: "uvicorn"})
	if !got.Time.Equal(time.Date(2026, 11, 13, 10, 0, 0, 123456789, time.UTC)) {
		t.Errorf("time %v", got.Time)
	}

	// pino inside Docker: the time of the line itself is used.
	pino := `{"log":"{\"level\":30,\"time\":1794564001000,\"req\":{\"method\":\"POST\",\"url\":\"/auth/login\",\"remoteAddress\":\"::ffff:203.0.113.77\"},\"res\":{\"statusCode\":401},\"msg\":\"request completed\"}\n","stream":"stdout","time":"2026-11-13T10:00:05Z"}`
	got = one(t, pino)
	want(t, got, request401)
	if !got.Time.Equal(time.UnixMilli(1794564001000)) {
		t.Errorf("pino time %v", got.Time)
	}

	stamped := "2026-11-13T10:00:00.123456789Z INFO:     203.0.113.77:51234 - \"POST /auth/login HTTP/1.1\" 401 Unauthorized"
	want(t, one(t, stamped), request401)
	// A line of text that no reader knows is kept as a message when Docker gives it a time.
	got = one(t, "2026-11-13T10:00:00.123456789Z Unauthorized: /auth/login")
	want(t, got, map[string]string{event.Message: "Unauthorized: /auth/login", event.Product: "app", WrapperField: "docker"})
}

func TestALineWithoutATimeIsNotGuessed(t *testing.T) {
	events, stats := readText(t, "INFO:     203.0.113.77:51234 - \"POST /auth/login HTTP/1.1\" 401 Unauthorized\n", FormatApp)
	if len(events) != 0 || stats.Malformed != 1 {
		t.Fatalf("events %v, stats %+v", events, stats)
	}
}

func TestJournalEntries(t *testing.T) {
	sshd := `{"__REALTIME_TIMESTAMP":"1794564000123456","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd-session","_PID":"812","_SYSTEMD_UNIT":"ssh.service","MESSAGE":"Failed password for root from 203.0.113.77 port 51234 ssh2"}`
	got := one(t, sshd)
	want(t, got, map[string]string{event.Service: "sshd", event.Action: "login", event.Outcome: "failure", event.User: "root", event.SourceIP: "203.0.113.77",
		event.Host: "web01", WrapperField: "journald", "unit": "ssh.service"})
	if !got.Time.Equal(time.UnixMicro(1794564000123456)) {
		t.Errorf("time %v", got.Time)
	}
	// A message that is not UTF-8 is written by journalctl as a list of bytes.
	bytes := `{"__REALTIME_TIMESTAMP":"1794564000000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"app","MESSAGE":[70,97,105,108,101,100,32,108,111,103,105,110,255]}`
	if got := one(t, bytes); !strings.HasPrefix(got.Fields[event.Message], "Failed login") {
		t.Errorf("bytes message: %v", got.Fields)
	}
	app := `{"__REALTIME_TIMESTAMP":"1794564000000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"node","MESSAGE":"{\"level\":40,\"time\":1794564000000,\"msg\":\"Failed login for admin from 203.0.113.77\"}"}`
	want(t, one(t, app), map[string]string{"level": "warn", event.SourceIP: "203.0.113.77", WrapperField: "journald", event.Product: "app"})
}

func TestJSONLoggersOfTheFrameworks(t *testing.T) {
	cases := map[string]string{
		"echo":    `{"time":"2026-11-13T10:00:00Z","remote_ip":"203.0.113.77","method":"POST","uri":"/auth/login","status":401,"user_agent":"curl/8"}`,
		"serilog": `{"@t":"2026-11-13T10:00:00.1234567Z","@m":"HTTP POST /auth/login responded 401 in 1.2 ms","RequestMethod":"POST","RequestPath":"/auth/login","StatusCode":401,"RemoteIpAddress":"203.0.113.77"}`,
		"ecs":     `{"@timestamp":"2026-11-13T10:00:00.000Z","http.request.method":"POST","url.path":"/auth/login","http.response.status_code":401,"client.ip":"203.0.113.77"}`,
		"lograge": `{"time":"2026-11-13T10:00:00Z","method":"POST","path":"/auth/login","status":401,"remote_ip":"203.0.113.77"}`,
		"zap":     `{"ts":1794564000.123,"level":"info","msg":"request","method":"POST","path":"/auth/login","status":401,"ip":"203.0.113.77:51234"}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) { want(t, one(t, line), request401) })
	}
}

// Behind nginx, the application sees nginx. The first address of X-Forwarded-For is the client, but only when
// the peer is the machine itself or a private address: anyone can write the header.
func TestForwardedForIsTakenOnlyFromAProxy(t *testing.T) {
	proxied := `{"time":1794564000000,"req":{"method":"POST","url":"/auth/login","remoteAddress":"::ffff:127.0.0.1","headers":{"x-forwarded-for":"203.0.113.77, 10.0.0.5"}},"res":{"statusCode":401},"msg":"request completed"}`
	want(t, one(t, proxied), map[string]string{event.SourceIP: "203.0.113.77", "proxy_ip": "127.0.0.1", "src_ip_from": "x-forwarded-for"})
	direct := `{"time":1794564000000,"req":{"method":"POST","url":"/auth/login","remoteAddress":"198.51.100.4","headers":{"x-forwarded-for":"203.0.113.77"}},"res":{"statusCode":401},"msg":"request completed"}`
	got := one(t, direct)
	if got.Fields[event.SourceIP] != "198.51.100.4" || got.Fields["proxy_ip"] != "" {
		t.Errorf("a public peer took the header: %v", got.Fields)
	}
}

func TestRailsJoinsTheStartAndTheEndOfARequest(t *testing.T) {
	text := strings.Join([]string{
		`2026-11-13T10:00:00.100000000Z [req-1] Started POST "/auth/login" for 203.0.113.77 at 2026-11-13 10:00:00 +0000`,
		`2026-11-13T10:00:00.110000000Z [req-1] Processing by AuthController#login as */*`,
		`2026-11-13T10:00:00.120000000Z [req-1] Completed 401 Unauthorized in 2ms (Views: 0.1ms | Allocations: 400)`,
		`2026-11-13T10:00:00.200000000Z [req-2] Completed 200 OK in 1ms`,
	}, "\n") + "\n"
	events, _ := readText(t, text, FormatAuto)
	var requests []event.Event
	for _, current := range events {
		if current.Fields[event.Category] == "webserver" && current.Fields[event.Status] != "" {
			requests = append(requests, current)
		}
	}
	if len(requests) != 1 {
		t.Fatalf("%d requests: %v", len(requests), events)
	}
	want(t, requests[0], request401)
}

func TestColorsAreRemovedAndOtherEscapesAreNot(t *testing.T) {
	colored := "\x1b[2m2026-11-13T10:00:00.123456Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2mlab_axum\x1b[0m\x1b[2m:\x1b[0m Failed login for admin from 203.0.113.77"
	want(t, one(t, colored), map[string]string{"level": "warn", event.SourceIP: "203.0.113.77"})
	_, stats := readText(t, "2026-11-13T10:00:00.123456Z  WARN x: a\x1b[2Jb\n", FormatApp)
	if stats.Malformed != 1 {
		t.Errorf("a line that clears the screen was read: %+v", stats)
	}
}

func TestClientAddress(t *testing.T) {
	cases := map[string]string{"203.0.113.77": "203.0.113.77", "203.0.113.77:51234": "203.0.113.77", "::ffff:203.0.113.77": "203.0.113.77",
		"[2001:db8::1]:443": "2001:db8::1", "2001:db8::1": "2001:db8::1", "web01": "", "": "", "fe80::1%eth0": ""}
	for text, wanted := range cases {
		if got, _ := clientAddress(text); got != wanted {
			t.Errorf("clientAddress(%q) = %q, want %q", text, got, wanted)
		}
	}
}

func FuzzAppLines(f *testing.F) {
	for _, seed := range []string{
		`[GIN] 2026/11/13 - 10:00:00 | 401 |      12.3ms |    203.0.113.77 | POST     "/auth/login"`,
		`{"log":"x\n","stream":"stdout","time":"2026-11-13T10:00:00Z"}`,
		`{"__REALTIME_TIMESTAMP":"1794564000000000","MESSAGE":[1,2,3]}`,
		`[2026-11-13 10:00:00] production.WARNING: Failed login {"ip":"203.0.113.77"} []`,
		"2026-11-13T10:00:00.1Z [r] Completed 401 x",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		events, _, err := Parse(strings.NewReader(line+"\n"), "fuzz.log", Options{Year: 2026, Location: time.UTC})
		if err != nil {
			return
		}
		for _, current := range events {
			for name, value := range current.Fields {
				if strings.ContainsAny(value, "\x00\x1b\n") || len(value) > maxValueRunes*4 {
					t.Fatalf("%s = %q", name, value)
				}
			}
		}
	})
}

// Found in the real NestJS log: Node writes the client as ::ffff:172.21.0.3, and the message names the account.
func TestTheAddressAndTheAccountOfAMessage(t *testing.T) {
	cases := []struct{ message, ip, user string }{
		{"Failed login for user1@example.test from ::ffff:172.21.0.3", "172.21.0.3", "user1@example.test"},
		{"Login failed for user admin from 203.0.113.77", "203.0.113.77", "admin"},
		{"Authentication failure for \"root\"", "", "root"},
		{"Failed login", "", ""},
		{"Connection from 203.0.113.77 and 198.51.100.4 failed", "", ""},
		{"Server started for 3 workers", "", ""},
	}
	for _, current := range cases {
		fields := map[string]string{}
		messageFields(fields, current.message)
		if fields[event.SourceIP] != current.ip || fields[event.User] != current.user {
			t.Errorf("%q: ip %q user %q, want %q %q", current.message, fields[event.SourceIP], fields[event.User], current.ip, current.user)
		}
	}
}

func TestEmptyLinesInsideDockerAreBlank(t *testing.T) {
	text := "2026-11-13T10:00:00.1Z \n" + `{"log":"\n","stream":"stdout","time":"2026-11-13T10:00:00Z"}` + "\n" +
		`{"log":"\u001b[0m  \n","stream":"stdout","time":"2026-11-13T10:00:00Z"}` + "\n" +
		"2026-11-13T10:00:00.1Z INFO:     203.0.113.77:1 - \"GET / HTTP/1.1\" 200 OK\n"
	events, stats := readText(t, text, FormatAuto)
	if len(events) != 1 || stats.Blank != 3 || stats.Malformed != 0 {
		t.Fatalf("events %d, stats %+v", len(events), stats)
	}
}

func TestFieldNamesInAnyCase(t *testing.T) {
	line := `{"time":"2026-11-13T10:00:00Z","Method":"POST","Path":"/auth/login","Status":401,"ClientIP":"203.0.113.77","UserName":"admin","Message":"Login rejected"}`
	want(t, one(t, line), map[string]string{event.Method: "POST", event.URL: "/auth/login", event.Status: "401", event.SourceIP: "203.0.113.77", event.User: "admin"})
}

// tower-http writes a line when a request starts and one when it ends. Only the end, with its status, is the request.
func TestTheStartOfATracedRequestIsNotARequest(t *testing.T) {
	got := one(t, "2026-11-13T10:00:00.1Z DEBUG request{method=POST uri=/auth/login version=HTTP/1.1}: tower_http::trace::on_request: started processing request")
	if got.Fields[event.Category] == "webserver" || got.Fields[event.Method] != "" {
		t.Fatalf("the start of a request became a request: %v", got.Fields)
	}
}

// An application can write a field named log. Only the three or four fields of Docker are its wrapper.
func TestAnApplicationFieldNamedLogIsNotDocker(t *testing.T) {
	got := one(t, `{"time":"2026-11-13T10:00:00Z","log":"audit","level":"warn","msg":"Failed login for admin from 203.0.113.77","service":"api","env":"prod"}`)
	if got.Fields[WrapperField] != "" || got.Fields["log"] != "audit" || got.Fields[event.SourceIP] != "203.0.113.77" {
		t.Fatalf("got %v", got.Fields)
	}
}
