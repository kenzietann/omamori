package intake

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

// The logs of web applications: the frameworks that most backends are written with, and the two places where
// their logs are usually kept, the json-file logs of Docker and the journal of systemd.
//
// A request that an application logs becomes the same event as a line of an nginx access log: category
// webserver, with method, url, status, src_ip and user_agent. So the web rules read every framework the same
// way, and the rules for applications (login failures, errors, debug endpoints) read nginx too.
const (
	FormatApp = "app"

	// WrapperField says which log store a line came out of: docker or journald.
	WrapperField = "log_wrapper"
	// FrameworkField names the framework whose format the line has, when the format says it.
	FrameworkField = "framework"
)

// colorCodes are the escape sequences that only set a color (SGR), as frameworks write them to a terminal.
// Every other escape sequence (clearing the screen, moving the cursor) stays, and makes the line unreadable:
// it is a known way to hide or fake lines in a log.
var colorCodes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(text string) string {
	if !strings.Contains(text, "\x1b") {
		return text
	}

	return colorCodes.ReplaceAllString(text, "")
}

// appLine is one text format of a framework. parse gives the fields and, when the line has one, its time.
type appLine struct {
	name  string
	parse func(line string, options Options) (map[string]string, time.Time, bool)
}

var (
	// [Nest] 4123  - 11/13/2026, 10:00:01 AM     LOG [RouterExplorer] Mapped {/auth/login, POST} route
	nestLine = regexp.MustCompile(`^\[Nest\] (\d+)\s+-\s+(\d{1,2}/\d{1,2}/\d{4}),? (\d{1,2}:\d{2}:\d{2})(?:\s?([AP]M))?\s+(LOG|ERROR|WARN|DEBUG|VERBOSE|FATAL)\s+\[([^\]]*)\] (.*)$`)
	// [GIN] 2026/11/13 - 10:00:00 | 401 |      12.3ms |    203.0.113.77 | POST     "/auth/login"
	ginLine = regexp.MustCompile(`^\[GIN\] (\d{4}/\d{2}/\d{2} - \d{2}:\d{2}:\d{2}) \|\s*(\d{3}) \|\s*([^|]*?)\s*\|\s*(\S+)\s*\|\s*([A-Z]+)\s+"(.*)"$`)
	// 2026-11-13T10:00:00.123+09:00  INFO 1234 --- [app] [nio-8080-exec-1] c.e.d.AuthController : Login failed
	// 2026-11-13 10:00:00.123  INFO 1234 --- [nio-8080-exec-1] c.e.d.AuthController : Login failed (Spring Boot 2)
	springLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.\d{3}(?:Z|[+-]\d{2}:\d{2})?)\s+(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+(\d+) --- (?:\[[^\]]*\] )*?\[\s*([^\]]*)\]\s+(\S+)\s+:\s?(.*)$`)
	// I, [2026-11-13T10:00:00.123456 #1234]  INFO -- : [1f2e...] Started POST "/login" for 203.0.113.77 at ...
	rubyLogger = regexp.MustCompile(`^[DIWEFUA], \[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?) #(\d+)\]\s+(\w+) -- [^:]*: (.*)$`)
	railsTags  = regexp.MustCompile(`^((?:\[[^\]]*\] )*)(.*)$`)
	railsStart = regexp.MustCompile(`^Started ([A-Z]+) "([^"]*)" for (\S+) at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})`)
	railsDone  = regexp.MustCompile(`^Completed (\d{3}) `)
	// [2026-11-13 10:00:00] production.WARNING: Login failed {"email":"a@example.test","ip":"203.0.113.77"} []
	laravelLine = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)\] (\w+)\.([A-Z]+): (.*)$`)
	// 203.0.113.77 - - [13/Nov/2026 10:00:00] "POST /login HTTP/1.1" 401 -   (Flask and Werkzeug)
	// [13/Nov/2026 10:00:00] "POST /login HTTP/1.1" 401 52                    (Django runserver)
	pythonDevLine = regexp.MustCompile(`^(?:(?:INFO|WARNING):werkzeug:)?(?:(\S+) - - )?\[(\d{2}/[A-Z][a-z]{2}/\d{4} \d{2}:\d{2}:\d{2})\] "([A-Z]+) (\S+) HTTP/[\d.]+" (\d{3}) (\d+|-)$`)
	// INFO:     203.0.113.77:51234 - "POST /auth/login HTTP/1.1" 401 Unauthorized   (uvicorn, FastAPI; no time)
	uvicornLine = regexp.MustCompile(`^(?:INFO|WARNING|ERROR|DEBUG):\s+(\S+?):(\d{1,5}) - "([A-Z]+) (\S+) HTTP/[\d.]+" (\d{3})`)
	// 2026-11-13T10:00:00.123456Z  INFO request{method=POST uri=/auth/login version=HTTP/1.1}: tower_http::trace::on_response: finished processing request latency=1 ms status=401
	tracingLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+(.*)$`)
	keyValue    = regexp.MustCompile(`(?:^|[\s{,])([a-z_][a-z0-9_.]*)=("(?:[^"\\]|\\.)*"|[^\s},]+)`)
	// [2026-11-13T10:00:00Z INFO  actix_web::middleware::logger] 203.0.113.77 "POST /auth/login HTTP/1.1" 401 0 "-" "curl/8.5" 0.000123
	envLogger = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (TRACE|DEBUG|INFO|WARN|ERROR)\s+(\S+)\] (.*)$`)
	actixLine = regexp.MustCompile(`^(\S+) "([A-Z]+) (\S+) HTTP/[\d.]+" (\d{3}) (\d+|-) "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"`)
	// 2026/11/13 10:00:00 "POST http://localhost:8080/auth/login HTTP/1.1" from 203.0.113.77:51234 - 401 52B in 1.2ms   (chi)
	chiLine = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) (?:\[\S+\] )?"([A-Z]+) (\S+) HTTP/[\d.]+" from (\S+) - (\d{3}) `)
	// 2026-11-13T10:00:00.123456789Z <line>   (docker logs --timestamps, and kubectl logs --timestamps)
	dockerPrefix = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) (.*)$`)
	// An IPv4 address in a message, also as Node.js writes it (::ffff:203.0.113.77).
	addressInText = regexp.MustCompile(`(?:^|[^0-9A-Za-z.:]|::ffff:)((?:\d{1,3}\.){3}\d{1,3})(?:[^0-9A-Za-z.]|$)`)
	// "Failed login for admin from 203.0.113.77", "Login failed for user admin": the account of a failed login.
	accountInText = regexp.MustCompile(`(?i)\b(?:fail(?:ed|ure)|invalid|denied|refused|wrong)\b.{0,40}?\bfor (?:the )?(?:invalid )?(?:user |account |email )?["']?([^\s"',;]{1,128}?)["']?(?:\s+from\b|[,;]|$)`)
)

var appLines = []appLine{
	{"nestjs", parseNest}, {"gin", parseGin}, {"spring", parseSpring}, {"rails", parseRubyLogger},
	{"laravel", parseLaravel}, {"python", parsePythonDev}, {"uvicorn", parseUvicorn}, {"actix", parseEnvLogger},
	{"tracing", parseTracing}, {"chi", parseChi}, {"rails", parseRailsBare},
}

// parseAppLine reads one line of a framework. A line without its own time gives a zero time; the caller
// decides whether a time from around it (Docker, the journal) can be used.
func parseAppLine(line string, options Options) (map[string]string, time.Time, bool) {
	line = strings.TrimRight(stripANSI(line), "\r\n ")
	for _, format := range appLines {
		if fields, moment, ok := format.parse(line, options); ok {
			if fields[FrameworkField] == "" {
				fields[FrameworkField] = format.name
			}
			return fields, moment, true
		}
	}

	return nil, time.Time{}, false
}

func request(fields map[string]string, method, url, status, source string) {
	fields[event.Category], fields[event.Action] = "webserver", "http_request"
	fields[event.Method], fields[event.URL] = limit(method, maxNameRunes), limit(url, maxValueRunes)
	if status != "" {
		fields[event.Status] = status
	}
	if ip, ok := clientAddress(source); ok {
		fields[event.SourceIP] = ip
	}
}

// clientAddress reads an address that can carry a port ("203.0.113.77:51234", "[2001:db8::1]:443") or be an
// IPv4 address written as IPv6 ("::ffff:203.0.113.77", as Node.js writes it).
func clientAddress(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if address, err := netip.ParseAddr(text); err == nil && address.Zone() == "" {
		return address.Unmap().String(), true
	}
	if pair, err := netip.ParseAddrPort(text); err == nil && pair.Addr().Zone() == "" {
		return pair.Addr().Unmap().String(), true
	}

	return "", false
}

// messageFields keeps the message and, when it names exactly one IPv4 address, that address as the source:
// "Failed login for admin from 203.0.113.77". The field src_ip_from says where the address came from.
func messageFields(fields map[string]string, message string) {
	fields[event.Message] = limit(message, maxValueRunes)
	if fields[event.User] == "" {
		if found := accountInText.FindStringSubmatch(message); found != nil {
			fields[event.User], fields["user_from"] = limit(found[1], maxNameRunes), "message"
		}
	}
	if fields[event.SourceIP] != "" {
		return
	}
	found := addressInText.FindAllStringSubmatch(message, 3)
	if len(found) != 1 {
		return
	}
	if ip, ok := clientAddress(found[0][1]); ok {
		fields[event.SourceIP], fields["src_ip_from"] = ip, "message"
	}
}

func appBase(level string) map[string]string {
	return map[string]string{event.Product: "app", "level": strings.ToLower(level)}
}

func parseNest(line string, options Options) (map[string]string, time.Time, bool) {
	parts := nestLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	layout := "1/2/2006 15:04:05"
	stamp := parts[2] + " " + parts[3]
	if parts[4] != "" {
		layout, stamp = "1/2/2006 3:04:05 PM", stamp+" "+parts[4]
	}
	moment, err := time.ParseInLocation(layout, stamp, options.Location)
	if err != nil {
		return nil, time.Time{}, false
	}
	fields := appBase(parts[5])
	fields["pid"], fields["context"] = parts[1], limit(parts[6], maxNameRunes)
	messageFields(fields, parts[7])

	return fields, moment, true
}

func parseGin(line string, options Options) (map[string]string, time.Time, bool) {
	parts := ginLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	moment, err := time.ParseInLocation("2006/01/02 - 15:04:05", parts[1], options.Location)
	if err != nil {
		return nil, time.Time{}, false
	}
	fields := appBase("info")
	request(fields, parts[5], parts[6], parts[2], parts[4])
	fields["latency"] = limit(parts[3], maxNameRunes)

	return fields, moment, true
}

func parseSpring(line string, options Options) (map[string]string, time.Time, bool) {
	parts := springLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	stamp := strings.Replace(parts[1], " ", "T", 1)
	moment, err := time.Parse("2006-01-02T15:04:05.000Z07:00", stamp)
	if err != nil {
		if moment, err = time.ParseInLocation("2006-01-02T15:04:05.000", stamp, options.Location); err != nil {
			return nil, time.Time{}, false
		}
	}
	fields := appBase(parts[2])
	fields["pid"], fields["thread"], fields["logger"] = parts[3], limit(parts[4], maxNameRunes), limit(parts[5], maxNameRunes)
	messageFields(fields, parts[6])

	return fields, moment, true
}

func parseRubyLogger(line string, options Options) (map[string]string, time.Time, bool) {
	parts := rubyLogger.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	moment, err := time.ParseInLocation("2006-01-02T15:04:05.999999", parts[1], options.Location)
	if err != nil {
		return nil, time.Time{}, false
	}
	fields := rails(parts[4])
	fields["level"], fields["pid"] = strings.ToLower(parts[3]), parts[2]

	return fields, moment, true
}

// parseRailsBare reads the lines that Rails 7.1 and later writes to standard output: no time, only the tags and
// the message. Only the request lines are taken, so that ordinary text is not read as Rails.
func parseRailsBare(line string, _ Options) (map[string]string, time.Time, bool) {
	tagged := railsTags.FindStringSubmatch(line)
	if tagged == nil || !railsStart.MatchString(tagged[2]) && !(tagged[1] != "" && railsDone.MatchString(tagged[2])) {
		return nil, time.Time{}, false
	}

	return rails(line), time.Time{}, true
}

// rails reads the message of a Rails log line. "Started" names the method, the path and the client; "Completed"
// the status. Both carry the request id as a tag, and Omamori joins them by it when the file is read
// (joinRails), so that the end has the method, the path, the client and the status.
func rails(message string) map[string]string {
	fields := appBase("info")
	fields[FrameworkField] = "rails"
	tagged := railsTags.FindStringSubmatch(message)
	text := tagged[2]
	if tags := strings.Fields(strings.NewReplacer("[", " ", "]", " ").Replace(tagged[1])); len(tags) > 0 {
		fields["request_id"] = limit(tags[0], maxNameRunes)
	}
	switch {
	case railsStart.MatchString(text):
		parts := railsStart.FindStringSubmatch(text)
		// The start is a request without a status. Rails writes no end for a path that has no route (a scan for
		// /.env ends with a routing error), so the start is the only line of such a request. Rules that need
		// the status read the end, which is joined to the start (joinRails).
		request(fields, parts[1], parts[2], "", parts[3])
		fields[event.Action] = "http_request_started"
	case railsDone.MatchString(text):
		fields[event.Action], fields[event.Status] = "http_request_completed", railsDone.FindStringSubmatch(text)[1]
	}
	messageFields(fields, text)

	return fields
}

func parseLaravel(line string, options Options) (map[string]string, time.Time, bool) {
	parts := laravelLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	stamp := strings.Replace(parts[1], "T", " ", 1)
	moment, err := time.Parse("2006-01-02 15:04:05.999999Z07:00", stamp)
	if err != nil {
		if moment, err = time.ParseInLocation("2006-01-02 15:04:05.999999", stamp, options.Location); err != nil {
			return nil, time.Time{}, false
		}
	}
	fields := appBase(parts[3])
	fields["environment"] = limit(parts[2], maxNameRunes)
	message := parts[4]
	// The context is a JSON object after the message. Its address and user are kept.
	if start := strings.Index(message, " {"); start >= 0 {
		var context map[string]any
		decoder := json.NewDecoder(strings.NewReader(strings.TrimSuffix(strings.TrimSpace(message[start+1:]), " []")))
		decoder.UseNumber()
		if decoder.Decode(&context) == nil {
			flat := map[string]string{}
			flatten("", context, flat, 0)
			appFields(flat)
			for _, name := range []string{event.SourceIP, event.User} {
				if flat[name] != "" {
					fields[name] = flat[name]
				}
			}
			message = message[:start]
		}
	}
	messageFields(fields, message)

	return fields, moment, true
}

func parsePythonDev(line string, options Options) (map[string]string, time.Time, bool) {
	parts := pythonDevLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	moment, err := time.ParseInLocation("02/Jan/2006 15:04:05", parts[2], options.Location)
	if err != nil {
		return nil, time.Time{}, false
	}
	fields := appBase("info")
	request(fields, parts[3], parts[4], parts[5], parts[1])
	if parts[6] != "-" {
		fields[event.Bytes] = parts[6]
	}
	fields[FrameworkField] = "django"
	if parts[1] != "" {
		fields[FrameworkField] = "flask"
	}

	return fields, moment, true
}

func parseUvicorn(line string, _ Options) (map[string]string, time.Time, bool) {
	parts := uvicornLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	fields := appBase("info")
	request(fields, parts[3], parts[4], parts[5], parts[1])

	return fields, time.Time{}, true
}

func parseTracing(line string, _ Options) (map[string]string, time.Time, bool) {
	parts := tracingLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	moment, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil {
		return nil, time.Time{}, false
	}
	fields := appBase(parts[2])
	values := map[string]string{}
	for _, pair := range keyValue.FindAllStringSubmatch(parts[3], 50) {
		if _, seen := values[pair[1]]; !seen {
			values[pair[1]] = strings.Trim(pair[2], `"`)
		}
	}
	// tower-http writes the request in a span and the status on the line that ends it. Only the end is a request.
	if values["status"] != "" && values["method"] != "" && (values["uri"] != "" || values["path"] != "") {
		url := values["uri"]
		if url == "" {
			url = values["path"]
		}
		source := values["client_ip"]
		if source == "" {
			source = values["remote_addr"]
		}
		request(fields, values["method"], url, values["status"], source)
	}
	messageFields(fields, parts[3])

	return fields, moment, true
}

func parseEnvLogger(line string, _ Options) (map[string]string, time.Time, bool) {
	parts := envLogger.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	moment, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil {
		return nil, time.Time{}, false
	}
	fields := appBase(parts[2])
	fields["logger"] = limit(parts[3], maxNameRunes)
	if access := actixLine.FindStringSubmatch(parts[4]); access != nil {
		request(fields, access[2], access[3], access[4], access[1])
		if access[7] != "" && access[7] != "-" {
			fields[event.UserAgent] = limit(access[7], maxValueRunes)
		}
	}
	messageFields(fields, parts[4])

	return fields, moment, true
}

func parseChi(line string, options Options) (map[string]string, time.Time, bool) {
	parts := chiLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	moment, err := time.ParseInLocation("2006/01/02 15:04:05", parts[1], options.Location)
	if err != nil {
		return nil, time.Time{}, false
	}
	url := parts[3]
	// chi writes the whole address of the request. The path and the query are what the rules read.
	if index := strings.Index(url, "://"); index >= 0 {
		if slash := strings.Index(url[index+3:], "/"); slash >= 0 {
			url = url[index+3+slash:]
		} else {
			url = "/"
		}
	}
	fields := appBase("info")
	request(fields, parts[2], url, parts[5], parts[4])
	fields[FrameworkField] = "chi"

	return fields, moment, true
}

// appKeys are the names under which the JSON loggers of the frameworks write a request: pino (NestJS and
// Fastify), winston, Go slog, zap, zerolog and logrus, Echo, Serilog and the JSON console of ASP.NET Core,
// Spring Boot (ECS and Logstash), Rails lograge, Django and Python structlog, and Google Cloud.
var appKeys = []struct {
	field string
	names []string
}{
	{event.Method, []string{"req.method", "request.method", "http.request.method", "http.method", "httpRequest.requestMethod", "RequestMethod", "http_method", "request_method", "method"}},
	{event.URL, []string{"req.url", "request.url", "request.uri", "request.path", "url.original", "url.path", "http.target", "http.url", "httpRequest.requestUrl", "RequestPath", "request_uri", "uri", "path", "url"}},
	{event.Status, []string{"res.statusCode", "response.statusCode", "response.status", "http.response.status_code", "http.status_code", "httpRequest.status", "StatusCode", "status_code", "statusCode", "status"}},
	{event.SourceIP, []string{"req.remoteAddress", "req.ip", "request.remote_ip", "client.ip", "source.ip", "http.client_ip", "httpRequest.remoteIp", "RemoteIpAddress", "remote_ip", "remoteAddress", "remoteAddr", "remote_addr", "client_ip", "clientIp", "peer.address", "ip"}},
	{event.UserAgent, []string{"req.headers.user-agent", "request.headers.user-agent", "http.request.headers.user_agent", "user_agent.original", "http.user_agent", "httpRequest.userAgent", "headers.user-agent", "userAgent", "user_agent"}},
	{event.User, []string{"user.name", "user.email", "user.id", "userName", "userId", "user_id", "username", "email", "user"}},
	{event.Message, []string{"msg", "message", "@m", "@mt", "Message", "MessageTemplate"}},
	{"level", []string{"level", "severity", "@l", "LogLevel", "log.level", "levelname"}},
}

var forwardedKeys = []string{"req.headers.x-forwarded-for", "request.headers.x-forwarded-for", "http.request.headers.x_forwarded_for", "headers.x-forwarded-for", "x_forwarded_for", "forwarded_for"}

var pinoLevels = map[string]string{"10": "trace", "20": "debug", "30": "info", "40": "warn", "50": "error", "60": "fatal"}

// appFields adds the shared fields to a flattened JSON line of an application, from the names that its logger
// uses. The original names stay. A line that names a method, a path and a status is a request.
func appFields(fields map[string]string) {
	// A name that event.Canonical already turned into src_ip (remote_addr) can still carry a port.
	if text := fields[event.SourceIP]; text != "" {
		if ip, ok := clientAddress(text); ok {
			fields[event.SourceIP] = ip
		} else {
			delete(fields, event.SourceIP)
		}
	}
	// Loggers differ in case: Serilog writes User and StatusCode, others user and status_code.
	lowered := make(map[string]string, len(fields))
	for name, value := range fields {
		if _, taken := lowered[strings.ToLower(name)]; !taken {
			lowered[strings.ToLower(name)] = value
		}
	}
	for _, key := range appKeys {
		if fields[key.field] != "" && key.field != event.SourceIP {
			continue
		}
		for _, name := range key.names {
			value := strings.TrimSpace(lowered[strings.ToLower(name)])
			if value == "" {
				continue
			}
			if key.field == event.SourceIP {
				ip, ok := clientAddress(value)
				if !ok {
					continue
				}
				value = ip
			}
			fields[key.field] = limit(value, maxValueRunes)
			break
		}
	}
	if level, found := pinoLevels[fields["level"]]; found {
		fields["level"] = level
	}
	fields["level"] = strings.ToLower(fields["level"])
	if fields["level"] == "" {
		delete(fields, "level")
	}
	// Behind a proxy (nginx in front of the application), the application sees the proxy. The first address
	// of X-Forwarded-For is the client as the proxy saw it, and it is taken only when the direct peer is the
	// machine itself or a private address. Anyone can write the header, so the peer is kept as proxy_ip.
	if peer, err := netip.ParseAddr(fields[event.SourceIP]); err != nil || peer.IsLoopback() || peer.IsPrivate() {
		for _, name := range forwardedKeys {
			first, _, _ := strings.Cut(fields[name], ",")
			if ip, ok := clientAddress(first); ok {
				if fields[event.SourceIP] != "" {
					fields["proxy_ip"] = fields[event.SourceIP]
				}
				fields[event.SourceIP], fields["src_ip_from"] = ip, "x-forwarded-for"
				break
			}
		}
	}
	// A JSON line that no other reader claimed and that carries a message or a request is the log of an
	// application, so the rules for applications read it.
	if fields[event.Product] == "" && (fields[event.Message] != "" || fields[event.Method] != "") {
		fields[event.Product] = "app"
	}
	if fields[event.Method] != "" && fields[event.URL] != "" && validStatus(fields[event.Status]) {
		if fields[event.Category] == "" {
			fields[event.Category] = "webserver"
		}
		if fields[event.Action] == "" {
			fields[event.Action] = "http_request"
		}
		fields[event.Method] = strings.ToUpper(fields[event.Method])
	} else if fields[event.Message] != "" && (fields[event.SourceIP] == "" || fields[event.User] == "") {
		messageFields(fields, fields[event.Message])
	}
}

func validStatus(text string) bool {
	number, err := strconv.Atoi(text)

	return err == nil && number >= 100 && number <= 599
}
