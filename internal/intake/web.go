package intake

import (
	"regexp"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

// The combined log format of nginx and Apache, and the common format (without referrer and user agent):
//
//	203.0.113.77 - - [10/Nov/2026:08:15:02 +0900] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
var webLine = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]{20,40})\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`)

func parseWebLine(line string) (map[string]string, time.Time, bool) {
	parts := webLine.FindStringSubmatch(line)
	if parts == nil {
		return nil, time.Time{}, false
	}
	ip, valid := address(parts[1])
	if !valid {
		return nil, time.Time{}, false
	}
	moment, err := time.Parse("02/Jan/2006:15:04:05 -0700", parts[3])
	if err != nil {
		return nil, time.Time{}, false
	}

	fields := map[string]string{
		event.Category: "webserver", event.SourceIP: ip, event.Status: parts[5],
		event.Message: limit(parts[4], maxValueRunes),
	}
	// A request that is not "METHOD address PROTOCOL" (a TLS hello on a plain port, for example) keeps its text as the address.
	if request := strings.Split(parts[4], " "); len(request) == 3 && strings.HasPrefix(request[2], "HTTP/") {
		fields[event.Method], fields[event.URL] = limit(request[0], maxNameRunes), limit(request[1], maxValueRunes)
	} else {
		fields[event.URL] = limit(parts[4], maxValueRunes)
	}
	if parts[2] != "-" {
		fields[event.User] = limit(parts[2], maxNameRunes)
	}
	if parts[6] != "-" {
		fields[event.Bytes] = parts[6]
	}
	if parts[7] != "" && parts[7] != "-" {
		fields[event.Referrer] = limit(parts[7], maxValueRunes)
	}
	if parts[8] != "" && parts[8] != "-" {
		fields[event.UserAgent] = limit(parts[8], maxValueRunes)
	}

	return fields, moment, true
}
