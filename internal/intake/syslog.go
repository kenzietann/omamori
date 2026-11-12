package intake

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

var (
	classicHeader = regexp.MustCompile(`^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) ([A-Za-z0-9_./()-]+?)(?:\[\d+\])?: ?(.*)$`)
	isoHeader     = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:?\d{2})) (\S+) ([A-Za-z0-9_./()-]+?)(?:\[\d+\])?: ?(.*)$`)

	sshFailed    = regexp.MustCompile(`^Failed (password|publickey|keyboard-interactive/pam|none) for (invalid user )?(.*) from (\S+) port \d{1,5}(?: ssh2)?(?:: .*)?$`)
	sshAccepted  = regexp.MustCompile(`^Accepted (password|publickey|keyboard-interactive/pam|gssapi-with-mic|hostbased) for (.*) from (\S+) port \d{1,5}(?: ssh2)?(?:: .*)?$`)
	sshInvalid   = regexp.MustCompile(`^Invalid user (.*) from (\S+)(?: port \d{1,5})?$`)
	sshMaxTries  = regexp.MustCompile(`^(?:error: )?maximum authentication attempts exceeded for (invalid user )?(.*) from (\S+) port \d{1,5}(?: ssh2)?(?: \[preauth\])?$`)
	sudoLine     = regexp.MustCompile(`^\s*(\S+) : (.*)$`)
	userAdded    = regexp.MustCompile(`^new user: name=([^,\s]+)`)
	groupAdded   = regexp.MustCompile(`^add '([^']+)' to (?:shadow )?group '([^']+)'$`)
	cronLine     = regexp.MustCompile(`^\(([^)]+)\) (CMD|REPLACE|BEGIN EDIT|END EDIT|DELETE|LIST) \((.*)\)$`)
	suFailed     = regexp.MustCompile(`^FAILED SU \(to (\S+)\) (\S+) on \S+$`)
	suSucceeded  = regexp.MustCompile(`^\(to (\S+)\) (\S+) on \S+$`)
	syslogMonths = map[string]time.Month{
		"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April, "May": time.May, "Jun": time.June,
		"Jul": time.July, "Aug": time.August, "Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December,
	}
)

// newSyslogParser gives a parser for one file. It remembers the last time, because the classic format has no
// year: when the month jumps back from December to January, the year goes up by one.
func newSyslogParser(options Options) lineParser {
	year := options.Year
	var previous time.Time

	return func(line string) (map[string]string, time.Time, bool) {
		var moment time.Time
		var host, program, message string

		if parts := isoHeader.FindStringSubmatch(line); parts != nil {
			parsed, err := time.Parse(time.RFC3339Nano, normalizeZone(parts[1]))
			if err != nil {
				return nil, time.Time{}, false
			}
			moment, host, program, message = parsed, parts[2], parts[3], parts[4]
		} else if parts := classicHeader.FindStringSubmatch(line); parts != nil {
			month, known := syslogMonths[parts[1]]
			clock, err := time.Parse("15:04:05", parts[3])
			day := atoi(parts[2])
			if !known || err != nil {
				return nil, time.Time{}, false
			}
			candidateYear := year
			moment = time.Date(candidateYear, month, day, clock.Hour(), clock.Minute(), clock.Second(), 0, options.Location)
			if !previous.IsZero() && previous.Sub(moment) > 180*24*time.Hour {
				candidateYear++
				moment = time.Date(candidateYear, month, day, clock.Hour(), clock.Minute(), clock.Second(), 0, options.Location)
			}
			if moment.Day() != day || moment.Month() != month {
				return nil, time.Time{}, false
			}
			year = candidateYear
			previous = moment
			host, program, message = parts[4], parts[5], parts[6]
		} else {
			return nil, time.Time{}, false
		}

		service := serviceName(program)
		fields := map[string]string{
			event.Product: "linux", event.Service: service, event.Host: limit(host, 255),
			event.Process: limit(program, maxNameRunes), event.Message: limit(message, maxValueRunes),
		}
		message = strings.TrimRight(message, " ")
		switch service {
		case "sshd":
			sshFields(message, fields)
		case "sudo":
			sudoFields(message, fields)
		case "cron", "crontab":
			cronFields(message, fields)
		case "useradd":
			if parts := userAdded.FindStringSubmatch(message); parts != nil {
				fields[event.Action], fields[event.User] = "user_created", limit(parts[1], maxNameRunes)
			}
		case "usermod", "gpasswd":
			if parts := groupAdded.FindStringSubmatch(message); parts != nil {
				fields[event.Action], fields[event.User], fields["group"] = "group_add", limit(parts[1], maxNameRunes), limit(parts[2], maxNameRunes)
			}
		case "su":
			if parts := suFailed.FindStringSubmatch(message); parts != nil {
				fields[event.Action], fields[event.Outcome], fields["target_user"], fields[event.User] = "su", "failure", limit(parts[1], maxNameRunes), limit(parts[2], maxNameRunes)
			} else if parts := suSucceeded.FindStringSubmatch(message); parts != nil {
				fields[event.Action], fields[event.Outcome], fields["target_user"], fields[event.User] = "su", "success", limit(parts[1], maxNameRunes), limit(parts[2], maxNameRunes)
			}
		}

		return fields, moment, true
	}
}

func normalizeZone(stamp string) string {
	if length := len(stamp); length > 5 && (stamp[length-5] == '+' || stamp[length-5] == '-') {
		return stamp[:length-2] + ":" + stamp[length-2:]
	}

	return stamp
}

func serviceName(program string) string {
	name := strings.ToLower(program)
	if slash := strings.LastIndex(name, "/"); slash >= 0 && slash < len(name)-1 {
		name = name[slash+1:]
	}
	switch name {
	case "crond", "cron", "anacron":
		return "cron"
	case "sshd-session", "sshd-auth":
		return "sshd"
	}

	return name
}

func address(text string) (string, bool) {
	parsed, err := netip.ParseAddr(text)
	if err != nil {
		return "", false
	}

	return parsed.Unmap().WithZone("").String(), true
}

func sshFields(message string, fields map[string]string) {
	login := func(outcome, method, user, from string, invalid bool) {
		ip, valid := address(from)
		if !valid {
			return
		}
		fields[event.Action], fields[event.Outcome], fields[event.AuthBy] = "login", outcome, method
		fields[event.User], fields[event.SourceIP] = limit(user, maxNameRunes), ip
		if invalid {
			fields["user_known"] = "false"
		}
	}

	if parts := sshFailed.FindStringSubmatch(message); parts != nil {
		login("failure", parts[1], parts[3], parts[4], parts[2] != "")
	} else if parts := sshAccepted.FindStringSubmatch(message); parts != nil {
		login("success", parts[1], parts[2], parts[3], false)
	} else if parts := sshMaxTries.FindStringSubmatch(message); parts != nil {
		if ip, valid := address(parts[3]); valid {
			fields[event.Action], fields[event.Outcome] = "max_auth_attempts", "failure"
			fields[event.User], fields[event.SourceIP] = limit(parts[2], maxNameRunes), ip
		}
	} else if parts := sshInvalid.FindStringSubmatch(message); parts != nil {
		if ip, valid := address(parts[2]); valid {
			fields[event.Action], fields[event.User], fields[event.SourceIP] = "invalid_user", limit(parts[1], maxNameRunes), ip
		}
	}
}

func sudoFields(message string, fields map[string]string) {
	parts := sudoLine.FindStringSubmatch(message)
	if parts == nil || !strings.Contains(parts[2], "COMMAND=") {
		return
	}

	fields[event.Action], fields[event.User], fields[event.Outcome] = "sudo", limit(parts[1], maxNameRunes), "success"
	settings, command, _ := strings.Cut(parts[2], "COMMAND=")
	fields[event.Command] = limit(command, maxValueRunes)
	for _, part := range strings.Split(settings, " ; ") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "USER="):
			fields["target_user"] = limit(strings.TrimPrefix(part, "USER="), maxNameRunes)
		case strings.HasPrefix(part, "PWD="):
			fields["directory"] = limit(strings.TrimPrefix(part, "PWD="), maxValueRunes)
		case part == "user NOT in sudoers", part == "command not allowed", strings.HasSuffix(part, "incorrect password attempts"), strings.HasSuffix(part, "incorrect password attempt"):
			fields[event.Outcome], fields["reason"] = "failure", part
		}
	}
}

func cronFields(message string, fields map[string]string) {
	parts := cronLine.FindStringSubmatch(message)
	if parts == nil {
		return
	}
	fields[event.User] = limit(parts[1], maxNameRunes)
	if parts[2] == "CMD" {
		fields[event.Action], fields[event.Command] = "cron_run", limit(parts[3], maxValueRunes)
	} else {
		fields[event.Action], fields["cron_change"] = "cron_edit", parts[2]
	}
}

func atoi(text string) int {
	value := 0
	for _, digit := range text {
		value = value*10 + int(digit-'0')
	}

	return value
}
