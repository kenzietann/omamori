package forensics

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/intake"
)

func lines(data []byte, stats *intake.Stats, each func(number int, line string)) {
	text := string(data)
	for number := 1; text != "" && number <= maxLinesPerFile; number++ {
		line, rest, _ := strings.Cut(text, "\n")
		text = rest
		line = strings.TrimSuffix(line, "\r")
		stats.Lines++
		switch {
		case !utf8.ValidString(line) || strings.ContainsRune(line, 0):
			stats.Malformed++
		case strings.TrimSpace(line) == "":
			stats.Blank++
		default:
			each(number, line)
		}
	}
}

func (c *collector) parse(kind, name string, data []byte, modified time.Time, stats *intake.Stats) {
	switch kind {
	case KindCron:
		c.cron(name, data, modified, stats)
	case KindCronJob:
		stats.Lines = strings.Count(string(data), "\n")
		c.add(kind, name, 0, modified, TimeFileChange, map[string]string{event.Action: "cron_script", "file": name})
	case KindHistory:
		c.history(name, data, modified, stats)
	case KindUnit:
		c.unit(name, data, modified, stats)
	case KindKeys:
		c.keys(name, data, modified, stats)
	case KindAccounts:
		c.accounts(name, data, modified, stats)
	case KindProcesses:
		c.processes(name, data, modified, stats)
	case KindSockets:
		c.sockets(name, data, modified, stats)
	}
}

var (
	cronSchedule = regexp.MustCompile(`^(@[a-z]+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$`)
	cronUser     = regexp.MustCompile(`^(\S+)\s+(.+)$`)
	cronSetting  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)
)

// cron reads a crontab. The files of the system (/etc/crontab, /etc/cron.d) name the user before the command.
// The files of users (/var/spool/cron) do not: the name of the file is the user.
func (c *collector) cron(name string, data []byte, modified time.Time, stats *intake.Stats) {
	system := strings.HasPrefix(name, "etc/")
	lines(data, stats, func(number int, line string) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || cronSetting.MatchString(line) {
			stats.Blank++
			return
		}
		parts := cronSchedule.FindStringSubmatch(line)
		if parts == nil {
			stats.Malformed++
			return
		}
		user, command := owner(name), parts[2]
		if system {
			named := cronUser.FindStringSubmatch(command)
			if named == nil {
				stats.Malformed++
				return
			}
			user, command = named[1], named[2]
		}
		c.add(KindCron, name, number, modified, TimeFileChange, map[string]string{
			event.Action: "cron_entry", event.User: tidy(user, maxNameRunes), event.Command: strings.TrimSpace(command), "schedule": parts[1],
		})
	})
}

var (
	zshStamp  = regexp.MustCompile(`^: (\d{9,11}):\d+;(.*)$`)
	bashStamp = regexp.MustCompile(`^#(\d{9,11})$`)
)

// history reads the history of bash or zsh. A time is in the file only when the shell was set to write it.
// Without it, the only time is the last change of the file, which is the time of the last command at best.
func (c *collector) history(name string, data []byte, modified time.Time, stats *intake.Stats) {
	user := owner(name)
	var stamp time.Time
	lines(data, stats, func(number int, line string) {
		when, source, command := modified, TimeFileChange, line
		if parts := bashStamp.FindStringSubmatch(line); parts != nil {
			seconds, _ := strconv.ParseInt(parts[1], 10, 64)
			stamp = time.Unix(seconds, 0)
			stats.Blank++
			return
		}
		if parts := zshStamp.FindStringSubmatch(line); parts != nil {
			seconds, _ := strconv.ParseInt(parts[1], 10, 64)
			when, source, command = time.Unix(seconds, 0), TimeRecorded, parts[2]
		} else if !stamp.IsZero() {
			when, source = stamp, TimeRecorded
		}
		stamp = time.Time{}
		c.add(KindHistory, name, number, when, source, map[string]string{event.Action: "history_command", event.User: user, event.Command: command})
	})
}

func (c *collector) unit(name string, data []byte, modified time.Time, stats *intake.Stats) {
	unit := name[strings.LastIndex(name, "/")+1:]
	runAs := "root"
	if strings.Contains(name, "/.config/systemd/user/") {
		runAs = owner(name)
	}
	type start struct {
		line         int
		key, command string
	}
	var starts []start
	description := ""
	lines(data, stats, func(number int, line string) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			stats.Blank++
			return
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			stats.Malformed++
			return
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "User" && value != "":
			runAs = tidy(value, maxNameRunes)
		case key == "Description":
			description = value
		case strings.HasPrefix(key, "ExecStart") || strings.HasPrefix(key, "ExecStop") || key == "ExecReload":
			starts = append(starts, start{number, key, strings.TrimLeft(value, "-@+!:")})
		}
	})
	for _, found := range starts {
		c.add(KindUnit, name, found.line, modified, TimeFileChange, map[string]string{
			event.Action: "unit_exec", "unit": unit, event.User: runAs, event.Command: found.command, "exec_key": found.key, "description": description,
		})
	}
}

var keyTypes = map[string]bool{
	"ssh-ed25519": true, "ssh-rsa": true, "ssh-dss": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

func (c *collector) keys(name string, data []byte, modified time.Time, stats *intake.Stats) {
	user := owner(name)
	lines(data, stats, func(number int, line string) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			stats.Blank++
			return
		}
		fields := strings.Fields(line)
		at := -1
		var blob []byte
		for index := 0; index+1 < len(fields) && at < 0; index++ {
			if !keyTypes[fields[index]] {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(fields[index+1])
			if err == nil && keyOfType(decoded, fields[index]) {
				at, blob = index, decoded
			}
		}
		if at < 0 {
			stats.Malformed++
			return
		}
		sum := sha256.Sum256(blob)
		options := strings.Join(fields[:at], " ")
		made := map[string]string{
			event.Action: "authorized_key", event.User: user, "key_type": fields[at],
			"fingerprint": "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), "key_comment": strings.Join(fields[at+2:], " "),
		}
		if options != "" {
			made["key_options"] = options
		}
		c.add(KindKeys, name, number, modified, TimeFileChange, made)
	})
}

func keyOfType(blob []byte, keyType string) bool {
	size := len(keyType)
	if len(blob) < 4+size+4 || blob[0] != 0 || blob[1] != 0 || blob[2] != 0 || int(blob[3]) != size {
		return false
	}

	return string(blob[4:4+size]) == keyType
}

// accounts reads /etc/passwd. The file with the password hashes (/etc/shadow) is never read.
func (c *collector) accounts(name string, data []byte, modified time.Time, stats *intake.Stats) {
	lines(data, stats, func(number int, line string) {
		if strings.HasPrefix(line, "#") {
			stats.Blank++
			return
		}
		parts := strings.Split(line, ":")
		if len(parts) != 7 || parts[0] == "" {
			stats.Malformed++
			return
		}
		uid, uidErr := strconv.ParseUint(parts[2], 10, 32)
		gid, gidErr := strconv.ParseUint(parts[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			stats.Malformed++
			return
		}
		login := "true"
		if shell := parts[6]; shell == "" || strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") || strings.HasSuffix(shell, "/sync") {
			login = "false"
		}
		c.add(KindAccounts, name, number, modified, TimeFileChange, map[string]string{
			event.Action: "account", event.User: tidy(parts[0], maxNameRunes), "uid": strconv.FormatUint(uid, 10), "gid": strconv.FormatUint(gid, 10),
			"home": parts[5], "shell": parts[6], "can_login": login,
		})
	})
}

func (c *collector) processes(name string, data []byte, modified time.Time, stats *intake.Stats) {
	columns := -1
	userAt, pidAt := -1, -1
	lines(data, stats, func(number int, line string) {
		fields := strings.Fields(line)
		if columns < 0 {
			for index, field := range fields {
				switch field {
				case "USER", "UID":
					userAt = index
				case "PID":
					pidAt = index
				case "COMMAND", "CMD":
					columns = index
				}
			}
			if columns < 0 || userAt < 0 || pidAt < 0 || userAt > columns || pidAt > columns {
				columns = -2
				stats.Malformed++
			} else {
				stats.Blank++
			}
			return
		}
		if columns == -2 || len(fields) <= columns {
			stats.Malformed++
			return
		}
		if _, err := strconv.ParseUint(fields[pidAt], 10, 32); err != nil {
			stats.Malformed++
			return
		}
		command := strings.Join(fields[columns:], " ")
		c.add(KindProcesses, name, number, modified, TimeFileChange, map[string]string{
			event.Action: "process", event.User: tidy(fields[userAt], maxNameRunes), "pid": fields[pidAt], event.Command: command, event.Process: fields[columns],
		})
	})
}

var (
	ssProcess      = regexp.MustCompile(`users:\(\("([^"]{1,64})",pid=(\d{1,10})`)
	netstatProcess = regexp.MustCompile(`^(\d{1,10})/(\S{1,64})`)
)

func (c *collector) sockets(name string, data []byte, modified time.Time, stats *intake.Stats) {
	lines(data, stats, func(number int, line string) {
		fields := strings.Fields(line)
		if len(fields) < 5 || !(strings.HasPrefix(fields[0], "tcp") || strings.HasPrefix(fields[0], "udp")) {
			stats.Blank++
			return
		}
		made := map[string]string{event.Action: "listening_socket", event.Protocol: strings.TrimRight(fields[0], "46")}
		local := ""
		if strings.EqualFold(fields[1], "LISTEN") || strings.EqualFold(fields[1], "UNCONN") {
			local = fields[4]
			if parts := ssProcess.FindStringSubmatch(line); parts != nil {
				made[event.Process], made["pid"] = parts[1], parts[2]
			}
		} else {
			local = fields[3]
			for _, field := range fields[4:] {
				if parts := netstatProcess.FindStringSubmatch(field); parts != nil {
					made["pid"], made[event.Process] = parts[1], parts[2]
					break
				}
			}
		}
		separator := strings.LastIndex(local, ":")
		if separator < 0 {
			stats.Malformed++
			return
		}
		port, err := strconv.ParseUint(local[separator+1:], 10, 16)
		if err != nil {
			stats.Malformed++
			return
		}
		made["local_address"], made["local_port"] = strings.Trim(local[:separator], "[]"), strconv.FormatUint(port, 10)
		c.add(KindSockets, name, number, modified, TimeFileChange, made)
	})
}
