package lab

import (
	"fmt"
	"sort"
	"strings"
)

// Where says which run must find a check: the forensic triage of web01 (its logs and files), or the detection
// over the capture of its traffic.
const (
	FromSystem  = "system"
	FromCapture = "capture"
)

// Check is one thing that the attack does and the rule that must find it.
type Check struct {
	Stage string
	What  string
	Rule  string
	From  string
}

// Checks are the detections that one run of the attack must give. A rule that is not here can fire too, and
// is listed as more; an alert is a lead, and the lab does not count more alerts as a fault.
var Checks = []Check{
	{"scan", "ports 1 to 200 of web01 tried and refused", "net_port_scan", FromCapture},
	{"web", "scan for sensitive files (in the access log)", "web_sensitive_scan", FromSystem},
	{"web", "many pages that are not there (in the access log)", "web_path_enumeration", FromSystem},
	{"web", "SQL injection and path traversal (in the access log)", "web_injection_attempt", FromSystem},
	{"web", "a known scanner tool (in the access log)", "web_scanner_tool", FromSystem},
	{"web", "SQL injection and path traversal (in the capture)", "web_injection_attempt", FromCapture},
	{"web", "a known scanner tool (in the capture)", "web_scanner_tool", FromCapture},
	{"spray", "one password for many accounts", "ssh_password_spray", FromSystem},
	{"guess", "many passwords of alice", "ssh_brute_force", FromSystem},
	{"guess", "a login after the guessing", "ssh_brute_force_success", FromSystem},
	{"persist", "sudo refused for alice", "linux_sudo_refused", FromSystem},
	{"persist", "a cron job that downloads and runs a script (crontab)", "forensics_cron_download_exec", FromSystem},
	{"persist", "the same job when cron runs it (syslog)", "linux_cron_download_exec", FromSystem},
	{"persist", "a download piped into a shell in the history", "forensics_history_download_exec", FromSystem},
	{"persist", "a key added after a password login", "forensics_key_after_password_login", FromSystem},
	{"tools", "a dropper in /tmp", "file_download_and_run", FromSystem},
	{"tools", "the dropper adds a key", "file_ssh_key_planting", FromSystem},
	{"tools", "the dropper turns the history off", "file_log_wiping", FromSystem},
	{"tools", "a program in /dev/shm", "file_program_in_temp", FromSystem},
	{"tools", "a miner config in /dev/shm", "file_coin_miner", FromSystem},
	{"tools", "a reverse shell in /var/tmp", "file_reverse_shell", FromSystem},
	{"tools", "a PHP web shell in an upload folder", "file_web_shell", FromSystem},
	{"tools", "a command sent to the web shell (access log)", "web_shell_command", FromSystem},
	{"tools", "a command sent to the web shell (capture)", "web_shell_command", FromCapture},
}

// Score compares the rules that fired in each run with the checks.
type Score struct {
	Found  []Check
	Missed []Check
	// More are rules that fired and are not a check, with the run that gave them.
	More []string
}

func Grade(system, capture map[string]int) Score {
	var score Score
	expected := map[string]bool{}
	for _, check := range Checks {
		fired := system
		if check.From == FromCapture {
			fired = capture
		}
		expected[check.From+"/"+check.Rule] = true
		if fired[check.Rule] > 0 {
			score.Found = append(score.Found, check)
		} else {
			score.Missed = append(score.Missed, check)
		}
	}
	for from, fired := range map[string]map[string]int{FromSystem: system, FromCapture: capture} {
		for rule, count := range fired {
			if !expected[from+"/"+rule] && count > 0 {
				score.More = append(score.More, fmt.Sprintf("%s (%s, %d)", rule, from, count))
			}
		}
	}
	sort.Strings(score.More)

	return score
}

// Markdown writes the score as a table, one line for each check.
func (score Score) Markdown() string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Omamori lab\n\nFound %d of %d expected detections.\n\n", len(score.Found), len(score.Found)+len(score.Missed))
	out.WriteString("| Stage | What the attack did | Rule | Read from | Found |\n|---|---|---|---|---|\n")
	missed := map[Check]bool{}
	for _, check := range score.Missed {
		missed[check] = true
	}
	for _, check := range Checks {
		mark := "yes"
		if missed[check] {
			mark = "**no**"
		}
		fmt.Fprintf(&out, "| %s | %s | `%s` | %s | %s |\n", check.Stage, check.What, check.Rule, check.From, mark)
	}
	if len(score.More) > 0 {
		out.WriteString("\nAlso fired (not a check of the lab; the lab network uses private addresses, so rules for internal movement fire too):\n\n")
		for _, more := range score.More {
			fmt.Fprintf(&out, "- %s\n", more)
		}
	}
	out.WriteString("\nThe lab attacked only its own container web01, on a Docker network with no way out. " +
		"A missed check means that Omamori did not find a step of a real attack on a real Debian server: read the reports of the run to see why.\n")

	return out.String()
}
