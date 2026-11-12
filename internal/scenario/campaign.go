package scenario

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// Addresses of the made-up network of the campaign. The servers have private addresses, the people work
// from the office (a public documentation range), and the attackers are in another documentation range.
const (
	WebAddress     = "10.0.1.10"
	AppAddress     = "10.0.2.20"
	DataAddress    = "10.0.2.30"
	monitorAddress = "10.0.9.5"
	backupAddress  = "10.0.9.6"
	dropAddress    = "203.0.113.80"
)

// Campaign is one attack that moves through three servers, seen by five kinds of logs:
//
//	web01/auth.log, web01/access.log   the server at the edge (the same day as Generate makes)
//	app01/auth.log, db01/auth.log      the two servers behind it
//	sensor/conn.log                    Zeek connection log (JSON lines)
//	sensor/eve.json                    Suricata alerts (JSON lines)
//
// The story: an address guesses the password of root on web01 and stays there. From web01 it looks for
// other hosts, guesses the password of deploy on app01 and logs in. With a key that it finds there it logs
// in to db01, and from db01 a large amount of data goes to an address outside.
//
// With attacks false, the same network has an ordinary day, with the things that look like the attack and
// are not: a monitoring host that connects to everything, a person who goes from web01 to app01 and types
// a wrong password, a backup of 3 GB to an internal address, and a host that keeps trying an address that is gone.
func GenerateCampaign(seed int64, day time.Time, attacks bool) Host {
	edge := Generate(seed, day, attacks)
	random := rand.New(rand.NewSource(seed + 104729))
	evening := day.Add(23*time.Hour + 30*time.Minute)
	at := func(hour, minute, second int) time.Time {
		return day.Add(time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute + time.Duration(second)*time.Second)
	}

	logs := map[string][]entry{}
	pid := 0
	syslog := func(file, host string, when time.Time, program, message string) {
		pid++
		logs[file] = append(logs[file], entry{when, fmt.Sprintf("%s %s %s[%d]: %s", when.Format("Jan _2 15:04:05"), host, program, 2000+pid%30000, message)})
	}
	port := func() int { return 30000 + random.Intn(30000) }
	connections := 0
	conn := func(when time.Time, from, to string, toPort int, state, service string, sent, received int64) {
		connections++
		logs["sensor/conn.log"] = append(logs["sensor/conn.log"], entry{when, fmt.Sprintf(
			`{"ts":%d.%06d,"uid":"C%07dsynth","id.orig_h":"%s","id.orig_p":%d,"id.resp_h":"%s","id.resp_p":%d,"proto":"tcp","service":"%s","conn_state":"%s","orig_bytes":%d,"resp_bytes":%d}`,
			when.Unix(), random.Intn(1000000), connections, from, port(), to, toPort, service, state, sent, received)})
	}
	sensor := func(when time.Time, from, to string, toPort, severity int, signature string) {
		connections++
		logs["sensor/eve.json"] = append(logs["sensor/eve.json"], entry{when, fmt.Sprintf(
			`{"timestamp":"%s","event_type":"alert","flow_id":%d,"src_ip":"%s","src_port":%d,"dest_ip":"%s","dest_port":%d,"proto":"TCP","alert":{"action":"allowed","signature_id":%d,"signature":"%s","category":"Synthetic","severity":%d}}`,
			when.Format("2006-01-02T15:04:05.000000-0700"), 900000+connections, from, port(), to, toPort, 9000000+severity, signature, severity)})
	}

	servers := []struct{ file, host, address string }{{"app01/auth.log", "app01", AppAddress}, {"db01/auth.log", "db01", DataAddress}}
	for number, server := range servers {
		for index, user := range []string{"aiko", "kenji", "deploy"} {
			office := fmt.Sprintf("198.51.100.%d", 10+index)
			when := at(9+index*2+number, 5+random.Intn(40), random.Intn(60))
			syslog(server.file, server.host, when, "sshd", fmt.Sprintf("Accepted publickey for %s from %s port %d ssh2: ED25519 SHA256:Zm9yLXRlc3RzLW9ubHktbm90LWEtcmVhbC1rZXk", user, office, port()))
			syslog(server.file, server.host, when.Add(40*time.Second), "sudo", fmt.Sprintf("   %s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=/usr/bin/systemctl status app", user, user))
			conn(when, office, server.address, 22, "SF", "ssh", int64(4000+random.Intn(9000)), int64(9000+random.Intn(30000)))
		}
		for hour := 0; hour < 24; hour += 4 {
			syslog(server.file, server.host, at(hour, 17, 1), "CRON", "(root) CMD (   cd / && run-parts --report /etc/cron.hourly)")
		}
	}
	// A person goes from web01 to app01 and types a wrong password twice. An internal address, failures, then a success.
	hop := at(15, 12, 0)
	for typo := 0; typo < 2; typo++ {
		syslog("app01/auth.log", "app01", hop.Add(time.Duration(typo*7)*time.Second), "sshd", fmt.Sprintf("Failed password for aiko from %s port %d ssh2", WebAddress, port()))
	}
	syslog("app01/auth.log", "app01", hop.Add(20*time.Second), "sshd", fmt.Sprintf("Accepted password for aiko from %s port %d ssh2", WebAddress, port()))
	conn(hop, WebAddress, AppAddress, 22, "SF", "ssh", 5200, 18000)

	for minute := 0; minute < 24*60; minute += 10 {
		for _, target := range []string{WebAddress, AppAddress, DataAddress} {
			conn(at(0, minute, 2+random.Intn(5)), monitorAddress, target, 9100, "SF", "http", 300, 4200)
		}
	}
	for try := 0; try < 30; try++ {
		conn(at(11, try*2, random.Intn(60)), AppAddress, "10.0.2.99", 6379, "S0", "-", 0, 0)
	}
	conn(at(1, 0, 4), DataAddress, backupAddress, 873, "SF", "rsync", 3_200_000_000+int64(random.Intn(100_000_000)), 60000)
	for index := 0; index < 6; index++ {
		conn(at(8+index*2, 30, random.Intn(60)), AppAddress, "198.51.100.200", 443, "SF", "ssl", int64(2_000_000+random.Intn(6_000_000)), 9000)
	}
	for index := 0; index < 8; index++ {
		sensor(at(3+index*2, random.Intn(60), random.Intn(60)), fmt.Sprintf("198.51.100.%d", 20+index), WebAddress, 443, 3, "SYNTHETIC POLICY outdated TLS client")
	}

	campaign := Host{Files: map[string]HostFile{}, Expected: append([]Expected{}, edge.Expected...), KnownMisses: append([]string{}, edge.KnownMisses...)}
	if attacks {
		// Step 2: from web01, a search for hosts with SSH. Most addresses do not answer.
		sweep := at(2, 25, 0)
		for last := 1; last <= 40; last++ {
			target := fmt.Sprintf("10.0.2.%d", last)
			state := []string{"S0", "S0", "REJ"}[random.Intn(3)]
			if target == AppAddress || target == DataAddress {
				state = "SF"
			}
			conn(sweep.Add(time.Duration(last*2)*time.Second), WebAddress, target, 22, state, "ssh", 0, 0)
		}
		for index := 0; index < 3; index++ {
			sensor(sweep.Add(time.Duration(20+index*25)*time.Second), WebAddress, fmt.Sprintf("10.0.2.%d", 9+index*10), 22, 1, "SYNTHETIC SCAN many SSH connection attempts from one host")
		}

		guess := at(2, 31, 0)
		for try := 0; try < 7; try++ {
			syslog("app01/auth.log", "app01", guess, "sshd", fmt.Sprintf("Failed password for deploy from %s port %d ssh2", WebAddress, port()))
			guess = guess.Add(time.Duration(3+random.Intn(5)) * time.Second)
		}
		syslog("app01/auth.log", "app01", guess, "sshd", fmt.Sprintf("Accepted password for deploy from %s port %d ssh2", WebAddress, port()))
		conn(guess, WebAddress, AppAddress, 22, "SF", "ssh", 48000, 310000)

		key := at(2, 41, 10+random.Intn(40))
		syslog("db01/auth.log", "db01", key, "sshd", fmt.Sprintf("Accepted publickey for deploy from %s port %d ssh2: ED25519 SHA256:Zm9yLXRlc3RzLW9ubHktbm90LWEtcmVhbC1rZXk", AppAddress, port()))
		conn(key, AppAddress, DataAddress, 22, "SF", "ssh", 61000, 2_500_000_000)

		conn(at(2, 52, random.Intn(60)), DataAddress, dropAddress, 443, "SF", "ssl", 2_400_000_000+int64(random.Intn(50_000_000)), 120000)

		campaign.Expected = append(campaign.Expected,
			Expected{"net_internal_sweep", WebAddress}, Expected{"ids_high_severity_alerts", WebAddress},
			Expected{"ssh_internal_guessing", WebAddress}, Expected{"ssh_internal_guessing_success", WebAddress},
			Expected{"net_large_upload_external", DataAddress})
		campaign.KnownMisses = append(campaign.KnownMisses,
			"the login to db01 with a stolen key from "+AppAddress+": one accepted key from an internal address looks like every ordinary login",
			"nothing connects the host name web01 in its own logs with the address "+WebAddress+" in the logs of the other hosts and of the sensor: the two halves of the story are found, and a person has to join them")
	}

	campaign.Files["web01/auth.log"] = HostFile{Text: edge.Files["auth.log"], Modified: evening}
	campaign.Files["web01/access.log"] = HostFile{Text: edge.Files["access.log"], Modified: evening}
	names := make([]string, 0, len(logs))
	for name := range logs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		campaign.Files[name] = HostFile{Text: join(logs[name]), Modified: evening}
	}

	return campaign
}

func Story() []string {
	return strings.Split(strings.TrimSpace(`
02:10 an outside address guesses the password of root on web01 and logs in (web01/auth.log)
02:14 a new account and a cron job that downloads a script are made on web01 (web01/auth.log)
02:25 web01 looks for hosts with SSH in the server network (sensor/conn.log, sensor/eve.json)
02:31 web01 guesses the password of deploy on app01 and logs in (app01/auth.log)
02:41 app01 logs in to db01 with a key (db01/auth.log) - no rule finds this step
02:52 db01 sends 2.4 GB to an outside address (sensor/conn.log)
the rest of the day: other outside addresses scan and attack web01 without a link to the steps above`), "\n")
}
