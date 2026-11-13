# Attack lab

`omamori lab` checks Omamori end to end against a real attack on a real Linux server. Synthetic logs show
that the code agrees with what its author thinks logs look like; the lab shows what a current Debian,
OpenSSH, nginx, cron and rsyslog really write when they are attacked.

```sh
omamori lab                 # about a minute; ten minutes the first time, while Docker downloads Debian
omamori lab --keep          # leave the containers running to look at them by hand
omamori lab clean           # remove containers and networks that a run left (--images: the images too)
```

It needs Docker (Docker Desktop, colima, or Docker Engine). It is also on the home screen as "Attack lab".

## What it does

1. Builds two images from files inside Omamori: `web01` (Debian with sshd, nginx, cron, rsyslog, sudo and
   tcpdump) and an attacker (ssh, sshpass, curl).
2. Puts both on a new Docker network made with `--internal`: neither container can reach your machine, your
   network or the internet. No port is published, no folder is shared, nothing runs privileged.
3. Starts tcpdump on web01, then runs the attack from the attacker, against web01 only:

   | Stage | What the attacker does |
   |---|---|
   | scan | tries ports 1 to 200 |
   | web | looks for `.env`, `.git` and other files, many pages that are not there, SQL injection and path traversal, a scanner user agent |
   | spray | one password for ten accounts |
   | guess | passwords of alice until one works |
   | persist | as alice: a real key pair made by the attacker (public half added to `authorized_keys`), a cron job that pipes a download into a shell, a refused sudo, a shell history |
   | tools | a dropper in `/tmp`, a program and a miner config in `/dev/shm`, a reverse shell script in `/var/tmp`, a PHP web shell in an upload folder, and one command sent to that shell |

4. Waits until cron has run alice's job, stops the capture, and copies out the logs, the files
   (`etc`, `home`, `root`, `tmp`, `var`, `srv`, `opt`, `usr/local`, `dev/shm`), `ps aux`, `ss -tulpn` and the
   capture.
5. Removes the containers and the network (also after an error), unless `--keep` is given.
6. Reads the copy with `forensics` (logs, artifacts, file rules) and the capture with `detect`, and scores
   the result against a fixed list of 24 detections, one or more for each stage.

Nothing the attacker leaves is started on web01, except a copy of `sleep` that cannot run from `/dev/shm`.
The download addresses are `203.0.113.80`, a range kept for documentation: nothing answers there, and the
network has no way out anyway.

## Why it has no target

The lab attacks only the server it builds. It has no option to point the attack at another address, and the
target is fixed in the script (a test checks this). A tool that runs an attack against any system it is
given is an attack tool, whoever uses it. The question the lab answers ("does Omamori find a real attack on
a real server?") does not need one. To check your own servers, run `omamori forensics` and `omamori detect`
on their logs, files and captures.

## Output

Everything goes to a new folder `lab-<time>` under the report folder (`--output`, default
`~/omamori-output`):

| Folder | What is in it |
|---|---|
| `evidence/` | the copy of web01 (`root/`), `ps.txt`, `ss.txt`, `capture.pcap` |
| `forensics/` | the forensic report, `alerts.json`, the manifest and its hash |
| `capture/` | the detection report over the capture |
| `score/` | `lab.md` and `lab.html` (one line per check: found or not), `attack.txt` (what the attack printed) |

The run ends with an error code when a check was missed, so it can guard a change in a script or in CI
(where Docker is available). Rules that fire and are not checks are listed as "also fired": the lab network
uses private addresses, so the rules for movement inside a network fire too.

## Copying the system out

The copy comes from a server on which an attacker had a shell, so it is unpacked as hostile data: names that
leave the folder are refused, links are made as links and never followed (`os.Root` refuses any path through
a link that leads outside), devices and hard links are not made, setuid and other special bits are dropped,
and sizes are limited (256 MB a file, 4 GB in all). The copy uses the posix tar format, which keeps the times
of files to the nanosecond.

## Measured (2026-11-13)

Three runs in a row on colima (Apple silicon), Debian 13: 24 of 24 in each, about 65 seconds each after the
first build. The capture had 1,470 packets, 0 that could not be read; the port scan shows 198 refused
ports of 200 (22 and 80 are open).

The first runs found three faults, all fixed:

| Seen | Cause | Fix |
|---|---|---|
| The copy failed with a broken pipe | Omamori stopped reading at the end of the tar archive, while tar still wrote its padding | The stream is read to its end; a test fakes the padding |
| `linux_cron_download_exec` missed | The lab ended before cron ran the job | The lab waits (up to 75 seconds) until cron has run it |
| `forensics_key_after_password_login` missed | The copy kept whole seconds: the key, written 0.3 s after the login, looked older than it. Before that, the attack wrote a fake key that sshd could never use, and the key parser rightly skipped it | The posix tar format; the attacker makes a real key pair |

The second one is a limit of forensics in general: a copy of a system that keeps only whole seconds can put
two things of the same second in the wrong order. The forensic guide names it.
