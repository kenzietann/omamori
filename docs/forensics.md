# Forensic triage

`omamori forensics` reads the artifacts of a Linux system from a folder, hashes every file it reads,
runs the rules over the artifacts and the logs, and writes a report with one timeline.
It uses no AI and no network. It never changes the folder it reads.

This is a first triage ("what needs a look, and in which order"), not a full forensic examination.
The limits are listed at the end, and the report repeats them.

## Try it

`omamori scenario --host` writes a synthetic system: the logs of one day, the files that an attacker
left behind after a password of root was guessed, and the output of `ps` and `ss`. Everything is made up.

```sh
omamori scenario --host --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-host
omamori forensics --year 2026 --timezone Asia/Tokyo \
  --processes ./demo-host/snapshots/ps.txt --sockets ./demo-host/snapshots/ss.txt ./demo-host/root
```

The second command prints the place of the report and the SHA-256 of the manifest. Write that hash
down somewhere else. To check later that the evidence is the same:

```sh
omamori forensics verify ~/omamori-output/forensics-<time>/manifest.json ./demo-host/root
```

`--benign` gives the same server on a day without an attack. `expected.json` in the scenario folder
lists the alerts that must fire and what is known to give no alert.

## The evidence folder

The folder is the top of the system that is looked at: a mounted disk image (mount it read-only), an
unpacked copy, or `/` of a running system. Paths in the report and in the manifest are relative to it.

| Kind (`service`) | Read from | One event for each |
|---|---|---|
| logs | `var/log/auth.log`, `secure`, `syslog`, `messages`, `cron` (and `.1`), nginx and Apache access logs | log line, as in `detect` |
| `passwd` | `etc/passwd` | account |
| `cron_file` | `etc/crontab`, `etc/cron.d/*`, `var/spool/cron/crontabs/*`, `var/spool/cron/*` | job |
| `cron_script` | `etc/cron.hourly`, `daily`, `weekly`, `monthly` | script (listed and hashed, its lines are not read) |
| `systemd_unit` | `etc/systemd/system/*.service` and `*.timer`, `~/.config/systemd/user/*.service` | line that starts a program |
| `authorized_keys` | `~/.ssh/authorized_keys` and `authorized_keys2` of root and of each home folder | key (type, fingerprint, comment, options) |
| `shell_history` | `.bash_history` and `.zsh_history` of root and of each home folder | command |
| `process_snapshot` | the file given with `--processes` (`ps aux` or `ps -ef`) | process |
| `socket_snapshot` | the file given with `--sockets` (`ss -tulpn` or `netstat -tulpn`) | listening socket |

Every artifact event has `product: linux`, `category: forensics`, the `service` of the table, and
`time_source`. Rules can ask for one kind with `logsource`. The artifact rules are in
`internal/rules/forensic/` and follow the same format as all rules ([rules.md](rules.md)). With
`--rules folder` your own rules are used in place of the built-in ones.

## What is safe to rely on

- **Read-only.** Files are opened for reading only. Tests compare the content, the mode and the time of
  change of every file and folder before and after a run.
- **Links are not followed.** A link is named in the manifest under "skipped", with nothing read from
  its target. This holds for links inside the folder too. A folder that is a link to a place outside
  the evidence folder is refused by the operating system interface that is used (`os.Root`).
  Named pipes and devices are skipped.
- **Never read:** `/etc/shadow` (password hashes) and private keys. Only the fixed list above is opened.
- **Hashes are of whole files.** A file larger than 8 MiB is hashed to its end, and its first 8 MiB are
  looked at. The manifest says so for that file.
- **Reports go to a new folder** that is not inside the evidence folder and not around it. An existing
  folder is never written into.
- **Text from the system is data.** Control characters are removed, long values are cut, and values pass
  the filter for secrets before they are written to a report, to `alerts.json` or to the store.
  A public key is kept as its fingerprint (as `ssh-keygen -l` prints it), not as the key.

## The manifest

`manifest.json` lists each file that was read: path, kind, size, mode, time of last change, SHA-256,
and the number of events made from it. `skipped` lists what was found and not read, with the reason.
`manifest.sha256` holds the hash of `manifest.json` in the format of `sha256sum -c`.

`forensics verify` hashes the files again and names each one that is missing, changed, or no longer a
normal file. It ends with an error code when a file is not as the manifest says. Snapshot files are
outside the evidence folder; they are named as "not checked". The check compares the files with the
manifest you give it, so the hash of the manifest must be kept where an attacker cannot change it.

## The timeline and its times

The report has one timeline of the alerts from the logs and from the artifacts. The column
"Time comes from" matters:

| Text | Meaning |
|---|---|
| log line | the time that the log wrote down |
| written in the history | the shell wrote the time of the command (zsh extended history, or bash with `HISTTIMEFORMAT`) |
| last change of the file | the entry has no time. The time is the last change of the file that holds it |

The last one is weak evidence: the entry can be older than the change, a copy of the file can have a
new time, and an attacker can set the time of a file. Mount images in a way that keeps the times.

## AI analyst over the triage

Add `--analyze` to let the AI analyst review the alerts of the triage. It is the same service as
`omamori analyze` ([analyst.md](analyst.md)): one bounded, sanitized snapshot of the alerts goes
through the outbound guard, the AI has no tools, every claim is checked by code against the
evidence, and only checked claims are shown.

```sh
omamori forensics --analyze ./demo-host/root --year 2026 --timezone Asia/Tokyo            # preview only
omamori forensics --analyze --yes ./demo-host/root --year 2026 --timezone Asia/Tokyo      # send and check
omamori forensics --analyze --replay recording.json ./demo-host/root --year 2026 --timezone Asia/Tokyo
```

- Without `--yes` the guarded request is shown. Nothing is sent, no report is written, and no
  database is opened. `--yes`, `--dry-run` and `--replay` are refused without `--analyze`.
- The output folder holds the triage report with the checked review added, `analysis.json`,
  `recording.json`, and the same `manifest.json` and `manifest.sha256` as a run without the analyst.
- The files of the system are never sent. The snapshot holds the alerts and, for each, a few sampled
  events with their fields after the filter for secrets. A public key is sent as its fingerprint.
- **Times.** Evidence from artifacts carries `time_source`. The request tells the AI that
  `file_modified` is not the time of an action. More important, the checker does not rely on the AI
  for this: when a checked claim cites an item whose only time is the last change of its file, the
  finding is marked `weak_times` and its text says that the times do not show when or in which order
  things happened. The AI has no field to add or remove this mark.
- A recording is bound to the evidence. After a file of the system changes, the recording no longer
  fits, the run ends as incomplete, and no old finding is shown.
- A run over logs alone sends the same request as before. Recordings of earlier `analyze` runs still fit.

## Measurement on synthetic systems

`go test ./internal/forensics -run HostScenario -v` writes 25 different attacked systems and 25
systems without an attack, and runs the real path over each (files, hashes, parsers, rules).

- 600 of 600 expected alerts were found (24 for each system: 13 from the logs, 11 from the artifacts
  and the logs together).
- No alert that the scenario does not expect, and no alert on the systems without an attack
  (1,375 artifact events, with a cron job that uses curl, a job that cleans `/tmp`, a key with a
  forced command, and histories with `nc -zv`, `/dev/tcp` port checks and `tail` of the login log).

These are numbers about made-up systems that I wrote together with the rules. They show that the
path works end to end and that the rules do what their tests say. They are not an estimate of how
many real intrusions would be found.

A key in `authorized_keys` gives an alert when the file was changed within a day after a password
login over SSH of the same account (`forensics_key_after_password_login`). The time of the key is the
last change of the file, so the finding is marked as having weak times. A key alone, without such a
login, is listed with its fingerprint and gives no alert. Known gap that the scenario names: a
listening port of an odd process is listed and gives no alert by itself.

## Limits

- Only the places in the table are read. Not read: kernel modules, shell start files (`.bashrc`,
  `/etc/profile.d`), `at` jobs, units of installed packages under `/usr/lib/systemd`, changed
  system programs, `wtmp`/`btmp`/`lastlog` (binary), the journal of systemd (binary), browser data,
  and anything that was deleted.
- A running system with a rootkit can show files that are not what is on the disk. Prefer an image.
- Snapshot files are text that someone saved. Their content is taken as it is.
- A rule hit on an artifact means "look at this". Administrators add keys and write cron jobs too.
- The AI review has been run with scripted answers and with recordings only. No live model has
  reviewed a forensic run yet, so nothing is known about the quality of real answers.
