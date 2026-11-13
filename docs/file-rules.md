# File rules

File rules look at the content of files, in the way of YARA. `omamori forensics` runs them over the
places of a Linux system where an attacker leaves tools, and each hit becomes an alert in the same
timeline, store and AI review as the alerts from the logs and the artifacts.

A file rule is data. It is read, matched against bytes and counted. Nothing in it is run, and nothing
in a scanned file is run.

## Where the file rules look

In this order, without following any link:

`tmp`, `var/tmp`, `dev/shm`, `var/www`, `srv`, `usr/share/nginx`, `usr/local/bin`, `usr/local/sbin`,
`opt`, `etc`, `var/spool/cron`, `root`, `home`

The homes come last. They can hold gigabytes of projects and data, and they must not use up the limit
of the scan before the places of the system are looked at. In the live test below, they did exactly
that with the first order, and a web shell was missed.

The programs of the system (`/usr/bin`, `/usr/lib`) are not looked at. Each file that is read is
hashed into `manifest.json` with the kind `file_scan`, so `forensics verify` checks it like every
other file.

Passed over, and why:

| What | Why |
|---|---|
| Password hashes, private keys and credentials: `shadow`, `gshadow`, `etc/ssh`, `etc/ssl/private`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.netrc`, `.pgpass`, `.git-credentials`, `.env` files, `id_*` keys, `*.key`, `*.pem`, `*.p12`, `*.kdbx` and like files | They are never opened: not read, not hashed and not named in any output |
| Files that are read as artifacts (logs, crontabs, units, `authorized_keys`, histories, `passwd`) | The artifact rules look at their lines already, so one line does not give two alerts. Cron scripts are not in this list: their content is looked at |
| `node_modules`, `.git`, `.cache`, `__pycache__`, `site-packages`, `venv`, `.venv`, `.npm`, `.cargo`, `.rustup`, `.m2`, `.gradle` | Packages and caches. Each one that is passed over is named under `skipped` |
| Files over 64 MB | Counted under `skipped` |
| More than 20,000 files or 1 GB in all | The scan stops and says so under `skipped` |

A file is looked at up to its first 8 MiB and hashed to its end. The manifest says so for that file.

`--no-file-rules` turns the scan off. `--file-rules folder` uses your own file rules in place of the
built-in ones. In the home screen, the forensics form has the same choice: empty for the built-in
rules, a folder, or `none`.

With an indicator list (`--indicators`), the scan also hashes each file and looks for the SHA-256
hashes of the list, with or without file rules. A file with a known hash gives the alert "Known bad
indicator seen".

## The built-in file rules

| Rule | Level | Finds |
|---|---|---|
| `file_download_and_run` | high | a script that pipes a download into a shell, or saves a download, makes it a program and starts it from a temporary folder |
| `file_reverse_shell` | high | `bash -i` with `/dev/tcp`, `nc -e`, `socat exec:`, a Python socket with `dup2` or `pty.spawn` |
| `file_coin_miner` | high | a stratum pool address, or `xmrig` with its settings |
| `file_program_in_temp` | high | a Linux program (ELF) in `/tmp`, `/var/tmp` or `/dev/shm` |
| `file_web_shell` | high | a PHP file in a web folder that gives a value of the request to `system`, `eval` and the like |
| `file_ssh_key_planting` | medium | a script that appends to an `authorized_keys` file |
| `file_log_wiping` | medium | a script that empties a login log or turns the shell history off |

They are in `internal/filerules/builtin/`. A hit means "look at this file". An administrator can
have a reason for each of them.

The rules for scripts (all but the miner and the program in a temporary folder) have `max_size: 1048576`.
A backdoor script or a web shell is small; a large file with the same text is data, like a list of
CVEs that quotes an injection. `file_reverse_shell` asks for the shell and `/dev/tcp` on one line.

## Writing a file rule

```yaml
name: own_miner                    # small letters, digits and _
id: 0b8e5a52-...                   # optional
title: Our own miner rule
description: What it finds and why it matters.
level: high                        # informational, low, medium, high, critical
tags: [attack.impact, attack.t1496]
paths: [tmp/, var/tmp/, dev/shm/]  # optional: the file must be in one of these folders
max_size: 1048576                  # optional: larger files are not matched
strings:
  pool: {regex: 'stratum\+(tcp|ssl)://', nocase: true}
  name: {text: xmrig, nocase: true}
  elf: {hex: '7f 45 4c 46', at: 0}
condition: pool or (elf and name)
tests:
  - {name: a miner, path: dev/shm/k, text: "stratum+tcp://pool.example.test:3333", match: true}
  - {name: notes, text: "read about xmrig", match: false}
```

Strings:

- `text`: plain bytes. `nocase: true` ignores the case of ASCII letters. `at: N` asks for the text at
  that byte of the file.
- `hex`: bytes like `7f 45 4c 46`. `??` fits any byte. Two fixed bytes in a row are needed. `at` works.
- `regex`: a regular expression of Go (RE2). It takes a time that grows with the length of the file and
  never more, so no rule can make a scan hang. Back references and look-arounds do not exist in RE2.
  A regex that matches an empty text is refused, because it would match every file. `at` does not fit
  a regex: write `\A` instead.

The condition has `and`, `or`, `not`, brackets, the names of the strings, and `any of them`,
`all of them`, `2 of them`, `any of (a, b)`, `2 of (a, b, c)`, `any of name_*`.

A file rule needs tests: a text or hex, a path (default `tmp/test`), and `match: true` or `false`.
When a test fails, the whole folder of rules is refused and the error names the rule and the test.
Unknown keys are refused too, so a typing error does not quietly turn a rule off.

The hit becomes an event with `service: file_scan`, `action: file_rule_match`, `file_rule`, `file`,
`sha256`, `matched` (the names of the strings that were found) and `excerpt` (the first text that was
found, without control characters and at most 160 bytes). Its time is the last change of the file, so
an AI finding that rests on it is marked as having weak times.

## Measured live (2026-11-13)

A Debian container (`web01`, on a Docker network with no way out) held copies of the owner's 12
projects in `/home/alice/code` (61,149 files, 8.5 GB, without `.git`, `node_modules` and `.env`
files). An attacker container guessed a password over SSH and, as that user, left a dropper in
`/tmp`, a program and a miner config in `/dev/shm`, a reverse shell helper in `/var/tmp` (never run),
and a PHP web shell in an upload folder, then sent `?c=id` to it. The system was exported and read
with `omamori forensics`.

| Run | Result |
|---|---|
| First order (homes before `var/www`) | 6 of 7 planted kinds found; the scan stopped at 1 GB inside the homes and the web shell was missed; 1 false alarm (a 60 MB list of CVEs) |
| After the fixes (homes last, size limit for scripts, one line for `/dev/tcp`) | 7 of 7 found, plus `web_shell_command` in the access log; no false alarm in the 10,803 files scanned |
| Every file of the 12 projects (a build without the scan limits, 28,889 files read) | 0 false alarms in 11 projects. All other hits were in the source of Omamori itself (its rules, tests, scenario and docs hold attack text on purpose) |
| `--analyze` with gpt-6-luna | 24 claims verified, 0 rejected, 0 alerts unreviewed; the 9 findings that rest on file times are marked as weak |

A folder of security tools or rule sets (the source of Omamori, or of YARA rules) gives hits: the
text is there. Read the path before the title.

## Limits

- This is a subset of YARA, not YARA. There are no modules (`pe`, `elf`, `math`), no counts or offsets
  of strings in the condition, no `filesize` in the condition (use `max_size`), no wide strings and no
  XOR or base64 forms of strings. YARA rules cannot be loaded as they are.
- The owner of a file is not used yet: a hit in `/tmp` has no user, even when the file belongs to the
  account that logged in. The analyst relates it by time only.
- Only the folders in the list are looked at. A tool in `/usr/bin` that replaced a system program is
  not found this way.
- Packed or encrypted programs show none of their strings. A miner that is packed is found by
  `file_program_in_temp` only when it lies in a temporary folder.
- The built-in rules were measured on made-up files only. No real malware was scanned.
