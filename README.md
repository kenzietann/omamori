<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.png">
    <img src="docs/assets/logo.png" alt="Omamori logo" width="320">
  </picture>
</p>

# Omamori (お守り)

[日本語](README.jp.md)

Omamori is a blue-team tool for the terminal. It checks projects for leaked secrets, reads logs, packet
captures and whole Linux systems, finds attacks with rules, and lets an AI review what it found. A **guard**
sits between the AI and your data: secrets and personal data are removed before anything leaves your
computer, the AI can only use read-only tools, and every claim the AI makes is checked by plain code before
you see it.

It runs on your own computer, as a CLI with a terminal home screen and a local web dashboard. Most features
need no AI at all.

**Status: v0.1.0, a public preview.** All features below run and have tests, and the main paths have been
tested live (see [Live test results](#live-test-results)). It is not a finished product: read the limits of
each feature. What changed in each version is in the [changelog](CHANGELOG.md).

## Contents

- [Why I am building this](#why-i-am-building-this)
- [How the guard keeps your data safe](#how-the-guard-keeps-your-data-safe)
- [Install](#install)
- [A five-minute tour, no API key needed](#a-five-minute-tour-no-api-key-needed)
- [Two ways to use it: home screen or commands](#two-ways-to-use-it-home-screen-or-commands)
- [Features](#features)
  1. [Exposure check (Task A)](#1-exposure-check-task-a)
  2. [Log triage (Task B)](#2-log-triage-task-b)
  3. [Detection with rules](#3-detection-with-rules)
  4. [AI analyst](#4-ai-analyst)
  5. [Forensic triage of a Linux system](#5-forensic-triage-of-a-linux-system)
  6. [File rules (YARA-like)](#6-file-rules-yara-like)
  7. [Packet captures](#7-packet-captures)
  8. [AI rule writing (Task C)](#8-ai-rule-writing-task-c)
  9. [Store, search, cases and timelines](#9-store-search-cases-and-timelines)
  10. [Local web dashboard](#10-local-web-dashboard)
  11. [Attack lab](#11-attack-lab)
  12. [Synthetic demo data](#12-synthetic-demo-data)
  13. [Replay and live evaluation](#13-replay-and-live-evaluation)
- [AI providers and API keys](#ai-providers-and-api-keys)
- [Where the output goes](#where-the-output-goes)
- [What it cannot do](#what-it-cannot-do)
- [Live test results](#live-test-results)
- [Docs](#docs)
- [About the project](#about-the-project)

## Why I am building this

Security teams want to use AI for blue-team work: checking logs, finding leaks, writing detection rules. But
logs and code are full of secrets and personal data. Sending them to an AI company as they are is a risk,
and in a big company it can break company rules. And an AI that sounds sure can still be wrong.

Omamori tries to fix both. You use your own API key. Before anything leaves your computer, the guard removes
the sensitive data it can detect. After the AI answers, code checks each claim against the evidence and
throws away what it cannot prove.

It is for security engineers and developers, in teams of any size: a security team for first-pass work, or a
small team with no security person. It is not a SIEM and not a hosted service.

## How the guard keeps your data safe

These rules hold for every feature:

- **One way out.** A single function sends data to the AI provider, and it cleans the whole request first.
  Secrets and personal data become placeholders like `[SECRET:aws_key:001]`, which are never turned back.
- **Read-only.** The AI can only use read-only tools: no shell, no network, no writing. It cannot change its
  own permissions. Collectors (logs, forensics, captures) only read, and never follow links out of the
  folder you give.
- **Data is data.** Text from files, logs and packets is treated as data, never as instructions. There are
  prompt-injection tests with booby-trapped files.
- **Checked claims.** For the analyst features, every citation, count, time and link the AI gives is checked
  by code. Claims that fail are rejected and shown as rejected; the rule alerts never get replaced.
- **You see it first.** Before a live AI run, you see the request that would be sent. Nothing is sent without
  `--yes` (or your confirmation on the screen).
- **Safe reports.** Reports show the place, the type and a placeholder, never the secret itself. Reports go
  into a new folder that is never inside the evidence.
- **Your key stays yours.** The API key is never printed, logged or written to a file. On macOS a key that
  works is kept in your Keychain.

The [platform plan](docs/platform-plan.md) has the details and the tests behind each rule.

## Install

**Download a release** (macOS and Linux, Apple silicon and Intel/AMD). Pick the archive of your system from
the [latest release](https://github.com/kenzietann/omamori/releases/latest), then:

```sh
shasum -a 256 -c checksums.txt --ignore-missing       # check the download
tar xzf omamori_0.1.0_darwin_arm64.tar.gz
sudo mv omamori_0.1.0_darwin_arm64/omamori /usr/local/bin/
omamori version
```

The binaries are not signed. If macOS refuses to open a file that a browser downloaded, run
`xattr -d com.apple.quarantine /usr/local/bin/omamori` once.

**Or build it from source** with Go 1.26.5 or newer:

```sh
go install github.com/kenzietann/omamori/cmd/omamori@v0.1.0
# or, in a clone: go install ./cmd/omamori
```

Optional:

- an **API key** of an AI provider, for the AI features (see [AI providers](#ai-providers-and-api-keys))
- **Docker** (Docker Desktop, colima or Docker Engine), for the [attack lab](#11-attack-lab)
- **PostgreSQL or MariaDB**, if you want the store on a server instead of the built-in SQLite

## A five-minute tour, no API key needed

Everything here uses made-up data and runs offline.

```sh
# 1. Make a day of synthetic logs with planted attacks, and find them with the rules.
omamori scenario --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-logs
omamori detect ./demo-logs --year 2026 --timezone Asia/Tokyo
#    -> Read 2 files and 1254 events. 35 rules. 15 alerts, 1 critical, 6 high, 8 medium.

# 2. Watch the AI analyst work, with recorded answers instead of a live AI.
omamori analyze ./demo-logs --year 2026 --timezone Asia/Tokyo \
  --replay ./testdata/fixtures/analyst/recording.json
#    -> REPLAY (scripted answers) ... Analyst: complete. 16 verified findings, 0 rejected claims.

# 3. Make a whole synthetic Linux system that was broken into, and triage it.
omamori scenario --host --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-host
omamori forensics --year 2026 --timezone Asia/Tokyo \
  --processes ./demo-host/snapshots/ps.txt --sockets ./demo-host/snapshots/ss.txt ./demo-host/root
#    -> Read and hashed 31 files ... 55 rules. 34 alerts, 3 critical, 20 high, 11 medium.

# 4. Open the home screen and try the other tasks.
omamori ui ./demo-logs
```

Each command prints where its report is. Open `report.html` in a browser. If Docker runs, try
`omamori lab` too: it attacks a real Debian server in a container and scores what Omamori finds.

## Two ways to use it: home screen or commands

**Home screen.** `omamori ui <folder>` opens a terminal home menu for the folder: exposure check, log triage,
detect, analyze, forensics (with or without the AI review), rule draft, the dashboard, stored runs, verify
hashes, the attack lab and demo data. Each task with options opens a short form first. Text fields take
paths (`~/` works), choices change with left and right, and every field can stay empty for the default. A
wrong value brings you back to the form with the reason. AI tasks show the guarded request before you
confirm; a recording on the form replays instead, and nothing is sent. When the run starts, the screen
gives way to the normal terminal, so you can scroll and select the report.

| Task on the home screen | What the form takes |
|---|---|
| Detect | rules folder, asset list, indicator list, log format, store the run |
| Analyze | the same, and a recording to replay instead of asking a provider |
| Forensics | saved `ps` and `ss` output, rules folder, file rules folder (or `none`), asset list, indicator list, store the run |
| Forensics + AI review | the same, and a recording to replay |
| Rule draft | goal, examples, clean logs, title, level, number of answers, log format, asset list, indicator list, a recording |
| Verify hashes | the manifest of an earlier forensic run; the folder is the evidence |
| Attack lab | no form: needs Docker |
| Make demo data | logs and a system, the three-host campaign, or a day without attacks; a seed |

**Commands.** Every feature is also a command, for scripts and for options the forms do not have (the year
and time zone of syslog, `--db`, `--dry-run`, `--timeout`). `omamori help` lists them all.

## Features

### 1. Exposure check (Task A)

**What it does.** Looks through a project folder for leaked secrets and personal data, and gives fix advice
like "rotate this key". An AI agent explores the project with read-only tools (list folders, read files,
search text, run the detectors) through the guard.

**How to use it.**

```sh
omamori check ./my-project           # opens the screen: choose a provider, see the request, confirm
omamori peek ~/omamori-output/run-<time> ./my-project            # see what matched (middle of values hidden)
omamori peek --reveal ~/omamori-output/run-<time> ./my-project   # full values, on your screen only
```

**What it finds.** AWS access key IDs, GitHub tokens, AI provider keys (`sk-`, `sk-ant-`, `sk-proj-`), Google
API keys, Slack tokens, Stripe live keys, JWTs, private key blocks, passwords inside addresses
(`scheme://user:password@host`), マイナンバー (a valid check digit means "possible identifier" only) and
Japanese phone numbers.

**What it does not count.** Every match is hidden from the AI, but these are listed apart and not counted as
findings: a key in a `.env` file that `.gitignore` keeps out of git and that was never committed (it is a
finding if it is in the history), matches in libraries and caches (`deps`, `site-packages`, `.angular`),
phone-like numbers in build output, numbers inside decimals, UUIDs and hex dumps, test values like
`0123456789`, and example passwords like `user:pass@`. Binary files are not scanned.

**What you get.** `report.md` and `report.html` with each finding's place, type and placeholder, a "limits"
section, an event log and `recording.json`. `peek` finds each match again and shows it on your screen;
nothing is saved and nothing is sent. A private key block is never shown, only its first line.

### 2. Log triage (Task B)

**What it does.** The AI reads an sshd `auth.log` (classic or ISO time stamps, `sshd` or the `sshd-session`
of OpenSSH 9.8 and later) and looks for two attacks: many failed logins followed by a success (password
guessing), and one address trying many usernames (password spraying). A normal program checks every line,
time and count the AI cites, so it cannot make things up. Findings that code sees and the AI did not claim
are listed too.

```sh
omamori triage /var/log/auth.log --year 2026 --timezone Asia/Tokyo
```

Classic syslog lines have no year and no time zone, so give `--year` and `--timezone`. `--triage-config`
changes the window and thresholds. A log in which no password event was read gets a warning, so an empty
result is never read as "clean".

### 3. Detection with rules

**What it does.** `detect` reads logs, runs detection rules over them, and writes a report of alerts. No AI
and no API key are used.

**What it reads.** sshd and Linux syslog, nginx and Apache access logs, JSON lines, Suricata EVE, Zeek JSON,
Wazuh alerts, Windows and Sysmon events (Winlogbeat or NXLog JSON), and packet captures (see
[7](#7-packet-captures)). Give files or folders; the format of each file is found from its first bytes and
lines, or set it with `--format`. Dependency folders like `node_modules` are skipped and listed.

**The rules.** 35 built-in rules for SSH (guessing, spraying, a login after guessing, sshd penalties), Linux
hosts (sudo refused, new users, admin groups, cron jobs that download a script), web servers (scans for
sensitive files, path enumeration, injection, scanner tools, commands sent to a web shell), and networks
(internal sweeps, port scans, large uploads, IDS alerts). The format is a documented subset of
[Sigma](https://sigmahq.io), with counts, distinct counts and ordered sequences. Every rule carries tests, and
a rule set whose tests fail is refused.

```sh
omamori detect ./logs --year 2026 --timezone Asia/Tokyo
omamori detect ./logs --rules ./my-rules                     # your own rules in place of the built-in ones
omamori detect ./logs --assets assets.yml --indicators bad.yml
```

- **Asset list** (`--assets`): names and addresses of your own machines. Then a host name in one log and its
  address in another are known to be one machine, and rules and the AI can join them.
- **Indicator list** (`--indicators`): addresses, domains and SHA-256 hashes known to be bad. Every event
  that names one is marked, in every kind of log, and one alert is given per indicator.

**What you get.** A new `detect-<time>` folder with `report.md`, `report.html` and `alerts.json`. The logs are
not changed. Guides: [rules](docs/rules.md), [log intake](docs/intake.md).

### 4. AI analyst

**What it does.** `analyze` runs detection, then sends a bounded, sanitized snapshot of the alerts and a few
sample events to the AI. The AI reviews each alert, links alerts that share an address, user or host, and
suggests next steps. Code then checks every citation, count, time and link. Only checked claims are shown;
the AI has no tools, and its suggestions are never run.

```sh
omamori analyze ./logs --year 2026 --timezone Asia/Tokyo            # preview only: shows the request
omamori analyze ./logs --year 2026 --timezone Asia/Tokyo --yes      # send, then check the answer
omamori analyze ./logs --year 2026 --timezone Asia/Tokyo --replay recording.json   # offline
```

It takes every `detect` flag, plus `--provider`, `--model`, `--reasoning`, `--dry-run` and `--timeout`. The
report holds the rule alerts, the checked review, the rejected claims and what was not reviewed, and
`analysis.json`. Guide: [analyst](docs/analyst.md).

### 5. Forensic triage of a Linux system

**What it does.** `forensics` reads a Linux system from a folder (a mounted image, an unpacked copy, or `/` of
a running system): login, system and web logs, crontabs, systemd units, `authorized_keys`, shell histories,
`/etc/passwd`, and saved `ps` and `ss` output if you give it. The same rules run over the logs and the
artifacts, and everything stands in one attack timeline. The [file rules](#6-file-rules-yara-like) look at
the content of the files where attackers leave tools.

```sh
omamori forensics --year 2026 --timezone Asia/Tokyo --processes ps.txt --sockets ss.txt /mnt/server
omamori forensics verify ~/omamori-output/forensics-<time>/manifest.json /mnt/server
omamori forensics --analyze --yes /mnt/server          # add the checked AI review
```

- **Evidence you can prove.** Every file that is read is hashed into `manifest.json`, and the hash of the
  manifest is printed. `forensics verify` hashes the files again later and names each one that changed.
- **Nothing is changed or run.** Links are never followed. Password hashes, private keys and credential
  files (`.aws`, `.netrc`, `.env` and the like) are never opened.
- **Honest times.** The timeline says where each time comes from: a log line, a time written in the history,
  or only the last change of a file. An AI finding that rests on file times is marked as having weak times.

Guide: [forensics](docs/forensics.md).

### 6. File rules (YARA-like)

**What it does.** File rules look at the content of files, in the way of YARA: text, hex (with `??`
wildcards) and regular expression strings, and a condition like `any of them` or `2 of (a, b, c)`. During
`forensics` they scan `/tmp`, `/var/tmp`, `/dev/shm`, web folders, `/usr/local`, `/opt`, `/etc` and the home
folders (in that order). Each hit is an alert with the SHA-256 of the file from the manifest.

Seven built-in rules find droppers that download and run a program, reverse shells, coin miners, programs in
temporary folders, PHP web shells, scripts that add SSH keys, and scripts that wipe logs or the history.

```sh
omamori forensics --file-rules ./my-file-rules /mnt/server     # your own file rules
omamori forensics --no-file-rules /mnt/server                  # turn the scan off
```

Every file rule carries tests (a text or bytes, and whether it must match); a rule with a failing test is
refused. Regular expressions are those of Go, so no rule can make a scan hang. Guide:
[file rules](docs/file-rules.md).

### 7. Packet captures

**What it does.** `detect`, `analyze` and `rule draft` read packet captures: pcap (tcpdump) and pcapng
(Wireshark). A capture becomes events in the shape of Zeek logs: one per TCP or UDP connection (with its
state, bytes and packets), one per HTTP request (with its status) and one per DNS question (with its answer
code), plus the TLS server name. The network and web rules read them, so a port scan, web probes or a web
shell show up from the traffic alone.

```sh
sudo tcpdump -i eth0 -w capture.pcap        # on a server you own
omamori detect capture.pcap /var/log/auth.log
```

A capture is found by its first bytes, so it can lie in a folder of logs. Every length in a packet is
checked, and the reader was fuzzed with 11 million inputs. Guide: [packet captures](docs/pcap.md).

### 8. AI rule writing (Task C)

**What it does.** You point at log lines and say what you want a rule to find. The AI writes the matching
part of one detection rule. Omamori accepts it only if it loads, passes its own tests, matches every example
you gave, matches nothing on built-in days without an attack and in clean logs you give, and is not too broad
on your logs. If it is refused, the AI is told the fixed reasons and may try again.

```sh
omamori rule draft --goal "cron jobs that download a script and pipe it to a shell" \
  --example web01/auth.log:68 --benign ./clean-logs --year 2026 --timezone UTC ./logs
```

Without `--yes` it only shows the request. `rule.yml` is written only for an accepted rule; put it in a folder
and use it with `omamori detect --rules`. Guide: [rule writing](docs/rule-writing.md).

### 9. Store, search, cases and timelines

**What it does.** Add `--store` to `detect`, `analyze` or `forensics` to keep the sanitized run: its events,
alerts and checked analysis. Then search across runs, group alerts into cases, and build timelines. SQLite is
built in (`~/omamori-data/omamori.db`, or `--db file`); PostgreSQL and MariaDB are set with
`OMAMORI_DB_DRIVER` and `OMAMORI_DB_DSN`. Database passwords are never command-line flags.

```sh
omamori detect ./logs --year 2026 --timezone Asia/Tokyo --store
omamori store runs
omamori store search --field src_ip --value 203.0.113.9
omamori store search --kind alerts --level critical
omamori store cases create --title "Authentication review"
omamori store timeline --from 2026-11-10T00:00:00Z --to 2026-11-11T00:00:00Z
```

Cases keep versions so that two people cannot overwrite each other. Guide: [storage](docs/storage.md).

### 10. Local web dashboard

**What it does.** `omamori dashboard <workspace>` starts a web interface on `127.0.0.1` (port 8765) and prints
a private session link. It shows stored runs, alerts beside their evidence, checked AI citations, search,
cases, timelines and charts, and it can start detection and forensic runs on folders inside the workspace.
Provider keys stay on the server side; AI runs need a preview and a confirmation. Guide:
[dashboard](docs/dashboard.md).

### 11. Attack lab

**What it does.** `omamori lab` checks Omamori end to end against a real attack on a real Linux server. It
builds a Debian server (`web01`, with sshd, nginx, cron and rsyslog) and an attacker in Docker, on a network
with no way out, and runs a fixed attack on that server only: a port scan, web probes, password spraying and
guessing, persistence (a key, a cron job, a history), dropped tools and a web shell. It records the traffic,
copies out the logs and files, reads them with `forensics` and `detect`, and scores 24 expected detections.

```sh
omamori lab                 # about a minute; about ten the first time, while Docker downloads Debian
omamori lab --keep          # leave the containers running to look at them
omamori lab clean           # remove what a run left (--images: the images too)
```

It ends with an error code when a detection is missed, so it can guard changes. It has **no target option**:
the attack is fixed to its own container, and a test checks that. To check your own servers, use
`forensics` and `detect` on their logs, files and captures. Guide: [attack lab](docs/lab.md).

### 12. Synthetic demo data

**What it does.** `scenario` writes made-up data with planted attacks and a list of what must be found
(`expected.json`). All data is fake: addresses come from the ranges kept for documentation.

```sh
omamori scenario --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-logs       # logs of one server
omamori scenario --benign --seed 3 --date 2026-11-10 ./quiet-day                     # the same day, no attack
omamori scenario --host --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-host # a whole system
omamori scenario --campaign --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-campaign
```

The campaign is one attack through three hosts, with host logs, Zeek and Suricata sensor logs, an asset list
and an indicator list. The story, and what is found and what is not, is in [the demo guide](docs/demo.md).

### 13. Replay and live evaluation

- **Replay.** Every live AI run saves `recording.json`. `omamori replay <recording>` plays the answers back
  through the same guard, tools, checker and report, with no network call. It is always labeled REPLAY. A
  recording only fits the same evidence; if a file changed, the replay stops instead of showing old findings.
- **Eval.** `omamori eval --yes --runs 3` runs fixed live tests on the fake fixtures and scores them on
  correct findings and locations, with a token cap. It costs tokens.

## AI providers and API keys

Providers: Anthropic and any OpenAI-compatible API (OpenAI, Gemini, Mistral, Groq, Together, DeepSeek, xAI,
OpenRouter, Ollama, LM Studio). With Ollama or LM Studio, nothing leaves your computer at all.

```sh
omamori providers                 # which providers have a key set
omamori models anthropic          # the models your key can use
export ANTHROPIC_API_KEY=...      # or type the key in the screen
```

Choose with `--provider` and `--model`, the variables `OMAMORI_PROVIDER` and `OMAMORI_MODEL`, or the home
screen (your choice is remembered). Keys are never read from the command line. On macOS a key that works is
kept in your Keychain; remove it in Settings. Runs have limits on requests and tokens (`--max-steps`,
`--max-tokens`).

## Where the output goes

Reports go to `~/omamori-output/` (or `--output folder`), always into a new folder per run, such as
`detect-<time>`, `forensics-<time>` or `lab-<time>`. A folder that exists is never written into, and a report
folder may not be inside the evidence. Typical files:

| File | What it is |
|---|---|
| `report.md`, `report.html` | the report (the HTML has no script and loads nothing) |
| `alerts.json` | the alerts with their evidence |
| `analysis.json` | the checked AI review |
| `recording.json` | the AI answers, for replay |
| `manifest.json`, `manifest.sha256` | forensics: the hash of every file that was read |

## What it cannot do

- It only removes the data types it can detect. A password in a line like `password = hunter2` is not found.
  IP addresses, names and street addresses are not removed (log triage needs the addresses).
- A valid マイナンバー check digit only means "possible identifier": about 1 in 10 random 12-digit numbers
  pass by luck.
- It reduces what the AI company sees. It cannot control what the company does with it.
- Detection is batch: it reads files, it does not watch live traffic or logs. There is no agent on hosts, no
  blocking and no active response.
- The rules and the synthetic tests were written by me together. Numbers from them show that the code works
  as designed, not how many real attacks would be found. The attack lab is the check against a real server.
- It is for defense only. The attack lab attacks only its own container.

## Live test results

`omamori eval` runs fixed real-provider tests on the fake fixtures and scores findings and locations, not
wording. Latest run (2026-11-11, `gpt-6-luna`, 3 runs per case, 43,220 tokens): **14 of 15 runs passed.**

| Case | Passed | Avg requests | Avg tokens |
|---|---|---|---|
| Task A: exposure fixture | 3 of 3 | 2 | 1307 |
| Task B: guessing.log | 3 of 3 | 3 | 3440 |
| Task B: spraying.log | 3 of 3 | 3 | 3421 |
| Task B: benign.log | 3 of 3 | 3 | 2992 |
| Task B: malformed.log | 2 of 3 | 3 | 3246 |

The one failure: the AI did not claim a finding that was in the log, so the checker listed it as "found by
Omamori, not claimed by the AI". Nothing false was accepted. Three runs per case is a small sample.

Other live checks (2026-11-13): the attack lab found 24 of 24 detections in four runs in a row; a forensic
run with the AI review on an attacked lab server had 24 claims verified and 0 rejected; the exposure check
completed on two real projects of mine. The details and the faults these runs found are in the
[platform plan](docs/platform-plan.md), [file rules](docs/file-rules.md) and [lab](docs/lab.md) guides.

## Docs

| Guide | About |
|---|---|
| [Platform plan](docs/platform-plan.md) | design, decisions, verification results, what was fixed and why |
| [Toolkit map](docs/toolkit.md) | which blue-team tools Omamori stands in for, and what is missing |
| [Log intake](docs/intake.md) | formats, field maps and limits |
| [Rules](docs/rules.md) | the detection and correlation rule format |
| [AI analyst](docs/analyst.md) | checked reviews, schema, replay |
| [Forensics](docs/forensics.md) | what is read, the manifest, times, limits |
| [File rules](docs/file-rules.md) | the YARA-like format and the scan |
| [Packet captures](docs/pcap.md) | pcap and pcapng into events |
| [Rule writing](docs/rule-writing.md) | `rule draft`, its checks and limits |
| [Storage](docs/storage.md) | databases, search, cases, timelines |
| [Dashboard](docs/dashboard.md) | the local web interface |
| [Attack lab](docs/lab.md) | the lab, its safety and its results |
| [Demo campaign](docs/demo.md) | one attack through three hosts |
| [Roadmap](ROADMAP.md) | the plan for v1 |

## About the project

**Plan.** I am building this for my 就職作品 presentation in February 2027, and as the start of a product for
my startup, Millelith.

**How I use AI.** I built the first parts by hand to learn Go. Later parts, the tests and the docs were
written with an AI coding tool; I review, run and commit them. The product's own AI is limited by the guard.

**Releases.** Pushing a tag like `v0.1.0` runs the tests and builds the archives with
[`scripts/release.sh`](scripts/release.sh); every push to `main` runs the test gate in GitHub Actions.

**Tech.** Go, one binary. Tests with `go test`, including fuzz tests and mutation checks; the dashboard has
browser tests (`npm test --prefix tests`). Terminal screen with Bubble Tea. Commit messages follow
Conventional Commits.

**License.** MIT. See [LICENSE](LICENSE).
