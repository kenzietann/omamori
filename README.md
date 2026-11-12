<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.png">
    <img src="docs/assets/logo.png" alt="Omamori logo" width="320">
  </picture>
</p>

# Omamori (お守り)

[日本語](README.jp.md)

An AI blue-team tool for exposure checks, log detection and evidence-based alert
review. It uses read-only tools, and a guard sits between the AI and your data.
The CLI and a dashboard running locally on `127.0.0.1` use the same detection,
analyst and investigation services.

**Status: work in progress, detection, AI analysis and persistent investigation data run.** Task A
(exposure check), Task B (AI log triage), the guard, a terminal screen and replay
mode work. `detect` checks local logs with rules and `scenario` makes synthetic
demo logs. `analyze` reviews detected alerts with the AI and verifies its claims.
SQLite, PostgreSQL and MariaDB can store runs for search, cases and timelines.
`forensics` reads the artifacts of a Linux system read-only, hashes them and
builds a timeline. `rule draft` (Task C) lets the AI write the matching part of a detection rule,
and code accepts it only if it passes fixed checks. No live model has been measured on it yet.
The remaining Should items are not done. I am learning Go while I build it.

## Why I am building this

Security teams want to use AI for blue team work, like detection, log checks,
and leak checks. But logs and code are full of secrets and personal data.
Sending them to an AI company as they are is a risk. In a big company it may
also break company rules.

Omamori tries to fix that. You use your own API key. Before anything leaves
your computer, the guard removes the sensitive data it can detect.

## Who it is for

Security engineers and developers, in companies of any size. A security team in
a big company can use it for first-pass blue team work, like checking logs and
writing detection rules. A small team with no security person can use it too.

v1 runs on one computer. It reads local files and logs. It is not a
SIEM and not a hosted service.

## Quick start

```
go install ./cmd/omamori
omamori providers                       # which AI providers have a key
omamori check ./some-project            # Task A
omamori triage ./auth.log --year 2026   # Task B
omamori replay ~/omamori-output/run-.../recording.json ./some-project
omamori eval --yes --runs 3             # live test on the fake fixtures, with a token cap
```

You can type the key in the screen. On macOS a key that works is saved in your
Keychain (you can remove it in Settings). It is never printed or written to a
file. Every live run saves a report (`report.md` and a static `report.html` with no script),
an event log and a `recording.json` in `~/omamori-output/`. Use `--help` for all flags.

### Local detection, without an AI provider

`detect` reads sshd/Linux syslog, Apache/Nginx access logs, or JSON lines with a
timestamp. It normalizes supported Suricata EVE, Zeek, Wazuh and Windows/Sysmon
JSON exports into the shared event fields. It applies 29 built-in rules, including counts, distinct counts and
ordered sequences such as password guessing followed by a successful login.
Rule evaluation uses no API key. The command stays local unless you enable
storage on a configured database server.

Try it with made-up logs in a new folder:

```sh
omamori scenario --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-logs
omamori detect ./demo-logs --year 2026 --timezone Asia/Tokyo --output ./demo-reports
```

This example produces 14 alerts, including one critical alert for a login after
password guessing. Reports are saved in a new `detect-...` folder as `report.md`,
`report.html` and `alerts.json`. Existing run folders are refused. The logs stay
unchanged. `expected.json` describes the synthetic scenario; the report lists it
as skipped because it is not a log.

Use `scenario --benign` for a day without planted attacks, `detect --rules ./rules`
to load your own YAML rules, or `--format syslog|web|json|suricata|zeek|wazuh|windows`
to choose a parser. Auto mode can read mixed JSON sources; an explicit source
format counts other shapes as unread. See the [intake guide](docs/intake.md)
for field mappings, supported exporters and limits. The built-in rules cover
SSH, Linux host events, web servers, and movement inside a network as Zeek and
Suricata see it; additional sources can use custom rules.
Custom rules replace the built-in set. The rule format is a documented subset of
Sigma: unsupported conditions and modifiers are refused. Rules can include test
events, and a rule set with failing tests is refused too.

The tests cover 25 synthetic seeds, including ordinary logins, typos, web visits
and scans. These checks measure the generated fixtures, not production accuracy.
Slow password guessing below the configured thresholds is a known miss. Classic
syslog has no year or time zone, so set `--year` and `--timezone` for the logs.

### AI analyst over the alerts

Use the same logs with `analyze`. It sends a bounded, sanitized evidence snapshot
through the existing guard. The AI can review alerts, identify shared entities
and suggest investigation steps. Code checks its citations, counts, times and
relationships before constructing the displayed findings. It has no tools, and
its suggestions are not executed.

```sh
omamori analyze ./demo-logs --year 2026 --timezone Asia/Tokyo --dry-run
omamori analyze ./demo-logs --year 2026 --timezone Asia/Tokyo --yes
```

Select the provider and model using `--provider` and `--model`, the environment,
or existing saved settings. Without `--yes`, the command shows a request preview
and sends nothing. Runs save the detection report, checked analysis, coverage
gaps and a replay recording when an answer can be recorded. Invalid AI claims
never replace the rule alerts. The versioned `analysis.json` result and shared
run service are also intended for the local dashboard.

For a demo with no provider or key, use the [bundled scripted analyst replay](testdata/fixtures/analyst/README.md).
It checks 14 alert reviews plus one shared-entity link, and is explicitly labeled
as scripted. See the [analyst guide](docs/analyst.md) for the schema boundaries,
replay behavior and integration APIs. Local fake-provider and replay tests verify
the pipeline; live model quality has not been measured for this slice.

The [multi-source fixture](testdata/fixtures/intake/README.md) exercises all four
new source families with eight synthetic records and six expected observation
alerts. It runs through the same detection and analyst services as the CLI and
local dashboard.

### Store, search and investigate

Add `--store` to `detect` or `analyze` to keep the sanitized run, including all
parsed events, its alerts and checked analysis. SQLite is the default local
backend at `~/omamori-data/omamori.db`; `--db file` chooses another SQLite file.
PostgreSQL and MariaDB use `OMAMORI_DB_DRIVER` and `OMAMORI_DB_DSN` from the
environment. Request previews never open the database.

```sh
omamori detect ./demo-logs --year 2026 --timezone Asia/Tokyo --store
omamori store runs
omamori store search --field src_ip --value 203.0.113.9
omamori store search --kind alerts --level critical
omamori store cases create --title 'Authentication review'
omamori store timeline --from 2026-11-10T00:00:00Z --to 2026-11-11T00:00:00Z
```

Cases link chosen alerts across runs and use versions to prevent stale updates.
Timelines retain event/alert provenance, and AI citations resolve to full stored
events. These APIs are shared with the local dashboard. See the
[storage guide](docs/storage.md) for backend setup, case commands, query semantics
and limits. PostgreSQL and MariaDB have been tested with disposable real servers,
including the CLI detection and analyst replay paths.

### Forensic triage of a Linux system

`forensics` reads logs, crontabs, systemd units, `authorized_keys`, shell
histories and `/etc/passwd` from a folder (a mounted image, a copy, or `/`), and
saved output of `ps` and `ss` when you give it. It only reads. Every file it
opens is hashed into a manifest that can be checked again later. The same rules
and the same store are used, and alerts from logs and artifacts stand in one
timeline that says where each time comes from.

```sh
omamori scenario --host --date 2026-11-10 --timezone Asia/Tokyo ./demo-host
omamori forensics --year 2026 --timezone Asia/Tokyo \
  --processes ./demo-host/snapshots/ps.txt --sockets ./demo-host/snapshots/ss.txt ./demo-host/root
omamori forensics verify ~/omamori-output/forensics-<time>/manifest.json ./demo-host/root
```

Password hashes and private keys are never read, and links are not followed.
Add `--analyze` for the checked AI review of the alerts; findings that rest only
on a file's last change are marked as having weak times.
See the [forensics guide](docs/forensics.md) for what is read, what the times
mean and what is not covered.

## Live test results

`omamori eval` runs a fixed set of real-provider runs on the fake fixtures (Task A, and four
logs for Task B) and scores them on correct findings and correct locations, not on wording.
It stops at a token cap. The table is saved as `live-results-*.md`; paste the latest one here.

Latest run (2026-11-11, `gpt-6-luna`, 3 runs per case, 43,220 tokens in all): **14 of 15 runs passed.**

| Case | Passed | Avg requests | Avg tokens |
|---|---|---|---|
| Task A: exposure fixture | 3 of 3 | 2 | 1307 |
| Task B: guessing.log | 3 of 3 | 3 | 3440 |
| Task B: spraying.log | 3 of 3 | 3 | 3421 |
| Task B: benign.log | 3 of 3 | 3 | 2992 |
| Task B: malformed.log | 2 of 3 | 3 | 3246 |

The one failure: the AI did not claim a finding that was in the log, so the checker listed it
as "found by Omamori, not claimed by the AI". Nothing false was accepted. Three runs per case is a
small sample, so the rates are rough. The first live run was 12 of 15: the AI read "invalid user
admin" as a different user. The instruction was made clearer for that, which is why the
numbers changed between runs.

## What it will do (v1)

- **Task A: exposure check.** Look through a local project folder for leaked
  secrets and personal data. Give fix advice, like "rotate this key".
- **Task B: log triage.** Read an sshd `auth.log`. Find two cases: many failed
  logins followed by a success, and one IP trying many usernames. A normal
  program checks the AI's answer, so the AI cannot just make things up.
- **Task C: detection rules.** You point at log lines and say what you want. The AI writes
  the matching part of a rule. Omamori accepts it only if it loads, passes its tests,
  matches every example, and matches nothing on days without an attack
  ([rule-writing.md](docs/rule-writing.md)).
- A terminal screen: setup pages, then the run prints a live progress bar and the
  report into the normal terminal, so you can select and scroll it.
- **Replay mode.** Recorded AI answers play back through the real pipeline, so
  the demo works offline. It is always labeled REPLAY.

## How the guard works

- One function sends data to the AI provider. It cleans the whole request first.
- The AI can only use read-only tools. No shell. No network tools.
- Text from scanned files is treated as data, never as instructions.
- The AI cannot change its own permissions.
- Reports show the place, the type, and a placeholder. They never show the
  secret itself.
- Your API key is never printed, logged, or written to a file. On macOS it can be
  kept in the Keychain.

## What it detects

- AWS access key IDs (`AKIA`, `ASIA`) and GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- AI provider keys (`sk-`, including `sk-ant-` and `sk-proj-`), Google API keys (`AIza`),
  Slack tokens (`xox`), Stripe live keys (`sk_live_`, `rk_live_`)
- JWTs (three parts, starting with `eyJ`)
- Private key blocks (the whole block, from BEGIN to END)
- Passwords written inside web or database addresses (`scheme://user:password@host`)
- マイナンバー (a valid check digit gives "possible identifier" only) and Japanese phone numbers

A phone-like number in a generated file (build output, a cache, a test report, `.map` and
`.min.js` files) gets severity `low`, because it is nearly always code and not a person.
A secret in the same file stays `high`.

A key in an env file (`.env`) that a `.gitignore` file keeps out of git is the normal setup.
It is listed in its own section, "Kept out of git", and is not counted as a finding. If the
file is not ignored, the key is `high`.

Matches in libraries (`deps`, `.angular`, `site-packages`, ...) and phone-like numbers in build
output (`dist`, `.map`, `.min.js`, test reports) are listed in their own section, one line per
file line, and are not counted as findings. A secret in your own build output still counts.

### What is not counted as a finding

Every match is still hidden from the AI. These are only left out of the count, and each one is
listed in its own section of the report:

- digits inside a long decimal (`-0.0643290124`), a UUID, a table or hex dump, next to letters
  (`abc0312345678`), or between colons (an AWS account number in an ARN)
- test values: digits that count up or repeat (`0123456789`, `0000000000`)
- example passwords in an address (`user:pass@`, `${PASSWORD}`, `<password>`)
- library, cache and plugin folders (`deps`, `.angular`, `.agents/skills`, `.claude/plugins`, ...)
- phone numbers and My Numbers in build output
- a key in an env file that `.gitignore` keeps out of git, and that git says was never committed.
  If the file is in the history (committed once, ignored later), the key is a finding: it is still
  readable by anyone who can read the repository
- binary files (images, archives) are not scanned

A real password in an address, a key in your own code, and a phone number in your own data are
still counted.

### Looking at the matches

A report holds places and placeholders only. To tell a false alarm from a real leak, look at
the matches on your own screen:

```
omamori peek ~/omamori-output/run-... ./your-project           # the middle of each value is hidden
omamori peek --reveal ~/omamori-output/run-... ./your-project  # full values
```

It finds each match again in the file and prints the value and the text around it. Nothing is
saved and nothing is sent to the AI. A private key block is never shown, only its first line.

Every detector has a test table with fake values, a list of look-alikes that must not match,
and a fuzz test.

## What it cannot do

I want to be clear about the limits.

- It only removes the data types it can detect (see above). A password in a
  config line like `password = hunter2` is not found.
- It does **not** remove IP addresses, names, or street addresses in v1.
  IP addresses stay because log triage needs them.
- A valid マイナンバー check digit only means "possible identifier". About 1 in
  10 random 12-digit numbers pass by luck.
- It reduces what the AI company sees. It cannot control what the company does
  with the data after it gets it.
- It is for defense only. There is no attack code, and there never will be.

## How I use AI

I built the first parts by hand to learn. Later parts, the tests and the docs were
written with an AI coding tool, and I review, run and commit them. The product's own
AI is limited by the guard and can only use read-only tools.

## Docs

- [Platform plan and decisions](docs/platform-plan.md): the detection pipeline,
  supported rule subset, verification results and next slices.
- [AI analyst](docs/analyst.md): checked alert reviews, replay and the shared
  service for the local dashboard.
- [Local rules](docs/rules.md): supported detection and correlation YAML.
- [AI rule writing](docs/rule-writing.md): `rule draft`, what is sent, the checks
  that decide whether a rule is accepted, and their limits.
- [Log intake](docs/intake.md): supported source formats, field maps and a
  mixed-source demo.
- [Storage and investigations](docs/storage.md): SQLite/PostgreSQL/MariaDB,
  persistent runs, search, cases, timelines and dashboard APIs.
- [Toolkit map](docs/toolkit.md): the blue-team tool families Omamori is growing
  toward, what exists for each and what is missing.
- [Demo: one attack through three hosts](docs/demo.md): the synthetic campaign
  across host logs and network sensors, what is found and what is not.
- [Forensic triage](docs/forensics.md): read-only collection of Linux artifacts,
  the hash manifest, the timeline and its limits.
- [My Number test table](docs/mynumber-test-table.md): my test cases for the
  first detector. All numbers are dummy numbers.

## Plan

I am building this for my 就職作品 presentation in February 2027. There are two
check points: end of December (Task A works through the guard) and end of
January (all must-have parts are done).

## Tech

Go. Tests with `go test`, including fuzz tests. Terminal screen with Bubble Tea.
Providers: Anthropic and any OpenAI-compatible API (OpenAI, Gemini, Mistral, Groq,
Together, DeepSeek, xAI, OpenRouter, Ollama, LM Studio). Design choices are in
[DECISIONS.md](DECISIONS.md).

Code style: I use clear, full-word names (like `expectedCheckDigit`, not `x`). Commit
messages follow Conventional Commits.

## License

MIT. See [LICENSE](LICENSE).

### Home menu

`omamori ui <folder>` opens the terminal home menu. It connects exposure checks,
log triage, local detection, checked AI analysis, forensic collection (with an
optional AI review), stored-run listing and synthetic demo generation to their
real services. Local tasks skip provider setup; AI tasks preview the sanitized
request before confirmation. Stored-run listing uses the configured database and
does not create a missing local store during preparation.

The menu uses built-in rules and the supplied folder. Use the direct commands
for custom rules, optional forensic process/socket snapshots, storage filters,
case management and other advanced flags. Demo generation writes separate logs
and host artifacts under a new output folder; open its `logs` or `host/root`
folder for the corresponding task.

### Local web dashboard

Run `omamori dashboard <evidence-workspace>` and open the private session link
printed in the terminal. The dashboard includes saved runs, alert/event details,
checked AI citations, search, cases, timelines and confirmed detection/forensic
runs. It uses the configured SQLite, PostgreSQL or MariaDB store.

The UI is embedded in the Go binary, listens only on `127.0.0.1` (port 8765 by
default), and accepts new evidence paths only inside the chosen workspace.
Prepare a preview before confirming an AI request; provider keys stay server-side.
See [dashboard.md](docs/dashboard.md) for setup, capabilities and limits.

The dashboard’s Reference workspace puts the alert queue beside its evidence, with scoped activity
and severity charts and a persistent light/dark theme switch. On small screens, chart detail can be
expanded while the alert queue remains immediately accessible. See [DESIGN.md](DESIGN.md) for the
shared visual system and [the validation notes](docs/dashboard-design-validation.md) for test scope.
