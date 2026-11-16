# Changelog

All notable changes to Omamori. The format follows [Keep a Changelog](https://keepachangelog.com), and
versions follow [Semantic Versioning](https://semver.org). Before 1.0, a minor version can change commands,
flags and file formats.

## [0.3.0] - 2026-11-16

Omamori reads a Mac: `forensics` on a mounted Mac disk or on `/` of a running Mac, and `detect` on the
unified log.

### Added

- **Forensic triage of macOS.** A folder with `System/Library/CoreServices/SystemVersion.plist` is read as a
  Mac, at the real places under `/private` (no link is followed). It reads the reports of the crash reporter
  in `/Library/Logs/DiagnosticReports` (kernel panics, ResetCounter reports, crashes, Jetsam events),
  LaunchDaemons and LaunchAgents (XML and binary property lists), `system.log`, `install.log`, crontabs in
  `/private/var/at/tabs`, and the shell histories (with `~/.zsh_sessions`) and `authorized_keys` of `/Users`.
  The file rules look at `/private/tmp`, `/Users/Shared`, the launchd folders and the homes.
- **The unified log of macOS** (`--format macos`): the output of `log show` in the styles default, syslog,
  compact and ndjson, found by itself. sshd and sudo of a Mac give the same events as on Linux, and the kernel
  line with the cause of the last shutdown is read. `forensics --unified-log file` adds a saved `log show`.
- **Rules for a Mac:** a kernel panic, a reset with the power button, a reset by the watchdog or another fault,
  a shutdown that was not normal, and a LaunchAgent or LaunchDaemon that starts a program from `/tmp`,
  `/Users/Shared` or a hidden folder, downloads a script, or runs encoded or inline code.
- A rule's `logsource` can list choices, as in `{product: [linux, macos]}`. The rules for SSH, sudo, crontabs,
  shell histories, `authorized_keys`, accounts and processes now fit both systems.
- **Easier installation.** `install.sh` (finds the latest release, checks its sha256, installs to
  `/usr/local/bin` or `~/.local/bin`) and a Homebrew formula that the release workflow writes to the tap
  `kenzietann/homebrew-tap` (`brew install kenzietann/tap/omamori`). CI tests the script on every push.

### Fixed

- `omamori forensics /` was refused on every system, although the README said it works. The check that keeps
  the report out of the evidence took the whole tree for the evidence. It now keeps the report out of the
  places that the run reads (`/etc`, `/var/log`, `/tmp`, `/home`, and on a Mac `/Users` and `/private`), and
  the run needs `--output`. Tested on a real Linux system in Docker and on a real Mac.
- On a Mac, `forensics` found nothing: it only knew the paths of Linux.

## [0.2.0] - 2026-11-14

Omamori reads the logs of web applications: fifteen framework setups, Docker and the systemd journal, with
rules for attacks on applications and APIs.

### Added

- **Logs of web frameworks.** Express, NestJS, Django, Flask, FastAPI, Spring Boot, ASP.NET Core, Laravel,
  Rails, Go (Gin, Echo, chi, slog, zap, zerolog, logrus) and Rust (actix-web, Axum with tracing): their text
  formats (`--format app`) and the field names of their JSON loggers. A logged request is read like an nginx
  line, so the web rules work on every framework; behind a proxy the client comes from `X-Forwarded-For`.
- **Docker and journald.** Docker json-file logs, `docker logs --timestamps`, and `journalctl -o json` (system
  programs as syslog, applications with the framework readers). Servers without `auth.log` can be read now.
- **Rules for applications and APIs:** login guessing, many accounts tried, a login after guessing, bursts of
  refused requests and of server errors, exposed debug endpoints of frameworks, database errors from inputs.
- **Real logs as tests.** Fifteen framework setups were attacked in Docker; their logs are fixtures, and a
  test checks that every line is read and the same rules fire.

### Fixed

- The injection rule missed an injection written with a raw quote and encoded spaces, as Flask logs it.
- The message for a folder without logs did not name `pcap` among the formats.

## [0.1.0] - 2026-11-13

The first public preview. Every feature below runs and has tests, and the main paths were tested live, but
nobody outside the project has used it yet. Read the limits before you rely on a result.

### Features

- **Guard around the AI.** One outbound function sanitizes every request (secrets and personal data become
  placeholders that are never turned back), the AI only has read-only tools, text from evidence is treated
  as data, and the request is shown before anything is sent.
- **Exposure check (Task A).** An AI agent looks through a project for leaked secrets and personal data
  (cloud and AI provider keys, tokens, JWTs, private keys, passwords in addresses, マイナンバー, Japanese
  phone numbers) and gives fix advice. `peek` shows the matches on your screen only.
- **Log triage (Task B).** The AI finds password guessing and spraying in an sshd `auth.log` (classic or
  ISO times, `sshd-session` of OpenSSH 9.8+); code checks every line, time and count it cites.
- **Detection.** `detect` reads syslog, web logs, JSON, Suricata, Zeek, Wazuh, Windows/Sysmon and packet
  captures, and runs 35 built-in rules in a documented Sigma subset with tests in each rule. Asset and
  indicator lists join machines and mark known bad addresses, domains and hashes.
- **AI analyst.** `analyze` lets the AI review the alerts; every citation, count, time and link is checked
  by code, and only checked claims are shown.
- **Forensic triage.** `forensics` reads a Linux system read-only, hashes every file into a manifest
  (`forensics verify` checks it later) and builds one timeline from logs and artifacts, with an optional
  checked AI review.
- **File rules.** A YARA-like format (text, hex and RE2 strings, conditions, tests in the rule) and seven
  built-in rules for droppers, reverse shells, miners, programs in temporary folders, web shells, key
  planting and log wiping.
- **Packet captures.** pcap and pcapng become Zeek-like connection, HTTP and DNS events with the TLS server
  name; a port scan rule.
- **AI rule writing (Task C).** `rule draft`: the AI writes the matching part of a rule, and code accepts it
  only if it passes fixed checks.
- **Store and investigations.** SQLite, PostgreSQL or MariaDB; search, cases and timelines.
- **Local web dashboard** on `127.0.0.1`.
- **Attack lab.** `omamori lab` attacks a Debian server that it builds in Docker, on a network with no way
  out, and scores 24 expected detections.
- **Home screen** (`omamori ui`) with a form for every task, **replay** of every AI run with no network,
  **synthetic scenarios**, and `eval` for live tests.

### Known limits

- Batch only: no live monitoring, no host agent, no blocking or response.
- The sanitizer removes only the data types it detects; IP addresses, names and street addresses are kept.
- The rules and the synthetic tests were written together; their numbers show that the code works as
  designed, not how many real attacks are found. The attack lab is the check against a real server.
- Live AI quality was measured on a small sample (14 of 15 runs of the fixed tests, one model).
- Binaries for macOS and Linux only. They are not signed.

[Unreleased]: https://github.com/kenzietann/omamori/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kenzietann/omamori/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kenzietann/omamori/releases/tag/v0.1.0
