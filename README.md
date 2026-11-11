<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.png">
    <img src="docs/assets/logo.png" alt="Omamori logo" width="320">
  </picture>
</p>

# Omamori (お守り)

[日本語](README.jp.md)

An AI helper for blue team work. It checks a project for exposure, looks through
sshd logs, and can help write detection rules. It uses read-only tools, and a
guard sits between the AI and your data.

**Status: work in progress, Task A and Task B run.** Task A (exposure check), Task B
(log triage), the guard, a terminal screen and replay mode work. Task C and the
Should items are not done. I am learning Go while I build it.

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

v1 runs on one computer. It reads local files and one log format. It is not a
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
- **Task C: detection rules (if I have time).** The AI proposes a rule. Omamori
  tests it on sample logs.
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
- a key in an env file that `.gitignore` keeps out of git
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
