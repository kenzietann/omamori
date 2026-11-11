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
```

You can type the key in the screen. On macOS a key that works is saved in your
Keychain (you can remove it in Settings). It is never printed or written to a
file. Every live run saves a report, an event log and a `recording.json` in
`~/omamori-output/`. Use `--help` for all flags.

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

## What it cannot do

I want to be clear about the limits.

- It only removes the data types it can detect: some secret formats,
  マイナンバー, and Japanese phone numbers.
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
