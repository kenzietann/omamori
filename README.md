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

**Status: early work in progress.** Nothing runs yet. I am building it by hand,
step by step, and I am learning Go while I do it.

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

## What it will do (v1)

- **Task A: exposure check.** Look through a local project folder for leaked
  secrets and personal data. Give fix advice, like "rotate this key".
- **Task B: log triage.** Read an sshd `auth.log`. Find two cases: many failed
  logins followed by a success, and one IP trying many usernames. A normal
  program checks the AI's answer, so the AI cannot just make things up.
- **Task C: detection rules (if I have time).** The AI proposes a rule. Omamori
  tests it on sample logs.
- A very simple terminal screen set: Home, Run, Results.
- **Replay mode.** Recorded AI answers play back through the real pipeline, so
  the demo works offline. It is always labeled REPLAY.

## How the guard works

- One function sends data to the AI provider. It cleans the whole request first.
- The AI can only use read-only tools. No shell. No network tools.
- Text from scanned files is treated as data, never as instructions.
- The AI cannot change its own permissions.
- Reports show the place, the type, and a placeholder. They never show the
  secret itself.
- Your API key stays in memory. It is never written to a file or a log.

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

I write all the code by hand, to learn. I use an AI tool as a mentor and
reviewer: it explains ideas and reviews code I paste. It does not write the
code. Docs like this README were drafted with AI help and edited by me.

## Docs

- [My Number test table](docs/mynumber-test-table.md): my test cases for the
  first detector. All numbers are dummy numbers.

## Plan

I am building this for my 就職作品 presentation in February 2027. There are two
check points: end of December (Task A works through the guard) and end of
January (all must-have parts are done).

## Tech

Go. Tests with `go test`, including fuzz tests. Terminal screen with Bubble Tea
(not final yet).

## License

MIT. See [LICENSE](LICENSE).
