# Omamori roadmap

Last updated 2026-10-29. This is a plan, and plans can change. Dates may move.
What I build in version 1 stays small on purpose.

## Vision (long term, not v1)

Think of [Strix](https://github.com/usestrix/strix), an open-source AI
penetration testing tool, but for the blue team: an AI agent that helps security
people with defense work like detection, log hunting, and exposure checks. It is
built for security teams of any size, including big companies. Omamori is an
independent project and is not affiliated with Strix.

What makes Omamori different is the **guard** around the AI. Logs and code hold
secrets and personal data. The guard removes what it can detect before anything
leaves the machine. It also limits what the AI may do, and it checks the AI's
claims with normal code.

The vision is big. Version 1 is a small, finished, well-tested first slice.

## Time budget

- About 15 hours per week, planned at the low end.
- 2026-10-28 to 2026-12-31 is about 9 weeks, about 135 hours.
- The plan below has no spare week. If a week slips, I cut something (see
  "Cut order").

## Done so far

- Repo, license, README (English and Japanese), logo, and a branch and PR workflow.
- My Number check digit: `CheckDigit` and `Validate`, with a table test,
  bad-input tests, and a fuzz test. All test data is fake.

## Weekly plan to the December milestone

Every week has one "done check". If it fails, the week is not done.

| Week | Dates | Work | Done check |
|---|---|---|---|
| 1 | Oct 28 - Nov 3 | Write down the result of the Go spike. My Number detector for **text** (spaces, hyphens, full-width digits, boundaries). | Spike notes written. Text detector tests and fuzz pass. |
| 2 | Nov 4 - 10 | Secrets detector. Japanese phone number detector. Choose the first AI provider and the terminal UI library. | Each detector has a test corpus, held-out examples, negative tests, and a fuzz test. |
| 3 | Nov 11 - 17 | Sanitizer: placeholders such as `[SECRET:type:001]`, never restored. Set detector precision and recall targets, and a speed budget. | A planted fake value never survives the sanitizer. Targets written down. |
| 4 | Nov 18 - 24 | Path and argument checks (no `..`, no symlink escape, output folder must not overlap the project). Tool gateway with an allow-list and limits. Read-only tools and a constrained report writer. | A security test for each refusal: unknown tool, bad argument, over limit, path escape. |
| 5 | Nov 25 - Dec 1 | Terminal UI skeleton (Home, Run, Results) that opens and quits cleanly. Safe event log. Compare with 2 or 3 similar tools. | UI opens and quits from every screen. Every created file is scanned for planted values. |
| 6 | Dec 2 - 8 | Provider adapter and **one** outbound function. Consent text and dry run. API key from an environment variable, memory only. | Tests with a fake provider (multi-turn, retries): no planted value in any request. |
| 7 | Dec 9 - 15 | Agent loop with a fake provider: step limit, token limit, retries, cancel. Prompt-injection tests. | The same scripted run gives the same result every time. Cancel stops everything. |
| 8 | Dec 16 - 22 | Task A, the exposure check: a fixture project with expected findings, safe file references, fix advice, and a report with a "limits" section. | The report has exactly the expected placeholders at the expected places. |
| 9 | Dec 23 - 31 | Connect the screens to the real run. One real live run on the fixture. Record it and replay it through the real pipeline. | **December milestone** (below). |

## December milestone

With one provider, the agent completes Task A on a sample project through the
guard, started from the terminal UI. The result has the correct expected findings
and locations, checked automatically. The run is recorded and replays through
the real pipeline.

## January: finish v1

| Work | Done check |
|---|---|
| Task B: triage of sshd `auth.log`, two scenarios, a deterministic checker | All Task B tests pass |
| Replay mode complete (always labeled REPLAY, never falls back to a live call) | A changed request stops the run with an error |
| Report and README finished, with the supported secret formats listed | A new reader can run the demo in 10 minutes |
| Usability test with 3 people who never saw Omamori | Each runs Task A in under 5 minutes. I fix what confused them. |
| Threat model built from the tests (at least 10 prompt-injection attempts) | Listed with results |
| Only if time remains: detection rule writing, canary tokens, HTML report, language switch | Never at the cost of the items above |

## February

- Freeze features. No new work.
- Rehearse the 10-minute demo. Run it three times in a row, offline.
- Record a backup video. Prepare slides. Present.

## Cut order (when time runs short)

1. Optional items (rule writing, canary tokens, HTML report, language switch,
   second provider).
2. Terminal UI polish. Keep three simple screens that work.
3. Fixture size and report formatting.

Never cut: the three detectors (secrets, My Number, phone numbers), the one
outbound function, the safe event log, the prompt-injection tests, the consent
step, and API key handling. A smaller demo must not be a less safe demo.

## Habits for every week

- One branch per task, a PR for each, squash merge, Conventional Commits.
- Test first. See the test fail once before it passes.
- Fake data only. Read `git diff` before every commit.
- New ideas go to a parking list, not into the code.
- Friday check: did this week's done check pass? If not, say what is cut or moved.

## After February (not part of v1)

Written here so the ideas are not lost:

- Learn what an AI tool normally does, then write a rule list for it.
- Consistent placeholders for IP addresses and usernames (needs a design,
  because log triage needs them visible).
- More detectors: email, passwords in recognizable places, custom term lists.
- More tasks and log formats: Windows event logs, Sysmon, Sigma-style rule
  writing, hardening and persistence audits.
- More than one agent, and more than one AI provider.
- A local web interface.
- Human-approved containment steps (isolate a host, revoke a credential).
  These change systems, so they will never run automatically, and they need
  their own safety design first.
- A hosted version, public repo links, zip upload with safe handling.
- CI: GitHub Actions running `gofmt`, `go vet`, and `go test` on every PR.
