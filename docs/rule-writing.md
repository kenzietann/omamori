# AI rule writing (Task C)

`omamori rule draft` asks the AI for the matching part of one detection rule, and plain code decides
whether the rule is accepted. It stands in for a person writing a Sigma rule by hand from a few log
lines. It is PRD FR-09 (Task C).

You point at log lines and say what the rule is for. The AI writes only `logsource`, `detection` and
`tests`. The title, the level, the name, the tags and the description of the saved rule come from you
and from Omamori, so no sentence of the AI ends up in a file that a person reads as a statement.

## Try it on the synthetic campaign

```bash
omamori scenario --campaign ~/omamori-demo
```

```bash
omamori rule draft --goal "cron jobs that download a script and pipe it to a shell" \
  --title "Cron download piped to a shell" --level high \
  --example web01/auth.log:68 --year 2026 --timezone UTC \
  --provider anthropic --model <model> ~/omamori-demo/logs
```

Without `--yes` this only prints the guarded request: what would be sent, after the filter for secrets.
Nothing is sent and nothing is written. Add `--yes` to ask the AI. A live run writes
`rule-<UTC time>/` in the output folder with `report.md`, `report.html`, `draft.json`,
`recording.json`, and `rule.yml` only when a rule was accepted. To use the rule, copy `rule.yml` into a
folder and give that folder to `omamori detect --rules`.

`--replay recording.json` plays the recorded answers back with no provider. It needs the same logs, the
same examples and the same goal: if the request differs, the replay stops and no rule is written.

An example is written as a report names an event: the file name relative to the folder you gave, a
colon and the line, like `auth.log:290` or `web01/auth.log:68`. Give up to 20 with `--example`.

## From the home screen

`omamori ui <folder of logs>`, then **Rule draft**. A page asks for the goal, the example events
(separated by spaces or commas), a title and a level; tab or up/down moves between the fields, and
enter on the last field goes on. Then come the same provider, model and consent pages as for the other
AI tasks: the guarded request is shown, and nothing is sent before you confirm. If the input is wrong
(an example that is not in the logs, a level that does not exist), you are back on the page with the
reason and your text kept. The run uses the built-in benign days, 3 answers at most, and writes the
same folder as the command. The page was tested through the screen model and the backend, not by a
person in a terminal.

## What is sent

- A fixed instruction, your goal (after the filter), the example events, and up to 30 other events of
  the same logs. Other events of the same service as an example come first. Copies of an example (the
  same fields on another host) are left out, because they are not events to tell apart.
- Every field goes through the filter for secrets, then the whole request goes through the guarded
  sender again. The AI has no tools. A request for tools ends the run.
- After a refused answer, the next request holds the refused answer (filtered again) and the fixed
  reasons. At most `--attempts` answers (default 3, at most 5).

## When a rule is accepted

Every check is plain code. The AI's answer is refused if:

| Check | Why |
|---|---|
| it is not one YAML document with only `logsource`, `detection`, `tests`, or more than 16 KB | a title, description, level or correlation from the AI is never taken |
| selection, field or test-event names are not plain names (letters, digits, `_ . @ -`) | names show up in the rule file and in loader messages |
| the detection has control characters or a placeholder such as `[SECRET:...]` | a placeholder is removed text and never in a real log |
| it has fewer than 2 tests, or no test that expects alerts, or none that expects 0 | the rule must show what it matches and what it does not |
| the real loader refuses it, or its own tests fail | same loader and test runner as `detect --rules` |
| it misses an example in the real logs | the examples are what the rule is for |
| it matches any event of the built-in days without an attack | 4 synthetic days: three of one server, one of the three-host network (4756 events in the test run) |
| it matches any event of logs given with `--benign` | your own clean logs, the better test |
| it matches more than 5% of the events of your logs and more than 10 times the number of examples | too broad. These two numbers are a guess, not measured |

An accepted rule also gets one more test: the examples as they were sent, which it must match. The
description says the rule was drafted by an AI, from how many examples, and what it matched.

Refusal reasons are fixed text with numbers and event references. When the loader refuses a rule, its
message is kept, but every quoted name in it is replaced by "(a name)" (except the names of tests,
which Omamori writes). The model's own test names and comments never reach the report or the rule.

What does reach `rule.yml` from the AI: the log source, the detection, and the field values of its test
events. They are data with plain names, short values and no control characters, after the filter for
secrets. Read them like any rule from someone else.

## Measured

Synthetic campaign, seed 1, 1826 events. With the cron answer used in the tests (`action: cron_run`
and `command` containing `curl` and `| sh`), the rule matched the example, 3 of 1826 events (the three
runs of the planted cron job on web01), and 0 of 4756 events of the built-in days. The backup job that
also calls curl was not matched.

Tests (fake provider and recordings only): an accepted first answer; a refused then accepted answer
where the second request holds exactly the fixed feedback; every refusal reason above; a secret
planted in an example or in an answer is absent from the requests, the report, the recording and the
rule; the preview sends and writes nothing; replay with no provider, also over two answers, and a
replay that fails closed on changed logs or another goal; tool calls, the token limit, a provider
failure and cancel. A CLI test drafts the cron rule on the campaign and loads the saved `rule.yml`
with `omamori detect --rules`. `Check` was fuzzed for 60 seconds (about 3.4 million inputs). 20
mutations of the checks in a copy of the repository were all caught. One more survived because it was
equivalent (it removed an early return that a later check covers); it was replaced by two mutations of
the real condition, which are among the 20.

## Limits

- **No live provider has been called.** Nothing here says how good a real model is at this.
- Accepted means it passed these checks. It does not mean the rule is right for your network, or quiet
  on real logs. The built-in days are synthetic and small; give real clean logs with `--benign`.
- A rule that matches the examples can miss the next variant of the same attack. Read the detection.
- Only single-event detection rules. Counting and sequences (correlations) are written by hand.
- Not in the dashboard yet. The home screen has no `--benign`, `--attempts`, `--assets` or
  `--indicators`, and no replay: use the command for those.
