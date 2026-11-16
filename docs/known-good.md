# Known-good list

On your own machine, some alerts are your own doing: an installer you ran with `curl … | sh`, an agent you
installed that starts at login. The rules are right to show them, because an attacker does the same things.
But after you have looked at one, you do not want to see it in every run.

The known-good list is where you say "I looked at this one, it is mine". An alert on the list is lowered to
**known good**. It is never removed.

## Use it

```sh
# 1. A run as usual. Note the numbers of the alerts you reviewed in report.md.
sudo omamori forensics --output "/Library/Application Support/omamori" /

# 2. Add them. Each alert is shown, and only "yes" adds it.
sudo omamori known-good add --list "/Library/Application Support/omamori/known-good.yml" \
  --note "my own installers and the hermes agent" \
  "/Library/Application Support/omamori/forensics-<time>" 1 2 3

# 3. Later runs take the list.
sudo omamori forensics --output "/Library/Application Support/omamori" \
  --known-good "/Library/Application Support/omamori/known-good.yml" /

# See what is on it.
omamori known-good show --list known-good.yml
```

`detect` takes `--known-good` too. The terminal line then says how many alerts are known good:
`2 alerts, 1 medium, 1 low. 13 known good, from your list.`

## What "lowered, never removed" means

- The report has a section **Known good, from your list**, with each alert, your note, and the dates.
- The alerts stay in the timeline, with the level "known good".
- Their events stay in every rule that counts or joins events. If an attack goes through a tool you allowed,
  a rule over several events still sees it.
- `alerts.json` keeps them under `known_good_alerts`, apart from `alerts`.
- The report names the list and prints its SHA-256, so a reader sees which list was used.

## What an entry holds

No text from your system. Each event of an alert becomes a SHA-256 **fingerprint** of:

- the rule,
- every field of the event (the command, the user, the label, the file…), except the number of the process
  and what Omamori writes about where the event came from,
- for an artifact that is a whole file (a LaunchAgent, a crash report), the hash of that file,
- for a LaunchAgent or LaunchDaemon, the hashes of the programs and files that its command names: the
  hermes agent starts `osascript`, and the script names `~/.hermes/…/hermes`, so both are pinned.

An entry also holds your note (required), the date it was added, the date it expires, and the machine.

```yaml
version: 1
entries:
  - rule: forensics_launchd_suspicious_program
    title: A launchd item starts something that does not belong in a service
    host: keng
    note: the hermes agent, installed by me
    added: "2026-11-16"
    expires: "2027-02-14"
    items:
      - subject: 3f1c…
        fingerprint: 9a07…
```

## When an alert comes back

| What happened | What you see |
|---|---|
| The thing changed: the LaunchAgent, or a program it starts, is not the same file | the alert is back, "changed since you allowed it on …, look again" |
| The entry expired (90 days by default, `--days` up to 366) | the alert is back, "your entry expired on …, look again" |
| Something new that looks like what you allowed: another `curl … \| sh`, another agent | a new alert, because its fingerprint is different |
| The same thing on another machine | an alert: an entry holds on the machine of its report, unless you add it with `--any-host` |

## What it refuses

- **A list inside the evidence** or the places that a run reads. Whoever controls the system must not
  control which alerts are lowered. On a running Mac, keep it next to the reports, for example in
  `/Library/Application Support/omamori`, or on a disk of your own.
- **A list that is not valid**: an unknown field, a missing note, a hash that is not 64 hex characters, an
  entry that holds longer than 366 days, another version.
- **An alert that counts more events than it keeps**, like password guessing over hundreds of lines. Not every
  event can be pinned, so it cannot be put on the list.
- **`--store` and `--analyze` with a list**, in this version. The store and the AI review would treat the
  known-good alerts as alerts; until they know the difference, the two are refused.
- **Adding without an answer.** There is no flag to skip the question. A person says yes to each alert.

## What it does not protect against

Read this before you rely on it.

- **The list is a plain file, not signed.** Someone with root on the machine that holds it can change it,
  and also change Omamori. The report prints the hash of the list; compare it with the one you know. For an
  incident that matters, copy the disk and look at it from a clean machine, with a list kept there.
- **What you allowed can go bad later**, for example a vendor whose installer is hacked next month. The list
  says what you trusted when you looked, not that it is still safe. That is why entries expire.
- **If an attacker was there before you looked**, and you say yes to their agent, the list trusts it. You are
  the last check. Read each alert before you type yes.
- **alerts.json is what `add` reads.** Someone who can change a report folder can change what `add` shows
  you. Keep report folders where only you can write (a run as root makes them so).
- An entry pins programs by hash, so every update of the program brings its alert back once. That is on
  purpose: look, and add it again.
