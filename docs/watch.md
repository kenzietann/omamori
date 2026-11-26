# Continuous watch and alerts

**Status: design, not yet built.** This is the plan for `omamori watch`, the first piece of turning
Omamori's batch detection into something that runs continuously and tells you when something happens.

## Goal

Run the existing rules continuously over growing log files (or `docker logs -f` / `journalctl -f`
style sources), and send new alerts to a webhook (Slack, Discord, generic) or email, without
re-alerting on the same event twice and without re-reading the whole file every time.

Everything downstream of intake stays the same: the same `rules.Set`, the same `intake.Options`, the
same sanitizer. `watch` only adds a loop and a delivery step around `detect.Run`.

## Not in this phase

- No active response (blocking, killing, changing anything on the watched system). That is a later,
  separate decision, and AI-proposed actions will always need human confirmation when it happens.
- No central collection server. `watch` reads local files/streams on the machine it runs on, same as
  `detect` does today. Multi-host collection is a later phase.
- No threat-intel feed puller yet. `--indicators` keeps working as a static file; pulling feeds on a
  schedule is a follow-up, independent of this.

## How it works

### Loop

- `omamori watch <paths>... [flags]` starts a loop. Each tick (default 15s, `--interval`):
  1. Read any new bytes appended to each watched file since the last tick (see "Offsets" below).
  2. Run them through the same intake normalization and rule set as `detect`.
  3. Compare resulting alerts against a seen-alert set (see "Dedup" below).
  4. Send genuinely new alerts to configured sinks.
  5. Persist updated offsets and seen-alert state to disk.
- Runs until cancelled (Ctrl-C / context cancellation). No daemon/service management in this phase —
  if you want it always-on, run it under systemd/launchd yourself; that's an ops concern, not
  something Omamori should reinvent.

### Offsets (and why this phase skips them)

- The design originally called for byte-offset tailing. In practice `intake.Read`'s format sniffing
  (`sniffLines`) needs a run of whole lines from the start of a file to identify its format
  reliably, and teaching it to sniff from an arbitrary offset is a bigger, riskier change than this
  first phase should make.
- **This phase instead re-reads each whole file every tick** and relies entirely on the dedup step
  below to avoid re-alerting. This costs CPU on large files re-parsed every interval, which is fine
  at the log sizes `detect` already targets, but does not scale to multi-gigabyte files or a large
  tick rate. A follow-up can add real offset tracking once the sniffer supports resuming
  mid-stream, without changing the sink or dedup logic above it.
- A state file (default `.omamori-watch-state.json` next to the first path, or `--state <file>`) is
  still used, but only to persist the dedup set (below) across restarts — not file offsets.

### Dedup (never alerting twice on the same thing)

- Reuses the fingerprinting already built for the known-good list (SHA-256 of the event content that
  made the alert fire, per `internal/knowngood`), rather than inventing a second alert-identity scheme.
- The state file keeps a bounded set (e.g. last 10,000) of fingerprints already sent, with an
  expiry so the set doesn't grow forever. An alert whose fingerprint was already sent is written to
  the local report/store (if `--store` is given) but not sent to a sink again.

### Delivery (`internal/alertsink`, new package)

- `Sink` interface: `Send(ctx, []rules.Alert) error`. Keeps alert formatting separate from transport.
- `WebhookSink`: POSTs a JSON payload to a URL (`--webhook <url>`). Works for Slack and Discord
  incoming-webhook URLs as-is, and for any endpoint that accepts a JSON body otherwise.
- `SMTPSink`: sends an email via SMTP (`--smtp-host`, `--smtp-from`, `--smtp-to`, auth from env vars,
  never from flags, so a secret never appears in `ps` output or shell history).
- Every alert body goes through the sanitizer before it leaves the process, same as the AI outbound
  path — an alert can quote a log line, and that line can contain a secret or injected text.
- Sink failures are retried a bounded number of times, then logged and skipped (never crash the
  loop, never block later ticks waiting on one dead webhook).

### Severity filter

- `--severity <level>` (default `low`): only alerts at or above this level are sent to sinks. Lower
  ones still land in the store/report if present. Keeps a noisy new rule set from spamming Slack
  during tuning.

## Open questions before building

1. Poll interval vs. real filesystem notify (`fsnotify`): polling is simpler, has no extra
   dependency beyond what's already in `go.mod`, and is good enough at a 15s default for log
   triage (not a low-latency IDS). Proposal: start with polling; revisit `fsnotify` only if the
   interval is a real complaint.
2. What counts as "the same source" across a restart of `watch` itself, vs. log rotation vs. a
   totally different file reused at the same path — covered above by inode+offset, but worth a
   dedicated test matrix.
3. Should `watch` also accept Docker/journald as live subprocess streams (`docker logs -f`,
   `journalctl -f`) piped to stdin, rather than only polling files? Proposal: yes, via `--` to pass a
   command whose stdout is treated as one growing virtual file with no offset tracking needed
   (it's already a live stream) — same dedup and sink logic applies.

## Testing plan

- Offsets: append to a file across two ticks, confirm only new lines are read, confirm restart from
  a saved state file resumes correctly, confirm rotation (truncate-then-shrink) resets and re-reads.
- Dedup: same alert fires twice across ticks (e.g. a long-running brute force), confirm only the
  first delivery reaches the sink, confirm the bounded set actually bounds and expires.
- Sinks: a fake HTTP server captures webhook payloads; a fake SMTP server (or interface mock)
  captures emails; both get a test for sanitizer application and for retry-then-skip on failure.
- Loop: cancellation mid-tick stops cleanly; a `--once` flag runs a single tick for use in tests and
  cron, without the loop.
