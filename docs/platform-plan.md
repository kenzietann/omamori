# Omamori AI blue-team platform plan and decisions

Started 2026-11-11. This file holds the plan of the platform and the reasons for the decisions.
`ROADMAP.md` is the older plan of the exposure check (v1) and is not changed here.

## Shape

One Go binary, `omamori`. Everything is a library package under `internal/`, and the CLI only connects them.

    log files ──> intake (parsers) ──> event.Event ──> rules (Sigma subset) ──> alerts
                                            │                                     │
                                            └──> store (later: SQLite) <──────────┤
                                                                                  ├──> report (Markdown, HTML)
    Linux artifacts ──> forensics (later) ──> event.Event (same timeline)         └──> AI analyst (later),
                                                                                       every claim checked by code

Omamori is an AI blue-team tool with a CLI now and a local dashboard planned. The dashboard will run on
`127.0.0.1` and use the same application services as the CLI: it is another way to use the platform,
not a separate detection or AI implementation. The guard that already exists (sanitizer, outbound,
replay, gateway, eventlog) stays the only way to an AI provider. The exposure check remains one module.

## Slices

Each slice runs end to end and ends with gofmt, vet and tests clean.

| # | Slice | State |
|---|---|---|
| 1 | `omamori detect`: sshd/syslog, web access logs and JSON lines in; Sigma-subset rules with count, distinct count, ordered sequence; alerts; Markdown, HTML and JSON report; synthetic scenarios with measured detection and false positives | built and verified (2026-11-12) |
| 2 | AI analyst on alerts: sanitized alert summaries out, claims in, each claim checked against alerts and events, only verified claims shown; replay recording; shared run service for CLI and local dashboard | built and verified (2026-11-12); live model evaluation pending |
| 3 | More intake: Suricata eve.json, Zeek, Wazuh alerts, Sysmon/Windows event JSON, with field maps and fuzz tests | December |
| 4 | Store (SQLite), search, cases, timeline across runs | January |
| 5 | Forensic triage: read-only collectors (cron, shell history, systemd units, authorized_keys, snapshots), hash manifest, attack timeline | January |
| 6 | Local web UI on 127.0.0.1 over the store | February |
| 7 | Full synthetic scenario across sources (SSH takeover, persistence, lateral movement), rehearsed demo | February |

## Decisions

1. **One event shape, flat string fields.** (`internal/event`) Parsers fill `action`, `outcome`, `user`,
   `src_ip`, ... and rules read only those. Flat strings keep the rule matcher small and make every parser
   easy to fuzz. Sigma field names of web logs and Sysmon (`c-ip`, `sc-status`, `CommandLine`, ...) are
   mapped to the same names, so shared rules have a chance to work as written.
2. **`internal/event` no longer imports `internal/authlog`.** The event type is the bottom of the platform
   and must not depend on one parser. The adapter that was there is replaced by the syslog parser of
   `internal/intake`.
3. **`internal/authlog` and `internal/triage` remain the existing Task B path.** They are the checked path of
   Task B (the AI cites line numbers and `authlog` proves them). `intake` has its own, wider sshd parser.
   Slice 2 adds a checker over events and alerts without removing the working Task B or invalidating its
   replay recordings. Consolidating the older parser is separate work.
4. **Rules are a subset of Sigma, and what is not supported is an error, never ignored.** An unknown
   modifier, an unknown correlation type or an old `| count()` condition stops the load. A rule that
   silently matches less than its author meant is worse than a rule that is refused.
5. **Everything a rule gives is a "hit", and correlations count hits.** A correlation may refer to another
   correlation (not in a circle). This is how "many failures, then a success" is written: an
   `event_count` rule, then a `temporal_ordered` rule over it and the success rule. The earlier draft
   refused this; it was the one thing the goal asks for by name.
6. **One alert for one burst.** A count rule fires when the limit is reached and then takes the next
   events into the same alert while they keep coming inside the window. 400 failed logins give one alert
   with count 400, not 391 alerts.
7. **Only `gte` and `gt` for counts.** `lt`, `lte` and `eq` mean "too few events", which needs a clock and
   not only events. It is refused until there is a real use.
8. **Rules can carry their own tests, and a rule whose tests fail is not loaded.** (Kept from the draft.)
   The built-in rules are inside the binary (`go:embed`), each with attack and benign test events.
9. **Batch first, no store yet.** Slice 1 reads files, sorts events by time and evaluates in memory, with
   hard limits on lines, events and alerts. The store comes in slice 4. Planned: `modernc.org/sqlite`
   (pure Go, so the single static binary stays; no cgo).
10. **Reports go through the code that already exists.** `reportwriter` (new folder, never overwrite,
    output must not overlap the input) and `htmlreport` (everything escaped, no script). Values from logs
    pass the sanitizer before they are written, so a token in a URL does not land in a report.
11. **Log text is data.** Parsers reject control characters and over-long lines and count what they drop.
    Nothing from a log is run or used as a path.
12. **Synthetic scenarios are code, with a seed.** (`internal/scenario`) The same seed gives the same logs
    and the same list of expected alerts, so detection and false positives are numbers in a test and not
    an impression.
13. **The CLI and local dashboard share the analyst service.** `internal/analyst` owns the bounded
    evidence snapshot, strict claim schema, checker and rendering. `internal/analysisrun` owns provider
    setup, preview/confirmation, cancellation, progress, recording and output. Neither depends on a
    terminal UI or an HTTP server. The versioned `analysis.json` result gives the dashboard checked
    findings, citations, review suggestions, rejected claims, unreviewed alerts and coverage gaps.
14. **The analyst receives evidence, not tool permissions.** One bounded alert snapshot is sent through
    the outbound guard, with no filesystem or shell tools. AI claims cite opaque alert, evidence and
    entity IDs. Code verifies the facts and writes the displayed explanations. Shared-entity links are
    investigation leads, not proof of causation or compromise. Review suggestions are never executed.

## Slice 1 verification (2026-11-12)

The continuation finished the mutation-test gaps and checked the actual command-line path.

- `go build ./...`, `go vet ./...` and `go test -race ./...` passed. Formatting and
  `git diff --check` were clean. The race run also found an older TUI test polling a context without
  synchronization; that test now uses a channel and passed 30 consecutive race-enabled runs.
- Across 25 seeds, all 300 expected rule/entity cases were found, with no unexpected rule/entity cases
  on attack days and no alerts across 26,622 benign events. These are synthetic fixture measurements,
  not estimates of production precision or recall. The expected cases count rule/entity combinations;
  repeated cron executions can produce multiple alerts for one case.
- A built binary read the seed-3 attack scenario: 2 files, 1,254 events, 17 rules, 14 alerts
  (1 critical, 5 high, 8 medium). The benign scenario had 1,056 events and no alerts. Both produced
  Markdown, HTML and valid JSON reports, and input-file hashes were unchanged.
- The three earlier surviving mutations now fail assertions: treating a missing field as empty text,
  matching `union` inside another word, and letting log text add Markdown table columns.
- The 22-case mutation rerun took place in a separate repository copy: 21 were caught by test
  assertions; removing the sequence order guard alone is now equivalent because same-event steps
  are processed in reverse order. Reversing that ordering and removing the guard together was also
  caught by the one-event sequence regression. The rollover mutation keeps its variable references
  so it fails behavior checks instead of compilation; the output-overlap case disables both checks.
- Short JSON and syslog fuzz runs passed. Regression tests also cover trailing JSON delimiters,
  leap-day rollover, overlapping inputs, distinct source references, duplicate rule aliases,
  overlapping sequence matches, capped evidence, secret redaction in JSON fields and filenames,
  literal `--` paths, and exclusive report-directory creation.

Try the commands in the [README](../README.md#local-detection-without-an-ai-provider).
The supported YAML syntax is in [rules.md](rules.md).

The detection slice is batch-only and uses no AI provider. Slow guessing below the thresholds is a named miss.
Compressed inputs, source-specific mappings for the later log formats, production log baselines,
streaming and storage remain outside this slice.

## Slice 2 verification (2026-11-12)

`analyze` connects local detection to the AI analyst, while `detect` remains entirely local.
Live analysis previews the sanitized request unless `--yes` is supplied. Analyst replay is available
through `analyze --replay` and the existing `replay` command. Both use the same checker and never fall
back to a live provider.

- Fake-provider integration tests cover guarded preview, confirmation, successful reviews, wrong
  counts, invalid model prose, provider errors, cancellation, forbidden tool requests, usage limits,
  no-alert runs, replay mismatch, transient retries and exclusive output reservation.
- The CLI path verifies all 14 alerts in the seed-3 scenario, preserves the input logs, saves the
  detection and analysis artifacts, and replays the recorded answer without constructing a live provider.
- The bundled offline fixture adds a checked shared-source-address link: 14 alerts, 15 verified
  scripted claims. It is labeled `REPLAY (scripted answers)` and makes no claim about live model quality.
- Claim tests cover fabricated evidence, unrelated entities, wrong times, duplicate and unknown
  fields, sensitive values, injection text, response-size limits, deterministic request snapshots and
  evidence omissions. A short structured-claims fuzz run completed over 117,000 executions.
- Independent review checked duplicate JSON key casing, immutable replay preparation, nested
  correlation evidence counts and request size after JSON escaping. Regression tests cover the fixes.
- `go build ./...`, `go vet ./...` and `go test -race ./...` passed. Full validation is local; no real
  provider was called, no user logs were sent, and live model accuracy remains unmeasured.

The response schema deliberately allows checkable facts and fixed review suggestions. Model prose
does not become a verified finding. Request fingerprints bind replay to the included sanitized
snapshot rather than all source bytes or full rule definitions. Evidence caps and unreviewed alerts
stay visible in the result. See [analyst.md](analyst.md) for these boundaries and the dashboard service API.

## Not decided yet

- Streaming (tail -f) evaluation. The engine is written so that state is per group, which is what a
  stream needs, but slice 1 is batch only.
- How cases are stored and linked to alerts.
