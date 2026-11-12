# Omamori AI blue-team platform plan and decisions

Started 2026-11-11. This file holds the plan of the platform and the reasons for the decisions.
`ROADMAP.md` is the older plan of the exposure check (v1) and is not changed here.

## Shape

One Go binary, `omamori`. Everything is a library package under `internal/`, and the CLI only connects them.

    log files ──> intake (parsers) ──> event.Event ──> rules (Sigma subset) ──> alerts
                                            │                                     │
                                            └──> SQL store <─────────────────────┤
                                                                                  ├──> report (Markdown, HTML)
    Linux artifacts ──> forensics (hashed) ─> event.Event (same timeline)         └──> AI analyst,
                                                                                       every claim checked by code

Omamori is an AI blue-team tool with a CLI and a local dashboard. The dashboard runs on
`127.0.0.1` and uses the same application services as the CLI: it is another way to use the platform,
not a separate detection or AI implementation. The guard that already exists (sanitizer, outbound,
replay, gateway, eventlog) stays the only way to an AI provider. The exposure check remains one module.

## Slices

Each slice runs end to end and ends with gofmt, vet and tests clean.

| # | Slice | State |
|---|---|---|
| 1 | `omamori detect`: sshd/syslog, web access logs and JSON lines in; Sigma-subset rules with count, distinct count, ordered sequence; alerts; Markdown, HTML and JSON report; synthetic scenarios with measured detection and false positives | built and verified (2026-11-12) |
| 2 | AI analyst on alerts: sanitized alert summaries out, claims in, each claim checked against alerts and events, only verified claims shown; replay recording; shared run service for CLI and local dashboard | built and verified (2026-11-12); live model evaluation pending |
| 3 | More intake: Suricata eve.json, Zeek, Wazuh alerts, Sysmon/Windows event JSON, with field maps and fuzz tests | built and verified (2026-11-12), documented JSON subsets |
| 4 | SQLite/PostgreSQL/MariaDB storage, search, cases, timelines across runs | built and verified (2026-11-12) |
| 5 | Forensic triage: read-only collectors (cron, shell history, systemd units, authorized_keys, snapshots), hash manifest, attack timeline | built and verified (2026-11-12), with the checked AI review (`--analyze`); live model evaluation pending |
| 6 | Local web UI on 127.0.0.1 over the store | built and verified (2026-11-12), initial investigation dashboard |
| 7 | Full synthetic scenario across sources (SSH takeover, persistence, lateral movement), rehearsed demo | started (2026-11-12): campaign, nine network rules and the walk-through are built and measured; the asset list joins the story (`--assets`); a bundled analyst replay, a forensic image of web01 and a rehearsal are open |

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
9. **Batch detection with optional durable storage.** Intake and rules evaluate bounded batches in
   memory. Slice 4 adds a shared SQL store: pure-Go SQLite for local use, PostgreSQL and MariaDB for
   configured server use. Database-specific details stay behind `internal/store`; CLI and dashboard
   use the same typed APIs. Persistence is opt-in with `--store` or a SQLite `--db` path.
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
15. **Source normalization is shared and explicit.** Both commands use the same intake library.
    Documented source shapes get canonical fields plus bounded original fields under `raw.*`;
    unknown JSON remains generic. Event source and collector identity remain available to reports
    and the future dashboard. Source type is inferred from schema, never from filenames alone.
16. **Source semantics are observations.** Windows login outcomes require the Security provider and
    channel plus event ID. Sysmon process/network events do not imply malicious intent. Sensor
    policy actions and connection states do not imply attack success. Windows target accounts are
    domain-qualified when the domain is present, so same-named accounts in different domains are
    not silently combined.
17. **Store sanitized evidence, keep run identity explicit.** Every parsed event is retained within
    bounded run-size limits, including benign events. Runs are immutable and saves are atomic and
    idempotent. Alert links are resolved before redaction. Case links use run/alert IDs; placeholders
    never create inferred identity links. Analyst citation IDs map to stored event IDs within a run.
18. **Portable queries before specialized search.** Exact field filters and literal substring search
    have the same contract on all three databases. Cases use optimistic versions and explicit
    evidence membership. Timelines merge selected events and alerts with deterministic ordering.
    Full-text indexing, retention and data migration between backends are separate work.

19. **Artifacts are events.** (`internal/forensics`) A cron job, a key or a history command becomes
    an `event.Event` with `category: forensics` and a `service` that names its kind. So the rule engine,
    the report, the store and later the analyst and the dashboard take forensic runs with no second
    code path. `forensics.Run` gives a `detect.Outcome` plus the manifest, and it writes nothing.
20. **Hash what is read, while it is read.** A file is opened once, without following a link, and the
    same bytes go to the hasher and to the parser. The manifest therefore describes exactly what the
    findings were made from. The hash is always of the whole file, also when only a part is parsed.
21. **A fixed list of places, opened through `os.Root`.** No walk of the whole system: the collector
    opens named places only, so `/etc/shadow` and private keys are out by construction, not by a
    filter. `os.Root` refuses any path that leaves the evidence folder. Links are skipped and named.
22. **A time says where it comes from.** Most artifacts have no time of their own. Their events carry
    `time_source`, and the timeline shows it in words, because "last change of the file" must not be
    read as "when it happened".
23. **Artifact rules are a second embedded set.** `rules.BuiltinForensics()` is the built-in rules plus
    `internal/rules/forensic/`. `detect` keeps its 17 rules and its measured behavior unchanged.
24. **Table cells write `|` as `¦`, not as `/`.** (Changes decision 10's detail from slice 1.) In a
    shell command `curl x / sh` reads as something else than `curl x | sh`. The report says what `¦` is.

25. **The analyst takes a forensic run through the same service.** `analysisrun.Config.Base` gives the
    service another base report, more files for its folder (the manifest, written byte for byte) and a
    folder prefix. `analyze` and `forensics --analyze` end in one function, so preview, guard,
    recording, replay and storage cannot differ between them.
26. **Code, not the model, says when times are weak.** A finding that cites evidence with
    `time_source: file_modified` gets `weak_times` and a fixed sentence. The texts of findings live in
    one place (`analyst.AlertSummary`, `RelatedSummary`, `WeakTimeNote`) and the store uses the same
    functions, so a stored finding cannot read stronger than a checked one.
27. **Artifact fields are added to the snapshot, and the note to the request, only when artifacts are
    there.** A log-only run gives the same request bytes as before, which keeps earlier live recordings valid.

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
Compressed inputs, production log baselines and streaming remain outside the detection slice.
Source-specific mappings were added in slice 3.

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

## Slice 3 verification (2026-11-12)

The shared intake now normalizes Suricata EVE alert/HTTP/DNS/flow/TLS, Zeek connection/HTTP/DNS/notice,
Wazuh alerts (including nested Windows events), Winlogbeat and NXLog Windows JSON. Supported Windows
behavior covers Sysmon 1/3 and Security 4624/4625; other event IDs retain metadata without inferred behavior.
The source field dictionary and primary references are in [intake.md](intake.md).

- The mixed-source CLI fixture reads 8 synthetic records using 8 custom rules and produces 6 expected
  alerts. All four normalized source families appear in alert evidence; generic JSON remains generic.
- A fake-provider analysis of those alerts verifies all 6 claims, includes source/process/network
  context and leaves the original fixture unchanged. An explicit `windows` run accepts 3 records,
  produces 2 alerts and reports the other 5 records as unread.
- Regression tests cover source look-alikes, conflicting raw canonical fields, invalid IPs/ports,
  source event times versus collector times, UTC Sysmon times, target versus subject accounts,
  domain-qualified users, malformed identity text and ambiguous flattened evidence paths.
- Network normalization fuzzing completed 517,853 executions; host normalization 240,914; the full
  source-aware JSON parsing path completed 294,413. These bounded fuzz runs found no failures.
- Richer analyst metadata exposed a worst-case request-size edge: a single large alert could leave
  no alerts after pruning. Each evidence item now has a 1,600-rune cumulative field-value budget,
  with a 200-rune per-field maximum and explicit `truncated_fields` coverage. Regression tests retain
  useful evidence and keep the serialized request within 256 KiB.
- `go build ./...`, `go vet ./...`, `go test -race ./...`, formatting and diff checks passed.
  A built binary also completed the fixture through offline scripted analysis: 6 verified claims,
  no rejected or unreviewed alerts, all four source families present and input hashes unchanged.

The 17 built-in rules are unchanged. Parser support is not complete detection coverage. Native EVTX,
XML, Zeek TSV, JSON arrays and arbitrary PowerShell object dumps are not supported. Real sensor
deployments and live AI quality remain unmeasured. The SQL store added in slice 4 supports these
normalized records and will supply the local dashboard.

## Slice 4 verification (2026-11-12)

The shared store supports SQLite, PostgreSQL and MariaDB with versioned schema initialization,
parameterized queries, atomic immutable run saves, sanitized case notes and bounded pagination.
`detect` and `analyze` can persist runs, and `store` provides run listing/details, event and alert search,
case create/update/link/detach operations, and cross-run timelines. Previews never touch the database.

- SQLite scenario integration stores all 1,254 parsed events and 14 alerts; all 288 benign health-check
  events remain searchable. Re-saving identical data is idempotent.
- A case linked to the critical SSH sequence has 42 timeline entries: 41 retained step events plus
  the alert. Unrelated run events stay outside the case; cross-run evidence keeps its run identity.
- Opaque AI citations map to full stored event IDs through each alert payload. Regression tests cover
  duplicated input records, pre-redaction identity, final successful-login evidence and run scoping.
- Shared contracts passed on SQLite, PostgreSQL 18.4 and MariaDB 12.2.2, including a MariaDB database
  with case-insensitive defaults. Real testing exposed padded-string comparison differences; the
  MariaDB schema uses explicit nonpadding binary collation and exact-value hashes.
- Real server CLI smoke tests stored 8 mixed-source events/6 alerts, searched them, linked a case,
  rendered its timeline, rejected stale updates and persisted a 6-claim analyst replay. No live AI
  provider was used, and source-file hashes stayed unchanged.
- Tests cover rollback after an insert failure, foreign keys, future-schema rejection, concurrent
  idempotent saves, cancellation, database-error redaction and restrictive new SQLite file modes.
- `go build ./...`, `go vet ./...`, the full `go test -race ./...` suite, formatting and diff checks
  passed. A final race-enabled contract run passed on both real server backends after the combined
  case/filter regression was fixed. Disposable servers, test credentials and data were cleaned up.
- A `CGO_ENABLED=0` build also passed an actual SQLite CLI smoke: 8 events/6 alerts persisted,
  a linked case timeline returned its 2 expected entries, a versioned close succeeded, and the new
  database file had mode `0600`.

See [storage.md](storage.md) for configuration, command examples, query semantics and limits.
The store supplies the local dashboard implemented in slice 6.

## Slice 5 verification (2026-11-12)

`omamori forensics` reads a fixed list of Linux artifacts from an evidence folder, hashes each file,
evaluates 27 rules (17 built-in, 10 for artifacts) and writes `report.md`, `report.html`, `alerts.json`,
`manifest.json` and `manifest.sha256`. `forensics verify` checks the hashes again. `scenario --host`
writes a synthetic system. See [forensics.md](forensics.md).

- Across 25 seeds, 550 of 550 expected rule/entity cases were found on attacked systems (12 from logs
  and 10 from artifacts each), with no unexpected case and no alert on the 25 systems without an attack
  (1,375 benign artifact events). These are synthetic fixtures written together with the rules, not an
  estimate for real intrusions.
- The seed-3 system through the built command: 22 files hashed, 1,254 log events, 77 artifacts, 26 alerts
  (3 critical, 14 high, 9 medium). `shasum -c manifest.sha256` and `forensics verify` agree; after one
  changed byte `verify` names the file and ends with an error code. The run was stored in SQLite and
  its artifacts and alerts were found by search.
- Tests compare content, mode and time of change of every file and folder of the evidence before and
  after a run. Links (inside and outside the folder, to files and to folders), a named pipe, a hostile
  manifest with paths out of the folder, `/etc/shadow`, private keys and a secret inside a history are
  each covered by a test with a canary value.
- Looking at the real report found two defects that the tests had missed: tab-separated lines of
  `/etc/crontab` put a part of the command into the user column, and `|` in table cells was shown as `/`.
  Fuzzing found a crash in the process snapshot parser (a heading with COMMAND before PID). All three
  are fixed and have regression tests; the fuzz input is kept in `testdata`.
- Seven parser fuzz targets ran 10 to 20 seconds each after the fix with no failure.
- 23 mutations were made in a copy of the repository. 19 were caught at once. Two survivors showed
  missing assertions, which were added (appending to a log is not emptying it; a manifest path out of
  the folder is reported as an invalid manifest, not as a missing file). Two were each one half of a
  deliberate double check (file type before and after opening): removing either half alone changes
  nothing, removing both is caught.
- Two test expectations of mine were wrong and were corrected, not the code: a tab inside a cron
  schedule is turned into a space, and the report itself names `/etc/shadow` in its limits.

Not verified: real disk images, real distributions other than the Debian-like layout of the scenario,
SELinux or immutable-file cases, very large evidence folders, and Windows as the machine that runs the
tool (`O_NOFOLLOW` and named pipes are Unix).

### Analyst over forensic runs (2026-11-12)

`omamori forensics --analyze` sends the alert snapshot of a triage through the existing analyst service.

- With a fake provider on the seed-3 system: 26 alerts, 26 verified claims, one request, no tools.
  Seven findings are marked `weak_times` (the account, two cron entries, the unit, two processes and
  the history link). A secret planted in the history is absent from the preview, the request, the
  reports, `alerts.json`, the recording and the stored run.
- The preview sends nothing, writes nothing and makes no database. The manifest of an analyzed run is
  byte for byte the manifest of the triage, and `forensics verify` accepts it.
- The recording replays offline with no provider. After one byte of `/etc/passwd` changes, the replay
  ends as incomplete with no verified finding. An answer that is prose is rejected, and the triage
  report, the alerts and the manifest are still written.
- The request of a log-only run is unchanged, which a test compares with the fixed instruction.
- 13 mutations in a copy of the repository were all caught by test assertions. Two of them compiled
  only after a second try, and one showed a missing test (an added file with the name of a report),
  which was written.
- No live provider was called. How well a real model reviews artifact evidence is not measured.

## Slice 6 implementation (2026-11-12)

`omamori dashboard` embeds the UI in the binary and adapts shared services over a loopback-only HTTP
server. It provides recent-run overview, stored runs, alerts/events, checked AI citation navigation,
search, case editing with optimistic versions, scoped timelines and a confirmed run queue.

- A per-launch token protects API access; Host/Origin checks and JSON-only mutations reject foreign
  browser access. No arbitrary files or shell commands are served. New input/rule/snapshot paths
  are confined to the approved root, and outputs/database files stay away from evidence.
- Run preparation sends no AI request and writes no run artifacts. Explicit confirmation starts a
  frozen preview once. Progress, cancellation, expiry, incomplete results and saved-run links are
  exposed through bounded job state. Existing services perform the actual analysis and persistence.
- Provider keys and database credentials stay server-side. The UI uses no CDN or external scripts.
  It renders evidence and case notes as text and preserves weak-time and coverage disclosures.
- Desktop browser checks exercised case create/link/update, case timeline, a confirmed 8-event /
  6-alert detection run and AI citation-to-event navigation using a labeled scripted replay.
  Script-like case notes remained inert. At 390 px, tables scroll inside panels without page overflow.
- Build, vet, the full race-enabled Go suite, formatting and JavaScript syntax checks passed.
  The final browser session reported no console errors; a server restart invalidated the old token
  and the new private link reconnected successfully. No real AI provider was called for these checks.
- Automated tests cover access boundaries, path escape, cancelled/expired previews, double starts,
  fake-provider review, source preservation, metadata redaction and forensic manifests. External
  process/socket snapshots remain explicitly not rechecked by manifest verification, as in the CLI.

See [dashboard.md](dashboard.md). Full cross-source rehearsal remains slice 7. Live model evaluation,
streaming, multi-user access and production sensor/disk validation are not claimed by this dashboard.

## Slice 7, first part (2026-11-12)

`omamori scenario --campaign` writes one attack through three hosts (web01, app01, db01) as six log
files of five kinds: sshd logs of each host, the web log of web01, a Zeek connection log and Suricata
alerts. Nine rules were added to the built-in set (26 in all) in `internal/rules/builtin/network.yml`:
guessing from an internal address and a login after it, a sweep of internal addresses, a large upload
to an external address, and sensor alerts of severity 1. [demo.md](demo.md) is the walk-through.
The home screen also got a Dashboard line, which starts the same server as the `dashboard` command.

- Across 25 seeds, 425 of 425 expected rule/entity cases were found, with no unexpected case and no
  alert on 39,397 events of days without the attack. Synthetic fixtures written with the rules.
- Seed 3 through the built command: 6 files, 1,820 events, 19 alerts (2 critical, 9 high, 8 medium);
  the benign campaign gives none. The report names evidence from every source in one timeline.
- 13 mutations in a copy of the repository were caught by test assertions. One of them (removing the
  check for the confirmation of the Dashboard task) first made a test wait forever; that test now has
  a deadline and fails in five seconds.
- One expectation of a new test was wrong (the split of alert levels) and was corrected.

Open, and said in the demo: the login to db01 with a stolen key gives no alert; nothing joins the host
name `web01` with its address `10.0.1.10`, so the alerts of the first host and of the movement share no
entity; the rules have no knowledge of the network and need filters for jump hosts, scanners and cloud
backups. Next: an asset list that gives events of a host its address (and the other way), a scripted
analyst replay of the campaign, a forensic image of web01 that fits the same story, and a timed rehearsal.
The Dashboard line of the home screen was tested through its backend, not by a person in a terminal.

### Asset list (2026-11-12)

`internal/assets` reads a YAML list of your machines (name, addresses). `detect --assets` and
`analyze --assets` give every event `asset`, `src_asset` and `dst_asset` from that list. Correlations got
Sigma's `aliases`, and a correlation hit now has every field on which all its kept events agree. One rule
uses both: a host that was logged in to after guessing and then guesses inside (27 built-in rules).

- Campaign with the list, 25 seeds: all expected alerts plus the joining alert, its two steps from the
  logs of web01 and of app01, nothing unexpected, and no alert on days without the attack.
  Without the list the result is as before.
- Through the command line with seed 3: 20 alerts (3 critical). A scripted AI answer that relates the
  takeover of web01 and the guessing from web01 through the machine is verified (21 findings) and
  stored. The same answer without the list is refused for that one claim.
- That test found a defect: the store kept its own copy of the list of entity kinds and refused the
  finding that the checker had accepted. Both now ask one function.
- A value under `asset`, `src_asset` or `dst_asset` that comes from a log line is removed, so a log
  cannot say which of your machines it is about. A list with a name or an address twice is refused.
- 15 mutations in a copy: 12 caught at once. Three survived and showed weak tests (a hit whose events
  disagree, an alias with one rule too many, entity kinds); cases were added and all three are caught.
- The asset parser was fuzzed for 15 seconds with no failure.

Not done: `--assets` for forensics, the home screen and the dashboard; address ranges and addresses
that change over time (DHCP); and the login to db01 with a stolen key is still not found.
The correlation change (a hit has the fields its events agree on) applies to all rules. The existing
measurements did not change, but your own rules with group-by over other correlations can now group
hits that were left out before.

## Not decided yet

- Streaming (tail -f) evaluation. The engine is written so that state is per group, which is what a
  stream needs, but slice 1 is batch only.
- Broader dashboard workflows and backend-specific search optimization after the initial release.
