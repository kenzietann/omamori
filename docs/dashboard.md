# Local dashboard

`omamori dashboard` starts the investigation UI on **127.0.0.1**. HTML, CSS,
JavaScript and the icon are embedded in the Go binary. It needs no frontend build
server, CDN, hosted account or public deployment.

```sh
go install ./cmd/omamori
omamori dashboard /path/to/evidence-workspace
```

Open the private session link printed in the terminal. Keep the command running;
Ctrl+C stops HTTP access and cancels queued/active work. Port 8765 is the default.
Use `--port 0` to choose an available port, `--db file` for another SQLite store,
and `--output folder` for report output. PostgreSQL/MariaDB use the same
`OMAMORI_DB_DRIVER` and `OMAMORI_DB_DSN` configuration as the CLI store commands.
The dashboard initializes the configured store at startup.

The evidence root defaults to the working directory if omitted. New runs accept
paths relative to this root. Paths and symlinks that resolve outside it are
refused. Choose a workspace containing the logs/artifacts and any custom rules
or previously collected process/socket snapshots you want to use. Output and
SQLite database/journal paths must remain outside the selected input evidence.

## Investigation views

- **Alert review:** a selected-run alert queue with adjacent evidence, rule and AI-review tabs.
  The picker lists 50 recent runs (and a directly linked older run when selected). The charts and
  queue use up to 200 of the selected run’s latest alerts; this scope is disclosed. Event/alert totals
  come from that run, while the open-case count is scoped to 50 recent cases.
- **Data charts:** severity counts and a UTC activity histogram with explicit bucket duration,
  full interval endpoints, per-bucket values and a data table. Zero results never invent history.
  On phones, chart detail is available through a disclosure so an alert is immediately reachable.
- **Saved runs:** paginated history, run details, coverage and source provenance.
- **Alert and event details:** severity, rule metadata, group values, full stored
  fields and retained evidence links. Checked AI citations resolve through the
  run-scoped mapping to their full stored event.
- **Search:** events or alerts, literal text, exact field/value, source, rule,
  severity, run, case and inclusive time filters. Search pages hold 25 results.
- **Cases:** create, edit notes/status, attach or detach alerts. Updates use the
  stored version and reject stale edits. The case list and picker show the 100
  most recently updated cases; the CLI remains available for broader paging.
- **Timeline:** oldest-first events and alerts across runs, or scoped to a case.
  A case includes only its attached alerts and linked retained evidence. Timestamp
  ties do not establish causation.
- **Run activity:** preparation, preview, confirmation, progress, cancellation,
  completion/failure and links to saved results.

Log values, case notes, rule text and model-derived values are inserted as text,
not interpreted as HTML. Weak forensic timestamps, rejected claims, unreviewed
alerts and coverage limits remain visible. Stored scripted replays are labeled.
Displayed dates use the browser’s local timezone and include its zone label.
Tables scroll within their panels on small screens and support keyboard focus.

## Starting work

Choose **New run** and one of:

1. Detect: local rule evaluation.
2. Analyze: detection followed by a checked AI review.
3. Forensics: read-only Linux artifact triage and a hash manifest.
4. Forensics + AI review: the forensic outcome through the same analyst service.

Supply an evidence path, optional custom-rule folder, year and timezone. Log runs
can choose a format. Forensic runs can select previously collected `ps` and
`ss`/`netstat` text snapshots; the dashboard does not execute those commands.
All these paths stay within the approved workspace.

**Prepare preview** reads evidence and freezes the result in memory. It writes
no run output or stored run and makes no AI request. Review the request or local
run summary, then **Confirm and run**. AI providers use the existing environment
or CLI key-store configuration; keys are not accepted in browser forms or HTTP
requests. A failed preparation does not send data to a provider.

Only one run can be preparing, waiting for confirmation or executing at a time.
A confirmed job cannot be executed twice. Previews expire after 30 minutes;
execution has a five-minute context deadline. Cancellation interrupts log reads
between buffers and stops pending provider calls. A bounded rule evaluation or
forensic read already underway can finish before the worker stops. Cancellation
cannot retract a request already received by a provider. Reports that can be
saved may remain available for an incomplete/cancelled analysis.

The last 20 job summaries are kept in process memory. They are not restored after
restart; completed stored runs and cases are durable. Provider/model quality has
not been measured by the fake-provider and scripted browser fixtures.

## Local access boundary

Each server launch generates a random session token. The printed URL places it
in a fragment, so the browser does not send it as a URL query or referrer. The
client removes it from the address bar and keeps it in that tab's session storage.
API requests carry it in an authorization header. Treat the printed link as access
to this local workspace; restarting the server invalidates it.

The server binds only IPv4 loopback, checks the exact Host and Origin, rejects
cross-site browser requests, requires JSON for mutations and limits request
bodies. Its content policy excludes third-party scripts, frames and embedded
objects. Static files contain no access token. There is no arbitrary file-serving
endpoint, shell endpoint, uploaded-source execution or remote listener option.

This is a local single-user interface, not multi-user authentication or a public
web application. Database credentials and provider keys remain server-side.

## Shared implementation

`internal/dashboard` is the HTTP adapter and embedded UI. It calls the existing
store, detector, forensic collector, runstore and analyst services. It does not
invoke the CLI as a subprocess. `detect.RunContext` / `intake.ReadContext` support
cancellable log preparation, while stored event/alert detail methods resolve
references without scanning entire query pages.

The current web UI focuses on detection, forensic review and investigations.
Exposure checks, legacy Task B, creating replay recordings by hand, replay launch,
manifest verification, demo generation and advanced storage operations remain
available through the existing CLI/TUI. Saved replay results can be inspected here.

Tests cover token/host/origin boundaries, strict request decoding, root and symlink
escape, preview side effects, duplicate confirmation, cancellation, expired
previews, case-version conflicts, source preservation, safe metadata, AI checks
and forensic manifests. Browser verification covers case creation/link/update,
case timelines, detection preview/confirmation, stored AI citation navigation,
script-like notes remaining inert, and desktop/mobile layouts.

## Reference workspace design

Light is the default; the theme switch saves a matching dark preference locally. Fonts and brand
assets are self-hosted. Desktop queue and inspector panes scroll independently in a bounded working
frame. Mobile stacks the panes, moves to selected evidence on selection, and has an explicit menu.
The design contract is in `DESIGN.md`, product facts in `PRODUCT.md`, and surface-specific decisions
in `.impeccable/surfaces/dashboard.md`. Optional frontend tests live under `tests/`; they add no
runtime dependency to the Go binary. See [design validation](dashboard-design-validation.md) for
measured checks and the marketing-template gate’s unresolved, separately recorded findings.
