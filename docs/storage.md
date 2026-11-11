# Storage, search, cases and timelines

Omamori supports **SQLite, PostgreSQL and MariaDB** through one shared store API.
SQLite is the local default. PostgreSQL and MariaDB let the same CLI and planned
local dashboard use a database server without changing detection or analyst code.
Changing the configured backend selects a different store; it does not migrate
existing records between databases.

Storage is opt-in for a run. `detect --store` and `analyze --store` persist the
sanitized run; `--db file` chooses SQLite and also enables persistence. Existing
commands without these flags keep their report-only behavior. An analyst preview
never creates or opens the database, even when storage flags are supplied.

## Choose a backend

| Backend | Configuration | Driver |
|---|---|---|
| SQLite | Default; `--db /path/to/omamori.db`, or `OMAMORI_DB_DSN` as a file path | `modernc.org/sqlite`, pure Go |
| PostgreSQL | `OMAMORI_DB_DRIVER=postgres`, `OMAMORI_DB_DSN` set to its connection string | `pgx/v5/stdlib` |
| MariaDB | `OMAMORI_DB_DRIVER=mariadb`, `OMAMORI_DB_DSN` set to its connection string | `go-sql-driver/mysql` |

Without an explicit SQLite path, the CLI uses `~/omamori-data/omamori.db`.
New SQLite files are created with mode `0600`, and newly created parent folders
with mode `0700`. A SQLite database and its journal files must stay outside the
input logs. File URIs and in-memory databases are not accepted by the CLI; the
library supports `:memory:` for isolated callers and tests.

Database credentials are read from the environment, never command-line flags,
case records or report metadata. Set `OMAMORI_DB_DSN` through your environment or
secret manager. `--db` is only a SQLite path and is rejected with a server backend.
For PostgreSQL and MariaDB, the database must already exist; Omamori creates its
own `omamori_*` tables and indexes there. Configure the driver's TLS options when
connecting to a remote server.

PostgreSQL accepts a connection URL or keyword/value DSN. MariaDB uses the Go
driver's `user:password@tcp(host:port)/database?options` form, rather than a
`mariadb://` URL. See the official [pgx database/sql adapter](https://pkg.go.dev/github.com/jackc/pgx/v5/stdlib),
[MySQL/MariaDB driver DSN documentation](https://github.com/go-sql-driver/mysql#dsn-data-source-name),
and [pure-Go SQLite driver](https://pkg.go.dev/modernc.org/sqlite) for their options.

Initialize or verify the configured store:

```sh
omamori store init
omamori store init --db ./local-data/omamori.db
```

Schema changes are versioned. Unknown future versions are refused. Initial
schema creation is transactional on SQLite/PostgreSQL; MariaDB initialization
uses restartable steps because its DDL commits implicitly. All run saves use a
transaction on every backend. The server account needs permission to create the
Omamori schema objects as well as read and write them.

## Save runs

```sh
omamori detect ./logs --year 2026 --timezone Asia/Tokyo --store
omamori analyze ./logs --year 2026 --timezone Asia/Tokyo --yes --store
omamori analyze ./logs --year 2026 --timezone Asia/Tokyo \
  --replay ./saved-run/recording.json --store
```

A successful save prints `Stored run: r_...`. Analyst `analysis.json` also carries
that `run_id`. File reports remain available. If a storage operation fails, the
CLI reports failure while retaining the deterministic reports where they could
be written. Analyst results explicitly mark a failed store write as incomplete.

A stored run contains:

- Every parsed event, including benign events and events outside the analyst's
  evidence sample, within the run-size limit.
- Alerts, their rule metadata and links to retained evidence events, including
  retained correlation-step evidence.
- Coverage information: read files, skipped files, malformed lines, rule limits,
  evidence omissions, and text/field-name truncation or renaming.
- The checked analysis result when available. Raw provider responses, API keys,
  database credentials and replay recordings are not stored in the database.

Text passes the existing sanitizer before persistence. This does not anonymize
all data: IP addresses, account names, host names and usable source references
remain important investigation context. Placeholder labels are not identities;
the store does not automatically link records merely because redacted text
matches. Evidence links are resolved before redaction.

Runs are immutable. A repeated save of the same normalized payload is idempotent;
an explicit run ID cannot be reused for different content. By default, the ID is
derived from the normalized sanitized payload, including its run time. Event IDs
(`e1`, `e2`, ...) and alert IDs (`a1`, `a2`, ...) are local to the containing run.
Always retain the run ID with an event or alert reference.

## Search and timeline

Store commands return JSON, suitable for scripts and a future dashboard adapter:

```sh
omamori store runs --limit 20
omamori store run RUN_ID
omamori store search --run RUN_ID --source windows
omamori store search --field src_ip --value 203.0.113.9
omamori store search --kind alerts --level critical
omamori store search --kind alerts --field user --value 'LAB\alice'
omamori store search --text 'powershell.exe'
omamori store timeline --from 2026-11-10T00:00:00Z --to 2026-11-11T00:00:00Z
```

Replace `RUN_ID` with the printed identifier. Add the same `--db` path to commands
when using a nondefault SQLite file. Server backends use the environment above.

Event text search covers source, reference, field names and field values. Alert
text search covers rule name, title, level and group fields. `--text` is a literal
case-insensitive substring: `%`, `_` and SQL-looking text are not query syntax.
This portable implementation may scan matching tables; it is not a dedicated
full-text search engine.

`--field` and `--value` match exact stored sanitized values. Alert field filters
match group fields or linked evidence fields; alert source filters use linked
events. Exact matches preserve case and trailing spaces across backends. Supported
filters include `--run`, `--case`, `--source`, `--level`, `--rule`, and inclusive
`--from` / `--to` timestamps. Run lists filter by run creation time; event and
alert searches filter by their event/firing time.

Search results are newest first; timelines merge events and alerts oldest first.
Ties use deterministic run/type/ID ordering, not an inferred causal ordering.
`--limit` defaults to 50 and is capped at 500 in the CLI; use `--offset` to page.
The library supports up to 1,000 results per page and an offset up to 1,000,000.

## Cases

Cases organize selected alerts across runs. Closing a case does not delete its
evidence. Case titles and notes are sanitized before they are written.

```sh
omamori store cases create --title 'Authentication review' --notes 'Verify with account owner'
omamori store cases list --status open
omamori store cases show CASE_ID
omamori store cases add CASE_ID --run RUN_ID --alert a1
omamori store cases update CASE_ID --version 2 --status investigating
omamori store timeline --case CASE_ID
omamori store cases remove CASE_ID --run RUN_ID --alert a1
```

Replace the example IDs and version with the returned values. Statuses are
`open`, `investigating` and `closed`. Updating a case requires its current
`--version`; stale updates fail instead of overwriting a newer change. Attaching
or detaching evidence changes the version only when the membership changes.
Repeated attachment is idempotent.

A case timeline includes linked alerts and their retained evidence events,
including retained correlation-step evidence. It does not pull every unrelated
event from those runs into the case. Use run/entity search for wider context.

## Shared dashboard API and bounds

`internal/store` exposes backend-independent run, query, case and timeline DTOs.
`internal/runstore` builds sanitized immutable snapshots from detector results
and attaches checked analysis. `analysisrun.Config.Store` enables persistence
through the same service used by the CLI.

Stored alert payloads include an `analyst_evidence` map from snapshot citation
IDs such as `a1_e2` to stored event IDs such as `e19`. Resolve it with the containing
run ID to open the full stored evidence. Case links also use explicit run/alert
IDs. The dashboard should call the detection and analyst services; client-supplied
JSON must not be treated as a previously verified analysis result.

The initial store supports up to 1,000,000 events and 500,000 alerts in a run,
subject to a 256 MiB normalized run-payload limit. Event maps are capped at 500
fields. Dates must be in 1678–2261 so nanosecond timestamps cannot overflow.
Analysis/coverage JSON payloads are individually bounded. No automatic retention,
deletion, backend-to-backend migration, or web server is included in this slice.

The shared contract was tested against SQLite, PostgreSQL 18.4 and MariaDB 12.2.2,
including MariaDB with case-insensitive database defaults. Tests cover rollback,
durability, exact/literal search, case-version conflicts, scoped timelines and
credential-safe failures. To rerun against disposable server databases, supply
`OMAMORI_TEST_POSTGRES_DSN` and `OMAMORI_TEST_MARIADB_DSN`, then run
`go test -race ./internal/store`. These are integration-test databases; ordinary
tests use temporary SQLite files.
