# Web applications and APIs

Omamori reads the logs of the backend frameworks that most people use, and finds attacks on the application
itself: password guessing at your login API, lists of leaked passwords tried against many accounts, a login
after guessing, injection, scans, exposed debug endpoints and database errors caused by inputs.

```sh
omamori detect ./logs                       # any mix of framework, Docker, journald, nginx and system logs
docker logs --timestamps api > api.log && omamori detect api.log
journalctl -o json -u api.service > api.json && omamori detect api.json
```

The format of each file is found by itself; `--format app` asks for the text formats of the frameworks.

## How it works

A request that a framework logs becomes the same event as a line of an nginx access log: category
`webserver`, with `method`, `url`, `status`, `src_ip`, `user_agent` and, when the log says it, `user`. So the
web rules (scans, injection, scanner tools, web shells) read every framework, and the rules for applications
read nginx and Apache too. Lines that the application writes itself ("Failed login for admin from
203.0.113.77") keep their message, and the address and the account in it are taken out.

- **Docker.** The json-file logs of Docker (`/var/lib/docker/containers/<id>/<id>-json.log`) and the output of
  `docker logs --timestamps` (also `kubectl logs --timestamps`) are unwrapped. The line inside is read with
  every reader of Omamori, and the time of Docker is used when the line has none (uvicorn writes none).
- **systemd journal.** `journalctl -o json` is read: sshd, sudo, cron and the other system programs as their
  syslog lines, applications with the readers below. This also covers servers that keep no `auth.log`.
- **Behind a proxy.** When the application sees only the proxy (nginx on the same machine or in a private
  network), the first address of `X-Forwarded-For` is taken as the client, and the proxy is kept as
  `proxy_ip`. It is never taken when the peer is a public address, because anyone can write the header.
- **Colors** that frameworks write to a terminal are removed. Every other escape sequence (clearing the
  screen, moving the cursor) makes a line unreadable, because it is a known way to hide lines in a log.

## Measured on real applications (2026-11-13)

A small application of each setup (a login API and one endpoint that reaches a database) ran in Docker,
logging the way that framework does by default or most commonly. One attack ran against each: twelve
failed logins with twelve accounts, then the right password, a scan for six sensitive files, three SQL
injections that end in a database error, and one request with the sqlmap user agent. The logs that the
applications wrote are in [`testdata/fixtures/apps`](../testdata/fixtures/apps), the applications and the
scripts in [`testdata/applab`](../testdata/applab). A test reads every one of them on each run: every line
must be read, and exactly the same rules must fire.

| Setup | Log | Guessing | Many accounts | Login after guessing | File scan | Injection | Scanner tool | SQL error |
|---|---|---|---|---|---|---|---|---|
| Express | morgan `combined` | yes | yes | yes | yes | yes | yes | yes |
| NestJS | nestjs-pino | yes | yes | yes | yes | yes | yes | yes |
| NestJS | default logger | yes | yes | no | no | no | no | yes |
| Django | gunicorn access log | yes | yes | yes | yes | yes | yes | yes |
| Flask | built-in server | yes | yes | yes | yes | yes | no | yes |
| FastAPI | uvicorn | yes | yes | yes | yes | yes | no | yes |
| Spring Boot | default logging and Tomcat access log | yes | yes | yes | yes | yes | no | yes |
| ASP.NET Core | Serilog request logging (compact JSON) | yes | yes | yes | yes | no | no | yes |
| Laravel | `storage/logs/laravel.log` | yes | yes | no | no | no | no | yes |
| Rails 8 | production log on standard output | yes | yes | yes | yes | yes | no | yes |
| Go, Gin | `gin.Default()` | yes | yes | yes | yes | yes | no | yes |
| Go, Echo | `middleware.Logger()` (JSON) | yes | yes | yes | yes | yes | yes | yes |
| Go, chi | `middleware.Logger` | yes | yes | yes | yes | yes | no | yes |
| Rust, actix-web | `Logger::default()` with env_logger | yes | yes | yes | yes | yes | yes | yes |
| Rust, Axum | tower-http `TraceLayer` with tracing-subscriber | yes | yes | no | no | no | no | yes |

Spring Boot also gave the alert for its Actuator `env` endpoint, which answered from outside. All 31 log
files were read with no unread line. The "no" cells are not faults of a reader: the information is not in
that log, and the next section says how to add it.

Where "many accounts" and "guessing" come from the messages of the application, a request and the line about
it are both counted; ten failures can then be five attempts.

## When a log leaves something out

| Missing | Why | What to do |
|---|---|---|
| Requests of NestJS with the default logger | Nest logs no requests | Use nestjs-pino (`LoggerModule.forRoot()`), or put nginx in front and read its access log |
| Requests of Laravel | Laravel logs no requests | Read the access log of nginx or Apache in front of PHP-FPM, as in production |
| The client of Axum | `TraceLayer` does not record it | Add the address to the span (`ConnectInfo<SocketAddr>` in `make_span_with`, as `client_ip`) |
| The query of ASP.NET Core | Serilog's request log has the path without the query | Add `QueryString` in `EnrichDiagnosticContext`, or read the access log of the proxy |
| The user agent (scanner tools) | Flask, uvicorn, Gin, chi, Rails, Serilog and the Tomcat `common` pattern do not log it | Use a combined format (Tomcat pattern `combined`), or read the access log of the proxy |
| The time of uvicorn lines | uvicorn writes no time | Read them through Docker or journald, or set a log config with `%(asctime)s` |
| The Tomcat access log, right away | Tomcat buffers it | `server.tomcat.accesslog.buffered=false`, or read it after a flush |

## The rules for applications

| Rule | Level | Fires when |
|---|---|---|
| `app_login_bruteforce` | high | ten or more refused logins from one address in ten minutes |
| `app_credential_stuffing` | high | refused logins for ten or more accounts from one address in ten minutes |
| `app_login_after_bruteforce` | critical | a successful login after guessing, from the same address, within 30 minutes |
| `app_denied_burst` | medium | fifty or more requests refused with 401 or 403 from one address in five minutes |
| `app_server_error_burst` | medium | twenty or more server errors caused by one address in five minutes |
| `app_debug_endpoint_exposed` | high | a debug endpoint answered with success: Spring Boot Actuator `env` and `heapdump`, Django and Symfony debug tools, Laravel Telescope, the Rails info page, the H2 console, Go pprof, ELMAH |
| `app_sql_error` | medium | the application wrote a database syntax error (MySQL, PostgreSQL, SQLite, SQL Server, Oracle) |

A refused login is a `POST` to a path like `/login`, `/auth/token` or `/users/sign_in` answered with 400, 401,
403, 422 or 429, or a message of the application like "login failed", "invalid credentials" or
"bad credentials". Rules are in [`internal/rules/builtin/app.yml`](../internal/rules/builtin/app.yml).

## Limits

- A login that fails with a redirect (302 back to the login page, as some server-rendered apps answer) looks
  like a success to the status rules; the message rules still see it if the application logs it.
- The address in a message is taken only when the message names exactly one IPv4 address. The account is
  taken from the usual wording ("failed ... for X from Y"); other wordings keep only the message.
- Formats that a project changed (its own log pattern, another JSON logger) may not be read. They show up as
  unread lines in the report, never as a quiet clean result. Give such logs as JSON when you can: the usual
  field names of pino, winston, slog, zap, zerolog, logrus, Echo, Serilog, ASP.NET Core, Spring Boot (ECS and
  Logstash), lograge and Google Cloud are read.
- ASP.NET Core's default console output (several lines for one entry, no time) is not read; use its JSON
  console formatter or Serilog.
- These measurements are fifteen setups, one attack each, made by me. They show that the readers and rules
  work on real output of these versions; another version or setup can write differently.
