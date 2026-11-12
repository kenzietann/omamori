# Local detection rules

`omamori detect` reads YAML rules and checks local log events. Rules never run
commands or call an AI provider. The format is a subset of Sigma, with local
extensions for tests and burst alerts. It is not a full Sigma implementation.

## Load your own rules

Put `.yml` or `.yaml` files in a folder. Subfolders are read too. One file can
hold several rules, separated by `---`.

```sh
omamori detect --rules ./rules --year 2026 --timezone Asia/Tokyo \
  --output ./reports ./logs
```

`--rules` replaces the built-in set. Every reference must resolve within the
chosen folder. An invalid rule or a failing embedded test stops the run before
reports are written. Without `--rules`, the built-in rules are used.

To let the AI draft a rule from log lines that you point at, see [rule-writing.md](rule-writing.md).
A drafted rule is an ordinary rule file in this format.

## A small example

Save this as `rules/ssh.yml`. The first rule matches failed SSH logins. The second
groups them by source address and alerts after three failures in a minute. This
small threshold is for trying the example; tune it for your own logs.

```yaml
title: Failed SSH login
name: example_ssh_failure
level: low
logsource: {product: linux, service: sshd}
detection:
  selection: {action: login, outcome: failure}
  condition: selection
tests:
  - name: only the failure matches
    events:
      - {product: linux, service: sshd, action: login, outcome: failure}
      - {product: linux, service: sshd, action: login, outcome: success}
    expect: {alerts: 1}
---
title: Repeated SSH failures
name: example_ssh_burst
level: medium
correlation:
  type: event_count
  rules: [example_ssh_failure]
  group-by: [src_ip]
  timespan: 1m
  condition: {gte: 3}
tests:
  - name: three failures are one burst
    events:
      - {product: linux, service: sshd, action: login, outcome: failure, src_ip: 203.0.113.9}
      - {product: linux, service: sshd, action: login, outcome: failure, src_ip: 203.0.113.9}
      - {product: linux, service: sshd, action: login, outcome: failure, src_ip: 203.0.113.9}
    expect: {alerts: 1}
```

Each rule needs `title` and exactly one of `detection` or `correlation`. `name`,
`id`, `description` and `tags` are optional. References can use a rule's name, ID
or title; these identifiers must be unique across the set. Referencing one rule
twice through different identifiers is refused.

Levels are `informational`, `low`, `medium`, `high` and `critical`; the default is
`medium`. Levels describe rule alerts, not proof that an attack succeeded.

Embedded tests use flat event fields. An optional `time` is an RFC 3339 timestamp.
Without it, events start at `2026-01-01T00:00:00Z`, one second apart. Each test's
`expect.alerts` counts that rule's hits, even if another rule suppresses its
standalone alerts. Include both matching and ordinary events in your tests.

## Detection selections and conditions

A selection map requires every field to match. A field's list of values matches
any value, unless `|all` is present. A list of selection maps matches any map.
A keyword list, such as `selection: [segfault, 'out of memory']`, searches every
event field for any listed pattern.

Conditions support selection names, `and`, `or`, `not`, parentheses,
`1 of selection_*`, `all of selection_*`, `1 of them` and `all of them`.
`not` binds before `and`, and `and` before `or`. A YAML list of conditions means
any listed condition may match. Selection names are case-sensitive; operators
are not. Counts such as `2 of them` are not supported.

| Field expression | Meaning |
|---|---|
| `user: root` | Equal text, ignoring case |
| `url: '/admin/*'` | `*` matches any text; `?` matches one character |
| `command\|contains: curl` | Contains the text or wildcard pattern |
| `url\|startswith: /admin` | Starts with the pattern |
| `url\|endswith: .php` | Ends with the pattern |
| `command\|contains\|all: [curl, '\| sh']` | Every listed pattern must match |
| `user\|cased: Root` | Case-sensitive text matching |
| `url\|re: '^/v[0-9]+/'` | Go regular expression, case-sensitive by default |
| `url\|re\|i: select` | Regular expression ignoring case |
| `src_ip\|cidr: 10.0.0.0/8` | Address belongs to the network |
| `status\|gte: 500` | Numeric comparison; `gt`, `gte`, `lt`, `lte` are supported |
| `user\|exists: true` | Field is present, including an empty string |
| `user\|exists: false` | Field is absent |

Use `\*` or `\?` inside a single-quoted YAML value to match a literal wildcard.
`|all` changes list matching, and `|cased` changes text matching. `|i` is only
valid with `|re`. Two matching modes, such as `|contains|endswith`, are refused.
Regexes use Go's syntax; lookarounds and backreferences are not supported.

Missing and empty fields differ. `user: ''` matches a present empty string;
`user: '*'` also requires the field to exist. In this implementation,
`user: null` matches either a missing field or an empty string. JSON input nulls
are omitted during intake. Use `|exists` when presence itself matters.

## Fields and log sources

Events have flat string fields such as `action`, `outcome`, `user`, `src_ip`,
`host`, `process`, `command`, `url`, `method`, `status`, `message` and `service`.
Numbers and booleans in rule values are converted to text for ordinary matching.

`logsource` supports `product`, `service` and `category`. Every specified value
must be present and equal, ignoring case. `definition` is allowed as descriptive
metadata. Syslog intake sets `product: linux` and the parsed service, such as
`sshd`, `sudo` or `cron`. Web intake sets `category: webserver`. Generic JSON uses
the fields in the input. Recognized Suricata, Zeek, Wazuh and Windows JSON shapes
have explicit source mappings; their original scalar fields are retained under
`raw.*`. See the [intake field dictionary](intake.md) for product/service/category
values and source-specific limits.

Some common field names are mapped to the same internal field:

| Input or rule field | Internal field |
|---|---|
| `c-ip`, `SourceIp`, `source_ip`, `src`, `ClientIp`, `remote_addr` | `src_ip` |
| `DestinationIp`, `dest_ip`, `dst` | `dst_ip` |
| `sc-status`, `cs-method` | `status`, `method` |
| `cs-user-agent`, `cs-referer` | `user_agent`, `referrer` |
| `cs-uri`, `cs-uri-stem`, `cs-uri-query`, `c-uri`, `request` | `url` |
| `cs-username`, `UserName`, `TargetUserName` | `user` |
| `CommandLine`, `Image`, `ComputerName`, `HostName` | `command`, `process`, `host`, `host` |
| `EventID`, `SourcePort`, `DestinationPort` | `event_id`, `src_port`, `dst_port` |

Alias lookup ignores case. Other field names keep their spelling. URI aliases
all refer to the stored URL; they do not split its path and query. Web URLs keep
their logged encoding, so a rule may need both plain and percent-encoded forms.
JSON objects become dotted fields such as `alert.signature`; scalar array items
are joined with commas, and nulls are omitted.

## Correlation and time

| Type | Required condition |
|---|---|
| `event_count` | `condition: {gte: 10}` or `condition: {gt: 9}` |
| `value_count` | `condition: {gte: 5, field: user}` for five distinct users |
| `temporal` | No condition; every referenced rule must have a hit |
| `temporal_ordered` | No condition; hits must follow the order in `rules` |

`group-by` is optional. Without it, all hits share a group. With it, each field
must be present and nonempty; incomplete hits are not counted. A distinct count
also ignores hits whose counted field is missing or empty. Group values and
distinct values are case-sensitive.

A hit of a correlation has the fields that it was grouped by. It also has any
other field that every event it kept has with one and the same value: ten failed
logins on one host are a hit on that host, whatever they were grouped by. When
the kept events disagree, or one lacks the field, the hit does not have it.

`aliases` lets one group-by name stand for a different field in each rule of the
list, as in Sigma. Every rule of the list needs a field:

```yaml
correlation:
  type: temporal_ordered
  rules: [ssh_brute_force_success, ssh_internal_guessing]
  aliases:
    machine:
      ssh_brute_force_success: asset      # the host that was logged in to
      ssh_internal_guessing: src_asset    # the host that guesses
  group-by: [machine]
  timespan: 6h
```

The fields `asset`, `src_asset` and `dst_asset` exist only when an asset list is
given with `--assets` (see [demo.md](demo.md)). They are set from that list
alone; a value under these names in a log line is removed.

Events are sorted by time, preserving their input order for equal timestamps.
Windows include the boundary: a hit exactly one minute later fits `1m`.
Durations accept forms such as `30s`, `5m`, `2h` and `1d`, up to 30 days.

A count alerts when its threshold is reached. Further hits extend that same
burst while each arrives within the timespan of the previous hit's end. A longer
gap starts a new window. A long continuous burst therefore produces one alert,
and its total count may span longer than the original window.

For `temporal`, the completing hit must be within the timespan of every other
step's end. For `temporal_ordered`, each next step must be within the timespan of
the previous step's end. This is a wait between steps, not a limit on the whole
chain's duration. Two ordered steps need separate events, even if they share a
timestamp. A completed sequence clears its accumulated chain.

Correlations can refer to other correlations, but cycles are refused. A nested
correlation contributes one hit, not one hit per underlying event, and exposes
its grouping fields for further grouping. Referenced detection rules normally
produce no standalone alerts; their correlation does. `generate: true` on a
correlation also exposes its referenced rules' alerts. Referenced correlations
keep their own alerts regardless.

## Scope and limits

Unknown matching modifiers and correlation keys or types are refused. Old
`timeframe` and `selection | count()` syntax are refused too. Count conditions
support only `gte` and `gt`; absence detection, streaming evaluation, arbitrary
Sigma transforms and full Sigma compatibility are outside this implementation.

A rule file is limited to 256 KiB, and a folder to 5,000 rules. Conditions are
limited to 500 bytes and 32 nesting levels; regexes to 1,000 bytes. A rule may
include at most 100 tests with 1,000 events each. Correlations allow up to 20 rule
references, 10 grouping fields and a threshold of 1,000,000.

An evaluation keeps up to 500,000 hits per rule and reports any cut. Each alert
retains at most 50 evidence events and 200 distinct values; its count can be
larger. Intake accepts up to 2,000 files and 1,000,000 events per run, rejects
lines longer than 64 KiB, and truncates many field values to 2,048 characters.
Reports disclose skipped files and malformed lines. Check those coverage gaps
before interpreting a run with no alerts.
