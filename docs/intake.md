# Local log intake

`detect` and `analyze` use the same read-only intake library. They read files or
folders, normalize recognized events, and retain source references for reports
and the future local dashboard. No collector is installed and no remote system
is contacted.

Automatic format detection supports classic/ISO Linux syslog, Apache/Nginx
access logs, and JSON lines. Use `--format syslog`, `web`, `json`, `suricata`,
`zeek`, `wazuh` or `windows` to choose explicitly. `json` recognizes all supported
JSON shapes and leaves other timestamped objects generic. A specific source
format rejects other shapes and counts those lines as unread.

Inside a folder, dependency folders (`node_modules`, `vendor`, `venv`, `site-packages`, `Pods` and
the like) and folders marked as a cache with a `CACHEDIR.TAG` file (the `target` folder of Rust) are
skipped and listed as skipped, so a project folder can be read for its logs. A folder that you give
directly is always read. More than 2000 files is refused with its own message: give the folder of the
logs, not a whole project.

## Supported JSON shapes

| Source | Supported records | Normalized source metadata |
|---|---|---|
| Suricata EVE | `alert`, `http`, `dns`, `flow`, `tls` with a matching nested object and flow/tuple context | `collector=suricata`, `product=suricata`, `service` identifies the event type |
| Zeek JSON | Connection, HTTP, DNS, notice records with stream-specific fields | `collector=zeek`, `product=zeek`, `service=conn/http/dns/notice` |
| Wazuh JSON | Alerts with rule ID/level, agent ID and decoder identity | `collector=wazuh`; ordinary alerts use `product=wazuh`, `action=alert` |
| Wazuh Windows | `data.win.system` and named `data.win.eventdata` inside the Wazuh envelope | `collector=wazuh`, `product=windows`, service chosen from validated Windows metadata |
| Winlogbeat JSON | `winlog.event_id`, provider/channel and named `winlog.event_data` | `collector=windows`, `product=windows` |
| NXLog JSON | `EventID`, `SourceName`, `Channel`, `EventTime` and named top-level event fields | `collector=windows`, `product=windows` |

A filename or a lone timestamp is insufficient to identify a source. Unknown
valid JSON stays generic. A file may contain multiple supported JSON sources;
the report lists the sources it actually parsed, and each JSON evidence event
has a `source` field.

The native EVE structure is described in the [Suricata format reference](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html).
Zeek documents [connection](https://docs.zeek.org/en/lts/reference/logs/conn.html),
[HTTP](https://docs.zeek.org/en/current/reference/logs/http.html),
[DNS](https://docs.zeek.org/en/current/reference/logs/dns.html) and
[notice](https://docs.zeek.org/en/current/reference/logs/weird-and-notice.html) records.
Wazuh documents [JSON alert output](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html)
and its [nested Windows event structure](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html).
The Windows exporter mappings follow [Winlogbeat's exported fields](https://www.elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog)
and [NXLog's Windows event fields](https://docs.nxlog.co/agent/current/im/msvistalog.html).

## Field mapping

Recognized records have two views: normalized fields for common rules and
original flattened scalar fields under `raw.*`. For example, a Zeek address is
available as both `src_ip` and `raw.id.orig_h`. A raw `action`, `outcome`, `host`
or `product` value cannot overwrite the normalized interpretation. Generic JSON
keeps the earlier flat-field behavior and does not acquire a `raw.*` namespace.

| Source fields | Normalized fields |
|---|---|
| EVE `src_ip`, `dest_ip`, `src_port`, `dest_port`, `proto` | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` |
| EVE `alert.signature`, `alert.signature_id`, `alert.severity`, `alert.action` | `signature`, `signature_id`, `rule_severity`, `policy_action` |
| EVE `http.url`, `http.http_method`, `http.status` | `url`, `method`, `status` |
| Zeek `id.orig_h/p`, `id.resp_h/p` | `src_ip/src_port`, `dst_ip/dst_port` |
| Zeek `uri`, `method`, `status_code`, `user_agent` | `url`, `method`, `status`, `user_agent` |
| Zeek `note`, `msg` | `signature`, `message` |
| Wazuh `agent.name`, `data.srcip/dstip`, `data.dstuser` | `host`, `src_ip/dst_ip`, `user` |
| Wazuh `rule.id`, `rule.level`, `rule.description` | `wazuh_rule_id`, `wazuh_level`, `signature` |
| Windows named `Image`, `CommandLine`, `User` | `process`, `command`, `user` for supported Sysmon events |
| Security `TargetUserName`, `TargetDomainName` | Domain-qualified `user`, plus `target_user` and `user_domain` |

Addresses and ports are validated. Malformed numeric/boolean descriptive text
does not become an invented username, host or URL. Invalid or oversized host and
account identities are omitted from canonical identity fields rather than
repaired into a different identity. Supported original values remain in `raw.*`.

HTTP Host headers, TLS SNI and DNS questions are kept as `http_host`, `tls_sni`
and `dns_query`; they are not treated as the observed asset's canonical `host`.
Connection state and byte counts remain observations. Suricata's `allowed`
policy action is not an authentication outcome or proof of a successful attack.
HTTP transaction records use `category=webserver`, so existing web rules can
read them. HTTP metadata attached to a sensor alert does not become another
HTTP transaction.

## Windows meanings and timestamps

Event IDs only acquire behavior when both provider and channel match:

| Provider and channel | Event ID | Normalized behavior |
|---|---|---|
| Microsoft-Windows-Sysmon / Microsoft-Windows-Sysmon/Operational | 1 | `category=process_creation`, `action=process_create` |
| Same Sysmon identity | 3 | `category=network_connection`, `action=network_connect` |
| Microsoft-Windows-Security-Auditing / Security | 4624 | `category=authentication`, `action=login`, `outcome=success` |
| Same Security identity | 4625 | `category=authentication`, `action=login`, `outcome=failure` |

Unknown IDs or mismatched providers retain event metadata without an invented
action or outcome. Security uses the target account, not the subject account.
When a domain exists, the canonical account is `DOMAIN\user`, aligning with
Sysmon's account shape. Equality remains exact; no domain or username is guessed.
These meanings follow [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[Security 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
and [Security 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).

The original Windows event time takes precedence over collector time. Sysmon's
zone-less `UtcTime` is interpreted as UTC regardless of `--timezone`. An explicit
preferred timestamp that cannot be parsed makes the line unreadable; it is not
silently replaced with a later collection time. Missing timestamps can use the
documented alternate fields. Generic zone-less timestamps use `--timezone`.

## Bounds and coverage

- Inputs are JSON lines, not JSON arrays, XML, native EVTX, Zeek TSV or arbitrary
  PowerShell object exports. No attempt is made to decode XML inside a string.
- Only the listed source subsets are normalized. Other EVE/Zeek/Windows fields
  may remain raw metadata, and other valid JSON shapes may stay generic.
- Original flattened fields are bounded: at most 300 total fields per event,
  six nested object levels, 200 characters per field name and 2,048 characters
  per value. Arrays of scalar values are joined; arrays of objects are not
  expanded. A single EVE DNS question can be mapped, but multiple questions are
  not joined into an invented query.
- Ambiguous flattened paths, such as a literal `id.orig_h` and an `id` object
  with an `orig_h` field, are rejected for recognized sources. Their contradictory
  evidence does not silently choose a winner.
- Intake keeps the existing 64 KiB line, 2,000 file and 1,000,000 event limits.
  The report shows malformed lines, skipped files and parsed source types.
- Analyst snapshots retain selected normalized fields, not every `raw.*` field.
  Per-field and per-event text budgets are disclosed as `truncated_fields`,
  alongside omitted alerts and evidence. Original logs remain unchanged.

Nine built-in rules use Zeek connection records and Suricata alerts (a sweep of internal
addresses, a large upload to an external address, sensor alerts of severity 1); see
[demo.md](demo.md). A parser does not imply complete attack coverage for its source. Use [custom rules](rules.md) for the additional
fields. The [mixed-source fixture](../testdata/fixtures/intake/README.md) provides
eight demonstration rules and reproducible expected results. Its data is
synthetic, and live sensor/model accuracy has not been measured by these tests.
