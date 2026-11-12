# Where Omamori stands against the blue-team toolkit

The aim (owner, 2026-11-12): AI-powered versions of the four families of blue-team tools below, in one
CLI with a terminal UI. This page says honestly how far each part is. "Stands in for" names the open
tool that does the full job today. Omamori is far smaller than each of them.

Every part follows the same rules: the AI gets a sanitized, bounded view, it has no tools, each of its
claims is checked by code, and collectors only read.

## 1. Network and traffic analysis

| Stands in for | What exists | What is missing |
|---|---|---|
| Zeek | Reads Zeek JSON logs (conn, http, dns, notice). Rules for a sweep of internal addresses and a large upload | Its own protocol analysis. Zeek TSV logs |
| Suricata / Snort | Reads Suricata EVE JSON (alert, http, dns, flow, tls). A rule for alerts of severity 1 | Its own packet inspection and signatures |
| Wireshark / tshark, Arkime | nothing | Reading PCAP files into connection, DNS and HTTP events. **Next candidate** |

## 2. Endpoint and host monitoring

| Stands in for | What exists | What is missing |
|---|---|---|
| Sysmon | Reads Sysmon and Windows Security events from Winlogbeat/NXLog JSON (process, network, logon) | Native EVTX. Rules for these events |
| Velociraptor | `forensics`: read-only collection of Linux artifacts with a hash manifest, rules and a timeline | Remote collection, a query language, Windows and macOS artifacts |
| osquery | nothing | Asking a live host questions (processes, sockets, users, packages) as tables. **Next candidate** |

## 3. Threat intelligence and detection engineering

| Stands in for | What exists | What is missing |
|---|---|---|
| Sigma | A documented subset as the rule format, with correlations, aliases and tests inside the rule | Conversion to other SIEM query languages. Many modifiers |
| MISP | `--indicators`: a list of addresses, domains and SHA-256 hashes marks events in every source ([demo.md](demo.md)) | Feeds, sharing, sightings, expiry, scores, MISP's own formats |
| YARA | nothing (the exposure check finds secrets, not malware) | Pattern rules over files |
| AI rule writing | `rule draft`: the AI writes the matching part of one rule for events you point at; code accepts it only if it loads, passes its tests, matches every example, matches nothing on built-in benign days or `--benign` logs, and is not too broad ([rule-writing.md](rule-writing.md)) | Correlation rules, a live model measurement, the home screen and the dashboard |

## 4. SIEM, log management and orchestration

| Stands in for | What exists | What is missing |
|---|---|---|
| Elastic / OpenSearch | Store on SQLite, PostgreSQL or MariaDB with exact and substring search, the local dashboard | Full-text index, aggregations, live ingestion (everything is batch) |
| Wazuh | Reads Wazuh alert JSON. Syslog and web log rules | File integrity monitoring, agents, active response (not planned without your say) |
| TheHive | Cases with linked alerts, versions and timelines | Tasks, assignment, several users, observables |

## What is AI-powered today

`rule draft`: the AI drafts the matching part of a detection rule and code decides whether it is
accepted ([rule-writing.md](rule-writing.md)).

`analyze` and `forensics --analyze`: the AI reviews alerts, relates them through an address, a user, a
host, a machine of the asset list or an indicator, and suggests review steps from a fixed list. No live
model has been measured on the campaign, on a forensic run or on rule writing yet. Everything else on this page is
plain code, on purpose: rules, parsers and lists must work the same with and without a provider.
