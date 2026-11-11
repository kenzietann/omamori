# Multi-source intake fixture

Everything here is synthetic. It follows the documented exporter shapes but was
not collected from a real sensor, host or incident.

`logs/mixed.jsonl` contains eight records: Suricata EVE, Zeek HTTP, a generic
Wazuh alert, Wazuh-wrapped Sysmon process creation, Winlogbeat Sysmon network
activity, NXLog Windows login failure and success, and generic JSON.

`rules/observations.yml` contains eight demonstration rules. They produce six
alerts: five source observations and one Windows failure-followed-by-success
sequence. These are observation checks, not claims of malicious intent. The
two individual authentication rules are suppressed by their correlation.

From the repository root:

```sh
go run ./cmd/omamori detect ./testdata/fixtures/intake/logs \
  --rules ./testdata/fixtures/intake/rules --year 2026 --timezone UTC \
  --output ./intake-demo-reports
```

Expected summary: **1 file, 8 events, 8 rules, 6 alerts** (2 medium, 2 low,
2 informational). The file table names all five source types, including generic
JSON. Source-specific original scalar fields are retained under `raw.*`.

To review the same alerts with your configured AI provider, use `analyze` with
the same arguments. Its default is a guarded request preview; add `--yes` to
send it. The automated CLI test uses a fake provider and verifies all six claims
without sending fixture data to a real provider.

With `--format windows`, only the three direct Windows records are accepted.
The report explicitly counts the other five lines as unread: Wazuh-wrapped
Windows events have source `wazuh` and are selected with `--format wazuh`.

See [the intake guide](../../../docs/intake.md) for supported shapes and limits.
