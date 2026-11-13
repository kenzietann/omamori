# AI analyst over detected alerts

Omamori is an AI blue-team tool. `analyze` runs local detection, asks the selected
AI provider to review the resulting alerts, and checks its claims against the
available evidence. The original rule alerts remain available even when the
provider fails or its response cannot be verified.

The CLI is the current interface. A dashboard running locally on `127.0.0.1` is
planned, and will call the same analysis service. This slice does not start a web
server or expose an HTTP endpoint.

## Run it

Generate the synthetic logs first, or use your own local logs:

```sh
omamori scenario --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./demo-logs
omamori analyze ./demo-logs --year 2026 --timezone Asia/Tokyo --dry-run
omamori analyze ./demo-logs --year 2026 --timezone Asia/Tokyo --yes
```

Select a provider and model with `--provider` and `--model`, environment variables
`OMAMORI_PROVIDER` and `OMAMORI_MODEL`, or the existing saved settings. API keys
come from the provider's environment variable or the saved key store, never a
command-line argument. `--reasoning` overrides the saved reasoning level.

Without `--yes`, a live run only shows the guarded request preview. It sends
nothing and writes no reports. `--dry-run` makes that behavior explicit.
`--yes` authorizes sending the sanitized snapshot to the selected provider.
Local providers use the same guard. A run with no detected alerts needs no
provider call.

The detection flags also work here: `--rules`, `--format`, `--year`, `--timezone`
and `--output`. Custom rules replace the built-in set. Use `--timeout`, for
example `--timeout 90s`, to change the default two-minute run timeout. The service
makes one logical analysis request; the existing sender may retry a temporary
failure up to twice. This is not a strict provider billing cap.

`omamori forensics --analyze` uses the same service for the alerts of a forensic triage. Evidence
from files of a system carries `time_source`, and a finding that rests on a time that is only the
last change of a file is marked `weak_times` by the checker. See [forensics.md](forensics.md).

## What the AI can contribute

The AI can review individual alerts, identify useful groups sharing an address,
user or host, and select investigation steps from a fixed defensive catalog.
It has no tools and cannot run commands, alter files, contain hosts or contact
anyone.

The response is a strict JSON object containing claims. A single-alert claim
must cite that alert's evidence and state its exact count. A related-alert claim
must cite evidence from every included alert, name a shared entity, and fit within
24 hours. Optional claimed times must agree with the alerts. A shared address or
account is a reason to investigate; it does not establish a single attacker or
a causal chain.

The checker rejects fabricated identifiers, wrong counts or times, citations
from another alert, unsupported actions, duplicate claims, unknown fields and
malformed responses. Displayed explanations are constructed from the checked
facts. Free-form model narrative is not shown as a finding. Suggested review
steps are labeled as suggestions and are not executed.

The snapshot includes at most 100 alerts and eight retained evidence events per
alert, subject to a total request-size limit. It gives priority to higher-severity
alerts and reports omitted alerts and evidence. Opaque IDs preserve entity links
even when sensitive values are replaced by placeholders. Secret filtering is
limited to Omamori's supported detectors; it is not universal anonymization.

Selected source metadata includes event IDs, collector type, ports, signatures
and process context from the [source adapters](intake.md). Each evidence item has
a 1,600-rune budget across field values and a 200-rune limit per field, including
any ellipsis. `truncated_fields` reports shortened or omitted fields. This keeps
the serialized request bounded while retaining useful high-priority evidence.

## Results and replay

Each completed or partial run creates a fresh output folder containing the
deterministic detection results and the analysis:

- `report.md` and `report.html`: detection results, analyst status, verified
  findings, rejected-claim reasons and coverage limits.
- `alerts.json`: the deterministic alerts.
- `analysis.json`: a versioned structured result for local consumers, including
  the future dashboard. It contains checked findings and does not contain raw
  model prose. `recording_status` distinguishes saved, replayed, absent and
  unavailable recordings; an oversized or invalid recording does not hide the
  saved detection results.
- `events.jsonl`: run and provider-request metadata.
- `recording.json`: sanitized provider responses bound to the guarded request,
  when a live provider returned a recordable answer. This replay artifact may
  contain rejected model content; it is not a verified findings report.

The [bundled demo](../testdata/fixtures/analyst/README.md) provides scripted answers
for the seed-3 scenario and needs no provider key.

Play back an analyst recording with the same logs, parser settings and rules:

```sh
omamori analyze ./demo-logs --year 2026 --timezone Asia/Tokyo \
  --replay ./saved-run/recording.json
```

`omamori replay ./saved-run/recording.json ./demo-logs` also routes an analyst
recording to the analyst service. Pass the original year and timezone if they
differ from the current defaults, and the `--rules`, `--assets`, `--indicators`
and `--format` that the run used: without them the alerts differ and the replay
stops. For multiple input paths, use `analyze --replay` and repeat the original
detection flags.

Replay requires no provider key, is labeled `REPLAY`, and never falls back to a
live call. Live recordings match the fingerprint of the guarded request. Changing
facts in the included snapshot or the request causes replay to fail instead of
silently applying an old answer to a different snapshot. The fingerprint covers
that sanitized snapshot, not every source-file byte or the full rule definitions;
changes outside the included evidence may leave it unchanged. Claims are still
checked against the current detection results. Scripted recordings are explicitly
labeled as scripted and do not establish live model quality.

An incomplete analysis returns a nonzero exit status while retaining its
deterministic detection results where output can be written. Rejected claims and
alerts without a checked review remain visible. A successful run means the
displayed claims agree with the supplied evidence; it does not prove compromise,
benign intent or the absence of activity outside those logs.

## Shared application service

The future dashboard should use the same service lifecycle:

1. Build detection results using `internal/detect`.
2. Call `analysisrun.Prepare` with the detected outcome and provider configuration.
3. Display `Session.Preview` and `Session.ConsentText`.
4. Confirm the chosen run, then call `Session.Run` with a cancellable context and
   a progress callback.
5. Render the typed result, including verification status and coverage gaps.

The pure `internal/analyst` package builds snapshots, requests and verified
results. Provider setup, guarded sending, replay and output live in
`internal/analysisrun`. The CLI adapts these APIs in `cmd/omamori/analyze.go`.
An HTTP handler should reuse those APIs, including preview and confirmation,
rather than invoking a subprocess or calling an AI provider directly.
