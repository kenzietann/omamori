# Scripted analyst demo

`recording.json` contains made-up model answers for the built-in seed-3 scenario.
It is labeled `scripted`, has no live request fingerprint, and is not evidence of
a real model's quality. The answers still go through the normal claim checker.

From the repository root, generate the logs and run the offline demo:

```sh
go run ./cmd/omamori scenario --seed 3 --date 2026-11-10 --timezone Asia/Tokyo ./analyst-demo-logs
go run ./cmd/omamori analyze ./analyst-demo-logs --year 2026 --timezone Asia/Tokyo \
  --replay ./testdata/fixtures/analyst/recording.json --output ./analyst-demo-reports
```

Use new output folders if those names already exist. The demo makes 15 alerts and
16 checked claims: one review per alert, plus a shared-source-address link between
the guessing burst and the successful-login sequence. No provider is created and
no API key is needed. The report says `REPLAY (scripted answers)`.

This fixture uses opaque IDs from the seed-3 snapshot. Changes to detection or
snapshot ordering may require updating it; the CLI regression test checks that
the bundled example remains valid.
