# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Existing Go application with embedded HTML, CSS and vanilla JavaScript. No frontend server or external CDN is required. The terminal UI and web dashboard share the detector, analyst, forensic and SQL services.

## Users

Blue-team security practitioners and developers investigating local logs and collected evidence. The user confirmed that reviewing alerts and opening their evidence should lead the redesigned dashboard.

## Product Purpose

Omamori helps inspect exposure, detect patterns in logs and Linux artifacts, verify AI review claims, and assemble investigations with explicit evidence references.

## Positioning

AI reviews are checked against locally detected facts. The analyst has no executable tools; unsupported model prose does not become a verified finding.

## Operating Context

The dashboard runs on IPv4 loopback and uses a per-launch access token. Evidence paths are confined to a user-selected root. Users inspect saved runs, alert details, events, checked citations, cases and timelines; new work requires preview and confirmation.

## Capabilities and Constraints

SQLite, PostgreSQL and MariaDB share one store API. Synthetic fixtures are available but must never be presented as production telemetry or proof of live model quality. Preserve security controls, real data, source provenance, weak-time disclosures, case versions, query scope, loading/error/empty states, cancellation and keyboard operation. No public hosting or remote fonts/scripts. The requested change is a complete visual redesign of the dashboard, not a backend replacement.

## Brand Commitments

Keep the name Omamori and the existing O+M brand mark. The user chose the light Reference workspace direction and explicitly requested a matching dark mode and charts of actual stored data. Use direct, concise English. No invented performance claims, customers, alerts or incident verdicts.

## Evidence on Hand

Repository feature guides in docs/, implemented APIs in internal/dashboard and internal/store, and labeled synthetic fixtures in testdata/fixtures. Current visual implementation: internal/dashboard/assets. The previous dark mint, card-heavy world is the redesign's anti-reference, not a binding palette.

## Product Principles

- Put the alert and its evidence before promotional copy.
- Preserve provenance and uncertainty while reducing navigation effort.
- Treat stored text as data, never executable content.
- Keep AI use explicit and locally checked.
- Let CLI and browser use the same services.
