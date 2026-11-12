# Dashboard redesign validation — 2026-11-12

Design Taste result: **GATE: OPEN 42 (rounds used up)**. No waivers were added and no skill-kit files were edited.

This is the user-approved **Operate dashboard**, not a product landing page. The template gate expects
sales-category headlines, full-screen hero/section/footer composition, a staged visual moment and
hash links that identify document sections. This app instead has routed views, independently scrolling
panes and progressively disclosed charts. The gate also compares text rectangles outside clipped scroll
panes, reporting overlaps that were not visible in the rendered captures. These findings remain recorded
below; they are not presented as a passing template gate.

The independent Impeccable reviewer scored four material fixes **resolved**: persistent desktop
selection/context, phone alert-first placement, complete UTC chart intervals at tablet width, and honest
synthetic-run labeling. The resulting `ship` verdict covers those four fixes, not a whole-surface
certification. The Impeccable detector returned no findings.

## Functional and visual evidence

- `go build ./...`, `go vet ./...` and the full race-enabled Go suite passed.
- Seven frontend tests cover real-sample chart counts, timezone-aware buckets, no invented empty
  history, theme preferences, queue selection, keyboard tabs, full-event opening, script-like text,
  mobile menu/chart disclosure and case creation. Run with `npm ci --prefix tests` then
  `npm test --prefix tests`. The DOM tests complement rather than replace browser rendering.
- Headless captures used the Design Taste scripts at 1440 (light/dark), 1024, 768 and 390 px,
  with a separate lower-row selection capture. Every capture was opened for inspection.
- Performance script: **0 FAIL, 2 WARN**. Both warnings concern the existing light brand PNG's
  approximately 371 KiB transfer at desktop/phone sizes. It was retained to preserve the supplied
  brand asset; no general production performance claim is made from this local fixture run.
- Screenshots used an actual stored run labeled **Synthetic scenario · seed 3**, generated from the
  repository fixture: 1,254 events and 14 alerts. Runtime charts show stored data and do not invent
  production activity. No real AI provider was called during this redesign.
- Existing security controls, SQL services and AI confirmation were not changed.

## Open template-gate findings

| Check | Target | Tool finding |
|---|---|---|
| overlap-text | main#main > div.review-page > div.actions > a.link:nth-of-type(1) "Open selected run"  [1440] | lies over the text "linux_sudo_refused · 1 events / hits" (span:nth-of-type(2) > span.row-meta) (and 1 more like it: "Omamori · Local investig") |
| copy-headline | h1#page-title "Alert review"  [1440] | "Alert review" does not name what is sold (blue team investigation dashboard, blue, team, investigation, from flags) |
| heading-scale | div.review-page > div.review-workspace > section.inspector > h2 "SSH login succeeded after  [1440] | h2 headings in 3 sizes, 15px ("Alert activity") to 22px (x1.47) |
| off-grid | main#main > div.review-page > details.charts-disclosure > summary "Charts · 14 displayed a  [1440, 390] | left edge at 264px, 14px off the page margin at 250px (9 elements, like section.chart-panel:nth-of-type(1)) |
| links | div.shell > aside.navigation > a.brand "omamori"  [1440] | "omamori" goes to #overview, which is not on this page |
| links | div.shell > aside.navigation > nav > a.active "Alert review"  [1440] | "Alert review" goes to #overview, which is not on this page |
| links | div.shell > aside.navigation > nav > a:nth-of-type(2) "Saved runs"  [1440] | "Saved runs" goes to #runs, which is not on this page |
| links | div.shell > aside.navigation > nav > a:nth-of-type(3) "Search evidence"  [1440] | "Search evidence" goes to #search, which is not on this page |
| links | div.shell > aside.navigation > nav > a:nth-of-type(4) "Cases"  [1440] | "Cases" goes to #cases, which is not on this page |
| links | div.shell > aside.navigation > nav > a:nth-of-type(5) "Timeline"  [1440] | "Timeline" goes to #timeline, which is not on this page |
| links | div.shell > aside.navigation > nav > a:nth-of-type(6) "Run activity"  [1440] | "Run activity" goes to #activity, which is not on this page |
| links | div.workspace > header.app-header > div.header-actions > a.button.primary "Start a run"  [1440] | "Start a run" goes to #new, which is not on this page |
| links | nav#mobile-nav > a.active "Alert review"  [1440] | "Alert review" goes to #overview, which is not on this page |
| links | nav#mobile-nav > a:nth-of-type(2) "Saved runs"  [1440] | "Saved runs" goes to #runs, which is not on this page |
| links | nav#mobile-nav > a:nth-of-type(3) "Search evidence"  [1440] | "Search evidence" goes to #search, which is not on this page |
| links | nav#mobile-nav > a:nth-of-type(4) "Cases"  [1440] | "Cases" goes to #cases, which is not on this page |
| links | nav#mobile-nav > a:nth-of-type(5) "Timeline"  [1440] | "Timeline" goes to #timeline, which is not on this page |
| links | nav#mobile-nav > a:nth-of-type(6) "Run activity"  [1440] | "Run activity" goes to #activity, which is not on this page |
| links | div#review-panel > div.actions > a.link "Open run timeline"  [1440] | "Open run timeline" goes to #timeline/r_[fixture-run], which is not on this page |
| links | main#main > div.review-page > div.actions > a.link:nth-of-type(1) "Open selected run"  [1440] | "Open selected run" goes to #run/r_[fixture-run], which is not on this page |
| links | main#main > div.review-page > div.actions > a.link:nth-of-type(2) "Search all evidence"  [1440] | "Search all evidence" goes to #search/r_[fixture-run], which is not on this page |
| fold-action | div#review-panel > button.secondary  [1440, 390] | the hero's main button "Open alert details" starts 926px below the first screen (900px tall): it is not seen on load |
| moment-none | (the page)  [1440] | a software page (--type) deals no moment: every kind carries one, two on a long page (moments.md) |
| hero-screen | main#main > div.review-page "Selected runSynthetic scenario · seed 3 "  [1440] | the hero ends at 1308px on a 900px screen, 408px below the fold: it ends at the fold, 1px either way (SR-1) |
| section-height | div.shell > div.workspace > footer "Omamori · Local investigation workspaceR"  [1440] | the section is 49px tall (0.1 screens), 851px short of one screen (900px): every section after the hero is one screen or two, 2px either way (SR-2) |
| section-height | main#main > div.review-page "Selected runSynthetic scenario · seed 3 "  [1440] | the section starts at 137px, 137px below the screen grid (0 x 900px): sections start on whole screens (SR-2) |
| one-section | div.shell > div.workspace > footer "Omamori · Local investigation workspaceR"  [1440] | the screen at scroll 497px (the top of section 2) shows 49px of section 2 beside section 1: a screen shows one section (another may peek 8px, 24px WARN) (SR-4) |
| one-section | main#main > div.review-page "Selected runSynthetic scenario · seed 3 "  [1440] | a <div> sits directly in <main>: every part of <main> is a <section> (SR-4) |
| one-heading | div.charts-grid > section.chart-panel:nth-of-type(1) > div.chart-heading > h2 "Alert activ  [1440] | the hero holds an h2 (4): its heading is the h1, and an h2 opens the next section (SR-5) |
| container-edges | div.shell > div.workspace > header.app-header "Alert review Review alerts with their so"  [1440] | the nav's content runs 250px from the left and 32px from the right (read from its outermost blocks: no .wrap): 250 and 32px are not one margin; the margin is 64-120px at 1440px (one container, equal margins, 2px either w |
| container-edges | main#main > div.review-page "Selected runSynthetic scenario · seed 3 "  [1440] | the content of section 1 runs 250px from the left and 32px from the right (read from its outermost blocks: no .wrap): 250 and 32px are not one margin; the margin is 64-120px at 1440px (one container, equal margins, 2px e |
| container-edges | div.shell > div.workspace > footer "Omamori · Local investigation workspaceR"  [1440] | the content of section 2 runs 250px from the left and 32px from the right (read from its outermost blocks: no .wrap): 250 and 32px are not one margin; the margin is 64-120px at 1440px (one container, equal margins, 2px e |
| container-edges | a.skip "Skip to content"  [1440] | a <a> at the top of the page, outside header.nav, main, footer.closing and nav.actionbar (SR-6) |
| container-edges | div.shell "omamori Alert reviewSaved runsSearch evi"  [1440] | a <div> at the top of the page, outside header.nav, main, footer.closing and nav.actionbar (SR-6) |
| container-edges | div.charts-grid > section.chart-panel:nth-of-type(2) > div.chart-heading > h2 "Alert sever  [1440] | the h2 starts 708px right of the container's left: every h1 and h2 starts on it, 2px either way (SR-6) |
| container-edges | div.review-workspace > section.inspector > div.status-line > span.badge.critical "critical  [1440] | 1 text block starts on a left line at x 860, 610px from the container's left: text starts on the container's left, or on one split line (x 743, 841, 940) (and 4 more like it: x 853, "SSH login succeeded afte", "Alert act |
| split-pair | main#main > div.review-page > div.review-workspace "AlertsSeverityAll severitiescriticalhi  [1440] | the two columns of the split start 24px apart at the top (centred on each other): a split's columns are top-aligned, 8px either way (SR-8) |
| overlap-text | div.review-workspace > section.inspector > div.status-line > span.mono.subtle "a1"  [390] | lies over the text "Cron runs a download that is piped into " (span:nth-of-type(2) > span.row-title) (and 3 more like it: "root · 203.0.113.9 · web", "auth.log:27 · 11/10/2026", "auth.log:34 · 11/10/2026") |
| overlap-text | div.review-page > div.review-workspace > section.inspector > h2 "SSH login succeeded after  [390] | lies over the text "linux_cron_download_exec · 1 events / hi" (span:nth-of-type(2) > span.row-meta) (and 2 more like it: "root · 203.0.113.9 · web", "root · 203.0.113.9 · web") |
| overlap-text | div#review-panel > div.evidence-list > article.evidence-entry:nth-of-type(1) > p:nth-of-ty  [390] | lies over the text "Medium" (button.alert-row:nth-of-type(8) > span.severity-label) (and 1 more like it: "login") |
| text-only | main#main > div.review-page "Alert activity"  [390] | the closing section is only text: no picture, icon, mock or effect in it |
| container | page  [1440, 390] | no .wrap |
