---
name: Omamori
description: A precise local investigation workspace for alerts and their source evidence.
colors:
  bg: '#f2f3ef'
  surface: '#fff'
  soft: '#f8f9f6'
  ink: '#172b29'
  muted: '#52645f'
  line: '#d6ddd7'
  accent: '#155bd7'
  accent-ink: '#fff'
  selected: '#e9effb'
  focus: '#155bd7'
  critical: '#b82b38'
  critical-bg: '#fcebed'
  high: '#914318'
  high-bg: '#fff0e5'
  medium: '#835700'
  medium-bg: '#faf2d9'
  low: '#17685e'
  low-bg: '#e5f3ee'
  info: '#52677d'
  info-bg: '#edf1f6'
  dark-bg: '#151d20'
  dark-surface: '#1c272b'
  dark-soft: '#202e32'
  dark-ink: '#eaf0ed'
  dark-muted: '#afc0ba'
  dark-line: '#3a4b4e'
  dark-accent: '#8db6ff'
  dark-accent-ink: '#102443'
  dark-selected: '#293c51'
  dark-focus: '#a0c3ff'
  dark-critical: '#ff9aa7'
  dark-critical-bg: '#482e36'
  dark-high: '#f2b88a'
  dark-high-bg: '#44372b'
  dark-medium: '#e8cb79'
  dark-medium-bg: '#3c3b2b'
  dark-low: '#8fd2be'
  dark-low-bg: '#243d36'
  dark-info: '#b3c5df'
  dark-info-bg: '#2e394b'
typography:
  headline:
    fontFamily: '"Public Sans", sans-serif'
    fontSize: 28px
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: -0.8px
  title:
    fontFamily: '"Public Sans", sans-serif'
    fontSize: 18px
    fontWeight: 650
    letterSpacing: -0.3px
  body:
    fontFamily: '"Public Sans", sans-serif'
    fontSize: 14px
  label:
    fontFamily: '"Public Sans", sans-serif'
    fontSize: 12px
    fontWeight: 500
  button:
    fontFamily: '"Public Sans", sans-serif'
    fontSize: 13px
    fontWeight: 600
  evidence-mono:
    fontFamily: ui-monospace, SFMono-Regular, Menlo, monospace
    fontSize: 12px
rounded:
  badge: 4px
  control: 5px
  compact-panel: 6px
  panel: 8px
  dialog: 12px
spacing:
  xs: 8px
  sm: 12px
  md: 16px
  lg: 20px
  xl: 24px
  workspace: 32px
components:
  button-primary:
    backgroundColor: '{colors.accent}'
    textColor: '{colors.accent-ink}'
    typography: '{typography.button}'
    rounded: '{rounded.control}'
    padding: 10px 16px
  button-secondary:
    backgroundColor: '{colors.surface}'
    textColor: '{colors.ink}'
    typography: '{typography.button}'
    rounded: '{rounded.control}'
    padding: 10px 16px
  input:
    backgroundColor: '{colors.surface}'
    textColor: '{colors.ink}'
    typography: '{typography.body}'
    rounded: '{rounded.control}'
    padding: 10px 12px
  navigation-active:
    backgroundColor: '{colors.selected}'
    textColor: '{colors.accent}'
    rounded: '{rounded.control}'
    padding: 12px 14px
  badge-info:
    backgroundColor: '{colors.info-bg}'
    textColor: '{colors.info}'
    rounded: '{rounded.badge}'
    padding: 4px 7px
  panel:
    backgroundColor: '{colors.surface}'
    rounded: '{rounded.panel}'
  alert-row-selected:
    backgroundColor: '{colors.selected}'
    textColor: '{colors.ink}'
    padding: 19px 20px
  inspector-tab-active:
    textColor: '{colors.accent}'
    padding: 10px 0
---

# Design System: Omamori

## Overview

**Creative North Star: "The Reference Workspace"**

The Reference Workspace makes investigation feel precise and grounded: warm light surfaces, green-black ink, cobalt selection and aligned records. Its matching dark theme preserves the same geometry, reading order and semantic distinctions. Light is the default; the user chooses when to switch.

Omamori keeps its existing O+M mark and concise English. Public Sans gives the application a clear, modern voice; dividers and restrained state feedback do the structural work. This is an operational application, so information density follows the task and motion supports changes of state.

**Key Characteristics:**
- Warm neutral surfaces and strong reading contrast.
- One clear selection accent, separate from severity colors.
- Aligned records, adjacent evidence and visible provenance.
- Self-hosted assets and matching light/dark geometry.

## Colors

Warm, slightly green neutral surfaces carry deep green ink; cobalt identifies the current action or selection. The frontmatter records the exact CSS values. Unprefixed colors map to the light `:root` variables; `dark-` entries map to the same variable under `data-theme="dark"`.

### Primary
- **Cobalt / Night Blue** (`accent`, `dark-accent`): primary actions, links, activity bars and active navigation. The paired `accent-ink` supplies button text.
- **Selection Wash** (`selected`): selected records and navigation backgrounds.
- **Focus Blue** (`focus`): keyboard outline, kept distinct in dark mode.

### Secondary
- **Critical Rose**, **High Rust**, **Medium Ochre**, **Low Green** and **Informational Slate**: the `critical`, `high`, `medium`, `low` and `info` families pair readable foregrounds with their `-bg` washes. Preserve labels alongside color. These are semantic states, not decorative accents.

### Neutral
- **Workspace Paper / Night Ground** (`bg`): overall workspace.
- **Surface** (`surface`): navigation, controls, panels and dialogs.
- **Soft Surface** (`soft`): quiet hover, table headings and raw-evidence blocks.
- **Reading Ink** (`ink`), **Supporting Ink** (`muted`) and **Divider** (`line`): primary text, metadata and structural edges.

**The Selection Is Not Severity Rule.** Use the accent for navigation, actions and selection. Use labeled severity colors for alert level and status; color alone never carries the meaning.

## Typography

**Body and heading font:** self-hosted Public Sans variable TrueType, loaded from `/public-sans.ttf` with `font-display: swap` and weights 100–900. The fallback is sans-serif. The font license is retained in `internal/dashboard/assets/FONT-LICENSE.txt`.

**Evidence font:** ui-monospace, SFMono-Regular, Menlo, monospace. This is reserved for machine-readable identifiers and raw content.

**Character:** clear, compact and modern, with modest tightening on headings. There is no separate display face or marketing type scale.

### Hierarchy
- **Headline:** page heading; the normative headline token reduces to 25px on mobile.
- **Title:** section headings; inspector titles use 22px, line-height 1.4 and weight 650, reducing to 21px on mobile. Chart headings use 15px.
- **Body:** the base reading face; paragraphs use line-height 1.65. Dense evidence rows use 13px, with 12px metadata after the readability corrections.
- **Label:** form and table labels; buttons have their own normative role.
- **Evidence mono:** identifiers and technical text; raw blocks use line-height 1.7.
- **Numerals:** strong values, times and statistics use tabular numerals. The brand wordmark uses weight 750 and 25px on desktop.

**The Evidence Stays Legible Rule.** Keep identifiers and source text selectable and allow long values to wrap. Use monospace for raw evidence, not as a substitute for the main reading face.

## Layout

The desktop shell has a sticky navigation rail (218px) and a flexible workspace with 32px gutters. At 1150px and below the rail/gutter become 190px/24px; at 900px and below they become 170px/20px. Above 1700px, the workspace is centered with a 1600px maximum width. Spacing uses repeated compact steps in the frontmatter; chart and panel interiors also use the observed 22px inset.

The alert-review surface pairs the queue with the selected evidence. Above 900px the shared frame is 640px high, with independent queue and inspector scrolling. At 900px and below they stack and the queue is capped at 350px. At 650px and below the rail becomes a top bar, the menu reveals a two-column navigation list, gutters become 16px and the queue cap becomes 370px. Review panels then size naturally. Forms move from three columns to two at 1150px, then one at 650px. Inputs reach 16px text on mobile.

Chart panels use a 1.4:1 desktop split, equal columns at 900px, and one column at 650px. Their disclosure starts collapsed at mobile width and open above it. A narrow chart scrolls inside its labeled focusable plot; its minimum plot width is 320px. Tables likewise scroll inside a focusable region rather than widening the page. These are observed dashboard patterns, not a requirement that every future screen repeat this composition.

## Elevation & Depth

Surface tones and single-pixel dividers establish hierarchy. Working panels stay flat. Only the native dialog uses the theme-dependent ambient shadow; its translucent backdrop separates focused evidence from the workspace. The sidecar owns the exact shadow values and motion tokens. The dialog backdrop uses the observed translucent green-black overlay (`#142b2966`).

**The Flat Working Surfaces Rule.** Working panels use surface tone and borders. Reserve the ambient shadow for the modal dialog; the active tab underline is a state indicator, not elevation.

## Shapes

Small corners keep controls precise: badges use the badge radius, inputs/buttons/navigation use the control radius, and panels use the panel radius. Mobile panels use the compact-panel radius. Dialogs use the larger dialog radius. Queue rows remain square within the shared rounded frame, and dividers align from row to row. No universal pill shape is implied by the small circular local-workspace indicator.

## Components

### Buttons
Compact, clearly labeled controls. Primary actions use accent with accent ink; secondary actions use surface with reading ink. Both have a 44px minimum height and a single-pixel border. Secondary hover changes surface and border; primary hover applies brightness 0.93. Press translates by 1px, except queue rows. Disabled buttons reduce opacity to 0.5. Links underline on hover.

### Inputs / Fields
Surface-filled controls with divider borders and the control radius. They share the 44px minimum height; labels sit above with an 8px gap. Text areas resize vertically and begin at 120px. Placeholder text uses supporting ink. Focus uses a 2px focus-colored outline offset 3px.

### Navigation
A quiet vertical list on desktop; the active item uses selection wash, accent text and weight 650. Hover uses the soft surface. Mobile navigation is revealed by an explicit Menu button with expanded state. The theme switch announces its target theme and pressed state; `omamori-theme` in localStorage persists the choice. A valid `?theme=` override applies for the visit and is removed when switching manually. The light theme is the fallback when storage is unavailable. The existing dashboard brand assets are `/icon-light.png` for light and `/icon.png` for dark, loaded locally from `internal/dashboard/assets`; these are the confirmed O+M identity assets, not newly invented marks.

### Status badges
Small rectangular labels with 11px text, weight 600, line-height 1.5 and severity-specific foreground/background pairs. Complete/closed use the low palette; failed uses critical; running/preparing use medium; incomplete uses high; open/ready use informational. Their visible text remains the authority.

### Panels and dialogs
A bordered surface with modest corners. Panel heads separate title/actions from the body; chart panels use the same visual vocabulary. Dialog headings stay sticky, with a labeled close control. Use native dialog behavior and preserve existing action guards.

### Alert queue and evidence inspector
Selectable rows display severity, a two-line title and wrapping metadata. Selection uses `aria-pressed` and the selection wash; the full title and provenance are available in the adjacent inspector. Inspector tabs use a single accent underline with `aria-selected`, roving tab stops and ArrowLeft/ArrowRight/Home/End keyboard navigation. The evidence body enters over 160ms from opacity 0.75 and a 3px vertical offset; reduced motion disables animation and transitions. Rows do not jump when pressed.

### Real-data charts
Severity bars count the fetched alerts. Activity bars count UTC intervals from alert timestamps, choosing hourly or daily base units and grouping into at most twelve buckets. Counts and interval labels are visible, with chart data tables available. The chart and queue cover the selected run's latest up-to-200 alerts and disclose displayed versus total counts. Invalid timestamps raise an error; empty runs do not generate invented series. These counts are sample descriptions, not a verdict or a full-history claim.

## Do's and Don'ts

### Do:
- **Do** keep the existing Omamori name and O+M mark, with the matching icon for each theme.
- **Do** preserve labeled severity, visible keyboard focus, reduced-motion behavior and readable source paths.
- **Do** disclose the selected run, displayed alert count and UTC bucket intervals beside charts.
- **Do** keep real evidence, explicit uncertainty and guarded actions intact when changing presentation.

### Don't:
- **Don't** present synthetic fixtures or the latest retained sample as complete production telemetry.
- **Don't** replace adjacent evidence with a decorative dashboard statistic or hide its provenance.
- **Don't** add remote fonts or scripts to this local application.
- **Don't** turn marketing hero or perpetual-motion conventions into requirements for operational screens.
