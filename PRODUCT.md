# Argus — product context

> **Provenance:** written from the user's explicit brief and the pinned Claude
> Design reference rather than a live interview — the user asked to proceed
> directly to the build. Assumptions are labelled **[assumed]**.

## What it is

Argus is a desktop security scanner (Tauri + React shell over a Python
engine). It reads a codebase or attacks a running target, then reports what it
found. Named for Argus Panoptes, the hundred-eyed guardian of Greek myth.

## Who uses it

A developer or security engineer auditing their own code or deployment,
working alone, on a desktop, usually in a dim room for a long session
— which is why the surface is dark. **[assumed]**

## What must stay true

- **Never fabricate findings.** The app ships with no demo data. Every
  finding, count, model and path shown comes from the real engine. If there is
  no data, the screen says so plainly rather than showing a placeholder chart.
- **Report honestly.** A blocked or inconclusive scan says so; it never reads
  as "clean".
- Three real surfaces: the overview, scan setup, and the findings register.
- Real data lives in `gui/src/store.ts` (zustand) via Tauri IPC; the browser
  dev build reads an optional `report.json` and is otherwise empty.

## Mode

**Operate.** The user is completing a task, not being persuaded. Scanability
and honest state outrank expression. The mythic voice is carried in *language*
and *ornament*, never at the cost of legibility.
