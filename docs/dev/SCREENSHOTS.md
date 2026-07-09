# Capturing real GUI screenshots for marketing/README

The GUI ships with **no bundled demo data** by design (every screen shows real
engine output or an honest empty state). To get a populated, real screenshot for
the README/launch posts, generate a real report and drop it where the browser dev
build looks for one.

## Steps (verified working)

1. Generate a real combined scan + attack report from the bundled demo target:

   ```bash
   python -c "
   import json, tempfile, shutil
   from pathlib import Path
   from argus.demo.target import SAMPLE_FILES, DemoServer
   from argus.pipeline import _do_scan
   from argus.llm.orchestrator import run_attack_sync

   tmp = Path(tempfile.mkdtemp(prefix='argus-shot-'))
   for name, content in SAMPLE_FILES.items():
       (tmp / name).write_text(content, encoding='utf-8')

   result = _do_scan(str(tmp), deep=False, depth=None, no_llm=True)

   server = DemoServer().start()
   try:
       findings, reports, _eps = run_attack_sync(server.url)
       for f in findings:
           result.add(f)
   finally:
       server.stop()

   shutil.rmtree(tmp, ignore_errors=True)
   Path('gui/public/report.json').write_text(json.dumps(result.to_dict(), indent=2), encoding='utf-8')
   print('findings:', len(result.findings), 'risk:', result.risk_score, result.risk_band)
   "
   ```

   This produces a real, non-fabricated report (last verified: 26 findings, risk
   100/CRITICAL) — `gui/public/report.json` is gitignored, so this never ships.

2. Start the GUI dev server: `cd gui && npm run dev` (or via the Claude Code preview
   tool using the `argus-gui` launch config).

3. Open `http://localhost:5173`, navigate to **Reports** — it renders the dropped-in
   report immediately (no click needed beyond selecting the tab).

4. For the best screenshot: the report table is wider than a typical browser
   screenshot capture width. Either widen the browser window substantially before
   capturing, or apply `document.body.style.zoom = '0.65'` via devtools console to
   fit the full table (severity, title, endpoint, agent, CVSS columns) into frame.

5. Also worth capturing: **Live Attack** screen during an actual `argus attack --url
   <demo-server-url>` run (shows the real-time agent feed), and **Dashboard** after
   a couple of real scans have populated the risk-trend graph (`argus history`
   needs 2+ real scan runs saved via the CLI, not just the dropped-in report.json,
   to show a trend line).

## Where to use the results

- README: replace/augment the `docs/assets/hero-banner.svg` hero with a real
  screenshot in the "Desktop GUI" section.
- Launch posts (`docs/launch/` drafts, if kept, or wherever they were saved):
  attach alongside `docs/assets/social-preview.png`.
- Keep exported PNGs under `docs/assets/` (e.g. `screenshot-reports.png`,
  `screenshot-live-attack.png`) — small enough not to bloat the repo, and this
  keeps every visual asset in one place.
