# Capturing README Screenshots

This project's README references real screenshots of the running dashboard.
No fake/mocked images are shipped in this repo — the files under
`docs/images/` are 1x1 placeholders so the README renders correctly before
you replace them. Follow the steps below to capture the real ones.

## Setup

```bash
./install.sh                                   # one-time
uvicorn backend.api.server:app --reload --port 8787
```

Open `frontend/index.html` directly in your browser (or serve it with any
static file server). Use a browser window sized to **1440x900** for
consistent framing, and your OS's built-in screenshot tool (or an extension
like "GoFullPage" for full-page captures where noted).

Save every file as **PNG**, into `docs/images/`, using the exact filenames
below so the README's `<img>` tags pick them up with no further edits.

---

## 1. `docs/images/dashboard-idle.png`
**State:** page freshly loaded, before starting a scan.
**Shows:** the domain input bar and the empty page chrome.
**Steps:** load `frontend/index.html`, take the screenshot before typing
anything.

## 2. `docs/images/scan-running.png`
**State:** a scan in progress.
**Shows:** the stage label, the "running" status badge, the animated
progress bar mid-fill, and the live log console (`#logConsole`) populated
with several real scanner-output lines.
**Steps:** type a domain you're authorized to test into `#domainInput`,
click **Scan**, and capture within the first 20-40 seconds while
`progressPanel` is visible and the log console has scrolled content.

## 3. `docs/images/scan-complete.png`
**State:** scan finished (`statusBadge` shows `done`).
**Shows:** the finished progress bar at 100%, the stats row (`#statsRow`)
with real counts (JS files found, secrets found, endpoints, APIs), and the
export links row (`#exportLinks`: HTML / JSON / CSV).
**Steps:** let a real scan run to completion against a small test target,
then screenshot the full panel stack.

## 4. `docs/images/findings-table.png`
**State:** scan complete, findings table populated.
**Shows:** the `#findingsBody` table with several real rows — severity,
confidence, JS URL, line number, evidence, recommendation columns visible.
**Steps:** scroll to the findings table after a completed scan; if it's
long, use a full-page capture so multiple severities are visible in one
image. Prefer a target that produced at least one High/Medium/Low finding
each, so the severity color-coding is visible.

## 5. `docs/images/html-report.png`
**State:** the standalone exported report, opened directly.
**Shows:** `exports/<domain>/report/report.html` opened in a new tab
(click the "📄 HTML Report" export link).
**Steps:** click through from the export links row, screenshot the
generated report page itself (not the live dashboard).

## 6. `docs/images/cli-scan.png`
**State:** terminal output of a CLI run.
**Shows:** the output of:
```bash
python -m backend.cli scan example.com
```
from start to the final summary line, in a terminal with a dark theme and
monospace font matching the rest of the docs.
**Steps:** run the command in a normal-width terminal (~120 columns),
screenshot the full pane once the scan finishes.

---

## Notes

- Only scan domains you are authorized to test (see the Security notes in
  the main README).
- Do not hand-edit or mock up any of these images — they must be real
  captures of the actual running application, or the README's claims about
  the UI stop being accurate.
- If a UI element referenced above doesn't exist yet in your checkout
  (e.g. you're on a branch mid-feature), skip that screenshot and note it
  in your PR description rather than faking the shot.
- After capturing, optimize file size with `pngquant docs/images/*.png` or
  similar before committing (screenshots this size shouldn't exceed
  ~300-500KB each).
