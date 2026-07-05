# JS Intelligence & Sensitive Information Mining Platform

<p align="center">
  <img src="docs/images/banner.png" alt="JS Intelligence Platform banner" width="100%">
</p>

Automated recon → JavaScript discovery → secret/PII detection pipeline for
authorized bug bounty and security audit engagements.

> **Note on images:** the screenshots below are placeholders (see
> [`docs/images/README.md`](docs/images/README.md)). Run the app and follow
> [`scripts/screenshots.md`](scripts/screenshots.md) to capture and drop in
> the real ones — filenames already match, so no README edits are needed.

> **Scope note:** this repo currently ships the **core engine** (async pipeline,
> plugin scanners, static + AI-assisted detection, HTML/JSON/CSV reporting) as a
> CLI. The Tauri/React desktop UI with live WebSocket dashboard described in the
> original spec is a planned Phase 2 — the backend is already structured
> (`on_event` callback + resumable `ScanState`) so a UI can bolt straight on.

## Pipeline

```
Domain → Subfinder/Assetfinder/Amass → Dedup → HTTPX (alive check)
       → Katana/Hakrawler/GoSpider/GAU/Waybackurls (crawl)
       → JS URL extraction → Download
       → Regex + Entropy detectors → TruffleHog + Nuclei
       → Gemini AI triage (severity / confidence / false-positive)
       → HTML + JSON + CSV report
```

## Requirements

- Python 3.10+
- Go 1.21+ (for subfinder, httpx, katana, nuclei, gau, waybackurls, hakrawler, gospider, assetfinder)
- `amass`, `trufflehog` (see `install.sh` for install commands)
- Optional: a Gemini API key for AI triage (`GEMINI_API_KEY` or `set-key` command)

Works on Kali, Ubuntu, Debian, and WSL. Windows native works for the Python
layer; Go recon tools need WSL or native Go builds.

## Install

```bash
git clone https://PradyumnTiwareNexus/js-intel-scanner.git
cd js-intelligence
./install.sh
```

`install.sh` installs Python deps, attempts to `go install` every recon tool,
and runs the first-run tool-detection wizard.

## Configure

All external tool binary paths are auto-detected via `$PATH` on first run and
cached in `configs/config.yaml`. Override any path manually there — nothing is
hard-coded.

```bash
python -m backend.cli detect-tools     # re-run detection
python -m backend.cli set-key <your_gemini_api_key>
python -m backend.cli settings         # view current config
```

## Run a scan

```bash
python -m backend.cli scan example.com
python -m backend.cli scan -f domains.txt -o exports/
```

<p align="center">
  <img src="docs/images/cli-scan.png" alt="CLI scan output" width="85%">
</p>

Output per domain lands in `exports/<domain>/report/`:
- `report.html` — dashboard
- `report.json` — full structured findings
- `report.csv` — flat export

Scans are **resumable** — re-running the same domain skips completed stages
(checkpoint stored in `exports/<domain>/checkpoint.json`).

## Known caveat: `httpx` name collision

The Python `httpx` library (used internally for downloads/AI calls) also
installs a CLI shim called `httpx` in some environments, which can shadow
ProjectDiscovery's `httpx` recon tool on `$PATH`. If `detect-tools` finds an
`httpx` that isn't the recon tool, set the correct path explicitly in
`configs/config.yaml` under `tool_paths.httpx`.

## Security notes

- Matched secrets are **redacted** before being written to disk or sent to
  Gemini (short prefix/suffix only) — full plaintext secrets are never stored
  in reports.
- AI triage is optional enrichment; the pipeline works fully offline with
  regex + entropy + TruffleHog + Nuclei if no Gemini key is set.
- Only run this against domains you are authorized to test.

## Phase 2 — Live web dashboard (done)

A FastAPI server + WebSocket live-progress stream is included, along with a
single-file dark-themed dashboard (`frontend/index.html`, no build step).

```bash
uvicorn backend.api.server:app --reload --port 8787
# then open frontend/index.html in a browser (or file:// it directly)
```

<p align="center">
  <img src="docs/images/dashboard-idle.png" alt="Dashboard, idle" width="32%">
  <img src="docs/images/scan-running.png" alt="Scan in progress with live logs" width="32%">
  <img src="docs/images/scan-complete.png" alt="Scan complete with stats and export links" width="32%">
</p>
<p align="center">
  <img src="docs/images/findings-table.png" alt="Findings table with severity/confidence" width="48%">
  <img src="docs/images/html-report.png" alt="Exported standalone HTML report" width="48%">
</p>

API surface:
- `POST /api/scan` `{domain}` → `{scan_id}` — starts an async scan
- `GET /api/scan/{id}` → status + full summary once done
- `POST /api/scan/{id}/cancel` — cancel a running scan
- `WS /ws/{id}` — live stage/progress/log events, replays history to late joiners
- `GET /api/tools` — tool auto-detection status
- `GET /POST /api/settings` — read/update config (API key masked in responses)
- `GET /api/report/{id}/{html|json|csv}` — download a finished report

This same API is what a Tauri shell (Phase 3) will point its webview at —
`frontend/index.html` can be loaded as-is inside a Tauri window with no
rewrite needed.

## Phase 3 — Tauri desktop app

`src-tauri/` wraps the Phase 2 dashboard into a native desktop window. On
launch it spawns `uvicorn backend.api.server:app` as a child process, waits
for it to accept connections, then shows the window pointed at
`frontend/index.html` — no rewrite of the frontend was needed.

### Prerequisites (one-time, per OS)

- Rust + Cargo: https://rustup.rs
- Tauri system deps for your OS: https://tauri.app/v1/guides/getting-started/prerequisites
  (Linux needs `webkit2gtk`, `libappindicator`; Windows needs the WebView2
  runtime, usually already present; macOS needs Xcode command line tools)
- Node.js (already required if you use the npm-based Tauri CLI)
- Python 3 + this repo's `requirements.txt` installed (`./install.sh`)

### Generate real app icons

Placeholder icons ship in `src-tauri/icons/` so the project builds out of
the box. Replace them with your own artwork:

```bash
npm install
npx tauri icon path/to/your-1024px-logo.png
```

This regenerates every required size/format, including `icon.icns` for
macOS (not included by default — it can't be generated outside macOS).

### Dev mode

```bash
npm install
npm run dev
```

### Production build

```bash
npm run build
```

Outputs a native installer (`.deb`/`.AppImage` on Linux, `.msi`/`.exe` on
Windows, `.dmg`/`.app` on macOS) under `src-tauri/target/release/bundle/`.

### Packaging: standalone sidecar (Phase 4, no Python needed)

By default `main.rs` tries a bundled sidecar binary first and only falls
back to `python3 -m uvicorn` if it's missing (dev convenience). To ship a
fully self-contained installer with **no Python dependency** for end users:

```bash
pip install pyinstaller
./build_sidecar.sh
```

This freezes the entire FastAPI backend into one binary via PyInstaller,
verified end-to-end (starts, serves `/api/*`, runs a full scan lifecycle)
in this repo's test build, and drops it into
`src-tauri/binaries/js-intelligence-server-<target-triple>` — the naming
convention Tauri's `externalBin`/sidecar mechanism expects. Then:

```bash
npm run build
```

produces a native installer with the backend baked in — nothing else to
install.

Build the sidecar **on each target OS** (or cross-compile PyInstaller,
which is finicky) — a Linux-built binary won't run on Windows/macOS. Set
`TARGET_TRIPLE` manually if `rustc` isn't installed on the build machine:

```bash
TARGET_TRIPLE=x86_64-pc-windows-msvc ./build_sidecar.sh   # example override
```

The sidecar binary is ~40MB and is gitignored — build it locally or in CI,
don't commit it to the repo.

## Roadmap (Phase 5)

- [ ] Source-map deobfuscation + AST-based endpoint extraction
- [ ] Proxy rotation UI, per-scan rate-limit controls
- [ ] Screenshot capture per JS-serving host
- [ ] Persistent scan history (SQLite) instead of in-memory registry
- [ ] Cross-platform CI job that builds the sidecar + installer for
      Linux/Windows/macOS on tagged releases

## License

MIT — see `LICENSE`.
