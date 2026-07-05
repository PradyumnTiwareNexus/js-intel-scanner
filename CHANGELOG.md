# Changelog

## [0.4.0] - Phase 4 — Standalone Sidecar (no Python required)
### Added
- `backend/sidecar_entry.py` — PyInstaller entry point running the FastAPI
  backend standalone
- `build_sidecar.sh` — builds + names the binary per Tauri's
  `externalBin` target-triple convention
- `main.rs` now tries the bundled sidecar first, falls back to
  `python3 -m uvicorn` for dev mode
- Verified end-to-end in this repo: built a ~40MB onefile Linux binary,
  ran it from a clean working directory, confirmed `/api/settings`,
  `/api/tools`, and a full `/api/scan` lifecycle all work with zero
  Python installed on the invoking shell's PATH assumption
### Known limitation
- Sidecar must be built per target OS (Linux/Windows/macOS separately);
  cross-compiling PyInstaller binaries is unreliable, so CI should build
  on native runners per platform (see Phase 5 roadmap)

## [0.3.0] - Phase 3 — Tauri Desktop Shell
### Added
- `src-tauri/` native desktop wrapper (Rust + Tauri v1)
- Auto-spawns and lifecycle-manages the Python backend as a child process
- Loads the existing Phase 2 dashboard with zero frontend rewrite
- Placeholder app icons (regenerate via `npx tauri icon`)
- `package.json` with `npm run dev` / `npm run build` scripts
### Known limitation
- Requires Python installed on the end-user machine (see README packaging
  note for the PyInstaller sidecar follow-up)

## [0.2.0] - Phase 2 — Live Web Dashboard
### Added
- FastAPI server (`backend/api/server.py`): scan lifecycle, settings, tool
  detection, and report-download endpoints
- WebSocket live progress/log streaming with history replay for late joiners
- In-memory scan registry with pub-sub broadcast (`backend/api/registry.py`)
- Single-file dark-themed dashboard (`frontend/index.html`, no build step)
- Verified end-to-end: start → poll → cancel → report download

## [0.1.0] - Phase 1 — Core Engine
### Added
- Async orchestrator with resumable checkpointing (`backend/core/orchestrator.py`)
- Subdomain enumeration: subfinder, assetfinder, amass (passive)
- Live-host validation via httpx
- Crawling: katana, hakrawler, gospider, gau, waybackurls
- JS URL extraction + concurrent downloader
- Static detectors: 30+ regex patterns (cloud keys, DB URIs, JWTs, private keys, etc.) + Shannon entropy scanner
- TruffleHog + Nuclei wrapper integrations
- Gemini AI second-stage triage (severity, confidence, false-positive likelihood)
- HTML/JSON/CSV report export
- Typer CLI with `scan`, `detect-tools`, `set-key`, `settings` commands
- Config auto-detection of all external tool binaries, no hard-coded paths
- Secret redaction before storage (prefix/suffix only)
- CI (lint + test), release workflow, issue/PR templates

### Planned (0.2.0)
- FastAPI + WebSocket live progress server
- Tauri + React desktop UI
- Source-map deobfuscation + AST endpoint extraction
- Screenshot capture, proxy rotation, scan cancellation
