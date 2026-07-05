"""
FastAPI backend for the desktop/web UI.

Endpoints:
  POST   /api/scan               -> start a scan, returns {scan_id}
  GET    /api/scan/{id}          -> status + summary (if done)
  POST   /api/scan/{id}/cancel   -> cancel a running scan
  GET    /api/scans              -> list all scans (this session)
  WS     /ws/{id}                -> live progress + log stream
  GET    /api/tools              -> detect/list external tool status
  GET/POST /api/settings         -> read/update config
  GET    /api/pipeline           -> stage order, per-stage settings, profiles
  POST   /api/pipeline           -> save reordered/enabled stages + active profile
  GET    /api/profiles           -> list named profiles
  POST   /api/profiles/{name}    -> create/overwrite a profile (save/duplicate)
  DELETE /api/profiles/{name}    -> remove a profile
  GET    /api/profiles/{name}/export -> profile as JSON for download
  POST   /api/profiles/import    -> import a profile JSON
  GET    /api/report/{id}/{fmt}  -> download html/json/csv report

Run: uvicorn backend.api.server:app --reload --port 8787
The Tauri desktop shell (Phase 2 UI) points its webview at this server.
"""
import asyncio
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.core.config import Config, detect_all_tools
from backend.core.orchestrator import run_pipeline
from backend.core.stages import build_registry
from backend.core.report import export_all
from backend.api.registry import registry

app = FastAPI(title="JS Intelligence Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # local desktop shell only; tighten if exposed beyond localhost
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_EXPORT_DIR = Path("exports")


class ScanRequest(BaseModel):
    domain: str


class SettingsUpdate(BaseModel):
    threads: int | None = None
    timeout: int | None = None
    retries: int | None = None
    proxy: str | None = None
    rate_limit: int | None = None
    gemini_api_key: str | None = None
    tool_paths: dict | None = None
    theme: str | None = None


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    cfg = Config.load()
    job = registry.create(req.domain)

    async def on_event(stage, pct, msg):
        event = {"scan_id": job.scan_id, "stage": stage, "pct": pct, "message": msg}
        await registry.broadcast(job, event)

    async def runner():
        job.status = "running"
        try:
            summary = await run_pipeline(job.domain, cfg, BASE_EXPORT_DIR, on_event)
            job.summary = summary
            job.status = "done"
            out_dir = BASE_EXPORT_DIR / job.domain.replace("/", "_") / "report"
            export_all(summary, out_dir)
            await registry.broadcast(job, {"scan_id": job.scan_id, "stage": "done",
                                            "pct": 100, "message": "Scan complete"})
        except asyncio.CancelledError:
            job.status = "cancelled"
            await registry.broadcast(job, {"scan_id": job.scan_id, "stage": "cancelled",
                                            "pct": -1, "message": "Scan cancelled by user"})
        except Exception as e:
            job.status = "error"
            job.error = str(e)
            await registry.broadcast(job, {"scan_id": job.scan_id, "stage": "error",
                                            "pct": -1, "message": str(e)})

    job.task = asyncio.create_task(runner())
    return {"scan_id": job.scan_id, "domain": job.domain}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    job = registry.get(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    return {
        "scan_id": job.scan_id, "domain": job.domain, "status": job.status,
        "error": job.error, "summary": job.summary,
    }


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    job = registry.get(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    if job.task and not job.task.done():
        job.task.cancel()
        return {"cancelled": True}
    return {"cancelled": False, "reason": "job already finished"}


@app.get("/api/scans")
async def list_scans():
    return [{"scan_id": j.scan_id, "domain": j.domain, "status": j.status} for j in registry.all()]


@app.websocket("/ws/{scan_id}")
async def ws_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    job = registry.get(scan_id)
    if not job:
        await websocket.send_json({"error": "scan not found"})
        await websocket.close()
        return

    # replay history so a client joining mid-scan isn't lost
    for event in job.history:
        await websocket.send_json(event)

    job.subscribers.add(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep connection alive; ignore client pings
    except WebSocketDisconnect:
        job.subscribers.discard(websocket)


@app.get("/api/tools")
async def tools_status():
    cfg = Config.load()
    results = detect_all_tools(cfg)
    return {"tools": results, "missing": [t for t, p in results.items() if not p]}


@app.get("/api/settings")
async def get_settings():
    cfg = Config.load()
    safe = cfg.__dict__.copy()
    if safe.get("gemini_api_key"):
        safe["gemini_api_key"] = "•" * 8 + safe["gemini_api_key"][-4:]
    return safe


@app.post("/api/settings")
async def update_settings(update: SettingsUpdate):
    cfg = Config.load()
    for field_name, value in update.model_dump(exclude_none=True).items():
        setattr(cfg, field_name, value)
    cfg.save()
    return {"saved": True}


class PipelineUpdate(BaseModel):
    pipeline: list[str] | None = None
    stages: dict | None = None
    active_profile: str | None = None


class ProfileUpsert(BaseModel):
    disable: list[str] = []
    workers: dict = {}
    rate_limit: int | None = None


@app.get("/api/pipeline")
async def get_pipeline():
    """Full pipeline config: stage order, per-stage settings, profiles,
    and the effective (profile-filtered) order actually used on the next scan."""
    cfg = Config.load()
    return {
        "pipeline": cfg.pipeline,
        "stages": cfg.stages,
        "profiles": cfg.profiles,
        "active_profile": cfg.active_profile,
        "effective_pipeline": cfg.effective_pipeline(),
        "available_stages": sorted(build_registry().keys()),
    }


@app.post("/api/pipeline")
async def update_pipeline(update: PipelineUpdate):
    """Persist stage order / enabled state / active profile — no manual
    config.yaml editing required, this is what the web UI's drag-and-drop
    pipeline editor calls."""
    cfg = Config.load()
    if update.pipeline is not None:
        unknown = [s for s in update.pipeline if s not in build_registry()]
        if unknown:
            raise HTTPException(400, f"Unknown stage(s): {', '.join(unknown)}")
        cfg.pipeline = update.pipeline
    if update.stages is not None:
        for name, settings in update.stages.items():
            cfg.stages.setdefault(name, {}).update(settings)
    if update.active_profile is not None:
        if update.active_profile not in cfg.profiles:
            raise HTTPException(400, f"Unknown profile '{update.active_profile}'")
        cfg.active_profile = update.active_profile
    cfg.save()
    return {"saved": True, "effective_pipeline": cfg.effective_pipeline()}


@app.get("/api/profiles")
async def list_profiles():
    cfg = Config.load()
    return {"profiles": cfg.profiles, "active_profile": cfg.active_profile}


@app.post("/api/profiles/{name}")
async def save_profile(name: str, profile: ProfileUpsert):
    """Create or overwrite a profile — used for Save/Save As/Duplicate in the UI."""
    cfg = Config.load()
    cfg.profiles[name] = profile.model_dump(exclude_none=True)
    cfg.save()
    return {"saved": True, "profile": cfg.profiles[name]}


@app.delete("/api/profiles/{name}")
async def delete_profile(name: str):
    cfg = Config.load()
    if name not in cfg.profiles:
        raise HTTPException(404, "profile not found")
    if name == cfg.active_profile:
        raise HTTPException(400, "cannot delete the active profile — switch first")
    del cfg.profiles[name]
    cfg.save()
    return {"deleted": True}


@app.get("/api/profiles/{name}/export")
async def export_profile(name: str):
    cfg = Config.load()
    if name not in cfg.profiles:
        raise HTTPException(404, "profile not found")
    return {"name": name, "profile": cfg.profiles[name]}


@app.post("/api/profiles/import")
async def import_profile(payload: dict):
    """Body: {"name": "my-profile", "profile": {"disable": [...], "workers": {...}}}"""
    name = payload.get("name")
    profile = payload.get("profile")
    if not name or not isinstance(profile, dict):
        raise HTTPException(400, "expected {name, profile}")
    cfg = Config.load()
    cfg.profiles[name] = profile
    cfg.save()
    return {"imported": True, "name": name}


@app.get("/api/report/{scan_id}/{fmt}")
async def download_report(scan_id: str, fmt: str):
    job = registry.get(scan_id)
    if not job or job.status != "done":
        raise HTTPException(404, "report not ready")
    out_dir = BASE_EXPORT_DIR / job.domain.replace("/", "_") / "report"
    fname = {"html": "report.html", "json": "report.json", "csv": "report.csv"}.get(fmt)
    if not fname or not (out_dir / fname).exists():
        raise HTTPException(400, "invalid format or file missing")
    return FileResponse(out_dir / fname)
