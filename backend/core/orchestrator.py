"""
Config-driven pipeline engine.

Stage order, enabled/disabled state, and worker counts all come from
Config (configs/config.yaml + active profile) — nothing is hardcoded here.
The orchestrator's only job is to:

  1. Resolve the effective stage list (config.pipeline, filtered by
     config.stage_cfg(name)["enabled"], intersected with the stage
     registry — built-ins + auto-discovered plugins).
  2. Walk it in order, checking each stage's declared `requires` against
     what earlier *enabled and successful* stages actually produced.
     Missing dependency -> skip with a logged reason, never crash.
  3. Run each stage with its own timeout/retries from config, isolate
     exceptions per stage (a failing stage is recorded as an error and
     the pipeline continues — it is never terminated by one bad stage).
  4. Checkpoint progress to disk so a re-run with the same scan_dir
     resumes instead of repeating completed stages.

Emits progress via `on_event(stage, pct, message)` so a CLI, WebSocket,
or desktop UI can all reuse the same core.
"""
import asyncio
import json
import time
from pathlib import Path

from backend.core.config import Config
from backend.core.stages import build_registry

REGISTRY = build_registry()


class ScanState:
    """Holds per-stage results, resumable via JSON checkpoint on disk.
    Only JSON-serializable stage outputs are persisted (sets are stored as
    sorted lists); the live run always keeps the richer in-memory ctx."""

    def __init__(self, scan_dir: Path):
        self.scan_dir = scan_dir
        self.checkpoint_file = scan_dir / "checkpoint.json"
        self.data = {"completed_stages": {}}
        if self.checkpoint_file.exists():
            try:
                self.data = json.loads(self.checkpoint_file.read_text())
            except (json.JSONDecodeError, OSError):
                self.data = {"completed_stages": {}}

    def save(self):
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.checkpoint_file.write_text(json.dumps(self.data, indent=2, default=str))
        except OSError:
            pass  # checkpointing is best-effort; never fail the scan over disk I/O

    def mark_done(self, stage: str, stats: dict):
        self.data["completed_stages"][stage] = stats
        self.save()

    def is_done(self, stage: str) -> bool:
        return stage in self.data["completed_stages"]


def new_context(domain: str, scan_dir: Path) -> dict:
    """Shared mutable state passed to every stage. Accumulator keys start
    empty so a stage can be disabled/missing without downstream stages
    crashing on a KeyError — they just see no data from that source."""
    return {
        "domain": domain,
        "scan_dir": scan_dir,
        "subdomains_set": set(),
        "crawled_urls_set": set(),
        "static_findings": [],
        "ext_findings": [],
    }


async def run_pipeline(domain: str, cfg: Config, base_dir: Path, on_event=None) -> dict:
    """
    on_event(stage, pct, message) — async or sync callable for live progress.
    Resumable: re-running with the same base_dir/domain skips completed stages.
    Returns the summary dict built by the `report` stage (or a minimal
    fallback if `report` itself was disabled/skipped).
    """
    scan_dir = base_dir / domain.replace("/", "_")
    state = ScanState(scan_dir)
    ctx = new_context(domain, scan_dir)
    stage_results: dict[str, dict] = {}
    available: set[str] = {"domain", "scan_dir"}

    async def emit(stage, pct, msg):
        if on_event:
            r = on_event(stage, pct, msg)
            if asyncio.iscoroutine(r):
                await r

    def make_line_cb(stage_name):
        async def _cb(line):
            await emit(stage_name, -1, line)
        return _cb

    pipeline = cfg.effective_pipeline()
    total = max(len(pipeline), 1)

    for i, name in enumerate(pipeline):
        pct = round(5 + (i / total) * 90)
        spec = REGISTRY.get(name)

        if spec is None:
            stage_results[name] = {"status": "skipped", "reason": "unknown stage (not in registry or plugins)"}
            await emit(name, pct, f"Skipped {name}: not found in stage registry or plugins/")
            continue

        missing = [r for r in spec.requires if r not in available]
        if missing:
            reason = f"missing dependency: {', '.join(missing)} (an earlier stage that produces this was disabled, failed, or removed from the pipeline)"
            stage_results[name] = {"status": "skipped", "reason": reason}
            await emit(name, pct, f"Skipped {name}: {reason}")
            continue

        if state.is_done(name):
            stage_results[name] = state.data["completed_stages"][name]
            available.update(spec.produces)
            await emit(name, pct, f"{name}: resumed from checkpoint")
            continue

        await emit(name, pct, f"Running {name}...")
        start = time.monotonic()
        try:
            stats = await spec.fn(ctx, cfg, make_line_cb(name)) or {}
            duration = round(time.monotonic() - start, 2)
            result = {"status": "done", "duration": duration, **stats}
            available.update(spec.produces)
            stage_results[name] = result
            state.mark_done(name, result)
            await emit(name, pct, f"{name} complete ({stats.get('items_found', '?')} items, {duration}s)")
        except Exception as e:  # noqa: BLE001 — a stage must never take down the scan
            duration = round(time.monotonic() - start, 2)
            result = {"status": "error", "duration": duration, "error": str(e)}
            stage_results[name] = result
            await emit(name, pct, f"{name} failed (continuing pipeline): {e}")

    summary = ctx.get("summary")
    if summary is None:
        # `report` stage was disabled/skipped/missing — still return something usable.
        findings = ctx.get("all_findings")
        if findings is None:
            findings = ctx.get("static_findings", []) + ctx.get("ext_findings", [])
        summary = {
            "domain": domain,
            "subdomains": len(ctx.get("subdomains") or [domain]),
            "live_hosts": len(ctx.get("live_hosts", [])),
            "js_files": len(ctx.get("js_urls", [])),
            "downloaded": len(ctx.get("downloaded", [])),
            "findings": findings,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    summary["stage_results"] = stage_results
    summary["pipeline"] = pipeline
    await emit("done", 100, "Scan complete")
    return summary
