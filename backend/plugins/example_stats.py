"""
Example plugin — demonstrates the plugin interface with something real and
self-contained (no external binary, no network calls, no fake data): it
computes basic size/line-count statistics over the downloaded JS files.

This is intentionally not a security detector — copy this file's shape to
add your own scanner (e.g. a wrapper around a new external tool, following
the pattern in backend/scanners/recon.py or backend/detectors/patterns.py).
"""
from pathlib import Path

STAGE_NAME = "example_stats"
REQUIRES = ["downloaded"]
PRODUCES = ["js_stats"]


async def run(ctx: dict, cfg, on_line=None) -> dict:
    downloaded = ctx.get("downloaded", [])
    total_bytes = 0
    total_lines = 0
    for f in downloaded:
        try:
            data = Path(f["local_path"]).read_bytes()
        except OSError:
            continue
        total_bytes += len(data)
        total_lines += data.count(b"\n") + 1

    ctx["js_stats"] = {
        "files": len(downloaded),
        "total_bytes": total_bytes,
        "total_lines": total_lines,
    }
    return {"items_found": len(downloaded)}
