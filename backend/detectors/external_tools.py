"""
Wrappers for TruffleHog (filesystem mode) and Nuclei (secret-exposure templates)
run against the downloaded JS directory.
"""
import json
from pathlib import Path
from backend.core.runner import run_tool
from backend.core.config import Config


async def run_trufflehog(js_dir: Path, cfg: Config, on_line=None) -> list[dict]:
    path = cfg.get_tool("trufflehog")
    if not path:
        return []
    out = await run_tool(
        [path, "filesystem", str(js_dir), "--json", "--no-update"],
        timeout=cfg.timeout * 30, retries=cfg.retries, on_line=on_line,
    )
    findings = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "type": obj.get("DetectorName", "TruffleHog Finding"),
            "match": "REDACTED",
            "severity": "High",
            "source": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", str(js_dir)),
            "detector": "trufflehog",
            "verified": obj.get("Verified", False),
        })
    return findings


async def run_nuclei(js_dir: Path, cfg: Config, on_line=None) -> list[dict]:
    path = cfg.get_tool("nuclei")
    if not path:
        return []
    out = await run_tool(
        [path, "-target", str(js_dir), "-tags", "exposure,token,secret", "-jsonl", "-silent"],
        timeout=cfg.timeout * 30, retries=cfg.retries, on_line=on_line,
    )
    findings = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "type": obj.get("info", {}).get("name", "Nuclei Finding"),
            "match": "See nuclei template output",
            "severity": obj.get("info", {}).get("severity", "medium").capitalize(),
            "source": obj.get("matched-at", str(js_dir)),
            "detector": "nuclei",
        })
    return findings
