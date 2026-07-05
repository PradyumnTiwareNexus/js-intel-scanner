"""
Stage registry for the config-driven pipeline.

Each stage is a thin adapter around the real scanner/detector functions
that already exist in backend/scanners and backend/detectors — nothing
here re-implements scanning logic, it just gives every step a stable
name, declared inputs/outputs, and a uniform async signature so the
orchestrator can run whatever order configs/config.yaml specifies.

Stage function signature:
    async def fn(ctx: dict, cfg: Config, on_line) -> dict
      - ctx:      shared mutable state for the whole scan (see defaults
                  in orchestrator.new_context())
      - cfg:      the loaded Config
      - on_line:  async callback(line: str), forwarded to external tools
                  for live-log streaming
      - returns:  a small dict of stats about the run, e.g. {"items_found": N}
                  (merged into the stage's result record; never required)

Plugins: any .py file dropped into backend/plugins/ that defines
STAGE_NAME (str), REQUIRES (list[str]), PRODUCES (list[str]), and an
async run(ctx, cfg, on_line) function is auto-registered the same way,
without touching this file.
"""
import asyncio
import importlib.util
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from backend.core.config import Config
from backend.scanners import recon, crawl, downloader, webfiles
from backend.detectors import patterns, entropy, external_tools, extras
from backend.ai import gemini_analyzer

logger = logging.getLogger("stages")

PLUGINS_DIR = Path(__file__).resolve().parents[1] / "plugins"


@dataclass
class StageSpec:
    name: str
    fn: Callable
    requires: list[str] = field(default_factory=list)   # ctx keys that must already be populated
    produces: list[str] = field(default_factory=list)   # ctx keys this stage sets on success
    source: str = "builtin"                              # "builtin" or plugin filename


# ---------------------------------------------------------------------------
# Built-in stage adapters
# ---------------------------------------------------------------------------

async def _read_texts(downloaded: list[dict]) -> list[tuple[str, str]]:
    """Return [(text, source_url), ...] for every downloaded JS file."""
    out = []
    for f in downloaded:
        try:
            out.append((Path(f["local_path"]).read_text(errors="ignore"), f["url"]))
        except OSError:
            continue
    return out


async def stage_subfinder(ctx, cfg: Config, on_line=None) -> dict:
    subs = await recon.subfinder(ctx["domain"], cfg, on_line)
    ctx["subdomains_set"].update(subs)
    return {"items_found": len(subs)}


async def stage_assetfinder(ctx, cfg: Config, on_line=None) -> dict:
    subs = await recon.assetfinder(ctx["domain"], cfg, on_line)
    ctx["subdomains_set"].update(subs)
    return {"items_found": len(subs)}


async def stage_amass(ctx, cfg: Config, on_line=None) -> dict:
    subs = await recon.amass_passive(ctx["domain"], cfg, on_line)
    ctx["subdomains_set"].update(subs)
    return {"items_found": len(subs)}


async def stage_deduplicate(ctx, cfg: Config, on_line=None) -> dict:
    subs = set(ctx["subdomains_set"])
    subs.add(ctx["domain"])
    ctx["subdomains"] = sorted(subs)
    return {"items_found": len(ctx["subdomains"])}


async def stage_httpx(ctx, cfg: Config, on_line=None) -> dict:
    hosts = ctx.get("subdomains") or [ctx["domain"]]
    live = await recon.httpx_alive(hosts, cfg, on_line)
    ctx["live_hosts"] = live
    ctx["live_urls"] = [h["url"] for h in live if "url" in h]
    return {"items_found": len(live)}


async def stage_katana(ctx, cfg: Config, on_line=None) -> dict:
    results = await asyncio.gather(
        *[crawl.katana_crawl(u, cfg, on_line) for u in ctx["live_urls"]]
    )
    merged: set[str] = set().union(*results) if results else set()
    ctx["crawled_urls_set"].update(merged)
    return {"items_found": len(merged)}


async def stage_hakrawler(ctx, cfg: Config, on_line=None) -> dict:
    results = await asyncio.gather(
        *[crawl.hakrawler_crawl(u, cfg, on_line) for u in ctx["live_urls"]]
    )
    merged: set[str] = set().union(*results) if results else set()
    ctx["crawled_urls_set"].update(merged)
    return {"items_found": len(merged)}


async def stage_gospider(ctx, cfg: Config, on_line=None) -> dict:
    results = await asyncio.gather(
        *[crawl.gospider_crawl(u, cfg, on_line) for u in ctx["live_urls"]]
    )
    merged: set[str] = set().union(*results) if results else set()
    ctx["crawled_urls_set"].update(merged)
    return {"items_found": len(merged)}


async def stage_gau(ctx, cfg: Config, on_line=None) -> dict:
    urls = await crawl.gau_urls(ctx["domain"], cfg, on_line)
    ctx["crawled_urls_set"].update(urls)
    return {"items_found": len(urls)}


async def stage_waybackurls(ctx, cfg: Config, on_line=None) -> dict:
    urls = await crawl.wayback_urls(ctx["domain"], cfg, on_line)
    ctx["crawled_urls_set"].update(urls)
    return {"items_found": len(urls)}


async def stage_robots(ctx, cfg: Config, on_line=None) -> dict:
    urls = await webfiles.fetch_robots(ctx["domain"], cfg)
    ctx["crawled_urls_set"].update(urls)
    return {"items_found": len(urls)}


async def stage_sitemap(ctx, cfg: Config, on_line=None) -> dict:
    urls = await webfiles.fetch_sitemap(ctx["domain"], cfg)
    ctx["crawled_urls_set"].update(urls)
    return {"items_found": len(urls)}


async def stage_jsfinder(ctx, cfg: Config, on_line=None) -> dict:
    js = crawl.extract_js_urls(sorted(ctx["crawled_urls_set"]))
    ctx["js_urls"] = js
    return {"items_found": len(js)}


async def stage_verify_js(ctx, cfg: Config, on_line=None) -> dict:
    stage_cfg = cfg.stage_cfg("verify_js")
    verified = await downloader.verify_js_urls(
        ctx["js_urls"], threads=stage_cfg.get("workers", cfg.threads), timeout=cfg.timeout
    )
    ctx["js_urls_verified"] = verified
    return {"items_found": len(verified)}


async def stage_download_js(ctx, cfg: Config, on_line=None) -> dict:
    js = ctx.get("js_urls_verified") if ctx.get("js_urls_verified") is not None else ctx["js_urls"]
    stage_cfg = cfg.stage_cfg("download_js")
    downloaded = await downloader.download_js_files(
        js, ctx["scan_dir"], threads=stage_cfg.get("workers", cfg.threads), timeout=cfg.timeout
    )
    ctx["downloaded"] = downloaded
    return {"items_found": len(downloaded)}


async def stage_regex(ctx, cfg: Config, on_line=None) -> dict:
    findings = []
    for text, source in await _read_texts(ctx["downloaded"]):
        findings += patterns.scan_text(text, source)
    ctx["static_findings"].extend(findings)
    return {"items_found": len(findings)}


async def stage_entropy(ctx, cfg: Config, on_line=None) -> dict:
    findings = []
    for text, source in await _read_texts(ctx["downloaded"]):
        findings += entropy.scan_entropy(text, source)
    ctx["static_findings"].extend(findings)
    return {"items_found": len(findings)}


async def stage_endpoints(ctx, cfg: Config, on_line=None) -> dict:
    findings = []
    for text, source in await _read_texts(ctx["downloaded"]):
        findings += extras.extract_endpoints(text, source)
    ctx["static_findings"].extend(findings)
    return {"items_found": len(findings)}


async def stage_comments(ctx, cfg: Config, on_line=None) -> dict:
    findings = []
    for text, source in await _read_texts(ctx["downloaded"]):
        findings += extras.extract_comments(text, source)
    ctx["static_findings"].extend(findings)
    return {"items_found": len(findings)}


async def stage_trufflehog(ctx, cfg: Config, on_line=None) -> dict:
    found = await external_tools.run_trufflehog(ctx["scan_dir"] / "js", cfg, on_line)
    ctx["ext_findings"].extend(found)
    return {"items_found": len(found)}


async def stage_nuclei(ctx, cfg: Config, on_line=None) -> dict:
    found = await external_tools.run_nuclei(ctx["scan_dir"] / "js", cfg, on_line)
    ctx["ext_findings"].extend(found)
    return {"items_found": len(found)}


async def stage_gemini(ctx, cfg: Config, on_line=None) -> dict:
    combined = ctx["static_findings"] + ctx["ext_findings"]
    classified = await gemini_analyzer.classify_findings(
        js_context=ctx["domain"], findings=combined, cfg=cfg
    )
    ctx["all_findings"] = classified
    return {"items_found": len(classified)}


async def stage_report(ctx, cfg: Config, on_line=None) -> dict:
    findings = ctx.get("all_findings")
    if findings is None:
        findings = ctx["static_findings"] + ctx["ext_findings"]
    import time
    ctx["summary"] = {
        "domain": ctx["domain"],
        "subdomains": len(ctx.get("subdomains") or [ctx["domain"]]),
        "live_hosts": len(ctx.get("live_hosts", [])),
        "js_files": len(ctx.get("js_urls", [])),
        "downloaded": len(ctx.get("downloaded", [])),
        "findings": findings,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return {"items_found": len(findings)}


BUILTIN_STAGES: list[StageSpec] = [
    StageSpec("subfinder", stage_subfinder, requires=[], produces=["subdomains_set"]),
    StageSpec("assetfinder", stage_assetfinder, requires=[], produces=["subdomains_set"]),
    StageSpec("amass", stage_amass, requires=[], produces=["subdomains_set"]),
    StageSpec("deduplicate", stage_deduplicate, requires=[], produces=["subdomains"]),
    StageSpec("httpx", stage_httpx, requires=["subdomains"], produces=["live_hosts", "live_urls"]),
    StageSpec("katana", stage_katana, requires=["live_hosts"], produces=["crawled_urls_set"]),
    StageSpec("hakrawler", stage_hakrawler, requires=["live_hosts"], produces=["crawled_urls_set"]),
    StageSpec("gospider", stage_gospider, requires=["live_hosts"], produces=["crawled_urls_set"]),
    StageSpec("gau", stage_gau, requires=[], produces=["crawled_urls_set"]),
    StageSpec("waybackurls", stage_waybackurls, requires=[], produces=["crawled_urls_set"]),
    StageSpec("robots", stage_robots, requires=[], produces=["crawled_urls_set"]),
    StageSpec("sitemap", stage_sitemap, requires=[], produces=["crawled_urls_set"]),
    StageSpec("jsfinder", stage_jsfinder, requires=[], produces=["js_urls"]),
    StageSpec("verify_js", stage_verify_js, requires=["js_urls"], produces=["js_urls_verified"]),
    StageSpec("download_js", stage_download_js, requires=[], produces=["downloaded"]),
    StageSpec("regex", stage_regex, requires=["downloaded"], produces=["static_findings"]),
    StageSpec("entropy", stage_entropy, requires=["downloaded"], produces=["static_findings"]),
    StageSpec("endpoints", stage_endpoints, requires=["downloaded"], produces=["static_findings"]),
    StageSpec("comments", stage_comments, requires=["downloaded"], produces=["static_findings"]),
    StageSpec("trufflehog", stage_trufflehog, requires=["downloaded"], produces=["ext_findings"]),
    StageSpec("nuclei", stage_nuclei, requires=["downloaded"], produces=["ext_findings"]),
    StageSpec("gemini", stage_gemini, requires=["static_findings"], produces=["all_findings"]),
    StageSpec("report", stage_report, requires=["static_findings"], produces=["summary"]),
]


def _load_plugins() -> list[StageSpec]:
    """Import every .py file under backend/plugins/ and register any module
    that exposes STAGE_NAME + run() as a new stage. Never raises — a broken
    plugin is logged and skipped so it can't take down the whole platform."""
    specs = []
    if not PLUGINS_DIR.is_dir():
        return specs
    for path in sorted(PLUGINS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"backend.plugins.{path.stem}", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            stage_name = getattr(module, "STAGE_NAME", None)
            run_fn = getattr(module, "run", None)
            if not stage_name or not callable(run_fn):
                logger.warning("Plugin %s missing STAGE_NAME or run() — skipped", path.name)
                continue
            specs.append(StageSpec(
                name=stage_name,
                fn=run_fn,
                requires=list(getattr(module, "REQUIRES", [])),
                produces=list(getattr(module, "PRODUCES", [])),
                source=path.name,
            ))
        except Exception as e:
            logger.error("Failed to load plugin %s: %s", path.name, e)
    return specs


def build_registry() -> dict[str, StageSpec]:
    """Built-ins first, then plugins (a plugin cannot silently override a
    built-in stage name — it's logged and ignored so behavior stays predictable)."""
    registry = {s.name: s for s in BUILTIN_STAGES}
    for spec in _load_plugins():
        if spec.name in registry:
            logger.warning("Plugin stage '%s' from %s conflicts with a built-in — ignored",
                            spec.name, spec.source)
            continue
        registry[spec.name] = spec
    return registry
