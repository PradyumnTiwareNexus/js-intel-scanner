"""
Phase 1: Subdomain enumeration + live host validation.
Modular — each source is a plugin function that returns a set[str].
"""
import asyncio
from backend.core.runner import run_tool
from backend.core.config import Config


async def subfinder(domain: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("subfinder")
    if not path:
        return set()
    out = await run_tool([path, "-d", domain, "-silent"], timeout=cfg.timeout * 10,
                          retries=cfg.retries, on_line=on_line)
    return {line.strip() for line in out.splitlines() if line.strip()}


async def assetfinder(domain: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("assetfinder")
    if not path:
        return set()
    out = await run_tool([path, "--subs-only", domain], timeout=cfg.timeout * 10,
                          retries=cfg.retries, on_line=on_line)
    return {line.strip() for line in out.splitlines() if line.strip()}


async def amass_passive(domain: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("amass")
    if not path:
        return set()
    out = await run_tool([path, "enum", "-passive", "-d", domain, "-silent"],
                          timeout=cfg.timeout * 15, retries=cfg.retries, on_line=on_line)
    return {line.strip() for line in out.splitlines() if line.strip()}


async def enumerate_subdomains(domain: str, cfg: Config, on_line=None) -> list[str]:
    """Run all sources concurrently, merge + dedupe."""
    results = await asyncio.gather(
        subfinder(domain, cfg, on_line),
        assetfinder(domain, cfg, on_line),
        amass_passive(domain, cfg, on_line),
    )
    merged: set[str] = set()
    for r in results:
        merged |= r
    merged.add(domain)  # always include root
    return sorted(merged)


async def httpx_alive(hosts: list[str], cfg: Config, on_line=None) -> list[dict]:
    """Return list of {url, status_code, title, tech} for live hosts."""
    path = cfg.get_tool("httpx")
    if not path or not hosts:
        return []
    out = await run_tool(
        [path, "-silent", "-json", "-status-code", "-title", "-tech-detect",
         "-threads", str(cfg.threads), "-timeout", str(cfg.timeout)],
        input_data="\n".join(hosts),
        timeout=cfg.timeout * 20,
        retries=cfg.retries,
        on_line=on_line,
    )
    import json
    live = []
    for line in out.splitlines():
        try:
            live.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return live
