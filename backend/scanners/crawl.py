"""
Phase 2: Crawl live hosts, collect all URLs, then filter JS assets.
"""
import asyncio
import re
from backend.core.runner import run_tool
from backend.core.config import Config

JS_URL_RE = re.compile(r"\.js(\?.*)?$", re.IGNORECASE)


async def katana_crawl(url: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("katana")
    if not path:
        return set()
    out = await run_tool([path, "-u", url, "-silent", "-jc", "-d", "3"],
                          timeout=cfg.timeout * 20, retries=cfg.retries, on_line=on_line)
    return {line.strip() for line in out.splitlines() if line.strip()}


async def gau_urls(domain: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("gau")
    if not path:
        return set()
    out = await run_tool([path, domain], timeout=cfg.timeout * 20,
                          retries=cfg.retries, on_line=on_line)
    return {line.strip() for line in out.splitlines() if line.strip()}


async def wayback_urls(domain: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("waybackurls")
    if not path:
        return set()
    out = await run_tool([path, domain], timeout=cfg.timeout * 20,
                          retries=cfg.retries, on_line=on_line)
    return {line.strip() for line in out.splitlines() if line.strip()}


async def hakrawler_crawl(url: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("hakrawler")
    if not path:
        return set()
    out = await run_tool([path, "-url", url, "-depth", "3"],
                          timeout=cfg.timeout * 20, retries=cfg.retries,
                          input_data=url, on_line=on_line)
    return {line.strip() for line in out.splitlines() if line.strip()}


async def gospider_crawl(url: str, cfg: Config, on_line=None) -> set[str]:
    path = cfg.get_tool("gospider")
    if not path:
        return set()
    out = await run_tool([path, "-s", url, "-d", "3", "-q"],
                          timeout=cfg.timeout * 20, retries=cfg.retries, on_line=on_line)
    urls = set()
    for line in out.splitlines():
        m = re.search(r"(https?://\S+)", line)
        if m:
            urls.add(m.group(1))
    return urls


async def collect_all_urls(live_hosts: list[str], root_domain: str, cfg: Config,
                            on_line=None) -> list[str]:
    """Run every crawler concurrently across live hosts + passive URL sources."""
    tasks = [gau_urls(root_domain, cfg, on_line), wayback_urls(root_domain, cfg, on_line)]
    for host in live_hosts:
        tasks += [
            katana_crawl(host, cfg, on_line),
            hakrawler_crawl(host, cfg, on_line),
            gospider_crawl(host, cfg, on_line),
        ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    merged: set[str] = set()
    for r in results:
        if isinstance(r, set):
            merged |= r
    return sorted(merged)


def extract_js_urls(all_urls: list[str]) -> list[str]:
    """Filter crawled URLs down to JavaScript assets only."""
    return sorted({u for u in all_urls if JS_URL_RE.search(u.split("#")[0])})
