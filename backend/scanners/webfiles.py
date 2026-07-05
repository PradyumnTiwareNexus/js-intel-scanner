"""
Lightweight passive-recon sources that don't need an external binary:
robots.txt Disallow/Allow paths, and sitemap.xml <loc> URLs.
Uses the Python httpx library (network client), not the recon tool of the
same name — see downloader.py for the same distinction.
"""
import re
import httpx as httpx_client

from backend.core.config import Config

SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
ROBOTS_PATH_RE = re.compile(r"(?im)^\s*(?:Disallow|Allow)\s*:\s*(\S+)")


async def fetch_robots(domain: str, cfg: Config) -> set[str]:
    """Fetch robots.txt over both schemes, return absolute URLs for every listed path."""
    urls: set[str] = set()
    async with httpx_client.AsyncClient(verify=False, timeout=cfg.timeout) as client:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{domain}/robots.txt", follow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200 or not r.text:
                continue
            for m in ROBOTS_PATH_RE.finditer(r.text):
                path = m.group(1).strip()
                if path and path != "/":
                    urls.add(f"{scheme}://{domain}{path}")
            break  # one successful scheme is enough
    return urls


async def fetch_sitemap(domain: str, cfg: Config) -> set[str]:
    """Fetch sitemap.xml (and any nested sitemap it references, one level deep)."""
    urls: set[str] = set()

    async def _fetch_one(client, url: str, depth: int = 0):
        try:
            r = await client.get(url, follow_redirects=True)
        except Exception:
            return
        if r.status_code != 200 or not r.text:
            return
        locs = SITEMAP_LOC_RE.findall(r.text)
        for loc in locs:
            if depth == 0 and loc.endswith((".xml", ".xml.gz")):
                await _fetch_one(client, loc, depth=1)
            else:
                urls.add(loc)

    async with httpx_client.AsyncClient(verify=False, timeout=cfg.timeout) as client:
        for scheme in ("https", "http"):
            before = len(urls)
            await _fetch_one(client, f"{scheme}://{domain}/sitemap.xml")
            if len(urls) > before:
                break
    return urls
