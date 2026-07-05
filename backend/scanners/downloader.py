"""
Downloads JS files concurrently with a semaphore, saves under
exports/<scan_id>/js/, returns list of {url, local_path}.
"""
import asyncio
import hashlib
from pathlib import Path
import httpx as httpx_client  # python httpx library (not the recon tool)


async def _fetch(client: httpx_client.AsyncClient, url: str, dest_dir: Path,
                  sem: asyncio.Semaphore, timeout: int) -> dict | None:
    async with sem:
        try:
            r = await client.get(url, timeout=timeout, follow_redirects=True)
            if r.status_code != 200 or not r.content:
                return None
            fname = hashlib.sha1(url.encode()).hexdigest()[:16] + ".js"
            fpath = dest_dir / fname
            fpath.write_bytes(r.content)
            return {"url": url, "local_path": str(fpath), "size": len(r.content)}
        except Exception:
            return None


async def _check(client: httpx_client.AsyncClient, url: str, sem: asyncio.Semaphore,
                  timeout: int) -> str | None:
    async with sem:
        try:
            r = await client.head(url, timeout=timeout, follow_redirects=True)
            if r.status_code == 405:  # some servers reject HEAD; fall back to GET
                r = await client.get(url, timeout=timeout, follow_redirects=True)
            return url if r.status_code == 200 else None
        except Exception:
            return None


async def verify_js_urls(js_urls: list[str], threads: int = 40, timeout: int = 15) -> list[str]:
    """Drop dead links before spending bandwidth downloading them."""
    if not js_urls:
        return []
    sem = asyncio.Semaphore(threads)
    async with httpx_client.AsyncClient(verify=False) as client:
        results = await asyncio.gather(*[_check(client, u, sem, timeout) for u in js_urls])
    return [u for u in results if u]


async def download_js_files(js_urls: list[str], scan_dir: Path, threads: int = 40,
                             timeout: int = 15) -> list[dict]:
    dest_dir = scan_dir / "js"
    dest_dir.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(threads)
    async with httpx_client.AsyncClient(verify=False) as client:
        results = await asyncio.gather(
            *[_fetch(client, u, dest_dir, sem, timeout) for u in js_urls]
        )
    return [r for r in results if r]
