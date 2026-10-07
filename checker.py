"""Async username checker. Uses the WhatsMyName dataset (700+ sites) + aiohttp."""
import asyncio
import json
import re
import time
from pathlib import Path

import aiohttp

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
CACHE = Path(__file__).with_name("wmn-data.json")
CACHE_MAX_AGE = 7 * 24 * 3600  
CONCURRENCY = 50
SITE_TIMEOUT = aiohttp.ClientTimeout(total=12)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,40}$")
BASE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


async def load_sites(session: aiohttp.ClientSession) -> list[dict]:
    fresh = CACHE.exists() and time.time() - CACHE.stat().st_mtime < CACHE_MAX_AGE
    if not fresh:
        try:
            async with session.get(WMN_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
                r.raise_for_status()
                CACHE.write_text(await r.text(), encoding="utf-8")
        except Exception:
            if not CACHE.exists():
                raise
    data = json.loads(CACHE.read_text(encoding="utf-8"))
    sites = []
    for s in data["sites"]:
        if s.get("post_body") or s.get("valid") is False:
            continue  
        sites.append(s)
    return sites


async def _check(session, sem, site: dict, username: str):
    bad = site.get("strip_bad_char") or ""
    name = "".join(c for c in username if c not in bad)
    url = site["uri_check"].replace("{account}", name)
    headers = {**BASE_HEADERS, **(site.get("headers") or {})}

    async with sem:
        try:
            async with session.get(
                url, headers=headers, timeout=SITE_TIMEOUT, allow_redirects=True
            ) as r:
                status = r.status
                body = await r.text(errors="ignore")
        except Exception:
            return None

    if status != site.get("e_code"):
        return None
    e_string, m_string = site.get("e_string"), site.get("m_string")
    if e_string and e_string not in body:
        return None
    if m_string and m_string in body:
        return None

    pretty = site.get("uri_pretty") or site["uri_check"]
    return {
        "site": site["name"],
        "cat": site.get("cat") or "other",
        "url": pretty.replace("{account}", name),
    }


async def scan(username: str) -> tuple[list[dict], int]:
    """Returns (hits, number_of_sites_checked)."""
    sem = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY * 2, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        sites = await load_sites(session)
        results = await asyncio.gather(*(_check(session, sem, s, username) for s in sites))
    hits = sorted((r for r in results if r), key=lambda h: (h["cat"], h["site"].lower()))
    return hits, len(sites)