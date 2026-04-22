from __future__ import annotations

import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from src.vuln import Finding
from src.util.wordlists import OPEN_REDIRECT_PAYLOADS, REDIRECT_PARAMS


def _inject(url, param, val):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [val]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _has_redirect_param(url):
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    return [p for p in params if p.lower() in REDIRECT_PARAMS]


async def scan_open_redirect(session, url, concurrency=10):
    sem = asyncio.Semaphore(concurrency)
    findings = []

    target_params = _has_redirect_param(url)
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    check_params = target_params if target_params else list(params.keys())

    if not check_params:
        return []

    async def _test(param, payload):
        injected = _inject(url, param, payload)
        async with sem:
            try:
                async with session.get(injected, ssl=False, allow_redirects=False) as resp:
                    location = resp.headers.get("Location", "")
                    if resp.status in (301, 302, 303, 307, 308):
                        if "evil.com" in location:
                            return Finding(
                                vuln_type="open-redirect", severity="medium",
                                url=injected, parameter=param, payload=payload,
                                evidence=f"Location: {location}",
                                description="Open Redirect — user can be redirected to arbitrary domain",
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    for param in check_params:
        for payload in OPEN_REDIRECT_PAYLOADS[:8]:
            r = await _test(param, payload)
            if r:
                findings.append(r)
                break

    return findings
