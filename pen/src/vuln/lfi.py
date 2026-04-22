from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from src.vuln import Finding
from src.util.wordlists import LFI_PAYLOADS

UNIX_MARKERS = [re.compile(r"root:.*:0:0:"), re.compile(r"daemon:.*:/usr/sbin")]
WIN_MARKERS = [re.compile(r"\[boot loader\]", re.I), re.compile(r"\[fonts\]", re.I)]
PROC_MARKERS = [re.compile(r"PATH="), re.compile(r"Linux version")]
PHP_B64 = re.compile(r"^[A-Za-z0-9+/=]{20,}", re.MULTILINE)

def _inject(url, param, val):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [val]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

def _match(body):
    for m in UNIX_MARKERS:
        if m.search(body): return "unix filesystem content"
    for m in WIN_MARKERS:
        if m.search(body): return "windows filesystem content"
    for m in PROC_MARKERS:
        if m.search(body): return "process environment leaked"
    if PHP_B64.search(body): return "base64 file content (php://filter)"
    return ""


async def scan_lfi(session, url, concurrency=10):
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    if not params: return []
    sem = asyncio.Semaphore(concurrency)
    findings = []

    async def _test(param, payload):
        injected = _inject(url, param, payload)
        async with sem:
            try:
                async with session.get(injected, ssl=False) as resp:
                    body = await resp.text(errors="replace")
                    ev = _match(body)
                    if ev:
                        return Finding(vuln_type="lfi", severity="critical", url=injected,
                            parameter=param, payload=payload, evidence=ev,
                            description="Local File Inclusion — arbitrary file read")
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    for param in params:
        for payload in LFI_PAYLOADS:
            r = await _test(param, payload)
            if r:
                findings.append(r)
                break
    return findings
